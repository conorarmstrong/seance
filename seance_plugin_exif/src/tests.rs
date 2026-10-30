use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Minimal little-endian TIFF/EXIF fixture builder.
//
// Produces a real, parseable EXIF (TIFF) block so tests do not depend on any
// checked-in binary sample or external tooling. Values are placed in an external
// data pool when they exceed the 4-byte inline value slot, exactly per TIFF.
// ---------------------------------------------------------------------------

enum Val {
    Ascii(&'static str),
    Short(u16),
    Long(u32),
    Byte(u8),
    Rationals(Vec<(u32, u32)>),
}

struct Entry {
    tag: u16,
    val: Val,
}

fn tiff_type(v: &Val) -> u16 {
    match v {
        Val::Byte(_) => 1,
        Val::Ascii(_) => 2,
        Val::Short(_) => 3,
        Val::Long(_) => 4,
        Val::Rationals(_) => 5,
    }
}

fn tiff_count(v: &Val) -> u32 {
    match v {
        Val::Ascii(s) => (s.len() + 1) as u32,
        Val::Rationals(r) => r.len() as u32,
        _ => 1,
    }
}

fn pad_even(mut v: Vec<u8>) -> Vec<u8> {
    if !v.len().is_multiple_of(2) {
        v.push(0);
    }
    v
}

/// Returns the 4-byte value slot and any external bytes for `ext_offset`.
fn entry_value_bytes(v: &Val, ext_offset: u32) -> ([u8; 4], Vec<u8>) {
    match v {
        Val::Ascii(s) => {
            let mut bytes = s.as_bytes().to_vec();
            bytes.push(0);
            if bytes.len() <= 4 {
                let mut inline = [0u8; 4];
                inline[..bytes.len()].copy_from_slice(&bytes);
                (inline, Vec::new())
            } else {
                (ext_offset.to_le_bytes(), pad_even(bytes))
            }
        }
        Val::Short(x) => {
            let mut inline = [0u8; 4];
            inline[..2].copy_from_slice(&x.to_le_bytes());
            (inline, Vec::new())
        }
        Val::Long(x) => (x.to_le_bytes(), Vec::new()),
        Val::Byte(x) => ([*x, 0, 0, 0], Vec::new()),
        Val::Rationals(rs) => {
            let mut ext = Vec::new();
            for (n, d) in rs {
                ext.extend_from_slice(&n.to_le_bytes());
                ext.extend_from_slice(&d.to_le_bytes());
            }
            (ext_offset.to_le_bytes(), ext)
        }
    }
}

/// Serialize a full IFD (entries + external data) beginning at absolute `base`.
fn build_ifd(base: u32, entries: &[Entry]) -> Vec<u8> {
    let n = entries.len() as u32;
    let ifd_size = 2 + 12 * n + 4;
    let ext_start = base + ifd_size;

    let mut ext = Vec::new();
    let mut out = Vec::new();
    out.extend_from_slice(&(n as u16).to_le_bytes());
    for e in entries {
        let (value, ext_bytes) = entry_value_bytes(&e.val, ext_start + ext.len() as u32);
        out.extend_from_slice(&e.tag.to_le_bytes());
        out.extend_from_slice(&tiff_type(&e.val).to_le_bytes());
        out.extend_from_slice(&tiff_count(&e.val).to_le_bytes());
        out.extend_from_slice(&value);
        ext.extend_from_slice(&ext_bytes);
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // next IFD: none
    out.extend_from_slice(&ext);
    out
}

fn exif_subifd_entries() -> Vec<Entry> {
    // Ascending tag order.
    vec![
        Entry {
            tag: 0x829A,
            val: Val::Rationals(vec![(1, 60)]),
        }, // ExposureTime
        Entry {
            tag: 0x829D,
            val: Val::Rationals(vec![(4, 1)]),
        }, // FNumber
        Entry {
            tag: 0x8827,
            val: Val::Short(100),
        }, // PhotographicSensitivity
        Entry {
            tag: 0x9003,
            val: Val::Ascii("2021:07:04 15:30:00"),
        }, // DateTimeOriginal
        Entry {
            tag: 0x920A,
            val: Val::Rationals(vec![(50, 1)]),
        }, // FocalLength
        Entry {
            tag: 0xA002,
            val: Val::Short(4000),
        }, // PixelXDimension
        Entry {
            tag: 0xA003,
            val: Val::Short(3000),
        }, // PixelYDimension
        Entry {
            tag: 0xA434,
            val: Val::Ascii("EF50mm f/1.8"),
        }, // LensModel
    ]
}

fn ifd0_entries(exif_ptr: u32, gps_ptr: Option<u32>) -> Vec<Entry> {
    let mut e = vec![
        Entry {
            tag: 0x010F,
            val: Val::Ascii("Canon"),
        }, // Make
        Entry {
            tag: 0x0110,
            val: Val::Ascii("Canon EOS 5D"),
        }, // Model
        Entry {
            tag: 0x0112,
            val: Val::Short(1),
        }, // Orientation
        Entry {
            tag: 0x0131,
            val: Val::Ascii("TestFirmware 1.0"),
        }, // Software
        Entry {
            tag: 0x0132,
            val: Val::Ascii("2021:07:04 15:31:00"),
        }, // DateTime
        Entry {
            tag: 0x8769,
            val: Val::Long(exif_ptr),
        }, // ExifIFDPointer
    ];
    if let Some(g) = gps_ptr {
        e.push(Entry {
            tag: 0x8825,
            val: Val::Long(g),
        }); // GPSInfoIFDPointer
    }
    e
}

fn gps_ifd_entries() -> Vec<Entry> {
    // N 37 48 30 / W 122 25 09 / altitude 100 m above sea level.
    vec![
        Entry {
            tag: 0x0001,
            val: Val::Ascii("N"),
        },
        Entry {
            tag: 0x0002,
            val: Val::Rationals(vec![(37, 1), (48, 1), (30, 1)]),
        },
        Entry {
            tag: 0x0003,
            val: Val::Ascii("W"),
        },
        Entry {
            tag: 0x0004,
            val: Val::Rationals(vec![(122, 1), (25, 1), (9, 1)]),
        },
        Entry {
            tag: 0x0005,
            val: Val::Byte(0),
        },
        Entry {
            tag: 0x0006,
            val: Val::Rationals(vec![(100, 1)]),
        },
    ]
}

/// Build a complete TIFF/EXIF blob (magic `II*\0`), optionally with a GPS IFD.
fn build_tiff(with_gps: bool) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(&[0x49, 0x49, 0x2A, 0x00]); // II, 42
    file.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at offset 8

    // Measure IFD0 length (pointer-independent) to place following IFDs.
    let placeholder = build_ifd(8, &ifd0_entries(0, if with_gps { Some(0) } else { None }));
    let l0 = placeholder.len() as u32;

    let exif_start = 8 + l0;
    let exif_ifd = build_ifd(exif_start, &exif_subifd_entries());
    let le = exif_ifd.len() as u32;

    let (gps_ptr, gps_ifd) = if with_gps {
        let gps_start = exif_start + le;
        (Some(gps_start), build_ifd(gps_start, &gps_ifd_entries()))
    } else {
        (None, Vec::new())
    };

    let ifd0 = build_ifd(8, &ifd0_entries(exif_start, gps_ptr));
    assert_eq!(
        ifd0.len() as u32,
        l0,
        "IFD0 length must be pointer-independent"
    );

    file.extend_from_slice(&ifd0);
    file.extend_from_slice(&exif_ifd);
    file.extend_from_slice(&gps_ifd);
    file
}

/// Wrap a TIFF/EXIF blob in a minimal JPEG (SOI + APP1/Exif + EOI).
fn wrap_jpeg(tiff: &[u8]) -> Vec<u8> {
    let mut out = vec![0xFF, 0xD8, 0xFF, 0xE1]; // SOI + APP1 marker
    let seg_len = (2 + 6 + tiff.len()) as u16;
    out.extend_from_slice(&seg_len.to_be_bytes());
    out.extend_from_slice(b"Exif\0\0");
    out.extend_from_slice(tiff);
    out.extend_from_slice(&[0xFF, 0xD9]); // EOI
    out
}

fn file_entry(bytes: Vec<u8>, name: &str) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({ "name": name }),
    )
}

fn get_f64(a: &Artifact, key: &str) -> Option<f64> {
    a.metadata.get(key).and_then(|v| v.as_f64())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn module_metadata_is_stable() {
    let p = ExifParser::new();
    assert_eq!(p.id(), "plugin.media.exif_parser");
    assert_eq!(p.subscribes_to(), vec![ArtifactType::FileEntry]);
    assert_eq!(p.input_capability(), InputCapability::RandomAccess);
    assert_eq!(p.execution_mode(), ExecutionMode::Automatic);
}

#[test]
fn stripped_jpeg_still_reports_true_dimensions() {
    // A real JPEG with no Exif segment — the image crate writes a plain JFIF,
    // exactly what WhatsApp/Messenger produce after re-encoding on send.
    let img = image::RgbImage::from_pixel(64, 48, image::Rgb([120, 130, 140]));
    let mut bytes: Vec<u8> = Vec::new();
    image::DynamicImage::ImageRgb8(img)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Jpeg,
        )
        .unwrap();

    let artifact = file_entry(bytes, "00000003-PHOTO-2019-01-15-20-57-37.jpg");
    let out = ExifParser::new().process(&artifact).unwrap();

    assert_eq!(
        out.len(),
        1,
        "a metadata-stripped image should still yield a dimensions record"
    );
    let rec = &out[0].metadata;
    assert_eq!(rec["type"], "exif");
    assert_eq!(rec["has_exif"], false);
    assert_eq!(rec["width"].as_u64(), Some(64));
    assert_eq!(rec["height"].as_u64(), Some(48));
    assert_eq!(rec["actual_width"].as_u64(), Some(64));
    assert!(rec["metadata_status"]
        .as_str()
        .unwrap_or("")
        .contains("No EXIF"));
}

#[test]
fn gps_tagged_jpeg_yields_signed_coordinates() {
    let jpeg = wrap_jpeg(&build_tiff(true));
    let artifact = file_entry(jpeg, "IMG_0001.jpg");
    let out = ExifParser::new().process(&artifact).unwrap();

    assert_eq!(out.len(), 1);
    let rec = &out[0];
    assert_eq!(rec.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(rec.parent_id, Some(artifact.id));
    assert_eq!(
        rec.metadata.get("type").and_then(|v| v.as_str()),
        Some("exif")
    );
    assert_eq!(
        rec.metadata.get("source_name").and_then(|v| v.as_str()),
        Some("IMG_0001.jpg")
    );
    assert_eq!(
        rec.metadata.get("has_gps").and_then(|v| v.as_bool()),
        Some(true)
    );

    let lat = get_f64(rec, "gps_lat").expect("gps_lat present");
    let lon = get_f64(rec, "gps_lon").expect("gps_lon present");
    // N 37 48 30 => +37.8083 ; W 122 25 09 => -122.4192
    assert!((lat - 37.808333).abs() < 0.001, "lat was {}", lat);
    assert!(lat > 0.0, "N latitude must be positive");
    assert!((lon - (-122.419167)).abs() < 0.001, "lon was {}", lon);
    assert!(lon < 0.0, "W longitude must be negative");

    assert_eq!(get_f64(rec, "gps_altitude"), Some(100.0));
    assert_eq!(
        rec.metadata.get("camera").and_then(|v| v.as_str()),
        Some("Canon Canon EOS 5D")
    );
    assert_eq!(
        rec.metadata
            .get("datetime_original")
            .and_then(|v| v.as_str()),
        Some("2021:07:04 15:30:00")
    );
}

#[test]
fn gps_tagged_raw_tiff_is_parsed() {
    // Exercises the TIFF magic path (II*\0) directly, no JPEG wrapper.
    let artifact = file_entry(build_tiff(true), "scan.tiff");
    let out = ExifParser::new().process(&artifact).unwrap();
    assert_eq!(out.len(), 1);
    let rec = &out[0];
    assert_eq!(
        rec.metadata.get("has_gps").and_then(|v| v.as_bool()),
        Some(true)
    );
    let lat = get_f64(rec, "gps_lat").unwrap();
    let lon = get_f64(rec, "gps_lon").unwrap();
    assert!(lat > 0.0 && lon < 0.0);
    assert!((lat - 37.808333).abs() < 0.001);
}

#[test]
fn non_gps_image_has_no_gps_keys() {
    let jpeg = wrap_jpeg(&build_tiff(false));
    let artifact = file_entry(jpeg, "no_gps.jpg");
    let out = ExifParser::new().process(&artifact).unwrap();

    assert_eq!(out.len(), 1);
    let rec = &out[0];
    assert_eq!(
        rec.metadata.get("has_gps").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert!(rec.metadata.get("gps_lat").is_none());
    assert!(rec.metadata.get("gps_lon").is_none());
    assert!(rec.metadata.get("gps_altitude").is_none());
    assert!(rec.metadata.get("gps_datetime").is_none());

    // Non-GPS metadata still extracted.
    assert_eq!(
        rec.metadata.get("width").and_then(|v| v.as_u64()),
        Some(4000)
    );
    assert_eq!(
        rec.metadata.get("height").and_then(|v| v.as_u64()),
        Some(3000)
    );
    assert_eq!(rec.metadata.get("iso").and_then(|v| v.as_u64()), Some(100));
    assert_eq!(
        rec.metadata.get("camera").and_then(|v| v.as_str()),
        Some("Canon Canon EOS 5D")
    );
    assert_eq!(
        rec.metadata
            .get("datetime_original")
            .and_then(|v| v.as_str()),
        Some("2021:07:04 15:30:00")
    );
    assert_eq!(
        rec.metadata.get("lens").and_then(|v| v.as_str()),
        Some("EF50mm f/1.8")
    );
}

#[test]
fn garbage_non_image_yields_nothing() {
    let artifact = file_entry(vec![0x00, 0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF], "random.bin");
    let out = ExifParser::new().process(&artifact).unwrap();
    assert!(out.is_empty());
}

#[test]
fn jpeg_magic_but_corrupt_body_does_not_panic() {
    // Valid JPEG magic, a broken marker chain: must not panic, and must say the
    // EXIF could not be read rather than go quiet (HUNT-200) — whether a
    // segment was there is unknown, so nothing claims it was absent.
    let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xE0];
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]);
    let artifact = file_entry(bytes, "corrupt.jpg");
    let out = ExifParser::new().process(&artifact).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["exif_status"], "exif_unreadable");
    assert!(out[0].metadata.get("has_exif").is_none());
    assert!(out[0].metadata.get("width").is_none());
}

#[test]
fn truncated_exif_jpeg_does_not_panic() {
    // Take a valid GPS JPEG and truncate it mid-EXIF.
    let full = wrap_jpeg(&build_tiff(true));
    let truncated = full[..full.len() / 2].to_vec();
    let artifact = file_entry(truncated, "trunc.jpg");
    // Whatever the outcome, it must be Ok and never panic.
    let out = ExifParser::new().process(&artifact).unwrap();
    let _ = out;
}

#[test]
fn png_signature_over_a_broken_body_is_unreadable_not_silent() {
    // A PNG signature followed by zeros is not a PNG without EXIF: its chunks
    // could not be walked, so the EXIF question is unanswered (HUNT-200).
    let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend_from_slice(&[0x00; 32]);
    let artifact = file_entry(bytes, "plain.png");
    let out = ExifParser::new().process(&artifact).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["exif_status"], "exif_unreadable");
    assert_eq!(out[0].metadata["content_incomplete"], true);
}

#[test]
fn a_real_png_without_exif_is_reported_not_present() {
    let img = image::RgbImage::from_pixel(5, 3, image::Rgb([9, 9, 9]));
    let mut bytes: Vec<u8> = Vec::new();
    image::DynamicImage::ImageRgb8(img)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
    let out = ExifParser::new()
        .process(&file_entry(bytes, "plain.png"))
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["exif_status"], "not_present");
    assert_eq!(out[0].metadata["width"].as_u64(), Some(5));
}

#[test]
fn directory_is_skipped() {
    let data: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(wrap_jpeg(&build_tiff(true))));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({ "name": "dir", "is_directory": true }),
    );
    let out = ExifParser::new().process(&artifact).unwrap();
    assert!(out.is_empty());
}

#[test]
fn missing_data_source_is_skipped() {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": "ghost.jpg" }),
    );
    let out = ExifParser::new().process(&artifact).unwrap();
    assert!(out.is_empty());
}

/// A windowed source returning a few bytes per call must still pass the magic
/// gate. A single-shot probe saw a 4-byte "header", failed `is_supported_image`
/// and dropped a real photograph as a non-image (B2-053).
#[test]
fn a_chunked_source_still_passes_the_image_magic_gate() {
    #[derive(Debug)]
    struct FourBytesPerCall(Vec<u8>);
    impl DataSource for FourBytesPerCall {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = offset as usize;
            if off >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - off).min(4);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
    }

    let jpeg = wrap_jpeg(&build_tiff(true));
    let ds: Arc<dyn DataSource> = Arc::new(FourBytesPerCall(jpeg));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "chunked.jpg" }),
    );
    let out = ExifParser::new().process(&artifact).unwrap();
    assert!(
        !out.is_empty(),
        "a chunked source must not be mis-rejected as a non-image"
    );
}

// ---------------------------------------------------------------------------
// HUNT-200: where a dimension came from, and a damaged APP1 is not "no EXIF"
// ---------------------------------------------------------------------------

/// Written by Pillow 12.1.1 (`Image.save(..., exif=...)`): a 64x48 JPEG whose
/// APP1 holds Make, Model, DateTimeOriginal and PixelX/YDimension 64x48.
const PILLOW_EXIF_JPG: &[u8] = include_bytes!("../tests/fixtures/pillow_exif.jpg");
/// The same file with the two TIFF byte-order bytes inside its APP1 overwritten
/// with `XX`: the Exif segment is there and its header is not a TIFF header.
const DAMAGED_APP1_JPG: &[u8] = include_bytes!("../tests/fixtures/damaged_app1.jpg");

/// Red before the fix: a damaged Exif segment went to the stripped-image
/// record, which asserts "No EXIF metadata present (stripped in transport or
/// never written)" — the absence of the very thing that is present and broken.
#[test]
fn a_damaged_app1_is_reported_unreadable_not_absent() {
    let out = ExifParser::new()
        .process(&file_entry(DAMAGED_APP1_JPG.to_vec(), "IMG_0001.JPG"))
        .unwrap();
    assert_eq!(out.len(), 1, "one record for the image");
    let rec = &out[0].metadata;
    let status = rec["metadata_status"].as_str().unwrap_or("");
    assert!(
        !status.contains("No EXIF"),
        "a damaged segment must not be reported as absent: {rec}"
    );
    assert_eq!(rec["exif_status"], "exif_unreadable", "{rec}");
    assert!(
        rec["exif_error"].as_str().is_some_and(|e| !e.is_empty()),
        "the reader's error travels with the record: {rec}"
    );
    assert_eq!(rec["content_incomplete"], true);
    assert!(rec.get("has_exif").is_none() || rec["has_exif"] != false);
    // The pixels still decode, and say so.
    assert_eq!(rec["width"].as_u64(), Some(64));
    assert_eq!(rec["dimensions_source"], "decoded");
}

/// The undamaged original reads, and its dimensions are the decoded ones.
#[test]
fn a_real_exif_jpeg_reads_with_decoded_dimensions() {
    let out = ExifParser::new()
        .process(&file_entry(PILLOW_EXIF_JPG.to_vec(), "IMG_0001.JPG"))
        .unwrap();
    assert_eq!(out.len(), 1);
    let rec = &out[0].metadata;
    assert_eq!(rec["make"], "Canon");
    assert_eq!(rec["exif_status"], "read");
    assert_eq!(rec["dimensions_source"], "decoded");
    assert_eq!(rec["dimensions_mismatch"], false);
}

/// Red before the fix: where the bitstream cannot be decoded (a TIFF here;
/// HEIC in the field), `width`/`height` were the EXIF-declared values with no
/// key saying so, though the code comment claimed they were marked.
#[test]
fn fallback_dimensions_are_marked_as_declared() {
    let out = ExifParser::new()
        .process(&file_entry(build_tiff(false), "scan.tiff"))
        .unwrap();
    let rec = &out[0].metadata;
    assert_eq!(rec["width"].as_u64(), Some(4000));
    assert_eq!(rec["dimensions_source"], "exif_declared", "{rec}");
    assert!(rec.get("actual_width").is_none());
}

/// The stripped-image record's dimensions are decoded, and it says so.
#[test]
fn stripped_image_dimensions_are_marked_decoded() {
    let img = image::RgbImage::from_pixel(8, 8, image::Rgb([1, 2, 3]));
    let mut bytes: Vec<u8> = Vec::new();
    image::DynamicImage::ImageRgb8(img)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Jpeg,
        )
        .unwrap();
    let out = ExifParser::new()
        .process(&file_entry(bytes, "plain.jpg"))
        .unwrap();
    assert_eq!(out[0].metadata["dimensions_source"], "decoded");
    assert_eq!(out[0].metadata["exif_status"], "not_present");
}
