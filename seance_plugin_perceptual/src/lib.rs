#![forbid(unsafe_code)]
//! Perceptual hashing (PDQ) over decodable images.
//!
//! Exact cryptographic hashes miss a re-encoded, resized or lightly-cropped copy
//! of a known image — which is exactly the material a triage unit needs
//! surfaced. This module decodes each image, computes an open **PDQ** perceptual
//! hash ([`seance_vics::PdqHash`]), and emits it as a record. Two images a small
//! Hamming distance apart are near-duplicates; a hash can also be compared
//! against an externally-supplied PDQ set (e.g. from VICS) at query time.
//!
//! The hash is graded *Scanned*: a perceptual match is a lead for human review,
//! never an identification. That discipline is fixed in [`seance_vics`].
//!
//! # Honesty
//!
//! Séance's PDQ is not bit-compatible with Meta's reference implementation and
//! has never been run against its reference vectors, so every record that
//! carries a hash also carries [`seance_vics::PDQ_VARIANT`] and the interop
//! caveat, stamped through [`seance_vics::stamp_pdq_interop`]. A record labelled
//! only `"pdq"` would read as reference output, and an examiner comparing it
//! against an externally-supplied PDQ set would take a non-match at face value
//! when it may be nothing but two different filters (REC-017).
//!
//! Once the magic sniff has settled that a file *is* an image, every exit leaves
//! a record. An image that is too large, truncated, unreadable or undecodable is
//! emitted with `hash_skipped: "<reason>"`, the standard incompleteness pair and
//! no hashes — never as silence, which an examiner would read as "this picture
//! was hashed and has no near-duplicates", and never as hashes over partial
//! pixels, which fail to match a complete copy of the same picture.

use image::GenericImageView;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_vics::{stamp_pdq_interop, AHash, DHash, PHash, PdqHash};
use serde_json::json;
use tracing::debug;

/// Largest image this module will decode into memory.
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

pub struct PerceptualHasher;

/// A record for an image that was detected but not hashed.
///
/// Emitting nothing is indistinguishable from "that file was not an image", so
/// an unhashed picture would silently leave near-duplicate matching with a hole
/// no surface reports (REC-003/REC-014). The record names why in `hash_skipped`,
/// mirroring the file hasher's convention, carries no hashes at all, and stamps
/// the standard incompleteness pair so the product's existing honesty surfaces
/// show the gap.
fn skipped(
    artifact: &Artifact,
    reason: &str,
    incomplete: IncompleteReason,
    size: u64,
    detail: Option<String>,
) -> Artifact {
    let mut meta = json!({
        "type": "PerceptualHash",
        "hash_skipped": reason,
        "size": size,
        CONTENT_INCOMPLETE: true,
        CONTENT_INCOMPLETE_REASON: incomplete.as_str(),
        "note": "An image was detected here but no perceptual hash could be \
                 computed, so near-duplicate and PDQ-set matching do not cover \
                 this file. `hash_skipped` names why.",
    });
    if let Some(detail) = detail {
        meta["hash_skipped_detail"] = json!(detail);
    }
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta).with_parent(artifact.id)
}

/// Does this look like an image this module can decode? Content sniff on the
/// leading magic bytes, never the filename.
fn looks_like_image(head: &[u8]) -> bool {
    head.starts_with(&[0xFF, 0xD8, 0xFF]) // JPEG
        || head.starts_with(b"\x89PNG\r\n\x1a\n") // PNG
        || head.starts_with(b"GIF87a")
        || head.starts_with(b"GIF89a")
        || head.starts_with(b"BM") // BMP
        || (head.len() >= 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WEBP")
}

impl ForensicsModule for PerceptualHasher {
    fn id(&self) -> &str {
        "plugin.media.perceptual_hash"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let size = data.size();
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut head = [0u8; 16];
        let n = data.read_at(0, &mut head).unwrap_or(0);
        if n < 12 || !looks_like_image(&head[..n]) {
            return Ok(Vec::new());
        }
        // Past the sniff this file IS an image, so every remaining exit leaves a
        // record: from here, silence would say "no image here" rather than
        // "an image nothing was matched against" (REC-014).
        if size > MAX_IMAGE_BYTES {
            let record = skipped(artifact, "size", IncompleteReason::CapReached, size, None);
            return Ok(vec![record]);
        }
        // Pull the bytes and decode.
        let mut bytes = vec![0u8; size as usize];
        let mut got = 0usize;
        let mut read_error: Option<String> = None;
        while got < bytes.len() {
            match data.read_at(got as u64, &mut bytes[got..]) {
                Ok(0) => break,
                Ok(k) => got += k,
                Err(e) => {
                    read_error = Some(e.to_string());
                    break;
                }
            }
        }

        // A perceptual hash of a prefix is not the picture's hash: it fails to
        // match a complete copy of the same image, and re-hashing the same
        // truncated view would "confirm" it. Withhold every digest and say how
        // far the read got, as the file hasher does for content hashes
        // (REC-003 / BUG-158).
        if got < bytes.len() {
            debug!(
                "perceptual: {got} of {size} bytes readable ({}); hashes withheld",
                read_error.as_deref().unwrap_or("short read")
            );
            let reason = if read_error.is_some() {
                "io_error"
            } else {
                "short_read"
            };
            let mut record = skipped(
                artifact,
                reason,
                IncompleteReason::ShortRead,
                size,
                read_error,
            );
            record.metadata["bytes_read"] = json!(got);
            return Ok(vec![record]);
        }

        let img = match image::load_from_memory(&bytes) {
            Ok(i) => i,
            Err(e) => {
                debug!("perceptual: undecodable image: {e}");
                let record = skipped(
                    artifact,
                    "undecodable",
                    IncompleteReason::UnresolvedStructure,
                    size,
                    Some(e.to_string()),
                );
                return Ok(vec![record]);
            }
        };
        let (w, h) = img.dimensions();
        if w == 0 || h == 0 {
            let record = skipped(
                artifact,
                "zero_dimensions",
                IncompleteReason::UnresolvedStructure,
                size,
                None,
            );
            return Ok(vec![record]);
        }
        let luma = img.to_luma8();
        let (lw, lh) = (w as usize, h as usize);
        let raw = luma.as_raw();
        let Some(hash) = PdqHash::from_luminance(lw, lh, raw) else {
            let record = skipped(
                artifact,
                "pdq_unavailable",
                IncompleteReason::UnresolvedStructure,
                size,
                None,
            );
            return Ok(vec![record]);
        };
        // Classic 64-bit companions to PDQ, for cross-tool interoperability: a
        // hash set published as aHash/dHash/pHash can only be matched if Séance
        // computes the same kind. Best-effort — an image PDQ could hash always
        // hashes here too, but guard anyway.
        let ahash = AHash::from_luminance(lw, lh, raw);
        let dhash = DHash::from_luminance(lw, lh, raw);
        let phash = PHash::from_luminance(lw, lh, raw);

        // `algorithm` names the family so a consumer can select PDQ records;
        // `pdq_variant`, stamped below, names the pipeline that actually
        // computed this hash. Both are needed: the family alone claims interop
        // with every other tool's PDQ, which this one has not earned.
        let mut meta = json!({
            "type": "PerceptualHash",
            "subtype": "pdq",
            "algorithm": "pdq",
            "pdq_hex": hash.to_hex(),
            "width": w,
            "height": h,
            "evidence_grade": "scanned",
            "note": "Open perceptual hashes. A small Hamming distance to another hash of \
                     the same kind indicates a near-duplicate — a lead for review, not an \
                     identification. PDQ (256-bit) is the primary; aHash/dHash/pHash \
                     (64-bit) are for cross-tool matching.",
        });
        let obj = meta
            .as_object_mut()
            .expect("the metadata above is an object literal");
        if let Some(a) = ahash {
            obj.insert("ahash_hex".into(), json!(a.to_hex()));
        }
        if let Some(d) = dhash {
            obj.insert("dhash_hex".into(), json!(d.to_hex()));
        }
        if let Some(p) = phash {
            obj.insert("phash_hex".into(), json!(p.to_hex()));
        }
        // Stamped last, so nothing above can weaken the caveat. This is the only
        // record this module emits with a hash on it, and it does not leave here
        // without saying which PDQ produced it.
        stamp_pdq_interop(obj);

        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            meta,
        )
        .with_parent(artifact.id)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource, RunListDataSource};
    use std::sync::Arc;
    use uuid::Uuid;

    /// Encode a grayscale gradient-ish "photo" as PNG.
    fn png(width: u32, height: u32) -> Vec<u8> {
        use std::f32::consts::PI;
        let mut buf = image::GrayImage::new(width, height);
        for (x, y, px) in buf.enumerate_pixels_mut() {
            let uu = (x as f32 + 0.5) / width as f32;
            let vv = (y as f32 + 0.5) / height as f32;
            let mut v = 128.0;
            v += 55.0 * (2.0 * PI * 3.0 * uu).sin();
            v += 45.0 * (2.0 * PI * 2.0 * vv).cos();
            v += 35.0 * (2.0 * PI * 5.0 * (uu + vv)).sin();
            // A localized high-contrast blob so the DCT coefficients spread well
            // away from their median — a perceptual hash is legitimately unstable
            // on a near-flat image, so the fixture must have real structure.
            let (du, dv) = (uu - 0.7, vv - 0.35);
            v += 70.0 * (-(du * du + dv * dv) * 40.0).exp();
            *px = image::Luma([v.clamp(0.0, 255.0) as u8]);
        }
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageLuma8(buf)
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    fn artifact(bytes: Vec<u8>) -> Artifact {
        artifact_over(Arc::new(ByteSliceDataSource::new(bytes)))
    }

    fn artifact_over(src: Arc<dyn DataSource>) -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": "img.png" }),
        )
    }

    /// A source that serves its bytes up to `fail_from` and then errors — a bad
    /// sector or a dropped network share partway through a picture.
    #[derive(Debug)]
    struct FailsAfter {
        bytes: Vec<u8>,
        fail_from: usize,
    }

    impl DataSource for FailsAfter {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = offset as usize;
            if off >= self.fail_from {
                return Err(std::io::Error::other("simulated bad sector"));
            }
            let n = buf.len().min(self.fail_from - off);
            buf[..n].copy_from_slice(&self.bytes[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }
    }

    /// The record must name why nothing was hashed and carry no hash of any
    /// kind: a partial-content hash is worse than none, because it looks like
    /// the picture's hash and quietly fails to match a complete copy.
    fn assert_skipped(record: &Artifact, reason: &str, incomplete: IncompleteReason) {
        let m = &record.metadata;
        assert_eq!(m["type"], "PerceptualHash");
        assert_eq!(m["hash_skipped"], reason);
        assert_eq!(m[CONTENT_INCOMPLETE], json!(true));
        assert_eq!(m[CONTENT_INCOMPLETE_REASON], incomplete.as_str());
        for key in ["pdq_hex", "ahash_hex", "dhash_hex", "phash_hex"] {
            assert!(m.get(key).is_none(), "skipped record must carry no {key}");
        }
    }

    #[test]
    fn emits_a_pdq_hash_for_a_png() {
        let out = PerceptualHasher.process(&artifact(png(200, 200))).unwrap();
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["type"], "PerceptualHash");
        assert_eq!(m["algorithm"], "pdq");
        assert_eq!(m["evidence_grade"], "scanned");
        assert_eq!(m["pdq_hex"].as_str().unwrap().len(), 64);
    }

    /// A record labelled only `"pdq"` reads as Meta's reference output. Séance's
    /// PDQ is a simplified pipeline that has never been run against the
    /// reference vectors, so an examiner comparing this hash against an
    /// externally-supplied PDQ set would read a non-match as a non-match when it
    /// may be nothing but two different filters. The pipeline and the caveat
    /// travel on the record, not in a module comment (REC-017).
    #[test]
    fn an_emitted_hash_names_the_pdq_pipeline_that_computed_it() {
        let out = PerceptualHasher.process(&artifact(png(200, 200))).unwrap();
        let m = &out[0].metadata;
        assert_eq!(m["pdq_variant"], json!(seance_vics::PDQ_VARIANT));
        assert_ne!(
            m["pdq_variant"],
            json!("pdq"),
            "the bare family name claims reference-faithful interop"
        );
        assert_eq!(
            m["pdq_reference_validated"],
            json!(false),
            "no run against Meta's reference vectors has happened"
        );
        assert_eq!(m["pdq_interop_note"], json!(seance_vics::PDQ_INTEROP_NOTE));
        // The family name stays alongside it, so PDQ records remain selectable.
        assert_eq!(m["algorithm"], "pdq");
    }

    #[test]
    fn a_resized_copy_is_a_near_duplicate() {
        // Same picture at two resolutions must hash within the PDQ threshold.
        let a = PerceptualHasher.process(&artifact(png(256, 256))).unwrap();
        let b = PerceptualHasher.process(&artifact(png(128, 128))).unwrap();
        let ha = PdqHash::from_hex(a[0].metadata["pdq_hex"].as_str().unwrap()).unwrap();
        let hb = PdqHash::from_hex(b[0].metadata["pdq_hex"].as_str().unwrap()).unwrap();
        assert!(
            ha.is_near(&hb, 31),
            "resized copy should be near; distance {}",
            ha.distance(&hb)
        );
    }

    #[test]
    fn emits_the_classic_companion_hashes_too() {
        let out = PerceptualHasher.process(&artifact(png(200, 200))).unwrap();
        let m = &out[0].metadata;
        // Each 64-bit hash is 16 hex chars.
        assert_eq!(m["ahash_hex"].as_str().unwrap().len(), 16);
        assert_eq!(m["dhash_hex"].as_str().unwrap().len(), 16);
        assert_eq!(m["phash_hex"].as_str().unwrap().len(), 16);
    }

    #[test]
    fn companion_hashes_also_match_a_resized_copy() {
        let a = PerceptualHasher.process(&artifact(png(256, 256))).unwrap();
        let b = PerceptualHasher.process(&artifact(png(128, 128))).unwrap();
        let da = DHash::from_hex(a[0].metadata["dhash_hex"].as_str().unwrap()).unwrap();
        let db = DHash::from_hex(b[0].metadata["dhash_hex"].as_str().unwrap()).unwrap();
        // dHash of the same picture at half resolution stays close.
        assert!(
            da.is_near(&db, 10),
            "resized copy should be near under dHash; distance {}",
            da.distance(&db)
        );
    }

    #[test]
    fn ignores_non_images() {
        let out = PerceptualHasher
            .process(&artifact(
                b"this is not an image at all, just text".to_vec(),
            ))
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ignores_an_artifact_with_no_data() {
        let art = Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, None, json!({}));
        assert!(PerceptualHasher.process(&art).unwrap().is_empty());
    }

    /// A truncated picture still decodes (the JPEG/PNG decoders render what they
    /// have), so hashing it would publish digests of partial pixels as ordinary
    /// perceptual hashes — they would miss a complete copy of the same image and
    /// a re-hash of the same truncated view would agree with them (REC-003).
    #[test]
    fn truncated_image_is_recorded_as_short_read_instead_of_hashed() {
        let full = png(200, 200);
        let prefix = full.len() / 2;
        // Declared size is the whole picture; the backing only holds a prefix —
        // exactly a file whose tail is unallocated or unreadable.
        let inner: Arc<dyn DataSource> =
            Arc::new(ByteSliceDataSource::new(full[..prefix].to_vec()));
        let src: Arc<dyn DataSource> = Arc::new(RunListDataSource::from_allocation(
            inner,
            vec![(Some(0), full.len() as u64)],
        ));
        assert_eq!(src.size(), full.len() as u64);

        let out = PerceptualHasher.process(&artifact_over(src)).unwrap();
        assert_eq!(out.len(), 1, "a detected image must never vanish");
        assert_skipped(&out[0], "short_read", IncompleteReason::ShortRead);
        assert_eq!(out[0].metadata["size"], json!(full.len()));
        assert_eq!(out[0].metadata["bytes_read"], json!(prefix));
    }

    /// An I/O error mid-picture is not "no image here": it must be reported, and
    /// distinguished from a source that simply ended early.
    #[test]
    fn read_error_mid_image_is_recorded_not_dropped() {
        let full = png(200, 200);
        let fail_from = full.len() / 2;
        let src: Arc<dyn DataSource> = Arc::new(FailsAfter {
            bytes: full.clone(),
            fail_from,
        });

        let out = PerceptualHasher.process(&artifact_over(src)).unwrap();
        assert_eq!(out.len(), 1);
        assert_skipped(&out[0], "io_error", IncompleteReason::ShortRead);
        assert_eq!(out[0].metadata["bytes_read"], json!(fail_from));
        let detail = out[0].metadata["hash_skipped_detail"].as_str().unwrap();
        assert!(
            detail.contains("simulated bad sector"),
            "the I/O error must reach the record"
        );
    }

    /// Over the size cap the module hashes nothing; without a record the case
    /// cannot tell an unhashed picture from a file that was never an image, and
    /// an examiner reads "no near-duplicates" (REC-014).
    #[test]
    fn oversize_image_is_recorded_as_skipped_not_dropped() {
        let head = png(64, 64);
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(head.clone()));
        // Sparse tail: declares a size past the cap without allocating it.
        let tail = MAX_IMAGE_BYTES + 1 - head.len() as u64;
        let src: Arc<dyn DataSource> = Arc::new(RunListDataSource::from_allocation(
            inner,
            vec![(Some(0), head.len() as u64), (None, tail)],
        ));
        assert!(src.size() > MAX_IMAGE_BYTES);

        let out = PerceptualHasher.process(&artifact_over(src)).unwrap();
        assert_eq!(out.len(), 1);
        assert_skipped(&out[0], "size", IncompleteReason::CapReached);
        assert_eq!(out[0].metadata["size"], json!(MAX_IMAGE_BYTES + 1));
    }

    /// A file with an image header that will not decode is a corrupt picture,
    /// not a non-image: the module must say it could not hash it.
    #[test]
    fn undecodable_image_is_recorded_as_skipped() {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend_from_slice(&[0x00; 64]);

        let out = PerceptualHasher.process(&artifact(bytes)).unwrap();
        assert_eq!(out.len(), 1);
        assert_skipped(
            &out[0],
            "undecodable",
            IncompleteReason::UnresolvedStructure,
        );
    }
}
