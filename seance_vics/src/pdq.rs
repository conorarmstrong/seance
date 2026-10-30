//! PDQ — an open 256-bit perceptual image hash.
//!
//! PDQ (Meta, BSD-licensed algorithm) hashes an image into 256 bits such that
//! visually similar images — re-encoded, resized, lightly cropped or
//! recompressed — produce hashes a small Hamming distance apart, while unrelated
//! images are far apart. That is exactly what exact cryptographic hashing cannot
//! do and what a triage unit needs to catch derivatives of known material.
//!
//! # Input
//!
//! This crate does not decode images (JPEG/PNG decode belongs to the caller, who
//! already has a decoder in the thumbnail pipeline). The entry point takes a
//! **8-bit luminance buffer** of arbitrary dimensions. The caller converts RGB
//! to luminance with the standard Rec.601 weights.
//!
//! # Pipeline
//!
//! 1. Area-average downsample the luminance to 64×64.
//! 2. Apply a 16×16 DCT-II (skipping the DC term, per PDQ) to the 64×64 block.
//! 3. Threshold each of the 256 coefficients against their median → 256 bits.
//!
//! # Verification status — read this before trusting cross-tool matches
//!
//! The property tests below prove the behaviours matching depends on: an image
//! hashes to distance 0 with itself, a small perturbation stays close, an
//! inverted/unrelated image is far, and the hash is invariant to the encode of
//! the *same* pixels. That is sufficient for **near-duplicate detection within a
//! case** (comparing hashes Séance computed).
//!
//! **Bit-exact interoperability with externally-supplied PDQ hash sets is NOT
//! yet asserted here** — that requires validation against Meta's official
//! reference vectors, which is tracked as follow-up. Until then, a match against
//! an external PDQ hash is reported at the [`crate::MatchGrade::Scanned`] grade
//! with that caveat, never as authoritative. This is a documented limitation,
//! not a silent one — the same discipline the rest of the tree applies.
//!
//! Where this pipeline knowingly departs from Meta's reference implementation:
//!
//! * **Downsample**: a plain area average straight to 64×64. The reference
//!   pre-filters with a Jarosz box blur and then decimates.
//! * **Median rule**: the mean of the two central order statistics of the 256
//!   coefficients. The reference uses a Torben median (an actual element).
//! * **Bit packing**: coefficient `i` sets bit `i % 8` of byte `i / 8`, and
//!   [`PdqHash::to_hex`] serialises those bytes in order. The reference's hex
//!   form follows its own word layout.
//!
//! The DCT stage itself is the reference's matrix with the DC row skipped, so
//! the divergence is in the filtering, the threshold rule and the serialisation,
//! not in the transform. Because a hash labelled only `"pdq"` reads as the
//! reference's output, everything that emits one stamps [`PDQ_VARIANT`] and
//! [`PDQ_INTEROP_NOTE`] beside it — through [`stamp_pdq_interop`], so the field
//! names cannot drift between the surfaces an examiner reads.

/// Identifier for the exact pipeline that produced a hash from this crate.
///
/// An examiner comparing a Séance hash against an externally-supplied PDQ set
/// has to be able to see, from the record itself, which pipeline computed it —
/// the difference decides whether a non-match is a non-match or an artefact of
/// two different filters. Bump the suffix if the pipeline ever changes: an
/// unbumped label would make hashes from before and after look comparable.
pub const PDQ_VARIANT: &str = "pdq-seance-v1";

/// The interop caveat that travels with an emitted hash, in the words an
/// examiner reads. It lives next to the algorithm so it cannot drift from the
/// code that earns it.
pub const PDQ_INTEROP_NOTE: &str =
    "Computed by Séance's PDQ pipeline (pdq-seance-v1), which has not been validated against \
     Meta's official PDQ reference vectors: it area-averages where the reference applies a \
     box-filter pre-pass, and differs in the median rule and the bit packing. Distances between \
     hashes Séance computed are sound; a comparison against an externally-supplied PDQ set is a \
     lead to verify, never an identification.";

/// The provenance fields every emitted PDQ hash carries.
///
/// Merged into the artifact metadata by whatever writes the hash, so the variant
/// and the caveat are part of the record rather than tribal knowledge.
pub fn pdq_interop_stamp() -> serde_json::Value {
    serde_json::json!({
        "pdq_variant": PDQ_VARIANT,
        "pdq_reference_validated": false,
        "pdq_interop_note": PDQ_INTEROP_NOTE,
    })
}

/// Stamp [`pdq_interop_stamp`] onto a record body that carries a PDQ hash.
///
/// Every emitter goes through here rather than writing the three keys itself:
/// an emitter that spelled `pdq_variant` differently, or that shipped a hash
/// with no variant at all, would put a bare `"pdq"` in front of an examiner —
/// who would then be entitled to read it as Meta's reference output and compare
/// it against a reference PDQ set (REC-017).
///
/// Overwrites rather than merges: a caller that had somehow set one of these
/// keys itself must not be able to weaken the caveat.
pub fn stamp_pdq_interop(object: &mut serde_json::Map<String, serde_json::Value>) {
    for (key, value) in pdq_interop_stamp()
        .as_object()
        .expect("pdq_interop_stamp is an object literal")
    {
        object.insert(key.clone(), value.clone());
    }
}

/// Rec.601 luminance of an interleaved RGB(A) buffer. `channels` is 3 (RGB) or 4
/// (RGBA); alpha is ignored. Integer arithmetic, so it is deterministic. This is
/// the single conversion **every** perceptual hash in this crate keys on — PDQ
/// and the aHash/dHash/pHash companions — so they all hash the same pixels; do
/// not reimplement it.
pub(crate) fn rgb_to_luminance(
    width: usize,
    height: usize,
    pixels: &[u8],
    channels: usize,
) -> Option<Vec<u8>> {
    if !(channels == 3 || channels == 4) || pixels.len() != width * height * channels {
        return None;
    }
    let mut lum = vec![0u8; width * height];
    for (i, px) in pixels.chunks_exact(channels).enumerate() {
        let y = (77 * px[0] as u32 + 150 * px[1] as u32 + 29 * px[2] as u32) >> 8;
        lum[i] = y as u8;
    }
    Some(lum)
}

/// A 256-bit PDQ hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PdqHash(pub [u8; 32]);

/// Side length of the downsampled buffer the DCT runs on.
const DOWN: usize = 64;
/// Side length of the DCT output block (256 coefficients → 256 bits).
const OUT: usize = 16;

impl PdqHash {
    /// Compute the PDQ hash of an 8-bit luminance image.
    ///
    /// `lum` is row-major, `width * height` bytes. Returns `None` if the buffer
    /// length does not match the dimensions or the image is empty.
    pub fn from_luminance(width: usize, height: usize, lum: &[u8]) -> Option<Self> {
        if width == 0 || height == 0 || lum.len() != width * height {
            return None;
        }
        let down = downsample_to(width, height, lum);
        let dct = dct16(&down);
        Some(Self(threshold_median(&dct)))
    }

    /// Convert an interleaved RGB(A) buffer to luminance and hash it.
    ///
    /// `channels` is 3 (RGB) or 4 (RGBA); alpha is ignored. Rec.601 weights.
    pub fn from_rgb(width: usize, height: usize, pixels: &[u8], channels: usize) -> Option<Self> {
        let lum = rgb_to_luminance(width, height, pixels, channels)?;
        Self::from_luminance(width, height, &lum)
    }

    /// Hamming distance to another hash, in bits (0..=256).
    pub fn distance(&self, other: &PdqHash) -> u32 {
        self.0
            .iter()
            .zip(other.0.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum()
    }

    /// Whether two hashes are within `threshold` bits. Meta's guidance treats
    /// ~31/256 as a conservative "same image" cut-off; the caller chooses.
    pub fn is_near(&self, other: &PdqHash, threshold: u32) -> bool {
        self.distance(other) <= threshold
    }

    /// Lower-case hex, 64 chars — the form used in VICS/JSON and reports.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-char hex string back into a hash.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        Some(Self(bytes.try_into().ok()?))
    }
}

/// Area-average downsample of a luminance image to `DOWN`×`DOWN` floats.
///
/// Each output cell averages the source pixels whose centres fall in its region.
/// Averaging (rather than nearest-neighbour) is what makes the hash stable
/// across resolution changes of the same picture.
fn downsample_to(width: usize, height: usize, lum: &[u8]) -> [f32; DOWN * DOWN] {
    let mut out = [0f32; DOWN * DOWN];
    for oy in 0..DOWN {
        // Source row span for this output row.
        let y0 = oy * height / DOWN;
        let y1 = ((oy + 1) * height / DOWN).max(y0 + 1).min(height);
        for ox in 0..DOWN {
            let x0 = ox * width / DOWN;
            let x1 = ((ox + 1) * width / DOWN).max(x0 + 1).min(width);
            let mut sum = 0u64;
            let mut count = 0u64;
            for y in y0..y1 {
                let row = y * width;
                for x in x0..x1 {
                    sum += lum[row + x] as u64;
                    count += 1;
                }
            }
            out[oy * DOWN + ox] = if count == 0 {
                0.0
            } else {
                sum as f32 / count as f32
            };
        }
    }
    out
}

/// The `OUT`×`DOWN` DCT-II matrix, skipping the DC row (k+1) as PDQ does, so the
/// hash keys on structure rather than overall brightness. The 1024 cosine cells
/// are constant, so build them once and reuse across every image hashed.
fn dct_matrix() -> &'static [[f32; DOWN]; OUT] {
    static MATRIX: std::sync::OnceLock<[[f32; DOWN]; OUT]> = std::sync::OnceLock::new();
    MATRIX.get_or_init(|| {
        let mut m = [[0f32; DOWN]; OUT];
        let scale = std::f32::consts::PI / (DOWN as f32);
        for (k, row) in m.iter_mut().enumerate() {
            for (j, cell) in row.iter_mut().enumerate() {
                *cell = (scale * ((k + 1) as f32) * (j as f32 + 0.5)).cos();
            }
        }
        m
    })
}

/// 16×16 DCT of the 64×64 block: `D · A · Dᵀ`.
fn dct16(a: &[f32; DOWN * DOWN]) -> [f32; OUT * OUT] {
    let d = dct_matrix();
    // t = D · A  → OUT×DOWN
    let mut t = [[0f32; DOWN]; OUT];
    for (i, trow) in t.iter_mut().enumerate() {
        for (j, tcell) in trow.iter_mut().enumerate() {
            let mut s = 0f32;
            for k in 0..DOWN {
                s += d[i][k] * a[k * DOWN + j];
            }
            *tcell = s;
        }
    }
    // out = t · Dᵀ  → OUT×OUT
    let mut out = [0f32; OUT * OUT];
    for i in 0..OUT {
        for j in 0..OUT {
            let mut s = 0f32;
            for k in 0..DOWN {
                s += t[i][k] * d[j][k];
            }
            out[i * OUT + j] = s;
        }
    }
    out
}

/// Threshold the 256 coefficients against their median into 256 bits.
fn threshold_median(dct: &[f32; OUT * OUT]) -> [u8; 32] {
    let mut sorted = *dct;
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    // Median of an even count: average the two central order statistics, which
    // keeps the split near 128/128 bits and avoids a coefficient equal to a
    // single central element biasing the threshold.
    let median = (sorted[OUT * OUT / 2 - 1] + sorted[OUT * OUT / 2]) / 2.0;
    let mut bits = [0u8; 32];
    for (i, &v) in dct.iter().enumerate() {
        if v > median {
            bits[i / 8] |= 1 << (i % 8);
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic, perceptually *rich* "photo-like" image, sampled from a
    /// continuous function of normalised coordinates.
    ///
    /// Sampling a continuous function (rather than pixel indices) is what lets
    /// the resize test compare the *same picture* at two resolutions. The
    /// function mixes several spatial frequencies plus a bright blob, so the DCT
    /// coefficients spread well away from their median — a flat gradient does
    /// not, and a perceptual hash is legitimately unstable on near-flat input.
    fn photo(width: usize, height: usize) -> Vec<u8> {
        use std::f32::consts::PI;
        let mut v = vec![0u8; width * height];
        for y in 0..height {
            let vv = (y as f32 + 0.5) / height as f32;
            for x in 0..width {
                let uu = (x as f32 + 0.5) / width as f32;
                let mut val = 128.0;
                val += 55.0 * (2.0 * PI * 3.0 * uu).sin();
                val += 45.0 * (2.0 * PI * 2.0 * vv).cos();
                val += 35.0 * (2.0 * PI * 5.0 * (uu + vv)).sin();
                // A round bright blob off-centre.
                let (du, dv) = (uu - 0.7, vv - 0.35);
                val += 60.0 * (-(du * du + dv * dv) * 40.0).exp();
                v[y * width + x] = val.clamp(0.0, 255.0) as u8;
            }
        }
        v
    }

    /// A distinct structured image (diagonal stripes) unrelated to `photo`.
    fn stripes(width: usize, height: usize) -> Vec<u8> {
        let mut v = vec![0u8; width * height];
        for y in 0..height {
            for x in 0..width {
                v[y * width + x] = if (x + y) % 16 < 8 { 20 } else { 235 };
            }
        }
        v
    }

    #[test]
    fn an_emitted_hash_is_labelled_with_a_non_reference_variant() {
        // A hash labelled only "pdq" reads as Meta's reference output, and an
        // examiner told to compare it against an externally-supplied PDQ set
        // has no way to see otherwise from the artifact. The label must name
        // this pipeline, and the caveat must travel on the record rather than
        // living in a module comment nobody reads at 2am.
        assert_ne!(
            PDQ_VARIANT, "pdq",
            "the bare family name claims reference-faithful interop"
        );
        assert!(
            PDQ_VARIANT.starts_with("pdq-"),
            "the variant must stay recognisable as the PDQ family: {PDQ_VARIANT}"
        );

        let stamp = pdq_interop_stamp();
        assert_eq!(stamp["pdq_variant"], PDQ_VARIANT);
        assert_eq!(
            stamp["pdq_reference_validated"], false,
            "no run against Meta's reference vectors has happened"
        );
        assert_eq!(stamp["pdq_interop_note"], PDQ_INTEROP_NOTE);
        assert!(
            PDQ_INTEROP_NOTE.contains("reference vectors"),
            "the note must state which validation is missing"
        );
    }

    #[test]
    fn stamping_a_record_puts_the_variant_and_the_caveat_on_it() {
        // The stamp exists so an emitter cannot ship a hash labelled only with
        // the family name. All three fields have to land, under exactly these
        // keys, because that is what the surfaces reading the record look for.
        let mut object = serde_json::Map::new();
        object.insert("pdq_hex".into(), serde_json::json!("00".repeat(32)));
        stamp_pdq_interop(&mut object);
        assert_eq!(object["pdq_variant"], serde_json::json!(PDQ_VARIANT));
        assert_eq!(object["pdq_reference_validated"], serde_json::json!(false));
        assert_eq!(
            object["pdq_interop_note"],
            serde_json::json!(PDQ_INTEROP_NOTE)
        );
        // The hash itself is untouched.
        assert_eq!(object["pdq_hex"], serde_json::json!("00".repeat(32)));
    }

    #[test]
    fn stamping_overwrites_a_weaker_interop_claim_already_on_the_record() {
        // "validated against the reference" is the one claim this pipeline is
        // not entitled to make, so the stamp wins over anything an emitter set.
        let mut object = serde_json::Map::new();
        object.insert("pdq_reference_validated".into(), serde_json::json!(true));
        object.insert("pdq_variant".into(), serde_json::json!("pdq"));
        stamp_pdq_interop(&mut object);
        assert_eq!(object["pdq_reference_validated"], serde_json::json!(false));
        assert_eq!(object["pdq_variant"], serde_json::json!(PDQ_VARIANT));
    }

    #[test]
    fn identical_input_hashes_to_distance_zero() {
        let img = photo(200, 150);
        let a = PdqHash::from_luminance(200, 150, &img).unwrap();
        let b = PdqHash::from_luminance(200, 150, &img).unwrap();
        assert_eq!(a.distance(&b), 0);
        assert_eq!(a, b);
    }

    #[test]
    fn same_picture_at_different_resolution_stays_close() {
        // The whole point of a perceptual hash: a resized copy of one picture
        // must be near, not far. Downsample the gradient to half size by area.
        let big = photo(256, 256);
        let small = photo(128, 128);
        let a = PdqHash::from_luminance(256, 256, &big).unwrap();
        let b = PdqHash::from_luminance(128, 128, &small).unwrap();
        assert!(
            a.is_near(&b, 31),
            "resized copy should be within threshold, distance was {}",
            a.distance(&b)
        );
    }

    #[test]
    fn light_recompression_noise_stays_close() {
        // Add small per-pixel noise (simulating JPEG requantisation) and check
        // the hash barely moves.
        let base = photo(200, 200);
        let mut noisy = base.clone();
        for (i, p) in noisy.iter_mut().enumerate() {
            let delta = ((i * 2654435761) % 7) as i16 - 3; // deterministic ±3
            *p = (*p as i16 + delta).clamp(0, 255) as u8;
        }
        let a = PdqHash::from_luminance(200, 200, &base).unwrap();
        let b = PdqHash::from_luminance(200, 200, &noisy).unwrap();
        assert!(
            a.is_near(&b, 31),
            "light noise should stay near, distance was {}",
            a.distance(&b)
        );
    }

    #[test]
    fn unrelated_images_are_far_apart() {
        let a = PdqHash::from_luminance(200, 200, &photo(200, 200)).unwrap();
        let b = PdqHash::from_luminance(200, 200, &stripes(200, 200)).unwrap();
        assert!(
            a.distance(&b) > 31,
            "unrelated images must exceed threshold, distance was {}",
            a.distance(&b)
        );
    }

    #[test]
    fn distance_is_symmetric_and_bounded() {
        let a = PdqHash::from_luminance(64, 64, &photo(64, 64)).unwrap();
        let b = PdqHash::from_luminance(64, 64, &stripes(64, 64)).unwrap();
        assert_eq!(a.distance(&b), b.distance(&a));
        assert!(a.distance(&b) <= 256);
    }

    #[test]
    fn hex_round_trips() {
        let h = PdqHash::from_luminance(80, 80, &stripes(80, 80)).unwrap();
        let hex = h.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(PdqHash::from_hex(&hex), Some(h));
        assert_eq!(PdqHash::from_hex("nothex"), None);
    }

    #[test]
    fn rgb_conversion_matches_manual_luminance() {
        // A pure-grey RGB image converts to that grey level, so its hash equals
        // the hash of the equivalent luminance buffer.
        let (w, h) = (64, 64);
        let mut rgb = vec![0u8; w * h * 3];
        let lum: Vec<u8> = (0..w * h).map(|i| (i % 200) as u8).collect();
        for (i, l) in lum.iter().enumerate() {
            rgb[i * 3] = *l;
            rgb[i * 3 + 1] = *l;
            rgb[i * 3 + 2] = *l;
        }
        let from_rgb = PdqHash::from_rgb(w, h, &rgb, 3).unwrap();
        let from_lum = PdqHash::from_luminance(w, h, &lum).unwrap();
        assert_eq!(from_rgb, from_lum);
    }

    #[test]
    fn rejects_mismatched_buffer() {
        assert!(PdqHash::from_luminance(10, 10, &[0u8; 50]).is_none());
        assert!(PdqHash::from_luminance(0, 0, &[]).is_none());
        assert!(PdqHash::from_rgb(4, 4, &[0u8; 10], 3).is_none());
    }

    #[test]
    fn hash_is_roughly_balanced() {
        // Median thresholding should yield close to 128 set bits, which is what
        // keeps distances meaningful. Allow slack for ties.
        let h = PdqHash::from_luminance(200, 200, &photo(200, 200)).unwrap();
        let ones: u32 = h.0.iter().map(|b| b.count_ones()).sum();
        assert!(
            (100..=156).contains(&ones),
            "unbalanced hash: {ones} bits set"
        );
    }
}
