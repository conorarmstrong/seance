//! Classic 64-bit perceptual hashes — aHash, dHash and pHash — as companions to
//! [`crate::pdq::PdqHash`].
//!
//! PDQ is the strong, 256-bit hash Séance uses for near-duplicate detection. The
//! three classic 64-bit hashes here exist for **cross-tool interoperability**:
//! many hash sets and other forensic tools publish aHash/dHash/pHash values, and
//! an examiner given such a set needs Séance to compute the same *kind* so a
//! match is possible at all. They are weaker than PDQ (64 bits, simpler
//! transforms) and are offered alongside it, never instead of it.
//!
//! These follow the conventions of the widely-used `imagehash` library (aHash:
//! mean threshold; dHash: horizontal gradient; pHash: DCT low-frequency block
//! thresholded against its median, **including** the DC term). **Bit-exact
//! equality with another tool's output is not guaranteed**, because the result
//! also depends on the resize filter (this uses area-averaging, not Lanczos) and
//! the DCT normalisation — so treat a small Hamming distance to an external hash
//! as a lead, like PDQ, not an identification. This limitation is documented, not
//! silent.
//!
//! # Input
//!
//! Like PDQ, these take an 8-bit **luminance** buffer (row-major, `w*h` bytes) so
//! image decoding stays with the caller. RGB helpers convert with Rec.601 weights,
//! matching PDQ exactly so the same pixels feed every hash.
//!
//! # The three hashes
//!
//! * **aHash** (average): 8×8 area-average, each cell brighter than the mean → 1.
//!   Cheapest; robust to scaling, weak against brightness/gamma shifts.
//! * **dHash** (difference/gradient): 9×8, each cell compared to its right
//!   neighbour → 8×8 = 64 bits. Robust to brightness because it keys on gradient.
//! * **pHash** (DCT): 32×32 area-average, 2-D DCT-II, take the low-frequency 8×8
//!   block (**including** the DC term, as `imagehash` does — it medians all 64
//!   of `dct[:8,:8]`) and threshold against its median. The most robust of the
//!   three to gamma, compression and minor edits.

use crate::pdq::rgb_to_luminance;

/// Area-average downsample a luminance image to `tw`×`th`, returning `f32` cells.
/// Every output cell averages the source pixels that map into it, so the result
/// does not depend on the source resolution — the property matching needs.
fn downsample(width: usize, height: usize, lum: &[u8], tw: usize, th: usize) -> Vec<f32> {
    let mut out = vec![0f32; tw * th];
    for oy in 0..th {
        let y0 = oy * height / th;
        let y1 = ((oy + 1) * height / th).max(y0 + 1).min(height);
        for ox in 0..tw {
            let x0 = ox * width / tw;
            let x1 = ((ox + 1) * width / tw).max(x0 + 1).min(width);
            let mut sum = 0u64;
            let mut count = 0u64;
            for y in y0..y1 {
                let row = y * width;
                for x in x0..x1 {
                    sum += lum[row + x] as u64;
                    count += 1;
                }
            }
            out[oy * tw + ox] = if count == 0 {
                0.0
            } else {
                sum as f32 / count as f32
            };
        }
    }
    out
}

/// Lower-case 16-char hex of a 64-bit hash, big-endian so bit 63 leads.
fn to_hex64(bits: u64) -> String {
    hex::encode(bits.to_be_bytes())
}

/// Parse a 16-char hex string back into a 64-bit hash.
fn from_hex64(s: &str) -> Option<u64> {
    let bytes = hex::decode(s).ok()?;
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

macro_rules! hash64_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub u64);

        impl $name {
            /// Hamming distance to another hash, in bits (0..=64).
            pub fn distance(&self, other: &Self) -> u32 {
                (self.0 ^ other.0).count_ones()
            }

            /// Whether two hashes are within `threshold` bits.
            pub fn is_near(&self, other: &Self, threshold: u32) -> bool {
                self.distance(other) <= threshold
            }

            /// Lower-case 16-char hex.
            pub fn to_hex(&self) -> String {
                to_hex64(self.0)
            }

            /// Parse from a 16-char hex string.
            pub fn from_hex(s: &str) -> Option<Self> {
                from_hex64(s).map(Self)
            }
        }
    };
}

hash64_type!(AHash, "64-bit average perceptual hash.");
hash64_type!(DHash, "64-bit difference (gradient) perceptual hash.");
hash64_type!(PHash, "64-bit DCT perceptual hash.");

impl AHash {
    /// Average hash of an 8-bit luminance image, or `None` if the buffer length
    /// does not match the dimensions or the image is empty.
    pub fn from_luminance(width: usize, height: usize, lum: &[u8]) -> Option<Self> {
        if width == 0 || height == 0 || lum.len() != width * height {
            return None;
        }
        let cells = downsample(width, height, lum, 8, 8);
        let mean = cells.iter().sum::<f32>() / cells.len() as f32;
        let mut bits = 0u64;
        for (i, &c) in cells.iter().enumerate() {
            if c >= mean {
                bits |= 1 << (63 - i);
            }
        }
        Some(Self(bits))
    }

    /// Convert an interleaved RGB(A) buffer to luminance and hash it.
    pub fn from_rgb(width: usize, height: usize, pixels: &[u8], channels: usize) -> Option<Self> {
        let lum = rgb_to_luminance(width, height, pixels, channels)?;
        Self::from_luminance(width, height, &lum)
    }
}

impl DHash {
    /// Difference hash of an 8-bit luminance image.
    pub fn from_luminance(width: usize, height: usize, lum: &[u8]) -> Option<Self> {
        if width == 0 || height == 0 || lum.len() != width * height {
            return None;
        }
        // 9 wide so 8 horizontal comparisons per row give 8×8 = 64 bits.
        let cells = downsample(width, height, lum, 9, 8);
        let mut bits = 0u64;
        let mut i = 0;
        for row in 0..8 {
            for col in 0..8 {
                let left = cells[row * 9 + col];
                let right = cells[row * 9 + col + 1];
                if right > left {
                    bits |= 1 << (63 - i);
                }
                i += 1;
            }
        }
        Some(Self(bits))
    }

    /// Convert an interleaved RGB(A) buffer to luminance and hash it.
    pub fn from_rgb(width: usize, height: usize, pixels: &[u8], channels: usize) -> Option<Self> {
        let lum = rgb_to_luminance(width, height, pixels, channels)?;
        Self::from_luminance(width, height, &lum)
    }
}

/// Side of the pHash pre-DCT block.
const PHASH_DOWN: usize = 32;
/// Side of the low-frequency block pHash keys on (8×8 = 64 bits).
const PHASH_OUT: usize = 8;

impl PHash {
    /// DCT perceptual hash of an 8-bit luminance image.
    pub fn from_luminance(width: usize, height: usize, lum: &[u8]) -> Option<Self> {
        if width == 0 || height == 0 || lum.len() != width * height {
            return None;
        }
        let block = downsample(width, height, lum, PHASH_DOWN, PHASH_DOWN);
        let low = dct_low_block(&block);
        // Standard pHash convention (matching the widely-used `imagehash` library
        // this exists to interoperate with): threshold every one of the 64
        // low-frequency coefficients — INCLUDING the DC term — against their
        // median. The DC term sits at the top of the sorted set, so the median is
        // a low-frequency value and the hash still keys on structure.
        let mut sorted: Vec<f32> = low.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        // Median of an even count is the mean of the two middle elements.
        let median = (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0;
        let mut bits = 0u64;
        for (i, &c) in low.iter().enumerate() {
            if c > median {
                bits |= 1 << (63 - i);
            }
        }
        Some(Self(bits))
    }

    /// Convert an interleaved RGB(A) buffer to luminance and hash it.
    pub fn from_rgb(width: usize, height: usize, pixels: &[u8], channels: usize) -> Option<Self> {
        let lum = rgb_to_luminance(width, height, pixels, channels)?;
        Self::from_luminance(width, height, &lum)
    }
}

/// The `PHASH_OUT`×`PHASH_DOWN` DCT-II matrix, built once and reused.
fn phash_dct_matrix() -> &'static [[f32; PHASH_DOWN]; PHASH_OUT] {
    static MATRIX: std::sync::OnceLock<[[f32; PHASH_DOWN]; PHASH_OUT]> = std::sync::OnceLock::new();
    MATRIX.get_or_init(|| {
        let mut m = [[0f32; PHASH_DOWN]; PHASH_OUT];
        let scale = std::f32::consts::PI / (PHASH_DOWN as f32);
        for (k, row) in m.iter_mut().enumerate() {
            for (j, cell) in row.iter_mut().enumerate() {
                *cell = (scale * (k as f32) * (j as f32 + 0.5)).cos();
            }
        }
        m
    })
}

/// 8×8 low-frequency DCT of the 32×32 block: `D · A · Dᵀ`, row-major length 64.
/// Unlike PDQ this keeps the k=0 (DC) row, because the `imagehash` convention
/// pHash interoperates with thresholds all 64 coefficients, DC included.
fn dct_low_block(a: &[f32]) -> [f32; PHASH_OUT * PHASH_OUT] {
    let d = phash_dct_matrix();
    // t = D · A → OUT×DOWN
    let mut t = [[0f32; PHASH_DOWN]; PHASH_OUT];
    for (i, trow) in t.iter_mut().enumerate() {
        for (j, tcell) in trow.iter_mut().enumerate() {
            let mut s = 0f32;
            for k in 0..PHASH_DOWN {
                s += d[i][k] * a[k * PHASH_DOWN + j];
            }
            *tcell = s;
        }
    }
    // out = t · Dᵀ → OUT×OUT
    let mut out = [0f32; PHASH_OUT * PHASH_OUT];
    for i in 0..PHASH_OUT {
        for j in 0..PHASH_OUT {
            let mut s = 0f32;
            for k in 0..PHASH_DOWN {
                s += t[i][k] * d[j][k];
            }
            out[i * PHASH_OUT + j] = s;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A left-to-right brightness ramp. Useful for gradient/brightness tests, but
    /// a *pathological* input for a DCT hash: a pure ramp leaves most pHash
    /// coefficients near zero and sign-unstable, so it is not used for pHash.
    fn gradient(width: usize, height: usize) -> Vec<u8> {
        let mut v = vec![0u8; width * height];
        for y in 0..height {
            for x in 0..width {
                v[y * width + x] = ((x * 255) / width.max(1)) as u8;
            }
        }
        v
    }

    /// A four-quadrant image with strong, stable low-frequency structure — the
    /// kind of content a real photo has, so every hash (including the DCT-based
    /// pHash) is stable across a rescale.
    fn quadrants(width: usize, height: usize) -> Vec<u8> {
        let mut v = vec![0u8; width * height];
        for y in 0..height {
            for x in 0..width {
                let top = y < height / 2;
                let left = x < width / 2;
                v[y * width + x] = match (top, left) {
                    (true, true) => 30,
                    (true, false) => 200,
                    (false, true) => 120,
                    (false, false) => 235,
                };
            }
        }
        v
    }

    #[test]
    fn all_three_are_scale_invariant_on_the_same_image() {
        // Same picture at two resolutions must hash near-identically. aHash/dHash
        // are bit-exact here; pHash keys on real low-frequency structure so it is
        // stable to within a few bits (perceptual hashes are robust, not required
        // to be bit-identical across a rescale).
        let a = quadrants(128, 96);
        let b = quadrants(64, 48); // same picture, half resolution
        assert_eq!(
            AHash::from_luminance(128, 96, &a),
            AHash::from_luminance(64, 48, &b),
            "aHash must not depend on source resolution"
        );
        assert_eq!(
            DHash::from_luminance(128, 96, &a),
            DHash::from_luminance(64, 48, &b),
            "dHash must not depend on source resolution"
        );
        let pd = PHash::from_luminance(128, 96, &a)
            .unwrap()
            .distance(&PHash::from_luminance(64, 48, &b).unwrap());
        assert!(
            pd <= 4,
            "pHash must be stable across a rescale (got {pd} bits)"
        );
    }

    #[test]
    fn phash_medians_all_64_dct_coefficients_including_dc() {
        // The convention this hash exists to interoperate with (`imagehash`)
        // takes dct[:8,:8] and medians all 64 values, DC included. The earlier
        // in-tree convention dropped the DC term and medianed the remaining 63,
        // which shifts the threshold and always clears bit 63 — a silent
        // cross-tool mismatch, since both produce a plausible-looking hash. Pin
        // the convention to the behaviour, so a doc or code drift back to it
        // fails here rather than in an examiner's hash set.
        let (w, h) = (96, 96);
        let img = quadrants(w, h);
        let low = dct_low_block(&downsample(w, h, &img, PHASH_DOWN, PHASH_DOWN));

        let mut sorted = low.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        // DC sums a block of non-negative luminance, so it is the largest of the
        // 64 — which is exactly why the two conventions disagree on the median
        // and on bit 63.
        assert_eq!(
            sorted[63], low[0],
            "fixture must put the DC term at the top of the sorted set"
        );

        let median = (sorted[31] + sorted[32]) / 2.0;
        let mut expected = 0u64;
        for (i, &c) in low.iter().enumerate() {
            if c > median {
                expected |= 1 << (63 - i);
            }
        }

        let got = PHash::from_luminance(w, h, &img).unwrap();
        assert_eq!(
            got.0, expected,
            "pHash must threshold all 64 coefficients against the median of all 64"
        );
        assert_eq!(
            got.0 >> 63,
            1,
            "the DC coefficient exceeds the median, so its bit must be emitted"
        );
    }

    #[test]
    fn an_image_is_distance_zero_from_itself() {
        let img = gradient(80, 60);
        let (w, h) = (80, 60);
        assert_eq!(
            AHash::from_luminance(w, h, &img)
                .unwrap()
                .distance(&AHash::from_luminance(w, h, &img).unwrap()),
            0
        );
        assert_eq!(
            DHash::from_luminance(w, h, &img)
                .unwrap()
                .distance(&DHash::from_luminance(w, h, &img).unwrap()),
            0
        );
        assert_eq!(
            PHash::from_luminance(w, h, &img)
                .unwrap()
                .distance(&PHash::from_luminance(w, h, &img).unwrap()),
            0
        );
    }

    #[test]
    fn dhash_keys_on_gradient_not_brightness() {
        // Two gradients differing only by a uniform brightness offset must hash
        // the same under dHash, which compares neighbours rather than a mean.
        let base = gradient(64, 64);
        let brighter: Vec<u8> = base.iter().map(|&p| p.saturating_add(40)).collect();
        assert_eq!(
            DHash::from_luminance(64, 64, &base),
            DHash::from_luminance(64, 64, &brighter),
            "dHash must be invariant to a uniform brightness shift"
        );
    }

    #[test]
    fn unrelated_images_are_far_apart() {
        // A left-to-right gradient vs its horizontal mirror: structurally opposite.
        let g = gradient(64, 64);
        let mut mirror = vec![0u8; 64 * 64];
        for y in 0..64 {
            for x in 0..64 {
                mirror[y * 64 + x] = g[y * 64 + (63 - x)];
            }
        }
        let d = DHash::from_luminance(64, 64, &g)
            .unwrap()
            .distance(&DHash::from_luminance(64, 64, &mirror).unwrap());
        assert!(
            d > 16,
            "a mirrored gradient must be far under dHash (got {d})"
        );
    }

    #[test]
    fn hex_round_trips_for_each() {
        let a = AHash(0x0123_4567_89ab_cdef);
        assert_eq!(AHash::from_hex(&a.to_hex()), Some(a));
        assert_eq!(a.to_hex().len(), 16);
        let d = DHash(0xffff_0000_ffff_0000);
        assert_eq!(DHash::from_hex(&d.to_hex()), Some(d));
        let p = PHash(0xdead_beef_cafe_babe);
        assert_eq!(PHash::from_hex(&p.to_hex()), Some(p));
        assert_eq!(PHash::from_hex("nothex"), None);
    }

    #[test]
    fn rgb_and_luminance_agree() {
        // A grey RGB image and its luminance must produce the same hash.
        let (w, h) = (40, 40);
        let mut rgb = vec![0u8; w * h * 3];
        let mut lum = vec![0u8; w * h];
        for i in 0..w * h {
            let v = ((i * 255) / (w * h)) as u8;
            rgb[i * 3] = v;
            rgb[i * 3 + 1] = v;
            rgb[i * 3 + 2] = v;
            lum[i] = v; // grey: luma == channel value
        }
        assert_eq!(
            AHash::from_rgb(w, h, &rgb, 3),
            AHash::from_luminance(w, h, &lum)
        );
    }

    #[test]
    fn empty_or_mismatched_input_is_none() {
        assert!(AHash::from_luminance(0, 10, &[]).is_none());
        assert!(DHash::from_luminance(10, 10, &[0u8; 5]).is_none());
        assert!(PHash::from_rgb(10, 10, &[0u8; 10], 3).is_none());
    }
}
