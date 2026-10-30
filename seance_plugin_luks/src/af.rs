//! Anti-forensic (AF) information splitter.
//!
//! LUKS never stores the master key directly. Each keyslot holds the master key
//! inflated to `stripes * key_len` bytes by Clemens Fruhwirth's AF splitter, so
//! that a partial recovery of the keyslot area leaks nothing about the key. To
//! recover the master key we decrypt the keyslot area (elsewhere) and then
//! `af_merge` it back down to `key_len` bytes.
//!
//! Reference: cryptsetup `lib/luks1/af.c`.

use crate::hash::HashSpec;

/// The diffuse step: hash each `digest_size` chunk with a 4-byte big-endian
/// block counter prepended, so a change anywhere avalanches across the block.
fn diffuse(hash: HashSpec, block: &[u8]) -> Vec<u8> {
    let ds = hash.digest_size();
    let mut out = vec![0u8; block.len()];
    let mut counter: u32 = 0;
    let mut off = 0;
    while off < block.len() {
        let chunk = std::cmp::min(ds, block.len() - off);
        let mut input = Vec::with_capacity(4 + chunk);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(&block[off..off + chunk]);
        let digest = hash.digest(&input);
        out[off..off + chunk].copy_from_slice(&digest[..chunk]);
        off += chunk;
        counter += 1;
    }
    out
}

#[inline]
fn xor_into(acc: &mut [u8], other: &[u8]) {
    for (a, b) in acc.iter_mut().zip(other.iter()) {
        *a ^= *b;
    }
}

/// Merge an AF-split buffer back into the original `blocksize`-byte secret.
///
/// `src` must be exactly `blocksize * stripes` bytes.
pub fn af_merge(src: &[u8], blocksize: usize, stripes: usize, hash: HashSpec) -> Vec<u8> {
    debug_assert_eq!(src.len(), blocksize * stripes);
    let mut acc = vec![0u8; blocksize];
    for i in 0..stripes.saturating_sub(1) {
        xor_into(&mut acc, &src[i * blocksize..(i + 1) * blocksize]);
        acc = diffuse(hash, &acc);
    }
    // Final stripe XORs directly into the accumulator to yield the secret.
    let last = &src[(stripes - 1) * blocksize..stripes * blocksize];
    xor_into(&mut acc, last);
    acc
}

/// Split a `blocksize`-byte secret into `blocksize * stripes` bytes.
///
/// `fill_random` fills the first `stripes-1` stripes with random material; it is
/// exposed so tests can drive it deterministically. Round-trips with [`af_merge`].
pub fn af_split(
    secret: &[u8],
    stripes: usize,
    hash: HashSpec,
    mut fill_random: impl FnMut(&mut [u8]),
) -> Vec<u8> {
    let blocksize = secret.len();
    let mut out = vec![0u8; blocksize * stripes];
    fill_random(&mut out[..(stripes - 1) * blocksize]);

    let mut acc = vec![0u8; blocksize];
    for i in 0..stripes - 1 {
        xor_into(&mut acc, &out[i * blocksize..(i + 1) * blocksize]);
        acc = diffuse(hash, &acc);
    }
    // Last stripe stores secret XOR accumulator so merge recovers the secret.
    let last = &mut out[(stripes - 1) * blocksize..stripes * blocksize];
    last.copy_from_slice(secret);
    xor_into(last, &acc);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic pseudo-random fill for reproducible round-trips.
    fn lcg_fill(buf: &mut [u8], mut state: u64) {
        for b in buf.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
    }

    #[test]
    fn merge_inverts_split_sha256() {
        let secret: Vec<u8> = (0..64).map(|i| (i * 7 + 3) as u8).collect();
        let split = af_split(&secret, 4000, HashSpec::Sha256, |b| {
            lcg_fill(b, 0xDEAD_BEEF)
        });
        assert_eq!(split.len(), 64 * 4000);
        let merged = af_merge(&split, 64, 4000, HashSpec::Sha256);
        assert_eq!(merged, secret);
    }

    #[test]
    fn merge_inverts_split_sha1_small_stripes() {
        let secret: Vec<u8> = (0..32).map(|i| (255 - i) as u8).collect();
        let split = af_split(&secret, 8, HashSpec::Sha1, |b| lcg_fill(b, 0x1234_5678));
        let merged = af_merge(&split, 32, 8, HashSpec::Sha1);
        assert_eq!(merged, secret);
    }

    #[test]
    fn split_actually_diffuses() {
        // The split material must not simply contain the secret in the clear.
        let secret = vec![0xAAu8; 64];
        let split = af_split(&secret, 100, HashSpec::Sha256, |b| lcg_fill(b, 1));
        // No stripe should equal the raw secret.
        for stripe in split.chunks(64) {
            assert_ne!(stripe, secret.as_slice());
        }
    }
}
