//! Recover AES keys from a memory image by their key schedules.
//!
//! When AES encrypts, it first expands the key into a *key schedule* — 11, 13 or
//! 15 round keys for AES-128/192/256. That schedule sits in RAM for as long as
//! the cipher is live, and it has rigid internal structure: every word after the
//! first `Nk` is derived from earlier words by a fixed recurrence. So a
//! candidate region can be *verified*, not guessed — take its first key-length
//! bytes, run the expansion, and check the rest matches byte-for-byte. A match
//! is mathematically a real schedule, not a coincidence.
//!
//! This is the standard technique (bulk_extractor's `scan_aes`, and the AESKeyFind
//! lineage) for pulling TrueCrypt/VeraCrypt/BitLocker/LUKS keys out of a captured
//! memory image or hibernation file when no password is known. In Séance it feeds
//! the decryption plugins with a *recovered* key.
//!
//! ## Grading
//!
//! A recovered key whose schedule verifies is a real schedule — but "this is the
//! volume key" is only proven once it decrypts the volume header. So this module
//! reports a *candidate* (the schedule is valid); confirming it against a volume
//! is the decryptor's job, and only then does it earn the `Validated` grade.

/// The AES S-box, used by the key-expansion recurrence.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Round constants for key expansion (enough rounds for AES-256).
const RCON: [u8; 15] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
];

/// The three AES key sizes, in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesBits {
    Aes128,
    Aes192,
    Aes256,
}

impl AesBits {
    /// Key length in bytes (16 / 24 / 32).
    pub fn key_len(self) -> usize {
        match self {
            AesBits::Aes128 => 16,
            AesBits::Aes192 => 24,
            AesBits::Aes256 => 32,
        }
    }

    /// Total expanded key-schedule length in bytes (176 / 208 / 240).
    pub fn schedule_len(self) -> usize {
        match self {
            AesBits::Aes128 => 176,
            AesBits::Aes192 => 208,
            AesBits::Aes256 => 240,
        }
    }

    /// Number of bits, for reporting.
    pub fn bits(self) -> u32 {
        match self {
            AesBits::Aes128 => 128,
            AesBits::Aes192 => 192,
            AesBits::Aes256 => 256,
        }
    }

    fn nk(self) -> usize {
        self.key_len() / 4
    }
}

/// A recovered AES key candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredKey {
    /// Byte offset in the scanned buffer where the schedule begins.
    pub offset: usize,
    /// Key size.
    pub bits: AesBits,
    /// The recovered key (the first `key_len` bytes of the schedule).
    pub key: Vec<u8>,
}

/// Expand an AES key into its full round-key schedule.
///
/// Returns the schedule bytes. Panics only if `key.len()` is not 16/24/32; call
/// sites here always pass a correct length.
pub fn expand_key(key: &[u8]) -> Vec<u8> {
    let bits = match key.len() {
        16 => AesBits::Aes128,
        24 => AesBits::Aes192,
        32 => AesBits::Aes256,
        n => panic!("invalid AES key length {n}"),
    };
    let nk = bits.nk();
    let total_words = bits.schedule_len() / 4;
    let mut w = vec![[0u8; 4]; total_words];
    for i in 0..nk {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            // RotWord + SubWord + Rcon
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for b in temp.iter_mut() {
                *b = SBOX[*b as usize];
            }
            temp[0] ^= RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            // AES-256 extra SubWord.
            for b in temp.iter_mut() {
                *b = SBOX[*b as usize];
            }
        }
        for j in 0..4 {
            w[i][j] = w[i - nk][j] ^ temp[j];
        }
    }
    let mut out = Vec::with_capacity(bits.schedule_len());
    for word in w {
        out.extend_from_slice(&word);
    }
    out
}

/// Test whether the bytes at `buf[offset..]` are a valid key schedule of size
/// `bits`: expand the leading key and compare the remainder. Returns the
/// recovered key on success.
///
/// The comparison is **incremental and bails at the first mismatched word**,
/// which is what makes scanning gigabytes of RAM tractable: on random data the
/// first derived word almost never matches, so a non-key offset costs one word
/// of key-expansion work, not a full 176/208/240-byte expansion.
pub fn verify_schedule_at(buf: &[u8], offset: usize, bits: AesBits) -> Option<RecoveredKey> {
    let end = offset.checked_add(bits.schedule_len())?;
    if end > buf.len() {
        return None;
    }
    let region = &buf[offset..end];
    let nk = bits.nk();
    let total_words = bits.schedule_len() / 4;

    // Working set of expanded words; the first `nk` are the candidate key. This
    // is called at *every* byte offset of a multi-gigabyte scan, so it must not
    // allocate: a fixed stack array (max 60 words for AES-256) is used and only
    // the first `total_words` are touched.
    let mut w = [[0u8; 4]; 60];
    let w = &mut w[..total_words];
    for (i, word) in w.iter_mut().enumerate().take(nk) {
        word.copy_from_slice(&region[4 * i..4 * i + 4]);
    }
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for b in temp.iter_mut() {
                *b = SBOX[*b as usize];
            }
            temp[0] ^= RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            for b in temp.iter_mut() {
                *b = SBOX[*b as usize];
            }
        }
        for j in 0..4 {
            w[i][j] = w[i - nk][j] ^ temp[j];
        }
        // Compare this derived word against the region immediately; a real
        // schedule matches every one, random data almost never matches the first.
        if w[i] != region[4 * i..4 * i + 4] {
            return None;
        }
    }
    Some(RecoveredKey {
        offset,
        bits,
        key: region[..bits.key_len()].to_vec(),
    })
}

/// Scan a byte buffer for AES key schedules of every size.
///
/// Slides a one-byte window over the buffer. At each offset it checks 128, 192
/// then 256; a hit is a mathematically-verified schedule. Overlapping hits at
/// the same offset are impossible (a region cannot verify as two sizes at once
/// beyond astronomically unlikely coincidence), so the first size that verifies
/// wins and the scan continues past it.
///
/// `step` lets a caller trade completeness for speed; keys are word-aligned in
/// practice, so `4` is a safe fast default, `1` is exhaustive.
pub fn scan_for_keys(buf: &[u8], step: usize) -> Vec<RecoveredKey> {
    let step = step.max(1);
    let mut found = Vec::new();
    let mut offset = 0;
    while offset + AesBits::Aes128.schedule_len() <= buf.len() {
        let hit = verify_schedule_at(buf, offset, AesBits::Aes128)
            .or_else(|| verify_schedule_at(buf, offset, AesBits::Aes192))
            .or_else(|| verify_schedule_at(buf, offset, AesBits::Aes256));
        match hit {
            Some(k) => {
                let advance = k.bits.schedule_len();
                found.push(k);
                offset += advance;
            }
            None => offset += step,
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 Appendix A.1: the AES-128 key expansion of the all-known key
    /// `2b7e1516...` has a documented first round key. This anchors the schedule
    /// to the standard, so the scanner is verified against AES itself, not against
    /// our own output.
    #[test]
    fn aes128_expansion_matches_fips197() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let sched = expand_key(&key);
        assert_eq!(sched.len(), 176);
        // w[4] (first word of round key 1) is a0fafe17 per FIPS-197.
        assert_eq!(&sched[16..20], &[0xa0, 0xfa, 0xfe, 0x17]);
        // w[43] (last word) is b6630ca6 per FIPS-197.
        assert_eq!(&sched[172..176], &[0xb6, 0x63, 0x0c, 0xa6]);
    }

    #[test]
    fn aes256_expansion_matches_fips197() {
        // FIPS-197 Appendix A.3 key. This exercises the AES-256-only extra
        // SubWord step that the 128-bit vector cannot reach.
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let sched = expand_key(&key);
        assert_eq!(sched.len(), 240);
        // w[56] = fe4890d1 (first word of the final round key) per FIPS-197 A.3.
        assert_eq!(&sched[224..228], &[0xfe, 0x48, 0x90, 0xd1]);
        // w[59] = 706c631e (last word) per FIPS-197 A.3.
        assert_eq!(&sched[236..240], &[0x70, 0x6c, 0x63, 0x1e]);
    }

    #[test]
    fn recovers_a_planted_aes256_key_from_memory() {
        // A realistic scenario: a key schedule sitting in a buffer of noise.
        let key: Vec<u8> = (0..32).map(|i| (i * 7 + 1) as u8).collect();
        let sched = expand_key(&key);
        let mut mem = vec![0xABu8; 10_000];
        // Deterministic "noise" that is not all one byte.
        for (i, b) in mem.iter_mut().enumerate() {
            *b = (i * 131 % 251) as u8;
        }
        let plant_at = 4096;
        mem[plant_at..plant_at + sched.len()].copy_from_slice(&sched);

        let keys = scan_for_keys(&mem, 1);
        let hit = keys
            .iter()
            .find(|k| k.offset == plant_at)
            .expect("planted key must be recovered");
        assert_eq!(hit.bits, AesBits::Aes256);
        assert_eq!(hit.key, key);
    }

    #[test]
    fn recovers_planted_128_and_192() {
        for bits in [AesBits::Aes128, AesBits::Aes192] {
            let key: Vec<u8> = (0..bits.key_len()).map(|i| (i * 3 + 5) as u8).collect();
            let sched = expand_key(&key);
            let mut mem = vec![0u8; 2000];
            for (i, b) in mem.iter_mut().enumerate() {
                *b = (i % 97) as u8;
            }
            mem[500..500 + sched.len()].copy_from_slice(&sched);
            let keys = scan_for_keys(&mem, 1);
            let hit = keys.iter().find(|k| k.offset == 500).expect("recovered");
            assert_eq!(hit.bits, bits);
            assert_eq!(hit.key, key);
        }
    }

    #[test]
    fn does_not_false_positive_on_random_bytes() {
        // A pseudo-random buffer with no planted schedule must yield nothing.
        // The probability a random 176-byte region satisfies the expansion
        // recurrence is astronomically small, so any hit is a bug.
        let mut mem = vec![0u8; 100_000];
        let mut state = 0x12345678u32;
        for b in mem.iter_mut() {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (state >> 24) as u8;
        }
        assert!(
            scan_for_keys(&mem, 1).is_empty(),
            "no schedule should verify in random data"
        );
    }

    #[test]
    fn all_zero_key_is_a_valid_schedule_but_only_at_its_offset() {
        // The all-zero key expands to a specific (non-zero) schedule; a buffer of
        // pure zeros is NOT that schedule, so zeros must not false-positive.
        let zeros = vec![0u8; 1000];
        assert!(scan_for_keys(&zeros, 1).is_empty());
    }

    #[test]
    fn step_alignment_still_finds_word_aligned_keys() {
        let key: Vec<u8> = (0..16).map(|i| (i + 1) as u8).collect();
        let sched = expand_key(&key);
        let mut mem = vec![0u8; 1000];
        for (i, b) in mem.iter_mut().enumerate() {
            *b = (i % 100 + 1) as u8;
        }
        mem[400..400 + sched.len()].copy_from_slice(&sched); // 400 is word-aligned
        let keys = scan_for_keys(&mem, 4);
        assert!(keys.iter().any(|k| k.offset == 400 && k.key == key));
    }
}
