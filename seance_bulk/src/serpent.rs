//! Recover Serpent-256 keys from a memory image by their key schedules.
//!
//! VeraCrypt (like TrueCrypt) expands a Serpent key into 140 32-bit words held in the volume's
//! `CRYPTO_INFO` while the volume is mounted. The layout is Brian Gladman's: the 32-byte key
//! itself is the first eight words, and words 8 to 139 are the 33 round subkeys (132 words) derived
//! from it by the key schedule in the Serpent specification (Anderson, Biham and Knudsen). A region
//! whose first eight words, run through that schedule, reproduce the next 132 words byte for byte is
//! a real Serpent schedule: the check is mathematical, as for AES (`crate::aes`), not a pattern.
//!
//! The expansion here is written from the specification's S-boxes and key schedule and graded
//! against `pyserpent` (Gladman's own Serpent, as VeraCrypt's) on twelve keys
//! (`tests/fixtures/serpent_schedules.json`), and against a real mounted Serpent volume in the
//! Windows 11 capture of `MEM-044` (`VALIDATION.md` `MEM-VC-3`).

/// Serpent's eight 4-bit S-boxes (Serpent specification, Appendix A).
const SBOX: [[u8; 16]; 8] = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
];

/// The inverse of S-box 3, for the cheap rejection in [`verify_schedule_at`].
const INV_SBOX3: [u8; 16] = {
    let mut inv = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        inv[SBOX[3][i] as usize] = i as u8;
        i += 1;
    }
    inv
};

/// The golden-ratio constant of the key schedule.
const PHI: u32 = 0x9e37_79b9;

/// Words in the expanded schedule: the key (8), then 33 subkeys of four words, then padding to 140.
pub const SCHEDULE_WORDS: usize = 140;

/// Bytes of the schedule that carry meaning: the key and the 132 subkey words.
pub const SCHEDULE_BYTES: usize = (8 + 132) * 4;

/// Apply S-box `s` to four words bit-sliced: bit `b` of the four words is one nibble.
fn sbox_sliced(s: usize, w: [u32; 4]) -> [u32; 4] {
    let mut out = [0u32; 4];
    for b in 0..32 {
        let nibble = ((w[0] >> b) & 1)
            | (((w[1] >> b) & 1) << 1)
            | (((w[2] >> b) & 1) << 2)
            | (((w[3] >> b) & 1) << 3);
        let r = u32::from(SBOX[s][nibble as usize]);
        for (t, o) in out.iter_mut().enumerate() {
            *o |= ((r >> t) & 1) << b;
        }
    }
    out
}

/// Expand a 256-bit key into Gladman's 140-word schedule.
pub fn expand_key(key: &[u8; 32]) -> [u32; SCHEDULE_WORDS] {
    let mut l = [0u32; SCHEDULE_WORDS];
    for (i, w) in l.iter_mut().take(8).enumerate() {
        *w = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    // Prekeys: w[i] = (w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ i) <<< 11.
    for i in 0..132 {
        let lk = l[i] ^ l[i + 3] ^ l[i + 5] ^ l[i + 7] ^ PHI ^ (i as u32);
        l[i + 8] = lk.rotate_left(11);
    }
    // Subkeys: block j of four prekeys goes through S-box (3 - j) mod 8, bit-sliced.
    for j in 0..33 {
        let s = (3usize.wrapping_sub(j)) % 8;
        let base = 8 + 4 * j;
        let sliced = sbox_sliced(s, [l[base], l[base + 1], l[base + 2], l[base + 3]]);
        l[base..base + 4].copy_from_slice(&sliced);
    }
    l
}

/// A Serpent-256 schedule found in a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSerpentKey {
    /// Byte offset in the scanned buffer where the schedule begins (the key's first byte).
    pub offset: usize,
    /// The 32-byte key.
    pub key: [u8; 32],
}

/// Whether the bytes at `offset` are a Serpent-256 schedule: the first 32 bytes are the key and the
/// next 528 are what the key schedule makes of it.
///
/// Called at every four-byte offset of a scan, so it is cheap on a miss: the first derived word is
/// compared before anything else is computed.
pub fn verify_schedule_at(buf: &[u8], offset: usize) -> Option<RecoveredSerpentKey> {
    let end = offset.checked_add(SCHEDULE_BYTES)?;
    let region = buf.get(offset..end)?;
    let word = |i: usize| {
        u32::from_le_bytes([
            region[4 * i],
            region[4 * i + 1],
            region[4 * i + 2],
            region[4 * i + 3],
        ])
    };
    // A schedule of all-zero or all-equal words is a page of zeros, not a key.
    if (1..8).all(|i| word(i) == word(0)) {
        return None;
    }
    // The first subkey block is the cheap discriminator: its four words are the first four prekeys
    // through S-box 3, and the S-box acts on each bit column alone, so a few columns decide a miss
    // without computing the 32.
    let mut w = [0u32; 8];
    for (i, x) in w.iter_mut().enumerate() {
        *x = word(i);
    }
    let mut pre = [0u32; 4];
    let mut l = [0u32; 12];
    l[..8].copy_from_slice(&w);
    for i in 0..4 {
        let lk = l[i] ^ l[i + 3] ^ l[i + 5] ^ l[i + 7] ^ PHI ^ (i as u32);
        l[i + 8] = lk.rotate_left(11);
        pre[i] = l[i + 8];
    }
    for b in 0..4 {
        let stored = ((word(8) >> b) & 1)
            | (((word(9) >> b) & 1) << 1)
            | (((word(10) >> b) & 1) << 2)
            | (((word(11) >> b) & 1) << 3);
        let expect = INV_SBOX3[stored as usize];
        let have = ((pre[0] >> b) & 1)
            | (((pre[1] >> b) & 1) << 1)
            | (((pre[2] >> b) & 1) << 2)
            | (((pre[3] >> b) & 1) << 3);
        if u32::from(expect) != have {
            return None;
        }
    }
    if sbox_sliced(3, pre) != [word(8), word(9), word(10), word(11)] {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&region[..32]);
    let want = expand_key(&key);
    (0..140 - 8)
        .all(|i| word(8 + i) == want[8 + i])
        .then_some(RecoveredSerpentKey { offset, key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Vec<([u8; 32], Vec<u32>)> {
        let v: Value =
            serde_json::from_str(include_str!("../tests/fixtures/serpent_schedules.json")).unwrap();
        v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let key: Vec<u8> = (0..32)
                    .map(|i| {
                        u8::from_str_radix(&e["key"].as_str().unwrap()[2 * i..2 * i + 2], 16)
                            .unwrap()
                    })
                    .collect();
                let sched = e["schedule"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|w| u32::from_str_radix(w.as_str().unwrap(), 16).unwrap())
                    .collect();
                (key.try_into().unwrap(), sched)
            })
            .collect()
    }

    /// Twelve keys: the expansion equals Gladman's, which is what VeraCrypt keeps.
    #[test]
    fn the_expansion_equals_pyserpents_on_twelve_keys() {
        for (key, want) in vectors() {
            let got = expand_key(&key);
            assert_eq!(&got[..], &want[..], "key {key:02x?}");
        }
    }

    #[test]
    fn a_schedule_in_a_buffer_is_found_at_its_offset_and_a_neighbour_is_not() {
        let (key, _) = vectors().remove(5);
        let sched = expand_key(&key);
        let mut buf = vec![0xA5u8; 4096];
        for (i, w) in sched.iter().enumerate() {
            buf[100 + 4 * i..104 + 4 * i].copy_from_slice(&w.to_le_bytes());
        }
        assert_eq!(
            verify_schedule_at(&buf, 100),
            Some(RecoveredSerpentKey { offset: 100, key })
        );
        assert_eq!(verify_schedule_at(&buf, 104), None);
        assert_eq!(verify_schedule_at(&buf, 96), None);
    }

    #[test]
    fn a_schedule_with_one_word_wrong_is_not_a_schedule() {
        let (key, _) = vectors().remove(3);
        let sched = expand_key(&key);
        let mut buf = vec![0u8; 1024];
        for (i, w) in sched.iter().enumerate().take(140) {
            buf[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        assert!(verify_schedule_at(&buf, 0).is_some());
        buf[4 * 130] ^= 1;
        assert!(verify_schedule_at(&buf, 0).is_none());
    }

    #[test]
    fn zeros_and_short_buffers_are_not_schedules() {
        assert_eq!(verify_schedule_at(&vec![0u8; 4096], 0), None);
        assert_eq!(verify_schedule_at(&[1u8; 100], 0), None);
    }
}
