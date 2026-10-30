//! Recover Camellia-256 keys from a memory image by the key-dependent words of their key table.
//!
//! VeraCrypt (1.22 and later) keeps a mounted Camellia volume's key table as 68 little-endian 32-bit
//! words, 272 bytes, in the `CRYPTO_INFO` (observed on VeraCrypt 1.26.29, Windows 11; `VALIDATION.md`
//! `MEM-VC-4`). Read as 34 64-bit subkeys in the order of RFC 3713 (`kw1 kw2 k1..k6 ke1 ke2 k7..k12 ke3
//! ke4 k13..k18 ke5 ke6 k19..k24 kw3 kw4`), the six `ke` subkeys are stored as the RFC defines them and
//! every other subkey has the whitening keys absorbed into it (the optimisation of the NTT and Linux
//! implementations). The raw key is not stored, but the `ke` subkeys give it back:
//! `ke1 ke2 = KR <<< 30`, `ke3 ke4 = KL <<< 60` and `ke5 ke6 = KA <<< 77`, where the key is `KL || KR`
//! and `KA` is what four Feistel rounds under the RFC's constants make of `KL` and `KR`. The key is
//! recovered from the first two pairs and the third pair must equal the `KA` computed from it, a 128-bit
//! check, so a hit is a real table and the recovered bytes are the real key. **The other subkeys are not
//! checked**: the match is on the three `ke` pairs.
//!
//! Written from RFC 3713. Graded against `scripts/oracle/camellia_schedule.py` (which passes the RFC's
//! published ciphertext for the 256-bit example key) on twelve keys
//! (`tests/fixtures/camellia_schedules.json`) and against three real tables read from a Windows 11
//! capture of mounted volumes (`tests/fixtures/camellia_real_tables.json`).

/// The S-box `s1` (RFC 3713 section 2.4.3); `s2`, `s3` and `s4` are rotations and an index rotation of it.
const S1: [u8; 256] = [
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65, 35, 239, 107, 147,
    69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189, 134, 184, 175, 143, 124, 235, 31, 206, 62,
    48, 220, 95, 94, 197, 11, 26, 166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108,
    77, 139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153, 223, 76, 203,
    194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215, 20, 88, 58, 97, 222, 27, 17, 28, 50,
    15, 156, 22, 83, 24, 242, 34, 254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252,
    105, 80, 170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210, 16, 196,
    0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148, 135, 92, 131, 2, 205, 74, 144,
    51, 115, 103, 246, 243, 157, 127, 191, 226, 82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111,
    75, 19, 190, 99, 46, 233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180,
    89, 120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250, 114, 7, 185, 85,
    248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164, 64, 40, 211, 123, 187, 201, 67, 193, 21,
    227, 173, 244, 119, 199, 128, 158,
];

const SIGMA: [u64; 4] = [
    0xA09E_667F_3BCC_908B,
    0xB67A_E858_4CAA_73B2,
    0xC6EF_372F_E94F_82BE,
    0x54FF_53A5_F1D3_6F1C,
];

/// Bytes of the key table.
pub const TABLE_BYTES: usize = 272;

fn s2(x: u8) -> u8 {
    S1[x as usize].rotate_left(1)
}

fn s3(x: u8) -> u8 {
    S1[x as usize].rotate_left(7)
}

fn s4(x: u8) -> u8 {
    S1[x.rotate_left(1) as usize]
}

/// The round function `F` (RFC 3713 section 2.4.1).
fn f(input: u64, key: u64) -> u64 {
    let x = (input ^ key).to_be_bytes();
    let t1 = S1[x[0] as usize];
    let t2 = s2(x[1]);
    let t3 = s3(x[2]);
    let t4 = s4(x[3]);
    let t5 = s2(x[4]);
    let t6 = s3(x[5]);
    let t7 = s4(x[6]);
    let t8 = S1[x[7] as usize];
    u64::from_be_bytes([
        t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8,
        t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8,
        t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8,
        t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7,
        t1 ^ t2 ^ t6 ^ t7 ^ t8,
        t2 ^ t3 ^ t5 ^ t7 ^ t8,
        t3 ^ t4 ^ t5 ^ t6 ^ t8,
        t1 ^ t4 ^ t5 ^ t6 ^ t7,
    ])
}

/// `KA` of the key `KL || KR` (RFC 3713 section 2.2, the first four Feistel rounds).
pub fn derive_ka(kl: u128, kr: u128) -> u128 {
    let x = kl ^ kr;
    let (mut d1, mut d2) = ((x >> 64) as u64, x as u64);
    d2 ^= f(d1, SIGMA[0]);
    d1 ^= f(d2, SIGMA[1]);
    d1 ^= (kl >> 64) as u64;
    d2 ^= kl as u64;
    d2 ^= f(d1, SIGMA[2]);
    d1 ^= f(d2, SIGMA[3]);
    (u128::from(d1) << 64) | u128::from(d2)
}

/// The six `ke` subkeys of a key (`ke1 ke2 = KR <<< 30`, `ke3 ke4 = KL <<< 60`, `ke5 ke6 = KA <<< 77`), the
/// part of the in-memory table that is stored as the RFC defines it and that [`verify_table_at`] reads back.
pub fn ke_words(key: &[u8; 32]) -> [u64; 6] {
    let kl = u128::from_be_bytes(key[..16].try_into().expect("16 bytes"));
    let kr = u128::from_be_bytes(key[16..].try_into().expect("16 bytes"));
    let ka = derive_ka(kl, kr);
    let pair = |v: u128| [(v >> 64) as u64, v as u64];
    let [a, b] = pair(kr.rotate_left(30));
    let [c, d] = pair(kl.rotate_left(60));
    let [e, f] = pair(ka.rotate_left(77));
    [a, b, c, d, e, f]
}

/// A key recovered from a table in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCamelliaKey {
    /// Offset in the buffer of the table's first word.
    pub offset: usize,
    pub key: [u8; 32],
}

/// Subkey `i` of the table: two little-endian 32-bit words, high then low.
fn subkey(region: &[u8], i: usize) -> u64 {
    let word = |at: usize| {
        u32::from_le_bytes([region[at], region[at + 1], region[at + 2], region[at + 3]])
    };
    (u64::from(word(8 * i)) << 32) | u64::from(word(8 * i + 4))
}

/// Subkey `i` of the table as one little-endian 64-bit word (VeraCrypt 1.19's encoding).
fn subkey_le64(region: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(region[8 * i..8 * i + 8].try_into().expect("eight bytes"))
}

/// The check both encodings share: `KR` from `ke1 ke2`, `KL` from `ke3 ke4`, and the `KA` computed from them
/// must be what `ke5 ke6` hold.
fn verify_with(
    buf: &[u8],
    offset: usize,
    subkey: fn(&[u8], usize) -> u64,
) -> Option<RecoveredCamelliaKey> {
    let end = offset.checked_add(TABLE_BYTES)?;
    let region = buf.get(offset..end)?;
    let pair =
        |a: usize, b: usize| (u128::from(subkey(region, a)) << 64) | u128::from(subkey(region, b));
    let kr = pair(8, 9).rotate_right(30);
    let kl = pair(16, 17).rotate_right(60);
    if kl == 0 || kr == 0 {
        return None;
    }
    let ka = derive_ka(kl, kr);
    if ka.rotate_left(77) != pair(24, 25) {
        return None;
    }
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&kl.to_be_bytes());
    key[16..].copy_from_slice(&kr.to_be_bytes());
    Some(RecoveredCamelliaKey { offset, key })
}

/// Whether the bytes at `offset` are a Camellia-256 key table and, if so, the key.
///
/// `KR` comes from `ke1 ke2`, `KL` from `ke3 ke4`, and `KA` computed from them must be what `ke5 ke6` hold.
/// Called at every four-byte offset of a scan: four evaluations of `F` on a miss.
pub fn verify_table_at(buf: &[u8], offset: usize) -> Option<RecoveredCamelliaKey> {
    verify_with(buf, offset, subkey)
}

/// The same table in VeraCrypt 1.19's encoding (`VALIDATION.md` `MEM-VC-7`): the 34 subkeys of RFC 3713 in the same
/// order and at the same offsets, each stored as one little-endian 64-bit word, and every subkey (the `ke` ones
/// included) as the RFC defines it, with no whitening absorbed. The three `ke` pairs give the key back the same way.
/// 1.21 and later use the encoding of [`verify_table_at`].
pub fn verify_table_le64_at(buf: &[u8], offset: usize) -> Option<RecoveredCamelliaKey> {
    verify_with(buf, offset, subkey_le64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn key(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// A table whose six `ke` subkeys are `ke` and whose other words are `fill`.
    fn table(ke: &[u64], fill: u8) -> Vec<u8> {
        let mut t = vec![fill; TABLE_BYTES];
        for (slot, k) in [8, 9, 16, 17, 24, 25].iter().zip(ke) {
            t[8 * slot..8 * slot + 4].copy_from_slice(&((k >> 32) as u32).to_le_bytes());
            t[8 * slot + 4..8 * slot + 8].copy_from_slice(&(*k as u32).to_le_bytes());
        }
        t
    }

    fn fixture() -> Vec<Value> {
        serde_json::from_str(include_str!("../tests/fixtures/camellia_schedules.json")).unwrap()
    }

    /// The reference's KA for twelve keys, the RFC 3713 example key first.
    #[test]
    fn ka_agrees_with_the_reference_script_on_twelve_keys() {
        let v = fixture();
        assert_eq!(v.len(), 12);
        for row in &v {
            let k = key(row["key"].as_str().unwrap());
            let kl = u128::from_be_bytes(k[..16].try_into().unwrap());
            let kr = u128::from_be_bytes(k[16..].try_into().unwrap());
            let want = u128::from_str_radix(row["ka"].as_str().unwrap(), 16).unwrap();
            assert_eq!(derive_ka(kl, kr), want, "{}", row["key"]);
        }
    }

    /// The forward map agrees with the reference script's `ke` subkeys.
    #[test]
    fn ke_words_agree_with_the_reference_script() {
        for row in &fixture() {
            let want: Vec<u64> = row["ke"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| u64::from_str_radix(x.as_str().unwrap(), 16).unwrap())
                .collect();
            assert_eq!(ke_words(&key(row["key"].as_str().unwrap())).to_vec(), want);
        }
    }

    #[test]
    fn a_table_with_the_three_ke_pairs_gives_back_its_key() {
        for row in &fixture() {
            let ke: Vec<u64> = row["ke"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| u64::from_str_radix(x.as_str().unwrap(), 16).unwrap())
                .collect();
            let t = table(&ke, 0x6B);
            let found = verify_table_at(&t, 0).expect("the table verifies");
            assert_eq!(found.key, key(row["key"].as_str().unwrap()));
        }
    }

    /// Three real tables from a Windows 11 capture of VeraCrypt 1.26.29 with Camellia volumes mounted.
    #[test]
    fn real_tables_from_a_veracrypt_capture_give_the_volume_keys() {
        let v: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/camellia_real_tables.json"))
                .unwrap();
        assert_eq!(v.len(), 3);
        for row in &v {
            let t = unhex(row["table"].as_str().unwrap());
            assert_eq!(t.len(), TABLE_BYTES);
            let found = verify_table_at(&t, 0).expect("a real table verifies");
            assert_eq!(found.key, key(row["key"].as_str().unwrap()));
        }
    }

    #[test]
    fn found_at_an_offset_and_a_short_tail_is_not_a_table() {
        let row = &fixture()[0];
        let ke: Vec<u64> = row["ke"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| u64::from_str_radix(x.as_str().unwrap(), 16).unwrap())
            .collect();
        let mut buf = vec![0x33u8; 900];
        buf[300..300 + TABLE_BYTES].copy_from_slice(&table(&ke, 0x6B));
        assert_eq!(verify_table_at(&buf, 300).unwrap().offset, 300);
        assert!(verify_table_at(&buf, 304).is_none());
        assert!(verify_table_at(&buf, 900 - 100).is_none());
    }

    /// One flipped bit in any of the 48 `ke` bytes breaks the 128-bit check; zeros and a repeated byte are not keys.
    #[test]
    fn a_damaged_table_zeros_and_repeats_are_not_keys() {
        let row = &fixture()[1];
        let ke: Vec<u64> = row["ke"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| u64::from_str_radix(x.as_str().unwrap(), 16).unwrap())
            .collect();
        let good = table(&ke, 0x6B);
        for slot in [8usize, 9, 16, 17, 24, 25] {
            for b in 0..8 {
                let mut bad = good.clone();
                bad[8 * slot + b] ^= 0x10;
                assert!(verify_table_at(&bad, 0).is_none(), "slot {slot} byte {b}");
            }
        }
        assert!(verify_table_at(&[0u8; TABLE_BYTES], 0).is_none());
        assert!(verify_table_at(&[0x5Au8; TABLE_BYTES], 0).is_none());
    }

    /// A table in 1.19's encoding: the same slots, each `ke` subkey as one little-endian 64-bit word.
    fn table_le64(ke: &[u64], fill: u8) -> Vec<u8> {
        let mut t = vec![fill; TABLE_BYTES];
        for (slot, k) in [8, 9, 16, 17, 24, 25].iter().zip(ke) {
            t[8 * slot..8 * slot + 8].copy_from_slice(&k.to_le_bytes());
        }
        t
    }

    /// A real table from a Windows 11 capture of VeraCrypt 1.19 (volume `c.hc`, Camellia): its 34 subkeys are the
    /// RFC 3713 schedule of the key, as little-endian 64-bit words. The other encoding does not read it.
    #[test]
    fn a_real_veracrypt_1_19_table_gives_the_volume_key() {
        let v: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/camellia_real_tables_119.json"
        ))
        .unwrap();
        assert_eq!(v.len(), 1);
        for row in &v {
            let t = unhex(row["table"].as_str().unwrap());
            assert_eq!(t.len(), TABLE_BYTES);
            let found = verify_table_le64_at(&t, 0).expect("a real 1.19 table verifies");
            assert_eq!(found.key, key(row["key"].as_str().unwrap()));
            assert!(verify_table_at(&t, 0).is_none());
        }
    }

    #[test]
    fn the_two_encodings_are_not_taken_for_each_other() {
        for row in &fixture() {
            let ke: Vec<u64> = row["ke"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| u64::from_str_radix(x.as_str().unwrap(), 16).unwrap())
                .collect();
            let want = key(row["key"].as_str().unwrap());
            assert_eq!(
                verify_table_le64_at(&table_le64(&ke, 0x6B), 0).unwrap().key,
                want
            );
            assert!(verify_table_at(&table_le64(&ke, 0x6B), 0).is_none());
            assert!(verify_table_le64_at(&table(&ke, 0x6B), 0).is_none());
        }
    }

    #[test]
    fn zeros_repeats_and_short_tails_are_not_le64_tables() {
        assert!(verify_table_le64_at(&[0u8; TABLE_BYTES], 0).is_none());
        assert!(verify_table_le64_at(&[0x5Au8; TABLE_BYTES], 0).is_none());
        assert!(verify_table_le64_at(&[0u8; TABLE_BYTES - 1], 0).is_none());
    }
}
