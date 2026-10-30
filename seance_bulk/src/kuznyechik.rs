//! Recover Kuznyechik (GOST R 34.12-2015) keys from a memory image by their round keys.
//!
//! VeraCrypt (1.22 and later) keeps a mounted Kuznyechik volume's encryption round keys as the first
//! 160 bytes of the cipher's structure in the `CRYPTO_INFO` (observed on VeraCrypt 1.26.29, Windows 11;
//! `VALIDATION.md` `MEM-VC-4`): `K1` and `K2` are the two halves of the 256-bit key, so the raw key is
//! the first 32 bytes, and `K3` to `K10` are what the key schedule makes of them (RFC 7801 section 4.3:
//! four rounds of eight Feistel steps, each step the `LSX` transform under a constant that is `L` of
//! the step number). A candidate is a hit only when all ten round keys agree, so the 32 key bytes are
//! the key and not a coincidence.
//!
//! Written from RFC 7801. Graded against its appendix A round keys (`K1` to `K10` of the published
//! example key) and against `scripts/oracle/kuznyechik_schedule.py` on twelve more keys
//! (`tests/fixtures/kuznyechik_schedules.json`), and against the real structures of two mounted
//! volumes in a Windows 11 capture (`tests/fixtures/kuznyechik_real_schedules.json`).

use std::sync::OnceLock;

/// The non-linear permutation `pi` (RFC 7801 section 4.1.1).
const PI: [u8; 256] = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219,
    147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129,
    28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212,
    211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112,
    14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154,
    199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198,
    128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
    3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115,
    30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
    165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217,
    231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113,
    103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244,
    180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
];

/// The coefficients of the linear function `l` (RFC 7801 section 4.1.2), from `a15` to `a0`.
const LC: [u8; 16] = [
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
];

/// Bytes of the ten round keys.
pub const SCHEDULE_BYTES: usize = 160;

/// Multiply in GF(2^8) modulo `x^8 + x^7 + x^6 + x + 1`.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0xC3;
        }
        b >>= 1;
    }
    r
}

/// One step of `R`: the first byte becomes `l` of all sixteen and the rest shift down.
fn r_step(b: [u8; 16]) -> [u8; 16] {
    let mut x = 0u8;
    for i in 0..16 {
        x ^= gmul(b[i], LC[i]);
    }
    let mut out = [0u8; 16];
    out[0] = x;
    out[1..].copy_from_slice(&b[..15]);
    out
}

/// `L = R^16`, computed directly.
fn l_slow(mut b: [u8; 16]) -> [u8; 16] {
    for _ in 0..16 {
        b = r_step(b);
    }
    b
}

/// `L` of a block that has one non-zero byte, for each position and value: `L` is linear, so `L` of any
/// block is the XOR of the entries for its bytes.
fn l_table() -> &'static Vec<u128> {
    static TABLE: OnceLock<Vec<u128>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = Vec::with_capacity(16 * 256);
        for pos in 0..16 {
            for v in 0..=255u8 {
                let mut b = [0u8; 16];
                b[pos] = v;
                t.push(u128::from_be_bytes(l_slow(b)));
            }
        }
        t
    })
}

/// `LSX[k](a) = L(S(k xor a))`.
fn lsx(table: &[u128], k: u128, a: u128) -> u128 {
    let x = (k ^ a).to_be_bytes();
    let mut out = 0u128;
    for (pos, byte) in x.iter().enumerate() {
        out ^= table[pos * 256 + PI[*byte as usize] as usize];
    }
    out
}

/// The ten round keys of a 256-bit key.
pub fn expand_key(key: &[u8; 32]) -> [[u8; 16]; 10] {
    let table = l_table();
    let mut a1 = u128::from_be_bytes(key[..16].try_into().expect("16 bytes"));
    let mut a0 = u128::from_be_bytes(key[16..].try_into().expect("16 bytes"));
    let mut out = [[0u8; 16]; 10];
    out[0] = a1.to_be_bytes();
    out[1] = a0.to_be_bytes();
    for round in 0..4 {
        for step in 0..8 {
            let c = u128::from_be_bytes(l_slow({
                let mut v = [0u8; 16];
                v[15] = (8 * round + step + 1) as u8;
                v
            }));
            (a1, a0) = (lsx(table, c, a1) ^ a0, a1);
        }
        out[2 * round + 2] = a1.to_be_bytes();
        out[2 * round + 3] = a0.to_be_bytes();
    }
    out
}

/// A key recovered from a schedule in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredKuznyechikKey {
    /// Offset in the buffer of the first round key.
    pub offset: usize,
    pub key: [u8; 32],
}

/// The 32 constants `C1..C32`, computed once.
fn constants() -> &'static [u128; 32] {
    static C: OnceLock<[u128; 32]> = OnceLock::new();
    C.get_or_init(|| {
        let mut c = [0u128; 32];
        for (i, v) in c.iter_mut().enumerate() {
            let mut b = [0u8; 16];
            b[15] = (i + 1) as u8;
            *v = u128::from_be_bytes(l_slow(b));
        }
        c
    })
}

/// Whether the bytes at `offset` are Kuznyechik's ten round keys and, if so, the key.
///
/// Called at every four-byte offset of a scan, so it is cheap on a miss: `K3` and `K4` are computed first
/// (eight Feistel steps) and compared before the other six round keys are.
pub fn verify_schedule_at(buf: &[u8], offset: usize) -> Option<RecoveredKuznyechikKey> {
    let end = offset.checked_add(SCHEDULE_BYTES)?;
    let region = buf.get(offset..end)?;
    let block =
        |i: usize| u128::from_be_bytes(region[16 * i..16 * i + 16].try_into().expect("16 bytes"));
    // A page of zeros or of one repeated block is not a key.
    if block(0) == block(1) || block(0) == 0 || block(1) == 0 {
        return None;
    }
    let table = l_table();
    let c = constants();
    let (mut a1, mut a0) = (block(0), block(1));
    for round in 0..4 {
        for step in 0..8 {
            (a1, a0) = (lsx(table, c[8 * round + step], a1) ^ a0, a1);
        }
        if (a1, a0) != (block(2 * round + 2), block(2 * round + 3)) {
            return None;
        }
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&region[..32]);
    Some(RecoveredKuznyechikKey { offset, key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// RFC 7801 appendix A: the example key and its ten round keys.
    const RFC_KEY: &str = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";
    const RFC_ROUND_KEYS: [&str; 10] = [
        "8899aabbccddeeff0011223344556677",
        "fedcba98765432100123456789abcdef",
        "db31485315694343228d6aef8cc78c44",
        "3d4553d8e9cfec6815ebadc40a9ffd04",
        "57646468c44a5e28d3e59246f429f1ac",
        "bd079435165c6432b532e82834da581b",
        "51e640757e8745de705727265a0098b1",
        "5a7925017b9fdd3ed72a91a22286f984",
        "bb44e25378c73123a5f32f73cdb6e517",
        "72e9dd7416bcf45b755dbaa88e4a4043",
    ];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn key(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn the_rfc_7801_round_keys_are_reproduced() {
        let rks = expand_key(&key(RFC_KEY));
        for (i, want) in RFC_ROUND_KEYS.iter().enumerate() {
            assert_eq!(rks[i].to_vec(), unhex(want), "K{}", i + 1);
        }
    }

    /// Twelve more keys against the pure-Python reference, which passes the same RFC vector.
    #[test]
    fn twelve_keys_agree_with_the_reference_script() {
        let v: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/kuznyechik_schedules.json"))
                .unwrap();
        assert_eq!(v.len(), 12);
        for row in &v {
            let k = key(row["key"].as_str().unwrap());
            let want = unhex(row["round_keys"].as_str().unwrap());
            let got: Vec<u8> = expand_key(&k).concat();
            assert_eq!(got, want, "{}", row["key"]);
            assert_eq!(verify_schedule_at(&want, 0).unwrap().key, k);
        }
    }

    /// Two real structures read out of a Windows 11 capture of VeraCrypt 1.26.29 with Kuznyechik volumes
    /// mounted: the key is the first 32 bytes and every round key agrees.
    #[test]
    fn real_round_keys_from_a_veracrypt_capture_verify() {
        let v: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/kuznyechik_real_schedules.json"
        ))
        .unwrap();
        assert_eq!(v.len(), 2);
        for row in &v {
            let rks = unhex(row["round_keys"].as_str().unwrap());
            let found = verify_schedule_at(&rks, 0).expect("a real schedule verifies");
            assert_eq!(found.key.to_vec(), unhex(row["key"].as_str().unwrap()));
        }
    }

    #[test]
    fn found_at_an_offset_inside_a_larger_buffer() {
        let mut buf = vec![0xA5u8; 1000];
        let rks = expand_key(&key(RFC_KEY)).concat();
        buf[404..404 + SCHEDULE_BYTES].copy_from_slice(&rks);
        let found = verify_schedule_at(&buf, 404).unwrap();
        assert_eq!((found.offset, found.key), (404, key(RFC_KEY)));
        assert!(verify_schedule_at(&buf, 400).is_none());
        assert!(
            verify_schedule_at(&buf, 1000 - 100).is_none(),
            "a short tail is not a schedule"
        );
    }

    /// One flipped bit in any round key (not the key itself) breaks it, and so do zeros and a repeated block.
    #[test]
    fn a_damaged_schedule_zeros_and_repeats_are_not_keys() {
        let rks = expand_key(&key(RFC_KEY)).concat();
        for i in 0..SCHEDULE_BYTES {
            let mut bad = rks.clone();
            bad[i] ^= 0x01;
            assert!(verify_schedule_at(&bad, 0).is_none(), "byte {i}");
        }
        assert!(verify_schedule_at(&[0u8; SCHEDULE_BYTES], 0).is_none());
        assert!(verify_schedule_at(&[0x5Au8; SCHEDULE_BYTES], 0).is_none());
    }
}
