//! Recover Twofish-256 keys from a memory image by their key schedules.
//!
//! VeraCrypt (like TrueCrypt) keeps a mounted Twofish volume's key schedule in the `CRYPTO_INFO`
//! as two pieces laid end to end (observed on VeraCrypt 1.25.9, Windows 11; `VALIDATION.md` `MEM-VC-3`):
//! the four key-dependent S-box tables, 4 x 256 words (4,096 bytes), then the 40 round subkeys
//! `K[0..39]` (160 bytes). The raw key is stored nowhere, so unlike AES and Serpent it cannot be
//! read off the schedule's first bytes. It can be *recovered* from it: the subkeys are a function of
//! the key's even and odd 32-bit words through the `h` function (a keyed byte permutation per byte lane
//! followed by the MDS matrix), and `h` can be inverted lane by lane by a search over four key bytes
//! per lane. The recovered key is then expanded forward and must reproduce the whole 4,256-byte
//! structure word for word, so a hit is a real schedule and the recovered bytes are the real key.
//!
//! Written from the Twofish paper (Schneier, Kelsey, Whiting, Wagner, Hall and Ferguson). Graded
//! against Niels Ferguson's reference library (`K[40]`) and against `scripts/oracle/twofish_schedule.py`
//! (the same key schedule, plus the table layout read off real memory) on twelve keys
//! (`tests/fixtures/twofish_schedules.json`), and against a real mounted Twofish cascade in the
//! Windows 11 capture of `MEM-044`.

/// The two 4-bit-table definitions of the `q0` and `q1` byte permutations (paper section 4.3.5).
const T: [[[u8; 16]; 4]; 2] = [
    [
        [
            0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4,
        ],
        [
            0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD,
        ],
        [
            0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1,
        ],
        [
            0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA,
        ],
    ],
    [
        [
            0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5,
        ],
        [
            0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8,
        ],
        [
            0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF,
        ],
        [
            0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA,
        ],
    ],
];

const fn ror4(x: u8, n: u32) -> u8 {
    ((x >> n) | (x << (4 - n))) & 0xF
}

const fn q_entry(which: usize, x: u8) -> u8 {
    let t = &T[which];
    let (a0, b0) = (x >> 4, x & 15);
    let a1 = a0 ^ b0;
    let b1 = (a0 ^ ror4(b0, 1) ^ ((8 * a0) & 15)) & 15;
    let (a2, b2) = (t[0][a1 as usize], t[1][b1 as usize]);
    let a3 = a2 ^ b2;
    let b3 = (a2 ^ ror4(b2, 1) ^ ((8 * a2) & 15)) & 15;
    let (a4, b4) = (t[2][a3 as usize], t[3][b3 as usize]);
    (b4 << 4) | a4
}

const fn q_table(which: usize) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        out[x] = q_entry(which, x as u8);
        x += 1;
    }
    out
}

const fn q_inverse(t: &[u8; 256]) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        out[t[x] as usize] = x as u8;
        x += 1;
    }
    out
}

const Q0: [u8; 256] = q_table(0);
const Q1: [u8; 256] = q_table(1);
const Q0_INV: [u8; 256] = q_inverse(&Q0);
const Q1_INV: [u8; 256] = q_inverse(&Q1);

/// The MDS matrix (field polynomial `x^8 + x^6 + x^5 + x^3 + 1`, 0x169).
const MDS: [[u8; 4]; 4] = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
];

/// The Reed-Solomon matrix (field polynomial `x^8 + x^6 + x^3 + x^2 + 1`, 0x14D).
const RS: [[u8; 8]; 4] = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
];

const fn gf_mul(mut a: u8, mut b: u8, poly: u16) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= (poly & 0xFF) as u8;
        }
        b >>= 1;
    }
    r
}

const fn mul_table(m: u8) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut y = 0;
    while y < 256 {
        out[y] = gf_mul(m, y as u8, 0x169);
        y += 1;
    }
    out
}

/// The MDS coefficients 0x5B and 0xEF times every byte.
const MUL_5B: [u8; 256] = mul_table(0x5B);
const MUL_EF: [u8; 256] = mul_table(0xEF);

/// For each byte lane of `h` (key size 256 bits), the five permutations applied in order: the
/// first four are each followed by an XOR with a key byte (`L3`, `L2`, `L1`, `L0`), the fifth is last.
const LANES: [[&[u8; 256]; 5]; 4] = [
    [&Q1, &Q1, &Q0, &Q0, &Q1],
    [&Q0, &Q1, &Q1, &Q0, &Q0],
    [&Q0, &Q0, &Q0, &Q1, &Q1],
    [&Q1, &Q0, &Q1, &Q1, &Q0],
];

/// Lane `j` of `h` on byte `x` with the key bytes `l` (`l[0]` is `L0`'s byte, `l[3]` `L3`'s).
fn lane(j: usize, x: u8, l: [u8; 4]) -> u8 {
    let q = &LANES[j];
    q[4][(q[3][(q[2][(q[1][(q[0][x as usize] ^ l[3]) as usize] ^ l[2]) as usize] ^ l[1]) as usize]
        ^ l[0]) as usize]
}

fn mds_apply(y: [u8; 4]) -> u32 {
    let mut z = 0u32;
    for (r, row) in MDS.iter().enumerate() {
        let mut v = 0u8;
        for (c, m) in row.iter().enumerate() {
            v ^= gf_mul(*m, y[c], 0x169);
        }
        z |= u32::from(v) << (8 * r);
    }
    z
}

/// `h(x, L)` for a 256-bit key: `L` is `(L0, L1, L2, L3)`.
fn h(x: u32, l: [u32; 4]) -> u32 {
    let mut y = [0u8; 4];
    for (j, yj) in y.iter_mut().enumerate() {
        let lb = [
            (l[0] >> (8 * j)) as u8,
            (l[1] >> (8 * j)) as u8,
            (l[2] >> (8 * j)) as u8,
            (l[3] >> (8 * j)) as u8,
        ];
        *yj = lane(j, (x >> (8 * j)) as u8, lb);
    }
    mds_apply(y)
}

fn le_word(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// The round subkeys `K[0..39]` of a 256-bit key.
pub fn subkeys(key: &[u8; 32]) -> [u32; 40] {
    let m: Vec<u32> = (0..8).map(|i| le_word(&key[4 * i..])).collect();
    let me = [m[0], m[2], m[4], m[6]];
    let mo = [m[1], m[3], m[5], m[7]];
    let mut k = [0u32; 40];
    for i in 0..20u32 {
        let a = h(2 * i * 0x0101_0101, me);
        let b = h((2 * i + 1) * 0x0101_0101, mo).rotate_left(8);
        k[2 * i as usize] = a.wrapping_add(b);
        k[2 * i as usize + 1] = a.wrapping_add(b.wrapping_mul(2)).rotate_left(9);
    }
    k
}

/// The four S-vector words `S_0..S_3` (Reed-Solomon of each eight key bytes).
pub fn s_vector(key: &[u8; 32]) -> [u32; 4] {
    let mut s = [0u32; 4];
    for (i, si) in s.iter_mut().enumerate() {
        for (r, row) in RS.iter().enumerate() {
            let mut acc = 0u8;
            for (c, m) in row.iter().enumerate() {
                acc ^= gf_mul(*m, key[8 * i + c], 0x14D);
            }
            *si |= u32::from(acc) << (8 * r);
        }
    }
    s
}

/// VeraCrypt's four key-dependent S-box tables for a key: table `j`, entry `x` is MDS column `j` times
/// lane `j` of `x` keyed by the S vector taken in reverse.
pub fn mk_tab(key: &[u8; 32]) -> Vec<u32> {
    let s = s_vector(key);
    let l = [s[3], s[2], s[1], s[0]];
    let mut out = Vec::with_capacity(1024);
    for j in 0..4 {
        let lb = [
            (l[0] >> (8 * j)) as u8,
            (l[1] >> (8 * j)) as u8,
            (l[2] >> (8 * j)) as u8,
            (l[3] >> (8 * j)) as u8,
        ];
        for x in 0..=255u8 {
            let mut y = [0u8; 4];
            y[j] = lane(j, x, lb);
            out.push(mds_apply(y));
        }
    }
    out
}

/// The whole in-memory structure of a Twofish-256 key: the tables, then the subkeys.
pub const STRUCT_BYTES: usize = (1024 + 40) * 4;

/// Recover the key from `K[0..39]` alone, or `None` if no 256-bit key makes them.
///
/// The subkeys are `A_i + B_i` and `ROL(A_i + 2 B_i, 9)` with `A_i = h(2i*rho, Me)` and
/// `B_i = ROL(h((2i+1)*rho, Mo), 8)`, so each `A_i` and `h`-of-`Mo` value follows from a pair of subkeys.
/// `h` is the MDS matrix over four byte lanes, each a keyed byte permutation of `x = 2i` (or `2i + 1`,
/// the same byte in every lane); the MDS matrix is inverted and each lane is solved for its four key
/// bytes by searching the outer two and the inner one, which fixes the last.
pub fn recover_key(k: &[u32; 40]) -> Option<[u8; 32]> {
    let mds_inv = mds_inverse();
    // y[half][i][lane] for half 0 = Me (A values), half 1 = Mo (rotated B values).
    let mut y = [[[0u8; 4]; 20]; 2];
    for i in 0..20 {
        let b = k[2 * i + 1].rotate_right(9).wrapping_sub(k[2 * i]);
        let a = k[2 * i].wrapping_sub(b);
        for (half, z) in [(0usize, a), (1usize, b.rotate_right(8))] {
            let zb = z.to_le_bytes();
            for (lane_j, row) in mds_inv.iter().enumerate() {
                let mut v = 0u8;
                for (m, b) in row.iter().zip(&zb) {
                    v ^= gf_mul(*m, *b, 0x169);
                }
                y[half][i][lane_j] = v;
            }
        }
    }
    let mut me = [0u32; 4];
    let mut mo = [0u32; 4];
    for (half, ys) in y.iter().enumerate() {
        for j in 0..4 {
            let points: Vec<(u8, u8)> = ys
                .iter()
                .enumerate()
                .map(|(i, lanes)| ((2 * i + half) as u8, lanes[j]))
                .collect();
            let l = solve_lane(j, &points)?;
            for (idx, byte) in l.iter().enumerate() {
                let word = if half == 0 {
                    &mut me[idx]
                } else {
                    &mut mo[idx]
                };
                *word |= u32::from(*byte) << (8 * j);
            }
        }
    }
    let mut key = [0u8; 32];
    for i in 0..4 {
        key[8 * i..8 * i + 4].copy_from_slice(&me[i].to_le_bytes());
        key[8 * i + 4..8 * i + 8].copy_from_slice(&mo[i].to_le_bytes());
    }
    (subkeys(&key) == *k).then_some(key)
}

/// The inverse of the MDS matrix over GF(2^8), found by Gauss-Jordan.
fn mds_inverse() -> [[u8; 4]; 4] {
    let mut a = [[0u8; 8]; 4];
    for r in 0..4 {
        a[r][..4].copy_from_slice(&MDS[r]);
        a[r][4 + r] = 1;
    }
    for col in 0..4 {
        let piv = (col..4)
            .find(|&r| a[r][col] != 0)
            .expect("the MDS matrix is invertible");
        a.swap(col, piv);
        let inv = (1..=255u8)
            .find(|&x| gf_mul(a[col][col], x, 0x169) == 1)
            .expect("a field element has an inverse");
        for v in a[col].iter_mut() {
            *v = gf_mul(*v, inv, 0x169);
        }
        let pivot_row = a[col];
        for (r, row) in a.iter_mut().enumerate() {
            if r != col && row[col] != 0 {
                let f = row[col];
                for (v, p) in row.iter_mut().zip(&pivot_row) {
                    *v ^= gf_mul(f, *p, 0x169);
                }
            }
        }
    }
    let mut out = [[0u8; 4]; 4];
    for r in 0..4 {
        out[r].copy_from_slice(&a[r][4..]);
    }
    out
}

/// Find the four key bytes `(L0, L1, L2, L3)` of lane `j` that map every `(x, y)` point.
///
/// `y = Qe[Qd[Qc[Qb[Qa[x] ^ L3] ^ L2] ^ L1] ^ L0]`. With `u = Qe^-1[y]`, two points give
/// `u0 ^ u1 = Qd[c0 ^ L1] ^ Qd[c1 ^ L1]` where `c = Qc[Qb[Qa[x] ^ L3] ^ L2]`: a search over `L3`, `L2`
/// and `L1` that fixes `L0`, then every point is checked. `None` unless exactly one solution exists.
fn solve_lane(j: usize, points: &[(u8, u8)]) -> Option<[u8; 4]> {
    let q = &LANES[j];
    let qe_inv: &[u8; 256] = if std::ptr::eq(q[4], &Q0) {
        &Q0_INV
    } else {
        &Q1_INV
    };
    let u: Vec<u8> = points.iter().map(|&(_, y)| qe_inv[y as usize]).collect();
    let mut found: Option<[u8; 4]> = None;
    for l3 in 0..=255u8 {
        for l2 in 0..=255u8 {
            let c: Vec<u8> = points
                .iter()
                .map(|&(x, _)| q[2][(q[1][(q[0][x as usize] ^ l3) as usize] ^ l2) as usize])
                .collect();
            for l1 in 0..=255u8 {
                let d0 = q[3][(c[0] ^ l1) as usize];
                if d0 ^ q[3][(c[1] ^ l1) as usize] != u[0] ^ u[1] {
                    continue;
                }
                let l0 = u[0] ^ d0;
                if c.iter()
                    .zip(&u)
                    .all(|(&ci, &ui)| q[3][(ci ^ l1) as usize] ^ l0 == ui)
                {
                    if found.is_some() {
                        return None;
                    }
                    found = Some([l0, l1, l2, l3]);
                }
            }
        }
    }
    found
}

/// A Twofish-256 schedule found in a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredTwofishKey {
    /// Offset in the buffer of the first S-box table word (the structure's start).
    pub offset: usize,
    /// The recovered 32-byte key.
    pub key: [u8; 32],
}

/// Whether the bytes at `offset` are a Twofish-256 schedule (the four tables, then the subkeys) and, if
/// so, the key. The first table's low bytes must be a permutation of 0..=255 (the lane-0 output is one,
/// and its MDS coefficient is 1), which a random region fails within a few words; only then is the key
/// recovered from the subkeys and the whole structure checked against it.
pub fn verify_schedule_at(buf: &[u8], offset: usize) -> Option<RecoveredTwofishKey> {
    let end = offset.checked_add(STRUCT_BYTES)?;
    let region = buf.get(offset..end)?;
    // Every entry of table 0 is MDS column 0 times one byte y: the word's bytes are (y, 5B.y, EF.y, EF.y).
    // That is checked on the first words before anything else, so a region that is merely a table of counters
    // (whose low bytes are distinct too) never reaches the key recovery.
    for i in 0..8 {
        let w = &region[4 * i..4 * i + 4];
        if w[1] != MUL_5B[w[0] as usize] || w[2] != MUL_EF[w[0] as usize] || w[3] != w[2] {
            return None;
        }
    }
    // Four u64 as a 256-bit set: this runs at every word offset of a scan, so it must be cheap.
    let mut seen = [0u64; 4];
    for i in 0..256 {
        let low = region[4 * i] as usize;
        let (word, bit) = (low >> 6, 1u64 << (low & 63));
        if seen[word] & bit != 0 {
            return None;
        }
        seen[word] |= bit;
    }
    let mut k = [0u32; 40];
    for (i, w) in k.iter_mut().enumerate() {
        *w = le_word(&region[4096 + 4 * i..]);
    }
    let key = recover_key(&k)?;
    let want = mk_tab(&key);
    (0..1024)
        .all(|i| le_word(&region[4 * i..]) == want[i])
        .then_some(RecoveredTwofishKey { offset, key })
}

/// VeraCrypt 1.19's Twofish structure (`VALIDATION.md` `MEM-VC-7`): the same data as [`verify_schedule_at`] reads, in
/// the opposite order, the 40 subkeys first and then the four tables (the same `STRUCT_BYTES`). Observed on a mounted
/// volume of 1.19; 1.21 and later put the tables first.
///
/// The first table words are checked for their shape before the key is recovered from the subkeys, and the recovered
/// key must reproduce every table word.
pub fn verify_subkeys_first_schedule_at(buf: &[u8], offset: usize) -> Option<RecoveredTwofishKey> {
    let end = offset.checked_add(STRUCT_BYTES)?;
    let region = buf.get(offset..end)?;
    let tables = &region[160..];
    for i in 0..8 {
        let w = &tables[4 * i..4 * i + 4];
        if w[1] != MUL_5B[w[0] as usize] || w[2] != MUL_EF[w[0] as usize] || w[3] != w[2] {
            return None;
        }
    }
    let mut seen = [0u64; 4];
    for i in 0..256 {
        let low = tables[4 * i] as usize;
        let (word, bit) = (low >> 6, 1u64 << (low & 63));
        if seen[word] & bit != 0 {
            return None;
        }
        seen[word] |= bit;
    }
    let mut k = [0u32; 40];
    for (i, w) in k.iter_mut().enumerate() {
        *w = le_word(&region[4 * i..]);
    }
    let key = recover_key(&k)?;
    let want = mk_tab(&key);
    (0..1024)
        .all(|i| le_word(&tables[4 * i..]) == want[i])
        .then_some(RecoveredTwofishKey { offset, key })
}

/// TrueCrypt 7.1a's whole Twofish structure: `l_key[40]`, `s_key[4]` and the four tables interleaved.
pub const TC_STRUCT_BYTES: usize = (40 + 4 + 1024) * 4;

/// Whether the bytes at `offset` are a Twofish-256 structure in TrueCrypt 7.1a's order and, if so, the key.
///
/// TrueCrypt (Brian Gladman's Twofish) stores `l_key[40]` (the subkeys), then `s_key[4]` (the `S` vector,
/// reversed) and then `mk_tab[4 * 256]` with entry `x` of table `j` at index `4x + j` (observed on a mounted
/// volume, `VALIDATION.md` `MEM-VC-5`). The tables are VeraCrypt's, interleaved. The first table words are
/// checked for their shape before the key is recovered from the subkeys, and the recovered key must reproduce
/// `s_key` and every table word.
pub fn verify_tc_schedule_at(buf: &[u8], offset: usize) -> Option<RecoveredTwofishKey> {
    let end = offset.checked_add(TC_STRUCT_BYTES)?;
    let region = buf.get(offset..end)?;
    // Table 0, entry x, is at word 44 + 4x: a MDS column times one byte, shaped (y, 5B.y, EF.y, EF.y).
    for x in 0..8 {
        let at = 4 * (44 + 4 * x);
        let w = &region[at..at + 4];
        if w[1] != MUL_5B[w[0] as usize] || w[2] != MUL_EF[w[0] as usize] || w[3] != w[2] {
            return None;
        }
    }
    // Table 0's low bytes are a permutation of 0..=255 (the lane-0 output is one and its MDS coefficient is 1):
    // a page of zeros passes the shape test above and must not reach the key recovery, which costs a second.
    let mut seen = [0u64; 4];
    for x in 0..256 {
        let low = region[4 * (44 + 4 * x)] as usize;
        let (word, bit) = (low >> 6, 1u64 << (low & 63));
        if seen[word] & bit != 0 {
            return None;
        }
        seen[word] |= bit;
    }
    let mut k = [0u32; 40];
    for (i, w) in k.iter_mut().enumerate() {
        *w = le_word(&region[4 * i..]);
    }
    let key = recover_key(&k)?;
    let s = s_vector(&key);
    // `s_key` holds S in reverse order.
    if (0..4).any(|i| le_word(&region[4 * (40 + i)..]) != s[3 - i]) {
        return None;
    }
    let want = mk_tab(&key);
    (0..256)
        .all(|x| (0..4).all(|j| le_word(&region[4 * (44 + 4 * x + j)..]) == want[j * 256 + x]))
        .then_some(RecoveredTwofishKey { offset, key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    struct Vector {
        key: [u8; 32],
        k: Vec<u32>,
        s: Vec<u32>,
        mk: Option<Vec<u32>>,
    }

    fn words(v: &Value) -> Vec<u32> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|w| u32::from_str_radix(w.as_str().unwrap(), 16).unwrap())
            .collect()
    }

    fn vectors() -> Vec<Vector> {
        let v: Value =
            serde_json::from_str(include_str!("../tests/fixtures/twofish_schedules.json")).unwrap();
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
                Vector {
                    key: key.try_into().unwrap(),
                    k: words(&e["K"]),
                    s: words(&e["S"]),
                    mk: (!e["mk_tab"].is_null()).then(|| words(&e["mk_tab"])),
                }
            })
            .collect()
    }

    /// The paper's known answer: the all-zero 256-bit key encrypts the zero block to
    /// 57ff739d4dc92c1bd7fc01700cc8216f; the key schedule here is what that cipher runs on.
    /// The check that does not need a cipher: `q0` and `q1` are permutations of the bytes.
    #[test]
    fn q0_and_q1_are_permutations_with_the_documented_first_entries() {
        for q in [&Q0, &Q1] {
            let mut seen = [false; 256];
            for &v in q.iter() {
                seen[v as usize] = true;
            }
            assert!(seen.iter().all(|&s| s));
        }
        // The paper's tables begin 0xA9 0x67 0xB3 0xE8 (q0) and 0x75 0xF3 0xC6 0xF4 (q1).
        assert_eq!(&Q0[..4], &[0xA9, 0x67, 0xB3, 0xE8]);
        assert_eq!(&Q1[..4], &[0x75, 0xF3, 0xC6, 0xF4]);
    }

    #[test]
    fn the_subkeys_equal_the_reference_librarys_on_twelve_keys() {
        for v in vectors() {
            assert_eq!(subkeys(&v.key).to_vec(), v.k, "key {:02x?}", v.key);
            assert_eq!(s_vector(&v.key).to_vec(), v.s, "key {:02x?}", v.key);
        }
    }

    #[test]
    fn the_tables_equal_the_oracles_that_matched_real_memory() {
        let mut checked = 0;
        for v in vectors() {
            if let Some(mk) = v.mk {
                assert_eq!(mk_tab(&v.key), mk, "key {:02x?}", v.key);
                checked += 1;
            }
        }
        assert_eq!(checked, 3);
    }

    #[test]
    fn the_key_is_recovered_from_the_subkeys_alone() {
        // Four keys: each recovery is a search of about 134 million table lookups, ten seconds in a debug
        // build; the other eight are covered by the subkey test above and the real capture.
        for v in vectors().into_iter().take(4) {
            let k: [u32; 40] = v.k.clone().try_into().unwrap();
            assert_eq!(recover_key(&k), Some(v.key), "key {:02x?}", v.key);
        }
    }

    #[test]
    fn subkeys_no_key_makes_are_not_recovered() {
        let v = &vectors()[4];
        let mut k: [u32; 40] = v.k.clone().try_into().unwrap();
        k[17] ^= 0x100;
        assert_eq!(recover_key(&k), None);
    }

    fn structure_for(key: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(STRUCT_BYTES);
        for w in mk_tab(key) {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for w in subkeys(key) {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    #[test]
    fn a_schedule_in_a_buffer_is_found_at_its_offset_and_its_key_recovered() {
        let v = &vectors()[6];
        let mut buf = vec![0x5Au8; 16384];
        let s = structure_for(&v.key);
        buf[1000..1000 + s.len()].copy_from_slice(&s);
        assert_eq!(
            verify_schedule_at(&buf, 1000),
            Some(RecoveredTwofishKey {
                offset: 1000,
                key: v.key
            })
        );
        assert_eq!(verify_schedule_at(&buf, 1004), None);
    }

    #[test]
    fn a_structure_with_one_table_word_wrong_is_not_a_schedule() {
        let v = &vectors()[2];
        let mut s = structure_for(&v.key);
        s[4 * 700] ^= 1;
        assert!(verify_schedule_at(&s, 0).is_none());
    }

    /// A table of counters has distinct low bytes, like a Twofish S-box table, and on the Windows 11
    /// capture of `MEM-044` such regions sent the sweep into the key recovery for 50 seconds. The
    /// algebra of table 0's words (MDS column 0 times one byte) rejects them first.
    #[test]
    fn a_table_of_counters_is_rejected_before_any_key_recovery() {
        let mut buf = Vec::new();
        for i in 0..(STRUCT_BYTES / 4) as u32 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
        let started = std::time::Instant::now();
        assert_eq!(verify_schedule_at(&buf, 0), None);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn zeros_and_short_buffers_are_not_schedules() {
        assert_eq!(verify_schedule_at(&vec![0u8; 8192], 0), None);
        assert_eq!(verify_schedule_at(&[1u8; 100], 0), None);
    }

    fn subkeys_first_structure_for(key: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(STRUCT_BYTES);
        for w in subkeys(key) {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for w in mk_tab(key) {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// VeraCrypt 1.19 writes the subkeys, then the tables. Read off a mounted volume: the subkeys at the structure's
    /// start and the tables 160 bytes on, each word equal to this crate's.
    #[test]
    fn a_subkeys_first_structure_is_found_at_its_offset_and_its_key_recovered() {
        let v = &vectors()[6];
        let mut buf = vec![0x5Au8; 16384];
        let s = subkeys_first_structure_for(&v.key);
        buf[1000..1000 + s.len()].copy_from_slice(&s);
        assert_eq!(
            verify_subkeys_first_schedule_at(&buf, 1000),
            Some(RecoveredTwofishKey {
                offset: 1000,
                key: v.key
            })
        );
        assert_eq!(verify_subkeys_first_schedule_at(&buf, 1004), None);
    }

    /// Each reader takes its own order and no other: the tables-first structure is not read as subkeys-first
    /// and the reverse, so a hit names the layout it was found in.
    #[test]
    fn the_two_orders_of_the_structure_are_not_taken_for_each_other() {
        let v = &vectors()[2];
        let tables_first = structure_for(&v.key);
        let subkeys_first = subkeys_first_structure_for(&v.key);
        assert!(verify_schedule_at(&tables_first, 0).is_some());
        assert!(verify_subkeys_first_schedule_at(&tables_first, 0).is_none());
        assert!(verify_subkeys_first_schedule_at(&subkeys_first, 0).is_some());
        assert!(verify_schedule_at(&subkeys_first, 0).is_none());
    }

    #[test]
    fn a_subkeys_first_structure_with_one_table_word_wrong_is_not_a_schedule() {
        let v = &vectors()[2];
        let mut s = subkeys_first_structure_for(&v.key);
        s[160 + 4 * 700] ^= 1;
        assert!(verify_subkeys_first_schedule_at(&s, 0).is_none());
    }

    #[test]
    fn zeros_counters_and_short_buffers_are_not_subkeys_first_schedules() {
        assert_eq!(verify_subkeys_first_schedule_at(&vec![0u8; 8192], 0), None);
        assert_eq!(verify_subkeys_first_schedule_at(&[1u8; 100], 0), None);
        let mut buf = Vec::new();
        for i in 0..(STRUCT_BYTES / 4) as u32 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
        let started = std::time::Instant::now();
        assert_eq!(verify_subkeys_first_schedule_at(&buf, 0), None);
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
    }

    /// TrueCrypt 7.1a keeps the same Twofish data in another order: the 40 subkeys, then `S` reversed, then
    /// the four tables interleaved (entry `x` of table `j` at word `4x + j`). Four keys' structures, written by
    /// the reference script (whose tables agree word for word with a real mounted volume's), give their keys back.
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn truecrypt_structures_give_back_their_keys() {
        let rows: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/twofish_tc_structures.json"))
                .unwrap();
        assert_eq!(rows.len(), 4);
        for row in &rows {
            let key: [u8; 32] = unhex(row["key"].as_str().unwrap()).try_into().unwrap();
            let structure = unhex(row["structure"].as_str().unwrap());
            assert_eq!(structure.len(), TC_STRUCT_BYTES);
            let found = verify_tc_schedule_at(&structure, 0).expect("the structure verifies");
            assert_eq!(found.key, key);
            // The VeraCrypt reader does not take it for its own.
            assert!(verify_schedule_at(&structure, 0).is_none());
        }
    }

    #[test]
    fn a_truecrypt_structure_is_found_at_an_offset_and_damage_or_noise_is_refused() {
        let rows: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/twofish_tc_structures.json"))
                .unwrap();
        let structure = unhex(rows[2]["structure"].as_str().unwrap());
        let mut buf = vec![0x3Cu8; 9000];
        buf[1004..1004 + TC_STRUCT_BYTES].copy_from_slice(&structure);
        assert_eq!(verify_tc_schedule_at(&buf, 1004).unwrap().offset, 1004);
        assert!(verify_tc_schedule_at(&buf, 1008).is_none());
        // One flipped bit in a subkey, in S, and in the first and last table words each breaks it.
        for at in [4 * 7, 4 * 41, 4 * 44 + 1, TC_STRUCT_BYTES - 4] {
            let mut bad = structure.clone();
            bad[at] ^= 0x01;
            assert!(verify_tc_schedule_at(&bad, 0).is_none(), "byte {at}");
        }
        assert!(verify_tc_schedule_at(&[0u8; TC_STRUCT_BYTES], 0).is_none());
        assert!(verify_tc_schedule_at(&structure[..TC_STRUCT_BYTES - 1], 0).is_none());
    }
}
