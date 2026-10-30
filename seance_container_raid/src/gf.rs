//! GF(2⁸) arithmetic for RAID-6 Q-syndrome recovery.
//!
//! RAID 6 protects against two simultaneous failures with two syndromes: P (the
//! XOR parity, handled in [`crate::raid`]) and Q, a Reed-Solomon code over the
//! Galois field GF(2⁸). Recovering two lost members needs field multiplication,
//! division and the generator's powers — that is what this module provides.
//!
//! The field follows the Linux `md` RAID-6 convention exactly (H. Peter Anvin,
//! "The mathematics of RAID-6"): the reduction polynomial is
//! x⁸ + x⁴ + x³ + x² + 1 (`0x11d`) and the generator is `g = 2`. Using the same
//! field as `md` is what lets this reconstruct a real Linux RAID-6 array.

/// Reduction step for the `0x11d` polynomial: on overflow, XOR `0x1d`.
const POLY: u16 = 0x11d;

/// Antilog (exp) and log tables for the field, generator 2. `EXP[i] = 2^i`,
/// `LOG[EXP[i]] = i`. Built once.
struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn build_tables() -> Tables {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for (i, slot) in exp.iter_mut().take(255).enumerate() {
        *slot = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
    }
    // Duplicate the cycle so `exp[a+b]` needs no modulo for a,b in 0..255.
    exp.copy_within(0..257, 255);
    Tables { exp, log }
}

use std::sync::OnceLock;
static TABLES: OnceLock<Tables> = OnceLock::new();
fn tables() -> &'static Tables {
    TABLES.get_or_init(build_tables)
}

/// Multiply two field elements.
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

/// Multiplicative inverse of a non-zero element (`inv(0)` is defined as 0, which
/// never arises in the recovery formulas).
pub fn inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let t = tables();
    t.exp[255 - t.log[a as usize] as usize]
}

/// Divide `a` by non-zero `b`.
pub fn div(a: u8, b: u8) -> u8 {
    mul(a, inv(b))
}

/// The generator raised to the power `n` — the Q-syndrome coefficient for the
/// data disk at index `n` in a stripe (`g^n`, `g = 2`).
pub fn gpow(n: usize) -> u8 {
    tables().exp[n % 255]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_matches_known_field_values() {
        // The RAID-6 field uses the 0x11d reduction polynomial (not AES's 0x11b).
        assert_eq!(mul(0, 5), 0);
        assert_eq!(mul(1, 5), 5);
        assert_eq!(mul(2, 1), 2);
        assert_eq!(mul(2, 2), 4);
        // 2 * 0x80 overflows and reduces by the polynomial: 0x100 ^ 0x11d = 0x1d.
        assert_eq!(mul(2, 0x80), 0x1d);
        // Distributivity over the field's XOR addition: 2*(3^5) == 2*3 ^ 2*5.
        assert_eq!(mul(2, 3 ^ 5), mul(2, 3) ^ mul(2, 5));
        // Commutativity.
        assert_eq!(mul(0x1d, 0x4b), mul(0x4b, 0x1d));
    }

    #[test]
    fn inverse_and_division_are_consistent() {
        // The definitive field check: every non-zero element has a true inverse.
        for a in 1u8..=255 {
            let ai = inv(a);
            assert_eq!(mul(a, ai), 1, "a * inv(a) must be 1 for a={a}");
        }
        // Division is multiplication by the inverse, and round-trips.
        assert_eq!(mul(div(100, 7), 7), 100);
        assert_eq!(div(mul(0x53, 0xca), 0xca), 0x53);
    }

    #[test]
    fn generator_powers_cycle_and_start_at_one() {
        assert_eq!(gpow(0), 1);
        assert_eq!(gpow(1), 2);
        assert_eq!(gpow(2), 4);
        // The multiplicative group has order 255, so g^255 == g^0 == 1.
        assert_eq!(gpow(255), 1);
        assert_eq!(gpow(256), 2);
    }

    #[test]
    fn every_nonzero_power_is_distinct() {
        // A correct generator visits all 255 non-zero elements exactly once.
        let mut seen = std::collections::HashSet::new();
        for i in 0..255 {
            seen.insert(gpow(i));
        }
        assert_eq!(seen.len(), 255);
        assert!(!seen.contains(&0));
    }
}
