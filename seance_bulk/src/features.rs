//! Selectors over the raw byte stream, with byte-offset provenance.
//!
//! Séance's existing entity extractor (`seance_api::entities`) is good, but it
//! runs only over already-parsed record JSON. bulk_extractor's whole value is
//! running the same class of selector over *every byte* — allocated, slack,
//! unallocated, and decoded layers — so a card number in freed space or an email
//! in a carved fragment is found. This module is that scanner: it takes a byte
//! buffer and returns typed [`FeatureHit`]s each carrying the offset where they
//! were found (bulk_extractor's "forensic path"), so a hit is traceable back to a
//! device location.
//!
//! The selectors here are a superset of the entity extractor's, adding the ones
//! the gap analysis called out: SSN, IBAN, VIN, and free-text GPS.

use regex::bytes::Regex;

/// A selector match, with where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureHit {
    /// Selector kind, a stable identifier (`"email"`, `"ccn"`, `"ssn"`, …).
    pub kind: &'static str,
    /// The matched text, UTF-8 (selectors only match ASCII-representable text).
    pub value: String,
    /// Byte offset of the match within the scanned buffer.
    pub offset: usize,
}

/// A compiled selector: kind + pattern + an optional validator that rejects a
/// syntactic match that fails a semantic check (Luhn for cards, checksum for VIN).
struct Selector {
    kind: &'static str,
    re: Regex,
    validate: Option<fn(&[u8]) -> bool>,
}

/// The feature scanner. Compiles every selector once and reuses it.
pub struct FeatureScanner {
    selectors: Vec<Selector>,
}

impl Default for FeatureScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureScanner {
    /// Build the scanner with the full selector set.
    pub fn new() -> Self {
        let selectors = vec![
            Selector {
                kind: "email",
                re: Regex::new(r"(?i-u)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap(),
                validate: None,
            },
            Selector {
                kind: "url",
                re: Regex::new(r#"(?i-u)\bhttps?://[^\s"'<>)\]}]{3,}"#).unwrap(),
                validate: None,
            },
            Selector {
                kind: "ipv4",
                re: Regex::new(
                    r"(?-u)\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
                )
                .unwrap(),
                validate: None,
            },
            Selector {
                kind: "mac",
                re: Regex::new(r"(?i-u)\b(?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}\b").unwrap(),
                validate: None,
            },
            Selector {
                kind: "btc",
                re: Regex::new(r"(?-u)\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b")
                    .unwrap(),
                validate: None,
            },
            Selector {
                kind: "ccn",
                re: Regex::new(r"(?-u)\b(?:\d[ \-]?){13,19}\b").unwrap(),
                validate: Some(valid_card),
            },
            Selector {
                kind: "phone",
                re: Regex::new(r"(?-u)\+\d[\d .()\-]{6,}\d").unwrap(),
                validate: None,
            },
            Selector {
                // US SSN: 3-2-4, excluding the impossible ranges.
                kind: "ssn",
                re: Regex::new(r"(?-u)\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                validate: Some(valid_ssn),
            },
            Selector {
                // IBAN: 2-letter country + 2 check digits + up to 30 alnum.
                kind: "iban",
                re: Regex::new(r"(?-u)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
                validate: Some(valid_iban),
            },
            Selector {
                // VIN: 17 chars, no I/O/Q.
                kind: "vin",
                re: Regex::new(r"(?-u)\b[A-HJ-NPR-Z0-9]{17}\b").unwrap(),
                validate: Some(valid_vin),
            },
            Selector {
                // Free-text GPS decimal pair, e.g. "51.5074, -0.1278".
                kind: "gps",
                re: Regex::new(r"(?-u)-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,}").unwrap(),
                validate: Some(valid_gps),
            },
        ];
        Self { selectors }
    }

    /// Scan a buffer, returning every hit with its offset. Hits are ordered by
    /// offset then kind so output is deterministic.
    pub fn scan(&self, buf: &[u8]) -> Vec<FeatureHit> {
        let mut hits = Vec::new();
        for sel in &self.selectors {
            for m in sel.re.find_iter(buf) {
                let bytes = m.as_bytes();
                if let Some(v) = sel.validate {
                    if !v(bytes) {
                        continue;
                    }
                }
                // Selectors only match ASCII-representable spans, so this is safe.
                if let Ok(s) = std::str::from_utf8(bytes) {
                    hits.push(FeatureHit {
                        kind: sel.kind,
                        value: s.to_string(),
                        offset: m.start(),
                    });
                }
            }
        }
        hits.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.kind.cmp(b.kind)));
        hits
    }
}

/// Standard Luhn checksum over ASCII digits (separators ignored).
fn luhn_ok(bytes: &[u8]) -> bool {
    let digits: Vec<u8> = bytes
        .iter()
        .filter(|b| b.is_ascii_digit())
        .copied()
        .collect();
    if digits.len() < 13 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = (d - b'0') as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// A digit run is a card only if Luhn passes AND it matches a real IIN prefix at
/// the right length AND is not a uniform run — mirrors the entity extractor's
/// noise gate, which is what makes card detection usable on real evidence.
fn valid_card(bytes: &[u8]) -> bool {
    let digits: Vec<u8> = bytes
        .iter()
        .filter(|b| b.is_ascii_digit())
        .copied()
        .collect();
    let len = digits.len();
    if !(13..=19).contains(&len) {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false; // uniform run
    }
    if !luhn_ok(bytes) {
        return false;
    }
    let n2: u32 = std::str::from_utf8(&digits[..2]).unwrap().parse().unwrap();
    let n4: u32 = std::str::from_utf8(&digits[..4]).unwrap().parse().unwrap();
    match digits[0] {
        b'4' => matches!(len, 13 | 16 | 19),              // Visa
        b'5' => (51..=55).contains(&n2) && len == 16,     // Mastercard
        b'2' => (2221..=2720).contains(&n4) && len == 16, // Mastercard 2-series
        b'3' => {
            (n2 == 34 || n2 == 37) && len == 15                 // Amex
                || (n2 == 36 || n2 == 38) && len == 14          // Diners
                || (3528..=3589).contains(&n4) && (16..=19).contains(&len) // JCB
        }
        b'6' => (n4 == 6011 || n2 == 65) && (16..=19).contains(&len), // Discover
        _ => false,
    }
}

/// SSN validity: reject the ranges the SSA never issues (area 000, 666, 900-999;
/// group 00; serial 0000). Kills the timestamp/offset noise that matches 3-2-4.
fn valid_ssn(bytes: &[u8]) -> bool {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area: u32 = parts[0].parse().unwrap_or(0);
    let group: u32 = parts[1].parse().unwrap_or(0);
    let serial: u32 = parts[2].parse().unwrap_or(0);
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// IBAN validity: the mod-97 check (ISO 13616). Rejects the vast majority of
/// random uppercase-alnum runs that match the syntactic pattern.
fn valid_iban(bytes: &[u8]) -> bool {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    // Move the first four chars to the end, then map letters to 10-35 and take
    // the whole thing mod 97; a valid IBAN gives 1.
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut remainder = 0u32;
    for ch in rearranged.chars() {
        let val = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else if ch.is_ascii_uppercase() {
            ch as u32 - 'A' as u32 + 10
        } else {
            return false;
        };
        // Fold in one or two decimal digits at a time to avoid overflow.
        if val >= 10 {
            remainder = (remainder * 100 + val) % 97;
        } else {
            remainder = (remainder * 10 + val) % 97;
        }
    }
    remainder == 1
}

/// VIN validity: the ISO 3779 / NHTSA check-digit in position 9.
fn valid_vin(bytes: &[u8]) -> bool {
    if bytes.len() != 17 {
        return false;
    }
    // Reject a uniform run (17 identical valid chars pass the checksum trivially
    // but are never a real VIN).
    if bytes.iter().all(|&b| b == bytes[0]) {
        return false;
    }
    const WEIGHTS: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let translit = |c: u8| -> Option<u32> {
        Some(match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'A' | b'J' => 1,
            b'B' | b'K' | b'S' => 2,
            b'C' | b'L' | b'T' => 3,
            b'D' | b'M' | b'U' => 4,
            b'E' | b'N' | b'V' => 5,
            b'F' | b'W' => 6,
            b'G' | b'P' | b'X' => 7,
            b'H' | b'Y' => 8,
            b'R' | b'Z' => 9,
            b'I' | b'O' | b'Q' => return None, // not allowed in a VIN
            _ => return None,
        })
    };
    let mut sum = 0u32;
    for (i, &c) in bytes.iter().enumerate() {
        match translit(c) {
            Some(v) => sum += v * WEIGHTS[i],
            None => return false,
        }
    }
    let check = sum % 11;
    let expected = if check == 10 {
        b'X'
    } else {
        b'0' + check as u8
    };
    bytes[8] == expected
}

/// GPS validity: latitude in [-90,90], longitude in [-180,180].
fn valid_gps(bytes: &[u8]) -> bool {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut it = s.split(',');
    let lat: f64 = match it.next().and_then(|p| p.trim().parse().ok()) {
        Some(v) => v,
        None => return false,
    };
    let lon: f64 = match it.next().and_then(|p| p.trim().parse().ok()) {
        Some(v) => v,
        None => return false,
    };
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(buf: &[u8]) -> Vec<FeatureHit> {
        FeatureScanner::new().scan(buf)
    }

    fn kinds_values(buf: &[u8]) -> Vec<(&'static str, String)> {
        scan(buf).into_iter().map(|h| (h.kind, h.value)).collect()
    }

    #[test]
    fn finds_email_url_ip_with_offsets() {
        let buf = b"contact bob@example.com at http://evil.test/x from 192.168.1.55 ok";
        let hits = scan(buf);
        let email = hits.iter().find(|h| h.kind == "email").unwrap();
        assert_eq!(email.value, "bob@example.com");
        assert_eq!(email.offset, 8); // provenance: exact byte offset
        assert!(hits
            .iter()
            .any(|h| h.kind == "url" && h.value.starts_with("http://evil.test")));
        assert!(hits
            .iter()
            .any(|h| h.kind == "ipv4" && h.value == "192.168.1.55"));
    }

    #[test]
    fn scans_across_binary_noise_not_just_text() {
        // A selector embedded in binary junk (the unallocated-space case) is
        // exactly what the parsed-record extractor could never reach.
        let mut buf = vec![0u8, 1, 2, 255, 254];
        buf.extend_from_slice(b"agent@agency.gov");
        buf.extend_from_slice(&[0u8, 0, 0]);
        let hits = scan(&buf);
        assert!(hits
            .iter()
            .any(|h| h.kind == "email" && h.value == "agent@agency.gov"));
    }

    #[test]
    fn valid_visa_and_amex_match_but_noise_does_not() {
        assert!(kinds_values(b"card 4111 1111 1111 1111 end")
            .iter()
            .any(|(k, _)| *k == "ccn"));
        assert!(kinds_values(b"amex 378282246310005 x")
            .iter()
            .any(|(k, _)| *k == "ccn"));
        // A uniform run and a bad-prefix Luhn-passing run must NOT match.
        assert!(!kinds_values(b"0000000000000000")
            .iter()
            .any(|(k, _)| *k == "ccn"));
    }

    #[test]
    fn ssn_matches_valid_and_rejects_impossible_ranges() {
        assert!(kinds_values(b"ssn 123-45-6789 x")
            .iter()
            .any(|(k, v)| *k == "ssn" && v == "123-45-6789"));
        // area 000, 666, 9xx and zero group/serial are impossible.
        for bad in [
            "000-45-6789",
            "666-45-6789",
            "900-45-6789",
            "123-00-6789",
            "123-45-0000",
        ] {
            let s = format!("x {bad} y");
            assert!(
                !kinds_values(s.as_bytes()).iter().any(|(k, _)| *k == "ssn"),
                "should reject {bad}"
            );
        }
    }

    #[test]
    fn iban_mod97_gates_out_noise() {
        // A real, mod-97-valid IBAN (GB example).
        assert!(kinds_values(b"pay GB82WEST12345698765432 now")
            .iter()
            .any(|(k, _)| *k == "iban"));
        // Same shape, wrong check digits.
        assert!(!kinds_values(b"pay GB00WEST12345698765432 now")
            .iter()
            .any(|(k, _)| *k == "iban"));
    }

    #[test]
    fn vin_checksum_gates_out_noise() {
        // A VIN with a valid check digit (NHTSA example).
        assert!(kinds_values(b"vin 1M8GDM9AXKP042788 end")
            .iter()
            .any(|(k, v)| *k == "vin" && v == "1M8GDM9AXKP042788"));
        // Flip the check digit → reject.
        assert!(!kinds_values(b"vin 1M8GDM9A0KP042788 end")
            .iter()
            .any(|(k, _)| *k == "vin"));
    }

    #[test]
    fn gps_pair_matches_and_out_of_range_rejected() {
        assert!(kinds_values(b"here 51.5074, -0.1278 spot")
            .iter()
            .any(|(k, _)| *k == "gps"));
        assert!(!kinds_values(b"bad 999.999, 999.999 x")
            .iter()
            .any(|(k, _)| *k == "gps"));
    }

    #[test]
    fn hits_are_ordered_by_offset() {
        let buf = b"192.168.0.1 then a@b.co then +12025550123";
        let hits = scan(buf);
        let offsets: Vec<usize> = hits.iter().map(|h| h.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn empty_and_tiny_buffers_do_not_panic() {
        assert!(scan(b"").is_empty());
        assert!(scan(b"a").is_empty());
    }
}
