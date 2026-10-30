//! Entity extraction: pull high-signal identifiers (emails, URLs, IPs, MACs,
//! crypto addresses, payment cards, international phone numbers) out of the
//! text of parsed records. Patterns are anchored and validated (octet ranges,
//! Luhn) so the results stay low-noise rather than matching every hex blob.

use regex::Regex;

/// A single extracted identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityHit {
    pub kind: &'static str,
    pub value: String,
}

/// Hosts whose "address" is a messaging identifier, not a mailbox.
///
/// A WhatsApp JID is a phone number at a service host, so it has the exact
/// shape of an email address and was counted as one. On a real handset backup
/// that put tens of thousands of JID hits at the top of the Email facet and
/// buried every genuine address beneath them (LIVE-019). The test is on the
/// host, not on the text: `careers@whatsapp.com` is a mailbox at a company and
/// stays an email.
/// Note the absence of `broadcast`: WhatsApp's `status@broadcast` is a real
/// identifier, but the extraction regex requires a dot and a TLD after the `@`,
/// so a dotless host is never matched and never reaches this list. Listing it
/// here claimed a coverage that did not exist. Status/broadcast rows are
/// recovered by the WhatsApp parser, which reads them out of ChatStorage
/// directly rather than by scraping text.
const MESSAGING_HOSTS: &[&str] = &["s.whatsapp.net", "g.us", "c.us"];

/// The kind an `user@host` match should be recorded as.
fn address_kind(value: &str) -> &'static str {
    match value.rsplit_once('@') {
        Some((_, host)) if MESSAGING_HOSTS.contains(&host) => "messaging_id",
        _ => "email",
    }
}

/// Compiled once and reused across every scanned record.
pub struct EntityExtractor {
    email: Regex,
    url: Regex,
    ipv4: Regex,
    mac: Regex,
    eth: Regex,
    btc: Regex,
    card: Regex,
    phone: Regex,
}

impl Default for EntityExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl EntityExtractor {
    pub fn new() -> Self {
        Self {
            email: Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap(),
            url: Regex::new(r#"(?i)\bhttps?://[^\s"'<>)\]}]+"#).unwrap(),
            // Octet-validated IPv4 to avoid matching arbitrary dotted numbers.
            ipv4: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            )
            .unwrap(),
            mac: Regex::new(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b").unwrap(),
            eth: Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap(),
            btc: Regex::new(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b").unwrap(),
            // 13-19 digits with optional space/dash separators; Luhn-checked below.
            card: Regex::new(r"\b(?:\d[ \-]?){13,19}\b").unwrap(),
            // International only (leading +) so it doesn't swallow ids/timestamps.
            phone: Regex::new(r"\+\d[\d .()\-]{6,}\d").unwrap(),
        }
    }

    /// Scan one text blob, appending hits to `out`.
    pub fn scan(&self, text: &str, out: &mut Vec<EntityHit>) {
        for m in self.email.find_iter(text) {
            let value = m.as_str().to_lowercase();
            out.push(EntityHit {
                kind: address_kind(&value),
                value,
            });
        }
        for m in self.url.find_iter(text) {
            out.push(EntityHit {
                kind: "url",
                value: m.as_str().to_string(),
            });
        }
        for m in self.ipv4.find_iter(text) {
            out.push(EntityHit {
                kind: "ipv4",
                value: m.as_str().to_string(),
            });
        }
        for m in self.mac.find_iter(text) {
            out.push(EntityHit {
                kind: "mac",
                value: m.as_str().to_uppercase(),
            });
        }
        for m in self.eth.find_iter(text) {
            out.push(EntityHit {
                kind: "eth",
                value: m.as_str().to_lowercase(),
            });
        }
        for m in self.btc.find_iter(text) {
            out.push(EntityHit {
                kind: "btc",
                value: m.as_str().to_string(),
            });
        }
        for m in self.card.find_iter(text) {
            let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
            if is_plausible_card(&digits) {
                out.push(EntityHit {
                    kind: "credit_card",
                    value: digits,
                });
            }
        }
        for m in self.phone.find_iter(text) {
            let digits = m.as_str().chars().filter(|c| c.is_ascii_digit()).count();
            if (7..=15).contains(&digits) {
                out.push(EntityHit {
                    kind: "phone",
                    value: m.as_str().trim().to_string(),
                });
            }
        }
    }
}

/// A digit run only counts as a payment card if it passes Luhn AND matches a
/// real card-network IIN prefix at the expected length AND isn't a uniform run
/// (e.g. all zeros). Forensic record text is full of Luhn-passing digit runs
/// (offsets, decoded blobs), so the prefix/length gate is what kills the noise.
fn is_plausible_card(d: &str) -> bool {
    let len = d.len();
    if !(13..=19).contains(&len) {
        return false;
    }
    let bytes = d.as_bytes();
    if bytes.iter().all(|&b| b == bytes[0]) {
        return false; // uniform run (0000…, 1111…)
    }
    if !luhn_valid(d) {
        return false;
    }
    let n2: u32 = d.get(..2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let n4: u32 = d.get(..4).and_then(|s| s.parse().ok()).unwrap_or(0);
    match bytes[0] {
        b'4' => matches!(len, 13 | 16 | 19),              // Visa
        b'5' => (51..=55).contains(&n2) && len == 16,     // Mastercard
        b'2' => (2221..=2720).contains(&n4) && len == 16, // Mastercard 2-series
        b'3' => {
            (n2 == 34 || n2 == 37) && len == 15                  // Amex
                || (n2 == 36 || n2 == 38) && len == 14           // Diners
                || (3528..=3589).contains(&n4) && (16..=19).contains(&len) // JCB
        }
        b'6' => (n4 == 6011 || n2 == 65) && (16..=19).contains(&len), // Discover
        _ => false,
    }
}

/// Standard Luhn checksum over a run of ASCII digits.
fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for c in digits.chars().rev() {
        let mut d = c.to_digit(10).unwrap_or(0);
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        EntityExtractor::new().scan(text, &mut out);
        out.into_iter().map(|h| (h.kind, h.value)).collect()
    }

    #[test]
    fn extracts_email_url_ip() {
        let hits = kinds("mail rms@gnu.org visit https://example.com/a?b=1 host 192.168.1.20 end");
        assert!(hits.contains(&("email", "rms@gnu.org".into())));
        assert!(hits
            .iter()
            .any(|(k, v)| *k == "url" && v.starts_with("https://example.com")));
        assert!(hits.contains(&("ipv4", "192.168.1.20".into())));
    }

    /// LIVE-019: a WhatsApp JID is a phone number at a service host, so it has
    /// the shape of an email address and was counted as one. On a real handset
    /// backup this put 36,166 hits of `447796268670@s.whatsapp.net` at the top
    /// of the Email facet and buried every genuine email address beneath the
    /// messaging identifiers.
    #[test]
    fn a_whatsapp_id_is_a_messaging_id_and_not_an_email() {
        let hits = kinds("from 447796268670@s.whatsapp.net to rms@gnu.org");
        assert!(hits.contains(&("messaging_id", "447796268670@s.whatsapp.net".into())));
        assert!(
            !hits
                .iter()
                .any(|(k, v)| *k == "email" && v.contains("whatsapp")),
            "a JID must not be counted as an email: {hits:?}"
        );
        assert!(
            hits.contains(&("email", "rms@gnu.org".into())),
            "a real address alongside it is still an email"
        );
    }

    #[test]
    fn a_whatsapp_group_id_is_also_a_messaging_id() {
        let hits = kinds("group 120363021234567890@g.us and 447796268670@c.us");
        assert!(hits
            .iter()
            .any(|(k, v)| *k == "messaging_id" && v.ends_with("@g.us")));
        assert!(hits
            .iter()
            .any(|(k, v)| *k == "messaging_id" && v.ends_with("@c.us")));
    }

    /// The rule is a suffix match on the service host, not "contains whatsapp":
    /// a person really can have an address at a company of that name.
    /// Review finding: a dotless service host cannot be extracted at all, so
    /// listing it as a messaging host was coverage that did not exist. Pinned
    /// so the list is not "fixed" by adding hosts the regex cannot reach.
    #[test]
    fn a_dotless_service_host_is_never_extracted_so_it_is_not_listed() {
        let hits = kinds("posted status@broadcast today");
        assert!(
            hits.is_empty() || !hits.iter().any(|(_, v)| v.contains("broadcast")),
            "the regex requires a dot and a TLD: {hits:?}"
        );
        assert!(!super::MESSAGING_HOSTS.contains(&"broadcast"));
    }

    #[test]
    fn an_ordinary_address_at_a_lookalike_domain_is_still_an_email() {
        let hits = kinds("careers@whatsapp.com");
        assert!(hits.contains(&("email", "careers@whatsapp.com".into())));
        assert!(!hits.iter().any(|(k, _)| *k == "messaging_id"));
    }

    #[test]
    fn ip_octets_are_validated() {
        // 999.1.1.1 is not a valid dotted-quad and must not match.
        let hits = kinds("bogus 999.1.1.1 and real 10.0.0.1");
        assert!(hits.contains(&("ipv4", "10.0.0.1".into())));
        assert!(!hits.iter().any(|(k, v)| *k == "ipv4" && v == "999.1.1.1"));
    }

    #[test]
    fn credit_card_requires_luhn_prefix_and_length() {
        // Valid Visa/Amex/MC test numbers vs noise.
        let hits = kinds("visa 4111 1111 1111 1111 amex 3782 822463 10005 mc 5555555555554444");
        assert!(hits.contains(&("credit_card", "4111111111111111".into())));
        assert!(hits.contains(&("credit_card", "378282246310005".into())));
        assert!(hits.contains(&("credit_card", "5555555555554444".into())));

        // The worst real-data noise must NOT match: a bad-prefix run and a
        // uniform zero run (which was the single biggest false positive).
        let noise = kinds("bad 1234567890123456 zeros 0000000000000000");
        assert!(!noise.iter().any(|(k, _)| *k == "credit_card"));
    }

    #[test]
    fn crypto_and_mac() {
        let eth = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
        let text = format!("eth {eth} mac 01:23:45:67:89:AB");
        let hits = kinds(&text);
        assert!(hits.iter().any(|(k, _)| *k == "eth"));
        assert!(hits.contains(&("mac", "01:23:45:67:89:AB".into())));
    }

    #[test]
    fn sha_hashes_do_not_masquerade_as_entities() {
        // A 64-hex sha256 and a 40-hex sha1 (no 0x) must not match eth/mac.
        let sha1 = "aabbccddeeff00112233445566778899aabbccdd";
        let sha256 = "a".repeat(64);
        let hits = kinds(&format!("h1 {sha1} h2 {sha256}"));
        assert!(!hits.iter().any(|(k, _)| *k == "eth"));
        assert!(!hits.iter().any(|(k, _)| *k == "mac"));
    }
}
