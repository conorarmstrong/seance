//! The fields of an X.509 certificate, read from DER (`ROADMAP` §4.3 stage 2).
//!
//! # Why a capture parser reads certificates at all
//!
//! A TLS server's certificate is the one thing in an encrypted conversation
//! that crosses the wire in the clear (before TLS 1.3, which encrypts it —
//! see [`crate::tls`]). The names in it are frequently the only evidence of
//! *what* a host was talking to: a self-signed certificate with a two-letter
//! organisation and a name nobody registered is what a commodity C2 framework
//! ships with, and an examiner who can read the subject, the issuer, the
//! validity window and the alternative names can say so.
//!
//! # What this reads, and what it deliberately does not
//!
//! It reads the fields. It does **not** verify the signature, build a chain,
//! consult a trust store, check revocation, or compare the validity window
//! against any clock. Every one of those is a verdict, and a verdict this
//! build has not earned must not appear on a record — so the record carries
//! `signature_verified: false` as a stated field rather than as a silence.
//!
//! # It refuses rather than half-reads
//!
//! A truncated certificate is not a certificate with some fields missing: it
//! is bytes whose structure is unknown, and a subject read out of one may not
//! be the subject the issuer signed. So [`Certificate::parse`] returns `None`
//! for anything it cannot walk end to end, and the caller records the refusal
//! with the bytes it had.

use std::collections::{BTreeMap, BTreeSet};

/// Bytes of one certificate this build will walk. A real one is one to four
/// kilobytes; past this the structure is not walked at all.
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

/// Names in one certificate's subject-alternative-name extension.
pub const MAX_NAMES: usize = 256;

/// Extensions recorded from one certificate.
pub const MAX_EXTENSIONS: usize = 64;

/// One DER tag-length-value, borrowed from the buffer it was read from.
#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    contents: &'a [u8],
    /// Bytes this TLV occupied, header included.
    total: usize,
}

/// Read one TLV from the front of `bytes`.
///
/// Refuses what DER forbids and BER allows: an indefinite length, a length
/// whose own byte count exceeds a `usize`, and any length running past the
/// buffer. A parser that guessed at one of these would be reading a structure
/// the issuer never signed.
fn tlv(bytes: &[u8]) -> Option<Tlv<'_>> {
    let tag = *bytes.first()?;
    // A high-tag-number form (tag bits all set) is not used by X.509 and is
    // not decoded rather than being decoded wrongly.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *bytes.get(1)?;
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2usize)
    } else {
        let count = (first & 0x7f) as usize;
        // 0x80 is BER's indefinite length, which DER forbids.
        if count == 0 || count > std::mem::size_of::<usize>() {
            return None;
        }
        let digits = bytes.get(2..2 + count)?;
        // A minimal encoding is required by DER; a leading zero here is a
        // longer encoding of a shorter number, which is how two parsers are
        // made to disagree about the same bytes.
        if digits[0] == 0 {
            return None;
        }
        let mut length = 0usize;
        for digit in digits {
            length = length.checked_mul(256)?.checked_add(*digit as usize)?;
        }
        (length, 2usize.checked_add(count)?)
    };
    let end = header.checked_add(length)?;
    let contents = bytes.get(header..end)?;
    Some(Tlv {
        tag,
        contents,
        total: end,
    })
}

/// Read one TLV of an expected tag, and nothing else.
fn tagged(bytes: &[u8], tag: u8) -> Option<Tlv<'_>> {
    let out = tlv(bytes)?;
    (out.tag == tag).then_some(out)
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

/// Walk the members of a constructed TLV, bounded by count.
///
/// **No depth bound, deliberately.** The walk is not recursive: each level is
/// walked by its own call, every member is a slice of its parent's contents,
/// and the deepest structure this module reaches is five levels because that
/// is what a certificate has. A depth counter here would be a guard that
/// never engages while implying one that does — the same reasoning
/// `seance_xml_util` records for its own missing depth bound. What does need
/// bounding is the number of members at one level, because that is what a
/// hostile certificate can make large.
fn members(contents: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = contents;
    while !rest.is_empty() {
        if out.len() >= 1024 {
            return None;
        }
        let member = tlv(rest)?;
        rest = rest.get(member.total..)?;
        out.push(member);
    }
    Some(out)
}

/// An object identifier in dotted form. The dotted form is the evidence: a
/// name this build does not know is still a name the reader can look up, and
/// "unknown extension" is not.
fn oid_dotted(contents: &[u8]) -> Option<String> {
    let first = *contents.first()?;
    let mut out = format!("{}.{}", first / 40, first % 40);
    let mut value: u64 = 0;
    let mut pending = false;
    for byte in &contents[1..] {
        value = value.checked_mul(128)?.checked_add((byte & 0x7f) as u64)?;
        pending = true;
        if byte & 0x80 == 0 {
            out.push('.');
            out.push_str(&value.to_string());
            value = 0;
            pending = false;
        }
    }
    // A final byte with the continuation bit set is an arc that never ended.
    (!pending).then_some(out)
}

/// The names this build knows, by OID. Everything else is reported dotted.
fn oid_name(dotted: &str) -> Option<&'static str> {
    Some(match dotted {
        // Distinguished-name attributes.
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.42" => "GN",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        // Signature algorithms.
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassaPss",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.10040.4.3" => "dsaWithSha1",
        "1.2.840.10045.2.1" => "id-ecPublicKey",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        // Curves.
        "1.2.840.10045.3.1.7" => "prime256v1",
        "1.3.132.0.34" => "secp384r1",
        "1.3.132.0.35" => "secp521r1",
        // Extensions.
        "2.5.29.14" => "subjectKeyIdentifier",
        "2.5.29.15" => "keyUsage",
        "2.5.29.17" => "subjectAltName",
        "2.5.29.18" => "issuerAltName",
        "2.5.29.19" => "basicConstraints",
        "2.5.29.31" => "cRLDistributionPoints",
        "2.5.29.32" => "certificatePolicies",
        "2.5.29.35" => "authorityKeyIdentifier",
        "2.5.29.37" => "extKeyUsage",
        "1.3.6.1.5.5.7.1.1" => "authorityInfoAccess",
        "1.3.6.1.4.1.11129.2.4.2" => "signedCertificateTimestampList",
        _ => return None,
    })
}

/// One extension, whether or not this build reads its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The dotted OID, always.
    pub oid: String,
    /// Its name where this build knows one, and the dotted OID where it does
    /// not — never the word "unknown", which sends nobody anywhere.
    pub name: String,
    pub critical: bool,
    pub bytes: usize,
}

/// The fields of one certificate.
#[derive(Debug, Clone, Default)]
pub struct Certificate {
    pub version: u8,
    /// The serial as lower-case hex, unpunctuated: the form a search box and
    /// a report can both carry.
    pub serial_hex: String,
    pub signature_algorithm: String,
    /// The whole distinguished name, in the one-line form OpenSSL prints.
    pub subject: String,
    pub issuer: String,
    pub subject_common_name: Option<String>,
    pub subject_organisation: Option<String>,
    pub issuer_common_name: Option<String>,
    pub issuer_organisation: Option<String>,
    /// The validity window as stated by the certificate, in UTC. Not compared
    /// against any clock here: "expired" depends on when the question is
    /// asked, and the answer belongs where the question is.
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub key_algorithm: Option<String>,
    /// The modulus size for RSA, the curve size for EC; `None` where this
    /// build cannot say.
    pub key_bits: Option<u32>,
    pub key_curve: Option<String>,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub email_addresses: Vec<String>,
    pub uris: Vec<String>,
    pub other_names: usize,
    /// `None` where the certificate carries no basic-constraints extension,
    /// which is not the same as carrying one that says `false`.
    pub is_certificate_authority: Option<bool>,
    pub extensions: Vec<Extension>,
    /// Extensions past [`MAX_EXTENSIONS`], and alternative names past
    /// [`MAX_NAMES`], that this build did not read. Counted, because a name
    /// list that was cut must never be read as the certificate's names — the
    /// name an examiner is looking for may be the one past the cut.
    pub extensions_beyond_cap: usize,
    pub names_beyond_cap: usize,
    /// Whether the subject and the issuer are the same name. A fact about two
    /// strings, and not a verdict: see the module documentation.
    pub self_signed: bool,
    pub sha256: String,
    pub der_bytes: usize,
}

impl Certificate {
    /// Read a certificate, or refuse it.
    pub fn parse(der: &[u8]) -> Option<Certificate> {
        if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
            return None;
        }
        let certificate = tagged(der, SEQUENCE)?;
        // Trailing bytes after the certificate mean this is not one
        // certificate, and which of the two it is cannot be known.
        if certificate.total != der.len() {
            return None;
        }
        let top = members(certificate.contents)?;
        let tbs = top.first().filter(|t| t.tag == SEQUENCE)?;
        let signature_algorithm = top
            .get(1)
            .filter(|t| t.tag == SEQUENCE)
            .and_then(|t| algorithm_name(t.contents))
            .unwrap_or_default();

        let mut fields = members(tbs.contents)?;
        let mut version = 1u8;
        // [0] EXPLICIT version, present for a v2 or v3 certificate.
        if fields.first().is_some_and(|f| f.tag == 0xa0) {
            let explicit = fields.remove(0);
            let number = tagged(explicit.contents, INTEGER)?;
            version = number
                .contents
                .last()
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
        }
        let serial = fields.first().filter(|f| f.tag == INTEGER)?;
        let serial_hex = hex(strip_leading_zero(serial.contents));
        let issuer_tlv = fields.get(2).filter(|f| f.tag == SEQUENCE)?;
        let validity = fields.get(3).filter(|f| f.tag == SEQUENCE)?;
        let subject_tlv = fields.get(4).filter(|f| f.tag == SEQUENCE)?;
        let key_info = fields.get(5).filter(|f| f.tag == SEQUENCE)?;

        let issuer_parts = distinguished_name(issuer_tlv.contents)?;
        let subject_parts = distinguished_name(subject_tlv.contents)?;
        let times = members(validity.contents)?;
        let not_before = times.first().and_then(|t| time(t.tag, t.contents));
        let not_after = times.get(1).and_then(|t| time(t.tag, t.contents));

        let (key_algorithm, key_curve, key_bits) = public_key(key_info.contents);

        let mut out = Certificate {
            version,
            serial_hex,
            signature_algorithm,
            subject: one_line(&subject_parts),
            issuer: one_line(&issuer_parts),
            subject_common_name: attribute(&subject_parts, "CN"),
            subject_organisation: attribute(&subject_parts, "O"),
            issuer_common_name: attribute(&issuer_parts, "CN"),
            issuer_organisation: attribute(&issuer_parts, "O"),
            not_before,
            not_after,
            key_algorithm,
            key_bits,
            key_curve,
            self_signed: issuer_tlv.contents == subject_tlv.contents,
            sha256: sha256_hex(der),
            der_bytes: der.len(),
            ..Certificate::default()
        };

        // [3] EXPLICIT extensions, last in the TBS.
        if let Some(explicit) = fields.iter().find(|f| f.tag == 0xa3) {
            let list = tagged(explicit.contents, SEQUENCE)?;
            let all = members(list.contents)?;
            out.extensions_beyond_cap = all.len().saturating_sub(MAX_EXTENSIONS);
            for extension in all.iter().take(MAX_EXTENSIONS) {
                if extension.tag != SEQUENCE {
                    continue;
                }
                let parts = members(extension.contents)?;
                let oid = parts
                    .first()
                    .filter(|p| p.tag == OID)
                    .and_then(|p| oid_dotted(p.contents))?;
                let critical = parts
                    .iter()
                    .find(|p| p.tag == BOOLEAN)
                    .is_some_and(|p| p.contents.first().copied().unwrap_or(0) != 0);
                let value = parts.iter().find(|p| p.tag == OCTET_STRING);
                let name = oid_name(&oid).map(str::to_string).unwrap_or(oid.clone());
                out.extensions.push(Extension {
                    oid: oid.clone(),
                    name,
                    critical,
                    bytes: value.map_or(0, |v| v.contents.len()),
                });
                let Some(value) = value else { continue };
                match oid.as_str() {
                    "2.5.29.17" => out.read_subject_alt_names(value.contents),
                    "2.5.29.19" => {
                        let constraints = tagged(value.contents, SEQUENCE);
                        out.is_certificate_authority = Some(
                            constraints
                                .and_then(|c| members(c.contents))
                                .map(|m| {
                                    m.iter().find(|p| p.tag == BOOLEAN).is_some_and(|p| {
                                        p.contents.first().copied().unwrap_or(0) != 0
                                    })
                                })
                                .unwrap_or(false),
                        );
                    }
                    _ => {}
                }
            }
        }
        Some(out)
    }

    /// `GeneralNames`, each under the kind of name it is. A `DNS` entry and an
    /// `IP` entry are different claims and are never folded together.
    fn read_subject_alt_names(&mut self, contents: &[u8]) {
        let Some(list) = tagged(contents, SEQUENCE) else {
            return;
        };
        let Some(names) = members(list.contents) else {
            return;
        };
        self.names_beyond_cap = self
            .names_beyond_cap
            .saturating_add(names.len().saturating_sub(MAX_NAMES));
        for name in names.iter().take(MAX_NAMES) {
            match name.tag {
                // [2] dNSName, [1] rfc822Name, [6] uniformResourceIdentifier.
                0x82 => self.dns_names.push(text(name.contents)),
                0x81 => self.email_addresses.push(text(name.contents)),
                0x86 => self.uris.push(text(name.contents)),
                // [7] iPAddress, four or sixteen bytes and nothing else.
                0x87 => match name.contents.len() {
                    4 => self.ip_addresses.push(
                        std::net::Ipv4Addr::new(
                            name.contents[0],
                            name.contents[1],
                            name.contents[2],
                            name.contents[3],
                        )
                        .to_string(),
                    ),
                    16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(name.contents);
                        self.ip_addresses
                            .push(std::net::Ipv6Addr::from(octets).to_string());
                    }
                    _ => self.other_names += 1,
                },
                _ => self.other_names += 1,
            }
        }
    }

    /// Every name this certificate claims, in the order it claimed them, with
    /// the common name first — the list an examiner searches. Deduplicated,
    /// because a name repeated in the CN and a SAN is one name.
    pub fn names(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        // Through a set, not a scan of the list so far: a chain of sixteen
        // certificates with two hundred and fifty-six names each is four
        // thousand names, and a linear dedup over them is quadratic in
        // attacker-controlled input.
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut push = |name: &str| {
            if !name.is_empty() && seen.insert(name.to_string()) {
                out.push(name.to_string());
            }
        };
        if let Some(cn) = &self.subject_common_name {
            push(cn);
        }
        for list in [
            &self.dns_names,
            &self.ip_addresses,
            &self.email_addresses,
            &self.uris,
        ] {
            for name in list {
                push(name);
            }
        }
        out
    }

    /// The sentence a certificate record carries. Without it, a record showing
    /// a subject, an issuer and a validity window reads as a certificate this
    /// build checked, which it is not.
    pub fn statement(&self) -> &'static str {
        "The fields above are read from the certificate the server presented. Its signature is \
         NOT verified, no chain is built, no trust store is consulted, no revocation is checked, \
         and the validity window is not compared against any clock -- so `self_signed` is a \
         statement about two names being identical and nothing more. A certificate is what a \
         host CLAIMED to be."
    }

    /// Every reason this record is short of the certificate.
    pub fn shortfalls(&self) -> Vec<(seance_core::io::IncompleteReason, String)> {
        use seance_core::io::IncompleteReason as R;
        let mut out = Vec::new();
        if self.names_beyond_cap > 0 {
            out.push((
                R::CapReached,
                format!(
                    "{} alternative name(s) past this build's ceiling of {MAX_NAMES} were not \
                     read. The name list on this record is therefore a PREFIX of the \
                     certificate's names, and a name that is not on it may still be in the \
                     certificate",
                    self.names_beyond_cap
                ),
            ));
        }
        if self.extensions_beyond_cap > 0 {
            out.push((
                R::CapReached,
                format!(
                    "{} extension(s) past this build's ceiling of {MAX_EXTENSIONS} were not \
                     read or listed",
                    self.extensions_beyond_cap
                ),
            ));
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": self.version,
            "serial": self.serial_hex,
            "signature_algorithm": self.signature_algorithm,
            "subject": self.subject,
            "issuer": self.issuer,
            "subject_common_name": self.subject_common_name,
            "subject_organisation": self.subject_organisation,
            "issuer_common_name": self.issuer_common_name,
            "issuer_organisation": self.issuer_organisation,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "key_algorithm": self.key_algorithm,
            "key_bits": self.key_bits,
            "key_curve": self.key_curve,
            "dns_names": self.dns_names,
            "ip_addresses": self.ip_addresses,
            "email_addresses": self.email_addresses,
            "uris": self.uris,
            "other_names": self.other_names,
            "names": self.names(),
            "is_certificate_authority": self.is_certificate_authority,
            "extensions": self.extensions.iter().map(|e| serde_json::json!({
                "oid": e.oid,
                "name": e.name,
                "critical": e.critical,
                "bytes": e.bytes,
            })).collect::<Vec<_>>(),
            "extensions_beyond_cap": self.extensions_beyond_cap,
            "names_beyond_cap": self.names_beyond_cap,
            "names_are_complete": self.names_beyond_cap == 0,
            "self_signed": self.self_signed,
            "signature_verified": false,
            "chain_built": false,
            "revocation_checked": false,
            "sha256": self.sha256,
            "der_bytes": self.der_bytes,
            "statement": self.statement(),
        })
    }
}

/// An `AlgorithmIdentifier`'s algorithm, named where this build knows it.
fn algorithm_name(contents: &[u8]) -> Option<String> {
    let oid = tagged(contents, OID)?;
    let dotted = oid_dotted(oid.contents)?;
    Some(oid_name(&dotted).map(str::to_string).unwrap_or(dotted))
}

/// The public key's algorithm, its curve where it names one, and its size in
/// bits where this build can count them.
fn public_key(contents: &[u8]) -> (Option<String>, Option<String>, Option<u32>) {
    let Some(parts) = members(contents) else {
        return (None, None, None);
    };
    let Some(algorithm) = parts.first().filter(|p| p.tag == SEQUENCE) else {
        return (None, None, None);
    };
    let name = algorithm_name(algorithm.contents);
    let mut curve = None;
    if let Some(inner) = members(algorithm.contents) {
        if let Some(parameters) = inner.get(1).filter(|p| p.tag == OID) {
            curve = oid_dotted(parameters.contents)
                .map(|dotted| oid_name(&dotted).map(str::to_string).unwrap_or(dotted));
        }
    }
    let bits = parts
        .get(1)
        .filter(|p| p.tag == BIT_STRING)
        .and_then(|key| match name.as_deref() {
            // The BIT STRING's first byte is the count of unused bits; for
            // RSA what follows is SEQUENCE { modulus, exponent }.
            Some("rsaEncryption") => {
                let inner = key.contents.get(1..)?;
                let sequence = tagged(inner, SEQUENCE)?;
                let numbers = members(sequence.contents)?;
                let modulus = numbers.first().filter(|n| n.tag == INTEGER)?;
                let significant = strip_leading_zero(modulus.contents);
                let leading = significant.first()?.leading_zeros();
                u32::try_from(significant.len())
                    .ok()?
                    .checked_mul(8)?
                    .checked_sub(leading)
            }
            // An EC key's size is its curve's; the point itself is twice that
            // plus a format byte, and reporting that as a key size would
            // double every ECDSA certificate in the case.
            _ => None,
        });
    (name, curve, bits)
}

/// A `Name`: a sequence of relative distinguished names, each a set of
/// attribute-and-value pairs.
fn distinguished_name(contents: &[u8]) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for rdn in members(contents)? {
        if rdn.tag != SET {
            continue;
        }
        for pair in members(rdn.contents)? {
            if pair.tag != SEQUENCE {
                continue;
            }
            let parts = members(pair.contents)?;
            let oid = parts
                .first()
                .filter(|p| p.tag == OID)
                .and_then(|p| oid_dotted(p.contents))?;
            let value = parts.get(1).map(|v| text(v.contents)).unwrap_or_default();
            let name = oid_name(&oid).map(str::to_string).unwrap_or(oid);
            out.push((name, value));
        }
    }
    Some(out)
}

/// The one-line form of a distinguished name, in the order it was encoded.
fn one_line(parts: &[(String, String)]) -> String {
    parts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One attribute of a distinguished name. The first, where a name repeats it:
/// every value is in the one-line form, which is the record of the whole name.
fn attribute(parts: &[(String, String)], name: &str) -> Option<String> {
    parts
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// A DER string as text. Lossy on purpose: a name with a byte that is not
/// valid UTF-8 is evidence, and rendering it beats dropping the name.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches('\0')
        .to_string()
}

/// `UTCTime` (two-digit year, 1950–2049 by RFC 5280) or `GeneralizedTime`
/// (four-digit), rendered as RFC 3339 in UTC. `None` for anything else,
/// because a date this build cannot read must not become one it invents.
///
/// Read as **bytes**, not as a `&str` sliced at fixed offsets: a time field is
/// attacker-controlled, `from_utf8` accepts multi-byte characters, and slicing
/// a `&str` at a position that is not a character boundary panics — which, in
/// a certificate inside a capture, would take the whole capture's parse with
/// it.
fn time(tag: u8, contents: &[u8]) -> Option<String> {
    let digits = match contents.split_last() {
        Some((b'Z', rest)) => rest,
        _ => return None,
    };
    // Every remaining byte must be a digit. That is what makes the fixed
    // offsets below safe, and it also refuses the offset forms (`+0100`)
    // RFC 5280 forbids rather than reading them as if they were UTC.
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<u32> {
        let slice = digits.get(from..to)?;
        std::str::from_utf8(slice).ok()?.parse::<u32>().ok()
    };
    let (year, base) = match tag {
        UTC_TIME if digits.len() == 12 => {
            let two = number(0, 2)?;
            // RFC 5280: 50 and above is 19xx, below is 20xx.
            let year = if two >= 50 { 1900 + two } else { 2000 + two };
            (year, 2usize)
        }
        GENERALIZED_TIME if digits.len() == 14 => (number(0, 4)?, 4usize),
        _ => return None,
    };
    let month = number(base, base + 2)?;
    let day = number(base + 2, base + 4)?;
    let hour = number(base + 4, base + 6)?;
    let minute = number(base + 6, base + 8)?;
    let second = number(base + 8, base + 10)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// DER encodes an INTEGER with a leading zero where the top bit would
/// otherwise make it negative. A serial is read as the unsigned number it is,
/// which is the form every other tool prints.
fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The digest an examiner quotes to name one certificate.
fn sha256_hex(der: &[u8]) -> String {
    seance_core::hashing::compute_hashes(der).sha256
}

/// The names in a chain, deduplicated, for the record that summarises it.
pub fn names_in(chain: &[Certificate]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for certificate in chain {
        for name in certificate.names() {
            if seen.insert(name.clone()) {
                out.push(name);
            }
        }
    }
    out
}

/// Every extension OID in a chain and how often it appears — the inventory
/// that says what this build passed over.
pub fn extension_census(chain: &[Certificate]) -> BTreeMap<String, usize> {
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for certificate in chain {
        for extension in &certificate.extensions {
            *out.entry(extension.name.clone()).or_insert(0) += 1;
        }
    }
    out
}

/// Read one TLV, for a test that needs to know what the parser will see.
#[cfg(test)]
pub(crate) fn tlv_for_test(bytes: &[u8]) -> Option<(u8, usize)> {
    tlv(bytes).map(|t| (t.tag, t.total))
}

/// Read one DER time value, for the tests that grade what this build refuses.
#[cfg(test)]
pub(crate) fn validity_for_test(der: &[u8]) -> Option<String> {
    let value = tlv(der)?;
    time(value.tag, value.contents)
}

#[cfg(test)]
#[path = "x509_tests.rs"]
mod x509_tests;
