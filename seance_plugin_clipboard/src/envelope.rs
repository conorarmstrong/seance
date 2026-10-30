//! Recognising a CNG DPAPI protected blob, without decrypting it.
//!
//! # What this is for
//!
//! Windows encrypts each pinned clipboard payload before writing it. This
//! establishes **that** a file is such a blob, and recovers the part of it that
//! is deliberately left in the clear, so a record can say what the file is
//! rather than reporting an unreadable lump of bytes.
//!
//! It does not decrypt, and is not a step towards decrypting. See
//! [`crate`] for why that is the right scope.
//!
//! # The format
//!
//! `NCryptProtectSecret` output is an ASN.1 DER blob holding CMS enveloped
//! content: encrypted content, recipient information carrying an encrypted
//! content-encryption key, and a header that includes — Microsoft's own
//! documentation is explicit about this — *the unencrypted protection
//! descriptor rule string*.
//!
//! That rule string is the forensically useful part. For clipboard data it
//! names the SID the payload was protected to, which answers "whose clipboard
//! is this?" from a file whose contents cannot be read.
//!
//! # What is parsed, and what is scanned
//!
//! The two are kept apart because they carry different confidence, and a record
//! that presented them alike would overstate the weaker one.
//!
//! The outer `ContentInfo` is **parsed**: a DER `SEQUENCE` whose first element
//! is an OID, compared against `id-envelopedData`. That is a structural fact.
//!
//! The rule string is **scanned** for. Its exact nesting inside
//! `KEKRecipientInfo` is not something this parser walks to, so it is found by
//! searching the blob for the documented `SID=` prefix in both byte encodings
//! Windows uses. A scan can miss, and can in principle match a coincidence, so
//! the result is reported as recovered-by-scan and never as a parsed field.

/// DER tag for a constructed SEQUENCE.
const TAG_SEQUENCE: u8 = 0x30;
/// DER tag for an OBJECT IDENTIFIER.
const TAG_OID: u8 = 0x06;

/// `id-envelopedData` — 1.2.840.113549.1.7.3 — DER-encoded.
const OID_ENVELOPED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03];

/// `id-data` — 1.2.840.113549.1.7.1. Not a content type this artifact uses;
/// kept so the test that proves an unexpected type is *named rather than
/// guessed at* has a real OID to name.
#[cfg(test)]
const OID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];

/// How far into a blob to look for the descriptor rule string.
///
/// It sits in the header, ahead of the ciphertext. Scanning the whole of a
/// large payload would cost time to find nothing, and would raise the chance of
/// matching `SID=` inside encrypted bytes, which look random and are long.
const DESCRIPTOR_SCAN_LIMIT: usize = 8 * 1024;

/// Longest plausible descriptor rule string, in characters. A SID runs to about
/// 90; the ceiling is a bound on a value taken from evidence, not an estimate.
const MAX_DESCRIPTOR_CHARS: usize = 512;

/// What a payload file turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    /// A CMS enveloped-data blob, as `NCryptProtectSecret` writes.
    Protected {
        /// The protection descriptor rule string, when the scan found one.
        ///
        /// `None` means it was not found, which is **not** the same as the blob
        /// having none: see the module documentation on scanning.
        descriptor: Option<String>,
        /// How the descriptor was encoded, when one was found.
        descriptor_encoding: Option<&'static str>,
    },
    /// Well-formed DER, but not the content type this format uses.
    OtherDer {
        /// The content-type OID, dotted, when it could be read.
        content_type: Option<String>,
    },
    /// Not DER at all. Recorded rather than assumed to be corruption: an
    /// unencrypted payload would land here, and that would be a finding.
    NotDer,
    /// Too short to be either.
    TooShort,
}

impl Envelope {
    /// A stable token for artifact metadata.
    pub fn kind(&self) -> &'static str {
        match self {
            Envelope::Protected { .. } => "cms_enveloped_data",
            Envelope::OtherDer { .. } => "der_other_content_type",
            Envelope::NotDer => "not_der",
            Envelope::TooShort => "too_short",
        }
    }

    /// One sentence for an examiner, saying what can and cannot be read.
    pub fn statement(&self) -> String {
        match self {
            Envelope::Protected {
                descriptor: Some(d),
                ..
            } => format!(
                "Encrypted by Windows before it was written (CMS enveloped data, as \
                 NCryptProtectSecret produces). The contents cannot be read from this file \
                 alone. The blob's own unencrypted header says it is protected to {d}."
            ),
            Envelope::Protected {
                descriptor: None, ..
            } => "Encrypted by Windows before it was written (CMS enveloped data, as \
                  NCryptProtectSecret produces). The contents cannot be read from this file \
                  alone, and no protection descriptor was recovered from its header."
                .to_string(),
            Envelope::OtherDer { content_type } => format!(
                "A DER structure whose content type is {}, which is not the enveloped-data \
                 type this artifact normally uses. Worth looking at directly.",
                content_type.as_deref().unwrap_or("unreadable")
            ),
            Envelope::NotDer => "Not a DER structure. Windows encrypts these payloads before \
                                 writing them, so a file that is not one has either been \
                                 altered or is not what its location implies — either way it \
                                 is worth looking at directly."
                .to_string(),
            Envelope::TooShort => {
                "Too short to be a protected payload; nothing can be said about it.".to_string()
            }
        }
    }
}

/// Identify a payload file.
pub fn inspect(bytes: &[u8]) -> Envelope {
    let Some((content_type, _rest)) = outer_content_type(bytes) else {
        return if bytes.len() < 4 {
            Envelope::TooShort
        } else {
            Envelope::NotDer
        };
    };

    if content_type == OID_ENVELOPED_DATA {
        let (descriptor, descriptor_encoding) = match find_descriptor(bytes) {
            Some((d, enc)) => (Some(d), Some(enc)),
            None => (None, None),
        };
        return Envelope::Protected {
            descriptor,
            descriptor_encoding,
        };
    }

    Envelope::OtherDer {
        content_type: Some(dotted_oid(content_type)),
    }
}

/// The content-type OID of a DER `ContentInfo`, if the blob is one.
///
/// Deliberately shallow: enough to name the structure, and no deeper, because
/// everything below it is either encrypted or not needed.
fn outer_content_type(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (body, rest) = read_tlv(bytes, TAG_SEQUENCE)?;
    let (oid, _) = read_tlv(body, TAG_OID)?;
    Some((oid, rest))
}

/// One DER tag-length-value, when the tag matches.
///
/// Rejects the indefinite-length form: DER forbids it, and accepting it would
/// mean trusting a length this function cannot check.
fn read_tlv(bytes: &[u8], want_tag: u8) -> Option<(&[u8], &[u8])> {
    let tag = *bytes.first()?;
    if tag != want_tag {
        return None;
    }
    let first_len = *bytes.get(1)?;
    let (len, header) = if first_len < 0x80 {
        (first_len as usize, 2usize)
    } else {
        let count = (first_len & 0x7F) as usize;
        // 0x80 is the indefinite form; more than 4 length bytes is a length no
        // evidence file legitimately carries and would risk overflow on 32-bit.
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | (*bytes.get(2 + i)? as usize);
        }
        (len, 2 + count)
    };
    let end = header.checked_add(len)?;
    let body = bytes.get(header..end)?;
    Some((body, &bytes[end..]))
}

/// A DER OID rendered dotted, so a record can name an unexpected content type.
fn dotted_oid(encoded: &[u8]) -> String {
    let Some(&first) = encoded.first() else {
        return String::new();
    };
    let mut parts = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut value: u64 = 0;
    let mut overflowed = false;
    for &byte in &encoded[1..] {
        // A component wider than u64 cannot come from a real OID; stop claiming
        // to have read it rather than wrap.
        if value > (u64::MAX >> 7) {
            overflowed = true;
            break;
        }
        value = (value << 7) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            parts.push(value.to_string());
            value = 0;
        }
    }
    if overflowed {
        parts.push("?".to_string());
    }
    parts.join(".")
}

/// Look for the protection descriptor rule string in the blob's header.
///
/// Returns the string and the encoding it was found in. Windows writes these
/// as either plain bytes or UTF-16LE depending on the field, so both are tried
/// and the answer records which matched — an examiner asked how a value was
/// obtained should not have to guess.
fn find_descriptor(bytes: &[u8]) -> Option<(String, &'static str)> {
    let window = &bytes[..bytes.len().min(DESCRIPTOR_SCAN_LIMIT)];

    if let Some(found) = scan_ascii(window) {
        return Some((found, "ascii"));
    }
    if let Some(found) = scan_utf16le(window) {
        return Some((found, "utf-16le"));
    }
    None
}

/// Characters a descriptor rule string is built from.
///
/// A SID is `S-1-` followed by digits and hyphens; the rule syntax adds `=`,
/// spaces and boolean keywords. Stopping at anything else is what keeps a match
/// from running on into the ciphertext that follows it.
fn is_descriptor_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '=' | '.' | '_' | ' ' | '(' | ')')
}

fn scan_ascii(window: &[u8]) -> Option<String> {
    const NEEDLE: &[u8] = b"SID=";
    let at = window
        .windows(NEEDLE.len())
        .position(|w| w.eq_ignore_ascii_case(NEEDLE))?;
    let mut out = String::new();
    for &byte in &window[at..] {
        let c = byte as char;
        if !byte.is_ascii() || !is_descriptor_char(c) || out.len() >= MAX_DESCRIPTOR_CHARS {
            break;
        }
        out.push(c);
    }
    plausible(out)
}

fn scan_utf16le(window: &[u8]) -> Option<String> {
    const NEEDLE: &[u8] = b"S\0I\0D\0=\0";
    let at = window
        .windows(NEEDLE.len())
        .position(|w| {
            w[0].eq_ignore_ascii_case(&b'S')
                && w[1] == 0
                && w[2..].eq_ignore_ascii_case(&b"I\0D\0=\0"[..])
        })
        .or_else(|| window.windows(NEEDLE.len()).position(|w| w == NEEDLE))?;
    let mut out = String::new();
    let mut i = at;
    while i + 1 < window.len() && out.len() < MAX_DESCRIPTOR_CHARS {
        // Non-zero high byte means this is no longer ASCII-in-UTF-16, which is
        // where a descriptor ends and the surrounding structure begins.
        if window[i + 1] != 0 {
            break;
        }
        let c = window[i] as char;
        if !window[i].is_ascii() || !is_descriptor_char(c) {
            break;
        }
        out.push(c);
        i += 2;
    }
    plausible(out)
}

/// Refuse a match that is only the needle.
///
/// `SID=` on its own says nothing and could as easily be four bytes of
/// ciphertext. Requiring the `S-1-` a real SID starts with is what makes the
/// scan's output worth printing.
fn plausible(found: String) -> Option<String> {
    descriptor_sid(&found)?;
    Some(found)
}

/// The SID a descriptor names: the text after a `SID=` prefix in any letter
/// case, provided it begins `S-1-`. The one predicate both the header scan
/// ([`plausible`]) and the record's `protected_to_sid` use, so a descriptor the
/// scan accepts always yields its SID.
pub(crate) fn descriptor_sid(descriptor: &str) -> Option<&str> {
    let value = descriptor
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("SID="))
        .map(|_| &descriptor[4..])?;
    if value.len() < 4 || !value.to_ascii_uppercase().starts_with("S-1-") {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DER `ContentInfo` around a content-type OID.
    fn content_info(oid: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut inner = vec![TAG_OID, oid.len() as u8];
        inner.extend_from_slice(oid);
        inner.extend_from_slice(payload);
        let mut out = vec![TAG_SEQUENCE];
        if inner.len() < 0x80 {
            out.push(inner.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn an_enveloped_data_blob_is_recognised() {
        let blob = content_info(OID_ENVELOPED_DATA, &[0xA0, 0x03, 0x02, 0x01, 0x00]);
        assert!(matches!(inspect(&blob), Envelope::Protected { .. }));
        assert_eq!(inspect(&blob).kind(), "cms_enveloped_data");
    }

    #[test]
    fn another_der_content_type_is_named_rather_than_guessed_at() {
        let blob = content_info(OID_DATA, &[0x04, 0x01, 0x00]);
        match inspect(&blob) {
            Envelope::OtherDer { content_type } => {
                assert_eq!(content_type.as_deref(), Some("1.2.840.113549.1.7.1"))
            }
            other => panic!("expected OtherDer, got {other:?}"),
        }
    }

    /// An unencrypted payload must be visible as such, not filed as damage.
    #[test]
    fn a_payload_that_is_not_der_is_reported_as_a_finding() {
        assert_eq!(inspect(b"plain text on disk!!"), Envelope::NotDer);
        assert!(inspect(b"plain text on disk!!")
            .statement()
            .contains("worth looking at directly"));
        assert_eq!(inspect(b"ab"), Envelope::TooShort);
        assert_eq!(inspect(&[]), Envelope::TooShort);
    }

    #[test]
    fn a_descriptor_is_recovered_from_ascii_and_from_utf16() {
        let sid = "S-1-5-21-1004336348-1177238915-682003330-512";

        let mut ascii = content_info(OID_ENVELOPED_DATA, &[]);
        ascii.extend_from_slice(format!("SID={sid}").as_bytes());
        match inspect(&ascii) {
            Envelope::Protected {
                descriptor: Some(d),
                descriptor_encoding: Some(enc),
            } => {
                assert_eq!(d, format!("SID={sid}"));
                assert_eq!(enc, "ascii");
            }
            other => panic!("expected an ascii descriptor, got {other:?}"),
        }

        let mut wide = content_info(OID_ENVELOPED_DATA, &[]);
        for b in format!("SID={sid}").bytes() {
            wide.push(b);
            wide.push(0);
        }
        match inspect(&wide) {
            Envelope::Protected {
                descriptor: Some(d),
                descriptor_encoding: Some(enc),
            } => {
                assert_eq!(d, format!("SID={sid}"));
                assert_eq!(enc, "utf-16le");
            }
            other => panic!("expected a utf-16le descriptor, got {other:?}"),
        }
    }

    /// **The scan must not report a coincidence as a finding.**
    ///
    /// `SID=` is four bytes, and the ciphertext it sits next to is long and
    /// looks random. A match that is not followed by something SID-shaped is a
    /// collision, and printing it would put an invented account identifier in
    /// front of an examiner.
    #[test]
    fn a_bare_needle_in_random_bytes_is_not_reported_as_a_descriptor() {
        let mut blob = content_info(OID_ENVELOPED_DATA, &[]);
        blob.extend_from_slice(b"SID=\xff\xfe\x01\x02rubbish");
        assert!(
            matches!(
                inspect(&blob),
                Envelope::Protected {
                    descriptor: None,
                    ..
                }
            ),
            "a needle with no SID behind it must not be reported"
        );

        let mut short = content_info(OID_ENVELOPED_DATA, &[]);
        short.extend_from_slice(b"SID=S-1");
        // "S-1" is three characters, below the floor: too little to be a SID.
        assert!(matches!(
            inspect(&short),
            Envelope::Protected {
                descriptor: None,
                ..
            }
        ));
    }

    /// A descriptor must stop at the ciphertext rather than run into it.
    #[test]
    fn a_descriptor_stops_where_the_string_stops() {
        let mut blob = content_info(OID_ENVELOPED_DATA, &[]);
        blob.extend_from_slice(b"SID=S-1-5-18\x00\xff\xfe\xfdmore ciphertext");
        match inspect(&blob) {
            Envelope::Protected {
                descriptor: Some(d),
                ..
            } => assert_eq!(d, "SID=S-1-5-18"),
            other => panic!("expected a bounded descriptor, got {other:?}"),
        }
    }

    /// Hostile input must not panic, hang, or run past the blob.
    #[test]
    fn arbitrary_bytes_are_refused_without_panicking() {
        // Lengths that claim more than the buffer holds.
        for blob in [
            vec![TAG_SEQUENCE, 0x7F],
            vec![TAG_SEQUENCE, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            vec![TAG_SEQUENCE, 0x80],
            vec![TAG_SEQUENCE, 0x85, 1, 2, 3, 4, 5],
            vec![TAG_SEQUENCE, 0x02, TAG_OID, 0x7F],
        ] {
            let _ = inspect(&blob);
        }
        let mut lcg: u64 = 0x2545_F491_4F6C_DD1D;
        for len in [1usize, 7, 64, 1024, 9000] {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    lcg = lcg.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    (lcg >> 33) as u8
                })
                .collect();
            let _ = inspect(&bytes);
        }
    }

    #[test]
    fn an_oid_is_rendered_dotted() {
        assert_eq!(dotted_oid(OID_ENVELOPED_DATA), "1.2.840.113549.1.7.3");
        assert_eq!(dotted_oid(&[0x2A, 0x03]), "1.2.3");
        assert_eq!(dotted_oid(&[]), "");
    }
}
