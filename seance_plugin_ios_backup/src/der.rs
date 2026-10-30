//! The DER reader for a decrypted iOS keychain item (HUNT-111).
//!
//! An item's decrypted attributes are one DER `SET` of `SEQUENCE { UTF8String
//! name, value }`, the value being a UTF8String, OCTET STRING, INTEGER or
//! GeneralizedTime (the Hickman iOS 17 backup uses exactly those four). This
//! reads that shape and nothing more. Values borrow from the plaintext buffer,
//! so the secret (`v_Data`) is never copied out of the zeroizing buffer the
//! decryption returned.
//!
//! Every length is checked against what remains: a truncated or malformed
//! item is an `Err`, never a panic and never a partial set presented as whole.

/// One attribute value, borrowed from the decrypted item.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DerValue<'a> {
    Utf8(&'a str),
    /// Tagged UTF8String but not valid UTF-8; the bytes are kept as found.
    InvalidUtf8(&'a [u8]),
    Octets(&'a [u8]),
    Integer(i64),
    /// An INTEGER wider than 64 bits, as its two's-complement bytes.
    BigInteger(&'a [u8]),
    /// A GeneralizedTime, as its text (`20240725182233Z`).
    Time(&'a str),
    Boolean(bool),
    Null,
    Other {
        tag: u8,
        bytes: &'a [u8],
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DerError(pub String);

impl std::fmt::Display for DerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_UTF8: u8 = 0x0c;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

/// Read one TLV at `pos`: its tag, its contents, and the offset after it.
fn read_tlv(data: &[u8], pos: usize) -> Result<(u8, &[u8], usize), DerError> {
    let err = |what: &str| DerError(format!("DER {what} at offset {pos}"));
    let tag = *data.get(pos).ok_or_else(|| err("tag truncated"))?;
    if tag & 0x1f == 0x1f {
        return Err(err("multi-byte tag (not used by the keychain)"));
    }
    let first = *data.get(pos + 1).ok_or_else(|| err("length truncated"))?;
    let mut p = pos + 2;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 {
            return Err(err("indefinite length (not DER)"));
        }
        if n > 4 {
            return Err(err("length wider than 32 bits"));
        }
        let bytes = data.get(p..p + n).ok_or_else(|| err("length truncated"))?;
        p += n;
        bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize)
    };
    let end = p
        .checked_add(len)
        .filter(|e| *e <= data.len())
        .ok_or_else(|| err("contents truncated"))?;
    Ok((tag, &data[p..end], end))
}

fn value(tag: u8, bytes: &[u8]) -> DerValue<'_> {
    match tag {
        TAG_UTF8 => match std::str::from_utf8(bytes) {
            Ok(s) => DerValue::Utf8(s),
            Err(_) => DerValue::InvalidUtf8(bytes),
        },
        TAG_OCTET_STRING => DerValue::Octets(bytes),
        TAG_INTEGER if !bytes.is_empty() && bytes.len() <= 8 => {
            let neg = bytes[0] & 0x80 != 0;
            let mut v: i64 = if neg { -1 } else { 0 };
            for b in bytes {
                v = (v << 8) | *b as i64;
            }
            DerValue::Integer(v)
        }
        TAG_INTEGER => DerValue::BigInteger(bytes),
        TAG_GENERALIZED_TIME => match std::str::from_utf8(bytes) {
            Ok(s) => DerValue::Time(s),
            Err(_) => DerValue::Other { tag, bytes },
        },
        TAG_BOOLEAN if bytes.len() == 1 => DerValue::Boolean(bytes[0] != 0),
        TAG_NULL if bytes.is_empty() => DerValue::Null,
        _ => DerValue::Other { tag, bytes },
    }
}

/// Read a keychain item's decrypted attribute set: `SET OF SEQUENCE {
/// UTF8String name, value }`, in stored order.
pub(crate) fn read_attribute_set(data: &[u8]) -> Result<Vec<(&str, DerValue<'_>)>, DerError> {
    let (tag, contents, end) = read_tlv(data, 0)?;
    if tag != TAG_SET {
        return Err(DerError(format!(
            "expected a DER SET (0x31), found tag 0x{tag:02x}"
        )));
    }
    if end != data.len() && data[end..].iter().any(|b| *b != 0) {
        return Err(DerError(format!(
            "{} bytes follow the attribute set",
            data.len() - end
        )));
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < contents.len() {
        let (tag, seq, next) = read_tlv(contents, pos)?;
        if tag != TAG_SEQUENCE {
            return Err(DerError(format!(
                "attribute {} is tag 0x{tag:02x}, not a SEQUENCE",
                out.len()
            )));
        }
        let (ktag, key, q) = read_tlv(seq, 0)?;
        if ktag != TAG_UTF8 {
            return Err(DerError(format!(
                "attribute {} has a name of tag 0x{ktag:02x}, not UTF8String",
                out.len()
            )));
        }
        let key = std::str::from_utf8(key)
            .map_err(|_| DerError(format!("attribute {} name is not UTF-8", out.len())))?;
        let (vtag, vbytes, r) = read_tlv(seq, q)?;
        if r != seq.len() {
            return Err(DerError(format!(
                "attribute {key} carries more than a name and a value"
            )));
        }
        out.push((key, value(vtag, vbytes)));
        pos = next;
    }
    Ok(out)
}

/// Build DER for a synthetic fixture. Nothing in the product writes DER.
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod build {
    pub(crate) fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = body.len();
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x100 {
            out.extend_from_slice(&[0x81, n as u8]);
        } else {
            out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        out.extend_from_slice(body);
        out
    }

    /// `SET { SEQUENCE { UTF8String name, <tag> value } ... }`.
    pub(crate) fn attribute_set(attrs: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, tag, v) in attrs {
            let mut seq = tlv(super::TAG_UTF8, name.as_bytes());
            seq.extend(tlv(*tag, v));
            body.extend(tlv(super::TAG_SEQUENCE, &seq));
        }
        tlv(super::TAG_SET, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_reads_keychain_attribute_set() {
        let secret = [0xAAu8; 200];
        let der = build::attribute_set(&[
            ("acct", TAG_UTF8, b"a@b"),
            ("cdat", TAG_GENERALIZED_TIME, b"20240725182233Z"),
            ("v_Data", TAG_OCTET_STRING, &secret),
            ("sync", TAG_INTEGER, &[0x01]),
            ("neg", TAG_INTEGER, &[0xff, 0x7f]),
        ]);
        let attrs = read_attribute_set(&der).unwrap();
        assert_eq!(
            attrs,
            vec![
                ("acct", DerValue::Utf8("a@b")),
                ("cdat", DerValue::Time("20240725182233Z")),
                ("v_Data", DerValue::Octets(&secret)),
                ("sync", DerValue::Integer(1)),
                ("neg", DerValue::Integer(-129)),
            ]
        );
    }

    #[test]
    fn der_truncated_or_malformed_is_an_error_not_a_panic() {
        let der = build::attribute_set(&[("acct", TAG_UTF8, b"someone")]);
        for cut in 0..der.len() {
            assert!(read_attribute_set(&der[..cut]).is_err(), "cut at {cut}");
        }
        // A length that claims more than the buffer holds.
        assert!(read_attribute_set(&[0x31, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
        // Indefinite length.
        assert!(read_attribute_set(&[0x31, 0x80, 0x00, 0x00]).is_err());
        // Not a SET.
        assert!(read_attribute_set(&[0x30, 0x00]).is_err());
    }
}
