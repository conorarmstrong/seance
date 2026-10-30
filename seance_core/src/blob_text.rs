//! Best-effort text recovery from serialized protobuf BLOBs.
//!
//! Several mobile messaging apps (Twitter/X DMs, Snapchat) store the message
//! body inside an opaque protobuf `data` BLOB rather than a plain text column.
//! There is no schema to parse against and it drifts between app versions, so
//! [`recover_protobuf_text`] does a schema-less recovery: it slides over every
//! byte offset, decodes any well-formed length-delimited (wire type 2) field it
//! finds there, and keeps the most sentence-like valid-UTF-8 payload.
//!
//! Reading the *exact* declared field length (rather than scanning printable
//! byte runs) gives clean field boundaries — no leading field tag, no trailing
//! next-field tag — and correct multi-byte UTF-8 (a real apostrophe or emoji,
//! not the mojibake a `byte as char` cast produces). A blob that carries no
//! clean text field (encrypted or ephemeral content) yields `None` rather than
//! binary noise, so callers can honestly flag the body as unrecovered.

/// How sentence-like a candidate string is: letters and spaces count for it,
/// digits against (so an embedded timestamp never outscores the message text).
fn text_score(s: &str) -> i32 {
    s.chars()
        .map(|c| {
            if c.is_alphabetic() || c == ' ' {
                1
            } else if c.is_ascii_digit() {
                -2
            } else {
                0
            }
        })
        .sum()
}

/// Whether `t` reads as a human message rather than an identifier or a bare
/// numeric field.
///
/// [`text_score`] ranks candidate decodes against each other, which is what it
/// is good at. It makes a poor *gate*: it charges -2 per digit, so an ordinary
/// message carrying a phone number scores negative and was discarded outright.
/// `call me on +15551234` earns +11 for its letters and spaces and -16 for its
/// digits, so it never survived — and a phone number, an address or an account
/// reference is exactly the content an examiner is trying to recover from a
/// deleted or partially-overwritten blob.
///
/// The shape test asks the question the digit penalty was reaching for: does
/// this break into separate tokens, the way prose does and an identifier never
/// does? Failing that, do letters at least outnumber digits? A bare numeric
/// field is already excluded by the caller's requirement for two alphabetic
/// characters.
fn is_message_shaped(t: &str) -> bool {
    let letters = t.chars().filter(|c| c.is_alphabetic()).count();
    let digits = t.chars().filter(|c| c.is_ascii_digit()).count();
    t.chars().any(char::is_whitespace) || letters > digits
}

/// Read a base-128 varint at the start of `buf`, returning `(value, bytes_read)`.
/// Caps at 10 bytes (the maximum for a 64-bit varint).
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate().take(10) {
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

fn is_inner_control(c: char) -> bool {
    c.is_control() && c != '\t' && c != '\n' && c != '\r'
}

/// Recover the most sentence-like text from a serialized protobuf BLOB, or
/// `None` if the blob carries no clean text field. Best-effort: the returned
/// string may occasionally include a stray framing character or drop a trailing
/// emoji, and callers should record that the body was recovered heuristically.
pub fn recover_protobuf_text(blob: &[u8]) -> Option<String> {
    let n = blob.len();
    let mut best: Option<(i32, usize, String)> = None; // (score, char_len, text)
    let mut i = 0usize;
    while i < n {
        if let Some((tag, tlen)) = read_varint(&blob[i..]) {
            // Only length-delimited fields (wire type 2) carry strings.
            if tag & 0x7 == 2 {
                if let Some((len, llen)) = read_varint(&blob[i + tlen..]) {
                    let start = i + tlen + llen;
                    // A crafted length varint can be up to u64::MAX: bound it with
                    // checked arithmetic so the window can neither overflow nor
                    // end below its start.
                    let window = usize::try_from(len)
                        .ok()
                        .filter(|&l| l >= 2)
                        .and_then(|l| blob.get(start..start.checked_add(l)?));
                    if let Some(window) = window {
                        let mut raw = window;
                        // A declared length can overrun into the next field's tag
                        // bytes; peel trailing control/binary bytes back off.
                        while let Some((&last, rest)) = raw.split_last() {
                            if last < 0x20 && last != b'\t' && last != b'\n' && last != b'\r' {
                                raw = rest;
                            } else {
                                break;
                            }
                        }
                        // The window may cut a multi-byte UTF-8 sequence (e.g. an
                        // emoji) mid-character; shrink to the last valid boundary.
                        while !raw.is_empty() {
                            match std::str::from_utf8(raw) {
                                Ok(_) => break,
                                Err(e) if e.valid_up_to() > 0 => raw = &raw[..e.valid_up_to()],
                                Err(_) => raw = &[],
                            }
                        }
                        if let Ok(s) = std::str::from_utf8(raw) {
                            let t = s.trim();
                            // Reject a control byte still *inside* the text: that is
                            // a wider offset splicing a neighbouring binary field
                            // onto the message. Trailing ones were already peeled;
                            // real message text has none.
                            let clean = !t.chars().any(is_inner_control);
                            if clean && t.chars().filter(|c| c.is_alphabetic()).count() >= 2 {
                                let score = text_score(t);
                                let cand = (score, t.chars().count(), t.to_string());
                                if is_message_shaped(t)
                                    && best.as_ref().is_none_or(|b| (cand.0, cand.1) > (b.0, b.1))
                                {
                                    best = Some(cand);
                                }
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    best.map(|(_, _, s)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A length varint of u64::MAX used to overflow `start + len` and slice
    /// with an end below its start (panic in debug and release).
    #[test]
    fn a_huge_length_varint_is_refused_not_a_panic() {
        let mut blob = vec![0x0a];
        blob.extend_from_slice(&[0xff; 9]);
        blob.push(0x01);
        blob.extend_from_slice(b"hello world");
        assert_eq!(recover_protobuf_text(&blob), None);
    }

    /// A length-delimited (wire type 2) field: tag byte, single-byte length, body.
    fn field(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn recovers_text_field_over_embedded_timestamp() {
        // A binary prefix, an embedded timestamp string, then the message text.
        let mut blob = vec![0x08, 0x96, 0x01]; // a varint field (noise)
        blob.extend(field(0x6a, b"1720297655680")); // timestamp digits
        blob.extend(field(0x6a, "What's up?!".as_bytes()));
        assert_eq!(recover_protobuf_text(&blob).as_deref(), Some("What's up?!"));
    }

    #[test]
    fn a_message_carrying_a_phone_number_is_not_discarded() {
        // The digit penalty in `text_score` made this score -5, so the body was
        // dropped and the message surfaced with no text at all. Phone numbers,
        // addresses and account references are the point of recovery, not noise.
        let blob = field(0x42, b"call me on +15551234");
        assert_eq!(
            recover_protobuf_text(&blob).as_deref(),
            Some("call me on +15551234")
        );
    }

    #[test]
    fn an_address_that_is_mostly_digits_survives() {
        let blob = field(0x42, b"123 High St, Flat 4");
        assert_eq!(
            recover_protobuf_text(&blob).as_deref(),
            Some("123 High St, Flat 4")
        );
    }

    #[test]
    fn an_identifier_run_is_still_rejected() {
        // No whitespace and digits outnumbering letters: the shape the digit
        // penalty existed to reject, and it still is rejected.
        let blob = field(0x42, b"ab1234567890123");
        assert_eq!(recover_protobuf_text(&blob), None);
    }

    #[test]
    fn decodes_multibyte_utf8_cleanly() {
        // A right single quote (U+2019) must survive as itself, not mojibake.
        let blob = field(0x42, "Let’s hope".as_bytes());
        assert_eq!(recover_protobuf_text(&blob).as_deref(), Some("Let’s hope"));
    }

    #[test]
    fn no_leading_or_trailing_framing() {
        // Preceding and following field tags must not leak into the result.
        let mut blob = field(0x4a, b"BV"); // a short neighbouring field
        blob.extend(field(0x42, b"It's ok. It's a darker roast."));
        blob.push(0x4d); // a trailing next-field tag byte
        assert_eq!(
            recover_protobuf_text(&blob).as_deref(),
            Some("It's ok. It's a darker roast."),
        );
    }

    #[test]
    fn rejects_encrypted_or_binary_blob() {
        // No clean length-delimited text field → None, not binary noise.
        let blob = [
            0x9f, 0x03, 0xdb, 0xdc, 0x7b, 0xe3, 0x46, 0x52, 0x00, 0x11, 0x88,
        ];
        assert_eq!(recover_protobuf_text(&blob), None);
    }

    #[test]
    fn empty_blob_is_none() {
        assert_eq!(recover_protobuf_text(&[]), None);
    }
}
