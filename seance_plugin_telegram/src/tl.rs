//! Message-body recovery from Telegram's TL-serialized `data` BLOB.
//!
//! `cache4.db` keeps the message text inside the row's `data` BLOB, a
//! TL-serialized `TLRPC.Message`. The object's *layout* is version-specific —
//! fields are added, re-typed and re-ordered between API layers — so decoding
//! it by assuming a layout is how a parser surfaces the wrong text. Two things
//! do not drift, and only those are used here:
//!
//! 1. TL's wire encoding of a `string`: a one-byte length, or `0xFE` followed
//!    by a three-byte little-endian length for 254 bytes and over, then the
//!    bytes, then **zero** padding to the next 4-byte boundary. Every TL value
//!    is 4-byte aligned, so every field starts on a multiple of 4.
//! 2. `message:string` immediately follows `date:int` in the `message`
//!    constructor, and has in every published layer.
//!
//! So the body is found by *anchoring on the row's own `date` column* — a fact
//! this parser already holds from ordinary SQL — instead of assuming where in
//! the object the field sits. A candidate must frame as a well-formed TL
//! string, land inside the blob, be padded with zeros, decode as UTF-8 and
//! carry no embedded control bytes.
//!
//! The row's date can legitimately appear more than once in one object (an
//! attached photo carries its own `date`, as does a forward header), so when
//! several anchors decode they must all agree. They disagree and the body stays
//! **absent**: recovering the wrong message text is worse than recovering none,
//! and the record says which happened (`text_recovered`).

/// The payload of a TL `string` at `at`, or `None` if nothing there frames as
/// one.
///
/// The padding is required to be zero. TL always writes it as zero, and it is
/// the check that rejects an offset which merely *looks* like a length prefix:
/// without it, any byte followed by that many bytes of text would read as a
/// string.
fn read_tl_string(blob: &[u8], at: usize) -> Option<&[u8]> {
    let (len, prefix) = match *blob.get(at)? {
        // 0xFF is not a legal length prefix; 0xFE introduces the long form.
        0xFF => return None,
        0xFE => {
            let n = blob.get(at + 1..at + 4)?;
            (u32::from_le_bytes([n[0], n[1], n[2], 0]) as usize, 4)
        }
        n => (n as usize, 1),
    };
    let unpadded = prefix + len;
    let padded = unpadded.next_multiple_of(4);
    let body = blob.get(at + prefix..at + unpadded)?;
    let padding = blob.get(at + unpadded..at + padded)?;
    if padding.iter().any(|&b| b != 0) {
        return None;
    }
    Some(body)
}

/// A control character no real message body carries. Tab, newline and carriage
/// return are ordinary in a multi-line message and stay.
fn is_inner_control(c: char) -> bool {
    c.is_control() && c != '\t' && c != '\n' && c != '\r'
}

/// A body candidate at `at`: a well-formed, non-empty TL string that decodes as
/// UTF-8 and holds no embedded control bytes.
///
/// An *empty* TL string is four zero bytes — a pattern far too common inside a
/// serialized object to read as evidence that this row had no text — so it is
/// ignored rather than reported as a decoded empty body. A media message with
/// no caption therefore keeps an absent body, which is what it is: this parser
/// could not establish one.
fn candidate(blob: &[u8], at: usize) -> Option<&str> {
    let text = std::str::from_utf8(read_tl_string(blob, at)?).ok()?;
    if text.is_empty() || text.chars().any(is_inner_control) {
        return None;
    }
    Some(text)
}

/// The message body from a TL-serialized `TLRPC.Message`, anchored on the
/// `date` the row carries in its own column.
///
/// `None` when no anchor decodes, and also when two anchors decode to different
/// text: an ambiguous read is not a body.
pub(crate) fn message_text(blob: &[u8], date_s: i64) -> Option<String> {
    // `date:int` is a 32-bit field. A row whose date does not fit was not
    // written by this schema, and there is nothing to anchor on.
    let needle = i32::try_from(date_s).ok()?.to_le_bytes();
    let mut found: Option<&str> = None;
    // Every TL value is 4-byte aligned, so only aligned offsets can hold the
    // `date` field. Offset 0 is the constructor id and is never it.
    for at in (4..blob.len().saturating_sub(3)).step_by(4) {
        if blob[at..at + 4] != needle {
            continue;
        }
        if let Some(text) = candidate(blob, at + 4) {
            match found {
                Some(prev) if prev != text => return None,
                _ => found = Some(text),
            }
        }
    }
    found.map(str::to_string)
}
