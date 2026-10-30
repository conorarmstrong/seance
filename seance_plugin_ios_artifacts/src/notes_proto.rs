//! The body of a modern Notes note: `ZICNOTEDATA.ZDATA`, gzip-wrapped
//! protobuf.
//!
//! The path to the text was verified field by field against the two blobs
//! on the Magnet 2022 iOS 15 device, not transcribed from a reference: the
//! top level carries field **2** (a Document), the Document carries field
//! **3** (a Note), and the Note's field **2** is the note text as UTF-8 with
//! `\n` separators. The Note's field 3 is the repeated styling run, field 4 a
//! UUID-ish message and field 5 the repeated edit record — those are walked
//! past, not decoded.
//!
//! The varint reader is local (base-128, ten bytes at most) rather than a
//! protobuf dependency: a length that runs past the buffer is refused, and
//! the inflate is capped so a gzip bomb in a note store cannot take the
//! process with it.

use std::io::Read;

use flate2::read::GzDecoder;

/// Ceiling on the inflated note document. A real body is kilobytes.
pub const MAX_INFLATED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteBodyError {
    /// The blob is not gzip, or the gzip stream is corrupt.
    NotGzip,
    /// The inflated document would exceed [`MAX_INFLATED_BYTES`].
    InflateCapReached,
    /// The protobuf did not have the 2 → 3 → 2 shape.
    UnexpectedStructure,
    /// The text field is not UTF-8.
    NotUtf8,
}

impl NoteBodyError {
    pub fn as_str(&self) -> &'static str {
        match self {
            NoteBodyError::NotGzip => "not_gzip",
            NoteBodyError::InflateCapReached => "inflate_cap_reached",
            NoteBodyError::UnexpectedStructure => "unexpected_structure",
            NoteBodyError::NotUtf8 => "not_utf8",
        }
    }
}

/// Inflate `ZDATA` and return the note's text.
pub fn note_text(zdata: &[u8]) -> Result<String, NoteBodyError> {
    let raw = inflate(zdata)?;
    let document = first_field(&raw, 2).ok_or(NoteBodyError::UnexpectedStructure)?;
    let note = first_field(document, 3).ok_or(NoteBodyError::UnexpectedStructure)?;
    let text = first_field(note, 2).ok_or(NoteBodyError::UnexpectedStructure)?;
    String::from_utf8(text.to_vec()).map_err(|_| NoteBodyError::NotUtf8)
}

fn inflate(zdata: &[u8]) -> Result<Vec<u8>, NoteBodyError> {
    if zdata.len() < 2 || zdata[0] != 0x1f || zdata[1] != 0x8b {
        return Err(NoteBodyError::NotGzip);
    }
    let mut out = Vec::new();
    let mut dec = GzDecoder::new(zdata).take(MAX_INFLATED_BYTES as u64 + 1);
    dec.read_to_end(&mut out)
        .map_err(|_| NoteBodyError::NotGzip)?;
    if out.len() > MAX_INFLATED_BYTES {
        return Err(NoteBodyError::InflateCapReached);
    }
    Ok(out)
}

/// Base-128 varint, at most ten bytes. `None` when it runs off the end.
fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for _ in 0..10 {
        let b = *buf.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            result |= u64::from(b & 0x7f) << shift;
        }
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

/// The payload of the first length-delimited field numbered `field` at this
/// level, skipping the others by wire type. `None` when the message is
/// malformed or the field is absent.
fn first_field(buf: &[u8], field: u64) -> Option<&[u8]> {
    let mut pos = 0usize;
    while pos < buf.len() {
        let key = varint(buf, &mut pos)?;
        let number = key >> 3;
        let wire = key & 7;
        match wire {
            0 => {
                varint(buf, &mut pos)?;
            }
            1 => {
                pos = pos.checked_add(8)?;
                if pos > buf.len() {
                    return None;
                }
            }
            2 => {
                let len = usize::try_from(varint(buf, &mut pos)?).ok()?;
                let end = pos.checked_add(len)?;
                if end > buf.len() {
                    return None;
                }
                if number == field {
                    return Some(&buf[pos..end]);
                }
                pos = end;
            }
            5 => {
                pos = pos.checked_add(4)?;
                if pos > buf.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn len_delimited(field: u64, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![(field << 3 | 2) as u8];
        let mut len = payload.len() as u64;
        loop {
            let b = (len & 0x7f) as u8;
            len >>= 7;
            if len == 0 {
                v.push(b);
                break;
            }
            v.push(b | 0x80);
        }
        v.extend_from_slice(payload);
        v
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    /// The 2 → 3 → 2 shape the real blobs have, with the varint fields the
    /// real Document carries before its Note, and a styling run after the
    /// text so the walk has something to skip.
    fn document(text: &str) -> Vec<u8> {
        let mut note = len_delimited(2, text.as_bytes());
        note.extend(len_delimited(3, &[0x08, 0x00]));
        let mut doc = vec![0x08, 0x00, 0x10, 0x00];
        doc.extend(len_delimited(3, &note));
        let mut top = vec![0x08, 0x00];
        top.extend(len_delimited(2, &doc));
        gzip(&top)
    }

    #[test]
    fn the_text_is_taken_from_field_two_of_the_note_inside_the_document() {
        assert_eq!(
            note_text(&document("Grocery list \nEnergy drinks")).unwrap(),
            "Grocery list \nEnergy drinks"
        );
    }

    #[test]
    fn a_blob_that_is_not_gzip_is_refused_by_name() {
        assert_eq!(note_text(b"plain text"), Err(NoteBodyError::NotGzip));
    }

    #[test]
    fn a_length_that_runs_past_the_buffer_is_refused_rather_than_trusted() {
        // Field 2, length 200, three bytes of payload.
        let bad = gzip(&[0x12, 0xc8, 0x01, 1, 2, 3]);
        assert_eq!(note_text(&bad), Err(NoteBodyError::UnexpectedStructure));
    }

    #[test]
    fn an_unknown_wire_type_stops_the_walk() {
        let bad = gzip(&[0x13]);
        assert_eq!(note_text(&bad), Err(NoteBodyError::UnexpectedStructure));
    }

    #[test]
    fn an_inflate_past_the_ceiling_is_refused() {
        let big = vec![0u8; MAX_INFLATED_BYTES + 1];
        assert_eq!(
            note_text(&gzip(&big)),
            Err(NoteBodyError::InflateCapReached)
        );
    }
}
