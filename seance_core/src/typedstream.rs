//! Extract message text from an iMessage `attributedBody` Apple typedstream blob.
//!
//! Modern iMessage stores the message body not in `message.text` but in
//! `message.attributedBody`: an `NSAttributedString` serialized with the classic
//! Apple *typedstream* format (`NSArchiver`, magic `\x04\x0bstreamtyped`), not
//! the bplist-based `NSKeyedArchiver`. Recovering the plain text turns an
//! otherwise-opaque blob (whose readable fragments are class names like
//! `NSMutableAttributedString`) into the actual message.
//!
//! This is an independent, forensic-tolerant implementation of the text-extraction
//! step. The byte layout — the `01 2B` marker that precedes the string, the
//! typedstream length encoding, and the `86 84` marker that begins the attribute
//! runs — matches the format documented by the reference `imessage-database`
//! crate's `util::streamtyped` parser and was verified against real `chat.db`
//! blobs. It never panics: malformed or partial input yields `None`.
//!
//! Layout of the relevant region (verified against a real message "Stalo se"):
//! ```text
//! ... NSString 01 94 84 | 01 2B | 08 | 53 74 61 6C 6F 20 73 65 | 86 84 ...
//!     class decl        | start | len| "Stalo se" (8 bytes)     | attr runs
//! ```

/// Marker immediately preceding the string's length byte.
const START: [u8; 2] = [0x01, 0x2b];
/// Marker that begins the trailing attribute-run data (end of the text).
const END: [u8; 2] = [0x86, 0x84];
/// Object-replacement char (U+FFFC) marks an attachment; drop it from the text.
const OBJ_REPLACEMENT: char = '\u{FFFC}';

/// Extract the message text from an `attributedBody` typedstream blob, or `None`
/// when the blob is not a recognizable typedstream string. Tolerant of partial /
/// recovered blobs: it only requires the `NSString`/`streamtyped` scaffolding and
/// the `01 2B` marker to be present.
pub fn extract_message_text(blob: &[u8]) -> Option<String> {
    // Gate on the typedstream signature so we never mis-parse an unrelated blob.
    if !contains(blob, b"streamtyped") && !contains(blob, b"NSString") {
        return None;
    }
    let mut from = 0;
    while let Some(rel) = find(&blob[from..], &START) {
        let after = from + rel + START.len();
        if let Some((text_start, len)) = read_length(blob, after) {
            let mut end = (text_start + len).min(blob.len());
            // A damaged length must not run past the attribute-run marker.
            if let Some(m) = find_end_marker(&blob[text_start..end]) {
                end = text_start + m;
            }
            if end > text_start {
                let text = clean(&String::from_utf8_lossy(&blob[text_start..end]));
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
        from = after; // try the next candidate marker
    }
    None
}

/// Read a typedstream length at `off`: a single byte for lengths < 128, or a
/// `0x81`-prefixed little-endian i16 (`0x82`-prefixed i32) for longer strings.
/// Returns `(text_start, length)`.
fn read_length(blob: &[u8], off: usize) -> Option<(usize, usize)> {
    let b = *blob.get(off)?;
    match b {
        0x81 => {
            let lo = *blob.get(off + 1)? as usize;
            let hi = *blob.get(off + 2)? as usize;
            Some((off + 3, lo | (hi << 8)))
        }
        0x82 => {
            let mut v = 0usize;
            for i in 0..4 {
                v |= (*blob.get(off + 1 + i)? as usize) << (8 * i);
            }
            Some((off + 5, v))
        }
        // 0x80 is a reserved typedstream marker, not a length.
        0x80 => None,
        n => Some((off + 1, n as usize)),
    }
}

/// Offset of the first [`END`] marker in `text` that is a real one.
///
/// `86 84` is also a valid UTF-8 continuation pair (U+2184, U+1F184, the Hangul
/// syllables U+B184 / U+C184 / U+D184 ...), so a match inside a multi-byte
/// character is text, not the attribute-run marker. A genuine marker follows a
/// complete character, so one whose preceding bytes end an unfinished
/// multi-byte sequence is skipped.
fn find_end_marker(text: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = find(&text[from..], &END) {
        let at = from + rel;
        if !ends_mid_character(&text[..at]) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// Whether `bytes` ends inside a UTF-8 multi-byte sequence that has not
/// received all of its continuation bytes.
fn ends_mid_character(bytes: &[u8]) -> bool {
    for (back, &b) in bytes.iter().rev().take(3).enumerate() {
        let have = back + 1; // bytes from this one to the end
        match b {
            0x80..=0xBF => continue, // continuation: keep looking for the lead
            0xC0..=0xDF => return 2 > have,
            0xE0..=0xEF => return 3 > have,
            0xF0..=0xF7 => return 4 > have,
            _ => return false, // ASCII or invalid: nothing is pending
        }
    }
    false
}

/// Strip attachment placeholders and surrounding whitespace/control noise.
fn clean(s: &str) -> String {
    s.chars()
        .filter(|&c| c != OBJ_REPLACEMENT && c != '\u{FFFD}')
        .collect::<String>()
        .trim_matches(|c: char| c.is_control() || c == '\u{0}')
        .to_string()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `attributedBody` blob for the message "Stalo se", captured from a
    /// chat.db message row.
    fn stalo_se_blob() -> Vec<u8> {
        let hex = "040B73747265616D747970656481E803840140848484124E5341747472696275746564\
                   537472696E67008484084E534F626A656374008592848484084E53537472696E6701948\
                   4012B08 5374616C6F207365 86840269490108928484840C4E5344696374696F6E617279\
                   009484016901928496961D5F5F6B494D4D657373616765506172744174747269627574654\
                   E616D658692848484084E534E756D626572008484074E5356616C7565009484012A849999\
                   00868686";
        let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn extracts_text_from_real_attributed_body() {
        assert_eq!(
            extract_message_text(&stalo_se_blob()).as_deref(),
            Some("Stalo se")
        );
    }

    #[test]
    fn extracts_long_string_with_81_length_prefix() {
        // Build a minimal typedstream with a 200-char body (needs the 0x81 i16 len).
        let body: String = "a".repeat(200);
        let mut blob = b"\x04\x0bstreamtyped".to_vec();
        blob.extend_from_slice(b"NSString\x01\x94\x84"); // scaffolding
        blob.extend_from_slice(&START);
        blob.push(0x81); // long-length marker
        blob.extend_from_slice(&(200u16).to_le_bytes());
        blob.extend_from_slice(body.as_bytes());
        blob.extend_from_slice(&END);
        assert_eq!(extract_message_text(&blob).as_deref(), Some(body.as_str()));
    }

    /// A well-formed typedstream carrying `text` with a correct declared length.
    fn blob_with(text: &str) -> Vec<u8> {
        let mut blob = b"\x04\x0bstreamtyped".to_vec();
        blob.extend_from_slice(b"NSString\x01\x94\x84");
        blob.extend_from_slice(&START);
        blob.push(text.len() as u8);
        blob.extend_from_slice(text.as_bytes());
        blob.extend_from_slice(&END);
        blob.extend_from_slice(b"\x02iI\x01");
        blob
    }

    #[test]
    fn a_character_whose_bytes_contain_the_end_marker_is_not_cut() {
        for text in [
            "a\u{2184}b",
            "a\u{1F184}b",
            "a\u{B184}b",
            "\u{C184}",
            "x\u{D184}",
        ] {
            assert_eq!(
                extract_message_text(&blob_with(text)).as_deref(),
                Some(text),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_real_end_marker_after_ascii_still_truncates_an_overlong_length() {
        let mut blob = b"\x04\x0bstreamtyped".to_vec();
        blob.extend_from_slice(b"NSString\x01\x94\x84");
        blob.extend_from_slice(&START);
        blob.push(100); // declared far past the real text
        blob.extend_from_slice(b"hello");
        blob.extend_from_slice(&END);
        blob.extend_from_slice(&[b'z'; 120]);
        assert_eq!(extract_message_text(&blob).as_deref(), Some("hello"));
    }

    #[test]
    fn returns_none_for_non_typedstream() {
        assert_eq!(extract_message_text(b"just some plain bytes"), None);
        assert_eq!(extract_message_text(&[0x01, 0x2b, 0x05]), None);
    }

    #[test]
    fn drops_attachment_placeholder() {
        // NSString scaffold + start + len(3) + U+FFFC ("\u{FFFC}" is 3 UTF-8 bytes).
        let mut blob = b"NSString\x94\x84".to_vec();
        blob.extend_from_slice(&START);
        blob.push(0x03);
        blob.extend_from_slice("\u{FFFC}".as_bytes());
        blob.extend_from_slice(&END);
        // Only the placeholder is present -> cleaned to empty -> None.
        assert_eq!(extract_message_text(&blob), None);
    }
}
