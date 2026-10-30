//! Key and value names, in the two encodings a hive stores them in.
//!
//! A name is either UTF-16LE or, when the structure's "compressed name" flag
//! is set, one byte per character in the ISO-8859-1 range. Both are kept as
//! borrowed bytes and decoded on demand: a name that does not decode is a
//! finding, not a reason to lose the key it belongs to.

use core::fmt;

/// A name as the hive stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiveNameString<'a> {
    /// One byte per character, ISO-8859-1 (the "compressed name" form).
    Latin1(&'a [u8]),
    /// UTF-16LE, as raw bytes; the length is not guaranteed to be even.
    Utf16Le(&'a [u8]),
}

impl<'a> HiveNameString<'a> {
    /// The name, with anything undecodable replaced rather than refused.
    ///
    /// Registry names are attacker-influenced — a key name is whatever wrote
    /// it — so a lone surrogate or an odd byte count must not cost the record.
    pub fn to_string_lossy(&self) -> String {
        match self {
            Self::Latin1(bytes) => bytes.iter().map(|&b| b as char).collect(),
            Self::Utf16Le(bytes) => {
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                let mut s = String::from_utf16_lossy(&units);
                // An odd byte count means the name was cut mid-character. Say
                // so in the value rather than silently dropping the byte.
                if bytes.len() % 2 == 1 {
                    s.push(char::REPLACEMENT_CHARACTER);
                }
                s
            }
        }
    }

    /// The name, or `None` when it does not decode cleanly.
    ///
    /// For callers that would rather know than guess.
    pub fn to_string_checked(&self) -> Option<String> {
        match self {
            Self::Latin1(bytes) => Some(bytes.iter().map(|&b| b as char).collect()),
            Self::Utf16Le(bytes) => {
                if bytes.len() % 2 == 1 {
                    return None;
                }
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                String::from_utf16(&units).ok()
            }
        }
    }
}

impl fmt::Display for HiveNameString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    use super::HiveNameString;

    #[test]
    fn a_latin1_name_decodes_byte_for_byte() {
        let name = HiveNameString::Latin1(b"ControlSet001");
        assert_eq!(name.to_string_lossy(), "ControlSet001");
        assert_eq!(name.to_string_checked().as_deref(), Some("ControlSet001"));
        // 0xE9 is é in ISO-8859-1, and is NOT valid UTF-8 on its own: the
        // difference between the two encodings has to be honoured.
        let accented = HiveNameString::Latin1(&[b'c', b'a', b'f', 0xE9]);
        assert_eq!(accented.to_string_lossy(), "café");
    }

    #[test]
    fn a_utf16_name_decodes_and_a_truncated_one_says_so() {
        let bytes: Vec<u8> = "Software"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let name = HiveNameString::Utf16Le(&bytes);
        assert_eq!(name.to_string_lossy(), "Software");

        // A name cut mid-character: lossy keeps what is there and marks the
        // cut; checked refuses, because the caller asked to know.
        let mut cut = bytes.clone();
        cut.push(0x41);
        let cut = HiveNameString::Utf16Le(&cut);
        assert_eq!(cut.to_string_lossy(), "Software\u{FFFD}");
        assert_eq!(cut.to_string_checked(), None);
    }

    /// An unpaired surrogate is a name a hive can hold and Rust's `String`
    /// cannot. It must not cost the key.
    #[test]
    fn an_unpaired_surrogate_is_replaced_not_refused() {
        let bytes = [0x00u8, 0xD8, 0x41, 0x00]; // lone high surrogate, then 'A'
        let name = HiveNameString::Utf16Le(&bytes);
        assert_eq!(name.to_string_lossy(), "\u{FFFD}A");
        assert_eq!(name.to_string_checked(), None);
    }
}
