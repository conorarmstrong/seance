//! Single-byte code-page decoding for Windows ANSI and DOS/OEM byte fields.
//!
//! Several on-disk structures store text as raw bytes with no encoding
//! declaration: the INFO2 Recycle Bin table's ANSI path, a `.lnk` file's
//! LocalBasePath / CommonPathSuffix / NetName and its non-Unicode StringData,
//! and FAT's 8.3 short names and volume labels. Those bytes are not UTF-8, and
//! every one of these fields was previously run through
//! `String::from_utf8_lossy`, which turns each byte 0x80-0xFF into U+FFFD.
//!
//! That is wrong twice over. `C:\Users\José\Résumé.doc` came out as
//! `C:\Users\Jos\u{FFFD}\R\u{FFFD}sum\u{FFFD}.doc` -- a path that names no user
//! and no file, so a search for the account or the document finds nothing and an
//! examiner concludes it was never there. And nothing on the record said a
//! substitution had happened, so the mangled string read as what the disk
//! actually held.
//!
//! [`decode`] maps the bytes through the correct table and reports whether any
//! byte outside ASCII was mapped, so a caller can stamp the emitted record with
//! the code page it assumed. The code page is a parameter because these fields
//! do not share one: FAT 8.3 names and volume labels are OEM (CP437 on a US
//! system), while Windows ANSI paths are CP1252. Decoding either through the
//! other's table produces a different -- and equally confident-looking -- wrong
//! string.
//!
//! A single-byte code page cannot be recovered from the bytes; both tables are
//! the US/Western-European defaults. A volume written on a Cyrillic or Japanese
//! system used a different one, which is exactly why the code page assumed is
//! recorded on the record rather than left implicit.

/// The character emitted for a byte the chosen code page leaves undefined.
/// Five CP1252 positions (0x81, 0x8D, 0x8F, 0x90, 0x9D) have no assignment;
/// inventing a character for them would be a fabrication, so they are marked.
const REPLACEMENT: char = '\u{FFFD}';

/// Which single-byte code page a byte field is to be read through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePage {
    /// Windows-1252 ("Windows ANSI", Western European) -- the default ANSI code
    /// page on a Western Windows install, and what the ANSI fields of `.lnk`
    /// and INFO2 records were written with.
    Cp1252,
    /// IBM code page 437 (the original DOS/OEM US set) -- what FAT 8.3 short
    /// names and volume labels are written in.
    Cp437,
}

impl CodePage {
    /// The name to record on an artifact whose strings were decoded through
    /// this table, e.g. `"path_decode": "cp1252"`.
    pub fn name(self) -> &'static str {
        match self {
            CodePage::Cp1252 => "cp1252",
            CodePage::Cp437 => "cp437",
        }
    }
}

/// CP1252 bytes 0x80-0x9F, indexed by `byte - 0x80`.
///
/// This range is the whole difference between CP1252 and ISO-8859-1: Latin-1
/// leaves it as C1 control codes, CP1252 fills it with punctuation. It is also
/// where the two encodings a naive decoder might reach for disagree -- a byte
/// 0x92 is a right single quotation mark in a Windows path (`Bob\u{2019}s
/// files`), not a control character and not U+FFFD.
const CP1252_80_9F: [char; 32] = [
    '\u{20AC}',  // 0x80 EURO SIGN
    REPLACEMENT, // 0x81 undefined
    '\u{201A}',  // 0x82 SINGLE LOW-9 QUOTATION MARK
    '\u{0192}',  // 0x83 LATIN SMALL LETTER F WITH HOOK
    '\u{201E}',  // 0x84 DOUBLE LOW-9 QUOTATION MARK
    '\u{2026}',  // 0x85 HORIZONTAL ELLIPSIS
    '\u{2020}',  // 0x86 DAGGER
    '\u{2021}',  // 0x87 DOUBLE DAGGER
    '\u{02C6}',  // 0x88 MODIFIER LETTER CIRCUMFLEX ACCENT
    '\u{2030}',  // 0x89 PER MILLE SIGN
    '\u{0160}',  // 0x8A LATIN CAPITAL LETTER S WITH CARON
    '\u{2039}',  // 0x8B SINGLE LEFT-POINTING ANGLE QUOTATION MARK
    '\u{0152}',  // 0x8C LATIN CAPITAL LIGATURE OE
    REPLACEMENT, // 0x8D undefined
    '\u{017D}',  // 0x8E LATIN CAPITAL LETTER Z WITH CARON
    REPLACEMENT, // 0x8F undefined
    REPLACEMENT, // 0x90 undefined
    '\u{2018}',  // 0x91 LEFT SINGLE QUOTATION MARK
    '\u{2019}',  // 0x92 RIGHT SINGLE QUOTATION MARK
    '\u{201C}',  // 0x93 LEFT DOUBLE QUOTATION MARK
    '\u{201D}',  // 0x94 RIGHT DOUBLE QUOTATION MARK
    '\u{2022}',  // 0x95 BULLET
    '\u{2013}',  // 0x96 EN DASH
    '\u{2014}',  // 0x97 EM DASH
    '\u{02DC}',  // 0x98 SMALL TILDE
    '\u{2122}',  // 0x99 TRADE MARK SIGN
    '\u{0161}',  // 0x9A LATIN SMALL LETTER S WITH CARON
    '\u{203A}',  // 0x9B SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
    '\u{0153}',  // 0x9C LATIN SMALL LIGATURE OE
    REPLACEMENT, // 0x9D undefined
    '\u{017E}',  // 0x9E LATIN SMALL LETTER Z WITH CARON
    '\u{0178}',  // 0x9F LATIN CAPITAL LETTER Y WITH DIAERESIS
];

/// CP437 bytes 0x80-0xFF, indexed by `byte - 0x80` (Unicode's CP437.TXT).
///
/// Unlike CP1252 this diverges from Latin-1 across the entire high range, so a
/// FAT name decoded with the wrong table is wrong in every accented character:
/// byte 0x82 is `é` here and a low quotation mark in CP1252.
const CP437_HIGH: [char; 128] = [
    // 0x80
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
    // 0x90
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '\u{20A7}', 'ƒ',
    // 0xA0
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '\u{2310}', '¬', '½', '¼', '¡', '«', '»',
    // 0xB0
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255D}', '\u{255C}', '\u{255B}', '\u{2510}',
    // 0xC0
    '\u{2514}', '\u{2534}', '\u{252C}', '\u{251C}', '\u{2500}', '\u{253C}', '\u{255E}', '\u{255F}',
    '\u{255A}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256C}', '\u{2567}',
    // 0xD0
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256B}',
    '\u{256A}', '\u{2518}', '\u{250C}', '\u{2588}', '\u{2584}', '\u{258C}', '\u{2590}', '\u{2580}',
    // 0xE0
    'α', 'ß', '\u{0393}', '\u{03C0}', '\u{03A3}', '\u{03C3}', 'µ', '\u{03C4}', '\u{03A6}',
    '\u{0398}', '\u{03A9}', '\u{03B4}', '\u{221E}', '\u{03C6}', '\u{03B5}', '\u{2229}',
    // 0xF0
    '\u{2261}', '±', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '÷', '\u{2248}', '°',
    '\u{2219}', '·', '\u{221A}', '\u{207F}', '²', '\u{25A0}', '\u{00A0}',
];

/// Decode a single-byte-encoded field, returning the text and whether any byte
/// outside ASCII had to be mapped through the code-page table.
///
/// The flag is the point: a `true` means the returned string is this build's
/// *interpretation* of the bytes under `code_page`, not text read off the disk,
/// and the record carrying it must say so. A `false` means every byte was
/// plain ASCII, where all single-byte code pages agree -- so a caller that
/// stamps provenance on `false` would cry wolf on the overwhelming majority of
/// real paths and names.
pub fn decode(bytes: &[u8], code_page: CodePage) -> (String, bool) {
    let mut out = String::with_capacity(bytes.len());
    let mut substituted = false;
    for &b in bytes {
        if b < 0x80 {
            out.push(b as char);
            continue;
        }
        substituted = true;
        out.push(match code_page {
            // CP1252 is ISO-8859-1 from 0xA0 up; only 0x80-0x9F is specific to
            // it. Callers elsewhere that cast `b as char` are therefore right
            // above 0x9F and wrong below it.
            CodePage::Cp1252 if b >= 0xA0 => b as char,
            CodePage::Cp1252 => CP1252_80_9F[(b - 0x80) as usize],
            CodePage::Cp437 => CP437_HIGH[(b - 0x80) as usize],
        });
    }
    (out, substituted)
}

/// Decode a little-endian UTF-16 string, stopping at the first NUL code unit.
///
/// This is the common contract several plugins each hand-rolled (asep startup
/// items, `$RECYCLE.BIN` `$I` names, NTFS `$I30` filenames): a NUL-terminated
/// wide string, decoded lossily so an unpaired surrogate becomes U+FFFD rather
/// than failing the whole field. A trailing odd byte (a truncated final code
/// unit) is ignored rather than discarding the string. Callers whose data is NOT
/// NUL-terminated (e.g. a length-prefixed field that may contain embedded NULs)
/// must not use this; decode their own units.
pub fn decode_utf16le(bytes: &[u8]) -> String {
    // `as_chunks` rather than `chunks_exact(2)`: the pair is a fixed-size array
    // the compiler can see, so the bounds check inside `from_le_bytes` goes
    // away. A trailing odd byte lands in the remainder half, which is dropped —
    // the documented behaviour above, unchanged.
    let (pairs, _trailing_odd_byte) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What an examiner learns: the name of the user whose account held a
    /// deleted file. `String::from_utf8_lossy` replaced every accented byte
    /// with U+FFFD, so `José` became `Jos\u{FFFD}` -- a name that matches no
    /// account and no keyword search.
    #[test]
    fn a_cp1252_high_byte_decodes_to_its_character_not_to_a_replacement() {
        let (text, substituted) = decode(b"C:\\Users\\Jos\xe9\\Documents", CodePage::Cp1252);
        assert_eq!(text, "C:\\Users\\José\\Documents");
        assert!(
            !text.contains('\u{FFFD}'),
            "a defined CP1252 byte must not surface as a replacement character"
        );
        assert!(substituted, "a non-ASCII byte was interpreted; say so");
    }

    /// 0x80-0x9F is the range where CP1252 and ISO-8859-1 disagree: 0x92 is a
    /// typographic apostrophe in a Windows path, not a C1 control code.
    #[test]
    fn the_cp1252_specific_punctuation_block_is_not_latin1() {
        let (text, _) = decode(b"Bob\x92s files", CodePage::Cp1252);
        assert_eq!(text, "Bob\u{2019}s files");
    }

    /// The same byte means different characters in the two code pages, which is
    /// why the table is a parameter: decoding a FAT 8.3 name as CP1252 (or a
    /// Windows path as CP437) yields a confident, wrong string.
    #[test]
    fn the_same_byte_decodes_differently_per_code_page() {
        let (ansi, _) = decode(b"\x82", CodePage::Cp1252);
        let (oem, _) = decode(b"\x82", CodePage::Cp437);
        assert_eq!(ansi, "\u{201A}");
        assert_eq!(oem, "é");
        assert_ne!(ansi, oem);
    }

    /// CP437 diverges from Latin-1 across the whole high range, not just the
    /// C1 block: 0xA5 is `Ñ` on a DOS volume and `¥` in Latin-1.
    #[test]
    fn cp437_high_bytes_are_not_latin1() {
        let (text, substituted) = decode(b"\xa5\x81\xe1", CodePage::Cp437);
        assert_eq!(text, "Ñüß");
        assert!(substituted);
    }

    /// Anti-cry-wolf: an all-ASCII field is identical under every single-byte
    /// code page, so nothing was interpreted and no provenance stamp is owed.
    #[test]
    fn a_pure_ascii_field_reports_no_substitution() {
        for cp in [CodePage::Cp1252, CodePage::Cp437] {
            let (text, substituted) = decode(b"C:\\WINDOWS\\NOTEPAD.EXE", cp);
            assert_eq!(text, "C:\\WINDOWS\\NOTEPAD.EXE");
            assert!(
                !substituted,
                "{} must not claim an interpretation",
                cp.name()
            );
        }
    }

    /// Fail closed: CP1252 leaves five positions unassigned. Marking them keeps
    /// the decoder from inventing a character the code page does not define,
    /// and the substitution flag still fires so the record says it was decoded.
    #[test]
    fn an_undefined_cp1252_position_is_marked_rather_than_invented() {
        let (text, substituted) = decode(b"\x81\x8d\x8f\x90\x9d", CodePage::Cp1252);
        assert_eq!(text, "\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}");
        assert!(substituted);
    }

    #[test]
    fn code_page_names_are_stable_record_values() {
        assert_eq!(CodePage::Cp1252.name(), "cp1252");
        assert_eq!(CodePage::Cp437.name(), "cp437");
    }

    #[test]
    fn utf16le_decodes_and_stops_at_the_nul_terminator() {
        // "Hi" then a NUL then trailing garbage that must be ignored.
        let bytes = [b'H', 0, b'i', 0, 0, 0, b'X', 0];
        assert_eq!(decode_utf16le(&bytes), "Hi");
    }

    #[test]
    fn utf16le_tolerates_a_trailing_odd_byte() {
        // A truncated final code unit must not discard the whole string.
        let bytes = [b'O', 0, b'k', 0, 0x41]; // "Ok" + one stray byte
        assert_eq!(decode_utf16le(&bytes), "Ok");
    }

    #[test]
    fn utf16le_is_lossy_on_an_unpaired_surrogate() {
        // A lone high surrogate (0xD800) becomes U+FFFD, not a decode failure.
        let bytes = [0x00, 0xD8, b'!', 0];
        assert_eq!(decode_utf16le(&bytes), "\u{FFFD}!");
    }

    #[test]
    fn utf16le_of_empty_or_leading_nul_is_empty() {
        assert_eq!(decode_utf16le(&[]), "");
        assert_eq!(decode_utf16le(&[0, 0, b'a', 0]), "");
    }
}
