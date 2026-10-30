//! The RTF extractor — stated before it was written.
//!
//! There is no RTF fixture on this machine and no Sticky Notes evidence of
//! either format, so every case here is a hand-built stream. Each one exists
//! because an extractor that gets it wrong puts something in a note that the
//! note does not say.

use super::rtf::*;

#[test]
fn an_rtf_stream_is_recognised_by_its_five_opening_bytes() {
    assert!(is_rtf(br"{\rtf1\ansi Hello}"));
    assert!(is_rtf(&[0x7B, 0x5C, 0x72, 0x74, 0x66]));
    for not_rtf in [
        &b"{\\rt"[..],
        &b""[..],
        &b"Hello"[..],
        &b"\xd0\xcf\x11\xe0"[..],
    ] {
        assert!(!is_rtf(not_rtf));
    }
}

#[test]
fn the_control_words_are_stripped_and_the_text_is_kept() {
    let e = extract(br"{\rtf1\ansi\deff0\fs20 Buy milk}");
    assert_eq!(e.text, "Buy milk");
    assert!(e.embedded.is_empty());
    assert!(e.unbalanced.is_none());
}

/// `\par` and `\line` are the note's own line structure; a newline in the
/// source is not.
#[test]
fn a_paragraph_break_is_a_line_and_a_source_newline_is_not() {
    let e = extract(b"{\\rtf1\\ansi Line one\\par\nLine two\\line Line three}");
    assert_eq!(e.text, "Line one\nLine two\nLine three");
}

/// **`\'hh` carries every non-ASCII character a note holds**, and dropping it
/// silently removes them.
#[test]
fn a_hex_escape_yields_its_character() {
    let e = extract(br"{\rtf1\ansi caf\'e9 open}");
    assert_eq!(e.text, "café open");
}

/// A byte in `0x80..=0x9F` means different characters in different code pages,
/// and this extractor does not claim to know which. A guess there would put a
/// wrong character in a note.
#[test]
fn a_byte_whose_meaning_depends_on_the_code_page_is_not_guessed() {
    let e = extract(br"{\rtf1\ansi a\'93b}");
    assert_eq!(
        e.text, "a\u{FFFD}b",
        "replaced, not guessed and not dropped"
    );
}

/// **`\uN` is followed by an ANSI fallback of the same character.** Emitting
/// both prints every non-ASCII character twice.
#[test]
fn a_unicode_escape_does_not_also_emit_its_ansi_fallback() {
    // `\uc1`, then the euro sign as `\u8364` with a one-byte `?` fallback.
    let e = extract(br"{\rtf1\ansi\uc1 Pay \u8364?50}");
    assert_eq!(e.text, "Pay €50");

    // A two-byte fallback, which is what a surrogate pair or a DBCS code page
    // produces.
    let e = extract(br"{\rtf1\ansi\uc2 Pay \u8364?\'3f50}");
    assert_eq!(e.text, "Pay €50");

    // And `\uc0` means there is no fallback at all to swallow, so the digits
    // after the control word's space delimiter are text.
    let e = extract(br"{\rtf1\ansi\uc0 Pay \u8364 50}");
    assert_eq!(e.text, "Pay \u{20AC}50");

    // A control word's parameter is the WHOLE digit run, which is RTF's own
    // rule: `\u836450` is code point 836450 and not 8364 followed by "50".
    // Getting this wrong prints stray digits into every note that holds a
    // non-ASCII character.
    let e = extract(br"{\rtf1\ansi\uc0 Pay \u836450}");
    assert_eq!(e.text, "Pay \u{cc362}");

    // And a parameter outside Unicode emits nothing rather than a replacement
    // character, because there is no character there to replace.
    let e = extract(br"{\rtf1\ansi\uc0 Pay \u1234567}");
    assert_eq!(e.text, "Pay ");
}

/// A negative `\uN` is the 16-bit value written as a signed short.
#[test]
fn a_negative_unicode_parameter_is_read_as_the_unsigned_code_point() {
    // -3891 + 65536 = 61645, in a private-use area — a real thing in notes
    // written with a symbol font.
    let e = extract(br"{\rtf1\ansi\uc1 x\u-3891?y}");
    assert_eq!(e.text.chars().count(), 3);
    assert!(e.text.starts_with('x') && e.text.ends_with('y'));
}

/// The literal escapes.
#[test]
fn escaped_braces_and_backslashes_are_text() {
    let e = extract(br"{\rtf1\ansi a\{b\}c\\d}");
    assert_eq!(e.text, "a{b}c\\d");
}

/// **A font table is not a note.** A stripper that keeps ignorable
/// destinations prints the font and colour tables into the text.
#[test]
fn an_ignorable_destination_is_skipped_and_named() {
    let rtf =
        br"{\rtf1\ansi{\fonttbl{\f0\fswiss Segoe UI;}}{\colortbl ;\red0\green0\blue0;}Call Bob}";
    let e = extract(rtf);
    assert_eq!(e.text, "Call Bob");
    assert!(
        e.skipped_destinations.contains(&"fonttbl".to_string())
            && e.skipped_destinations.contains(&"colortbl".to_string()),
        "and it says which it skipped: {:?}",
        e.skipped_destinations
    );
}

/// A `\*\` destination this build has never heard of is skipped too, because
/// that is exactly what the marker means.
#[test]
fn a_starred_destination_this_build_does_not_know_is_still_skipped() {
    let e = extract(br"{\rtf1\ansi{\*\somethingnew this is not text}Real text}");
    assert_eq!(e.text, "Real text");
}

/// **An embedded picture is reported, never rendered.** Its hex payload is not
/// a note's words, and printing it turns a note into a page of gibberish.
#[test]
fn an_embedded_picture_is_reported_rather_than_rendered_as_text() {
    let rtf = br"{\rtf1\ansi Before{\pict\pngblip 89504e470d0a1a0a0000000d}After}";
    let e = extract(rtf);
    assert_eq!(e.text, "BeforeAfter");
    assert!(
        !e.text.contains("89504e47"),
        "hex image bytes are not text: {:?}",
        e.text
    );
    assert_eq!(e.embedded, vec!["pict".to_string()]);
}

#[test]
fn an_embedded_object_is_reported_too() {
    let e = extract(br"{\rtf1\ansi A{\object\objemb{\*\objclass Excel.Sheet}{\objdata 0105}}B}");
    assert_eq!(e.text, "AB");
    assert!(
        e.embedded.contains(&"object".to_string()),
        "{:?}",
        e.embedded
    );
}

/// **A truncated note.** What was read is kept, and the imbalance is stated —
/// an examiner reading a half note must know it is half.
#[test]
fn an_unbalanced_stream_keeps_what_it_read_and_says_it_is_unbalanced() {
    let e = extract(br"{\rtf1\ansi The note was cut off here");
    assert_eq!(e.text, "The note was cut off here");
    assert!(
        e.unbalanced
            .as_deref()
            .is_some_and(|u| u.contains("still open")),
        "got {:?}",
        e.unbalanced
    );

    let e = extract(br"{\rtf1\ansi Half}} and this is past the end");
    assert_eq!(e.text, "Half");
    assert!(
        e.unbalanced
            .as_deref()
            .is_some_and(|u| u.contains("never opened")),
        "got {:?}",
        e.unbalanced
    );
}

/// A nested group inside a skipped destination is skipped too.
#[test]
fn a_group_nested_inside_a_skipped_destination_is_also_skipped() {
    let e = extract(br"{\rtf1\ansi{\fonttbl{\f0 Arial;}{\f1 Courier;}}Text}");
    assert_eq!(e.text, "Text");
}

/// The cap is stated rather than silent.
#[test]
fn a_note_past_the_text_cap_says_so() {
    let mut rtf = br"{\rtf1\ansi ".to_vec();
    rtf.extend(std::iter::repeat_n(b'a', MAX_TEXT_CHARS + 100));
    rtf.push(b'}');
    let e = extract(&rtf);
    assert!(e.capped, "the cap must never be silent");
    assert_eq!(e.text.chars().count(), MAX_TEXT_CHARS);
}

/// An empty note is an empty note, not an error.
#[test]
fn an_empty_rtf_document_yields_no_text_and_no_complaint() {
    let e = extract(br"{\rtf1\ansi\deff0}");
    assert_eq!(e.text, "");
    assert!(e.unbalanced.is_none());
    assert!(!e.capped);
}

/// The document ends where its outermost group closes. The real Windows 7
/// note (`SNT-1` in `documentation/VALIDATION.md`) stores `}\r\n` and then a
/// NUL terminator; reading on past the brace put a `U+0000` at the end of the
/// note's text, which a report prints and a search index stores.
#[test]
fn nothing_after_the_outermost_group_is_text() {
    let e = extract(b"{\\rtf1\\ansi Tomorrow...\\par\r\n}\r\n\0");
    assert_eq!(e.text, "Tomorrow...\n");
    assert!(e.unbalanced.is_none());
}
