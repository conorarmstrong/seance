//! A minimal, honest RTF text extractor.
//!
//! Windows' pre-Anniversary Sticky Notes stores each note as an RTF stream
//! inside `StickyNotes.snt`. Nothing in this repository extracted RTF text
//! before this, and nothing else should: one extractor, here, and if a second
//! consumer ever appears this module moves to a shared crate rather than being
//! copied.
//!
//! # It is small on purpose
//!
//! It is not an RTF renderer and does not pretend to be. It strips control
//! words and groups, honours the escapes that carry a note's actual characters,
//! and **reports** the constructs it will not render rather than emitting their
//! control words as if they were text — which is the failure that turns a note
//! into a page of `\pict\pngblip` gibberish.
//!
//! What it handles, and why each matters for a note's text:
//!
//! * `\'hh` — a byte in the document's code page. Dropping it loses every
//!   non-ASCII character a note holds.
//! * `\uN` with the `\ucN` skip count — a Unicode code point followed by N
//!   bytes of ANSI fallback for readers that cannot do Unicode. Emitting the
//!   fallback as well prints every such character twice.
//! * `\par`, `\line`, `\tab` — the note's own line structure.
//! * `\{`, `\}`, `\\` — literal braces and backslashes in the text.
//! * `\*\<destination>` — an ignorable destination group. Its contents are
//!   **not** text, and a stripper that keeps them prints font tables and
//!   colour tables into the note.
//! * `\pict` and `\object` — an embedded picture or object. Reported as
//!   present, never rendered: hex-encoded image bytes are not a note's words.
//! * Unbalanced braces — a truncated or carved note. What was read is kept and
//!   the imbalance is stated.

/// What an extraction produced, and what it refused.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extracted {
    /// The note's text.
    pub text: String,
    /// Embedded objects reported rather than rendered, by control word.
    pub embedded: Vec<String>,
    /// Ignorable destination groups skipped, by control word.
    pub skipped_destinations: Vec<String>,
    /// Set when the braces do not balance, which is what a truncated or carved
    /// note looks like.
    pub unbalanced: Option<String>,
    /// Set when the text hit the cap.
    pub capped: bool,
}

/// Characters of note text kept.
///
/// A note is a note; a multi-megabyte RTF stream under that name is either an
/// embedded object this extractor refuses anyway or something that is not a
/// note, and either way the cap is stated rather than silent.
pub const MAX_TEXT_CHARS: usize = 64 * 1024;

/// The destinations whose contents are never a note's text.
///
/// `\*\<word>` marks a destination an unrecognising reader must skip, and RTF
/// also defines these unmarked. Keeping them prints a font table into the note.
const NEVER_TEXT: &[&str] = &[
    "fonttbl",
    "colortbl",
    "stylesheet",
    "listtable",
    "listoverridetable",
    "revtbl",
    "rsidtbl",
    "generator",
    "info",
    "xmlnstbl",
    "themedata",
    "colorschememapping",
    "latentstyles",
    "datastore",
    "pgptbl",
    "filetbl",
];

/// The destinations that hold an embedded thing, reported and not rendered.
const EMBEDDED: &[&str] = &[
    "pict",
    "object",
    "objdata",
    "result",
    "shppict",
    "nonshppict",
];

/// Whether these bytes open an RTF document.
///
/// The same five bytes `seance_plugin_file_analysis`'s magic table uses.
pub fn is_rtf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"{\\rtf")
}

/// One parsed control word: its name, and its numeric parameter if it had one.
struct Control<'a> {
    word: &'a str,
    param: Option<i64>,
    /// Bytes consumed, from the backslash.
    len: usize,
}

/// Read a control word at `at`, which must point at the backslash.
fn control_at(b: &[u8], at: usize) -> Option<Control<'_>> {
    let mut i = at + 1;
    let start = i;
    while i < b.len() && b[i].is_ascii_alphabetic() {
        i += 1;
    }
    if i == start {
        return None;
    }
    let word = std::str::from_utf8(&b[start..i]).ok()?;
    let neg = i < b.len() && b[i] == b'-';
    if neg {
        i += 1;
    }
    let digits_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let param = (i > digits_start).then(|| {
        let n: i64 = std::str::from_utf8(&b[digits_start..i])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if neg {
            -n
        } else {
            n
        }
    });
    // A single space after a control word is its delimiter and is consumed.
    if i < b.len() && b[i] == b' ' {
        i += 1;
    }
    Some(Control {
        word,
        param,
        len: i - at,
    })
}

/// Extract a note's text from an RTF stream.
pub fn extract(bytes: &[u8]) -> Extracted {
    let mut out = Extracted::default();
    // One entry per open brace: `Some(word)` when this group is a destination
    // whose contents are not text.
    let mut skipping: Vec<Option<String>> = Vec::new();
    // `\ucN`: how many bytes of ANSI fallback follow a `\uN`. Per-group, and
    // inherited by nested groups, which is what RTF specifies.
    let mut uc_stack: Vec<usize> = vec![1];
    // Bytes of fallback still to swallow after a `\uN`.
    let mut swallow = 0usize;
    let mut i = 0usize;
    let mut depth: i64 = 0;
    let push = |out: &mut Extracted, s: &str| {
        if out.text.chars().count() >= MAX_TEXT_CHARS {
            out.capped = true;
            return;
        }
        out.text.push_str(s);
    };

    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'{' => {
                depth += 1;
                let inherited = *uc_stack.last().unwrap_or(&1);
                uc_stack.push(inherited);
                // Inherit the enclosing group's skip state, so a nested group
                // inside a font table is skipped too.
                let inherited_skip = skipping.last().cloned().flatten();
                skipping.push(inherited_skip);
                i += 1;
            }
            b'}' => {
                depth -= 1;
                uc_stack.pop();
                skipping.pop();
                if depth < 0 {
                    out.unbalanced = Some(format!(
                        "This RTF stream closes a group that was never opened, at byte {i}. What \
                         was read up to that point is kept; a stream whose braces do not balance \
                         is what a truncated or carved note looks like, and the rest of it was \
                         not read as text."
                    ));
                    return out;
                }
                i += 1;
                if depth == 0
                    && bytes[i..]
                        .iter()
                        .all(|b| matches!(b, b'\r' | b'\n' | b' ' | b'\t' | 0))
                {
                    // The outermost group closed and only line ends, blanks
                    // and NULs follow: the document is complete. On a real
                    // Windows 7 note that tail is `\r\n` and a NUL terminator
                    // (`SNT-1`), and reading it as text put a U+0000 at the
                    // end of the note. Anything else after the close — a stray
                    // brace, more text — is still read and reported as before,
                    // so a spliced or carved stream is not quietly trimmed.
                    break;
                }
            }
            b'\\' => {
                // The literal escapes first: they are not control words.
                match bytes.get(i + 1) {
                    Some(b'\\') => {
                        if skipping.last().cloned().flatten().is_none() {
                            push(&mut out, "\\");
                        }
                        i += 2;
                        continue;
                    }
                    Some(b'{') => {
                        if skipping.last().cloned().flatten().is_none() {
                            push(&mut out, "{");
                        }
                        i += 2;
                        continue;
                    }
                    Some(b'}') => {
                        if skipping.last().cloned().flatten().is_none() {
                            push(&mut out, "}");
                        }
                        i += 2;
                        continue;
                    }
                    Some(b'\'') => {
                        // `\'hh` — one byte in the document's code page.
                        let hex = bytes.get(i + 2..i + 4);
                        i += 4;
                        if swallow > 0 {
                            swallow -= 1;
                            continue;
                        }
                        if skipping.last().cloned().flatten().is_some() {
                            continue;
                        }
                        if let Some(h) = hex.and_then(|h| std::str::from_utf8(h).ok()) {
                            if let Ok(byte) = u8::from_str_radix(h, 16) {
                                // Windows-1252 and Latin-1 agree with Unicode on
                                // every byte outside 0x80..=0x9F, and this
                                // extractor does not claim to know the document's
                                // code page. A byte in that window is the one case
                                // where a guess would put a wrong character in a
                                // note, so it is replaced rather than guessed.
                                if (0x80..=0x9F).contains(&byte) {
                                    push(&mut out, "\u{FFFD}");
                                } else {
                                    push(&mut out, &(byte as char).to_string());
                                }
                            }
                        }
                        continue;
                    }
                    Some(b'*') => {
                        // `\*\<destination>` — ignorable. Mark this group.
                        if let Some(top) = skipping.last_mut() {
                            if top.is_none() {
                                *top = Some("*".to_string());
                            }
                        }
                        i += 2;
                        continue;
                    }
                    _ => {}
                }
                let Some(ctl) = control_at(bytes, i) else {
                    // A backslash before something that is not a control word.
                    i += 1;
                    continue;
                };
                i += ctl.len;
                let in_skip = skipping.last().cloned().flatten().is_some();
                let word = ctl.word.to_string();

                if NEVER_TEXT.contains(&ctl.word) {
                    if let Some(top) = skipping.last_mut() {
                        *top = Some(word.clone());
                    }
                    if !out.skipped_destinations.contains(&word) {
                        out.skipped_destinations.push(word);
                    }
                    continue;
                }
                if EMBEDDED.contains(&ctl.word) {
                    if let Some(top) = skipping.last_mut() {
                        *top = Some(word.clone());
                    }
                    if !out.embedded.contains(&word) {
                        out.embedded.push(word);
                    }
                    continue;
                }
                match ctl.word {
                    "uc" => {
                        if let Some(n) = ctl.param {
                            if let Some(top) = uc_stack.last_mut() {
                                *top = n.max(0) as usize;
                            }
                        }
                    }
                    "u" => {
                        let n = *uc_stack.last().unwrap_or(&1);
                        if !in_skip {
                            if let Some(cp) = ctl.param {
                                // A negative parameter is the 16-bit value
                                // written as a signed short.
                                let cp = if cp < 0 {
                                    (cp + 65536) as u32
                                } else {
                                    cp as u32
                                };
                                if let Some(ch) = char::from_u32(cp) {
                                    push(&mut out, &ch.to_string());
                                }
                            }
                        }
                        // The ANSI fallback that follows is the SAME character
                        // again. Emitting it too prints every non-ASCII
                        // character twice.
                        swallow = n;
                        continue;
                    }
                    "par" | "line" | "sect" => {
                        if !in_skip {
                            push(&mut out, "\n");
                        }
                    }
                    "tab" if !in_skip => push(&mut out, "\t"),
                    _ => {}
                }
            }
            b'\r' | b'\n' => {
                // A newline in the source is not a newline in the text; `\par`
                // is.
                i += 1;
            }
            _ => {
                i += 1;
                if swallow > 0 {
                    swallow -= 1;
                    continue;
                }
                if skipping.last().cloned().flatten().is_none() {
                    push(&mut out, &(c as char).to_string());
                }
            }
        }
    }
    if depth > 0 {
        out.unbalanced = Some(format!(
            "This RTF stream ends with {depth} group(s) still open. What was read is kept; a \
             stream whose braces do not balance is what a truncated or carved note looks like."
        ));
    }
    out
}
