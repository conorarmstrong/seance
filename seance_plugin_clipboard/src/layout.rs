//! Recognising the on-disk shape of the clipboard store, from a path.
//!
//! Windows lays the store out as
//! `%LOCALAPPDATA%\Microsoft\Windows\Clipboard\`, holding `Pinned` and
//! `HistoryData`. Under each sits a GUID folder, and under that one GUID folder
//! per clipboard item. Inside an item folder are `metadata.json` and one file
//! per clipboard format, **named for the format in base64** — `VGV4dA==` is
//! `Text`, `Qml0bWFw` is `Bitmap`, `TG9jYWxl` is `Locale`.
//!
//! The base64 is the format name, not the content: decoding a filename says
//! *what kind* of thing was copied without touching the encrypted payload. That
//! alone is evidence — "an image was pinned" and "a password was pinned" are
//! different findings, and the difference is legible from the filename.
//!
//! # Why the path decides
//!
//! `metadata.json` is a name millions of files carry, and a base64 filename is
//! not a signature at all. Neither can self-select the way a SQLite header or an
//! ESE schema can. So this artifact is identified by **where it sits**, and the
//! gate is deliberately narrow: the two parent folders must be present in
//! order, under a `Microsoft/Windows/Clipboard` path. A looser test would
//! attach clipboard findings to unrelated files.

use base64::Engine;

/// Longest filename this will try to decode. A clipboard format name is short;
/// the ceiling stops a long name in an unrelated directory costing anything.
const MAX_FORMAT_NAME_BYTES: usize = 256;

/// Which part of the clipboard store a path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// The per-store inventory. One per store, listing its items.
    Metadata {
        /// `Pinned` or `HistoryData`.
        store: Store,
    },
    /// One clipboard format of one item.
    Payload {
        store: Store,
        /// The item's GUID folder name, which is its identity in the metadata.
        item: String,
        /// The clipboard format, when the filename decoded to a plausible name.
        format: Option<String>,
        /// The filename as it sits on disk, always, so a record can cite it.
        file_name: String,
    },
}

/// Which of the two stores a path is under.
///
/// Kept apart because they mean different things to an examiner. A pinned item
/// was chosen deliberately by the user and survives a reboot; history data is
/// the ordinary rolling buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    Pinned,
    HistoryData,
}

impl Store {
    pub fn as_str(self) -> &'static str {
        match self {
            Store::Pinned => "pinned",
            Store::HistoryData => "history_data",
        }
    }

    /// What this store's presence means, for a record an examiner reads.
    pub fn meaning(self) -> &'static str {
        match self {
            Store::Pinned => {
                "A pinned clipboard item. The user chose to keep this one, and \
                              pinned items survive the sign-out and reboot that clear the rest \
                              of clipboard history."
            }
            Store::HistoryData => {
                "A clipboard history item held on disk. Most history is kept \
                                   in the clipboard service's memory and never written; an \
                                   item here was retained for another reason, commonly \
                                   clipboard sync being enabled."
            }
        }
    }
}

/// Split a path into components, tolerating either separator.
///
/// Evidence paths arrive in whatever form the filesystem parser produced —
/// `\` from NTFS, `/` from a normalised path, mixed from a container. Matching
/// one and not the other would make the gate depend on which parser ran.
///
/// **Case is preserved.** Folder names are matched case-insensitively, because
/// Windows paths are, but the payload filename is base64 and base64 is
/// case-sensitive: lowercasing `VGV4dA==` yields `vgv4da==`, which decodes to
/// bytes that are not "Text" and are not printable. Folding the whole path
/// would silently turn every clipboard format into "unrecognised".
fn components(path: &str) -> Vec<String> {
    path.split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .map(str::to_string)
        .collect()
}

/// Case-insensitive comparison, for the folder names.
fn eq_fold(part: Option<&String>, want: &str) -> bool {
    part.map(|p| p.eq_ignore_ascii_case(want)).unwrap_or(false)
}

/// Where in the components the clipboard store begins, and which store it is.
///
/// Requires `microsoft`, `windows`, `clipboard` **adjacent and in order**, so
/// that a path merely containing the word "clipboard" does not qualify.
fn locate_store(parts: &[String]) -> Option<(usize, Store)> {
    for i in 0..parts.len() {
        if eq_fold(parts.get(i), "microsoft")
            && eq_fold(parts.get(i + 1), "windows")
            && eq_fold(parts.get(i + 2), "clipboard")
        {
            let store = if eq_fold(parts.get(i + 3), "pinned") {
                Store::Pinned
            } else if eq_fold(parts.get(i + 3), "historydata") {
                Store::HistoryData
            } else {
                return None;
            };
            return Some((i + 3, store));
        }
    }
    None
}

/// Whether a component looks like one of the store's GUID folders.
///
/// Windows writes them braced or bare depending on the level, so both are
/// accepted. The shape is checked rather than parsed: this only has to
/// distinguish a GUID folder from `metadata.json`, not validate a UUID.
fn is_guidish(part: &str) -> bool {
    let trimmed = part.trim_start_matches('{').trim_end_matches('}');
    trimmed.len() == 36
        && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        && trimmed.matches('-').count() == 4
}

/// What, if anything, this path is.
///
/// `None` for everything that is not part of a clipboard store, which is almost
/// every path in a case.
pub fn classify(path: &str) -> Option<Role> {
    let parts = components(path);
    let (store_at, store) = locate_store(&parts)?;
    let rest = parts.get(store_at + 1..)?;

    // The inventory sits directly under the store, or under its GUID folder.
    // Both have been observed; accepting either costs nothing and missing the
    // real one would lose the timestamps entirely.
    if eq_fold(rest.last(), "metadata.json") {
        return Some(Role::Metadata { store });
    }

    // A payload: <store>/<guid>/<item-guid>/<format-file>. The item is the
    // last GUID-shaped component, so a store that gains or loses a level of
    // nesting still yields the item's identity rather than nothing.
    let file_name = rest.last()?.clone();
    if is_guidish(&file_name) {
        // A folder, not a file. Directories are filtered by the caller too, but
        // a path ending in a GUID is not a payload under any reading.
        return None;
    }
    // Lowercased: the folder name is the item's identity and is compared
    // against the inventory's, so one casing has to be chosen. The filename
    // above is NOT folded, for the reason `components` records.
    let item = rest
        .iter()
        .rev()
        .skip(1)
        .find(|p| is_guidish(p))?
        .to_ascii_lowercase();

    Some(Role::Payload {
        store,
        item,
        format: decode_format_name(&file_name),
        file_name,
    })
}

/// A clipboard format name, from a base64 filename.
///
/// `None` when the name does not decode to something a clipboard format could
/// be called. That is the honest answer for a file this parser does not
/// recognise, and it leaves the raw filename — which the record always carries —
/// as the thing an examiner works from.
pub fn decode_format_name(file_name: &str) -> Option<String> {
    if file_name.is_empty() || file_name.len() > MAX_FORMAT_NAME_BYTES {
        return None;
    }
    // Windows filenames cannot contain '/', so a name using the standard
    // alphabet's 62nd and 63rd characters would be unwritable. Both the
    // standard and URL-safe alphabets are tried rather than assuming which was
    // used, since either yields a legal name for the short strings involved.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(file_name)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(file_name))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(file_name))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(file_name))
        .ok()?;

    let text = String::from_utf8(decoded).ok()?;
    if text.is_empty() || text.len() > MAX_FORMAT_NAME_BYTES {
        return None;
    }
    // A format name is printable. Anything else means the filename decoded by
    // coincidence — short base64 does that — and reporting it would invent a
    // format that was never on the clipboard.
    if !text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }
    Some(text)
}

/// What a clipboard format means, where it is one of the documented ones.
///
/// Returns `None` for a format this does not know, which is deliberate: an
/// application can register its own clipboard format, and inventing a
/// description for one would be worse than leaving the name to speak for
/// itself.
pub fn describe_format(format: &str) -> Option<&'static str> {
    match format.to_ascii_lowercase().as_str() {
        "text" => Some(
            "Text copied to the clipboard. This is the format that carries passwords, \
             addresses, message contents and anything else typed or selected as text.",
        ),
        "bitmap" | "png" | "dib" | "dibv5" => Some(
            "An image copied to the clipboard — a screenshot, or a picture copied from an \
             application.",
        ),
        "html format" | "html" => Some(
            "Rich text copied from a browser or editor. It normally carries the source URL \
             alongside the visible text.",
        ),
        "locale" => Some(
            "The locale of the copied data. Written alongside the payload; not user content \
             itself.",
        ),
        "unicodetext" => Some("Text copied to the clipboard, in its Unicode form."),
        "filenamew" | "filename" | "filedrop" | "filegroupdescriptorw" => Some(
            "A file or files copied to the clipboard. The payload names what was copied, \
             which can evidence a transfer even when the file itself is gone.",
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIN: &str = r"C:\Users\jo\AppData\Local\Microsoft\Windows\Clipboard";
    const ITEM: &str = "{6f1e2a3b-4c5d-6e7f-8091-a2b3c4d5e6f7}";
    const OUTER: &str = "{11111111-2222-3333-4444-555555555555}";

    #[test]
    fn the_documented_format_filenames_decode_to_their_names() {
        assert_eq!(decode_format_name("VGV4dA==").as_deref(), Some("Text"));
        assert_eq!(decode_format_name("Qml0bWFw").as_deref(), Some("Bitmap"));
        assert_eq!(decode_format_name("TG9jYWxl").as_deref(), Some("Locale"));
    }

    /// A name that is not base64, or decodes to rubbish, yields nothing.
    ///
    /// Short base64 decodes by coincidence often enough that accepting whatever
    /// falls out would invent clipboard formats. The raw filename is always
    /// kept on the record, so `None` loses nothing.
    #[test]
    fn a_filename_that_is_not_a_format_name_decodes_to_nothing() {
        assert_eq!(decode_format_name("metadata.json"), None);
        assert_eq!(decode_format_name(""), None);
        assert_eq!(decode_format_name("!!!!"), None);
        // Valid base64, decodes to bytes that are not printable text.
        assert_eq!(decode_format_name("//79/A=="), None);
        assert_eq!(decode_format_name(&"A".repeat(400)), None);
    }

    #[test]
    fn a_pinned_payload_path_is_classified_with_its_item_and_format() {
        let path = format!(r"{WIN}\Pinned\{OUTER}\{ITEM}\VGV4dA==");
        match classify(&path).expect("a pinned payload") {
            Role::Payload {
                store,
                item,
                format,
                file_name,
            } => {
                assert_eq!(store, Store::Pinned);
                assert_eq!(item, ITEM.to_ascii_lowercase());
                assert_eq!(format.as_deref(), Some("Text"));
                // Not folded: base64 is case-sensitive, and lowercasing this
                // would decode to bytes that are not a format name.
                assert_eq!(file_name, "VGV4dA==");
            }
            other => panic!("expected a payload, got {other:?}"),
        }
    }

    #[test]
    fn the_two_stores_are_told_apart() {
        let pinned = format!(r"{WIN}\Pinned\{OUTER}\{ITEM}\Qml0bWFw");
        let history = format!(r"{WIN}\HistoryData\{OUTER}\{ITEM}\Qml0bWFw");
        assert!(matches!(
            classify(&pinned),
            Some(Role::Payload {
                store: Store::Pinned,
                ..
            })
        ));
        assert!(matches!(
            classify(&history),
            Some(Role::Payload {
                store: Store::HistoryData,
                ..
            })
        ));
        assert_ne!(Store::Pinned.meaning(), Store::HistoryData.meaning());
    }

    #[test]
    fn the_inventory_is_found_under_either_nesting() {
        let direct = format!(r"{WIN}\Pinned\metadata.json");
        let nested = format!(r"{WIN}\Pinned\{OUTER}\metadata.json");
        for p in [direct, nested] {
            assert!(
                matches!(
                    classify(&p),
                    Some(Role::Metadata {
                        store: Store::Pinned
                    })
                ),
                "{p}"
            );
        }
    }

    /// Forward slashes must work: which separator a path carries is a property
    /// of the filesystem parser that produced it, not of the evidence.
    #[test]
    fn either_path_separator_is_accepted() {
        let unix = format!(
            "/Users/jo/AppData/Local/Microsoft/Windows/Clipboard/Pinned/{OUTER}/{ITEM}/VGV4dA=="
        );
        assert!(matches!(classify(&unix), Some(Role::Payload { .. })));
    }

    /// **The gate must be narrow.** Attaching clipboard findings to an
    /// unrelated file would put a claim about a user's clipboard onto evidence
    /// that says nothing of the kind.
    #[test]
    fn paths_that_merely_mention_clipboard_are_refused() {
        for path in [
            r"C:\Users\jo\Documents\clipboard\Pinned\notes.txt",
            r"C:\Program Files\ClipboardTool\Pinned\VGV4dA==",
            r"C:\Users\jo\AppData\Local\Microsoft\Windows\Clipboard\VGV4dA==",
            r"C:\Users\jo\AppData\Local\Microsoft\Clipboard\Pinned\VGV4dA==",
            r"C:\Users\jo\AppData\Local\Microsoft\Windows\Explorer\Pinned\VGV4dA==",
            r"C:\metadata.json",
            "",
        ] {
            assert_eq!(classify(path), None, "must not classify: {path}");
        }
    }

    /// A payload path needs an item GUID above it; without one there is nothing
    /// to tie the file to an entry in the inventory.
    #[test]
    fn a_payload_with_no_item_folder_is_not_classified() {
        let path = format!(r"{WIN}\Pinned\{OUTER}\VGV4dA==");
        // The outer GUID is the only one, and it is the item.
        match classify(&path) {
            Some(Role::Payload { item, .. }) => assert_eq!(item, OUTER.to_ascii_lowercase()),
            other => panic!("expected the outer guid to serve as the item, got {other:?}"),
        }
        // With no GUID at all there is nothing to attribute.
        let bare = format!(r"{WIN}\Pinned\VGV4dA==");
        assert_eq!(classify(&bare), None);
    }

    #[test]
    fn a_guid_folder_itself_is_not_a_payload() {
        let path = format!(r"{WIN}\Pinned\{OUTER}\{ITEM}");
        assert_eq!(classify(&path), None);
    }

    #[test]
    fn a_format_this_parser_does_not_know_is_left_to_speak_for_itself() {
        assert!(describe_format("Text").is_some());
        assert!(describe_format("BITMAP").is_some());
        assert!(describe_format("Locale").is_some());
        assert_eq!(describe_format("AcmeCorpInternalFormat"), None);
    }
}
