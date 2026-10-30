//! Turning the `Message-ID` / `In-Reply-To` / `References` headers into a
//! thread an examiner can read as a thread (`ROADMAP.md` §5.14).
//!
//! # Why this is derived here and not in SQL
//!
//! A conversation key everywhere else in this project is a field the parser
//! read: a chat identifier, a JID, a thread id. Email has no such field. What
//! it has is a *chain* — each message names its parent, and by RFC 5322
//! convention carries the whole ancestry in `References`, oldest first. The
//! thread is the root of that chain, and a reader has to walk headers to find
//! it.
//!
//! So the walk happens here, in the parser that holds the headers, and it
//! publishes one plain string that the existing conversation machinery can
//! group on. Deriving it in the query instead would mean a `COALESCE` over
//! JSON paths, which is what every other channel uses and which cannot express
//! "the first element of the ancestry list, unless the list is empty, in which
//! case the parent, unless there is no parent, in which case this message is
//! itself a root".
//!
//! # And why the basis travels with it
//!
//! The four bases below are not equally strong, and an examiner reading a
//! thread has to know which one assembled it:
//!
//! * [`BASIS_REFERENCES`] — the message carries its ancestry and names its own
//!   thread root. This is the strong case and the common one for anything that
//!   passed through an ordinary mail client.
//! * [`BASIS_IN_REPLY_TO`] — no `References`, but the message names its parent.
//!   The key is then the *parent's* id, so a two-level exchange threads
//!   correctly and a deeper one **splits**: a reply to a reply keys on its own
//!   parent rather than on the root. Stated rather than hidden, because a
//!   thread that is silently half of a longer exchange reads as the whole of
//!   it.
//! * [`BASIS_OWN_MESSAGE_ID`] — neither header. As far as this evidence shows,
//!   the message starts a thread; it is keyed on itself so replies to it can
//!   find it, and if none were recovered it reads as a thread of one. That is
//!   not a claim that no reply exists.
//! * **No key at all** — no `Message-ID` either, so nothing can address this
//!   message's thread. `None`, never a fabricated key: a made-up key would
//!   group every header-less message in the mailbox into one "conversation"
//!   that never existed, which is worse than no thread view.
//!
//! Notably absent: grouping by subject line. "Re: invoice" is not evidence that
//! two messages are the same exchange, and a threading rule that treats it as
//! evidence would put two unrelated people's mail in one conversation and
//! present it as a recovered thread.

/// The message named its own thread root in `References`.
pub const BASIS_REFERENCES: &str = "references_root";
/// No `References`; the key is the parent named in `In-Reply-To`.
pub const BASIS_IN_REPLY_TO: &str = "in_reply_to";
/// Neither header; the message is keyed on its own `Message-ID`.
pub const BASIS_OWN_MESSAGE_ID: &str = "own_message_id";

/// A short sentence for each basis, written onto the record so the sentence an
/// examiner reads is the one this code is responsible for.
pub fn basis_note(basis: &str) -> &'static str {
    match basis {
        BASIS_REFERENCES => {
            "This message carries its own ancestry in the References header and names its \
             thread root, so the thread it is grouped into is the one the mail client recorded."
        }
        BASIS_IN_REPLY_TO => {
            "This message carries no References header, so it is grouped by the parent its \
             In-Reply-To header names. A reply to a reply keys on its own parent rather than on \
             the thread root, so a deeper exchange may appear here as more than one thread."
        }
        BASIS_OWN_MESSAGE_ID => {
            "This message names no parent, so as far as this evidence shows it begins a thread \
             and is keyed on its own Message-ID. A thread of one means no reply to it was \
             recovered — not that none was sent."
        }
        _ => {
            "The basis on which this message was grouped was not recorded, which should not \
             happen; treat the grouping as unverified."
        }
    }
}

/// Normalise a header-form message identifier for use as a key.
///
/// RFC 5322 writes an id inside angle brackets and permits folding whitespace
/// around it, and the same id reaches this code with and without them
/// depending on the format it was read from — `Message-ID: <a@b>` from an
/// `.eml`, `a@b` from a MAPI property. Two spellings of one id would be two
/// threads.
///
/// Case is **not** folded. The local part of an address is case-sensitive by
/// the standard, and folding it would merge two ids that a strict mail store
/// treats as different.
fn normalise(id: &str) -> Option<String> {
    let trimmed = id
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// The thread key for one message, and the basis it rests on.
///
/// `None` where the message carries none of the three headers: nothing can
/// address its thread, and a fabricated key would be worse than no thread
/// view. See the module documentation for what each basis is worth.
pub fn thread_key(
    message_id: &str,
    in_reply_to: &str,
    references: &[String],
) -> Option<(String, &'static str)> {
    // The ancestry, oldest first: its first entry is the thread root. Skip any
    // leading entry that is not an id at all rather than taking it and keying
    // the thread on whitespace.
    if let Some(root) = references.iter().find_map(|r| normalise(r)) {
        return Some((root, BASIS_REFERENCES));
    }
    if let Some(parent) = normalise(in_reply_to) {
        return Some((parent, BASIS_IN_REPLY_TO));
    }
    if let Some(own) = normalise(message_id) {
        return Some((own, BASIS_OWN_MESSAGE_ID));
    }
    None
}

/// Write the thread key, its basis and the basis note onto a message record,
/// or write the reason there is none.
///
/// One writer, so every format this crate reads publishes the same three keys
/// and a new reader cannot ship a thread key with no basis beside it.
pub fn stamp(
    metadata: &mut serde_json::Map<String, serde_json::Value>,
    message_id: &str,
    in_reply_to: &str,
    references: &[String],
) {
    match thread_key(message_id, in_reply_to, references) {
        Some((key, basis)) => {
            metadata.insert("email_thread_key".into(), serde_json::json!(key));
            metadata.insert("email_thread_basis".into(), serde_json::json!(basis));
            metadata.insert(
                "email_thread_basis_note".into(),
                serde_json::json!(basis_note(basis)),
            );
        }
        None => {
            // Absent, not empty: a key of "" would group every header-less
            // message in the mailbox into one conversation that never existed.
            metadata.insert(
                "email_thread_unavailable_reason".into(),
                serde_json::json!(
                    "This message carries no Message-ID, In-Reply-To or References header, so \
                     the exchange it belongs to cannot be addressed from the evidence. It is \
                     shown as a single record rather than grouped with messages it may belong \
                     with."
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_carrying_its_ancestry_is_keyed_on_the_thread_root() {
        let refs = vec![
            "<root@example.com>".to_string(),
            "<second@example.com>".to_string(),
        ];
        assert_eq!(
            thread_key("<third@example.com>", "<second@example.com>", &refs),
            Some(("root@example.com".to_string(), BASIS_REFERENCES))
        );
    }

    /// The root itself carries no ancestry and no parent, so it keys on its own
    /// id — which is exactly the key its replies computed from `References`.
    #[test]
    fn a_thread_root_and_its_replies_reach_the_same_key() {
        let (root_key, root_basis) = thread_key("<root@example.com>", "", &[]).unwrap();
        assert_eq!(root_basis, BASIS_OWN_MESSAGE_ID);
        let (reply_key, reply_basis) = thread_key(
            "<reply@example.com>",
            "<root@example.com>",
            &["<root@example.com>".to_string()],
        )
        .unwrap();
        assert_eq!(reply_basis, BASIS_REFERENCES);
        assert_eq!(root_key, reply_key, "the root and its reply must thread");
    }

    /// A direct reply with no `References` threads with the root; a reply to
    /// *that* keys on its own parent and splits. The basis is what tells an
    /// examiner which of the two they are reading.
    #[test]
    fn an_in_reply_to_only_chain_threads_two_levels_and_says_so() {
        let (root, _) = thread_key("<root@x>", "", &[]).unwrap();
        let (reply, basis) = thread_key("<r1@x>", "<root@x>", &[]).unwrap();
        assert_eq!(basis, BASIS_IN_REPLY_TO);
        assert_eq!(reply, root);

        let (deep, deep_basis) = thread_key("<r2@x>", "<r1@x>", &[]).unwrap();
        assert_eq!(deep_basis, BASIS_IN_REPLY_TO);
        assert_ne!(deep, root, "the limit is real");
        // And the note names it, so a split thread is not read as a whole one.
        assert!(basis_note(BASIS_IN_REPLY_TO).contains("more than one thread"));
    }

    /// Angle brackets and folding whitespace are spelling, not identity.
    #[test]
    fn the_same_id_spelled_two_ways_is_one_thread() {
        let bare = thread_key("root@example.com", "", &[]).unwrap().0;
        let bracketed = thread_key("  <root@example.com>  ", "", &[]).unwrap().0;
        assert_eq!(bare, bracketed);
    }

    /// The local part of an address is case-sensitive by the standard, so two
    /// ids differing in case are two ids and must not be merged.
    #[test]
    fn case_is_not_folded() {
        let lower = thread_key("<Root@example.com>", "", &[]).unwrap().0;
        assert_eq!(lower, "Root@example.com");
        assert_ne!(lower, thread_key("<root@example.com>", "", &[]).unwrap().0);
    }

    /// A message with no usable header gets no key. A fabricated one would
    /// group every header-less message in the mailbox into one conversation
    /// that never existed.
    #[test]
    fn a_message_with_no_usable_header_gets_no_key() {
        for (id, parent, refs) in [
            ("", "", vec![]),
            ("   ", "  ", vec!["".to_string(), "<>".to_string()]),
            ("<>", "<>", vec![]),
        ] {
            assert_eq!(thread_key(id, parent, &refs), None, "{id:?}");
        }
    }

    /// An empty leading entry in `References` is skipped rather than taken as
    /// the root: keying a thread on whitespace groups by nothing.
    #[test]
    fn an_unusable_leading_reference_is_skipped() {
        let refs = vec!["".to_string(), "<root@x>".to_string()];
        assert_eq!(
            thread_key("<r@x>", "", &refs),
            Some(("root@x".to_string(), BASIS_REFERENCES))
        );
    }

    #[test]
    fn a_record_carries_its_key_its_basis_and_the_sentence_for_it() {
        let mut m = serde_json::Map::new();
        stamp(&mut m, "<r@x>", "<root@x>", &["<root@x>".to_string()]);
        assert_eq!(m["email_thread_key"], "root@x");
        assert_eq!(m["email_thread_basis"], BASIS_REFERENCES);
        assert!(m["email_thread_basis_note"]
            .as_str()
            .unwrap()
            .contains("the mail client recorded"));
        assert!(m.get("email_thread_unavailable_reason").is_none());
    }

    /// The reason is on the record, so a message that cannot be threaded says
    /// why rather than simply not appearing in any thread.
    #[test]
    fn a_record_that_cannot_be_threaded_carries_the_reason_and_no_key() {
        let mut m = serde_json::Map::new();
        stamp(&mut m, "", "", &[]);
        assert!(m.get("email_thread_key").is_none());
        assert!(m.get("email_thread_basis").is_none());
        assert!(m["email_thread_unavailable_reason"]
            .as_str()
            .unwrap()
            .contains("cannot be addressed"));
    }

    /// Every basis has its own sentence, and an unrecognised one does not
    /// silently borrow another's.
    #[test]
    fn every_basis_has_its_own_sentence() {
        let notes: Vec<&str> = [BASIS_REFERENCES, BASIS_IN_REPLY_TO, BASIS_OWN_MESSAGE_ID]
            .iter()
            .map(|b| basis_note(b))
            .collect();
        assert_eq!(
            notes.iter().collect::<std::collections::HashSet<_>>().len(),
            3
        );
        assert!(basis_note("something_new").contains("should not happen"));
    }
}
