//! Folders and messages of a version-36 store.

use super::ltp::{read_pc, read_tc, PropValue};
use super::ndb::Ndb;
use std::collections::BTreeMap;

/// A folder node, named from its own property context.
#[derive(Debug, Clone)]
pub struct Folder {
    pub nid: u32,
    pub parent: u32,
    pub name: String,
    /// `/`-joined names from the root folder down, this one included.
    pub path: String,
    /// `PidTagContentCount`: how many messages the folder says it holds.
    pub content_count: Option<i64>,
    /// The name was stored as 8-bit text that is not UTF-8 and was decoded in
    /// the assumed Windows-1252: a decoding of bytes, not stored Unicode.
    pub name_legacy_8bit: bool,
}

/// A message node and what could be read of it.
#[derive(Debug, Clone)]
pub struct Message {
    pub nid: u32,
    pub folder_nid: u32,
    pub props: BTreeMap<u16, PropValue>,
    /// Properties present whose value could not be read, by tag.
    pub props_unreadable: Vec<(u16, String)>,
    pub attachments: Vec<BTreeMap<u16, PropValue>>,
    pub attachments_unreadable: usize,
    /// The recipient table's rows when the message has one and it was read.
    pub recipients: Option<Vec<BTreeMap<u16, PropValue>>>,
    /// Why a recipient table the message has could not be read.
    pub recipients_error: Option<String>,
}

/// Everything the walk of a store's folders and messages reached, and every
/// node it could not read.
#[derive(Debug, Clone, Default)]
pub struct Mailbox {
    pub store: BTreeMap<u16, PropValue>,
    pub folders: Vec<Folder>,
    pub messages: Vec<Message>,
    /// Folder and message nodes that would not read, with why.
    pub nodes_unreadable: Vec<(u32, String)>,
}

/// NID types (the low five bits of a NID).
const NID_TYPE_NORMAL_FOLDER: u32 = 0x02;
const NID_TYPE_NORMAL_MESSAGE: u32 = 0x04;
const NID_TYPE_ATTACHMENT: u32 = 0x05;
const NID_TYPE_RECIPIENT_TABLE: u32 = 0x12;
/// The store's own property context.
pub const NID_MESSAGE_STORE: u32 = 0x21;

const PID_TAG_DISPLAY_NAME: u16 = 0x3001;
const PID_TAG_CONTENT_COUNT: u16 = 0x3602;
/// Deeper than this, a folder's path is not followed further.
const MAX_FOLDER_DEPTH: usize = 64;

/// Read the folders and messages of a store.
///
/// Folders and messages are found in the node B-tree by node type — every
/// normal-folder node (type 2) and every normal-message node (type 4) — and
/// placed by the parent NID the B-tree records for them, not by walking the
/// folders' hierarchy and contents tables. A folder's `PidTagContentCount` is
/// kept so the caller can compare what the folder says it holds with what was
/// found under it. Folder-associated (hidden) messages, type 8, are not read.
/// Attachments are the message's attachment subnodes (type 5), each read as a
/// property context.
pub fn read_mailbox(ndb: &Ndb<'_>) -> Mailbox {
    let mut mb = Mailbox::default();
    match ndb.node(NID_MESSAGE_STORE) {
        Some(n) => match read_pc(ndb, n.bid_data, n.bid_sub) {
            Ok(pc) => mb.store = pc.props,
            Err(e) => mb.nodes_unreadable.push((NID_MESSAGE_STORE, e.to_string())),
        },
        None => mb.nodes_unreadable.push((
            NID_MESSAGE_STORE,
            "the store node is not in the node B-tree".into(),
        )),
    }

    let mut names: BTreeMap<u32, (u32, String, Option<i64>)> = BTreeMap::new();
    let mut legacy_names = std::collections::BTreeSet::new();
    for n in ndb.nodes() {
        let nid = n.nid as u32;
        if nid & 0x1F != NID_TYPE_NORMAL_FOLDER {
            continue;
        }
        match read_pc(ndb, n.bid_data, n.bid_sub) {
            Ok(pc) => {
                let (name, legacy) = folder_display_name(&pc.props);
                if legacy {
                    legacy_names.insert(nid);
                }
                let count = match pc.props.get(&PID_TAG_CONTENT_COUNT) {
                    Some(PropValue::I32(c)) => Some(i64::from(*c)),
                    _ => None,
                };
                names.insert(nid, (n.nid_parent, name, count));
            }
            Err(e) => mb.nodes_unreadable.push((nid, e.to_string())),
        }
    }
    for (&nid, (parent, name, count)) in &names {
        mb.folders.push(Folder {
            nid,
            parent: *parent,
            name: name.clone(),
            path: folder_path(nid, &names),
            content_count: *count,
            name_legacy_8bit: legacy_names.contains(&nid),
        });
    }

    for n in ndb.nodes() {
        let nid = n.nid as u32;
        if nid & 0x1F != NID_TYPE_NORMAL_MESSAGE {
            continue;
        }
        let pc = match read_pc(ndb, n.bid_data, n.bid_sub) {
            Ok(pc) => pc,
            Err(e) => {
                mb.nodes_unreadable.push((nid, e.to_string()));
                continue;
            }
        };
        let mut attachments = Vec::new();
        let mut attachments_unreadable = 0;
        for (&snid, sub) in &pc.subnodes {
            if snid & 0x1F != NID_TYPE_ATTACHMENT {
                continue;
            }
            match read_pc(ndb, sub.bid_data, sub.bid_sub) {
                Ok(a) => attachments.push(a.props),
                Err(_) => attachments_unreadable += 1,
            }
        }
        let (mut recipients, mut recipients_error) = (None, None);
        if let Some(sub) = pc
            .subnodes
            .iter()
            .find(|(snid, _)| **snid & 0x1F == NID_TYPE_RECIPIENT_TABLE)
            .map(|(_, sub)| sub)
        {
            match read_tc(ndb, sub.bid_data, sub.bid_sub) {
                Ok(t) if t.unreadable.is_empty() => recipients = Some(t.rows),
                Ok(t) => {
                    recipients_error = Some(format!(
                        "{} recipient cell(s) or row(s) could not be read",
                        t.unreadable.len()
                    ));
                    recipients = Some(t.rows);
                }
                Err(e) => recipients_error = Some(e.to_string()),
            }
        }
        mb.messages.push(Message {
            nid,
            folder_nid: n.nid_parent,
            props: pc.props,
            props_unreadable: pc.unreadable,
            attachments,
            attachments_unreadable,
            recipients,
            recipients_error,
        });
    }
    mb
}

/// A folder's names from the root down. A chain that does not reach the root
/// (a parent that is not a folder read here, a parent that is not a folder
/// node at all, a chain of parents that loops, or nesting past
/// [`MAX_FOLDER_DEPTH`]) starts with a marker saying where it stopped, in the
/// words `pst512::Store::folder_paths` uses, so a path is never silently
/// shorter than the chain it stands for.
fn folder_path(nid: u32, names: &BTreeMap<u32, (u32, String, Option<i64>)>) -> String {
    let mut parts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut at = nid;
    let mut stopped = None;
    loop {
        let Some((parent, name, _)) = names.get(&at) else {
            stopped = Some(if at & 0x1F != NID_TYPE_NORMAL_FOLDER {
                format!("(parent node {at:#x} is not a folder)")
            } else {
                format!("(parent node {at:#x} not found)")
            });
            break;
        };
        // The root folder is its own parent and has no name.
        if *parent == at && name.is_empty() {
            break;
        }
        if !seen.insert(at) {
            stopped = Some("(folder parent chain loops)".to_string());
            break;
        }
        if parts.len() >= MAX_FOLDER_DEPTH {
            stopped = Some("(path truncated at depth limit)".to_string());
            break;
        }
        parts.push(name.clone());
        at = *parent;
    }
    parts.extend(stopped);
    parts.reverse();
    parts.join("/")
}

/// A folder's display name, and whether it was stored as 8-bit text that is
/// not UTF-8. A folder carries no code page of its own, so such a name is
/// decoded in the assumed default, Windows-1252, and flagged: the flag says
/// the characters are a decoding of bytes, under an assumption.
fn folder_display_name(props: &BTreeMap<u16, PropValue>) -> (String, bool) {
    match props.get(&PID_TAG_DISPLAY_NAME) {
        Some(PropValue::Str(s)) => (s.clone(), false),
        Some(PropValue::Other { ptype: 0x001E, raw }) => {
            let (text, _, _) = encoding_rs::WINDOWS_1252.decode(raw);
            (text.trim_end_matches('\0').to_string(), true)
        }
        _ => (String::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Names = BTreeMap<u32, (u32, String, Option<i64>)>;

    fn folder(names: &mut Names, nid: u32, parent: u32, name: &str) {
        names.insert(nid, (parent, name.to_string(), None));
    }

    #[test]
    fn a_healthy_chain_has_no_marker() {
        let mut n = Names::new();
        folder(&mut n, 0x122, 0x122, "");
        folder(&mut n, 0x142, 0x122, "Top");
        folder(&mut n, 0x162, 0x142, "Inbox");
        assert_eq!(folder_path(0x162, &n), "Top/Inbox");
        assert_eq!(folder_path(0x122, &n), "");
    }

    #[test]
    fn an_orphan_folder_path_starts_with_the_not_found_marker() {
        let mut n = Names::new();
        folder(&mut n, 0x162, 0x1042, "Inbox");
        assert_eq!(
            folder_path(0x162, &n),
            "(parent node 0x1042 not found)/Inbox"
        );
    }

    #[test]
    fn a_non_folder_parent_is_marked() {
        let mut n = Names::new();
        folder(&mut n, 0x162, 0x8004, "Inbox");
        assert_eq!(
            folder_path(0x162, &n),
            "(parent node 0x8004 is not a folder)/Inbox"
        );
    }

    #[test]
    fn a_parent_cycle_is_marked() {
        let mut n = Names::new();
        folder(&mut n, 0x142, 0x162, "A");
        folder(&mut n, 0x162, 0x142, "B");
        assert_eq!(folder_path(0x142, &n), "(folder parent chain loops)/B/A");
    }

    #[test]
    fn a_chain_deeper_than_the_limit_is_marked() {
        let mut n = Names::new();
        folder(&mut n, 0x122, 0x122, "");
        let mut parent = 0x122;
        for i in 1..=70u32 {
            let nid = (0x200 + i * 0x20) | 0x02;
            folder(&mut n, nid, parent, &format!("d{i}"));
            parent = nid;
        }
        let p = folder_path(parent, &n);
        assert!(p.starts_with("(path truncated at depth limit)/"), "{p}");
        assert_eq!(p.split('/').count(), MAX_FOLDER_DEPTH + 1);
    }

    #[test]
    fn an_8_bit_folder_name_is_decoded_and_flagged_not_read_as_empty() {
        let mut p = BTreeMap::new();
        p.insert(
            PID_TAG_DISPLAY_NAME,
            PropValue::Other {
                ptype: 0x001E,
                raw: b"Bo\xEEte\0".to_vec(),
            },
        );
        assert_eq!(folder_display_name(&p), ("Bo\u{ee}te".to_string(), true));
        p.insert(PID_TAG_DISPLAY_NAME, PropValue::Str("Inbox".into()));
        assert_eq!(folder_display_name(&p), ("Inbox".to_string(), false));
        assert_eq!(
            folder_display_name(&BTreeMap::new()),
            (String::new(), false)
        );
    }
}
