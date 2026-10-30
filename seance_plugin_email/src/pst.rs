use crate::{is_truncated, truncate_str};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use serde_json::json;
use std::rc::Rc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use outlook_pst::ltp::prop_context::PropertyValue;
use outlook_pst::messaging::attachment::{AnsiAttachment, AttachmentProperties, UnicodeAttachment};
use outlook_pst::messaging::folder::{AnsiFolder, UnicodeFolder};
use outlook_pst::messaging::message::{AnsiMessage, UnicodeMessage};
use outlook_pst::messaging::store::{AnsiStore, UnicodeStore};
use outlook_pst::ndb::node_id::NodeId;

use crate::ost4k::ltp::PropValue as Ost4kValue;

const MAX_BODY_SIZE: usize = 64 * 1024; // 64KB
const MAX_PST_MESSAGES: usize = 100_000;
const MAX_PST_FOLDERS: usize = 10_000;

// Property IDs (MS-OXPROPS)
const PID_TAG_SUBJECT: u16 = 0x0037;
const PID_TAG_CLIENT_SUBMIT_TIME: u16 = 0x0039;
const PID_TAG_SENDER_NAME: u16 = 0x0C1A;
const PID_TAG_SENDER_EMAIL: u16 = 0x0C1F;
const PID_TAG_SENT_REPRESENTING_NAME: u16 = 0x0042;
const PID_TAG_SENT_REPRESENTING_EMAIL: u16 = 0x0065;
/// PidTagSenderSmtpAddress / PidTagSentRepresentingSmtpAddress. On
/// Exchange-originated mail the legacy *EmailAddress properties hold an X.500
/// DN, not a usable address, so these must win (the MSG path already does this).
const PID_TAG_SENDER_SMTP: u16 = 0x5D01;
const PID_TAG_SENT_REPRESENTING_SMTP: u16 = 0x5D02;
// Attachment properties (read from each row of the message's attachment table).
const PID_TAG_DISPLAY_NAME: u16 = 0x3001;
const PID_TAG_RECIPIENT_TYPE: u16 = 0x0C15;
const PID_TAG_ADDRESS_TYPE: u16 = 0x3002;
const PID_TAG_RECIPIENT_EMAIL_ADDRESS: u16 = 0x3003;
const PID_TAG_RECIPIENT_SMTP_ADDRESS: u16 = 0x39FE;
const PID_TAG_ATTACH_SIZE: u16 = 0x0E20;
const PID_TAG_ATTACH_EXTENSION: u16 = 0x3703;
const PID_TAG_ATTACH_FILENAME: u16 = 0x3704;
const PID_TAG_ATTACH_METHOD: u16 = 0x3705;
const PID_TAG_ATTACH_LONG_FILENAME: u16 = 0x3707;
const PID_TAG_ATTACH_MIME_TAG: u16 = 0x370E;
const PID_TAG_DISPLAY_BCC: u16 = 0x0E02;
const PID_TAG_DISPLAY_CC: u16 = 0x0E03;
const PID_TAG_DISPLAY_TO: u16 = 0x0E04;
const PID_TAG_MESSAGE_DELIVERY_TIME: u16 = 0x0E06;
const PID_TAG_HAS_ATTACHMENTS: u16 = 0x0E1B;
const PID_TAG_MESSAGE_CLASS: u16 = 0x001A;
const PID_TAG_BODY: u16 = 0x1000;
/// PidTagBodyHtml: binary (in a code page) or string.
const PID_TAG_BODY_HTML: u16 = 0x1013;
/// PidTagInternetCodepage: the Windows code page the HTML body's bytes are in.
const PID_TAG_INTERNET_CODEPAGE: u16 = 0x3FDE;
/// The code page of the message's 8-bit text (MS-OXPROPS PidTagMessageCodepage).
const PID_TAG_MESSAGE_CODEPAGE: u16 = 0x3FFD;
/// PidTagMessageLocaleId: the Windows locale the message was written in.
const PID_TAG_MESSAGE_LOCALE_ID: u16 = 0x3FF1;
/// What 8-bit text is read as when the message declares no code page: the
/// ANSI default of the Windows that wrote nearly every such store.
const ASSUMED_8BIT_CODEPAGE: i64 = 1252;
/// PidTagRtfCompressed: the LZFu-compressed RTF body. Its presence is noted;
/// it is not decoded.
const PID_TAG_RTF_COMPRESSED: u16 = 0x1009;
const PID_TAG_CREATION_TIME: u16 = 0x3007;
// The three RFC 5322 threading headers as a PST stores them. Never read until
// 2026-09-14, so every message out of a PST published an empty `message_id`,
// `in_reply_to` and `references` and no PST mailbox could be read as a thread
// at all (ROADMAP §5.14) — on the format most likely to hold a long exchange.
const PID_TAG_INTERNET_MESSAGE_ID: u16 = 0x1035;
const PID_TAG_IN_REPLY_TO_ID: u16 = 0x1042;
const PID_TAG_INTERNET_REFERENCES: u16 = 0x1039;

/// What a mail store's own header says it is, before any reader is asked to
/// open it.
///
/// PST and OST share the `!BDN` magic; the two bytes after the CRC name the
/// client format (`SM` for a PST, `SO` for an OST) and `wVer` at offset 10 names
/// the on-disk layout. Versions 14 and 15 (ANSI) and 23 (Unicode) are read by
/// the linked `outlook-pst` reader; version 36, the 4 KiB-page layout Outlook
/// 2013 and later write, is read by this crate's own reader
/// ([`crate::ost4k`]). A store of any other version is refused by its number,
/// and the message must say so rather than call the file invalid: the NIST Data
/// Leakage OST was once reported as "Not a valid PST file", which is false
/// about the evidence (HUNT-063).
pub struct StoreHeader {
    pub client: &'static str,
    pub version: u16,
}

impl StoreHeader {
    pub fn read(data: &[u8]) -> Option<Self> {
        if data.len() < 12 || &data[..4] != b"!BDN" {
            return None;
        }
        let client = match &data[8..10] {
            b"SM" => "PST",
            b"SO" => "OST",
            _ => "unknown client",
        };
        let version = u16::from_le_bytes([data[10], data[11]]);
        Some(Self { client, version })
    }

    /// Whether some reader in this build (the linked one for 14, 15 and 23, this
    /// crate's own for 36) opens this layout at all.
    pub fn readable_by_this_build(&self) -> bool {
        matches!(self.version, 14 | 15 | 23 | 36)
    }

    /// The sentence the parse-failed record carries when it cannot.
    pub fn unsupported_message(&self) -> String {
        format!(
            "This is a {} store, format version {}. This build's readers open versions 14, 15, \
             23 and 36 only, so none of it was read; the store is not malformed",
            self.client, self.version
        )
    }
}

/// Parse a PST/OST file and produce email message artifacts.
pub fn parse_pst(data: &[u8], case_id: Uuid, parent_id: Uuid, name: &str) -> Vec<Artifact> {
    let mut artifacts = Vec::new();

    // Say what the store is before asking a reader that will refuse it, so the
    // record names the version rather than calling a valid file invalid.
    if let Some(header) = StoreHeader::read(data) {
        if !header.readable_by_this_build() {
            artifacts.push(make_parse_failed_artifact(
                case_id,
                parent_id,
                name,
                &header.unsupported_message(),
                IncompleteReason::UnresolvedStructure,
            ));
            return artifacts;
        }
        // Outlook 2013 and later: the 4 KiB-page layout, read by this crate's
        // own reader because the linked one refuses it (ROADMAP §2.6a).
        if header.version == 36 {
            return parse_ost4k(data, case_id, parent_id, name);
        }
    }

    // Try Unicode PST first (modern format), then ANSI (legacy). A reader that
    // refuses the store says why; the reason of the reader that matches the
    // header's version is the one reported.
    let unicode = match try_unicode_pst(data, case_id, parent_id, name) {
        Ok(result) => return with_recovery(result, data, case_id, parent_id, name),
        Err(why) => why,
    };
    let ansi = match try_ansi_pst(data, case_id, parent_id, name) {
        Ok(result) => return with_recovery(result, data, case_id, parent_id, name),
        Err(why) => why,
    };

    warn!(
        "Failed to parse PST file {} (Unicode reader: {}; ANSI reader: {})",
        name, unicode, ansi
    );
    // A header that names a supported version is a store, not a file that is
    // "not valid": the magic and version were read, and what the reader
    // refused is its structure. Only a file with no `!BDN` at all is called
    // not a PST (HUNT-063).
    let message = match StoreHeader::read(data) {
        Some(header) => {
            let why = if header.version == 23 {
                &unicode
            } else {
                &ansi
            };
            format!(
                "This is a {} store, format version {}: its signature and version were \
                 recognised, but this build's reader refused its structure ({why}). The store \
                 is not shown to be malformed, and none of it was read",
                header.client, header.version
            )
        }
        None => "Not a valid PST file".to_string(),
    };
    artifacts.push(make_parse_failed_artifact(
        case_id,
        parent_id,
        name,
        &message,
        IncompleteReason::UnresolvedStructure,
    ));
    artifacts
}

/// Add deleted-message recovery (ROADMAP §3.10) to what the version 14, 15 or
/// 23 reader produced. The recovered messages go in before the summary, which
/// is the last artifact, and the summary says what the scan covered. A store
/// the scan could not read is named on the summary, never passed over: no
/// recovery is not the same statement as nothing to recover.
fn with_recovery(
    mut artifacts: Vec<Artifact>,
    data: &[u8],
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
) -> Vec<Artifact> {
    let Some(mut summary) = artifacts
        .pop_if(|a| a.metadata.get("subtype").and_then(|v| v.as_str()) == Some("pst_summary"))
    else {
        return artifacts;
    };
    let version = u32::from(StoreHeader::read(data).map_or(0, |h| h.version));
    // Opened once: the scan of every block and both live B-tree walks are paid
    // for here, and the recovery runs over the same open store.
    let scanned = crate::pst512::Store::open(data).map(|store| {
        let paths = store.folder_paths();
        (crate::pst512::recover_store(&store), paths)
    });
    let meta = summary.metadata.as_object_mut();
    match (scanned, meta) {
        (Ok((rec, paths)), Some(meta)) => {
            let PublishedRecovery {
                recovered_messages,
                entries_without_data,
            } = publish_recovery(
                &rec,
                version,
                &|nid| paths.get(&nid).cloned(),
                case_id,
                parent_id,
                name,
                &mut artifacts,
            );
            let undecided = rec
                .messages
                .iter()
                .chain(&rec.fragments)
                .filter(|m| !m.could_be_live.is_empty())
                .count();
            let mut note = format!(
                "The bytes supplied were walked a second time with the allocation map ignored, \
                 for 512-byte B-tree pages and blocks that neither live B-tree references: {} \
                 such page(s) and {} such block(s) were found, giving {} deleted message(s) \
                 from node entries the live node B-tree no longer holds and {} message \
                 fragment(s) from property contexts no node entry names; {} node entr(y/ies) \
                 were found whose data was not; {} copy(ies) of messages the store still holds \
                 were counted, not listed. Each recovery is marked recovered from unallocated \
                 space. Attachments and the recipient table are read for versions 14, 15 and 23. A deletion that left \
                 no stale node entry behind is not found by this method.",
                rec.unreferenced_pages.len(),
                rec.unreferenced_blocks,
                rec.messages.len() - entries_without_data.len(),
                rec.fragments.len(),
                entries_without_data.len(),
                rec.superseded_copies + rec.copies_of_live.len(),
            );
            if undecided > 0 {
                note.push_str(&format!(
                    " {undecided} recovery(ies) are marked undecided rather than deleted: a live \
                     B-tree could not be read in full, so each may still be live."
                ));
            }
            if rec.capped {
                note.push_str(&format!(
                    " The recovery listing stopped at its cap of {} items.",
                    crate::ost4k::recover::MAX_RECOVERED
                ));
            }
            note_recovery_blind_spots(&rec, &mut note, meta);
            if version == 23 {
                note.push_str(
                    " The Unicode (version 23) layout is pinned on a real, empty store only; no \
                     Unicode message has been recovered from real evidence.",
                );
            }
            meta.insert("recovery_scanned_version".into(), json!(version));
            meta.insert(
                "recovered_messages".into(),
                json!(recovered_messages - rec.fragments.len()),
            );
            meta.insert("recovered_fragments".into(), json!(rec.fragments.len()));
            meta.insert(
                "recovered_entries_without_data".into(),
                json!(entries_without_data),
            );
            meta.insert(
                "recovered_copies_of_live".into(),
                json!(rec
                    .copies_of_live
                    .iter()
                    .map(|n| format!("{n:#x}"))
                    .collect::<Vec<_>>()),
            );
            meta.insert("superseded_copies".into(), json!(rec.superseded_copies));
            meta.insert(
                "unreferenced_pages".into(),
                json!(rec.unreferenced_pages.len()),
            );
            meta.insert("unreferenced_blocks".into(), json!(rec.unreferenced_blocks));
            meta.insert("blocks_found_by_scan".into(), json!(rec.blocks_found));
            meta.insert("recovery_capped".into(), json!(rec.capped));
            if rec.capped {
                mark_recovery_capped(meta);
            }
            let prior = meta
                .get("store_note")
                .and_then(|n| n.as_str())
                .map(|n| format!("{n} "))
                .unwrap_or_default();
            meta.insert("store_note".into(), json!(format!("{prior}{note}")));
            if recovered_messages > 0 {
                if let Some(n) = meta
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(str::to_string)
                {
                    meta.insert(
                        "name".into(),
                        json!(format!(
                            "{n}, {recovered_messages} recovered from unallocated space"
                        )),
                    );
                }
            }
        }
        (Err(e), Some(meta)) => {
            meta.insert("recovery_not_run".into(), json!(e.to_string()));
            meta.insert(
                "store_note".into(),
                json!(format!(
                    "{}This store was not scanned for deleted messages: {e}. Nothing is said \
                     about whether it holds any.",
                    meta.get("store_note")
                        .and_then(|n| n.as_str())
                        .map(|n| format!("{n} "))
                        .unwrap_or_default()
                )),
            );
        }
        (_, None) => {}
    }
    artifacts.push(summary);
    artifacts
}

/// The reader `outlook-pst` needs: seekable, and owning its bytes. The bytes
/// are copied once rather than spilled to a file in the shared temporary
/// directory, where another local user could read them and a killed process
/// would leave them behind.
fn pst_reader(data: &[u8]) -> Box<dyn outlook_pst::PstReader> {
    Box::new(std::io::Cursor::new(data.to_vec()))
}

/// Ask this crate's own reader for the live messages the linked reader refused (HUNT-281). The
/// linked reader needs a recipient table a message need not have; an Outlook 2000 "Welcome"
/// message has none, and the row used to be only counted. A message read here is published like
/// any other, says which reader read it, and lists its recipient table when it has one; one this reader
/// cannot open either stays counted as unreadable.
fn publish_refused_with_own_reader(
    data: &[u8],
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
    stats: &mut PstWalkStats,
    artifacts: &mut Vec<Artifact>,
) {
    if stats.unreadable_nodes.is_empty() {
        return;
    }
    let Ok(store) = crate::pst512::Store::open(data) else {
        return;
    };
    for (nid, path) in std::mem::take(&mut stats.unreadable_nodes) {
        let Ok(m) = store.read_live_message(nid) else {
            stats.unreadable_nodes.push((nid, path));
            continue;
        };
        let inventory = AttachmentInventory {
            count: m.attachments.len() + m.attachments_unreadable,
            items: m
                .attachments
                .iter()
                .map(|a| attachment_entry(a, declared_page_of(&m.props)))
                .collect(),
            incomplete: m.attachments_unreadable > 0 || !m.subnodes_read,
        };
        let mut extra = serde_json::Map::new();
        extra.insert("node_id".into(), json!(format!("{nid:#x}")));
        extra.insert("read_by".into(), json!("own_reader"));
        extra.insert(
            "read_by_note".into(),
            json!(
                "the linked reader refused this message, as it does one with no recipient table; \
                 this crate's own reader opened it"
            ),
        );
        insert_recipients(
            &mut extra,
            m.recipients.as_ref(),
            declared_page_of(&m.props),
        );
        let unreadable: Vec<_> = m
            .props_unreadable
            .iter()
            .map(|(tag, why)| json!({"tag": format!("{tag:#06x}"), "error": why}))
            .collect();
        if !unreadable.is_empty() {
            extra.insert("properties_unreadable".into(), json!(unreadable));
        }
        extract_message_artifacts(
            &m.props, case_id, parent_id, name, &path, inventory, &extra, artifacts,
        );
        stats.messages += 1;
        stats.messages_own_reader += 1;
        stats.messages_unreadable -= 1;
    }
}

/// Read `data` as a Unicode (version 23) store. `Err` says why the reader
/// refused it, so a store that was recognised is never reported as invalid.
fn try_unicode_pst(
    data: &[u8],
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
) -> Result<Vec<Artifact>, String> {
    let pst = outlook_pst::UnicodePstFile::read_from(pst_reader(data))
        .map_err(|e| format!("the Unicode reader could not open it: {e}"))?;
    let pst_rc = Rc::new(pst);
    let store = UnicodeStore::read(pst_rc).map_err(|e| {
        debug!("Failed to read Unicode store: {}", e);
        format!("the Unicode reader could not read the store's root structure: {e}")
    })?;

    let mut artifacts = Vec::new();
    let mut stats = PstWalkStats::default();

    // Get the IPM subtree root (main folder hierarchy). A store that opens and
    // whose hierarchy cannot be entered is a half-read store, not an empty
    // mailbox: the summary below says so rather than reporting zero messages
    // and claiming to be complete (B8-038).
    match store.properties().ipm_sub_tree_entry_id() {
        Ok(ipm_entry_id) => {
            // Open root folder and walk recursively
            match UnicodeFolder::read(store.clone(), &ipm_entry_id) {
                Ok(root_folder) => {
                    info!("Opened Unicode PST file: {}", name);
                    stats.enter_folder(u32::from(ipm_entry_id.node_id()));
                    walk_unicode_folder(
                        &root_folder,
                        &store,
                        case_id,
                        parent_id,
                        name,
                        "",
                        &mut artifacts,
                        &mut stats,
                        0,
                    );
                    info!(
                        "PST {} produced {} messages from {} folders",
                        name, stats.messages, stats.folders
                    );
                }
                Err(e) => {
                    debug!("Failed to open PST root folder: {}", e);
                    stats.root_unreachable = Some(format!(
                        "the store's root folder would not open ({e}), so no folder or message \
                         in it was examined"
                    ));
                }
            }
        }
        Err(e) => {
            debug!("Failed to get IPM subtree entry ID: {}", e);
            stats.root_unreachable = Some(format!(
                "the store's IPM subtree entry id could not be read ({e}), so its folder \
                 hierarchy was never entered"
            ));
        }
    }

    publish_refused_with_own_reader(data, case_id, parent_id, name, &mut stats, &mut artifacts);

    artifacts.push(make_summary_artifact(
        case_id, parent_id, name, "unicode", &stats,
    ));
    Ok(artifacts)
}

/// [`try_unicode_pst`] for an ANSI (version 14 or 15) store.
fn try_ansi_pst(
    data: &[u8],
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
) -> Result<Vec<Artifact>, String> {
    let pst = outlook_pst::AnsiPstFile::read_from(pst_reader(data))
        .map_err(|e| format!("the ANSI reader could not open it: {e}"))?;
    let pst_rc = Rc::new(pst);
    let store = AnsiStore::read(pst_rc).map_err(|e| {
        debug!("Failed to read ANSI store: {}", e);
        format!("the ANSI reader could not read the store's root structure: {e}")
    })?;

    let mut artifacts = Vec::new();
    let mut stats = PstWalkStats::default();

    // Same honesty as the Unicode path: an ANSI store that opens and whose
    // hierarchy cannot be entered must not summarise as an empty mailbox
    // (B8-038).
    match store.properties().ipm_sub_tree_entry_id() {
        Ok(ipm_entry_id) => match AnsiFolder::read(store.clone(), &ipm_entry_id) {
            Ok(root_folder) => {
                info!("Opened ANSI PST file: {}", name);
                stats.enter_folder(u32::from(ipm_entry_id.node_id()));
                let store_page = ansi_store_page(data, &mut stats);
                walk_ansi_folder(
                    &root_folder,
                    &store,
                    case_id,
                    parent_id,
                    name,
                    "",
                    &mut artifacts,
                    &mut stats,
                    store_page,
                    0,
                );
                info!(
                    "PST {} produced {} messages from {} folders",
                    name, stats.messages, stats.folders
                );
            }
            Err(e) => {
                debug!("Failed to open ANSI PST root folder: {}", e);
                stats.root_unreachable = Some(format!(
                    "the store's root folder would not open ({e}), so no folder or message in \
                     it was examined"
                ));
            }
        },
        Err(e) => {
            debug!("Failed to get ANSI IPM subtree entry ID: {}", e);
            stats.root_unreachable = Some(format!(
                "the store's IPM subtree entry id could not be read ({e}), so its folder \
                 hierarchy was never entered"
            ));
        }
    }

    publish_refused_with_own_reader(data, case_id, parent_id, name, &mut stats, &mut artifacts);

    artifacts.push(make_summary_artifact(
        case_id, parent_id, name, "ansi", &stats,
    ));
    Ok(artifacts)
}

/// Read an Outlook 2013-and-later store (format version 36) with this crate's
/// own reader, `crate::ost4k`, and emit the same records the other versions
/// produce, plus a summary that states how much of the node database was
/// reached: B-tree pages walked, every block in the block B-tree read and
/// CRC-checked (and inflated where compressed), and each page or block that
/// could not be — past the bytes supplied, all zeros, or damaged.
fn parse_ost4k(data: &[u8], case_id: Uuid, parent_id: Uuid, name: &str) -> Vec<Artifact> {
    use crate::ost4k::{block::read_block, mailbox::read_mailbox, ndb::Ndb};

    let ndb = match Ndb::open(data) {
        Ok(n) => n,
        Err(e) => {
            return vec![make_parse_failed_artifact(
                case_id,
                parent_id,
                name,
                &format!(
                    "This is a format version 36 (Outlook 2013 and later) store whose header \
                     could not be used: {e}. None of it was read"
                ),
                IncompleteReason::UnresolvedStructure,
            )];
        }
    };
    let h = &ndb.header;
    if h.crypt_method != 0 {
        return vec![make_parse_failed_artifact(
            case_id,
            parent_id,
            name,
            &format!(
                "This version 36 {} store is encoded (bCryptMethod {:#04x}), which this build's \
                 version-36 reader does not decode, so none of it was read; the store is not \
                 malformed",
                h.client, h.crypt_method
            ),
            IncompleteReason::UnresolvedStructure,
        )];
    }

    // Every block the block B-tree names, read once: CRC, trailer, and
    // inflation to the stated size.
    let mut blocks_verified = 0usize;
    let mut blocks_inflated = 0usize;
    let mut blocks_unwritten = 0usize;
    let mut block_faults = Vec::new();
    for e in &ndb.bbt.entries {
        match read_block(data, e) {
            Ok(_) => {
                blocks_verified += 1;
                if e.cb != e.cb_inflated {
                    blocks_inflated += 1;
                }
            }
            Err(f) => {
                if f.is_unwritten() {
                    blocks_unwritten += 1;
                }
                block_faults.push(f.to_string());
            }
        }
    }
    let page_faults: Vec<_> = ndb.nbt.faults.iter().chain(&ndb.bbt.faults).collect();
    let pages_unwritten = page_faults.iter().filter(|f| f.is_unwritten()).count();

    let mb = read_mailbox(&ndb);
    let folder_paths: std::collections::HashMap<u32, &str> = mb
        .folders
        .iter()
        .map(|f| (f.nid, f.path.as_str()))
        .collect();

    let mut artifacts = Vec::new();
    // Every folder is listed and counted: the folder cap belongs to the
    // table-driven walk, and only messages are cut off here, when more than the
    // cap are held (`messages_skipped`, below).
    let mut stats = PstWalkStats {
        folders: mb.folders.len(),
        folders_8bit_names: mb
            .folders
            .iter()
            .filter(|f| f.name_legacy_8bit)
            .map(|f| f.name.clone())
            .collect(),
        counted_whole: true,
        ..PstWalkStats::default()
    };
    // Counted here rather than in `stats`, whose sentences describe the
    // table-driven walk of the other versions.
    let unreadable_of = |t: u32| {
        mb.nodes_unreadable
            .iter()
            .filter(|(nid, _)| nid & 0x1F == t)
            .count()
    };
    let (folder_nodes_unreadable, message_nodes_unreadable) =
        (unreadable_of(0x02), unreadable_of(0x04));
    let mut messages_with_unreadable_properties = 0usize;
    for m in &mb.messages {
        if stats.messages >= MAX_PST_MESSAGES {
            break;
        }
        let path = folder_paths
            .get(&m.folder_nid)
            .map(|p| p.to_string())
            .unwrap_or_else(|| {
                format!("(parent node {:#x}, not a folder read here)", m.folder_nid)
            });
        let inventory = AttachmentInventory {
            count: m.attachments.len() + m.attachments_unreadable,
            items: m
                .attachments
                .iter()
                .map(|a| attachment_entry(a, declared_page_of(&m.props)))
                .collect(),
            incomplete: m.attachments_unreadable > 0,
        };
        let mut extra = serde_json::Map::new();
        extra.insert("store_version".into(), json!(36));
        extra.insert("node_id".into(), json!(format!("{:#x}", m.nid)));
        insert_recipients(
            &mut extra,
            m.recipients.as_ref(),
            declared_page_of(&m.props),
        );
        if let Some(why) = &m.recipients_error {
            extra.insert("recipients_error".into(), json!(why));
        }
        if !m.props_unreadable.is_empty() {
            messages_with_unreadable_properties += 1;
            extra.insert(
                "properties_unreadable".into(),
                json!(m
                    .props_unreadable
                    .iter()
                    .map(|(tag, why)| json!({"tag": format!("{tag:#06x}"), "error": why}))
                    .collect::<Vec<_>>()),
            );
        }
        extract_message_artifacts(
            &m.props,
            case_id,
            parent_id,
            name,
            &path,
            inventory,
            &extra,
            &mut artifacts,
        );
        stats.messages += 1;
    }
    stats.messages_skipped = mb.messages.len() - stats.messages;

    // Deleted-message recovery (ROADMAP §3.10): the same page and block reads
    // with the allocation map ignored. Each recovery is published as a message
    // record marked recovered from unallocated space, with its offsets and how
    // complete it is; node entries whose data was not found are named in the
    // summary.
    let rec = crate::ost4k::recover::recover(&ndb, &mb);
    let PublishedRecovery {
        recovered_messages,
        entries_without_data,
    } = publish_recovery(
        &rec,
        36,
        &|nid| folder_paths.get(&nid).map(|p| p.to_string()),
        case_id,
        parent_id,
        name,
        &mut artifacts,
    );

    // What each folder says it holds against what was found under it.
    let mut mismatches = Vec::new();
    let mut folders_short = 0usize;
    let mut per_folder: std::collections::HashMap<u32, i64> = std::collections::HashMap::new();
    for m in &mb.messages {
        *per_folder.entry(m.folder_nid).or_default() += 1;
    }
    for f in &mb.folders {
        let found = per_folder.get(&f.nid).copied().unwrap_or(0);
        if let Some(said) = f.content_count {
            if said != found {
                if found < said {
                    folders_short += 1;
                }
                mismatches.push(json!({
                    "folder": f.path, "content_count": said, "messages_found": found,
                }));
            }
        }
    }

    let mut summary = make_summary_artifact(case_id, parent_id, name, "ost_v36", &stats);
    let supplied = data.len() as u64;
    let mut note = format!(
        "Read by this build's own version-36 reader: {} of the node and block B-tree pages \
         walked, {blocks_verified} of {} blocks read with a matching CRC ({blocks_inflated} \
         inflated from zlib). Messages are the node B-tree's message nodes placed by their \
         parent folder; folder contents tables were not read. The bytes supplied were then \
         walked again with the allocation map ignored, for pages and blocks that neither \
         B-tree references: {} such B-tree page(s) and {} such block(s) were found, giving \
         {} deleted message(s) from node entries the live node B-tree no longer holds and \
         {} message fragment(s) from property contexts no node entry names; {} node \
         entr(y/ies) were found whose data was not; {} copy(ies) of messages the store still \
         holds were counted, not listed. Each recovery is marked recovered from \
         unallocated space, with its offsets and how complete it is. Anything past the \
         bytes supplied was not examined.",
        ndb.nbt.pages_walked + ndb.bbt.pages_walked,
        ndb.bbt.entries.len(),
        rec.unreferenced_pages.len(),
        rec.unreferenced_blocks,
        rec.messages.len() - entries_without_data.len(),
        rec.fragments.len(),
        entries_without_data.len(),
        rec.superseded_copies + rec.copies_of_live.len(),
    );
    if rec.associated_items > 0 {
        note.push_str(&format!(
            " {} unreferenced folder-associated item(s) (views, rules, configuration) were \
             counted, not listed as mail.",
            rec.associated_items
        ));
    }
    let undecided = rec
        .messages
        .iter()
        .chain(&rec.fragments)
        .filter(|m| !m.could_be_live.is_empty())
        .count();
    if undecided > 0 {
        note.push_str(&format!(
            " {undecided} recovery(ies) are marked undecided rather than deleted: the live \
             walk did not read every node, so each may still be live."
        ));
    }
    if rec.capped {
        note.push_str(&format!(
            " The recovery listing stopped at its cap of {} items; more may lie in the \
             unreferenced space.",
            crate::ost4k::recover::MAX_RECOVERED
        ));
    }
    if supplied < h.file_eof {
        note.push_str(&format!(
            " The {supplied} bytes supplied are shorter than the {} the header records \
             (ibFileEof); on a disk image that is typically a file whose tail was never \
             initialised. Any page or block the B-trees reference in the missing part is \
             named as a fault.",
            h.file_eof
        ));
    }
    let mut shortfalls: Vec<String> = Vec::new();
    if !page_faults.is_empty() {
        shortfalls.push(format!(
            "{} B-tree page(s) could not be walked ({pages_unwritten} not initialised on the \
             image or past the bytes supplied), and every node or block below them is missing \
             from this mailbox: {}",
            page_faults.len(),
            page_faults
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if !block_faults.is_empty() {
        shortfalls.push(format!(
            "{} block(s) named in the block B-tree could not be read ({blocks_unwritten} past \
             the bytes supplied or all zeros — not initialised on the image), and any folder, \
             message or property stored in them is missing",
            block_faults.len()
        ));
    }
    if message_nodes_unreadable + folder_nodes_unreadable > 0 {
        shortfalls.push(format!(
            "{message_nodes_unreadable} message node(s) and {folder_nodes_unreadable} folder \
             node(s) in the node B-tree could not be read: {}",
            mb.nodes_unreadable
                .iter()
                .take(20)
                .map(|(nid, why)| format!("node {nid:#x}: {why}"))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if messages_with_unreadable_properties > 0 {
        shortfalls.push(format!(
            "{messages_with_unreadable_properties} message(s) have properties whose values \
             could not be read"
        ));
    }
    if folders_short > 0 {
        shortfalls.push(format!(
            "{folders_short} folder(s) say they hold more messages than were found under them"
        ));
    }
    // A folder holding more message nodes than its PidTagContentCount says is
    // listed in `folder_count_mismatches` and stated here, but it does not mark
    // the summary incomplete: nothing is missing from what was read, the count
    // and the node B-tree simply disagree (a stale count, or messages the
    // contents table no longer lists). Only "fewer than said" is a shortfall.
    let folders_over = mismatches.len() - folders_short;
    if folders_over > 0 {
        note.push_str(&format!(
            " {folders_over} folder(s) hold more message nodes than their stored content \
             count says; every node found is listed, and which count is current was not \
             decided."
        ));
    }
    if let Some(meta) = summary.metadata.as_object_mut() {
        meta.insert("format".into(), json!("pst"));
        meta.insert("store_client".into(), json!(h.client));
        meta.insert("store_version".into(), json!(36));
        meta.insert("header_file_eof".into(), json!(h.file_eof));
        meta.insert("bytes_supplied".into(), json!(supplied));
        meta.insert(
            "btree_pages_walked".into(),
            json!(ndb.nbt.pages_walked + ndb.bbt.pages_walked),
        );
        meta.insert(
            "page_faults".into(),
            json!(page_faults
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()),
        );
        meta.insert("pages_unwritten".into(), json!(pages_unwritten));
        meta.insert("blocks_in_bbt".into(), json!(ndb.bbt.entries.len()));
        meta.insert("blocks_verified".into(), json!(blocks_verified));
        meta.insert("blocks_inflated".into(), json!(blocks_inflated));
        meta.insert("blocks_unwritten".into(), json!(blocks_unwritten));
        meta.insert(
            "messages_unreadable".into(),
            json!(message_nodes_unreadable),
        );
        meta.insert("folders_unreadable".into(), json!(folder_nodes_unreadable));
        meta.insert("block_faults".into(), json!(block_faults));
        meta.insert("folder_count_mismatches".into(), json!(mismatches));
        meta.insert(
            "messages_with_unreadable_properties".into(),
            json!(messages_with_unreadable_properties),
        );
        meta.insert(
            "recovered_messages".into(),
            json!(recovered_messages - rec.fragments.len()),
        );
        meta.insert("recovered_fragments".into(), json!(rec.fragments.len()));
        meta.insert(
            "recovered_entries_without_data".into(),
            json!(entries_without_data),
        );
        meta.insert(
            "recovered_copies_of_live".into(),
            json!(rec
                .copies_of_live
                .iter()
                .map(|n| format!("{n:#x}"))
                .collect::<Vec<_>>()),
        );
        meta.insert("superseded_copies".into(), json!(rec.superseded_copies));
        meta.insert(
            "unreferenced_pages".into(),
            json!(rec.unreferenced_pages.len()),
        );
        meta.insert("unreferenced_blocks".into(), json!(rec.unreferenced_blocks));
        meta.insert("blocks_found_by_scan".into(), json!(rec.blocks_found));
        meta.insert("recovery_capped".into(), json!(rec.capped));
        note_recovery_blind_spots(&rec, &mut note, meta);
        meta.insert("store_note".into(), json!(note));
        if !shortfalls.is_empty() {
            let prior = meta
                .get("message")
                .and_then(|m| m.as_str())
                .map(str::to_string);
            let mut all: Vec<String> = prior.into_iter().collect();
            all.extend(shortfalls);
            meta.insert("message".into(), json!(all.join("; ")));
            meta.insert("truncated".into(), json!(true));
            meta.insert("content_incomplete".into(), json!(true));
            let reason = ost4k_incomplete_reason(
                meta.get("content_incomplete_reason")
                    .and_then(|r| r.as_str()),
                pages_unwritten + blocks_unwritten > 0,
            );
            meta.insert("content_incomplete_reason".into(), json!(reason));
            meta.insert("inventory_incomplete".into(), json!(true));
        }
        // After the shortfalls, so a reason they set is the one that stays.
        if rec.capped {
            mark_recovery_capped(meta);
        }
        meta.insert(
            "name".into(),
            json!(format!(
                "{} (version 36): {} messages from {} folders{} ({name})",
                h.client,
                stats.messages,
                stats.folders,
                if recovered_messages > 0 {
                    format!(", {recovered_messages} recovered from unallocated space")
                } else {
                    String::new()
                }
            )),
        );
    }
    artifacts.push(summary);
    artifacts
}

/// Say, in the note and the metadata, what the scan of unallocated space
/// matched and could not read, so "nothing more was found" is never read off a
/// scan that was blind in places. Shared by every store layout.
fn note_recovery_blind_spots(
    rec: &crate::ost4k::recover::Recovery,
    note: &mut String,
    meta: &mut serde_json::Map<String, serde_json::Value>,
) {
    let offsets = |l: &crate::ost4k::recover::Listed<u64>| {
        json!({
            "count": l.count,
            "offsets": l.listed.iter().map(|o| format!("{o:#x}")).collect::<Vec<_>>(),
        })
    };
    meta.insert(
        "unreferenced_pages_unvalidated".into(),
        offsets(&rec.pages_unvalidated),
    );
    meta.insert(
        "unreferenced_blocks_unvalidated".into(),
        offsets(&rec.blocks_unvalidated),
    );
    meta.insert(
        "property_contexts_not_decoded".into(),
        json!({
            "count": rec.unread_contexts.count,
            "blocks": rec.unread_contexts.listed.iter().map(|u| json!({
                "block_id": format!("{:#x}", u.bid),
                "offset": format!("{:#x}", u.ib),
                "reason": u.reason,
            })).collect::<Vec<_>>(),
        }),
    );
    let (pages, blocks) = (rec.pages_unvalidated.count, rec.blocks_unvalidated.count);
    if pages + blocks > 0 {
        note.push_str(&format!(
            " {pages} page offset(s) and {blocks} block offset(s) carried a trailer whose \
             signature matched but whose CRC or metadata did not validate; a signature match \
             is a 16-bit check, so some are chance, but a damaged page or block is among them, \
             and nothing stored there was read."
        ));
    }
    if rec.unread_contexts.count > 0 {
        note.push_str(&format!(
            " {} unreferenced block(s) carry the property-context signature and did not \
             decode (damaged, or past the read budget); they may or may not have been \
             messages, and what they held was not recovered.",
            rec.unread_contexts.count
        ));
    }
}

/// Mark a summary whose recovery listing stopped at its cap: deleted messages
/// beyond it were not listed, so the store does not export as completely
/// recovered. The live inventory is not touched (`truncated` and
/// `inventory_incomplete` stay as they were), and a reason already on the
/// summary is kept, as it is the more specific one.
fn mark_recovery_capped(meta: &mut serde_json::Map<String, serde_json::Value>) {
    meta.insert("content_incomplete".into(), json!(true));
    meta.entry("content_incomplete_reason")
        .or_insert_with(|| json!(IncompleteReason::CapReached.as_str()));
    let said = format!(
        "the recovery listing stopped at its cap of {} items; more deleted messages may lie in \
         unreferenced space",
        crate::ost4k::recover::MAX_RECOVERED
    );
    let message = match meta.get("message").and_then(|m| m.as_str()) {
        Some(prior) => format!("{prior}; {said}"),
        None => said,
    };
    meta.insert("message".into(), json!(message));
}

/// What publishing a recovery produced, for the summary.
struct PublishedRecovery {
    recovered_messages: usize,
    entries_without_data: Vec<serde_json::Value>,
}

/// Publish each recovered message (deleted from a stale node entry, or a
/// fragment of an unreferenced block) as a message record marked recovered from
/// unallocated space, with its offsets and how complete it is. A node entry
/// whose data was not found is not published; it is returned to be named in the
/// summary. Shared by every store version, so a recovery reads the same
/// whichever layout it came from.
fn publish_recovery(
    rec: &crate::ost4k::recover::Recovery,
    store_version: u32,
    folder_path: &dyn Fn(u32) -> Option<String>,
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
    artifacts: &mut Vec<Artifact>,
) -> PublishedRecovery {
    let mut entries_without_data = Vec::new();
    let mut recovered_messages = 0usize;
    for m in rec.messages.iter().chain(&rec.fragments) {
        let node = |nid: u32| format!("{nid:#x}");
        if m.completeness == crate::ost4k::recover::Completeness::EntryOnly {
            entries_without_data.push(json!({
                "node_id": node(m.nid),
                "parent_node_id": node(m.parent_nid),
                "folder_path": folder_path(m.parent_nid),
                "data_bid": format!("{:#x}", m.bid_data),
                "nbt_page_offsets": recovery_page_offsets(m),
                "reason": m.gaps.join("; "),
            }));
            continue;
        }
        let fragment = m.source == crate::ost4k::recover::Source::UnreferencedBlock;
        let path = if fragment {
            "(unknown: no node entry was found for this message)".to_string()
        } else {
            folder_path(m.parent_nid).unwrap_or_else(|| {
                format!("(parent node {:#x}, not a folder read here)", m.parent_nid)
            })
        };
        let inventory = AttachmentInventory {
            count: m.attachments.len() + m.attachments_unreadable,
            items: m
                .attachments
                .iter()
                .map(|a| attachment_entry(a, declared_page_of(&m.props)))
                .collect(),
            // A fragment's attachments live in a subnode tree that was not found.
            incomplete: m.attachments_unreadable > 0 || fragment,
        };
        let mut extra = serde_json::Map::new();
        extra.insert("store_version".into(), json!(store_version));
        if !fragment {
            extra.insert("node_id".into(), json!(node(m.nid)));
        }
        extra.insert("recovered".into(), json!(true));
        extra.insert("allocation".into(), json!("unallocated"));
        extra.insert(
            "recovery_source".into(),
            json!(if fragment {
                "unreferenced_block"
            } else {
                "stale_node_entry"
            }),
        );
        extra.insert(
            "recovery_completeness".into(),
            json!(m.completeness.as_str()),
        );
        extra.insert("recovery_gaps".into(), json!(m.gaps));
        // Deleted only when the live walk was whole: otherwise the message may
        // be live under a node that walk did not reach, and the record says so.
        extra.insert(
            "deletion_status".into(),
            json!(if m.could_be_live.is_empty() {
                "deleted"
            } else {
                "undecided"
            }),
        );
        if !m.could_be_live.is_empty() {
            extra.insert("could_be_live".into(), json!(m.could_be_live));
        }
        extra.insert(
            "recovery_offsets".into(),
            json!({
                "nbt_pages": recovery_page_offsets(m),
                "data_block": m.data_block_offset,
                "subnode_block": m.subnode_block_offset,
            }),
        );
        extra.insert(
            "recovery_other_versions".into(),
            json!(m
                .other_versions
                .iter()
                .map(|v| json!({
                    "data_bid": format!("{:#x}", v.bid_data),
                    "nbt_pages": v.page_offsets,
                    "newer_than_recovered": v.newer,
                    "read_error": v.read_error,
                }))
                .collect::<Vec<_>>()),
        );
        insert_recipients(
            &mut extra,
            m.recipients.as_ref(),
            declared_page_of(&m.props),
        );
        if !m.props_unreadable.is_empty() {
            extra.insert(
                "properties_unreadable".into(),
                json!(m
                    .props_unreadable
                    .iter()
                    .map(|(tag, why)| json!({"tag": format!("{tag:#06x}"), "error": why}))
                    .collect::<Vec<_>>()),
            );
        }
        let before = artifacts.len();
        extract_message_artifacts(
            &m.props, case_id, parent_id, name, &path, inventory, &extra, artifacts,
        );
        for a in &mut artifacts[before..] {
            if let Some(meta) = a.metadata.as_object_mut() {
                meta.insert("recovered".into(), json!(true));
                meta.insert("allocation".into(), json!("unallocated"));
                if m.completeness == crate::ost4k::recover::Completeness::Partial
                    && meta.get("subtype").and_then(|v| v.as_str()) == Some("email_message")
                    && meta.get("content_incomplete").is_none()
                {
                    meta.insert("content_incomplete".into(), json!(true));
                    meta.insert(
                        "content_incomplete_reason".into(),
                        json!(IncompleteReason::UnresolvedStructure.as_str()),
                    );
                }
            }
        }
        recovered_messages += 1;
    }
    PublishedRecovery {
        recovered_messages,
        entries_without_data,
    }
}

/// The stale node B-tree page offsets a recovery was found in (none for a
/// fragment).
fn recovery_page_offsets(m: &crate::ost4k::recover::RecoveredMessage) -> Vec<u64> {
    match &m.source {
        crate::ost4k::recover::Source::StaleNodeEntry { page_offsets } => page_offsets.clone(),
        crate::ost4k::recover::Source::UnreferencedBlock => Vec::new(),
    }
}

/// The summary's `content_incomplete_reason` once the version-36 walk's own
/// shortfalls are added to what [`make_summary_artifact`] already set.
///
/// A cap that fired is kept: `cap_reached` tells the examiner the listing was
/// cut short on purpose, and a later short read must not overwrite that. When
/// no cap fired, bytes missing from the image (`unwritten`) are a short read;
/// anything else is a structure that could not be resolved.
fn ost4k_incomplete_reason(prior: Option<&str>, unwritten: bool) -> &'static str {
    let cap = IncompleteReason::CapReached.as_str();
    if prior == Some(cap) {
        cap
    } else if unwritten {
        IncompleteReason::ShortRead.as_str()
    } else {
        IncompleteReason::UnresolvedStructure.as_str()
    }
}

/// What one PST walk reached, and everything it did not.
///
/// Forensic meaning: `messages` and `folders` are what this tool recovered, not
/// what the store holds. Every other field is a way the walk fell short — a
/// subtree abandoned at the depth limit, a row whose message would not open —
/// and each one makes the absence of a message from the case something other
/// than evidence that the custodian never had it. Counting them is what lets
/// the summary say so; before this they were `debug!` and nothing else
/// (B5-023, B5-028).
#[derive(Debug, Default, Clone)]
struct PstWalkStats {
    /// Messages extracted.
    messages: usize,
    /// Folders entered.
    folders: usize,
    /// Subtrees abandoned at the nesting limit, each one a folder and
    /// everything below it.
    depth_limited: usize,
    /// Rows whose message would not open, even with the minimal-property
    /// fallback.
    messages_unreadable: usize,
    /// Rows whose message the linked reader refused: node id and folder path,
    /// so this crate's own reader can be asked for them (HUNT-281).
    unreadable_nodes: Vec<(u32, String)>,
    /// Of those, the ones this crate's own reader published.
    messages_own_reader: usize,
    /// Messages published from the minimal-property fallback after the full
    /// read failed: present, but with most of their properties unread.
    messages_partial: usize,
    /// Hierarchy rows that named a folder already entered (a hierarchy that
    /// points back at an ancestor, or names one folder twice), skipped so
    /// their messages are not published again.
    folder_cycles: usize,
    /// Node ids of the folders entered, so a folder is walked once.
    visited_folders: std::collections::HashSet<u32>,
    /// The counts are of everything the reader holds (the version-36 reader
    /// lists every node it found), so reaching a cap count is not itself
    /// evidence that the walk stopped: `messages_skipped` says what was left.
    counted_whole: bool,
    /// Messages found and not published because the message cap was reached
    /// (only where `counted_whole`).
    messages_skipped: usize,
    /// Rows whose EntryId could not be constructed, so nothing could be opened.
    entry_ids_unresolved: usize,
    /// Subfolders named in a hierarchy table that would not open.
    folders_unreadable: usize,
    /// Folders whose name was stored as 8-bit text that is not UTF-8 and was
    /// decoded in the assumed Windows-1252 (a folder declares no code page).
    /// The decoded names, so the summary can list them.
    folders_8bit_names: Vec<String>,
    /// The code page the store's folder names were read in when the sampled messages agreed on one.
    folders_8bit_codepage: Option<serde_json::Value>,
    /// The store opened but its folder hierarchy was never entered, and why.
    ///
    /// This is the difference between "we walked this mailbox and it held no
    /// mail" and "we recognised this mailbox and could not open it". Both used
    /// to produce a summary reading `message_count: 0` with no incompleteness,
    /// which is the second one dressed as the first (B8-038).
    root_unreachable: Option<String>,
}

impl PstWalkStats {
    /// Whether the message cap stopped the walk. The table-driven walk stops
    /// *at* the cap, so reaching it is the evidence; a walk whose counts are
    /// whole (version 36) has stopped only if messages were left over.
    fn messages_capped(&self) -> bool {
        if self.counted_whole {
            self.messages_skipped > 0
        } else {
            self.messages >= MAX_PST_MESSAGES
        }
    }

    /// Whether the folder cap stopped the walk. A walk whose counts are whole
    /// lists every folder, so the folder cap does not apply to it.
    fn folders_capped(&self) -> bool {
        !self.counted_whole && self.folders >= MAX_PST_FOLDERS
    }

    /// Record that folder `nid` is being entered; `false` when it was already,
    /// which is counted as a cycle and the folder is not walked again.
    fn enter_folder(&mut self, nid: u32) -> bool {
        let first = self.visited_folders.insert(nid);
        if !first {
            self.folder_cycles += 1;
        }
        first
    }

    /// Whether the walk stopped short of the store in any way.
    fn fell_short(&self) -> bool {
        self.messages_capped()
            || self.folders_capped()
            || self.depth_limited > 0
            || self.messages_unreadable > 0
            || self.messages_partial > 0
            || self.folder_cycles > 0
            || self.entry_ids_unresolved > 0
            || self.folders_unreadable > 0
            || self.root_unreachable.is_some()
    }
}

/// The properties read when a message's full read fails.
const MINIMAL_PROPS: [u16; 8] = [
    PID_TAG_SUBJECT,
    PID_TAG_SENDER_NAME,
    PID_TAG_SENDER_EMAIL,
    PID_TAG_SENDER_SMTP,
    PID_TAG_DISPLAY_TO,
    PID_TAG_CLIENT_SUBMIT_TIME,
    PID_TAG_CREATION_TIME,
    PID_TAG_MESSAGE_CLASS,
];

/// How a message was read.
enum MessageRead<T> {
    /// All its properties.
    Full(T),
    /// Only [`MINIMAL_PROPS`], because the full read failed with `error`.
    Minimal { message: T, error: String },
    /// Not even the minimal read opened it.
    Failed,
}

/// Read a message with all properties and, if that fails, with
/// [`MINIMAL_PROPS`]. `read` takes the property filter (`None` for all). One
/// function for both store layouts, so they cannot recover different messages.
fn read_with_fallback<T, E: std::fmt::Display>(
    path: &str,
    read: impl Fn(Option<&[u16]>) -> Result<T, E>,
) -> MessageRead<T> {
    match read(None) {
        Ok(message) => MessageRead::Full(message),
        Err(e) => {
            debug!("Failed to read message in '{}': {}", path, e);
            match read(Some(&MINIMAL_PROPS)) {
                Ok(message) => MessageRead::Minimal {
                    message,
                    error: e.to_string(),
                },
                Err(_) => MessageRead::Failed,
            }
        }
    }
}

/// The metadata a message read from [`MINIMAL_PROPS`] carries, so that it is
/// published as incomplete and says why: `properties_unreadable` is what
/// [`extract_message_artifacts`] turns into `content_incomplete`.
fn partial_read_extra(error: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut extra = serde_json::Map::new();
    extra.insert("read_fallback".into(), json!(true));
    extra.insert("read_fallback_error".into(), json!(error));
    extra.insert(
        "properties_unreadable".into(),
        json!([{
            "tag": "all properties outside the minimal set",
            "error": format!(
                "the full read failed ({error}); only {} properties were read: {}",
                MINIMAL_PROPS.len(),
                MINIMAL_PROPS
                    .iter()
                    .map(|t| format!("{t:#06x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }]),
    );
    extra
}

// --- Unicode folder walking ---

fn walk_unicode_folder(
    folder: &Rc<UnicodeFolder>,
    store: &Rc<UnicodeStore>,
    case_id: Uuid,
    parent_id: Uuid,
    pst_name: &str,
    folder_path: &str,
    artifacts: &mut Vec<Artifact>,
    stats: &mut PstWalkStats,
    depth: usize,
) {
    // The depth limit is counted, not merely obeyed: a subtree abandoned here
    // is folders and messages that were never looked at, and a summary that
    // does not say so presents the rest as the whole mailbox (B5-023).
    if depth > 32 {
        stats.depth_limited += 1;
        return;
    }
    if stats.folders >= MAX_PST_FOLDERS || stats.messages >= MAX_PST_MESSAGES {
        return;
    }

    let folder_name = folder
        .properties()
        .display_name()
        .unwrap_or_else(|_| format!("Folder_{}", stats.folders));
    let current_path = if folder_path.is_empty() {
        folder_name.clone()
    } else {
        format!("{}/{}", folder_path, folder_name)
    };

    stats.folders += 1;

    // Process messages in this folder's contents table
    if let Some(contents) = folder.contents_table() {
        for row in contents.rows_matrix() {
            if stats.messages >= MAX_PST_MESSAGES {
                break;
            }

            // Get the row's NID to construct an EntryId for the message
            let msg_node_id = row.id();
            let entry_id = match store
                .properties()
                .make_entry_id(NodeId::from(u32::from(msg_node_id)))
            {
                Ok(eid) => eid,
                Err(_) => {
                    stats.entry_ids_unresolved += 1;
                    continue;
                }
            };

            // Read the message with all properties, falling back to a minimal
            // set; a message read that way is published but marked partial.
            let (msg, extra, partial) = match read_with_fallback(&current_path, |props| {
                UnicodeMessage::read(store.clone(), &entry_id, props)
            }) {
                MessageRead::Full(msg) => (msg, serde_json::Map::new(), false),
                MessageRead::Minimal { message, error } => {
                    (message, partial_read_extra(&error), true)
                }
                // The row is in the folder's contents table, so the message
                // existed. Counting it is the difference between "this mailbox
                // held 400 messages" and "400 is what we could read of it"
                // (B5-028).
                MessageRead::Failed => {
                    stats.messages_unreadable += 1;
                    stats
                        .unreadable_nodes
                        .push((u32::from(msg_node_id), current_path.clone()));
                    continue;
                }
            };
            let attachments = unicode_attachments(&msg);
            extract_message_artifacts(
                msg.properties(),
                case_id,
                parent_id,
                pst_name,
                &current_path,
                attachments,
                &extra,
                artifacts,
            );
            stats.messages += 1;
            stats.messages_partial += usize::from(partial);
        }
    }

    // Recurse into subfolders via hierarchy table
    if let Some(hier) = folder.hierarchy_table() {
        // Each row in the hierarchy table represents a subfolder
        // The row's NID corresponds to the folder node
        for row in hier.rows_matrix() {
            if stats.folders >= MAX_PST_FOLDERS || stats.messages >= MAX_PST_MESSAGES {
                break;
            }

            let sub_node_id = row.id();
            let sub_entry_id = match store
                .properties()
                .make_entry_id(NodeId::from(u32::from(sub_node_id)))
            {
                Ok(eid) => eid,
                Err(_) => {
                    stats.entry_ids_unresolved += 1;
                    continue;
                }
            };

            // A folder already entered is not entered again: a hierarchy that
            // points back at an ancestor would publish its messages once per
            // pass, and the copies would read as distinct evidence.
            if !stats.enter_folder(u32::from(sub_node_id)) {
                continue;
            }

            match UnicodeFolder::read(store.clone(), &sub_entry_id) {
                Ok(sub_folder) => {
                    walk_unicode_folder(
                        &sub_folder,
                        store,
                        case_id,
                        parent_id,
                        pst_name,
                        &current_path,
                        artifacts,
                        stats,
                        depth + 1,
                    );
                }
                Err(e) => {
                    debug!("Failed to open subfolder (NID {:?}): {}", sub_node_id, e);
                    stats.folders_unreadable += 1;
                }
            }
        }
    }
}

// --- ANSI folder walking ---

/// Messages sampled to choose a code page for the folder names of an ANSI store, at most.
const PAGE_SAMPLE_MESSAGES: usize = 64;

/// A code page for the 8-bit folder names of an ANSI store (`HUNT-281`). A folder declares none, so the
/// pages its messages declare or imply are sampled with this crate's own reader (the linked one refuses
/// a message with no recipient table): up to [`PAGE_SAMPLE_MESSAGES`] live messages spread over the node
/// B-tree. One page is taken only if every sampled message that names one names the same, and a name
/// that page cannot decode is read in Windows-1252 as before ([`decode_string8`]). The sample is
/// recorded on the summary.
fn ansi_store_page(data: &[u8], stats: &mut PstWalkStats) -> Option<Page> {
    let store = crate::pst512::Store::open(data).ok()?;
    let nodes = store.live_message_nodes();
    let step = nodes.len().div_ceil(PAGE_SAMPLE_MESSAGES).max(1);
    let mut sampled = 0usize;
    let mut votes: Vec<Page> = Vec::new();
    for nid in nodes.iter().step_by(step) {
        let Ok(pc) = store.read_live_pc(*nid) else {
            continue;
        };
        sampled += 1;
        votes.extend(declared_page_of(&pc.props));
    }
    let first = votes.first()?;
    if votes.iter().any(|v| v.codepage != first.codepage) {
        return None;
    }
    stats.folders_8bit_codepage = Some(json!({
        "codepage": first.codepage,
        "basis": PageBasis::StoreMessages.as_str(),
        "messages_sampled": sampled,
        "messages_naming_it": votes.len(),
        "note": "a folder declares no code page; the sampled messages of the store agree on this one, \
                 which is an inference, and a name it cannot decode is read in Windows-1252",
    }));
    Some(Page {
        codepage: first.codepage,
        basis: PageBasis::StoreMessages,
    })
}

fn walk_ansi_folder(
    folder: &Rc<AnsiFolder>,
    store: &Rc<AnsiStore>,
    case_id: Uuid,
    parent_id: Uuid,
    pst_name: &str,
    folder_path: &str,
    artifacts: &mut Vec<Artifact>,
    stats: &mut PstWalkStats,
    store_page: Option<Page>,
    depth: usize,
) {
    // The depth limit is counted, not merely obeyed: a subtree abandoned here
    // is folders and messages that were never looked at, and a summary that
    // does not say so presents the rest as the whole mailbox (B5-023).
    if depth > 32 {
        stats.depth_limited += 1;
        return;
    }
    if stats.folders >= MAX_PST_FOLDERS || stats.messages >= MAX_PST_MESSAGES {
        return;
    }

    // The linked reader's `display_name()` widens each 8-bit byte to the
    // code point of the same value; the stored bytes are decoded here instead.
    let folder_name = match folder.properties().get(PID_TAG_DISPLAY_NAME) {
        Some(PropertyValue::String8(s)) => {
            let d = decode_string8(s.buffer(), store_page);
            if d.legacy.is_some() {
                stats.folders_8bit_names.push(d.text.clone());
            }
            d.text
        }
        _ => folder
            .properties()
            .display_name()
            .unwrap_or_else(|_| format!("Folder_{}", stats.folders)),
    };
    let current_path = if folder_path.is_empty() {
        folder_name.clone()
    } else {
        format!("{}/{}", folder_path, folder_name)
    };

    stats.folders += 1;

    // Process messages
    if let Some(contents) = folder.contents_table() {
        for row in contents.rows_matrix() {
            if stats.messages >= MAX_PST_MESSAGES {
                break;
            }

            let msg_node_id = row.id();
            let entry_id = match store
                .properties()
                .make_entry_id(NodeId::from(u32::from(msg_node_id)))
            {
                Ok(eid) => eid,
                Err(_) => {
                    stats.entry_ids_unresolved += 1;
                    continue;
                }
            };

            let (msg, extra, partial) = match read_with_fallback(&current_path, |props| {
                AnsiMessage::read(store.clone(), &entry_id, props)
            }) {
                MessageRead::Full(msg) => (msg, serde_json::Map::new(), false),
                MessageRead::Minimal { message, error } => {
                    (message, partial_read_extra(&error), true)
                }
                MessageRead::Failed => {
                    stats.messages_unreadable += 1;
                    stats
                        .unreadable_nodes
                        .push((u32::from(msg_node_id), current_path.clone()));
                    continue;
                }
            };
            let attachments = ansi_attachments(&msg);
            extract_message_artifacts(
                msg.properties(),
                case_id,
                parent_id,
                pst_name,
                &current_path,
                attachments,
                &extra,
                artifacts,
            );
            stats.messages += 1;
            stats.messages_partial += usize::from(partial);
        }
    }

    // Recurse into subfolders
    if let Some(hier) = folder.hierarchy_table() {
        for row in hier.rows_matrix() {
            if stats.folders >= MAX_PST_FOLDERS || stats.messages >= MAX_PST_MESSAGES {
                break;
            }

            let sub_node_id = row.id();
            let sub_entry_id = match store
                .properties()
                .make_entry_id(NodeId::from(u32::from(sub_node_id)))
            {
                Ok(eid) => eid,
                Err(_) => {
                    stats.entry_ids_unresolved += 1;
                    continue;
                }
            };

            if !stats.enter_folder(u32::from(sub_node_id)) {
                continue;
            }

            match AnsiFolder::read(store.clone(), &sub_entry_id) {
                Ok(sub_folder) => {
                    walk_ansi_folder(
                        &sub_folder,
                        store,
                        case_id,
                        parent_id,
                        pst_name,
                        &current_path,
                        artifacts,
                        stats,
                        store_page,
                        depth + 1,
                    );
                }
                Err(e) => {
                    debug!("Failed to open ANSI subfolder: {}", e);
                    stats.folders_unreadable += 1;
                }
            }
        }
    }
}

// --- Shared message extraction ---

/// One message's or attachment's properties, whichever reader produced them:
/// the linked `outlook-pst` reader (versions 14, 15, 23) or this crate's own
/// version-36 reader. Every record is built by the one extractor below, so the
/// two paths cannot publish different fields for the same property.
trait Props {
    /// A text property. 8-bit text that is not UTF-8 is decoded in the code
    /// page `page` names, else the one this object declares itself, else
    /// Windows-1252. An attachment declares none of its own, so its caller
    /// passes the message's.
    fn string_in(&self, id: u16, page: Option<Page>) -> Option<String>;
    fn string(&self, id: u16) -> Option<String> {
        self.string_in(id, None)
    }
    fn instant(&self, id: u16) -> Option<(String, i64)>;
    fn int(&self, id: u16) -> Option<i64>;
    fn boolean(&self, id: u16) -> Option<bool>;
    fn bytes(&self, id: u16) -> Option<Vec<u8>>;
    /// Tags whose 8-bit text was not valid UTF-8 and so was decoded in a legacy
    /// code page rather than read as stored, and the code page used.
    fn legacy_8bit_text_in(&self, _page: Option<Page>) -> Option<LegacyText> {
        None
    }
    fn legacy_8bit_text(&self) -> Option<LegacyText> {
        self.legacy_8bit_text_in(None)
    }
}

/// How the code page of a message's 8-bit text was chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PageBasis {
    /// The message names it (`PidTagMessageCodepage`).
    Declared,
    /// The message names the locale it was written in (`PidTagMessageLocaleId`), and that locale's ANSI
    /// code page is taken. An inference, not a statement of the message.
    MessageLocaleId,
    /// The message names its transport code page (`PidTagInternetCodepage`) and the single-byte or
    /// double-byte Windows page it stands for is taken. An inference.
    InternetCodepage,
    /// The sampled messages of the store agree on one page and a folder name is read in it.
    StoreMessages,
}

impl PageBasis {
    fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::MessageLocaleId => "message_locale_id",
            Self::InternetCodepage => "internet_codepage",
            Self::StoreMessages => "store_messages",
        }
    }
}

/// A code page for 8-bit text and how it was chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Page {
    codepage: i64,
    basis: PageBasis,
}

/// The Windows ANSI code page a locale id (LCID) writes in, for the languages whose ANSI page is not
/// Windows-1252. `None` for Western locales and any locale not listed: nothing is then inferred.
fn ansi_codepage_of_locale(lcid: i64) -> Option<i64> {
    let primary = lcid & 0x3FF;
    Some(match lcid {
        0x0804 | 0x1004 => 936,
        0x0404 | 0x0C04 | 0x1404 => 950,
        _ => match primary {
            0x11 => 932,
            0x04 => 936,
            0x12 => 949,
            0x1E => 874,
            // Cyrillic: Russian, Ukrainian, Belarusian, Bulgarian, Macedonian, Serbian, Kazakh, Tatar, Mongolian.
            0x19 | 0x22 | 0x23 | 0x02 | 0x2F | 0x1A | 0x3F | 0x44 | 0x50 => 1251,
            0x08 => 1253,
            0x1F => 1254,
            0x0D => 1255,
            0x01 => 1256,
            0x25..=0x27 => 1257,
            0x2A => 1258,
            // Czech, Hungarian, Polish, Romanian, Croatian/Serbian Latin, Slovak, Slovenian, Albanian.
            0x05 | 0x0E | 0x15 | 0x18 | 0x1B | 0x24 | 0x1C => 1250,
            _ => return None,
        },
    })
}

/// The Windows ANSI code page an Internet code page stands for: a Windows page as itself, and the
/// East Asian transport encodings as the page their text is stored in on a Windows machine.
fn ansi_codepage_of_internet(cpid: i64) -> Option<i64> {
    Some(match cpid {
        874 | 932 | 936 | 949 | 950 | 1250..=1258 => cpid,
        // ISO-2022-JP (three variants), EUC-JP.
        50220..=50222 | 51932 | 20932 => 932,
        // HZ-GB-2312, GB 2312, GB 18030.
        52936 | 20936 | 54936 => 936,
        // ISO-2022-KR, EUC-KR.
        50225 | 51949 => 949,
        _ => return None,
    })
}

/// The code page of a message's 8-bit text from the values of its properties: the one it declares, else
/// the non-Western page its locale or its transport code page implies. A page this build cannot decode
/// is not offered.
fn page_from(get: impl Fn(u16) -> Option<i64>) -> Option<Page> {
    if let Some(codepage) = get(PID_TAG_MESSAGE_CODEPAGE) {
        return Some(Page {
            codepage,
            basis: PageBasis::Declared,
        });
    }
    let candidates = [
        get(PID_TAG_MESSAGE_LOCALE_ID)
            .and_then(ansi_codepage_of_locale)
            .map(|c| (c, PageBasis::MessageLocaleId)),
        get(PID_TAG_INTERNET_CODEPAGE)
            .and_then(ansi_codepage_of_internet)
            .map(|c| (c, PageBasis::InternetCodepage)),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|(codepage, _)| encoding_for_codepage(*codepage).is_some())
        .map(|(codepage, basis)| Page { codepage, basis })
}

/// Which text properties were decoded in a legacy code page, and which one.
struct LegacyText {
    tags: Vec<u16>,
    codepage: &'static encoding_rs::Encoding,
    /// How the page was chosen; `None` is the assumed Windows-1252.
    basis: Option<PageBasis>,
    /// Some byte could not be mapped in the code page and was replaced.
    lossy: bool,
}

/// How one 8-bit string was decoded when it was not valid UTF-8.
struct Legacy8 {
    codepage: &'static encoding_rs::Encoding,
    basis: Option<PageBasis>,
    lossy: bool,
}

struct Decoded8 {
    text: String,
    /// `None` when the bytes were valid UTF-8 and were read as stored.
    legacy: Option<Legacy8>,
}

/// The encoding of 8-bit text under a page: that page when this build can decode it, else the assumed
/// default (and `None`).
fn encoding_for_page(page: Option<Page>) -> (&'static encoding_rs::Encoding, Option<PageBasis>) {
    match page.and_then(|p| encoding_for_codepage(p.codepage).map(|e| (e, p.basis))) {
        Some((e, basis)) => (e, Some(basis)),
        None => (
            encoding_for_codepage(ASSUMED_8BIT_CODEPAGE).unwrap_or(encoding_rs::WINDOWS_1252),
            None,
        ),
    }
}

/// The one rule for a PtypString8 value, shared by the linked reader's stores
/// (versions 14, 15, 23) and this crate's own version-36 reader: valid UTF-8 is
/// read as stored; anything else is decoded in the declared code page, else in the page the message's
/// locale implies, else Windows-1252, and says so. A page that was only inferred and cannot decode the
/// bytes (it replaces one) is not taken: Windows-1252 is assumed instead. Trailing NULs are dropped.
fn decode_string8(bytes: &[u8], page: Option<Page>) -> Decoded8 {
    let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    let bytes = &bytes[..end];
    if let Ok(t) = std::str::from_utf8(bytes) {
        return Decoded8 {
            text: t.to_string(),
            legacy: None,
        };
    }
    let (mut codepage, mut basis) = encoding_for_page(page);
    let (mut text, _, mut lossy) = codepage.decode(bytes);
    if lossy && basis.is_some_and(|b| b != PageBasis::Declared) {
        (codepage, basis) = encoding_for_page(None);
        (text, _, lossy) = codepage.decode(bytes);
    }
    Decoded8 {
        text: text.into_owned(),
        legacy: Some(Legacy8 {
            codepage,
            basis,
            lossy,
        }),
    }
}

impl LegacyText {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "tags": self.tags.iter().map(|t| format!("{t:#06x}")).collect::<Vec<_>>(),
            "codepage": self.codepage.name().to_ascii_lowercase(),
            "codepage_declared": self.basis == Some(PageBasis::Declared),
            "codepage_basis": self.basis.map_or("assumed", PageBasis::as_str),
            "decoding_lossy": self.lossy,
            "note": match self.basis {
                Some(PageBasis::Declared) => "these text properties were stored as 8-bit text in the message's own code page \
                 and are decoded in it",
                Some(PageBasis::MessageLocaleId) => "these text properties were stored as 8-bit text and the message declares no \
                 code page; the page is the one its locale (PidTagMessageLocaleId) writes in, an inference, \
                 and a message written elsewhere would read differently",
                Some(PageBasis::InternetCodepage) => "these text properties were stored as 8-bit text and the message declares no \
                 code page; the page is the one its Internet code page (PidTagInternetCodepage) stands for, \
                 an inference, and a message written elsewhere would read differently",
                Some(PageBasis::StoreMessages) => "these text properties were stored as 8-bit text and the page is the one the \
                 store's sampled messages agree on, an inference",
                None => "these text properties were stored as 8-bit text and the message declares no \
                 code page, so Windows-1252 is assumed; another code page would read some \
                 characters differently",
            },
        })
    }
}

macro_rules! props_via_get {
    ($t:ty) => {
        impl Props for $t {
            fn string_in(&self, id: u16, page: Option<Page>) -> Option<String> {
                match self.get(id) {
                    Some(PropertyValue::String8(s)) => {
                        Some(decode_string8(s.buffer(), self.page_or_own(page)).text)
                    }
                    other => prop_to_string(other),
                }
            }
            fn legacy_8bit_text_in(&self, page: Option<Page>) -> Option<LegacyText> {
                let page = self.page_or_own(page);
                let mut tags = Vec::new();
                let mut lossy = false;
                let mut decoded_in = None;
                for (tag, v) in self.iter() {
                    if let PropertyValue::String8(s) = v {
                        if let Some(l) = decode_string8(s.buffer(), page).legacy {
                            tags.push(*tag);
                            lossy |= l.lossy;
                            decoded_in.get_or_insert((l.codepage, l.basis));
                        }
                    }
                }
                let (codepage, basis) = decoded_in?;
                tags.sort_unstable();
                Some(LegacyText {
                    tags,
                    codepage,
                    basis,
                    lossy,
                })
            }
            fn instant(&self, id: u16) -> Option<(String, i64)> {
                prop_to_instant(self.get(id))
            }
            fn int(&self, id: u16) -> Option<i64> {
                prop_to_i64(self.get(id))
            }
            fn boolean(&self, id: u16) -> Option<bool> {
                prop_to_bool(self.get(id))
            }
            fn bytes(&self, id: u16) -> Option<Vec<u8>> {
                match self.get(id) {
                    Some(PropertyValue::Binary(b)) => Some(b.buffer().to_vec()),
                    _ => None,
                }
            }
        }
    };
}

/// The code page an object's 8-bit text is read in: the one passed, else the
/// one the object itself names or implies (an attachment has none).
trait PageOrOwn {
    fn page_or_own(&self, page: Option<Page>) -> Option<Page>;
}
macro_rules! page_or_own {
    ($t:ty) => {
        impl PageOrOwn for $t {
            fn page_or_own(&self, page: Option<Page>) -> Option<Page> {
                page.or_else(|| page_from(|id| prop_to_i64(self.get(id))))
            }
        }
    };
}
page_or_own!(outlook_pst::messaging::message::MessageProperties);
page_or_own!(AttachmentProperties);
props_via_get!(outlook_pst::messaging::message::MessageProperties);
props_via_get!(AttachmentProperties);

/// The code page of a message read by this crate's own reader for its 8-bit text: the one it declares,
/// else the one its locale or transport code page implies.
fn declared_page_of(props: &std::collections::BTreeMap<u16, Ost4kValue>) -> Option<Page> {
    page_from(|id| props.int(id))
}

impl Props for std::collections::BTreeMap<u16, Ost4kValue> {
    fn string_in(&self, id: u16, page: Option<Page>) -> Option<String> {
        match self.get(&id)? {
            Ost4kValue::Str(s) => Some(s.clone()),
            Ost4kValue::Other { ptype: 0x001E, raw } => {
                Some(decode_string8(raw, page.or_else(|| declared_page_of(self))).text)
            }
            _ => None,
        }
    }
    fn legacy_8bit_text_in(&self, page: Option<Page>) -> Option<LegacyText> {
        let page = page.or_else(|| declared_page_of(self));
        let mut tags = Vec::new();
        let mut lossy = false;
        let mut decoded_in = None;
        for (t, v) in self {
            if let Ost4kValue::Other { ptype: 0x001E, raw } = v {
                if let Some(l) = decode_string8(raw, page).legacy {
                    tags.push(*t);
                    lossy |= l.lossy;
                    decoded_in.get_or_insert((l.codepage, l.basis));
                }
            }
        }
        let (codepage, basis) = decoded_in?;
        Some(LegacyText {
            tags,
            codepage,
            basis,
            lossy,
        })
    }
    fn instant(&self, id: u16) -> Option<(String, i64)> {
        match self.get(&id)? {
            Ost4kValue::Time(t) => filetime_instant(*t),
            _ => None,
        }
    }
    fn int(&self, id: u16) -> Option<i64> {
        match self.get(&id)? {
            Ost4kValue::I16(v) => Some(i64::from(*v)),
            Ost4kValue::I32(v) => Some(i64::from(*v)),
            Ost4kValue::I64(v) => Some(*v),
            _ => None,
        }
    }
    fn boolean(&self, id: u16) -> Option<bool> {
        match self.get(&id)? {
            Ost4kValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    fn bytes(&self, id: u16) -> Option<Vec<u8>> {
        match self.get(&id)? {
            Ost4kValue::Bin(b) => Some(b.clone()),
            _ => None,
        }
    }
}

fn extract_message_artifacts(
    props: &dyn Props,
    case_id: Uuid,
    parent_id: Uuid,
    pst_name: &str,
    folder_path: &str,
    attachments: AttachmentInventory,
    extra: &serde_json::Map<String, serde_json::Value>,
    artifacts: &mut Vec<Artifact>,
) {
    let subject = normalise_subject(&props.string(PID_TAG_SUBJECT).unwrap_or_default());
    // One principal supplies both the name and the address: the sender when it
    // has a usable address, else the party it sent on behalf of. Mixing the two
    // published a delegate's name over the principal's address.
    let (principal, on_behalf) = pick_sender(
        Party::new(
            props.string(PID_TAG_SENDER_NAME),
            props.string(PID_TAG_SENDER_SMTP),
            props.string(PID_TAG_SENDER_EMAIL),
        ),
        Party::new(
            props.string(PID_TAG_SENT_REPRESENTING_NAME),
            props.string(PID_TAG_SENT_REPRESENTING_SMTP),
            props.string(PID_TAG_SENT_REPRESENTING_EMAIL),
        ),
    );
    let sender_name = principal.name.clone();
    let sender_email = principal.email();
    let display_to = props.string(PID_TAG_DISPLAY_TO).unwrap_or_default();
    let display_cc = props.string(PID_TAG_DISPLAY_CC).unwrap_or_default();
    let display_bcc = props.string(PID_TAG_DISPLAY_BCC).unwrap_or_default();
    // The plain-text body where the store holds one. Exchange-synchronised
    // stores often hold only the HTML body (most messages NIST's Data Leakage
    // key lists do; "RE: Watch out!" holds only a plain body), so the text is
    // then rendered from the HTML and `body_source` says which it was. The
    // compressed-RTF body (PidTagRtfCompressed) is not decoded: a message that
    // holds only that body says `rtf_not_decoded` and is marked incomplete
    // (`compressed`), because its body is present and was not read — never
    // `none`, which is kept for a message that holds no body property at all.
    let html = html_body(props);
    let raw_html = html.text;
    let (body_text, body_source) = match props.string(PID_TAG_BODY) {
        Some(t) if !t.is_empty() => (t, "text"),
        _ if !raw_html.is_empty() => (mail_parser::decoders::html::html_to_text(&raw_html), "html"),
        _ if props.bytes(PID_TAG_RTF_COMPRESSED).is_some() => (String::new(), "rtf_not_decoded"),
        _ => (String::new(), "none"),
    };
    let message_class = props.string(PID_TAG_MESSAGE_CLASS).unwrap_or_default();

    let to: Vec<String> = parse_display_list(&display_to);
    let cc: Vec<String> = parse_display_list(&display_cc);
    let bcc: Vec<String> = parse_display_list(&display_bcc);

    // One walk for both fields, so the string and the integer always name the
    // same instant read from the same property.
    let instant = props
        .instant(PID_TAG_CLIENT_SUBMIT_TIME)
        .or_else(|| props.instant(PID_TAG_MESSAGE_DELIVERY_TIME))
        .or_else(|| props.instant(PID_TAG_CREATION_TIME));
    let date_str = instant
        .as_ref()
        .map(|(text, _)| text.clone())
        .unwrap_or_default();
    let date_epoch = instant.as_ref().map(|(_, secs)| *secs);

    let has_attachments = props.boolean(PID_TAG_HAS_ATTACHMENTS).unwrap_or(false);

    let message_id = props
        .string(PID_TAG_INTERNET_MESSAGE_ID)
        .unwrap_or_default();
    let in_reply_to = props.string(PID_TAG_IN_REPLY_TO_ID).unwrap_or_default();
    // One string in the store; the header's own form is a whitespace-separated
    // list of angle-bracketed ids.
    let references: Vec<String> = props
        .string(PID_TAG_INTERNET_REFERENCES)
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();

    let body_truncated =
        is_truncated(&body_text, MAX_BODY_SIZE) || is_truncated(&raw_html, MAX_BODY_SIZE);
    let mut metadata = json!({
        "type": "EmailMessage",
        "analysis_type": "email",
        "subtype": "email_message",
        "format": "pst",
        "from": sender_email,
        "from_name": sender_name,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "subject": subject,
        "date": date_str,
        // Unix seconds beside the RFC 3339 string; see the eml reader for why.
        "date_epoch": date_epoch,
        "message_id": message_id,
        "in_reply_to": in_reply_to,
        "references": references,
        "body_text": truncate_str(&body_text, MAX_BODY_SIZE),
        // Structured honesty: the `...[truncated]` sentinel inside the text is
        // prose that search/export/UI do not read (B2-105).
        // True when either body was cut: a clipped HTML body is as incomplete as
        // a clipped plain one, and the sibling formats say so the same way.
        "body_truncated": body_truncated,
        "body_html": truncate_str(&raw_html, MAX_BODY_SIZE),
        // The code page the HTML body's bytes were decoded with (null when the
        // message names none), and whether decoding replaced bytes it could not
        // map: the text is then not the evidence's own.
        "body_html_codepage": html.codepage,
        "body_decoding_lossy": html.lossy,
        "body_source": body_source,
        // Real inventory read from the attachment table. The old code derived a
        // count of 0/1 from the PidTagHasAttachments boolean and always shipped
        // an empty list, so a 5-attachment message reported one nameless
        // attachment (BUG-224). `attachments_incomplete` is set when a row could
        // not be read, so a short inventory is never mistaken for a full one.
        "attachment_count": attachments.count,
        "attachments": attachments.items,
        "attachments_incomplete": attachments.incomplete,
        "has_attachments": has_attachments || attachments.count > 0,
        "container": pst_name,
        "folder_path": folder_path,
        "message_class": message_class,
    });

    // The thread the message belongs to, derived from the RFC 5322 headers by
    // the one writer in `crate::thread` so every format this crate reads
    // publishes the same keys with the same basis beside them (§5.14).
    if let Some(map) = metadata.as_object_mut() {
        if let Some(behalf) = &on_behalf {
            map.insert(
                "sent_on_behalf_of".into(),
                json!({"name": behalf.name, "email": behalf.email()}),
            );
        }
        crate::thread::stamp(map, &message_id, &in_reply_to, &references);
        if let Some(legacy) = props.legacy_8bit_text() {
            map.insert("legacy_8bit_text".into(), legacy.to_json());
        }
        for (k, v) in extra {
            map.insert(k.clone(), v.clone());
        }
    }

    // `attachments_incomplete` / `body_truncated` are this parser's own keys and
    // nothing downstream reads them. The standard pair is what the API, export
    // and cross-plugin honesty paths key on, so a message with an unreadable
    // attachment row or a clipped body is no longer exported as a complete
    // recovery (B3-085). Both sets are emitted.
    let props_incomplete = extra
        .get("properties_unreadable")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    let rtf_only = body_source == "rtf_not_decoded";
    if attachments.incomplete || props_incomplete || html.lossy || body_truncated || rtf_only {
        let reason = if attachments.incomplete || props_incomplete || html.lossy {
            IncompleteReason::UnresolvedStructure
        } else if rtf_only {
            IncompleteReason::Compressed
        } else {
            IncompleteReason::CapReached
        };
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!(reason.as_str());
    }

    let record =
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id);
    artifacts.push(record);

    // Create timeline event if we have a date
    if !date_str.is_empty() {
        let description = if !sender_email.is_empty() {
            format!("Email from {} - {}", sender_email, subject)
        } else if !sender_name.is_empty() {
            format!("Email from {} - {}", sender_name, subject)
        } else {
            format!("Email - {}", subject)
        };

        let timeline_metadata = json!({
            "timestamp": date_str,
            "timestamp_desc": "Email Sent",
            "source_module": "plugin.email.parser",
            "short_desc": description,
            "event_type": "email_message",
            "source": pst_name,
            "from": sender_email,
            "to": to,
            "subject": subject,
        });

        let timeline = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            timeline_metadata,
        )
        .with_parent(parent_id);
        artifacts.push(timeline);
    }
}

/// The subject as it is read, with Outlook's two-character prefix marker
/// removed (MS-OXCMSG PidTagSubject: a leading U+0001 and a length character).
pub(crate) fn normalise_subject(s: &str) -> String {
    match s.strip_prefix('\u{1}') {
        Some(rest) => rest.chars().skip(1).collect(),
        None => s.to_string(),
    }
}

// --- Sender / attachment helpers ---

/// One party to a message: the sender, or the party it was sent on behalf of.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Party {
    name: String,
    /// A usable address: the SMTP-address property, else a legacy address that
    /// is not an X.500 DN. Empty values are skipped so a present-but-blank
    /// property cannot mask a good one further down the chain.
    address: Option<String>,
    /// An Exchange X.500 distinguished name (`/O=...`), published only where no
    /// usable address exists for the party that leads (BUG-224).
    dn: Option<String>,
}

impl Party {
    fn new(name: Option<String>, smtp: Option<String>, legacy: Option<String>) -> Self {
        let present = |s: Option<String>| s.filter(|s| !s.trim().is_empty());
        let legacy = present(legacy);
        let is_dn = |s: &String| s.starts_with("/O=") || s.starts_with("/o=");
        let (legacy_dn, legacy_address) = match legacy {
            Some(l) if is_dn(&l) => (Some(l), None),
            other => (None, other),
        };
        Self {
            name: name.unwrap_or_default(),
            address: present(smtp).or(legacy_address),
            dn: legacy_dn,
        }
    }

    /// The address to publish: a usable one, else the DN, else nothing —
    /// never a fabricated one.
    fn email(&self) -> String {
        self.address
            .clone()
            .or_else(|| self.dn.clone())
            .unwrap_or_default()
    }

    fn is_blank(&self) -> bool {
        self.name.trim().is_empty() && self.address.is_none() && self.dn.is_none()
    }

    /// Whether two parties are visibly different people: their names differ, or
    /// both have a usable address and the addresses differ. A DN against an
    /// SMTP address is not comparable, so it does not make a difference.
    fn differs_from(&self, other: &Self) -> bool {
        let names_differ = !self.name.trim().is_empty()
            && !other.name.trim().is_empty()
            && !self.name.trim().eq_ignore_ascii_case(other.name.trim());
        let addresses_differ = match (&self.address, &other.address) {
            (Some(a), Some(b)) => !a.trim().eq_ignore_ascii_case(b.trim()),
            _ => false,
        };
        names_differ || addresses_differ
    }
}

/// Choose the one party whose name and address the record carries, and the
/// party it was sent on behalf of when that is someone else.
///
/// The sender leads when it has a usable address, preferring the SMTP-address
/// property over a legacy one that is not an X.500 DN. Exchange stores a DN in
/// the legacy properties, which surfaced as `from: /O=EXCHANGE/OU=.../CN=ALICE`
/// (BUG-224), so a party with only a DN does not lead while the other has a real
/// address. A delegate's message is the sender's, with the principal named in
/// `sent_on_behalf_of`: taking the principal's address under the delegate's name
/// attributed the message to someone who did not send it.
fn pick_sender(sender: Party, representing: Party) -> (Party, Option<Party>) {
    let sender_leads =
        sender.address.is_some() || (representing.address.is_none() && !sender.is_blank());
    if sender_leads {
        let behalf = (!representing.is_blank() && sender.differs_from(&representing))
            .then_some(representing);
        (sender, behalf)
    } else {
        (representing, None)
    }
}

/// The HTML body as text, and how it was decoded.
struct HtmlBody {
    text: String,
    /// `PidTagInternetCodepage`, when the message names one.
    codepage: Option<i64>,
    /// Bytes that could not be mapped were replaced (U+FFFD), so the text is not
    /// the stored body.
    lossy: bool,
}

/// The encoding of a Windows code page, where this build knows it.
fn encoding_for_codepage(codepage: i64) -> Option<&'static encoding_rs::Encoding> {
    use encoding_rs::*;
    Some(match codepage {
        65001 => UTF_8,
        1200 => UTF_16LE,
        1201 => UTF_16BE,
        874 | 1250..=1258 => Encoding::for_label(format!("windows-{codepage}").as_bytes())?,
        932 => SHIFT_JIS,
        936 => GBK,
        949 => EUC_KR,
        950 => BIG5,
        10000 => MACINTOSH,
        20866 => KOI8_R,
        21866 => KOI8_U,
        28591..=28599 | 28605 => {
            Encoding::for_label(format!("iso-8859-{}", codepage - 28590).as_bytes())?
        }
        50220..=50222 => ISO_2022_JP,
        51932 => EUC_JP,
        54936 => GB18030,
        _ => return None,
    })
}

/// Decode `bytes` as the message's code page. A missing or unknown code page
/// decodes as UTF-8, and any bytes replaced either way are reported, so a
/// damaged quotation is never presented as the stored text.
fn decode_html(bytes: &[u8], codepage: Option<i64>) -> (String, bool) {
    match codepage.and_then(encoding_for_codepage) {
        Some(encoding) => {
            let (text, had_errors) = encoding.decode_without_bom_handling(bytes);
            (text.into_owned(), had_errors)
        }
        None => match String::from_utf8_lossy(bytes) {
            std::borrow::Cow::Borrowed(s) => (s.to_string(), false),
            std::borrow::Cow::Owned(s) => (s, true),
        },
    }
}

fn html_body(props: &dyn Props) -> HtmlBody {
    let codepage = props.int(PID_TAG_INTERNET_CODEPAGE);
    match props.bytes(PID_TAG_BODY_HTML) {
        Some(bytes) => {
            let (text, lossy) = decode_html(&bytes, codepage);
            HtmlBody {
                text: text.trim_end_matches('\0').to_string(),
                codepage,
                lossy,
            }
        }
        // A string-typed body was decoded by the reader that produced it.
        None => HtmlBody {
            text: props.string(PID_TAG_BODY_HTML).unwrap_or_default(),
            codepage,
            lossy: false,
        },
    }
}

/// Attachment inventory for one message, read from its attachment table.
#[derive(Default)]
struct AttachmentInventory {
    /// Number of rows in the attachment table (the true attachment count).
    count: usize,
    /// One entry per attachment that could be read.
    items: Vec<serde_json::Value>,
    /// At least one attachment row failed to read, so `items` is shorter than
    /// `count`. Reported so a partial inventory is never read as complete.
    incomplete: bool,
}

/// One attachment's inventory entry. `message_page` is the code page the
/// holding message declares: an attachment declares none, and its 8-bit names
/// are read in the message's. The entry carries the same `legacy_8bit_text`
/// marker a message does when any of its text was decoded rather than stored.
fn attachment_entry(props: &dyn Props, message_page: Option<Page>) -> serde_json::Value {
    let filename = props
        .string_in(PID_TAG_ATTACH_LONG_FILENAME, message_page)
        .or_else(|| props.string_in(PID_TAG_ATTACH_FILENAME, message_page))
        .or_else(|| props.string_in(PID_TAG_DISPLAY_NAME, message_page))
        .unwrap_or_default();
    let mut entry = json!({
        "filename": filename,
        "size": props.int(PID_TAG_ATTACH_SIZE),
        "extension": props.string_in(PID_TAG_ATTACH_EXTENSION, message_page),
        "mime_type": props.string_in(PID_TAG_ATTACH_MIME_TAG, message_page),
        "attach_method": props.int(PID_TAG_ATTACH_METHOD),
    });
    if let (Some(legacy), Some(map)) = (
        props.legacy_8bit_text_in(message_page),
        entry.as_object_mut(),
    ) {
        map.insert("legacy_8bit_text".into(), legacy.to_json());
    }
    entry
}

/// One recipient-table row as a record: To, Cc or Bcc, and the name and addresses the row holds.
/// `message_page` decodes 8-bit text the way the message's own text is.
fn recipient_entry(props: &dyn Props, message_page: Option<Page>) -> serde_json::Value {
    let kind = match props.int(PID_TAG_RECIPIENT_TYPE) {
        Some(1) => "to",
        Some(2) => "cc",
        Some(3) => "bcc",
        Some(_) => "other",
        None => "unknown",
    };
    let mut entry = json!({
        "type": kind,
        "name": props.string_in(PID_TAG_DISPLAY_NAME, message_page),
        "address_type": props.string_in(PID_TAG_ADDRESS_TYPE, message_page),
        "address": props.string_in(PID_TAG_RECIPIENT_EMAIL_ADDRESS, message_page),
        "smtp_address": props.string_in(PID_TAG_RECIPIENT_SMTP_ADDRESS, message_page),
    });
    if let (Some(legacy), Some(map)) = (
        props.legacy_8bit_text_in(message_page),
        entry.as_object_mut(),
    ) {
        map.insert("legacy_8bit_text".into(), legacy.to_json());
    }
    entry
}

/// Say what the recipient table of a message read by this crate's own reader held: its rows, or that it
/// was not read and why (`None` is a message with no recipient table, or one whose subnode tree failed,
/// which `gaps` names).
fn insert_recipients(
    extra: &mut serde_json::Map<String, serde_json::Value>,
    recipients: Option<&Vec<std::collections::BTreeMap<u16, Ost4kValue>>>,
    message_page: Option<Page>,
) {
    match recipients {
        Some(rows) => {
            extra.insert("recipients_read".into(), json!(true));
            extra.insert(
                "recipients".into(),
                json!(rows
                    .iter()
                    .map(|r| recipient_entry(r, message_page))
                    .collect::<Vec<_>>()),
            );
        }
        None => {
            extra.insert("recipients_read".into(), json!(false));
            extra.insert("recipients".into(), json!([]));
            extra.insert(
                "recipients_note".into(),
                json!(
                    "this message holds no recipient table, or the subnode tree that holds it could \
                     not be read (the recovery gaps say which): no recipient is listed, and that does \
                     not show the message had none"
                ),
            );
        }
    }
}

fn unicode_attachments(msg: &Rc<UnicodeMessage>) -> AttachmentInventory {
    let mut inv = AttachmentInventory::default();
    let page = page_from(|id| prop_to_i64(msg.properties().get(id)));
    let Some(table) = msg.attachment_table() else {
        return inv;
    };
    for row in table.rows_matrix() {
        inv.count += 1;
        let node = NodeId::from(u32::from(row.id()));
        match UnicodeAttachment::read(msg.clone(), node, None) {
            Ok(att) => inv.items.push(attachment_entry(att.properties(), page)),
            Err(e) => {
                debug!("Failed to read PST attachment: {}", e);
                inv.incomplete = true;
            }
        }
    }
    inv
}

fn ansi_attachments(msg: &Rc<AnsiMessage>) -> AttachmentInventory {
    let mut inv = AttachmentInventory::default();
    let page = page_from(|id| prop_to_i64(msg.properties().get(id)));
    let Some(table) = msg.attachment_table() else {
        return inv;
    };
    for row in table.rows_matrix() {
        inv.count += 1;
        let node = NodeId::from(u32::from(row.id()));
        match AnsiAttachment::read(msg.clone(), node, None) {
            Ok(att) => inv.items.push(attachment_entry(att.properties(), page)),
            Err(e) => {
                debug!("Failed to read ANSI PST attachment: {}", e);
                inv.incomplete = true;
            }
        }
    }
    inv
}

// --- Property value helpers ---

fn prop_to_i64(prop: Option<&PropertyValue>) -> Option<i64> {
    prop.and_then(|val| match val {
        PropertyValue::Integer16(v) => Some(i64::from(*v)),
        PropertyValue::Integer32(v) => Some(i64::from(*v)),
        PropertyValue::Integer64(v) => Some(*v),
        _ => None,
    })
}

fn prop_to_string(prop: Option<&PropertyValue>) -> Option<String> {
    prop.and_then(|val| match val {
        PropertyValue::String8(s) => Some(s.to_string()),
        PropertyValue::Unicode(u) => Some(u.to_string()),
        PropertyValue::Binary(b) => {
            let buf = b.buffer();
            if buf.len() >= 2 && buf.len() % 2 == 0 {
                let chars: Vec<u16> = buf
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                Some(
                    String::from_utf16_lossy(&chars)
                        .trim_end_matches('\0')
                        .to_string(),
                )
            } else {
                Some(
                    String::from_utf8_lossy(buf)
                        .trim_end_matches('\0')
                        .to_string(),
                )
            }
        }
        _ => None,
    })
}

/// One property as **both** an RFC 3339 string and unix seconds, accepted or
/// refused once.
///
/// The two were two independent chains with different acceptance rules:
/// `prop_to_time` went through `filetime_to_datetime`, which rejects anything
/// below the 1601→1970 difference and anything at or past the year 10000,
/// while `prop_to_epoch` required the value to be *strictly* greater than that
/// difference and had no upper bound at all. So a FILETIME landing exactly on
/// `1970-01-01T00:00:00` produced a `date` string with a null `date_epoch`,
/// and a `0x7FFF…` "never" value produced a year-30828 `date_epoch` with an
/// empty `date` and no timeline event. Worse, because each field walked its own
/// fallback chain, one record's two fields could come from **different
/// properties**. One decision, one pair.
fn prop_to_instant(prop: Option<&PropertyValue>) -> Option<(String, i64)> {
    prop.and_then(|val| match val {
        PropertyValue::Time(filetime) => filetime_instant(*filetime),
        _ => None,
    })
}

/// A FILETIME as the (RFC 3339, unix seconds) pair, accepted or refused once;
/// shared by both readers so they draw the same line.
fn filetime_instant(ticks: i64) -> Option<(String, i64)> {
    const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;
    // At or below the epoch difference is what an unset FILETIME decodes to,
    // and 1601 is not a date a message was sent on.
    if ticks <= FILETIME_UNIX_DIFF {
        return None;
    }
    let ft = u64::try_from(ticks).ok()?;
    // The string conversion is the stricter of the two and carries the upper
    // bound, so it decides for both.
    let text = seance_core::time::filetime_to_rfc3339(ft)?;
    Some((text, (ticks - FILETIME_UNIX_DIFF) / 10_000_000))
}

fn prop_to_bool(prop: Option<&PropertyValue>) -> Option<bool> {
    prop.and_then(|val| match val {
        PropertyValue::Boolean(b) => Some(*b),
        _ => None,
    })
}

fn parse_display_list(display: &str) -> Vec<String> {
    if display.is_empty() {
        return Vec::new();
    }
    display
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The per-store summary record, carrying the honest extraction counts and — if
/// a safety cap stopped the walk — an explicit incomplete marker.
///
/// Forensic meaning: `message_count` / `folder_count` are what this tool
/// actually recovered, not what the PST holds. When `content_incomplete` is set,
/// folders and messages beyond the cap were never opened, so the absence of a
/// message from the case is NOT evidence that the custodian never had it. A
/// missing marker on a truncated walk is the wrong answer: a 300k-message
/// archive would present its first 100k as the complete mailbox.
fn make_summary_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
    variant: &str,
    stats: &PstWalkStats,
) -> Artifact {
    let message_count = stats.messages;
    let folder_count = stats.folders;
    let messages_capped = stats.messages_capped();
    let folders_capped = stats.folders_capped();
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("PstSummary"));
    meta.insert("subtype".into(), json!("pst_summary"));
    meta.insert("format".into(), json!("pst"));
    meta.insert("pst_variant".into(), json!(variant));
    meta.insert("file_name".into(), json!(name));
    meta.insert("message_count".into(), json!(message_count));
    meta.insert("folder_count".into(), json!(folder_count));
    meta.insert("max_messages".into(), json!(MAX_PST_MESSAGES));
    meta.insert("max_folders".into(), json!(MAX_PST_FOLDERS));
    // Every way the walk fell short travels on the summary, whether or not a
    // cap fired. A count cap is only one of them: a subtree abandoned at the
    // nesting limit, a message whose row exists and whose properties will not
    // read, and a subfolder that will not open all leave messages out of the
    // case, and all of them used to leave the summary saying "complete"
    // (B5-023, B5-028).
    meta.insert("depth_limited_folders".into(), json!(stats.depth_limited));
    meta.insert(
        "messages_unreadable".into(),
        json!(stats.messages_unreadable),
    );
    meta.insert(
        "entry_ids_unresolved".into(),
        json!(stats.entry_ids_unresolved),
    );
    meta.insert("folders_unreadable".into(), json!(stats.folders_unreadable));
    // Folder names decoded from 8-bit text under an assumed Windows-1252.
    meta.insert(
        "folders_8bit_name_decoded".into(),
        json!(stats.folders_8bit_names.len()),
    );
    if !stats.folders_8bit_names.is_empty() {
        meta.insert("folders_8bit_names".into(), json!(stats.folders_8bit_names));
    }
    if let Some(basis) = &stats.folders_8bit_codepage {
        meta.insert("folders_8bit_codepage".into(), basis.clone());
    }
    meta.insert("messages_partial".into(), json!(stats.messages_partial));
    // Messages the linked reader refused and this crate's own reader published (HUNT-281).
    meta.insert(
        "messages_read_by_own_reader".into(),
        json!(stats.messages_own_reader),
    );
    meta.insert("folder_cycles".into(), json!(stats.folder_cycles));
    meta.insert(
        "root_unreachable".into(),
        json!(stats.root_unreachable.is_some()),
    );
    if stats.fell_short() {
        meta.insert("truncated".into(), json!(true));
        meta.insert("content_incomplete".into(), json!(true));
        meta.insert(
            "content_incomplete_reason".into(),
            json!(if messages_capped || folders_capped {
                IncompleteReason::CapReached.as_str()
            } else {
                IncompleteReason::UnresolvedStructure.as_str()
            }),
        );
        meta.insert("inventory_incomplete".into(), json!(true));
        meta.insert("message_cap_reached".into(), json!(messages_capped));
        meta.insert("folder_cap_reached".into(), json!(folders_capped));
        let mut reasons: Vec<String> = Vec::new();
        if let Some(detail) = &stats.root_unreachable {
            reasons.push(format!(
                "this store was identified and opened but {detail}; a message count of \
                 {message_count} here is what was read, not what the mailbox holds"
            ));
        }
        if messages_capped || folders_capped {
            reasons.push(
                "the walk stopped at a parser cap; later folders and messages were not extracted"
                    .to_string(),
            );
        }
        if stats.depth_limited > 0 {
            reasons.push(format!(
                "{} folder(s) were nested deeper than this parser follows; those subtrees and \
                 every message in them were not opened",
                stats.depth_limited
            ));
        }
        if stats.messages_unreadable > 0 {
            reasons.push(format!(
                "{} message(s) exist in a folder's contents table and could not be read",
                stats.messages_unreadable
            ));
        }
        if stats.messages_partial > 0 {
            reasons.push(format!(
                "{} message(s) could not be read in full and were published from a fallback \
                 read of eight properties only: their bodies, recipients, attachment inventory \
                 and threading identifiers were not read",
                stats.messages_partial
            ));
        }
        if stats.folder_cycles > 0 {
            reasons.push(format!(
                "{} hierarchy row(s) named a folder already entered (a hierarchy that points \
                 back at an ancestor, or names a folder twice) and were not walked again",
                stats.folder_cycles
            ));
        }
        if stats.entry_ids_unresolved > 0 {
            reasons.push(format!(
                "{} table row(s) named a node this parser could not turn into an entry id, so \
                 nothing was opened for them",
                stats.entry_ids_unresolved
            ));
        }
        if stats.folders_unreadable > 0 {
            reasons.push(format!(
                "{} subfolder(s) named in a hierarchy table would not open",
                stats.folders_unreadable
            ));
        }
        meta.insert("message".into(), json!(reasons.join("; ")));
    }
    // The display name is what a list of case records shows. "PST: 0 messages
    // from 0 folders" next to a store that was recognised and could not be
    // opened reads as an empty mailbox, which is the claim this whole record
    // exists to avoid making (B8-038).
    let display_name = if stats.root_unreachable.is_some() {
        format!("PST: identified but not readable ({name})")
    } else {
        format!("PST: {message_count} messages from {folder_count} folders ({name})")
    };
    meta.insert("name".into(), json!(display_name));
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("pst_summary")
}

/// A record stating that a mail store was recognised as a PST and produced no
/// messages, and why.
///
/// The standard incompleteness pair travels on it because that is what the API,
/// export and cross-plugin honesty paths read; without it a store the tool could
/// not open exported as a complete recovery of nothing.
fn make_parse_failed_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
    error: &str,
    reason: IncompleteReason,
) -> Artifact {
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            // An OST is named as one: "PST not parsed" over an `.ost` reads as
            // the wrong file having been examined.
            "name": format!(
                "{} not parsed: {name}",
                if name.to_ascii_lowercase().ends_with(".ost") { "OST" } else { "PST" }
            ),
            "file_name": name,
            "subtype": "parse_failed",
            "format": "pst",
            "error": error,
            "content_incomplete": true,
            "content_incomplete_reason": reason.as_str(),
            "inventory_incomplete": true,
            "message": error,
        }),
    )
    .with_parent(parent_id)
}

#[cfg(test)]
mod tests {
    /// **`date` and `date_epoch` are one decision.** They were two chains with
    /// different acceptance rules: the string went through
    /// `filetime_to_datetime`, which refuses anything below the 1601→1970
    /// difference and anything at or past the year 10000, while the integer
    /// required a value strictly greater than that difference and had no upper
    /// bound. A FILETIME landing exactly on the Unix epoch therefore produced a
    /// date string with a null epoch, and a `0x7FFF…` "never" value produced a
    /// year-30828 epoch with an empty date and no timeline event.
    #[test]
    fn a_date_and_its_epoch_are_accepted_or_refused_together() {
        use outlook_pst::ltp::prop_context::PropertyValue;
        const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;

        // Exactly the Unix epoch: the string path used to take it and the
        // integer path did not.
        let epoch = PropertyValue::Time(FILETIME_UNIX_DIFF);
        assert_eq!(super::prop_to_instant(Some(&epoch)), None);

        // A "never" FILETIME: the integer path used to take it and the string
        // path did not.
        let never = PropertyValue::Time(0x7FFF_FFFF_FFFF_FFFF);
        assert_eq!(super::prop_to_instant(Some(&never)), None);

        // An ordinary time answers both, and the two name the same instant.
        let one_day = PropertyValue::Time(FILETIME_UNIX_DIFF + 864_000_000_000);
        let (text, secs) = super::prop_to_instant(Some(&one_day)).expect("a real time decodes");
        assert_eq!(secs, 86_400);
        assert!(text.starts_with("1970-01-02T00:00:00"), "{text}");
        // And nothing else reads a time: both fields come from this one call.
        assert!(text.contains("1970-01-02"));
    }

    /// The version-36 walk's shortfalls never overwrite a cap that fired.
    #[test]
    fn a_cap_that_fired_is_not_overwritten_by_a_later_shortfall() {
        let cap = IncompleteReason::CapReached.as_str();
        assert_eq!(ost4k_incomplete_reason(Some(cap), true), cap);
        assert_eq!(ost4k_incomplete_reason(Some(cap), false), cap);
        assert_eq!(
            ost4k_incomplete_reason(None, true),
            IncompleteReason::ShortRead.as_str()
        );
        assert_eq!(
            ost4k_incomplete_reason(None, false),
            IncompleteReason::UnresolvedStructure.as_str()
        );
        assert_eq!(
            ost4k_incomplete_reason(Some(IncompleteReason::UnresolvedStructure.as_str()), true),
            IncompleteReason::ShortRead.as_str()
        );
    }

    /// HUNT-063, as amended by ROADMAP §2.6a. Version 36 is now read (by
    /// `crate::ost4k`); a store of any version this build has no reader for
    /// is still refused by its number, and still not called invalid.
    #[test]
    fn a_version_35_store_is_still_refused_by_number() {
        let mut hdr = vec![0u8; 512];
        hdr[..4].copy_from_slice(b"!BDN");
        hdr[8..10].copy_from_slice(b"SO");
        hdr[10..12].copy_from_slice(&35u16.to_le_bytes());
        let out = super::parse_pst(&hdr, uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), "x.ost");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        let msg = m["message"].as_str().unwrap();
        assert!(msg.contains("OST store"), "{msg}");
        assert!(msg.contains("version 35"), "{msg}");
        assert!(msg.contains("14, 15, 23 and 36"), "{msg}");
        assert!(msg.contains("not malformed"), "{msg}");
        assert!(!msg.contains("Not a valid"), "{msg}");
        assert_eq!(m["content_incomplete"], true);

        // A PST of a supported version is not intercepted here, and neither
        // is version 36.
        let h = super::StoreHeader::read(&{
            let mut p = vec![0u8; 12];
            p[..4].copy_from_slice(b"!BDN");
            p[8..10].copy_from_slice(b"SM");
            p[10..12].copy_from_slice(&23u16.to_le_bytes());
            p
        })
        .unwrap();
        assert_eq!(h.client, "PST");
        assert!(h.readable_by_this_build());
        let mut v36 = hdr.clone();
        v36[10] = 36;
        assert!(super::StoreHeader::read(&v36)
            .unwrap()
            .readable_by_this_build());
    }

    /// A version-36 header whose CRC does not match is handed to the v36
    /// reader, which says what failed, rather than to the refusal.
    #[test]
    fn a_version_36_store_with_a_bad_header_names_the_crc() {
        let mut hdr = vec![0u8; 4096];
        hdr[..4].copy_from_slice(b"!BDN");
        hdr[8..10].copy_from_slice(b"SO");
        hdr[10..12].copy_from_slice(&36u16.to_le_bytes());
        let out = super::parse_pst(&hdr, uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), "x.ost");
        assert_eq!(out.len(), 1);
        let msg = out[0].metadata["message"].as_str().unwrap();
        assert!(msg.contains("version 36"), "{msg}");
        assert!(msg.contains("CRC"), "{msg}");
        assert_eq!(out[0].metadata["subtype"], "parse_failed");
    }

    /// Outlook stores a subject as a two-character marker and the text: the
    /// second character is one more than the length of the prefix ("RE: ").
    /// The marker is not part of the subject anyone reads.
    #[test]
    fn the_subject_prefix_marker_is_not_published() {
        assert_eq!(
            super::normalise_subject("\u{1}\u{5}RE: Hello, Iaman"),
            "RE: Hello, Iaman"
        );
        assert_eq!(super::normalise_subject("\u{1}\u{1}Done"), "Done");
        assert_eq!(
            super::normalise_subject("Synchronization Log: "),
            "Synchronization Log: "
        );
        assert_eq!(super::normalise_subject("\u{1}"), "");
    }

    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_parse_display_list_empty() {
        assert!(parse_display_list("").is_empty());
    }

    #[test]
    fn test_parse_display_list_single() {
        let result = parse_display_list("alice@example.com");
        assert_eq!(result, vec!["alice@example.com"]);
    }

    #[test]
    fn test_parse_display_list_multiple() {
        let result = parse_display_list("alice@example.com; bob@example.com; charlie@example.com");
        assert_eq!(result.len(), 3);
    }

    fn party(name: &str, smtp: Option<&str>, legacy: Option<&str>) -> Party {
        Party::new(
            Some(name.to_string()),
            smtp.map(str::to_string),
            legacy.map(str::to_string),
        )
    }

    const DN: &str = "/O=EXCHANGE/OU=EAG/CN=RECIPIENTS/CN=ALICE";

    /// BUG-224: Exchange PSTs put an X.500 DN in the legacy *EmailAddress
    /// properties. The SMTP-address properties must win, matching the MSG path.
    #[test]
    fn sender_prefers_smtp_over_exchange_dn() {
        let nobody = Party::default();
        let email =
            |sender: Party, representing: Party| pick_sender(sender, representing).0.email();
        assert_eq!(
            email(
                party("", Some("alice@example.com"), Some(DN)),
                nobody.clone()
            ),
            "alice@example.com"
        );
        // Plain SMTP mail sets only the legacy property: still used.
        assert_eq!(
            email(party("", None, Some("bob@example.com")), nobody.clone()),
            "bob@example.com"
        );
        // A present-but-blank SMTP property must not mask the legacy value.
        assert_eq!(
            email(
                party("", Some("  "), Some("bob@example.com")),
                nobody.clone()
            ),
            "bob@example.com"
        );
        // A sender with only a DN does not lead while the representing party has
        // a real address: ordinary Exchange mail, where both are the one person.
        let (p, behalf) = pick_sender(
            party("Alice", None, Some(DN)),
            party("Alice", Some("alice@example.com"), None),
        );
        assert_eq!(
            (p.name.as_str(), p.email().as_str()),
            ("Alice", "alice@example.com")
        );
        assert!(behalf.is_none());
        // Where only a DN exists it is shown, not hidden, and not invented over.
        assert_eq!(email(party("", None, Some(DN)), nobody.clone()), DN);
        // Nothing at all yields an empty string, not a fabricated address.
        assert_eq!(email(nobody.clone(), nobody), "");
    }

    /// An assistant sends on behalf of the boss. The sender SMTP property is
    /// absent (common) and the sender's legacy address is an SMTP address. The
    /// record names the assistant, at the assistant's address, and says it was
    /// sent on behalf of the boss, rather than the boss's address under the
    /// assistant's name.
    #[test]
    fn a_delegates_message_is_attributed_to_the_delegate_and_names_the_principal() {
        let (p, behalf) = pick_sender(
            party("Assistant", None, Some("assistant@x.com")),
            party("Boss", Some("boss@x.com"), None),
        );
        assert_eq!(
            (p.name.as_str(), p.email().as_str()),
            ("Assistant", "assistant@x.com")
        );
        let behalf = behalf.expect("the principal is named");
        assert_eq!(
            (behalf.name.as_str(), behalf.email().as_str()),
            ("Boss", "boss@x.com")
        );

        let mut props = BTreeMap::new();
        for (tag, v) in [
            (PID_TAG_SENDER_NAME, "Assistant"),
            (PID_TAG_SENDER_EMAIL, "assistant@x.com"),
            (PID_TAG_SENT_REPRESENTING_NAME, "Boss"),
            (PID_TAG_SENT_REPRESENTING_SMTP, "boss@x.com"),
            (PID_TAG_SUBJECT, "Minutes"),
        ] {
            props.insert(tag, Ost4kValue::Str(v.into()));
        }
        let m = extracted(&props, serde_json::Map::new());
        assert_eq!(m["from"], "assistant@x.com");
        assert_eq!(m["from_name"], "Assistant");
        assert_eq!(m["sent_on_behalf_of"]["email"], "boss@x.com");
        assert_eq!(m["sent_on_behalf_of"]["name"], "Boss");

        // Mail sent as oneself names nobody else.
        props.insert(
            PID_TAG_SENT_REPRESENTING_NAME,
            Ost4kValue::Str("assistant".into()),
        );
        props.insert(
            PID_TAG_SENT_REPRESENTING_SMTP,
            Ost4kValue::Str("Assistant@X.com".into()),
        );
        let m = extracted(&props, serde_json::Map::new());
        assert!(m.get("sent_on_behalf_of").is_none(), "{m}");
    }

    /// The first record `extract_message_artifacts` publishes for `props`.
    fn extracted(
        props: &BTreeMap<u16, Ost4kValue>,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Value {
        let mut out = Vec::new();
        extract_message_artifacts(
            props,
            Uuid::nil(),
            Uuid::nil(),
            "t.pst",
            "Inbox",
            AttachmentInventory::default(),
            &extra,
            &mut out,
        );
        out[0].metadata.clone()
    }

    /// An HTML body stored as bytes in a legacy code page is decoded with it,
    /// not as UTF-8 with its accented letters replaced; where bytes cannot be
    /// mapped, the record says the text is not the stored one.
    #[test]
    fn legacy_8_bit_text_is_decoded_in_the_declared_or_assumed_code_page_and_says_so() {
        let mut props = BTreeMap::new();
        props.insert(
            0x0037,
            Ost4kValue::Other {
                ptype: 0x001E,
                raw: b"caf\xE9\0".to_vec(),
            },
        );
        // No code page declared: Windows-1252 is assumed, and the record says
        // that it was an assumption.
        let m = extracted(&props, serde_json::Map::new());
        assert_eq!(m["subject"], "caf\u{e9}");
        assert_eq!(m["legacy_8bit_text"]["tags"], serde_json::json!(["0x0037"]));
        assert_eq!(m["legacy_8bit_text"]["codepage"], "windows-1252");
        assert_eq!(m["legacy_8bit_text"]["codepage_declared"], false);

        // The message's own code page, declared, is used.
        props.insert(
            0x0037,
            Ost4kValue::Other {
                ptype: 0x001E,
                raw: vec![0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2, 0],
            },
        );
        props.insert(PID_TAG_MESSAGE_CODEPAGE, Ost4kValue::I32(1251));
        let m = extracted(&props, serde_json::Map::new());
        assert_eq!(m["subject"], "\u{41F}\u{440}\u{438}\u{432}\u{435}\u{442}");
        assert_eq!(m["legacy_8bit_text"]["codepage_declared"], true);
        assert_eq!(m["legacy_8bit_text"]["codepage"], "windows-1251");

        // Text that was valid UTF-8 or ASCII makes no such claim.
        let mut plain = BTreeMap::new();
        plain.insert(0x0037, Ost4kValue::Str("plain".into()));
        assert!(extracted(&plain, serde_json::Map::new())
            .get("legacy_8bit_text")
            .is_none());
    }

    /// `decode_string8` is the one rule the live (14/15/23) reader and the
    /// version-36 reader share for 8-bit text. Pure units on bytes, no store.
    #[test]
    fn decode_string8_applies_the_declared_page_else_windows_1252_and_flags_it() {
        let declared = |codepage| {
            Some(Page {
                codepage,
                basis: PageBasis::Declared,
            })
        };
        // UTF-8 passes as stored and makes no legacy claim.
        let d = decode_string8("caf\u{e9}".as_bytes(), declared(1251));
        assert_eq!(d.text, "caf\u{e9}");
        assert!(d.legacy.is_none());
        // 0xE9 under 1252 undeclared (e-acute), 1251 declared (Cyrillic short i), 932 declared.
        let d = decode_string8(b"caf\xE9\0", None);
        assert_eq!(d.text, "caf\u{e9}");
        let l = d.legacy.unwrap();
        assert_eq!(
            (l.codepage.name(), l.basis, l.lossy),
            ("windows-1252", None, false)
        );
        let d = decode_string8(b"caf\xE9", declared(1251));
        assert_eq!(d.text, "caf\u{439}");
        let l = d.legacy.unwrap();
        assert_eq!(
            (l.codepage.name(), l.basis),
            ("windows-1251", Some(PageBasis::Declared))
        );
        // Shift-JIS double byte: 0x82 0xA0 is HIRAGANA LETTER A.
        let d = decode_string8(&[0x82, 0xA0], declared(932));
        assert_eq!(d.text, "\u{3042}");
        assert_eq!(d.legacy.unwrap().codepage.name(), "Shift_JIS");
        // A declared page this build cannot decode is treated as undeclared.
        let d = decode_string8(b"\xE9", declared(99999));
        let l = d.legacy.unwrap();
        assert_eq!((l.codepage.name(), l.basis), ("windows-1252", None));
        // Bytes the page cannot map are replaced and the decoding says so.
        let d = decode_string8(&[0x82], declared(932));
        assert!(d.text.contains('\u{FFFD}'));
        assert!(d.legacy.unwrap().lossy);
    }

    /// A message with no declared page is read in the page its locale implies, and says that is an inference
    /// (`HUNT-281`). The locale and Internet code page tables are pinned on the languages whose ANSI page is
    /// not Windows-1252, and nothing is inferred for a Western locale.
    #[test]
    fn the_page_a_message_implies_is_its_locales_and_a_western_locale_implies_none() {
        let page = |props: &[(u16, i64)]| {
            page_from(|id| props.iter().find(|(t, _)| *t == id).map(|(_, v)| *v))
        };
        // Declared wins over everything.
        assert_eq!(
            page(&[
                (PID_TAG_MESSAGE_CODEPAGE, 1251),
                (PID_TAG_MESSAGE_LOCALE_ID, 0x0411)
            ]),
            Some(Page {
                codepage: 1251,
                basis: PageBasis::Declared
            })
        );
        // Locale: Japanese, Simplified and Traditional Chinese, Korean, Thai, Russian, Greek, Turkish, Hebrew.
        for (lcid, want) in [
            (0x0411, 932),
            (0x0804, 936),
            (0x0404, 950),
            (0x0412, 949),
            (0x041E, 874),
            (0x0419, 1251),
            (0x0408, 1253),
            (0x041F, 1254),
            (0x040D, 1255),
        ] {
            assert_eq!(
                page(&[(PID_TAG_MESSAGE_LOCALE_ID, lcid)]),
                Some(Page {
                    codepage: want,
                    basis: PageBasis::MessageLocaleId
                }),
                "{lcid:#x}"
            );
        }
        // Western locales (English, German, French, Spanish, Portuguese, Dutch, Italian) imply nothing.
        for lcid in [
            0x0409, 0x0809, 0x0407, 0x040C, 0x0C0A, 0x0416, 0x0413, 0x0410,
        ] {
            assert_eq!(
                page(&[(PID_TAG_MESSAGE_LOCALE_ID, lcid)]),
                None,
                "{lcid:#x}"
            );
        }
        // The Internet code page, when the locale says nothing: ISO-2022-JP and EUC-KR stand for the
        // Windows pages their text is stored in; UTF-8 and ISO-8859-1 imply nothing.
        for (cpid, want) in [
            (50220, 932),
            (51932, 932),
            (52936, 936),
            (51949, 949),
            (1251, 1251),
        ] {
            assert_eq!(
                page(&[(PID_TAG_INTERNET_CODEPAGE, cpid)]),
                Some(Page {
                    codepage: want,
                    basis: PageBasis::InternetCodepage
                }),
                "{cpid}"
            );
        }
        for cpid in [65001, 28591, 20127] {
            assert_eq!(page(&[(PID_TAG_INTERNET_CODEPAGE, cpid)]), None, "{cpid}");
        }
        // A Western locale does not stop the Internet code page from speaking.
        assert_eq!(
            page(&[
                (PID_TAG_MESSAGE_LOCALE_ID, 0x0409),
                (PID_TAG_INTERNET_CODEPAGE, 50220)
            ]),
            Some(Page {
                codepage: 932,
                basis: PageBasis::InternetCodepage
            })
        );
    }

    /// An inferred page that cannot decode the bytes is not taken: the text is read as Windows-1252 and the
    /// record says it is assumed, so a wrong inference never hides behind replacement characters.
    #[test]
    fn an_inferred_page_that_cannot_decode_the_bytes_falls_back_to_the_assumed_one() {
        let inferred = Some(Page {
            codepage: 932,
            basis: PageBasis::MessageLocaleId,
        });
        // 0xE9 alone is a Shift-JIS lead byte with no trail: lossy in 932, e-acute in 1252.
        let d = decode_string8(b"caf\xE9", inferred);
        assert_eq!(d.text, "caf\u{e9}");
        let l = d.legacy.unwrap();
        assert_eq!(
            (l.codepage.name(), l.basis, l.lossy),
            ("windows-1252", None, false)
        );
        // The same bytes under a page the message DECLARES are kept in it, replacement characters and all.
        let d = decode_string8(
            b"caf\xE9",
            Some(Page {
                codepage: 932,
                basis: PageBasis::Declared,
            }),
        );
        assert!(d.legacy.unwrap().lossy);
        // Valid Shift-JIS under the inferred page is decoded in it and the basis is kept.
        let d = decode_string8(&[0x83, 0x52, 0x83, 0x80], inferred);
        assert_eq!(d.text, "\u{30b3}\u{30e0}");
        assert_eq!(d.legacy.unwrap().basis, Some(PageBasis::MessageLocaleId));
    }

    /// An attachment has no code page of its own; its name is read in the
    /// message's, and the entry says so.
    #[test]
    fn an_attachment_name_is_decoded_in_the_messages_code_page_and_marked() {
        let mut att = BTreeMap::new();
        att.insert(
            PID_TAG_ATTACH_LONG_FILENAME,
            Ost4kValue::Other {
                ptype: 0x001E,
                raw: vec![
                    0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2, b'.', b't', b'x', b't', 0,
                ],
            },
        );
        let e = attachment_entry(
            &att,
            Some(Page {
                codepage: 1251,
                basis: PageBasis::Declared,
            }),
        );
        assert_eq!(
            e["filename"],
            "\u{41F}\u{440}\u{438}\u{432}\u{435}\u{442}.txt"
        );
        assert_eq!(e["legacy_8bit_text"]["codepage"], "windows-1251");
        assert_eq!(e["legacy_8bit_text"]["codepage_declared"], true);
        // The message declares nothing: Windows-1252, and the entry says assumed.
        let e = attachment_entry(&att, None);
        assert_eq!(e["legacy_8bit_text"]["codepage"], "windows-1252");
        assert_eq!(e["legacy_8bit_text"]["codepage_declared"], false);
        // A name stored as Unicode makes no such claim.
        let mut plain = BTreeMap::new();
        plain.insert(
            PID_TAG_ATTACH_LONG_FILENAME,
            Ost4kValue::Str("a.txt".into()),
        );
        assert!(attachment_entry(
            &plain,
            Some(Page {
                codepage: 1251,
                basis: PageBasis::Declared
            })
        )
        .get("legacy_8bit_text")
        .is_none());
    }

    #[test]
    fn an_html_body_is_decoded_in_its_code_page_and_loss_is_flagged() {
        let mut props = BTreeMap::new();
        props.insert(
            PID_TAG_BODY_HTML,
            Ost4kValue::Bin(b"<p>caf\xE9</p>".to_vec()),
        );
        props.insert(PID_TAG_INTERNET_CODEPAGE, Ost4kValue::I32(1252));
        let m = extracted(&props, serde_json::Map::new());
        assert_eq!(m["body_html"], "<p>caf\u{e9}</p>");
        assert_eq!(m["body_html_codepage"], 1252);
        assert_eq!(m["body_decoding_lossy"], false);
        assert!(m.get("content_incomplete").is_none(), "{m}");
        assert!(m["body_text"].as_str().unwrap().contains("caf\u{e9}"));

        // No code page named: UTF-8 is tried, and the loss is not silent.
        props.remove(&PID_TAG_INTERNET_CODEPAGE);
        let m = extracted(&props, serde_json::Map::new());
        assert!(m["body_html"].as_str().unwrap().contains('\u{FFFD}'));
        assert_eq!(m["body_decoding_lossy"], true);
        assert_eq!(m["content_incomplete"], true);
        // An unknown code page is the same.
        props.insert(PID_TAG_INTERNET_CODEPAGE, Ost4kValue::I32(99999));
        assert_eq!(
            extracted(&props, serde_json::Map::new())["body_decoding_lossy"],
            true
        );
        // Valid UTF-8 with no code page is not lossy.
        props.remove(&PID_TAG_INTERNET_CODEPAGE);
        props.insert(
            PID_TAG_BODY_HTML,
            Ost4kValue::Bin("<p>café</p>".as_bytes().to_vec()),
        );
        let m = extracted(&props, serde_json::Map::new());
        assert_eq!(m["body_decoding_lossy"], false);
        assert_eq!(m["body_html"], "<p>café</p>");
    }

    /// A clipped HTML body is flagged like a clipped plain body, even when the
    /// plain body is short.
    #[test]
    fn a_clipped_html_body_marks_the_record_incomplete() {
        let mut props = BTreeMap::new();
        props.insert(PID_TAG_BODY, Ost4kValue::Str("short".into()));
        props.insert(
            PID_TAG_BODY_HTML,
            Ost4kValue::Str("x".repeat(MAX_BODY_SIZE + 10)),
        );
        let m = extracted(&props, serde_json::Map::new());
        assert_eq!(m["body_truncated"], true);
        assert_eq!(m["content_incomplete"], true);
        assert_eq!(m["content_incomplete_reason"], "cap_reached");
        props.insert(PID_TAG_BODY_HTML, Ost4kValue::Str("small".into()));
        let m = extracted(&props, serde_json::Map::new());
        assert_eq!(m["body_truncated"], false);
        assert!(m.get("content_incomplete").is_none());
    }

    /// A message whose full read fails and whose minimal read opens is not
    /// published as an ordinary complete message: it says it is partial and why.
    #[test]
    fn a_message_read_from_the_fallback_is_marked_partial() {
        let calls = std::cell::Cell::new(0);
        let read = |props: Option<&[u16]>| -> Result<&'static str, String> {
            calls.set(calls.get() + 1);
            match props {
                None => Err("a property block is corrupt".to_string()),
                Some(p) => {
                    assert_eq!(p, MINIMAL_PROPS.as_slice());
                    Ok("opened")
                }
            }
        };
        let MessageRead::Minimal { message, error } = read_with_fallback("Inbox", read) else {
            panic!("the minimal read should have been used");
        };
        assert_eq!(
            (message, error.as_str()),
            ("opened", "a property block is corrupt")
        );
        assert_eq!(calls.get(), 2);

        let mut props = BTreeMap::new();
        props.insert(PID_TAG_SUBJECT, Ost4kValue::Str("Hello".into()));
        let m = extracted(&props, partial_read_extra(&error));
        assert_eq!(m["content_incomplete"], true);
        assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
        assert_eq!(m["read_fallback"], true);
        assert!(m["read_fallback_error"]
            .as_str()
            .unwrap()
            .contains("corrupt"));
        assert!(!m["properties_unreadable"].as_array().unwrap().is_empty());

        // Both reads failing is a message that could not be opened; the first
        // succeeding is a full read.
        assert!(matches!(
            read_with_fallback("Inbox", |_| Err::<(), _>("x")),
            MessageRead::Failed
        ));
        assert!(matches!(
            read_with_fallback("Inbox", |_| Ok::<_, String>(1)),
            MessageRead::Full(1)
        ));
    }

    /// The summary counts partial messages and folder cycles, and a walk with
    /// either is not complete.
    #[test]
    fn partial_messages_and_folder_cycles_make_the_summary_incomplete() {
        let mut stats = walked(10, 3);
        assert!(!stats.fell_short());
        assert!(stats.enter_folder(0x122));
        assert!(!stats.fell_short());
        assert!(!stats.enter_folder(0x122), "a folder is walked once");
        assert_eq!(stats.folder_cycles, 1);
        stats.messages_partial = 2;
        let a = make_summary_artifact(Uuid::nil(), Uuid::nil(), "c.pst", "unicode", &stats);
        assert_eq!(a.metadata["folder_cycles"], 1);
        assert_eq!(a.metadata["messages_partial"], 2);
        assert_eq!(a.metadata["content_incomplete"], true);
        let msg = a.metadata["message"].as_str().unwrap();
        assert!(
            msg.contains("fallback read") && msg.contains("already entered"),
            "{msg}"
        );
        let only_cycle = PstWalkStats {
            folder_cycles: 1,
            ..PstWalkStats::default()
        };
        assert!(only_cycle.fell_short());
    }

    /// The version-36 walk lists every folder and publishes every message up to
    /// the cap. Exactly the cap in either is not a walk that stopped; messages
    /// left over are.
    #[test]
    fn the_version_36_walk_is_capped_only_when_something_was_left_over() {
        let whole = |messages, folders, skipped| PstWalkStats {
            messages,
            folders,
            counted_whole: true,
            messages_skipped: skipped,
            ..PstWalkStats::default()
        };
        let summary = |s: &PstWalkStats| {
            make_summary_artifact(Uuid::nil(), Uuid::nil(), "o.ost", "ost_v36", s)
        };
        // 10,000 folders (and more) are all read: nothing was cut.
        for folders in [MAX_PST_FOLDERS, MAX_PST_FOLDERS + 5] {
            let a = summary(&whole(40, folders, 0));
            assert!(a.metadata.get("content_incomplete").is_none(), "{folders}");
            assert_eq!(a.metadata["folder_count"], folders);
        }
        // Exactly 100,000 messages with none left over.
        let a = summary(&whole(MAX_PST_MESSAGES, 3, 0));
        assert!(a.metadata.get("content_incomplete").is_none());
        // One left over is a cap.
        let a = summary(&whole(MAX_PST_MESSAGES, 3, 1));
        assert_eq!(a.metadata["content_incomplete"], true);
        assert_eq!(a.metadata["content_incomplete_reason"], "cap_reached");
        assert_eq!(a.metadata["message_cap_reached"], true);
        assert_eq!(a.metadata["folder_cap_reached"], false);
    }

    /// A recovery listing that stopped at its cap leaves the summary
    /// incomplete, without claiming the live inventory was short, and without
    /// replacing a more specific reason already there.
    #[test]
    fn a_capped_recovery_marks_the_summary_incomplete() {
        let clean =
            make_summary_artifact(Uuid::nil(), Uuid::nil(), "c.pst", "unicode", &walked(3, 1));
        let mut meta = clean.metadata.as_object().unwrap().clone();
        mark_recovery_capped(&mut meta);
        assert_eq!(meta["content_incomplete"], true);
        assert_eq!(meta["content_incomplete_reason"], "cap_reached");
        assert!(meta["message"]
            .as_str()
            .unwrap()
            .contains("recovery listing"));
        assert!(meta.get("truncated").is_none());
        assert!(meta.get("inventory_incomplete").is_none());

        let mut meta = serde_json::Map::new();
        meta.insert("content_incomplete_reason".into(), json!("short_read"));
        meta.insert("message".into(), json!("a page was past the data"));
        mark_recovery_capped(&mut meta);
        assert_eq!(meta["content_incomplete_reason"], "short_read");
        let msg = meta["message"].as_str().unwrap();
        assert!(msg.starts_with("a page was past the data; "), "{msg}");
    }

    /// What the scan matched and could not read is stated in the note and the
    /// metadata, with the offsets.
    #[test]
    fn what_the_recovery_scan_could_not_read_is_stated() {
        use crate::ost4k::recover::{Recovery, UnreadContext};
        let mut rec = Recovery::default();
        rec.pages_unvalidated.push(0x3000);
        rec.blocks_unvalidated.push(0x4a40);
        rec.unread_contexts.push(UnreadContext {
            bid: 0x614,
            ib: 0x5000,
            reason: "BTH header is not one".into(),
        });
        let (mut note, mut meta) = (String::new(), serde_json::Map::new());
        note_recovery_blind_spots(&rec, &mut note, &mut meta);
        assert_eq!(meta["unreferenced_pages_unvalidated"]["count"], 1);
        assert_eq!(
            meta["unreferenced_pages_unvalidated"]["offsets"][0],
            "0x3000"
        );
        assert_eq!(
            meta["unreferenced_blocks_unvalidated"]["offsets"][0],
            "0x4a40"
        );
        assert_eq!(meta["property_contexts_not_decoded"]["count"], 1);
        assert_eq!(
            meta["property_contexts_not_decoded"]["blocks"][0]["block_id"],
            "0x614"
        );
        assert!(
            note.contains("did not validate") && note.contains("did not decode"),
            "{note}"
        );
        // A clean scan says nothing in the note and zero in the metadata.
        let (mut note, mut meta) = (String::new(), serde_json::Map::new());
        note_recovery_blind_spots(&Recovery::default(), &mut note, &mut meta);
        assert!(note.is_empty());
        assert_eq!(meta["property_contexts_not_decoded"]["count"], 0);
    }

    const V23_EMPTY: &[u8] =
        include_bytes!("../tests/fixtures/pst_old/outlook_pst_crate_empty_v23.pst");

    /// A store whose header names a supported version and whose body the
    /// reader refuses is not called "not a valid PST": the record names the
    /// client and version and the reader's own reason (HUNT-063).
    #[test]
    fn a_recognised_store_the_reader_refuses_is_not_called_invalid() {
        for (version, data) in [(23u16, &V23_EMPTY[..600]), (14, &V14_ADMIN[..600])] {
            let out = parse_pst(data, Uuid::new_v4(), Uuid::new_v4(), "cut.pst");
            assert_eq!(out.len(), 1, "v{version}");
            assert_eq!(out[0].metadata["subtype"], "parse_failed");
            let msg = out[0].metadata["message"].as_str().unwrap();
            assert!(!msg.contains("Not a valid"), "{msg}");
            assert!(msg.contains(&format!("format version {version}")), "{msg}");
            assert!(msg.contains("refused its structure"), "{msg}");
            assert!(msg.contains("not shown to be malformed"), "{msg}");
            assert_eq!(out[0].metadata["content_incomplete"], true);
        }
    }

    /// A message with no attachment table reports zero attachments and an empty
    /// inventory that is flagged complete -- not a fabricated count of 1.
    #[test]
    fn empty_attachment_inventory_is_zero_and_complete() {
        let inv = AttachmentInventory::default();
        assert_eq!(inv.count, 0);
        assert!(inv.items.is_empty());
        assert!(!inv.incomplete);
    }

    const V14_ADMIN: &[u8] =
        include_bytes!("../tests/fixtures/pst_old/m57_jean_administrator_outlook.pst");

    /// An untouched real version 14 store publishes its live message and
    /// states that it was scanned for deleted ones and found none.
    #[test]
    fn an_untouched_version_14_store_says_it_was_scanned_and_found_nothing_deleted() {
        let arts = parse_pst(V14_ADMIN, Uuid::new_v4(), Uuid::new_v4(), "outlook.pst");
        assert!(arts.iter().all(|a| a.metadata.get("recovered").is_none()));
        let summary = arts.last().unwrap();
        assert_eq!(summary.metadata["subtype"], "pst_summary");
        assert_eq!(summary.metadata["recovered_messages"], 0);
        assert_eq!(summary.metadata["recovery_scanned_version"], 14);
        assert!(summary.metadata["unreferenced_pages"].as_u64().unwrap() > 0);
        assert!(summary.metadata["store_note"]
            .as_str()
            .unwrap()
            .contains("allocation map ignored"));
    }

    /// HUNT-281: the linked reader refuses a message that has no recipient table (an Outlook 2000
    /// "Welcome" message is one), and the row used to be only counted as unreadable. This crate's own
    /// reader opens it, so it is published, says which reader read it and that it has no recipient
    /// table (which is why the linked reader refused it), and the summary no longer calls the
    /// inventory short. The expected subject and folder are
    /// libpff's (`m57_jean_administrator_outlook.pst`, node 0x200024).
    #[test]
    fn a_live_message_the_linked_reader_refuses_is_published_by_the_crates_own_reader() {
        let arts = parse_pst(V14_ADMIN, Uuid::new_v4(), Uuid::new_v4(), "outlook.pst");
        let msg = arts
            .iter()
            .find(|a| a.metadata["subtype"] == "email_message")
            .expect("the live message is published");
        assert_eq!(
            msg.metadata["subject"],
            "Welcome to Microsoft Outlook 2000!"
        );
        assert_eq!(msg.metadata["folder_path"], "Top of Personal Folders/Inbox");
        assert_eq!(msg.metadata["read_by"], "own_reader");
        assert_eq!(msg.metadata["node_id"], "0x200024");
        assert!(
            msg.metadata.get("recovered").is_none(),
            "it is live, not recovered"
        );
        // The message holds no recipient table, which is why the linked reader refused it: nothing is
        // unread, so the record is not marked incomplete, and it says it has no recipients to list.
        assert!(
            msg.metadata.get("content_incomplete").is_none(),
            "{}",
            msg.metadata
        );
        assert_eq!(msg.metadata["recipients_read"], json!(false));
        let summary = arts.last().unwrap();
        assert_eq!(summary.metadata["message_count"], 1);
        assert_eq!(summary.metadata["messages_unreadable"], 0);
        assert_eq!(summary.metadata["messages_read_by_own_reader"], 1);
        assert!(
            summary.metadata.get("truncated").is_none(),
            "{}",
            summary.metadata
        );
        assert!(summary.metadata.get("inventory_incomplete").is_none());
    }

    const V14_SYNTHETIC_8BIT_FOLDER: &[u8] =
        include_bytes!("../tests/fixtures/pst_old/m57_jean_synthetic_8bit_folder.pst");

    /// SYNTHETIC: the Jean store with one byte of the "Sent Items" name patched
    /// to 0xE9, in the folder's own property context and in its parent's
    /// hierarchy table, block CRCs recomputed (see the fixture's
    /// PROVENANCE.txt). It grades the mechanics only: the live (version 14)
    /// walker decodes a folder's 8-bit name in the assumed Windows-1252, not as
    /// the linked reader's Latin-1 widening, and the summary lists the name. It
    /// says nothing about any real mailbox. (The store's one message has no
    /// recipient table, which the linked reader refuses; the crate's own reader
    /// publishes it, HUNT-281.)
    #[test]
    fn a_live_version_14_8bit_folder_name_is_decoded_and_listed_on_the_summary() {
        let arts = parse_pst(
            V14_SYNTHETIC_8BIT_FOLDER,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "outlook.pst",
        );
        let summary = arts.last().unwrap();
        assert_eq!(summary.metadata["subtype"], "pst_summary");
        assert_eq!(summary.metadata["folders_8bit_name_decoded"], 1);
        assert_eq!(
            summary.metadata["folders_8bit_names"],
            serde_json::json!(["S\u{e9}nt Items"])
        );
        // The untouched store lists none.
        let clean = parse_pst(V14_ADMIN, Uuid::new_v4(), Uuid::new_v4(), "outlook.pst");
        let clean = clean.last().unwrap();
        assert_eq!(clean.metadata["folders_8bit_name_decoded"], 0);
        assert!(clean.metadata.get("folders_8bit_names").is_none());
    }

    /// HUNT-280: a deleted message's recipient table is read. The store is the public `pstsdk-sample2` (ANSI,
    /// version 14, one message, one recipient, libpff's answer in
    /// `tests/fixtures/pst_public/pstsdk-sample2.recipients.tsv`) with the message's live node entry cut,
    /// so it comes back from the stale entry. Corpus-gated (`SEANCE_PUBLIC_PST_CORPUS`).
    #[test]
    fn a_deleted_messages_recipient_table_is_published_with_its_addresses() {
        let Some(path) = seance_core::test_support::corpus::file(
            "SEANCE_PUBLIC_PST_CORPUS",
            "pstsdk-sample2.pst",
        ) else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let cut = crate::pst512::without_live_node(&data, 0x0020_0024);
        let arts = parse_pst(&cut, Uuid::new_v4(), Uuid::new_v4(), "sample2.pst");
        let msg = arts
            .iter()
            .find(|a| a.metadata["subtype"] == "email_message" && a.metadata["recovered"] == true)
            .expect("the deleted message is recovered");
        assert_eq!(msg.metadata["recipients_read"], json!(true));
        assert_eq!(
            msg.metadata["recipients"],
            json!([{
                "type": "to",
                "name": "Terry Mahaffey",
                "address_type": "EX",
                "address": "/O=MICROSOFT/OU=Northamerica/cn=Recipients/cn=terrymah1",
                "smtp_address": "terrymah@microsoft.com",
            }])
        );
    }

    /// A message with no recipient table says so rather than listing nobody.
    #[test]
    fn a_message_without_a_recipient_table_says_it_has_none() {
        let arts = parse_pst(V14_ADMIN, Uuid::new_v4(), Uuid::new_v4(), "outlook.pst");
        let msg = arts
            .iter()
            .find(|a| a.metadata["subtype"] == "email_message")
            .unwrap();
        assert_eq!(msg.metadata["recipients_read"], json!(false));
        assert!(msg.metadata["recipients"].as_array().unwrap().is_empty());
        assert!(
            msg.metadata["recipients_note"]
                .as_str()
                .unwrap()
                .contains("no recipient table"),
            "{}",
            msg.metadata
        );
        assert!(msg
            .metadata
            .get("properties_unreadable")
            .is_none_or(|u| { !u.to_string().contains("recipient table") }));
    }

    /// A message whose live entry is gone is published as recovered from
    /// unallocated space, in its folder, with the store version and how
    /// complete it is; the summary counts it.
    #[test]
    fn a_deleted_message_in_a_version_14_store_is_published_as_recovered() {
        let cut = crate::pst512::without_live_node(V14_ADMIN, 0x0020_0024);
        let arts = parse_pst(&cut, Uuid::new_v4(), Uuid::new_v4(), "outlook.pst");
        let msg = arts
            .iter()
            .find(|a| a.metadata["subtype"] == "email_message")
            .expect("the recovered message is published");
        assert_eq!(msg.metadata["recovered"], true);
        assert_eq!(msg.metadata["allocation"], "unallocated");
        assert_eq!(msg.metadata["recovery_source"], "stale_node_entry");
        assert_eq!(msg.metadata["recovery_completeness"], "complete");
        assert_eq!(msg.metadata["store_version"], 14);
        assert_eq!(msg.metadata["deletion_status"], "deleted");
        assert_eq!(
            msg.metadata["subject"],
            "Welcome to Microsoft Outlook 2000!"
        );
        assert_eq!(msg.metadata["folder_path"], "Top of Personal Folders/Inbox");
        let summary = arts.last().unwrap();
        assert_eq!(summary.metadata["recovered_messages"], 1);
        assert_eq!(summary.metadata["recovery_scanned_version"], 14);
    }

    /// Bytes that are not a store, and no bytes, each leave one record saying
    /// the parse failed: an empty answer here would read as "no mail".
    fn assert_one_parse_failed(data: &[u8], name: &str) {
        let artifacts = parse_pst(data, Uuid::new_v4(), Uuid::new_v4(), name);
        assert_eq!(artifacts.len(), 1, "{artifacts:?}");
        let m = &artifacts[0].metadata;
        assert_eq!(m["subtype"], "parse_failed");
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
    }

    #[test]
    fn test_parse_pst_invalid_data() {
        assert_one_parse_failed(&[0x00, 0x01, 0x02, 0x03], "bad.pst");
    }

    #[test]
    fn test_parse_pst_empty() {
        assert_one_parse_failed(&[], "empty.pst");
    }

    #[test]
    fn test_make_parse_failed_artifact() {
        let art = make_parse_failed_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test.pst",
            "test error",
            IncompleteReason::UnresolvedStructure,
        );
        assert_eq!(art.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(art.metadata["subtype"], "parse_failed");
        assert_eq!(art.metadata["format"], "pst");
        assert_eq!(art.metadata["file_name"], "test.pst");
        // The standard pair: an unparsed store must not export as a complete
        // recovery of nothing (B8-038).
        assert_eq!(art.metadata["content_incomplete"], json!(true));
        assert_eq!(
            art.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
    }

    #[test]
    fn test_prop_to_string_none() {
        assert!(prop_to_string(None).is_none());
    }

    #[test]
    fn test_prop_to_bool_none() {
        assert!(prop_to_bool(None).is_none());
    }

    #[test]
    fn test_prop_to_time_none() {
        assert!(prop_to_instant(None).map(|(text, _)| text).is_none());
    }

    #[test]
    fn test_prop_to_bool_true() {
        let val = PropertyValue::Boolean(true);
        assert_eq!(prop_to_bool(Some(&val)), Some(true));
    }

    #[test]
    fn test_prop_to_bool_false() {
        let val = PropertyValue::Boolean(false);
        assert_eq!(prop_to_bool(Some(&val)), Some(false));
    }

    #[test]
    fn test_prop_to_time_valid() {
        // 2024-01-01 00:00:00 UTC in FILETIME
        // Unix epoch diff: 116_444_736_000_000_000
        // 2024-01-01 = 1704067200 seconds from Unix epoch
        // FILETIME = 116_444_736_000_000_000 + 1704067200 * 10_000_000
        let unix_secs: i64 = 1704067200;
        let filetime = 116_444_736_000_000_000i64 + unix_secs * 10_000_000;
        let val = PropertyValue::Time(filetime);
        let result = prop_to_instant(Some(&val)).map(|(text, _)| text);
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("2024-01-01"));
    }

    /// Sub-second precision must survive.
    ///
    /// What an examiner learns: the order two messages were sent in. A PST
    /// stores 100-nanosecond ticks; truncating them to whole seconds makes two
    /// messages sent in the same second indistinguishable, and their order in a
    /// timeline is then decided by the sort rather than by the evidence
    /// (B5-030).
    #[test]
    fn prop_to_time_keeps_the_sub_second_ticks_the_pst_stored() {
        let unix_secs: i64 = 1_704_067_200;
        let base = 116_444_736_000_000_000i64 + unix_secs * 10_000_000;
        // A quarter of a second later, in 100 ns ticks.
        let later = PropertyValue::Time(base + 2_500_000);
        let earlier = PropertyValue::Time(base);

        let earlier = prop_to_instant(Some(&earlier))
            .map(|(text, _)| text)
            .expect("a convertible time");
        let later = prop_to_instant(Some(&later))
            .map(|(text, _)| text)
            .expect("a convertible time");
        assert_ne!(
            earlier, later,
            "two messages a quarter-second apart must not share a timestamp"
        );
        assert!(later > earlier, "{earlier} then {later}");
        assert!(later.contains(".25"), "{later}");
    }

    /// A walk that ran to completion reports its counts and claims nothing about
    /// being incomplete.
    /// A walk with the given counts and no shortfall.
    fn walked(messages: usize, folders: usize) -> PstWalkStats {
        PstWalkStats {
            messages,
            folders,
            ..PstWalkStats::default()
        }
    }

    #[test]
    fn a_complete_pst_walk_is_not_marked_incomplete() {
        let a = make_summary_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "mail.pst",
            "unicode",
            &walked(12, 3),
        );
        assert_eq!(a.metadata["message_count"], json!(12));
        assert_eq!(a.metadata["folder_count"], json!(3));
        assert!(a.metadata.get("content_incomplete").is_none());
        assert!(a.metadata.get("truncated").is_none());
    }

    /// Hitting the message cap must be visible on the summary: a 300k-message
    /// archive must never present its first 100k as the whole mailbox.
    #[test]
    fn a_pst_stopped_by_the_message_cap_is_marked_incomplete() {
        let a = make_summary_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "big.pst",
            "unicode",
            &walked(MAX_PST_MESSAGES, 42),
        );
        assert_eq!(a.metadata["truncated"], json!(true));
        assert_eq!(a.metadata["content_incomplete"], json!(true));
        assert_eq!(a.metadata["content_incomplete_reason"], "cap_reached");
        assert_eq!(a.metadata["message_cap_reached"], json!(true));
        assert_eq!(a.metadata["folder_cap_reached"], json!(false));
    }

    /// The folder cap is reported independently of the message cap.
    #[test]
    fn a_pst_stopped_by_the_folder_cap_is_marked_incomplete() {
        let a = make_summary_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "wide.pst",
            "ansi",
            &walked(5, MAX_PST_FOLDERS),
        );
        assert_eq!(a.metadata["content_incomplete"], json!(true));
        assert_eq!(a.metadata["folder_cap_reached"], json!(true));
        assert_eq!(a.metadata["message_cap_reached"], json!(false));
        assert_eq!(a.metadata["pst_variant"], "ansi");
    }
    /// A walk stopped by the nesting limit, or one that could not read every
    /// message it saw, must be marked incomplete even though no count cap
    /// fired.
    ///
    /// What an examiner learns: whether "this message is not in the mailbox" is
    /// supportable. A deeply nested archive folder, or a message whose
    /// properties will not read, leaves messages out of the case; before this
    /// the summary said 400 messages and claimed to be complete (B5-023,
    /// B5-028).
    #[test]
    fn a_pst_walk_that_skipped_folders_or_messages_is_marked_incomplete() {
        let deep = PstWalkStats {
            messages: 400,
            folders: 9,
            depth_limited: 2,
            ..PstWalkStats::default()
        };
        let a = make_summary_artifact(Uuid::new_v4(), Uuid::new_v4(), "deep.pst", "unicode", &deep);
        assert_eq!(a.metadata["message_count"], json!(400));
        assert_eq!(a.metadata["depth_limited_folders"], json!(2));
        assert_eq!(a.metadata["content_incomplete"], json!(true));
        assert_eq!(a.metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            a.metadata["content_incomplete_reason"], "unresolved_structure",
            "no cap fired, so this is a structure shortfall and not a cap"
        );
        assert_eq!(a.metadata["message_cap_reached"], json!(false));
        assert!(a.metadata["message"]
            .as_str()
            .expect("a stated reason")
            .contains("nested deeper"));

        let lossy = PstWalkStats {
            messages: 400,
            folders: 9,
            messages_unreadable: 7,
            entry_ids_unresolved: 1,
            folders_unreadable: 3,
            ..PstWalkStats::default()
        };
        let b = make_summary_artifact(Uuid::new_v4(), Uuid::new_v4(), "lossy.pst", "ansi", &lossy);
        assert_eq!(b.metadata["messages_unreadable"], json!(7));
        assert_eq!(b.metadata["entry_ids_unresolved"], json!(1));
        assert_eq!(b.metadata["folders_unreadable"], json!(3));
        assert_eq!(b.metadata["content_incomplete"], json!(true));
        let message = b.metadata["message"].as_str().expect("a stated reason");
        assert!(message.contains("could not be read"), "{message}");
        assert!(message.contains("would not open"), "{message}");
    }

    /// A store that opened and whose folder hierarchy could never be entered
    /// must summarise as "identified and not readable", never as an empty
    /// mailbox.
    ///
    /// What an examiner learns: whether "this custodian had no email" is
    /// supportable. A half-open Unicode store — the IPM subtree entry id will
    /// not read, or the root folder will not open — walks zero folders and zero
    /// messages, and neither of those was a cap or a skipped row, so before
    /// this the summary carried `message_count: 0` with no incompleteness at
    /// all and the display name read "PST: 0 messages from 0 folders"
    /// (B8-038).
    #[test]
    fn a_store_whose_hierarchy_never_opened_is_not_reported_as_an_empty_mailbox() {
        let stalled = PstWalkStats {
            root_unreachable: Some(
                "the store's root folder would not open (bad node), so no folder or message in \
                 it was examined"
                    .to_string(),
            ),
            ..PstWalkStats::default()
        };
        assert!(stalled.fell_short());

        let a = make_summary_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "half.pst",
            "unicode",
            &stalled,
        );
        assert_eq!(a.metadata["message_count"], json!(0));
        assert_eq!(a.metadata["root_unreachable"], json!(true));
        assert_eq!(a.metadata["content_incomplete"], json!(true));
        assert_eq!(
            a.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert_eq!(a.metadata["inventory_incomplete"], json!(true));
        let message = a.metadata["message"].as_str().expect("a stated reason");
        assert!(
            message.contains("identified and opened"),
            "the reason must say the store was recognised: {message}"
        );
        assert_eq!(
            a.metadata["name"], "PST: identified but not readable (half.pst)",
            "a case list must not show this as an empty mailbox"
        );

        // Control: a walk that really did enter the hierarchy and found nothing
        // still reports zero and claims completeness, because that is a
        // supportable answer.
        let empty = walked(0, 1);
        let b = make_summary_artifact(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "empty.pst",
            "unicode",
            &empty,
        );
        assert_eq!(b.metadata["root_unreachable"], json!(false));
        assert!(b.metadata.get("content_incomplete").is_none());
    }
}
