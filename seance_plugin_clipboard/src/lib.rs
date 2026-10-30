#![forbid(unsafe_code)]
//! Windows clipboard history: the items Windows writes to disk.
//!
//! # What this artifact is
//!
//! Windows 10 1809 introduced clipboard history — the list behind **Win+V**. It
//! keeps roughly the last 25 items, and the user can **pin** one to keep it.
//!
//! Almost all of it lives in the clipboard service's memory (`cbdhsvc`, hosted
//! in `svchost.exe`) and is cleared on sign-out or restart. What reaches disk,
//! and therefore what a dead-box examination can recover, is the pinned items —
//! and history items where clipboard sync is on — under
//! `%LOCALAPPDATA%\Microsoft\Windows\Clipboard\`.
//!
//! Each item is a GUID-named folder holding `metadata.json` and one file per
//! clipboard format, the filename being the **format name in base64**:
//! `VGV4dA==` for `Text`, `Qml0bWFw` for `Bitmap`, `TG9jYWxl` for `Locale`.
//!
//! # What this parser does, and the one thing it deliberately does not
//!
//! It reports the inventory, the item folders, the formats each held, when each
//! was pinned, and — from the payload's own unencrypted header — which account
//! the data was protected to.
//!
//! **It does not decrypt the payloads, and does not try.** Windows protects
//! each one with CNG DPAPI (`NCryptProtectSecret`), which writes CMS enveloped
//! data. Recovering the plaintext needs key material this artifact does not
//! contain: the user's DPAPI master key, or a domain root key over RPC. A
//! parser that guessed would produce plausible-looking clipboard text, and
//! clipboard text is exactly the kind of evidence — a password, a message, an
//! address — that nobody would think to doubt.
//!
//! So the record says what the file is, states plainly that its contents are
//! encrypted, and names what would be needed to read them. That is a smaller
//! claim than an examiner might want and it is one that will survive being
//! challenged.
//!
//! # What is still evidence without the plaintext
//!
//! More than it first appears, which is why this is worth parsing at all:
//!
//! - **That an item was pinned at all**, and when. The folder's own timestamps
//!   and the inventory's entry both date it.
//! - **What kind of thing it was.** A folder holding `Qml0bWFw` means an image
//!   was copied; one holding only `VGV4dA==` means text. That is legible from
//!   the filename without touching the payload.
//! - **Whose it was.** The protection descriptor in the blob's header names the
//!   SID the payload was protected to.
//! - **Whether it came from this machine.** The inventory distinguishes a
//!   locally-copied item from one that arrived by clipboard sync — which places
//!   a second device in the account.
//!
//! # What an examiner should be told to look at instead
//!
//! The unpinned history — the bulk of it — is in memory, not here. A memory
//! capture and the `cbdhsvc` service's heap are where it is recoverable, and
//! `ActivitiesCache.db` carries clipboard payloads on builds where Windows
//! Timeline is present (`seance_plugin_win_timeline` reads those). Records from
//! this parser say so, because an examiner who finds two pinned items should
//! not conclude that two things were copied.
//!
//! A note on a common misattribution: `%ProgramData%\Microsoft\Windows\ClipSVC`
//! and its `tokens.dat` appear in several published clipboard-forensics
//! write-ups. **ClipSVC is the Client License Service** — Microsoft Store
//! licensing — and has nothing to do with the clipboard. Nothing here reads it.

pub mod envelope;
pub mod layout;
pub mod metadata;

use seance_core::io::read_full;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use uuid::Uuid;

const MODULE_ID: &str = "plugin.windows.clipboard";
const MODULE_VERSION: &str = "0.1.0";

/// Record type for an item's inventory entry.
const INDEX_RECORD: &str = "WindowsClipboardIndex";
/// Record type for one clipboard format of one item.
const PAYLOAD_RECORD: &str = "WindowsClipboardItem";

/// How much of a payload to read.
///
/// Only the header is needed: the content type and the protection descriptor
/// both sit ahead of the ciphertext. A pinned bitmap runs to megabytes and
/// reading it whole would buy nothing this parser can use.
const PAYLOAD_HEADER_BYTES: usize = 16 * 1024;

/// What every record says about the limits of this artifact.
///
/// Attached to each one rather than stated once, because records are read
/// individually — filtered, exported, pasted into a statement — and a caveat
/// that lives only on a summary is a caveat that will be separated from the
/// finding it qualifies.
const SCOPE_NOTE: &str = "Windows keeps most clipboard history in the clipboard service's \
     memory (cbdhsvc), where it is cleared on sign-out or restart. Only pinned items — and, \
     where clipboard sync is enabled, some history items — are written to disk. The absence \
     of an item here is therefore NOT evidence that it was never copied.";

fn artifact_path(artifact: &Artifact) -> Option<String> {
    artifact
        .metadata
        .get("path")
        .or_else(|| artifact.metadata.get("full_path"))
        .or_else(|| artifact.metadata.get("relative_path"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn is_directory(artifact: &Artifact) -> bool {
    artifact
        .metadata
        .get("is_directory")
        .and_then(|v| v.as_bool())
        == Some(true)
}

/// Timestamps the filesystem recorded for the file itself.
///
/// Carried onto the record because the folder's creation time is what dates a
/// pinned item when the inventory cannot be read — published research
/// establishes it as the pin time — and because it can be compared against the
/// inventory's own figure. Two sources agreeing is worth more than either.
fn filesystem_times(artifact: &Artifact) -> Map<String, Value> {
    let mut out = Map::new();
    for key in [
        "created",
        "created_time",
        "birth_time",
        "modified",
        "modified_time",
        "accessed",
        "accessed_time",
    ] {
        if let Some(value) = artifact.metadata.get(key) {
            if !value.is_null() {
                out.insert(key.to_string(), value.clone());
            }
        }
    }
    out
}

fn stamp(map: &mut Map<String, Value>) {
    map.insert("analysed_by".into(), json!(MODULE_ID));
    map.insert("analysed_by_version".into(), json!(MODULE_VERSION));
    map.insert("analysed_os".into(), json!("windows"));
    map.insert("scope_note".into(), json!(SCOPE_NOTE));
}

/// Parse the store inventory into one record per listed item.
fn parse_index(artifact: &Artifact, store: layout::Store, path: &str) -> Vec<Artifact> {
    let Some(data) = artifact.data.as_ref() else {
        return Vec::new();
    };
    let size = data.size().min(metadata::MAX_METADATA_BYTES);
    let mut bytes = vec![0u8; size as usize];
    let read = read_full(data.as_ref(), 0, &mut bytes);
    bytes.truncate(read);

    let Some(inventory) = metadata::parse(&bytes) else {
        // The file is where the inventory lives and could not be read as JSON.
        // Silence here would read as "this user pinned nothing", which is a
        // claim about the custodian this parser has not established.
        let mut m = Map::new();
        m.insert("type".into(), json!(INDEX_RECORD));
        m.insert("record_type".into(), json!(INDEX_RECORD));
        m.insert("name".into(), json!("Clipboard inventory (unreadable)"));
        m.insert("clipboard_store".into(), json!(store.as_str()));
        m.insert("source_path".into(), json!(path));
        m.insert("parse_failed".into(), json!(true));
        m.insert(
            "parse_failure".into(),
            json!(
                "the clipboard inventory did not parse as JSON, so the items it lists could \
                   not be enumerated; the item folders beside it are still reported \
                   individually"
            ),
        );
        stamp(&mut m);
        return vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            Value::Object(m),
        )
        .with_parent(artifact.id)];
    };

    let mut out = Vec::new();
    for item in &inventory.items {
        let mut m = Map::new();
        m.insert("type".into(), json!(INDEX_RECORD));
        m.insert("record_type".into(), json!(INDEX_RECORD));
        m.insert("subtype".into(), json!("clipboard_index_entry"));
        m.insert(
            "name".into(),
            json!(format!(
                "Clipboard item {}",
                item.id.as_deref().unwrap_or("(unidentified)")
            )),
        );
        m.insert("clipboard_store".into(), json!(store.as_str()));
        m.insert("store_meaning".into(), json!(store.meaning()));
        m.insert("source_path".into(), json!(path));
        if let Some(id) = &item.id {
            m.insert("item_id".into(), json!(id));
        }
        if let Some(source) = &item.source {
            m.insert("clipboard_source".into(), json!(source));
        }
        if let Some(ts) = &item.timestamp {
            m.insert("timestamp".into(), json!(ts.utc));
            m.insert("timestamp_field".into(), json!(ts.field));
            // How the stored number was read is itself a claim; a report that
            // cannot say which reading it made cannot be checked.
            m.insert("timestamp_interpretation".into(), json!(ts.interpretation));
        }
        m.insert("inventory_entry".into(), item.raw.clone());
        if inventory.truncated {
            m.insert("index_truncated".into(), json!(true));
        }
        stamp(&mut m);

        out.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                Value::Object(m),
            )
            .with_parent(artifact.id),
        );

        if let Some(ts) = &item.timestamp {
            out.push(timeline_event(
                artifact.case_id,
                artifact.id,
                &ts.utc,
                &format!(
                    "Clipboard item {} recorded in the {} store",
                    item.id.as_deref().unwrap_or("(unidentified)"),
                    store.as_str()
                ),
                json!({
                    "item_id": item.id,
                    "clipboard_store": store.as_str(),
                    "clipboard_source": item.source,
                    // Which inventory field the time came from, as on the
                    // index record: the first of several candidate names that
                    // held a readable time (HUNT-198).
                    "timestamp_field": ts.field,
                    "timestamp_interpretation": ts.interpretation,
                    "source_path": path,
                }),
            ));
        }
    }
    out
}

/// Describe one payload file: which format, and what its header says.
fn parse_payload(
    artifact: &Artifact,
    store: layout::Store,
    item: &str,
    format: Option<&str>,
    file_name: &str,
    path: &str,
) -> Vec<Artifact> {
    let mut head = vec![0u8; PAYLOAD_HEADER_BYTES];
    let mut byte_len = 0u64;
    if let Some(data) = artifact.data.as_ref() {
        byte_len = data.size();
        let read = read_full(data.as_ref(), 0, &mut head);
        head.truncate(read);
    } else {
        head.clear();
    }
    let env = envelope::inspect(&head);

    let mut m = Map::new();
    m.insert("type".into(), json!(PAYLOAD_RECORD));
    m.insert("record_type".into(), json!(PAYLOAD_RECORD));
    m.insert("subtype".into(), json!("clipboard_payload"));
    m.insert(
        "name".into(),
        json!(format!(
            "Clipboard {} — {}",
            format.unwrap_or("payload"),
            item
        )),
    );
    m.insert("clipboard_store".into(), json!(store.as_str()));
    m.insert("store_meaning".into(), json!(store.meaning()));
    m.insert("item_id".into(), json!(item));
    m.insert("source_path".into(), json!(path));
    // Always recorded, decoded or not: it is what is actually on the disk, and
    // an examiner working from a record must be able to find the file again.
    m.insert("payload_file_name".into(), json!(file_name));
    m.insert("payload_bytes".into(), json!(byte_len));

    match format {
        Some(f) => {
            m.insert("clipboard_format".into(), json!(f));
            if let Some(meaning) = layout::describe_format(f) {
                m.insert("format_meaning".into(), json!(meaning));
            }
        }
        None => {
            m.insert(
                "clipboard_format_note".into(),
                json!(
                    "the payload filename did not decode to a clipboard format name; \
                       Windows names these files for the format in base64, so this is either \
                       an application-registered format or not a clipboard payload"
                ),
            );
        }
    }

    m.insert(
        "content_encrypted".into(),
        json!(matches!(env, envelope::Envelope::Protected { .. })),
    );
    m.insert("payload_encoding".into(), json!(env.kind()));
    m.insert("content_statement".into(), json!(env.statement()));
    if let envelope::Envelope::Protected {
        descriptor,
        descriptor_encoding,
    } = &env
    {
        if let Some(d) = descriptor {
            m.insert("protected_to".into(), json!(d));
            // The same prefix rule the header scan admitted the descriptor
            // under, so an accepted `Sid=` always yields its SID (HUNT-198).
            if let Some(sid) = envelope::descriptor_sid(d) {
                m.insert("protected_to_sid".into(), json!(sid));
            }
            m.insert("protected_to_encoding".into(), json!(descriptor_encoding));
            // How the value was obtained travels with it. This one was found by
            // scanning the header, not by walking to a parsed field, and a
            // record that presented the two alike would overstate it.
            m.insert(
                "protected_to_recovery".into(),
                json!(
                    "recovered by scanning the blob's unencrypted header for a protection \
                       descriptor rule string, not by parsing the CMS recipient structure"
                ),
            );
        }
        m.insert(
            "decryption_requirement".into(),
            json!(
                "The payload is CMS enveloped data written by CNG DPAPI \
                   (NCryptProtectSecret). Reading it needs key material this file does not \
                   contain — the user's DPAPI master key, or the domain root key over RPC. \
                   Seance does not attempt decryption and reports no plaintext for it."
            ),
        );
    }

    let times = filesystem_times(artifact);
    if !times.is_empty() {
        m.insert("filesystem_times".into(), Value::Object(times));
    }
    stamp(&mut m);

    vec![Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(artifact.id)]
}

fn timeline_event(
    case: Uuid,
    parent: Uuid,
    timestamp: &str,
    short_desc: &str,
    details: Value,
) -> Artifact {
    let mut ev = Map::new();
    ev.insert("timestamp".into(), json!(timestamp));
    ev.insert("timestamp_desc".into(), json!("Windows Clipboard"));
    ev.insert("source_module".into(), json!(MODULE_ID));
    ev.insert("short_desc".into(), json!(short_desc));
    ev.insert("full_details".into(), json!(details.to_string()));
    Artifact::new(case, ArtifactType::TimelineEvent, None, Value::Object(ev)).with_parent(parent)
}

/// Parser for the on-disk Windows clipboard store.
pub struct ClipboardParser;

impl ForensicsModule for ClipboardParser {
    fn id(&self) -> &str {
        MODULE_ID
    }
    fn version(&self) -> &str {
        MODULE_VERSION
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if is_directory(artifact) {
            return Ok(Vec::new());
        }
        let Some(path) = artifact_path(artifact) else {
            return Ok(Vec::new());
        };
        let Some(role) = layout::classify(&path) else {
            return Ok(Vec::new());
        };
        Ok(match role {
            layout::Role::Metadata { store } => parse_index(artifact, store, &path),
            layout::Role::Payload {
                store,
                item,
                format,
                file_name,
            } => parse_payload(artifact, store, &item, format.as_deref(), &file_name, &path),
        })
    }
}

#[cfg(test)]
mod tests;
