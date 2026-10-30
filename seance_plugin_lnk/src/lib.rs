#![forbid(unsafe_code)]
#[cfg(test)]
mod tests;

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    codepage::{self, CodePage},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::io::{Cursor, Read, Seek, SeekFrom};
use tracing::{info, warn};

/// What the volume fields are, and are not.
const VOLUME_NOTE: &str = concat!(
    "The drive type, volume serial and label are what the shortcut recorded when it was ",
    "WRITTEN, not what is true now. `removable` means Windows classified the volume ",
    "removable at that moment — it is a lead towards external media, not proof the target ",
    "is on a USB stick, and a drive letter can be reused by a different volume. The serial ",
    "is the FILE SYSTEM's volume serial, which changes when the volume is reformatted; it ",
    "is not a hardware or manufacturer serial and it does not identify a physical device."
);

/// Where `shell_item_path` comes from, matching the note `seance_plugin_registry`
/// publishes alongside its own `ShellMruEntry::shell_item_path` — the same
/// reader, so the same caveat about a type this build cannot name.
const SHELL_ITEM_PATH_BASIS: &str = concat!(
    "read by walking the LinkTargetIDList's shell item ID list and taking each item's own name ",
    "out of its structure, through `seance_shell_item`. An item of a type this build does not ",
    "know appears as `UnknownType_0x<hex>` rather than as a guess, so a path may name a level ",
    "it could not read."
);

pub struct LnkParser;

impl ForensicsModule for LnkParser {
    fn id(&self) -> &str {
        "plugin.windows.lnk_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl LnkParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let mut produced_artifacts = Vec::new();

        let name = seance_core::shadow_copy::original_name(artifact)
            .unwrap_or_default()
            .to_lowercase();

        if !name.ends_with(".lnk") {
            return Ok(produced_artifacts);
        }

        info!("LnkParser processing: {}", name);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("LNK parser requires data source".to_string())
        })?;

        // Read the LNK into memory (usually small, <4KB). Cap the load so a
        // mis-detected or hostile large file cannot be pulled into RAM unbounded
        // and OOM the worker (BUG-132); real LNKs are KB-scale.
        const MAX_LNK_BYTES: u64 = 16 * 1024 * 1024;
        let declared_size = data_source.as_ref().size();
        let buffer = seance_core::io::read_capped(data_source.as_ref(), MAX_LNK_BYTES);

        // Every string in a LNK is reached by an offset into this buffer. When
        // the buffer is short of the file, those reads fall off the end and
        // return empty strings — a shortcut with a blank target reads exactly
        // like one that never had a target. Record the shortfall so the two are
        // told apart (B2-168).
        let incomplete_reason = if declared_size > MAX_LNK_BYTES {
            Some(seance_core::io::IncompleteReason::CapReached)
        } else if (buffer.len() as u64) < declared_size {
            Some(seance_core::io::IncompleteReason::ShortRead)
        } else {
            None
        };
        if let Some(reason) = incomplete_reason {
            warn!(
                "LNK '{}' (artifact {}): read {} of {} declared bytes ({}); target/argument fields may be blank because they were not read",
                name,
                artifact.id,
                buffer.len(),
                declared_size,
                reason.as_str()
            );
        }

        if buffer.len() < 76 {
            warn!(
                "LNK file too small: '{}' (artifact ID: {}, size: {} bytes, minimum: 76 bytes)",
                name,
                artifact.id,
                buffer.len()
            );
            // A file whose own length is under the header size is simply not a
            // shortcut. But if the bytes exist and we could not read them, the
            // shortcut and everything it points at is missing from the case
            // because of an I/O failure, not because it was never there.
            if let Some(reason) = incomplete_reason {
                produced_artifacts.push(unread_status_artifact(
                    artifact,
                    &name,
                    reason,
                    buffer.len(),
                    declared_size,
                ));
            }
            return Ok(produced_artifacts);
        }

        let mut reader = Cursor::new(&buffer);

        // 1. Shell Link Header
        let _header_size = reader.read_u32::<LittleEndian>()?;
        // The LinkCLSID is a full 16-byte GUID {00021401-0000-0000-C000-...}.
        // Its first 4 bytes (Data1, LE) are 0x00021401, which we use as the
        // signature check; the remaining 12 bytes must be skipped so that
        // LinkFlags and the MAC timestamps are read from their true offsets
        // (0x14, 0x1C, 0x24, 0x2C) rather than 12 bytes too early.
        let signature = reader.read_u32::<LittleEndian>()?; // 0x00021401

        if _header_size != 76 || signature != 0x00021401 {
            warn!(
                "Invalid LNK header in '{}' (artifact ID: {}): header_size={} (expected 76), signature=0x{:08X} (expected 0x00021401)",
                name, artifact.id, _header_size, signature
            );
            return Ok(produced_artifacts);
        }

        // Skip the remaining 12 bytes of the 16-byte LinkCLSID.
        reader.seek(SeekFrom::Current(12))?;

        let link_flags = reader.read_u32::<LittleEndian>()?;
        let file_attrs = reader.read_u32::<LittleEndian>()?;
        let creation_time = reader.read_u64::<LittleEndian>()?;
        let access_time = reader.read_u64::<LittleEndian>()?;
        let write_time = reader.read_u64::<LittleEndian>()?;
        let target_size = reader.read_u32::<LittleEndian>()?;
        let _icon_index = reader.read_i32::<LittleEndian>()?;
        let _show_command = reader.read_u32::<LittleEndian>()?;
        let _hot_key = reader.read_u16::<LittleEndian>()?;
        let _reserved = reader.read_u16::<LittleEndian>()?;
        let _reserved2 = reader.read_u32::<LittleEndian>()?;
        let _reserved3 = reader.read_u32::<LittleEndian>()?;

        // Flags
        let has_link_target_id_list = (link_flags & 0x01) != 0;
        let has_link_info = (link_flags & 0x02) != 0;
        let has_name = (link_flags & 0x04) != 0;
        let has_rel_path = (link_flags & 0x08) != 0;
        let has_working_dir = (link_flags & 0x10) != 0;
        let has_arguments = (link_flags & 0x20) != 0;
        let has_icon_location = (link_flags & 0x40) != 0;
        let is_unicode = (link_flags & 0x80) != 0;

        // 2. LinkTargetIDList
        //
        // Read through `seance_shell_item`, the same reader the registry
        // MRUs use, rather than only skipping past it (`ROADMAP` §5.16):
        // this is the target's folder chain, and the deepest item is the
        // one thing on the whole shortcut that carries the target's OWN
        // times rather than the shortcut file's.
        let mut shell_item_path: Vec<String> = Vec::new();
        let mut shell_item_modified: Option<String> = None;
        let mut shell_item_created: Option<String> = None;
        let mut shell_item_accessed: Option<String> = None;
        // Whether the deepest item's own structure was read (not a guess),
        // and the MFT reference where a version-7+ `BEEF0004` block carries
        // one. Same shape `ShellMruEntry` publishes — added 2026-09-18 after
        // a code review noted this record read `seance_shell_item`'s richer
        // per-item decoder (`walk_id_list_detail`) nowhere, though the
        // doc comment on `shell_item_path` already claimed field-shape parity
        // with the MRU reader.
        let mut shell_item_parsed: Option<bool> = None;
        let mut shell_item_mft_entry: Option<u64> = None;
        let mut shell_item_mft_sequence: Option<u16> = None;
        // The field was there and all zero: stated, never published as
        // entry 0 (which is `$MFT`).
        let mut shell_item_mft_reference_zero = false;
        if has_link_target_id_list {
            let list_size = reader.read_u16::<LittleEndian>()?;
            let list_start = reader.position() as usize;
            let list_end = list_start + list_size as usize;
            // A short read (the cap, or a truncated file) can leave fewer
            // bytes than IDListSize declares; when it does, the list is
            // absent from this record rather than read out of whatever
            // bytes happen to follow (`incomplete_reason` already says why).
            if let Some(list_bytes) = buffer.get(list_start..list_end) {
                let items = seance_shell_item::walk_id_list_detail(list_bytes);
                shell_item_path = items.iter().map(|item| item.name.clone()).collect();
                // The deepest item is the target itself; the ones above it
                // are the folders it sat in.
                if let Some(last) = items.last() {
                    let times = seance_shell_item::shell_item_times(&last.raw);
                    shell_item_modified = times.modified.map(|t| t.to_rfc3339());
                    shell_item_created = times.created.map(|t| t.to_rfc3339());
                    shell_item_accessed = times.accessed.map(|t| t.to_rfc3339());
                    shell_item_parsed = Some(last.parsed);
                    if let Some(mft) = &last.mft_reference {
                        shell_item_mft_entry = Some(mft.entry);
                        shell_item_mft_sequence = Some(mft.sequence);
                    }
                    shell_item_mft_reference_zero = last.mft_reference_zero;
                }
            }
            reader.seek(SeekFrom::Current(list_size as i64))?;
        }

        // 3. LinkInfo
        let mut local_base_path = String::new();
        let mut volume_id: Option<VolumeId> = None;
        // Whether any string on this record came from an ANSI byte field that
        // held a character outside ASCII, i.e. is this build's reading of those
        // bytes under an assumed code page rather than text read off the disk.
        let mut ansi_decoded = false;

        if has_link_info {
            let link_info_size = reader.read_u32::<LittleEndian>()?;
            let link_info_start = reader.position() - 4; // Start of LinkInfo
            let link_info_header_size = reader.read_u32::<LittleEndian>()?;
            let link_info_flags = reader.read_u32::<LittleEndian>()?;
            let vol_id_offset = reader.read_u32::<LittleEndian>()?;
            let local_base_path_offset = reader.read_u32::<LittleEndian>()?;
            let cn_rel_link_offset = reader.read_u32::<LittleEndian>()?;
            let common_path_suffix_offset = reader.read_u32::<LittleEndian>()?;

            // The Unicode path offsets only exist when the LinkInfo header is
            // >= 0x24 (MS-SHLLINK 2.3); ANSI-only LinkInfo omits them.
            let (local_base_path_offset_unicode, common_path_suffix_offset_unicode) =
                if link_info_header_size >= 0x24 {
                    let lbp_u = reader.read_u32::<LittleEndian>()?;
                    let cps_u = reader.read_u32::<LittleEndian>()?;
                    (lbp_u, cps_u)
                } else {
                    (0u32, 0u32)
                };

            let has_volume_id_local_base = (link_info_flags & 0x01) != 0;
            let has_common_network_relative = (link_info_flags & 0x02) != 0;

            // The volume the target sat on, when the shortcut says it had one.
            if has_volume_id_local_base && vol_id_offset != 0 {
                volume_id = read_volume_id(&buffer, link_info_start + vol_id_offset as u64);
            }

            // Base path: the local volume path, or the network share (NetName,
            // e.g. \\server\share) for a remote target. Prefer the Unicode form.
            let (base, base_decoded) = if has_volume_id_local_base {
                if local_base_path_offset_unicode != 0 {
                    (
                        read_utf16z_at(
                            &buffer,
                            link_info_start + local_base_path_offset_unicode as u64,
                        ),
                        false,
                    )
                } else if local_base_path_offset != 0 {
                    read_ansiz_at(&buffer, link_info_start + local_base_path_offset as u64)
                } else {
                    (String::new(), false)
                }
            } else if has_common_network_relative && cn_rel_link_offset != 0 {
                read_common_network_relative_link(
                    &buffer,
                    link_info_start + cn_rel_link_offset as u64,
                )
            } else {
                (String::new(), false)
            };

            // CommonPathSuffix completes the target path (again Unicode-first).
            let (suffix, suffix_decoded) = if common_path_suffix_offset_unicode != 0 {
                (
                    read_utf16z_at(
                        &buffer,
                        link_info_start + common_path_suffix_offset_unicode as u64,
                    ),
                    false,
                )
            } else if common_path_suffix_offset != 0 {
                read_ansiz_at(&buffer, link_info_start + common_path_suffix_offset as u64)
            } else {
                (String::new(), false)
            };
            ansi_decoded |= base_decoded || suffix_decoded;

            // The full target path is base (LocalBasePath or NetName) followed
            // by CommonPathSuffix. Join with a single separator only when both
            // sides are present and neither already provides one.
            local_base_path = join_link_path(&base, &suffix);

            reader.set_position(link_info_start + link_info_size as u64);
        }

        // 4. String Data
        let mut rel_path = String::new();
        let mut working_dir = String::new();
        let mut args = String::new();
        let mut icon_loc = String::new();

        if has_name {
            // NAME_STRING is read only to advance the cursor to the fields that
            // follow; it is not emitted, so its decoding is not stamped.
            let (_name_str, _) = read_string_data(&mut reader, is_unicode)?;
        }
        if has_rel_path {
            let (value, decoded) = read_string_data(&mut reader, is_unicode)?;
            rel_path = value;
            ansi_decoded |= decoded;
        }
        if has_working_dir {
            let (value, decoded) = read_string_data(&mut reader, is_unicode)?;
            working_dir = value;
            ansi_decoded |= decoded;
        }
        if has_arguments {
            let (value, decoded) = read_string_data(&mut reader, is_unicode)?;
            args = value;
            ansi_decoded |= decoded;
        }
        if has_icon_location {
            let (value, decoded) = read_string_data(&mut reader, is_unicode)?;
            icon_loc = value;
            ansi_decoded |= decoded;
        }

        // Create ParsedRecord Artifact. Target MAC timestamps are omitted (not
        // stored as an empty string) when the FILETIME is the 0/unset or
        // pre-epoch sentinel, so an unset value is never surfaced as a date.
        let mut metadata = serde_json::Map::new();
        metadata.insert("type".to_string(), json!("LnkFile"));
        metadata.insert(
            "target_local_path".to_string(),
            json!(local_base_path.clone()),
        );
        metadata.insert("relative_path".to_string(), json!(rel_path.clone()));
        metadata.insert("arguments".to_string(), json!(args));
        metadata.insert("working_dir".to_string(), json!(working_dir));
        metadata.insert("icon_location".to_string(), json!(icon_loc));
        if let Some(ts) = seance_core::time::filetime_to_rfc3339(creation_time) {
            metadata.insert("target_created".to_string(), json!(ts));
        }
        if let Some(ts) = seance_core::time::filetime_to_rfc3339(access_time) {
            metadata.insert("target_accessed".to_string(), json!(ts));
        }
        if let Some(ts) = seance_core::time::filetime_to_rfc3339(write_time) {
            metadata.insert("target_modified".to_string(), json!(ts));
        }
        metadata.insert("flags".to_string(), json!(link_flags));
        metadata.insert("attributes".to_string(), json!(file_attrs));
        // The target's size as the shortcut recorded it. A `u32`, so a target
        // over 4 GiB is recorded modulo 2^32 by the format itself — which is
        // why this is the shortcut's figure and not the file's.
        metadata.insert("target_size_recorded".to_string(), json!(target_size));

        // What the shortcut recorded about the volume the target sat on.
        if let Some(vol) = &volume_id {
            metadata.insert("drive_type".to_string(), json!(vol.drive_type));
            match drive_type_name(vol.drive_type) {
                Some(word) => {
                    metadata.insert("drive_type_name".to_string(), json!(word));
                }
                // A code this build has not been shown is reported as the
                // number, not mapped onto a nearby word.
                None => {
                    metadata.insert("drive_type_name_known".to_string(), json!(false));
                }
            }
            // Rendered the way Windows shows a volume serial, because that is
            // the form an examiner will be comparing against.
            metadata.insert(
                "volume_serial".to_string(),
                json!(format!(
                    "{:04X}-{:04X}",
                    (vol.serial >> 16) & 0xFFFF,
                    vol.serial & 0xFFFF
                )),
            );
            if !vol.label.is_empty() {
                metadata.insert("volume_label".to_string(), json!(vol.label));
            }
            metadata.insert("volume_note".to_string(), json!(VOLUME_NOTE));
            ansi_decoded |= vol.label_ansi_decoded;
        }
        // A shortcut written without the Unicode flag stores its target path and
        // string data as raw ANSI bytes with no encoding declaration. When one
        // of those fields held a byte outside ASCII, the strings above are this
        // build's reading of the bytes under an assumed code page, not text read
        // off the disk: the same bytes on a machine running a Cyrillic or
        // Japanese ANSI code page name a different file. Say which table was
        // used so the path is not quoted as literal.
        if ansi_decoded {
            metadata.insert("path_decode".to_string(), json!(CodePage::Cp1252.name()));
        }
        // The names the LinkTargetIDList's shell item ID list encodes, read
        // through the format and not out of an offset skip. Same field
        // names and shapes as `ShellMruEntry` in `seance_plugin_registry`,
        // so a viewer built for one reads the other (`ROADMAP` §5.16).
        if !shell_item_path.is_empty() {
            metadata.insert("shell_item_path".to_string(), json!(shell_item_path));
            metadata.insert("shell_item_name".to_string(), json!(shell_item_path.last()));
            metadata.insert(
                "shell_item_path_basis".to_string(),
                json!(SHELL_ITEM_PATH_BASIS),
            );
            // Per item, not a blanket flag: true only where the deepest
            // item's own structure was actually read, matching
            // `ShellMruEntry::shell_item_parsed`'s contract exactly.
            if let Some(parsed) = shell_item_parsed {
                metadata.insert("shell_item_parsed".to_string(), json!(parsed));
            }
            if let Some(entry) = shell_item_mft_entry {
                metadata.insert("shell_item_mft_entry".to_string(), json!(entry));
            }
            if let Some(sequence) = shell_item_mft_sequence {
                metadata.insert("shell_item_mft_sequence".to_string(), json!(sequence));
            }
            if shell_item_mft_reference_zero {
                metadata.insert(
                    "shell_item_mft_reference_note".to_string(),
                    json!(seance_shell_item::MFT_REFERENCE_ZERO_NOTE),
                );
            }
        }
        for (key, value) in [
            ("shell_item_modified", &shell_item_modified),
            ("shell_item_created", &shell_item_created),
            ("shell_item_accessed", &shell_item_accessed),
        ] {
            if let Some(t) = value {
                metadata.insert(key.to_string(), json!(t));
            }
        }
        if shell_item_modified.is_some()
            || shell_item_created.is_some()
            || shell_item_accessed.is_some()
        {
            // These belong to the deepest shell item — the target — not to
            // the shortcut file, and they are FAT pairs: local wall-clock
            // with no recorded zone, like every shell-item time.
            metadata.insert(
                "shell_item_time_scope".to_string(),
                json!("the deepest shell item"),
            );
            metadata.insert("shell_item_timezone".to_string(), json!("local"));
            metadata.insert(
                "shell_item_time_note".to_string(),
                json!(seance_shell_item::FAT_TIME_NOTE),
            );
        }
        if let Some(reason) = incomplete_reason {
            metadata.insert("content_incomplete".to_string(), json!(true));
            metadata.insert(
                "content_incomplete_reason".to_string(),
                json!(reason.as_str()),
            );
            metadata.insert("bytes_read".to_string(), json!(buffer.len()));
            metadata.insert("declared_size".to_string(), json!(declared_size));
        }

        let parsed_artifact = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::Value::Object(metadata),
        )
        .with_parent(artifact.id);

        produced_artifacts.push(parsed_artifact);

        // Generate TimelineEvent artifacts for file access/modification timestamps
        let target_path = if !local_base_path.is_empty() {
            local_base_path.clone()
        } else if !rel_path.is_empty() {
            rel_path.clone()
        } else {
            name.clone()
        };

        // Creation time event
        if let Some(ts) = seance_core::time::filetime_to_rfc3339(creation_time) {
            let timeline_event = Artifact::new(
                artifact.case_id,
                ArtifactType::TimelineEvent,
                None,
                json!({
                    "timestamp": ts,
                    "timestamp_desc": "LNK Target Created",
                    "short_desc": format!("File created: {}", target_path),
                    "description": format!("LNK file indicates target was created: {}", target_path),
                    "source_module": "plugin.windows.lnk_parser",
                    "target_path": target_path,
                    "lnk_source": name
                })
            ).with_parent(artifact.id);
            produced_artifacts.push(timeline_event);
        }

        // Access time event
        if let Some(ts) = seance_core::time::filetime_to_rfc3339(access_time) {
            let timeline_event = Artifact::new(
                artifact.case_id,
                ArtifactType::TimelineEvent,
                None,
                json!({
                    "timestamp": ts,
                    "timestamp_desc": "LNK Target Accessed",
                    "short_desc": format!("File accessed: {}", target_path),
                    "description": format!("LNK file indicates target was accessed: {}", target_path),
                    "source_module": "plugin.windows.lnk_parser",
                    "target_path": target_path,
                    "lnk_source": name
                })
            ).with_parent(artifact.id);
            produced_artifacts.push(timeline_event);
        }

        // Modification time event
        if let Some(ts) = seance_core::time::filetime_to_rfc3339(write_time) {
            let timeline_event = Artifact::new(
                artifact.case_id,
                ArtifactType::TimelineEvent,
                None,
                json!({
                    "timestamp": ts,
                    "timestamp_desc": "LNK Target Modified",
                    "short_desc": format!("File modified: {}", target_path),
                    "description": format!("LNK file indicates target was modified: {}", target_path),
                    "source_module": "plugin.windows.lnk_parser",
                    "target_path": target_path,
                    "lnk_source": name
                })
            ).with_parent(artifact.id);
            produced_artifacts.push(timeline_event);
        }

        Ok(produced_artifacts)
    }
}

/// The record that says a `.lnk` exists in the evidence but its bytes were not
/// read, so nothing about its target reached the case.
///
/// Forensic meaning: a shortcut proves a file was opened from this machine. Its
/// silent absence reads as "no such file was ever opened"; this record makes the
/// difference visible (B2-168).
fn unread_status_artifact(
    source: &Artifact,
    name: &str,
    reason: seance_core::io::IncompleteReason,
    bytes_read: usize,
    declared_size: u64,
) -> Artifact {
    Artifact::new(
        source.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "LnkParseStatus",
            "record_type": "lnk_parse_status",
            "name": format!("{} (not parsed)", name),
            "content_incomplete": true,
            "content_incomplete_reason": reason.as_str(),
            "bytes_read": bytes_read,
            "declared_size": declared_size,
            "message": "This shortcut's bytes could not be read in full, so its target, \
                        arguments and target timestamps are absent from this case; that \
                        absence is not evidence that the shortcut pointed nowhere",
        }),
    )
    .with_parent(source.id)
}

/// Read a LNK StringData item, returning the text and whether a non-ASCII byte
/// had to be interpreted through the ANSI code page.
///
/// A shortcut written without the Unicode flag stores these fields (relative
/// path, working directory, arguments) as Windows ANSI bytes, not UTF-8. The
/// old `String::from_utf8_lossy` turned every byte 0x80-0xFF into U+FFFD, so a
/// working directory of `D:\Beweismittel\Müller` was reported as
/// `D:\Beweismittel\M\u{FFFD}ller` and command-line arguments naming an
/// accented file were mangled past recognition -- the examiner then searches
/// for a directory that never existed and finds nothing.
fn read_string_data(
    reader: &mut Cursor<&Vec<u8>>,
    unicode: bool,
) -> Result<(String, bool), std::io::Error> {
    let char_count = reader.read_u16::<LittleEndian>()?;
    if char_count == 0 {
        return Ok((String::new(), false));
    }

    if unicode {
        let mut u16s = Vec::with_capacity(char_count as usize);
        for _ in 0..char_count {
            u16s.push(reader.read_u16::<LittleEndian>()?);
        }
        Ok((String::from_utf16_lossy(&u16s), false))
    } else {
        let mut bytes = vec![0u8; char_count as usize];
        reader.read_exact(&mut bytes)?;
        Ok(codepage::decode(&bytes, CodePage::Cp1252))
    }
}

/// Join a base path (LocalBasePath or a network NetName) with CommonPathSuffix.
/// A single `\` is inserted only when both parts are non-empty and neither
/// already carries the separator, so no spurious separator is fabricated.
fn join_link_path(base: &str, suffix: &str) -> String {
    if base.is_empty() {
        return suffix.to_string();
    }
    if suffix.is_empty() {
        return base.to_string();
    }
    if base.ends_with('\\') || suffix.starts_with('\\') {
        format!("{base}{suffix}")
    } else {
        format!("{base}\\{suffix}")
    }
}

/// Read a null-terminated ANSI string from `buffer` at absolute byte `offset`,
/// returning the text and whether a non-ASCII byte had to be interpreted
/// through the ANSI code page.
/// Out-of-bounds or unterminated reads yield the available bytes (or empty).
///
/// These bytes are Windows ANSI (CP1252 on a Western install), and they carry
/// the target path itself -- LocalBasePath, CommonPathSuffix and the network
/// NetName. Reading them as UTF-8 replaced every accented byte with U+FFFD, so
/// a shortcut proving a user opened `\\fileserver\Röntgen\scan.pdf` reported a
/// share and a file that match nothing an examiner can search for.
/// What a shortcut recorded about the volume its target sat on.
///
/// `MS-SHLLINK` 2.3.1. Read at last: the structure's offset used to be read
/// only to step past it, so **no drive type, volume serial or label reached
/// the case** — and `WINDOWS_DESIGN.md` claimed all three. Drive type is how
/// an examiner says "the target was on removable media".
#[derive(Debug, Clone, PartialEq, Eq)]
struct VolumeId {
    /// The `DriveType` code, as the file holds it.
    drive_type: u32,
    /// The **volume** serial number — the one a file system carries and that
    /// changes when the volume is reformatted. Not a hardware serial.
    serial: u32,
    /// The volume label, where the shortcut recorded one.
    label: String,
    /// True when the label came from an ANSI byte field holding a character
    /// outside ASCII, so it is this build's reading under an assumed code page.
    label_ansi_decoded: bool,
}

/// `DriveType` in words, or `None` for a value this build has not been shown.
fn drive_type_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0 => "unknown",
        1 => "no_root_directory",
        2 => "removable",
        3 => "fixed",
        4 => "remote",
        5 => "cdrom",
        6 => "ramdisk",
        _ => return None,
    })
}

/// Read the `VolumeID` structure at `offset`.
///
/// Returns `None` when the declared size cannot hold the fixed fields, which
/// is the only thing that makes the rest of the structure addressable —
/// reading it anyway would publish a drive type out of whatever bytes follow.
fn read_volume_id(buffer: &[u8], offset: u64) -> Option<VolumeId> {
    let at = usize::try_from(offset).ok()?;
    let le = |i: usize| -> Option<u32> {
        let s = buffer.get(at + i..at + i + 4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    let size = le(0)? as usize;
    // 0x10 is the smallest a `VolumeID` can be: the four fixed `u32`s.
    if size < 0x10 || at.checked_add(size)? > buffer.len() {
        return None;
    }
    let drive_type = le(4)?;
    let serial = le(8)?;
    let label_offset = le(12)? as usize;
    // 0x14 in `VolumeLabelOffset` is the sentinel meaning "the label is
    // Unicode and its offset is the next field".
    let (label, label_ansi_decoded) = if label_offset == 0x14 {
        let unicode_offset = le(16)? as usize;
        if unicode_offset == 0 || unicode_offset >= size {
            (String::new(), false)
        } else {
            (
                read_utf16z_at(buffer, offset + unicode_offset as u64),
                false,
            )
        }
    } else if label_offset >= 0x10 && label_offset < size {
        read_ansiz_at(buffer, offset + label_offset as u64)
    } else {
        (String::new(), false)
    };
    Some(VolumeId {
        drive_type,
        serial,
        label,
        label_ansi_decoded,
    })
}

fn read_ansiz_at(buffer: &[u8], offset: u64) -> (String, bool) {
    let offset = offset as usize;
    if offset >= buffer.len() {
        return (String::new(), false);
    }
    let end = buffer[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(buffer.len());
    codepage::decode(&buffer[offset..end], CodePage::Cp1252)
}

/// Read a null-terminated UTF-16LE string from `buffer` at absolute byte `offset`.
fn read_utf16z_at(buffer: &[u8], offset: u64) -> String {
    let mut i = offset as usize;
    let mut units = Vec::new();
    while i + 1 < buffer.len() {
        let u = u16::from_le_bytes([buffer[i], buffer[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

/// Extract the NetName (e.g. `\\server\share`) from a CommonNetworkRelativeLink
/// structure located at absolute byte `start` (MS-SHLLINK 2.3.2). Prefers the
/// Unicode NetName when the structure advertises one (NetNameOffset > 0x14).
/// The second value says whether the ANSI form had to be interpreted through a
/// code page; the Unicode form assumes nothing.
fn read_common_network_relative_link(buffer: &[u8], start: u64) -> (String, bool) {
    let start = start as usize;
    // Need at least through NetNameOffset (bytes 0x08..0x0C).
    if start + 0x0C > buffer.len() {
        return (String::new(), false);
    }
    let net_name_offset = u32::from_le_bytes([
        buffer[start + 8],
        buffer[start + 9],
        buffer[start + 10],
        buffer[start + 11],
    ]) as u64;
    if net_name_offset == 0 {
        return (String::new(), false);
    }
    // A Unicode NetName exists only when NetNameOffset > 0x14; its own offset is
    // stored at CommonNetworkRelativeLink+0x14.
    if net_name_offset > 0x14 && start + 0x18 <= buffer.len() {
        let net_name_offset_unicode = u32::from_le_bytes([
            buffer[start + 0x14],
            buffer[start + 0x15],
            buffer[start + 0x16],
            buffer[start + 0x17],
        ]) as u64;
        if net_name_offset_unicode != 0 {
            return (
                read_utf16z_at(buffer, start as u64 + net_name_offset_unicode),
                false,
            );
        }
    }
    read_ansiz_at(buffer, start as u64 + net_name_offset)
}
