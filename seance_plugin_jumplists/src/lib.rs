#![forbid(unsafe_code)]
//! Windows jump lists.
//!
//! An `automaticDestinations-ms` file is an OLE compound file. Its directory
//! names one stream per destination, numbered in hex, each holding a
//! shortcut (MS-SHLLINK), and a `DestList` stream that is the jump list's
//! own record of those destinations: their order (most recently used first,
//! by observation of real files — the format documentation does not state
//! it), the time each was last recorded, whether it is pinned and — on
//! Windows 10 and later — a 32-bit field the documentation leaves unknown,
//! possibly an access count, reported under that name and no other. This
//! module reads the directory and
//! `DestList` first, and hands each shortcut stream on to the shortcut
//! reader with the `DestList` entry it belongs to written beside it. Where
//! the directory cannot be followed it falls back to scanning the bytes for
//! the shortcut signature, and every shortcut says which of the two ways it
//! was found. A `customDestinations-ms` file has no directory and is only
//! scanned.
//!
//! The hex digits in front of the extension are the AppID of the program
//! that wrote the list; `appid` resolves the ones this build can name and
//! reports every other one as unknown.

pub mod appid;
pub mod destlist;
pub mod free_sectors;
pub mod ole;

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_capped, read_exact_or_fail, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use tracing::{info, warn};

/// The OLE compound-file signature, in full.
///
/// All eight bytes are checked. An earlier reading compared only the first
/// four while its own comment claimed the eight, so any file opening
/// `D0 CF 11 E0` was accepted and scanned.
const OLE_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Maximum number of LNK entries to carve from a single JumpList file.
/// Prevents unbounded memory/CPU usage from pathological OLE files.
const MAX_CARVED_LINKS: usize = 10_000;

/// Upper bound on how much of a JumpList file is buffered into RAM for carving.
/// Real JumpLists are KB-to-MB; a hostile/corrupt size would otherwise allocate
/// unbounded memory and OOM the worker. 256 MiB is far beyond any legitimate file.
const MAX_JUMPLIST_BYTES: u64 = 256 * 1024 * 1024;

const MODULE_ID: &str = "plugin.windows.jumplist_parser";

const LNK_SIGNATURE: [u8; 8] = [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];

pub struct JumpListParser;

/// Which application the jump list's file name says wrote it.
struct Attribution {
    app_id: Option<String>,
    app: Option<&'static appid::KnownApp>,
}

impl Attribution {
    fn from_file_name(name: &str) -> Self {
        let app_id = appid::app_id_from_file_name(name);
        let app = app_id.as_deref().and_then(appid::resolve);
        Attribution { app_id, app }
    }

    fn application_label(&self) -> &str {
        self.app
            .map(|a| a.application)
            .unwrap_or("an application this build cannot name")
    }

    fn write(&self, m: &mut Map<String, Value>) {
        match &self.app_id {
            Some(id) => {
                m.insert("app_id".into(), json!(id));
            }
            None => {
                m.insert(
                    "app_id_unavailable".into(),
                    json!("the file name does not carry an AppID in front of the extension"),
                );
            }
        }
        match self.app {
            Some(app) => {
                m.insert("application".into(), json!(app.application));
                m.insert("application_identifier".into(), json!(app.identifier));
                m.insert("application_basis".into(), json!(app.basis.describe()));
            }
            None => {
                m.insert("application".into(), Value::Null);
                m.insert(
                    "application_unknown".into(),
                    json!(
                        "this AppID is not one this build can name; the application that wrote \
                         this jump list is not established"
                    ),
                );
            }
        }
    }
}

/// What a signature scan of a buffer found and where it stopped.
struct Carve {
    shortcuts: Vec<Artifact>,
    stopped: Option<&'static str>,
    /// How many bytes from the start of the buffer the scan examined: the
    /// whole buffer, unless the link cap stopped it.
    bytes_scanned: usize,
}

/// One reason the record of a jump list is not the whole of it.
struct Shortfall {
    reason: IncompleteReason,
    detail: String,
}

impl ForensicsModule for JumpListParser {
    fn id(&self) -> &str {
        MODULE_ID
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

impl JumpListParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // A prior version is selected, and its application attributed, by the
        // file's own name; its `name` carries a `[shadow copy …]` label.
        let name = seance_core::shadow_copy::original_name(artifact).unwrap_or_default();

        // Case-insensitively, as the LNK and shellbag parsers already match
        // theirs. NTFS is case-insensitive and a file named
        // `.AutomaticDestinations-ms` or `.automaticdestinations-ms` — as a
        // copy tool, an export, or a case-folding filesystem can spell it — is
        // the same artifact; matched by exact case, every jump list in such an
        // acquisition was silently skipped and the case recovered none.
        let lower = name.to_ascii_lowercase();
        let is_auto = lower.ends_with(".automaticdestinations-ms");
        let is_custom = lower.ends_with(".customdestinations-ms");

        if !is_auto && !is_custom {
            return Ok(Vec::new());
        }

        info!("JumpListParser processing: {}", name);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("JumpList parser requires data source".to_string())
        })?;
        let attribution = Attribution::from_file_name(name);

        if is_auto {
            return Ok(process_automatic(
                artifact,
                name,
                &**data_source,
                &attribution,
                ole::Caps::default(),
            ));
        }

        // CustomDestinations: a header, then shortcut structures in sequence.
        // The signature scan is the reading; there is no directory to consult.
        let mut produced = Vec::new();
        let full_data = read_capped(&**data_source, MAX_JUMPLIST_BYTES);
        let staged_short = staged_shortfall(&full_data, &**data_source);
        let carve = carve_shortcuts(artifact, name, &full_data, "entry", &attribution, None);
        let stopped = carve.stopped.or(staged_short);
        produced.extend(carve.shortcuts);
        finish_carve(
            &mut produced,
            artifact,
            name,
            stopped,
            false,
            carve.bytes_scanned,
        );
        Ok(produced)
    }
}

/// Why the staged read fell short of the source's declared size, if it did.
fn staged_shortfall(full_data: &[u8], data_source: &dyn DataSource) -> Option<&'static str> {
    if (full_data.len() as u64) < data_source.size() {
        // A file larger than the buffer cap and a source that stopped
        // early call for different follow-up.
        Some(if data_source.size() > MAX_JUMPLIST_BYTES {
            IncompleteReason::CapReached.as_str()
        } else {
            IncompleteReason::ShortRead.as_str()
        })
    } else {
        None
    }
}

fn process_automatic(
    artifact: &Artifact,
    name: &str,
    data_source: &dyn DataSource,
    attribution: &Attribution,
    caps: ole::Caps,
) -> Vec<Artifact> {
    let mut produced = Vec::new();

    // Read the 512-byte OLE header, looping so a chunked / short-reading
    // source still fills it: a single read_at may return fewer bytes, and
    // a valid OLE jumplist read in small chunks must not be rejected here
    // as "too short" before the carve even runs (BUG-065).
    //
    // A file too short to hold the header is still scanned. It used to
    // return here, so a jump list recovered from a fragment gave a shortfall
    // record and no shortcuts — even though the signature scan works on
    // whatever bytes are present, and a shortcut found in them is a real
    // shortcut. What is lost is the corroboration that the container is an
    // OLE compound file, and that is said on the record rather than being
    // turned into silence.
    let mut header = [0u8; 512];
    let header_short =
        read_exact_or_fail(data_source, 0, &mut header, "OLE jumplist header").is_err();
    if header_short {
        warn!(
            "JumpList {}: fewer than 512 bytes, so the OLE signature could not be \
             checked; scanning what is there",
            name
        );
    }

    // The whole eight-byte OLE compound-file signature, not the first four.
    // Checking four accepted a file opening `D0 CF 11 E0` with any second
    // half — and then reported a byte-scan carve over it as a jump list,
    // while the comment beside the check claimed all eight were tested.
    // Skipped when the header could not be filled: a fragment has no
    // signature to check, and refusing it for failing a check that was never
    // made is the same error in the other direction.
    if !header_short && header.get(..OLE_SIGNATURE.len()) != Some(&OLE_SIGNATURE[..]) {
        warn!(
            "JumpList {}: no OLE compound-file signature; nothing carved",
            name
        );
        produced.push(carve_status_artifact(
            artifact,
            name,
            Some(IncompleteReason::UnresolvedStructure.as_str()),
            0,
            0,
            "This file is named as an automaticDestinations JumpList but does not \
             begin with the eight-byte OLE compound-file signature, so no shortcuts \
             were carved from it",
        ));
        return produced;
    }

    // The shared capped read bounds the allocation (a hostile/corrupt size
    // must not OOM the worker) and returns only the bytes actually read, so
    // neither the directory walk nor the scan touches a fabricated zero tail.
    let full_data = read_capped(data_source, MAX_JUMPLIST_BYTES);
    let staged_short = staged_shortfall(&full_data, data_source);

    let directory = if header_short {
        Err("fewer than the 512 bytes an OLE header occupies could be read".to_string())
    } else {
        ole::read(&full_data, caps)
    };

    match directory {
        Ok(streams) => {
            produced.extend(publish_directory(
                artifact,
                name,
                &full_data,
                streams,
                attribution,
                staged_short,
                caps,
            ));
        }
        Err(error) => {
            // The container cannot be followed. The bytes are scanned for the
            // shortcut signature instead, and every shortcut so found says
            // so: nothing ties it to a DestList entry, and nothing says
            // whether the sectors it lay in were still referenced.
            warn!(
                "JumpList {}: OLE directory could not be read ({}); carving by signature",
                name, error
            );
            let carve = carve_shortcuts(
                artifact,
                name,
                &full_data,
                "stream",
                attribution,
                Some(&error),
            );
            let links = carve.shortcuts.len();
            let bytes_scanned = carve.bytes_scanned;
            let stopped = carve.stopped.or(staged_short);
            produced.extend(carve.shortcuts);
            let detail = format!(
                "The OLE compound-file directory of this jump list could not be read ({error}), \
                 so the DestList stream — the list's own record of each entry's \
                 most-recently-used position, recorded time and pin state — could not be \
                 looked for, and the {links} shortcut(s) reported were found by scanning the \
                 bytes for the shortcut signature (a carve). A carved shortcut cannot be tied \
                 to a DestList entry, and a live stream cannot be told from a freed one."
            );
            let mut m = Map::new();
            m.insert("ole_directory_read".into(), json!(false));
            m.insert("ole_directory_error".into(), json!(error));
            // Null, not false: the directory was never read, so whether a
            // DestList exists is not established.
            m.insert("dest_list_present".into(), Value::Null);
            m.insert(
                "dest_list_present_note".into(),
                json!(
                    "the OLE directory could not be read, so whether a DestList stream \
                       exists is not established"
                ),
            );
            m.insert("lnk_streams_in_directory".into(), Value::Null);
            m.insert("lnk_streams_read".into(), json!(0));
            m.insert("shortcuts_carved".into(), json!(links));
            m.insert("recovery_method".into(), json!("signature_carve"));
            produced.push(dest_list_summary_artifact(
                artifact,
                name,
                attribution,
                m,
                vec![Shortfall {
                    reason: IncompleteReason::UnresolvedStructure,
                    detail,
                }],
            ));
            finish_carve(
                &mut produced,
                artifact,
                name,
                stopped,
                header_short,
                bytes_scanned,
            );
        }
    }
    produced
}

/// The directory could be followed: publish the shortcut streams, the
/// DestList entries and the summary that accounts for all of them.
fn publish_directory(
    artifact: &Artifact,
    name: &str,
    full_data: &[u8],
    streams: ole::JumpListStreams,
    attribution: &Attribution,
    staged_short: Option<&'static str>,
    caps: ole::Caps,
) -> Vec<Artifact> {
    let mut produced = Vec::new();
    let mut shortfalls: Vec<Shortfall> = Vec::new();
    if let Some(reason) = staged_short {
        shortfalls.push(Shortfall {
            reason: if reason == IncompleteReason::CapReached.as_str() {
                IncompleteReason::CapReached
            } else {
                IncompleteReason::ShortRead
            },
            detail: format!(
                "Only {} of the {} bytes the source declares were staged, so the directory was \
                 read from a partial copy of the file: streams lying past that point could not \
                 be read.",
                full_data.len(),
                artifact
                    .data
                    .as_ref()
                    .map(|d| d.size())
                    .unwrap_or(full_data.len() as u64)
            ),
        });
    }

    // The DestList stream.
    let mut dest_list: Option<destlist::DestList> = None;
    let mut summary = Map::new();
    summary.insert("ole_directory_read".into(), json!(true));
    summary.insert("recovery_method".into(), json!("ole_directory"));
    summary.insert(
        "lnk_streams_in_directory".into(),
        json!(streams.lnk_streams_in_directory),
    );
    summary.insert(
        "other_directory_entries".into(),
        json!(streams.other_entries),
    );
    match &streams.dest_list {
        None => {
            summary.insert("dest_list_present".into(), json!(false));
            shortfalls.push(Shortfall {
                reason: IncompleteReason::UnresolvedStructure,
                detail: "The directory names no DestList stream, so the list's own record of \
                         its entries — most-recently-used order, recorded times and pin \
                         state — is absent. The shortcut streams are reported on their own."
                    .to_string(),
            });
        }
        Some(stream) => {
            summary.insert("dest_list_present".into(), json!(true));
            summary.insert("dest_list_declared_len".into(), json!(stream.declared_len));
            if let Some(why) = &stream.unavailable {
                let reason = if why.contains("ceiling") {
                    IncompleteReason::CapReached
                } else {
                    IncompleteReason::ShortRead
                };
                shortfalls.push(Shortfall {
                    reason,
                    detail: format!(
                        "The DestList stream was not read in full: {why}. Whatever was read is \
                         decoded below; entries past that point are absent."
                    ),
                });
            }
            if stream.declared_len == 0 && stream.bytes.is_empty() {
                // Windows writes an empty DestList for a jump list with no
                // entries; that is a finding, not a shortfall.
                summary.insert("dest_list_empty".into(), json!(true));
            } else {
                match destlist::parse(&stream.bytes) {
                    Ok(dl) => dest_list = Some(dl),
                    Err(e) => shortfalls.push(Shortfall {
                        reason: IncompleteReason::UnresolvedStructure,
                        detail: format!(
                            "The DestList stream could not be decoded: {e}. Its entries are \
                             absent and the shortcut streams are reported on their own."
                        ),
                    }),
                }
            }
        }
    }

    if let Some(dl) = &dest_list {
        summary.insert(
            "dest_list_format_version".into(),
            json!(dl.header.format_version),
        );
        summary.insert("dest_list_layout".into(), json!(dl.layout.label()));
        summary.insert(
            "entries_declared".into(),
            json!(dl.header.number_of_entries),
        );
        summary.insert(
            "pinned_entries_declared".into(),
            json!(dl.header.number_of_pinned_entries),
        );
        summary.insert(
            "last_entry_number".into(),
            json!(dl.header.last_entry_number),
        );
        summary.insert(
            "last_revision_number".into(),
            json!(dl.header.last_revision_number),
        );
        summary.insert("entries_read".into(), json!(dl.entries.len()));
        match &dl.stopped {
            Some(destlist::Stop::Truncated {
                offset,
                needed,
                available,
            }) => shortfalls.push(Shortfall {
                reason: IncompleteReason::UnresolvedStructure,
                detail: format!(
                    "The DestList entry at offset {offset} needs {needed} bytes and {available} \
                     remain in the stream, so decoding stopped there with {} entries read of \
                     the {} the header declares.",
                    dl.entries.len(),
                    dl.header.number_of_entries
                ),
            }),
            Some(destlist::Stop::EntryCap { cap }) => shortfalls.push(Shortfall {
                reason: IncompleteReason::CapReached,
                detail: format!(
                    "Decoding stopped at this build's ceiling of {cap} DestList entries; the \
                     header declares {}.",
                    dl.header.number_of_entries
                ),
            }),
            None => {
                if dl.entries.len() as u64 != dl.header.number_of_entries as u64 {
                    summary.insert(
                        "entry_count_note".into(),
                        json!(format!(
                            "the header declares {} entries and the stream holds {}; both are \
                             reported as read",
                            dl.header.number_of_entries,
                            dl.entries.len()
                        )),
                    );
                }
            }
        }
    }

    // The shortcut streams, each tied to its DestList entry by number.
    let entry_for = |stream_name: &str| -> Option<&destlist::DestListEntry> {
        let n = ole::lnk_stream_number(stream_name)?;
        dest_list
            .as_ref()?
            .entries
            .iter()
            .find(|e| e.entry_number == n)
    };
    let candidates = lnk_signature_offsets(full_data);
    let mut streams_read = 0usize;
    let mut streams_unread: Vec<Value> = Vec::new();
    let mut streams_without_entry: Vec<String> = Vec::new();
    let mut stream_names_read: Vec<String> = Vec::new();
    for stream in &streams.lnk_streams {
        if stream.bytes.is_empty() {
            let why = stream
                .unavailable
                .clone()
                .unwrap_or_else(|| format!("stream `{}` is empty", stream.name));
            streams_unread.push(json!({ "stream_name": stream.name, "reason": why }));
            continue;
        }
        streams_read += 1;
        stream_names_read.push(stream.name.clone());
        let entry = entry_for(&stream.name);
        if entry.is_none() && dest_list.is_some() {
            streams_without_entry.push(stream.name.clone());
        }
        let mut m = Map::new();
        m.insert(
            "name".into(),
            json!(format!("{}_stream_{}.lnk", name, stream.name)),
        );
        m.insert("type".into(), json!("JumpListStream"));
        m.insert("recovery_method".into(), json!("ole_directory"));
        m.insert("stream_name".into(), json!(stream.name));
        m.insert("stream_declared_len".into(), json!(stream.declared_len));
        m.insert("stream_read_len".into(), json!(stream.bytes.len()));
        if let Some(why) = &stream.unavailable {
            m.insert("stream_read_note".into(), json!(why));
        }
        // Where the stream's bytes lie contiguously in the file, that offset
        // is recorded; a stream the allocation table scatters has no single
        // offset, and none is invented.
        match find_contiguous(full_data, &stream.bytes, &candidates) {
            Some(off) => {
                m.insert("source_offset".into(), json!(off));
                m.insert(
                    "source_offset_basis".into(),
                    json!("the stream's bytes were found contiguous at this offset in the file"),
                );
            }
            None => {
                m.insert(
                    "source_offset_unavailable".into(),
                    json!(
                        "the stream was read through the allocation table and its bytes \
                           were not found whole at any shortcut signature in the file, so \
                           it has no single offset"
                    ),
                );
            }
        }
        attribution.write(&mut m);
        match entry {
            Some(e) => {
                m.insert("dest_list_correlation".into(), json!("matched"));
                m.insert("dest_list_entry_number".into(), json!(e.entry_number));
                m.insert("dest_list_mru_position".into(), json!(e.mru_position));
                m.insert("dest_list_path".into(), json!(e.path));
                match &e.last_recorded_time {
                    Some(t) => {
                        m.insert("dest_list_last_recorded_time".into(), json!(t));
                    }
                    None => {
                        m.insert("dest_list_last_recorded_time".into(), Value::Null);
                    }
                }
                m.insert("dest_list_pinned".into(), pinned_value(e.pin_status));
                if let Some(c) = e.offset_116 {
                    m.insert(
                        "dest_list_offset_116_unknown_possibly_access_count".into(),
                        json!(c),
                    );
                    m.insert(
                        "dest_list_offset_116_note".into(),
                        json!(destlist::OFFSET_116_NOTE),
                    );
                }
            }
            None if dest_list.is_some() => {
                m.insert("dest_list_correlation".into(), json!("no_dest_list_entry"));
                m.insert(
                    "dest_list_correlation_note".into(),
                    json!(
                        "the DestList names no entry with this stream's number; the stream \
                           exists in the directory without the list's record of it"
                    ),
                );
            }
            None => {
                m.insert(
                    "dest_list_correlation".into(),
                    json!("dest_list_unavailable"),
                );
            }
        }
        produced.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::FileEntry,
                Some(Arc::new(MemoryDataSource::new(stream.bytes.clone()))),
                Value::Object(m),
            )
            .with_parent(artifact.id),
        );
    }
    if streams.lnk_streams_in_directory > streams.lnk_streams.len() {
        shortfalls.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "The directory lists {} numbered shortcut streams and this build reads at most \
                 {}; the lowest-numbered were read and the rest are absent.",
                streams.lnk_streams_in_directory, caps.lnk_streams
            ),
        });
    }
    if !streams_unread.is_empty() {
        let capped = streams_unread
            .iter()
            .any(|s| s["reason"].as_str().is_some_and(|r| r.contains("ceiling")));
        shortfalls.push(Shortfall {
            reason: if capped {
                IncompleteReason::CapReached
            } else {
                IncompleteReason::ShortRead
            },
            detail: format!(
                "{} shortcut stream(s) the directory lists could not be read; each is named \
                 with its reason under `lnk_streams_unread`.",
                streams_unread.len()
            ),
        });
    }

    // The DestList entries, each saying whether its shortcut stream exists.
    let mut entries_without_stream: Vec<u32> = Vec::new();
    if let Some(dl) = &dest_list {
        for e in &dl.entries {
            let present = stream_names_read
                .iter()
                .any(|s| ole::lnk_stream_number(s) == Some(e.entry_number));
            if !present {
                entries_without_stream.push(e.entry_number);
            }
            produced.push(dest_list_entry_artifact(
                artifact,
                name,
                attribution,
                dl,
                e,
                present,
            ));
            if let Some(t) = &e.last_recorded_time {
                produced.push(
                    Artifact::new(
                        artifact.case_id,
                        ArtifactType::TimelineEvent,
                        None,
                        json!({
                            "timestamp": t,
                            "timestamp_desc": "Jump list entry last recorded",
                            "short_desc": format!("Jump list entry recorded: {}", e.path),
                            "description": format!(
                                "The jump list of {} ({}) recorded {} at most-recently-used \
                                 position {} (entry {})",
                                attribution.application_label(), name, e.path,
                                e.mru_position, e.entry_number
                            ),
                            "source_module": MODULE_ID,
                            "jump_list": name,
                            "path": e.path,
                            "entry_number": e.entry_number,
                            "mru_position": e.mru_position,
                        }),
                    )
                    .with_parent(artifact.id),
                );
            }
        }
    }

    // Shortcuts in sectors the directory no longer references (ROADMAP §2.5).
    let live: Vec<&[u8]> = streams
        .lnk_streams
        .iter()
        .map(|s| s.bytes.as_slice())
        .collect();
    let (unreferenced, unreferenced_note, unreferenced_capped) = carve_unreferenced(
        artifact,
        name,
        full_data,
        &live,
        attribution,
        MAX_CARVED_LINKS,
    );
    summary.insert(
        "shortcuts_carved_from_unreferenced_sectors".into(),
        json!(unreferenced.len()),
    );
    summary.insert("unreferenced_sector_scan".into(), json!(unreferenced_note));
    summary.insert(
        "unreferenced_sector_cap_reached".into(),
        json!(unreferenced_capped),
    );
    if unreferenced_capped {
        summary.insert("max_carved_links".into(), json!(MAX_CARVED_LINKS));
        shortfalls.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "The carve of free sectors stopped at its {MAX_CARVED_LINKS}-shortcut cap; the \
                 {} shortcut(s) carved from them are a floor, and free sectors past the stopping \
                 point were not scanned.",
                unreferenced.len()
            ),
        });
    }
    produced.extend(unreferenced);

    summary.insert("lnk_streams_read".into(), json!(streams_read));
    summary.insert("lnk_streams_unread".into(), json!(streams_unread));
    summary.insert(
        "entries_without_stream".into(),
        json!(entries_without_stream),
    );
    summary.insert("streams_without_entry".into(), json!(streams_without_entry));
    if !entries_without_stream.is_empty() {
        summary.insert(
            "entries_without_stream_note".into(),
            json!(
                "these DestList entries name a stream the directory does not hold or that \
                   could not be read; the entry's own path and times are still reported"
            ),
        );
    }
    produced.push(dest_list_summary_artifact(
        artifact,
        name,
        attribution,
        summary,
        shortfalls,
    ));
    produced
}

/// `true`/`false` where the pin field holds a documented value, `null` with
/// the raw value beside it otherwise.
fn pinned_value(pin_status: i32) -> Value {
    match pin_status {
        -1 => json!(false),
        p if p >= 0 => json!(true),
        _ => Value::Null,
    }
}

fn dest_list_entry_artifact(
    source: &Artifact,
    name: &str,
    attribution: &Attribution,
    dl: &destlist::DestList,
    e: &destlist::DestListEntry,
    lnk_stream_present: bool,
) -> Artifact {
    let mut m = Map::new();
    m.insert("type".into(), json!("JumpListDestListEntry"));
    m.insert("record_type".into(), json!("jumplist_destlist_entry"));
    m.insert(
        "name".into(),
        json!(format!("{} entry {}: {}", name, e.entry_number, e.path)),
    );
    m.insert("jump_list".into(), json!(name));
    attribution.write(&mut m);
    m.insert(
        "dest_list_format_version".into(),
        json!(dl.header.format_version),
    );
    m.insert("dest_list_layout".into(), json!(dl.layout.label()));
    m.insert("offset_in_dest_list".into(), json!(e.offset));
    m.insert("mru_position".into(), json!(e.mru_position));
    m.insert(
        "mru_position_basis".into(),
        json!(
            "the entry's index in DestList stream order, 0 first. The libyal format \
               documentation this module follows does not state the order of entries; that \
               the stream is kept most recently used first is what real files show (last \
               recorded times descending) and how plaso and JLECmd read it, and the \
               position is reported on that basis"
        ),
    );
    m.insert("entry_number".into(), json!(e.entry_number));
    m.insert("stream_name".into(), json!(e.stream_name));
    m.insert("lnk_stream_present".into(), json!(lnk_stream_present));
    if lnk_stream_present {
        m.insert(
            "lnk_artifact_name".into(),
            json!(format!("{}_stream_{}.lnk", name, e.stream_name)),
        );
    }
    m.insert("path".into(), json!(e.path));
    if e.path_had_invalid_utf16 {
        m.insert(
            "path_note".into(),
            json!("the path held UTF-16 units that do not decode; each is shown as U+FFFD"),
        );
    }
    if let Some(h) = &e.hostname {
        m.insert("hostname".into(), json!(h));
    }
    m.insert(
        "droid_volume_identifier".into(),
        json!(e.droid_volume_identifier),
    );
    m.insert(
        "droid_file_identifier".into(),
        json!(e.droid_file_identifier),
    );
    m.insert(
        "birth_droid_volume_identifier".into(),
        json!(e.birth_droid_volume_identifier),
    );
    m.insert(
        "birth_droid_file_identifier".into(),
        json!(e.birth_droid_file_identifier),
    );
    match &e.last_recorded_time {
        Some(t) => {
            m.insert("last_recorded_time".into(), json!(t));
        }
        None => {
            m.insert(
                "last_recorded_time_unavailable".into(),
                json!(format!(
                    "the entry's time field holds {:#x}, which is the unset sentinel or outside \
                     the range a date can express; no date is reported for it",
                    e.last_recorded_time_raw
                )),
            );
        }
    }
    m.insert(
        "last_recorded_time_raw_filetime".into(),
        json!(e.last_recorded_time_raw),
    );
    m.insert("pin_status".into(), json!(e.pin_status));
    let pinned = pinned_value(e.pin_status);
    if pinned == json!(true) {
        m.insert("pinned_position".into(), json!(e.pin_status));
    }
    if pinned.is_null() {
        m.insert(
            "pin_status_note".into(),
            json!(
                "the pin field holds a value the format does not document (-1 is unpinned, \
                   0 and above a pinned position); whether the entry is pinned is not \
                   established"
            ),
        );
    }
    m.insert("pinned".into(), pinned);
    match e.offset_116 {
        Some(c) => {
            m.insert("offset_116_unknown_possibly_access_count".into(), json!(c));
            m.insert("offset_116_note".into(), json!(destlist::OFFSET_116_NOTE));
        }
        None => {
            m.insert(
                "offset_116_unavailable".into(),
                json!(destlist::OFFSET_116_UNAVAILABLE),
            );
        }
    }
    Artifact::new(
        source.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(source.id)
}

/// The one record per jump list that says what was read and what was not.
fn dest_list_summary_artifact(
    source: &Artifact,
    name: &str,
    attribution: &Attribution,
    mut m: Map<String, Value>,
    shortfalls: Vec<Shortfall>,
) -> Artifact {
    m.insert("type".into(), json!("JumpListDestList"));
    m.insert("record_type".into(), json!("jumplist_destlist"));
    m.insert("name".into(), json!(format!("{} (DestList)", name)));
    m.insert("jump_list".into(), json!(name));
    attribution.write(&mut m);
    m.insert("content_incomplete".into(), json!(!shortfalls.is_empty()));
    if let Some(first) = shortfalls.first() {
        let detail: Vec<&str> = shortfalls.iter().map(|s| s.detail.as_str()).collect();
        let detail = detail.join(" ");
        let reasons: Vec<&str> = shortfalls.iter().map(|s| s.reason.as_str()).collect();
        m.insert(
            "content_incomplete_reason".into(),
            json!(first.reason.as_str()),
        );
        m.insert("content_incomplete_reasons".into(), json!(reasons));
        m.insert("content_incomplete_detail".into(), json!(detail));
        m.insert("inventory_incomplete".into(), json!(true));
        m.insert(
            "inventory_incomplete_reason".into(),
            json!(first.reason.as_str()),
        );
        m.insert("inventory_incomplete_detail".into(), json!(detail));
        m.insert("message".into(), json!(detail));
    } else {
        m.insert(
            "message".into(),
            json!(
                "The OLE directory and the DestList stream were read in full, and every \
                   shortcut stream the directory lists was read."
            ),
        );
    }
    Artifact::new(
        source.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(source.id)
}

/// Every offset in `hay` at which the shortcut signature begins: the only
/// places a shortcut stream can lie, collected in one pass so that locating
/// each stream is a comparison at a few candidates, not a scan of the file.
fn lnk_signature_offsets(hay: &[u8]) -> Vec<usize> {
    if hay.len() < LNK_SIGNATURE.len() {
        return Vec::new();
    }
    hay.windows(LNK_SIGNATURE.len())
        .enumerate()
        .filter(|(_, w)| *w == LNK_SIGNATURE)
        .map(|(i, _)| i)
        .collect()
}

/// The first candidate offset at which `needle` lies whole in `hay`, if any.
fn find_contiguous(hay: &[u8], needle: &[u8], candidates: &[usize]) -> Option<usize> {
    if needle.is_empty() || !needle.starts_with(&LNK_SIGNATURE) {
        return None;
    }
    candidates
        .iter()
        .copied()
        .find(|&c| hay.get(c..c + needle.len()) == Some(needle))
}

/// Scan a buffer for shortcut signatures and carve a shortcut at each.
///
/// `label` is the naming scheme (`stream` for an automaticDestinations file,
/// `entry` for a customDestinations one); `directory_error` is set when the
/// scan is the fallback for a container whose directory could not be read.
fn carve_shortcuts(
    artifact: &Artifact,
    name: &str,
    full_data: &[u8],
    label: &str,
    attribution: &Attribution,
    directory_error: Option<&str>,
) -> Carve {
    let mut shortcuts = Vec::new();
    let mut stopped = None;
    let sig_len = LNK_SIGNATURE.len();
    // Every offset at which the whole signature fits is tested, the last
    // eight bytes included (HUNT-168: the scan used to stop at `len − 8`
    // exclusive, so a signature ending the file was never tested). A file
    // shorter than the signature skips the loop.
    let mut offset = 0;
    while offset + sig_len <= full_data.len() {
        if full_data[offset..offset + sig_len] != LNK_SIGNATURE {
            offset += 1;
            continue;
        }
        // The cap is tested on a hit, not on every byte: a file holding
        // exactly the cap's worth of shortcuts was carved whole.
        if shortcuts.len() >= MAX_CARVED_LINKS {
            warn!(
                "JumpList carving hit limit of {} LNK entries in {}, stopping",
                MAX_CARVED_LINKS, name
            );
            stopped = Some(IncompleteReason::CapReached.as_str());
            break;
        }
        info!("Found LNK signature at offset {}", offset);
        // Size the carved slice from the LNK structure (BUG-101). When the
        // structure cannot be walked, take up to 4096 bytes — but never past
        // the next signature, so an unwalkable shortcut does not swallow the
        // one after it (HUNT-168).
        let structural = lnk_length(&full_data[offset..]);
        let end = match structural {
            Some(len) => (offset + len).min(full_data.len()),
            None => {
                let window_end = std::cmp::min(offset + 4096, full_data.len());
                full_data[offset + 1..window_end]
                    .windows(sig_len)
                    .position(|w| w == LNK_SIGNATURE)
                    .map_or(window_end, |p| offset + 1 + p)
            }
        };
        let mut m = Map::new();
        m.insert(
            "name".into(),
            json!(format!("{}_{}_{}.lnk", name, label, offset)),
        );
        m.insert("type".into(), json!("JumpListCarvedShortcut"));
        m.insert("recovery_method".into(), json!("signature_carve"));
        m.insert("source_offset".into(), json!(offset));
        if structural.is_none() {
            m.insert(
                "length_note".into(),
                json!(
                    "the shortcut's structure could not be walked to its end; the carve \
                       takes 4096 bytes, the rest of the buffer or up to the next shortcut \
                       signature, whichever is least, so it may be cut short or carry \
                       bytes of what follows"
                ),
            );
        }
        attribution.write(&mut m);
        if let Some(e) = directory_error {
            m.insert(
                "dest_list_correlation".into(),
                json!("dest_list_unavailable"),
            );
            m.insert(
                "dest_list_correlation_note".into(),
                json!(format!(
                    "found by scanning for the shortcut signature because the OLE directory \
                     could not be read ({e}); no DestList entry can be tied to it and a live \
                     stream cannot be told from a freed one"
                )),
            );
        }
        shortcuts.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::FileEntry,
                Some(Arc::new(MemoryDataSource::new(
                    full_data[offset..end].to_vec(),
                ))),
                Value::Object(m),
            )
            .with_parent(artifact.id),
        );
        // Resume where this carve ends: past a walked shortcut's declared
        // length, or at the next signature for an unwalkable one. The old
        // fixed 76-byte step both overlapped carves and stepped over a
        // signature lying inside it (HUNT-168). `end > offset` always.
        offset = end;
    }
    let bytes_scanned = if stopped.is_some() {
        offset
    } else {
        full_data.len()
    };
    Carve {
        shortcuts,
        stopped,
        bytes_scanned,
    }
}

/// Carve shortcuts out of the sectors and mini-sectors the compound file's
/// allocation tables mark free, in a jump list whose directory was read.
///
/// Each run of free sectors is scanned for the shortcut signature; a hit is
/// sized by the shortcut's own structure (or cut at the next signature or the
/// run's end when that cannot be walked). A hit whose bytes are a prefix of a
/// live stream's is left out: that covers an exact copy of a stream already
/// reported and a carve cut short of one (no structural length, cut at the
/// end of the free run), both of which the live stream already holds whole.
/// Returns the carved shortcuts, a sentence saying what was scanned, and
/// whether the carve stopped at `cap` (then the count is a floor).
fn carve_unreferenced(
    artifact: &Artifact,
    name: &str,
    full_data: &[u8],
    live: &[&[u8]],
    attribution: &Attribution,
    cap: usize,
) -> (Vec<Artifact>, String, bool) {
    let runs = match free_sectors::free_runs(full_data) {
        Ok(r) => r,
        Err(e) => {
            return (
                Vec::new(),
                format!("not run: the allocation tables could not be read ({e})"),
                false,
            )
        }
    };
    let sectors: usize = runs.iter().map(|r| r.sector_offsets.len()).sum();
    let mut out = Vec::new();
    let mut capped = false;
    let sig_len = LNK_SIGNATURE.len();
    'runs: for run in &runs {
        let data = &run.bytes;
        let mut at = 0usize;
        while at + sig_len <= data.len() {
            if data[at..at + sig_len] != LNK_SIGNATURE {
                at += 1;
                continue;
            }
            if out.len() >= cap {
                // A further signature was found with the cap already met.
                capped = true;
                break 'runs;
            }
            let structural = lnk_length(&data[at..]);
            let end = match structural {
                Some(len) => (at + len).min(data.len()),
                None => data[at + 1..]
                    .windows(sig_len)
                    .position(|w| w == LNK_SIGNATURE)
                    .map_or(data.len(), |p| at + 1 + p),
            };
            let carved = &data[at..end];
            let slot = at / run.sector_size;
            let index = run.first_index as usize + slot;
            let offset = run.sector_offsets.get(slot).copied().unwrap_or(0) + at % run.sector_size;
            if live.iter().any(|l| l.starts_with(carved)) {
                at = end.max(at + 1);
                continue;
            }
            let mut m = Map::new();
            m.insert(
                "name".into(),
                json!(format!("{}_unreferenced_{}_{}.lnk", name, run.kind, index)),
            );
            m.insert("type".into(), json!("JumpListCarvedShortcut"));
            m.insert("recovery_method".into(), json!("unreferenced_sector_carve"));
            m.insert("sector_kind".into(), json!(run.kind));
            m.insert("sector_index".into(), json!(index));
            m.insert("source_offset".into(), json!(offset));
            m.insert("dest_list_correlation".into(), json!("none"));
            m.insert(
                "dest_list_correlation_note".into(),
                json!(
                    "found in a sector (or mini-sector) the compound file's allocation tables \
                     mark free, in a jump list whose directory was read: it is a shortcut the \
                     directory no longer references, and nothing ties it to a DestList entry \
                     or says when it was freed"
                ),
            );
            m.insert(
                "validation_note".into(),
                json!(
                    "the mechanism is pinned on compound files written and edited by the cfb \
                     crate; no real jump list examined has yet held a freed shortcut (30 real \
                     files checked on 2026-09-26, none)"
                ),
            );
            if structural.is_none() {
                m.insert(
                    "length_note".into(),
                    json!(
                        "the shortcut's structure could not be walked to its end; the carve \
                         runs to the next shortcut signature or the end of the free run"
                    ),
                );
            }
            attribution.write(&mut m);
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::FileEntry,
                    Some(Arc::new(MemoryDataSource::new(carved.to_vec()))),
                    Value::Object(m),
                )
                .with_parent(artifact.id),
            );
            at = end.max(at + 1);
        }
    }
    let mut note = format!(
        "{sectors} free sector(s) and mini-sector(s) in {} run(s) scanned for the shortcut \
         signature; {} shortcut(s) found that no live stream holds",
        runs.len(),
        out.len()
    );
    if capped {
        note.push_str(&format!(
            "; the carve stopped at its {cap}-shortcut cap with a further signature found, so \
             the count is a floor and free sectors past that point were not scanned"
        ));
    }
    (out, note, capped)
}

/// Append the carve-status record a scan calls for, if any.
///
/// The carve did not cover the whole file: that is a record of its own
/// rather than a log line, because shortcuts past the stopping point are
/// absent from the case and their absence is not evidence. A fragment is
/// scanned, and the one record it leaves says both things — the carve did
/// not cover a whole file, AND the container could not be corroborated.
fn finish_carve(
    produced: &mut Vec<Artifact>,
    artifact: &Artifact,
    name: &str,
    stopped: Option<&'static str>,
    header_short: bool,
    bytes_scanned: usize,
) {
    let links_carved = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .count();
    if header_short {
        produced.push(carve_status_artifact(
            artifact,
            name,
            Some(IncompleteReason::ShortRead.as_str()),
            links_carved,
            bytes_scanned,
            concat!(
                "This file is named as an automaticDestinations JumpList but fewer than ",
                "the 512 bytes an OLE compound-file header occupies could be read, so the ",
                "signature was never checked. Whatever bytes were available were scanned ",
                "for shortcut structures and anything found is reported alongside this ",
                "record — but the container is NOT corroborated as a JumpList, and a ",
                "fragment may hold only some of the shortcuts the whole file held."
            ),
        ));
    } else if let Some(reason) = stopped {
        produced.push(carve_status_artifact(
            artifact,
            name,
            Some(reason),
            links_carved,
            bytes_scanned,
            "JumpList carving stopped before the end of the file: shortcuts past that \
             point were never examined",
        ));
    } else if links_carved == 0 {
        // The whole file was scanned and held no shortcut. Say so: a
        // JumpList that yielded nothing and a JumpList that was never
        // examined must not both be silence (B5-040).
        produced.push(carve_status_artifact(
            artifact,
            name,
            None,
            0,
            bytes_scanned,
            "The whole of this JumpList was scanned and it contained no shortcut \
             structures",
        ));
    }
}

/// The record that states what a JumpList carve covered.
///
/// `reason` is `Some` only when the carve did not cover the file: then, and only
/// then, the standard incompleteness pair is written. With `None` the record is
/// a positive statement that the file was scanned end to end, which is what
/// keeps "scanned, nothing there" apart from "never examined".
fn carve_status_artifact(
    source: &Artifact,
    name: &str,
    reason: Option<&str>,
    links_carved: usize,
    bytes_scanned: usize,
    message: &str,
) -> Artifact {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("JumpListCarveStatus"));
    m.insert("record_type".into(), json!("jumplist_carve_status"));
    m.insert(
        "name".into(),
        json!(match reason {
            Some(_) => format!("{} (partially carved)", name),
            None => format!("{} (no shortcuts found)", name),
        }),
    );
    m.insert("links_carved".into(), json!(links_carved));
    // How many bytes, from the start of what was read, were tested for the
    // shortcut signature — so "scanned" is a number, not a claim.
    m.insert("bytes_scanned".into(), json!(bytes_scanned));
    m.insert("max_carved_links".into(), json!(MAX_CARVED_LINKS));
    m.insert("carve_complete".into(), json!(reason.is_none()));
    m.insert("content_incomplete".into(), json!(reason.is_some()));
    if let Some(reason) = reason {
        m.insert("content_incomplete_reason".into(), json!(reason));
        m.insert("inventory_incomplete".into(), json!(true));
        m.insert("inventory_incomplete_reason".into(), json!(reason));
        // The sentence goes on the keys the examiner-facing reader shows
        // (`frontend/src/lib/incompleteness.ts` keys it off `<flag>_detail`);
        // a bare `message` is read by nothing on that path, so the examiner
        // was shown `cap_reached` with no statement of what stopped. Written
        // only where the flags are set, so a jump list that carved cleanly
        // carries no sentence contradicting its own `carve_complete`.
        m.insert("content_incomplete_detail".into(), json!(message));
        m.insert("inventory_incomplete_detail".into(), json!(message));
    }
    m.insert("message".into(), json!(message));
    Artifact::new(
        source.case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(source.id)
}

/// Compute the on-disk byte length of an MS-SHLLINK (`.lnk`) shortcut that begins
/// at the start of `data`, by walking its structures per MS-SHLLINK:
/// ShellLinkHeader (76) -> optional LinkTargetIDList -> optional LinkInfo ->
/// StringData -> ExtraData (terminated by a block whose size is < 4).
///
/// Returns `None` when the structure is malformed or would run past `data`, so
/// the carver can fall back to a fixed cap rather than fabricate a length
/// (BUG-101: the old carver hard-truncated every LNK at 4096 bytes, losing
/// path/args/tracker data on large shortcuts). Used by the signature carve only;
/// a stream read through the directory is sized by the directory.
fn lnk_length(data: &[u8]) -> Option<usize> {
    const HEADER_SIZE: usize = 0x4C; // 76
    if data.len() < HEADER_SIZE {
        return None;
    }
    // The HeaderSize field (offset 0) must be 0x4C for a valid shortcut.
    if u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize != HEADER_SIZE {
        return None;
    }
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let has_link_target_idlist = flags & 0x0000_0001 != 0;
    let has_link_info = flags & 0x0000_0002 != 0;
    let string_flags = [
        flags & 0x0000_0004 != 0, // HasName
        flags & 0x0000_0008 != 0, // HasRelativePath
        flags & 0x0000_0010 != 0, // HasWorkingDir
        flags & 0x0000_0020 != 0, // HasArguments
        flags & 0x0000_0040 != 0, // HasIconLocation
    ];
    let is_unicode = flags & 0x0000_0080 != 0;

    let mut pos = HEADER_SIZE;

    // LinkTargetIDList: u16 IDListSize followed by IDListSize bytes.
    if has_link_target_idlist {
        let field_end = pos.checked_add(2)?;
        let size_bytes = data.get(pos..field_end)?;
        let idlist_size = u16::from_le_bytes([size_bytes[0], size_bytes[1]]) as usize;
        pos = field_end.checked_add(idlist_size)?;
        if pos > data.len() {
            return None;
        }
    }

    // LinkInfo: first u32 is the total LinkInfoSize (includes the size field).
    if has_link_info {
        let field_end = pos.checked_add(4)?;
        let b = data.get(pos..field_end)?;
        let link_info_size = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if link_info_size < 4 {
            return None;
        }
        pos = pos.checked_add(link_info_size)?;
        if pos > data.len() {
            return None;
        }
    }

    // StringData: each present string is a u16 CountCharacters then the chars
    // (2 bytes each when the Unicode flag is set, otherwise 1).
    let char_size = if is_unicode { 2 } else { 1 };
    for present in string_flags {
        if present {
            let field_end = pos.checked_add(2)?;
            let b = data.get(pos..field_end)?;
            let count = u16::from_le_bytes([b[0], b[1]]) as usize;
            pos = field_end.checked_add(count.checked_mul(char_size)?)?;
            if pos > data.len() {
                return None;
            }
        }
    }

    // ExtraData: a run of blocks, each a u32 BlockSize (>= 4) then payload. The
    // terminal block has a size < 4 (4 bytes total) and ends the shortcut.
    loop {
        let field_end = pos.checked_add(4)?;
        let b = data.get(pos..field_end)?;
        let block_size = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if block_size < 4 {
            return Some(field_end); // include the 4-byte terminal block
        }
        pos = pos.checked_add(block_size)?;
        if pos > data.len() {
            return None;
        }
    }
}

// Simple in-memory data source
#[derive(Debug)]
pub struct MemoryDataSource {
    data: Vec<u8>,
}

impl MemoryDataSource {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for MemoryDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.data.len() as u64 {
            return Ok(0);
        }
        let len = self.data.len() as u64;
        let remaining = len - offset;
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        buf[..to_read].copy_from_slice(&self.data[offset as usize..offset as usize + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::test_support::{DribbleSource, TruncatedSource, UnreadableSource};
    use uuid::Uuid;

    /// LNK file header magic — what the carver scans for.
    const LNK_SIG: [u8; 8] = [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
    /// OLE2 compound-file header magic.
    const OLE_SIG: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    /// Build an OLE-shaped buffer (>=512 bytes) with N embedded LNK signatures.
    /// LNKs are placed 200 bytes apart to ensure the 76-byte skip-on-match still
    /// lets the scanner find subsequent signatures.
    fn ole_with_lnks(lnk_count: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[..8].copy_from_slice(&OLE_SIG);
        for i in 0..lnk_count {
            let off = 512 + i * 200;
            assert!(
                off + 8 <= buf.len(),
                "fixture too small for {} lnks",
                lnk_count
            );
            buf[off..off + 8].copy_from_slice(&LNK_SIG);
        }
        buf
    }

    fn custom_dest_with_lnks(lnk_count: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 64 + lnk_count * 200];
        for i in 0..lnk_count {
            let off = 64 + i * 200;
            buf[off..off + 8].copy_from_slice(&LNK_SIG);
        }
        buf
    }

    fn make_artifact(name: &str, data: Option<Arc<dyn DataSource>>) -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            data,
            json!({ "name": name }),
        )
    }

    /// HUNT-277: a jump list inside a shadow copy is read, it is selected by its
    /// own file name (not the `[shadow copy …]` label its `name` carries), what
    /// it yields repeats the snapshot identity, and any other `ParsedRecord` is
    /// not read.
    #[test]
    fn a_shadow_copy_prior_version_of_a_jump_list_is_read_and_stamped() {
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(ole_with_lnks(3)));
        let prior = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(src.clone()),
            json!({
                "type": "VssPriorVersion",
                "name": "1b4dd67f29cb1962.automaticDestinations-ms [shadow copy 2015-03-23T00:00:00Z]",
                "file_name": "1b4dd67f29cb1962.automaticDestinations-ms",
                "is_snapshot_version": true,
                "vss_snapshot_id": "snap-1",
                "vss_creation_time": "2015-03-23T00:00:00Z",
            }),
        );
        let out = JumpListParser.process(&prior).expect("no error");
        assert!(!out.is_empty(), "the prior version's jump list is read");
        assert!(out
            .iter()
            .all(|a| a.metadata["vss_snapshot_id"] == json!("snap-1")));

        let other = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(src),
            json!({ "type": "SomethingElse" }),
        );
        assert!(JumpListParser.process(&other).unwrap().is_empty());
    }

    /// The check that was four bytes wide while claiming eight.
    #[test]
    fn a_file_matching_only_half_the_ole_signature_is_refused() {
        // `D0 CF 11 E0` is a common enough opening for a binary file; the
        // other four bytes are what make it an OLE compound file. Accepting
        // the half meant a byte-scan carve was run over an unrelated file and
        // its hits reported as jump-list shortcuts.
        let mut buf = ole_with_lnks(3);
        buf[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let out = JumpListParser
            .process(&make_artifact(
                "1b4dd67f29cb1962.automaticDestinations-ms",
                Some(Arc::new(
                    seance_core::data_source::ByteSliceDataSource::new(buf),
                )),
            ))
            .expect("no error");
        assert!(
            !out.iter()
                .any(|a| a.artifact_type == ArtifactType::FileEntry),
            "no shortcut may be carved from a file that is not an OLE compound file"
        );
        let status = out
            .iter()
            .find(|a| a.metadata["type"] == "JumpListCarveStatus")
            .expect("a status record, because silence would read as an empty jump list");
        assert!(status.metadata["message"]
            .as_str()
            .expect("a message")
            .contains("eight-byte OLE compound-file signature"));
        // And the whole signature is still accepted.
        let ok = JumpListParser
            .process(&make_artifact(
                "1b4dd67f29cb1962.automaticDestinations-ms",
                Some(Arc::new(
                    seance_core::data_source::ByteSliceDataSource::new(ole_with_lnks(3)),
                )),
            ))
            .expect("no error");
        assert_eq!(
            ok.iter()
                .filter(|a| a.artifact_type == ArtifactType::FileEntry)
                .count(),
            3,
            "and the whole signature still carves"
        );
    }

    #[test]
    fn module_identity() {
        let p = JumpListParser;
        assert_eq!(p.id(), "plugin.windows.jumplist_parser");
        assert!(!p.version().is_empty());
        // FileEntry, and ParsedRecord for a shadow-copy prior version only (HUNT-277).
        assert_eq!(
            p.subscribes_to(),
            vec![ArtifactType::FileEntry, ArtifactType::ParsedRecord]
        );
    }

    #[test]
    fn non_jumplist_filenames_are_ignored() {
        // Random filename + matching data source — should still skip before reading bytes.
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(ole_with_lnks(3)));
        let art = make_artifact("notepad.exe", Some(src));
        let out = JumpListParser.process(&art).unwrap();
        assert!(out.is_empty());
    }

    /// A jump list is recognised whatever case its extension arrived in.
    ///
    /// `InvalidInputFormat` here is the RECOGNITION succeeding: the name matched
    /// and the parser then objected to the missing data. Before this, an
    /// upper- or lower-cased extension was not matched at all and the artifact
    /// passed through as "not a jump list" — `Ok` with nothing produced — so an
    /// acquisition whose tool folded case recovered zero jump lists in silence.
    #[test]
    fn extension_case_does_not_decide_whether_a_jump_list_is_one() {
        for name in [
            "12345.AUTOMATICDESTINATIONS-MS",
            "12345.automaticdestinations-ms",
            "12345.AutomaticDestinations-ms",
            "abc.CUSTOMDESTINATIONS-MS",
        ] {
            let art = make_artifact(name, None);
            match JumpListParser.process(&art) {
                Err(ModuleError::InvalidInputFormat(_)) => {}
                other => panic!("{name}: expected recognition (InvalidInputFormat), got {other:?}"),
            }
        }
    }

    #[test]
    fn missing_data_on_matching_name_is_invalid_input() {
        let art = make_artifact("12345.automaticDestinations-ms", None);
        match JumpListParser.process(&art) {
            Err(ModuleError::InvalidInputFormat(_)) => {}
            other => panic!("expected InvalidInputFormat, got {:?}", other),
        }
    }

    #[test]
    fn automatic_destinations_without_ole_header_produces_nothing() {
        // Right name, but the first 4 bytes are not the OLE magic — carver short-circuits.
        let mut buf = vec![0u8; 1024];
        buf[..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        // Even with a valid LNK sig later in the buffer, no OLE header → no carving.
        buf[600..608].copy_from_slice(&LNK_SIG);
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(buf));

        let art = make_artifact("a.automaticDestinations-ms", Some(src));
        let out = JumpListParser.process(&art).unwrap();
        // No shortcuts are carved — but the file was named as a JumpList, so the
        // result says the structure was not recognised rather than staying
        // silent (B5-021). Silence here reads as "no documents were opened".
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["record_type"], "jumplist_carve_status");
        assert_eq!(out[0].metadata["content_incomplete"], true);
        assert_eq!(
            out[0].metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
    }

    /// The fixture has the signature and nothing else of an OLE file, so the
    /// directory cannot be read and the shortcuts come out of the fallback
    /// scan — typed and labelled as carved, beside a DestList record that
    /// says why the directory route was not taken.
    #[test]
    fn automatic_destinations_with_ole_header_carves_lnk_streams() {
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(ole_with_lnks(3)));
        let parent = make_artifact("abc.automaticDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();

        let summary = out
            .iter()
            .find(|a| a.metadata["record_type"] == "jumplist_destlist")
            .expect("the DestList record says the directory could not be read");
        assert_eq!(summary.metadata["ole_directory_read"], false);
        assert_eq!(summary.metadata["shortcuts_carved"], 3);
        let shortcuts: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(shortcuts.len(), 3);
        for a in shortcuts {
            assert_eq!(a.metadata["type"], "JumpListCarvedShortcut");
            assert_eq!(a.metadata["recovery_method"], "signature_carve");
            assert_eq!(a.metadata["dest_list_correlation"], "dest_list_unavailable");
            assert_eq!(a.parent_id, Some(parent.id));
            // Streams from automatic dests use the "_stream_" naming scheme.
            let name = a.metadata.get("name").and_then(|v| v.as_str()).unwrap();
            assert!(name.contains("_stream_"), "got {}", name);
            assert!(name.ends_with(".lnk"));
            // Each carved artifact must have its own data source attached, so the
            // LnkParser downstream module can read it.
            assert!(a.data.is_some(), "carved LNK missing data source");
        }
    }

    #[test]
    fn custom_destinations_carves_lnk_entries() {
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(custom_dest_with_lnks(4)));
        let parent = make_artifact("xyz.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();

        assert_eq!(out.len(), 4);
        for a in &out {
            let name = a.metadata.get("name").and_then(|v| v.as_str()).unwrap();
            // Custom dests use the "_entry_" naming scheme.
            assert!(name.contains("_entry_"), "got {}", name);
            assert!(name.ends_with(".lnk"));
        }
    }

    #[test]
    fn source_offset_is_recorded_for_each_carve() {
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(custom_dest_with_lnks(2)));
        let parent = make_artifact("rec.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();

        let offsets: Vec<u64> = out
            .iter()
            .map(|a| {
                a.metadata
                    .get("source_offset")
                    .and_then(|v| v.as_u64())
                    .unwrap()
            })
            .collect();
        // Fixture places LNKs at offsets 64 and 264.
        assert_eq!(offsets, vec![64, 264]);
    }

    #[test]
    fn small_custom_destinations_under_8_bytes_does_not_panic() {
        // Regression: the `while offset < full_data.len() - 8` loop in the
        // custom-destinations branch underflows usize when file_size < 8.
        // In debug mode this panics on overflow; in release mode it wraps
        // to a huge value and the inner `full_data[offset..offset+8]` slice
        // panics on out-of-bounds. Either way, a 5-byte malformed jumplist
        // file would crash the worker.
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(vec![0xCC; 5]));
        let art = make_artifact("tiny.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&art).expect("must not error/panic");
        // Scanned end to end, nothing found: stated positively, and NOT marked
        // incomplete, so the marker keeps its meaning (B5-040).
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["record_type"], "jumplist_carve_status");
        assert_eq!(out[0].metadata["carve_complete"], true);
        assert_eq!(out[0].metadata["content_incomplete"], false);
        assert_eq!(out[0].metadata["links_carved"], 0);
    }

    #[test]
    fn empty_custom_destinations_does_not_panic() {
        // Zero-byte file should also be handled gracefully.
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(Vec::new()));
        let art = make_artifact("empty.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&art).expect("must not error/panic");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["carve_complete"], true);
        assert_eq!(out[0].metadata["content_incomplete"], false);
    }

    #[test]
    fn short_reads_still_carve_all_lnks_automatic() {
        // BUG-065: a single read_at that returns only 64 bytes would leave the
        // rest of the buffer zero-padded, dropping every real LNK past the first
        // chunk. The read loop must recover them all. 64 bytes per call is well
        // under the 200-byte stride between the fixture's LNK signatures.
        let src = Arc::new(DribbleSource::new(ole_with_lnks(3), 64));
        let parent = make_artifact("s.automaticDestinations-ms", Some(src.clone()));
        let out = JumpListParser.process(&parent).unwrap();
        assert_eq!(
            out.iter()
                .filter(|a| a.artifact_type == ArtifactType::FileEntry)
                .count(),
            3,
            "all LNKs must be carved despite short reads"
        );
        src.assert_dribbled();
    }

    #[test]
    fn short_reads_still_carve_all_lnks_custom() {
        let src = Arc::new(DribbleSource::new(custom_dest_with_lnks(4), 50));
        let parent = make_artifact("s.customDestinations-ms", Some(src.clone()));
        let out = JumpListParser.process(&parent).unwrap();
        assert_eq!(out.len(), 4, "all LNKs must be carved despite short reads");
        src.assert_dribbled();
    }

    #[test]
    fn oversized_reported_size_is_truncated_not_zero_scanned() {
        // Source reports a larger size() than it actually has data for. The tail
        // must be truncated away, not scanned as fabricated zero content.
        let data = custom_dest_with_lnks(2);
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(data, 100_000));
        let parent = make_artifact("o.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();

        // Both shortcuts are carved from the bytes that actually exist, and
        // none is fabricated from the over-reported tail.
        let links: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["record_type"] != "jumplist_carve_status")
            .collect();
        assert_eq!(links.len(), 2, "both real shortcuts are carved");

        // The source declared 100,000 bytes and could produce far fewer. The
        // parser cannot tell a tail that never existed from one it could not
        // read, so it says the carve stopped short rather than letting the
        // silence read as "there was nothing else here".
        let status: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["record_type"] == "jumplist_carve_status")
            .collect();
        assert_eq!(status.len(), 1, "the shortfall is recorded exactly once");
        assert_eq!(status[0].metadata["content_incomplete"], true);
        assert_eq!(status[0].metadata["links_carved"], 2);
    }

    /// B5-021: an `.automaticDestinations-ms` whose header cannot be read must
    /// not return an empty result. An unreadable JumpList and a user who opened
    /// no documents would otherwise be the same answer.
    #[test]
    fn unreadable_automatic_destinations_header_is_reported() {
        // A source that declares a full-size file and then refuses to read.
        let src: Arc<dyn DataSource> = Arc::new(UnreadableSource::new(4096));
        let art = make_artifact("f.automaticDestinations-ms", Some(src));
        let out = JumpListParser.process(&art).expect("must not error");
        assert!(
            out.iter()
                .all(|a| a.artifact_type == ArtifactType::ParsedRecord),
            "an unreadable JumpList yields no shortcut"
        );
        let status = out
            .last()
            .expect("an unreadable JumpList must report itself");
        assert_eq!(status.metadata["record_type"], "jumplist_carve_status");
        assert_eq!(status.metadata["content_incomplete"], true);
        assert_eq!(status.metadata["content_incomplete_reason"], "short_read");
        assert_eq!(status.metadata["links_carved"], 0);
        // And the DestList record says the same thing from its side.
        let summary = out
            .iter()
            .find(|a| a.metadata["record_type"] == "jumplist_destlist")
            .expect("a DestList record");
        // "Could not look" is not "not there": the directory was never read,
        // so whether a DestList exists is not established.
        assert!(summary.metadata["dest_list_present"].is_null());
        assert!(summary.metadata["dest_list_present_note"]
            .as_str()
            .is_some_and(|n| n.contains("not established")));
        assert_eq!(summary.metadata["content_incomplete"], true);
    }

    /// A jump list recovered from a fragment used to give a shortfall record
    /// and no shortcuts, because the 512-byte header read failed before the
    /// carve ran. The signature scan works on whatever bytes are there, and a
    /// shortcut found in them is a real shortcut.
    #[test]
    fn a_truncated_jumplist_is_still_scanned_and_says_its_container_is_unverified() {
        // 400 bytes with a shortcut signature at offset 100: too short for the
        // OLE header, long enough to hold a shortcut.
        let mut buf = vec![0u8; 400];
        buf[..8].copy_from_slice(&OLE_SIGNATURE);
        buf[100..108].copy_from_slice(&LNK_SIG);
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::ByteSliceDataSource::new(buf));
        let art = make_artifact("f.automaticDestinations-ms", Some(src));
        let out = JumpListParser.process(&art).expect("must not error");

        let carved: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(carved.len(), 1, "the shortcut in the fragment is recovered");

        let status: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["record_type"] == "jumplist_carve_status")
            .collect();
        assert_eq!(status.len(), 1, "one shortfall, reported once");
        assert_eq!(status[0].metadata["links_carved"], 1);
        assert_eq!(
            status[0].metadata["content_incomplete_reason"],
            "short_read"
        );
        let message = status[0].metadata["message"].as_str().expect("a message");
        assert!(
            message.contains("signature was never checked"),
            "the container could not be corroborated and the record must say so: {message}"
        );
        assert!(
            message.contains("NOT corroborated as a JumpList"),
            "{message}"
        );
        assert!(
            message.contains("may hold only some of the shortcuts"),
            "{message}"
        );
    }

    /// A JumpList that really is empty is reported as scanned-and-empty, which
    /// is a different record from the one above.
    #[test]
    fn a_fully_scanned_empty_jumplist_says_so_without_claiming_incompleteness() {
        let mut buf = vec![0u8; 4096];
        buf[..8].copy_from_slice(&OLE_SIG);
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(buf));
        let art = make_artifact("e.automaticDestinations-ms", Some(src));
        let out = JumpListParser.process(&art).unwrap();
        assert!(out
            .iter()
            .all(|a| a.artifact_type == ArtifactType::ParsedRecord));
        let status = out.last().unwrap();
        assert_eq!(status.metadata["record_type"], "jumplist_carve_status");
        assert_eq!(status.metadata["carve_complete"], true);
        assert_eq!(status.metadata["content_incomplete"], false);
    }

    #[test]
    fn carved_lnk_data_starts_with_lnk_signature() {
        // The carved data source's first 8 bytes must be the LNK header
        // so the downstream LnkParser can detect it.
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(custom_dest_with_lnks(1)));
        let parent = make_artifact("rec.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();
        assert_eq!(out.len(), 1);

        let carved = out[0].data.as_ref().expect("data source attached");
        let mut hdr = [0u8; 8];
        carved.read_at(0, &mut hdr).unwrap();
        assert_eq!(hdr, LNK_SIG);
    }

    #[test]
    fn large_lnk_is_not_truncated_at_4096() {
        // BUG-101: a shortcut larger than 4096 bytes must be carved in full. Build
        // a customDestinations file with one LNK whose LinkInfo alone is 5000
        // bytes, so its true length (76 header + 5000 LinkInfo + 4 terminal) is
        // well past the old hard 4096-byte cap.
        const LNK_OFFSET: usize = 64;
        let link_info_size: usize = 5000;
        let lnk_len = 76 + link_info_size + 4; // 5080

        let mut buf = vec![0u8; LNK_OFFSET + lnk_len];
        buf[LNK_OFFSET..LNK_OFFSET + 8].copy_from_slice(&LNK_SIG);
        // LinkFlags @ +20: HasLinkInfo (0x02) only. HeaderSize (@0) is already
        // 0x4C via the first 4 bytes of the signature.
        buf[LNK_OFFSET + 20..LNK_OFFSET + 24].copy_from_slice(&0x02u32.to_le_bytes());
        // LinkInfo @ +76: total LinkInfoSize (u32).
        let li = LNK_OFFSET + 76;
        buf[li..li + 4].copy_from_slice(&(link_info_size as u32).to_le_bytes());
        // ExtraData terminal block (4 zero bytes) is already zeroed at li+5000.

        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(buf));
        let parent = make_artifact("big.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();
        assert_eq!(out.len(), 1);

        let carved = out[0].data.as_ref().expect("data source attached");
        assert_eq!(
            carved.size(),
            lnk_len as u64,
            "carved LNK must equal its parsed length, not the 4096 cap"
        );
        assert!(carved.size() > 4096);
    }

    #[test]
    fn malformed_lnk_falls_back_to_4096_cap() {
        // A shortcut claiming a huge LinkInfo that runs past the buffer is
        // malformed: lnk_length returns None and the carver falls back to the cap
        // rather than fabricating a length.
        let mut buf = vec![0u8; 64 + 2000];
        buf[64..72].copy_from_slice(&LNK_SIG);
        buf[64 + 20..64 + 24].copy_from_slice(&0x02u32.to_le_bytes()); // HasLinkInfo
        let li = 64 + 76;
        buf[li..li + 4].copy_from_slice(&100_000u32.to_le_bytes()); // overruns buffer

        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(buf));
        let parent = make_artifact("bad.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();
        assert_eq!(out.len(), 1);
        let carved = out[0].data.as_ref().expect("data source attached");
        // Buffer is only 2064 bytes total, so the cap clamps to the remaining len.
        assert_eq!(carved.size(), (64 + 2000 - 64) as u64);
    }

    #[test]
    fn a_carve_that_stops_at_the_link_cap_says_so_instead_of_looking_complete() {
        // One more shortcut than the carver will take. The shortcuts past the
        // cap are absent from the case; without a marker their absence reads as
        // "this document was never opened from this application".
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(custom_dest_with_lnks(
            MAX_CARVED_LINKS + 1,
        )));
        let parent = make_artifact("capped.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();

        let status = out
            .iter()
            .find(|a| {
                a.metadata.get("type").and_then(|v| v.as_str()) == Some("JumpListCarveStatus")
            })
            .expect("hitting the carve cap must emit a status record");
        assert_eq!(status.metadata["content_incomplete"], true);
        // The reason is the shared vocabulary (`IncompleteReason`), not a name
        // invented here: a token no `IncompleteReason::from_str` recognises
        // cannot be classified by the API, the export or the report, so the
        // examiner would be shown the raw string and nothing else.
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            IncompleteReason::CapReached.as_str()
        );
        assert_eq!(status.metadata["links_carved"], MAX_CARVED_LINKS);
        assert_eq!(status.metadata["max_carved_links"], MAX_CARVED_LINKS);
        // "instead of looking complete", literally: this is the key the record
        // uses to make the positive claim that a file was scanned end to end,
        // and a capped carve must not make it.
        assert_eq!(status.metadata["carve_complete"], false);
        // The shortcuts past the cap are missing from the INVENTORY as well as
        // from the content; the census and the report's "not recovered" section
        // read the inventory pair.
        assert_eq!(status.metadata["inventory_incomplete"], true);
        assert_eq!(
            status.metadata["inventory_incomplete_reason"],
            IncompleteReason::CapReached.as_str()
        );
        // And the sentence lands where the examiner-facing reader shows it.
        assert!(status.metadata["content_incomplete_detail"]
            .as_str()
            .is_some_and(|s| s.contains("stopped before the end of the file")));
    }

    #[test]
    fn a_carve_that_reaches_the_end_of_the_file_emits_no_status_record() {
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(custom_dest_with_lnks(3)));
        let parent = make_artifact("short.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();
        assert!(
            out.iter()
                .all(|a| a.metadata.get("type").and_then(|v| v.as_str())
                    != Some("JumpListCarveStatus")),
            "a complete carve must not claim to be incomplete"
        );
    }

    // ---- The directory route, on compound files built for the purpose ----

    use crate::destlist::fixtures::{entry as dl_entry, header as dl_header};
    use crate::destlist::Layout;
    use std::io::Write;

    // 2012-04-01T13:52:38.9975382Z
    const FT: u64 = 129_777_619_589_975_382;

    /// A minimal, structurally complete shortcut: header, no optional
    /// structures, terminal ExtraData block.
    fn minimal_lnk(tag: u8) -> Vec<u8> {
        let mut l = vec![0u8; 80];
        l[..8].copy_from_slice(&LNK_SIG);
        l[8] = tag;
        l
    }

    fn compound(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
        for (name, bytes) in streams {
            let mut st = comp.create_stream(format!("/{name}")).unwrap();
            st.write_all(bytes).unwrap();
        }
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(bytes));
        JumpListParser
            .process(&make_artifact(name, Some(src)))
            .unwrap()
    }

    /// HUNT-168: the signature carve used to step 76 bytes past every hit and
    /// stop scanning at `len − 8`. A shortcut whose structure could not be
    /// walked was carved at 4096 bytes (overlapping whatever followed it), a
    /// second signature inside the 76-byte step was never reached, and a
    /// signature in the file's last eight bytes was never tested — while the
    /// status record said the whole file had been scanned.
    #[test]
    fn the_signature_carve_neither_overlaps_nor_stops_short() {
        let mut buf = vec![0u8; 16];
        // A shortcut whose structure cannot be walked: HasLinkInfo is set and
        // the LinkInfoSize it points at (inside the next shortcut) is zero.
        let mut malformed = vec![0u8; 40];
        malformed[..8].copy_from_slice(&LNK_SIG);
        malformed[20..24].copy_from_slice(&0x2u32.to_le_bytes());
        buf.extend_from_slice(&malformed); // 16..56
        buf.extend_from_slice(&minimal_lnk(1)); // 56..136, 40 bytes after the first
        buf.extend_from_slice(&minimal_lnk(2)); // 136..216
        buf.extend_from_slice(&LNK_SIG); // 216..224: the file's last eight bytes
        let len = buf.len();

        let out = run("tail.customDestinations-ms", buf);
        let carves: Vec<(u64, usize)> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .map(|a| {
                (
                    a.metadata["source_offset"].as_u64().unwrap(),
                    a.data.as_ref().unwrap().size() as usize,
                )
            })
            .collect();
        let offsets: Vec<u64> = carves.iter().map(|c| c.0).collect();
        assert_eq!(
            offsets,
            vec![16, 56, 136, 216],
            "every signature, including one inside the old 76-byte step and one in the \
             last eight bytes, must be carved"
        );
        for pair in carves.windows(2) {
            let (start, size) = pair[0];
            assert!(
                start as usize + size <= pair[1].0 as usize,
                "carve at {start} ({size} bytes) overlaps the carve at {}",
                pair[1].0
            );
        }
        // The unwalkable shortcut ends where the next signature begins.
        assert_eq!(carves[0].1, 40);
        assert_eq!(carves[3].0 as usize + carves[3].1, len);
    }

    /// A carve that found nothing says what it scanned, not just that it
    /// scanned "the whole" file.
    #[test]
    fn a_carve_that_found_nothing_states_the_bytes_it_scanned() {
        let out = run("none.customDestinations-ms", vec![0xAB; 300]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["carve_complete"], true);
        assert_eq!(out[0].metadata["bytes_scanned"], 300);
    }

    fn summary(out: &[Artifact]) -> &Artifact {
        let s: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["record_type"] == "jumplist_destlist")
            .collect();
        assert_eq!(s.len(), 1, "one DestList record per jump list");
        assert_eq!(
            out.last().unwrap().metadata["record_type"],
            "jumplist_destlist",
            "the DestList record comes last"
        );
        s[0]
    }

    #[test]
    fn a_directory_without_a_dest_list_reports_the_streams_and_says_the_list_is_absent() {
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[("1", minimal_lnk(1)), ("2", minimal_lnk(2))]),
        );
        let s = summary(&out);
        assert_eq!(s.metadata["ole_directory_read"], true);
        assert_eq!(s.metadata["dest_list_present"], false);
        assert_eq!(s.metadata["content_incomplete"], true);
        assert_eq!(
            s.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert!(s.metadata["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("names no DestList stream"));
        assert_eq!(s.metadata["lnk_streams_read"], 2);
        let lnks: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(lnks.len(), 2);
        for l in lnks {
            assert_eq!(l.metadata["type"], "JumpListStream");
            assert_eq!(l.metadata["dest_list_correlation"], "dest_list_unavailable");
            assert!(
                l.metadata["source_offset"].is_u64(),
                "a mini-stream is contiguous"
            );
        }
        assert!(out
            .iter()
            .all(|a| a.metadata["record_type"] != "jumplist_destlist_entry"));
        assert!(out
            .iter()
            .all(|a| a.metadata["record_type"] != "jumplist_carve_status"));
    }

    #[test]
    fn an_entry_without_its_stream_and_a_stream_without_its_entry_are_each_named() {
        let mut dl = dl_header(1, 2, 0);
        dl.extend(dl_entry(Layout::Windows7, 1, FT, -1, 0, "C:\\has-stream"));
        dl.extend(dl_entry(
            Layout::Windows7,
            2,
            FT - 1,
            -1,
            0,
            "C:\\no-stream",
        ));
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[
                ("1", minimal_lnk(1)),
                ("3", minimal_lnk(3)),
                ("DestList", dl),
            ]),
        );
        let s = summary(&out);
        assert_eq!(s.metadata["entries_without_stream"], json!([2]));
        assert_eq!(s.metadata["streams_without_entry"], json!(["3"]));
        assert_eq!(s.metadata["entries_read"], 2);
        assert_eq!(s.metadata["lnk_streams_read"], 2);
        // A mismatch between list and directory is a finding about the
        // file, not a shortfall in the reading.
        assert_eq!(s.metadata["content_incomplete"], false);

        let entries: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["record_type"] == "jumplist_destlist_entry")
            .collect();
        assert_eq!(entries[0].metadata["lnk_stream_present"], true);
        assert_eq!(
            entries[0].metadata["lnk_artifact_name"],
            "1b4dd67f29cb1962.automaticDestinations-ms_stream_1.lnk"
        );
        assert_eq!(entries[1].metadata["lnk_stream_present"], false);
        assert!(entries[1].metadata.get("lnk_artifact_name").is_none());

        let three = out
            .iter()
            .find(|a| {
                a.metadata["stream_name"] == "3" && a.artifact_type == ArtifactType::FileEntry
            })
            .unwrap();
        assert_eq!(
            three.metadata["dest_list_correlation"],
            "no_dest_list_entry"
        );
        let one = out
            .iter()
            .find(|a| {
                a.metadata["stream_name"] == "1" && a.artifact_type == ArtifactType::FileEntry
            })
            .unwrap();
        assert_eq!(one.metadata["dest_list_correlation"], "matched");
        assert_eq!(one.metadata["dest_list_path"], "C:\\has-stream");
    }

    #[test]
    fn an_app_id_this_build_cannot_name_is_reported_unknown_not_guessed() {
        let dl = dl_header(1, 0, 0);
        let out = run(
            "ffffffffffffffff.automaticDestinations-ms",
            compound(&[("DestList", dl)]),
        );
        let s = summary(&out);
        assert_eq!(s.metadata["app_id"], "ffffffffffffffff");
        assert!(s.metadata["application"].is_null());
        assert!(s.metadata["application_unknown"]
            .as_str()
            .unwrap()
            .contains("not established"));
        assert!(s.metadata.get("application_basis").is_none());
    }

    #[test]
    fn a_file_named_without_an_app_id_says_so() {
        let out = run(
            "notes.automaticDestinations-ms",
            compound(&[("DestList", dl_header(1, 0, 0))]),
        );
        let s = summary(&out);
        assert!(s.metadata.get("app_id").is_none());
        assert!(s.metadata["app_id_unavailable"].is_string());
    }

    #[test]
    fn a_custom_destinations_carve_is_typed_as_carved_and_attributed_by_its_app_id() {
        // c98dce577f884ef8 is not in the table: unknown, stated.
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(custom_dest_with_lnks(2)));
        let parent = make_artifact("c98dce577f884ef8.customDestinations-ms", Some(src));
        let out = JumpListParser.process(&parent).unwrap();
        assert_eq!(out.len(), 2);
        for a in &out {
            assert_eq!(a.metadata["type"], "JumpListCarvedShortcut");
            assert_eq!(a.metadata["recovery_method"], "signature_carve");
            assert_eq!(a.metadata["app_id"], "c98dce577f884ef8");
            assert!(a.metadata["application"].is_null());
            assert!(a.metadata["application_unknown"].is_string());
            // A custom list has no DestList; the key is simply absent.
            assert!(a.metadata.get("dest_list_correlation").is_none());
        }
    }

    #[test]
    fn a_shortcut_stream_this_build_can_name_carries_the_application_on_the_artifact() {
        let out = run(
            "9d1f905ce5044aee.automaticDestinations-ms",
            compound(&[("1", minimal_lnk(1)), ("DestList", dl_header(3, 0, 0))]),
        );
        let l = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .unwrap();
        assert_eq!(l.metadata["application"], "Microsoft Edge (EdgeHTML)");
        assert_eq!(
            l.metadata["application_identifier"],
            "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge"
        );
    }

    #[test]
    fn an_empty_dest_list_is_an_empty_list_not_a_shortfall() {
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[("DestList", Vec::new())]),
        );
        let s = summary(&out);
        assert_eq!(s.metadata["dest_list_present"], true);
        assert_eq!(s.metadata["dest_list_empty"], true);
        assert_eq!(s.metadata["content_incomplete"], false);
        assert_eq!(s.metadata["lnk_streams_read"], 0);
        assert_eq!(out.len(), 1, "nothing else to report");
    }

    #[test]
    fn a_dest_list_of_an_undocumented_version_is_refused_with_the_version_and_the_streams_still_reported(
    ) {
        let mut dl = dl_header(9, 1, 0);
        dl.extend(dl_entry(Layout::Windows10, 1, FT, -1, 1, "x"));
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[("1", minimal_lnk(1)), ("DestList", dl)]),
        );
        let s = summary(&out);
        assert_eq!(s.metadata["dest_list_present"], true);
        assert_eq!(s.metadata["content_incomplete"], true);
        assert_eq!(
            s.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert!(s.metadata["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("format version 9"));
        assert!(
            s.metadata.get("dest_list_layout").is_none(),
            "no layout was decoded"
        );
        assert!(out
            .iter()
            .all(|a| a.metadata["record_type"] != "jumplist_destlist_entry"));
        assert_eq!(
            out.iter()
                .filter(|a| a.artifact_type == ArtifactType::FileEntry)
                .count(),
            1
        );
    }

    #[test]
    fn a_truncated_dest_list_reports_the_entries_it_could_read_and_where_it_stopped() {
        let mut dl = dl_header(1, 2, 0);
        dl.extend(dl_entry(Layout::Windows7, 1, FT, -1, 0, "C:\\whole"));
        let cut = dl_entry(Layout::Windows7, 2, FT, -1, 0, "C:\\cut");
        dl.extend_from_slice(&cut[..cut.len() - 4]);
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[("DestList", dl)]),
        );
        let s = summary(&out);
        assert_eq!(s.metadata["entries_declared"], 2);
        assert_eq!(s.metadata["entries_read"], 1);
        assert_eq!(s.metadata["content_incomplete"], true);
        assert_eq!(
            s.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        let detail = s.metadata["content_incomplete_detail"].as_str().unwrap();
        assert!(detail.contains("1 entries read of the 2"), "{detail}");
        assert_eq!(
            out.iter()
                .filter(|a| a.metadata["record_type"] == "jumplist_destlist_entry")
                .count(),
            1
        );
    }

    #[test]
    fn the_offset_116_field_is_never_called_an_access_count_on_any_record() {
        let mut dl = dl_header(3, 1, 0);
        dl.extend(dl_entry(Layout::Windows10, 1, FT, -1, 9, "C:\\x"));
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[("DestList", dl), ("1", minimal_lnk(1))]),
        );
        for a in &out {
            for key in a.metadata.as_object().expect("an object").keys() {
                assert!(
                    !key.contains("access_count") || key.contains("unknown_possibly"),
                    "{key} on {} asserts a meaning the sources do not give",
                    a.metadata["record_type"]
                );
            }
        }
        let e = out
            .iter()
            .find(|a| a.metadata["record_type"] == "jumplist_destlist_entry")
            .expect("an entry record");
        assert_eq!(e.metadata["offset_116_unknown_possibly_access_count"], 9);
        assert!(e.metadata["offset_116_note"]
            .as_str()
            .is_some_and(|n| n.contains("unknown5")));
        let lnk = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("the shortcut stream");
        assert_eq!(
            lnk.metadata["dest_list_offset_116_unknown_possibly_access_count"],
            9
        );
        assert_eq!(
            lnk.metadata["dest_list_offset_116_note"],
            destlist::OFFSET_116_NOTE
        );
    }

    #[test]
    fn a_version_1_entry_says_it_has_no_field_at_offset_116() {
        let mut dl = dl_header(1, 1, 0);
        dl.extend(dl_entry(Layout::Windows7, 1, FT, -1, 0, "C:\\x"));
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[("DestList", dl)]),
        );
        let e = out
            .iter()
            .find(|a| a.metadata["record_type"] == "jumplist_destlist_entry")
            .expect("an entry record");
        assert!(e
            .metadata
            .get("offset_116_unknown_possibly_access_count")
            .is_none());
        assert!(e.metadata["offset_116_unavailable"]
            .as_str()
            .is_some_and(|n| n.contains("version 1") && n.contains("114-byte")));
    }

    #[test]
    fn the_mru_basis_is_stated_as_an_observation_not_as_the_format_documentation() {
        let mut dl = dl_header(1, 1, 0);
        dl.extend(dl_entry(Layout::Windows7, 1, FT, -1, 0, "C:\\x"));
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[("DestList", dl)]),
        );
        let e = out
            .iter()
            .find(|a| a.metadata["record_type"] == "jumplist_destlist_entry")
            .expect("an entry record");
        let basis = e.metadata["mru_position_basis"].as_str().unwrap();
        assert!(
            basis.contains("does not state"),
            "the libyal document gives no entry order; the basis must say so: {basis}"
        );
        assert!(!basis.contains("which the format keeps"));
    }

    #[test]
    fn a_pinned_entry_and_an_unset_time_are_each_stated_as_what_they_are() {
        let mut dl = dl_header(3, 2, 1);
        dl.extend(dl_entry(Layout::Windows10, 1, FT, 0, 4, "C:\\pinned"));
        dl.extend(dl_entry(Layout::Windows10, 2, 0, -1, 2, "C:\\undated"));
        let out = run(
            "1b4dd67f29cb1962.automaticDestinations-ms",
            compound(&[("DestList", dl)]),
        );
        let entries: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["record_type"] == "jumplist_destlist_entry")
            .collect();
        assert_eq!(entries[0].metadata["pinned"], true);
        assert_eq!(entries[0].metadata["pinned_position"], 0);
        assert!(entries[0].metadata.get("access_count").is_none());
        assert_eq!(
            entries[0].metadata["offset_116_unknown_possibly_access_count"],
            4
        );
        assert_eq!(
            entries[0].metadata["offset_116_note"],
            destlist::OFFSET_116_NOTE
        );
        assert_eq!(entries[1].metadata["pinned"], false);
        assert!(entries[1].metadata.get("last_recorded_time").is_none());
        assert!(entries[1].metadata["last_recorded_time_unavailable"]
            .as_str()
            .unwrap()
            .contains("0x0"));
        // One timeline event: the undated entry puts nothing on the timeline.
        assert_eq!(
            out.iter()
                .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
                .count(),
            1
        );
        assert_eq!(summary(&out).metadata["pinned_entries_declared"], 1);
    }

    #[test]
    fn the_stream_ceiling_is_stated_with_both_numbers() {
        let file = compound(&[
            ("1", minimal_lnk(1)),
            ("2", minimal_lnk(2)),
            ("3", minimal_lnk(3)),
            ("DestList", dl_header(1, 0, 0)),
        ]);
        let name = "1b4dd67f29cb1962.automaticDestinations-ms";
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(file));
        let parent = make_artifact(name, Some(src.clone()));
        let caps = ole::Caps {
            lnk_streams: 2,
            ..ole::Caps::default()
        };
        let out = process_automatic(
            &parent,
            name,
            &*src,
            &Attribution::from_file_name(name),
            caps,
        );
        let s = summary(&out);
        assert_eq!(s.metadata["lnk_streams_in_directory"], 3);
        assert_eq!(s.metadata["lnk_streams_read"], 2);
        assert_eq!(s.metadata["content_incomplete_reason"], "cap_reached");
        let detail = s.metadata["content_incomplete_detail"].as_str().unwrap();
        assert!(
            detail.contains("lists 3") && detail.contains("at most 2"),
            "{detail}"
        );
        let names: Vec<&str> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .map(|a| a.metadata["stream_name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ["1", "2"],
            "the lowest-numbered streams are the ones read"
        );
    }

    #[test]
    fn a_stream_past_the_byte_ceiling_is_named_unread_and_its_entry_says_the_stream_is_absent() {
        let mut dl = dl_header(1, 1, 0);
        dl.extend(dl_entry(Layout::Windows7, 1, FT, -1, 0, "C:\\big"));
        let file = compound(&[("1", vec![0x4C; 500]), ("DestList", dl)]);
        let name = "1b4dd67f29cb1962.automaticDestinations-ms";
        let src: Arc<dyn DataSource> = Arc::new(MemoryDataSource::new(file));
        let parent = make_artifact(name, Some(src.clone()));
        let caps = ole::Caps {
            lnk_stream_bytes: 100,
            ..ole::Caps::default()
        };
        let out = process_automatic(
            &parent,
            name,
            &*src,
            &Attribution::from_file_name(name),
            caps,
        );
        let s = summary(&out);
        assert_eq!(s.metadata["lnk_streams_read"], 0);
        assert_eq!(s.metadata["lnk_streams_unread"][0]["stream_name"], "1");
        assert!(s.metadata["lnk_streams_unread"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("100-byte ceiling"));
        assert_eq!(s.metadata["content_incomplete_reason"], "cap_reached");
        assert_eq!(s.metadata["entries_without_stream"], json!([1]));
        assert!(out
            .iter()
            .all(|a| a.artifact_type != ArtifactType::FileEntry));
        let e = out
            .iter()
            .find(|a| a.metadata["record_type"] == "jumplist_destlist_entry")
            .unwrap();
        assert_eq!(e.metadata["lnk_stream_present"], false);
        assert_eq!(e.metadata["path"], "C:\\big");
    }

    // ---- Shortcuts in sectors a readable directory no longer references ----

    /// A compound file holding `streams`, with `removed` then deleted through
    /// the `cfb` writer — an independent MS-CFB implementation whose
    /// `remove_stream` marks the stream's FAT or mini-FAT entries free and
    /// leaves the bytes where they were.
    fn compound_with_removed(streams: &[(&str, Vec<u8>)], removed: &str) -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
        for (name, bytes) in streams {
            let mut st = comp.create_stream(format!("/{name}")).unwrap();
            st.write_all(bytes).unwrap();
        }
        comp.remove_stream(format!("/{removed}")).unwrap();
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    fn unreferenced(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["recovery_method"] == "unreferenced_sector_carve")
            .collect()
    }

    #[test]
    fn a_shortcut_left_in_a_freed_mini_sector_of_a_readable_jump_list_is_recovered_and_labelled() {
        let bytes = compound_with_removed(
            &[
                ("1", minimal_lnk(1)),
                ("2", minimal_lnk(2)),
                ("DestList", Vec::new()),
            ],
            "2",
        );
        let out = run("f.automaticDestinations-ms", bytes);
        let carved = unreferenced(&out);
        assert_eq!(carved.len(), 1, "{out:#?}");
        let c = carved[0];
        assert_eq!(c.metadata["type"], "JumpListCarvedShortcut");
        assert_eq!(c.metadata["sector_kind"], "mini_sector");
        assert!(c.metadata["sector_index"].as_u64().is_some());
        assert_eq!(c.metadata["dest_list_correlation"], "none");
        let mut tag = [0u8; 9];
        c.data.as_ref().unwrap().read_at(0, &mut tag).unwrap();
        assert_eq!(tag[8], 2, "the removed stream's shortcut, not the live one");
        // The live stream is still reported as a stream, and not carved again.
        assert_eq!(
            summary(&out).metadata["shortcuts_carved_from_unreferenced_sectors"],
            1
        );
    }

    #[test]
    fn a_shortcut_left_in_a_freed_regular_sector_is_recovered() {
        let mut big = minimal_lnk(7);
        big.resize(5000, 0x41); // past the 4,096-byte mini-stream cutoff
        let bytes = compound_with_removed(
            &[("1", minimal_lnk(1)), ("2", big), ("DestList", Vec::new())],
            "2",
        );
        let out = run("g.automaticDestinations-ms", bytes);
        let carved = unreferenced(&out);
        assert_eq!(carved.len(), 1, "{out:#?}");
        assert_eq!(carved[0].metadata["sector_kind"], "sector");
        let mut tag = [0u8; 9];
        carved[0]
            .data
            .as_ref()
            .unwrap()
            .read_at(0, &mut tag)
            .unwrap();
        assert_eq!(tag[8], 7);
    }

    /// The free-sector carve stops at its cap like the whole-file carve does,
    /// and says so: the count it reports is then a floor.
    #[test]
    fn the_free_sector_carve_says_when_it_stopped_at_its_cap() {
        let mut two = minimal_lnk(2);
        two.extend(minimal_lnk(3));
        let bytes = compound_with_removed(
            // The removed stream is written first so its freed mini-sectors
            // sit inside the mini stream, below the live streams.
            &[("2", two), ("1", minimal_lnk(1)), ("DestList", Vec::new())],
            "2",
        );
        let a = make_artifact("c.automaticDestinations-ms", None);
        let attr = Attribution::from_file_name("c.automaticDestinations-ms");
        let live_one = minimal_lnk(1);
        let live: [&[u8]; 1] = [&live_one];
        let (all, note, capped) =
            carve_unreferenced(&a, "c", &bytes, &live, &attr, MAX_CARVED_LINKS);
        assert_eq!(all.len(), 2, "{note}");
        assert!(!capped, "{note}");
        assert!(!note.contains("cap"), "{note}");
        let (cut, note, capped) = carve_unreferenced(&a, "c", &bytes, &live, &attr, 1);
        assert_eq!(cut.len(), 1);
        assert!(capped, "{note}");
        assert!(note.contains("a floor"), "{note}");
    }

    #[test]
    fn a_jump_list_with_nothing_removed_carves_nothing_from_free_space() {
        let bytes = compound(&[
            ("1", minimal_lnk(1)),
            ("2", minimal_lnk(2)),
            ("DestList", Vec::new()),
        ]);
        let out = run("h.automaticDestinations-ms", bytes);
        assert!(unreferenced(&out).is_empty(), "{out:#?}");
        assert_eq!(
            summary(&out).metadata["shortcuts_carved_from_unreferenced_sectors"],
            0
        );
    }
}
