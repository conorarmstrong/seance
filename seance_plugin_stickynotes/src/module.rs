//! The module: a Sticky Notes store on disk becomes records.
//!
//! # Recognised by content, with the name only deciding whether to look
//!
//! `StickyNotes.snt` is an OLE2 compound file and `plum.sqlite` is a SQLite
//! database, and each is checked by its magic. A file merely named
//! `StickyNotes.snt` that is not a compound file produces nothing at all — not
//! a refusal, not an empty record.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};

// A windowed or container-backed source may hand back fewer bytes than asked
// for, and a single short read would file a real store as "not one".
use seance_core::io::read_full;

use crate::{plum, snt, unvalidated::stamp_snt};

/// Bytes read to decide which format, if either, this is.
const SNIFF_BYTES: usize = 16;

/// The largest `.snt` this build will read whole.
const MAX_SNT_BYTES: u64 = 256 * 1024 * 1024;

/// The largest `plum.sqlite` this build will stage.
const MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The largest `-wal` read for deleted-note recovery: the cap the SQLite
/// staging helper puts on the WAL it stages, so the two read the same log.
const MAX_WAL_BYTES: u64 = 512 * 1024 * 1024;

pub struct StickyNotesParser;

/// A status record about a `.snt`: the shared shape, carrying the `.snt`
/// format's validation stamp rather than the `plum.sqlite` one.
fn snt_status(source_file: &str, status: &str, detail: String) -> serde_json::Value {
    let mut v = plum::parse_status(source_file, status, detail, Vec::new(), None);
    if let Some(m) = v.as_object_mut() {
        stamp_snt(m);
    }
    v
}

fn basename(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}

/// Whether a name is worth opening.
fn worth_sniffing(name: &str) -> bool {
    let base = basename(name);
    base == "stickynotes.snt" || base.ends_with(".snt") || base == "plum.sqlite"
}

impl ForensicsModule for StickyNotesParser {
    fn id(&self) -> &str {
        "plugin.windows.sticky_notes"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::SystemArtifact]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(source) = artifact.data.as_ref() else {
            return Ok(vec![]);
        };
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(vec![]);
        }
        let name = artifact
            .metadata
            .get("name")
            .or_else(|| artifact.metadata.get("file_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("path")
            .or_else(|| artifact.metadata.get("source_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !worth_sniffing(name) && !worth_sniffing(path) {
            return Ok(vec![]);
        }
        let source_file = if name.is_empty() { path } else { name };

        let mut head = [0u8; SNIFF_BYTES];
        let n = read_full(source.as_ref(), 0, &mut head);

        if snt::is_compound_file(&head[..n]) {
            return Ok(self.read_snt(artifact, source_file));
        }
        if seance_core::io::is_sqlite_header(&head[..n]) {
            return Ok(self.read_plum(artifact, source_file));
        }
        // Named like a store and not one. Nothing is said about it.
        Ok(vec![])
    }
}

impl StickyNotesParser {
    fn read_snt(&self, artifact: &Artifact, source_file: &str) -> Vec<Artifact> {
        let Some(source) = artifact.data.as_ref() else {
            return vec![];
        };
        let size = source.size();
        if size > MAX_SNT_BYTES {
            return vec![Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                snt_status(
                    source_file,
                    "NotRead",
                    format!(
                        "This Sticky Notes file is {size} bytes, past this build's \
                         {MAX_SNT_BYTES}-byte ceiling, and was not read. Nothing about the notes \
                         it holds is established either way."
                    ),
                ),
            )
            .with_parent(artifact.id)];
        }
        let mut bytes = vec![0u8; size as usize];
        let read = read_full(source.as_ref(), 0, &mut bytes);
        bytes.truncate(read);
        let short = (read as u64) < size;

        let file = match snt::read(&bytes) {
            Ok(f) => f,
            Err(e) => {
                // A status record, never `vec![]`: the file IS a compound file
                // and would not open, which is a finding.
                return vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    snt_status(
                        source_file,
                        "CompoundFileUnreadable",
                        format!(
                            "This file carries the OLE2 compound-file magic and its structure \
                             would not open ({e}). Nothing about the notes it holds is \
                             established either way."
                        ),
                    ),
                )
                .with_parent(artifact.id)];
            }
        };

        let mut out = Vec::new();
        let mut coverage = serde_json::json!({
            "type": "StickyNotesCoverage",
            "name": format!("{source_file} — {} note storage(s)", file.notes.len()),
            "source_file": source_file,
            "source_format": snt::SOURCE_FORMAT,
            "note_storages": file.notes.len(),
            "notes_with_text": file.notes.iter().filter(|n| !n.unrecognised).count(),
            "storages_not_recognised": file.notes.iter().filter(|n| n.unrecognised).count(),
            // Streams the documented layout does not put at the root. Listed
            // rather than dropped, so a layout this build has not met shows up.
            "root_streams": file
                .root_streams
                .iter()
                .map(snt::NoteStream::to_json)
                .collect::<Vec<_>>(),
            "coverage_note": if file.notes.is_empty() {
                "This compound file opened and holds no storages beneath its root, so it records \
                 no notes. That is not the same as this build having failed to read it."
            } else {
                "One record per storage beneath the root, whether or not a stream in it was \
                 recognised. A storage with no recognised stream is a note this build could not \
                 read, and it is listed rather than dropped."
            },
        });
        if let Some(m) = coverage.as_object_mut() {
            if let Some(cap) = &file.capped {
                m.insert("content_incomplete".into(), serde_json::json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    serde_json::json!(seance_core::io::IncompleteReason::CapReached.as_str()),
                );
                m.insert("content_incomplete_detail".into(), serde_json::json!(cap));
            }
            if short {
                m.insert("content_incomplete".into(), serde_json::json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    serde_json::json!(seance_core::io::IncompleteReason::ShortRead.as_str()),
                );
                m.insert(
                    "short_read_detail".into(),
                    serde_json::json!(format!(
                        "{read} of {size} bytes were readable, so this file may hold notes that \
                         are not reported here."
                    )),
                );
            }
            stamp_snt(m);
        }
        out.push(
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, coverage)
                .with_parent(artifact.id),
        );
        for note in &file.notes {
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    note.to_json(source_file),
                )
                .with_parent(artifact.id),
            );
        }
        out
    }

    fn read_plum(&self, artifact: &Artifact, source_file: &str) -> Vec<Artifact> {
        let Some(source) = artifact.data.as_ref() else {
            return vec![];
        };
        // The same staging discipline the Windows Timeline reader uses: spill
        // to a temporary file, and stamp the record when the spill was short.
        let temp =
            match seance_sqlite_util::TempDb::spill(source.as_ref(), "stickynotes", MAX_DB_BYTES) {
                Ok(t) => t,
                Err(e) => {
                    return vec![Artifact::new(
                        artifact.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        plum::parse_status(
                            source_file,
                            "DatabaseUnreadable",
                            format!("This database could not be staged for reading ({e})."),
                            Vec::new(),
                            None,
                        ),
                    )
                    .with_parent(artifact.id)];
                }
            };
        let records = match temp.open() {
            Ok(conn) => {
                let mut records = plum::read(&conn, source_file);
                // The app hard-deletes a note (PLUM-1), so the only trace of
                // one is an older image of its row in the WAL. The WAL is
                // read again from the source rather than from the spill, and
                // only when the spill staged it whole.
                if temp.wal_incomplete_reason().is_none() {
                    if let Some(wal) = source.open_sibling("-wal") {
                        if wal.size() > 0 && wal.size() <= MAX_WAL_BYTES {
                            let bytes = seance_core::io::read_capped(wal.as_ref(), MAX_WAL_BYTES);
                            records.extend(plum::recover_deleted_from_wal(
                                &conn,
                                &bytes,
                                source.as_ref(),
                                source_file,
                            ));
                        }
                    }
                }
                records
            }
            Err(e) => vec![plum::parse_status(
                source_file,
                "DatabaseUnreadable",
                format!("The staged database could not be opened ({e})."),
                Vec::new(),
                None,
            )],
        };
        let mut out: Vec<Artifact> = records
            .into_iter()
            .map(|r| {
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, r)
                    .with_parent(artifact.id)
            })
            .collect();
        temp.stamp_incompleteness(artifact.case_id, artifact.id, source_file, &mut out);
        out
    }
}
