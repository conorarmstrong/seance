//! Voice Memos: the recordings listed in `CloudRecordings.db`, with the audio
//! file each names looked for beside the database.
//!
//! **Where it is.** iOS 12–16 keep the store in `Media/Recordings/` (iOS 16:
//! `Library/Recordings/`); iOS 17/18 keep it in the Voice Memos app group,
//! `Containers/Shared/AppGroup/<uuid>/Recordings/`. The file name is what
//! selects it, wherever it is, and the `.m4a` files sit in the same
//! directory in every generation held.
//!
//! **Validated on** the MSAB 2026 CTF iPhone 12 (iOS 18.7, AppGroup
//! location: 3 recordings, all three `.m4a` present) and the Cellebrite 2023
//! CTF "Abe" iPhone X (iOS 16.5: 31 recordings in two folders, one with an
//! eviction date). Four stores with the table and no row (Hickman iOS 13.4.1
//! and 14.3, Magnet 2020 and 2021) are the empty case.
//!
//! **What is not claimed.**
//! * `ZEVICTIONDATE` is published under its column's name. The community
//!   reading is "moved to Recently Deleted"; one row on one device carries
//!   it, 28 s after its recording, so the meaning is not validated and the
//!   record says so.
//! * `ZFLAGS` is published as a number; its bits are not named.
//! * No transcript is read: the MSAB recordings carry none (no `tsrp`
//!   atom), so a reader would have nothing to be checked against.
//! * The title: iOS 16+ keeps the displayed title in `ZENCRYPTEDTITLE` (a
//!   misnomer: it is plain text on both devices held) and, on iOS 18, an ISO
//!   timestamp in `ZCUSTOMLABEL`. The record says which column it took.

use std::collections::HashMap;

use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{table_columns, RowDrops};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    cfloat, cint, cstr, expected_table, insert_cocoa, parent_record, query_unusable_artifact,
    with_db,
};

/// Ceiling on recordings carried into one case from a single store.
const MAX_RECORDINGS: usize = 100_000;

const FILE_NAME: &str = "CloudRecordings.db";

/// Voice Memos recordings (`CloudRecordings.db`).
pub struct VoiceMemosParser;

impl ForensicsModule for VoiceMemosParser {
    fn id(&self) -> &str {
        "plugin.ios.voice_memos"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
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
        Ok(with_db(
            artifact,
            &["cloudrecordings.db"],
            "voicememos",
            |conn, ds, case, parent| read_store(conn, ds, case, parent),
        ))
    }
}

/// Folder names by `Z_PK` (`ZFOLDER.ZENCRYPTEDNAME`, plain text on the
/// devices held). Empty when the table is absent or will not read.
fn folders(conn: &Connection) -> HashMap<i64, String> {
    let mut out = HashMap::new();
    let cols = table_columns(conn, "ZFOLDER");
    if !cols.contains("zencryptedname") {
        return out;
    }
    if let Ok(mut stmt) = conn.prepare("SELECT Z_PK, ZENCRYPTEDNAME FROM ZFOLDER") {
        if let Ok(rows) = stmt.query_map([], |r| Ok((cint(r, 0), cstr(r, 1)))) {
            for (pk, name) in rows.flatten() {
                if let (Some(pk), Some(name)) = (pk, name) {
                    out.insert(pk, name);
                }
            }
        }
    }
    out
}

/// The audio file's name: the last component of `ZPATH`, which is a bare
/// name on iOS 17/18 and an absolute device path before.
fn audio_file_name(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    (!name.is_empty() && name != "." && name != "..").then_some(name)
}

fn read_store(conn: &Connection, ds: &dyn DataSource, case: Uuid, parent: Uuid) -> Vec<Artifact> {
    if let Err(owed) = expected_table(
        conn,
        case,
        parent,
        FILE_NAME,
        &["ZCLOUDRECORDING"],
        true,
        true,
    ) {
        return owed;
    }
    let cols = table_columns(conn, "ZCLOUDRECORDING");
    let opt = |c: &str| {
        if cols.contains(&c.to_ascii_lowercase()) {
            c.to_string()
        } else {
            "NULL".to_string()
        }
    };
    let sql = format!(
        "SELECT Z_PK, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM ZCLOUDRECORDING ORDER BY {} , Z_PK LIMIT {}",
        opt("ZDATE"),
        opt("ZDURATION"),
        opt("ZCUSTOMLABEL"),
        opt("ZENCRYPTEDTITLE"),
        opt("ZPATH"),
        opt("ZUNIQUEID"),
        opt("ZFLAGS"),
        opt("ZEVICTIONDATE"),
        opt("ZFOLDER"),
        opt("ZDATE"),
        MAX_RECORDINGS + 1
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            return vec![query_unusable_artifact(
                case,
                parent,
                FILE_NAME,
                "ZCLOUDRECORDING",
                &e,
            )]
        }
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            cint(r, 0),
            cfloat(r, 1),
            cfloat(r, 2),
            cstr(r, 3),
            cstr(r, 4),
            cstr(r, 5),
            cstr(r, 6),
            cint(r, 7),
            cfloat(r, 8),
            cint(r, 9),
        ))
    });
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            return vec![query_unusable_artifact(
                case,
                parent,
                FILE_NAME,
                "ZCLOUDRECORDING",
                &e,
            )]
        }
    };
    let folder_names = folders(conn);
    let can_look = ds.supports_siblings();
    let mut out = Vec::new();
    let mut drops = RowDrops::default();
    let (mut present, mut absent, mut unresolved, mut evicted) = (0usize, 0usize, 0usize, 0usize);
    let mut capped = false;
    for row in rows {
        let (pk, date, duration, label, title, path, uid, flags, eviction, folder) = match row {
            Ok(r) => r,
            Err(e) => {
                drops.record(&e);
                continue;
            }
        };
        if out.len() >= MAX_RECORDINGS {
            capped = true;
            break;
        }
        let mut m = Map::new();
        m.insert("type".into(), json!("VoiceMemo"));
        m.insert("subtype".into(), json!("voice_memo"));
        m.insert("platform".into(), json!("iOS"));
        m.insert("source".into(), json!(FILE_NAME));
        if let Some(pk) = pk {
            m.insert("recording_id".into(), json!(pk));
        }
        // The displayed title: ZENCRYPTEDTITLE where the generation has it,
        // ZCUSTOMLABEL before.
        let (shown, from) = match (&title, &label) {
            (Some(t), _) => (Some(t.clone()), "ZENCRYPTEDTITLE"),
            (None, Some(l)) => (Some(l.clone()), "ZCUSTOMLABEL"),
            (None, None) => (None, ""),
        };
        if let Some(t) = &shown {
            m.insert("title".into(), json!(t));
            m.insert("title_source".into(), json!(from));
        }
        if let Some(l) = &label {
            m.insert("custom_label".into(), json!(l));
        }
        if let Some(d) = date {
            insert_cocoa(&mut m, "date", d, "ZCLOUDRECORDING.ZDATE");
        }
        if let Some(d) = duration {
            m.insert("duration_seconds".into(), json!(d));
        }
        if let Some(u) = uid {
            m.insert("unique_id".into(), json!(u));
        }
        if let Some(f) = flags {
            m.insert("flags".into(), json!(f));
        }
        if let Some(f) = folder {
            m.insert("folder_id".into(), json!(f));
            if let Some(n) = folder_names.get(&f) {
                m.insert("folder".into(), json!(n));
            }
        }
        if let Some(e) = eviction {
            if crate::cocoa_secs_to_unix_nanos(e).is_some() {
                evicted += 1;
                insert_cocoa(&mut m, "eviction_date", e, "ZCLOUDRECORDING.ZEVICTIONDATE");
                m.insert("eviction_date_meaning_validated".into(), json!(false));
            }
        }
        if let Some(p) = &path {
            m.insert("path".into(), json!(p));
            if let Some(name) = audio_file_name(p) {
                m.insert("file_name".into(), json!(name));
                if !can_look {
                    unresolved += 1;
                    m.insert(
                        "audio_unresolved".into(),
                        json!("source_cannot_open_neighbours"),
                    );
                } else {
                    match ds.open_relative(name) {
                        Some(audio) => {
                            present += 1;
                            m.insert("audio_present".into(), json!(true));
                            m.insert("audio_bytes".into(), json!(audio.size()));
                        }
                        None if ds.relative_withheld(name) => {
                            unresolved += 1;
                            m.insert("audio_unresolved".into(), json!("neighbour_withheld"));
                        }
                        None => {
                            absent += 1;
                            m.insert("audio_present".into(), json!(false));
                            m.insert(
                                "audio_absent_detail".into(),
                                json!("no file of this name beside the database"),
                            );
                        }
                    }
                }
            }
        }
        m.insert(
            "name".into(),
            json!(format!(
                "Voice memo: {}",
                shown.as_deref().unwrap_or("(untitled)")
            )),
        );
        out.push(parent_record(case, parent, Value::Object(m)));
    }
    let recordings = out.len();
    if let Some(marker) = drops.marker(
        case,
        parent,
        "VoiceMemoIncomplete",
        "ZCLOUDRECORDING",
        recordings,
    ) {
        out.push(marker);
    }
    let mut s = Map::new();
    s.insert("type".into(), json!("VoiceMemosSummary"));
    s.insert("platform".into(), json!("iOS"));
    s.insert("source".into(), json!(FILE_NAME));
    s.insert("recordings".into(), json!(recordings));
    s.insert("audio_present".into(), json!(present));
    s.insert("audio_absent".into(), json!(absent));
    s.insert("audio_unresolved".into(), json!(unresolved));
    s.insert("with_eviction_date".into(), json!(evicted));
    s.insert("folders".into(), json!(folder_names.len()));
    s.insert("transcripts_read".into(), json!(false));
    s.insert("rows_undecodable".into(), json!(drops.dropped()));
    s.insert("records_recovered".into(), json!(recordings));
    if capped || drops.dropped() > 0 {
        s.insert("inventory_incomplete".into(), json!(true));
        s.insert(
            "inventory_incomplete_reason".into(),
            json!(if capped {
                seance_core::io::IncompleteReason::CapReached.as_str()
            } else {
                seance_core::io::IncompleteReason::UnresolvedStructure.as_str()
            }),
        );
    }
    s.insert(
        "name".into(),
        json!(format!(
            "Voice Memos: {recordings} recording(s), {present} with audio beside the store"
        )),
    );
    out.push(parent_record(case, parent, Value::Object(s)));
    out
}
