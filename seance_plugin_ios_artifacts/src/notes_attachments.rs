//! Notes attachments: every `ICAttachment` row, its `ICMedia` row, and the
//! media file under `Accounts/<account>/Media/` beside `NoteStore.sqlite`.
//!
//! **The path.** `Accounts/<ICAccount.ZIDENTIFIER>/Media/<ICMedia.ZIDENTIFIER>/`
//! then, on iOS 17/18, the media's generation directory
//! (`ICMedia.ZGENERATION1`, e.g. `1_B5E2…`), then the file: `ICMedia.ZFILENAME`,
//! or — for a password-protected attachment, whose media row names no file —
//! the media identifier itself, holding ciphertext.
//!
//! **Validated on** the MSAB 2026 iPhone 12 (iOS 18.7: 11 attachments, the
//! live PNG `Screenshot 2025-12-11 at 4.29.52 PM.png` at its path with 83,062
//! bytes, five locked media under their identifiers, and the two attachments
//! of deleted note 73 whose files are present and empty) and the Magnet 2021
//! iPhone 8 (iOS 14: `IMG_0003.heic` under `Media/<id>/` with no generation
//! directory).
//!
//! **Not read:** drawings (`com.apple.paper`) keep a bundle, not a media file,
//! and are listed with `media_not_applicable`; previews and fallback images
//! are not linked; the ciphertext of a locked attachment is not decrypted.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;
use seance_core::artifact::Artifact;
use seance_core::data_source::DataSource;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{cfloat, cint, cstr, insert_cocoa, parent_record};

/// Ceiling on attachments carried into one case from a single store.
const MAX_ATTACHMENTS: usize = 200_000;

/// What the notes walk knows of a note, for its attachments.
pub(crate) struct NoteInfo {
    pub(crate) title: Option<String>,
    pub(crate) deleted: Option<bool>,
    pub(crate) account: Option<i64>,
}

pub(crate) struct AttachmentRead {
    pub(crate) records: Vec<Artifact>,
    pub(crate) per_note: HashMap<i64, usize>,
    pub(crate) deleted: usize,
    pub(crate) media_present: usize,
    pub(crate) media_absent: usize,
    pub(crate) media_unresolved: usize,
    pub(crate) error: Option<String>,
    pub(crate) capped: bool,
}

/// The inputs the notes walk has already resolved.
pub(crate) struct Context<'a> {
    pub(crate) attachment_ent: i64,
    pub(crate) cols: &'a HashSet<String>,
    pub(crate) accounts: &'a HashMap<i64, String>,
    pub(crate) account_cols: &'a [String],
    pub(crate) notes: &'a HashMap<i64, NoteInfo>,
}

pub(crate) fn read_attachments(
    conn: &Connection,
    ds: &dyn DataSource,
    case: Uuid,
    parent: Uuid,
    cx: &Context<'_>,
) -> AttachmentRead {
    let mut read = AttachmentRead {
        records: Vec::new(),
        per_note: HashMap::new(),
        deleted: 0,
        media_present: 0,
        media_absent: 0,
        media_unresolved: 0,
        error: None,
        capped: false,
    };
    let col = |alias: &str, c: &str| {
        if cx.cols.contains(&c.to_ascii_lowercase()) {
            format!("{alias}.{c}")
        } else {
            "NULL".to_string()
        }
    };
    let acct = |alias: &str| {
        if cx.account_cols.is_empty() {
            "NULL".to_string()
        } else {
            cx.account_cols
                .iter()
                .map(|c| format!("{alias}.{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let n_acct = cx.account_cols.len().max(1);
    let media_join = if cx.cols.contains("zmedia") {
        "a.ZMEDIA"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT a.Z_PK, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, \
                m.Z_PK, {}, {}, {}, {}, {}, {}, {} \
         FROM ZICCLOUDSYNCINGOBJECT a LEFT JOIN ZICCLOUDSYNCINGOBJECT m ON m.Z_PK = {media_join} \
         WHERE a.Z_ENT = {} ORDER BY a.Z_PK LIMIT {}",
        col("a", "ZNOTE"),
        col("a", "ZTYPEUTI"),
        col("a", "ZIDENTIFIER"),
        col("a", "ZTITLE"),
        col("a", "ZCREATIONDATE"),
        col("a", "ZMODIFICATIONDATE"),
        col("a", "ZFILESIZE"),
        col("a", "ZSIZEWIDTH"),
        col("a", "ZSIZEHEIGHT"),
        col("a", "ZMARKEDFORDELETION"),
        col("a", "ZISPASSWORDPROTECTED"),
        col("m", "ZIDENTIFIER"),
        col("m", "ZFILENAME"),
        col("m", "ZGENERATION1"),
        col("m", "ZMARKEDFORDELETION"),
        col("m", "ZISPASSWORDPROTECTED"),
        acct("m"),
        acct("a"),
        cx.attachment_ent,
        MAX_ATTACHMENTS + 1
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            read.error = Some(e.to_string());
            return read;
        }
    };
    let first_acct = 18usize;
    let resolve = |r: &rusqlite::Row, first: usize| {
        (0..n_acct)
            .filter_map(|i| cint(r, first + i))
            .find(|a| cx.accounts.contains_key(a))
    };
    let rows = stmt.query_map([], |r| {
        Ok(Row {
            pk: cint(r, 0),
            note: cint(r, 1),
            uti: cstr(r, 2),
            ident: cstr(r, 3),
            title: cstr(r, 4),
            created: cfloat(r, 5),
            modified: cfloat(r, 6),
            size: cint(r, 7),
            width: cfloat(r, 8),
            height: cfloat(r, 9),
            marked: cint(r, 10),
            locked: cint(r, 11),
            media_pk: cint(r, 12),
            media_ident: cstr(r, 13),
            media_file: cstr(r, 14),
            media_gen: cstr(r, 15),
            media_marked: cint(r, 16),
            media_locked: cint(r, 17),
            media_acct: resolve(r, first_acct),
            att_acct: resolve(r, first_acct + n_acct),
        })
    });
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            read.error = Some(e.to_string());
            return read;
        }
    };
    let can_look = ds.supports_siblings();
    for row in rows {
        let row = match row {
            Ok(r) => r,
            Err(e) => {
                read.error = Some(e.to_string());
                break;
            }
        };
        if read.records.len() >= MAX_ATTACHMENTS {
            read.capped = true;
            break;
        }
        let mut m = Map::new();
        m.insert("type".into(), json!("NoteAttachment"));
        m.insert("subtype".into(), json!("note_attachment"));
        m.insert("platform".into(), json!("iOS"));
        if let Some(pk) = row.pk {
            m.insert("attachment_id".into(), json!(pk));
        }
        let note = row.note.and_then(|n| cx.notes.get(&n).map(|i| (n, i)));
        if let Some(n) = row.note {
            m.insert("note_id".into(), json!(n));
            *read.per_note.entry(n).or_default() += 1;
        }
        if let Some((_, info)) = note {
            if let Some(t) = &info.title {
                m.insert("note_title".into(), json!(t));
            }
            m.insert("note_deleted".into(), json!(info.deleted));
        }
        if let Some(u) = &row.uti {
            m.insert("type_uti".into(), json!(u));
        }
        if let Some(i) = &row.ident {
            m.insert("identifier".into(), json!(i));
        }
        if let Some(t) = &row.title {
            m.insert("title".into(), json!(t));
        }
        if let Some(c) = row.created {
            insert_cocoa(&mut m, "created", c, "ICAttachment.ZCREATIONDATE");
            insert_cocoa(&mut m, "date", c, "ICAttachment.ZCREATIONDATE");
        }
        if let Some(c) = row.modified {
            insert_cocoa(&mut m, "modified", c, "ICAttachment.ZMODIFICATIONDATE");
        }
        if let Some(s) = row.size.filter(|&s| s > 0) {
            m.insert("file_size".into(), json!(s));
        }
        if let (Some(w), Some(h)) = (row.width, row.height) {
            if w > 0.0 && h > 0.0 {
                m.insert("width".into(), json!(w));
                m.insert("height".into(), json!(h));
            }
        }
        let marked = row.marked.map(|v| v != 0);
        if let Some(mk) = marked {
            m.insert("marked_for_deletion".into(), json!(mk));
        }
        let note_deleted = note.and_then(|(_, i)| i.deleted);
        let deleted = match (marked, note_deleted) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) | (None, Some(false)) => Some(false),
            (Some(false), None) if note.is_none() => Some(false),
            _ => None,
        };
        if deleted == Some(true) {
            read.deleted += 1;
        }
        m.insert("deleted".into(), json!(deleted));
        let locked = row.locked.unwrap_or(0) != 0 || row.media_locked.unwrap_or(0) != 0;
        m.insert("password_protected".into(), json!(locked));

        match row.media_pk {
            None => {
                m.insert("media_not_applicable".into(), json!(true));
            }
            Some(mpk) => {
                m.insert("media_id".into(), json!(mpk));
                if let Some(mm) = row.media_marked {
                    m.insert("media_marked_for_deletion".into(), json!(mm != 0));
                }
                let account = row
                    .media_acct
                    .or(row.att_acct)
                    .or(note.and_then(|(_, i)| i.account))
                    .and_then(|a| cx.accounts.get(&a));
                let file = match (&row.media_file, locked) {
                    (Some(f), _) => Some(f.clone()),
                    (None, true) => row.media_ident.clone(),
                    (None, false) => None,
                };
                match (account, &row.media_ident, file) {
                    (Some(acct), Some(mid), Some(file)) => {
                        let path = match &row.media_gen {
                            Some(g) => format!("Accounts/{acct}/Media/{mid}/{g}/{file}"),
                            None => format!("Accounts/{acct}/Media/{mid}/{file}"),
                        };
                        m.insert("media_file_name".into(), json!(file));
                        m.insert("media_path".into(), json!(path));
                        if !can_look {
                            read.media_unresolved += 1;
                            m.insert(
                                "media_unresolved".into(),
                                json!("source_cannot_open_neighbours"),
                            );
                        } else {
                            match ds.open_relative(&path) {
                                Some(src) => {
                                    read.media_present += 1;
                                    let n = src.size();
                                    m.insert("media_present".into(), json!(true));
                                    m.insert("media_bytes".into(), json!(n));
                                    if n == 0 {
                                        m.insert("media_empty".into(), json!(true));
                                    }
                                    if locked {
                                        m.insert("media_encrypted".into(), json!(true));
                                    }
                                }
                                None => {
                                    read.media_absent += 1;
                                    m.insert("media_present".into(), json!(false));
                                }
                            }
                        }
                    }
                    (acct, mid, file) => {
                        read.media_unresolved += 1;
                        let why = if acct.is_none() {
                            "the account the media belongs to did not resolve"
                        } else if mid.is_none() {
                            "the media row has no identifier"
                        } else if file.is_none() {
                            "the media row records no file name"
                        } else {
                            "unresolved"
                        };
                        m.insert("media_unresolved".into(), json!(why));
                    }
                }
            }
        }
        m.insert(
            "name".into(),
            json!(format!(
                "Note attachment: {}",
                row.title
                    .as_deref()
                    .or(row.media_file.as_deref())
                    .or(row.uti.as_deref())
                    .unwrap_or("(untyped)")
            )),
        );
        read.records
            .push(parent_record(case, parent, Value::Object(m)));
    }
    read
}

struct Row {
    pk: Option<i64>,
    note: Option<i64>,
    uti: Option<String>,
    ident: Option<String>,
    title: Option<String>,
    created: Option<f64>,
    modified: Option<f64>,
    size: Option<i64>,
    width: Option<f64>,
    height: Option<f64>,
    marked: Option<i64>,
    locked: Option<i64>,
    media_pk: Option<i64>,
    media_ident: Option<String>,
    media_file: Option<String>,
    media_gen: Option<String>,
    media_marked: Option<i64>,
    media_locked: Option<i64>,
    media_acct: Option<i64>,
    att_acct: Option<i64>,
}
