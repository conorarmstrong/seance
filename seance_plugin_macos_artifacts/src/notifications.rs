//! Notification Center history — `usernoted` `db2/db`.
//!
//! macOS keeps every delivered notification in a SQLite database at
//! `~/Library/Group Containers/group.com.apple.usernoted/db2/db`. Each `record`
//! row references an `app` (bundle identifier), carries a `delivered_date`, and
//! stores the notification itself as a binary-plist `data` blob whose `req` dict
//! holds the title (`titl`), body (`body`) and subtitle (`subt`). This surfaces
//! the message content of iMessage/Slack/Teams/etc. alerts that flashed on
//! screen — often the only on-disk copy for apps that store nothing else.

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{probe_table, Presence, TempDb};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    basename_lower, cfabsolute_to_unix_parts, staged_looks_like_sqlite, to_rfc3339_nanos, unix_ns,
    MAX_DB_BYTES,
};

/// Emits one `Notification` record per delivered notification.
pub struct NotificationsParser;

/// Whether a file is worth staging as the usernoted database.
#[derive(Debug, PartialEq, Eq)]
enum Candidate {
    /// Named or located as the usernoted database.
    Yes,
    /// Not this reader's file.
    No,
    /// A bare `db` with no recorded path: only a SQLite file is worth the
    /// spill, and the `record`/`app` probe decides the rest.
    IfSqlite,
}

/// The usernoted db is literally named `db`; match that plus the safer
/// `usernoted`-tagged copies an examiner may have renamed on extraction.
///
/// A bare `db` is ambiguous. Where a path was recorded it must name
/// `usernoted`; where none was, the file is staged only if its first sixteen
/// bytes are the SQLite header. `.unwrap_or(true)` used to accept every
/// pathless `db` and spill up to 512 MiB of it to find out what it was
/// (HUNT-179).
fn is_notifications_db(name: &str, path: Option<&str>) -> Candidate {
    let b = basename_lower(name);
    if b == "db" {
        return match path {
            Some(p) if p.to_lowercase().contains("usernoted") => Candidate::Yes,
            Some(_) => Candidate::No,
            None => Candidate::IfSqlite,
        };
    }
    if b.contains("usernoted") {
        Candidate::Yes
    } else {
        Candidate::No
    }
}

/// What could be read of one notification's `data` blob.
#[derive(Debug, Default)]
struct Content {
    title: Option<String>,
    body: Option<String>,
    subtitle: Option<String>,
    /// The blob did not parse as a property list.
    unparsable: bool,
    /// Keys present whose value could not be read as text (a `UID` that does
    /// not resolve to a string, or a value of another type).
    undecoded: Vec<&'static str>,
}

/// Pull `titl`/`body`/`subt` out of a notification `data` bplist. The strings
/// live in a `req` dict, but the blob is sometimes an archiver graph, so scan
/// recursively for the first dict that carries them — and in an archiver
/// graph, follow a `UID` value through `$objects` to the string it names.
fn extract_content(blob: &[u8]) -> Content {
    let Ok(value) = plist::from_bytes::<plist::Value>(blob) else {
        return Content {
            unparsable: true,
            ..Content::default()
        };
    };
    let objects: Option<&[plist::Value]> = value
        .as_dictionary()
        .filter(|d| {
            matches!(d.get("$archiver"), Some(plist::Value::String(a)) if a == "NSKeyedArchiver")
        })
        .and_then(|d| d.get("$objects"))
        .and_then(|o| o.as_array())
        .map(Vec::as_slice);

    /// The text a value stands for: itself, or the string a `UID` names.
    fn text(v: &plist::Value, objects: Option<&[plist::Value]>) -> Option<String> {
        match v {
            plist::Value::String(s) => Some(s.clone()),
            plist::Value::Uid(u) => objects
                .and_then(|o| o.get(u.get() as usize))
                .and_then(|t| t.as_string())
                .filter(|s| *s != "$null")
                .map(String::from),
            _ => None,
        }
    }

    fn walk(v: &plist::Value, objects: Option<&[plist::Value]>, out: &mut Content, depth: usize) {
        if depth > 16 || (out.title.is_some() && out.body.is_some()) {
            return;
        }
        match v {
            plist::Value::Dictionary(d) => {
                if d.contains_key("titl") || d.contains_key("body") {
                    for (key, slot) in [
                        ("titl", &mut out.title),
                        ("body", &mut out.body),
                        ("subt", &mut out.subtitle),
                    ] {
                        if slot.is_some() {
                            continue;
                        }
                        if let Some(raw) = d.get(key) {
                            *slot = text(raw, objects);
                            // A `$null` reference is the archive's absent value,
                            // not an unread one.
                            let is_null_ref = matches!(raw, plist::Value::Uid(u)
                                if objects.and_then(|o| o.get(u.get() as usize))
                                    .and_then(|t| t.as_string()) == Some("$null"));
                            if slot.is_none() && !is_null_ref && !out.undecoded.contains(&key) {
                                out.undecoded.push(key);
                            }
                        }
                    }
                }
                for (_, child) in d.iter() {
                    walk(child, objects, out, depth + 1);
                }
            }
            plist::Value::Array(a) => {
                for child in a {
                    walk(child, objects, out, depth + 1);
                }
            }
            _ => {}
        }
    }
    let mut out = Content::default();
    walk(&value, objects, &mut out, 0);
    // A key read later from another dict is no longer undecoded.
    out.undecoded.retain(|k| match *k {
        "titl" => out.title.is_none(),
        "body" => out.body.is_none(),
        _ => out.subtitle.is_none(),
    });
    out
}

impl ForensicsModule for NotificationsParser {
    fn id(&self) -> &str {
        "macos.notifications"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let path = artifact
            .metadata
            .get("path")
            .or_else(|| artifact.metadata.get("parent_path"))
            .and_then(|v| v.as_str());
        let candidate = is_notifications_db(name, path);
        if candidate == Candidate::No {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        if candidate == Candidate::IfSqlite {
            let mut header = [0u8; 16];
            let got = seance_core::io::read_full(ds.as_ref(), 0, &mut header);
            if got < header.len() || &header != b"SQLite format 3\0" {
                return Ok(Vec::new());
            }
        }

        let temp = TempDb::spill(ds.as_ref(), "usernoted", MAX_DB_BYTES)
            .map_err(|e| ModuleError::ParsingError(format!("spill failed: {e}")))?;

        let result = (|| -> Result<Vec<Artifact>> {
            if !staged_looks_like_sqlite(temp.path()) {
                return Ok(Vec::new());
            }
            let conn = temp.open().context("open notifications database")?;
            // The record+app pair is what makes this the usernoted db, not some
            // other file literally named "db".
            match (probe_table(&conn, "record"), probe_table(&conn, "app")) {
                (Presence::Present, Presence::Present) => {}
                (Presence::Undetermined(why), _) | (_, Presence::Undetermined(why)) => {
                    anyhow::bail!("schema unreadable: {why}")
                }
                _ => return Ok(Vec::new()),
            }
            parse_records(&conn, artifact.case_id, artifact.id)
        })();

        match result {
            Ok(mut artifacts) => {
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!(
                    "NotificationsParser: {} notifications from {name}",
                    artifacts.len()
                );
                Ok(artifacts)
            }
            Err(e) => {
                warn!("NotificationsParser failed on {name}: {e}");
                Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        // Not `Notification`: a failed read filed as one more
                        // notification is a shortfall nobody is shown.
                        "type": "NotificationParseStatus",
                        "subtype": "parse_incomplete",
                        "file_name": name,
                        "status": "ParseFailed",
                        "error": e.to_string(),
                        "content_incomplete": true,
                        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                        "content_incomplete_detail": format!(
                            "{name} could not be read ({e}); none of its notifications \
                             were extracted"
                        ),
                    }),
                )
                .with_parent(artifact.id)])
            }
        }
    }
}

fn record_columns(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(record)")?;
    let set = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(set)
}

fn parse_records(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Result<Vec<Artifact>> {
    let cols = record_columns(conn)?;
    let delivered = if cols.contains("delivered_date") {
        "record.delivered_date"
    } else if cols.contains("date") {
        "record.date"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT app.identifier, {delivered}, record.data \
         FROM record LEFT JOIN app ON record.app_id = app.app_id \
         ORDER BY {delivered} DESC"
    );

    let mut stmt = conn.prepare(&sql).context("prepare record query")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,  // bundle id
                row.get::<_, Option<f64>>(1)?,     // delivered_date (CFAbsoluteTime)
                row.get::<_, Option<Vec<u8>>>(2)?, // data blob
            ))
        })
        .context("query record")?;

    let mut out = Vec::new();
    for row in rows {
        let (bundle, delivered_cf, blob) = row.context("read record row")?;
        let content = blob.as_deref().map(extract_content);
        let (title, body, subtitle) = content
            .as_ref()
            .map(|c| (c.title.clone(), c.body.clone(), c.subtitle.clone()))
            .unwrap_or((None, None, None));

        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("Notification"));
        meta.insert("subtype".into(), json!("usernoted"));
        meta.insert("app_bundle_id".into(), json!(bundle));
        meta.insert("title".into(), json!(title));
        meta.insert("body".into(), json!(body));
        meta.insert("subtitle".into(), json!(subtitle));
        if let Some((unix, nanos)) = delivered_cf.and_then(cfabsolute_to_unix_parts) {
            meta.insert("timestamp".into(), json!(unix));
            if let Some(ns) = unix_ns(unix, nanos) {
                meta.insert("timestamp_ns".into(), json!(ns));
            }
            if let Some(r) = to_rfc3339_nanos(unix, nanos) {
                meta.insert("timestamp_rfc3339".into(), json!(r));
            }
        }
        // Three nulls must not read as a notification that said nothing when
        // the truth is that its content could not be read (HUNT-179).
        match &content {
            None => {
                meta.insert(
                    "content_note".into(),
                    json!("the record carries no data blob; there is no title, body or subtitle to decode"),
                );
            }
            Some(c) if c.unparsable => {
                meta.insert("content_incomplete".into(), json!(true));
                meta.insert(
                    "content_incomplete_reason".into(),
                    json!(IncompleteReason::UnresolvedStructure.as_str()),
                );
                meta.insert(
                    "content_incomplete_detail".into(),
                    json!(format!(
                        "the notification's data blob ({} bytes) did not parse as a property \
                         list; its title, body and subtitle were not read",
                        blob.as_ref().map_or(0, Vec::len)
                    )),
                );
            }
            Some(c) if !c.undecoded.is_empty() => {
                meta.insert("content_incomplete".into(), json!(true));
                meta.insert(
                    "content_incomplete_reason".into(),
                    json!(IncompleteReason::UnresolvedStructure.as_str()),
                );
                meta.insert(
                    "content_incomplete_detail".into(),
                    json!(format!(
                        "the notification's data blob holds {} but not as text this reader \
                         can decode; those fields are null because they were not read, not \
                         because they were empty",
                        c.undecoded.join(", ")
                    )),
                );
            }
            Some(_) => {}
        }
        let app = bundle.as_deref().unwrap_or("(unknown app)");
        let summary = title
            .as_deref()
            .or(body.as_deref())
            .unwrap_or("(no content decoded)");
        meta.insert(
            "name".into(),
            json!(format!("Notification from {app}: {summary}")),
        );

        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta.into())
                .with_parent(parent_id)
                .with_subtype("usernoted"),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    /// A notification `data` blob: a binary plist with the `req` dict Apple uses.
    fn notification_blob(title: &str, body: &str, subt: &str) -> Vec<u8> {
        let mut req = plist::Dictionary::new();
        req.insert("titl".into(), plist::Value::String(title.into()));
        req.insert("body".into(), plist::Value::String(body.into()));
        req.insert("subt".into(), plist::Value::String(subt.into()));
        let mut top = plist::Dictionary::new();
        top.insert("req".into(), plist::Value::Dictionary(req));
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(top)).unwrap();
        buf
    }

    fn build_db(rows: &[(&str, f64, Vec<u8>)]) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("un_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE app (app_id INTEGER PRIMARY KEY, identifier VARCHAR);
                 CREATE TABLE record (rec_id INTEGER PRIMARY KEY, app_id INTEGER,
                    uuid BLOB, data BLOB, delivered_date REAL);",
            )
            .unwrap();
            for (i, (bundle, ts, blob)) in rows.iter().enumerate() {
                let app_id = (i + 1) as i64;
                conn.execute(
                    "INSERT INTO app VALUES (?1,?2)",
                    rusqlite::params![app_id, bundle],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO record (app_id,uuid,data,delivered_date) VALUES (?1,NULL,?2,?3)",
                    rusqlite::params![app_id, blob, ts],
                )
                .unwrap();
            }
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": name, "path": "/Users/x/Library/Group Containers/group.com.apple.usernoted/db2/db" }),
        );
        NotificationsParser.process(&art).unwrap()
    }

    #[test]
    fn parses_notification_content_and_app_and_time() {
        let blob = notification_blob("New Message", "Meet at 5pm", "from Alice");
        let db = build_db(&[("com.apple.MobileSMS", 700_000_000.0, blob)]);
        let out = run(db, "db");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["app_bundle_id"], json!("com.apple.MobileSMS"));
        assert_eq!(m["title"], json!("New Message"));
        assert_eq!(m["body"], json!("Meet at 5pm"));
        assert_eq!(m["subtitle"], json!("from Alice"));
        assert_eq!(
            m["timestamp_rfc3339"].as_str().unwrap(),
            "2023-03-08T20:26:40+00:00"
        );
    }

    #[test]
    fn newest_first_and_undecodable_blob_is_not_fatal() {
        let good = notification_blob("Hi", "there", "");
        let db = build_db(&[
            ("com.a", 100.0, b"not a plist".to_vec()),
            ("com.b", 900.0, good),
        ]);
        let out = run(db, "db");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].metadata["app_bundle_id"], json!("com.b")); // newest first
        assert_eq!(out[0].metadata["title"], json!("Hi"));
        // The undecodable one still produces a record (app + time), just no body.
        assert_eq!(out[1].metadata["app_bundle_id"], json!("com.a"));
        assert_eq!(out[1].metadata["title"], json!(null));
    }

    /// `delivered_date` is a REAL CFAbsoluteTime; notifications from a busy app
    /// arrive several to a second and lose their order without the fraction.
    #[test]
    fn a_fractional_delivery_time_keeps_its_sub_second_precision() {
        let blob = notification_blob("Hi", "there", "");
        let db = build_db(&[("com.a", 700_000_000.5, blob)]);
        let out = run(db, "db");
        let m = &out[0].metadata;
        assert_eq!(m["timestamp"], json!(700_000_000 + crate::CF_EPOCH_OFFSET));
        assert_eq!(
            m["timestamp_ns"],
            json!((700_000_000 + crate::CF_EPOCH_OFFSET) * 1_000_000_000 + 500_000_000)
        );
        assert_eq!(
            m["timestamp_rfc3339"].as_str().unwrap(),
            "2023-03-08T20:26:40.500+00:00"
        );
    }

    #[test]
    fn a_bare_db_without_usernoted_path_is_skipped() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 16]))),
            json!({ "name": "db", "path": "/some/other/db" }),
        );
        assert!(NotificationsParser.process(&art).unwrap().is_empty());
    }

    /// A source that fails the test if anything past the SQLite header is read.
    #[derive(Debug)]
    struct HeaderOnly {
        declared: u64,
    }
    impl seance_core::data_source::DataSource for HeaderOnly {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                offset < 16,
                "read at {offset}: a file named `db` with no path was spilled before \
                 it was known to be SQLite"
            );
            let n = buf.len().min(16 - offset as usize);
            buf[..n].fill(0);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.declared
        }
    }

    /// HUNT-179. `.unwrap_or(true)` accepted any basename `db` with no `path`
    /// and spilled up to 512 MiB of it to find out what it was.
    #[test]
    fn a_bare_db_with_no_path_is_not_spilled_unless_it_is_sqlite() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(HeaderOnly {
                declared: 256 * 1024 * 1024,
            })),
            json!({ "name": "db" }),
        );
        assert!(NotificationsParser.process(&art).unwrap().is_empty());
    }

    /// A real usernoted database handed over with no path is still read: the
    /// header says SQLite, and the `record`/`app` pair decides the rest.
    #[test]
    fn a_bare_sqlite_db_with_no_path_is_still_read() {
        let blob = notification_blob("Hi", "there", "");
        let db = build_db(&[("com.a", 700_000_000.0, blob)]);
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(db))),
            json!({ "name": "db" }),
        );
        let out = NotificationsParser.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["title"], json!("Hi"));
    }

    /// HUNT-179. A blob that will not parse yielded `null` title, body and
    /// subtitle with nothing saying they were unread rather than empty.
    #[test]
    fn an_undecodable_blob_says_its_content_was_not_read() {
        let db = build_db(&[("com.a", 100.0, b"not a plist".to_vec())]);
        let out = run(db, "db");
        let m = &out[0].metadata;
        assert_eq!(m["title"], json!(null));
        assert_eq!(m["content_incomplete"], json!(true), "{m}");
        assert_eq!(
            m["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap_or_default()
            .contains("did not parse"));
    }

    /// A record with no `data` blob at all has nothing to decode, and says so
    /// rather than presenting three nulls.
    #[test]
    fn an_absent_blob_is_stated() {
        let dir = std::env::temp_dir().join(format!("un_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE app (app_id INTEGER PRIMARY KEY, identifier VARCHAR);
                 CREATE TABLE record (rec_id INTEGER PRIMARY KEY, app_id INTEGER,
                    uuid BLOB, data BLOB, delivered_date REAL);
                 INSERT INTO app VALUES (1, 'com.a');
                 INSERT INTO record (app_id, uuid, data, delivered_date)
                    VALUES (1, NULL, NULL, 100.0);",
            )
            .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let out = run(bytes, "db");
        let m = &out[0].metadata;
        assert_eq!(m["title"], json!(null));
        assert!(
            m["content_note"]
                .as_str()
                .unwrap_or_default()
                .contains("no data blob"),
            "{m}"
        );
        assert!(
            m.get("content_incomplete").is_none(),
            "nothing was left unread"
        );
    }

    /// An archiver-graph blob — `$objects` with `titl`/`body` as `UID`
    /// references, the layout the module comment says the blob sometimes has —
    /// yielded nulls. The references are followed.
    #[test]
    fn uid_typed_title_and_body_are_resolved_through_the_archive() {
        use plist::{Dictionary, Uid, Value};
        let mut req = Dictionary::new();
        req.insert("titl".into(), Value::Uid(Uid::new(2)));
        req.insert("body".into(), Value::Uid(Uid::new(3)));
        req.insert("subt".into(), Value::Uid(Uid::new(5)));
        req.insert("$class".into(), Value::Uid(Uid::new(4)));
        let mut class = Dictionary::new();
        class.insert(
            "$classname".into(),
            Value::String("UNNotificationContent".into()),
        );
        class.insert(
            "$classes".into(),
            Value::Array(vec![
                Value::String("UNNotificationContent".into()),
                Value::String("NSObject".into()),
            ]),
        );
        let mut top = Dictionary::new();
        top.insert("root".into(), Value::Uid(Uid::new(1)));
        let mut archive = Dictionary::new();
        archive.insert("$version".into(), Value::Integer(100_000.into()));
        archive.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
        archive.insert("$top".into(), Value::Dictionary(top));
        archive.insert(
            "$objects".into(),
            Value::Array(vec![
                Value::String("$null".into()),
                Value::Dictionary(req),
                Value::String("New Message".into()),
                Value::String("Meet at 5pm".into()),
                Value::Dictionary(class),
                // A subtitle reference to something that is not a string.
                Value::Integer(7.into()),
            ]),
        );
        let mut blob = Vec::new();
        plist::to_writer_binary(&mut blob, &Value::Dictionary(archive)).unwrap();
        let db = build_db(&[("com.apple.MobileSMS", 700_000_000.0, blob)]);
        let out = run(db, "db");
        let m = &out[0].metadata;
        assert_eq!(m["title"], json!("New Message"), "{m}");
        assert_eq!(m["body"], json!("Meet at 5pm"));
        assert_eq!(m["subtitle"], json!(null));
        // The subtitle was there and could not be read as text: said, not null.
        assert_eq!(m["content_incomplete"], json!(true), "{m}");
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap_or_default()
            .contains("subt"));
    }

    /// plaso's `mac_notificationcenter.db`, a real usernoted database
    /// (gitignored reference tree; skipped where absent): every record's
    /// content decodes, so none carries the unread-content stamp.
    #[test]
    fn the_real_usernoted_database_decodes_without_a_content_stamp() {
        let path = std::path::Path::new("../reference/plaso/test_data/mac_notificationcenter.db");
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("skipping: {} not present (gitignored)", path.display());
            return;
        };
        let out = run(bytes, "db");
        // The harness hands over no `-wal` sibling, so the reader also says
        // the log was not reachable; that marker is the only other record.
        let notes: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == "Notification")
            .collect();
        assert_eq!(notes.len(), 6, "the database holds six records");
        for a in notes {
            assert!(a.metadata["title"].is_string(), "{}", a.metadata);
            assert!(a.metadata["body"].is_string(), "{}", a.metadata);
            assert!(a.metadata.get("content_incomplete_detail").is_none());
            assert_ne!(
                a.metadata["content_incomplete_reason"],
                json!("unresolved_structure"),
                "{}",
                a.metadata
            );
        }
    }
}
