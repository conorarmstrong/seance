#![forbid(unsafe_code)]
//! IE/Edge (legacy) `WebCacheV01.dat` parser.
//!
//! Internet Explorer and legacy (EdgeHTML) Edge keep their history, cache and
//! cookie index in `WebCacheV01.dat`, an **ESE** database. [`WebCacheParser`]
//! opens it with `libesedb` (the same engine the SRUM parser uses), reads the
//! `Containers` table to learn each container's name (History / Content /
//! Cookies / …), then walks each `Container_<id>` table emitting one
//! `WebCacheEntry` [`ParsedRecord`](ArtifactType::ParsedRecord) per cached/visited
//! URL with its access and modified times.
//!
//! # Testing
//!
//! `libesedb` is read-only, so a valid ESE database cannot be synthesised. As
//! with the SRUM parser, the end-to-end path is covered by a **gated** test that
//! runs only when a real `test_data/WebCacheV01.dat` is present. The URL cleanup
//! and record-shaping logic — where mistakes would actually corrupt evidence —
//! are pure functions with ordinary unit tests.
//!
//! # Honesty & robustness
//!
//! A non-ESE file, a database without a `Containers` table, or unreadable rows
//! never panic and never fail the pipeline: whatever parsed is emitted, otherwise
//! an empty result.
//!
//! An empty result is not, however, allowed to mean two different things. The
//! `Containers` table names every container the database holds, so a
//! `Container_<id>` table that will not open is a container the database SAYS is
//! there and the parser could not read — quite unlike a profile with no browsing
//! history. Those, along with rows the ESE layer refuses and a `Containers`
//! table that will not iterate, are counted and published as one
//! `WebCacheParseStatus` record, and every recovered entry is stamped
//! `content_incomplete`. Without it a damaged `WebCacheV01.dat` presents as
//! "this user never browsed the web" (B2-171).
//!
//! # Why a missing table is not automatically a damaged one
//!
//! That stamp only works if it stays rare. A warning an examiner sees on every
//! Windows image is a warning they stop reading, and it then fails on the case
//! where it mattered. So the two ways a declared container can yield nothing are
//! kept apart:
//!
//! * The catalog holds no `Container_<id>` table at all. The row outlived its
//!   table — an **inventory** gap, not a content one.
//! * The catalog holds the table and it will not open or iterate. Bytes are
//!   there and were not read: a **content** gap, and only this one stamps the
//!   surviving entries.
//!
//! The distinction was checked against a real `WebCacheV01.dat` (Windows 8.1,
//! 33 MB, 21 containers) rather than assumed. `Containers` declared ids
//! 1-8, 10-17, 19-23 and the catalog held exactly those 21 `Container_<id>`
//! tables: not one orphan row. The gaps at 9 and 18 are containers Windows
//! scavenged, and scavenging removes the row **and** the table together. Orphan
//! rows are therefore not the ordinary state of a healthy database, and
//! `tests::the_real_fixtures_containers_and_tables_agree_exactly` pins that
//! measurement so a future change cannot quietly start flagging clean evidence.
//!
//! The same rule governs a refused ROW. A `Url` this parser could not decode is
//! a URL that was lost; a `Url` the row simply does not store is a placeholder
//! row, and a value ESE keeps outside the row (`Value::Long`) is neither —
//! it is one call away. `text_column` tells the three apart, because counting
//! any of the last two as refused put a content-incompleteness banner on every
//! entry of a perfectly healthy `WebCacheV01.dat`.

use anyhow::{Context, Result};
use libesedb::{EseDb, Value};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    file_detection::{try_detect_file_type, DetectedFileType},
    io::read_exact_or_fail,
    module::{ForensicsModule, InputCapability, ModuleError},
    temp_spill::TempSpill,
    time::filetime_to_rfc3339,
};
use seance_ese_util::{find_column, read_value, value_to_u64};
use serde_json::json;
use std::collections::HashSet;
use std::path::Path;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct WebCacheParser;

impl ForensicsModule for WebCacheParser {
    fn id(&self) -> &str {
        "plugin.browsers.webcache"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl WebCacheParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(data_source) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // Cheap content gate: only ESE databases are ours to consider.
        // An unreadable header is "could not look", not "not ESE" (CR-047).
        if try_detect_file_type(data_source.as_ref()).map_err(ModuleError::IoError)?
            != DetectedFileType::EseDatabase
        {
            return Ok(Vec::new());
        }

        // Whether this file is named as a WebCache database. The content gate
        // above admits every ESE database (SRUM, others), so a failure to stage
        // or parse one of those is not a WebCache gap and must not be reported
        // as one. When the NAME says WebCache, a failure is a real browsing
        // history this case cannot show (B6-021).
        let named_webcache = seance_core::shadow_copy::original_name(artifact)
            .map(|n| {
                n.rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(n)
                    .to_ascii_lowercase()
                    .contains("webcache")
            })
            .unwrap_or(false);

        let temp = match extract_to_temp(data_source.as_ref()) {
            Ok(t) => t,
            Err(e) => {
                debug!("WebCache: failed to stage ESE db: {e}");
                if named_webcache {
                    return Ok(vec![unreadable_database_record(
                        artifact.case_id,
                        artifact.id,
                        "DatabaseNotStaged",
                        &format!("the database could not be staged for reading ({e})"),
                    )]);
                }
                return Ok(Vec::new());
            }
        };
        // `temp` is an RAII guard: the staged file is removed when it drops at the
        // end of this scope, on every path including a panic inside parse_webcache.
        let result = parse_webcache(temp.path(), artifact.case_id, artifact.id);

        match result {
            Ok(records) => {
                if !records.is_empty() {
                    info!("WebCache: {} entries extracted", records.len());
                }
                Ok(records)
            }
            Err(e) => {
                debug!("WebCache: not a WebCache database or parse error: {e}");
                if named_webcache {
                    return Ok(vec![unreadable_database_record(
                        artifact.case_id,
                        artifact.id,
                        "DatabaseNotOpened",
                        &format!("the staged database could not be opened or walked ({e})"),
                    )]);
                }
                Ok(Vec::new())
            }
        }
    }
}

/// The record that says a file named as a WebCache database could not be read
/// at all.
///
/// Without it, an unreadable `WebCacheV01.dat` returns exactly what a browser
/// with no history returns: nothing.
fn unreadable_database_record(
    case_id: Uuid,
    parent_id: Uuid,
    status: &'static str,
    detail: &str,
) -> Artifact {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("WebCacheParseStatus"));
    m.insert("subtype".into(), json!("parse_incomplete"));
    m.insert("browser".into(), json!("Internet Explorer / Edge"));
    m.insert("status".into(), json!(status));
    m.insert("content_incomplete".into(), json!(true));
    m.insert(
        "content_incomplete_reason".into(),
        json!("unresolved_structure"),
    );
    m.insert("inventory_incomplete".into(), json!(true));
    m.insert(
        "inventory_incomplete_reason".into(),
        json!("unresolved_structure"),
    );
    m.insert("entries_recovered".into(), json!(0));
    // Both `<flag>_detail` keys, not only the bare `detail`: the examiner-facing
    // reader (`frontend/src/lib/incompleteness.ts`) takes the parser's sentence
    // from those and reads nothing named `detail`, so this record used to reach
    // the examiner as the token "unresolved structure" with no statement of what
    // failed.
    m.insert("content_incomplete_detail".into(), json!(detail));
    m.insert("inventory_incomplete_detail".into(), json!(detail));
    m.insert("detail".into(), json!(detail));
    m.insert(
        "message".into(),
        json!(
            "This WebCache database was recognised but could not be read; the absence of \
               browsing history below is not evidence that the browser was never used"
        ),
    );
    m.insert(
        "name".into(),
        json!(format!("WebCache: unreadable — {detail}")),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// Copy the ESE bytes to a temp file for libesedb, tolerating short reads.
fn extract_to_temp(data_source: &dyn DataSource) -> Result<TempSpill> {
    let size = data_source.size();
    if size == 0 || size > 4 * 1024 * 1024 * 1024 {
        anyhow::bail!("implausible ESE size: {size}");
    }
    let mut buffer = vec![0u8; size as usize];
    // Loop short reads and fail closed: staging a partial ESE database would let
    // libesedb emit whatever subset of containers/URLs it could still parse as
    // if the whole WebCache had been recovered (BUG-269).
    read_exact_or_fail(data_source, 0, &mut buffer, "WebCache database")
        .context("reading WebCache database")?;
    // An RAII spill: the temp file is removed when the returned guard drops, so a
    // panic in libesedb (swallowed by the orchestrator's catch_unwind) can no
    // longer leak /tmp/seance_webcache_*.dat.
    TempSpill::write(&buffer, "webcache", "dat").context("writing temporary WebCache database")
}

/// What the WebCache walk could not read.
///
/// Every field here was previously a bare `continue` or a `warn!`. The
/// distinction that matters: the `Containers` table is an inventory, so a
/// container it declares whose `Container_<id>` table will not open is a KNOWN
/// gap — the database states those URLs exist and the parser could not reach
/// them. Reporting that as "no entries" would let an examiner testify that a
/// site was never visited on the strength of a table that failed to open.
#[derive(Debug, Default, PartialEq, Eq)]
struct WalkGaps {
    /// Containers named in `Containers` whose own table is in the catalog and
    /// could not be read: `(id, name, what failed)`.
    unreadable_containers: Vec<(i64, String, &'static str)>,
    /// Containers named in `Containers` for which the database holds no
    /// `Container_<id>` table at all: `(id, name)`.
    ///
    /// A row that outlived its table. Real evidence says this does not happen
    /// in a healthy database (see the module docs), so it is reported — but as
    /// a gap in the *inventory*, because no bytes were refused and the entries
    /// that were recovered are whole.
    orphan_containers: Vec<(i64, String)>,
    /// Rows the ESE layer refused, or whose `Url` column could not be read.
    rows_skipped: usize,
    /// The `Containers` table itself would not iterate, so the container
    /// inventory is unknown and no container table was even attempted.
    container_list_unreadable: bool,
    /// Whether the table catalog could be enumerated.
    ///
    /// `false` means a container table that would not open could not be shown
    /// absent, so it is reported as unreadable: a parser that cannot establish
    /// absence must not assert it.
    catalog_enumerated: bool,
}

impl WalkGaps {
    /// Whether anything at all needs saying to the examiner.
    fn is_complete(&self) -> bool {
        !self.content_incomplete() && self.orphan_containers.is_empty()
    }

    /// Whether bytes this database holds were not read.
    ///
    /// Kept apart from [`WalkGaps::is_complete`] because only this drives the
    /// per-entry `content_incomplete` stamp. An orphan container row costs the
    /// examiner an entry in the inventory, not confidence in the entries they
    /// have, and stamping every URL for it would spend the warning's meaning on
    /// the ordinary case.
    fn content_incomplete(&self) -> bool {
        !self.unreadable_containers.is_empty()
            || self.rows_skipped > 0
            || self.container_list_unreadable
    }
}

/// Why a declared container yielded nothing.
#[derive(Debug, PartialEq, Eq)]
enum ContainerGap {
    /// The catalog holds no table of that name: the `Containers` row outlived
    /// its `Container_<id>` table.
    Orphan,
    /// The table is in the catalog and would not open or iterate.
    Unreadable(&'static str),
}

/// Decide which of the two a declared-but-empty container is.
///
/// `catalog` is `None` when the table list could not be enumerated. In that
/// case the container is reported as unreadable rather than orphaned: absence
/// has not been established, and "the table is gone" is a stronger claim than
/// the evidence supports.
fn classify_container_gap(
    catalog: Option<&HashSet<String>>,
    table_name: &str,
    what_failed: &'static str,
) -> ContainerGap {
    match catalog {
        Some(names) if !names.contains(table_name) => ContainerGap::Orphan,
        _ => ContainerGap::Unreadable(what_failed),
    }
}

/// Every table name the database's catalog holds.
///
/// `None` when the catalog would not enumerate. Returning an empty set instead
/// would make every container look orphaned on a database whose table list
/// merely could not be walked.
fn catalog_table_names(db: &EseDb) -> Option<HashSet<String>> {
    let mut names = HashSet::new();
    for table in db.iter_tables().ok()? {
        // A table whose name will not read leaves a set that is short by one,
        // and a short set makes some other container look absent when it is
        // merely unnamed. The whole catalog is therefore withheld: this set is
        // only ever used to assert absence, so it has to be complete or nothing.
        match table.ok().map(|t| t.name()) {
            Some(Ok(name)) => {
                names.insert(name);
            }
            _ => return None,
        }
    }
    Some(names)
}

fn parse_webcache(path: &Path, case_id: Uuid, parent_id: Uuid) -> Result<Vec<Artifact>> {
    let db = EseDb::open(path).context("opening ESE database")?;
    // The Containers table is what makes this a WebCache database (vs SRUM etc.).
    let containers = db
        .table_by_name("Containers")
        .context("no Containers table — not a WebCache database")?;

    // The catalog, read once: it is what separates "this container's table is
    // gone" from "this container's table refused to open".
    let catalog = catalog_table_names(&db);
    let mut gaps = WalkGaps {
        catalog_enumerated: catalog.is_some(),
        ..WalkGaps::default()
    };

    // Map ContainerId -> human name (History / Content / Cookies / ...).
    let cols = column_names(&containers);
    let mut container_names: Vec<(i64, String)> = Vec::new();
    match containers.iter_records() {
        Ok(records) => {
            for rec in records {
                let Ok(rec) = rec else {
                    // A container we cannot even name: its whole table is
                    // therefore never visited below.
                    gaps.rows_skipped += 1;
                    continue;
                };
                let id = col_value(&rec, &cols, "ContainerId").and_then(|v| as_i64(&v));
                let name = match text_column(&rec, &cols, "Name") {
                    TextRead::Text(s) => s,
                    TextRead::Empty | TextRead::Unreadable => String::new(),
                };
                match id {
                    Some(id) => container_names.push((id, name)),
                    None => gaps.rows_skipped += 1,
                }
            }
        }
        Err(e) => {
            warn!("WebCache: Containers table would not iterate: {e}");
            gaps.container_list_unreadable = true;
        }
    }

    let mut out = Vec::new();
    for (id, cname) in &container_names {
        let table_name = format!("Container_{id}");
        let Ok(table) = db.table_by_name(&table_name) else {
            // Declared by the inventory and it produced nothing. Which kind of
            // nothing decides whether the surviving entries get stamped.
            match classify_container_gap(catalog.as_ref(), &table_name, "table_not_opened") {
                ContainerGap::Orphan => gaps.orphan_containers.push((*id, cname.clone())),
                ContainerGap::Unreadable(why) => {
                    gaps.unreadable_containers.push((*id, cname.clone(), why))
                }
            }
            continue;
        };
        let tcols = column_names(&table);
        let Ok(records) = table.iter_records() else {
            gaps.unreadable_containers
                .push((*id, cname.clone(), "records_not_iterated"));
            continue;
        };
        for rec in records {
            let Ok(rec) = rec else {
                gaps.rows_skipped += 1;
                continue;
            };
            let raw_url = match text_column(&rec, &tcols, "Url") {
                TextRead::Text(s) => s,
                // The row stores nothing in its Url column. WebCache keeps
                // placeholder rows, and an ESE NULL is the database saying this
                // row holds no URL — not this parser failing to read one. Same
                // treatment as the blank string below; counting it as a refused
                // row put a content-incompleteness banner on every entry of a
                // perfectly healthy database.
                TextRead::Empty => continue,
                // A value is there and this decoder could not turn it into
                // text: a URL that existed and was not recovered.
                TextRead::Unreadable => {
                    gaps.rows_skipped += 1;
                    continue;
                }
            };
            // A blank Url really is a blank row (WebCache keeps placeholder
            // entries); that is not a gap.
            if raw_url.trim().is_empty() {
                continue;
            }
            let accessed = col_value(&rec, &tcols, "AccessedTime")
                .and_then(|v| as_filetime(&v))
                .and_then(filetime_to_rfc3339);
            let modified = col_value(&rec, &tcols, "ModifiedTime")
                .and_then(|v| as_filetime(&v))
                .and_then(filetime_to_rfc3339);
            let access_count =
                col_value(&rec, &tcols, "AccessCount").and_then(|v| value_to_u64(&v));
            out.push(build_record(
                case_id,
                parent_id,
                cname,
                &raw_url,
                accessed,
                modified,
                access_count,
            ));
        }
    }

    if !gaps.is_complete() {
        warn!(
            "WebCache: {} containers unreadable, {} orphan container rows, {} rows skipped",
            gaps.unreadable_containers.len(),
            gaps.orphan_containers.len(),
            gaps.rows_skipped
        );
        stamp_gaps(&mut out, &gaps);
        let recovered = out.len();
        out.push(gap_status_record(
            case_id,
            parent_id,
            &gaps,
            container_names.len(),
            recovered,
        ));
    }
    Ok(out)
}

/// Mark every recovered entry as coming from a database that did not give up
/// everything it names, so the fact travels with the data into any export,
/// report or viewer.
///
/// The two scopes are kept apart. `content_incomplete` is driven by
/// [`WalkGaps::content_incomplete`] alone: an orphan container row does not
/// brand every URL, because the URLs are whole and a warning that fires on
/// ordinary evidence teaches an examiner to ignore it. `inventory_incomplete`
/// is stamped for any gap at all, because in every one of them the entry list
/// on screen is short of a container the database declares.
fn stamp_gaps(records: &mut [Artifact], gaps: &WalkGaps) {
    if gaps.is_complete() {
        return;
    }
    let content = gaps.content_incomplete();
    // The sentence each stamp carries, on the key the examiner-facing reader
    // displays. Without it every WebCache entry in a damaged database showed the
    // examiner "unresolved structure" and nothing about what was unread.
    let content_detail = if gaps.container_list_unreadable {
        "the Containers inventory would not iterate, so no container table was read; the \
         absence of entries says nothing about what this database held"
            .to_string()
    } else {
        format!(
            "{} container(s) this database names could not be read and {} row(s) were refused, \
             so the entries listed here are a subset of what it holds",
            gaps.unreadable_containers.len(),
            gaps.rows_skipped
        )
    };
    let inventory_detail = if gaps.container_list_unreadable {
        content_detail.clone()
    } else {
        format!(
            "{} of the containers this database names produced no entries ({} whose table would \
             not open or iterate, {} whose table is no longer in the database), so this listing \
             is short of them",
            gaps.unreadable_containers.len() + gaps.orphan_containers.len(),
            gaps.unreadable_containers.len(),
            gaps.orphan_containers.len()
        )
    };
    for record in records.iter_mut() {
        let Some(map) = record.metadata.as_object_mut() else {
            continue;
        };
        if content {
            map.insert("content_incomplete".into(), json!(true));
            map.insert(
                "content_incomplete_reason".into(),
                json!("unresolved_structure"),
            );
            map.insert("content_incomplete_detail".into(), json!(content_detail));
        }
        // The status record is its own record type, and an examiner reaches it
        // only by going looking. What they open is the WebCache entry list
        // (`RecordsViewerPage` fetches one record type and raises its banner
        // from `readIncompleteness` over those records), so the fact that the
        // list is short of a container the database names has to travel on the
        // entries themselves. Stamped whichever way a declared container came
        // up empty — an orphan row costs the examiner entries just as an
        // unreadable table does, it just does not make the surviving URLs
        // partial.
        map.insert("inventory_incomplete".into(), json!(true));
        map.insert(
            "inventory_incomplete_reason".into(),
            json!("unresolved_structure"),
        );
        map.insert(
            "inventory_incomplete_detail".into(),
            json!(inventory_detail),
        );
    }
}

/// The record that says this WebCache database did not give up everything it
/// names.
///
/// What an examiner learns: which named containers could not be opened, which
/// no longer have a table at all, how many rows were refused, and how many URLs
/// were published in spite of that. It is emitted even when NOTHING was
/// recovered — that is the case it exists for, because an unreadable
/// `WebCacheV01.dat` and a browser that was never used produce the same empty
/// list without it.
///
/// `content_incomplete` is set only when bytes were refused. A database whose
/// only fault is a container row without a table is short in its **inventory**
/// and whole in its content, and says so.
fn gap_status_record(
    case_id: Uuid,
    parent_id: Uuid,
    gaps: &WalkGaps,
    containers_declared: usize,
    entries_recovered: usize,
) -> Artifact {
    let unreadable: Vec<serde_json::Value> = gaps
        .unreadable_containers
        .iter()
        .map(|(id, name, why)| json!({ "container_id": id, "container": name, "reason": why }))
        .collect();
    let orphans: Vec<serde_json::Value> = gaps
        .orphan_containers
        .iter()
        .map(|(id, name)| {
            json!({
                "container_id": id,
                "container": name,
                "reason": "table_absent_from_catalog",
            })
        })
        .collect();
    let content_incomplete = gaps.content_incomplete();
    let detail = if gaps.container_list_unreadable {
        "the Containers inventory would not iterate, so no container table was read; \
         the absence of entries says nothing about what this database held"
            .to_string()
    } else if content_incomplete {
        format!(
            "{} of the {containers_declared} declared containers could not be read and \
             {} rows were refused; the {entries_recovered} entries published here are a \
             subset of what this database holds",
            gaps.unreadable_containers.len(),
            gaps.rows_skipped
        )
    } else {
        format!(
            "{} of the {containers_declared} containers named in the inventory no longer have \
             a table in this database, so nothing remains of them to recover; the \
             {entries_recovered} entries published here are everything the surviving tables \
             held and are themselves complete",
            gaps.orphan_containers.len()
        )
    };
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("WebCacheParseStatus"));
    m.insert("subtype".into(), json!("parse_incomplete"));
    m.insert("browser".into(), json!("Internet Explorer / Edge"));
    m.insert(
        "status".into(),
        json!(if content_incomplete {
            "DatabaseNotReadInFull"
        } else {
            "ContainerRowsWithoutTables"
        }),
    );
    m.insert("content_incomplete".into(), json!(content_incomplete));
    if content_incomplete {
        m.insert(
            "content_incomplete_reason".into(),
            json!("unresolved_structure"),
        );
    }
    // The inventory is short whenever the database names a container this walk
    // did not publish entries for, whichever of the two reasons applies.
    m.insert("inventory_incomplete".into(), json!(true));
    m.insert(
        "inventory_incomplete_reason".into(),
        json!("unresolved_structure"),
    );
    m.insert(
        "container_list_unreadable".into(),
        json!(gaps.container_list_unreadable),
    );
    // Whether the two could be told apart at all. `false` means an unopenable
    // container was reported as unreadable because its absence could not be
    // established, not because the table was seen to be present.
    m.insert("catalog_enumerated".into(), json!(gaps.catalog_enumerated));
    m.insert("containers_declared".into(), json!(containers_declared));
    m.insert("unreadable_containers".into(), json!(unreadable));
    m.insert("orphan_containers".into(), json!(orphans));
    m.insert("rows_skipped".into(), json!(gaps.rows_skipped));
    m.insert("entries_recovered".into(), json!(entries_recovered));
    // The sentence goes on the keys the examiner-facing reader shows, beside the
    // bare `detail` the existing consumers read. `content_incomplete_detail` is
    // written only when that flag is set, so a database whose only fault is an
    // inventory gap does not carry a content sentence it would contradict.
    if content_incomplete {
        m.insert("content_incomplete_detail".into(), json!(detail.clone()));
    }
    m.insert("inventory_incomplete_detail".into(), json!(detail.clone()));
    m.insert("detail".into(), json!(detail.clone()));
    m.insert(
        "name".into(),
        json!(if content_incomplete {
            format!("WebCache: partially parsed — {detail}")
        } else {
            format!("WebCache: inventory incomplete — {detail}")
        }),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// Strip IE's `Visited: user@` decoration from a History URL, best-effort.
fn clean_url(raw: &str) -> String {
    let s = raw.strip_prefix("Visited: ").unwrap_or(raw);
    if let Some(at) = s.find('@') {
        let after = &s[at + 1..];
        if after.starts_with("http")
            || after.starts_with("res:")
            || after.starts_with("about:")
            || after.starts_with("ftp")
        {
            return after.to_string();
        }
    }
    s.to_string()
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    container: &str,
    raw_url: &str,
    accessed: Option<String>,
    modified: Option<String>,
    access_count: Option<u64>,
) -> Artifact {
    let url = clean_url(raw_url);
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("WebCacheEntry"));
    m.insert("subtype".into(), json!("webcache_entry"));
    m.insert("browser".into(), json!("Internet Explorer / Edge"));
    m.insert("container".into(), json!(container));
    m.insert("url".into(), json!(url));
    if url != raw_url {
        m.insert("raw_url".into(), json!(raw_url));
    }
    if let Some(a) = accessed {
        m.insert("accessed_time".into(), json!(a));
    }
    if let Some(md) = modified {
        m.insert("modified_time".into(), json!(md));
    }
    if let Some(c) = access_count {
        m.insert("access_count".into(), json!(c));
    }
    m.insert("name".into(), json!(format!("{container}: {url}")));
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(parent_id)
    .with_subtype("webcache_entry")
}

// ── libesedb value helpers ───────────────────────────────────────────────────
//
// The generic column/value primitives are shared with the other ESE plugins via
// `seance_ese_util` (`find_column`, `read_value`, `value_to_u64`). Three helpers
// stay local ON PURPOSE, because WebCache needs behaviour the shared ones do not
// provide and MUST NOT be "consolidated" into them:
//   - `column_names` degrades a column whose name will not read to an empty
//     string and keeps going, where `get_column_names` fails the whole table;
//   - `text_column` returns a three-way [`TextRead`] and resolves out-of-row
//     `Value::Long` URLs, where `text` collapses absent/unreadable into `None`
//     and drops long values — exactly the longest URLs a case turns on;
//   - `as_i64` has no shared equivalent.

fn column_names(table: &libesedb::Table) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(count) = table.count_columns() {
        for i in 0..count {
            if let Ok(col) = table.column(i) {
                if let Ok(name) = col.name() {
                    names.push(name);
                    continue;
                }
            }
            names.push(String::new());
        }
    }
    names
}

/// Read a column by name (case-insensitively) as a raw value, via the shared
/// `seance_ese_util` primitives so the lookup rule stays in one place.
fn col_value(record: &libesedb::Record, columns: &[String], name: &str) -> Option<Value> {
    read_value(record, find_column(columns, name)?)
}

/// The outcome of reading one text column of one row.
///
/// The three cases must stay apart. "The row holds no value here" and "the
/// value is there and we could not read it" are the difference between a
/// placeholder row and a lost URL, and collapsing them into one `Option::None`
/// made every WebCache database report refused rows it never had — which
/// stamps a content-incompleteness banner on ordinary evidence and teaches an
/// examiner to ignore the banner that matters.
#[derive(Debug)]
enum TextRead {
    /// The column held text.
    Text(String),
    /// The row stores no value in this column (ESE NULL).
    Empty,
    /// The column is absent from this table, or a value is present that this
    /// decoder could not turn into text.
    Unreadable,
}

/// Read one column of a record as text.
///
/// ESE stores a value too large to sit inline in the row in the long-value
/// tree. [`libesedb::Record::value`] reports those as [`Value::Long`], which
/// carries no bytes at all — the data is one `Record::long` call away. Treating
/// that variant as "unreadable" silently dropped exactly the longest URLs (the
/// ones with the query strings a case usually turns on) and then reported them
/// as rows the evidence had refused.
fn text_column(record: &libesedb::Record, columns: &[String], name: &str) -> TextRead {
    let Some(idx) = columns.iter().position(|c| c.eq_ignore_ascii_case(name)) else {
        return TextRead::Unreadable;
    };
    let idx = idx as i32;
    match record.value(idx) {
        Ok(Value::Text(s)) | Ok(Value::LargeText(s)) => TextRead::Text(s),
        // Stored out of row. Fetch it; a fetch that fails is a real gap, so it
        // falls through to `Unreadable` rather than to "this row had none".
        Ok(Value::Long) => match record.long(idx).and_then(|lv| lv.utf8()) {
            Ok(s) => TextRead::Text(s),
            Err(e) => {
                warn!("WebCache: long value for column {name} would not decode: {e}");
                TextRead::Unreadable
            }
        },
        Ok(Value::Null(_)) => TextRead::Empty,
        Ok(_) => TextRead::Unreadable,
        Err(e) => {
            warn!("WebCache: column {name} would not read: {e}");
            TextRead::Unreadable
        }
    }
}

fn as_i64(v: &Value) -> Option<i64> {
    v.to_i64()
        .or_else(|| v.to_i32().map(|x| x as i64))
        .or_else(|| v.to_u32().map(|x| x as i64))
        .or_else(|| v.to_u64().map(|x| x as i64))
}

/// Read a column as a Windows FILETIME.
///
/// A FILETIME is an unsigned count of 100 ns ticks since 1601. When the column
/// holds a *signed* integer, a negative value is corrupt — but reinterpreting
/// its bits as `u64` produces a number so large it sails past every epoch and
/// range check and lands the record thousands of years in the future. A visit
/// or download dated 30828 AD is obviously wrong to a human and invisible to a
/// sort; refuse the value instead so the timestamp is reported as absent.
fn as_filetime(v: &Value) -> Option<u64> {
    match v {
        Value::DateTime(ft) => Some(*ft),
        _ => match as_i64(v) {
            Some(ticks) if ticks >= 0 => Some(ticks as u64),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests;
