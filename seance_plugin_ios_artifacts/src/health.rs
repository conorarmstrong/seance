//! HealthKit: the samples in `healthdb_secure.sqlite`, with the source name
//! resolved from `healthdb.sqlite` beside it.
//!
//! Three things decide the shape of what is published:
//!
//! * **`samples.data_type` is an integer whose meaning is not in the
//!   database.** It is Apple's private enum and it moves between releases.
//!   The number is published on every record; a name appears only for the
//!   few types in [`DATA_TYPE_NAMES`], each marked as asserted rather than
//!   read, and every other type carries `data_type_name_unknown`.
//! * **The unit is what the file says, or nothing.** `quantity_samples.
//!   original_unit` points into `unit_strings`; on the device held that
//!   table is empty, so every sample says `unit_not_recorded` and none is
//!   given HealthKit's canonical unit for a guessed type.
//! * **The source's name lives in the other file.** `data_provenances` in
//!   the secure store gives the product type, build, iOS version and — the
//!   valuable one — the timezone the sample was recorded in, but the
//!   human-readable source name is `sources.name` in `healthdb.sqlite`. It is
//!   opened as a neighbour; a source that cannot look says
//!   `source_cannot_open_neighbours`, which is not the same as "not there".
//!
//! Workouts (both generations) and sleep stages are decoded in
//! [`crate::workouts`], each validated against a device's creation notes.
//! Workout events, ECG, location series and the rest of the 83 tables are
//! counted and left unread: no answer key held checks a decoder against them.

use std::collections::{BTreeMap, HashMap};

use rusqlite::Connection;
use seance_core::io::IncompleteReason;
use seance_core::time::cocoa_secs_to_unix_nanos;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::stale::{check_schema_version, SupportedRange};
use seance_sqlite_util::{cap_marker, CapCounter, RowDrops, TempDb};
use serde_json::{json, Map, Value};

use crate::workouts::{
    read_workouts, sleep_stage, MAX_WORKOUTS, SLEEP_ANALYSIS_TYPE, SLEEP_STAGE_BASIS,
};
use crate::{
    cfloat, cint, cstr, has_table, insert_cocoa, parent_record, query_unusable_artifact,
    rows_until_failure, table_count_checked, with_db, MAX_DB_BYTES,
};

/// The real store the `HEALTH_SECURE_SCHEMA` range was read out of.
const HEALTH_SECURE_EVIDENCE: &str =
    "Magnet 2022 CTF iPhone 8 (iOS 15.0.2, 19A404) Library/Health/healthdb_secure.sqlite";
/// `PRAGMA user_version` of the `healthdb_secure.sqlite` generation this
/// reader was validated against (iOS 15.0.2, 19A404).
const HEALTH_SECURE_SCHEMA: SupportedRange = SupportedRange {
    min: 15043,
    max: Some(15043),
};

/// Ceiling on samples carried into one case from a single store.
const MAX_HEALTH_SAMPLES: usize = 500_000;
/// Ceiling on metadata rows joined onto samples.
const MAX_METADATA_ROWS: usize = 2_000_000;

/// The `data_type` values given a name, and the name.
///
/// These three are the only ones this reader asserts, because their meaning
/// is corroborated by the evidence itself on the device held: type 7 is
/// integer-valued (2..958, every one of 131 samples a whole number, summing
/// to 21,285 over a month), type 12 is integer-valued 1..8, and type 8 runs
/// 0.96..682.83 alongside the step samples over the same intervals. The
/// names are the public HealthKit identifiers those shapes match. Nothing
/// else is named: the mobility types on the same device (182, 187, 188, 194)
/// have no corroboration in the file beyond a metadata key on one of them.
const DATA_TYPE_NAMES: &[(i64, &str)] = &[
    (7, "step_count"),
    (8, "distance_walking_running"),
    (12, "flights_climbed"),
];

/// Build the observed name table was checked under.
const DATA_TYPE_NAMES_OBSERVED_BUILD: &str = "19A404";

fn data_type_name(t: i64) -> Option<&'static str> {
    DATA_TYPE_NAMES
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, n)| *n)
}

/// What the neighbouring `healthdb.sqlite` gave, or why it gave nothing.
///
/// `resolution` answers for the `sources` table and `device_resolution` for
/// `source_devices`, and each is `"resolved"` only when its table was read
/// to the end. A table that is there but whose statement did not prepare
/// (another generation of the store) is a could-not-look, named as such
/// with SQLite's reason in `*_query_error`; it is never `"resolved"` with
/// `rows: None`, which read as a table looked at and found to hold none of
/// the ids the samples name.
struct Sources {
    by_id: HashMap<i64, (String, Option<String>, Option<String>)>,
    devices_by_id: HashMap<i64, Map<String, Value>>,
    resolution: &'static str,
    rows: Option<usize>,
    query_error: Option<String>,
    device_resolution: &'static str,
    device_rows: Option<usize>,
    device_query_error: Option<String>,
}

const SOURCES_QUERY_DID_NOT_RUN: &str = "sibling_sources_query_did_not_run";
const SOURCE_DEVICES_QUERY_DID_NOT_RUN: &str = "sibling_source_devices_query_did_not_run";

fn resolve_sources(ds: &dyn DataSource) -> Sources {
    let empty = |resolution| Sources {
        by_id: HashMap::new(),
        devices_by_id: HashMap::new(),
        resolution,
        rows: None,
        query_error: None,
        device_resolution: resolution,
        device_rows: None,
        device_query_error: None,
    };
    if !ds.supports_siblings() {
        return empty("source_cannot_open_neighbours");
    }
    let Some(sib) = ds.open_relative("healthdb.sqlite") else {
        return empty("sibling_not_found");
    };
    let Ok(temp) = TempDb::spill(sib.as_ref(), "health_sources", MAX_DB_BYTES) else {
        return empty("sibling_not_staged");
    };
    let Ok(conn) = temp.open() else {
        return empty("sibling_not_opened");
    };
    let mut out = empty("resolved");
    let sources_read: Option<rusqlite::Result<usize>> = has_table(&conn, "sources").then(|| {
        let mut stmt = conn.prepare("SELECT ROWID, name, bundle_id, product_type FROM sources")?;
        let iter = stmt.query_map([], |r| Ok((cint(r, 0), cstr(r, 1), cstr(r, 2), cstr(r, 3))))?;
        let mut n = 0usize;
        for row in iter.flatten() {
            n += 1;
            if let (Some(id), Some(name)) = (row.0, row.1) {
                out.by_id.insert(id, (name, row.2, row.3));
            }
        }
        Ok(n)
    });
    match sources_read {
        None => out.resolution = "sibling_has_no_sources_table",
        Some(Ok(n)) => out.rows = Some(n),
        Some(Err(e)) => {
            out.resolution = SOURCES_QUERY_DID_NOT_RUN;
            out.query_error = Some(e.to_string());
        }
    }
    let devices_read: Option<rusqlite::Result<usize>> = has_table(&conn, "source_devices").then(|| {
        let mut stmt = conn.prepare(
            "SELECT ROWID, name, manufacturer, model, hardware, firmware, software, localIdentifier \
             FROM source_devices",
        )?;
        let iter = stmt.query_map([], |r| {
            Ok((
                cint(r, 0),
                cstr(r, 1),
                cstr(r, 2),
                cstr(r, 3),
                cstr(r, 4),
                cstr(r, 5),
                cstr(r, 6),
                cstr(r, 7),
            ))
        })?;
        let mut n = 0usize;
        for row in iter.flatten() {
            n += 1;
            let Some(id) = row.0 else { continue };
            let mut m = Map::new();
            for (k, v) in [
                ("name", row.1),
                ("manufacturer", row.2),
                ("model", row.3),
                ("hardware", row.4),
                ("firmware", row.5),
                ("software", row.6),
                ("local_identifier", row.7),
            ] {
                if let Some(v) = v.filter(|v| !v.is_empty()) {
                    m.insert(k.into(), json!(v));
                }
            }
            out.devices_by_id.insert(id, m);
        }
        Ok(n)
    });
    match devices_read {
        None => out.device_resolution = "sibling_has_no_source_devices_table",
        Some(Ok(n)) => out.device_rows = Some(n),
        Some(Err(e)) => {
            out.device_resolution = SOURCE_DEVICES_QUERY_DID_NOT_RUN;
            out.device_query_error = Some(e.to_string());
        }
    }
    out
}

/// The `metadata_values ⋈ metadata_keys` read: the rows keyed by
/// `object_id`, or why there are none.
///
/// `Read` with `rows: 0` is a store whose join ran and returned nothing;
/// `TablesAbsent` is a store without the tables; `QueryDidNotRun` is a store
/// with both tables whose join did not prepare or start, with SQLite's
/// reason. The three used to collapse into `metadata_rows: 0` and no
/// `metadata` on any sample.
enum MetadataRead {
    Read {
        by_object: HashMap<i64, Map<String, Value>>,
        rows: usize,
        capped: bool,
    },
    TablesAbsent,
    QueryDidNotRun {
        error: String,
    },
}

impl MetadataRead {
    fn status(&self) -> &'static str {
        match self {
            MetadataRead::Read { .. } => "read",
            MetadataRead::TablesAbsent => "tables_absent",
            MetadataRead::QueryDidNotRun { .. } => "query_did_not_run",
        }
    }
    fn capped(&self) -> bool {
        matches!(self, MetadataRead::Read { capped: true, .. })
    }
}

fn read_metadata(conn: &Connection) -> MetadataRead {
    let mut by_object: HashMap<i64, Map<String, Value>> = HashMap::new();
    let mut rows = 0usize;
    let mut capped = false;
    if !has_table(conn, "metadata_values") || !has_table(conn, "metadata_keys") {
        return MetadataRead::TablesAbsent;
    }
    let mut stmt = match conn.prepare(
        "SELECT mv.object_id, mk.key, mv.value_type, mv.string_value, mv.numerical_value, \
                mv.date_value, length(mv.data_value) \
         FROM metadata_values mv JOIN metadata_keys mk ON mk.ROWID = mv.key_id LIMIT ?1",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            return MetadataRead::QueryDidNotRun {
                error: e.to_string(),
            }
        }
    };
    let iter = match stmt.query_map([MAX_METADATA_ROWS as i64 + 1], |r| {
        Ok((
            cint(r, 0),
            cstr(r, 1),
            cint(r, 2),
            cstr(r, 3),
            cfloat(r, 4),
            cfloat(r, 5),
            cint(r, 6),
        ))
    }) {
        Ok(iter) => iter,
        Err(e) => {
            return MetadataRead::QueryDidNotRun {
                error: e.to_string(),
            }
        }
    };
    for row in iter.flatten() {
        if rows >= MAX_METADATA_ROWS {
            capped = true;
            break;
        }
        rows += 1;
        let (Some(oid), Some(key)) = (row.0, row.1) else {
            continue;
        };
        let value = if let Some(s) = row.3 {
            json!(s)
        } else if let Some(n) = row.4 {
            json!(n)
        } else if let Some(d) = row.5 {
            match cocoa_secs_to_unix_nanos(d) {
                Some((secs, _)) => {
                    json!({ "unix_seconds": secs, "source": "metadata_values.date_value (Apple Cocoa seconds)" })
                }
                None => Value::Null,
            }
        } else if let Some(len) = row.6 {
            json!({ "data_bytes": len, "decoded": false })
        } else {
            Value::Null
        };
        by_object.entry(oid).or_default().insert(key, value);
    }
    MetadataRead::Read {
        by_object,
        rows,
        capped,
    }
}

/// HealthKit samples (`healthdb_secure.sqlite`).
pub struct HealthKitParser;

impl ForensicsModule for HealthKitParser {
    fn id(&self) -> &str {
        "plugin.ios.healthkit"
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
            &["healthdb_secure.sqlite"],
            "health",
            |conn, ds, case, parent| {
                if !has_table(conn, "samples") || !has_table(conn, "objects") {
                    return Vec::new();
                }
                let mut out = Vec::new();
                // Every answer is a record except an in-range version: 0 is
                // "not recorded" and a pragma that would not read is
                // "undetermined" — the `if let Ok(Some(w))` this replaced made
                // both silence (HUNT-186).
                out.extend(
                    check_schema_version(
                        conn,
                        "HealthKit healthdb_secure.sqlite",
                        &HEALTH_SECURE_SCHEMA,
                    )
                    .marker(case, parent, Some(HEALTH_SECURE_EVIDENCE)),
                );
                let sources = resolve_sources(ds);
                let metadata = read_metadata(conn);
                let metadata_capped = metadata.capped();

                let mut stmt = match conn.prepare(
                    "SELECT s.data_id, s.data_type, s.start_date, s.end_date, \
                            q.quantity, q.original_quantity, u.unit_string, \
                            c.value, o.type, o.creation_date, hex(o.uuid), \
                            p.origin_product_type, p.origin_build, p.source_version, p.tz_name, \
                            p.source_id, p.device_id, p.local_product_type, p.local_build \
                     FROM samples s \
                     JOIN objects o ON o.data_id = s.data_id \
                     LEFT JOIN data_provenances p ON p.ROWID = o.provenance \
                     LEFT JOIN quantity_samples q ON q.data_id = s.data_id \
                     LEFT JOIN category_samples c ON c.data_id = s.data_id \
                     LEFT JOIN unit_strings u ON u.ROWID = q.original_unit \
                     ORDER BY s.start_date DESC, s.data_id DESC LIMIT ?1",
                ) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        out.push(query_unusable_artifact(
                            case,
                            parent,
                            "healthdb_secure.sqlite",
                            "samples",
                            &e,
                        ));
                        return out;
                    }
                };
                let mut cap = CapCounter::new(MAX_HEALTH_SAMPLES);
                let rows = stmt.query_map([cap.limit()], |r| {
                    Ok((
                        cint(r, 0),
                        cint(r, 1),
                        cfloat(r, 2),
                        cfloat(r, 3),
                        cfloat(r, 4),
                        cfloat(r, 5),
                        cstr(r, 6),
                        cint(r, 7),
                        cint(r, 8),
                        cfloat(r, 9),
                        cstr(r, 10),
                        cstr(r, 11),
                        cstr(r, 12),
                        cstr(r, 13),
                        cstr(r, 14),
                        cint(r, 15),
                        cint(r, 16),
                        cstr(r, 17),
                        cstr(r, 18),
                    ))
                });
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(e) => {
                        out.push(query_unusable_artifact(
                            case,
                            parent,
                            "healthdb_secure.sqlite",
                            "samples",
                            &e,
                        ));
                        return out;
                    }
                };
                let mut drops = RowDrops::default();
                let mut samples = 0usize;
                let mut deleted = 0usize;
                let mut sleep_samples = 0usize;
                let mut named: BTreeMap<i64, usize> = BTreeMap::new();
                let mut unnamed: BTreeMap<i64, usize> = BTreeMap::new();
                for row in rows {
                    let row = match row {
                        Ok(r) => r,
                        Err(e) => {
                            drops.record(&e);
                            continue;
                        }
                    };
                    if !cap.admit() {
                        break;
                    }
                    let (
                        data_id,
                        data_type,
                        start,
                        end,
                        quantity,
                        original_quantity,
                        unit,
                        category,
                        obj_type,
                        created,
                        uuid,
                        origin_product,
                        origin_build,
                        origin_version,
                        tz,
                        source_id,
                        device_id,
                        local_product,
                        local_build,
                    ) = row;
                    samples += 1;
                    let mut m = Map::new();
                    m.insert("type".into(), json!("HealthSample"));
                    m.insert("subtype".into(), json!("health_sample"));
                    m.insert("platform".into(), json!("iOS"));
                    m.insert("source".into(), json!("healthdb_secure.sqlite"));
                    if let Some(id) = data_id {
                        m.insert("data_id".into(), json!(id));
                    }
                    match data_type {
                        Some(t) => {
                            m.insert("data_type".into(), json!(t));
                            match data_type_name(t) {
                                Some(n) => {
                                    *named.entry(t).or_default() += 1;
                                    m.insert("data_type_name".into(), json!(n));
                                    m.insert("data_type_name_basis".into(), json!("asserted"));
                                }
                                None if t == SLEEP_ANALYSIS_TYPE => {
                                    *named.entry(t).or_default() += 1;
                                }
                                None => {
                                    *unnamed.entry(t).or_default() += 1;
                                    m.insert("data_type_name_unknown".into(), json!(true));
                                }
                            }
                        }
                        None => {
                            m.insert("data_type_not_recorded".into(), json!(true));
                        }
                    }
                    if let Some(s) = start {
                        insert_cocoa(&mut m, "start", s, "samples.start_date");
                        insert_cocoa(&mut m, "date", s, "samples.start_date");
                    }
                    if let Some(e) = end {
                        insert_cocoa(&mut m, "end", e, "samples.end_date");
                    }
                    if let (Some(s), Some(e)) = (start, end) {
                        if e >= s {
                            m.insert("duration_seconds".into(), json!(e - s));
                        }
                    }
                    if let Some(q) = quantity {
                        m.insert("quantity".into(), json!(q));
                        match &unit {
                            Some(u) => {
                                m.insert("unit".into(), json!(u));
                            }
                            None => {
                                m.insert("unit_not_recorded".into(), json!(true));
                            }
                        }
                    }
                    if let Some(oq) = original_quantity {
                        m.insert("original_quantity".into(), json!(oq));
                    }
                    if let Some(c) = category {
                        m.insert("category_value".into(), json!(c));
                    }
                    // Sleep analysis: the type and its stage are named, with
                    // the basis of each (see `workouts`).
                    if data_type == Some(SLEEP_ANALYSIS_TYPE) {
                        sleep_samples += 1;
                        m.insert("data_type_name".into(), json!("sleep_analysis"));
                        m.insert("data_type_name_basis".into(), json!("asserted"));
                        match category.and_then(sleep_stage) {
                            Some((stage, asleep)) => {
                                m.insert("sleep_stage".into(), json!(stage));
                                m.insert("asleep".into(), json!(asleep));
                                m.insert("sleep_stage_basis".into(), json!(SLEEP_STAGE_BASIS));
                            }
                            None => {
                                m.insert("sleep_stage_unknown".into(), json!(true));
                            }
                        }
                    }
                    let is_deleted = obj_type == Some(2);
                    if is_deleted {
                        deleted += 1;
                    }
                    m.insert("deleted".into(), json!(is_deleted));
                    if let Some(t) = obj_type {
                        m.insert("object_type".into(), json!(t));
                    }
                    if let Some(c) = created {
                        insert_cocoa(&mut m, "created", c, "objects.creation_date");
                    }
                    if let Some(u) = uuid {
                        m.insert("uuid".into(), json!(u));
                    }
                    for (k, v) in [
                        ("origin_product_type", origin_product),
                        ("origin_build", origin_build),
                        ("origin_os_version", origin_version),
                        ("recording_timezone", tz),
                        ("local_product_type", local_product),
                        ("local_build", local_build),
                    ] {
                        if let Some(v) = v.filter(|v| !v.is_empty()) {
                            m.insert(k.into(), json!(v));
                        }
                    }
                    if let Some(sid) = source_id {
                        m.insert("source_id".into(), json!(sid));
                        match sources.by_id.get(&sid) {
                            Some((name, bundle, product)) => {
                                m.insert("source_name".into(), json!(name));
                                if let Some(b) = bundle {
                                    m.insert("source_bundle_id".into(), json!(b));
                                }
                                if let Some(p) = product {
                                    m.insert("source_product_type".into(), json!(p));
                                }
                            }
                            None => {
                                m.insert("source_name_unresolved".into(), json!(true));
                                m.insert(
                                    "source_name_unresolved_reason".into(),
                                    json!(if sources.resolution == "resolved" {
                                        "source_id_not_in_sources"
                                    } else {
                                        sources.resolution
                                    }),
                                );
                            }
                        }
                    }
                    if let Some(did) = device_id {
                        m.insert("device_id".into(), json!(did));
                        match sources.devices_by_id.get(&did) {
                            Some(dev) => {
                                m.insert("source_device".into(), Value::Object(dev.clone()));
                                // `data_provenances.device_id` is matched to
                                // `source_devices.ROWID`; the file does not declare
                                // that key, so the join is an inference.
                                m.insert(
                                    "source_device_join".into(),
                                    json!("inferred: data_provenances.device_id = healthdb.sqlite source_devices.ROWID"),
                                );
                            }
                            None => {
                                m.insert(
                                    "source_device_unresolved_reason".into(),
                                    json!(if sources.device_resolution == "resolved" {
                                        "device_id_not_in_source_devices"
                                    } else {
                                        sources.device_resolution
                                    }),
                                );
                            }
                        }
                    }
                    if let Some(id) = data_id {
                        match &metadata {
                            MetadataRead::Read { by_object, .. } => {
                                if let Some(md) = by_object.get(&id) {
                                    m.insert("metadata".into(), Value::Object(md.clone()));
                                }
                            }
                            MetadataRead::TablesAbsent => {}
                            MetadataRead::QueryDidNotRun { .. } => {
                                m.insert("metadata_unread".into(), json!(true));
                                m.insert(
                                    "metadata_unread_reason".into(),
                                    json!("metadata_values join did not run"),
                                );
                            }
                        }
                    }
                    let label = data_type
                        .map(|t| match data_type_name(t) {
                            Some(n) => n.to_string(),
                            None if t == SLEEP_ANALYSIS_TYPE => "sleep_analysis".to_string(),
                            None => format!("data_type {t}"),
                        })
                        .unwrap_or_else(|| "sample".into());
                    m.insert(
                        "name".into(),
                        json!(match quantity {
                            Some(q) => format!("Health {label}: {q}"),
                            None => format!("Health {label}"),
                        }),
                    );
                    out.push(parent_record(case, parent, Value::Object(m)));
                }
                if cap.truncated() {
                    out.push(cap_marker(
                        case,
                        parent,
                        "HealthSampleIncomplete",
                        "samples",
                        &cap,
                    ));
                }
                if let Some(marker) =
                    drops.marker(case, parent, "HealthSampleIncomplete", "samples", samples)
                {
                    out.push(marker);
                }

                // The census is taken over the whole table, not the capped
                // walk, so the histogram is the truth even when the list is
                // not all of it.
                // A census whose statement does not run is published as
                // such, not as an empty histogram, which is what a table
                // with no rows would give.
                // A census that fails part-way keeps the rows it read — they
                // are real — and is published as partial, not as counted:
                // `.flatten()` used to end it early and still say "counted"
                // (HUNT-237).
                let mut histogram = Map::new();
                let (histogram_rows, histogram_error) = rows_until_failure(
                    conn,
                    "SELECT data_type, count(*) FROM samples GROUP BY data_type ORDER BY data_type",
                    |r| Ok((cint(r, 0), cint(r, 1))),
                );
                for (t, n) in histogram_rows.iter().copied() {
                    if let (Some(t), Some(n)) = (t, n) {
                        histogram.insert(t.to_string(), json!(n));
                    }
                }
                // Every census this summary is built on that did not complete,
                // named. A count that would not read is not an absent table
                // (HUNT-238).
                let mut lookup_failures: Vec<String> = Vec::new();
                let total: Option<i64> = match table_count_checked(conn, "samples") {
                    Ok(n) => n,
                    Err(why) => {
                        lookup_failures.push(format!("sample_rows: {why}"));
                        None
                    }
                };
                // Both censuses are over the whole table, like the
                // histogram: `objects.type = 2` marks every deleted object,
                // sample or not, and the two are published apart under their
                // own names. The walked count stands in for the sample census
                // only if the join cannot run — and then says so, with the
                // census's error and whether the walk saw every sample
                // (HUNT-236). The object census has no stand-in.
                let deleted_objects: Result<i64, String> = conn
                    .query_row("SELECT count(*) FROM objects WHERE type = 2", [], |r| {
                        r.get(0)
                    })
                    .map_err(|e| e.to_string());
                let deleted_samples_census: Result<i64, String> = conn
                    .query_row(
                        "SELECT count(*) FROM samples s JOIN objects o ON o.data_id = s.data_id \
                         WHERE o.type = 2",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(|e| e.to_string());
                let deleted_samples: i64 = match &deleted_samples_census {
                    Ok(n) => *n,
                    Err(_) => deleted as i64,
                };

                let mut s = Map::new();
                s.insert("type".into(), json!("HealthKitSummary"));
                s.insert("platform".into(), json!("iOS"));
                s.insert("source".into(), json!("healthdb_secure.sqlite"));
                s.insert("samples".into(), json!(samples));
                if let Some(t) = total {
                    s.insert("sample_rows".into(), json!(t));
                }
                match (&histogram_error, histogram_rows.is_empty()) {
                    (None, _) => {
                        s.insert("data_type_histogram_status".into(), json!("counted"));
                        s.insert("data_type_histogram".into(), Value::Object(histogram));
                    }
                    (Some(e), true) => {
                        s.insert(
                            "data_type_histogram_status".into(),
                            json!("query_did_not_run"),
                        );
                        s.insert("data_type_histogram_query_error".into(), json!(e));
                        lookup_failures.push(format!("data_type_histogram: {e}"));
                    }
                    (Some(e), false) => {
                        // The data types after the failure were never seen:
                        // the histogram is a lower bound, not the table's.
                        s.insert("data_type_histogram_status".into(), json!("partial"));
                        s.insert("data_type_histogram".into(), Value::Object(histogram));
                        s.insert("data_type_histogram_query_error".into(), json!(e));
                        lookup_failures.push(format!(
                            "data_type_histogram: stopped after {} data type(s): {e}",
                            histogram_rows.len()
                        ));
                    }
                }
                s.insert(
                    "named_data_types".into(),
                    json!(named.keys().collect::<Vec<_>>()),
                );
                s.insert(
                    "unnamed_data_types".into(),
                    json!(unnamed.keys().collect::<Vec<_>>()),
                );
                s.insert(
                    "data_type_names_basis".into(),
                    json!(format!(
                        "asserted from public HealthKit identifiers, corroborated by value shape on build {DATA_TYPE_NAMES_OBSERVED_BUILD}; not read from the file"
                    )),
                );
                s.insert("deleted_samples".into(), json!(deleted_samples));
                match &deleted_samples_census {
                    Ok(_) => {
                        s.insert("deleted_samples_basis".into(), json!("whole_table"));
                    }
                    Err(e) => {
                        s.insert("deleted_samples_basis".into(), json!("walked_samples"));
                        s.insert("deleted_samples_census_error".into(), json!(e));
                        // The walk stops at the cap and skips an undecodable
                        // row, so its count can fall short of the table's.
                        s.insert(
                            "deleted_samples_is_lower_bound".into(),
                            json!(cap.truncated() || drops.dropped() > 0),
                        );
                    }
                }
                match &deleted_objects {
                    Ok(n) => {
                        s.insert("deleted_objects".into(), json!(n));
                    }
                    Err(e) => {
                        s.insert("deleted_objects_census_error".into(), json!(e));
                    }
                }
                // Counted once, here, for the label below as well.
                let mut workouts_count: Result<Option<i64>, String> = Ok(None);
                for (table, field) in [
                    ("workouts", "workout_rows"),
                    ("workout_events", "workout_event_rows"),
                    ("category_samples", "category_sample_rows"),
                    ("sleep_schedule_samples", "sleep_schedule_rows"),
                    ("unit_strings", "unit_strings_rows"),
                    ("data_provenances", "provenance_rows"),
                    ("ecg_samples", "ecg_sample_rows"),
                    ("location_series_data", "location_series_rows"),
                ] {
                    let count = table_count_checked(conn, table);
                    match &count {
                        Ok(Some(n)) => {
                            s.insert(field.into(), json!(n));
                        }
                        Ok(None) => {
                            s.insert(format!("{field}_table_absent"), json!(true));
                        }
                        Err(why) => {
                            lookup_failures.push(format!("{field}: {why}"));
                        }
                    }
                    if table == "workouts" {
                        workouts_count = count;
                    }
                }
                // Workouts, in whichever generation the store keeps them.
                let workouts = read_workouts(conn, case, parent);
                let workouts_read = workouts.records.len();
                match workouts.schema {
                    Some(schema) => {
                        s.insert("workouts_decoded".into(), json!(true));
                        s.insert("workout_schema".into(), json!(schema.as_str()));
                        s.insert("workouts".into(), json!(workouts_read));
                        s.insert("deleted_workouts".into(), json!(workouts.deleted));
                    }
                    None => {
                        // No `workouts` table, or one in a generation this
                        // reader was not validated on: counted, not decoded.
                        s.insert("workouts_decoded".into(), json!(false));
                    }
                }
                if let Some(e) = &workouts.error {
                    lookup_failures.push(format!("workouts: {e}"));
                }
                if workouts.capped {
                    s.insert("workouts_capped".into(), json!(true));
                    s.insert("workouts_cap".into(), json!(MAX_WORKOUTS));
                }
                s.insert("sleep_decoded".into(), json!(true));
                s.insert("sleep_samples".into(), json!(sleep_samples));
                s.insert(
                    "undecoded_detail".into(),
                    json!("workout_events (counted per workout, not decoded), sleep_schedule_samples, ecg_samples and location_series_data are counted and not decoded: no answer key held checks a decoder against them"),
                );
                s.insert("metadata_status".into(), json!(metadata.status()));
                match &metadata {
                    MetadataRead::Read { rows, capped, .. } => {
                        s.insert("metadata_rows".into(), json!(rows));
                        if *capped {
                            s.insert("metadata_rows_capped".into(), json!(true));
                            s.insert("metadata_cap".into(), json!(MAX_METADATA_ROWS));
                        }
                    }
                    MetadataRead::TablesAbsent => {
                        s.insert("metadata_tables_absent".into(), json!(true));
                    }
                    MetadataRead::QueryDidNotRun { error } => {
                        s.insert("metadata_query_error".into(), json!(error));
                    }
                }
                s.insert("source_name_resolution".into(), json!(sources.resolution));
                if let Some(n) = sources.rows {
                    s.insert("sources_rows".into(), json!(n));
                }
                if let Some(e) = &sources.query_error {
                    s.insert("sources_query_error".into(), json!(e));
                }
                s.insert(
                    "source_device_resolution".into(),
                    json!(sources.device_resolution),
                );
                if let Some(n) = sources.device_rows {
                    s.insert("source_device_rows".into(), json!(n));
                }
                if let Some(e) = &sources.device_query_error {
                    s.insert("source_devices_query_error".into(), json!(e));
                }
                if let Ok(v) = conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
                    s.insert("schema_version".into(), json!(v));
                }
                s.insert("records_recovered".into(), json!(samples + workouts_read));
                if cap.truncated() || drops.dropped() > 0 || metadata_capped || workouts.capped {
                    s.insert("inventory_incomplete".into(), json!(true));
                    s.insert(
                        "inventory_incomplete_reason".into(),
                        json!(if cap.truncated() || metadata_capped || workouts.capped {
                            IncompleteReason::CapReached.as_str()
                        } else {
                            IncompleteReason::UnresolvedStructure.as_str()
                        }),
                    );
                }
                // HUNT-240: the walk sorts before it returns a row, so a
                // failure mid-scan can lose every row. Say the walk failed,
                // on the record and in its name, rather than let 0 read as
                // an empty store.
                let walk_failed = drops.dropped() > 0;
                if walk_failed {
                    s.insert("samples_walk_failed".into(), json!(true));
                    s.insert(
                        "inventory_incomplete_detail".into(),
                        json!(format!(
                            "The sample walk failed ({}); {samples} sample(s) were read before it \
                             did, and because the walk sorts before returning rows the failure \
                             can cost rows on either side of it. The store's sample count is not \
                             known from this walk",
                            drops.first_error().unwrap_or("no error message")
                        )),
                    );
                }
                if !lookup_failures.is_empty() {
                    let detail = format!(
                        "{} census(es) this summary's counts are built on did not complete, so \
                         those counts are not the store's: {}",
                        lookup_failures.len(),
                        lookup_failures.join("; ")
                    );
                    s.insert("lookup_failures".into(), json!(lookup_failures));
                    s.insert("content_incomplete".into(), json!(true));
                    s.insert(
                        "content_incomplete_reason".into(),
                        json!(IncompleteReason::UnresolvedStructure.as_str()),
                    );
                    s.insert("content_incomplete_detail".into(), json!(detail));
                }
                let workouts_label = match workouts_count {
                    Ok(Some(n)) if workouts.schema.is_some() => {
                        format!("{workouts_read} of {n} workout(s) read")
                    }
                    Ok(Some(n)) => format!("{n} workout row(s) unread"),
                    Ok(None) => "workouts table absent".to_string(),
                    Err(_) => "workouts not counted".to_string(),
                };
                s.insert(
                    "name".into(),
                    json!(format!(
                        "HealthKit: {}, {deleted_samples} deleted, {workouts_label}",
                        if walk_failed {
                            format!("sample walk failed, {samples} read")
                        } else {
                            format!("{samples} sample(s)")
                        }
                    )),
                );
                out.extend(workouts.records);
                out.push(parent_record(case, parent, Value::Object(s)));
                out
            },
        ))
    }
}
