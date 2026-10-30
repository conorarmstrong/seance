//! HealthKit workouts and sleep stages, read out of `healthdb_secure.sqlite`.
//!
//! Two generations of the workout tables are read, each against a device
//! whose creation notes list the workouts it holds:
//!
//! * **`workout_activities` (iOS 16 and later).** `workouts` keeps only the
//!   distance; the activity type, location type, times and duration are on
//!   the activity row (`owner_id` = the workout), and the totals are rows of
//!   `workout_statistics`. Validated on the Hickman iOS 17 image
//!   (`user_version` 17012): the ten workouts its creation PDF lists
//!   (Fitness, p. 93) are ten of the 29 rows, with the PDF's start time,
//!   duration, distance, average heart rate and active calories.
//! * **`workouts` (before iOS 16).** One row carries the activity type,
//!   duration, energy and distance. Validated on the Hickman iOS 14.3 image
//!   (`user_version` 14201): the six workouts its creation PDF lists are six
//!   of the 12 rows, at the PDF's start and end times.
//!
//! **What is named, and on what basis.** Every number is published. A name
//! is given only where an answer key corroborates it: activity types 37
//! (running) and 52 (walking), location type 3 (outdoor), and statistics 5
//! (heart rate, stored per second), 8 (distance, metres) and 10 (active
//! energy, kcal). They are Apple's public HealthKit enumerations, so each
//! name is marked `asserted` — the file itself names none of them.
//!
//! **Sleep.** `samples.data_type` 63 is sleep analysis and its
//! `category_samples.value` is the stage. The stage names are Apple's public
//! `HKCategoryValueSleepAnalysis` values; the asleep set {1, 3, 4, 5} was
//! checked against the nightly sleep totals in the Hickman iOS 17 PDF
//! (Health, p. 94) — the Watch's asleep samples sum to within minutes of each
//! night listed — so the stage names are asserted, and the split between
//! the asleep stages is not independently corroborated.

use std::collections::HashMap;

use rusqlite::Connection;
use seance_core::artifact::Artifact;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{cfloat, cint, cstr, has_table, insert_cocoa, parent_record, table_columns};

/// Ceiling on workouts carried into one case from a single store.
pub(crate) const MAX_WORKOUTS: usize = 100_000;

/// `samples.data_type` of a sleep-analysis category sample.
pub(crate) const SLEEP_ANALYSIS_TYPE: i64 = 63;

/// The basis every sleep-stage name carries.
pub(crate) const SLEEP_STAGE_BASIS: &str = "asserted from Apple's public HKCategoryValueSleepAnalysis values; \
     the asleep set {1,3,4,5} corroborated against the nightly sleep totals of the Hickman iOS 17 creation notes";

/// A sleep stage's name, and whether it is time asleep.
pub(crate) fn sleep_stage(value: i64) -> Option<(&'static str, bool)> {
    Some(match value {
        0 => ("in_bed", false),
        1 => ("asleep_unspecified", true),
        2 => ("awake", false),
        3 => ("asleep_core", true),
        4 => ("asleep_deep", true),
        5 => ("asleep_rem", true),
        _ => return None,
    })
}

/// Workout activity types an answer key corroborates.
fn activity_name(t: i64) -> Option<&'static str> {
    match t {
        37 => Some("running"),
        52 => Some("walking"),
        _ => None,
    }
}

const ACTIVITY_BASIS: &str = "asserted from Apple's public HKWorkoutActivityType values; \
     37 and 52 corroborated by the Hickman iOS 14.3 and iOS 17 creation notes (Outdoor Run / Outdoor Walk)";

/// Which generation of the workout tables a store holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum WorkoutSchema {
    /// iOS 16+: `workout_activities` + `workout_statistics`.
    Activities,
    /// Before iOS 16: activity and totals on the `workouts` row.
    Legacy,
}

impl WorkoutSchema {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            WorkoutSchema::Activities => "workout_activities",
            WorkoutSchema::Legacy => "workouts",
        }
    }
}

/// What the workout read gave.
pub(crate) struct WorkoutRead {
    pub(crate) records: Vec<Artifact>,
    pub(crate) schema: Option<WorkoutSchema>,
    /// A statement that did not run, with SQLite's reason. The records read
    /// before it are kept.
    pub(crate) error: Option<String>,
    pub(crate) capped: bool,
    pub(crate) deleted: usize,
}

/// Which schema, if either, the store's `workouts` table is in.
pub(crate) fn workout_schema(conn: &Connection) -> Option<WorkoutSchema> {
    if !has_table(conn, "workouts") {
        return None;
    }
    let cols = table_columns(conn, "workouts");
    if has_table(conn, "workout_activities") {
        Some(WorkoutSchema::Activities)
    } else if cols.contains("activity_type") && cols.contains("duration") {
        Some(WorkoutSchema::Legacy)
    } else {
        None
    }
}

/// Per-workout statistics (`workout_statistics` joined through the
/// activity), keyed by workout `data_id`.
type Stat = (i64, f64, Option<f64>, Option<f64>);

fn read_statistics(conn: &Connection) -> Result<HashMap<i64, Vec<Stat>>, String> {
    let mut by_workout: HashMap<i64, Vec<Stat>> = HashMap::new();
    if !has_table(conn, "workout_statistics") {
        return Ok(by_workout);
    }
    let mut stmt = conn
        .prepare(
            "SELECT a.owner_id, st.data_type, st.quantity, st.min, st.max \
             FROM workout_statistics st JOIN workout_activities a ON a.ROWID = st.workout_activity_id \
             ORDER BY a.owner_id, st.data_type",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                cint(r, 0),
                cint(r, 1),
                cfloat(r, 2),
                cfloat(r, 3),
                cfloat(r, 4),
            ))
        })
        .map_err(|e| e.to_string())?;
    for row in rows {
        let (owner, ty, q, min, max) = row.map_err(|e| e.to_string())?;
        if let (Some(owner), Some(ty), Some(q)) = (owner, ty, q) {
            by_workout.entry(owner).or_default().push((ty, q, min, max));
        }
    }
    Ok(by_workout)
}

fn count_events(conn: &Connection) -> HashMap<i64, i64> {
    let mut out = HashMap::new();
    if !has_table(conn, "workout_events") {
        return out;
    }
    if let Ok(mut stmt) =
        conn.prepare("SELECT owner_id, count(*) FROM workout_events GROUP BY owner_id")
    {
        if let Ok(rows) = stmt.query_map([], |r| Ok((cint(r, 0), cint(r, 1)))) {
            for (o, n) in rows.flatten() {
                if let (Some(o), Some(n)) = (o, n) {
                    out.insert(o, n);
                }
            }
        }
    }
    out
}

/// The statistic's name, and the unit its quantity is in, where an answer
/// key corroborates both.
fn statistic_name(t: i64) -> Option<(&'static str, &'static str)> {
    match t {
        5 => Some(("heart_rate", "count/s")),
        8 => Some(("distance_walking_running", "m")),
        10 => Some(("active_energy_burned", "kcal")),
        _ => None,
    }
}

const STATISTIC_BASIS: &str = "asserted from Apple's public HealthKit type identifiers; 5, 8 and 10 \
     corroborated against the average heart rate, distance and active calories of the Hickman iOS 17 creation notes";

/// Read every workout the store holds, in the generation it holds them.
pub(crate) fn read_workouts(conn: &Connection, case: Uuid, parent: Uuid) -> WorkoutRead {
    let mut read = WorkoutRead {
        records: Vec::new(),
        schema: workout_schema(conn),
        error: None,
        capped: false,
        deleted: 0,
    };
    let Some(schema) = read.schema else {
        return read;
    };
    let (stats, stats_error) = match schema {
        WorkoutSchema::Activities => match read_statistics(conn) {
            Ok(s) => (s, None),
            Err(e) => (HashMap::new(), Some(e)),
        },
        WorkoutSchema::Legacy => (HashMap::new(), None),
    };
    let events = count_events(conn);
    let sql = match schema {
        // One row per workout: its primary activity (or, where none is marked
        // primary, the first). A multi-activity workout names how many.
        WorkoutSchema::Activities => {
            "SELECT w.data_id, s.start_date, s.end_date, o.type, o.creation_date, \
                    p.origin_product_type, p.tz_name, \
                    a.activity_type, a.location_type, a.start_date, a.end_date, a.duration, \
                    w.total_distance, NULL, NULL, \
                    (SELECT count(*) FROM workout_activities x WHERE x.owner_id = w.data_id) \
             FROM workouts w \
             LEFT JOIN samples s ON s.data_id = w.data_id \
             LEFT JOIN objects o ON o.data_id = w.data_id \
             LEFT JOIN data_provenances p ON p.ROWID = o.provenance \
             LEFT JOIN workout_activities a ON a.ROWID = ( \
                 SELECT y.ROWID FROM workout_activities y WHERE y.owner_id = w.data_id \
                 ORDER BY y.is_primary_activity DESC, y.start_date LIMIT 1) \
             ORDER BY s.start_date, w.data_id LIMIT ?1"
        }
        WorkoutSchema::Legacy => {
            "SELECT w.data_id, s.start_date, s.end_date, o.type, o.creation_date, \
                    p.origin_product_type, p.tz_name, \
                    w.activity_type, NULL, NULL, NULL, w.duration, \
                    w.total_distance, w.total_energy_burned, w.total_basal_energy_burned, NULL \
             FROM workouts w \
             LEFT JOIN samples s ON s.data_id = w.data_id \
             LEFT JOIN objects o ON o.data_id = w.data_id \
             LEFT JOIN data_provenances p ON p.ROWID = o.provenance \
             ORDER BY s.start_date, w.data_id LIMIT ?1"
        }
    };
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(e) => {
            read.error = Some(e.to_string());
            return read;
        }
    };
    let rows = stmt.query_map([MAX_WORKOUTS as i64 + 1], |r| {
        Ok((
            cint(r, 0),
            cfloat(r, 1),
            cfloat(r, 2),
            cint(r, 3),
            cfloat(r, 4),
            cstr(r, 5),
            cstr(r, 6),
            cint(r, 7),
            cint(r, 8),
            cfloat(r, 9),
            cfloat(r, 10),
            cfloat(r, 11),
            cfloat(r, 12),
            cfloat(r, 13),
            cfloat(r, 14),
            cint(r, 15),
        ))
    });
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            read.error = Some(e.to_string());
            return read;
        }
    };
    for row in rows {
        let row = match row {
            Ok(r) => r,
            Err(e) => {
                read.error = Some(e.to_string());
                break;
            }
        };
        if read.records.len() >= MAX_WORKOUTS {
            read.capped = true;
            break;
        }
        let (
            data_id,
            s_start,
            s_end,
            obj_type,
            created,
            product,
            tz,
            activity,
            location,
            a_start,
            a_end,
            duration,
            distance,
            energy,
            basal,
            n_activities,
        ) = row;
        let mut m = Map::new();
        m.insert("type".into(), json!("HealthWorkout"));
        m.insert("subtype".into(), json!("health_workout"));
        m.insert("platform".into(), json!("iOS"));
        m.insert("source".into(), json!("healthdb_secure.sqlite"));
        m.insert("schema".into(), json!(schema.as_str()));
        if let Some(id) = data_id {
            m.insert("data_id".into(), json!(id));
        }
        // The activity's own times where the generation has them; the
        // workout sample's otherwise.
        let (start, start_col) = match a_start {
            Some(s) => (Some(s), "workout_activities.start_date"),
            None => (s_start, "samples.start_date"),
        };
        let (end, end_col) = match a_end {
            Some(e) => (Some(e), "workout_activities.end_date"),
            None => (s_end, "samples.end_date"),
        };
        if let Some(s) = start {
            insert_cocoa(&mut m, "start", s, start_col);
            insert_cocoa(&mut m, "date", s, start_col);
        }
        if let Some(e) = end {
            insert_cocoa(&mut m, "end", e, end_col);
        }
        if let Some(d) = duration {
            m.insert("duration_seconds".into(), json!(d));
        }
        match activity {
            Some(a) => {
                m.insert("activity_type".into(), json!(a));
                match activity_name(a) {
                    Some(n) => {
                        m.insert("activity_type_name".into(), json!(n));
                        m.insert("activity_type_name_basis".into(), json!(ACTIVITY_BASIS));
                    }
                    None => {
                        m.insert("activity_type_name_unknown".into(), json!(true));
                    }
                }
            }
            None => {
                m.insert("activity_type_not_recorded".into(), json!(true));
            }
        }
        if let Some(l) = location {
            m.insert("location_type".into(), json!(l));
            if l == 3 {
                m.insert("location_type_name".into(), json!("outdoor"));
            } else {
                m.insert("location_type_name_unknown".into(), json!(true));
            }
        }
        if let Some(n) = n_activities.filter(|&n| n > 1) {
            m.insert("activity_rows".into(), json!(n));
        }
        if let Some(d) = distance {
            m.insert("total_distance_km".into(), json!(d));
            m.insert(
                "total_distance_unit_basis".into(),
                json!("workouts.total_distance; kilometres, corroborated against the distances in the Hickman iOS 14.3 and iOS 17 creation notes"),
            );
        }
        if let Some(e) = energy {
            m.insert("total_energy_burned".into(), json!(e));
            m.insert("total_energy_burned_unit_not_recorded".into(), json!(true));
        }
        if let Some(b) = basal {
            m.insert("total_basal_energy_burned".into(), json!(b));
        }
        let is_deleted = obj_type == Some(2);
        if is_deleted {
            read.deleted += 1;
        }
        m.insert("deleted".into(), json!(is_deleted));
        if let Some(c) = created {
            insert_cocoa(&mut m, "created", c, "objects.creation_date");
        }
        if let Some(p) = product.filter(|p| !p.is_empty()) {
            m.insert("origin_product_type".into(), json!(p));
        }
        if let Some(t) = tz.filter(|t| !t.is_empty()) {
            m.insert("recording_timezone".into(), json!(t));
        }
        if let Some(id) = data_id {
            if let Some(n) = events.get(&id) {
                m.insert("event_rows".into(), json!(n));
            }
            if schema == WorkoutSchema::Activities {
                let mut list = Vec::new();
                for (ty, q, min, max) in stats.get(&id).map(Vec::as_slice).unwrap_or(&[]) {
                    let mut st = Map::new();
                    st.insert("data_type".into(), json!(ty));
                    st.insert("quantity".into(), json!(q));
                    if let Some(v) = min {
                        st.insert("min".into(), json!(v));
                    }
                    if let Some(v) = max {
                        st.insert("max".into(), json!(v));
                    }
                    match statistic_name(*ty) {
                        Some((name, unit)) => {
                            st.insert("data_type_name".into(), json!(name));
                            st.insert("unit".into(), json!(unit));
                            match *ty {
                                5 => {
                                    m.insert("heart_rate_avg_bpm".into(), json!(q * 60.0));
                                    if let Some(v) = min {
                                        m.insert("heart_rate_min_bpm".into(), json!(v * 60.0));
                                    }
                                    if let Some(v) = max {
                                        m.insert("heart_rate_max_bpm".into(), json!(v * 60.0));
                                    }
                                }
                                10 => {
                                    m.insert("active_energy_kcal".into(), json!(q));
                                }
                                _ => {}
                            }
                        }
                        None => {
                            st.insert("data_type_name_unknown".into(), json!(true));
                        }
                    }
                    list.push(Value::Object(st));
                }
                if !list.is_empty() {
                    m.insert("statistics".into(), json!(list));
                    m.insert("statistics_names_basis".into(), json!(STATISTIC_BASIS));
                }
                if let Some(e) = &stats_error {
                    m.insert("statistics_unread".into(), json!(true));
                    m.insert("statistics_unread_reason".into(), json!(e));
                }
            }
        }
        let label = activity
            .map(|a| match activity_name(a) {
                Some(n) => n.to_string(),
                None => format!("activity {a}"),
            })
            .unwrap_or_else(|| "workout".into());
        m.insert(
            "name".into(),
            json!(match duration {
                Some(d) => format!("Workout: {label}, {:.0} s", d),
                None => format!("Workout: {label}"),
            }),
        );
        read.records
            .push(parent_record(case, parent, Value::Object(m)));
    }
    if read.error.is_none() {
        read.error = stats_error;
    }
    read
}
