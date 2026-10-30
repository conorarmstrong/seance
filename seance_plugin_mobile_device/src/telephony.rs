//! The phone's own number, and the SIMs that carried it.
//!
//! `telephony.db`'s `siminfo` table is one row per SIM the device has known:
//! the subscriber's number where the carrier provisioned it onto the card, the
//! ICCID that identifies the card itself, the carrier, and the name the user
//! gave the line.
//!
//! A dual-SIM phone has two of each, and that is not a contradiction — they are
//! emitted as several readings of a multi-valued fact, which the device-facts
//! compiler knows not to report as sources disagreeing.
//!
//! The column set has changed across Android versions, so the table's own
//! columns are read first and only those that exist are selected. A `SELECT`
//! naming a column this build expects and the device does not have fails whole,
//! and a phone's number would then be reported as absent because one unrelated
//! column was renamed.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{SupportedRange, TempDb};
use serde_json::json;
use tracing::debug;

use crate::schema_support::{
    assess_version, plan_columns, unresolved_fields_marker, user_version, SchemaSupport,
};

const MAX_DB_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SIMS: usize = 50;

/// The schema version this parser was validated against: the one real
/// `telephony.db` this project holds, from the android2022 (Pixel, Android 12)
/// full-file-system tar. A single version, so a single-point range.
const SUPPORT: SchemaSupport = SchemaSupport {
    app: "android-telephony",
    store: "telephony.db",
    record_type: "MobileDeviceInfo",
    range: SupportedRange {
        min: 1_703_944,
        max: Some(1_703_944),
    },
    evidence: "android2022 data/user_de/0/com.android.providers.telephony/databases/telephony.db \
               (PRAGMA user_version 1703944)",
};

/// Is this the telephony provider's database?
pub fn is_telephony_db(name: &str) -> bool {
    name.eq_ignore_ascii_case("telephony.db")
}

/// Columns of `siminfo` this build reads, and the fact each becomes.
const COLUMNS: &[(&str, &str)] = &[
    ("number", "phone_number"),
    ("icc_id", "iccid"),
    ("carrier_name", "carrier"),
    ("display_name", "sim_name"),
    ("imsi", "imsi"),
];

/// The columns a SIM record is meaningless without: losing either is declared.
const REQUIRED: &[(&str, &[&str])] = &[("number", &["number"]), ("icc_id", &["icc_id"])];

/// Columns the validated store may lack — `imsi` is absent from the real
/// android2022 file — so their absence is not drift.
const OPTIONAL: &[(&str, &[&str])] = &[
    ("carrier_name", &["carrier_name"]),
    ("display_name", &["display_name"]),
    ("imsi", &["imsi"]),
];

/// The record for a `telephony.db` the name matched and this parser could not
/// read.
///
/// "This phone had no SIM" and "we could not read which SIMs it had" are
/// different answers; an empty result gave the first for the second
/// (HUNT-188). The staging shortfall, when there is one, is carried too.
fn unreadable(artifact: &Artifact, path: &str, temp: Option<&TempDb>, detail: String) -> Artifact {
    let mut metadata = json!({
        "type": "MobileDeviceInfo",
        "platform": "android",
        "subtype": "telephony_unreadable",
        "name": "Android telephony store, not read",
        "source_file": path,
        "source_kind": "android_telephony",
        "facts": {},
        "fact_sources": {},
        CONTENT_INCOMPLETE: true,
        CONTENT_INCOMPLETE_REASON: IncompleteReason::UnresolvedStructure.as_str(),
        "content_incomplete_detail": detail,
    });
    if let Some(temp) = temp {
        if let Some(reason) = temp.content_incomplete_reason() {
            metadata["staging_incomplete_reason"] = json!(reason);
        }
        if let Some(wal) = temp.wal_incomplete_reason() {
            metadata["wal_incomplete_reason"] = json!(wal);
        }
    }
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(artifact.id)
}

/// Carry the spill's shortfall onto a record: the main file not staged in full
/// (its own reason, `cap_reached` or `short_read`) and a write-ahead log that
/// was refused or could not be looked for (`wal_incomplete_reason`, where a
/// phone's newest rows live). A reason the record already carries is kept —
/// it is the more specific one — and the staging reason sits beside it.
fn stamp_staging(metadata: &mut serde_json::Value, temp: &TempDb) {
    let Some(object) = metadata.as_object_mut() else {
        return;
    };
    if let Some(reason) = temp.content_incomplete_reason() {
        object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
        object
            .entry(CONTENT_INCOMPLETE_REASON.to_string())
            .or_insert(json!(reason));
        object
            .entry("content_incomplete_detail".to_string())
            .or_insert(json!("the telephony database was not staged in full"));
        object.insert("staging_incomplete_reason".to_string(), json!(reason));
    }
    if let Some(wal) = temp.wal_incomplete_reason() {
        object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
        object.insert("wal_incomplete_reason".to_string(), json!(wal));
        object
            .entry("content_incomplete_detail".to_string())
            .or_insert(json!(
                "the write-ahead log was not staged, so SIM rows committed but not yet \
             checkpointed are missing"
            ));
    }
}

/// One `siminfo` cell, read as whatever SQLite type it holds.
enum Cell {
    Null,
    Text(String),
    /// A BLOB, or text that is not UTF-8: a value this reader will not guess
    /// an encoding for.
    NotRendered,
}

/// SQLite is dynamically typed: a `number` held as an INTEGER failed the
/// string read and was published as absent (HUNT-212). Integers and reals are
/// rendered in their decimal form; a BLOB or non-UTF-8 text is `NotRendered`
/// and counted on the record.
fn cell(row: &rusqlite::Row, idx: usize) -> Cell {
    use rusqlite::types::ValueRef;
    match row.get_ref(idx) {
        Ok(ValueRef::Null) => Cell::Null,
        Ok(ValueRef::Integer(i)) => Cell::Text(i.to_string()),
        Ok(ValueRef::Real(f)) => Cell::Text(f.to_string()),
        Ok(ValueRef::Text(t)) => match std::str::from_utf8(t) {
            Ok(t) => Cell::Text(t.to_string()),
            Err(_) => Cell::NotRendered,
        },
        Ok(ValueRef::Blob(_)) | Err(_) => Cell::NotRendered,
    }
}

/// Reads the telephony provider into device facts.
#[derive(Debug, Default)]
pub struct AndroidTelephonyParser;

impl AndroidTelephonyParser {
    pub fn new() -> Self {
        Self
    }
}

impl ForensicsModule for AndroidTelephonyParser {
    fn id(&self) -> &str {
        "plugin.mobile.android_telephony_device"
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

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_telephony_db(name) {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(name);

        // Every failure past the name match is the store unread, and says so:
        // an empty result here read exactly like a device with no telephony
        // store at all (HUNT-188).
        let temp = match TempDb::spill(data.as_ref(), "android_telephony", MAX_DB_BYTES) {
            Ok(t) => t,
            Err(e) => {
                debug!("telephony.db could not be staged: {e}");
                return Ok(vec![unreadable(
                    artifact,
                    path,
                    None,
                    format!("the telephony database could not be staged for reading: {e}"),
                )]);
            }
        };
        let conn = match temp.open() {
            Ok(c) => c,
            Err(e) => {
                return Ok(vec![unreadable(
                    artifact,
                    path,
                    Some(&temp),
                    format!("the telephony database could not be opened: {e}"),
                )])
            }
        };

        // Which of the columns this build knows does this device's table have?
        let plan = match plan_columns(&conn, "siminfo", REQUIRED, OPTIONAL) {
            Ok(plan) => plan,
            Err(why) => {
                return Ok(vec![unreadable(
                    artifact,
                    path,
                    Some(&temp),
                    format!("the siminfo table's columns could not be read: {why}"),
                )])
            }
        };
        if plan.present.is_empty() {
            // The catalogue answered, and there is no siminfo table: this is
            // not the telephony provider.
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if !plan.missing_required().is_empty() {
            out.push(unresolved_fields_marker(
                &SUPPORT,
                "siminfo",
                &plan,
                0,
                artifact.case_id,
                artifact.id,
            ));
        }
        out.extend(assess_version(
            &SUPPORT,
            &user_version(&conn),
            artifact.case_id,
            artifact.id,
        ));
        let present: Vec<(&str, &str)> = COLUMNS
            .iter()
            .filter(|(column, _)| plan.column(column).is_some())
            .map(|(column, fact)| (*column, *fact))
            .collect();
        if present.is_empty() {
            return Ok(out);
        }

        let select = present
            .iter()
            .map(|(column, _)| *column)
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("SELECT {select} FROM siminfo LIMIT ?1");
        let mut statement = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                out.push(unreadable(
                    artifact,
                    path,
                    Some(&temp),
                    format!("the siminfo table could not be queried: {e}"),
                ));
                return Ok(out);
            }
        };
        let count = present.len();
        let rows = statement.query_map([MAX_SIMS as i64 + 1], move |row| {
            let mut values = Vec::with_capacity(count);
            for i in 0..count {
                values.push(cell(row, i));
            }
            Ok(values)
        });
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => {
                out.push(unreadable(
                    artifact,
                    path,
                    Some(&temp),
                    format!("the siminfo table could not be read: {e}"),
                ));
                return Ok(out);
            }
        };

        let mut by_fact: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
        // Values the device held that this reader will not render as text (a
        // BLOB, or text that is not UTF-8), by column: stated, never absent.
        let mut not_rendered: std::collections::BTreeMap<String, usize> = Default::default();
        let mut sims = 0usize;
        // A row the walk could not yield is counted, never flattened away: a
        // SIM that existed and would not decode is absent from the list, and
        // the list must say it is short (HUNT-188). rusqlite ends the walk at
        // the first step error, so the rows after it are unread too.
        let mut undecodable = 0usize;
        for row in rows {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    debug!("siminfo row would not decode: {e}");
                    undecodable += 1;
                    continue;
                }
            };
            sims += 1;
            for ((column, fact), value) in present.iter().zip(row) {
                match value {
                    Cell::Text(value) if !value.trim().is_empty() => {
                        by_fact.entry(fact).or_default().push(value)
                    }
                    Cell::Text(_) | Cell::Null => {}
                    Cell::NotRendered => {
                        *not_rendered.entry(format!("siminfo.{column}")).or_default() += 1
                    }
                }
            }
        }
        if sims == 0 && undecodable > 0 {
            // Not "no SIM recorded": the rows were there and would not read.
            out.push(unreadable(
                artifact,
                path,
                Some(&temp),
                format!(
                    "the siminfo walk stopped on a row that would not decode ({undecodable} \
                     row error(s)) before any SIM record was read"
                ),
            ));
            return Ok(out);
        }
        if sims == 0 {
            // The table is there and empty: a device that never had a SIM. Say
            // so rather than emitting nothing, which reads as "not examined".
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "MobileDeviceInfo",
                        "platform": "android",
                        "subtype": "no_sim_recorded",
                        "name": "Android telephony: no SIM recorded",
                        "source_file": path,
                        "source_kind": "android_telephony",
                        "sims_read": 0,
                        "facts": {},
                        "fact_sources": {},
                        "message": "the telephony provider's siminfo table is present and empty: \
                                    this device has no record of a SIM having been inserted",
                    }),
                )
                .with_parent(artifact.id),
            );
            // "Present and empty" is only as good as what was staged: a short
            // spill or a refused WAL qualifies it.
            if let Some(last) = out.last_mut() {
                stamp_staging(&mut last.metadata, &temp);
            }
            return Ok(out);
        }

        let capped = sims > MAX_SIMS;
        let mut facts = serde_json::Map::new();
        let mut sources = serde_json::Map::new();
        for (fact, mut values) in by_fact {
            values.truncate(MAX_SIMS);
            let column = COLUMNS
                .iter()
                .find(|(_, f)| f == &fact)
                .map(|(c, _)| *c)
                .unwrap_or(fact);
            facts.insert(fact.to_string(), json!(values));
            sources.insert(fact.to_string(), json!(format!("siminfo.{column}")));
        }

        let mut metadata = json!({
            "type": "MobileDeviceInfo",
            "platform": "android",
            "name": format!("Android telephony facts from {name}"),
            "source_file": path,
            "source_kind": "android_telephony",
            "sims_read": sims.min(MAX_SIMS),
            "facts": facts,
            "fact_sources": sources,
        });
        metadata["rows_undecodable"] = json!(undecodable);
        if !not_rendered.is_empty() {
            metadata["values_not_rendered"] = json!(not_rendered);
        }
        // Every way the SIM list can be short of what the device held, each
        // with its own reason (a capped spill is `cap_reached`, not the
        // `short_read` this used to say for every staging shortfall).
        let shortfall = if undecodable > 0 {
            Some((
                IncompleteReason::UnresolvedStructure.as_str(),
                format!(
                    "{undecodable} siminfo row(s) could not be decoded and the walk stopped \
                     there, so SIM records after it are not listed"
                ),
            ))
        } else if capped {
            Some((
                IncompleteReason::CapReached.as_str(),
                format!("more than {MAX_SIMS} SIM records are in this store"),
            ))
        } else if !not_rendered.is_empty() {
            Some((
                IncompleteReason::UnresolvedStructure.as_str(),
                format!(
                    "{} value(s) held as a BLOB or as text that is not UTF-8 were not rendered \
                     ({}), so those facts are missing here though the device recorded them",
                    not_rendered.values().sum::<usize>(),
                    not_rendered.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
            ))
        } else {
            None
        };
        if let Some((reason, detail)) = shortfall {
            let object = metadata.as_object_mut().expect("object literal");
            object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
            object.insert(CONTENT_INCOMPLETE_REASON.to_string(), json!(reason));
            object.insert("content_incomplete_detail".to_string(), json!(detail));
        }
        stamp_staging(&mut metadata, &temp);

        out.push(
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(artifact.id),
        );
        Ok(out)
    }
}
