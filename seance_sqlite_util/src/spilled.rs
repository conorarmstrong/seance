//! The `process` of a parser whose database is chosen by name and then proven
//! by its schema (call history, contacts).
//!
//! `seance_plugin_call_history` and `seance_plugin_contacts` carried identical
//! copies of this function and of the two probes below (ROADMAP §5.11, found by
//! `scripts/clone-scan.py`); they differed only in names, a record type and the
//! tables that prove the schema. Those are the fields of [`SpilledDbSpec`].
//!
//! The honesty contract is the point of keeping it in one place:
//!
//! * a file with no SQLite header is not this parser's, and stays silent;
//! * a file that carries the header and then fails is reported with the
//!   standard incompleteness pair, because zero artifacts would make a corrupt
//!   store indistinguishable from a device that never had the data;
//! * a database the spill could not stage in full says so on what it yields.

use rusqlite::Connection;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use seance_core::module::ModuleError;
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{probe_table, Presence, TempDb};

/// What distinguishes one spilled-database parser from another.
pub struct SpilledDbSpec<'a> {
    /// The parser's name, for the log (`CallHistoryParser`).
    pub log_label: &'a str,
    /// Tag for the temporary file (`call_history`).
    pub spill_tag: &'a str,
    /// `type` of the identification and failure records (`CallLog`).
    pub record_type: &'a str,
    /// How the store is named in a record (`Call History`).
    pub display_name: &'a str,
    /// How the store is named in a sentence (`call-history`).
    pub noun: &'a str,
    /// Tables, any one of which proves the schema is this parser's.
    pub schema_tables: &'a [&'a str],
    /// Most bytes of the database the spill will read.
    pub max_db_bytes: u64,
}

/// The catalogue could not be read, so whether a table exists is unknown.
#[derive(Debug)]
pub struct CatalogueUnreadable {
    pub table: String,
    pub why: String,
}

impl std::fmt::Display for CatalogueUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Failed to read the schema catalogue looking for '{}': {}",
            self.table, self.why
        )
    }
}

impl std::error::Error for CatalogueUnreadable {}

/// Whether a table (or view) exists.
///
/// `Err` when the catalogue itself could not be read. A corrupt database
/// answers that query with an error, and reporting it as "table absent" is what
/// turned an unreadable store into a device with no data: "no such table" and
/// "could not tell" must never render the same.
pub fn table_exists(conn: &Connection, table: &str) -> Result<bool, CatalogueUnreadable> {
    match probe_table(conn, table) {
        Presence::Present => Ok(true),
        Presence::Absent => Ok(false),
        Presence::Undetermined(why) => Err(CatalogueUnreadable {
            table: table.to_string(),
            why: why.to_string(),
        }),
    }
}

/// Whether the staged copy begins with the SQLite file magic: what tells "not
/// our database" (stay silent) from "a store that would not open" (report).
pub fn staged_looks_like_sqlite(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && seance_core::io::is_sqlite_header(&head)
}

fn marker(
    artifact: &Artifact,
    spec: &SpilledDbSpec<'_>,
    name: &str,
    extra: serde_json::Value,
    label: String,
) -> Artifact {
    let mut metadata = json!({
        "type": spec.record_type,
        "file_name": name,
        "name": label,
    });
    if let (Some(base), Some(extra)) = (metadata.as_object_mut(), extra.as_object()) {
        base.extend(extra.clone());
    }
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(artifact.id)
}

/// Run a name-selected, schema-proven database through `parse`.
///
/// The caller has already decided, by name, that the artifact might be its
/// database. `parse` gets the open connection, the case id, the parent id and
/// the file name.
pub fn process_spilled_db<E: std::fmt::Display>(
    artifact: &Artifact,
    name: &str,
    spec: &SpilledDbSpec<'_>,
    parse: impl FnOnce(&Connection, Uuid, Uuid, &str) -> Result<Vec<Artifact>, E>,
) -> Result<Vec<Artifact>, ModuleError> {
    info!("{} processing: {}", spec.log_label, name);

    let Some(data_source) = artifact.data.as_ref() else {
        info!(
            "No data source for {}, producing identification artifact only",
            name
        );
        return Ok(vec![marker(
            artifact,
            spec,
            name,
            json!({ "status": "Identified" }),
            format!(
                "{} Database (not parsed - no data): {}",
                spec.display_name, name
            ),
        )]);
    };

    let temp = TempDb::spill(data_source.as_ref(), spec.spill_tag, spec.max_db_bytes)
        .map_err(|e| ModuleError::ParsingError(format!("Failed to extract DB: {}", e)))?;

    let result = (|| -> Result<Vec<Artifact>, String> {
        // A file with no SQLite header is not our database, and silence is the
        // right answer. From here on every failure is reported.
        if !staged_looks_like_sqlite(temp.path()) {
            debug!("{} carries no SQLite header, skipping", name);
            return Ok(Vec::new());
        }
        let conn = temp
            .open()
            .map_err(|e| format!("Failed to open the {} database: {e}", spec.noun))?;
        // `?`, not "absent": a catalogue that will not read takes the failure
        // path, which carries the incompleteness pair.
        let mut proven = false;
        for table in spec.schema_tables {
            if table_exists(&conn, table).map_err(|e| e.to_string())? {
                proven = true;
                break;
            }
        }
        if !proven {
            info!("{} lacks a {} schema, skipping", name, spec.noun);
            return Ok(Vec::new());
        }
        parse(&conn, artifact.case_id, artifact.id, name).map_err(|e| e.to_string())
    })();

    match result {
        Ok(mut artifacts) => {
            // The truncation the parser cannot see: a database the spill could
            // not stage in full still opens and answers from the pages it
            // reaches, so what it yields would read as the whole store.
            temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
            info!(
                "{} extracted {} records from {}",
                spec.log_label,
                artifacts.len(),
                name
            );
            Ok(artifacts)
        }
        Err(e) => {
            warn!("Failed to parse {} database ({}): {}", spec.noun, name, e);
            let reason = IncompleteReason::UnresolvedStructure.as_str();
            Ok(vec![marker(
                artifact,
                spec,
                name,
                json!({
                    "status": "ParseFailed",
                    "error": e,
                    // The standard pair, not just a status string: the API,
                    // export and reporting paths key on these, and without them
                    // a failed parse exports as a store that held nothing.
                    "content_incomplete": true,
                    "content_incomplete_reason": reason,
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": reason,
                }),
                format!("{} Database (parse failed): {}", spec.display_name, name),
            )])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use std::sync::Arc;

    const SPEC: SpilledDbSpec<'static> = SpilledDbSpec {
        log_label: "TestParser",
        spill_tag: "spilled_test",
        record_type: "TestRecord",
        display_name: "Test",
        noun: "test",
        schema_tables: &["alpha", "beta"],
        max_db_bytes: 1 << 20,
    };

    fn database(sql: &str) -> Vec<u8> {
        let path = std::env::temp_dir().join(format!("seance_spilled_{}.db", Uuid::new_v4()));
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(sql).unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        bytes
    }

    fn artifact(bytes: Option<Vec<u8>>) -> Artifact {
        let data = bytes.map(|b| Arc::new(ByteSliceDataSource::new(b)) as Arc<dyn DataSource>);
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            data,
            json!({ "name": "x.db" }),
        )
    }

    fn parsed_one(
        _: &Connection,
        case: Uuid,
        parent: Uuid,
        _: &str,
    ) -> Result<Vec<Artifact>, String> {
        Ok(vec![Artifact::new(
            case,
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "Row" }),
        )
        .with_parent(parent)])
    }

    #[test]
    fn a_name_match_with_no_bytes_is_identified_and_not_parsed() {
        let a = artifact(None);
        let out = process_spilled_db(&a, "x.db", &SPEC, parsed_one).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["status"], "Identified");
        assert_eq!(out[0].metadata["type"], "TestRecord");
        assert!(out[0].metadata["name"]
            .as_str()
            .unwrap()
            .contains("not parsed - no data"));
    }

    #[test]
    fn a_file_with_no_sqlite_header_is_not_ours_and_says_nothing() {
        let a = artifact(Some(b"this is not a database at all, just text".to_vec()));
        assert!(process_spilled_db(&a, "x.db", &SPEC, parsed_one)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_database_without_a_proving_table_says_nothing_and_never_calls_parse() {
        let a = artifact(Some(database("CREATE TABLE other (id INTEGER);")));
        let out = process_spilled_db(
            &a,
            "x.db",
            &SPEC,
            |_: &Connection, _, _, _| -> Result<Vec<Artifact>, String> {
                panic!("parse must not run on a schema that is not ours")
            },
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn any_one_proving_table_admits_the_database_and_its_output_is_returned() {
        let a = artifact(Some(database("CREATE TABLE beta (id INTEGER);")));
        let out = process_spilled_db(&a, "x.db", &SPEC, parsed_one).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].parent_id, Some(a.id));
    }

    #[test]
    fn a_parse_failure_is_a_record_with_the_incompleteness_pair_not_silence() {
        let a = artifact(Some(database("CREATE TABLE alpha (id INTEGER);")));
        let out = process_spilled_db(
            &a,
            "x.db",
            &SPEC,
            |_: &Connection, _, _, _| -> Result<Vec<Artifact>, String> {
                Err("no such column: body".to_string())
            },
        )
        .unwrap();
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["status"], "ParseFailed");
        assert_eq!(m["error"], "no such column: body");
        assert_eq!(m["content_incomplete"], true);
        assert_eq!(m["inventory_incomplete"], true);
        assert!(m["content_incomplete_reason"].is_string());
        assert!(m["name"].as_str().unwrap().contains("parse failed"));
    }
}
