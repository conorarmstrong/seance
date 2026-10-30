#![forbid(unsafe_code)]
//! SRUM (System Resource Usage Monitor) Parser Module
//!
//! Parses Windows SRUDB.dat ESE database to extract application usage,
//! network connections, and system resource utilization data.
//!
//! Extracts full records from all major SRUM tables:
//! - SruDbIdMapTable: Maps integer IDs to application names and user SIDs
//! - Application Resource Usage: CPU cycles, I/O bytes, face time per app
//! - Network Data Usage: Bytes sent/received per app per interface
//! - Network Connectivity: Connection duration and start times
//! - Energy Usage: Battery and charge level data

pub mod tables;

use anyhow::{Context, Result};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    file_detection::{detect_file_type, DetectedFileType},
    io::read_exact_or_fail,
    module::{ForensicsModule, InputCapability, ModuleError},
    temp_spill::TempSpill,
};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use tables::{
    parse_app_resource_table, parse_energy_table, parse_id_map_table,
    parse_network_connectivity_table, parse_network_data_table, WalkStatus,
};
use tracing::{debug, info};

pub struct SrumParser;

impl SrumParser {
    /// Extract SRUDB.dat to a temporary file for libesedb processing. The
    /// returned [`TempSpill`] removes the file when it drops, so a panic in
    /// libesedb (swallowed by the orchestrator) cannot leak /tmp/seance_srum_*.dat.
    fn extract_to_temp_file(&self, data_source: &dyn DataSource) -> Result<TempSpill> {
        let size = data_source.size();
        // Bound the whole-file buffer: a hostile/corrupt size would otherwise
        // allocate unbounded RAM and OOM the worker (the orchestrator isolates
        // panics, not OOM). 2 GiB is far beyond any legitimate SRUDB.dat, and a
        // truncated ESE DB is useless anyway, so refuse rather than half-read.
        const MAX_SRUM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
        if size > MAX_SRUM_BYTES {
            anyhow::bail!(
                "SRUM database too large to buffer safely: {} bytes (cap {})",
                size,
                MAX_SRUM_BYTES
            );
        }
        let mut buffer = vec![0u8; size as usize];
        // read_at may short-read (e.g. when the DB is a window over a disk image);
        // the loop fills the buffer and FAILS if it cannot. Writing the partial
        // bytes instead would let libesedb open a truncated database and report
        // the subset of rows it could still read as though the whole SRUDB.dat
        // had been recovered (BUG-269).
        read_exact_or_fail(data_source, 0, &mut buffer, "SRUM database")
            .context("Failed to read SRUM database")?;

        TempSpill::write(&buffer, "srum", "dat").context("Failed to write SRUM temp file")
    }

    /// Resolve an integer ID to a human-readable name using the IdMap
    fn resolve_id(id_map: &HashMap<u32, String>, id: u32) -> String {
        id_map
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("Unknown({})", id))
    }

    /// Copy a table walk's incompleteness onto the record it produced.
    ///
    /// The record carries `record_count` and a `records` array; on its own that
    /// reads as the table's full contents. When the walk skipped rows or could
    /// not start, `content_incomplete` and `rows_skipped` travel with the data
    /// wherever it is exported, so no downstream view can quote the count as
    /// complete.
    fn stamp_walk(artifact: &mut Artifact, status: &WalkStatus) {
        let Some(reason) = status.reason() else {
            return;
        };
        let Some(map) = artifact.metadata.as_object_mut() else {
            return;
        };
        map.insert("content_incomplete".into(), json!(true));
        map.insert("content_incomplete_reason".into(), json!(reason));
        map.insert("rows_skipped".into(), json!(status.rows_skipped));
        map.insert("values_defaulted".into(), json!(status.values_defaulted));
        if !status.missing_columns.is_empty() {
            map.insert("missing_columns".into(), json!(status.missing_columns));
        }
        if let Some(what) = status.unreadable {
            map.insert("walk_unreadable".into(), json!(what));
        }
    }

    /// The standalone record that says a SRUM table walk did not read the whole
    /// table. `None` when the walk was complete, so an absent marker really does
    /// mean the rows published are everything the table held.
    ///
    /// `record_type` deliberately differs from the type the table's own records
    /// carry, so downstream grouping by `metadata.$.type` cannot file this
    /// marker as a usage record.
    ///
    /// This exists chiefly for the case where the walk recovered NOTHING: the
    /// table's own ParsedRecord is not emitted at all then, and without this an
    /// unopenable Network Data table is indistinguishable from a machine that
    /// never used the network.
    fn walk_status_artifact(
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
        record_type: &str,
        table_name: &str,
        status: &WalkStatus,
        rows_emitted: usize,
    ) -> Option<Artifact> {
        let reason = status.reason()?;
        let detail = match status.unreadable {
            Some(what) => format!(
                "the {table_name} table could not be walked: its {what} would not open, \
                 so the absence of rows here says nothing about what the table held"
            ),
            None if !status.missing_columns.is_empty() => format!(
                "{table_name} does not carry the column(s) {}: every row below reports 0 \
                 for them, which is not a measurement. {} further rows could not be \
                 decoded and {} individual values were published as 0 because the cell \
                 would not decode",
                status.missing_columns.join(", "),
                status.rows_skipped,
                status.values_defaulted
            ),
            None => format!(
                "{} of the rows in {table_name} could not be decoded and are absent from \
                 the {rows_emitted} published here; {} individual values were published \
                 as 0 because the cell would not decode",
                status.rows_skipped, status.values_defaulted
            ),
        };
        let metadata = json!({
            "type": record_type,
            "subtype": "parse_incomplete",
            "status": "TableWalkIncomplete",
            "table_name": table_name,
            "content_incomplete": true,
            "content_incomplete_reason": reason,
            "rows_skipped": status.rows_skipped,
            "rows_emitted": rows_emitted,
            "walk_unreadable": status.unreadable,
            // Columns this build expected and the table does not have, and the
            // number of cells published as 0 because they would not decode. A
            // zero that was never measured is not a measurement.
            "missing_columns": status.missing_columns,
            "values_defaulted": status.values_defaulted,
            // The key the UI renders from. `frontend/src/lib/incompleteness.ts`
            // reads `content_incomplete_detail` and knows nothing named
            // `detail`, so without this the examiner saw the reason and never
            // the skipped-row count, the missing columns or the defaulted cells.
            "content_incomplete_detail": detail.clone(),
            "detail": detail.clone(),
            "name": format!("SRUM {table_name}: incomplete - {detail}"),
        });
        Some(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(parent_id)
                .with_subtype("parse_incomplete"),
        )
    }

    /// Parse SRUM database and extract full records from all tables
    fn parse_srum_database(
        &self,
        db_path: &Path,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
    ) -> Result<Vec<Artifact>> {
        let mut artifacts = Vec::new();

        let db = libesedb::EseDb::open(db_path).context("Failed to open SRUM ESE database")?;

        info!("SRUM database opened successfully");

        // Which SRUM signature tables this database actually holds. The module
        // gates on the ESE magic alone, so every ESE database on the image
        // reaches here — WebCache, Windows Search, anything. Without this, a
        // foreign ESE file produced a "SRUDB detected" record and an examiner
        // read resource-usage evidence into a database that has none (B7-020).
        let mut srum_tables: Vec<&'static str> = Vec::new();

        // Step 1: Parse IdMapTable for ID resolution
        let (id_map, id_map_status) = if let Ok(table) = db.table_by_name("SruDbIdMapTable") {
            srum_tables.push("SruDbIdMapTable");
            let (map, status) = parse_id_map_table(&table);
            info!("SRUM IdMapTable: resolved {} ID mappings", map.len());
            (map, status)
        } else {
            debug!("SruDbIdMapTable not found, IDs will not be resolved");
            (HashMap::new(), WalkStatus::default())
        };
        // A partly-read ID map turns real application names into `Unknown(n)`
        // in every table below, so it is reported before any of them.
        if let Some(status) = Self::walk_status_artifact(
            case_id,
            parent_id,
            "SrumIdMapIncomplete",
            "SruDbIdMapTable",
            &id_map_status,
            id_map.len(),
        ) {
            artifacts.push(status);
        }

        // Step 2: Parse Application Resource Usage
        if let Ok(table) = db.table_by_name("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}") {
            srum_tables.push("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}");
            let (entries, walk) = parse_app_resource_table(&table);
            info!("SRUM Application Resource Usage: {} records", entries.len());

            if !entries.is_empty() {
                let records: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        json!({
                            "app": Self::resolve_id(&id_map, e.app_id),
                            "app_id": e.app_id,
                            "user": Self::resolve_id(&id_map, e.user_id),
                            "user_id": e.user_id,
                            "timestamp": e.timestamp.map(|t| t.to_rfc3339()),
                            "foreground_cycle_time": e.foreground_cycle_time,
                            "background_cycle_time": e.background_cycle_time,
                            "face_time": e.face_time,
                            "foreground_bytes_read": e.foreground_bytes_read,
                            "foreground_bytes_written": e.foreground_bytes_written,
                            "background_bytes_read": e.background_bytes_read,
                            "background_bytes_written": e.background_bytes_written,
                            "foreground_context_switches": e.foreground_context_switches,
                            "background_context_switches": e.background_context_switches,
                        })
                    })
                    .collect();

                let mut parsed = Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "SrumAppResourceUsage",
                        "table_name": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
                        "record_count": records.len(),
                        "records": records,
                    }),
                )
                .with_parent(parent_id);
                Self::stamp_walk(&mut parsed, &walk);

                // Create timeline events for records with timestamps
                let parsed_id = parsed.id;
                artifacts.push(parsed);

                for entry in &entries {
                    if let Some(ts) = entry.timestamp {
                        let app_name = Self::resolve_id(&id_map, entry.app_id);
                        let user_name = Self::resolve_id(&id_map, entry.user_id);
                        let total_io = entry.foreground_bytes_read
                            + entry.foreground_bytes_written
                            + entry.background_bytes_read
                            + entry.background_bytes_written;

                        let mut timeline = Artifact::new(
                            case_id,
                            ArtifactType::TimelineEvent,
                            None,
                            json!({
                                "timestamp": ts.to_rfc3339(),
                                "timestamp_desc": "SRUM App Resource Usage",
                                "source_module": "plugin.windows.srum_parser",
                                "short_desc": format!("App usage: {} (user: {})", app_name, user_name),
                                "full_details": json!({
                                    "app": app_name,
                                    "user": user_name,
                                    "face_time": entry.face_time,
                                    "total_io_bytes": total_io,
                                }).to_string(),
                            }),
                        )
                        .with_parent(parsed_id);
                        // The timeline is what an examiner reads as the
                        // machine's activity history. A walk that lost rows has
                        // to say so on the events too, or the markers sit on a
                        // sibling record nobody opens (B7-021).
                        Self::stamp_walk(&mut timeline, &walk);
                        artifacts.push(timeline);
                    }
                }
            }

            // Rows the ESE layer would not decode, or a walk that could not
            // start: either way the records above are a subset, and saying so
            // is the difference between "this never happened" and "we could not
            // read it" (B2-170).
            if let Some(status) = Self::walk_status_artifact(
                case_id,
                parent_id,
                "SrumAppResourceUsageIncomplete",
                "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
                &walk,
                entries.len(),
            ) {
                artifacts.push(status);
            }
        }

        // Step 3: Parse Network Data Usage
        if let Ok(table) = db.table_by_name("{973F5D5C-1D90-4944-BE8E-24B94231A174}") {
            srum_tables.push("{973F5D5C-1D90-4944-BE8E-24B94231A174}");
            let (entries, walk) = parse_network_data_table(&table);
            info!("SRUM Network Data Usage: {} records", entries.len());

            if !entries.is_empty() {
                let records: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        json!({
                            "app": Self::resolve_id(&id_map, e.app_id),
                            "app_id": e.app_id,
                            "user": Self::resolve_id(&id_map, e.user_id),
                            "user_id": e.user_id,
                            "timestamp": e.timestamp.map(|t| t.to_rfc3339()),
                            "interface_luid": e.interface_luid,
                            "l2_profile_id": e.l2_profile_id,
                            "l2_profile_flags": e.l2_profile_flags,
                            "bytes_sent": e.bytes_sent,
                            "bytes_recvd": e.bytes_recvd,
                        })
                    })
                    .collect();

                let mut parsed = Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "SrumNetworkDataUsage",
                        "table_name": "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
                        "record_count": records.len(),
                        "records": records,
                    }),
                )
                .with_parent(parent_id);
                Self::stamp_walk(&mut parsed, &walk);

                let parsed_id = parsed.id;
                artifacts.push(parsed);

                for entry in &entries {
                    if let Some(ts) = entry.timestamp {
                        let app_name = Self::resolve_id(&id_map, entry.app_id);
                        let mut timeline = Artifact::new(
                            case_id,
                            ArtifactType::TimelineEvent,
                            None,
                            json!({
                                "timestamp": ts.to_rfc3339(),
                                "timestamp_desc": "SRUM Network Data Usage",
                                "source_module": "plugin.windows.srum_parser",
                                "short_desc": format!("Network: {} sent={} recv={}", app_name, entry.bytes_sent, entry.bytes_recvd),
                                "full_details": json!({
                                    "app": app_name,
                                    "bytes_sent": entry.bytes_sent,
                                    "bytes_recvd": entry.bytes_recvd,
                                    "interface_luid": entry.interface_luid,
                                }).to_string(),
                            }),
                        )
                        .with_parent(parsed_id);
                        // The timeline is what an examiner reads as the
                        // machine's activity history. A walk that lost rows has
                        // to say so on the events too, or the markers sit on a
                        // sibling record nobody opens (B7-021).
                        Self::stamp_walk(&mut timeline, &walk);
                        artifacts.push(timeline);
                    }
                }
            }

            // Rows the ESE layer would not decode, or a walk that could not
            // start: either way the records above are a subset, and saying so
            // is the difference between "this never happened" and "we could not
            // read it" (B2-170).
            if let Some(status) = Self::walk_status_artifact(
                case_id,
                parent_id,
                "SrumNetworkDataUsageIncomplete",
                "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
                &walk,
                entries.len(),
            ) {
                artifacts.push(status);
            }
        }

        // Step 4: Parse Network Connectivity
        if let Ok(table) = db.table_by_name("{DD6636C4-8929-4683-974E-22C046A43763}") {
            srum_tables.push("{DD6636C4-8929-4683-974E-22C046A43763}");
            let (entries, walk) = parse_network_connectivity_table(&table);
            info!("SRUM Network Connectivity: {} records", entries.len());

            if !entries.is_empty() {
                let records: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        json!({
                            "app": Self::resolve_id(&id_map, e.app_id),
                            "app_id": e.app_id,
                            "user": Self::resolve_id(&id_map, e.user_id),
                            "user_id": e.user_id,
                            "timestamp": e.timestamp.map(|t| t.to_rfc3339()),
                            "interface_luid": e.interface_luid,
                            "l2_profile_id": e.l2_profile_id,
                            "connected_time": e.connected_time,
                            "connect_start_time": e.connect_start_time.map(|t| t.to_rfc3339()),
                        })
                    })
                    .collect();

                let mut parsed = Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "SrumNetworkConnectivity",
                        "table_name": "{DD6636C4-8929-4683-974E-22C046A43763}",
                        "record_count": records.len(),
                        "records": records,
                    }),
                )
                .with_parent(parent_id);
                Self::stamp_walk(&mut parsed, &walk);

                let parsed_id = parsed.id;
                artifacts.push(parsed);

                for entry in &entries {
                    if let Some(ts) = entry.connect_start_time {
                        let app_name = Self::resolve_id(&id_map, entry.app_id);
                        let mut timeline = Artifact::new(
                            case_id,
                            ArtifactType::TimelineEvent,
                            None,
                            json!({
                                "timestamp": ts.to_rfc3339(),
                                "timestamp_desc": "Network Connection Start",
                                "source_module": "plugin.windows.srum_parser",
                                "short_desc": format!("Connected: {} ({}s)", app_name, entry.connected_time),
                                "full_details": json!({
                                    "app": app_name,
                                    "connected_time_seconds": entry.connected_time,
                                    "interface_luid": entry.interface_luid,
                                }).to_string(),
                            }),
                        )
                        .with_parent(parsed_id);
                        // The timeline is what an examiner reads as the
                        // machine's activity history. A walk that lost rows has
                        // to say so on the events too, or the markers sit on a
                        // sibling record nobody opens (B7-021).
                        Self::stamp_walk(&mut timeline, &walk);
                        artifacts.push(timeline);
                    }
                }
            }

            // Rows the ESE layer would not decode, or a walk that could not
            // start: either way the records above are a subset, and saying so
            // is the difference between "this never happened" and "we could not
            // read it" (B2-170).
            if let Some(status) = Self::walk_status_artifact(
                case_id,
                parent_id,
                "SrumNetworkConnectivityIncomplete",
                "{DD6636C4-8929-4683-974E-22C046A43763}",
                &walk,
                entries.len(),
            ) {
                artifacts.push(status);
            }
        }

        // Step 5: Parse Energy Usage
        if let Ok(table) = db.table_by_name("{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}") {
            srum_tables.push("{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}");
            let (entries, walk) = parse_energy_table(&table);
            info!("SRUM Energy Usage: {} records", entries.len());

            if !entries.is_empty() {
                let records: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        json!({
                            "app": Self::resolve_id(&id_map, e.app_id),
                            "app_id": e.app_id,
                            "user": Self::resolve_id(&id_map, e.user_id),
                            "user_id": e.user_id,
                            "timestamp": e.timestamp.map(|t| t.to_rfc3339()),
                            "battery_level": e.battery_level,
                            "designed_capacity": e.designed_capacity,
                            "full_charged_capacity": e.full_charged_capacity,
                            "charge_level": e.charge_level,
                        })
                    })
                    .collect();

                let mut parsed = Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "SrumEnergyUsage",
                        "table_name": "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
                        "record_count": records.len(),
                        "records": records,
                    }),
                )
                .with_parent(parent_id);
                Self::stamp_walk(&mut parsed, &walk);

                artifacts.push(parsed);
            }

            // Rows the ESE layer would not decode, or a walk that could not
            // start: either way the records above are a subset, and saying so
            // is the difference between "this never happened" and "we could not
            // read it" (B2-170).
            if let Some(status) = Self::walk_status_artifact(
                case_id,
                parent_id,
                "SrumEnergyUsageIncomplete",
                "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
                &walk,
                entries.len(),
            ) {
                artifacts.push(status);
            }
        }

        if artifacts.is_empty() {
            if srum_tables.is_empty() {
                // An ESE database with none of SRUM's tables is not a SRUM
                // database. Claiming otherwise files a WebCache or Search index
                // in the case as resource-usage evidence.
                debug!(
                    "ESE database holds no SRUM tables; not a SRUDB (artifact {})",
                    parent_id
                );
                return Ok(Vec::new());
            }
            let metadata = json!({
                "type": "SrumDatabase",
                "status": "Detected",
                "source": "SrumParser",
                "srum_tables_present": srum_tables,
                "note": "SRUDB.dat detected: its standard tables are present but yielded no rows"
            });

            let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(parent_id);

            artifacts.push(artifact);
        }

        Ok(artifacts)
    }
}

impl ForensicsModule for SrumParser {
    fn id(&self) -> &str {
        "plugin.windows.srum_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
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

impl SrumParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()),
        };

        let detected_type = detect_file_type(data_source.as_ref());
        if detected_type != DetectedFileType::EseDatabase {
            return Ok(Vec::new());
        }

        info!(
            "Detected ESE database (likely SRUDB.dat) via content analysis (artifact ID: {})",
            artifact.id
        );

        // Extract database to temporary file (libesedb requires file path). The
        // guard removes the staged file on drop, including the panic path.
        let temp = self
            .extract_to_temp_file(data_source.as_ref())
            .map_err(|e| {
                ModuleError::ParsingError(format!("Failed to extract SRUM database: {}", e))
            })?;

        let artifacts = self
            .parse_srum_database(temp.path(), artifact.case_id, artifact.id)
            .map_err(|e| {
                ModuleError::ParsingError(format!("Failed to parse SRUM database: {}", e))
            })?;

        info!("SRUM parser produced {} artifacts", artifacts.len());

        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::FileDataSource;
    use seance_core::module::ForensicsModule;
    use seance_core::test_support::{DribbleSource, TruncatedSource};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn make_srum_artifact(path: &str) -> Option<Artifact> {
        let p = PathBuf::from(path);
        if !p.exists() {
            return None;
        }
        let ds = Arc::new(FileDataSource::new(p).unwrap());
        Some(Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "SRUDB.dat" }),
        ))
    }

    /// HUNT-277. A prior version of SRUDB.dat is parsed and stamped; one that
    /// is not a prior version is not read; a live copy is not stamped.
    ///
    /// The positive half needs a real SRUDB.dat (libesedb is read-only, so the
    /// ESE database cannot be synthesised), which is not committed; without it
    /// that half says so and returns. The refusal half is synthetic and
    /// always runs. No synthetic fixture grades a claim about real evidence.
    #[test]
    fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
        use seance_core::data_source::ByteSliceDataSource;

        assert!(SrumParser
            .subscribes_to()
            .contains(&ArtifactType::ParsedRecord));

        // Not a prior version: untouched, even though the bytes are ESE.
        let mut ese = vec![0u8; 8192];
        ese[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
        let plain = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(Arc::new(ByteSliceDataSource::new(ese))),
            json!({ "type": "SomethingElse", "name": "SRUDB.dat" }),
        );
        assert!(SrumParser.process(&plain).unwrap().is_empty());

        let Some(live) = make_srum_artifact("test_data/SRUDB.dat") else {
            eprintln!("Skipping the real-database half: test_data/SRUDB.dat not found");
            return;
        };
        let prior = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            live.data.clone(),
            json!({
                "type": "VssPriorVersion",
                "name": "SRUDB.dat [shadow copy 2015-03-23T00:00:00Z]",
                "file_name": "SRUDB.dat",
                "is_snapshot_version": true,
                "snapshot_label": "SHADOW COPY VERSION, not the live volume",
                "vss_snapshot_id": "snap-1",
                "vss_creation_time": "2015-03-23T00:00:00Z",
                "vss_stack_position": 1,
            }),
        );
        let out = SrumParser.process(&prior).unwrap();
        assert!(!out.is_empty(), "the prior version yields rows");
        assert!(out.iter().all(|a| {
            a.metadata["is_snapshot_version"] == true
                && a.metadata["vss_snapshot_id"] == "snap-1"
                && a.metadata
                    .get("shadow_copy_sidecars_not_searched")
                    .is_some()
        }));
        let live_out = SrumParser.process(&live).unwrap();
        assert!(live_out
            .iter()
            .all(|a| a.metadata.get("is_snapshot_version").is_none()));
    }

    /// B7-020: the module gates on the ESE magic alone, so every ESE database
    /// on the image reaches it. A WebCache database used to come back as a
    /// "SRUDB detected" record, putting resource-usage evidence in the case for
    /// a file that holds none.
    #[test]
    fn a_foreign_ese_database_is_not_reported_as_a_srum_database() {
        // Through the corpus gate, so `SEANCE_REQUIRE_CORPUS=1` can demand
        // this comparison actually ran: a bare `exists()` skip prints `ok` on
        // every machine where the fixture is absent, which is every machine in
        // the project — the file is not committed.
        let in_tree =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test_data/WebCacheV01.dat");
        let fixture = if in_tree.is_file() {
            in_tree
        } else {
            match seance_core::test_support::corpus::path("SEANCE_WEBCACHE") {
                Some(p) => p,
                None => return,
            }
        };
        let ds = Arc::new(FileDataSource::new(fixture).unwrap());
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "WebCacheV01.dat" }),
        );
        let out = SrumParser.process(&artifact).unwrap();
        assert!(
            out.is_empty(),
            "an ESE database with no SRUM tables must not be filed as SRUM evidence"
        );
    }

    /// A column the table does not carry is one fact about the table, not one
    /// fact about every row in it.
    ///
    /// The energy table on most Windows builds has no `BatteryLevel` column.
    /// Reading `EventTimestamp` in its place made every row report a value that
    /// would not decode, so `values_defaulted` grew to the row count and the
    /// rows where a cell really did fail were buried. The absence is now stated
    /// once, in `missing_columns`.
    #[test]
    fn a_missing_column_is_not_counted_once_per_row() {
        let artifact = match make_srum_artifact("test_data/SRUDB.dat") {
            Some(a) => a,
            None => {
                eprintln!("Skipping: test_data/SRUDB.dat not found");
                return;
            }
        };
        let out = SrumParser.process(&artifact).unwrap();
        let Some(status) = out
            .iter()
            .find(|a| a.metadata["type"] == "SrumEnergyUsageIncomplete")
        else {
            return;
        };
        let defaulted = status.metadata["values_defaulted"].as_u64().unwrap();
        let rows = status.metadata["rows_emitted"].as_u64().unwrap();
        assert!(
            defaulted < rows.max(1),
            "a missing column must not default one value per row \
             ({defaulted} defaulted across {rows} rows); missing_columns={}",
            status.metadata["missing_columns"]
        );
    }

    #[test]
    fn test_srum_database_parsing() {
        let artifact = match make_srum_artifact("test_data/SRUDB.dat") {
            Some(a) => a,
            None => {
                eprintln!("Skipping: test_data/SRUDB.dat not found");
                return;
            }
        };

        let parser = SrumParser;
        let results = parser.process(&artifact).unwrap();
        assert!(
            !results.is_empty(),
            "Should produce artifacts from SRUDB.dat"
        );

        // Check we have ParsedRecord artifacts
        let parsed_records: Vec<_> = results
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .collect();
        assert!(
            !parsed_records.is_empty(),
            "Should produce ParsedRecord artifacts"
        );

        // Check that at least one has actual records
        let has_records = parsed_records.iter().any(|a| {
            a.metadata
                .get("record_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0
        });

        if has_records {
            eprintln!(
                "SRUM parsed with full records: {} artifacts total",
                results.len()
            );

            // Check for timeline events
            let timeline_count = results
                .iter()
                .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
                .count();
            eprintln!("Timeline events generated: {}", timeline_count);

            // Print table summary
            for record in &parsed_records {
                if let Some(record_type) = record.metadata.get("type").and_then(|v| v.as_str()) {
                    let count = record
                        .metadata
                        .get("record_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    eprintln!("  {}: {} records", record_type, count);
                }
            }
        } else {
            eprintln!("SRUM database detected but tables may be empty");
        }
    }

    #[test]
    fn test_non_ese_skipped() {
        use seance_core::data_source::ByteSliceDataSource;

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 100]))),
            json!({ "name": "notadb.dat" }),
        );

        let parser = SrumParser;
        let results = parser.process(&artifact).unwrap();
        assert!(results.is_empty(), "Non-ESE file should be skipped");
    }

    #[test]
    fn test_truncated_database_is_not_staged() {
        // BUG-269: a short read used to be truncated and written anyway, so
        // libesedb opened a partial database and its subset of rows looked like
        // the whole of SRUDB.dat. The staging must fail instead.
        //
        // A source that claims more bytes than it can serve — a truncated image
        // or a sparse `SRUDB.dat` window.
        let src = TruncatedSource::new(vec![0xAAu8; 4096], 65536);
        let err = SrumParser
            .extract_to_temp_file(&src)
            .expect_err("a truncated SRUM database must not be staged");
        assert!(
            err.to_string().contains("SRUM database"),
            "error names what could not be read: {err}"
        );
    }

    #[test]
    fn test_complete_database_stages_every_byte() {
        // The same read path must still assemble a whole database from a source
        // that returns fewer bytes per call than requested. 512 bytes is below
        // the whole-database read this parser issues, so the loop is exercised.
        let bytes: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
        let src = DribbleSource::new(bytes.clone(), 512);
        let temp = SrumParser
            .extract_to_temp_file(&src)
            .expect("short reads must be looped, not treated as EOF");
        src.assert_dribbled();
        let staged = std::fs::read(temp.path()).unwrap();
        assert_eq!(staged, bytes);
        // The RAII guard removes the staged file when it drops.
    }
}

#[cfg(test)]
mod walk_status_tests {
    use super::*;
    use crate::tables::WalkStatus;

    /// A ParsedRecord shaped like the ones each SRUM table walk publishes.
    fn table_record(record_count: usize) -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "SrumAppResourceUsage",
                "table_name": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
                "record_count": record_count,
                "records": [],
            }),
        )
    }

    /// B2-170: rows the ESE layer refused were dropped with a bare `continue`,
    /// so a record saying `record_count: 4` from a 40,000-row table read as the
    /// machine's complete application-usage history.
    #[test]
    fn skipped_rows_are_stamped_on_the_record_they_are_missing_from() {
        let mut rec = table_record(4);
        SrumParser::stamp_walk(
            &mut rec,
            &WalkStatus {
                rows_skipped: 39_996,
                unreadable: None,
                missing_columns: Vec::new(),
                values_defaulted: 0,
            },
        );
        assert_eq!(rec.metadata["content_incomplete"], json!(true));
        assert_eq!(
            rec.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(rec.metadata["rows_skipped"], json!(39_996));
        // Still the table's own record: the stamp qualifies it, it does not
        // replace it.
        assert_eq!(rec.metadata["record_count"], json!(4));
    }

    #[test]
    fn a_complete_walk_leaves_the_record_untouched() {
        let mut rec = table_record(12);
        SrumParser::stamp_walk(&mut rec, &WalkStatus::default());
        assert!(rec.metadata.get("content_incomplete").is_none());
        assert!(rec.metadata.get("rows_skipped").is_none());
    }

    #[test]
    fn a_complete_walk_emits_no_marker() {
        assert!(SrumParser::walk_status_artifact(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "SrumAppResourceUsageIncomplete",
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
            &WalkStatus::default(),
            12,
        )
        .is_none());
    }

    #[test]
    fn a_marker_names_the_table_and_the_rows_lost() {
        let parent = uuid::Uuid::new_v4();
        let marker = SrumParser::walk_status_artifact(
            uuid::Uuid::new_v4(),
            parent,
            "SrumAppResourceUsageIncomplete",
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
            &WalkStatus {
                rows_skipped: 7,
                unreadable: None,
                missing_columns: Vec::new(),
                values_defaulted: 0,
            },
            12,
        )
        .expect("an incomplete walk must produce a marker");

        assert_eq!(marker.metadata["subtype"], json!("parse_incomplete"));
        assert_eq!(marker.metadata["status"], json!("TableWalkIncomplete"));
        assert_eq!(marker.metadata["rows_skipped"], json!(7));
        assert_eq!(marker.metadata["rows_emitted"], json!(12));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(marker.parent_id, Some(parent));
        // The marker must not carry the type the table's own records carry, or
        // grouping by `metadata.$.type` files it as a usage record.
        assert_ne!(marker.metadata["type"], json!("SrumAppResourceUsage"));
    }

    /// The case the marker exists for: the walk could not start, so the table
    /// published no ParsedRecord at all. Without this, an unopenable Network
    /// Data table looks exactly like a machine that never used the network.
    #[test]
    fn a_walk_that_could_not_start_is_reported_even_with_no_rows() {
        let marker = SrumParser::walk_status_artifact(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "SrumNetworkDataUsageIncomplete",
            "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
            &WalkStatus {
                rows_skipped: 0,
                unreadable: Some("records"),
                missing_columns: Vec::new(),
                values_defaulted: 0,
            },
            0,
        )
        .expect("a walk that never began must be reported, not returned empty");

        assert_eq!(marker.metadata["rows_emitted"], json!(0));
        assert_eq!(marker.metadata["walk_unreadable"], json!("records"));
        assert!(marker.metadata["detail"]
            .as_str()
            .unwrap()
            .contains("could not be walked"));
    }
}
