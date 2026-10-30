#![forbid(unsafe_code)]
//! User Access Logging (UAL) / Software Usage Metrics (SUM) parser.
//!
//! Windows Server records, in `C:\Windows\System32\LogFiles\SUM\`, which
//! account reached which server role, from which address, how many times, and
//! on which days — and keeps it for up to **three years**. That retention is
//! the point: by the time a server intrusion is investigated, the Security
//! event log has almost always rolled, and UAL is frequently the only surviving
//! record that an account authenticated at all.
//!
//! This is the Séance equivalent of Eric Zimmerman's `SumECmd`.
//!
//! # The files
//!
//! - `SystemIdentity.mdb` — `SYSTEM_IDENTITY` (the server's own name, domain,
//!   hardware and OS build), `ROLE_IDS` (GUID → role name), and
//!   `CHAINED_DATABASES` (the archives this one refers to).
//! - `Current.mdb` — the live year: the client-access table, plus `ROLE_ACCESS`,
//!   `DNS` and `VIRTUALMACHINES`. On the one real file checked (DFIR Madness
//!   Case 001's DC01, `VALIDATION.md` `UAL-1`) the client table is named
//!   `CLIENTS` and carries the role in its `RoleGuid` column; earlier text here
//!   said one table per role GUID, which that file does not have. Detection is
//!   by columns, so both shapes are read.
//! - `{GUID}.mdb` — a previous year, rolled over and archived, same shape.
//!
//! # Why detection is by schema and not by name
//!
//! Two things force it. The client tables are named after a role GUID, so there
//! is no name to match on; and the archived databases are themselves named
//! `{GUID}.mdb`, so the filename says nothing either. Every table is therefore
//! identified by the columns it carries.
//!
//! That also keeps this plugin from colliding with the SRUM parser. Both
//! subscribe to any file whose content is an ESE database — `SRUDB.dat`,
//! `SystemIdentity.mdb`, `Windows.edb` and `WebCacheV01.dat` are all ESE — so
//! "is this an ESE file" cannot be the whole test for either. A file carrying
//! none of the UAL tables produces nothing here.
//!
//! # Honesty
//!
//! Every walk returns a [`WalkStatus`](seance_ese_util::WalkStatus), and a walk
//! that fell short stamps `content_incomplete` onto the record it produced and
//! emits a standalone marker. The case that matters most is the table that
//! could not be opened at all: without a marker, an unreadable client table is
//! indistinguishable from a role nobody ever accessed, which in an intrusion
//! report is the difference between "no evidence of access" and "we could not
//! read the access log".

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
use seance_ese_util::WalkStatus;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use tables::{
    is_client_table, parse_chained_databases, parse_client_table, parse_dns, parse_role_access,
    parse_role_ids, parse_system_identity, parse_virtual_machines, role_name_map, UalClientAccess,
};
use tracing::{debug, info};
use uuid::Uuid;

/// Cap on the buffered database (2 GiB). A UAL database is normally single-digit
/// megabytes; the cap bounds a hostile or corrupt size rather than letting it
/// OOM the worker, which the orchestrator does not isolate.
const MAX_SUM_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub struct SumParser;

impl SumParser {
    pub fn new() -> Self {
        Self
    }

    /// Copy the database to a temporary file, which libesedb requires.
    ///
    /// A short read FAILS rather than writing the prefix: libesedb will happily
    /// open a truncated ESE database and hand back the rows it can still reach,
    /// which would publish a fraction of an access log as the whole of one.
    fn extract_to_temp_file(data_source: &dyn DataSource) -> Result<TempSpill> {
        let size = data_source.size();
        if size > MAX_SUM_BYTES {
            anyhow::bail!(
                "UAL database too large to buffer safely: {} bytes (cap {})",
                size,
                MAX_SUM_BYTES
            );
        }
        let mut buffer = vec![0u8; size as usize];
        read_exact_or_fail(data_source, 0, &mut buffer, "UAL database")
            .context("Failed to read UAL database")?;
        // RAII spill: removed on drop, so a libesedb panic cannot leak the file.
        TempSpill::write(&buffer, "sum", "mdb").context("Failed to write UAL temp file")
    }

    /// The database state field of an ESE file header (offset 0x34): 2 is
    /// "dirty shutdown", 3 is "clean shutdown". `None` when the header cannot
    /// be read, which is not the same as clean.
    fn db_state(db_path: &Path) -> Option<u32> {
        use std::io::Read;
        let mut header = [0u8; 0x38];
        std::fs::File::open(db_path)
            .ok()?
            .read_exact(&mut header)
            .ok()?;
        Some(u32::from_le_bytes([
            header[0x34],
            header[0x35],
            header[0x36],
            header[0x37],
        ]))
    }

    /// Say on a record that the database it came from was shut down dirty.
    ///
    /// A UAL database is written through an ESE transaction log (`Svc.log`).
    /// After a dirty shutdown the committed rows can sit in the log and not
    /// yet in the `.mdb`, and this reader does not replay logs, so a table
    /// that reads empty here may be full once recovered. DFIR Madness Case 001's
    /// DC01 is exactly that: `Current.mdb` reads 0 client rows while its
    /// `Svc.log` holds `c137\administrator` and `c137\citadel-dc01$`.
    const DIRTY_REASON: &'static str = "the database was not shut down cleanly (ESE state \
        'dirty shutdown'): committed rows may still be in the transaction log (Svc.log), \
        which this reader does not replay, so a count of 0 here does not show that no \
        client reached a role";

    fn stamp_dirty(artifact: &mut Artifact) {
        if let Some(map) = artifact.metadata.as_object_mut() {
            map.insert("database_state".into(), json!("dirty_shutdown"));
            map.entry("content_incomplete").or_insert(json!(true));
            map.entry("content_incomplete_reason")
                .or_insert(json!(Self::DIRTY_REASON));
            map.entry("content_incomplete_detail")
                .or_insert(json!(Self::DIRTY_REASON));
        }
    }

    /// Stamp a walk's incompleteness onto the record it produced.
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

    /// The standalone record saying a table walk did not read the whole table.
    ///
    /// `None` when the walk was complete, so an absent marker really does mean
    /// the rows published are everything the table held. Its `type` differs
    /// from the type the table's own rows carry, so downstream grouping by
    /// `metadata.$.type` cannot file this marker as an access record.
    fn walk_status_artifact(
        case_id: Uuid,
        parent_id: Uuid,
        table_name: &str,
        status: &WalkStatus,
        rows_emitted: usize,
    ) -> Option<Artifact> {
        let reason = status.reason()?;
        let detail = match status.unreadable {
            Some(what) => format!(
                "the UAL table {table_name} could not be walked: its {what} would not \
                 open, so the absence of access records here says nothing about who \
                 reached this role"
            ),
            None if !status.missing_columns.is_empty() => format!(
                "UAL table {table_name} does not carry the column(s) {}; {} further \
                 row(s) could not be decoded and {} value(s) were published as 0 \
                 because the cell would not decode",
                status.missing_columns.join(", "),
                status.rows_skipped,
                status.values_defaulted
            ),
            None => format!(
                "{} of the rows in UAL table {table_name} could not be decoded and are \
                 absent from the {rows_emitted} published here; {} value(s) were \
                 published as 0 because the cell would not decode",
                status.rows_skipped, status.values_defaulted
            ),
        };
        let metadata = json!({
            "type": "UalTableIncomplete",
            "subtype": "parse_incomplete",
            "status": "TableWalkIncomplete",
            "table_name": table_name,
            "content_incomplete": true,
            "content_incomplete_reason": reason,
            "rows_skipped": status.rows_skipped,
            "rows_emitted": rows_emitted,
            "walk_unreadable": status.unreadable,
            "missing_columns": status.missing_columns,
            "values_defaulted": status.values_defaulted,
            // The key the UI renders from; `frontend/src/lib/incompleteness.ts`
            // knows nothing named `detail`, so both are set.
            "content_incomplete_detail": detail.clone(),
            "detail": detail.clone(),
            "name": format!("UAL {table_name}: incomplete - {detail}"),
        });
        Some(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(parent_id)
                .with_subtype("parse_incomplete"),
        )
    }

    /// Turn one client-access row into a record.
    fn client_record(
        case_id: Uuid,
        parent_id: Uuid,
        row: &UalClientAccess,
        table_name: &str,
        roles: &HashMap<String, String>,
    ) -> Artifact {
        let role_name = row
            .role_guid
            .as_ref()
            .and_then(|g| roles.get(&g.to_lowercase()))
            .cloned();

        let mut metadata = json!({
            "type": "UalClientAccess",
            "source_table": table_name,
        });
        let map = metadata.as_object_mut().expect("just built as an object");

        // Every field is omitted when unknown rather than emitted as null or an
        // empty string: an account name that could not be read is not an
        // account with a blank name.
        if let Some(user) = &row.authenticated_user {
            map.insert("authenticated_user".into(), json!(user));
        }
        if let Some(address) = &row.client_address {
            map.insert("client_address".into(), json!(address));
        }
        if let Some(guid) = &row.role_guid {
            map.insert("role_guid".into(), json!(guid));
        }
        if let Some(name) = &role_name {
            map.insert("role_name".into(), json!(name));
        } else if row.role_guid.is_some() {
            // The GUID is known and the name is not. Said explicitly, because a
            // record showing only a GUID otherwise reads as a parser that could
            // not decode the role rather than one that never saw the mapping —
            // which lives in a *different file*, `SystemIdentity.mdb`.
            map.insert("role_name_unresolved".into(), json!(true));
            map.insert(
                "role_name_unresolved_reason".into(),
                json!(
                    "the ROLE_IDS mapping lives in SystemIdentity.mdb, which was not \
                       part of this artifact"
                ),
            );
        }
        if let Some(tenant) = &row.tenant_id {
            map.insert("tenant_id".into(), json!(tenant));
        }
        if let Some(total) = row.total_accesses {
            map.insert("total_accesses".into(), json!(total));
        }
        if let Some(insert) = row.insert_date {
            map.insert("insert_date".into(), json!(insert.to_rfc3339()));
            map.insert("timestamp".into(), json!(insert.timestamp()));
        }
        if let Some(last) = row.last_access {
            map.insert("last_access".into(), json!(last.to_rfc3339()));
        }
        if !row.active_days.is_empty() {
            map.insert("active_day_count".into(), json!(row.active_days.len()));
            map.insert("active_days".into(), json!(row.active_days));
        }

        let who = row.authenticated_user.as_deref().unwrap_or("unknown user");
        let from = row
            .client_address
            .as_deref()
            .map(|a| format!(" from {a}"))
            .unwrap_or_default();
        let what = role_name
            .clone()
            .or_else(|| row.role_guid.clone())
            .unwrap_or_else(|| "an unnamed role".to_string());
        map.insert("name".into(), json!(format!("{who}{from} accessed {what}")));

        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(parent_id)
            .with_subtype("ual_client_access")
    }

    /// Walk every table in the database and emit what UAL holds.
    fn parse_database(db_path: &Path, case_id: Uuid, parent_id: Uuid) -> Result<Vec<Artifact>> {
        let db = libesedb::EseDb::open(db_path).context("Failed to open UAL ESE database")?;
        let mut artifacts = Vec::new();
        let mut tables_seen: Vec<String> = Vec::new();
        let mut client_rows = 0usize;
        let dirty = Self::db_state(db_path) == Some(2);

        // ROLE_IDS first, so client rows in the same database resolve to role
        // names rather than bare GUIDs.
        let mut roles: HashMap<String, String> = HashMap::new();
        if let Ok(table) = db.table_by_name("ROLE_IDS") {
            let (parsed, status) = parse_role_ids(&table);
            roles = role_name_map(&parsed);
            tables_seen.push("ROLE_IDS".into());
            for role in &parsed {
                let mut metadata = json!({ "type": "UalRoleId" });
                let map = metadata.as_object_mut().expect("object");
                if let Some(g) = &role.role_guid {
                    map.insert("role_guid".into(), json!(g));
                }
                if let Some(n) = &role.role_name {
                    map.insert("role_name".into(), json!(n));
                }
                if let Some(p) = &role.product_name {
                    map.insert("product_name".into(), json!(p));
                }
                map.insert(
                    "name".into(),
                    json!(format!(
                        "UAL role {}",
                        role.role_name
                            .clone()
                            .or_else(|| role.role_guid.clone())
                            .unwrap_or_else(|| "(unnamed)".into())
                    )),
                );
                let mut artifact =
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(parent_id)
                        .with_subtype("ual_role_id");
                Self::stamp_walk(&mut artifact, &status);
                artifacts.push(artifact);
            }
            if let Some(marker) =
                Self::walk_status_artifact(case_id, parent_id, "ROLE_IDS", &status, parsed.len())
            {
                artifacts.push(marker);
            }
        }

        // SYSTEM_IDENTITY: what machine this database came from.
        if let Ok(table) = db.table_by_name("SYSTEM_IDENTITY") {
            let (parsed, status) = parse_system_identity(&table);
            tables_seen.push("SYSTEM_IDENTITY".into());
            for identity in &parsed {
                let mut metadata = json!({ "type": "UalSystemIdentity" });
                let map = metadata.as_object_mut().expect("object");
                if let Some(v) = &identity.dns_host_name {
                    map.insert("dns_host_name".into(), json!(v));
                }
                if let Some(v) = &identity.domain_name {
                    map.insert("domain_name".into(), json!(v));
                }
                if let Some(v) = &identity.manufacturer {
                    map.insert("system_manufacturer".into(), json!(v));
                }
                if let Some(v) = &identity.product_name {
                    map.insert("system_product_name".into(), json!(v));
                }
                if let Some(v) = &identity.serial_number {
                    map.insert("system_serial_number".into(), json!(v));
                }
                if let Some(v) = &identity.timezone {
                    map.insert("system_timezone".into(), json!(v));
                }
                if let Some(v) = identity.os_build {
                    map.insert("os_build_number".into(), json!(v));
                }
                if let (Some(major), Some(minor)) = (identity.os_major, identity.os_minor) {
                    map.insert("os_version".into(), json!(format!("{major}.{minor}")));
                }
                if let Some(v) = identity.creation_time {
                    map.insert("creation_time".into(), json!(v.to_rfc3339()));
                    map.insert("timestamp".into(), json!(v.timestamp()));
                }
                map.insert(
                    "name".into(),
                    json!(format!(
                        "UAL system identity: {}",
                        identity
                            .dns_host_name
                            .clone()
                            .unwrap_or_else(|| "(host unknown)".into())
                    )),
                );
                let mut artifact =
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(parent_id)
                        .with_subtype("ual_system_identity");
                Self::stamp_walk(&mut artifact, &status);
                artifacts.push(artifact);
            }
            if let Some(marker) = Self::walk_status_artifact(
                case_id,
                parent_id,
                "SYSTEM_IDENTITY",
                &status,
                parsed.len(),
            ) {
                artifacts.push(marker);
            }
        }

        // CHAINED_DATABASES: the archives this database refers to. An examiner
        // holding one year needs to know the others exist.
        if let Ok(table) = db.table_by_name("CHAINED_DATABASES") {
            let (parsed, status) = parse_chained_databases(&table);
            tables_seen.push("CHAINED_DATABASES".into());
            for chained in &parsed {
                let mut metadata = json!({ "type": "UalChainedDatabase" });
                let map = metadata.as_object_mut().expect("object");
                if let Some(y) = chained.year {
                    map.insert("year".into(), json!(y));
                }
                if let Some(f) = &chained.file_name {
                    map.insert("file_name".into(), json!(f));
                }
                map.insert(
                    "name".into(),
                    json!(format!(
                        "UAL archive for {}: {}",
                        chained
                            .year
                            .map(|y| y.to_string())
                            .unwrap_or_else(|| "an unrecorded year".into()),
                        chained
                            .file_name
                            .clone()
                            .unwrap_or_else(|| "(unnamed)".into())
                    )),
                );
                let mut artifact =
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(parent_id)
                        .with_subtype("ual_chained_database");
                Self::stamp_walk(&mut artifact, &status);
                artifacts.push(artifact);
            }
            if let Some(marker) = Self::walk_status_artifact(
                case_id,
                parent_id,
                "CHAINED_DATABASES",
                &status,
                parsed.len(),
            ) {
                artifacts.push(marker);
            }
        }

        // ROLE_ACCESS: when each role was first and last used.
        if let Ok(table) = db.table_by_name("ROLE_ACCESS") {
            let (parsed, status) = parse_role_access(&table);
            tables_seen.push("ROLE_ACCESS".into());
            for access in &parsed {
                let role_name = access
                    .role_guid
                    .as_ref()
                    .and_then(|g| roles.get(&g.to_lowercase()))
                    .cloned();
                let mut metadata = json!({ "type": "UalRoleAccess" });
                let map = metadata.as_object_mut().expect("object");
                if let Some(g) = &access.role_guid {
                    map.insert("role_guid".into(), json!(g));
                }
                if let Some(n) = &role_name {
                    map.insert("role_name".into(), json!(n));
                }
                if let Some(t) = access.first_seen {
                    map.insert("first_seen".into(), json!(t.to_rfc3339()));
                    map.insert("timestamp".into(), json!(t.timestamp()));
                }
                if let Some(t) = access.last_seen {
                    map.insert("last_seen".into(), json!(t.to_rfc3339()));
                }
                map.insert(
                    "name".into(),
                    json!(format!(
                        "UAL role access: {}",
                        role_name
                            .or_else(|| access.role_guid.clone())
                            .unwrap_or_else(|| "(unnamed role)".into())
                    )),
                );
                let mut artifact =
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(parent_id)
                        .with_subtype("ual_role_access");
                Self::stamp_walk(&mut artifact, &status);
                artifacts.push(artifact);
            }
            if let Some(marker) =
                Self::walk_status_artifact(case_id, parent_id, "ROLE_ACCESS", &status, parsed.len())
            {
                artifacts.push(marker);
            }
        }

        // DNS observations.
        if let Ok(table) = db.table_by_name("DNS") {
            let (parsed, status) = parse_dns(&table);
            tables_seen.push("DNS".into());
            for entry in &parsed {
                let mut metadata = json!({ "type": "UalDnsRecord" });
                let map = metadata.as_object_mut().expect("object");
                if let Some(h) = &entry.host_name {
                    map.insert("host_name".into(), json!(h));
                }
                if let Some(a) = &entry.address {
                    map.insert("address".into(), json!(a));
                }
                if let Some(t) = entry.last_seen {
                    map.insert("last_seen".into(), json!(t.to_rfc3339()));
                    map.insert("timestamp".into(), json!(t.timestamp()));
                }
                map.insert(
                    "name".into(),
                    json!(format!(
                        "UAL DNS: {}",
                        entry
                            .host_name
                            .clone()
                            .unwrap_or_else(|| "(unnamed host)".into())
                    )),
                );
                let mut artifact =
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(parent_id)
                        .with_subtype("ual_dns");
                Self::stamp_walk(&mut artifact, &status);
                artifacts.push(artifact);
            }
            if let Some(marker) =
                Self::walk_status_artifact(case_id, parent_id, "DNS", &status, parsed.len())
            {
                artifacts.push(marker);
            }
        }

        // Virtual machines seen by this host.
        if let Ok(table) = db.table_by_name("VIRTUALMACHINES") {
            let (parsed, status) = parse_virtual_machines(&table);
            tables_seen.push("VIRTUALMACHINES".into());
            for vm in &parsed {
                let mut metadata = json!({ "type": "UalVirtualMachine" });
                let map = metadata.as_object_mut().expect("object");
                if let Some(g) = &vm.vm_guid {
                    map.insert("vm_guid".into(), json!(g));
                }
                if let Some(g) = &vm.bios_guid {
                    map.insert("bios_guid".into(), json!(g));
                }
                if let Some(s) = &vm.serial_number {
                    map.insert("serial_number".into(), json!(s));
                }
                if let Some(t) = vm.creation_time {
                    map.insert("creation_time".into(), json!(t.to_rfc3339()));
                    map.insert("timestamp".into(), json!(t.timestamp()));
                }
                if let Some(t) = vm.last_seen_active {
                    map.insert("last_seen_active".into(), json!(t.to_rfc3339()));
                }
                map.insert(
                    "name".into(),
                    json!(format!(
                        "UAL virtual machine {}",
                        vm.vm_guid.clone().unwrap_or_else(|| "(unnamed)".into())
                    )),
                );
                let mut artifact =
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(parent_id)
                        .with_subtype("ual_virtual_machine");
                Self::stamp_walk(&mut artifact, &status);
                artifacts.push(artifact);
            }
            if let Some(marker) = Self::walk_status_artifact(
                case_id,
                parent_id,
                "VIRTUALMACHINES",
                &status,
                parsed.len(),
            ) {
                artifacts.push(marker);
            }
        }

        // The client-access tables, which have no fixed names: every table is
        // examined and those carrying the client schema are read.
        let known: &[&str] = &[
            "ROLE_IDS",
            "SYSTEM_IDENTITY",
            "CHAINED_DATABASES",
            "ROLE_ACCESS",
            "DNS",
            "VIRTUALMACHINES",
        ];
        if let Ok(all_tables) = db.iter_tables() {
            for table_result in all_tables {
                let Ok(table) = table_result else { continue };
                let Ok(name) = table.name() else { continue };
                if known.iter().any(|k| k.eq_ignore_ascii_case(&name)) {
                    continue;
                }
                let Ok(columns) = seance_ese_util::get_column_names(&table) else {
                    continue;
                };
                if !is_client_table(&columns) {
                    continue;
                }
                tables_seen.push(name.clone());
                let (parsed, status) = parse_client_table(&table);
                client_rows += parsed.len();
                for row in &parsed {
                    let mut artifact = Self::client_record(case_id, parent_id, row, &name, &roles);
                    Self::stamp_walk(&mut artifact, &status);
                    if dirty {
                        Self::stamp_dirty(&mut artifact);
                    }
                    artifacts.push(artifact);
                }
                if let Some(marker) =
                    Self::walk_status_artifact(case_id, parent_id, &name, &status, parsed.len())
                {
                    artifacts.push(marker);
                }
            }
        }

        // Nothing UAL-shaped here. Emit nothing at all rather than a summary
        // claiming a UAL database with no records — this plugin sees every ESE
        // file in the case, most of which are not UAL.
        if tables_seen.is_empty() {
            debug!("No UAL tables in {}", db_path.display());
            return Ok(Vec::new());
        }

        let mut summary = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "UalSummary",
                "tables_parsed": tables_seen,
                "client_access_records": client_rows,
                "name": format!(
                    "User Access Logging: {} client access record(s) across {} table(s){}",
                    client_rows,
                    tables_seen.len(),
                    if dirty { " (database shut down dirty; transaction log not replayed)" } else { "" }
                ),
            }),
        )
        .with_parent(parent_id)
        .with_subtype("ual_summary");
        if dirty {
            Self::stamp_dirty(&mut summary);
        }
        artifacts.push(summary);

        Ok(artifacts)
    }
}

impl Default for SumParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for SumParser {
    fn id(&self) -> &str {
        "plugin.windows.sum"
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

impl SumParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(data_source) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }

        if detect_file_type(data_source.as_ref()) != DetectedFileType::EseDatabase {
            return Ok(Vec::new());
        }

        let temp = Self::extract_to_temp_file(data_source.as_ref()).map_err(|e| {
            ModuleError::ParsingError(format!("Failed to extract UAL database: {e}"))
        })?;

        // `temp` removes the staged file on drop at end of scope, panic included.
        let parsed = Self::parse_database(temp.path(), artifact.case_id, artifact.id);

        let artifacts = parsed
            .map_err(|e| ModuleError::ParsingError(format!("Failed to parse UAL database: {e}")))?;

        if !artifacts.is_empty() {
            info!("UAL parser produced {} artifacts", artifacts.len());
        }
        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests;
