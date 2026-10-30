//! The accounts on the phone: whose device this is.
//!
//! `accounts_de.db` (device-encrypted) and `accounts_ce.db` (credential-
//! encrypted) are the AccountManager stores. Their `accounts` table is one row
//! per signed-in account — `name` is usually the address the account is known
//! by and `type` the authenticator that owns it (`com.google`,
//! `com.whatsapp`, …).
//!
//! This is the half of "whose phone is this?" the property files cannot answer.
//! A device's model and serial identify the handset; the Google account on it is
//! the person.
//!
//! Several accounts is the ordinary case, not a contradiction: a phone can hold
//! two Google accounts and a dozen app ones. They are emitted as several
//! readings of a multi-valued fact, which the device-facts compiler knows not to
//! report as sources disagreeing.

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

/// Ceiling on the staged database.
const MAX_DB_BYTES: u64 = 64 * 1024 * 1024;
/// Ceiling on accounts carried into one record.
const MAX_ACCOUNTS: usize = 500;

/// The first bytes of every SQLite database file.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Is this one of the AccountManager stores?
pub fn is_accounts_db(name: &str) -> bool {
    schema_support_for(name).is_some()
}

/// The schema version each store was validated against, read out of the
/// android2022 (Pixel, Android 12) full-file-system tar — one real device, so
/// each range is the single version that device carried. The two stores are
/// versioned independently by the framework (`AccountsDb`), hence one range
/// per file.
fn schema_support_for(name: &str) -> Option<SchemaSupport> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "accounts_de.db" => Some(SchemaSupport {
            app: "android-accounts",
            store: "accounts_de.db",
            record_type: "MobileDeviceInfo",
            range: SupportedRange::new(3, Some(3)),
            evidence: "android2022 data/system_de/0/accounts_de.db (PRAGMA user_version 3)",
        }),
        "accounts_ce.db" => Some(SchemaSupport {
            app: "android-accounts",
            store: "accounts_ce.db",
            record_type: "MobileDeviceInfo",
            range: SupportedRange::new(10, Some(10)),
            evidence: "android2022 data/system_ce/0/accounts_ce.db (PRAGMA user_version 10)",
        }),
        _ => None,
    }
}

/// The `accounts` columns this build reads. Both real stores carry exactly
/// these names; a candidate list absorbs a rename without a code change.
const REQUIRED: &[(&str, &[&str])] = &[("name", &["name"]), ("type", &["type"])];

/// Reads the AccountManager stores into device facts.
#[derive(Debug, Default)]
pub struct AndroidAccountsParser;

impl AndroidAccountsParser {
    pub fn new() -> Self {
        Self
    }
}

/// The record for a store that is named like an accounts database and could not
/// be read.
///
/// A phone whose account list would not open must not render as a phone with no
/// accounts on it: "nobody was signed in" and "we could not read who was" are
/// different answers to the only question this file exists to answer.
fn unreadable(artifact: &Artifact, path: &str, detail: String) -> Artifact {
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "MobileDeviceInfo",
            "platform": "android",
            "subtype": "accounts_unreadable",
            "name": "Android accounts store, not read",
            "source_file": path,
            "source_kind": "android_accounts",
            "facts": {},
            "fact_sources": {},
            CONTENT_INCOMPLETE: true,
            CONTENT_INCOMPLETE_REASON: IncompleteReason::UnresolvedStructure.as_str(),
            "content_incomplete_detail": detail,
        }),
    )
    .with_parent(artifact.id)
}

impl ForensicsModule for AndroidAccountsParser {
    fn id(&self) -> &str {
        "plugin.mobile.android_accounts"
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
        let Some(support) = schema_support_for(name) else {
            return Ok(Vec::new());
        };
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(name);

        // Is it a SQLite database at all? The two answers below are different
        // statements and must not collapse into one: a file that IS this store
        // and will not open has to be reported, while a file merely NAMED like
        // it and holding something else is not this parser's to claim
        // (the HUNT-071 shape).
        //
        // The probe loops over short reads (a windowed source may answer a few
        // bytes at a time), and a probe that still came back short has shown
        // nothing about the file: it is a short read, never "does not begin
        // with the SQLite header" (HUNT-188).
        let mut header = [0u8; SQLITE_MAGIC.len()];
        let read = seance_core::io::read_full(data.as_ref(), 0, &mut header);
        if read < SQLITE_MAGIC.len() {
            let mut record = unreadable(
                artifact,
                path,
                format!(
                    "only {read} of the first {} byte(s) of this AccountManager store could be \
                     read, so whether it is a SQLite database — and which accounts were signed \
                     in to this device — could not be established",
                    SQLITE_MAGIC.len()
                ),
            );
            record.metadata[CONTENT_INCOMPLETE_REASON] =
                json!(IncompleteReason::ShortRead.as_str());
            return Ok(vec![record]);
        }
        if header != *SQLITE_MAGIC {
            return Ok(vec![unreadable(
                artifact,
                path,
                "this file is named as an AccountManager store and does not begin with the \
                 SQLite header, so the accounts signed in to this device could not be read \
                 from it"
                    .to_string(),
            )]);
        }

        let temp = match TempDb::spill(data.as_ref(), "android_accounts", MAX_DB_BYTES) {
            Ok(t) => t,
            Err(e) => {
                debug!("accounts store {name} could not be staged: {e}");
                return Ok(vec![unreadable(
                    artifact,
                    path,
                    format!("the accounts database could not be staged for reading: {e}"),
                )]);
            }
        };
        let conn = match temp.open() {
            Ok(c) => c,
            Err(e) => {
                return Ok(vec![unreadable(
                    artifact,
                    path,
                    format!("the accounts database could not be opened: {e}"),
                )])
            }
        };

        // The column set is read before the query is written: a `SELECT`
        // naming a column this store renamed fails whole, and the accounts
        // would then read as unreadable when only their column moved.
        let plan = match plan_columns(&conn, "accounts", REQUIRED, &[]) {
            Ok(plan) if plan.present.is_empty() => {
                // No `accounts` table: named like the store and shaped like
                // something else.
                debug!("{name} has no accounts table");
                return Ok(Vec::new());
            }
            Ok(plan) => plan,
            Err(why) => {
                return Ok(vec![unreadable(
                    artifact,
                    path,
                    format!("the accounts table's columns could not be read: {why}"),
                )])
            }
        };
        let version = user_version(&conn);
        let mut out = Vec::new();
        if !plan.missing_required().is_empty() {
            out.push(unresolved_fields_marker(
                &support,
                "accounts",
                &plan,
                0,
                artifact.case_id,
                artifact.id,
            ));
        }
        out.extend(assess_version(
            &support,
            &version,
            artifact.case_id,
            artifact.id,
        ));
        let sql = format!(
            "SELECT {}, {} FROM accounts ORDER BY _id LIMIT ?1",
            plan.column("name").unwrap_or("NULL"),
            plan.column("type").unwrap_or("NULL"),
        );
        let mut statement = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                out.push(unreadable(
                    artifact,
                    path,
                    format!("the accounts table could not be queried: {e}"),
                ));
                return Ok(out);
            }
        };
        let rows = statement.query_map([MAX_ACCOUNTS as i64 + 1], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        });
        let Ok(rows) = rows else {
            out.push(unreadable(
                artifact,
                path,
                "the accounts table could not be read".to_string(),
            ));
            return Ok(out);
        };

        // A row that arrives with a NULL where a required column did not
        // resolve was read intact; the column is what is missing. Those rows
        // are counted apart from rows the store itself could not yield, so the
        // record does not send an examiner looking for damage in a table whose
        // schema simply moved.
        let unresolved_required = plan.missing_required();
        let mut accounts: Vec<(String, String)> = Vec::new();
        let mut undecodable = 0usize;
        let mut field_unresolved = 0usize;
        for row in rows {
            match row {
                Ok((Some(account), Some(kind))) if !account.is_empty() => {
                    accounts.push((account, kind))
                }
                Ok(_) if !unresolved_required.is_empty() => field_unresolved += 1,
                Ok(_) => undecodable += 1,
                Err(_) => undecodable += 1,
            }
        }
        let capped = accounts.len() > MAX_ACCOUNTS;
        accounts.truncate(MAX_ACCOUNTS);

        let mut facts = serde_json::Map::new();
        let mut sources = serde_json::Map::new();
        // The Google accounts are the device's owner in all but name, so they
        // are lifted out; every other account is still listed, because an app
        // account can be the identity a case turns on.
        let google: Vec<&(String, String)> = accounts
            .iter()
            .filter(|(_, kind)| kind.eq_ignore_ascii_case("com.google"))
            .collect();
        if !google.is_empty() {
            facts.insert(
                "google_account".to_string(),
                json!(google
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect::<Vec<_>>()),
            );
            sources.insert("google_account".to_string(), json!("accounts.name"));
        }
        if !accounts.is_empty() {
            facts.insert(
                "account".to_string(),
                json!(accounts
                    .iter()
                    .map(|(name, kind)| format!("{name} ({kind})"))
                    .collect::<Vec<_>>()),
            );
            sources.insert(
                "account".to_string(),
                json!("accounts.name + accounts.type"),
            );
        }

        let mut metadata = json!({
            "type": "MobileDeviceInfo",
            "platform": "android",
            "name": format!("Android accounts from {name}"),
            "source_file": path,
            "source_kind": "android_accounts",
            "accounts_read": accounts.len(),
            "rows_undecodable": undecodable,
            "rows_field_unresolved": field_unresolved,
            "facts": facts,
            "fact_sources": sources,
        });

        // Every way the list can be short of what the device held.
        let shortfall = if capped {
            Some((
                IncompleteReason::CapReached.as_str(),
                format!(
                    "more than {MAX_ACCOUNTS} accounts are in this store; the list stops there"
                ),
            ))
        } else if field_unresolved > 0 {
            Some((
                IncompleteReason::Unvalidated.as_str(),
                format!(
                    "{field_unresolved} row(s) were read from the accounts table, but it has \
                     no column this parser recognises for {}, so no account could be listed \
                     from them; the schema has moved beyond what this parser was written to",
                    unresolved_required.join(", ")
                ),
            ))
        } else if undecodable > 0 {
            Some((
                IncompleteReason::UnresolvedStructure.as_str(),
                format!("{undecodable} row(s) in the accounts table could not be decoded"),
            ))
        } else {
            // The spill's own reason: a file over the staging ceiling is
            // `cap_reached`, a source that stopped early `short_read`.
            temp.content_incomplete_reason().map(|reason| {
                (
                    reason,
                    "the accounts database was not staged in full, so accounts it holds may \
                     be missing from this list"
                        .to_string(),
                )
            })
        };
        let object = metadata.as_object_mut().expect("object literal");
        if let Some((reason, detail)) = shortfall {
            object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
            object.insert(CONTENT_INCOMPLETE_REASON.to_string(), json!(reason));
            object.insert("content_incomplete_detail".to_string(), json!(detail));
        }
        // A refused write-ahead log is its own shortfall, carried beside
        // whichever one above won: the newest sign-ins live there.
        if let Some(wal) = temp.wal_incomplete_reason() {
            object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
            object.insert("wal_incomplete_reason".to_string(), json!(wal));
        }

        out.push(
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(artifact.id),
        );
        Ok(out)
    }
}
