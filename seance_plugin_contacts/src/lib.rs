#![forbid(unsafe_code)]
//! Contacts / Address Book Parser Module
//!
//! Parses mobile address-book databases (iOS `AddressBook.sqlitedb` and Android
//! `contacts2.db`) extracting one record per contact as forensic artifacts.
//!
//! ## Supported Databases
//!
//! - iOS `AddressBook.sqlitedb` — `ABPerson` joined to `ABMultiValue`.
//! - Android `contacts2.db` — `raw_contacts` joined to `data` / `mimetypes`.
//!
//! ## Schema
//!
//! - iOS: `ABPerson` (`First`, `Last`, `Organization`), `ABMultiValue`
//!   (`record_id`, `property`, `value`); property 3 = phone, 4 = email.
//! - Android: `raw_contacts` (`display_name`), `data` (`data1` value keyed by
//!   `mimetype_id`), `mimetypes` (mimetype string: `.../phone_v2`,
//!   `.../email_v2`, `.../organization`).
//!
//! ## Schema-drift defence
//!
//! Each store's schema version is compared against the range this parser was
//! validated against on a real database: iOS `_SqliteDatabaseProperties.
//! _ClientVersion` 83 (ios2022ffs, iPhone 8; its `PRAGMA user_version` is 0 and
//! is not consulted) and Android `PRAGMA user_version` 1300 (android2022, Pixel,
//! Android 12). One real store each, so each range is a single version. Every
//! column read is resolved through a candidate list before a query is written.
//! A store outside its range, one whose version is not recorded, or one whose
//! required column no candidate matched is still parsed as far as it can be,
//! and a `ParserStaleWarning` record is appended naming the version seen or the
//! fields unresolved. See [`schema_support`].

mod schema_support;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use rusqlite::Connection;
use schema_support::{
    assess_version, keyed_version, plan_columns, unresolved_fields_marker, user_version,
    ColumnPlan, SchemaSupport, SchemaVersion,
};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::spilled::table_exists;
use seance_sqlite_util::SupportedRange;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::debug;
use uuid::Uuid;

/// The schema this parser was validated against for iOS: the one real
/// `AddressBook.sqlitedb` this project holds (ios2022ffs, iPhone 8, iOS 15),
/// whose version lives in `_SqliteDatabaseProperties._ClientVersion` — its
/// `PRAGMA user_version` is 0, SQLite's unset default, and is not consulted.
const IOS_SUPPORT: SchemaSupport = SchemaSupport {
    app: "ios-addressbook",
    store: "AddressBook.sqlitedb",
    record_type: "Contact",
    range: SupportedRange {
        min: 83,
        max: Some(83),
    },
    evidence: "ios2022ffs /private/var/mobile/Library/AddressBook/AddressBook.sqlitedb \
               (_SqliteDatabaseProperties._ClientVersion 83)",
};

/// The schema this parser was validated against for Android: the one real
/// `contacts2.db` with a contacts schema this project holds (android2022, Pixel,
/// Android 12; the ContactsProvider stamps `PRAGMA user_version`). The two
/// other `contacts2.db` samples on this machine validate nothing here, for
/// different reasons: `reference/plaso/test_data/contacts2.db` carries the
/// ContactsProvider table set (`contacts`, `data`, `mimetypes`, `groups`,
/// `calls`, ... — 20 tables plus `sqlite_sequence`) but no `raw_contacts`, the
/// table this parser selects on, and every table is empty except 3 `calls`
/// rows, at `PRAGMA user_version` 0; the Magnet-Agent copy
/// (`~/ctf-evidence/magnet2019android`) carries only `android_metadata` and
/// `calls` at `PRAGMA user_version` 1, a copy artefact rather than a
/// ContactsProvider version.
const ANDROID_SUPPORT: SchemaSupport = SchemaSupport {
    app: "android-contacts",
    store: "contacts2.db",
    record_type: "Contact",
    range: SupportedRange {
        min: 1300,
        max: Some(1300),
    },
    evidence: "android2022 data/data/com.android.providers.contacts/databases/contacts2.db \
               (PRAGMA user_version 1300)",
};

/// `ABPerson` columns a contact is meaningless without. `ROWID` is not planned:
/// SQLite provides it for every ordinary table whether or not it is declared.
const IOS_PERSON_FIELDS: &[(&str, &[&str])] = &[
    ("First", &["First"]),
    ("Last", &["Last"]),
    ("Organization", &["Organization"]),
];

/// `ABMultiValue` columns the join is meaningless without.
const IOS_MULTIVALUE_FIELDS: &[(&str, &[&str])] = &[
    ("record_id", &["record_id"]),
    ("property", &["property"]),
    ("value", &["value"]),
];

const ANDROID_RAW_CONTACT_FIELDS: &[(&str, &[&str])] =
    &[("_id", &["_id"]), ("display_name", &["display_name"])];

/// Optional: `deleted` is absent from older provider schemas.
const ANDROID_RAW_CONTACT_OPTIONAL: &[(&str, &[&str])] = &[("deleted", &["deleted"])];

const ANDROID_DATA_FIELDS: &[(&str, &[&str])] = &[
    ("raw_contact_id", &["raw_contact_id"]),
    ("mimetype_id", &["mimetype_id"]),
    ("data1", &["data1"]),
];

const ANDROID_MIMETYPE_FIELDS: &[(&str, &[&str])] =
    &[("_id", &["_id"]), ("mimetype", &["mimetype"])];

/// The SELECT expression for `logical`: its column, or `NULL` when no candidate
/// matched — which the plan's marker declares, so the substitution is never
/// silent.
fn sql_expr(plan: &ColumnPlan, logical: &str) -> String {
    plan.column(logical)
        .map(str::to_string)
        .unwrap_or_else(|| "NULL".to_string())
}

/// Maximum number of contacts to extract per database.
const MAX_CONTACT_ENTRIES: usize = 200_000;

/// Maximum on-disk database size we will spill and open.
const MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub struct ContactsParser;

/// What one address-book schema yielded.
///
/// `truncated` is load-bearing: `count` is what this tool extracted, not how
/// many contacts the device held. A capped address book that reports only its
/// count lets an examiner conclude a number was never in the phone when the walk
/// simply stopped before reaching it.
struct ContactExtraction {
    artifacts: Vec<Artifact>,
    count: usize,
    truncated: bool,
    /// Rows the walk fetched and could not decode. Counted because a `continue`
    /// alone makes them vanish, after which `count` reads as the exact number of
    /// contacts on the device rather than a floor (B3-023).
    dropped_rows: usize,
    /// The schema-drift markers this parse owes: a column the parser reads
    /// that no candidate resolved. Appended after the contacts so each can say
    /// how many records were recovered without it.
    stale: Vec<Artifact>,
}

/// Accumulator for a single contact while joining multi-value tables.
#[derive(Default)]
struct ContactAcc {
    display_name: Option<String>,
    organization: Option<String>,
    phones: Vec<String>,
    emails: Vec<String>,
    /// Multi-value rows this contact holds that are neither a phone nor an
    /// email — postal addresses, IM handles, URLs, birthdays, notes. They are
    /// not parsed, so they are counted: an address book that lists only phones
    /// and emails otherwise reads as an address book that held only those.
    unmapped_values: usize,
    /// The distinct kinds seen (iOS `ABMultiValue.property` codes, Android
    /// mimetype strings), so an examiner knows what was passed over.
    unmapped_kinds: Vec<String>,
    /// Android `raw_contacts.deleted`: `Some(true)` when the provider marked the
    /// contact removed but has not yet purged the row. `None` when the schema
    /// has no such column, so absence is never read as "live".
    deleted: Option<bool>,
}

impl ContactAcc {
    fn add_phone(&mut self, p: String) {
        if !p.is_empty() && !self.phones.contains(&p) {
            self.phones.push(p);
        }
    }
    fn add_email(&mut self, e: String) {
        if !e.is_empty() && !self.emails.contains(&e) {
            self.emails.push(e);
        }
    }
    /// Record a multi-value row this parser does not map to a field.
    fn note_unmapped(&mut self, kind: String) {
        self.unmapped_values += 1;
        // Bounded: a hostile or damaged store must not turn a per-contact list
        // into an unbounded allocation.
        if !self.unmapped_kinds.contains(&kind) && self.unmapped_kinds.len() < 32 {
            self.unmapped_kinds.push(kind);
        }
    }
}

/// Permissive filename pre-filter (only decides whether to open the file). The
/// authoritative check is the schema (`ABPerson` for iOS or `raw_contacts` for
/// Android), run after opening, which rejects any false positive. `contacts2.db`
/// is shared with the call-history parser: the schema decides what each parses.
fn identify_contacts_db(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("addressbook.sqlitedb") || n.contains("addressbook") || n.ends_with("contacts2.db")
}

/// Build a per-contact `ParsedRecord` from an accumulator.
fn build_contact_record(
    case_id: Uuid,
    parent_id: Uuid,
    platform: &str,
    id: i64,
    acc: ContactAcc,
) -> Artifact {
    let display_name = acc
        .display_name
        .filter(|s| !s.is_empty())
        .or_else(|| acc.organization.clone())
        .unwrap_or_else(|| "Unknown".to_string());

    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("Contact"));
    meta.insert("subtype".into(), json!("contact"));
    meta.insert("platform".into(), json!(platform));
    meta.insert("rowid".into(), json!(id));
    meta.insert("display_name".into(), json!(display_name));
    meta.insert("phone_numbers".into(), json!(acc.phones));
    meta.insert("emails".into(), json!(acc.emails));
    meta.insert("organization".into(), json!(acc.organization));
    if let Some(deleted) = acc.deleted {
        meta.insert("deleted".into(), json!(deleted));
    }
    if acc.unmapped_values > 0 {
        // The address book held more about this person than the record shows.
        // Without this, "phone and email only" reads as everything the device
        // stored about them.
        //
        // Stated as counts, NOT as the `content_incomplete` / `inventory_incomplete`
        // pair: on a Google-synced Android device nearly every contact carries a
        // `group_membership` or `identity` row, so flagging the pair here would
        // raise the incompleteness banner on essentially every contact in every
        // case, and an examiner who sees it everywhere stops reading it — which
        // is how a real truncation gets missed. The pair is raised once, on the
        // address book's summary record, where it is a scope statement rather
        // than noise.
        meta.insert("unmapped_value_count".into(), json!(acc.unmapped_values));
        meta.insert("unmapped_value_kinds".into(), json!(acc.unmapped_kinds));
    }
    meta.insert("name".into(), json!(format!("Contact: {}", display_name)));

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("contact")
}

/// Parse iOS `AddressBook.sqlitedb` (`ABPerson` + `ABMultiValue`).
fn parse_ios_contacts(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
) -> Result<ContactExtraction> {
    let mut accs: HashMap<i64, ContactAcc> = HashMap::new();
    let mut order: Vec<i64> = Vec::new();
    let mut truncated = false;
    let mut dropped_rows = 0usize;
    let mut stale = Vec::new();

    // The column set is read before the query is written: a `SELECT` naming a
    // column this store renamed fails whole, and an address book would then
    // read as unreadable when only a column moved. A name column that did move
    // is read as NULL and declared, so the people are still listed.
    let person = plan_columns(conn, "ABPerson", IOS_PERSON_FIELDS, &[])
        .map_err(|why| anyhow::anyhow!("Failed to read the ABPerson columns: {why}"))?;
    let sql = format!(
        "SELECT ROWID, {}, {}, {} FROM ABPerson",
        sql_expr(&person, "First"),
        sql_expr(&person, "Last"),
        sql_expr(&person, "Organization"),
    );
    let mut stmt = conn
        .prepare(&sql)
        .context("Failed to prepare ABPerson query")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .context("Failed to query ABPerson rows")?;

    for row in rows {
        let (id, first, last, org) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skipping malformed ABPerson row: {}", e);
                dropped_rows += 1;
                continue;
            }
        };
        if accs.len() >= MAX_CONTACT_ENTRIES {
            truncated = true;
            break;
        }
        let display_name = [first, last]
            .into_iter()
            .flatten()
            .filter(|s| !s.trim().is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let acc = accs.entry(id).or_default();
        if !order.contains(&id) {
            order.push(id);
        }
        acc.display_name = if display_name.is_empty() {
            None
        } else {
            Some(display_name)
        };
        acc.organization = org.filter(|s| !s.trim().is_empty());
    }

    // Multi-values: phone numbers (property 3) and emails (property 4). A
    // column this join needs that no candidate resolved skips the join and is
    // declared: nothing can be hung off the people without it.
    let multivalue = if table_exists(conn, "ABMultiValue")? {
        let plan = plan_columns(conn, "ABMultiValue", IOS_MULTIVALUE_FIELDS, &[])
            .map_err(|why| anyhow::anyhow!("Failed to read the ABMultiValue columns: {why}"))?;
        Some(plan)
    } else {
        None
    };
    if let Some(mv_plan) = multivalue
        .as_ref()
        .filter(|plan| plan.missing_required().is_empty())
    {
        let sql = format!(
            "SELECT {}, {}, {} FROM ABMultiValue",
            sql_expr(mv_plan, "record_id"),
            sql_expr(mv_plan, "property"),
            sql_expr(mv_plan, "value"),
        );
        let mut mv = conn
            .prepare(&sql)
            .context("Failed to prepare ABMultiValue query")?;
        let mv_rows = mv
            .query_map([], |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .context("Failed to query ABMultiValue rows")?;

        for row in mv_rows {
            let (record_id, property, value) = match row {
                Ok(r) => r,
                Err(e) => {
                    debug!("Skipping malformed ABMultiValue row: {}", e);
                    dropped_rows += 1;
                    continue;
                }
            };
            let (record_id, value) = match (record_id, value) {
                (Some(r), Some(v)) if !v.trim().is_empty() => (r, v.trim().to_string()),
                _ => continue,
            };
            let acc = match accs.get_mut(&record_id) {
                Some(a) => a,
                None => continue,
            };
            if value.contains('@') || property == Some(4) {
                acc.add_email(value);
            } else if property == Some(3) {
                acc.add_phone(value);
            } else {
                // Property 5 (address), 22 (URL), 23 (birthday), 46 (IM) and the
                // rest are not decoded here. Counted, not dropped in silence.
                acc.note_unmapped(match property {
                    Some(p) => format!("property {}", p),
                    None => "property unrecorded".to_string(),
                });
            }
        }
    }

    let mut artifacts = Vec::with_capacity(order.len());
    for id in order {
        if let Some(acc) = accs.remove(&id) {
            artifacts.push(build_contact_record(case_id, parent_id, "iOS", id, acc));
        }
    }
    let count = artifacts.len();
    for (table, plan) in [
        ("ABPerson", Some(&person)),
        ("ABMultiValue", multivalue.as_ref()),
    ] {
        if let Some(plan) = plan.filter(|p| !p.missing_required().is_empty()) {
            stale.push(unresolved_fields_marker(
                &IOS_SUPPORT,
                table,
                plan,
                count,
                case_id,
                parent_id,
            ));
        }
    }
    Ok(ContactExtraction {
        artifacts,
        count,
        truncated,
        dropped_rows,
        stale,
    })
}

/// Parse Android `contacts2.db` (`raw_contacts` + `data` + `mimetypes`).
fn parse_android_contacts(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
) -> Result<ContactExtraction> {
    let mut accs: HashMap<i64, ContactAcc> = HashMap::new();
    let mut order: Vec<i64> = Vec::new();
    let mut truncated = false;
    let mut dropped_rows = 0usize;
    let mut stale = Vec::new();

    let raw = plan_columns(
        conn,
        "raw_contacts",
        ANDROID_RAW_CONTACT_FIELDS,
        ANDROID_RAW_CONTACT_OPTIONAL,
    )
    .map_err(|why| anyhow::anyhow!("Failed to read the raw_contacts columns: {why}"))?;
    // Without `_id` nothing can be keyed to a person; a moved `display_name`
    // is read as NULL and declared, so the people are still listed.
    if raw.column("_id").is_some() {
        let sql = format!(
            "SELECT {}, {}, {} FROM raw_contacts",
            sql_expr(&raw, "_id"),
            sql_expr(&raw, "display_name"),
            sql_expr(&raw, "deleted"),
        );
        let mut stmt = conn
            .prepare(&sql)
            .context("Failed to prepare raw_contacts query")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })
            .context("Failed to query raw_contacts rows")?;
        for row in rows {
            let (id, display_name, deleted) = match row {
                Ok(r) => r,
                Err(e) => {
                    debug!("Skipping malformed raw_contacts row: {}", e);
                    dropped_rows += 1;
                    continue;
                }
            };
            if accs.len() >= MAX_CONTACT_ENTRIES {
                truncated = true;
                break;
            }
            let acc = accs.entry(id).or_default();
            if !order.contains(&id) {
                order.push(id);
            }
            acc.display_name = display_name.filter(|s| !s.trim().is_empty());
            if raw.column("deleted").is_some() {
                acc.deleted = Some(deleted.unwrap_or(0) != 0);
            }
        }
    }

    // Phones, emails and organizations live in `data`, typed via `mimetypes`.
    // A column the join needs that no candidate resolved skips the join and is
    // declared.
    let (data_plan, mimetype_plan) =
        if table_exists(conn, "data")? && table_exists(conn, "mimetypes")? {
            (
                Some(
                    plan_columns(conn, "data", ANDROID_DATA_FIELDS, &[])
                        .map_err(|why| anyhow::anyhow!("Failed to read the data columns: {why}"))?,
                ),
                Some(
                    plan_columns(conn, "mimetypes", ANDROID_MIMETYPE_FIELDS, &[]).map_err(
                        |why| anyhow::anyhow!("Failed to read the mimetypes columns: {why}"),
                    )?,
                ),
            )
        } else {
            (None, None)
        };
    if let (Some(d), Some(m)) = (
        data_plan
            .as_ref()
            .filter(|plan| plan.missing_required().is_empty()),
        mimetype_plan
            .as_ref()
            .filter(|plan| plan.missing_required().is_empty()),
    ) {
        let sql = format!(
            "SELECT d.{}, m.{}, d.{} FROM data d JOIN mimetypes m ON m.{} = d.{}",
            sql_expr(d, "raw_contact_id"),
            sql_expr(m, "mimetype"),
            sql_expr(d, "data1"),
            sql_expr(m, "_id"),
            sql_expr(d, "mimetype_id"),
        );
        let mut stmt = conn
            .prepare(&sql)
            .context("Failed to prepare data/mimetypes query")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .context("Failed to query data rows")?;
        for row in rows {
            let (raw_id, mimetype, data1) = match row {
                Ok(r) => r,
                Err(e) => {
                    debug!("Skipping malformed data row: {}", e);
                    dropped_rows += 1;
                    continue;
                }
            };
            let (raw_id, mimetype, data1) = match (raw_id, mimetype, data1) {
                (Some(r), Some(m), Some(v)) if !v.trim().is_empty() => (r, m, v.trim().to_string()),
                _ => continue,
            };
            let acc = match accs.get_mut(&raw_id) {
                Some(a) => a,
                None => continue,
            };
            if mimetype.ends_with("/phone_v2") || mimetype.ends_with("/phone") {
                acc.add_phone(data1);
            } else if mimetype.ends_with("/email_v2") || mimetype.ends_with("/email") {
                acc.add_email(data1);
            } else if mimetype.ends_with("/organization") {
                if acc.organization.is_none() {
                    acc.organization = Some(data1);
                }
            } else if mimetype.ends_with("/name") {
                // Structured name; fill display_name if raw_contacts lacked one.
                if acc.display_name.is_none() {
                    acc.display_name = Some(data1);
                }
            } else {
                // Postal addresses, IM handles, notes, websites, group
                // memberships and every app-specific mimetype. Counted, not
                // dropped in silence.
                acc.note_unmapped(mimetype);
            }
        }
    }

    let mut artifacts = Vec::with_capacity(order.len());
    for id in order {
        if let Some(acc) = accs.remove(&id) {
            artifacts.push(build_contact_record(case_id, parent_id, "Android", id, acc));
        }
    }
    let count = artifacts.len();
    for (table, plan) in [
        ("raw_contacts", Some(&raw)),
        ("data", data_plan.as_ref()),
        ("mimetypes", mimetype_plan.as_ref()),
    ] {
        if let Some(plan) = plan.filter(|p| !p.missing_required().is_empty()) {
            stale.push(unresolved_fields_marker(
                &ANDROID_SUPPORT,
                table,
                plan,
                count,
                case_id,
                parent_id,
            ));
        }
    }
    Ok(ContactExtraction {
        artifacts,
        count,
        truncated,
        dropped_rows,
        stale,
    })
}

/// Parse a contacts database, dispatching on the detected schema, and append a
/// summary record.
fn parse_contacts(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Result<Vec<Artifact>> {
    let (extraction, platform, support, version) = if table_exists(conn, "ABPerson")? {
        let version: SchemaVersion = keyed_version(
            conn,
            "_SqliteDatabaseProperties",
            "key",
            "value",
            "_ClientVersion",
        );
        (
            parse_ios_contacts(conn, case_id, parent_id)?,
            "iOS",
            &IOS_SUPPORT,
            version,
        )
    } else if table_exists(conn, "raw_contacts")? {
        (
            parse_android_contacts(conn, case_id, parent_id)?,
            "Android",
            &ANDROID_SUPPORT,
            user_version(conn),
        )
    } else {
        return Ok(Vec::new());
    };
    let ContactExtraction {
        mut artifacts,
        count,
        truncated,
        dropped_rows,
        stale,
    } = extraction;
    artifacts.extend(stale);
    artifacts.extend(assess_version(support, &version, case_id, parent_id));

    let summary = build_contact_summary(
        &artifacts,
        platform,
        file_name,
        count,
        truncated,
        dropped_rows,
    );
    artifacts.push(
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, summary)
            .with_parent(parent_id)
            .with_subtype("summary"),
    );

    Ok(artifacts)
}

/// Build the `Contact` summary metadata for one parsed address book.
///
/// Forensic meaning: `contact_count` is the number of contacts THIS TOOL
/// extracted. When `truncated` is set the walk stopped at a safety cap, so the
/// absence of a name or number from the case is not evidence it was absent from
/// the device.
fn build_contact_summary(
    artifacts: &[Artifact],
    platform: &str,
    file_name: &str,
    count: usize,
    truncated: bool,
    dropped_rows: usize,
) -> Value {
    let with_phone = artifacts
        .iter()
        .filter(|a| {
            a.metadata["phone_numbers"]
                .as_array()
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();
    let with_email = artifacts
        .iter()
        .filter(|a| {
            a.metadata["emails"]
                .as_array()
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .count();

    // Multi-values this build does not map, summed over every contact. Raised
    // once here rather than on each contact: the statement "this parser recovers
    // names, numbers, addresses and organisations, and N other stored values
    // were not decoded" is a scope statement about the extraction, and repeating
    // it on every record would bury the truncation and decode-loss warnings that
    // sit in the same fields.
    let mut unmapped_total: u64 = 0;
    let mut unmapped_kinds: Vec<String> = Vec::new();
    for a in artifacts {
        if let Some(n) = a.metadata.get("unmapped_value_count") {
            unmapped_total = unmapped_total.saturating_add(n.as_u64().unwrap_or(0));
        }
        let kinds = match a.metadata.get("unmapped_value_kinds") {
            Some(v) => v.as_array(),
            None => None,
        };
        for k in kinds.into_iter().flatten() {
            let Some(k) = k.as_str() else { continue };
            if !unmapped_kinds.iter().any(|s| s == k) && unmapped_kinds.len() < 64 {
                unmapped_kinds.push(k.to_string());
            }
        }
    }

    let mut summary = serde_json::Map::new();
    summary.insert("type".into(), json!("Contact"));
    summary.insert("subtype".into(), json!("summary"));
    summary.insert("platform".into(), json!(platform));
    summary.insert("contact_count".into(), json!(count));
    summary.insert("with_phone_count".into(), json!(with_phone));
    summary.insert("with_email_count".into(), json!(with_email));
    if artifacts
        .iter()
        .any(|a| a.metadata.get("deleted").is_some())
    {
        // Contacts the provider marked removed but had not yet purged. They are
        // counted in `contact_count`; this says how many of those are not live.
        let deleted = artifacts
            .iter()
            .filter(|a| a.metadata.get("deleted") == Some(&json!(true)))
            .count();
        summary.insert("deleted_count".into(), json!(deleted));
    }
    summary.insert("file_name".into(), json!(file_name));
    if truncated {
        summary.insert("truncated".into(), json!(true));
        summary.insert("content_incomplete".into(), json!(true));
        summary.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::CapReached.as_str()),
        );
        summary.insert("max_entries".into(), json!(MAX_CONTACT_ENTRIES));
        summary.insert(
            "message".into(),
            json!(
                "Contact walk stopped at the parser cap; the remaining contacts were not extracted"
            ),
        );
    }
    if dropped_rows > 0 {
        // Rows that were present and would not decode. Without this the count
        // above reads as the exact number of contacts the device held, and an
        // examiner could testify a number was never in the phone when in fact
        // its row could not be read (B3-023).
        summary.insert("rows_dropped".into(), json!(dropped_rows));
        summary.insert("inventory_incomplete".into(), json!(true));
        summary.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        summary.insert("content_incomplete".into(), json!(true));
        // A cap is the coarser statement; do not overwrite it.
        summary
            .entry("content_incomplete_reason")
            .or_insert_with(|| json!(IncompleteReason::UnresolvedStructure.as_str()));
    }
    if unmapped_total > 0 {
        // Stored values this build passed over: postal addresses, IM handles,
        // URLs, birthdays, notes, group memberships. The per-contact records
        // carry the same counts, so an examiner can see WHICH people had more on
        // file than the extraction shows.
        summary.insert("unmapped_value_count".into(), json!(unmapped_total));
        summary.insert("unmapped_value_kinds".into(), json!(unmapped_kinds));
        summary.insert("inventory_incomplete".into(), json!(true));
        summary
            .entry("inventory_incomplete_reason")
            .or_insert_with(|| json!(IncompleteReason::UnresolvedStructure.as_str()));
        summary.insert(
            "unmapped_value_message".into(),
            json!(
                "This parser decodes names, phone numbers, email addresses and organisations. \
                 The values counted here were stored against these contacts and were not \
                 decoded, so their absence from a record is not evidence of their absence \
                 from the device."
            ),
        );
    }
    summary.insert(
        "name".into(),
        json!(format!("Contacts: {} entries ({})", count, platform)),
    );
    Value::Object(summary)
}

impl ForensicsModule for ContactsParser {
    fn id(&self) -> &str {
        "plugin.mobile.contacts"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::SystemArtifact]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !identify_contacts_db(name) {
            return Ok(Vec::new());
        }
        seance_sqlite_util::spilled::process_spilled_db(
            artifact,
            name,
            &seance_sqlite_util::spilled::SpilledDbSpec {
                log_label: "ContactsParser",
                spill_tag: "contacts",
                record_type: "Contact",
                display_name: "Contacts",
                noun: "contacts",
                schema_tables: &["ABPerson", "raw_contacts"],
                max_db_bytes: MAX_DB_BYTES,
            },
            parse_contacts,
        )
    }
}
