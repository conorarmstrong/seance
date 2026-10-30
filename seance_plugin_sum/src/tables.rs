//! Table readers for the User Access Logging databases.
//!
//! Each reader takes a `libesedb::Table`, works out which columns it actually
//! has, and returns rows plus a [`WalkStatus`] saying what it could not read.
//! No reader assumes a column exists: UAL's schema has moved between Server
//! 2012 and 2025, and a build that indexes blindly reports zeros for a column
//! the table never carried.

use chrono::{DateTime, Utc};
use libesedb::{Table, Value};
use seance_ese_util::{
    column, counter, find_column, format_guid, get_column_names, read_value, text,
    value_to_datetime, WalkStatus,
};
use std::collections::HashMap;
use tracing::warn;

/// A GUID column, rendered canonically, or `None` when absent/undecodable.
///
/// UAL stores role GUIDs as 16 raw bytes. Some builds store them as text
/// instead, so both are accepted — a role that renders as hex in one column and
/// as a GUID in another would be two different roles to anyone reading the
/// report.
fn guid(record: &libesedb::Record, idx: Option<usize>) -> Option<String> {
    let value = read_value(record, idx?)?;
    match &value {
        Value::Binary(b) | Value::LargeBinary(b) => format_guid(b),
        Value::Text(s) | Value::LargeText(s) => {
            let t = s.trim().trim_matches(|c| c == '{' || c == '}').to_string();
            (!t.is_empty()).then_some(t)
        }
        Value::Guid(b) => format_guid(b),
        _ => None,
    }
}

/// An IP address column.
///
/// UAL writes the client address as raw bytes: 4 for IPv4, 16 for IPv6. Any
/// other length is left undecoded rather than guessed, because a half-decoded
/// address in an access log points at a machine that was never there.
fn address(record: &libesedb::Record, idx: Option<usize>) -> Option<String> {
    let value = read_value(record, idx?)?;
    let bytes = match &value {
        Value::Binary(b) | Value::LargeBinary(b) => b.clone(),
        // Already-formatted text addresses appear in some builds.
        Value::Text(s) | Value::LargeText(s) => {
            let t = s.trim().to_string();
            return (!t.is_empty()).then_some(t);
        }
        _ => return None,
    };
    match bytes.len() {
        4 => Some(format!(
            "{}.{}.{}.{}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )),
        16 => {
            let groups: Vec<String> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            Some(groups.join(":"))
        }
        _ => None,
    }
}

/// Read a timestamp column without inventing one.
fn when(record: &libesedb::Record, idx: Option<usize>) -> Option<DateTime<Utc>> {
    read_value(record, idx?)
        .as_ref()
        .and_then(value_to_datetime)
}

/// One row of a per-role client-access table.
///
/// This is the record UAL exists to produce, and the reason the feature matters
/// for server intrusion work: it names *which account*, from *which address*,
/// reached *which role*, *how many times*, and *when it was first and last
/// seen*. Windows keeps it for up to three years, long after the security event
/// log has rolled.
#[derive(Debug, Clone)]
pub struct UalClientAccess {
    pub authenticated_user: Option<String>,
    pub client_address: Option<String>,
    pub role_guid: Option<String>,
    pub tenant_id: Option<String>,
    pub total_accesses: Option<u64>,
    pub insert_date: Option<DateTime<Utc>>,
    pub last_access: Option<DateTime<Utc>>,
    /// Days in the year on which this client was seen, from the `Day1`..`Day366`
    /// columns. Only the days actually recorded are listed; an empty vector
    /// means none were set, which is different from the columns being absent.
    pub active_days: Vec<u16>,
}

/// Does this table look like a per-role client-access table?
///
/// UAL names these tables after the role GUID, so they cannot be found by name.
/// They are identified by the columns they carry instead — which also means a
/// schema change that renames the table does not hide it from this reader.
pub fn is_client_table(columns: &[String]) -> bool {
    find_column(columns, "AuthenticatedUserName").is_some()
        && find_column(columns, "TotalAccesses").is_some()
}

/// Read a per-role client-access table.
pub fn parse_client_table(table: &Table) -> (Vec<UalClientAccess>, WalkStatus) {
    let mut rows = Vec::new();
    let mut status = WalkStatus::default();

    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(e) => {
            warn!("UAL: client table columns unreadable: {}", e);
            return (rows, WalkStatus::unreadable("columns"));
        }
    };

    let user_idx = column(&columns, "AuthenticatedUserName", &mut status);
    let address_idx = column(&columns, "Address", &mut status);
    let role_idx = find_column(&columns, "RoleGuid");
    let tenant_idx = find_column(&columns, "TenantId");
    let total_idx = column(&columns, "TotalAccesses", &mut status);
    let insert_idx = find_column(&columns, "InsertDate");
    let last_idx = find_column(&columns, "LastAccess");

    // Day1..Day366. Collected once rather than per row: resolving 366 column
    // names for every client in a busy server's table is the difference between
    // a fast walk and a slow one.
    let day_indices: Vec<(u16, usize)> = (1u16..=366)
        .filter_map(|d| find_column(&columns, &format!("Day{d}")).map(|i| (d, i)))
        .collect();

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(e) => {
            warn!("UAL: client table records unreadable: {}", e);
            return (rows, WalkStatus::unreadable("records"));
        }
    };

    for record_result in records {
        let record = match record_result {
            Ok(r) => r,
            Err(_) => {
                status.rows_skipped += 1;
                continue;
            }
        };

        // `counter` records a defaulted value when the cell will not decode;
        // that is a real distinction here, because 0 accesses and an unreadable
        // access count are very different claims about an account.
        let total = total_idx.map(|_| counter(&record, total_idx, &mut status));

        let active_days = day_indices
            .iter()
            .filter_map(|(day, idx)| {
                let seen = read_value(&record, *idx)
                    .as_ref()
                    .and_then(seance_ese_util::value_to_u64)
                    .unwrap_or(0);
                (seen > 0).then_some(*day)
            })
            .collect();

        rows.push(UalClientAccess {
            authenticated_user: text(&record, user_idx),
            client_address: address(&record, address_idx),
            role_guid: guid(&record, role_idx),
            tenant_id: guid(&record, tenant_idx),
            total_accesses: total,
            insert_date: when(&record, insert_idx),
            last_access: when(&record, last_idx),
            active_days,
        });
    }

    (rows, status)
}

/// A role GUID and the product it belongs to, from `SystemIdentity.mdb`.
#[derive(Debug, Clone)]
pub struct UalRoleId {
    pub role_guid: Option<String>,
    pub role_name: Option<String>,
    pub product_name: Option<String>,
}

/// Read `ROLE_IDS`, which names the roles every other table refers to by GUID.
pub fn parse_role_ids(table: &Table) -> (Vec<UalRoleId>, WalkStatus) {
    let mut rows = Vec::new();
    let mut status = WalkStatus::default();

    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(_) => return (rows, WalkStatus::unreadable("columns")),
    };
    let guid_idx = column(&columns, "RoleGuid", &mut status);
    let name_idx = find_column(&columns, "RoleName");
    let product_idx = find_column(&columns, "ProductName");

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(_) => return (rows, WalkStatus::unreadable("records")),
    };

    for record_result in records {
        let Ok(record) = record_result else {
            status.rows_skipped += 1;
            continue;
        };
        rows.push(UalRoleId {
            role_guid: guid(&record, guid_idx),
            role_name: text(&record, name_idx),
            product_name: text(&record, product_idx),
        });
    }
    (rows, status)
}

/// Build the GUID → role-name map used to resolve access rows.
pub fn role_name_map(roles: &[UalRoleId]) -> HashMap<String, String> {
    roles
        .iter()
        .filter_map(|r| {
            let guid = r.role_guid.as_ref()?.to_lowercase();
            let name = r.role_name.clone().or_else(|| r.product_name.clone())?;
            Some((guid, name))
        })
        .collect()
}

/// When a role was first and last used, from `ROLE_ACCESS`.
#[derive(Debug, Clone)]
pub struct UalRoleAccess {
    pub role_guid: Option<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Read `ROLE_ACCESS`.
pub fn parse_role_access(table: &Table) -> (Vec<UalRoleAccess>, WalkStatus) {
    let mut rows = Vec::new();
    let mut status = WalkStatus::default();

    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(_) => return (rows, WalkStatus::unreadable("columns")),
    };
    let guid_idx = column(&columns, "RoleGuid", &mut status);
    let first_idx = find_column(&columns, "FirstSeen");
    let last_idx = find_column(&columns, "LastSeen");

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(_) => return (rows, WalkStatus::unreadable("records")),
    };

    for record_result in records {
        let Ok(record) = record_result else {
            status.rows_skipped += 1;
            continue;
        };
        rows.push(UalRoleAccess {
            role_guid: guid(&record, guid_idx),
            first_seen: when(&record, first_idx),
            last_seen: when(&record, last_idx),
        });
    }
    (rows, status)
}

/// The server's own identity, from `SYSTEM_IDENTITY`.
///
/// Worth extracting in its own right: it names the machine, its domain, its
/// hardware and its OS build, which is what ties a UAL database recovered from
/// an image to the server it was taken from.
#[derive(Debug, Clone, Default)]
pub struct UalSystemIdentity {
    pub creation_time: Option<DateTime<Utc>>,
    pub dns_host_name: Option<String>,
    pub domain_name: Option<String>,
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub serial_number: Option<String>,
    pub os_build: Option<u64>,
    pub os_major: Option<u64>,
    pub os_minor: Option<u64>,
    pub timezone: Option<String>,
}

/// Read `SYSTEM_IDENTITY`.
pub fn parse_system_identity(table: &Table) -> (Vec<UalSystemIdentity>, WalkStatus) {
    let mut rows = Vec::new();
    let mut status = WalkStatus::default();

    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(_) => return (rows, WalkStatus::unreadable("columns")),
    };
    let creation_idx = find_column(&columns, "CreationTime");
    let host_idx = find_column(&columns, "SystemDNSHostName");
    let domain_idx = find_column(&columns, "SystemDomainName");
    let manufacturer_idx = find_column(&columns, "SystemManufacturer");
    let product_idx = find_column(&columns, "SystemProductName");
    let serial_idx = find_column(&columns, "SystemSerialNumber");
    let build_idx = find_column(&columns, "OSBuildNumber");
    let major_idx = find_column(&columns, "OSMajor");
    let minor_idx = find_column(&columns, "OSMinor");
    // The real column is `OSCurrentTimeZone`, an unsigned 16-bit integer
    // holding minutes from UTC in two's complement (65116 is -420, UTC-7).
    // This reader looked for a text column named `SystemTimeZone`, which no
    // real database carries (`VALIDATION.md` `UAL-1`, DC01).
    let tz_idx = find_column(&columns, "OSCurrentTimeZone");

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(_) => return (rows, WalkStatus::unreadable("records")),
    };

    for record_result in records {
        let Ok(record) = record_result else {
            status.rows_skipped += 1;
            continue;
        };
        // Version numbers are read without defaulting: an OS build reported as
        // 0 because the cell would not decode is a claim about the machine.
        let number = |idx: Option<usize>| {
            read_value(&record, idx?)
                .as_ref()
                .and_then(seance_ese_util::value_to_u64)
        };
        rows.push(UalSystemIdentity {
            creation_time: when(&record, creation_idx),
            dns_host_name: text(&record, host_idx),
            domain_name: text(&record, domain_idx),
            manufacturer: text(&record, manufacturer_idx),
            product_name: text(&record, product_idx),
            serial_number: text(&record, serial_idx),
            os_build: number(build_idx),
            os_major: number(major_idx),
            os_minor: number(minor_idx),
            timezone: number(tz_idx).map(|raw| format_utc_offset(raw as u16 as i16)),
        });
    }
    (rows, status)
}

/// Render a signed minutes-from-UTC offset, e.g. `-420` as `UTC-07:00`.
pub(crate) fn format_utc_offset(minutes: i16) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let m = minutes.unsigned_abs();
    format!("UTC{sign}{:02}:{:02}", m / 60, m % 60)
}

/// A DNS observation, from the `DNS` table.
#[derive(Debug, Clone)]
pub struct UalDns {
    pub host_name: Option<String>,
    pub address: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Read `DNS`.
pub fn parse_dns(table: &Table) -> (Vec<UalDns>, WalkStatus) {
    let mut rows = Vec::new();
    let mut status = WalkStatus::default();

    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(_) => return (rows, WalkStatus::unreadable("columns")),
    };
    let host_idx = find_column(&columns, "HostName");
    let address_idx = find_column(&columns, "Address");
    let last_idx = find_column(&columns, "LastSeen");

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(_) => return (rows, WalkStatus::unreadable("records")),
    };

    for record_result in records {
        let Ok(record) = record_result else {
            status.rows_skipped += 1;
            continue;
        };
        rows.push(UalDns {
            host_name: text(&record, host_idx),
            address: address(&record, address_idx),
            last_seen: when(&record, last_idx),
        });
    }
    (rows, status)
}

/// A virtual machine seen by this host, from `VIRTUALMACHINES`.
#[derive(Debug, Clone)]
pub struct UalVirtualMachine {
    pub vm_guid: Option<String>,
    pub bios_guid: Option<String>,
    pub creation_time: Option<DateTime<Utc>>,
    pub last_seen_active: Option<DateTime<Utc>>,
    pub serial_number: Option<String>,
}

/// Read `VIRTUALMACHINES`.
pub fn parse_virtual_machines(table: &Table) -> (Vec<UalVirtualMachine>, WalkStatus) {
    let mut rows = Vec::new();
    let mut status = WalkStatus::default();

    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(_) => return (rows, WalkStatus::unreadable("columns")),
    };
    let vm_idx = find_column(&columns, "VmGuid");
    let bios_idx = find_column(&columns, "BIOSGuid");
    let creation_idx = find_column(&columns, "CreationTime");
    let last_idx = find_column(&columns, "LastSeenActive");
    let serial_idx = find_column(&columns, "SerialNumber");

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(_) => return (rows, WalkStatus::unreadable("records")),
    };

    for record_result in records {
        let Ok(record) = record_result else {
            status.rows_skipped += 1;
            continue;
        };
        rows.push(UalVirtualMachine {
            vm_guid: guid(&record, vm_idx),
            bios_guid: guid(&record, bios_idx),
            creation_time: when(&record, creation_idx),
            last_seen_active: when(&record, last_idx),
            serial_number: text(&record, serial_idx),
        });
    }
    (rows, status)
}

/// A chained (archived) database this one refers to, from `CHAINED_DATABASES`.
///
/// UAL rolls into a new `{GUID}.mdb` each year and records the chain here. An
/// examiner who has `SystemIdentity.mdb` but not the archives needs to know
/// they exist — otherwise the year present reads as the whole history.
#[derive(Debug, Clone)]
pub struct UalChainedDatabase {
    pub year: Option<u64>,
    pub file_name: Option<String>,
}

/// Read `CHAINED_DATABASES`.
pub fn parse_chained_databases(table: &Table) -> (Vec<UalChainedDatabase>, WalkStatus) {
    let mut rows = Vec::new();
    let mut status = WalkStatus::default();

    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(_) => return (rows, WalkStatus::unreadable("columns")),
    };
    let year_idx = find_column(&columns, "Year");
    let file_idx = find_column(&columns, "FileName");

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(_) => return (rows, WalkStatus::unreadable("records")),
    };

    for record_result in records {
        let Ok(record) = record_result else {
            status.rows_skipped += 1;
            continue;
        };
        rows.push(UalChainedDatabase {
            // Threaded through the `Option` rather than given a sentinel index.
            // `read_value` casts its index to `i32`, so a sentinel of
            // `usize::MAX` would truncate to -1 and query a column that is not
            // the one that is missing.
            year: year_idx
                .and_then(|i| read_value(&record, i))
                .as_ref()
                .and_then(seance_ese_util::value_to_u64),
            file_name: text(&record, file_idx).or_else(|| guid(&record, file_idx)),
        });
    }
    (rows, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_table_is_recognised_by_its_columns_not_its_name() {
        // UAL names these tables after the role GUID, so name matching cannot
        // find them at all.
        let columns: Vec<String> = ["AuthenticatedUserName", "TotalAccesses", "Address"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(is_client_table(&columns));
    }

    #[test]
    fn an_unrelated_ese_table_is_not_mistaken_for_a_client_table() {
        // SRUM's tables live in ESE databases too, and both plugins see every
        // ESE file. Detection has to be specific enough not to collide.
        let srum: Vec<String> = ["AppId", "UserId", "BytesSent", "InterfaceLuid"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(!is_client_table(&srum));

        let identity: Vec<String> = ["SystemDNSHostName", "OSBuildNumber"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(!is_client_table(&identity));
    }

    #[test]
    fn a_partial_client_schema_is_not_enough() {
        // A table with only one of the two required columns is not a client
        // table; treating it as one would publish rows with no access counts.
        let only_user: Vec<String> = vec!["AuthenticatedUserName".to_string()];
        assert!(!is_client_table(&only_user));
        let only_total: Vec<String> = vec!["TotalAccesses".to_string()];
        assert!(!is_client_table(&only_total));
    }

    #[test]
    fn role_names_resolve_case_insensitively_by_guid() {
        let roles = vec![
            UalRoleId {
                role_guid: Some("AD495E1E-B84B-4E42-9AE8-9AC9F4C1A2C4".to_string()),
                role_name: Some("File Server".to_string()),
                product_name: None,
            },
            // Falls back to the product name when the role name is absent.
            UalRoleId {
                role_guid: Some("10a9226f-50ee-49d8-a393-9a501d47ce04".to_string()),
                role_name: None,
                product_name: Some("Windows Server".to_string()),
            },
            // No GUID: cannot be keyed, and must not panic or key on "".
            UalRoleId {
                role_guid: None,
                role_name: Some("Orphan".to_string()),
                product_name: None,
            },
        ];
        let map = role_name_map(&roles);
        assert_eq!(map.len(), 2, "the GUID-less role cannot be keyed");
        assert_eq!(
            map.get("ad495e1e-b84b-4e42-9ae8-9ac9f4c1a2c4"),
            Some(&"File Server".to_string()),
            "lookup is lowercased so a GUID's case cannot split one role in two"
        );
        assert_eq!(
            map.get("10a9226f-50ee-49d8-a393-9a501d47ce04"),
            Some(&"Windows Server".to_string())
        );
    }
}
