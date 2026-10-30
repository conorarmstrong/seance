//! SRUM table-specific parsers for each table of interest.
//!
//! Each parser takes a libesedb Table, extracts column names, iterates records,
//! and produces structured output suitable for artifact creation.

use chrono::{DateTime, Utc};
use libesedb::{Table, Value};
use seance_ese_util::{
    column, counter, find_column, format_sid, get_column_names, id32, read_value,
    try_decode_utf16le, value_to_datetime,
};
use std::collections::HashMap;
use tracing::{debug, warn};

// The walk-status contract and the ESE value coercions are shared with the SUM
// (User Access Logging) reader; both live in `seance_ese_util` so the two
// cannot drift. Re-exported because this module's public parsers return it.
pub use seance_ese_util::WalkStatus;

// ─── ID Map Table ────────────────────────────────────────────────────────────

/// Parse SruDbIdMapTable to build AppId/UserId integer → string mappings.
///
/// The [`WalkStatus`] matters as much as the map: an unresolved ID surfaces as
/// `Unknown(1234)` in every downstream record, and an examiner has to be able to
/// tell "this ID was never in the map" from "the map could not be read".
pub fn parse_id_map_table(table: &Table) -> (HashMap<u32, String>, WalkStatus) {
    let mut map = HashMap::new();
    let mut status = WalkStatus::default();

    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read IdMapTable columns: {}", e);
            return (map, WalkStatus::unreadable("columns"));
        }
    };

    let id_type_idx = find_column(&columns, "IdType");
    // Without these two the map cannot be built at all, and every downstream
    // record shows `Unknown(n)` in place of an application name.
    let id_index_idx = column(&columns, "IdIndex", &mut status);
    let id_blob_idx = column(&columns, "IdBlob", &mut status);

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to iterate IdMapTable records: {}", e);
            return (map, WalkStatus::unreadable("records"));
        }
    };

    for record_result in records {
        let record = match record_result {
            Ok(r) => r,
            // A row the ESE layer will not decode is a row missing from the
            // result; tally it so the caller can say so (B2-170).
            Err(_) => {
                status.rows_skipped += 1;
                continue;
            }
        };

        let id_index = id_index_idx
            .and_then(|idx| read_value(&record, idx))
            .and_then(|v| v.to_u32());

        let id_blob = id_blob_idx.and_then(|idx| read_value(&record, idx));

        if let (Some(index), Some(blob)) = (id_index, id_blob) {
            // IdBlob can be a string (app name/path) or binary (SID)
            let resolved = match &blob {
                Value::Text(s) | Value::LargeText(s) => s.clone(),
                Value::Binary(b) | Value::LargeBinary(b) => {
                    // Try to decode as UTF-16LE string first
                    if let Some(s) = try_decode_utf16le(b) {
                        s
                    } else {
                        // Check if it's a SID
                        if b.len() >= 8 && b[0] == 1 {
                            format_sid(b)
                        } else {
                            hex::encode(b)
                        }
                    }
                }
                _ => blob.to_string(),
            };

            // IdType: 0 = unknown, 1 = interface, 2 = user (SID), 3 = app
            let _id_type = id_type_idx
                .and_then(|idx| read_value(&record, idx))
                .and_then(|v| v.to_u32())
                .unwrap_or(0);

            map.insert(index, resolved);
        }
    }

    debug!(
        "IdMapTable: resolved {} entries, {} rows skipped",
        map.len(),
        status.rows_skipped
    );
    (map, status)
}

// ─── Application Resource Usage ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SrumAppResource {
    pub timestamp: Option<DateTime<Utc>>,
    pub app_id: u32,
    pub user_id: u32,
    pub foreground_cycle_time: u64,
    pub background_cycle_time: u64,
    pub face_time: u64,
    pub foreground_bytes_read: u64,
    pub foreground_bytes_written: u64,
    pub background_bytes_read: u64,
    pub background_bytes_written: u64,
    pub foreground_context_switches: u64,
    pub background_context_switches: u64,
}

/// Walk the AppResource table. The [`WalkStatus`] returned alongside the rows is
/// what separates "this table held these rows" from "these are the rows we
/// managed to decode"; the caller must publish it.
pub fn parse_app_resource_table(table: &Table) -> (Vec<SrumAppResource>, WalkStatus) {
    let mut entries = Vec::new();
    let mut status = WalkStatus::default();
    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read AppResource columns: {}", e);
            return (entries, WalkStatus::unreadable("columns"));
        }
    };

    let idx_timestamp = column(&columns, "TimeStamp", &mut status);
    let idx_app_id = column(&columns, "AppId", &mut status);
    let idx_user_id = column(&columns, "UserId", &mut status);
    let idx_fg_cycle = column(&columns, "ForegroundCycleTime", &mut status);
    let idx_bg_cycle = column(&columns, "BackgroundCycleTime", &mut status);
    let idx_face_time = column(&columns, "FaceTime", &mut status);
    let idx_fg_bytes_read = column(&columns, "ForegroundBytesRead", &mut status);
    let idx_fg_bytes_written = column(&columns, "ForegroundBytesWritten", &mut status);
    let idx_bg_bytes_read = column(&columns, "BackgroundBytesRead", &mut status);
    let idx_bg_bytes_written = column(&columns, "BackgroundBytesWritten", &mut status);
    let idx_fg_ctx = column(&columns, "ForegroundContextSwitches", &mut status);
    let idx_bg_ctx = column(&columns, "BackgroundContextSwitches", &mut status);

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to iterate AppResource records: {}", e);
            return (entries, WalkStatus::unreadable("records"));
        }
    };

    for record_result in records {
        let record = match record_result {
            Ok(r) => r,
            // A row the ESE layer will not decode is a row missing from the
            // result; tally it so the caller can say so (B2-170).
            Err(_) => {
                status.rows_skipped += 1;
                continue;
            }
        };

        let timestamp = idx_timestamp
            .and_then(|idx| read_value(&record, idx))
            .as_ref()
            .and_then(value_to_datetime);
        let app_id = id32(&record, idx_app_id, &mut status);
        let user_id = id32(&record, idx_user_id, &mut status);

        entries.push(SrumAppResource {
            timestamp,
            app_id,
            user_id,
            foreground_cycle_time: counter(&record, idx_fg_cycle, &mut status),
            background_cycle_time: counter(&record, idx_bg_cycle, &mut status),
            face_time: counter(&record, idx_face_time, &mut status),
            foreground_bytes_read: counter(&record, idx_fg_bytes_read, &mut status),
            foreground_bytes_written: counter(&record, idx_fg_bytes_written, &mut status),
            background_bytes_read: counter(&record, idx_bg_bytes_read, &mut status),
            background_bytes_written: counter(&record, idx_bg_bytes_written, &mut status),
            foreground_context_switches: counter(&record, idx_fg_ctx, &mut status),
            background_context_switches: counter(&record, idx_bg_ctx, &mut status),
        });
    }

    debug!(
        "AppResource: parsed {} records, {} rows skipped",
        entries.len(),
        status.rows_skipped
    );
    (entries, status)
}

// ─── Network Data Usage ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SrumNetworkData {
    pub timestamp: Option<DateTime<Utc>>,
    pub app_id: u32,
    pub user_id: u32,
    pub interface_luid: u64,
    pub l2_profile_id: u32,
    pub l2_profile_flags: u32,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
}

/// Walk the NetworkData table. The [`WalkStatus`] returned alongside the rows is
/// what separates "this table held these rows" from "these are the rows we
/// managed to decode"; the caller must publish it.
pub fn parse_network_data_table(table: &Table) -> (Vec<SrumNetworkData>, WalkStatus) {
    let mut entries = Vec::new();
    let mut status = WalkStatus::default();
    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read NetworkData columns: {}", e);
            return (entries, WalkStatus::unreadable("columns"));
        }
    };

    let idx_timestamp = column(&columns, "TimeStamp", &mut status);
    let idx_app_id = column(&columns, "AppId", &mut status);
    let idx_user_id = column(&columns, "UserId", &mut status);
    let idx_interface = column(&columns, "InterfaceLuid", &mut status);
    let idx_l2_profile = column(&columns, "L2ProfileId", &mut status);
    let idx_l2_flags = column(&columns, "L2ProfileFlags", &mut status);
    let idx_bytes_sent = column(&columns, "BytesSent", &mut status);
    let idx_bytes_recvd = column(&columns, "BytesRecvd", &mut status);

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to iterate NetworkData records: {}", e);
            return (entries, WalkStatus::unreadable("records"));
        }
    };

    for record_result in records {
        let record = match record_result {
            Ok(r) => r,
            // A row the ESE layer will not decode is a row missing from the
            // result; tally it so the caller can say so (B2-170).
            Err(_) => {
                status.rows_skipped += 1;
                continue;
            }
        };

        entries.push(SrumNetworkData {
            timestamp: idx_timestamp
                .and_then(|idx| read_value(&record, idx))
                .as_ref()
                .and_then(value_to_datetime),
            app_id: id32(&record, idx_app_id, &mut status),
            user_id: id32(&record, idx_user_id, &mut status),
            interface_luid: counter(&record, idx_interface, &mut status),
            l2_profile_id: id32(&record, idx_l2_profile, &mut status),
            l2_profile_flags: id32(&record, idx_l2_flags, &mut status),
            bytes_sent: counter(&record, idx_bytes_sent, &mut status),
            bytes_recvd: counter(&record, idx_bytes_recvd, &mut status),
        });
    }

    debug!(
        "NetworkData: parsed {} records, {} rows skipped",
        entries.len(),
        status.rows_skipped
    );
    (entries, status)
}

// ─── Network Connectivity ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SrumNetworkConnectivity {
    pub timestamp: Option<DateTime<Utc>>,
    pub app_id: u32,
    pub user_id: u32,
    pub interface_luid: u64,
    pub l2_profile_id: u32,
    pub connected_time: u32,
    pub connect_start_time: Option<DateTime<Utc>>,
}

/// Walk the NetworkConnectivity table. The [`WalkStatus`] returned alongside the rows is
/// what separates "this table held these rows" from "these are the rows we
/// managed to decode"; the caller must publish it.
pub fn parse_network_connectivity_table(
    table: &Table,
) -> (Vec<SrumNetworkConnectivity>, WalkStatus) {
    let mut entries = Vec::new();
    let mut status = WalkStatus::default();
    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read NetworkConnectivity columns: {}", e);
            return (entries, WalkStatus::unreadable("columns"));
        }
    };

    let idx_timestamp = column(&columns, "TimeStamp", &mut status);
    let idx_app_id = column(&columns, "AppId", &mut status);
    let idx_user_id = column(&columns, "UserId", &mut status);
    let idx_interface = column(&columns, "InterfaceLuid", &mut status);
    let idx_l2_profile = column(&columns, "L2ProfileId", &mut status);
    let idx_connected_time = column(&columns, "ConnectedTime", &mut status);
    let idx_connect_start = column(&columns, "ConnectStartTime", &mut status);

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to iterate NetworkConnectivity records: {}", e);
            return (entries, WalkStatus::unreadable("records"));
        }
    };

    for record_result in records {
        let record = match record_result {
            Ok(r) => r,
            // A row the ESE layer will not decode is a row missing from the
            // result; tally it so the caller can say so (B2-170).
            Err(_) => {
                status.rows_skipped += 1;
                continue;
            }
        };

        entries.push(SrumNetworkConnectivity {
            timestamp: idx_timestamp
                .and_then(|idx| read_value(&record, idx))
                .as_ref()
                .and_then(value_to_datetime),
            app_id: id32(&record, idx_app_id, &mut status),
            user_id: id32(&record, idx_user_id, &mut status),
            interface_luid: counter(&record, idx_interface, &mut status),
            l2_profile_id: id32(&record, idx_l2_profile, &mut status),
            connected_time: id32(&record, idx_connected_time, &mut status),
            connect_start_time: idx_connect_start
                .and_then(|idx| read_value(&record, idx))
                .as_ref()
                .and_then(value_to_datetime),
        });
    }

    debug!(
        "NetworkConnectivity: parsed {} records, {} rows skipped",
        entries.len(),
        status.rows_skipped
    );
    (entries, status)
}

// ─── Energy Usage ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SrumEnergyUsage {
    pub timestamp: Option<DateTime<Utc>>,
    pub app_id: u32,
    pub user_id: u32,
    pub battery_level: u32,
    pub designed_capacity: u32,
    pub full_charged_capacity: u32,
    pub charge_level: u32,
}

/// Walk the EnergyUsage table. The [`WalkStatus`] returned alongside the rows is
/// what separates "this table held these rows" from "these are the rows we
/// managed to decode"; the caller must publish it.
pub fn parse_energy_table(table: &Table) -> (Vec<SrumEnergyUsage>, WalkStatus) {
    let mut entries = Vec::new();
    let mut status = WalkStatus::default();
    let columns = match get_column_names(table) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read EnergyUsage columns: {}", e);
            return (entries, WalkStatus::unreadable("columns"));
        }
    };

    let idx_timestamp = column(&columns, "TimeStamp", &mut status);
    let idx_app_id = column(&columns, "AppId", &mut status);
    let idx_user_id = column(&columns, "UserId", &mut status);
    // `BatteryLevel` only. The previous fallback to `EventTimestamp` read a
    // FILETIME column as though it were a battery percentage: on the Windows
    // builds that lack `BatteryLevel` (most of them) the value never fits in a
    // u32, so the row published 0 anyway — a fabricated flat battery drawn from
    // a timestamp. Its absence is stated once, as a fact about the table.
    let idx_battery = column(&columns, "BatteryLevel", &mut status);
    let idx_designed = column(&columns, "DesignedCapacity", &mut status);
    let idx_full_charged = column(&columns, "FullChargedCapacity", &mut status);
    let idx_charge = column(&columns, "ChargeLevel", &mut status);

    let records = match table.iter_records() {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to iterate EnergyUsage records: {}", e);
            return (entries, WalkStatus::unreadable("records"));
        }
    };

    for record_result in records {
        let record = match record_result {
            Ok(r) => r,
            // A row the ESE layer will not decode is a row missing from the
            // result; tally it so the caller can say so (B2-170).
            Err(_) => {
                status.rows_skipped += 1;
                continue;
            }
        };

        entries.push(SrumEnergyUsage {
            timestamp: idx_timestamp
                .and_then(|idx| read_value(&record, idx))
                .as_ref()
                .and_then(value_to_datetime),
            app_id: id32(&record, idx_app_id, &mut status),
            user_id: id32(&record, idx_user_id, &mut status),
            battery_level: id32(&record, idx_battery, &mut status),
            designed_capacity: id32(&record, idx_designed, &mut status),
            full_charged_capacity: id32(&record, idx_full_charged, &mut status),
            charge_level: id32(&record, idx_charge, &mut status),
        });
    }

    debug!(
        "EnergyUsage: parsed {} records, {} rows skipped",
        entries.len(),
        status.rows_skipped
    );
    (entries, status)
}
