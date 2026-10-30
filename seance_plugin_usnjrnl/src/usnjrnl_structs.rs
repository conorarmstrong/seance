use chrono::{DateTime, Utc};

/// A single changed byte range reported by a USN_RECORD_V4 record.
#[derive(Debug, Clone)]
pub struct UsnExtent {
    /// Byte offset within the file's data stream where the change begins.
    pub offset: i64,
    /// Length in bytes of the changed range.
    pub length: i64,
}

/// Represents a parsed USN Journal record.
///
/// V2/V3 records carry a `timestamp` and `file_name`. V4 records carry NEITHER;
/// they report changed byte ranges via `extents` instead and are paired with a
/// later V3 close record for the name/time. For V4, `timestamp` is always
/// `None` and `file_name` is always empty -- these must never be fabricated.
#[derive(Debug, Clone)]
pub struct UsnRecord {
    pub record_length: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference_number: u64,
    pub file_reference_number_hi: u64, // For v3+ records
    pub parent_reference_number: u64,
    pub parent_reference_number_hi: u64, // For v3+ records
    pub usn: u64,
    /// None when the on-disk FILETIME is zero or out of range (e.g. timestomped),
    /// and always None for V4 records (which carry no timestamp at all).
    pub timestamp: Option<DateTime<Utc>>,
    pub reason_flags: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub file_name: String,
    pub _file_name_length: u16,
    /// V4 change extents (empty for V2/V3).
    pub extents: Vec<UsnExtent>,
    /// V4 RemainingExtents field (0 for V2/V3).
    pub remaining_extents: u32,
}

/// Reason flags for USN Journal records
#[allow(dead_code)]
pub mod reason_flags {
    pub const DATA_OVERWRITE: u32 = 0x00000001;
    pub const DATA_EXTEND: u32 = 0x00000002;
    pub const DATA_TRUNCATION: u32 = 0x00000004;
    pub const NAMED_DATA_OVERWRITE: u32 = 0x00000010;
    pub const NAMED_DATA_EXTEND: u32 = 0x00000020;
    pub const NAMED_DATA_TRUNCATION: u32 = 0x00000040;
    pub const FILE_CREATE: u32 = 0x00000100;
    pub const FILE_DELETE: u32 = 0x00000200;
    pub const EA_CHANGE: u32 = 0x00000400;
    pub const SECURITY_CHANGE: u32 = 0x00000800;
    pub const RENAME_OLD_NAME: u32 = 0x00001000;
    pub const RENAME_NEW_NAME: u32 = 0x00002000;
    pub const INDEXABLE_CHANGE: u32 = 0x00004000;
    pub const BASIC_INFO_CHANGE: u32 = 0x00008000;
    pub const HARD_LINK_CHANGE: u32 = 0x00010000;
    pub const COMPRESSION_CHANGE: u32 = 0x00020000;
    pub const ENCRYPTION_CHANGE: u32 = 0x00040000;
    pub const OBJECT_ID_CHANGE: u32 = 0x00080000;
    pub const REPARSE_POINT_CHANGE: u32 = 0x00100000;
    pub const STREAM_CHANGE: u32 = 0x00200000;
    pub const TRANSACTED_CHANGE: u32 = 0x00400000;
    pub const INTEGRITY_CHANGE: u32 = 0x00800000;
    pub const DESIRED_STORAGE_CLASS_CHANGE: u32 = 0x01000000;
    pub const CLOSE: u32 = 0x80000000;
}

/// Convert reason flags to human-readable strings
pub fn decode_reason_flags(flags: u32) -> Vec<String> {
    let mut reasons = Vec::new();

    if flags & reason_flags::DATA_OVERWRITE != 0 {
        reasons.push("DATA_OVERWRITE".to_string());
    }
    if flags & reason_flags::DATA_EXTEND != 0 {
        reasons.push("DATA_EXTEND".to_string());
    }
    if flags & reason_flags::DATA_TRUNCATION != 0 {
        reasons.push("DATA_TRUNCATION".to_string());
    }
    if flags & reason_flags::NAMED_DATA_OVERWRITE != 0 {
        reasons.push("NAMED_DATA_OVERWRITE".to_string());
    }
    if flags & reason_flags::NAMED_DATA_EXTEND != 0 {
        reasons.push("NAMED_DATA_EXTEND".to_string());
    }
    if flags & reason_flags::NAMED_DATA_TRUNCATION != 0 {
        reasons.push("NAMED_DATA_TRUNCATION".to_string());
    }
    if flags & reason_flags::FILE_CREATE != 0 {
        reasons.push("FILE_CREATE".to_string());
    }
    if flags & reason_flags::FILE_DELETE != 0 {
        reasons.push("FILE_DELETE".to_string());
    }
    if flags & reason_flags::EA_CHANGE != 0 {
        reasons.push("EA_CHANGE".to_string());
    }
    if flags & reason_flags::SECURITY_CHANGE != 0 {
        reasons.push("SECURITY_CHANGE".to_string());
    }
    if flags & reason_flags::RENAME_OLD_NAME != 0 {
        reasons.push("RENAME_OLD_NAME".to_string());
    }
    if flags & reason_flags::RENAME_NEW_NAME != 0 {
        reasons.push("RENAME_NEW_NAME".to_string());
    }
    if flags & reason_flags::INDEXABLE_CHANGE != 0 {
        reasons.push("INDEXABLE_CHANGE".to_string());
    }
    if flags & reason_flags::BASIC_INFO_CHANGE != 0 {
        reasons.push("BASIC_INFO_CHANGE".to_string());
    }
    if flags & reason_flags::HARD_LINK_CHANGE != 0 {
        reasons.push("HARD_LINK_CHANGE".to_string());
    }
    if flags & reason_flags::COMPRESSION_CHANGE != 0 {
        reasons.push("COMPRESSION_CHANGE".to_string());
    }
    if flags & reason_flags::ENCRYPTION_CHANGE != 0 {
        reasons.push("ENCRYPTION_CHANGE".to_string());
    }
    if flags & reason_flags::OBJECT_ID_CHANGE != 0 {
        reasons.push("OBJECT_ID_CHANGE".to_string());
    }
    if flags & reason_flags::REPARSE_POINT_CHANGE != 0 {
        reasons.push("REPARSE_POINT_CHANGE".to_string());
    }
    if flags & reason_flags::STREAM_CHANGE != 0 {
        reasons.push("STREAM_CHANGE".to_string());
    }
    if flags & reason_flags::TRANSACTED_CHANGE != 0 {
        reasons.push("TRANSACTED_CHANGE".to_string());
    }
    if flags & reason_flags::INTEGRITY_CHANGE != 0 {
        reasons.push("INTEGRITY_CHANGE".to_string());
    }
    if flags & reason_flags::DESIRED_STORAGE_CLASS_CHANGE != 0 {
        reasons.push("DESIRED_STORAGE_CLASS_CHANGE".to_string());
    }
    if flags & reason_flags::CLOSE != 0 {
        reasons.push("CLOSE".to_string());
    }

    reasons
}

/// Format file reference number
pub fn format_file_reference(frn_lo: u64, frn_hi: u64) -> String {
    if frn_hi == 0 {
        // V2 format: extract record number (48 bits) and sequence number (16 bits)
        let record_number = frn_lo & 0x0000FFFFFFFFFFFF;
        let sequence_number = frn_lo >> 48;
        format!("{}-{}", record_number, sequence_number)
    } else {
        // V3+ format: use full 128-bit reference
        format!("{:X}-{:X}", frn_lo, frn_hi)
    }
}

/// Determine primary operation from reason flags
pub fn primary_operation(flags: u32) -> String {
    if flags & reason_flags::FILE_CREATE != 0 {
        return "FILE_CREATE".to_string();
    }
    if flags & reason_flags::FILE_DELETE != 0 {
        return "FILE_DELETE".to_string();
    }
    if flags & (reason_flags::RENAME_OLD_NAME | reason_flags::RENAME_NEW_NAME) != 0 {
        return "RENAME".to_string();
    }
    if flags
        & (reason_flags::DATA_OVERWRITE | reason_flags::DATA_EXTEND | reason_flags::DATA_TRUNCATION)
        != 0
    {
        return "DATA_MODIFY".to_string();
    }
    if flags & reason_flags::SECURITY_CHANGE != 0 {
        return "SECURITY_CHANGE".to_string();
    }
    if flags & reason_flags::CLOSE != 0 {
        return "CLOSE".to_string();
    }
    "UNKNOWN".to_string()
}
