/// VSS (Volume Shadow Snapshot) format structures
/// Based on libvshadow specification: https://github.com/libyal/libvshadow
use serde::{Deserialize, Serialize};

// VSS uses 16 KiB blocks
pub const VSS_BLOCK_SIZE: u64 = 16384;

// Volume header is located at offset 7680 (0x1e00) and is 512 bytes
pub const VSS_VOLUME_HEADER_OFFSET: u64 = 7680;
pub const VSS_VOLUME_HEADER_SIZE: usize = 512;

// Catalog and store block headers are 128 bytes
pub const VSS_BLOCK_HEADER_SIZE: usize = 128;

// Catalog entries are 128 bytes each
pub const VSS_CATALOG_ENTRY_SIZE: usize = 128;

// Record types
pub const VSS_RECORD_TYPE_VOLUME_HEADER: u32 = 0x01;
pub const VSS_RECORD_TYPE_CATALOG_BLOCK: u32 = 0x02;
pub const VSS_RECORD_TYPE_BLOCK_DESCRIPTOR: u32 = 0x03;
pub const VSS_RECORD_TYPE_DIFF_AREA_TABLE: u32 = 0x03;
pub const VSS_RECORD_TYPE_STORE_HEADER: u32 = 0x04;
pub const VSS_RECORD_TYPE_BLOCK_RANGE_LIST: u32 = 0x05;
pub const VSS_RECORD_TYPE_STORE_BITMAP: u32 = 0x06;

/// The diff-area/shadow-block GUID that prefixes every VSS shadow block
/// (3808876b-c176-4e48-b7ae-04046e6cc752), stored little-endian.
pub const VSS_DIFF_AREA_GUID: [u8; 16] = [
    0x6B, 0x87, 0x08, 0x38, 0x76, 0xC1, 0x48, 0x4E, 0xB7, 0xAE, 0x04, 0x04, 0x6E, 0x6C, 0xC7, 0x52,
];

// Catalog entry types
pub const VSS_CATALOG_ENTRY_TYPE_UNUSED: u64 = 0x01;
pub const VSS_CATALOG_ENTRY_TYPE_SNAPSHOT: u64 = 0x02;
pub const VSS_CATALOG_ENTRY_TYPE_STORE: u64 = 0x03;

// Diff-area table entry flags (see dfir_ntfs ShadowCopy.py). Exactly one of
// FORWARDER / OVERLAY may be set on an entry.
pub const DIFF_AREA_ENTRY_FORWARDER: u32 = 0x1; // resolve data via the next store (forward offset)
pub const DIFF_AREA_ENTRY_OVERLAY: u32 = 0x2; // partial block; allocation_bitmap selects 512B sectors
pub const DIFF_AREA_ENTRY_IGNORE: u32 = 0x4; // entry should be ignored

// Store flag: when set, blocks marked "used" in the store bitmap read as null
// bytes; when unset such blocks fall through to the original volume's data.
pub const STORE_FLAG_NULLIFY_UNUSED: u64 = 0x400;

// A 16 KiB VSS block holds 32 physical 512-byte sectors.
pub const VSS_SECTOR_SIZE: u64 = 512;
pub const VSS_SECTORS_PER_BLOCK: usize = (VSS_BLOCK_SIZE / VSS_SECTOR_SIZE) as usize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssVolumeHeader {
    pub identifier: [u8; 16], // GUID
    pub version: u32,
    pub record_type: u32,
    pub current_offset: u64,
    pub unknown_offset: u64,
    pub catalog_offset: u64,
    pub max_size: u64,
    pub volume_identifier: [u8; 16],         // GUID
    pub storage_volume_identifier: [u8; 16], // GUID
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssCatalogBlockHeader {
    pub identifier: [u8; 16], // GUID
    pub version: u32,
    pub record_type: u32,
    pub relative_offset: u64,
    pub current_offset: u64,
    pub next_offset: u64, // 0 if last block
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssStoreHeader {
    pub identifier: [u8; 16], // GUID
    pub version: u32,
    pub record_type: u32,
    pub relative_offset: u64,
    pub current_offset: u64,
    pub next_offset: u64,
    pub store_info_size: u64, // Only in first block
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssSnapshotEntry {
    pub store_identifier: [u8; 16], // GUID
    pub volume_size: u64,
    pub stack_position: u64, // position of this store in the shadow-copy stack
    pub attribute_flags: u64,
    pub creation_timestamp: u64, // FILETIME
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssStoreEntry {
    pub block_list_offset: u64,
    pub store_identifier: [u8; 16], // GUID
    pub store_header_offset: u64,
    pub block_range_list_offset: u64,
    pub bitmap_offset: u64,
    pub previous_bitmap_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssSnapshot {
    pub snapshot_id: String, // GUID as string
    pub store_id: String,    // GUID as string
    pub volume_size: u64,
    pub creation_time: String,
    pub store_header_offset: u64,
    pub block_list_offset: u64, // diff-area table chain start (store entry)
    pub bitmap_offset: u64,     // store bitmap chain start
    pub previous_bitmap_offset: u64, // previous-store bitmap chain start
    pub stack_position: u64,    // position in the shadow-copy stack (snapshot entry)
    pub attribute_flags: u64,   // store flags (snapshot entry)
    pub has_store_entry: bool,  // a matching type-3 store entry was found
}

// GUID rendering lives in `seance_core::guid::format_guid` — the single
// implementation of the Microsoft mixed-endian convention.
