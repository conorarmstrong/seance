// exFAT structures

use byteorder::{ByteOrder, LittleEndian};

// Decoded in full from the on-disk record. Fields the parser does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ExFatBootSector {
    pub bytes_per_sector_shift: u8,    // Power of 2
    pub sectors_per_cluster_shift: u8, // Power of 2
    pub number_of_fats: u8,
    pub fat_offset: u32,          // Sector offset to FAT
    pub fat_length: u32,          // FAT size in sectors
    pub cluster_heap_offset: u32, // Sector offset to data
    pub cluster_count: u32,
    pub root_directory_cluster: u32,
    pub volume_serial_number: u32,
    pub volume_flags: u16,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u16,
}

impl ExFatBootSector {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 512 {
            return Err("Boot sector too small".to_string());
        }

        // Verify exFAT signature
        if &data[3..11] != b"EXFAT   " {
            return Err("Not an exFAT filesystem".to_string());
        }

        // Verify boot signature
        if data[510] != 0x55 || data[511] != 0xAA {
            return Err("Invalid boot signature".to_string());
        }

        let bytes_per_sector_shift = data[108];
        let sectors_per_cluster_shift = data[109];
        let number_of_fats = data[110];

        // These two shift bytes are attacker-controlled. Per the exFAT spec
        // BytesPerSectorShift is 9..=12 (512..=4096) and SectorsPerClusterShift
        // is 0..=(25 - BytesPerSectorShift) (cluster size <= 32 MiB). Validate
        // BEFORE the `1u16 << shift` below: an out-of-range shift is a
        // shift-amount overflow that panics in debug builds and silently masks
        // the amount in release (yielding bogus geometry that corrupts every
        // downstream offset). The `<= 15` bound also keeps
        // `1u16 << sectors_per_cluster_shift` from overflowing the u16 result.
        if !(9..=12).contains(&bytes_per_sector_shift)
            || sectors_per_cluster_shift > 15
            || (bytes_per_sector_shift as u32 + sectors_per_cluster_shift as u32) > 25
        {
            return Err(format!(
                "Invalid exFAT geometry: bytes_per_sector_shift={bytes_per_sector_shift}, sectors_per_cluster_shift={sectors_per_cluster_shift}"
            ));
        }

        let fat_offset = LittleEndian::read_u32(&data[80..84]);
        let fat_length = LittleEndian::read_u32(&data[84..88]);
        let cluster_heap_offset = LittleEndian::read_u32(&data[88..92]);
        let cluster_count = LittleEndian::read_u32(&data[92..96]);
        let root_directory_cluster = LittleEndian::read_u32(&data[96..100]);
        let volume_serial_number = LittleEndian::read_u32(&data[100..104]);
        let volume_flags = LittleEndian::read_u16(&data[106..108]);

        // Calculate actual values from shifts
        let bytes_per_sector = 1u16 << bytes_per_sector_shift;
        let sectors_per_cluster = 1u16 << sectors_per_cluster_shift;

        Ok(ExFatBootSector {
            bytes_per_sector_shift,
            sectors_per_cluster_shift,
            number_of_fats,
            fat_offset,
            fat_length,
            cluster_heap_offset,
            cluster_count,
            root_directory_cluster,
            volume_serial_number,
            volume_flags,
            bytes_per_sector,
            sectors_per_cluster,
        })
    }

    pub fn cluster_to_offset(&self, cluster: u32) -> u64 {
        // Cluster numbers start at 2. Saturate rather than underflow-panic on a
        // cluster < 2 (callers filter these, but keep the helper crash-proof,
        // matching the FAT sibling in fat_structs.rs).
        let cluster_offset = cluster.saturating_sub(2) as u64;
        let sector =
            self.cluster_heap_offset as u64 + (cluster_offset * self.sectors_per_cluster as u64);
        sector * self.bytes_per_sector as u64
    }
}

// exFAT Directory Entry Types
#[derive(Debug, Clone, PartialEq)]
pub enum ExFatEntryType {
    EndOfDirectory,
    AllocationBitmap,
    UpCaseTable,
    VolumeLabel,
    FileEntry,
    /// `0x05`: a file entry whose InUse bit was cleared by deletion.
    DeletedFileEntry,
    VolumeGuid,
    StreamExtension,
    FileName,
    Unknown(u8),
}

impl From<u8> for ExFatEntryType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ExFatEntryType::EndOfDirectory,
            0x81 => ExFatEntryType::AllocationBitmap,
            0x82 => ExFatEntryType::UpCaseTable,
            0x83 => ExFatEntryType::VolumeLabel,
            0x85 => ExFatEntryType::FileEntry,
            // Bit 7 is InUse. A file entry with it cleared is a deleted file:
            // exFAT clears the bit on the primary and each secondary and leaves
            // the set — name, size, timestamps, first cluster — in place.
            0x05 => ExFatEntryType::DeletedFileEntry,
            0xA0 => ExFatEntryType::VolumeGuid,
            0xC0 => ExFatEntryType::StreamExtension,
            0xC1 => ExFatEntryType::FileName,
            _ => ExFatEntryType::Unknown(value),
        }
    }
}

// Decoded in full from the on-disk record. Fields the parser does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ExFatFileEntry {
    pub entry_type: u8,
    pub secondary_count: u8, // Number of following secondary entries
    pub set_checksum: u16,
    pub file_attributes: u16,
    pub create_timestamp: u32,
    pub modify_timestamp: u32,
    pub access_timestamp: u32,
    pub create_10ms: u8,
    pub modify_10ms: u8,
    pub create_utc_offset: u8,
    pub modify_utc_offset: u8,
    pub access_utc_offset: u8,
}

impl ExFatFileEntry {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 32 {
            return Err("Entry too small".to_string());
        }

        Ok(ExFatFileEntry {
            entry_type: data[0],
            secondary_count: data[1],
            set_checksum: LittleEndian::read_u16(&data[2..4]),
            file_attributes: LittleEndian::read_u16(&data[4..6]),
            create_timestamp: LittleEndian::read_u32(&data[8..12]),
            modify_timestamp: LittleEndian::read_u32(&data[12..16]),
            access_timestamp: LittleEndian::read_u32(&data[16..20]),
            create_10ms: data[20],
            modify_10ms: data[21],
            create_utc_offset: data[22],
            modify_utc_offset: data[23],
            access_utc_offset: data[24],
        })
    }

    pub fn is_directory(&self) -> bool {
        (self.file_attributes & 0x0010) != 0
    }
}

/// Allocation Bitmap directory entry (type 0x81)
#[derive(Debug, Clone)]
pub struct ExFatAllocationBitmap {
    pub bitmap_flags: u8,
    pub first_cluster: u32,
    pub data_length: u64,
}

impl ExFatAllocationBitmap {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 32 {
            return Err("Entry too small".to_string());
        }

        Ok(ExFatAllocationBitmap {
            bitmap_flags: data[1],
            first_cluster: LittleEndian::read_u32(&data[20..24]),
            data_length: LittleEndian::read_u64(&data[24..32]),
        })
    }

    /// Bit 0 clear = first allocation bitmap (the second exists only on TexFAT)
    pub fn is_first_bitmap(&self) -> bool {
        (self.bitmap_flags & 0x01) == 0
    }
}

// Decoded in full from the on-disk record. Fields the parser does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ExFatStreamExtension {
    pub entry_type: u8,
    pub flags: u8,
    pub name_length: u8, // Length of filename in characters
    pub name_hash: u16,
    pub valid_data_length: u64,
    pub first_cluster: u32,
    pub data_length: u64,
}

impl ExFatStreamExtension {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 32 {
            return Err("Entry too small".to_string());
        }

        Ok(ExFatStreamExtension {
            entry_type: data[0],
            flags: data[1],
            name_length: data[3],
            name_hash: LittleEndian::read_u16(&data[4..6]),
            valid_data_length: LittleEndian::read_u64(&data[8..16]),
            first_cluster: LittleEndian::read_u32(&data[20..24]),
            data_length: LittleEndian::read_u64(&data[24..32]),
        })
    }

    pub fn is_contiguous(&self) -> bool {
        (self.flags & 0x02) != 0
    }
}

// Decoded in full from the on-disk record. Fields the parser does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ExFatFileName {
    pub entry_type: u8,
    pub flags: u8,
    pub name_chars: Vec<u16>, // UTF-16 characters (15 per entry)
}

impl ExFatFileName {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 32 {
            return Err("Entry too small".to_string());
        }

        let mut name_chars = Vec::new();
        for i in 0..15 {
            let offset = 2 + (i * 2);
            let ch = LittleEndian::read_u16(&data[offset..offset + 2]);
            if ch != 0 {
                name_chars.push(ch);
            }
        }

        Ok(ExFatFileName {
            entry_type: data[0],
            flags: data[1],
            name_chars,
        })
    }
}

// Complete exFAT directory entry set
#[derive(Debug, Clone)]
pub struct ExFatDirectoryEntrySet {
    pub file_entry: ExFatFileEntry,
    pub stream_extension: ExFatStreamExtension,
    pub file_names: Vec<ExFatFileName>,
    /// The set's InUse bits were cleared: this is a deleted file whose entry
    /// the directory still holds whole. Its clusters are not vouched for.
    pub deleted: bool,
    /// Read from the end marker's own cluster behind the marker (`HUNT-278`): an earlier state of the
    /// directory left behind, state unknown. Only a set whose SetChecksum verifies is kept.
    pub after_end_marker: bool,
}

impl ExFatDirectoryEntrySet {
    pub fn get_filename(&self) -> String {
        let chars: Vec<u16> = self
            .file_names
            .iter()
            .flat_map(|f| f.name_chars.iter())
            .take(self.stream_extension.name_length as usize)
            .copied()
            .collect();

        String::from_utf16_lossy(&chars)
    }
}
