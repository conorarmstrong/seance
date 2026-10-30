use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, NaiveDate, Utc};
use seance_core::codepage::{self, CodePage};
use std::io::{Cursor, Read};

/// The code page FAT's byte-encoded names are read through.
///
/// FAT stores 8.3 short names, volume labels and the filesystem-type signature
/// as OEM bytes with no encoding declaration, so a table has to be assumed;
/// CP437 is the original DOS/US set and the default on Western systems. A
/// volume formatted under a different OEM code page holds the same bytes for
/// different characters, which is why every record carrying a decoded name is
/// stamped with the table used rather than presenting the name as literal.
pub const FAT_OEM_CODE_PAGE: CodePage = CodePage::Cp437;

/// The extended boot signature. Its presence is what declares that the volume
/// id, volume label and filesystem-type fields exist; without it those offsets
/// hold whatever the formatter left there.
pub const EXTENDED_BOOT_SIGNATURE: u8 = 0x29;

/// Strip the ASCII space padding FAT uses for its fixed-width name fields.
///
/// Deliberately not `str::trim`: that removes every Unicode whitespace
/// character, and CP437 byte 0xFF decodes to U+00A0 (no-break space). A name
/// or label ending in 0xFF would silently lose its last character, which is
/// the opposite of what decoding these fields properly is for. FAT pads with
/// 0x20 and nothing else.
fn trim_oem_padding(s: &str) -> String {
    s.trim_matches(' ').to_string()
}

/// FAT filesystem type.
///
/// exFAT is not a variant: it shares nothing but a name with FAT12/16/32 —
/// bitmap allocation, a different directory entry set, a different FAT — and
/// is parsed by `exfat_parser`, which has its own types.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

/// BIOS Parameter Block (common to FAT12/16/32)
// Decoded in full from the on-disk record. Fields the parser does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BiosParameterBlock {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entries: u16,     // FAT12/16 only, 0 for FAT32
    pub total_sectors_16: u16, // If 0, use total_sectors_32
    pub media_descriptor: u8,
    pub sectors_per_fat_16: u16, // FAT12/16 only, 0 for FAT32
    pub sectors_per_track: u16,
    pub num_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    /// The non-standard 64-bit sector count at boot-sector offset 82, read
    /// only on a FAT32-shaped BPB carrying the 0x29 extended boot signature
    /// with both standard counts zero (the condition `dfir_ntfs` uses in
    /// `get_bs_totsec64`); 0 otherwise. On any other FAT32 volume those bytes
    /// are the file-system-type string, not a count.
    pub total_sectors_64: u64,
}

/// Extended BPB for FAT32
// Decoded in full from the on-disk record. Fields the parser does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Fat32ExtendedBpb {
    pub sectors_per_fat_32: u32,
    pub flags: u16,
    pub version: u16,
    pub root_cluster: u32,
    pub fsinfo_sector: u16,
    pub backup_boot_sector: u16,
    pub drive_number: u8,
    pub volume_id: u32,
    pub volume_label: String,
    /// The OEM code page `volume_label` was decoded through, set only when the
    /// label held a byte outside ASCII (see [`FAT_OEM_CODE_PAGE`]).
    pub volume_label_decode: Option<&'static str>,
    pub filesystem_type: String,
}

/// Extended BPB for FAT12/16
// Decoded in full from the on-disk record. Fields the parser does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Fat16ExtendedBpb {
    pub drive_number: u8,
    pub volume_id: u32,
    pub volume_label: String,
    /// The OEM code page `volume_label` was decoded through, set only when the
    /// label held a byte outside ASCII (see [`FAT_OEM_CODE_PAGE`]).
    pub volume_label_decode: Option<&'static str>,
    pub filesystem_type: String,
}

/// Complete boot sector
#[derive(Debug, Clone)]
pub struct FatBootSector {
    pub bpb: BiosParameterBlock,
    pub extended: FatExtendedBpb,
    pub fat_type: FatType,
}

impl FatBootSector {
    pub fn cluster_size_bytes(&self) -> usize {
        self.bpb.bytes_per_sector as usize * self.bpb.sectors_per_cluster as usize
    }

    pub fn cluster_to_offset(&self, cluster: u32) -> u64 {
        let sectors_per_fat = match &self.extended {
            FatExtendedBpb::Fat32(ext) => ext.sectors_per_fat_32,
            FatExtendedBpb::Fat16(_) => self.bpb.sectors_per_fat_16 as u32,
        };

        // All operands derive from attacker-controlled BPB fields; saturate so a
        // crafted geometry produces an out-of-range (bounded) offset instead of
        // overflowing. The resulting read is bounded by the data source.
        let bps = (self.bpb.bytes_per_sector as u32).max(1);
        let root_dir_sectors = (self.bpb.root_entries as u32)
            .saturating_mul(32)
            .div_ceil(bps);
        let first_data_sector = (self.bpb.reserved_sectors as u32)
            .saturating_add((self.bpb.num_fats as u32).saturating_mul(sectors_per_fat))
            .saturating_add(root_dir_sectors);

        let cluster_offset = cluster.saturating_sub(2);
        let sector = first_data_sector
            .saturating_add(cluster_offset.saturating_mul(self.bpb.sectors_per_cluster as u32));

        sector as u64 * self.bpb.bytes_per_sector as u64
    }
}

// Decoded in full from the on-disk record. Fields the parser does not yet
// consult are kept — the decode is the record, and dropping a field would turn
// a faithful structure into a partial one — so the unused-field lint is
// silenced for this struct only, not the crate.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum FatExtendedBpb {
    Fat32(Fat32ExtendedBpb),
    Fat16(Fat16ExtendedBpb),
}

/// FAT directory entry (32 bytes)
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub name: [u8; 11], // 8.3 filename
    pub attributes: u8,
    pub reserved: u8,
    pub creation_time_tenth: u8,
    pub creation_time: u16,
    pub creation_date: u16,
    pub access_date: u16,
    pub first_cluster_high: u16, // FAT32 only
    pub modification_time: u16,
    pub modification_date: u16,
    pub first_cluster_low: u16,
    pub file_size: u32,
}

/// Long File Name (LFN) entry
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LfnEntry {
    pub sequence: u8,
    pub name1: [u16; 5],
    pub attributes: u8, // Always 0x0F
    pub entry_type: u8, // Always 0x00
    pub checksum: u8,
    pub name2: [u16; 6],
    pub first_cluster: u16, // Always 0x0000
    pub name3: [u16; 2],
}

// Directory entry attributes
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LONG_NAME: u8 = 0x0F;

// Special cluster values
pub const FAT12_END_OF_CHAIN: u16 = 0x0FF8;
pub const FAT16_END_OF_CHAIN: u16 = 0xFFF8;
pub const FAT32_END_OF_CHAIN: u32 = 0x0FFFFFF8;
pub const FAT32_CLUSTER_MASK: u32 = 0x0FFFFFFF;

impl BiosParameterBlock {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 512 {
            return Err("Boot sector too small".to_string());
        }

        let mut cursor = Cursor::new(data);

        // Skip jump instruction (3 bytes) and OEM name (8 bytes)
        cursor.set_position(11);

        Ok(BiosParameterBlock {
            bytes_per_sector: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            sectors_per_cluster: cursor.read_u8().map_err(|e| e.to_string())?,
            reserved_sectors: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            num_fats: cursor.read_u8().map_err(|e| e.to_string())?,
            root_entries: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            total_sectors_16: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            media_descriptor: cursor.read_u8().map_err(|e| e.to_string())?,
            sectors_per_fat_16: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            sectors_per_track: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            num_heads: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            hidden_sectors: cursor
                .read_u32::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            total_sectors_32: cursor
                .read_u32::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            total_sectors_64: 0,
        }
        .with_totsec64(data))
    }

    /// Read the 64-bit sector count (HUNT-157) when, and only when, the boot
    /// sector is FAT32-shaped (no root entries, no 16-bit FAT size, a nonzero
    /// 32-bit FAT size at offset 36), carries the 0x29 extended boot
    /// signature at offset 66, and both standard counts are zero.
    fn with_totsec64(mut self, data: &[u8]) -> Self {
        let fatsz32 = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        if self.total_sectors_16 == 0
            && self.total_sectors_32 == 0
            && self.root_entries == 0
            && self.sectors_per_fat_16 == 0
            && fatsz32 > 0
            && data[66] == EXTENDED_BOOT_SIGNATURE
        {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&data[82..90]);
            self.total_sectors_64 = u64::from_le_bytes(raw);
        }
        self
    }

    pub fn total_sectors(&self) -> u64 {
        if self.total_sectors_16 != 0 {
            self.total_sectors_16 as u64
        } else if self.total_sectors_32 != 0 {
            self.total_sectors_32 as u64
        } else {
            self.total_sectors_64
        }
    }

    /// Which boot-sector field the sector count came from.
    pub fn total_sectors_source(&self) -> &'static str {
        if self.total_sectors_16 != 0 {
            "bpb_totsec16"
        } else if self.total_sectors_32 != 0 {
            "bpb_totsec32"
        } else if self.total_sectors_64 != 0 {
            "bs_totsec64"
        } else {
            "none"
        }
    }

    pub fn sectors_per_fat(&self) -> u32 {
        if self.sectors_per_fat_16 != 0 {
            self.sectors_per_fat_16 as u32
        } else {
            0 // Must be read from FAT32 extended BPB
        }
    }

    pub fn root_dir_sectors(&self) -> u32 {
        (self.root_entries as u32 * 32).div_ceil(self.bytes_per_sector as u32)
    }

    pub fn data_sectors(&self, sectors_per_fat: u32) -> u32 {
        // reserved + num_fats*sectors_per_fat + root_dir_sectors can exceed the
        // total sector count on a malformed BPB. Compute the metadata region in
        // u64 (so num_fats*sectors_per_fat can't overflow) and saturate the
        // subtraction so we report 0 usable sectors instead of underflowing.
        let metadata_sectors = (self.reserved_sectors as u64)
            + (self.num_fats as u64 * sectors_per_fat as u64)
            + (self.root_dir_sectors() as u64);
        // A 64-bit count can exceed what a u32 holds; FAT32 addresses at most
        // 2^28 clusters, so saturating here loses nothing a FAT can reach.
        self.total_sectors()
            .saturating_sub(metadata_sectors)
            .min(u32::MAX as u64) as u32
    }

    pub fn total_clusters(&self, sectors_per_fat: u32) -> u32 {
        self.data_sectors(sectors_per_fat) / self.sectors_per_cluster as u32
    }

    /// True when the boot sector is laid out as FAT32: no 16-bit FAT size, so
    /// the FAT size and the root cluster live in the FAT32 extended BPB and the
    /// root directory is a cluster chain. The layout, not the cluster count,
    /// decides which extended BPB to decode, how large the FAT is and where the
    /// root directory sits; reading those from the field the cluster count
    /// implies would size a FAT32 volume's FAT from a field that is zero.
    pub fn is_fat32_layout(&self) -> bool {
        self.sectors_per_fat_16 == 0
    }

    /// Why this BPB cannot be one coherent layout, when it cannot. FAT32 has no
    /// fixed root directory (`root_entries == 0`) and FAT12/16 must have one;
    /// a BPB that mixes the two does not say where the root directory is, so
    /// the root listing is refused rather than read as empty.
    pub fn layout_inconsistency(&self) -> Option<&'static str> {
        (self.is_fat32_layout() != (self.root_entries == 0))
            .then_some("fat_bpb_layout_inconsistent")
    }

    /// The type the Microsoft FAT specification names for this cluster count,
    /// whatever the layout.
    pub fn fat_type_by_cluster_count(&self, sectors_per_fat: u32) -> FatType {
        let clusters = self.total_clusters(sectors_per_fat);

        if clusters < 4085 {
            FatType::Fat12
        } else if clusters < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        }
    }

    /// The FAT entry width this volume is read with. A FAT32 layout is always
    /// read with 32-bit entries, as Linux does, even when its cluster count is
    /// below the spec's 65,525 (a small `mkfs.fat -F32` image); a FAT12/16
    /// layout is never read as FAT32, even with 65,525 or more clusters,
    /// because its BPB has no FAT32 fields to read. The cluster count only
    /// picks between 12 and 16 bits. [`Self::fat_type_by_cluster_count`] is
    /// what the count alone says, kept so a disagreement can be recorded.
    pub fn determine_fat_type(&self, sectors_per_fat: u32) -> FatType {
        if self.is_fat32_layout() {
            return FatType::Fat32;
        }
        match self.fat_type_by_cluster_count(sectors_per_fat) {
            FatType::Fat12 => FatType::Fat12,
            _ => FatType::Fat16,
        }
    }
}

impl Fat32ExtendedBpb {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let mut cursor = Cursor::new(&data[36..]); // Start at offset 36

        let sectors_per_fat_32 = cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| e.to_string())?;
        let flags = cursor
            .read_u16::<LittleEndian>()
            .map_err(|e| e.to_string())?;
        let version = cursor
            .read_u16::<LittleEndian>()
            .map_err(|e| e.to_string())?;
        let root_cluster = cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| e.to_string())?;
        let fsinfo_sector = cursor
            .read_u16::<LittleEndian>()
            .map_err(|e| e.to_string())?;
        let backup_boot_sector = cursor
            .read_u16::<LittleEndian>()
            .map_err(|e| e.to_string())?;

        // Skip reserved (12 bytes)
        cursor.set_position(cursor.position() + 12);

        let drive_number = cursor.read_u8().map_err(|e| e.to_string())?;
        cursor.read_u8().map_err(|e| e.to_string())?; // Reserved
                                                      // The extended boot signature. 0x29 is what says the volume id, label
                                                      // and filesystem-type fields below exist at all. Reading it and
                                                      // discarding it meant that on a volume without an extended BPB -- which
                                                      // includes many FAT12 floppies -- the arbitrary bytes sitting at those
                                                      // offsets were read as a label anyway, and the allocation-map record
                                                      // carried a volume label that is not a label (FAT-001). Decoding those
                                                      // bytes through CP437 rather than mangling them to U+FFFD made this
                                                      // worse, not better: the garbage now renders as plausible text.
        let extended_signature = cursor.read_u8().map_err(|e| e.to_string())?;
        let extended_present = extended_signature == EXTENDED_BOOT_SIGNATURE;
        let volume_id = cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| e.to_string())?;

        let mut volume_label = vec![0u8; 11];
        cursor
            .read_exact(&mut volume_label)
            .map_err(|e| e.to_string())?;
        // Absent the signature these bytes mean nothing, so they are left
        // unset rather than presented as a name somebody gave the volume.
        let (volume_label, label_decoded) = if extended_present {
            codepage::decode(&volume_label, FAT_OEM_CODE_PAGE)
        } else {
            (String::new(), false)
        };
        let volume_label = trim_oem_padding(&volume_label);

        let mut filesystem_type = vec![0u8; 8];
        cursor
            .read_exact(&mut filesystem_type)
            .map_err(|e| e.to_string())?;
        // The filesystem-type signature ("FAT32   ") is an OEM field like the
        // label, so it goes through the same table; it is not emitted on any
        // record, so there is nothing to stamp its decoding on.
        let filesystem_type = if extended_present {
            trim_oem_padding(&codepage::decode(&filesystem_type, FAT_OEM_CODE_PAGE).0)
        } else {
            String::new()
        };

        Ok(Fat32ExtendedBpb {
            sectors_per_fat_32,
            flags,
            version,
            root_cluster,
            fsinfo_sector,
            backup_boot_sector,
            drive_number,
            volume_id,
            volume_label,
            volume_label_decode: label_decoded.then_some(FAT_OEM_CODE_PAGE.name()),
            filesystem_type,
        })
    }
}

impl Fat16ExtendedBpb {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let mut cursor = Cursor::new(&data[36..]); // Start at offset 36

        let drive_number = cursor.read_u8().map_err(|e| e.to_string())?;
        cursor.read_u8().map_err(|e| e.to_string())?; // Reserved
                                                      // The extended boot signature. 0x29 is what says the volume id, label
                                                      // and filesystem-type fields below exist at all. Reading it and
                                                      // discarding it meant that on a volume without an extended BPB -- which
                                                      // includes many FAT12 floppies -- the arbitrary bytes sitting at those
                                                      // offsets were read as a label anyway, and the allocation-map record
                                                      // carried a volume label that is not a label (FAT-001). Decoding those
                                                      // bytes through CP437 rather than mangling them to U+FFFD made this
                                                      // worse, not better: the garbage now renders as plausible text.
        let extended_signature = cursor.read_u8().map_err(|e| e.to_string())?;
        let extended_present = extended_signature == EXTENDED_BOOT_SIGNATURE;
        let volume_id = cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| e.to_string())?;

        let mut volume_label = vec![0u8; 11];
        cursor
            .read_exact(&mut volume_label)
            .map_err(|e| e.to_string())?;
        // Absent the signature these bytes mean nothing, so they are left
        // unset rather than presented as a name somebody gave the volume.
        let (volume_label, label_decoded) = if extended_present {
            codepage::decode(&volume_label, FAT_OEM_CODE_PAGE)
        } else {
            (String::new(), false)
        };
        let volume_label = trim_oem_padding(&volume_label);

        let mut filesystem_type = vec![0u8; 8];
        cursor
            .read_exact(&mut filesystem_type)
            .map_err(|e| e.to_string())?;
        // Same OEM field, same table; not emitted, so nothing to stamp.
        let filesystem_type = if extended_present {
            trim_oem_padding(&codepage::decode(&filesystem_type, FAT_OEM_CODE_PAGE).0)
        } else {
            String::new()
        };

        Ok(Fat16ExtendedBpb {
            drive_number,
            volume_id,
            volume_label,
            volume_label_decode: label_decoded.then_some(FAT_OEM_CODE_PAGE.name()),
            filesystem_type,
        })
    }
}

impl DirectoryEntry {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 32 {
            return Err("Directory entry too small".to_string());
        }

        let mut cursor = Cursor::new(data);

        let mut name = [0u8; 11];
        cursor.read_exact(&mut name).map_err(|e| e.to_string())?;

        Ok(DirectoryEntry {
            name,
            attributes: cursor.read_u8().map_err(|e| e.to_string())?,
            reserved: cursor.read_u8().map_err(|e| e.to_string())?,
            creation_time_tenth: cursor.read_u8().map_err(|e| e.to_string())?,
            creation_time: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            creation_date: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            access_date: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            first_cluster_high: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            modification_time: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            modification_date: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            first_cluster_low: cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?,
            file_size: cursor
                .read_u32::<LittleEndian>()
                .map_err(|e| e.to_string())?,
        })
    }

    // The walkers classify a slot from its raw bytes before deciding whether to
    // parse it as an 8.3 entry or an LFN slot, so these predicates have no
    // production caller; they pin the on-disk meaning in the unit tests.
    #[cfg(test)]
    pub fn is_deleted(&self) -> bool {
        self.name[0] == 0xE5
    }

    /// True when this slot's first name byte is the all-zero end-of-directory
    /// marker. Both directory walkers (root and cluster-chain) call this
    /// rather than re-testing `name[0] == 0x00` inline, so the on-disk meaning
    /// of the marker is defined in exactly one place.
    pub fn is_end_of_directory(&self) -> bool {
        self.name[0] == 0x00
    }

    #[cfg(test)]
    pub fn is_lfn(&self) -> bool {
        self.attributes == ATTR_LONG_NAME
    }

    pub fn is_volume_label(&self) -> bool {
        (self.attributes & ATTR_VOLUME_ID) != 0
    }

    pub fn is_directory(&self) -> bool {
        (self.attributes & ATTR_DIRECTORY) != 0
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_high as u32) << 16) | (self.first_cluster_low as u32)
    }

    /// The VFAT long-filename checksum over this entry's raw 8.3 name. Every LFN
    /// slot that belongs to this file stores this exact byte; validating it
    /// prevents a torn chain or an adjacent free slot from another file being
    /// attached as the wrong long name (BUG-163). Note: for a deleted entry the
    /// first name byte is the 0xE5 marker (unrecoverable), so this value will
    /// not match the slots' stored checksum.
    pub fn lfn_checksum(&self) -> u8 {
        let mut sum: u8 = 0;
        for &b in &self.name {
            // Rotate-right by one and add the next name byte, all wrapping u8.
            sum = (sum >> 1)
                .wrapping_add(if sum & 1 != 0 { 0x80 } else { 0 })
                .wrapping_add(b);
        }
        sum
    }

    /// The 8.3 short name, plus whether a byte outside ASCII had to be
    /// interpreted through the OEM code page.
    ///
    /// An 8.3 name is raw OEM bytes, not UTF-8. Running it through
    /// `String::from_utf8_lossy` turned every byte 0x80-0xFF into U+FFFD, so a
    /// file stored as `MÜLLER.DOC` (byte 0x9A for Ü) was listed as
    /// `M\u{FFFD}LLER.DOC`: a name matching no keyword search, no hash-set
    /// lookup and no witness statement. For a deleted entry, whose long-name
    /// slots are often gone, this is the only name that survives at all.
    pub fn get_short_name(&self) -> (String, bool) {
        if self.is_volume_label() {
            let (label, decoded) = codepage::decode(&self.name, FAT_OEM_CODE_PAGE);
            return (trim_oem_padding(&label), decoded);
        }

        let (base, base_decoded) = codepage::decode(&self.name[0..8], FAT_OEM_CODE_PAGE);
        let (ext, ext_decoded) = codepage::decode(&self.name[8..11], FAT_OEM_CODE_PAGE);
        let mut name_part = trim_oem_padding(&base);
        let mut ext_part = trim_oem_padding(&ext);
        let decoded = base_decoded || ext_decoded;

        // VFAT case-info byte (dir entry offset 12): bit 3 lowercases the base
        // name, bit 4 the extension. Windows/macOS set these for names that fit
        // 8.3 but differ only in case (e.g. "readme.txt"), avoiding a long-name
        // entry. Without this the parser reports the on-disk uppercase form.
        if self.reserved & 0x08 != 0 {
            name_part = name_part.to_lowercase();
        }
        if self.reserved & 0x10 != 0 {
            ext_part = ext_part.to_lowercase();
        }

        if ext_part.is_empty() {
            (name_part, decoded)
        } else {
            (format!("{}.{}", name_part, ext_part), decoded)
        }
    }

    /// Decode a DOS-packed date/time bitfield.
    ///
    /// FAT stores local wall-clock time; no timezone information exists on
    /// disk. The returned value is wrapped in DateTime<Utc> only to give it
    /// a concrete type — it is NOT true UTC. Callers must surface this by
    /// setting "timezone": "local" on artifacts carrying these timestamps
    /// (see create_file_artifact in fat_parser.rs).
    pub fn decode_datetime(date: u16, time: u16) -> Option<DateTime<Utc>> {
        if date == 0 {
            return None;
        }

        let year = ((date >> 9) & 0x7F) as i32 + 1980;
        let month = ((date >> 5) & 0x0F) as u32;
        let day = (date & 0x1F) as u32;

        let hour = ((time >> 11) & 0x1F) as u32;
        let minute = ((time >> 5) & 0x3F) as u32;
        let second = ((time & 0x1F) * 2) as u32;

        NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|d| d.and_hms_opt(hour, minute, second))
            .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
    }

    pub fn creation_datetime(&self) -> Option<DateTime<Utc>> {
        let base = Self::decode_datetime(self.creation_date, self.creation_time)?;
        // DIR_CrtTimeTenth refines the 2-second-resolution DOS creation time.
        // Despite the "tenths" name each unit is 10 ms (valid range 0-199 =>
        // 0-1.99 s), so it can carry an extra second plus a sub-second part.
        // Without this the creation time is truncated to the even second and
        // entries created in the same 2-second window cannot be ordered.
        Some(base + chrono::Duration::milliseconds(self.creation_time_tenth as i64 * 10))
    }

    pub fn modification_datetime(&self) -> Option<DateTime<Utc>> {
        Self::decode_datetime(self.modification_date, self.modification_time)
    }

    pub fn access_date(&self) -> Option<DateTime<Utc>> {
        Self::decode_datetime(self.access_date, 0)
    }
}

impl LfnEntry {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 32 {
            return Err("LFN entry too small".to_string());
        }

        let mut cursor = Cursor::new(data);

        let sequence = cursor.read_u8().map_err(|e| e.to_string())?;

        let mut name1 = [0u16; 5];
        for item in &mut name1 {
            *item = cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?;
        }

        let attributes = cursor.read_u8().map_err(|e| e.to_string())?;
        let entry_type = cursor.read_u8().map_err(|e| e.to_string())?;
        let checksum = cursor.read_u8().map_err(|e| e.to_string())?;

        let mut name2 = [0u16; 6];
        for item in &mut name2 {
            *item = cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?;
        }

        let first_cluster = cursor
            .read_u16::<LittleEndian>()
            .map_err(|e| e.to_string())?;

        let mut name3 = [0u16; 2];
        for item in &mut name3 {
            *item = cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| e.to_string())?;
        }

        Ok(LfnEntry {
            sequence,
            name1,
            attributes,
            entry_type,
            checksum,
            name2,
            first_cluster,
            name3,
        })
    }

    pub fn get_name_part(&self) -> String {
        let mut chars = Vec::new();

        for &c in &self.name1 {
            if c == 0x0000 || c == 0xFFFF {
                break;
            }
            chars.push(c);
        }

        for &c in &self.name2 {
            if c == 0x0000 || c == 0xFFFF {
                break;
            }
            chars.push(c);
        }

        for &c in &self.name3 {
            if c == 0x0000 || c == 0xFFFF {
                break;
            }
            chars.push(c);
        }

        String::from_utf16_lossy(&chars)
    }

    /// Whether the name ends inside this slot: a NUL among its 13 characters. The slot with
    /// the highest ordinal of a complete chain has one unless the name fills it exactly.
    pub fn is_terminated(&self) -> bool {
        self.name1
            .iter()
            .chain(&self.name2)
            .chain(&self.name3)
            .any(|&c| c == 0x0000)
    }

    /// Whether this slot opens its name's chain, as the ordinal itself says: the highest slot of a name
    /// carries `0x40`. `None` when the driver marked the slot deleted, because `0xE5` replaced the ordinal
    /// and says nothing (it is not a valid ordinal, whose highest value is `0x54`). A driver that frees a
    /// directory without marking its slots (Haiku's) leaves the ordinals, and then a cut name is not a
    /// guess.
    pub fn opens_chain_by_ordinal(&self) -> Option<bool> {
        (self.sequence != 0xE5).then_some(self.sequence & 0x40 != 0)
    }

    /// The slot's position in its name, 1 for the slot beside the short entry; meaningful only when
    /// `opens_chain_by_ordinal` is `Some`.
    pub fn ordinal_position(&self) -> u8 {
        self.sequence & 0x1F
    }

    // Chain assembly checks the checksum of every buffered slot rather than the
    // sequence byte, so these decoders have no production caller; they pin the
    // on-disk meaning of the sequence byte in the unit tests.
    #[cfg(test)]
    pub fn is_last(&self) -> bool {
        (self.sequence & 0x40) != 0
    }

    #[cfg(test)]
    pub fn sequence_number(&self) -> u8 {
        self.sequence & 0x1F
    }
}
