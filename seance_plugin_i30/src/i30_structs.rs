/// NTFS $I30 Index Entry
#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub file_reference: String,   // "record-sequence" format
    pub parent_reference: String, // "record-sequence" format
    pub file_name: String,
    pub created: u64,     // Windows FILETIME
    pub modified: u64,    // Windows FILETIME
    pub mft_changed: u64, // Windows FILETIME
    pub accessed: u64,    // Windows FILETIME
    pub allocated_size: u64,
    pub real_size: u64,
    pub file_attributes: u32,
    pub namespace: u8,
    pub flags: u16,
    pub is_directory: bool,
    pub from_slack: bool, // True if recovered from slack space
    pub buffer_index: usize,
    pub entry_offset: usize,
}

impl IndexEntry {
    pub fn created_time(&self) -> Option<String> {
        seance_core::time::filetime_to_rfc3339(self.created)
    }

    pub fn modified_time(&self) -> Option<String> {
        seance_core::time::filetime_to_rfc3339(self.modified)
    }

    pub fn mft_changed_time(&self) -> Option<String> {
        seance_core::time::filetime_to_rfc3339(self.mft_changed)
    }

    pub fn accessed_time(&self) -> Option<String> {
        seance_core::time::filetime_to_rfc3339(self.accessed)
    }

    pub fn namespace_string(&self) -> &'static str {
        match self.namespace {
            0x0 => "posix",
            0x1 => "win32",
            0x2 => "dos",
            0x3 => "win32_dos",
            _ => "unknown",
        }
    }

    pub fn flag_strings(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.flags & 0x1 != 0 {
            flags.push("has_subnode");
        }
        if self.flags & 0x2 != 0 {
            flags.push("last_entry");
        }
        flags
    }
}
