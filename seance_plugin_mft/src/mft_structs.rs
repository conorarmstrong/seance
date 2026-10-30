use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};
use tracing::debug;

// Constants
pub const FILE_SIGNATURE: &[u8; 4] = b"FILE";
pub const ATTR_TYPE_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_TYPE_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_TYPE_FILE_NAME: u32 = 0x30;
pub const ATTR_TYPE_DATA: u32 = 0x80;
pub const ATTR_TYPE_INDEX_ROOT: u32 = 0x90;
pub const ATTR_TYPE_INDEX_ALLOCATION: u32 = 0xA0;
pub const ATTR_TYPE_LOGGED_UTILITY_STREAM: u32 = 0x100;
pub const ATTR_TYPE_END: u32 = 0xFFFFFFFF;

#[derive(Debug, Clone)]
pub struct MftRecordHeader {
    pub signature: [u8; 4],
    pub update_seq_array_offset: u16,
    pub update_seq_array_size: u16,
    pub logfile_sequence_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16,
    pub real_size: u32,
    pub allocated_size: u32,
    pub base_record_reference: u64,
    pub next_attribute_id: u16,
    /// The record's own number, at 0x2C. Only NTFS 3.1 (Windows XP and later)
    /// headers carry it; in a 3.0 (Windows 2000) header the update sequence
    /// array starts at 0x2A, so 0x2C is the first sector-end replacement word,
    /// not a number. `None` means the record carries no number of its own and
    /// the caller must number it by its slot (HUNT-256).
    pub record_number: Option<u32>,
}

/// The update sequence array offset of an NTFS 3.1 header. A 3.1 header puts
/// the array after the record number at 0x2C; a 3.0 header puts it at 0x2A,
/// where the 3.1 padding and record number would be.
pub const NTFS31_USA_OFFSET: u16 = 0x30;

#[derive(Debug, Clone)]
pub struct AttributeHeader {
    pub attribute_type: u32,
    pub length: u32,
    pub non_resident: bool,
    pub name_length: u8,
    pub name_offset: u16,
    pub flags: u16,
    pub attribute_id: u16,
    // Resident fields
    pub content_size: u32,
    pub content_offset: u16,
    // Non-resident fields
    pub start_vcn: u64,
    pub last_vcn: u64,
    pub data_runs_offset: u16,
    pub compression_unit: u16,
    pub allocated_size: u64,
    pub real_size: u64,
    pub initialized_size: u64,
}

pub fn apply_fixups(record: &mut [u8], usa_offset: usize, usa_count: usize) -> Result<(), String> {
    if usa_count == 0 {
        return Ok(());
    }

    let usa_end = usa_offset + (usa_count * 2);
    if usa_end > record.len() {
        return Err("Update Sequence Array out of bounds".to_string());
    }

    // The first 2 bytes of USA are the Update Sequence Number (USN)
    let usn_bytes = [record[usa_offset], record[usa_offset + 1]];
    let usn = LittleEndian::read_u16(&usn_bytes);

    // Clone replacements to avoid holding a borrow on `record`
    let replacements = record[usa_offset + 2..usa_end].to_vec();
    let sector_size = 512;
    let num_sectors = usa_count - 1;

    for i in 0..num_sectors {
        let sector_end_offset = (i + 1) * sector_size - 2;
        if sector_end_offset + 2 > record.len() {
            return Err("Sector end out of bounds during fixup application".to_string());
        }

        let bytes_at_end = &record[sector_end_offset..sector_end_offset + 2];
        let val_at_end = LittleEndian::read_u16(bytes_at_end);

        if val_at_end != usn {
            return Err("Fixup mismatch: USN does not match bytes at end of sector".to_string());
        }

        // Apply replacement
        let replacement_start = i * 2;
        record[sector_end_offset] = replacements[replacement_start];
        record[sector_end_offset + 1] = replacements[replacement_start + 1];
    }

    Ok(())
}

pub fn parse_header(cursor: &mut Cursor<&[u8]>) -> std::io::Result<MftRecordHeader> {
    let mut signature = [0u8; 4];
    cursor.read_exact(&mut signature)?;

    let update_seq_array_offset = cursor.read_u16::<LittleEndian>()?;
    let update_seq_array_size = cursor.read_u16::<LittleEndian>()?;
    let logfile_sequence_number = cursor.read_u64::<LittleEndian>()?;
    let sequence_number = cursor.read_u16::<LittleEndian>()?;
    let hard_link_count = cursor.read_u16::<LittleEndian>()?;
    let first_attribute_offset = cursor.read_u16::<LittleEndian>()?;
    let flags = cursor.read_u16::<LittleEndian>()?;
    let real_size = cursor.read_u32::<LittleEndian>()?;
    let allocated_size = cursor.read_u32::<LittleEndian>()?;
    let base_record_reference = cursor.read_u64::<LittleEndian>()?;
    let next_attribute_id = cursor.read_u16::<LittleEndian>()?;
    // Padding/Align
    cursor.seek(SeekFrom::Current(2))?;
    let raw_record_number = cursor.read_u32::<LittleEndian>()?;
    // Only a 3.1 header (USA at 0x30 or later) has a record number at 0x2C.
    // Anything earlier puts the update sequence array over it (HUNT-256).
    let record_number = (update_seq_array_offset >= NTFS31_USA_OFFSET).then_some(raw_record_number);

    Ok(MftRecordHeader {
        signature,
        update_seq_array_offset,
        update_seq_array_size,
        logfile_sequence_number,
        sequence_number,
        hard_link_count,
        first_attribute_offset,
        flags,
        real_size,
        allocated_size,
        base_record_reference,
        next_attribute_id,
        record_number,
    })
}

pub fn parse_attribute_header(cursor: &mut Cursor<&[u8]>) -> std::io::Result<AttributeHeader> {
    let _start_pos = cursor.position();
    let attribute_type = cursor.read_u32::<LittleEndian>()?;
    if attribute_type == ATTR_TYPE_END {
        return Ok(AttributeHeader {
            attribute_type,
            length: 0,
            non_resident: false,
            name_length: 0,
            name_offset: 0,
            flags: 0,
            attribute_id: 0,
            content_size: 0,
            content_offset: 0,
            start_vcn: 0,
            last_vcn: 0,
            data_runs_offset: 0,
            compression_unit: 0,
            allocated_size: 0,
            real_size: 0,
            initialized_size: 0,
        });
    }

    let length = cursor.read_u32::<LittleEndian>()?;
    let non_resident_byte = cursor.read_u8()?;
    let non_resident = non_resident_byte != 0;
    let name_length = cursor.read_u8()?;
    let name_offset = cursor.read_u16::<LittleEndian>()?;
    let flags = cursor.read_u16::<LittleEndian>()?;
    let attribute_id = cursor.read_u16::<LittleEndian>()?;

    let mut header = AttributeHeader {
        attribute_type,
        length,
        non_resident,
        name_length,
        name_offset,
        flags,
        attribute_id,
        content_size: 0,
        content_offset: 0,
        start_vcn: 0,
        last_vcn: 0,
        data_runs_offset: 0,
        compression_unit: 0,
        allocated_size: 0,
        real_size: 0,
        initialized_size: 0,
    };

    if non_resident {
        header.start_vcn = cursor.read_u64::<LittleEndian>()?;
        header.last_vcn = cursor.read_u64::<LittleEndian>()?;
        header.data_runs_offset = cursor.read_u16::<LittleEndian>()?;
        header.compression_unit = cursor.read_u16::<LittleEndian>()?;
        // padding
        cursor.seek(SeekFrom::Current(4))?;
        header.allocated_size = cursor.read_u64::<LittleEndian>()?;
        header.real_size = cursor.read_u64::<LittleEndian>()?;
        header.initialized_size = cursor.read_u64::<LittleEndian>()?;
    } else {
        header.content_size = cursor.read_u32::<LittleEndian>()?;
        header.content_offset = cursor.read_u16::<LittleEndian>()?;
        // padding?
        // cursor.read_u16::<LittleEndian>()?;
    }

    Ok(header)
}

/// One entry of a resident $ATTRIBUTE_LIST attribute (type 0x20). Describes a
/// single extent of an attribute that lives in `base_record_number` (which may
/// be the record carrying the list itself or an extension MFT record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeListEntry {
    pub attribute_type: u32,
    /// UTF-16LE attribute name (empty in the file -> None, matching the
    /// convention used elsewhere for unnamed attributes).
    pub name: Option<String>,
    /// VCN at which this extent starts within the attribute.
    pub lowest_vcn: u64,
    /// Low 48 bits of the base file reference: the MFT record holding the extent.
    pub base_record_number: u64,
    /// High 16 bits of the base file reference: expected sequence number of the
    /// target record (0 = caller chooses not to validate).
    pub base_record_sequence: u16,
    pub attribute_id: u16,
}

/// Result of parsing a resident $ATTRIBUTE_LIST's content.
pub struct ParsedAttributeList {
    pub entries: Vec<AttributeListEntry>,
    /// True when the list was torn, truncated, or held a malformed entry.
    /// Callers must treat the file's data runs as potentially incomplete:
    /// entries past the corruption point were lost, and with them any extents
    /// they described.
    pub truncated: bool,
}

/// On-disk size of the fixed part of an attribute list entry (no name).
const ATTR_LIST_ENTRY_MIN_SIZE: usize = 0x1A;
/// Cap on parsed entries. A resident list lives inside a single MFT record, so
/// genuine lists hold at most a few dozen entries; this only guards against
/// corrupt content claiming more.
const MAX_ATTRIBUTE_LIST_ENTRIES: usize = 1024;

/// Parse the content of a resident $ATTRIBUTE_LIST attribute. Total function:
/// every field is bounds-checked and parsing stops at the first malformed
/// entry (a bogus entry_length makes it impossible to locate the next entry),
/// reporting the loss via `truncated` so callers never silently drop extents.
pub fn parse_attribute_list(content: &[u8]) -> ParsedAttributeList {
    let mut entries = Vec::new();
    let mut truncated = false;
    let mut offset = 0usize;

    loop {
        if entries.len() >= MAX_ATTRIBUTE_LIST_ENTRIES {
            truncated = true;
            break;
        }
        // Fewer bytes than the fixed part remain: a clean end only when the
        // content is consumed exactly; anything else is a torn entry.
        if offset + ATTR_LIST_ENTRY_MIN_SIZE > content.len() {
            if offset != content.len() {
                truncated = true;
            }
            break;
        }

        let attribute_type = LittleEndian::read_u32(&content[offset..offset + 4]);
        if attribute_type == ATTR_TYPE_END {
            break;
        }
        let entry_length = LittleEndian::read_u16(&content[offset + 4..offset + 6]) as usize;
        if entry_length < ATTR_LIST_ENTRY_MIN_SIZE || offset + entry_length > content.len() {
            truncated = true;
            break;
        }

        let name_length = content[offset + 6] as usize;
        let name_offset = content[offset + 7] as usize;
        let lowest_vcn_raw = LittleEndian::read_i64(&content[offset + 8..offset + 16]);
        let base_ref = LittleEndian::read_u64(&content[offset + 16..offset + 24]);
        let attribute_id = LittleEndian::read_u16(&content[offset + 24..offset + 26]);

        // A negative VCN is never valid; the list cannot be trusted past here.
        if lowest_vcn_raw < 0 {
            truncated = true;
            break;
        }

        // The name must fit inside its own entry. A corrupt name is fatal to
        // the whole list: dropping it would risk merging a named stream's
        // extents into the unnamed $DATA, fabricating wrong evidence.
        let name = if name_length > 0 {
            let name_start = offset + name_offset;
            let name_byte_len = name_length * 2;
            if name_offset < ATTR_LIST_ENTRY_MIN_SIZE
                || name_start + name_byte_len > offset + entry_length
            {
                truncated = true;
                break;
            }
            let u16_vec: Vec<u16> = content[name_start..name_start + name_byte_len]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| LittleEndian::read_u16(c))
                .collect();
            match String::from_utf16(&u16_vec) {
                Ok(s) => Some(s),
                Err(_) => {
                    truncated = true;
                    break;
                }
            }
        } else {
            None
        };

        entries.push(AttributeListEntry {
            attribute_type,
            name,
            lowest_vcn: lowest_vcn_raw as u64,
            base_record_number: base_ref & 0x0000_FFFF_FFFF_FFFF,
            base_record_sequence: (base_ref >> 48) as u16,
            attribute_id,
        });
        offset += entry_length;
    }

    ParsedAttributeList { entries, truncated }
}

/// Parses NTFS Data Runs.
/// Returns a vector of (LCN, LengthInClusters) pairs.
/// If LCN is None, it is a sparse run (all zeros).
/// `data` should be the slice starting at `data_runs_offset`.
///
/// # Safety against infinite loops
/// - Rejects runs with zero length size (invalid encoding)
/// - Skips runs with zero cluster length
/// - Limits to MAX_DATA_RUNS iterations to prevent hangs on corrupted data
pub fn parse_data_runs(data: &[u8]) -> Vec<(Option<u64>, u64)> {
    parse_data_runs_checked(data).0
}

/// Like [`parse_data_runs`], but also reports whether the run cap was hit.
///
/// When the returned flag is `true` the run list is a PREFIX of the file's real
/// extent list — either the `MAX_DATA_RUNS` cap was hit, the list ran off the
/// end of the attribute without its 0x00 terminator, or a malformed header
/// (`len_size == 0`, or a size nibble above 8) made the rest unreadable.
/// Callers MUST then flag the file's data as `data_runs_complete = false`: a
/// heavily fragmented or torn file must never be presented as complete.
///
/// A `false` flag means the list ended at its 0x00 terminator or exactly at the
/// end of the attribute — the only two ways a run list legitimately ends.
pub fn parse_data_runs_checked(data: &[u8]) -> (Vec<(Option<u64>, u64)>, bool) {
    const MAX_DATA_RUNS: usize = 10000; // No reasonable file has more than 10K fragments

    let mut runs = Vec::new();
    let mut idx = 0;
    let mut current_lcn: i64 = 0;
    let mut iteration_count = 0;
    let mut truncated = false;

    while idx < data.len() {
        // Guard against infinite loops on corrupted data
        iteration_count += 1;
        if iteration_count > MAX_DATA_RUNS {
            debug!(
                "Data runs parsing: hit iteration limit ({}) with {} runs parsed (file may be heavily fragmented or corrupted)",
                MAX_DATA_RUNS, runs.len()
            );
            truncated = true;
            break;
        }

        let header = data[idx];
        idx += 1;

        if header == 0 {
            break;
        }

        let len_size = (header & 0x0F) as usize;
        let offset_size = ((header >> 4) & 0x0F) as usize;

        // Guard: each field encodes into a u64, so more than 8 bytes is
        // malformed and would overflow the `<< (i*8)` shifts below (i*8 >= 64).
        // A valid NTFS runlist never exceeds 8 bytes per field.
        if len_size > 8 || offset_size > 8 {
            debug!(
                "Data runs parsing: invalid header 0x{:02X} at index {} (len_size={} offset_size={} > 8)",
                header, idx - 1, len_size, offset_size
            );
            // Everything after a malformed header is unreachable: the runs
            // collected so far are a PREFIX of the file, not the file.
            truncated = true;
            break;
        }

        // Guard: len_size of 0 is invalid (would mean 0 bytes to encode length)
        // This prevents infinite loops where idx doesn't advance
        if len_size == 0 {
            debug!(
                "Data runs parsing: invalid header 0x{:02X} at index {} (len_size=0 is invalid)",
                header,
                idx - 1
            );
            truncated = true;
            break;
        }

        if idx + len_size + offset_size > data.len() {
            debug!(
                "Data runs parsing: truncated at index {} (need {} bytes, have {})",
                idx,
                len_size + offset_size,
                data.len() - idx
            );
            // The run list ran off the end of the attribute record without a
            // 0x00 terminator: the remaining extents were never read.
            truncated = true;
            break;
        }

        // Read length
        let mut length: u64 = 0;
        for i in 0..len_size {
            length |= (data[idx + i] as u64) << (i * 8);
        }
        idx += len_size;

        // Guard: zero-length runs are meaningless, skip them
        // This also prevents issues with downstream calculations
        if length == 0 {
            // Still need to advance past offset bytes
            idx += offset_size;
            continue;
        }

        // Read offset (signed)
        let mut offset_val: i64 = 0;
        if offset_size > 0 {
            for i in 0..offset_size {
                offset_val |= (data[idx + i] as i64) << (i * 8);
            }
            // Sign extend
            if (data[idx + offset_size - 1] & 0x80) != 0 {
                let shift = 64 - (offset_size * 8);
                if shift < 64 {
                    // prevent overflow panic if offset_size is 8
                    offset_val = (offset_val << shift) >> shift;
                }
            }
            idx += offset_size;

            // Accumulated LCN deltas come from an attacker-controlled runlist;
            // saturate rather than overflow. A saturated/negative result is
            // treated as sparse just below.
            current_lcn = current_lcn.saturating_add(offset_val);

            if current_lcn < 0 {
                // Should not happen in valid NTFS - treat as sparse
                runs.push((None, length));
            } else {
                runs.push((Some(current_lcn as u64), length));
            }
        } else {
            // Sparse run
            runs.push((None, length));
        }
    }

    (runs, truncated)
}
#[cfg(test)]
mod fuzz_regression {
    use super::parse_data_runs;

    /// Malformed data-run headers must never panic (found by fuzzing the MFT
    /// parser): a size nibble > 8 overflowed the `<< (i*8)` shift, and huge
    /// signed LCN deltas overflowed the accumulator. The assertion here is that
    /// each call RETURNS (no panic) on adversarial input.
    #[test]
    fn malformed_runlists_do_not_panic() {
        // len_size/offset_size = 0x0F (15) each -> would shift a u64 by >= 64.
        let _ = parse_data_runs(&[0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
        // len_size = 8, offset_size = 8, max bytes -> u64 field + i64 delta near
        // the limit, repeated to overflow the accumulated LCN.
        let big = [
            0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let _ = parse_data_runs(&big);
        // Truncated / empty.
        let _ = parse_data_runs(&[0x21, 0x01]);
        let _ = parse_data_runs(&[]);
    }
}

#[cfg(test)]
mod run_cap {
    use super::parse_data_runs_checked;

    /// Hitting the run cap must surface a `truncated = true` flag so callers can
    /// mark data_runs_complete = false. Each 2-byte pair (0x01 header + 1 length
    /// byte) is one sparse run; 10001 of them exceed the 10_000 cap.
    #[test]
    fn run_cap_sets_truncated_flag() {
        // Well under the cap: complete, not truncated.
        let (runs, truncated) = parse_data_runs_checked(&[0x01u8; 200]);
        assert_eq!(runs.len(), 100);
        assert!(!truncated);

        // Over the cap: the run list is capped and flagged truncated.
        let (runs, truncated) = parse_data_runs_checked(&[0x01u8; 20002]);
        assert_eq!(runs.len(), 10000);
        assert!(truncated);
    }

    /// A run list that ends at its 0x00 terminator, or exactly at the end of
    /// the attribute, is complete. These are the only two clean endings, and
    /// they must NOT be reported as truncated or every ordinary file would be
    /// flagged incomplete.
    #[test]
    fn clean_endings_are_not_truncated() {
        // One run (0x11: len_size=1, offset_size=1) then the 0x00 terminator.
        let (runs, truncated) = parse_data_runs_checked(&[0x11, 0x04, 0x20, 0x00]);
        assert_eq!(runs, vec![(Some(0x20), 4)]);
        assert!(!truncated, "terminated list is complete");

        // Same run with no trailing terminator byte, ending exactly on the
        // attribute boundary.
        let (runs, truncated) = parse_data_runs_checked(&[0x11, 0x04, 0x20]);
        assert_eq!(runs, vec![(Some(0x20), 4)]);
        assert!(
            !truncated,
            "list ending on the attribute boundary is complete"
        );

        let (runs, truncated) = parse_data_runs_checked(&[]);
        assert!(runs.is_empty());
        assert!(!truncated);
    }

    /// Every mid-list abort drops the remaining extents, so each one must set
    /// `truncated`. Before this, only the 10 000-run cap did: a runlist torn by
    /// a bad header or a short attribute returned a PREFIX of the file's
    /// extents while reporting the attribute as complete, and the file was
    /// published with `data_runs_complete: true` over partial content.
    #[test]
    fn mid_list_aborts_set_truncated() {
        // Header 0xFF: len_size = offset_size = 15, both above the 8-byte max.
        let (runs, truncated) = parse_data_runs_checked(&[0x11, 0x04, 0x20, 0xFF, 0x01, 0x02]);
        assert_eq!(runs.len(), 1, "the one good run survives");
        assert!(
            truncated,
            "malformed size nibbles abort the rest of the list"
        );

        // Header 0x10: offset_size = 1, len_size = 0 — cannot encode a length.
        let (runs, truncated) = parse_data_runs_checked(&[0x11, 0x04, 0x20, 0x10, 0x02]);
        assert_eq!(runs.len(), 1);
        assert!(truncated, "len_size == 0 aborts the rest of the list");

        // Header 0x22 needs 4 more bytes but only 2 remain: the list ran off
        // the end of the attribute without a terminator.
        let (runs, truncated) = parse_data_runs_checked(&[0x11, 0x04, 0x20, 0x22, 0x01, 0x02]);
        assert_eq!(runs.len(), 1);
        assert!(truncated, "short trailing run aborts the rest of the list");
    }
}

#[cfg(test)]
mod header_version_tests {
    use super::*;

    fn parse(bytes: &[u8]) -> MftRecordHeader {
        parse_header(&mut Cursor::new(bytes)).expect("header parses")
    }

    /// A 48-byte FILE header with the given USA offset/count and 0x2C..0x30.
    fn header_bytes(usa_offset: u16, usa_count: u16, first_attr: u16, at_2c: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x30];
        b[0..4].copy_from_slice(b"FILE");
        b[4..6].copy_from_slice(&usa_offset.to_le_bytes());
        b[6..8].copy_from_slice(&usa_count.to_le_bytes());
        b[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        b[0x14..0x16].copy_from_slice(&first_attr.to_le_bytes());
        b[0x2C..0x30].copy_from_slice(&at_2c.to_le_bytes());
        b
    }

    /// NTFS 3.0: the USA begins at 0x2A, so 0x2C holds a fixup replacement
    /// word, not a record number. Publishing it would invent a number.
    #[test]
    fn ntfs30_header_has_no_record_number() {
        let h = parse(&header_bytes(0x2A, 3, 0x30, 0x1147));
        assert_eq!(h.record_number, None);
    }

    /// NTFS 3.1: the USA begins at 0x30 and 0x2C is the record's own number.
    #[test]
    fn ntfs31_header_reads_record_number() {
        let h = parse(&header_bytes(0x30, 3, 0x38, 42));
        assert_eq!(h.record_number, Some(42));
    }

    /// Known answer on a real Windows 2000 record. These are the first 0x40
    /// bytes of the page at physical offset 0x53ED000 of
    /// `boomer-win2k-2006-02-27-0824.img` (NIST CFReDS "Basic Memory Images",
    /// memory-images.rar; page SHA-256 75c72987e6691c9a5b3d70beaf62c825
    /// 09c33487b811e08cb359c126d163cd4b). It is a memory capture's copy of an
    /// MFT record, so it pins the 3.0 header layout, not a volume. Before
    /// HUNT-256 the parser published 0x2C..0x30 (47 11 00 00) as record
    /// number 4423.
    #[test]
    fn real_win2000_record_header_known_answer() {
        const RECORD: &str = "46494c452a00030090b108040000000000800c81300001000002000000040000\
                              0000000000000000060004004711000010000000600000000000000000000000";
        let hex: String = RECORD.split_whitespace().collect();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(bytes.len(), 0x40);
        let h = parse(&bytes);
        assert_eq!(h.update_seq_array_offset, 0x2A);
        assert_eq!(h.update_seq_array_size, 3);
        assert_eq!(h.first_attribute_offset, 0x30);
        assert_eq!(h.flags, 1, "in use");
        assert_eq!(h.real_size, 0x200);
        assert_eq!(h.allocated_size, 0x400);
        assert_eq!(h.next_attribute_id, 6);
        assert_eq!(
            h.record_number, None,
            "0x2C is the USA, not a record number"
        );
    }
}
