//! On-disk structures and parsing for the real NTFS `$LogFile` journal.
//!
//! Layout implemented here (Log File Service / LFS):
//! * a RESTART AREA: the first two pages, each a "restart page" (`RSTR`, or
//!   `CHKD` after a chkdsk repair);
//! * a LOGGING AREA: a ring of `RCRD` record pages holding LFS log records.
//!
//! Every page is protected by an update sequence array (USA). The last two
//! bytes of each 512-byte sector are replaced on disk with a sequence-number
//! placeholder; the true bytes live in the USA. The fixup verifies each
//! placeholder (detecting torn writes) and restores the real bytes. This MUST
//! run before any page content is read.
//!
//! Cross-checked against the dfir_ntfs, libfsntfs and Windows Internals
//! descriptions of the format. All input is untrusted evidence: every offset
//! and length is bounds-checked, arithmetic is checked/saturating, and loops
//! are capped so hostile input cannot panic or exhaust memory.

// The walk ends three different ways -- the offset overflows, it passes the end
// of the logging area, or a page will not read -- and each break says which.
// A `while let` would fold the first into the loop header and leave the other
// two behind, so the reasons stop sitting together.
#![allow(clippy::while_let_loop)]

use byteorder::{ByteOrder, LittleEndian};
use seance_core::data_source::DataSource;
use seance_core::module::ModuleError;

/// Sectors protected by the update sequence array are 512 bytes.
pub const USA_STRIDE: usize = 512;
/// Smallest page size accepted from a restart page header.
pub const MIN_PAGE_SIZE: usize = 512;
/// Largest page size accepted (guards against hostile values).
pub const MAX_PAGE_SIZE: usize = 65536;
/// Minimum size of an LFS log record header.
pub const LFS_RECORD_HEADER_MIN: usize = 48;
/// Size of the fixed NTFS log-record operation header.
pub const NTFS_OP_HEADER_LEN: usize = 32;

/// LFS record type: an NTFS client log record.
pub const LFS_CLIENT_RECORD: u32 = 1;
/// LFS record type: an NTFS client restart area.
pub const LFS_CLIENT_RESTART: u32 = 2;

const CLIENT_RECORD_SIZE: usize = 160;
const MAX_CLIENTS: usize = 64;
const RECORD_PAGE_HEADER_SIZE: usize = 40;
const DEFAULT_DATA_OFFSET: usize = 0x40;
const MAX_RECORDS_PER_PAGE: usize = 4096;
const MAX_LOG_PAGES: usize = 1_048_576;
const MAX_TOTAL_RECORDS: usize = 500_000;

// --- bounded little-endian readers (never panic, never read out of bounds) ---

#[inline]
fn rd_u16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(LittleEndian::read_u16)
}
#[inline]
fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(LittleEndian::read_u32)
}
#[inline]
fn rd_u64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(LittleEndian::read_u64)
}
#[inline]
fn rd_i64(b: &[u8], o: usize) -> Option<i64> {
    b.get(o..o + 8).map(LittleEndian::read_i64)
}

fn parse_err(msg: impl Into<String>) -> ModuleError {
    ModuleError::ParsingError(msg.into())
}

fn valid_page_size(v: u32) -> bool {
    let v = v as usize;
    (MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&v) && v.is_multiple_of(USA_STRIDE)
}

fn read_utf16le(b: &[u8], off: usize, len: usize) -> String {
    let end = off.saturating_add(len).min(b.len());
    let slice = match b.get(off..end) {
        Some(s) => s,
        None => return String::new(),
    };
    let units: Vec<u16> = slice
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| LittleEndian::read_u16(c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Decode a documented NTFS `$LogFile` operation code to its name.
pub fn ntfs_operation_name(op: u16) -> &'static str {
    match op {
        0x00 => "Noop",
        0x01 => "CompensationLogRecord",
        0x02 => "InitializeFileRecordSegment",
        0x03 => "DeallocateFileRecordSegment",
        0x04 => "WriteEndOfFileRecordSegment",
        0x05 => "CreateAttribute",
        0x06 => "DeleteAttribute",
        0x07 => "UpdateResidentValue",
        0x08 => "UpdateNonresidentValue",
        0x09 => "UpdateMappingPairs",
        0x0A => "DeleteDirtyClusters",
        0x0B => "SetNewAttributeSizes",
        0x0C => "AddIndexEntryRoot",
        0x0D => "DeleteIndexEntryRoot",
        0x0E => "AddIndexEntryAllocation",
        0x0F => "DeleteIndexEntryAllocation",
        0x10 => "WriteEndOfIndexBuffer",
        0x11 => "SetIndexEntryVcnRoot",
        0x12 => "SetIndexEntryVcnAllocation",
        0x13 => "UpdateFileNameRoot",
        0x14 => "UpdateFileNameAllocation",
        0x15 => "SetBitsInNonresidentBitMap",
        0x16 => "ClearBitsInNonresidentBitMap",
        0x17 => "HotFix",
        0x18 => "EndTopLevelAction",
        0x19 => "PrepareTransaction",
        0x1A => "CommitTransaction",
        0x1B => "ForgetTransaction",
        0x1C => "OpenNonresidentAttribute",
        0x1D => "OpenAttributeTableDump",
        0x1E => "AttributeNamesDump",
        0x1F => "DirtyPageTableDump",
        0x20 => "TransactionTableDump",
        0x21 => "UpdateRecordDataRoot",
        0x22 => "UpdateRecordDataAllocation",
        0x23 => "UpdateRelativeDataIndex",
        0x24 => "UpdateRelativeDataAllocation",
        0x25 => "ZeroEndOfFileRecord",
        _ => "Unknown",
    }
}

/// Verify and apply the update sequence array (USA) fixup to a page in place.
///
/// The page is divided into 512-byte sectors. On disk the last two bytes of
/// each sector hold a copy of the USA sequence number; the true bytes are kept
/// in the USA. This checks every sector's placeholder against the sequence
/// number (a mismatch means a torn or corrupt page) and restores the original
/// bytes. Returns the offset just past the USA on success, or an error the
/// caller can use to flag the page instead of reading garbage.
pub fn apply_usa_fixup(buf: &mut [u8]) -> Result<usize, ModuleError> {
    let len = buf.len();
    if len < 2 * USA_STRIDE || !len.is_multiple_of(USA_STRIDE) {
        return Err(parse_err(format!(
            "USA: page size {len} is not two or more whole 512-byte sectors"
        )));
    }

    let usa_offset = rd_u16(buf, 4).ok_or_else(|| parse_err("USA: truncated header"))? as usize;
    let usa_count = rd_u16(buf, 6).ok_or_else(|| parse_err("USA: truncated header"))? as usize;

    if !(8..=USA_STRIDE - 6).contains(&usa_offset) {
        return Err(parse_err(format!("USA: invalid array offset {usa_offset}")));
    }

    let sectors = len / USA_STRIDE;
    // The USA holds one sequence number plus one entry per protected sector.
    if usa_count < 2 || usa_count - 1 != sectors {
        return Err(parse_err(format!(
            "USA: count {usa_count} does not match {sectors} sectors"
        )));
    }

    let usa_end = usa_offset
        .checked_add(
            usa_count
                .checked_mul(2)
                .ok_or_else(|| parse_err("USA: overflow"))?,
        )
        .ok_or_else(|| parse_err("USA: overflow"))?;
    if usa_end > len {
        return Err(parse_err("USA: array extends past page"));
    }

    // DAX volumes protect the block with a CRC32 (marker "CRC4") rather than a
    // classic USA. That variant is not decoded here; flag it explicitly so it
    // is not mis-reported as a torn page.
    if buf.get(usa_offset + 4..usa_offset + 8) == Some(b"CRC4".as_slice()) {
        return Err(parse_err("USA: CRC32-protected (DAX) page not supported"));
    }

    let usn = [buf[usa_offset], buf[usa_offset + 1]];

    for i in 1..usa_count {
        let usa_pos = usa_offset + i * 2;
        let update = [buf[usa_pos], buf[usa_pos + 1]];

        // Last two bytes of sector (i - 1).
        let sector_tail = i * USA_STRIDE - 2;
        if buf[sector_tail] != usn[0] || buf[sector_tail + 1] != usn[1] {
            return Err(parse_err(format!(
                "USA: sequence mismatch at sector {} (torn/corrupt page)",
                i - 1
            )));
        }
        buf[sector_tail] = update[0];
        buf[sector_tail + 1] = update[1];
    }

    Ok(usa_end)
}

/// Summary of a single `LOG_CLIENT_RECORD` in the restart area.
#[derive(Debug, Clone)]
pub struct ClientRecordSummary {
    pub name: String,
    pub oldest_lsn: u64,
    pub client_restart_lsn: u64,
    pub seq_number: u16,
}

/// Parsed restart page header + restart area (post-USA-fixup).
#[derive(Debug, Clone)]
pub struct RestartPage {
    pub signature: [u8; 4],
    pub chkdsk_lsn: u64,
    pub system_page_size: u32,
    pub log_page_size: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub current_lsn: u64,
    pub log_clients: u16,
    pub flags: u16,
    pub seq_number_bits: u32,
    pub restart_area_length: u16,
    pub file_size: i64,
    pub record_header_length: u16,
    pub log_page_data_offset: u16,
    pub clients: Vec<ClientRecordSummary>,
}

/// Parse a restart page (`RSTR` or `CHKD`). `raw` is the full page; the USA
/// fixup runs on a private copy so the caller's buffer is untouched.
pub fn parse_restart_page(raw: &[u8]) -> Result<RestartPage, ModuleError> {
    let mut buf = raw.to_vec();
    apply_usa_fixup(&mut buf)?; // guarantees buf.len() >= 1024

    let signature = [buf[0], buf[1], buf[2], buf[3]];
    if &signature != b"RSTR" && &signature != b"CHKD" {
        return Err(parse_err(format!(
            "restart page: bad signature {signature:02X?}"
        )));
    }

    let chkdsk_lsn = rd_u64(&buf, 8).ok_or_else(|| parse_err("restart page: truncated"))?;
    let system_page_size = rd_u32(&buf, 16).ok_or_else(|| parse_err("restart page: truncated"))?;
    let log_page_size = rd_u32(&buf, 20).ok_or_else(|| parse_err("restart page: truncated"))?;
    let restart_offset =
        rd_u16(&buf, 24).ok_or_else(|| parse_err("restart page: truncated"))? as usize;
    let minor_version = rd_u16(&buf, 26).ok_or_else(|| parse_err("restart page: truncated"))?;
    let major_version = rd_u16(&buf, 28).ok_or_else(|| parse_err("restart page: truncated"))?;

    if !valid_page_size(system_page_size) {
        return Err(parse_err(format!(
            "restart page: invalid system page size {system_page_size}"
        )));
    }
    if !valid_page_size(log_page_size) {
        return Err(parse_err(format!(
            "restart page: invalid log page size {log_page_size}"
        )));
    }
    if restart_offset < 8 || !restart_offset.is_multiple_of(8) || restart_offset >= buf.len() {
        return Err(parse_err(format!(
            "restart page: invalid restart-area offset {restart_offset}"
        )));
    }

    let ra = &buf[restart_offset..];
    let current_lsn = rd_u64(ra, 0).ok_or_else(|| parse_err("restart area: truncated"))?;
    let log_clients = rd_u16(ra, 8).ok_or_else(|| parse_err("restart area: truncated"))?;
    let flags = rd_u16(ra, 14).ok_or_else(|| parse_err("restart area: truncated"))?;
    let seq_number_bits = rd_u32(ra, 16).ok_or_else(|| parse_err("restart area: truncated"))?;
    let restart_area_length = rd_u16(ra, 20).ok_or_else(|| parse_err("restart area: truncated"))?;
    let client_array_offset =
        rd_u16(ra, 22).ok_or_else(|| parse_err("restart area: truncated"))? as usize;
    let file_size = rd_i64(ra, 24).ok_or_else(|| parse_err("restart area: truncated"))?;
    let record_header_length =
        rd_u16(ra, 36).ok_or_else(|| parse_err("restart area: truncated"))?;
    let log_page_data_offset =
        rd_u16(ra, 38).ok_or_else(|| parse_err("restart area: truncated"))?;

    let mut clients = Vec::new();
    if client_array_offset >= 8 && client_array_offset.is_multiple_of(8) {
        let n = (log_clients as usize).min(MAX_CLIENTS);
        for i in 0..n {
            let base = match i
                .checked_mul(CLIENT_RECORD_SIZE)
                .and_then(|v| v.checked_add(client_array_offset))
            {
                Some(v) => v,
                None => break,
            };
            let cr = match ra.get(base..) {
                Some(s) if s.len() >= 32 => s,
                _ => break,
            };
            let oldest_lsn = rd_u64(cr, 0).unwrap_or(0);
            let client_restart_lsn = rd_u64(cr, 8).unwrap_or(0);
            let seq_number = rd_u16(cr, 20).unwrap_or(0);
            let name_len = rd_u32(cr, 28).unwrap_or(0) as usize;
            let name = read_utf16le(cr, 32, name_len.min(128));
            clients.push(ClientRecordSummary {
                name,
                oldest_lsn,
                client_restart_lsn,
                seq_number,
            });
        }
    }

    Ok(RestartPage {
        signature,
        chkdsk_lsn,
        system_page_size,
        log_page_size,
        major_version,
        minor_version,
        current_lsn,
        log_clients,
        flags,
        seq_number_bits,
        restart_area_length,
        file_size,
        record_header_length,
        log_page_data_offset,
        clients,
    })
}

/// Fixed NTFS operation fields decoded from LFS client-record data.
#[derive(Debug, Clone)]
pub struct NtfsOpFields {
    pub redo_operation: u16,
    pub undo_operation: u16,
    pub redo_offset: u16,
    pub redo_length: u16,
    pub undo_offset: u16,
    pub undo_length: u16,
    pub target_attribute: u16,
    pub lcns_to_follow: u16,
    pub record_offset: u16,
    pub attribute_offset: u16,
    pub mft_cluster_index: u16,
    pub target_vcn: i64,
    pub target_lcn: Option<i64>,
}

/// A single LFS log record (header plus, for client records, decoded NTFS op).
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub page_number: u64,
    pub lsn: u64,
    pub client_previous_lsn: u64,
    pub client_undo_next_lsn: u64,
    pub client_data_length: u32,
    pub client_id: u32,
    pub record_type: u32,
    pub transaction_id: u32,
    pub flags: u16,
    /// True when the client data continues past this page. Cross-page
    /// reassembly needs the full LSN-chain walk and is deferred.
    pub multi_page: bool,
    pub op: Option<NtfsOpFields>,
}

fn parse_ntfs_op(d: &[u8]) -> Option<NtfsOpFields> {
    if d.len() < NTFS_OP_HEADER_LEN {
        return None;
    }
    let redo_operation = rd_u16(d, 0)?;
    let undo_operation = rd_u16(d, 2)?;
    let redo_offset = rd_u16(d, 4)?;
    let redo_length = rd_u16(d, 6)?;
    let undo_offset = rd_u16(d, 8)?;
    let undo_length = rd_u16(d, 10)?;
    let target_attribute = rd_u16(d, 12)?;
    let lcns_to_follow = rd_u16(d, 14)?;
    let record_offset = rd_u16(d, 16)?;
    let attribute_offset = rd_u16(d, 18)?;
    let mft_cluster_index = rd_u16(d, 20)?;
    let target_vcn = rd_i64(d, 24)?;
    let target_lcn = if lcns_to_follow >= 1 {
        rd_i64(d, NTFS_OP_HEADER_LEN)
    } else {
        None
    };

    Some(NtfsOpFields {
        redo_operation,
        undo_operation,
        redo_offset,
        redo_length,
        undo_offset,
        undo_length,
        target_attribute,
        lcns_to_follow,
        record_offset,
        attribute_offset,
        mft_cluster_index,
        target_vcn,
        target_lcn,
    })
}

/// Parse an `RCRD`/`CHKD` record page and return the LFS log records it holds.
///
/// `page_number` is the absolute log page number (used only for provenance).
/// `data_offset` and `header_len` come from the restart area. The USA fixup is
/// applied first; a torn page yields an error so the caller can flag and skip
/// it rather than emit garbage. Records are walked within the page only; a
/// record whose client data spills into the next page is flagged `multi_page`
/// and terminates the page walk (cross-page reassembly is deferred).
pub fn parse_record_page(
    raw: &[u8],
    page_number: u64,
    data_offset: usize,
    header_len: usize,
) -> Result<(Vec<LogRecord>, bool), ModuleError> {
    let mut buf = raw.to_vec();
    apply_usa_fixup(&mut buf)?; // guarantees buf.len() >= 1024

    let sig = &buf[0..4];
    if sig != b"RCRD" && sig != b"CHKD" {
        return Err(parse_err(format!(
            "record page: bad signature {:02X?}",
            &buf[0..4]
        )));
    }

    let page_size = buf.len();
    let header_len = header_len.max(LFS_RECORD_HEADER_MIN);

    let start = if (RECORD_PAGE_HEADER_SIZE..page_size).contains(&data_offset)
        && data_offset.is_multiple_of(8)
    {
        data_offset
    } else {
        DEFAULT_DATA_OFFSET
    };

    // Offset of free space; records at or beyond it are stale.
    let next_record_offset = rd_u16(&buf, 24).unwrap_or(0) as usize;
    let limit = if next_record_offset > start && next_record_offset <= page_size {
        next_record_offset
    } else {
        page_size
    };

    let mut records = Vec::new();
    let mut off = start;
    let mut count = 0;

    while count < MAX_RECORDS_PER_PAGE {
        let header_end = match off.checked_add(header_len) {
            Some(v) => v,
            None => break,
        };
        if header_end > limit {
            break;
        }

        let rec = &buf[off..];
        let lsn = rd_u64(rec, 0).unwrap_or(0);
        if lsn == 0 {
            break; // free space / end of records in this page
        }

        let client_previous_lsn = rd_u64(rec, 8).unwrap_or(0);
        let client_undo_next_lsn = rd_u64(rec, 16).unwrap_or(0);
        let client_data_length = rd_u32(rec, 24).unwrap_or(0);
        let client_id = rd_u32(rec, 28).unwrap_or(0);
        let record_type = rd_u32(rec, 32).unwrap_or(0);
        let transaction_id = rd_u32(rec, 36).unwrap_or(0);
        let flags = rd_u16(rec, 40).unwrap_or(0);

        let cdl = client_data_length as usize;
        if cdl == 0 || !cdl.is_multiple_of(8) {
            // Client data length is always a positive multiple of 8. A value
            // that is not one leaves no way to find the next record.
            return Ok((records, false));
        }

        let data_start = header_end;
        let data_end = data_start.checked_add(cdl);
        let multi_page = match data_end {
            Some(e) => e > page_size,
            None => true,
        };

        let mut op = None;
        if record_type == LFS_CLIENT_RECORD {
            let avail_end = data_end.unwrap_or(page_size).min(page_size);
            if avail_end >= data_start + NTFS_OP_HEADER_LEN {
                op = parse_ntfs_op(&buf[data_start..avail_end]);
            }
        }

        records.push(LogRecord {
            page_number,
            lsn,
            client_previous_lsn,
            client_undo_next_lsn,
            client_data_length,
            client_id,
            record_type,
            transaction_id,
            flags,
            multi_page,
            op,
        });
        count += 1;

        if multi_page {
            // Cannot locate the next record without the LSN-chain walk, so the
            // rest of THIS page is abandoned too. Records after it in the same
            // page are never emitted: say the page was left part-walked rather
            // than let the operations in it read as operations that never
            // happened (B2-157).
            return Ok((records, false));
        }

        let next = match header_end.checked_add(cdl) {
            Some(v) => v,
            None => return Ok((records, false)),
        };
        if next <= off {
            return Ok((records, false)); // never advance backwards
        }
        off = next;
    }

    // Falling out of the loop means the record cap stopped the page walk while
    // the page still held records.
    let fully_walked = count < MAX_RECORDS_PER_PAGE;
    Ok((records, fully_walked))
}

/// Result of parsing a whole `$LogFile`.
#[derive(Debug)]
pub struct ParsedLogFile {
    pub restart: RestartPage,
    /// Which restart page supplied the metadata (1 = primary, 2 = backup).
    pub restart_page_used: u8,
    pub records: Vec<LogRecord>,
    /// RCRD pages that failed the USA fixup (torn/corrupt) and were skipped.
    pub torn_pages: usize,
    pub pages_scanned: usize,
    /// The page-scan cap stopped the walk while full pages remained.
    pub pages_capped: bool,
    /// The record cap stopped collection while full pages remained.
    pub records_capped: bool,
    /// A page inside the logging area could not be read in full, so the scan
    /// stopped there. Later pages exist but were never examined.
    pub short_read_stop: bool,
    /// RCRD pages whose in-page record walk stopped before the end of the page
    /// (a multi-page record, an unusable client-data length, or the per-page
    /// record cap). Operations recorded later in those pages were never
    /// emitted (B2-157).
    pub pages_part_walked: usize,
    /// The restart area declares a larger `$LogFile` than the source holds, so
    /// the walk ended at the end of the evidence rather than the end of the log.
    pub declared_beyond_source: bool,
}

impl ParsedLogFile {
    /// True when the parse covered the whole logging area with every page
    /// intact.
    ///
    /// Forensic meaning: `$LogFile` is the record of recent renames, deletes
    /// and attribute changes. If the walk stopped early or skipped torn pages,
    /// an operation an examiner cannot find may simply never have been read.
    /// The two cases must never look the same.
    pub fn complete(&self) -> bool {
        self.torn_pages == 0
            && self.pages_part_walked == 0
            && !self.pages_capped
            && !self.records_capped
            && !self.short_read_stop
            && !self.declared_beyond_source
    }

    /// Why the parse is not a complete view of the logging area, most
    /// significant reason first. Empty when [`complete`](Self::complete).
    pub fn incomplete_reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self.torn_pages > 0 {
            reasons.push("torn_pages_skipped");
        }
        if self.short_read_stop {
            reasons.push("page_read_short");
        }
        if self.pages_part_walked > 0 {
            reasons.push("page_records_not_fully_walked");
        }
        if self.declared_beyond_source {
            reasons.push("source_shorter_than_declared_log");
        }
        if self.pages_capped {
            reasons.push("page_scan_cap");
        }
        if self.records_capped {
            reasons.push("record_cap");
        }
        reasons
    }
}

/// Parse a `$LogFile` data source: locate a valid restart page, then walk the
/// logging area collecting LFS log records.
pub fn parse_logfile(ds: &dyn DataSource) -> Result<ParsedLogFile, ModuleError> {
    // Probe the primary restart page header to discover the system page size.
    // `read_full` loops: one `read_at` returning a handful of bytes is ordinary
    // on a windowed or container-backed source, and treating it as "$LogFile too
    // small" would refuse to parse a perfectly readable transaction log.
    let mut probe = [0u8; 64];
    let n = seance_core::io::read_full(ds, 0, &mut probe);
    if n < 32 {
        return Err(parse_err("$LogFile too small to contain a restart page"));
    }

    let candidate = rd_u32(&probe, 16).unwrap_or(0);
    let sps = if (&probe[0..4] == b"RSTR" || &probe[0..4] == b"CHKD") && valid_page_size(candidate)
    {
        candidate as usize
    } else {
        MIN_PAGE_SIZE.max(4096)
    };

    // Whole page or nothing: a partially delivered restart page would have its
    // zero tail parsed as real restart-area fields.
    let read_page = |offset: u64, size: usize| -> Option<Vec<u8>> {
        let mut b = vec![0u8; size];
        (seance_core::io::read_full(ds, offset, &mut b) == size).then_some(b)
    };

    let page0 = read_page(0, sps);
    let page1 = read_page(sps as u64, sps);

    let (restart, restart_page_used) =
        if let Some(r) = page0.as_deref().and_then(|p| parse_restart_page(p).ok()) {
            (r, 1u8)
        } else if let Some(r) = page1.as_deref().and_then(|p| parse_restart_page(p).ok()) {
            (r, 2u8)
        } else {
            return Err(parse_err("no valid restart page (RSTR/CHKD) found"));
        };

    if !valid_page_size(restart.system_page_size) || !valid_page_size(restart.log_page_size) {
        return Err(parse_err("restart area reports invalid page sizes"));
    }

    let system_page_size = restart.system_page_size as u64;
    let log_page_size = restart.log_page_size as usize;
    let data_offset = restart.log_page_data_offset as usize;
    let header_len = restart.record_header_length as usize;

    // The logging area begins after the two restart pages.
    let start = system_page_size
        .checked_mul(2)
        .ok_or_else(|| parse_err("restart area: page size overflow"))?;

    let ds_size = ds.size();
    let declared = if restart.file_size > 0 {
        restart.file_size as u64
    } else {
        ds_size
    };
    let max = declared.min(ds_size);
    // The restart area says how big `$LogFile` is. When the source holds less
    // than that, the walk below stops at the end of the evidence, which looks
    // exactly like reaching the end of the log: the pages that were cut off in
    // acquisition would otherwise read as pages that never held an operation.
    let declared_beyond_source = declared > ds_size;

    let mut records = Vec::new();
    let mut torn_pages = 0usize;
    let mut pages_scanned = 0usize;
    let mut pages_capped = false;
    let mut records_capped = false;
    let mut short_read_stop = false;
    let mut pages_part_walked = 0usize;
    let mut off = start;

    loop {
        let end = match off.checked_add(log_page_size as u64) {
            Some(v) => v,
            None => break,
        };
        if end > max {
            break; // genuine end of the logging area
        }

        // Caps are only a truncation when a whole page was still waiting; test
        // them here so "we reached the end" and "we gave up" stay distinct.
        if pages_scanned >= MAX_LOG_PAGES {
            pages_capped = true;
            break;
        }
        if records.len() >= MAX_TOTAL_RECORDS {
            records_capped = true;
            break;
        }

        let mut page = vec![0u8; log_page_size];
        // Gather the whole page before calling it short: a chunked source
        // delivers a 4 KiB page in several `read_at` calls, and abandoning the
        // rest of the log on the first partial one would drop most of the
        // transaction record on every E01-backed image.
        let got = seance_core::io::read_full(ds, off, &mut page);
        if got < log_page_size {
            // A short read inside the logging area is an unreadable page, not
            // the end of the log: the pages after it are never examined.
            short_read_stop = true;
            break;
        }

        if &page[0..4] == b"RCRD" || &page[0..4] == b"CHKD" {
            let page_number = off / log_page_size as u64;
            match parse_record_page(&page, page_number, data_offset, header_len) {
                Ok((mut recs, fully_walked)) => {
                    records.append(&mut recs);
                    if !fully_walked {
                        pages_part_walked += 1;
                    }
                }
                Err(_) => torn_pages += 1, // flagged torn/corrupt page, not mis-parsed
            }
        }

        off = end;
        pages_scanned += 1;
    }

    Ok(ParsedLogFile {
        restart,
        restart_page_used,
        records,
        torn_pages,
        pages_scanned,
        pages_capped,
        records_capped,
        short_read_stop,
        pages_part_walked,
        declared_beyond_source,
    })
}
