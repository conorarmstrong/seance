//! B-tree page and cell parsing plus table-tree traversal.
//!
//! Ported from the reference `parser.go` (`parsePageBytes`, `parseCell`,
//! `readPayload`) and `MapTablePages`. Every offset is bounds-checked; interior
//! traversal is cycle-guarded and depth-limited so malformed trees cannot loop
//! or overflow the stack.

use super::reader::PageReader;
use super::record::read_varint;
use super::record::{parse_record, Value};
use std::collections::HashSet;

/// A row decoded from a table b-tree leaf cell.
#[derive(Debug, Clone)]
pub struct RawRow {
    pub rowid: Option<i64>,
    pub values: Vec<Value>,
    pub page_index: usize,
    pub notes: Vec<String>,
}

pub const PAGE_LEAF_TABLE: u8 = 0x0D;
pub const PAGE_INTERIOR_TABLE: u8 = 0x05;
pub const PAGE_LEAF_INDEX: u8 = 0x02;
pub const PAGE_INTERIOR_INDEX: u8 = 0x0A;

const MAX_DEPTH: usize = 100;

/// Reads a leaf-table cell payload, following the overflow chain when the record
/// spills beyond the local page. Returns `(payload, _consumed)`.
fn read_payload(
    reader: &PageReader,
    page_data: &[u8],
    offset: usize,
    payload_length: usize,
) -> Vec<u8> {
    if offset > page_data.len() {
        return Vec::new();
    }
    let max_leaf = reader.max_leaf_payload();
    let usable = reader.usable_size();
    let min_leaf = reader.min_leaf_payload();

    let mut local = payload_length;
    if payload_length > max_leaf {
        if usable <= 4 {
            local = 0;
        } else {
            local = min_leaf + ((payload_length - min_leaf) % (usable - 4));
            if local > max_leaf {
                local = min_leaf;
            }
        }
    }
    if local > payload_length {
        local = payload_length;
    }
    let end = (offset + local).min(page_data.len());
    let mut payload = page_data[offset..end].to_vec();
    let remaining = payload_length.saturating_sub(payload.len());
    let overflow_off = offset + payload.len();
    if remaining > 0 && overflow_off + 4 <= page_data.len() {
        let first = i64::from(u32::from_be_bytes([
            page_data[overflow_off],
            page_data[overflow_off + 1],
            page_data[overflow_off + 2],
            page_data[overflow_off + 3],
        ]));
        let extra = reader.read_overflow_chain(first, remaining);
        payload.extend_from_slice(&extra);
    }
    payload
}

/// Parses one cell of a page. For leaf-table pages returns the decoded row.
/// Interior-table cells only yield child pointers (handled by [`walk_table`]),
/// so this returns `None` for them.
fn parse_leaf_cell(
    reader: &PageReader,
    page_data: &[u8],
    cell_offset: usize,
    page_index: usize,
) -> Option<RawRow> {
    if cell_offset >= page_data.len() {
        return None;
    }
    let mut cursor = cell_offset;
    let (payload_length, consumed) = read_varint(page_data, cursor);
    cursor += consumed;
    let (rowid, consumed_rowid) = read_varint(page_data, cursor);
    cursor += consumed_rowid;
    if payload_length < 0 {
        return None;
    }
    let payload = read_payload(reader, page_data, cursor, payload_length as usize);
    let (values, notes) = parse_record(&payload, payload_length as usize);
    if values.is_empty() && !notes.is_empty() {
        return None;
    }
    Some(RawRow {
        rowid: Some(rowid),
        values,
        page_index,
        notes,
    })
}

/// Returns the cell pointer offsets declared in a page's header.
fn cell_pointers(page_data: &[u8], content_offset: usize, page_type: u8) -> Vec<usize> {
    if content_offset + 5 > page_data.len() {
        return Vec::new();
    }
    let num_cells =
        u16::from_be_bytes([page_data[content_offset + 3], page_data[content_offset + 4]]) as usize;
    let header_size = if page_type == PAGE_INTERIOR_TABLE || page_type == PAGE_INTERIOR_INDEX {
        12
    } else {
        8
    };
    let mut ptrs = Vec::with_capacity(num_cells);
    for i in 0..num_cells {
        let ptr_off = content_offset + header_size + i * 2;
        if ptr_off + 2 > page_data.len() {
            break;
        }
        ptrs.push(u16::from_be_bytes([page_data[ptr_off], page_data[ptr_off + 1]]) as usize);
    }
    ptrs
}

/// Decodes all live leaf-table rows on a single page's bytes. Used both for main
/// database pages and for WAL/journal frame pages. Only leaf-table pages yield
/// rows; other page types yield an empty vector.
pub fn parse_leaf_page_rows(
    reader: &PageReader,
    page_data: &[u8],
    content_offset: usize,
    page_index: usize,
) -> Vec<RawRow> {
    if content_offset >= page_data.len() {
        return Vec::new();
    }
    let page_type = page_data[content_offset];
    if page_type != PAGE_LEAF_TABLE {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for ptr in cell_pointers(page_data, content_offset, page_type) {
        if let Some(row) = parse_leaf_cell(reader, page_data, ptr, page_index) {
            rows.push(row);
        }
    }
    rows
}

/// Walks the table b-tree rooted at 1-based `root_page`, returning every live
/// row and the set of page indexes visited (for table<->page mapping). Interior
/// pages are traversed via their child pointers; leaf pages yield rows.
pub fn walk_table(reader: &PageReader, root_page: i64) -> (Vec<RawRow>, HashSet<usize>) {
    let mut rows = Vec::new();
    let mut visited: HashSet<usize> = HashSet::new();
    if root_page <= 0 {
        return (rows, visited);
    }
    // Stack of (page_index, depth).
    let mut stack: Vec<(usize, usize)> = vec![((root_page - 1) as usize, 0)];
    while let Some((page_index, depth)) = stack.pop() {
        if depth > MAX_DEPTH || !visited.insert(page_index) {
            continue;
        }
        let page = reader.read_page(page_index);
        let content_offset = reader.content_offset(page_index);
        if content_offset >= page.len() {
            continue;
        }
        let page_type = page[content_offset];
        match page_type {
            PAGE_LEAF_TABLE => {
                for ptr in cell_pointers(&page, content_offset, page_type) {
                    if let Some(row) = parse_leaf_cell(reader, &page, ptr, page_index) {
                        rows.push(row);
                    }
                }
            }
            PAGE_INTERIOR_TABLE => {
                for cell in cell_pointers(&page, content_offset, page_type) {
                    if cell + 4 <= page.len() {
                        let child = u32::from_be_bytes([
                            page[cell],
                            page[cell + 1],
                            page[cell + 2],
                            page[cell + 3],
                        ]) as i64;
                        if child > 0 {
                            stack.push(((child - 1) as usize, depth + 1));
                        }
                    }
                }
                if content_offset + 12 <= page.len() {
                    let right = u32::from_be_bytes([
                        page[content_offset + 8],
                        page[content_offset + 9],
                        page[content_offset + 10],
                        page[content_offset + 11],
                    ]) as i64;
                    if right > 0 {
                        stack.push(((right - 1) as usize, depth + 1));
                    }
                }
            }
            _ => {}
        }
    }
    (rows, visited)
}

/// Reads a leaf-table cell payload directly (used by the carver). Public wrapper
/// around the bounds-checked payload reader.
pub fn read_cell_payload(
    reader: &PageReader,
    page_data: &[u8],
    offset: usize,
    payload_length: usize,
) -> Vec<u8> {
    read_payload(reader, page_data, offset, payload_length)
}
