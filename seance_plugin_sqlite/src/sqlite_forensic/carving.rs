//! Deleted-record recovery: freeblock chains, unallocated/slack carving, and
//! text salvage.
//!
//! Ported and adapted from the reference `carving.go`
//! (`CarveUnallocatedSpace`, `isLikelyValidRecord`, `salvageTextFromPayload`)
//! and `vacuum.go` (`RecoverFreeblockChains`). Two complementary passes run over
//! each page's unallocated bytes:
//!
//! 1. **Record-shape carving** — scan for `varint(payload_len) + varint(rowid) +
//!    record` byte runs and decode them, keeping only records that pass validity
//!    heuristics.
//! 2. **Text salvage** — recover printable string runs from freeblock bodies and
//!    slack that the record decoder could not reconstruct (e.g. when a freeblock
//!    header clobbered the original cell's length/rowid varints).

use super::btree::{read_cell_payload, PAGE_INTERIOR_TABLE, PAGE_LEAF_TABLE};
use super::reader::PageReader;
use super::record::{
    is_likely_text, parse_record, parse_serial_type, read_varint, serial_body_len, Value,
};
use super::RecoverySource;

/// A record (or salvaged string) recovered from unallocated space.
#[derive(Debug, Clone)]
pub struct CarvedRow {
    pub rowid: Option<i64>,
    pub values: Vec<Value>,
    pub page_index: usize,
    pub source: RecoverySource,
    pub notes: Vec<String>,
}

const MAX_CARVE_PAYLOAD: i64 = 16384;
const MIN_TEXT_RUN: usize = 5;
/// A freeblock's `[next][size]` header clobbers the first 4 bytes of the cell it
/// replaces; the deleted cell's leading `payload_len`/`rowid`/`header_len`
/// varints are usually gone. When reconstructing columns we skip a few residual
/// bytes to find where the surviving serial-type header resumes.
const MAX_CLOBBER_SKIP: usize = 12;

/// Reconstruct a deleted record's columns from a region whose leading
/// length/rowid/header varints were clobbered (a freeblock's `[next][size]`
/// header). The surviving bytes are the *tail* of the serial-type header
/// followed by the column bodies, so a normal `parse_record` (which expects the
/// header-length varint first) fails and the whole run collapses into one salvaged
/// string. Instead, search for the `(skip, header-end)` split whose serial types'
/// body lengths consume the region **exactly** and whose decoded columns are
/// clean — the exact-fit constraint disambiguates the true alignment. Returns the
/// split columns, or `None` when no clean alignment fits (caller falls back to
/// text salvage). Handles a single record per region; coalesced multi-cell
/// freeblocks fall through to salvage.
fn recover_clobbered_columns(region: &[u8]) -> Option<Vec<Value>> {
    let n = region.len();
    if n < 3 {
        return None;
    }
    let max_skip = MAX_CLOBBER_SKIP.min(n.saturating_sub(2));
    for skip in 0..=max_skip {
        let mut serials: Vec<i64> = Vec::new();
        let mut body_total: usize = 0;
        let mut p = skip;
        while p < n && serials.len() < 40 {
            let (st, used) = read_varint(region, p);
            if used == 0 {
                break;
            }
            let Some(blen) = serial_body_len(st) else {
                break; // reserved/invalid serial type: this alignment is wrong
            };
            if blen > MAX_CARVE_PAYLOAD as usize {
                break;
            }
            serials.push(st);
            body_total += blen;
            p += used;
            // Header = region[skip..p]; body = region[p..p+body_total]. Accept only
            // an exact fit to the region end, with >= 2 columns and clean values.
            if serials.len() >= 2 && p + body_total == n {
                let vals = decode_columns(region, p, &serials);
                if columns_plausible(&vals) {
                    return Some(vals);
                }
            }
        }
    }
    None
}

fn decode_columns(region: &[u8], body_start: usize, serials: &[i64]) -> Vec<Value> {
    let mut vals = Vec::with_capacity(serials.len());
    let mut off = body_start;
    for &st in serials {
        let (v, len) = parse_serial_type(region, off, st);
        off += len;
        vals.push(v);
    }
    vals
}

/// A reconstructed column set is only accepted when it has >= 2 non-null columns,
/// at least one convincingly-textual column, and no text column carrying control
/// or replacement bytes. A misaligned alignment (e.g. across a coalesced
/// freeblock holding two records) splits fields mid-value and leaves control
/// bytes inside a "text" column; rejecting those keeps a wrong multi-column claim
/// from beating clean text salvage.
fn columns_plausible(vals: &[Value]) -> bool {
    let mut text_ok = 0;
    let mut non_null = 0;
    for v in vals {
        match v {
            Value::Null => {}
            Value::Text(s) => {
                non_null += 1;
                if s.is_empty() {
                    continue;
                }
                // A control byte (other than tab/newline/CR) or a UTF-8
                // replacement char inside a text column means the alignment cut
                // through binary — reject the whole reconstruction.
                if s.chars().any(|c| {
                    (c.is_control() && c != '\t' && c != '\n' && c != '\r') || c == '\u{FFFD}'
                }) {
                    return false;
                }
                if is_likely_text(s) {
                    text_ok += 1;
                } else if s.chars().count() > 4 {
                    return false;
                }
            }
            _ => non_null += 1,
        }
    }
    non_null >= 2 && text_ok >= 1
}

/// A `[start, end)` byte range occupied by a page freeblock.
fn freeblock_ranges(page_data: &[u8], content_offset: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    if content_offset + 3 > page_data.len() {
        return ranges;
    }
    let page_type = page_data[content_offset];
    if !matches!(
        page_type,
        PAGE_LEAF_TABLE | PAGE_INTERIOR_TABLE | 0x02 | 0x0A
    ) {
        return ranges;
    }
    let mut current =
        u16::from_be_bytes([page_data[content_offset + 1], page_data[content_offset + 2]]) as usize;
    let mut seen = std::collections::HashSet::new();
    while current != 0 {
        if !seen.insert(current) || current + 4 > page_data.len() || current < content_offset {
            break;
        }
        let next = u16::from_be_bytes([page_data[current], page_data[current + 1]]) as usize;
        let size = u16::from_be_bytes([page_data[current + 2], page_data[current + 3]]) as usize;
        if size < 4 {
            break;
        }
        let end = (current + size).min(page_data.len());
        ranges.push((current, end));
        current = next;
    }
    ranges
}

/// Heuristic filter to reject carved garbage. Ported from `isLikelyValidRecord`.
fn is_likely_valid_record(values: &[Value], notes: &[String]) -> bool {
    if notes.len() > 1 {
        return false;
    }
    if values.len() < 2 || values.len() > 40 {
        return false;
    }
    let mut null_count = 0;
    let mut valid_text_count = 0;
    for v in values {
        match v {
            Value::Null => null_count += 1,
            Value::Text(s) if !s.is_empty() => {
                if is_likely_text(s) {
                    valid_text_count += 1;
                } else if s.len() > 10 {
                    return false;
                }
            }
            _ => {}
        }
    }
    if null_count == values.len() {
        return false;
    }
    if (null_count as f64) / (values.len() as f64) > 0.5 {
        return false;
    }
    if valid_text_count == 0 {
        return false;
    }
    let non_null = values.len() - null_count;
    if non_null < 2 {
        return false;
    }
    true
}

fn offset_in_ranges(off: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|&(s, e)| off >= s && off < e)
}

/// Carves deleted records from a single page. `origin` selects the recovery
/// source label used for records found in pure slack (Unallocated for live
/// pages, Freelist for freelist pages). Freeblock-resident records are always
/// labelled Freeblock.
pub fn carve_page(
    reader: &PageReader,
    page_data: &[u8],
    content_offset: usize,
    page_index: usize,
    slack_source: RecoverySource,
) -> Vec<CarvedRow> {
    let mut out = Vec::new();
    if content_offset >= page_data.len() {
        return out;
    }
    let page_type = page_data[content_offset];
    if page_type != PAGE_LEAF_TABLE && page_type != PAGE_INTERIOR_TABLE {
        return out;
    }
    if content_offset + 5 > page_data.len() {
        return out;
    }
    let num_cells =
        u16::from_be_bytes([page_data[content_offset + 3], page_data[content_offset + 4]]) as usize;
    let header_size = if page_type == PAGE_INTERIOR_TABLE {
        12
    } else {
        8
    };

    // Build the live-allocation map: header + cell pointer array + each live
    // cell extent. A genuine deleted record lives entirely outside this map.
    let mut live_allocated = vec![false; page_data.len()];
    let hdr_end = (content_offset + header_size + num_cells * 2).min(page_data.len());
    for b in live_allocated.iter_mut().take(hdr_end).skip(content_offset) {
        *b = true;
    }
    for i in 0..num_cells {
        let ptr_off = content_offset + header_size + i * 2;
        if ptr_off + 2 > page_data.len() {
            continue;
        }
        let cell = u16::from_be_bytes([page_data[ptr_off], page_data[ptr_off + 1]]) as usize;
        if cell >= page_data.len() {
            continue;
        }
        let (payload_len, consumed) = read_varint(page_data, cell);
        let mut cursor = cell + consumed;
        if page_type == PAGE_INTERIOR_TABLE {
            let (_c, cc) = read_varint(page_data, cursor);
            cursor += cc;
        }
        let (_rid, cr) = read_varint(page_data, cursor);
        cursor += cr;
        let cell_end = (cursor + payload_len.max(0) as usize).min(page_data.len());
        for b in live_allocated.iter_mut().take(cell_end).skip(cell) {
            *b = true;
        }
    }

    let fb_ranges = freeblock_ranges(page_data, content_offset);
    let scan_start = (content_offset + header_size + num_cells * 2).min(page_data.len());

    // `consumed` tracks live bytes plus any bytes claimed by a carved record, so
    // the salvage pass does not re-emit text already returned as a structured row.
    let mut consumed = live_allocated.clone();

    // Pass 1: record-shape carving over unallocated bytes. A candidate is kept
    // only when it decodes cleanly AND its byte span lies wholly in unallocated
    // space (a record that spills into a live cell is a false positive).
    let mut i = scan_start;
    while i + 4 < page_data.len() {
        if consumed[i] {
            i += 1;
            continue;
        }
        if i + 10 > page_data.len() {
            break;
        }
        let (payload_len, con) = read_varint(page_data, i);
        if payload_len > 0 && payload_len < MAX_CARVE_PAYLOAD && con > 0 && con <= 9 {
            let mut cursor = i + con;
            if page_type == PAGE_LEAF_TABLE && cursor + 9 < page_data.len() {
                let (rowid, cr) = read_varint(page_data, cursor);
                cursor += cr;
                if cursor < page_data.len() {
                    let payload =
                        read_cell_payload(reader, page_data, cursor, payload_len as usize);
                    if !payload.is_empty() {
                        let (values, notes) = parse_record(&payload, payload_len as usize);
                        let record_end = (cursor + payload.len()).min(page_data.len());
                        let overlaps_live = (i..record_end).any(|k| live_allocated[k]);
                        // Require a clean decode and no overlap with live cells:
                        // freeblock-clobbered fragments either fail to decode
                        // cleanly or run into adjacent live data. Text that cannot
                        // be reconstructed this way is caught by the salvage pass.
                        if !values.is_empty()
                            && notes.is_empty()
                            && !overlaps_live
                            && is_likely_valid_record(&values, &notes)
                        {
                            let source = if offset_in_ranges(i, &fb_ranges) {
                                RecoverySource::Freeblock
                            } else {
                                slack_source
                            };
                            for b in consumed.iter_mut().take(record_end).skip(i) {
                                *b = true;
                            }
                            out.push(CarvedRow {
                                rowid: Some(rowid),
                                values,
                                page_index,
                                source,
                                notes: vec!["recovered from unallocated space".to_string()],
                            });
                            i = record_end;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }

    // Pass 1.5: freeblock column reconstruction. A freeblock's [next][size] header
    // clobbers the cell's leading varints, so Pass 1 can't decode it and the bytes
    // would otherwise collapse into a single salvaged string. Recover the column
    // split from the surviving serial-type header + body instead. Runs before
    // text salvage so a clean multi-column row wins over one mashed-together field.
    for &(fb_start, fb_end) in &fb_ranges {
        let body_start = fb_start + 4; // skip the [next(2)][size(2)] header
        if body_start >= fb_end || fb_end > page_data.len() {
            continue;
        }
        if consumed[body_start] {
            continue; // already claimed by a Pass 1 record
        }
        let region = &page_data[body_start..fb_end];
        if let Some(vals) = recover_clobbered_columns(region) {
            for b in consumed.iter_mut().take(fb_end).skip(fb_start) {
                *b = true;
            }
            out.push(CarvedRow {
                rowid: None,
                values: vals,
                page_index,
                source: RecoverySource::Freeblock,
                notes: vec!["reconstructed from freeblock (header realigned)".to_string()],
            });
        }
    }

    // Pass 2: text salvage over bytes still unclaimed (recovers content the record
    // decoder could not reconstruct, e.g. freeblock-clobbered headers).
    let mut run_start: Option<usize> = None;
    let mut j = scan_start;
    while j <= page_data.len() {
        let printable = j < page_data.len() && !consumed[j] && is_printable(page_data[j]);
        match (printable, run_start) {
            (true, None) => run_start = Some(j),
            (false, Some(start)) => {
                let run = &page_data[start..j];
                if run.len() >= MIN_TEXT_RUN {
                    let text = String::from_utf8_lossy(run).into_owned();
                    if is_likely_text(&text) {
                        let source = if offset_in_ranges(start, &fb_ranges) {
                            RecoverySource::Freeblock
                        } else {
                            RecoverySource::Slack
                        };
                        out.push(CarvedRow {
                            rowid: None,
                            values: vec![Value::Text(text)],
                            page_index,
                            source,
                            notes: vec!["salvaged text from slack".to_string()],
                        });
                    }
                }
                run_start = None;
            }
            _ => {}
        }
        j += 1;
    }

    out
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_rejects_all_null() {
        let vals = vec![Value::Null, Value::Null];
        assert!(!is_likely_valid_record(&vals, &[]));
    }

    #[test]
    fn validity_accepts_mixed_record_with_text() {
        let vals = vec![Value::Int(1), Value::Text("Alice".to_string())];
        assert!(is_likely_valid_record(&vals, &[]));
    }

    #[test]
    fn validity_rejects_extra_corruption_notes() {
        let vals = vec![Value::Int(1), Value::Text("Alice".to_string())];
        let notes = vec!["a".to_string(), "b".to_string()];
        assert!(!is_likely_valid_record(&vals, &notes));
    }

    #[test]
    fn freeblock_reconstruction_splits_clobbered_columns() {
        // Surviving bytes after a freeblock [next][size] header clobbered the
        // cell's leading varints: [sender-serial=19][body-serial=39]["bob"][body].
        // body-serial 39 -> text of (39-13)/2 = 13 chars.
        let mut region = vec![0x13u8, 0x27]; // serial 19 (text3), serial 39 (text13)
        region.extend_from_slice(b"bob");
        region.extend_from_slice(b"hello world!!"); // 13 chars
        let vals = recover_clobbered_columns(&region).expect("should reconstruct");
        assert_eq!(vals.len(), 2, "should split into two columns, not mash");
        assert_eq!(vals[0], Value::Text("bob".to_string()));
        assert_eq!(vals[1], Value::Text("hello world!!".to_string()));
    }

    #[test]
    fn freeblock_reconstruction_absorbs_residual_prefix_bytes() {
        // A couple of residual clobbered bytes precede the surviving serial tail;
        // the skip search must find the real alignment.
        let mut region = vec![0xAB, 0xCD]; // residual garbage from the clobber
        region.push(0x13); // sender serial (text3)
        region.push(0x27); // body serial (text13)
        region.extend_from_slice(b"eve");
        region.extend_from_slice(b"meet at seven"); // 13 chars
        let vals = recover_clobbered_columns(&region).expect("should reconstruct");
        assert_eq!(vals[0], Value::Text("eve".to_string()));
        assert_eq!(vals[1], Value::Text("meet at seven".to_string()));
    }

    #[test]
    fn freeblock_reconstruction_rejects_non_fitting_garbage() {
        // Random bytes with no serial/body alignment that reaches the end exactly
        // must not be misreported as a record.
        let region = [0x91u8, 0x44, 0x02, 0x77, 0xF0, 0x13, 0x9C, 0x21];
        assert!(recover_clobbered_columns(&region).is_none());
    }
}
