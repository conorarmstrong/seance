//! Rollback journal (`-journal`) pre-image page parsing.
//!
//! Implements the on-disk SQLite rollback journal format: a 28-byte header
//! (page size at 24..28, sector size at 20..24), records beginning at the first
//! sector boundary, each record being `pageNumber(4) + pageData(pageSize) +
//! checksum(4)`. Zeroed page-size fields are recovered from the database page
//! size, and a truncated trailing record is tolerated. The reference Go parser
//! (`internal/journal/journal.go`) is used for its recovery ideas; the byte
//! layout here follows the actual SQLite specification.

const JOURNAL_HEADER_SIZE: usize = 28;
const DEFAULT_SECTOR: usize = 512;

fn be_u32(d: &[u8], o: usize) -> u32 {
    if o + 4 > d.len() {
        return 0;
    }
    u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

/// A journal pre-image record for one database page.
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_index: usize,
    pub page_number: u32,
    pub page_data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct JournalParse {
    pub page_size: usize,
    pub sector_size: usize,
    pub frames: Vec<Frame>,
    pub warnings: Vec<String>,
    pub truncated: bool,
}

fn round_up(offset: usize, boundary: usize) -> usize {
    if boundary == 0 {
        return offset;
    }
    offset.div_ceil(boundary) * boundary
}

/// Parses a `-journal` byte buffer. `expected_page_size` recovers a zeroed
/// page-size header field.
pub fn parse(data: &[u8], expected_page_size: usize) -> JournalParse {
    let mut result = JournalParse::default();
    if data.len() < JOURNAL_HEADER_SIZE {
        result
            .warnings
            .push("rollback journal truncated before header".to_string());
        return result;
    }

    let mut sector_size = be_u32(data, 20) as usize;
    if sector_size == 0 || sector_size > 65536 || (sector_size & (sector_size - 1)) != 0 {
        sector_size = DEFAULT_SECTOR;
    }
    let mut page_size = be_u32(data, 24) as usize;
    if page_size == 0 {
        page_size = if expected_page_size > 0 {
            expected_page_size
        } else {
            1024
        };
        result.warnings.push(format!(
            "journal page size field zeroed; using {}",
            page_size
        ));
    }
    result.page_size = page_size;
    result.sector_size = sector_size;

    let record_size = 4 + page_size + 4;
    let mut offset = round_up(JOURNAL_HEADER_SIZE, sector_size);
    let mut frame_index = 0;

    while offset + record_size <= data.len() {
        let page_number = be_u32(data, offset);
        // A zero page number marks the end of the record run (zero padding).
        if page_number == 0 {
            // Try to resync at the next sector boundary; stop if none advance.
            let next = round_up(offset + 1, sector_size);
            if next <= offset || next + record_size > data.len() {
                break;
            }
            // Only skip a bounded amount of padding.
            if next - offset > sector_size {
                break;
            }
            offset = next;
            continue;
        }
        if page_number > 4_000_000 {
            // Implausible page number: likely misaligned; stop.
            break;
        }
        let payload_start = offset + 4;
        let payload_end = payload_start + page_size;
        result.frames.push(Frame {
            frame_index,
            page_number,
            page_data: data[payload_start..payload_end].to_vec(),
        });
        frame_index += 1;
        offset = payload_end + 4;
    }

    // Note a trailing partial record.
    if offset < data.len() && offset + record_size > data.len() {
        let page_number = be_u32(data, offset);
        if page_number != 0 && page_number <= 4_000_000 {
            result.warnings.push(format!(
                "journal record {} truncated ({} of {} bytes)",
                frame_index,
                data.len() - offset,
                record_size
            ));
            result.truncated = true;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_journal(page_size: usize, sector: usize, pages: &[(u32, u8)]) -> Vec<u8> {
        let mut d = vec![0u8; JOURNAL_HEADER_SIZE];
        d[0..8].copy_from_slice(&0xd9d5_05f9_20a1_63d7u64.to_be_bytes());
        d[20..24].copy_from_slice(&(sector as u32).to_be_bytes());
        d[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());
        // pad to sector boundary
        d.resize(round_up(JOURNAL_HEADER_SIZE, sector), 0);
        for (pn, fill) in pages {
            d.extend_from_slice(&pn.to_be_bytes());
            d.extend_from_slice(&vec![*fill; page_size]);
            d.extend_from_slice(&[0u8; 4]); // checksum trailer
        }
        d
    }

    #[test]
    fn parses_sector_aligned_records() {
        let j = build_journal(1024, 512, &[(2, 0xAB), (5, 0xCD)]);
        let parsed = parse(&j, 1024);
        assert_eq!(parsed.frames.len(), 2);
        assert_eq!(parsed.frames[0].page_number, 2);
        assert_eq!(parsed.frames[1].page_number, 5);
        assert_eq!(parsed.frames[0].page_data.len(), 1024);
    }

    #[test]
    fn zeroed_page_size_recovers() {
        let mut j = build_journal(1024, 512, &[(2, 0xAB)]);
        for b in j[24..28].iter_mut() {
            *b = 0;
        }
        let parsed = parse(&j, 1024);
        assert_eq!(parsed.frames.len(), 1);
    }

    #[test]
    fn truncated_record_noted() {
        let mut j = build_journal(1024, 512, &[(2, 0xAB), (5, 0xCD)]);
        j.truncate(j.len() - 400);
        let parsed = parse(&j, 1024);
        assert_eq!(parsed.frames.len(), 1);
        assert!(parsed.truncated);
    }
}
