//! Write-Ahead Log (`-wal`) frame parsing.
//!
//! Parses the 32-byte WAL header and the sequence of 24-byte-header + page-data
//! frames, tolerating a zeroed magic (recovered via the database page size) and
//! a truncated trailing frame. Ported from the reference `internal/wal/wal.go`
//! (correct on-disk layout).
//!
//! # Checkpoint generations, and why the salts are read
//!
//! SQLite changes the WAL header's two salt values at every reset, and each
//! frame repeats the salts current when it was written. A frame whose salts do
//! not match the header's therefore belongs to an **earlier generation**: it
//! was written before the last checkpoint and has since been overwritten in
//! the log's own terms, though its bytes are still on disk. Those rows are
//! older than the live database and recovering them is the point of reading a
//! WAL forensically — but presenting them as current would be wrong, so the
//! parse marks each frame with `current_generation` and counts the rest.
//! Before this, both salts were parsed, stored on every frame and read
//! nowhere, while this comment claimed the boundaries were handled.

const WAL_HEADER_SIZE: usize = 32;
const WAL_FRAME_HEADER_SIZE: usize = 24;

fn be_u32(d: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

/// A single WAL frame: the pre/post image of one database page.
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_index: usize,
    pub page_number: u32,
    pub page_data: Vec<u8>,
    pub is_commit: bool,
    pub salt: [u32; 2],
    /// Whether this frame's salts match the WAL header's — that is, whether it
    /// belongs to the log's current generation. `false` means the frame
    /// predates the last checkpoint or reset: still readable, but older than
    /// the live database.
    pub current_generation: bool,
}

/// Result of parsing a WAL file.
#[derive(Debug, Default)]
pub struct WalParse {
    pub page_size: usize,
    pub frames: Vec<Frame>,
    pub warnings: Vec<String>,
    pub truncated: bool,
    /// The header's salt pair, which defines the current generation.
    pub salt: [u32; 2],
    /// Frames whose salts do not match the header's.
    pub stale_generation_frames: usize,
}

/// Parses a `-wal` byte buffer. `expected_page_size` (the database page size) is
/// used to recover a zeroed WAL page-size field or magic.
pub fn parse(data: &[u8], expected_page_size: usize) -> WalParse {
    let mut result = WalParse::default();
    if data.len() < WAL_HEADER_SIZE {
        result
            .warnings
            .push("WAL truncated before header".to_string());
        return result;
    }
    let magic = be_u32(data, 0);
    let magic_ok = magic == 0x377F_0682 || magic == 0x377F_0683;
    if !magic_ok {
        if magic == 0 && expected_page_size > 0 {
            result
                .warnings
                .push("WAL magic zeroed; recovering via database page size".to_string());
        } else {
            result
                .warnings
                .push(format!("WAL header magic mismatch (0x{:08X})", magic));
            return result;
        }
    }

    let mut page_size = be_u32(data, 8) as usize;
    if page_size == 0 {
        page_size = if expected_page_size > 0 {
            expected_page_size
        } else {
            1024
        };
        result
            .warnings
            .push(format!("WAL page size zeroed; using {}", page_size));
    }
    result.page_size = page_size;
    result.salt = [be_u32(data, 16), be_u32(data, 20)];

    let mut offset = WAL_HEADER_SIZE;
    let mut frame_index = 0;
    while offset + WAL_FRAME_HEADER_SIZE <= data.len() {
        let fh = &data[offset..offset + WAL_FRAME_HEADER_SIZE];
        let page_number = be_u32(fh, 0);
        let db_size = be_u32(fh, 4);
        let salt0 = be_u32(fh, 8);
        let salt1 = be_u32(fh, 12);
        let payload_start = offset + WAL_FRAME_HEADER_SIZE;
        let payload_end = payload_start + page_size;
        if payload_end > data.len() {
            result.warnings.push(format!(
                "WAL frame {} truncated ({} of {} page bytes)",
                frame_index,
                data.len() - payload_start,
                page_size
            ));
            result.truncated = true;
            break;
        }
        let current_generation = [salt0, salt1] == result.salt;
        if !current_generation {
            result.stale_generation_frames += 1;
        }
        result.frames.push(Frame {
            frame_index,
            page_number,
            page_data: data[payload_start..payload_end].to_vec(),
            is_commit: db_size != 0,
            salt: [salt0, salt1],
            current_generation,
        });
        offset = payload_end;
        frame_index += 1;
    }
    if result.stale_generation_frames > 0 {
        result.warnings.push(format!(
            concat!(
                "{} of {} WAL frames carry salts other than the header's, so they ",
                "were written before the last checkpoint or reset; their rows are ",
                "older than the live database"
            ),
            result.stale_generation_frames,
            result.frames.len()
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_wal(page_size: usize, pages: &[(u32, u8)]) -> Vec<u8> {
        let mut d = vec![0u8; WAL_HEADER_SIZE];
        d[0..4].copy_from_slice(&0x377F_0682u32.to_be_bytes());
        d[8..12].copy_from_slice(&(page_size as u32).to_be_bytes());
        for (i, (pn, fill)) in pages.iter().enumerate() {
            let mut fh = vec![0u8; WAL_FRAME_HEADER_SIZE];
            fh[0..4].copy_from_slice(&pn.to_be_bytes());
            // last frame commit
            if i == pages.len() - 1 {
                fh[4..8].copy_from_slice(&10u32.to_be_bytes());
            }
            d.extend_from_slice(&fh);
            d.extend_from_slice(&vec![*fill; page_size]);
        }
        d
    }

    /// A frame whose salts differ from the header's was written before the last
    /// checkpoint or reset. Both salts were parsed and stored and read nowhere,
    /// so a log holding two generations of the same page presented both as
    /// current.
    #[test]
    fn a_frame_from_an_earlier_generation_is_marked_and_counted() {
        let mut wal = build_wal(1024, &[(2, 0xAA), (3, 0xBB)]);
        // Give the header a salt pair; the frames still carry zeros, so both
        // frames belong to an earlier generation.
        wal[16..20].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        wal[20..24].copy_from_slice(&0x9ABC_DEF0u32.to_be_bytes());

        let parsed = parse(&wal, 1024);
        assert_eq!(parsed.frames.len(), 2);
        assert_eq!(parsed.stale_generation_frames, 2);
        assert!(parsed.frames.iter().all(|f| !f.current_generation));
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.contains("before the last checkpoint")),
            "the count must be stated, not just held: {:?}",
            parsed.warnings
        );

        // Match the second frame's salts to the header: one generation each.
        let frame2 = WAL_HEADER_SIZE + WAL_FRAME_HEADER_SIZE + 1024;
        wal[frame2 + 8..frame2 + 12].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        wal[frame2 + 12..frame2 + 16].copy_from_slice(&0x9ABC_DEF0u32.to_be_bytes());
        let parsed = parse(&wal, 1024);
        assert_eq!(parsed.stale_generation_frames, 1);
        assert!(!parsed.frames[0].current_generation);
        assert!(parsed.frames[1].current_generation);
    }

    #[test]
    fn parses_frames() {
        let wal = build_wal(1024, &[(2, 0xAA), (3, 0xBB)]);
        let parsed = parse(&wal, 1024);
        assert_eq!(parsed.frames.len(), 2);
        assert_eq!(parsed.frames[0].page_number, 2);
        assert!(parsed.frames[1].is_commit);
        assert!(!parsed.truncated);
    }

    #[test]
    fn truncated_frame_is_noted_not_panicked() {
        let mut wal = build_wal(1024, &[(2, 0xAA), (3, 0xBB)]);
        wal.truncate(wal.len() - 500); // cut the last frame's page data
        let parsed = parse(&wal, 1024);
        assert_eq!(parsed.frames.len(), 1);
        assert!(parsed.truncated);
    }

    #[test]
    fn zeroed_magic_recovers_with_page_size() {
        let mut wal = build_wal(1024, &[(2, 0xAA)]);
        for b in wal[0..4].iter_mut() {
            *b = 0;
        }
        let parsed = parse(&wal, 1024);
        assert_eq!(parsed.frames.len(), 1);
    }
}
