//! SQLite 100-byte database header parsing with corruption resilience.
//!
//! Ported from the vendored Go reference `internal/sqliteheader/header.go`:
//! zeroed/fuzzy magic tolerance, brute-force page-size detection, page-size
//! inference from file length, and magic-offset scanning.

pub const HEADER_LEN: usize = 100;
pub const MAGIC: &[u8; 16] = b"SQLite format 3\x00";
const MAX_SCAN_OFFSET: usize = 65536;

pub const COMMON_PAGE_SIZES: [usize; 8] = [4096, 2048, 8192, 1024, 16384, 32768, 65536, 512];

/// Interpreted SQLite header fields (subset relevant to forensic extraction).
#[derive(Debug, Clone)]
pub struct Header {
    pub magic_ok: bool,
    pub page_size: usize,
    pub reserved_space: usize,
    pub file_change_counter: u32,
    pub database_size_pages: u32,
    pub first_freelist_trunk: u32,
    pub total_freelist_pages: u32,
    pub schema_format: u32,
    pub largest_root_page: u32,
    pub text_encoding: u32,
    pub auto_vacuum_mode: u32,
    pub sqlite_version: u32,
    pub warnings: Vec<String>,
}

/// Text encoding as recorded at header offset 56.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Header {
    pub fn encoding(&self) -> TextEncoding {
        match self.text_encoding {
            2 => TextEncoding::Utf16Le,
            3 => TextEncoding::Utf16Be,
            _ => TextEncoding::Utf8,
        }
    }
}

fn be_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_be_bytes([data[off], data[off + 1]])
}

fn be_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn is_valid_page_size(size: usize) -> bool {
    if size == 0 {
        return false;
    }
    if size == 65536 {
        return true;
    }
    if !(512..=65536).contains(&size) {
        return false;
    }
    size & (size - 1) == 0
}

fn is_all_zero(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}

/// Up to 3 differing bytes counts as a fuzzy match (bit-flip corruption).
fn is_fuzzy_match(got: &[u8], expected: &[u8]) -> bool {
    if got.len() != expected.len() {
        return false;
    }
    let diffs = got.iter().zip(expected).filter(|(a, b)| a != b).count();
    diffs > 0 && diffs <= 3
}

/// Heuristic: does this look like a SQLite database despite a corrupt magic?
/// Requires BOTH a valid page-1 b-tree type byte AND a plausible page size.
fn looks_like_sqlite(data: &[u8]) -> bool {
    // Reads the page-1 b-tree type byte at index HEADER_LEN (the first byte
    // *after* the 100-byte header), so require strictly more than HEADER_LEN
    // bytes -- `< HEADER_LEN` let a len-100 slice through and panicked on
    // `data[HEADER_LEN]`.
    if data.len() <= HEADER_LEN {
        return false;
    }
    let page_type = data[HEADER_LEN];
    let valid_type = matches!(page_type, 0x0D | 0x05 | 0x02 | 0x0A);
    let ps_raw = be_u16(data, 16);
    let page_size = if ps_raw == 1 { 65536 } else { ps_raw as usize };
    let valid_size = COMMON_PAGE_SIZES.contains(&page_size);
    valid_type && valid_size
}

/// Brute-forces the page size by scoring b-tree page types at each candidate.
/// Returns `Some((size, reason))` when a candidate scores >= 10.
pub fn brute_force_page_size(data: &[u8]) -> Option<(usize, String)> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let mut best = 0usize;
    let mut best_score = 0i32;
    for &ps in COMMON_PAGE_SIZES.iter() {
        if data.len() < ps {
            continue;
        }
        let mut score = 0i32;
        if data.len() > 100 {
            let pt = data[100];
            if matches!(pt, 0x0D | 0x05 | 0x02 | 0x0A | 0x00) {
                score += 10;
            }
        }
        let mut page_num = 1;
        while page_num < 3 && page_num * ps < data.len() {
            let pt = data[page_num * ps];
            if matches!(pt, 0x0D | 0x05 | 0x02 | 0x0A | 0x00) {
                score += 5;
            }
            page_num += 1;
        }
        let remainder = data.len() % ps;
        if remainder == 0 {
            score += 3;
        } else if remainder < ps / 10 {
            score += 1;
        }
        if score > best_score {
            best_score = score;
            best = ps;
        }
    }
    if best > 0 && best_score >= 10 {
        Some((
            best,
            format!(
                "page size {} detected via brute-force (score {})",
                best, best_score
            ),
        ))
    } else {
        None
    }
}

fn guess_page_size_from_length(length: usize) -> Option<(usize, bool)> {
    if length == 0 {
        return None;
    }
    for &c in COMMON_PAGE_SIZES.iter() {
        if length >= c && length.is_multiple_of(c) {
            return Some((c, true));
        }
    }
    for &c in COMMON_PAGE_SIZES.iter() {
        if length >= c {
            return Some((c, false));
        }
    }
    None
}

fn infer_page_size(header: &[u8], file_len: usize) -> (usize, Vec<String>) {
    let mut warnings = Vec::new();
    let raw = be_u16(header, 16) as usize;
    let page_size = if raw == 1 { 65536 } else { raw };
    if is_valid_page_size(page_size) {
        return (page_size, warnings);
    }
    match guess_page_size_from_length(file_len) {
        Some((guessed, exact)) => {
            if raw != 0 {
                warnings.push(format!(
                    "invalid header page size {}; assuming {}",
                    raw, guessed
                ));
            } else {
                warnings.push(format!("page size missing; assuming {}", guessed));
            }
            if !exact {
                warnings.push(
                    "page size guess based on file length; final page may be truncated".to_string(),
                );
            }
            (guessed, warnings)
        }
        None => {
            if let Some((bf, msg)) = brute_force_page_size(header) {
                warnings.push(msg);
                (bf, warnings)
            } else {
                warnings.push("unable to infer page size from damaged header".to_string());
                (0, warnings)
            }
        }
    }
}

/// Scans `data` for the SQLite magic string. Returns the byte offset, or `None`.
/// `Some(0)` means the file starts with the magic.
pub fn detect_offset(data: &[u8]) -> Option<usize> {
    if data.len() >= 16 && &data[..16] == MAGIC.as_slice() {
        return Some(0);
    }
    if data.len() < 16 {
        return None;
    }
    let scan_limit = data.len().min(MAX_SCAN_OFFSET);
    let mut offset = 1;
    while offset + 16 <= scan_limit {
        if &data[offset..offset + 16] == MAGIC.as_slice() {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

/// Parses the 100-byte header from `data` (which must begin at the header/magic).
///
/// Tolerates zeroed, fuzzy, and structurally-implied magic. Returns `None` only
/// when the bytes are clearly not a SQLite database and page size cannot be
/// inferred.
pub fn parse(data: &[u8]) -> Option<Header> {
    if data.is_empty() {
        return None;
    }
    let mut header = [0u8; HEADER_LEN];
    let n = data.len().min(HEADER_LEN);
    header[..n].copy_from_slice(&data[..n]);
    let mut warnings = Vec::new();

    if data.len() < HEADER_LEN {
        warnings.push(format!(
            "header truncated ({} bytes available, expected {})",
            data.len(),
            HEADER_LEN
        ));
    }

    let magic_slice = &header[..16];
    // `magic_ok` reports whether the on-disk signature was clean; the other
    // branches decide whether a damaged header is still recoverable as SQLite.
    let magic_ok = magic_slice == MAGIC.as_slice();
    if !magic_ok {
        if data.len() < 16 {
            warnings
                .push("header signature unavailable (file too small); assuming SQLite".to_string());
        } else if is_all_zero(magic_slice) {
            warnings.push("header signature zeroed; assuming SQLite".to_string());
        } else if is_fuzzy_match(magic_slice, MAGIC.as_slice()) {
            warnings.push("header signature corrupted (fuzzy match); assuming SQLite".to_string());
        } else if looks_like_sqlite(data) {
            warnings.push("header signature invalid but structure suggests SQLite".to_string());
        } else {
            return None;
        }
    }

    let (page_size, page_warnings) = infer_page_size(&header, data.len());
    warnings.extend(page_warnings);
    if page_size == 0 {
        return None;
    }

    let mut schema_format = be_u32(&header, 44);
    if schema_format == 0 {
        schema_format = 4;
    }
    let mut text_encoding = be_u32(&header, 56);
    if text_encoding == 0 {
        text_encoding = 1;
    }

    Some(Header {
        magic_ok,
        page_size,
        reserved_space: header[20] as usize,
        file_change_counter: be_u32(&header, 24),
        database_size_pages: be_u32(&header, 28),
        first_freelist_trunk: be_u32(&header, 32),
        total_freelist_pages: be_u32(&header, 36),
        schema_format,
        largest_root_page: be_u32(&header, 52),
        text_encoding,
        auto_vacuum_mode: be_u32(&header, 64),
        sqlite_version: be_u32(&header, 96),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_header(page_size: u16) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_LEN + 1];
        h[..16].copy_from_slice(MAGIC.as_slice());
        h[16..18].copy_from_slice(&page_size.to_be_bytes());
        h[HEADER_LEN] = 0x0D; // leaf table page type on page 1
        h
    }

    #[test]
    fn parses_valid_header() {
        let h = synthetic_header(4096);
        let parsed = parse(&h).expect("should parse");
        assert!(parsed.magic_ok);
        assert_eq!(parsed.page_size, 4096);
    }

    #[test]
    fn page_size_one_means_65536() {
        let h = synthetic_header(1);
        let parsed = parse(&h).unwrap();
        assert_eq!(parsed.page_size, 65536);
    }

    #[test]
    fn zeroed_magic_recovers_via_structure() {
        let mut h = synthetic_header(4096);
        for b in h[..16].iter_mut() {
            *b = 0;
        }
        let parsed = parse(&h).expect("zeroed magic should recover");
        assert!(parsed.warnings.iter().any(|w| w.contains("zeroed")));
        assert_eq!(parsed.page_size, 4096);
    }

    #[test]
    fn non_sqlite_returns_none() {
        let junk = vec![0xAAu8; 200];
        assert!(parse(&junk).is_none());
    }

    #[test]
    fn garbage_magic_at_exactly_header_len_does_not_panic() {
        // Regression: `looks_like_sqlite` reads the page-1 b-tree type byte at
        // index HEADER_LEN -- the first byte AFTER the 100-byte header. A buffer
        // of exactly HEADER_LEN bytes with a garbage (non-zero, non-fuzzy)
        // signature passed the `< HEADER_LEN` length guard, then indexed
        // data[100] and panicked ("len is 100 but index is 100"). Small carved
        // fragments hit this during real image ingestion.
        let data = vec![0xABu8; HEADER_LEN]; // exactly 100 bytes, garbage magic
        assert!(parse(&data).is_none());
    }

    #[test]
    fn garbage_magic_below_and_above_header_len_do_not_panic() {
        // Exercise the whole boundary band, not just one length.
        for len in [16usize, 99, 100, 101, 128] {
            let data = vec![0xABu8; len];
            let _ = parse(&data); // must never panic
        }
    }

    #[test]
    fn detect_offset_finds_shifted_magic() {
        let mut data = vec![0u8; 600];
        data[512..512 + 16].copy_from_slice(MAGIC.as_slice());
        assert_eq!(detect_offset(&data), Some(512));
    }
}
