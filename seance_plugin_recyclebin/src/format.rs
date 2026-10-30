use chrono::{DateTime, Utc};
use seance_core::codepage::{self, CodePage};

/// A parsed Recycle Bin entry
#[derive(Debug, Clone)]
pub struct RecycleBinEntry {
    pub original_path: String,
    pub deleted_time: Option<DateTime<Utc>>,
    pub file_size: u64,
    pub recycle_bin_path: String,
    /// The `$I` record declared a longer original path than the file actually
    /// contained, so `original_path` is a prefix of the real one.
    ///
    /// Forensic meaning: the path of a deleted file is what attributes it to a
    /// user, a share, or a removable volume. A silently shortened path
    /// (`C:\Users\bob\Documents\rep` for `...\report.docx`) reads as a real
    /// location and can send an examiner to the wrong directory entirely, so a
    /// short record must say that it is short.
    pub path_truncated: bool,
    /// The single-byte code page `original_path` was decoded through, set only
    /// when the field actually carried a byte outside ASCII.
    ///
    /// Forensic meaning: a legacy INFO2 record stores the path as raw ANSI
    /// bytes with no encoding declaration, so `C:\Users\José\` is this build's
    /// reading of those bytes under an assumed code page, not text read off the
    /// disk. A volume written on a Cyrillic or Japanese system used a different
    /// one and the same bytes name a different directory. `None` means the
    /// field was pure ASCII (every code page agrees) or came from the record's
    /// UTF-16 path, where nothing was assumed.
    pub path_decode: Option<&'static str>,
}

/// Parse $I file version 1 (Vista through Win8)
/// Format:
///   0-7: Header version (u64 LE, value = 1)
///   8-15: Original file size (u64 LE)
///   16-23: Deletion time (FILETIME)
///   24+: Original path (UTF-16LE, 260 chars max, null-terminated)
pub fn parse_dollar_i_v1(data: &[u8], recycle_name: &str) -> Result<RecycleBinEntry, String> {
    if data.len() < 24 {
        return Err("$I file too small for v1 format".to_string());
    }

    let file_size = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    let deletion_filetime = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let deleted_time = seance_core::time::filetime_to_datetime(deletion_filetime);

    // Path starts at offset 24, UTF-16LE, a fixed 260-char (520-byte) field.
    let path_data = &data[24..data.len().min(24 + 520)];
    let original_path = codepage::decode_utf16le(path_data);

    // A v1 record is a fixed 544 bytes. A shorter file means the path field was
    // cut off (truncated acquisition, a capped read, a carved fragment): the
    // decoded path is a prefix, not the original location. The null terminator
    // proves the whole path survived even in a short buffer.
    let has_terminator = path_data
        .as_chunks::<2>()
        .0
        .iter()
        .any(|c| c[0] == 0 && c[1] == 0);
    let path_truncated = data.len() < 24 + 520 && !has_terminator;

    Ok(RecycleBinEntry {
        original_path,
        deleted_time,
        file_size,
        recycle_bin_path: recycle_name.to_string(),
        path_truncated,
        // A v1 path is UTF-16LE: no code page was assumed.
        path_decode: None,
    })
}

/// Parse $I file version 2 (Win10 1709+)
/// Format:
///   0-7: Header version (u64 LE, value = 2)
///   8-15: Original file size (u64 LE)
///   16-23: Deletion time (FILETIME)
///   24-27: Path length as a UTF-16 **character** count (u32 LE), including the
///          trailing null. On-disk byte length is therefore `path_len * 2`.
///   28+: Original path (UTF-16LE, variable length)
pub fn parse_dollar_i_v2(data: &[u8], recycle_name: &str) -> Result<RecycleBinEntry, String> {
    if data.len() < 28 {
        return Err("$I file too small for v2 format".to_string());
    }

    let file_size = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    let deletion_filetime = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let deleted_time = seance_core::time::filetime_to_datetime(deletion_filetime);

    // BUG-099: the field at offset 24 counts UTF-16 characters, not bytes. The
    // old code treated it as a byte length, under-reading real Win10+ paths by
    // ~half. Convert to a byte length (saturating so a hostile value cannot
    // overflow) and clamp to what the buffer actually holds.
    let path_chars = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;
    let path_bytes = path_chars.saturating_mul(2);

    // The record declares how long its path is. When the file holds fewer bytes
    // than that, the decoded path is a prefix of the deleted file's real
    // location; clamping and reporting it as the original path fabricates a
    // location that never existed.
    let declared_end = 28usize.saturating_add(path_bytes);
    let path_truncated = declared_end > data.len();
    let path_data = &data[28..declared_end.min(data.len())];
    let original_path = codepage::decode_utf16le(path_data);

    Ok(RecycleBinEntry {
        original_path,
        deleted_time,
        file_size,
        recycle_bin_path: recycle_name.to_string(),
        path_truncated,
        // A v2 path is UTF-16LE: no code page was assumed.
        path_decode: None,
    })
}

/// Outcome of walking an INFO2 table.
///
/// Forensic meaning: `entries` alone cannot distinguish a Recycle Bin that
/// held exactly this many deletions from a table whose last record was cut
/// off. `trailing_partial_record` says the buffer ended part-way through a
/// fixed-size record, so at least one more deletion existed and is not here.
pub struct Info2Scan {
    pub entries: Vec<RecycleBinEntry>,
    pub trailing_partial_record: bool,
}

/// Parse legacy INFO2 file format (pre-Vista)
/// INFO2 contains multiple fixed-size records (800 bytes each on Unicode systems)
/// Header: 5 u32 fields (20 bytes), then records
pub fn parse_info2(data: &[u8]) -> Result<Info2Scan, String> {
    if data.len() < 20 {
        return Err("INFO2 file too small".to_string());
    }

    let _version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let record_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

    if record_size == 0 || record_size > 4096 {
        return Err(format!("Invalid INFO2 record size: {}", record_size));
    }
    // The documented record layout runs to offset 280 (ANSI path 0..260,
    // deletion FILETIME 268..276, original size 276..280); the Unicode variant
    // is 800. A declared record smaller than 280 cannot hold those fields, so
    // not one deletion in the table can be decoded. The loop below would walk
    // the whole file, decode nothing and return an EMPTY entry list -- which an
    // examiner reads as "this Recycle Bin was empty" rather than "this table
    // could not be decoded". Fail instead: the caller turns an Err into a
    // visible `unresolved_structure` status record.
    if record_size < 280 {
        return Err(format!(
            "INFO2 record size {} is smaller than the 280-byte record layout: \
             no deletion in this table can be decoded",
            record_size
        ));
    }

    let mut entries = Vec::new();
    let mut pos = 20; // Skip header

    while pos + record_size <= data.len() {
        let record = &data[pos..pos + record_size];

        // Record format (Unicode, 800 bytes):
        // 0-259: ANSI original path (260 bytes)
        // 260-263: Record number (u32)
        // 264-267: Drive number (u32)
        // 268-275: Deletion time (FILETIME)
        // 276-279: Original file size (u32)
        // 280-799: Unicode original path (520 bytes)

        if record_size >= 280 {
            let deletion_filetime = if record.len() >= 276 {
                u64::from_le_bytes([
                    record[268],
                    record[269],
                    record[270],
                    record[271],
                    record[272],
                    record[273],
                    record[274],
                    record[275],
                ])
            } else {
                0
            };
            let deleted_time = seance_core::time::filetime_to_datetime(deletion_filetime);

            let file_size = if record.len() >= 280 {
                u32::from_le_bytes([record[276], record[277], record[278], record[279]]) as u64
            } else {
                0
            };

            // Try Unicode path first (offset 280)
            let (original_path, path_decode) = if record_size >= 800 {
                let unicode_path = codepage::decode_utf16le(&record[280..record_size.min(800)]);
                if !unicode_path.is_empty() {
                    (unicode_path, None)
                } else {
                    // Fall back to ANSI path
                    decode_ansi(&record[0..260])
                }
            } else {
                decode_ansi(&record[0..record.len().min(260)])
            };

            if !original_path.is_empty() {
                entries.push(RecycleBinEntry {
                    original_path,
                    deleted_time,
                    file_size,
                    recycle_bin_path: "INFO2".to_string(),
                    // INFO2 records are fixed size and the loop only accepts
                    // records that fit whole, so a record's path field is
                    // always present in full.
                    path_truncated: false,
                    path_decode,
                });
            }
        }

        pos += record_size;
    }

    // Anything left over is less than one whole record: the table was cut
    // mid-record rather than ending cleanly on a record boundary.
    let trailing_partial_record = pos < data.len();

    Ok(Info2Scan {
        entries,
        trailing_partial_record,
    })
}

/// Decode an INFO2 record's ANSI path field, reporting the code page assumed
/// when the field held a byte outside ASCII.
///
/// The field is Windows ANSI (CP1252 on a Western install), not UTF-8. The old
/// `String::from_utf8_lossy` turned every accented byte into U+FFFD, so
/// `C:\Users\José\Résumé.doc` was reported as
/// `C:\Users\Jos\u{FFFD}\R\u{FFFD}sum\u{FFFD}.doc` -- a path naming no user and
/// no file, which an examiner searching for either would find nothing for and
/// conclude was never on the machine.
fn decode_ansi(data: &[u8]) -> (String, Option<&'static str>) {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let (text, substituted) = codepage::decode(&data[..end], CodePage::Cp1252);
    (text, substituted.then_some(CodePage::Cp1252.name()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v1_dollar_i() {
        let mut data = vec![0u8; 544]; // 24 header + 520 path
                                       // Version = 1
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        // File size = 12345
        data[8..16].copy_from_slice(&12345u64.to_le_bytes());
        // Deletion time (some FILETIME)
        data[16..24].copy_from_slice(&132539328000000000u64.to_le_bytes());
        // Path "C:\test.txt" in UTF-16LE at offset 24
        let path = "C:\\test.txt";
        for (i, ch) in path.encode_utf16().enumerate() {
            let off = 24 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let entry = parse_dollar_i_v1(&data, "$I103S5F.jpg").unwrap();
        assert_eq!(entry.original_path, "C:\\test.txt");
        assert_eq!(entry.file_size, 12345);
        assert!(entry.deleted_time.is_some());
    }

    #[test]
    fn test_parse_v2_dollar_i() {
        let path_str = "C:\\Users\\test\\Documents\\report.docx";
        let path_utf16: Vec<u16> = path_str.encode_utf16().collect();
        let path_bytes_len = path_utf16.len() * 2;

        let mut data = vec![0u8; 28 + path_bytes_len + 2]; // +2 for null terminator
                                                           // Version = 2
        data[0..8].copy_from_slice(&2u64.to_le_bytes());
        // File size
        data[8..16].copy_from_slice(&98765u64.to_le_bytes());
        // Deletion time
        data[16..24].copy_from_slice(&132539328000000000u64.to_le_bytes());
        // BUG-099: the length field is a UTF-16 CHARACTER count (incl. the null
        // terminator), not a byte count. The old test wrote bytes, masking the
        // parser's byte/char confusion; a real Win10+ $I file stores char count.
        data[24..28].copy_from_slice(&((path_utf16.len() + 1) as u32).to_le_bytes());
        // Path
        for (i, ch) in path_utf16.iter().enumerate() {
            let off = 28 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let entry = parse_dollar_i_v2(&data, "$II3DF3L.zip").unwrap();
        assert_eq!(entry.original_path, path_str);
        assert_eq!(entry.file_size, 98765);
    }

    #[test]
    fn test_v2_char_count_not_byte_count() {
        // Regression for BUG-099: a $I v2 record whose length field is the char
        // count must decode the WHOLE path. If the parser treated it as bytes it
        // would read only half the UTF-16 units and truncate the path.
        let path_str = "C:\\Users\\investigator\\secret_evidence_folder\\report.docx";
        let path_utf16: Vec<u16> = path_str.encode_utf16().collect();

        let mut data = vec![0u8; 28 + path_utf16.len() * 2 + 2];
        data[0..8].copy_from_slice(&2u64.to_le_bytes());
        data[8..16].copy_from_slice(&4096u64.to_le_bytes());
        data[16..24].copy_from_slice(&132539328000000000u64.to_le_bytes());
        // Character count including the null terminator.
        data[24..28].copy_from_slice(&((path_utf16.len() + 1) as u32).to_le_bytes());
        for (i, ch) in path_utf16.iter().enumerate() {
            let off = 28 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let entry = parse_dollar_i_v2(&data, "$IXXXXXX.docx").unwrap();
        assert_eq!(
            entry.original_path, path_str,
            "path must not be truncated to half length"
        );
    }

    /// What an examiner learns: how many files this Recycle Bin recorded as
    /// deleted. A wrong answer here is an EMPTY list, which reads as "nothing
    /// was ever deleted" -- the strongest possible exculpatory claim -- when the
    /// truth is that the table's record layout was never decoded.
    #[test]
    fn an_info2_whose_record_layout_is_undecodable_errors_rather_than_reporting_no_deletions() {
        let mut data = vec![0u8; 20 + 128 * 4];
        data[0..4].copy_from_slice(&5u32.to_le_bytes());
        // 128 bytes cannot hold the deletion time (268..276) or size (276..280).
        data[12..16].copy_from_slice(&128u32.to_le_bytes());

        let err = parse_info2(&data)
            .err()
            .expect("an undecodable record layout must not present as an empty Recycle Bin");
        assert!(
            err.contains("280"),
            "the error must name the layout it could not satisfy, got: {err}"
        );
    }

    #[test]
    fn a_table_ending_on_a_record_boundary_reports_no_trailing_fragment() {
        // Anti-cry-wolf: a whole, well-formed table must not claim to be short.
        let mut data = vec![0u8; 20 + 800];
        data[0..4].copy_from_slice(&5u32.to_le_bytes());
        data[12..16].copy_from_slice(&800u32.to_le_bytes());
        let scan = parse_info2(&data).expect("a well-formed table parses");
        assert!(!scan.trailing_partial_record);
    }

    /// Build a one-record INFO2 table whose Unicode path field is left zeroed,
    /// so the ANSI field at offset 0 is the only record of the location -- the
    /// shape a pre-Vista, ANSI-only Recycle Bin actually has.
    fn info2_with_ansi_path(ansi_path: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&5u32.to_le_bytes());
        data[12..16].copy_from_slice(&800u32.to_le_bytes());
        let mut rec = vec![0u8; 800];
        rec[0..ansi_path.len()].copy_from_slice(ansi_path);
        rec[268..276].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());
        rec[276..280].copy_from_slice(&4096u32.to_le_bytes());
        data.extend_from_slice(&rec);
        data
    }

    /// What an examiner learns: which user account held a deleted file and what
    /// it was called. Decoding the ANSI field as UTF-8 replaced every accented
    /// byte with U+FFFD, so the record named a directory and a file that exist
    /// nowhere -- and a search for the account or the document returned nothing,
    /// which reads as "this file was never on the machine".
    #[test]
    fn an_ansi_info2_path_decodes_through_its_code_page_rather_than_mangling_to_replacements() {
        let scan = parse_info2(&info2_with_ansi_path(
            b"C:\\Users\\Jos\xe9\\R\xe9sum\xe9.doc",
        ))
        .expect("an ANSI-only INFO2 table parses");
        assert_eq!(scan.entries.len(), 1);
        let entry = &scan.entries[0];
        assert_eq!(entry.original_path, "C:\\Users\\José\\Résumé.doc");
        assert!(
            !entry.original_path.contains('\u{FFFD}'),
            "an ANSI path must not be reported with replacement characters"
        );
        assert_eq!(
            entry.path_decode,
            Some("cp1252"),
            "a path this build interpreted must name the code page it assumed"
        );
    }

    /// The CP1252 punctuation block (0x80-0x9F) is where a Latin-1 `b as char`
    /// decode would also be wrong: 0x92 is a typographic apostrophe in a
    /// Windows path, not a C1 control character.
    #[test]
    fn an_ansi_info2_path_uses_the_cp1252_punctuation_block_not_latin1() {
        let scan = parse_info2(&info2_with_ansi_path(b"C:\\Bob\x92s stuff\\a.txt"))
            .expect("an ANSI-only INFO2 table parses");
        assert_eq!(
            scan.entries[0].original_path,
            "C:\\Bob\u{2019}s stuff\\a.txt"
        );
    }

    /// Anti-cry-wolf: an all-ASCII path reads the same under every single-byte
    /// code page, so nothing was interpreted and no provenance is owed.
    #[test]
    fn an_ascii_only_ansi_info2_path_claims_no_code_page() {
        let scan = parse_info2(&info2_with_ansi_path(b"C:\\TEMP\\NOTES.TXT"))
            .expect("an ANSI-only INFO2 table parses");
        assert_eq!(scan.entries[0].original_path, "C:\\TEMP\\NOTES.TXT");
        assert_eq!(scan.entries[0].path_decode, None);
    }

    #[test]
    fn test_filetime_conversion() {
        let ft = 132539328000000000u64;
        let dt = seance_core::time::filetime_to_datetime(ft);
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().format("%Y-%m-%d").to_string(), "2021-01-01");
    }
}
