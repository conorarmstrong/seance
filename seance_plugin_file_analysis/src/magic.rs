/// File type detection via magic bytes.
///
/// Returns `(type_name, canonical_extension)` or `None` if unrecognized. The
/// extension is empty when the type names no single one (an "OOXML" package
/// whose family was not read).
pub fn detect_content_type(data: &[u8]) -> Option<(&'static str, &'static str)> {
    if data.len() < 4 {
        return None;
    }

    // === Images ===

    // JPEG: FF D8 FF
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return Some(("JPEG", "jpg"));
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if data.len() >= 8 && data[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some(("PNG", "png"));
    }

    // GIF: 47 49 46 38
    if data.len() >= 4 && data[..4] == [0x47, 0x49, 0x46, 0x38] {
        return Some(("GIF", "gif"));
    }

    // BMP: 42 4D
    if data.len() >= 2 && data[0] == 0x42 && data[1] == 0x4D {
        return Some(("BMP", "bmp"));
    }

    // TIFF: 49 49 2A 00 (little-endian) or 4D 4D 00 2A (big-endian)
    if data.len() >= 4
        && ((data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00)
            || (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A))
    {
        return Some(("TIFF", "tiff"));
    }

    // WEBP: RIFF....WEBP
    if data.len() >= 12
        && data[..4] == [0x52, 0x49, 0x46, 0x46]
        && data[8..12] == [0x57, 0x45, 0x42, 0x50]
    {
        return Some(("WEBP", "webp"));
    }

    // ICO: 00 00 01 00
    if data.len() >= 4 && data[..4] == [0x00, 0x00, 0x01, 0x00] {
        return Some(("ICO", "ico"));
    }

    // === Documents ===

    // PDF: %PDF
    if data.len() >= 4 && data[..4] == [0x25, 0x50, 0x44, 0x46] {
        return Some(("PDF", "pdf"));
    }

    // RTF: {\rtf
    if data.len() >= 5 && data[..5] == [0x7B, 0x5C, 0x72, 0x74, 0x66] {
        return Some(("RTF", "rtf"));
    }

    // OLE2 Compound Document (DOC/XLS/PPT): D0 CF 11 E0 A1 B1 1A E1
    if data.len() >= 8 && data[..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return Some(("OLE2", "doc"));
    }

    // === Archives ===

    // RAR: 52 61 72 21 1A 07
    if data.len() >= 6 && data[..6] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] {
        return Some(("RAR", "rar"));
    }

    // 7Z: 37 7A BC AF 27 1C
    if data.len() >= 6 && data[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Some(("7Z", "7z"));
    }

    // GZIP: 1F 8B
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return Some(("GZIP", "gz"));
    }

    // BZIP2: 42 5A 68
    if data.len() >= 3 && data[..3] == [0x42, 0x5A, 0x68] {
        return Some(("BZIP2", "bz2"));
    }

    // ZIP / OOXML: 50 4B 03 04
    // Check OOXML before generic ZIP by looking for content types
    if data.len() >= 4 && data[..4] == [0x50, 0x4B, 0x03, 0x04] {
        // Try to detect OOXML subtypes by looking for known filenames in the local file header
        if data.len() >= 30 {
            let name_len = u16::from_le_bytes([data[26], data[27]]) as usize;
            if data.len() >= 30 + name_len {
                let name = &data[30..30 + name_len];
                if name == b"[Content_Types].xml" || name == b"_rels/.rels" {
                    // An OPC package whose first member does not name the
                    // family. Word writes `[Content_Types].xml` first and
                    // LibreOffice writes `_rels/.rels` first; either part
                    // names the main document, so inflate it and read that
                    // (HUNT-181). When it cannot be read from the bytes we
                    // were given, say only "OOXML", which accepts the whole
                    // family rather than calling an `.xlsx` a mismatch, and
                    // names no single extension: "docx" for a workbook would
                    // be a claim nobody read (HUNT-209).
                    return Some(ooxml_family(data).unwrap_or(("OOXML", "")));
                }
                if name.starts_with(b"word/") {
                    return Some(("DOCX", "docx"));
                }
                if name.starts_with(b"xl/") {
                    return Some(("XLSX", "xlsx"));
                }
                if name.starts_with(b"ppt/") {
                    return Some(("PPTX", "pptx"));
                }
            }
        }
        return Some(("ZIP", "zip"));
    }

    // TAR: "ustar" at offset 257
    if data.len() >= 262 && data[257..262] == [0x75, 0x73, 0x74, 0x61, 0x72] {
        return Some(("TAR", "tar"));
    }

    // === Audio ===

    // ID3 (MP3 with ID3 tag): 49 44 33
    if data.len() >= 3 && data[..3] == [0x49, 0x44, 0x33] {
        return Some(("MP3", "mp3"));
    }

    // MP3 frame header: 11-bit sync, then a version that is not the reserved
    // `01`, and layer `01` (Layer III — MP3 is Layer III; `FF FE`, a UTF-16LE
    // byte-order mark, and `FF FF` both decode as Layer I), then a bitrate
    // index that is not the invalid `1111` and a sample-rate index that is not
    // the reserved `11` (HUNT-181).
    if data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
        let version = (data[1] >> 3) & 0b11;
        let layer = (data[1] >> 1) & 0b11;
        let bitrate = data[2] >> 4;
        let sample_rate = (data[2] >> 2) & 0b11;
        if version != 0b01 && layer == 0b01 && bitrate != 0b1111 && sample_rate != 0b11 {
            return Some(("MP3", "mp3"));
        }
    }

    // FLAC: 66 4C 61 43
    if data.len() >= 4 && data[..4] == [0x66, 0x4C, 0x61, 0x43] {
        return Some(("FLAC", "flac"));
    }

    // OGG: 4F 67 67 53
    if data.len() >= 4 && data[..4] == [0x4F, 0x67, 0x67, 0x53] {
        return Some(("OGG", "ogg"));
    }

    // WAV: RIFF....WAVE
    if data.len() >= 12
        && data[..4] == [0x52, 0x49, 0x46, 0x46]
        && data[8..12] == [0x57, 0x41, 0x56, 0x45]
    {
        return Some(("WAV", "wav"));
    }

    // === Video ===

    // MP4/MOV: "ftyp" at offset 4
    if data.len() >= 8 && data[4..8] == [0x66, 0x74, 0x79, 0x70] {
        return Some(("MP4", "mp4"));
    }

    // AVI: RIFF....AVI
    if data.len() >= 12
        && data[..4] == [0x52, 0x49, 0x46, 0x46]
        && data[8..12] == [0x41, 0x56, 0x49, 0x20]
    {
        return Some(("AVI", "avi"));
    }

    // MKV/WebM: 1A 45 DF A3
    if data.len() >= 4 && data[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return Some(("MKV", "mkv"));
    }

    // FLV: 46 4C 56
    if data.len() >= 3 && data[..3] == [0x46, 0x4C, 0x56] {
        return Some(("FLV", "flv"));
    }

    // === Executables ===

    // PE/EXE: 4D 5A (MZ)
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        return Some(("PE_EXE", "exe"));
    }

    // ELF: 7F 45 4C 46
    if data.len() >= 4 && data[..4] == [0x7F, 0x45, 0x4C, 0x46] {
        return Some(("ELF", "elf"));
    }

    // Mach-O: FE ED FA CE (32-bit) or FE ED FA CF (64-bit)
    // Also reversed: CE FA ED FE or CF FA ED FE
    if data.len() >= 4
        && ((data[..4] == [0xFE, 0xED, 0xFA, 0xCE])
            || (data[..4] == [0xFE, 0xED, 0xFA, 0xCF])
            || (data[..4] == [0xCE, 0xFA, 0xED, 0xFE])
            || (data[..4] == [0xCF, 0xFA, 0xED, 0xFE]))
    {
        return Some(("MACHO", "macho"));
    }

    // === Databases ===

    // SQLite: "SQLite format 3\0"
    if data.len() >= 16 && &data[..16] == b"SQLite format 3\0" {
        return Some(("SQLite", "sqlite"));
    }

    // ESE (Extensible Storage Engine): EF CD AB 89 at offset 4
    if data.len() >= 8 && data[4..8] == [0xEF, 0xCD, 0xAB, 0x89] {
        return Some(("ESE", "edb"));
    }

    // === System / Forensic ===

    // Registry: "regf"
    if data.len() >= 4 && data[..4] == [0x72, 0x65, 0x67, 0x66] {
        return Some(("Registry", "reg"));
    }

    // EVTX: "ElfFile\0"
    if data.len() >= 8 && data[..8] == [0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65, 0x00] {
        return Some(("EVTX", "evtx"));
    }

    // LNK: 4C 00 00 00 01 14 02 00
    if data.len() >= 8
        && data[..4] == [0x4C, 0x00, 0x00, 0x00]
        && data[4..8] == [0x01, 0x14, 0x02, 0x00]
    {
        return Some(("LNK", "lnk"));
    }

    None
}

/// How much inflated text of an OPC package's first member is read to find
/// the main document part. `[Content_Types].xml` and `_rels/.rels` name it in
/// their first kilobyte or two; this is a bound, not an expectation.
const OOXML_PART_READ_LIMIT: usize = 64 * 1024;

/// Reads the family of an OOXML package from its first member, when that
/// member is `[Content_Types].xml` or `_rels/.rels` and its bytes are present.
///
/// Both parts name the main document part (`/word/document.xml`,
/// `/xl/workbook.xml`, `/ppt/presentation.xml`); that is the whole test. It
/// returns `None` — the caller then says only "OOXML" — when the member is
/// neither stored nor deflated, when its bytes are not in `data`, or when the
/// text names none or more than one family.
fn ooxml_family(data: &[u8]) -> Option<(&'static str, &'static str)> {
    let method = u16::from_le_bytes([data[8], data[9]]);
    let name_len = u16::from_le_bytes([data[26], data[27]]) as usize;
    let extra_len = u16::from_le_bytes([data[28], data[29]]) as usize;
    let start = 30 + name_len + extra_len;
    let body = data.get(start..).filter(|b| !b.is_empty())?;
    let text: Vec<u8> = match method {
        0 => body[..body.len().min(OOXML_PART_READ_LIMIT)].to_vec(),
        8 => {
            // Raw deflate. The stream may be cut off at the end of the buffer
            // we were handed; whatever inflated before that is still text.
            let mut out = vec![0u8; OOXML_PART_READ_LIMIT];
            let mut inflater = flate2::Decompress::new(false);
            let _ = inflater.decompress(body, &mut out, flate2::FlushDecompress::Sync);
            out.truncate(inflater.total_out() as usize);
            out
        }
        _ => return None,
    };
    let names = |needle: &[u8]| text.windows(needle.len()).any(|w| w == needle);
    let word = names(b"word/document");
    let xl = names(b"xl/workbook");
    let ppt = names(b"ppt/presentation");
    match (word, xl, ppt) {
        (true, false, false) => Some(("DOCX", "docx")),
        (false, true, false) => Some(("XLSX", "xlsx")),
        (false, false, true) => Some(("PPTX", "pptx")),
        _ => None,
    }
}

/// Maps a file extension to known extensions for a detected type.
/// Returns true if the extension is compatible with the detected type.
pub fn extension_matches_type(extension: &str, type_name: &str) -> bool {
    let ext = extension.to_lowercase();
    match type_name {
        "JPEG" => matches!(ext.as_str(), "jpg" | "jpeg" | "jpe" | "jfif"),
        "PNG" => ext == "png",
        "GIF" => ext == "gif",
        "BMP" => matches!(ext.as_str(), "bmp" | "dib"),
        "TIFF" => matches!(ext.as_str(), "tiff" | "tif"),
        "WEBP" => ext == "webp",
        "ICO" => matches!(ext.as_str(), "ico" | "cur"),
        "PDF" => ext == "pdf",
        "RTF" => ext == "rtf",
        "OLE2" => matches!(ext.as_str(), "doc" | "xls" | "ppt" | "msi" | "msg"),
        // "OOXML" is an OPC package whose family was not read (HUNT-181):
        // any member of the three families is consistent with it.
        "OOXML" => is_word_ext(&ext) || is_excel_ext(&ext) || is_powerpoint_ext(&ext),
        "DOCX" => is_word_ext(&ext),
        "XLSX" => is_excel_ext(&ext),
        "PPTX" => is_powerpoint_ext(&ext),
        // Every OOXML extension is a ZIP: a package whose first member names
        // no family is labelled "ZIP", and a `.docm` or `.potx` is then no
        // more a mismatch than a `.docx` (HUNT-209).
        "ZIP" => {
            matches!(
                ext.as_str(),
                "zip" | "jar" | "apk" | "ipa" | "odt" | "ods" | "odp" | "epub"
            ) || is_word_ext(&ext)
                || is_excel_ext(&ext)
                || is_powerpoint_ext(&ext)
        }
        "RAR" => ext == "rar",
        "7Z" => ext == "7z",
        "GZIP" => matches!(ext.as_str(), "gz" | "gzip" | "tgz"),
        "BZIP2" => matches!(ext.as_str(), "bz2" | "tbz2"),
        "TAR" => matches!(ext.as_str(), "tar" | "tgz" | "tbz2"),
        "MP3" => ext == "mp3",
        "FLAC" => ext == "flac",
        "OGG" => matches!(ext.as_str(), "ogg" | "oga" | "ogv"),
        "WAV" => ext == "wav",
        "MP4" => matches!(ext.as_str(), "mp4" | "m4v" | "m4a" | "mov" | "3gp"),
        "AVI" => ext == "avi",
        "MKV" => matches!(ext.as_str(), "mkv" | "webm" | "mka"),
        "FLV" => ext == "flv",
        "PE_EXE" => matches!(
            ext.as_str(),
            "exe" | "dll" | "sys" | "ocx" | "scr" | "drv" | "cpl"
        ),
        "ELF" => matches!(ext.as_str(), "elf" | "so" | "o" | ""),
        "MACHO" => matches!(ext.as_str(), "dylib" | "bundle" | "app" | ""),
        "SQLite" => matches!(ext.as_str(), "sqlite" | "sqlite3" | "db" | "db3"),
        "ESE" => matches!(ext.as_str(), "edb" | "sdb"),
        "Registry" => matches!(ext.as_str(), "reg" | "dat" | ""),
        "EVTX" => ext == "evtx",
        "LNK" => ext == "lnk",
        _ => false,
    }
}

/// Word OOXML extensions: document, macro-enabled, and the two templates.
fn is_word_ext(ext: &str) -> bool {
    matches!(ext, "docx" | "docm" | "dotx" | "dotm")
}

/// Excel OOXML extensions: workbook, macro-enabled, templates and add-in.
fn is_excel_ext(ext: &str) -> bool {
    matches!(ext, "xlsx" | "xlsm" | "xltx" | "xltm" | "xlam")
}

/// PowerPoint OOXML extensions: presentation, show, template, add-in.
fn is_powerpoint_ext(ext: &str) -> bool {
    matches!(
        ext,
        "pptx" | "pptm" | "ppsx" | "ppsm" | "potx" | "potm" | "ppam"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_jpeg() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(detect_content_type(&data), Some(("JPEG", "jpg")));
    }

    #[test]
    fn test_detect_png() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_content_type(&data), Some(("PNG", "png")));
    }

    #[test]
    fn test_detect_pdf() {
        assert_eq!(detect_content_type(b"%PDF-1.4"), Some(("PDF", "pdf")));
    }

    #[test]
    fn test_detect_zip() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        assert_eq!(detect_content_type(&data), Some(("ZIP", "zip")));
    }

    #[test]
    fn test_detect_exe() {
        let data = [0x4D, 0x5A, 0x90, 0x00];
        assert_eq!(detect_content_type(&data), Some(("PE_EXE", "exe")));
    }

    #[test]
    fn test_detect_sqlite() {
        assert_eq!(
            detect_content_type(b"SQLite format 3\0extra"),
            Some(("SQLite", "sqlite"))
        );
    }

    #[test]
    fn test_detect_unknown() {
        let data = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(detect_content_type(&data), None);
    }

    #[test]
    fn test_extension_matches() {
        assert!(extension_matches_type("jpg", "JPEG"));
        assert!(extension_matches_type("jpeg", "JPEG"));
        assert!(!extension_matches_type("png", "JPEG"));
        assert!(extension_matches_type("docx", "ZIP"));
        assert!(extension_matches_type("exe", "PE_EXE"));
        assert!(extension_matches_type("dll", "PE_EXE"));
    }

    #[test]
    fn test_detect_mp4() {
        let data = [
            0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D,
        ];
        assert_eq!(detect_content_type(&data), Some(("MP4", "mp4")));
    }

    #[test]
    fn test_detect_elf() {
        let data = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01];
        assert_eq!(detect_content_type(&data), Some(("ELF", "elf")));
    }

    /// HUNT-181: a presentation written by LibreOffice Impress 26.2 (the fixture
    /// is that tool's output, unmodified) opens with `_rels/.rels`, not a
    /// `ppt/` member, so the header alone cannot name the family. It must not
    /// be reported as a signature mismatch against its own `.pptx` extension.
    #[test]
    fn ooxml_presentation_is_not_a_mismatch_against_pptx() {
        let data = include_bytes!("../tests/fixtures/libreoffice_impress.pptx");
        let (type_name, _) = detect_content_type(data).expect("a ZIP-family type");
        assert!(
            extension_matches_type("pptx", type_name),
            "a real .pptx was detected as {type_name}, which does not accept pptx"
        );
        assert_eq!(
            type_name, "PPTX",
            "the root relationship names ppt/presentation.xml"
        );
    }

    /// HUNT-181: the same shape from LibreOffice Writer resolves to the word family.
    #[test]
    fn ooxml_wordprocessing_resolves_to_docx() {
        let data = include_bytes!("../tests/fixtures/libreoffice_writer.docx");
        assert_eq!(detect_content_type(data), Some(("DOCX", "docx")));
        assert!(!extension_matches_type("pptx", "DOCX"));
    }

    /// HUNT-181: when the family cannot be read (the first member's bytes are
    /// not in the buffer), the generic OOXML label accepts every OOXML
    /// extension rather than calling an `.xlsx` a mismatch.
    #[test]
    fn undetermined_ooxml_accepts_the_whole_family() {
        for ext in ["docx", "docm", "xlsx", "xlsm", "pptx", "pptm"] {
            assert!(extension_matches_type(ext, "OOXML"), "{ext}");
        }
        assert!(!extension_matches_type("jpg", "OOXML"));
    }

    /// A ZIP local file header (the shape every ZIP member opens with) for a
    /// stored member called `name` whose bytes are `body`.
    fn local_header(name: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = b"PK\x03\x04".to_vec();
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&[0u8; 4]); // mod time + date
        out.extend_from_slice(&[0u8; 4]); // crc-32 (not checked here)
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(name);
        out.extend_from_slice(body);
        out
    }

    /// HUNT-209: an OOXML package whose first member is neither the content
    /// types, the root relationships nor a family part (`docProps/app.xml`
    /// first, as some writers order it) is labelled plain "ZIP". Every OOXML
    /// extension — macro-enabled, template, show and add-in — is a ZIP, so
    /// none of them is a mismatch against that label.
    #[test]
    fn zip_label_accepts_every_ooxml_extension() {
        let data = local_header(b"docProps/app.xml", b"<?xml version=\"1.0\"?>");
        assert_eq!(detect_content_type(&data), Some(("ZIP", "zip")));
        for ext in [
            "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlam", "pptx", "pptm",
            "ppsx", "ppsm", "potx", "potm", "ppam",
        ] {
            assert!(
                extension_matches_type(ext, "ZIP"),
                "a .{ext} detected as ZIP was called a mismatch"
            );
        }
        assert!(!extension_matches_type("jpg", "ZIP"));
    }

    /// HUNT-209: when the family could not be read the label is "OOXML", and it
    /// must not name a single extension (it used to say "docx" for a workbook).
    #[test]
    fn undetermined_ooxml_names_no_single_extension() {
        // `[Content_Types].xml` first, its bytes naming no main part.
        let data = local_header(b"[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>");
        assert_eq!(detect_content_type(&data), Some(("OOXML", "")));
    }

    /// HUNT-181: a UTF-16LE byte-order mark (`FF FE`) and an `FF FF` run are
    /// not MPEG audio frame headers (both decode as the Layer I bit pattern, and
    /// MP3 is Layer III).
    #[test]
    fn utf16le_bom_and_ff_ff_are_not_mp3() {
        let utf16 = [0xFF, 0xFE, b'h', 0x00, b'i', 0x00];
        assert_ne!(detect_content_type(&utf16), Some(("MP3", "mp3")));
        let ffff = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_ne!(detect_content_type(&ffff), Some(("MP3", "mp3")));
    }

    /// A real MPEG-1 Layer III header (128 kbit/s, 44.1 kHz) is still MP3.
    #[test]
    fn mpeg1_layer3_frame_header_is_mp3() {
        let frame = [0xFF, 0xFB, 0x90, 0x64, 0x00, 0x00];
        assert_eq!(detect_content_type(&frame), Some(("MP3", "mp3")));
        // MPEG-2 Layer III, 64 kbit/s, 22.05 kHz.
        let frame2 = [0xFF, 0xF3, 0x80, 0xC4, 0x00, 0x00];
        assert_eq!(detect_content_type(&frame2), Some(("MP3", "mp3")));
    }

    #[test]
    fn test_detect_evtx() {
        let data = [0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65, 0x00];
        assert_eq!(detect_content_type(&data), Some(("EVTX", "evtx")));
    }
}
