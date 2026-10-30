use super::*;
use seance_core::data_source::DataSource;
use seance_core::test_support::TruncatedSource;
use std::sync::Arc;
use uuid::Uuid;

/// Mock data source for testing
#[derive(Debug)]
struct MockDataSource {
    data: Vec<u8>,
}

impl MockDataSource {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for MockDataSource {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }

        let to_read = std::cmp::min(buffer.len(), self.data.len() - offset);
        buffer[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

#[test]
fn test_lnk_parser_module_metadata() {
    let parser = LnkParser;

    assert_eq!(parser.id(), "plugin.windows.lnk_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));

    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_lnk_parser_skips_non_lnk_files() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    let data = vec![0u8; 100];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "test.txt"}), // Not a .lnk file
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_lnk_parser_requires_data_source() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None, // No data source
        json!({"name": "test.lnk"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ModuleError::InvalidInputFormat(_)
    ));
}

#[test]
fn test_lnk_parser_handles_truncated_file() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    // File too small (< 76 bytes)
    let data = vec![0u8; 50];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "truncated.lnk"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0); // Should skip truncated files
}

#[test]
fn test_lnk_parser_handles_invalid_signature() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    // 76 bytes but invalid signature
    let mut data = vec![0u8; 100];
    // header_size at offset 0 (4 bytes) = 76 (0x4C)
    data[0] = 0x4C;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x00;
    // Invalid signature at offset 4
    data[4] = 0xFF;
    data[5] = 0xFF;
    data[6] = 0xFF;
    data[7] = 0xFF;

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "invalid_sig.lnk"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0); // Should skip files with invalid signature
}

#[test]
fn test_lnk_parser_handles_invalid_header_size() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    // Invalid header size (not 76)
    let mut data = vec![0u8; 100];
    // header_size at offset 0 = 50 (invalid, should be 76)
    data[0] = 50;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x00;
    // Correct signature
    data[4] = 0x01;
    data[5] = 0x14;
    data[6] = 0x02;
    data[7] = 0x00;

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "bad_header.lnk"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_lnk_parser_empty_data() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    let data = Vec::new();
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "empty.lnk"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_filetime_to_iso_zero() {
    // The 0/unset sentinel yields no timestamp (formerly an empty string).
    assert_eq!(seance_core::time::filetime_to_rfc3339(0), None);
}

#[test]
fn test_filetime_to_iso_valid() {
    // Known FileTime: 132456789000000000 corresponds to some date
    // Let's use a simple known value: Jan 1, 2000 00:00:00 UTC
    // FileTime = (seconds since Jan 1, 1601) * 10_000_000
    // Jan 1, 2000 = 12591158400 seconds since Jan 1, 1601
    let filetime = 125911584000000000u64;
    let result = seance_core::time::filetime_to_rfc3339(filetime).unwrap();
    assert!(result.contains("2000"));
}

// Integration test with real LNK file
#[test]
fn test_parse_real_lnk_file() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/sample.lnk");
    if !test_file.exists() {
        eprintln!("Skipping integration test: sample.lnk not found");
        return;
    }

    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    let data = fs::read(test_file).expect("Failed to read sample.lnk");
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "sample.lnk"}),
    );

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Failed to parse sample.lnk: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(
        !artifacts.is_empty(),
        "No artifacts produced from sample.lnk"
    );

    // First artifact should be ParsedRecord
    let lnk_artifact = &artifacts[0];
    assert_eq!(lnk_artifact.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(lnk_artifact.metadata["type"], "LnkFile");
}

/// Build a minimal, valid LNK with a full 16-byte LinkCLSID, a known
/// CreationTime and a Unicode RelativePath string. Regression fixture for the
/// 16-byte CLSID skip: with the old 4-byte skip, LinkFlags/timestamps were read
/// 12 bytes too early, so RelativePath and target_created came out empty/garbage.
fn build_min_lnk(creation_filetime: u64, flags: u32, rel_path: &str) -> Vec<u8> {
    let mut d = vec![0u8; 76];
    d[0..4].copy_from_slice(&76u32.to_le_bytes()); // HeaderSize
                                                   // LinkCLSID {00021401-0000-0000-C000-000000000046} (16 bytes)
    d[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    d[20..24].copy_from_slice(&flags.to_le_bytes()); // LinkFlags @ 0x14
                                                     // FileAttributes @ 0x18 left 0
    d[28..36].copy_from_slice(&creation_filetime.to_le_bytes()); // CreationTime @ 0x1C
                                                                 // AccessTime @ 0x24, WriteTime @ 0x2C left 0
                                                                 // StringData: RelativePath (CountCharacters u16 + UTF-16LE chars)
    let units: Vec<u16> = rel_path.encode_utf16().collect();
    d.extend_from_slice(&(units.len() as u16).to_le_bytes());
    for u in units {
        d.extend_from_slice(&u.to_le_bytes());
    }
    d
}

/// Minimal 76-byte Shell Link Header with the given LinkFlags. No
/// LinkTargetIDList, so LinkInfo (if HasLinkInfo is set) starts at offset 76.
fn build_lnk_header(link_flags: u32) -> Vec<u8> {
    let mut d = vec![0u8; 76];
    d[0..4].copy_from_slice(&76u32.to_le_bytes());
    d[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    d[20..24].copy_from_slice(&link_flags.to_le_bytes()); // LinkFlags @ 0x14
    d
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

/// BUG-059: a LinkInfo with header >= 0x24 must read LocalBasePathOffsetUnicode,
/// and the Unicode path must win over the ANSI one.
#[test]
fn test_lnk_unicode_local_base_path_preferred() {
    let mut d = build_lnk_header(0x02); // HasLinkInfo

    let ansi = b"C:\\ansi.txt\0";
    let uni = utf16z("C:\\u\u{0308}ni\u{0107}ode.txt"); // "C:\ünićode.txt"-ish
    let header_len = 0x24usize; // includes the two Unicode offset fields
    let ansi_off = header_len;
    let uni_off = ansi_off + ansi.len();
    let total = uni_off + uni.len();

    let mut li = vec![0u8; header_len];
    li[0..4].copy_from_slice(&(total as u32).to_le_bytes()); // LinkInfoSize
    li[4..8].copy_from_slice(&(header_len as u32).to_le_bytes()); // LinkInfoHeaderSize
    li[8..12].copy_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    li[16..20].copy_from_slice(&(ansi_off as u32).to_le_bytes()); // LocalBasePathOffset (ANSI)
    li[28..32].copy_from_slice(&(uni_off as u32).to_le_bytes()); // LocalBasePathOffsetUnicode
    li.extend_from_slice(ansi);
    li.extend_from_slice(&uni);
    d.extend_from_slice(&li);

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(d));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "u.lnk"}),
    );
    let out = LnkParser.process(&artifact).unwrap();
    let rec = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("ParsedRecord");
    assert_eq!(
        rec.metadata["target_local_path"].as_str(),
        Some("C:\\u\u{0308}ni\u{0107}ode.txt")
    );
}

/// BUG-059: a network shortcut (CommonNetworkRelativeLink + CommonPathSuffix)
/// must yield the assembled `\\server\share\...` target, not an empty path.
#[test]
fn test_lnk_network_path_assembled() {
    let mut d = build_lnk_header(0x02); // HasLinkInfo

    let net_name = b"\\\\server\\share\0";
    let suffix = b"sub\\file.txt\0";

    // CommonNetworkRelativeLink: 20-byte header + ANSI NetName at offset 0x14.
    let cnrl_header = 0x14usize;
    let net_name_off = cnrl_header; // 0x14 (not > 0x14 => ANSI NetName)
    let cnrl_size = cnrl_header + net_name.len();
    let mut cnrl = vec![0u8; cnrl_header];
    cnrl[0..4].copy_from_slice(&(cnrl_size as u32).to_le_bytes());
    cnrl[8..12].copy_from_slice(&(net_name_off as u32).to_le_bytes()); // NetNameOffset
    cnrl.extend_from_slice(net_name);

    // LinkInfo header 0x1C (ANSI-only, no Unicode offset fields).
    let header_len = 0x1Cusize;
    let cnrl_off = header_len;
    let suffix_off = cnrl_off + cnrl.len();
    let total = suffix_off + suffix.len();

    let mut li = vec![0u8; header_len];
    li[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    li[4..8].copy_from_slice(&(header_len as u32).to_le_bytes());
    li[8..12].copy_from_slice(&2u32.to_le_bytes()); // CommonNetworkRelativeLinkAndPathSuffix
    li[20..24].copy_from_slice(&(cnrl_off as u32).to_le_bytes()); // CommonNetworkRelativeLinkOffset
    li[24..28].copy_from_slice(&(suffix_off as u32).to_le_bytes()); // CommonPathSuffixOffset
    li.extend_from_slice(&cnrl);
    li.extend_from_slice(suffix);
    d.extend_from_slice(&li);

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(d));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "n.lnk"}),
    );
    let out = LnkParser.process(&artifact).unwrap();
    let rec = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("ParsedRecord");
    assert_eq!(
        rec.metadata["target_local_path"].as_str(),
        Some("\\\\server\\share\\sub\\file.txt")
    );
}

#[test]
fn test_lnk_header_fields_read_at_correct_offsets() {
    let parser = LnkParser;
    let case_id = Uuid::new_v4();

    // 2021-01-01T00:00:00Z, HasRelativePath (0x08) | IsUnicode (0x80).
    let creation = 132_539_328_000_000_000u64;
    let data = build_min_lnk(creation, 0x08 | 0x80, "..\\target.exe");
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "shortcut.lnk"}),
    );

    let artifacts = parser.process(&artifact).unwrap();
    let record = artifacts
        .iter()
        .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .expect("should produce a ParsedRecord");

    // RelativePath only decodes correctly if LinkFlags was read from 0x14.
    assert_eq!(
        record.metadata["relative_path"].as_str(),
        Some("..\\target.exe")
    );
    // CreationTime only decodes correctly if read from 0x1C.
    assert!(record.metadata["target_created"]
        .as_str()
        .unwrap()
        .starts_with("2021-01-01"));
}

/// A shortcut whose bytes were only partly read must not present a blank target
/// as fact.
///
/// What an examiner learns: what file this shortcut pointed at. A wrong answer
/// here is `target_local_path: ""` on a record that looks fully parsed — read as
/// "the shortcut had no target" when the target string simply sits in bytes that
/// were never read (B2-168).
#[test]
fn a_partly_read_lnk_is_marked_incomplete_not_blank() {
    // A well-formed LinkInfo shortcut, then cut short of its path strings while
    // still declaring the full length.
    let mut d = build_lnk_header(0x02); // HasLinkInfo
    let uni = utf16z("C:\\evidence\\secret.docx");
    let header_len = 0x24usize;
    let uni_off = header_len;
    let total = uni_off + uni.len();

    let mut li = vec![0u8; header_len];
    li[0..4].copy_from_slice(&(total as u32).to_le_bytes()); // LinkInfoSize
    li[4..8].copy_from_slice(&(header_len as u32).to_le_bytes()); // LinkInfoHeaderSize
    li[8..12].copy_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    li[28..32].copy_from_slice(&(uni_off as u32).to_le_bytes()); // LocalBasePathOffsetUnicode
    li.extend_from_slice(&uni);
    d.extend_from_slice(&li);

    let declared = d.len() as u64;
    let mut truncated = d.clone();
    truncated.truncate(76 + header_len); // header + LinkInfo header, no strings

    // Control: the whole file reads, the target is recovered, nothing is flagged.
    let whole: Arc<dyn DataSource> = Arc::new(MockDataSource::new(d));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(whole),
        json!({"name": "secret.lnk"}),
    );
    let rec = LnkParser
        .process(&artifact)
        .unwrap()
        .into_iter()
        .find(|a| a.metadata["type"] == "LnkFile")
        .expect("LnkFile");
    assert_eq!(
        rec.metadata["target_local_path"].as_str(),
        Some("C:\\evidence\\secret.docx")
    );
    assert!(rec.metadata.get("content_incomplete").is_none());

    // Short read: the target comes out empty, and that must be declared. The
    // declared size stays the whole shortcut's length, as the directory entry
    // records it.
    let short: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(truncated, declared));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(short),
        json!({"name": "secret.lnk"}),
    );
    let rec = LnkParser
        .process(&artifact)
        .unwrap()
        .into_iter()
        .find(|a| a.metadata["type"] == "LnkFile")
        .expect("LnkFile");
    assert_eq!(
        rec.metadata["target_local_path"].as_str(),
        Some(""),
        "the target string was never read"
    );
    assert_eq!(rec.metadata["content_incomplete"], json!(true));
    assert_eq!(rec.metadata["content_incomplete_reason"], "short_read");
    assert_eq!(rec.metadata["declared_size"], json!(declared));
}

/// A `.lnk` whose declared bytes exist but could not be read at all must be
/// reported, not skipped as "too small".
#[test]
fn an_unreadable_lnk_is_reported_rather_than_dropped() {
    // A truncated acquisition, or a shortcut stored in a run list that could
    // not be resolved: 4096 bytes on record, 20 of them staged.
    let source: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(vec![0u8; 20], 4096));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        json!({"name": "unreadable.lnk"}),
    );

    let out = LnkParser.process(&artifact).unwrap();
    assert_eq!(out.len(), 1, "an unread shortcut must not vanish");
    assert_eq!(out[0].metadata["type"], "LnkParseStatus");
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
    assert_eq!(out[0].metadata["bytes_read"], json!(20));
    assert_eq!(out[0].metadata["declared_size"], json!(4096));
}

/// Build an ANSI-only LinkInfo (header 0x1C, no Unicode offset fields) whose
/// LocalBasePath is the given raw byte string -- the shape a shortcut written by
/// a non-Unicode application has, where those bytes are the only record of the
/// target's location.
fn lnk_with_ansi_local_base_path(ansi_path: &[u8]) -> Vec<u8> {
    let mut d = build_lnk_header(0x02); // HasLinkInfo
    let header_len = 0x1Cusize;
    let path_off = header_len;
    let total = path_off + ansi_path.len();

    let mut li = vec![0u8; header_len];
    li[0..4].copy_from_slice(&(total as u32).to_le_bytes()); // LinkInfoSize
    li[4..8].copy_from_slice(&(header_len as u32).to_le_bytes()); // LinkInfoHeaderSize
    li[8..12].copy_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    li[16..20].copy_from_slice(&(path_off as u32).to_le_bytes()); // LocalBasePathOffset
    li.extend_from_slice(ansi_path);
    d.extend_from_slice(&li);
    d
}

/// A shortcut whose `LinkInfo` carries a `VolumeID` — the structure the reader
/// used to step over.
///
/// `label` is `Some((bytes, unicode))`; `None` writes `VolumeLabelOffset`
/// pointing at an empty string, which real shortcuts do.
fn lnk_with_volume_id(
    drive_type: u32,
    serial: u32,
    label: Option<(&[u8], bool)>,
    ansi_path: &[u8],
) -> Vec<u8> {
    let mut d = build_lnk_header(0x02); // HasLinkInfo
    let header_len = 0x1Cusize;
    // LinkInfo layout: header, then the VolumeID, then the local base path.
    let vol_off = header_len;
    // VolumeID: size, drive type, serial, label offset [, unicode label offset].
    let unicode_label = matches!(label, Some((_, true)));
    let vol_fixed = if unicode_label { 0x14 } else { 0x10 };
    let label_bytes: Vec<u8> = match label {
        Some((b, true)) => {
            // UTF-16LE with its terminator.
            let mut out = Vec::new();
            for ch in String::from_utf8_lossy(b).encode_utf16() {
                out.extend_from_slice(&ch.to_le_bytes());
            }
            out.extend_from_slice(&[0, 0]);
            out
        }
        Some((b, false)) => b.to_vec(),
        None => vec![0u8],
    };
    let vol_size = vol_fixed + label_bytes.len();
    let mut vol = vec![0u8; vol_fixed];
    vol[0..4].copy_from_slice(&(vol_size as u32).to_le_bytes());
    vol[4..8].copy_from_slice(&drive_type.to_le_bytes());
    vol[8..12].copy_from_slice(&serial.to_le_bytes());
    if unicode_label {
        // 0x14 is the sentinel: the label is Unicode, at the next field's offset.
        vol[12..16].copy_from_slice(&0x14u32.to_le_bytes());
        vol[16..20].copy_from_slice(&(vol_fixed as u32).to_le_bytes());
    } else {
        vol[12..16].copy_from_slice(&(vol_fixed as u32).to_le_bytes());
    }
    vol.extend_from_slice(&label_bytes);

    let path_off = vol_off + vol.len();
    let total = path_off + ansi_path.len();
    let mut li = vec![0u8; header_len];
    li[0..4].copy_from_slice(&(total as u32).to_le_bytes()); // LinkInfoSize
    li[4..8].copy_from_slice(&(header_len as u32).to_le_bytes()); // LinkInfoHeaderSize
    li[8..12].copy_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    li[12..16].copy_from_slice(&(vol_off as u32).to_le_bytes()); // VolumeIDOffset
    li[16..20].copy_from_slice(&(path_off as u32).to_le_bytes()); // LocalBasePathOffset
    li.extend_from_slice(&vol);
    li.extend_from_slice(ansi_path);
    d.extend_from_slice(&li);
    d
}

fn parsed_record(data: Vec<u8>, name: &str) -> Artifact {
    let source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        json!({ "name": name }),
    );
    LnkParser
        .process(&artifact)
        .unwrap()
        .into_iter()
        .find(|a| a.metadata["type"] == "LnkFile")
        .expect("LnkFile")
}

/// What an examiner learns: which file this shortcut proves was opened on the
/// machine. The ANSI target path was decoded as UTF-8, so every accented byte
/// became U+FFFD: `\\fileserver\Röntgen\scan.pdf` was reported as
/// `\\fileserver\R\u{FFFD}ntgen\scan.pdf`, a share and a file that match
/// nothing an examiner can search for -- and nothing on the record said the
/// string had been substituted, so it read as the literal target.
#[test]
fn an_ansi_lnk_target_path_is_decoded_and_stamped_with_its_code_page() {
    // 0xFC is ü and 0xE9 is é in CP1252, the Windows ANSI set these bytes use.
    let rec = parsed_record(
        lnk_with_ansi_local_base_path(b"C:\\Berichte\\M\xfcller\\r\xe9sum\xe9.doc\0"),
        "bericht.lnk",
    );

    assert_eq!(
        rec.metadata["target_local_path"].as_str(),
        Some("C:\\Berichte\\Müller\\résumé.doc")
    );
    let target = rec.metadata["target_local_path"].as_str().unwrap();
    assert!(
        !target.contains('\u{FFFD}'),
        "an ANSI target path must not be reported with replacement characters"
    );
    assert_eq!(
        rec.metadata["path_decode"], "cp1252",
        "a path this build interpreted must name the code page it assumed"
    );
}

/// The CP1252 punctuation block (0x80-0x9F) is where a plain Latin-1 decode is
/// also wrong: byte 0x92 is a typographic apostrophe in a Windows path, not a
/// C1 control character.
#[test]
fn an_ansi_lnk_path_uses_the_cp1252_punctuation_block_not_latin1() {
    let rec = parsed_record(
        lnk_with_ansi_local_base_path(b"C:\\Bob\x92s Files\\notes.txt\0"),
        "notes.lnk",
    );
    assert_eq!(
        rec.metadata["target_local_path"].as_str(),
        Some("C:\\Bob\u{2019}s Files\\notes.txt")
    );
}

/// StringData is ANSI too when the shortcut lacks the IsUnicode flag, and the
/// arguments are what show HOW a file was opened. Mangling them to U+FFFD
/// destroys the filename inside the command line.
#[test]
fn ansi_string_data_is_decoded_through_the_ansi_code_page() {
    // HasArguments (0x20) without IsUnicode (0x80).
    let mut d = build_lnk_header(0x20);
    let args: &[u8] = b"/open \"D:\\Fotos\\Gr\xfc\xdfe.jpg\"";
    d.extend_from_slice(&(args.len() as u16).to_le_bytes());
    d.extend_from_slice(args);

    let rec = parsed_record(d, "open.lnk");
    assert_eq!(
        rec.metadata["arguments"].as_str(),
        Some("/open \"D:\\Fotos\\Grüße.jpg\"")
    );
    assert_eq!(rec.metadata["path_decode"], "cp1252");
}

/// Anti-cry-wolf, both halves: an all-ASCII ANSI path assumed nothing (every
/// single-byte code page agrees there), and a Unicode shortcut assumed nothing
/// either. Neither may carry a stamp claiming a decode that did not happen.
#[test]
fn a_lnk_whose_strings_were_never_interpreted_carries_no_code_page_stamp() {
    let ascii_ansi = parsed_record(
        lnk_with_ansi_local_base_path(b"C:\\WINDOWS\\NOTEPAD.EXE\0"),
        "notepad.lnk",
    );
    assert_eq!(
        ascii_ansi.metadata["target_local_path"].as_str(),
        Some("C:\\WINDOWS\\NOTEPAD.EXE")
    );
    assert!(ascii_ansi.metadata.get("path_decode").is_none());

    // IsUnicode (0x80) with a UTF-16 RelativePath: read, not interpreted.
    let unicode = parsed_record(
        build_min_lnk(132_539_328_000_000_000u64, 0x08 | 0x80, "..\\Müller.exe"),
        "unicode.lnk",
    );
    assert_eq!(
        unicode.metadata["relative_path"].as_str(),
        Some("..\\Müller.exe")
    );
    assert!(unicode.metadata.get("path_decode").is_none());
}

/// B5-032: the three target MAC events all carried `timestamp_desc`
/// "LNK Target MAC Time", so a timeline filter could not separate "the target
/// was created" from "the target was opened" — only the prose differed, and
/// prose is not filterable.
#[test]
fn each_target_mac_event_has_its_own_timestamp_desc() {
    let mut data = build_min_lnk(132_539_328_000_000_000u64, 0x08 | 0x80, "..\\target.exe");
    // AccessTime @ 0x24 and WriteTime @ 0x2C, distinct from CreationTime.
    data[36..44].copy_from_slice(&132_539_328_000_000_001u64.to_le_bytes());
    data[44..52].copy_from_slice(&132_539_328_000_000_002u64.to_le_bytes());

    let source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        json!({"name": "shortcut.lnk"}),
    );

    let out = LnkParser.process(&artifact).unwrap();
    let descs: Vec<String> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .map(|a| a.metadata["timestamp_desc"].as_str().unwrap().to_string())
        .collect();

    assert_eq!(descs.len(), 3, "created, accessed and modified");
    assert!(descs.contains(&"LNK Target Created".to_string()));
    assert!(descs.contains(&"LNK Target Accessed".to_string()));
    assert!(descs.contains(&"LNK Target Modified".to_string()));
}

// --- the volume the target sat on --------------------------------------------

/// The answer `WINDOWS_DESIGN.md` promised and the code did not give: the
/// `VolumeID` offset was read into `let _vol_id_offset` and discarded, so no
/// drive type, volume serial or label reached the case. Drive type is how an
/// examiner says "the target was on removable media".
#[test]
fn a_shortcut_to_a_removable_volume_names_the_drive_type_and_serial() {
    let rec = parsed_record(
        lnk_with_volume_id(
            2, // DRIVE_REMOVABLE
            0xA1B2_C3D4,
            Some((b"EVIDENCE\0", false)),
            b"E:\\photos\\DSC001.jpg\0",
        ),
        "DSC001.lnk",
    );
    assert_eq!(rec.metadata["drive_type"], 2);
    assert_eq!(rec.metadata["drive_type_name"], "removable");
    // Rendered the way Windows shows a volume serial, because that is the form
    // an examiner compares against.
    assert_eq!(rec.metadata["volume_serial"], "A1B2-C3D4");
    assert_eq!(rec.metadata["volume_label"], "EVIDENCE");
    assert_eq!(rec.metadata["target_local_path"], "E:\\photos\\DSC001.jpg");
    // And the caution, on the record: "removable" is a lead towards external
    // media and not proof the file is on a USB stick now.
    let note = rec.metadata["volume_note"].as_str().expect("a note");
    assert!(note.contains("not proof the target"), "{note}");
    assert!(
        note.contains("not a hardware or manufacturer serial"),
        "{note}"
    );
    assert!(
        note.contains("changes when the volume is reformatted"),
        "{note}"
    );
}

#[test]
fn every_drive_type_the_format_defines_is_named_and_an_unknown_one_is_not_guessed() {
    for (code, word) in [
        (0u32, "unknown"),
        (1, "no_root_directory"),
        (2, "removable"),
        (3, "fixed"),
        (4, "remote"),
        (5, "cdrom"),
        (6, "ramdisk"),
    ] {
        let rec = parsed_record(lnk_with_volume_id(code, 1, None, b"C:\\a.txt\0"), "a.lnk");
        assert_eq!(rec.metadata["drive_type_name"], word, "code {code}");
        assert!(rec.metadata.get("drive_type_name_known").is_none());
    }
    // A code this build has not been shown is reported as the number it is,
    // not mapped onto the nearest word.
    let rec = parsed_record(lnk_with_volume_id(99, 1, None, b"C:\\a.txt\0"), "a.lnk");
    assert_eq!(rec.metadata["drive_type"], 99);
    assert!(rec.metadata.get("drive_type_name").is_none());
    assert_eq!(rec.metadata["drive_type_name_known"], false);
}

#[test]
fn a_unicode_volume_label_is_read_through_its_own_offset() {
    // `VolumeLabelOffset` of 0x14 is the sentinel saying the label is Unicode
    // and its offset is the next field. Reading the ANSI offset regardless
    // would return the two bytes 0x14 as text.
    let rec = parsed_record(
        lnk_with_volume_id(
            3,
            0x1234_5678,
            Some(("Datenträger".as_bytes(), true)),
            b"D:\\x\0",
        ),
        "x.lnk",
    );
    assert_eq!(rec.metadata["volume_label"], "Datenträger");
    assert_eq!(rec.metadata["volume_serial"], "1234-5678");
    // A Unicode label needs no code-page assumption, so nothing is stamped.
    assert!(rec.metadata.get("path_decode").is_none());
}

#[test]
fn an_ansi_volume_label_outside_ascii_names_the_code_page_it_was_read_under() {
    // 0xDF is ß in CP1252. The label is the examiner's handle on a volume
    // that is not in the evidence, so a substituted character matters here
    // for the same reason it does in a path.
    let rec = parsed_record(
        lnk_with_volume_id(2, 1, Some((b"MA\xdfENSPEICHER\0", false)), b"E:\\a.txt\0"),
        "a.lnk",
    );
    assert_eq!(rec.metadata["volume_label"], "MAßENSPEICHER");
    assert_eq!(rec.metadata["path_decode"], "cp1252");
}

#[test]
fn a_volume_id_too_short_for_its_own_fixed_fields_is_refused_not_read() {
    // The declared size is what makes the rest of the structure addressable.
    // Reading a drive type out of whatever follows a truncated one would
    // publish a removable-media lead from unrelated bytes.
    let mut data = lnk_with_volume_id(2, 0xDEAD_BEEF, None, b"E:\\a.txt\0");
    // The VolumeID's size field sits at the start of the LinkInfo's VolumeID,
    // which this fixture places at LinkInfo offset 0x1C.
    let vol_at = 76 + 0x1C;
    data[vol_at..vol_at + 4].copy_from_slice(&8u32.to_le_bytes());
    let rec = parsed_record(data, "a.lnk");
    assert!(rec.metadata.get("drive_type").is_none());
    assert!(rec.metadata.get("volume_serial").is_none());
    assert!(rec.metadata.get("volume_note").is_none());
    // And the target path is still read: one refused structure does not
    // discard the rest of the shortcut.
    assert_eq!(rec.metadata["target_local_path"], "E:\\a.txt");
}

#[test]
fn a_shortcut_with_no_volume_id_claims_nothing_about_a_volume() {
    let rec = parsed_record(lnk_with_ansi_local_base_path(b"C:\\a.txt\0"), "a.lnk");
    assert!(rec.metadata.get("drive_type").is_none());
    assert!(rec.metadata.get("volume_serial").is_none());
    assert!(rec.metadata.get("volume_label").is_none());
}

/// Build a `LinkTargetIDList`-only shortcut (`HasLinkTargetIDList`, no
/// `LinkInfo`): the header, `IDListSize` (u16), then the ID list itself.
fn lnk_with_link_target_id_list(list_bytes: &[u8]) -> Vec<u8> {
    let mut d = build_lnk_header(0x01); // HasLinkTargetIDList
    d.extend_from_slice(&(list_bytes.len() as u16).to_le_bytes());
    d.extend_from_slice(list_bytes);
    d
}

/// A shell item ID list of file-entry items, outermost first, the deepest one
/// carrying the FAT times a real shell item stores.
fn file_entry_id_list(names: &[&str], deepest_version: u16) -> Vec<u8> {
    let mut list = Vec::new();
    for name in &names[..names.len() - 1] {
        let mut item = vec![0u8; 14];
        item[2] = 0x31; // file-entry type
        item.extend_from_slice(name.as_bytes());
        item.push(0);
        let size = item.len() as u16;
        item[0..2].copy_from_slice(&size.to_le_bytes());
        list.extend_from_slice(&item);
    }
    list.extend_from_slice(&seance_shell_item::fixture::file_entry_with_times(
        deepest_version,
        names[names.len() - 1],
    ));
    list.extend_from_slice(&0u16.to_le_bytes()); // ID list terminator
    list
}

/// `ROADMAP` §5.16. `LinkTargetIDList` used to be read only far enough to
/// skip past it — none of the folder chain it names, and none of the
/// deepest item's own times, ever reached the `LnkFile` record. This feeds
/// the same bytes through `seance_shell_item::walk_id_list` that the
/// registry MRU reader already uses, and publishes the same field shape.
#[test]
fn link_target_id_list_produces_a_shell_item_path_on_the_record() {
    let list = file_entry_id_list(&["Users", "bob", "report.docx"], 8);
    let rec = parsed_record(lnk_with_link_target_id_list(&list), "target.lnk");

    assert_eq!(
        rec.metadata["shell_item_path"],
        json!(["Users", "bob", "report.docx"])
    );
    assert_eq!(rec.metadata["shell_item_name"], json!("report.docx"));
    // The deepest item's FAT times, per `fixture::file_entry_with_times`.
    assert_eq!(
        rec.metadata["shell_item_modified"],
        json!("2021-06-15T14:30:44+00:00")
    );
    assert_eq!(
        rec.metadata["shell_item_created"],
        json!("2019-01-02T03:04:06+00:00")
    );
    assert_eq!(
        rec.metadata["shell_item_accessed"],
        json!("2021-12-31T23:59:58+00:00")
    );
}

/// A shortcut with no `LinkTargetIDList` at all must not fabricate one —
/// this is additive, not a field that now always appears.
#[test]
fn no_link_target_id_list_means_no_shell_item_fields() {
    let rec = parsed_record(lnk_with_ansi_local_base_path(b"C:\\a.txt\0"), "a.lnk");
    assert!(rec.metadata.get("shell_item_path").is_none());
    assert!(rec.metadata.get("shell_item_name").is_none());
}

/// A code-review pass on 2026-09-18 caught this: `seance_shell_item` grew
/// `parse_shell_item_detail` (per-item `parsed` and the MFT file reference)
/// for exactly this record's `LinkTargetIDList`, and the crate's own doc
/// comment above `shell_item_path` claims "same field names and shapes as
/// `ShellMruEntry`" — but the code still called `parse_shell_item` (name
/// only), so `shell_item_parsed` never appeared here at all, unlike
/// `ShellMruEntry`, which always publishes it. This is the fix: the deepest
/// item's `parsed` flag and, where its `BEEF0004` block is version 7+, its
/// MFT file reference.
#[test]
fn link_target_id_list_publishes_shell_item_parsed_and_the_mft_reference() {
    use seance_shell_item::fixture::{build_beef0004, set_mft_reference};

    let mut block = build_beef0004(7, "report.docx");
    set_mft_reference(&mut block, 0x1234, 7);
    let mut deepest = vec![0u8; 14];
    deepest[2] = 0x31; // file-entry type
    deepest.extend_from_slice(&block);
    let size = deepest.len() as u16;
    deepest[0..2].copy_from_slice(&size.to_le_bytes());

    let mut list = Vec::new();
    list.extend_from_slice(&deepest);
    list.extend_from_slice(&0u16.to_le_bytes()); // terminator

    let rec = parsed_record(lnk_with_link_target_id_list(&list), "target.lnk");

    assert_eq!(rec.metadata["shell_item_parsed"], json!(true));
    assert_eq!(rec.metadata["shell_item_mft_entry"], json!(0x1234));
    assert_eq!(rec.metadata["shell_item_mft_sequence"], json!(7));
}

/// The counterweight: an item class this reader does not interpret structurally
/// must say so, and must not fabricate an MFT reference it never read.
#[test]
fn an_unparsed_shell_item_says_so_and_carries_no_mft_reference() {
    // A control-panel item (type 0x71): recognised as a class, not read
    // structurally, per `seance_shell_item`'s own
    // `a_control_panel_item_reports_parsed_false_with_bytes_preserved` test.
    let mut deepest = vec![0u8; 6];
    deepest[2] = 0x71;
    let size = deepest.len() as u16;
    deepest[0..2].copy_from_slice(&size.to_le_bytes());

    let mut list = Vec::new();
    list.extend_from_slice(&deepest);
    list.extend_from_slice(&0u16.to_le_bytes());

    let rec = parsed_record(lnk_with_link_target_id_list(&list), "target.lnk");

    assert_eq!(rec.metadata["shell_item_parsed"], json!(false));
    assert!(rec.metadata.get("shell_item_mft_entry").is_none());
    assert!(rec.metadata.get("shell_item_mft_sequence").is_none());
}

/// A version-7+ block whose file-reference field is all zero is what Windows
/// writes when it has no reference (38 of 38 `RecentDocs` `.lnk` items in
/// plaso's `NTUSER-WIN7.DAT`). Before this test the record published it as
/// `shell_item_mft_entry: 0`, which names `$MFT`. Now the fields are withheld
/// and `shell_item_mft_reference_note` says the field was there and zero —
/// the same sentence the registry MRU reader publishes.
#[test]
fn a_zero_file_reference_in_the_link_target_is_withheld_with_a_note() {
    use seance_shell_item::fixture::build_beef0004;

    let block = build_beef0004(8, "report.docx");
    let mut deepest = vec![0u8; 14];
    deepest[2] = 0x31;
    deepest.extend_from_slice(&block);
    let size = deepest.len() as u16;
    deepest[0..2].copy_from_slice(&size.to_le_bytes());

    let mut list = Vec::new();
    list.extend_from_slice(&deepest);
    list.extend_from_slice(&0u16.to_le_bytes());

    let rec = parsed_record(lnk_with_link_target_id_list(&list), "target.lnk");

    assert_eq!(rec.metadata["shell_item_parsed"], json!(true));
    assert!(rec.metadata.get("shell_item_mft_entry").is_none());
    assert!(rec.metadata.get("shell_item_mft_sequence").is_none());
    assert_eq!(
        rec.metadata["shell_item_mft_reference_note"],
        json!(seance_shell_item::MFT_REFERENCE_ZERO_NOTE)
    );
    let note = rec.metadata["shell_item_mft_reference_note"]
        .as_str()
        .unwrap();
    assert!(note.contains("it is zero"));
    assert!(note.contains("$MFT"));
}

/// The real deepest item of plaso's `OpenSavePidlMRU\exe` value 0 —
/// `Firefox Setup 3.6.12.exe`, version-8 block, zero reference — in a link
/// target: the same answer, on bytes Windows wrote.
#[test]
fn the_real_firefox_setup_item_yields_no_reference_and_the_note() {
    let value = seance_shell_item::real_items::open_save_pidl_mru_exe_0();
    let rec = parsed_record(lnk_with_link_target_id_list(&value), "target.lnk");
    assert_eq!(
        rec.metadata["shell_item_path"],
        json!([
            "NetworkPlaces",
            "UsersPropertyView",
            "\\\\controller\\WebDavShare",
            "Firefox Setup 3.6.12.exe"
        ])
    );
    assert_eq!(rec.metadata["shell_item_parsed"], json!(true));
    assert!(rec.metadata.get("shell_item_mft_entry").is_none());
    assert!(rec.metadata["shell_item_mft_reference_note"].is_string());
}

/// An item with no field at all gets neither the fields nor the note: the
/// note is a statement about a field that was read, not a default.
#[test]
fn an_absent_file_reference_field_gets_no_note() {
    use seance_shell_item::fixture::build_beef0004;

    let block = build_beef0004(3, "old.doc");
    let mut deepest = vec![0u8; 14];
    deepest[2] = 0x31;
    deepest.extend_from_slice(&block);
    let size = deepest.len() as u16;
    deepest[0..2].copy_from_slice(&size.to_le_bytes());

    let mut list = Vec::new();
    list.extend_from_slice(&deepest);
    list.extend_from_slice(&0u16.to_le_bytes());

    let rec = parsed_record(lnk_with_link_target_id_list(&list), "target.lnk");
    assert!(rec.metadata.get("shell_item_mft_entry").is_none());
    assert!(rec.metadata.get("shell_item_mft_reference_note").is_none());
}

/// This is additive: the target-path fields the crate already published from
/// `LinkInfo`/`VolumeID` must survive right alongside the new shell-item path.
#[test]
fn link_target_id_list_does_not_disturb_the_existing_target_fields() {
    let mut d = build_lnk_header(0x01 | 0x02); // HasLinkTargetIDList | HasLinkInfo
    let list = file_entry_id_list(&["report.docx"], 7);
    d.extend_from_slice(&(list.len() as u16).to_le_bytes());
    d.extend_from_slice(&list);

    let header_len = 0x1Cusize;
    let path_off = header_len;
    let ansi_path = b"C:\\a.txt\0";
    let total = path_off + ansi_path.len();
    let mut li = vec![0u8; header_len];
    li[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    li[4..8].copy_from_slice(&(header_len as u32).to_le_bytes());
    li[8..12].copy_from_slice(&1u32.to_le_bytes());
    li[16..20].copy_from_slice(&(path_off as u32).to_le_bytes());
    li.extend_from_slice(ansi_path);
    d.extend_from_slice(&li);

    let rec = parsed_record(d, "both.lnk");
    assert_eq!(rec.metadata["target_local_path"], "C:\\a.txt");
    assert_eq!(rec.metadata["shell_item_path"], json!(["report.docx"]));
}

#[test]
fn the_targets_recorded_size_is_published_as_the_shortcuts_figure() {
    // The field was read into `let _file_size` and dropped. It is a u32, so
    // the format itself records a target over 4 GiB modulo 2^32 — which is
    // why the key says `recorded`.
    let rec = parsed_record(lnk_with_ansi_local_base_path(b"C:\\a.txt\0"), "a.lnk");
    assert!(rec.metadata.get("target_size_recorded").is_some());
}

/// HUNT-277: a shortcut inside a shadow copy is parsed and what it yields says
/// so; a `ParsedRecord` that is not a prior version is not read.
#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    let src: Arc<dyn DataSource> = Arc::new(MockDataSource::new(build_min_lnk(
        132_223_104_000_000_000,
        0x80,
        "a.txt",
    )));
    let prior = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src.clone()),
        serde_json::json!({
            "type": "VssPriorVersion",
            "name": "a.lnk [shadow copy 2015-03-23T00:00:00Z]",
            "file_name": "a.lnk",
            "is_snapshot_version": true,
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
        }),
    );
    let out = LnkParser.process(&prior).unwrap();
    assert!(!out.is_empty(), "the prior version is parsed");
    assert!(out
        .iter()
        .all(|a| a.metadata["vss_snapshot_id"] == serde_json::json!("snap-1")));

    let other = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src),
        serde_json::json!({ "type": "SomethingElse" }),
    );
    assert!(LnkParser.process(&other).unwrap().is_empty());
}
