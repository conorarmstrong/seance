use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;
use uuid::Uuid;

// --- Pure-function units (always run) ----------------------------------------

#[test]
fn entropy_bounds() {
    assert_eq!(shannon_entropy(&[]), 0.0);
    assert_eq!(shannon_entropy(&[7u8; 4096]), 0.0); // single symbol -> 0 bits
    let uniform: Vec<u8> = (0..=255).cycle().take(4096).collect();
    assert!((shannon_entropy(&uniform) - 8.0).abs() < 0.01); // full byte range -> ~8
}

#[test]
fn imphash_entry_rules() {
    assert_eq!(
        imphash_entry("KERNEL32.dll", "CreateFileW", 0),
        "kernel32.createfilew"
    );
    assert_eq!(imphash_entry("USER32.DLL", "", 1567), "user32.ord1567");
    assert_eq!(
        imphash_entry("driver.SYS", "IoCreate", 0),
        "driver.iocreate"
    );
    // Non .dll/.ocx/.sys extension is kept (api-set style names).
    assert_eq!(
        imphash_entry("api-ms-win-core-x.l1-1-0", "Foo", 0),
        "api-ms-win-core-x.l1-1-0.foo"
    );
}

#[test]
fn imphash_md5_matches_reference() {
    // md5 of "kernel32.createfilew,user32.messageboxw" (computed independently).
    let parts = [
        imphash_entry("kernel32.dll", "CreateFileW", 0),
        imphash_entry("user32.dll", "MessageBoxW", 0),
    ];
    let mut h = md5::Md5::new();
    h.update(parts.join(",").as_bytes());
    assert_eq!(hex(&h.finalize()), "b4e9b10fbeb6c9101ac5441415aa9633");
}

#[test]
fn name_lookups() {
    assert_eq!(machine_name(0x014c), "x86 (i386)");
    assert_eq!(machine_name(0x8664), "x64 (AMD64)");
    assert_eq!(subsystem_name(2), "Windows GUI");
    assert_eq!(subsystem_name(3), "Windows Console");
}

#[test]
fn utf16_and_align() {
    assert_eq!(align4(6), 8);
    assert_eq!(align4(8), 8);
    // "Hi\0" as UTF-16LE.
    let buf = [b'H', 0, b'i', 0, 0, 0, b'X', 0];
    let (s, end) = read_utf16z(&buf, 0);
    assert_eq!(s, "Hi");
    assert_eq!(end, 6);
}

#[test]
fn non_pe_is_ignored() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"not a PE file".to_vec()));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "notes.txt" }),
    );
    assert!(PeSignatureParser.process(&art).unwrap().is_empty());
}

#[test]
fn module_metadata() {
    let p = PeSignatureParser;
    assert_eq!(p.id(), "plugin.executable.pe_signature");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}

// --- Real signed PE (gated on a sample) --------------------------------------
//
// Set SEANCE_PE_SAMPLE to a signed Windows PE to exercise the full pipeline.
// Validated against Sysinternals `strings.exe` (Microsoft-signed, SHA-256
// Authenticode); the assertions below are that binary's ground truth.

#[test]
fn signed_pe_full_analysis() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_PE_SAMPLE") else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read PE sample");
    let rec = analyze(&bytes).expect("analyze produced a record");

    // Authenticode: signed, Microsoft, and the bytes match the signed digest.
    assert_eq!(rec["signed"], json!(true));
    assert!(rec["publisher"]
        .as_str()
        .unwrap_or("")
        .contains("Microsoft Corporation"));
    assert_eq!(rec["digest_algorithm"], json!("sha256"));
    assert!(rec["signature_integrity"]
        .as_str()
        .unwrap_or("")
        .starts_with("valid"));

    // imphash is a 32-char md5 hex.
    let imphash = rec["imphash"].as_str().unwrap_or("");
    assert_eq!(imphash.len(), 32);
    assert!(imphash.chars().all(|c| c.is_ascii_hexdigit()));

    // Version resource carries the original filename.
    let orig = rec["version_info"]["OriginalFilename"]
        .as_str()
        .unwrap_or("");
    assert!(
        orig.eq_ignore_ascii_case("strings.exe"),
        "OriginalFilename was {orig:?}"
    );
}

/// A tampered signed PE must report a signature mismatch, not "valid".
#[test]
fn tampered_pe_fails_integrity() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_PE_SAMPLE") else {
        return;
    };
    let mut bytes = std::fs::read(&path).expect("read PE sample");
    // Flip a byte inside the code (well after the headers, before the cert table).
    let i = bytes.len() / 3;
    bytes[i] ^= 0xff;
    let rec = analyze(&bytes).expect("analyze");
    assert_eq!(rec["signed"], json!(true));
    assert!(
        rec["signature_integrity"]
            .as_str()
            .unwrap_or("")
            .contains("MISMATCH"),
        "expected MISMATCH, got {:?}",
        rec["signature_integrity"]
    );
}

// --- Truncated / capped reads must not read as "unsigned" (B2-052) -----------

/// Build a minimal but structurally valid unsigned PE32 image (0x400 bytes,
/// one `.text` section, a zeroed certificate-table data directory).
fn synthetic_pe32() -> Vec<u8> {
    const E_LFANEW: usize = 0x80;
    const OPT: usize = E_LFANEW + 4 + 20; // after "PE\0\0" + COFF header
    const SECTION_TABLE: usize = OPT + 224;
    let mut f = vec![0u8; 0x400];

    f[0] = b'M';
    f[1] = b'Z';
    f[0x3c..0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());
    f[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");

    // COFF header.
    let coff = E_LFANEW + 4;
    f[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // machine i386
    f[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // one section
    f[coff + 16..coff + 18].copy_from_slice(&224u16.to_le_bytes()); // optional header size
    f[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // characteristics

    // Optional header (PE32).
    f[OPT..OPT + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // magic PE32
    f[OPT + 20..OPT + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // base of code
    let win = OPT + 28;
    f[win..win + 4].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image base
    f[win + 4..win + 8].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    f[win + 8..win + 12].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    f[win + 28..win + 32].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
    f[win + 32..win + 36].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
    f[win + 40..win + 42].copy_from_slice(&3u16.to_le_bytes()); // subsystem: console
    f[win + 64..win + 68].copy_from_slice(&16u32.to_le_bytes()); // number of RVA and sizes
                                                                 // The 16 data directories (including the certificate table) stay zeroed.

    // One `.text` section header.
    let sec = SECTION_TABLE;
    f[sec..sec + 5].copy_from_slice(b".text");
    f[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
    f[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
    f[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // size of raw data
    f[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // pointer to raw data
    f[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // characteristics
    f
}

use seance_core::test_support::TruncatedSource;

fn pe_artifact(ds: Arc<dyn DataSource>, name: &str) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    )
}

#[test]
fn a_fully_read_unsigned_pe_reports_unsigned_without_an_incomplete_flag() {
    let bytes = synthetic_pe32();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "tool.exe"))
        .unwrap();
    assert_eq!(out.len(), 1);
    let md = &out[0].metadata;
    assert_eq!(md["signed"], json!(false));
    assert!(md.get("analysis_incomplete").is_none());
}

#[test]
fn a_pe_read_short_of_its_declared_size_withdraws_the_unsigned_verdict() {
    // The certificate table sits at the very end of a signed image, so a file we
    // could not read to the end must never be reported as "not signed".
    let bytes = synthetic_pe32();
    let declared = bytes.len() as u64 * 2;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "installer.exe"))
        .unwrap();
    assert_eq!(out.len(), 1);
    let md = &out[0].metadata;
    assert_eq!(md["analysis_incomplete"], json!(true));
    assert_eq!(md["analysis_incomplete_reason"], json!("short_read"));
    assert_eq!(md["declared_size"], json!(declared));
    assert!(
        md["signed"].is_null(),
        "an unread tail must not render as `signed: false`, got {:?}",
        md["signed"]
    );
    assert!(md["signature_integrity"]
        .as_str()
        .unwrap_or("")
        .starts_with("unverified"));
}

// --- The hash stops at the certificate table (HUNT-123) ----------------------

/// A signed image with a certificate table, and the same image with bytes
/// appended past that table.
///
/// This is the shape the evidence has, and the reason it is built this way
/// matters. A carve recovers a file from a header to a guessed end; on the
/// Magnet 2022 Linux image every one of 231 carved signed binaries overshot the
/// certificate table -- 8 bytes at the least, 504 at the median, 97,824 at the
/// worst. A fixture that put the certificate table at the end of the file, as
/// a signing tool does, could not have caught `HUNT-123`: the boundary the bug
/// is about and the end of the file would be the same byte. That is the same
/// failure as HUNT-122's fixtures, which passed a value shape no enumerator
/// produces.
fn synthetic_signed_pe(overshoot: usize) -> Vec<u8> {
    let mut f = synthetic_pe32();
    // A certificate table occupying the last 0x100 bytes of the signed image.
    // Its contents are never parsed by the hasher, so real DER is not needed --
    // only that these bytes are inside the table and therefore excluded.
    let cert_off = f.len();
    let cert_size = 0x100usize;
    // A WIN_CERTIFICATE header, because the PE parser reads one before the
    // hasher is ever reached: dwLength, wRevision 0x0200, wCertificateType
    // 0x0002 (PKCS#7 signed data). The payload after it is filler -- the
    // hasher does not parse the table, it excludes it.
    let mut table = Vec::with_capacity(cert_size);
    table.extend_from_slice(&(cert_size as u32).to_le_bytes());
    table.extend_from_slice(&0x0200u16.to_le_bytes());
    table.extend_from_slice(&0x0002u16.to_le_bytes());
    table.extend(std::iter::repeat_n(0xAB, cert_size - table.len()));
    f.extend_from_slice(&table);
    f[CERT_DIR_OFF..CERT_DIR_OFF + 4].copy_from_slice(&(cert_off as u32).to_le_bytes());
    f[CERT_DIR_OFF + 4..CERT_DIR_OFF + 8].copy_from_slice(&(cert_size as u32).to_le_bytes());
    // The carve overshoot: bytes that are in the recovered window and were
    // never part of what was signed. Non-zero, because 90 of the 231 real
    // tails held data rather than padding.
    f.extend((0..overshoot).map(|i| (i % 251) as u8 | 1));
    f
}

/// The Authenticode digest must not change when bytes follow the certificate
/// table.
///
/// The specification hashes the image up to `FileLength - SizeOfCertTable` and
/// nothing at or after it. This function used to hash the remainder as "any
/// trailing data after the cert table", which made the digest a function of
/// bytes outside the signed image.
///
/// What an examiner learns: whether the bytes of this binary still match what
/// its publisher signed. A wrong answer here is not a missing finding but a
/// fabricated one -- `pe_signature_mismatch` is the only detection this build
/// grades `Strong`, and its inference is that the file was modified after it
/// was signed. On the Magnet 2022 Linux image this produced 231 such
/// allegations against 231 binaries that were bit-for-bit what Microsoft
/// signed, recovered intact from unallocated space (`HUNT-123`).
#[test]
fn trailing_bytes_past_the_certificate_table_do_not_change_the_digest() {
    let clean = synthetic_signed_pe(0);
    let base = {
        let pe = goblin::pe::PE::parse(&clean).expect("parse the synthetic signed PE");
        authenticode_hash(&clean, &pe, "sha256").expect("digest over the clean image")
    };

    // Every overshoot the real evidence showed, and one far beyond it.
    for overshoot in [8usize, 504, 4096, 97_824] {
        let carved = synthetic_signed_pe(overshoot);
        let pe = goblin::pe::PE::parse(&carved).expect("parse the overshot image");
        let got =
            authenticode_hash(&carved, &pe, "sha256").expect("digest over the overshot image");
        assert_eq!(
            got, base,
            "{overshoot} bytes appended past the certificate table changed the Authenticode \
             digest; they are outside the signed image and must not be hashed"
        );
    }
}

/// And the digest must still answer to the bytes that ARE inside the image.
///
/// The fix above removes bytes from the hashed stream, and a hash that has
/// stopped responding to the file would pass the test above while reporting
/// every tampered binary as valid -- the opposite and worse error.
#[test]
fn a_byte_changed_inside_the_signed_image_does_change_the_digest() {
    let clean = synthetic_signed_pe(512);
    let base = {
        let pe = goblin::pe::PE::parse(&clean).expect("parse");
        authenticode_hash(&clean, &pe, "sha256").expect("digest")
    };
    // A byte in the `.text` section: inside the image, before the certificate
    // table, and covered by the signature.
    let mut tampered = clean.clone();
    tampered[0x200] ^= 0xff;
    let pe = goblin::pe::PE::parse(&tampered).expect("parse");
    let got = authenticode_hash(&tampered, &pe, "sha256").expect("digest");
    assert_ne!(
        got, base,
        "a byte changed inside the signed image must change the Authenticode digest"
    );
}

/// A real signed binary with a carve's overshoot appended must still verify.
///
/// The synthetic tests above pin the hash function; this pins the verdict an
/// examiner reads, end to end, on a binary a publisher actually signed. Set
/// `SEANCE_PE_SAMPLE` to a signed Windows PE to run it.
#[test]
fn a_signed_sample_with_a_carve_overshoot_still_reports_valid() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_PE_SAMPLE") else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read PE sample");
    // Confirm the ground truth first: without the overshoot this sample is
    // valid. Otherwise a broken sample would make the assertion below vacuous.
    let clean = analyze(&bytes).expect("analyze the sample");
    assert!(
        clean["signature_integrity"]
            .as_str()
            .unwrap_or("")
            .starts_with("valid"),
        "the sample itself must verify before this test means anything, got {:?}",
        clean["signature_integrity"]
    );

    let mut overshot = bytes.clone();
    overshot.extend((0..504).map(|i| (i % 251) as u8 | 1));
    let rec = analyze(&overshot).expect("analyze the overshot sample");
    assert!(
        rec["signature_integrity"]
            .as_str()
            .unwrap_or("")
            .starts_with("valid"),
        "a signed binary carried in a window that overshoots its end is still the binary its \
         publisher signed; got {:?}",
        rec["signature_integrity"]
    );
}

// --- Unreadable certificate table is not "unsigned" (B2-169) -----------------

/// Byte offset of the certificate-table data directory (index 4) in the PE32
/// image built by [`synthetic_pe32`]: optional header + 96 bytes of standard and
/// Windows-specific fields + 4 directories of 8 bytes.
const CERT_DIR_OFF: usize = 0x80 + 4 + 20 + 96 + 4 * 8;

/// An image that declares a certificate table pointing outside itself must
/// report the signature as unknown, not absent.
///
/// What an examiner learns: whether this binary was signed, and whether its
/// bytes still match what was signed. A wrong answer here is `signed: false` on
/// a file whose security directory was edited — the tampering renders as the
/// benign, common case of an unsigned binary, and nothing prompts a second look
/// (B2-169).
#[test]
fn an_out_of_bounds_certificate_table_is_reported_unknown_not_unsigned() {
    let mut bytes = synthetic_pe32();
    // Certificate table claims 0x1000 bytes starting far past the end of file.
    bytes[CERT_DIR_OFF..CERT_DIR_OFF + 4].copy_from_slice(&0x0009_0000u32.to_le_bytes());
    bytes[CERT_DIR_OFF + 4..CERT_DIR_OFF + 8].copy_from_slice(&0x1000u32.to_le_bytes());

    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "tampered.exe"))
        .unwrap();
    assert_eq!(out.len(), 1);
    let md = &out[0].metadata;
    assert!(
        md["signed"].is_null(),
        "an unreadable certificate table must not render as `signed: false`, got {:?}",
        md["signed"]
    );
    assert!(
        md["signature_integrity"]
            .as_str()
            .unwrap_or("")
            .starts_with("unverified"),
        "got {:?}",
        md["signature_integrity"]
    );
    // The file itself was read in full: this is a bad directory, not a short read.
    assert!(md.get("analysis_incomplete").is_none());
}

/// A certificate table shorter than a WIN_CERTIFICATE header is also unreadable,
/// not proof of an unsigned file.
#[test]
fn an_undersized_certificate_table_is_reported_unknown() {
    let mut bytes = synthetic_pe32();
    bytes[CERT_DIR_OFF..CERT_DIR_OFF + 4].copy_from_slice(&0x300u32.to_le_bytes());
    bytes[CERT_DIR_OFF + 4..CERT_DIR_OFF + 8].copy_from_slice(&4u32.to_le_bytes());

    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "stub.exe"))
        .unwrap();
    let md = &out[0].metadata;
    assert!(md["signed"].is_null(), "got {:?}", md["signed"]);
}

/// The common case must be untouched: no certificate table means unsigned, said
/// plainly.
#[test]
fn a_zero_sized_certificate_table_still_means_unsigned() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(synthetic_pe32()));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "plain.exe"))
        .unwrap();
    let md = &out[0].metadata;
    assert_eq!(md["signed"], json!(false));
    assert!(md.get("signature_integrity").is_none());
}

// --- B6-009 / B6-010: the standard pair, and MZ-but-unparsable --------------

/// B6-009: `analysis_incomplete` is a key this crate invented. The frontend's
/// incompleteness reader and the court report's completeness census key on
/// `content_incomplete` / `content_incomplete_reason`, so a signed binary whose
/// certificate table was never reached was invisible to both.
#[test]
fn a_short_read_pe_carries_the_standard_incompleteness_pair() {
    let bytes = synthetic_pe32();
    let declared = bytes.len() as u64 * 2;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "installer.exe"))
        .unwrap();
    let md = &out[0].metadata;
    assert_eq!(md["content_incomplete"], json!(true));
    assert_eq!(md["content_incomplete_reason"], json!("short_read"));
    // The crate-local key stays for the existing consumers.
    assert_eq!(md["analysis_incomplete"], json!(true));
}

/// The counterweight: a fully read PE must carry neither key, or the flag on
/// the short-read ones means nothing.
#[test]
fn a_fully_read_pe_carries_no_incompleteness_keys() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(synthetic_pe32()));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "tool.exe"))
        .unwrap();
    let md = &out[0].metadata;
    assert!(md.get("content_incomplete").is_none());
    assert!(md.get("analysis_incomplete").is_none());
}

/// B6-010: the DOS `MZ` magic matched, so this file claims to be a Windows
/// executable. Returning nothing filed it beside every text document in the
/// case — a corrupt or deliberately malformed dropper read as "not examined".
#[test]
fn an_mz_file_that_will_not_parse_as_a_pe_still_leaves_a_record() {
    // `MZ` header with an e_lfanew pointing nowhere useful: goblin refuses it.
    let mut bytes = vec![0u8; 256];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c..0x40].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "dropper.exe"))
        .unwrap();
    assert_eq!(
        out.len(),
        1,
        "an MZ file that will not parse must not vanish"
    );
    let md = &out[0].metadata;
    assert_eq!(md["status"], json!("pe_unparsable"));
    assert!(
        md["signed"].is_null(),
        "whether it is signed is unknown, not false: {:?}",
        md["signed"]
    );
    assert_eq!(md["content_incomplete"], json!(true));
    assert_eq!(md["source_name"], json!("dropper.exe"));
    assert_eq!(out[0].artifact_type, ArtifactType::ParsedRecord);
}

// --- Provenance carried onto the record --------------------------------------
//
// Where an executable was is a fact only the source artifact holds, and the
// findings layer subscribes to parsed records — it cannot walk back to the
// file. So these keys are the whole of what makes a PE-in-an-ADS lead possible.

fn pe_artifact_with(ds: Arc<dyn DataSource>, metadata: Value) -> Artifact {
    Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, Some(ds), metadata)
}

#[test]
fn a_pe_in_an_alternate_data_stream_records_the_stream_it_came_from() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(synthetic_pe32()));
    let out = PeSignatureParser
        .process(&pe_artifact_with(
            ds,
            json!({
                "name": "report.docx:update",
                "is_ads": true,
                "stream_name": "update",
                "parent_file": "report.docx",
            }),
        ))
        .unwrap();
    let md = &out[0].metadata;
    assert_eq!(md["in_alternate_data_stream"], json!(true));
    assert_eq!(md["stream_name"], json!("update"));
    assert_eq!(md["parent_file"], json!("report.docx"));
}

#[test]
fn a_pe_carved_from_slack_records_the_carving_source_and_the_host_file() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(synthetic_pe32()));
    let out = PeSignatureParser
        .process(&pe_artifact_with(
            ds,
            json!({
                "name": "carved_1048576.exe",
                "carving_source": "slack",
                "parent_file": "readme.txt",
                "deleted": true,
            }),
        ))
        .unwrap();
    let md = &out[0].metadata;
    assert_eq!(md["carving_source"], json!("slack"));
    assert_eq!(md["parent_file"], json!("readme.txt"));
    assert_eq!(md["source_deleted"], json!(true));
    // Not an ADS, and the key says nothing rather than saying false — absent
    // means the source did not claim it.
    assert!(md.get("in_alternate_data_stream").is_none());
}

#[test]
fn an_ordinary_file_gains_no_provenance_keys() {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(synthetic_pe32()));
    let out = PeSignatureParser
        .process(&pe_artifact(ds, "tool.exe"))
        .unwrap();
    let md = &out[0].metadata;
    for key in [
        "in_alternate_data_stream",
        "stream_name",
        "parent_file",
        "carving_source",
        "source_deleted",
    ] {
        assert!(md.get(key).is_none(), "{key} was invented");
    }
}

/// A file that will not parse as a PE still carries where it was: an
/// unparsable image in an alternate data stream is the more interesting one.
#[test]
fn an_unparsable_pe_still_records_where_it_was() {
    let ds: Arc<dyn DataSource> =
        Arc::new(ByteSliceDataSource::new(b"MZ\x00\x00 not a pe".to_vec()));
    let out = PeSignatureParser
        .process(&pe_artifact_with(
            ds,
            json!({
                "name": "report.docx:update",
                "is_ads": true,
                "stream_name": "update",
                "parent_file": "report.docx",
            }),
        ))
        .unwrap();
    let md = &out[0].metadata;
    assert_eq!(md["status"], json!("pe_unparsable"));
    assert_eq!(md["in_alternate_data_stream"], json!(true));
    assert_eq!(md["stream_name"], json!("update"));
}
