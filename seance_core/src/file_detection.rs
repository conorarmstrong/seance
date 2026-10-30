/// File type detection based on content (magic bytes, headers, etc.)
use crate::data_source::DataSource;

#[derive(Debug, Clone, PartialEq)]
pub enum DetectedFileType {
    // Container formats
    E01Container,
    Aff4Container,
    ZipArchive,
    TarArchive,
    GzipArchive,
    Bzip2Archive,
    XzArchive,
    SevenZipArchive,
    Ole2Document,
    RarArchive,
    MboxFile,
    // Virtual disk images
    VhdImage,
    VhdxImage,
    VmdkImage,
    Qcow2Image,
    SparseImage,
    // System artifacts
    NtfsMft,
    NtfsLogFile,
    RegistryHive,
    EvtxLog,
    PrefetchFile,
    EseDatabase,
    SqliteDatabase,
    NtfsIndx,
    // Network captures
    PcapFile,
    PcapNgFile,
    Unknown,
}

/// Detect file type by reading magic bytes and headers.
///
/// A read error is logged and answered with `Unknown`, which makes "could not
/// read the header" look like "unrecognised format". New callers should use
/// [`try_detect_file_type`] and record the failure as "could not look".
pub fn detect_file_type(data_source: &dyn DataSource) -> DetectedFileType {
    try_detect_file_type(data_source).unwrap_or_else(|e| {
        tracing::warn!("file type detection could not read the header: {e}");
        DetectedFileType::Unknown
    })
}

/// Detect file type by reading magic bytes and headers, reporting a read error
/// as an error. `Ok(Unknown)` means the header was read and matched nothing;
/// `Err` means it could not be read, which says nothing about the format.
pub fn try_detect_file_type(data_source: &dyn DataSource) -> std::io::Result<DetectedFileType> {
    // Read the first 512 bytes for detection. Loop the read: a single `read_at`
    // is allowed to return fewer bytes than requested, and a short return would
    // hide magics that live deep in the header -- TAR's is at byte 257 -- making
    // a real archive detect as Unknown (BUG-192).
    let mut header = vec![0u8; 512];
    let mut bytes_read = 0usize;
    while bytes_read < header.len() {
        match data_source.read_at(bytes_read as u64, &mut header[bytes_read..]) {
            Ok(0) => break, // genuine EOF: the source is shorter than 512 bytes
            Ok(n) => bytes_read += n,
            Err(e) => return Err(e),
        }
    }
    Ok(classify_header(&header, bytes_read))
}

/// Classify the first `bytes_read` bytes of a file by their magic numbers.
fn classify_header(header: &[u8], bytes_read: usize) -> DetectedFileType {
    if bytes_read < 4 {
        return DetectedFileType::Unknown;
    }

    // Check ZIP signature: a local file header (PK\x03\x04), an empty archive's
    // end-of-central-directory record (PK\x05\x06) or a spanned-archive marker
    // (PK\x07\x08). "PK" alone is a weak claim: it opens ordinary text such as
    // "PKCS#7 ..." and would route it to the ZIP expander as a corrupt archive.
    if bytes_read >= 4
        && matches!(
            header[0..4],
            [b'P', b'K', 3, 4] | [b'P', b'K', 5, 6] | [b'P', b'K', 7, 8]
        )
    {
        // AFF4 is a ZIP container whose first entry is `container.description`;
        // that filename appears in the first local file header, so it lands in
        // this 512-byte window. Distinguish it before treating it as a plain ZIP.
        if header[..bytes_read]
            .windows(21)
            .any(|w| w == b"container.description")
        {
            return DetectedFileType::Aff4Container;
        }
        return DetectedFileType::ZipArchive;
    }

    // An EWF segment's 8-byte signature is "EVF\x09\x0D\x0A\xFF\x00" for a
    // physical image and "LVF\x09\x0D\x0A\xFF\x00" for a logical evidence
    // file. Both are handed to `seance_container_e01`, which reads the
    // signature again and decides: a physical image is opened as a disk, a
    // logical evidence file has its entry tree walked and each entry published
    // as a file (HUNT-144). The physical family is matched on its first three
    // bytes as it always has been; the logical one on all eight, since `LVF`
    // alone is a weak claim.
    if bytes_read >= 8 && (&header[0..3] == b"EVF" || &header[0..8] == b"LVF\x09\x0d\x0a\xff\x00") {
        return DetectedFileType::E01Container;
    }

    // Check GZIP signature: 1F 8B at offset 0
    // Must come before TAR check since .tar.gz starts with GZIP magic
    if bytes_read >= 2 && header[0..2] == [0x1F, 0x8B] {
        return DetectedFileType::GzipArchive;
    }

    // Check BZIP2 signature: "BZh" at offset 0
    if bytes_read >= 3 && &header[0..3] == b"BZh" {
        return DetectedFileType::Bzip2Archive;
    }

    // Check XZ signature: FD 37 7A 58 5A 00 at offset 0
    if bytes_read >= 6 && header[0..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
        return DetectedFileType::XzArchive;
    }

    // Check 7z signature: 37 7A BC AF 27 1C at offset 0
    if bytes_read >= 6 && header[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return DetectedFileType::SevenZipArchive;
    }

    // Check OLE2/Compound Document signature: D0 CF 11 E0 A1 B1 1A E1
    // Shared by DOC, XLS, PPT, MSG files
    if bytes_read >= 8 && header[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return DetectedFileType::Ole2Document;
    }

    // Check RAR signature: "Rar!" at offset 0
    if bytes_read >= 4 && &header[0..4] == b"Rar!" {
        return DetectedFileType::RarArchive;
    }

    // Check QCOW2 signature: 0x514649FB ("QFI\xFB") at offset 0 (big-endian)
    if bytes_read >= 4 && header[0..4] == [0x51, 0x46, 0x49, 0xFB] {
        return DetectedFileType::Qcow2Image;
    }

    // Check Apple sparse disk image signature: "sprs" at offset 0
    if bytes_read >= 4 && &header[0..4] == b"sprs" {
        return DetectedFileType::SparseImage;
    }

    // Check VMDK sparse signature: VMDK magic 0x564D444B (little-endian "KDMV") at offset 0
    if bytes_read >= 4 {
        let vmdk_magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if vmdk_magic == 0x564D444B {
            return DetectedFileType::VmdkImage;
        }
    }

    // Check VHDX signature: "vhdxfile" at offset 0
    if bytes_read >= 8 && &header[0..8] == b"vhdxfile" {
        return DetectedFileType::VhdxImage;
    }

    // Check VHD signature: "conectix" at offset 0 (dynamic VHD has footer copy at start)
    if bytes_read >= 8 && &header[0..8] == b"conectix" {
        return DetectedFileType::VhdImage;
    }

    // Check TAR signature: "ustar" at offset 257
    if bytes_read >= 262 && &header[257..262] == b"ustar" {
        return DetectedFileType::TarArchive;
    }

    // Check MBOX signature: "From " at offset 0
    if bytes_read >= 5 && &header[0..5] == b"From " {
        return DetectedFileType::MboxFile;
    }

    // Check MFT signature: "FILE" at offset 0
    if bytes_read >= 4 && &header[0..4] == b"FILE" {
        return DetectedFileType::NtfsMft;
    }

    // Check $LogFile signature: "RSTR" at offset 0
    if bytes_read >= 4 && &header[0..4] == b"RSTR" {
        return DetectedFileType::NtfsLogFile;
    }

    // Check Registry hive signature: "regf" at offset 0
    if bytes_read >= 4 && &header[0..4] == b"regf" {
        return DetectedFileType::RegistryHive;
    }

    // Check EVTX signature: "ElfFile\0" at offset 0
    if bytes_read >= 8 && &header[0..8] == b"ElfFile\0" {
        return DetectedFileType::EvtxLog;
    }

    // Check MAM-compressed Prefetch (Windows 10/11): "MAM\x04" Xpress-Huffman
    // wrapper. Modern .pf files are compressed with this container; the blob
    // decompresses to an SCCA prefetch. The prefetch plugin validates the inner
    // SCCA after decompression, so a non-prefetch MAM blob yields no artifact.
    if bytes_read >= 8 && header[0..4] == [b'M', b'A', b'M', 0x04] {
        return DetectedFileType::PrefetchFile;
    }

    // Check Prefetch signature: version number at offset 0 (17, 23, 26, 30, 31)
    // followed by "SCCA" signature at offset 4
    if bytes_read >= 8 {
        let version = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if (version == 17 || version == 23 || version == 26 || version == 30 || version == 31)
            && &header[4..8] == b"SCCA"
        {
            return DetectedFileType::PrefetchFile;
        }
    }

    // Check classic libpcap: a magic at offset 0 that also declares the byte
    // order the rest of the header was written in. D4C3B2A1 and 4D3CB2A1 are
    // what a little-endian writer leaves on disk; A1B2C3D4 and A1B23C4D come
    // from a big-endian one. The 4D3C.. / ..3C4D pair is the nanosecond-
    // resolution variant tcpdump writes routinely, identical in header shape.
    //
    // The magic alone decides. These four bytes are strong -- no other format
    // opens with them -- so the version fields are deliberately NOT consulted
    // here: a header claiming 2.5, or 2.4 written in the byte order the magic
    // does not announce, is still a capture file, and the pcap module refuses
    // it by name with the version it read. Filtering it out at detection
    // would send it to a bare RawEvidence that no module parses, and the
    // examiner would see nothing under the source -- "unsupported" and
    // "empty" rendered identically. A full 24-byte header is still required:
    // shorter than that is a fragment, not a capture of any version.
    if bytes_read >= 24
        && matches!(
            header[0..4],
            [0xD4, 0xC3, 0xB2, 0xA1]
                | [0x4D, 0x3C, 0xB2, 0xA1]
                | [0xA1, 0xB2, 0xC3, 0xD4]
                | [0xA1, 0xB2, 0x3C, 0x4D]
        )
    {
        return DetectedFileType::PcapFile;
    }

    // Check pcapng: Section Header Block type 0A0D0D0A at offset 0, with the
    // byte-order magic at offset 8 corroborating it. The block type is
    // deliberately palindromic so it reads the same whichever way the section
    // was written, which is exactly why it cannot stand alone -- it is a
    // CR/LF-shaped sequence that occurs in ordinary text, and a file misrouted
    // on it shows an examiner a capture parser's refusal where there was never
    // a capture. Only the byte-order magic says how the section is encoded.
    if bytes_read >= 12
        && header[0..4] == [0x0A, 0x0D, 0x0D, 0x0A]
        && (header[8..12] == [0x4D, 0x3C, 0x2B, 0x1A] || header[8..12] == [0x1A, 0x2B, 0x3C, 0x4D])
    {
        return DetectedFileType::PcapNgFile;
    }

    // Check ESE database signature: 0xEF, 0xCD, 0xAB, 0x89 at offset 4
    if bytes_read >= 8 && header[4..8] == [0xEF, 0xCD, 0xAB, 0x89] {
        return DetectedFileType::EseDatabase;
    }

    // Check SQLite signature: "SQLite format 3\0" at offset 0
    if bytes_read >= 16 && &header[0..16] == b"SQLite format 3\0" {
        return DetectedFileType::SqliteDatabase;
    }

    // Check NTFS INDX signature: "INDX" at offset 0
    if bytes_read >= 4 && &header[0..4] == b"INDX" {
        return DetectedFileType::NtfsIndx;
    }

    DetectedFileType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Simple test data source that holds data in memory
    #[derive(Debug)]
    struct TestDataSource {
        data: Vec<u8>,
    }

    impl TestDataSource {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl DataSource for TestDataSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let offset = offset as usize;
            if offset >= self.data.len() {
                return Ok(0);
            }
            let available = self.data.len() - offset;
            let to_read = std::cmp::min(buf.len(), available);
            buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
            Ok(to_read)
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    /// HUNT-144: a logical evidence file is routed to the EWF reader by its
    /// full signature, which now walks it; three bytes of `LVF` alone are not.
    #[test]
    fn a_logical_evidence_file_is_detected_by_its_whole_signature() {
        let mut data = b"LVF\x09\x0d\x0a\xff\x00".to_vec();
        data.resize(512, 0);
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::E01Container
        );
        let mut near = b"LVF plain text".to_vec();
        near.resize(512, b' ');
        let source = Arc::new(TestDataSource::new(near));
        assert_ne!(
            detect_file_type(source.as_ref()),
            DetectedFileType::E01Container
        );
    }

    #[test]
    fn test_detect_mft() {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(b"FILE");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(detect_file_type(source.as_ref()), DetectedFileType::NtfsMft);
    }

    #[test]
    fn test_detect_logfile() {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(b"RSTR");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::NtfsLogFile
        );
    }

    #[test]
    fn test_detect_registry() {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(b"regf");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::RegistryHive
        );
    }

    #[test]
    fn test_detect_evtx() {
        let mut data = vec![0u8; 1024];
        data[0..8].copy_from_slice(b"ElfFile\0");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(detect_file_type(source.as_ref()), DetectedFileType::EvtxLog);
    }

    #[test]
    fn test_detect_prefetch() {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(&26u32.to_le_bytes()); // Windows 10 prefetch version
        data[4..8].copy_from_slice(b"SCCA");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::PrefetchFile
        );
    }

    #[test]
    fn test_detect_prefetch_v31_uncompressed() {
        // Windows 11 uncompressed SCCA prefetch version 31.
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(&31u32.to_le_bytes());
        data[4..8].copy_from_slice(b"SCCA");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::PrefetchFile
        );
    }

    #[test]
    fn test_detect_prefetch_mam_compressed() {
        // Win10/11 .pf files are MAM\x04 (Xpress-Huffman) compressed. Detection
        // must route them to the prefetch plugin, not leave them Unknown.
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(&[b'M', b'A', b'M', 0x04]);
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::PrefetchFile
        );
    }

    #[test]
    fn test_detect_ese() {
        let mut data = vec![0u8; 1024];
        data[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::EseDatabase
        );
    }

    #[test]
    fn test_detect_indx() {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(b"INDX");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::NtfsIndx
        );
    }

    #[test]
    fn test_detect_gzip() {
        let mut data = vec![0u8; 1024];
        data[0..2].copy_from_slice(&[0x1F, 0x8B]);
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::GzipArchive
        );
    }

    #[test]
    fn test_detect_bzip2() {
        let mut data = vec![0u8; 1024];
        data[0..3].copy_from_slice(b"BZh");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::Bzip2Archive
        );
    }

    #[test]
    fn test_detect_xz() {
        let mut data = vec![0u8; 1024];
        data[0..6].copy_from_slice(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]);
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::XzArchive
        );
    }

    #[test]
    fn test_detect_7z() {
        let mut data = vec![0u8; 1024];
        data[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::SevenZipArchive
        );
    }

    #[test]
    fn test_detect_ole2() {
        let mut data = vec![0u8; 1024];
        data[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::Ole2Document
        );
    }

    #[test]
    fn test_detect_rar() {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(b"Rar!");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::RarArchive
        );
    }

    #[test]
    fn test_detect_mbox() {
        let mut data = vec![0u8; 1024];
        data[0..5].copy_from_slice(b"From ");
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(
            detect_file_type(source.as_ref()),
            DetectedFileType::MboxFile
        );
    }

    #[test]
    fn test_detect_aff4_vs_zip() {
        // A plain ZIP.
        let mut zip = vec![0u8; 512];
        zip[0..4].copy_from_slice(b"PK\x03\x04");
        let src = Arc::new(TestDataSource::new(zip));
        assert_eq!(detect_file_type(src.as_ref()), DetectedFileType::ZipArchive);

        // An empty ZIP is just the end-of-central-directory record.
        let mut empty = vec![0u8; 22];
        empty[0..4].copy_from_slice(b"PK\x05\x06");
        let src = Arc::new(TestDataSource::new(empty));
        assert_eq!(detect_file_type(src.as_ref()), DetectedFileType::ZipArchive);

        // Text that merely starts with "PK" is not a ZIP.
        for text in [&b"PKI certificate bundle"[..], &b"PKCS#7 signed data"[..]] {
            let src = Arc::new(TestDataSource::new(text.to_vec()));
            assert_eq!(detect_file_type(src.as_ref()), DetectedFileType::Unknown);
        }

        // An AFF4 ZIP: first local file header names container.description.
        let mut aff4 = vec![0u8; 512];
        aff4[0..4].copy_from_slice(b"PK\x03\x04");
        aff4[30..51].copy_from_slice(b"container.description");
        let src = Arc::new(TestDataSource::new(aff4));
        assert_eq!(
            detect_file_type(src.as_ref()),
            DetectedFileType::Aff4Container
        );
    }

    /// An unreadable header is "could not look", never "unrecognised".
    #[test]
    fn an_unreadable_header_is_an_error_not_unknown() {
        let src = crate::test_support::UnreadableSource::new(4096);
        assert!(try_detect_file_type(&src).is_err());
        let ok = TestDataSource::new(vec![0x42u8; 1024]);
        assert_eq!(
            try_detect_file_type(&ok).unwrap(),
            DetectedFileType::Unknown
        );
    }

    #[test]
    fn test_detect_unknown() {
        let data = vec![0x42u8; 1024]; // Random data
        let source = Arc::new(TestDataSource::new(data));
        assert_eq!(detect_file_type(source.as_ref()), DetectedFileType::Unknown);
    }

    /// Build the 24-byte classic libpcap file header. `magic` is written as
    /// literal on-disk bytes because that is exactly what a reader sees; every
    /// other field is written in the byte order the magic announces.
    fn classic_pcap_header(magic: [u8; 4], little_endian: bool, major: u16, minor: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(24);
        h.extend_from_slice(&magic);
        let u16b = |v: u16| {
            if little_endian {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        let u32b = |v: u32| {
            if little_endian {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        h.extend_from_slice(&u16b(major));
        h.extend_from_slice(&u16b(minor));
        h.extend_from_slice(&u32b(0)); // thiszone
        h.extend_from_slice(&u32b(0)); // sigfigs
        h.extend_from_slice(&u32b(262_144)); // snaplen
        h.extend_from_slice(&u32b(1)); // network: LINKTYPE_ETHERNET
        h
    }

    /// Build a 28-byte pcapng Section Header Block. The block type is a fixed
    /// byte sequence in both byte orders -- that is the whole point of
    /// 0A0D0D0A, it reads the same either way -- so only the byte-order magic
    /// at offset 8 says how the rest of the file is encoded.
    fn pcapng_shb(little_endian: bool) -> Vec<u8> {
        let mut h = Vec::with_capacity(28);
        h.extend_from_slice(&[0x0A, 0x0D, 0x0D, 0x0A]);
        let u32b = |v: u32| {
            if little_endian {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        h.extend_from_slice(&u32b(28)); // block total length
        h.extend_from_slice(if little_endian {
            &[0x4D, 0x3C, 0x2B, 0x1A]
        } else {
            &[0x1A, 0x2B, 0x3C, 0x4D]
        });
        let u16b = |v: u16| {
            if little_endian {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        h.extend_from_slice(&u16b(1)); // version major
        h.extend_from_slice(&u16b(0)); // version minor
        h.extend_from_slice(&[0xFF; 8]); // section length: -1, not known
        h.extend_from_slice(&u32b(28)); // trailing block total length
        h
    }

    fn detect(bytes: Vec<u8>) -> DetectedFileType {
        let source = Arc::new(TestDataSource::new(bytes));
        detect_file_type(source.as_ref())
    }

    /// A capture written on a little-endian host carries the magic reversed on
    /// disk. Without this an examiner's own Linux/Windows captures -- which is
    /// nearly all of them -- detect as Unknown and reach no parser.
    #[test]
    fn a_little_endian_classic_pcap_header_is_detected_as_a_capture() {
        let h = classic_pcap_header([0xD4, 0xC3, 0xB2, 0xA1], true, 2, 4);
        assert_eq!(detect(h), DetectedFileType::PcapFile);
    }

    /// The same file written on a big-endian host. The magic is the way round
    /// the specification prints it, and the version fields follow suit.
    #[test]
    fn a_big_endian_classic_pcap_header_is_detected_as_a_capture() {
        let h = classic_pcap_header([0xA1, 0xB2, 0xC3, 0xD4], false, 2, 4);
        assert_eq!(detect(h), DetectedFileType::PcapFile);
    }

    /// Nanosecond-resolution captures differ only in the magic; the header is
    /// the same shape. tcpdump writes these routinely, so treating the magic as
    /// unrecognised would silently drop a whole class of evidence.
    #[test]
    fn a_nanosecond_resolution_pcap_header_is_detected_in_both_byte_orders() {
        let le = classic_pcap_header([0x4D, 0x3C, 0xB2, 0xA1], true, 2, 4);
        assert_eq!(detect(le), DetectedFileType::PcapFile);
        let be = classic_pcap_header([0xA1, 0xB2, 0x3C, 0x4D], false, 2, 4);
        assert_eq!(detect(be), DetectedFileType::PcapFile);
    }

    /// The Case 001 capture is named `case001.pcap` and is in fact pcapng, so
    /// the extension cannot be trusted and this block type is the only thing
    /// that identifies it.
    #[test]
    fn a_pcapng_section_header_block_is_detected_in_both_byte_orders() {
        assert_eq!(detect(pcapng_shb(true)), DetectedFileType::PcapNgFile);
        assert_eq!(detect(pcapng_shb(false)), DetectedFileType::PcapNgFile);
    }

    /// 0A0D0D0A on its own is four weak bytes -- it is a deliberately
    /// line-ending-shaped sequence and will occur in ordinary text. Detecting
    /// on it alone misroutes a file to a parser that can only refuse it, and an
    /// examiner then sees a refusal where there is no capture at all.
    #[test]
    fn a_pcapng_block_type_without_the_byte_order_magic_is_not_detected() {
        let mut h = pcapng_shb(true);
        h[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert_ne!(detect(h), DetectedFileType::PcapNgFile);

        // A plausible near-miss: the byte-order magic transposed by one byte.
        let mut h = pcapng_shb(true);
        h[8..12].copy_from_slice(&[0x3C, 0x4D, 0x2B, 0x1A]);
        assert_ne!(detect(h), DetectedFileType::PcapNgFile);

        // And the sequence appearing as ordinary CR/LF-laden text.
        let mut text = vec![0x0A, 0x0D, 0x0D, 0x0A];
        text.extend_from_slice(b"Subject: a mail body, not a capture at all......");
        assert_ne!(detect(text), DetectedFileType::PcapNgFile);
    }

    /// Detection is by magic alone; the version is the parser's to judge.
    /// The four magic bytes are strong -- nothing else opens with them -- so a
    /// header that then claims version 2.5, 3.0, or 2.4 written in the wrong
    /// byte order is still a capture file, just one this build cannot read.
    /// It must reach the pcap module so the module can refuse it BY NAME with
    /// a `NetworkCaptureRefusal` naming the version. If detection filtered it
    /// out first, the file would fall to a bare `RawEvidence` that no module
    /// parses, and the examiner would see nothing at all under the source --
    /// the HUNT-060 silence, where "unsupported" and "empty" look the same.
    #[test]
    fn a_classic_pcap_header_with_an_unexpected_version_is_detected_so_the_parser_can_refuse_it_by_name(
    ) {
        let h = classic_pcap_header([0xD4, 0xC3, 0xB2, 0xA1], true, 3, 0);
        assert_eq!(detect(h), DetectedFileType::PcapFile);
        let h = classic_pcap_header([0xD4, 0xC3, 0xB2, 0xA1], true, 2, 5);
        assert_eq!(detect(h), DetectedFileType::PcapFile);
        // Version fields written in the byte order the magic does not announce:
        // the parser reads 512.1024 and refuses by that number, which is a
        // better outcome than silence.
        let h = classic_pcap_header([0xA1, 0xB2, 0xC3, 0xD4], true, 2, 4);
        assert_eq!(detect(h), DetectedFileType::PcapFile);
    }

    /// Carved fragments and truncated exhibits routinely stop mid-header. The
    /// detector reads a fixed 512-byte window, so every field access past the
    /// bytes actually read must be guarded rather than trusted.
    #[test]
    fn a_capture_header_cut_short_neither_panics_nor_matches() {
        for len in 0..24usize {
            let h = classic_pcap_header([0xD4, 0xC3, 0xB2, 0xA1], true, 2, 4);
            assert_ne!(
                detect(h[..len].to_vec()),
                DetectedFileType::PcapFile,
                "a {len}-byte fragment is not enough to claim a classic pcap"
            );
        }
        for len in 0..12usize {
            let h = pcapng_shb(true);
            assert_ne!(
                detect(h[..len].to_vec()),
                DetectedFileType::PcapNgFile,
                "a {len}-byte fragment is not enough to claim a pcapng"
            );
        }
    }

    /// The capture checks are new arrivals in a long if-chain. An early return
    /// placed carelessly would shadow the detections below it, and the failure
    /// would show up as registry hives silently ceasing to parse rather than as
    /// anything about captures.
    #[test]
    fn the_existing_detections_still_win_after_the_capture_magics_were_added() {
        let mut hive = vec![0u8; 1024];
        hive[0..4].copy_from_slice(b"regf");
        assert_eq!(detect(hive), DetectedFileType::RegistryHive);

        let mut evtx = vec![0u8; 1024];
        evtx[0..8].copy_from_slice(b"ElfFile\0");
        assert_eq!(detect(evtx), DetectedFileType::EvtxLog);

        let mut sqlite = vec![0u8; 1024];
        sqlite[0..16].copy_from_slice(b"SQLite format 3\0");
        assert_eq!(detect(sqlite), DetectedFileType::SqliteDatabase);

        let mut ese = vec![0u8; 1024];
        ese[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
        assert_eq!(detect(ese), DetectedFileType::EseDatabase);
    }
}
