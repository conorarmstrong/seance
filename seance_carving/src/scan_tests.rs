//! Engine-level tests: whole scans through the full signature registry, for the
//! behaviours a signature's own unit test cannot show (what the engine hands it,
//! and what it records).

use crate::engine::{CarvedFile, CarvingDataSource, CarvingEngine, ScanResult};
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::io;
use std::sync::Arc;

pub(crate) struct Mem(pub(crate) Vec<u8>);

impl CarvingDataSource for Mem {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = (offset as usize).min(self.0.len());
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

fn full_registry() -> Arc<SignatureRegistry> {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    Arc::new(registry)
}

fn scan_all(data: Vec<u8>) -> ScanResult {
    let src = Mem(data);
    CarvingEngine::new(full_registry()).scan_with_progress(&src, src.size(), None, None)
}

fn carve_at_zero<'a>(result: &'a ScanResult, name: &str) -> &'a CarvedFile {
    result
        .files
        .iter()
        .find(|f| f.offset == 0 && f.signature_name == name)
        .unwrap_or_else(|| panic!("no {name} carve at offset 0 in {:?}", result.files))
}

// ---- footers that straddle a block boundary --------------------------------

/// A footer-terminated format: its header, its footer, the bytes the format
/// keeps after the footer, and the name the carve is recorded under.
struct Footered {
    name: &'static str,
    header: &'static [u8],
    footer: &'static [u8],
    after_footer: usize,
}

const FOOTERED: &[Footered] = &[
    Footered {
        name: "DXF",
        header: b"  0\nSECTION",
        footer: b"\nEOF",
        after_footer: 0,
    },
    Footered {
        name: "PNG",
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: b"IEND",
        after_footer: 4, // the chunk's CRC
    },
    Footered {
        name: "PDF",
        header: b"%PDF-1.7\n",
        footer: b"%%EOF",
        after_footer: 0,
    },
    Footered {
        name: "GP2",
        header: b"GOBE SCOTT/01/02DOC!",
        footer: &[0x00, 0x00, 0x00, 0x01, b'E', b'N', b'D', b'!'],
        after_footer: 0,
    },
    Footered {
        name: "Guitar Pro",
        header: b"\x18FICHIER GUITAR PRO v5.00",
        footer: &[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        after_footer: 0,
    },
    Footered {
        name: "FRM",
        header: b"#UGC:2 DWGFORMabcd",
        footer: b"#END_OF_UGC",
        after_footer: 1,
    },
    Footered {
        name: "PS",
        header: b"%!PS-Adobe-3.0\n",
        footer: b"%%EOF",
        after_footer: 1,
    },
];

/// The terminator of a carve may begin in the last bytes of one 512-byte block
/// and end in the next. Whichever of its bytes fall either side, the carve ends
/// at the footer, not at the next header or the size cap.
#[test]
fn a_footer_split_across_a_block_boundary_still_ends_the_carve() {
    for f in FOOTERED {
        for footer_at in 480..=520usize {
            let mut data = f.header.to_vec();
            data.resize(footer_at, b'x');
            data.extend_from_slice(f.footer);
            let end = data.len() + f.after_footer;
            data.extend_from_slice(&[0x55; 3000]); // unrelated data after the file
            let result = scan_all(data);
            let carve = carve_at_zero(&result, f.name);
            assert_eq!(
                carve.size, end as u64,
                "{} with its footer at {footer_at}",
                f.name
            );
            assert_eq!(carve.validated, Some(true), "{} at {footer_at}", f.name);
        }
    }
}

// ---- a header window past the first block ---------------------------------

/// An ISO 9660 volume descriptor lies 32 KiB into the volume: the engine shows
/// the signature that far, so the volume is found and sized from it.
#[test]
fn an_iso_volume_is_found_through_the_header_window() {
    let mut data = vec![0u8; 300_000];
    let pvd = 0x8000;
    data[pvd..pvd + 6].copy_from_slice(&[0x01, b'C', b'D', b'0', b'0', b'1']);
    data[pvd + 80..pvd + 84].copy_from_slice(&100u32.to_le_bytes());
    data[pvd + 84..pvd + 88].copy_from_slice(&100u32.to_be_bytes());
    data[pvd + 128..pvd + 130].copy_from_slice(&2048u16.to_le_bytes());
    data[pvd + 130..pvd + 132].copy_from_slice(&2048u16.to_be_bytes());
    let result = scan_all(data);
    let iso = carve_at_zero(&result, "ISO");
    assert_eq!(iso.size, 100 * 2048);
}

/// InnoDB's `infimum`/`supremum` records are 48 KiB in.
#[test]
fn an_innodb_file_is_found_through_the_header_window() {
    let mut data = vec![0u8; 0x10000];
    data[54..58].copy_from_slice(&1u32.to_be_bytes()); // FSP flags, page type 0
    data[0xc063..0xc06a].copy_from_slice(b"infimum");
    data[0xc070..0xc078].copy_from_slice(b"supremum");
    let result = scan_all(data);
    carve_at_zero(&result, "InnoDB");
}

/// FileMaker's `HBAM` marker is at 0x20d, past a 512-byte block.
#[test]
fn a_filemaker_file_is_found_through_the_header_window() {
    let mut data = vec![0u8; 0x2000];
    data[..20].copy_from_slice(&[
        0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x00, 0x02, 0x00, 0x02, 0xc0,
        b'H', b'B', b'A', b'M', b'7',
    ]);
    data[0x20d..0x211].copy_from_slice(b"HBAM");
    data[0x21e..0x224].copy_from_slice(b"Pro 12");
    let result = scan_all(data);
    assert_eq!(carve_at_zero(&result, "FP7").extension, "fmp12");
}

/// Nikon's `MLT` marker is at 588.
#[test]
fn a_nikon_dsc_file_is_found_through_the_header_window() {
    let mut data = vec![0u8; 0x2000];
    data[588..591].copy_from_slice(b"MLT");
    let result = scan_all(data);
    carve_at_zero(&result, "DSC");
}

/// A registration beyond the first block is only reachable if its signature
/// asks the engine to show it that far; otherwise it is dead. Every one must.
#[test]
fn every_registered_magic_fits_in_the_window_its_signature_asks_for() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let mut dead = Vec::new();
    for (offset, pattern, sig) in registry.registrations() {
        let end = offset as usize + pattern.len();
        let window = 512.max(sig.header_window());
        if end > window {
            dead.push(format!(
                "{} ({} bytes at {offset:#x}, shown {window})",
                sig.name(),
                pattern.len()
            ));
        }
    }
    assert!(
        dead.is_empty(),
        "registrations that can never match, because their signature is not shown \
         that far (declare `header_window`): {dead:?}"
    );
    assert!(registry.max_header_window() >= 0xc078);
}

// ---- short carves, unread bytes, stops past the end ------------------------

/// A truncated Clip Studio file ends at the end of the source before the size
/// its header declares: it is not recorded as a file, but it is reported.
#[test]
fn a_truncated_clip_file_is_reported_not_silently_dropped() {
    let mut data = b"CSFCHUNK".to_vec();
    data.extend_from_slice(&0x10_0000u64.to_be_bytes()); // declares 1 MiB
    data.resize(3000, 0x41); // but the source ends at 3000 bytes
    let result = scan_all(data);
    assert!(result
        .files
        .iter()
        .all(|f| f.signature_name != "Clip Studio Paint"));
    let dropped = result
        .below_minimum
        .iter()
        .find(|f| f.signature_name == "Clip Studio Paint")
        .expect("the truncated carve is reported");
    assert_eq!((dropped.offset, dropped.size), (0, 3000));
    assert_eq!(dropped.validated, Some(false));
}

/// The same for an Adobe brush file whose first record declares more than the
/// source holds.
#[test]
fn a_truncated_abr_file_is_reported_not_silently_dropped() {
    // Two bytes of version prefix, then the magic 00 02 "8BIMsamp" 00 at offset 2.
    let mut data = vec![
        0u8, 1, 0, 2, b'8', b'B', b'I', b'M', b's', b'a', b'm', b'p', 0,
    ];
    data.resize(12, 0);
    data.extend_from_slice(&0x10_0000u32.to_be_bytes());
    data.resize(2000, 0x41);
    let result = scan_all(data);
    assert!(result.files.iter().all(|f| f.signature_name != "ABR"));
    assert!(result
        .below_minimum
        .iter()
        .any(|f| f.signature_name == "ABR" && f.size == 2000));
}

/// A minimum size no carve can reach (it exceeds the signature's cap) is
/// reported too, rather than the file being unrecordable with nothing said.
#[test]
fn a_carve_below_an_unreachable_minimum_is_reported() {
    struct Greedy;
    impl FileSignature for Greedy {
        fn name(&self) -> &str {
            "Greedy"
        }
        fn extensions(&self) -> &[&str] {
            &["gr"]
        }
        fn header_check(&self, buf: &[u8], _o: usize) -> Option<RecoveryInit> {
            buf.starts_with(&[0xAA, 0xBB]).then(|| RecoveryInit {
                min_filesize: 1 << 30,
                extension: "gr".to_string(),
                calculated_file_size: None,
            })
        }
        fn data_check(&self, _b: &[u8], _r: &mut FileRecovery) -> DataCheckResult {
            DataCheckResult::Continue
        }
        fn file_check(&self, _d: &[u8], _r: &mut FileRecovery) {}
        fn max_file_size(&self) -> u64 {
            4096
        }
    }
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(Greedy));
    let mut data = vec![0xAA, 0xBB];
    data.resize(10_000, 0x41);
    let src = Mem(data);
    let result =
        CarvingEngine::new(Arc::new(registry)).scan_with_progress(&src, src.size(), None, None);
    assert!(result.files.is_empty());
    assert_eq!(result.below_minimum.len(), 1);
    assert_eq!(result.below_minimum[0].size, 4096);
}

/// A signature that never finds an end, and one that stops a few bytes past its
/// footer, for the tests below.
struct NeverEnds;
impl FileSignature for NeverEnds {
    fn name(&self) -> &str {
        "NeverEnds"
    }
    fn extensions(&self) -> &[&str] {
        &["ne"]
    }
    fn header_check(&self, buf: &[u8], _o: usize) -> Option<RecoveryInit> {
        buf.starts_with(&[0xAA, 0xBB]).then(|| RecoveryInit {
            min_filesize: 4,
            extension: "ne".to_string(),
            calculated_file_size: None,
        })
    }
    fn data_check(&self, _b: &[u8], _r: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }
    fn file_check(&self, _d: &[u8], _r: &mut FileRecovery) {}
    fn max_file_size(&self) -> u64 {
        1 << 20
    }
}

struct FailsFrom {
    data: Vec<u8>,
    fail_from: usize,
}
impl CarvingDataSource for FailsFrom {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = offset as usize;
        if off >= self.fail_from {
            return Err(io::Error::other("unreadable region"));
        }
        let n = buf
            .len()
            .min(self.data.len() - off)
            .min(self.fail_from - off);
        buf[..n].copy_from_slice(&self.data[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// A read that fails mid-source leaves the rest unexamined: the running carve
/// claims what was read, not the whole source.
#[test]
fn a_carve_never_claims_bytes_past_a_failed_read() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(NeverEnds));
    let mut data = vec![0xAA, 0xBB];
    data.resize(8192, 0x41);
    let src = FailsFrom {
        data,
        fail_from: 1024 + 100, // fails part-way into the third block
    };
    let result =
        CarvingEngine::new(Arc::new(registry)).scan_with_progress(&src, src.size(), None, None);
    assert!(result.bytes_scanned < src.size());
    let carve = &result.files[0];
    assert!(
        carve.size <= 1024 + 100,
        "the carve claims {} bytes but only {} were readable",
        carve.size,
        1024 + 100
    );
    assert_eq!(carve.validated, Some(false));
}

/// A stop that a trailing allowance puts past the end of the source is clamped
/// to the source and reported as not validated.
#[test]
fn a_stop_past_the_end_of_the_source_is_clamped() {
    struct StopsLong;
    impl FileSignature for StopsLong {
        fn name(&self) -> &str {
            "StopsLong"
        }
        fn extensions(&self) -> &[&str] {
            &["sl"]
        }
        fn header_check(&self, buf: &[u8], _o: usize) -> Option<RecoveryInit> {
            buf.starts_with(&[0xAA, 0xBB]).then(|| RecoveryInit {
                min_filesize: 4,
                extension: "sl".to_string(),
                calculated_file_size: None,
            })
        }
        fn data_check(&self, buf: &[u8], r: &mut FileRecovery) -> DataCheckResult {
            match buf.windows(2).position(|w| w == [0xCC, 0xDD]) {
                // The footer and seven bytes the format keeps after it.
                Some(i) => DataCheckResult::Stop(r.file_size + i as u64 + 2 + 7),
                None => DataCheckResult::Continue,
            }
        }
        fn file_check(&self, _d: &[u8], _r: &mut FileRecovery) {}
        fn max_file_size(&self) -> u64 {
            1 << 20
        }
    }
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(StopsLong));
    let mut data = vec![0xAA, 0xBB];
    data.resize(100, 0x41);
    data.extend_from_slice(&[0xCC, 0xDD, 1, 2, 3]); // only 3 of the 7 bytes exist
    let src = Mem(data);
    let size = src.size();
    let files = CarvingEngine::new(Arc::new(registry)).scan(&src, size);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].size, size, "clamped to the end of the source");
    assert_eq!(files[0].validated, Some(false));
}
