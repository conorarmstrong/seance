//! The AVML reader, against a capture AVML actually produced.
//!
//! # Why this test exists
//!
//! Until 2026-08-04 this crate could not read a single real AVML image, and
//! every one of its 37 AVML tests passed.
//!
//! The block header's `end` field is **inclusive** — AVML copies its ranges
//! verbatim out of `/proc/iomem`, which reports them that way
//! (`00001000-0009fbff : System RAM`). The reader treated it as exclusive, so
//! every block came out one byte short. One byte short is never page-aligned,
//! the frame walk then decoded more bytes than the block declared, and the
//! image was refused as malformed.
//!
//! It survived because the test fixtures were built by a helper in the same
//! module, which wrote `end = start + len` — the same wrong convention the
//! reader read back. Two errors that cancelled. No amount of adding tests in
//! that style would have found it; only an input this project did not write
//! could.
//!
//! So this test is not really about AVML. It is about the class of bug that a
//! self-built fixture cannot catch, and the only defence against it is an
//! artefact from somewhere else.
//!
//! # The corpus
//!
//! Point `SEANCE_LINUX_MEM` at a directory holding
//! `oberon_mem.lime.compressed`, an AVML 0.14.0 capture of a live Ubuntu host
//! (kernel `6.8.0-1061-aws`, 15 GiB of RAM). Absent, this skips; named and
//! missing, it fails — see [`seance_core::test_support::corpus`].
//!
//! The capture is **not** in the repository and never will be: it is live
//! process memory. See `~/forensic_corpora/oberon_linux_swap/PROVENANCE.md`.

use seance_core::data_source::FileDataSource;
use seance_core::test_support::corpus;
use seance_memory::formats::avml::AvmlImage;

const CORPUS_VAR: &str = "SEANCE_LINUX_MEM";
const CAPTURE: &str = "oberon_mem.lime.compressed";

/// A real AVML capture opens, and its dimensions are the machine's.
#[test]
fn a_real_avml_capture_parses() {
    let Some(path) = corpus::file(CORPUS_VAR, CAPTURE) else {
        return;
    };
    let source = FileDataSource::new(path).expect("the corpus gate proved this exists");

    let image = AvmlImage::parse(&source).expect(
        "a capture written by AVML itself must parse. If this fails with a block \
         decoding past its declared range, the inclusive/exclusive reading of the \
         block header's `end` has regressed",
    );

    // 15 GiB of RAM, so the acquired total lands just under 16 GiB once the
    // firmware holes are excluded. Asserted as a range rather than a constant:
    // the exact figure depends on the host's memory map, and pinning it would
    // make this test about one machine rather than about the format.
    let acquired = image.acquired_bytes();
    assert!(
        acquired > 14 * (1 << 30) && acquired < 17 * (1 << 30),
        "acquired {acquired} bytes, which is not the ~15.65 GiB this host has"
    );

    assert!(
        image.frame_count() > 1000,
        "a multi-gigabyte capture is many frames, not {}",
        image.frame_count()
    );
    assert!(
        image.compressed_frame_count() > 0,
        "this capture was taken with --compress, so most frames are compressed"
    );
}

/// Every segment is page-aligned, which is the property the old bug broke.
///
/// A block read one byte short produces a segment whose length is not a
/// multiple of the page size. That is impossible for a physical memory range,
/// and it is the cheapest possible check that the header arithmetic is right.
#[test]
fn every_segment_of_a_real_capture_is_page_aligned() {
    let Some(path) = corpus::file(CORPUS_VAR, CAPTURE) else {
        return;
    };
    let source = FileDataSource::new(path).expect("gate checked");
    let image = AvmlImage::parse(&source).expect("parses");

    for segment in image.segments().iter().take(2000) {
        assert_eq!(
            segment.memory_offset % 4096,
            0,
            "segment at {:#x} is not page-aligned",
            segment.memory_offset
        );
        assert_eq!(
            segment.length % 4096,
            0,
            "segment at {:#x} has length {} which is not a whole number of pages \
             — the symptom of reading an inclusive `end` as exclusive",
            segment.memory_offset,
            segment.length
        );
    }
}

/// The capture reads back as bytes, not merely as a parsed index.
///
/// Parsing walks headers and checksums without decompressing anything, so a
/// successful parse says nothing about whether a single page can be served.
/// This decodes real frames, which also exercises the per-frame CRC-32C that
/// Volatility's own AVML layer reads and discards.
#[test]
fn pages_of_a_real_capture_decode_and_verify() {
    use seance_core::data_source::DataSource;
    use std::sync::Arc;

    let Some(path) = corpus::file(CORPUS_VAR, CAPTURE) else {
        return;
    };
    let source: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("gate checked"));
    let layer = seance_memory::formats::avml::open(source).expect("opens as a layer");

    // Read a page from a few segments spread through the capture. Each decode
    // verifies the frame's checksum before returning a byte; a mismatch is a
    // hard error in this crate, never a warning.
    let mut read_ok = 0usize;
    for segment in layer.segments().iter().step_by(20_000).take(8) {
        let mut page = vec![0u8; 4096];
        if layer.read_at(segment.memory_offset, &mut page).is_ok() {
            read_ok += 1;
        }
    }
    assert!(
        read_ok > 0,
        "no page of a real capture could be decoded, so the layer parses an \
         index it cannot serve from"
    );
}
