//! The Linux swap header reader, against a header written by Linux.
//!
//! # Why a real fixture
//!
//! The unit tests in `formats::linux_swap` build headers with the same offset
//! constants the parser reads them back with, so they prove the two halves
//! agree and nothing more. A transposed field — `last_page` and `nr_badpages`
//! are adjacent `u32`s — would be invisible to every one of them.
//!
//! `fixtures/linux_swap_header_4k.bin` is the first 4096 bytes of a swap file
//! created by `mkswap` on an Ubuntu host, so its field order is the kernel's
//! and not this crate's opinion of it. The values below were read independently
//! by `file(1)`, whose magic database is maintained by someone else entirely:
//!
//! ```text
//! Linux swap file, 4k page size, little endian, version 1,
//! size 4194303 pages, 0 bad pages, no label,
//! UUID=8d45904d-b214-48fe-b777-cfe103a96347
//! ```
//!
//! Agreement between this parser and `file` on the UUID in particular is worth
//! having: it is 16 bytes at a fixed offset, so reading it correctly means the
//! offsets either side of it are right too.
//!
//! # What this fixture cannot show
//!
//! It is a header only, and the file it came from was **entirely zero beyond
//! it** — 16 GiB of never-used swap. So this establishes that Séance identifies
//! and measures a swap area correctly. It establishes nothing about recovering
//! swapped *pages*, which needs an area that was actually used, and nothing
//! about decoding swap entries out of a process's page tables, which needs a
//! Linux memory capture.

use seance_memory::formats::linux_swap::LinuxSwapHeader;

const REAL_HEADER: &[u8] = include_bytes!("fixtures/linux_swap_header_4k.bin");

/// Every field, against the values `file(1)` reported for the same bytes.
#[test]
fn the_real_header_parses_to_the_values_an_independent_tool_reported() {
    let parsed = LinuxSwapHeader::parse(REAL_HEADER, None).expect("this is a real swap header");

    assert_eq!(parsed.page_size, 4096, "file(1): 4k page size");
    assert_eq!(parsed.version, 1, "file(1): version 1");
    assert_eq!(parsed.last_page, 4_194_303, "file(1): size 4194303 pages");
    assert_eq!(parsed.nr_badpages, 0, "file(1): 0 bad pages");
    assert_eq!(parsed.label, None, "file(1): no label");
    assert_eq!(
        parsed.uuid_string().as_deref(),
        Some("8d45904d-b214-48fe-b777-cfe103a96347"),
        "the UUID is what ties this area to the host it came from"
    );
}

/// The area's declared span matches the 16 GiB the file actually occupied.
#[test]
fn the_declared_span_matches_the_file_it_came_from() {
    let parsed = LinuxSwapHeader::parse(REAL_HEADER, None).unwrap();
    assert_eq!(
        parsed.total_bytes(),
        16 * 1024 * 1024 * 1024,
        "4194303 usable pages plus the header page, at 4 KiB each"
    );
}

/// Page offsets computed from the real header land where they should.
#[test]
fn page_offsets_from_the_real_header_are_page_aligned_and_bounded() {
    let parsed = LinuxSwapHeader::parse(REAL_HEADER, None).unwrap();

    assert_eq!(parsed.page_offset(0), None, "page 0 is the header itself");
    assert_eq!(parsed.page_offset(1), Some(4096));
    assert_eq!(parsed.page_offset(4_194_303), Some(4_194_303 * 4096));
    assert_eq!(
        parsed.page_offset(4_194_304),
        None,
        "one past the last page must not resolve"
    );
}

/// Passing the wrong page size is refused rather than silently mis-sized.
///
/// The magic sits at `page_size - 10`, so a caller who insists on 64 KiB for a
/// 4 KiB area finds nothing there — which is the intended outcome. Accepting it
/// would multiply every subsequent page offset by sixteen.
#[test]
fn insisting_on_the_wrong_page_size_finds_no_magic() {
    assert!(
        LinuxSwapHeader::parse(REAL_HEADER, Some(65536)).is_err(),
        "a 4 KiB area must not parse as a 64 KiB one"
    );
    assert!(LinuxSwapHeader::parse(REAL_HEADER, Some(4096)).is_ok());
}
