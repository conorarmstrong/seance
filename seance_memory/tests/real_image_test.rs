//! End-to-end checks against real acquired memory images.
//!
//! These run only when `SEANCE_MEM_IMAGES` points at a directory holding the
//! reference captures (the images are gigabytes and are not in the repository).
//! Set it to the directory containing `win10.dmp` and `win-xp.img`.
//!
//! Unset, they skip and say so. Set but missing a named image, they FAIL: an
//! operator who pointed this at a corpus believes the comparison ran, and
//! reporting `ok` for a comparison that never happened is the defect this gate
//! exists to prevent. `SEANCE_REQUIRE_CORPUS=1` turns the skip into a failure
//! too, for CI.

use std::sync::Arc;

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::{detect, formats, MemoryImageFormat, MemoryLayer};

/// An image from the corpus, or `None` when the corpus was never provisioned.
/// A named corpus missing this file fails rather than skipping.
fn open_file(name: &str) -> Option<Arc<dyn DataSource>> {
    let path = seance_core::test_support::corpus::file("SEANCE_MEM_IMAGES", name)?;
    Some(Arc::new(FileDataSource::new(path).expect("open image")) as Arc<dyn DataSource>)
}

/// A real Windows x64 crash dump is identified from its header alone and
/// decoded to a usable address space.
///
/// No longer `#[ignore]`d: the `PAGEDU64` decode path has now been exercised
/// against a genuine acquisition. `win10.dmp` is a real Windows 11 26200 kernel
/// crash dump produced by a `MANUALLY_INITIATED_CRASH (0xE2)` bugcheck on the
/// corpus VM (its 383 MiB of stored pages reconstruct a 10 GiB sparse physical
/// space through the run table — proof the run-table geometry, not just the
/// header, is correct). Not in the repo (it is hundreds of MiB); provide it via
/// `SEANCE_MEM_IMAGES`. The test skips when the corpus is not provisioned and
/// FAILS if the corpus is named but this file is missing — it never passes
/// having decoded nothing.
#[test]
fn win10_crash_dump_is_detected_and_decoded() {
    let Some(src) = open_file("win10.dmp") else {
        return;
    };

    assert_eq!(
        detect(src.as_ref()),
        MemoryImageFormat::WindowsCrashDump64,
        "PAGEDU64 must be recognised from the header"
    );

    let layer = formats::crash::open(Arc::clone(&src)).expect("decode the crash dump");

    // The decoded address space is real: it spans more than the file, because a
    // crash dump's run table skips unbacked physical ranges.
    assert!(layer.mapped_len() > 0, "some memory must be mapped");
    assert!(
        !layer.segments().is_empty(),
        "the run table must produce segments"
    );

    // Reading the first mapped byte must work through the decoded view.
    let first = layer.segments()[0];
    let mut buf = [0u8; 64];
    let n = layer
        .read_at(first.memory_offset, &mut buf)
        .expect("read the first mapped page");
    assert_eq!(n, buf.len(), "a fully mapped page reads completely");

    eprintln!(
        "win10.dmp: {} segments, {} mapped bytes, span {}",
        layer.segments().len(),
        layer.mapped_len(),
        layer.size()
    );
}

/// A real Windows small "minidump" (`C:\Windows\Minidump\*.dmp`) carries the
/// `PAGEDU64` magic but a DumpType Séance does not decode (kernel/small/
/// automatic). It must be RECOGNISED as a crash dump yet REFUSED at open with a
/// clear reason — never misdecoded into plausible-but-wrong pages (VOL-MEM-007).
///
/// This validates the documented fail-closed boundary on a genuine acquisition:
/// a `MANUALLY_INITIATED_CRASH` minidump from the corpus VM, provided via
/// `SEANCE_WIN_MINIDUMP`. Full minidump support remains deliberate future work.
#[test]
fn real_windows_minidump_is_recognised_but_refused_not_misdecoded() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_WIN_MINIDUMP") else {
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path).expect("open minidump")) as Arc<dyn DataSource>;

    assert_eq!(
        detect(src.as_ref()),
        MemoryImageFormat::WindowsCrashDump64,
        "the PAGEDU64 magic must still be recognised"
    );

    let err = formats::crash::open(Arc::clone(&src))
        .expect_err("an unsupported dump type must be refused, not decoded");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("dump")
            && (msg.to_lowercase().contains("unsupported")
                || msg.to_lowercase().contains("not")
                || msg.to_lowercase().contains("kernel")
                || msg.to_lowercase().contains("small")),
        "the refusal must name why it declined this dump type, got: {msg}"
    );
    eprintln!("minidump correctly refused: {msg}");
}

/// The refusal above is only half of what the file states. VOL-MEM-007: the
/// minidump's `_DUMP_HEADER` is complete and says which bugcheck stopped the
/// machine, when, on which build and with how many processors — and every one
/// of those fields was being read on the path that maps memory and discarded on
/// the path that refuses, leaving the examiner with "decode failed".
///
/// The expected values are this acquisition's own: a `MANUALLY_INITIATED_CRASH`
/// (`0xE2`) on Windows 11 build 26100. It must still be refused as an address
/// space, which the test asserts alongside the facts — reading a header is not
/// the same as being able to map one.
#[test]
fn real_windows_minidump_publishes_its_bugcheck_while_still_being_refused() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_WIN_MINIDUMP") else {
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path).expect("open minidump")) as Arc<dyn DataSource>;

    assert!(
        formats::crash::open(Arc::clone(&src)).is_err(),
        "a triage dump must stay refused: the facts are added to the refusal, not instead of it"
    );

    let facts = formats::crash::header_facts(src.as_ref())
        .expect("a refused dump still has a readable _DUMP_HEADER");
    assert!(
        !facts.maps_an_address_space(),
        "the facts must state plainly that no memory was mapped"
    );

    assert_eq!(facts.bug_check_code, Some(0xE2), "MANUALLY_INITIATED_CRASH");
    assert_eq!(facts.bug_check_parameters, [Some(0); 4]);
    assert_eq!(facts.minor_version, Some(26100), "the build number");
    assert_eq!(facts.number_processors, Some(8));
    assert_eq!(facts.directory_table_base, Some(0x1a_e000));
    assert_eq!(facts.machine_image_type, Some(0x8664));
    assert!(
        facts.system_time.is_some_and(|t| t > 0),
        "the moment of the crash is a timeline fact this file states"
    );

    let exception = facts.exception.expect("the faulting exception record");
    assert_eq!(exception.code, 0x8000_0003, "STATUS_BREAKPOINT");
    assert_eq!(exception.flags, Some(1));
    assert_eq!(
        exception.parameter_count,
        Some(0),
        "the kernel wrote a count of zero here, which states that the fault carried no \
         parameters — an unwritten count would be absent instead"
    );
    // The faulting instruction is in kernel space on this acquisition. Asserted
    // as a kernel address rather than merely "present" because the failure this
    // guards against is a fill-pattern or unwritten field reaching the record as
    // a number: 0 would read as a NULL dereference, and 0x45474150 as a
    // user-mode address, and neither is a fact this file states.
    assert!(
        exception
            .address
            .is_some_and(|a| a >= 0xFFFF_8000_0000_0000),
        "the ExceptionAddress this dump states, got {:?}",
        exception.address
    );
    assert_eq!(
        facts.context_flags,
        Some(0x0010_000F),
        "CONTEXT_AMD64 with the control, integer, segment and floating-point blocks present"
    );
    assert_eq!(
        facts.machine_image_type,
        Some(0x8664),
        "and ContextFlags is published only because the header names the one machine whose \
         CONTEXT layout this reader pins"
    );

    // Windows stamps the header pages with the repeating word `PAGE` and writes
    // the fields over it, so this dump's `Comment[128]` is literally `PAGE`
    // thirty-two times. It is filler, not a comment, and must not be published.
    assert_eq!(
        facts.comment, None,
        "header fill pattern must never be published as an examiner-facing comment"
    );

    eprintln!(
        "minidump refused, bugcheck {:#x} on build {:?} at FILETIME {:?}",
        facts.bug_check_code.unwrap(),
        facts.minor_version,
        facts.system_time
    );
}

/// The strongest validation available for the derived offsets, and it needs no
/// new ground truth: the corpus holds a triage dump and a kernel-bitmap dump of
/// **the same crash**. One is refused and the other decodes, so every field
/// read here on the refused path is read from a header whose twin is proved
/// correct by a dump that reconstructs into a working address space.
///
/// If `BugCheckParameter1..4` or `Exception` sat anywhere other than where the
/// arithmetic in `Layout` puts them, the two files would disagree.
#[test]
fn the_minidump_and_the_kernel_dump_of_the_same_crash_agree_on_the_bugcheck() {
    let (Some(triage), Some(kernel)) = (
        seance_core::test_support::corpus::path("SEANCE_WIN_MINIDUMP"),
        seance_core::test_support::corpus::path("SEANCE_WIN_CRASHDUMP"),
    ) else {
        return;
    };

    let open = |path| {
        let src: Arc<dyn DataSource> =
            Arc::new(FileDataSource::new(path).expect("open dump")) as Arc<dyn DataSource>;
        formats::crash::header_facts(src.as_ref()).expect("a readable _DUMP_HEADER")
    };
    let triage = open(triage);
    let kernel = open(kernel);

    assert!(
        !triage.maps_an_address_space() && kernel.maps_an_address_space(),
        "the two files must be the refused one and the decoded one, or this proves nothing"
    );

    assert_eq!(triage.bug_check_code, kernel.bug_check_code);
    assert_eq!(triage.bug_check_parameters, kernel.bug_check_parameters);
    assert_eq!(triage.system_time, kernel.system_time);
    assert_eq!(triage.system_up_time, kernel.system_up_time);
    assert_eq!(triage.minor_version, kernel.minor_version);
    assert_eq!(triage.directory_table_base, kernel.directory_table_base);
    assert_eq!(triage.exception, kernel.exception);
    assert_eq!(triage.context_flags, kernel.context_flags);
}

/// The header of the dump that DECODES must be reported exactly as the header
/// of the dump that is refused, field for field.
///
/// A decoded image carries both blocks into one artifact — `crash_dump` from
/// `header_facts` and `layer_meta` from the decode — so a field read through
/// the fill-pattern guard on one path and raw on the other publishes two
/// contradictory values for one offset of one file. On this acquisition the
/// header pages are genuinely stamped with the repeating word `PAGE`, which is
/// what makes it worth asserting here rather than only against a fixture.
#[test]
fn the_decoded_dumps_published_notes_agree_with_its_header_facts() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_WIN_CRASHDUMP") else {
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path).expect("open crash dump")) as Arc<dyn DataSource>;

    let facts = formats::crash::header_facts(src.as_ref())
        .expect("a readable _DUMP_HEADER")
        .to_json();
    let layer = formats::crash::open(Arc::clone(&src)).expect("decode the crash dump");
    let notes = layer.layer_meta().to_json();

    for field in [
        "major_version",
        "minor_version",
        "machine_image_type",
        "number_processors",
        "bug_check_code",
        "directory_table_base",
        "pfn_database",
        "ps_loaded_module_list",
        "ps_active_process_head",
        "kd_debugger_data_block",
        "system_time_filetime",
        "system_up_time_100ns",
        "comment",
        "pae_enabled",
    ] {
        assert_eq!(
            notes["notes"][field], facts[field],
            "{field} must read the same on the decode path as on the facts path: {notes} vs \
             {facts}"
        );
    }

    // And neither block may carry the fill word itself, in any of the shapes an
    // examiner would read as a fact: 0x45474150 as a 32-bit field, or the same
    // word doubled as a 64-bit pointer.
    for block in [&notes, &facts] {
        let text = block.to_string();
        for filler in ["1162297680", "4992030524978970960", "PAGEPAGE"] {
            assert!(
                !text.contains(filler),
                "header fill pattern reached the record as {filler}: {block}"
            );
        }
    }

    eprintln!(
        "decoded dump: build {:?}, {} processors, DTB {:?}",
        notes["notes"]["minor_version"],
        notes["notes"]["number_processors"],
        notes["notes"]["directory_table_base"]
    );
}

/// The XP image is headerless. It must NOT be claimed by detection — that is the
/// safety property that stops every unrecognised file being called memory.
#[test]
fn raw_xp_image_is_not_auto_detected() {
    let Some(src) = open_file("win-xp-laptop.img") else {
        return;
    };
    assert_eq!(
        detect(src.as_ref()),
        MemoryImageFormat::Raw,
        "a headerless image yields Raw, which means 'no detection', not 'is raw memory'"
    );
}
