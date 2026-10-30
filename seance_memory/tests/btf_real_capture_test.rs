//! BTF extraction, against a kernel's own type information.
//!
//! # What these establish
//!
//! Two things, and the second is the point of the exercise:
//!
//! 1. The parser agrees with a BTF blob that the kernel wrote — not one this
//!    crate assembled from the same constants it reads back with. Twice now a
//!    defect has survived a full test suite because the fixture and the reader
//!    shared a misunderstanding (SQLCipher's HMAC framing, AVML's inclusive
//!    `end`), so any format this project both reads and writes needs at least
//!    one input from somewhere else. See `documentation/TESTING.md`.
//!
//! 2. That blob can be **recovered from a memory capture**, which is what makes
//!    it useful. If the kernel's own type description can be read out of the
//!    evidence, then analysing a Linux image no longer requires locating an ISF
//!    for that exact distribution, version, patch level and configuration — the
//!    layout comes from the same build being analysed, and cannot be another
//!    build's by construction.
//!
//! # Corpus
//!
//! - `SEANCE_LINUX_MEM` — a directory holding `vmlinux.btf`, a copy of
//!   `/sys/kernel/btf/vmlinux` from the host that was captured, and
//!   `oberon_mem.lime.compressed`, the AVML capture of that host.
//!
//! Absent, these skip; named and missing, they fail. Neither file is in the
//! repository: the capture is live process memory, and the BTF is 6 MB.

use seance_core::test_support::corpus;
use seance_memory::btf::Btf;

const CORPUS_VAR: &str = "SEANCE_LINUX_MEM";
const BTF_FILE: &str = "vmlinux.btf";

/// The kernel's own BTF parses, and describes the structures Linux analysis
/// depends on.
#[test]
fn the_kernels_own_btf_parses_and_describes_task_struct() {
    let Some(path) = corpus::file(CORPUS_VAR, BTF_FILE) else {
        return;
    };
    let data = std::fs::read(path).expect("the corpus gate proved this exists");
    let btf = Btf::parse(&data).expect("a blob the kernel wrote must parse");

    // Ubuntu's 6.8 kernel declares a few hundred thousand types. A parse that
    // stopped early would still "succeed", so the count is what catches it.
    assert!(
        btf.type_count() > 50_000,
        "only {} types walked, so the walk desynchronised and stopped early — \
         the usual cause is a kind whose tail length is mis-sized",
        btf.type_count()
    );
    assert!(btf.composite_count() > 5_000);

    // The structures a Linux memory tier actually needs. If BTF can supply
    // these, it can replace an ISF for this capture.
    for required in [
        "task_struct",
        "mm_struct",
        "vm_area_struct",
        "list_head",
        "module",
        "file",
        "dentry",
        "cred",
    ] {
        assert!(
            btf.composite(required).is_some(),
            "the kernel's BTF does not describe {required}, which Linux analysis needs"
        );
    }
}

/// Member offsets come out plausible and self-consistent.
///
/// Exact values are not asserted: they are properties of one build, and pinning
/// them would make this a test about one machine rather than about the parser.
/// What *is* asserted is the invariant that would break if the walk were
/// misaligned — every member must lie within its containing struct.
#[test]
fn every_member_lies_within_its_struct() {
    let Some(path) = corpus::file(CORPUS_VAR, BTF_FILE) else {
        return;
    };
    let data = std::fs::read(path).expect("gate checked");
    let btf = Btf::parse(&data).expect("parses");

    let mut checked = 0usize;
    for name in btf.composite_names().take(4000) {
        let Some(composite) = btf.composite(name) else {
            continue;
        };
        if composite.size == 0 {
            continue; // a forward declaration carries no members
        }
        for member in &composite.members {
            let Some(offset) = member.byte_offset() else {
                continue; // a bitfield, checked by bit offset instead
            };
            // `<=`, not `<`. A flexible array member — `char value[]` as the
            // last field — legally sits exactly at the struct's size, because
            // it contributes none of it. `squashfs_xattr_val` is one:
            // `{ __le32 vsize; char value[]; }`, size 4, `value` at byte 4.
            // Requiring a strict inequality rejects correct C.
            assert!(
                offset <= composite.size as u64,
                "{}.{} sits at byte {} in a struct of {} bytes — past the end, \
                 so the type walk is misaligned",
                composite.name,
                member.name,
                offset,
                composite.size
            );
            checked += 1;
        }
    }
    assert!(checked > 10_000, "only {checked} members checked");
}

/// `task_struct` carries the members the Linux tier reads, at sane offsets.
#[test]
fn task_struct_offsets_are_usable() {
    let Some(path) = corpus::file(CORPUS_VAR, BTF_FILE) else {
        return;
    };
    let data = std::fs::read(path).expect("gate checked");
    let btf = Btf::parse(&data).expect("parses");

    let size = btf
        .type_size("task_struct")
        .expect("task_struct is described");
    assert!(
        (1024..=65536).contains(&size),
        "task_struct is {size} bytes, which is not a plausible size for it"
    );

    // `comm` is the process name — 16 bytes, and the field a process listing is
    // built from. `pid` and `tgid` are what a listing reports.
    for member in ["comm", "pid", "tgid", "mm", "parent"] {
        let offset = btf
            .member_offset("task_struct", member)
            .unwrap_or_else(|| panic!("task_struct.{member} has no byte offset"));
        assert!(
            offset < size,
            "task_struct.{member} at {offset} is outside the {size}-byte struct"
        );
    }
}

/// **The one that matters: BTF is recoverable from the capture itself.**
///
/// The blob checked above came off `/sys/kernel/btf/vmlinux` on a running host.
/// This finds the same information inside the memory image, which is what an
/// examiner actually has. Verified by comparing what the scanner found against
/// the authoritative copy, member for member.
///
/// Skipped when the capture is absent even if the BTF file is present — they
/// are separate artefacts and only the pair proves anything.
#[test]
fn btf_is_recoverable_from_the_memory_capture() {
    use seance_core::data_source::{DataSource, FileDataSource};
    use std::sync::Arc;

    let Some(btf_path) = corpus::file(CORPUS_VAR, BTF_FILE) else {
        return;
    };
    let Some(capture_path) = corpus::file(CORPUS_VAR, "oberon_mem.lime.compressed") else {
        return;
    };

    let authoritative = Btf::parse(&std::fs::read(btf_path).expect("gate checked"))
        .expect("the authoritative copy parses");

    let source: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(capture_path).expect("gate checked"));
    let layer = seance_memory::formats::avml::open(source).expect("the capture opens");

    // The kernel's BTF is one contiguous blob in kernel memory, a few megabytes
    // long. Walk the capture in windows large enough to hold it whole, with an
    // overlap so a blob straddling a boundary is not missed.
    const WINDOW: u64 = 64 * 1024 * 1024;
    const OVERLAP: u64 = 16 * 1024 * 1024;
    // A module's BTF describes a handful of types; only the kernel's describes
    // this many, so the threshold is what distinguishes them.
    const MIN_TYPES: usize = 50_000;

    let mut found: Option<Btf> = None;
    let segments = layer.segments();
    let top = segments
        .iter()
        .map(|s| s.memory_offset + s.length)
        .max()
        .unwrap_or(0);

    let mut at = 0u64;
    let mut buffer = vec![0u8; WINDOW as usize];
    while at < top && found.is_none() {
        let want = WINDOW.min(top - at) as usize;
        if layer.read_at(at, &mut buffer[..want]).is_ok() {
            if let Some((_, btf)) = Btf::find_in(&buffer[..want], MIN_TYPES) {
                found = Some(btf);
            }
        }
        at += WINDOW.saturating_sub(OVERLAP);
    }

    let recovered = found.expect(
        "no kernel BTF found in the capture. The host was built with \
         CONFIG_DEBUG_INFO_BTF=y and /sys/kernel/btf/vmlinux exists, so the blob \
         is resident and this is a failure to locate it",
    );

    // The recovered blob must describe the same kernel as the authoritative
    // copy. Compared by content rather than by hash: the scan may begin at a
    // slightly different point, and what matters is that the answers agree.
    assert!(
        recovered.type_count() > MIN_TYPES,
        "recovered only {} types",
        recovered.type_count()
    );

    let mut compared = 0usize;
    for name in [
        "task_struct",
        "mm_struct",
        "vm_area_struct",
        "list_head",
        "cred",
    ] {
        let (Some(want), Some(got)) = (authoritative.composite(name), recovered.composite(name))
        else {
            panic!("{name} missing from one of the two BTF sources");
        };
        assert_eq!(
            want.size, got.size,
            "{name} is {} bytes in the authoritative BTF and {} in the one \
             recovered from the capture",
            want.size, got.size
        );
        // Compared positionally rather than by name. Real kernel structs carry
        // anonymous members — `vm_area_struct` has two, both with empty names —
        // and a lookup by name returns the first of them for every one, which
        // compares a member against a different member and fails on a
        // difference that is not there. Position also checks that the two
        // sources agree on member *order*, which a name lookup would not.
        assert_eq!(
            want.members.len(),
            got.members.len(),
            "{name} has {} members authoritatively and {} from the capture",
            want.members.len(),
            got.members.len()
        );
        for (i, member) in want.members.iter().enumerate() {
            let recovered_member = &got.members[i];
            let label = if member.name.is_empty() {
                format!("<anonymous #{i}>")
            } else {
                member.name.clone()
            };
            assert_eq!(
                member.name, recovered_member.name,
                "{name} member {i} is `{}` authoritatively and `{}` from the capture",
                member.name, recovered_member.name
            );
            assert_eq!(
                member.bit_offset, recovered_member.bit_offset,
                "{name}.{label} is at bit {} authoritatively and bit {} from the capture",
                member.bit_offset, recovered_member.bit_offset
            );
            compared += 1;
        }
    }
    assert!(
        compared > 50,
        "only {compared} members compared, which is too few to mean anything"
    );
}
