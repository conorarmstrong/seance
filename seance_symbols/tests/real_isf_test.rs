//! Known-answer tests against a real, production ISF file.
//!
//! Hand-built fixtures prove the parser handles the shapes we thought of. This
//! file proves it handles the shape Microsoft and the Volatility Foundation
//! actually ship: 558 user types, 10,390 symbols, nested type descriptors and
//! all. The offsets asserted below are the offsets every Windows XP process
//! listing in the world depends on, so if they drift, the failure is here and
//! not three layers up in a plugin where it would look like a plausible answer.
//!
//! The ISF is fetched by Volatility 3 into `reference/volatility3/` and is not
//! committed, so these tests skip when it is absent rather than failing a clean
//! checkout. Regenerate it with:
//!
//! ```text
//! cd reference/volatility3
//! .venv/bin/python vol.py -q -f <xp image> windows.info
//! ```
//!
//! Expected values are recorded in `seance_memory/tests/KNOWN_ANSWERS.md`.

use std::path::PathBuf;

use seance_symbols::{AdmissionState, CompileOptions, DecompressLimits, SymbolTable};

/// The ISF Volatility fetches for the Windows XP SP2 reference image.
const ISF_RELATIVE: &str = "reference/volatility3/volatility3/symbols/windows/\
                            ntoskrnl.pdb/32962337F0F646388B39535CD8DD70E8-2.json.xz";

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/seance_symbols.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has a parent")
        .to_path_buf()
}

/// Compile the real ISF, or return `None` when it has not been fetched.
fn real_table() -> Option<SymbolTable> {
    let path = workspace_root().join(ISF_RELATIVE);
    if !path.exists() {
        eprintln!("skipping: {} not present", path.display());
        return None;
    }
    let table = SymbolTable::compile_path(
        &path,
        &DecompressLimits::default(),
        &CompileOptions::default(),
    )
    .expect("the shipped ISF must compile");
    Some(table)
}

#[test]
fn a_production_isf_compiles_and_is_admitted() {
    let Some(table) = real_table() else { return };

    // A real, unmodified vendor ISF must not be rejected. If it is, a gate is
    // too strict, and being too strict here means refusing to analyse genuine
    // evidence.
    assert_ne!(
        table.state(),
        AdmissionState::Rejected,
        "the shipped ISF was rejected: {:?}",
        table.admission()
    );
}

#[test]
fn the_production_isf_has_the_counts_volatility_reports() {
    let Some(table) = real_table() else { return };

    assert!(!table.entries().is_empty(), "types were compiled");
    assert_eq!(
        table.symbols().len(),
        10_390,
        "symbol count drifted from the recorded known answer"
    );
    assert_eq!(
        table.pointer_size(),
        4,
        "the XP kernel is 32-bit, so pointers are four bytes"
    );
}

#[test]
fn eprocess_member_offsets_match_the_known_answers() {
    let Some(table) = real_table() else { return };

    // These five are the load-bearing offsets for pslist, psscan and pstree.
    // Every one of them is asserted against the value Volatility 3 reads from
    // the same file, not against something derived from our own parser.
    let expected: &[(&str, u64)] = &[
        ("Pcb", 0),
        ("UniqueProcessId", 132),
        ("ActiveProcessLinks", 136),
        ("InheritedFromUniqueProcessId", 332),
        ("ImageFileName", 372),
    ];

    for (member, offset) in expected {
        let got = table
            .member_offset("_EPROCESS", member)
            .unwrap_or_else(|e| panic!("_EPROCESS.{member} must resolve: {e}"));
        assert_eq!(
            got, *offset,
            "_EPROCESS.{member} offset is wrong; every process listing built on \
             it would be confidently wrong too"
        );
    }
}

#[test]
fn eprocess_is_the_size_the_vendor_declares() {
    let Some(table) = real_table() else { return };

    let agg = table
        .aggregate("_EPROCESS")
        .expect("_EPROCESS must be present in a kernel ISF");
    assert_eq!(agg.size, 608, "_EPROCESS size drifted");
}

#[test]
fn a_member_this_build_does_not_have_is_an_error_not_zero() {
    let Some(table) = real_table() else { return };

    // The single most dangerous failure mode in memory forensics: silently
    // returning offset 0 for a member that does not exist, which yields a
    // plausible value read from the wrong place.
    let err = table.member_offset("_EPROCESS", "NoSuchMemberExistsAnywhere");
    assert!(
        err.is_err(),
        "a missing member returned {:?} instead of an error",
        err.ok()
    );
}

#[test]
fn a_type_this_build_does_not_have_is_an_error_not_a_default() {
    let Some(table) = real_table() else { return };

    assert!(
        table.aggregate("_NOT_A_REAL_KERNEL_STRUCT").is_err(),
        "an unknown type must not resolve to a default"
    );
    assert!(!table.has_type("_NOT_A_REAL_KERNEL_STRUCT"));
}

#[test]
fn provenance_records_which_file_produced_the_table() {
    let Some(table) = real_table() else { return };

    // A finding in a report has to be traceable to the exact symbol file that
    // produced it. An empty or placeholder hash makes that impossible.
    let prov = table.provenance();
    let json = prov.to_json().to_string();
    assert!(
        json.contains("sha256") || json.contains("hash"),
        "provenance carries no hash: {json}"
    );
}

#[test]
fn well_known_kernel_structs_are_all_present() {
    let Some(table) = real_table() else { return };

    // These are the types the Windows plugin tier walks. A table missing any
    // of them cannot support the Volatility plugins, and it is
    // better to learn that here than at analysis time.
    for name in [
        "_EPROCESS",
        "_KPROCESS",
        "_LIST_ENTRY",
        "_UNICODE_STRING",
        "_PEB",
        "_MMVAD",
        "_OBJECT_HEADER",
        "_CMHIVE",
        "_ETHREAD",
        "_DRIVER_OBJECT",
    ] {
        assert!(
            table.has_type(name),
            "{name} missing from a kernel ISF; the plugin tier needs it"
        );
    }
}

#[test]
fn list_entry_is_two_pointers_wide_on_this_build() {
    let Some(table) = real_table() else { return };

    let agg = table.aggregate("_LIST_ENTRY").expect("_LIST_ENTRY present");
    assert_eq!(
        agg.size,
        2 * table.pointer_size(),
        "_LIST_ENTRY must be Flink+Blink; the list walker's stride depends on it"
    );
    assert_eq!(table.member_offset("_LIST_ENTRY", "Flink").unwrap(), 0);
    assert_eq!(
        table.member_offset("_LIST_ENTRY", "Blink").unwrap(),
        table.pointer_size()
    );
}
