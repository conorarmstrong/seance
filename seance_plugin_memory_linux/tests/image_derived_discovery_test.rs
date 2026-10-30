//! Profiling a Linux capture with no symbol file for it.
//!
//! # What this closes
//!
//! Until now a Linux memory image could only be analysed if the lab held an ISF
//! matched to its kernel. For a custom build, an appliance, or anything old
//! enough that nobody publishes symbols, none exists and the analysis stopped.
//! These exercise the path that does not stop: layouts from the kernel's own
//! BTF, addresses from its own kallsyms, both read out of the image.
//!
//! # What must be true, and what must not
//!
//! Recovering the symbols is the easy half. The half that matters is that a
//! result obtained this way is never passed off as one obtained the usual way:
//!
//! - the layout-agreement gate must **not** run, because it would compare the
//!   image's BTF against a table built from that same BTF, pass every time, and
//!   record a corroboration that never happened;
//! - the profile must say where the layouts came from, in terms a report can
//!   print and an examiner can be cross-examined on;
//! - a lab that refuses image-derived symbols must get the old failure.
//!
//! # Corpus
//!
//! `SEANCE_LINUX_MEM` must name a directory holding
//! `oberon_mem.lime.compressed`. Absent, these skip; named and missing, they
//! fail. The symbol directory is deliberately empty — the point is an image
//! nobody has symbols for.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::test_support::corpus;
use seance_memory::layer::MemoryLayer;
use seance_plugin_memory_linux::discovery::{self, DiscoveryError, DiscoveryOptions};
use seance_plugin_memory_linux::image_symbols::ImageDerivedSymbols;
use seance_plugin_memory_linux::profile::{LinuxProfile, SymbolOrigin};
use std::sync::Arc;

const CORPUS_VAR: &str = "SEANCE_LINUX_MEM";
const CAPTURE: &str = "oberon_mem.lime.compressed";

/// The capture, opened as a physical memory layer.
fn capture() -> Option<Arc<dyn MemoryLayer>> {
    let path = corpus::file(CORPUS_VAR, CAPTURE)?;
    let source: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("gate checked"));
    Some(Arc::new(
        seance_memory::formats::avml::open(source).expect("the capture opens"),
    ))
}

/// Discovery is expensive — a full sweep of a 15 GiB image, twice over. One
/// result serves every test that needs a successful profile.
fn profiled() -> Option<&'static LinuxProfile> {
    static ONCE: std::sync::OnceLock<Option<LinuxProfile>> = std::sync::OnceLock::new();
    corpus::file(CORPUS_VAR, CAPTURE)?;
    let profile = ONCE
        .get_or_init(|| {
            let physical = capture()?;
            // No symbol directories at all: this is the situation the fallback
            // exists for, not a lab whose store merely lacks this one kernel.
            discovery::discover(physical, &[], &DiscoveryOptions::default()).ok()
        })
        .as_ref();
    assert!(
        profile.is_some(),
        "the capture is present and discovery produced no profile from it. This kernel carries \
         BTF and kallsyms, so the image describes itself and discovery should not need a symbol \
         file"
    );
    profile
}

/// **The point of the whole change.** An image with no symbol file profiles.
#[test]
fn a_capture_with_no_symbol_file_still_profiles() {
    let Some(profile) = profiled() else { return };

    assert!(
        profile.build.banner.starts_with("Linux version "),
        "the banner should have been recovered: {}",
        profile.build.banner
    );
    // The members a Linux memory tier reads. If these do not resolve, the
    // profile is a shell and nothing downstream can use it.
    let size = profile
        .symbols
        .size_of("task_struct")
        .expect("task_struct must have a size");
    for member in ["comm", "pid", "tgid"] {
        let offset = profile
            .symbols
            .member_offset("task_struct", member)
            .unwrap_or_else(|e| panic!("task_struct.{member} did not resolve: {e:?}"));
        assert!(offset < size, "task_struct.{member} is outside the struct");
    }
    profile
        .symbols
        .symbol_address("init_task")
        .expect("init_task must resolve — this is the half BTF alone could never supply");
}

/// The profile says where the layouts came from, and does not claim a file.
#[test]
fn the_profile_states_that_the_symbols_came_out_of_the_image() {
    let Some(profile) = profiled() else { return };

    match &profile.build.symbols_from {
        SymbolOrigin::ImageDerived {
            btf_at,
            kallsyms_at,
            type_count,
            symbol_count,
            sha256,
        } => {
            assert!(*type_count > 5_000, "only {type_count} types");
            assert!(*symbol_count > 10_000, "only {symbol_count} symbols");
            assert_ne!(btf_at, kallsyms_at, "two structures, two offsets");
            assert_eq!(sha256.len(), 64, "a SHA-256 is 64 hex characters");
        }
        SymbolOrigin::SymbolFile { path } => {
            panic!("no symbol directory was searched, yet the profile names the file {path}")
        }
    }

    let json = profile.to_json();
    assert_eq!(json["symbols_origin"], "image_derived");
    assert_eq!(
        json["symbol_file"],
        serde_json::Value::Null,
        "a consumer that only reads `symbol_file` must get null, not a sentence it would print \
         as the path of a file that never existed"
    );
    assert_eq!(
        json["symbols_independently_corroborated"], false,
        "nothing independent corroborated these layouts, and the profile must not imply otherwise"
    );
}

/// **The circularity trap.** The layout-agreement gate must not have run.
///
/// It compares a symbol table against the image's own BTF. For a table built
/// *from* that BTF the comparison is a source against itself: it passes every
/// time, and a passing gate here would tell an examiner the layouts were
/// corroborated when nothing corroborated them. Recording it as not applicable
/// states the fact instead.
#[test]
fn the_layout_agreement_gate_did_not_run_against_symbols_built_from_that_layout() {
    let Some(profile) = profiled() else { return };

    let admission = profile.symbols.admission();
    let json = serde_json::to_string(&admission.to_json()).expect("serialises");
    assert!(
        json.contains("linux_btf_layout_agreement"),
        "the gate must be recorded, not omitted: an absent gate reads as a check nobody thought \
         of, and this one was thought of and deliberately not run"
    );
    assert!(
        json.contains("compare a source with itself"),
        "the recorded outcome must say why the gate did not run. Got: {json}"
    );

    let gate = admission
        .gates
        .iter()
        .find(|g| g.check == "linux_btf_layout_agreement")
        .expect("just proved it is recorded");
    assert!(
        !matches!(gate.outcome, seance_symbols::GateOutcome::Pass),
        "the layout-agreement gate PASSED for a table built from the layouts it checked against. \
         That is a corroboration that did not happen, and it is exactly what this test exists to \
         prevent"
    );
}

/// A lab that refuses image-derived symbols gets the old failure, not a profile.
#[test]
fn a_lab_that_requires_a_symbol_file_gets_a_failure_it_can_act_on() {
    let Some(physical) = capture() else { return };

    let options = DiscoveryOptions {
        image_derived_symbols: ImageDerivedSymbols::Refuse,
        ..DiscoveryOptions::default()
    };
    let outcome = discovery::discover(physical, &[], &options);

    match outcome {
        Err(DiscoveryError::SymbolsNotFound {
            banner, btf_note, ..
        }) => {
            assert!(banner.starts_with("Linux version "));
            assert!(
                btf_note.contains("configured to refuse"),
                "the failure must say the run refused these symbols, not that the image lacks \
                 them — the two send an examiner somewhere completely different. Got: {btf_note}"
            );
        }
        Err(other) => panic!("expected SymbolsNotFound, got {other:?}"),
        Ok(_) => panic!("a refusing policy produced a profile from image-derived symbols"),
    }
}

/// Generation is deterministic, which is what makes the hash worth printing.
///
/// There is no file path to cite, so the report cites a SHA-256 instead. That is
/// only meaningful if a defence expert regenerating the symbols from the same
/// image gets the same bytes. Two runs over the same capture must agree.
#[test]
fn regenerating_the_symbols_from_the_same_image_gives_the_same_hash() {
    let Some(physical) = capture() else { return };

    let first = discovery::discover(Arc::clone(&physical), &[], &DiscoveryOptions::default())
        .expect("the capture describes itself");
    let second = discovery::discover(physical, &[], &DiscoveryOptions::default())
        .expect("the capture describes itself");

    let hash = |profile: &LinuxProfile| match &profile.build.symbols_from {
        SymbolOrigin::ImageDerived { sha256, .. } => sha256.clone(),
        SymbolOrigin::SymbolFile { .. } => panic!("no symbol directory was searched"),
    };
    assert_eq!(
        hash(&first),
        hash(&second),
        "two runs over the same image produced different symbol documents, so the hash in the \
         report identifies nothing a defence expert could reproduce"
    );
}
