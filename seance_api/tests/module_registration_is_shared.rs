//! LIVE-005: the module set must be registered in exactly one place.
//!
//! `seance` and `seance_api` both run an orchestrator over evidence. Each used
//! to enumerate the ~50-100 forensic modules by hand in its own `main.rs`, and
//! nothing anywhere compared the two lists. They drifted, and the drift was
//! invisible: a module absent from one binary produces no error, no warning and
//! no failed test — just an ingest that examined less than the examiner
//! believes, which is indistinguishable from evidence that held nothing.
//!
//! The worst of it was the memory tier. A RAM capture ingested through the API
//! server was stored and then analysed by nothing at all: every stage reported
//! `did_not_run`, forever. Seven filesystem readers, both volume decryptors and
//! every messaging parser were missing the same way.
//!
//! These tests hold the structure that makes it impossible to recur:
//! one list, one registrar, both binaries.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use seance_api::modules::{build_module_set, register_all_modules, ModuleSetOptions};
use seance_core::module::ForensicsModule;
use seance_core::orchestrator::Orchestrator;

/// The workspace root, derived from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("seance_api sits directly under the workspace root")
        .to_path_buf()
}

/// Read a workspace file, failing the test if it cannot be read.
///
/// Fails closed on purpose: "the source could not be read" must never pass as
/// "the source contains no hand-written registration".
fn read_workspace_file(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {} to audit it: {e}", path.display()))
}

/// Every binary entry point that drives an orchestrator.
const BINARY_MAINS: &[&str] = &["seance_api/src/main.rs", "seance_cli/src/main.rs"];

/// Neither binary may register modules itself. A second hand-written list is
/// exactly the defect this whole arrangement exists to prevent, and it is
/// silent, so it has to be caught here rather than in review.
#[test]
fn no_binary_registers_modules_of_its_own() {
    for relative in BINARY_MAINS {
        let source = read_workspace_file(relative);
        assert!(
            !source.contains("register_module("),
            "{relative} calls Orchestrator::register_module directly. The module set is built \
             and registered in seance_api::modules; a second list here is invisible when it \
             drifts, which is how the API server came to run no memory analysis at all."
        );
    }
}

/// ...and both must call the shared registrar, so "no list of its own" cannot
/// be satisfied by registering nothing.
#[test]
fn both_binaries_call_the_shared_registrar() {
    for relative in BINARY_MAINS {
        let source = read_workspace_file(relative);
        assert!(
            source.contains("register_all_modules("),
            "{relative} never calls seance_api::modules::register_all_modules, so the \
             orchestrator it starts has no forensic modules and every ingest through it would \
             produce an empty case with no error."
        );
    }
}

/// Build the set the product actually builds, on a real orchestrator.
fn built_module_ids() -> Vec<String> {
    let index = tempfile::tempdir().expect("temp dir for the search index");
    let search_service = Arc::new(
        seance_search::SearchService::new(index.path()).expect("search service for the test"),
    );
    let orchestrator = Orchestrator::new(None, 8);
    let modules: Vec<Arc<dyn ForensicsModule>> =
        build_module_set(&orchestrator, ModuleSetOptions::new(search_service))
            .expect("the module set must build with no YARA rules named");
    modules.iter().map(|m| m.id().to_string()).collect()
}

/// The modules whose absence from the API server was the live defect, plus one
/// from each family that went with them. Named individually because the count
/// alone would not have caught it: the API server's list was 51 entries long
/// and still had no memory tier.
#[test]
fn the_shared_set_contains_the_modules_the_api_server_was_missing() {
    let ids = built_module_ids();
    let required = [
        // The memory tier. Its absence meant a capture was ingested and
        // examined by nothing, with every stage reporting `did_not_run`.
        "memory",
        // Filesystem readers: without these an image with one of these volumes
        // produced a partition and no files.
        "apfs",
        "fat",
        "xfs",
        "btrfs",
        "hfs",
        "iso9660",
        // The UDF half of a bridge disc (every Windows install ISO) holds the
        // files; the ISO 9660 half may hold only a README.
        "filesystem.udf",
        "f2fs",
        // Volume decryptors.
        "luks",
        "bitlocker",
        // Operating-system artifact readers.
        "utmp",
        "asep",
        "fsevents",
        "thumbcache",
        // A path-gated parser: it produces nothing for the overwhelming
        // majority of files, so an unregistered one looks exactly like a case
        // whose custodian never pinned a clipboard item.
        "clipboard",
        // Messaging and app parsers.
        "signal",
        "telegram",
        "instagram",
    ];
    for needle in required {
        assert!(
            ids.iter().any(|id| id.contains(needle)),
            "no module whose id contains {needle:?} is in the shared set. Registered ids: {ids:?}"
        );
    }
}

/// Two modules sharing an id is silent data loss: `Orchestrator::register_module`
/// inserts into `module_lookup` by id, so the second replaces the first in the
/// ad-hoc registry and in the module list the UI shows.
#[test]
fn module_ids_are_unique() {
    let ids = built_module_ids();
    let mut seen = std::collections::HashSet::new();
    let duplicates: Vec<&String> = ids.iter().filter(|id| !seen.insert(*id)).collect();
    assert!(
        duplicates.is_empty(),
        "duplicate module ids would silently replace each other in the orchestrator's \
         lookup: {duplicates:?}"
    );
}

/// The set is not merely built — every module in it reaches the orchestrator.
/// A registrar that built a hundred modules and registered none would satisfy
/// every other test here and analyse nothing.
#[test]
fn every_built_module_reaches_the_orchestrator() {
    let index = tempfile::tempdir().expect("temp dir for the search index");
    let search_service = Arc::new(
        seance_search::SearchService::new(index.path()).expect("search service for the test"),
    );
    let mut orchestrator = Orchestrator::new(None, 8);
    let registered = register_all_modules(&mut orchestrator, ModuleSetOptions::new(search_service))
        .expect("registration must succeed with no YARA rules named");

    let in_orchestrator: std::collections::HashSet<String> = orchestrator
        .module_info_list()
        .into_iter()
        .map(|info| info.id)
        .collect();

    assert_eq!(
        registered,
        in_orchestrator.len(),
        "register_all_modules reported {registered} modules but the orchestrator holds \
         {}; a module that was built and not registered analyses nothing.",
        in_orchestrator.len()
    );
    assert!(
        registered > 50,
        "only {registered} modules were registered; the product set is far larger, so \
         something is filtering the list"
    );
}

/// A rule set that was named and will not load is an error, not an absence. If
/// this returned Ok the run would continue with no scanner, and "YARA found
/// nothing" would be indistinguishable from "no rules were loaded".
#[test]
fn a_named_yara_rule_set_that_cannot_load_fails_the_run() {
    let index = tempfile::tempdir().expect("temp dir for the search index");
    let search_service = Arc::new(
        seance_search::SearchService::new(index.path()).expect("search service for the test"),
    );
    let orchestrator = Orchestrator::new(None, 8);

    let mut options = ModuleSetOptions::new(search_service);
    options.yara_rules = Some(workspace_root().join("no-such-rules-directory"));

    // Matched rather than `expect_err`: that would need `Debug` on the Ok type
    // to render it, and the module set is a vec of `dyn ForensicsModule`.
    let err = match build_module_set(&orchestrator, options) {
        Ok(_) => panic!("a rule path that does not exist must end the run"),
        Err(err) => err,
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("no-such-rules-directory"),
        "the failure must name the rule path the operator gave: {rendered}"
    );
}

/// A memory regular expression that was named and will not compile is an
/// error, for the same reason a rule set is: the operator asked for *this*
/// pattern by writing it, and a run that searched for nothing must not be
/// indistinguishable from one that searched and found nothing.
#[test]
fn a_named_memory_regex_that_cannot_compile_fails_the_run() {
    let index = tempfile::tempdir().expect("temp dir for the search index");
    let search_service = Arc::new(
        seance_search::SearchService::new(index.path()).expect("search service for the test"),
    );
    let orchestrator = Orchestrator::new(None, 8);

    let mut options = ModuleSetOptions::new(search_service);
    // An unclosed group: invalid in any regex dialect.
    options.memory_regex = Some("FORENSIC-W1[0-9".to_string());

    let err = match build_module_set(&orchestrator, options) {
        Ok(_) => panic!("a pattern that does not compile must end the run"),
        Err(err) => err,
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("FORENSIC-W1[0-9"),
        "the failure must name the pattern the operator gave: {rendered}"
    );
    assert!(
        rendered.contains("SEANCE_MEMORY_REGEX"),
        "and the variable it came from: {rendered}"
    );
}

/// A named pattern registers **exactly one** extra module: the image-level
/// scan, which is the only route for a capture with no page tables. The
/// per-process route rides on the Windows analysis module that is already in
/// the list, so it adds none of its own.
///
/// And with nothing named, the image scan is **not registered at all** — a
/// module that is registered, reports success and searches for nothing reads
/// to an examiner as "searched, nothing found".
#[test]
fn a_memory_regex_registers_exactly_the_image_scan() {
    let index = tempfile::tempdir().expect("temp dir for the search index");
    let search_service = Arc::new(
        seance_search::SearchService::new(index.path()).expect("search service for the test"),
    );
    let orchestrator = Orchestrator::new(None, 8);

    let without = build_module_set(
        &orchestrator,
        ModuleSetOptions::new(Arc::clone(&search_service)),
    )
    .expect("the default set builds");
    assert!(
        !without
            .iter()
            .any(|m| m.id() == "plugin.memory.pattern_scan"),
        "with no pattern named the image scan must not be in the list"
    );

    let mut options = ModuleSetOptions::new(search_service);
    options.memory_regex = Some("FORENSIC-W1[0-9]".to_string());
    let with = build_module_set(&orchestrator, options).expect("a valid pattern builds");

    assert_eq!(
        with.len(),
        without.len() + 1,
        "one module for the image scan, and nothing else"
    );
    assert_eq!(
        with.iter()
            .filter(|m| m.id() == "plugin.memory.pattern_scan")
            .count(),
        1
    );
}
