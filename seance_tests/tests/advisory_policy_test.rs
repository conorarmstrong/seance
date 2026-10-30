//! The two dependency-advisory ignore lists must say the same thing.
//!
//! Séance runs two advisory gates over the same lock file: `cargo deny check`
//! (test.yml) reads `deny.toml`, and `cargo audit` (audit.yml, and
//! `scripts/ci-gate.sh`) reads `.cargo/audit.toml`. Each has its own ignore
//! list, written by hand, and the two had drifted: `RUSTSEC-2026-0222`
//! (wasmtime, reached only through yara-x) and `RUSTSEC-2025-0141` (bincode,
//! unmaintained) were triaged in `deny.toml` and never mirrored, so `cargo
//! audit` failed while `cargo deny check` passed — and `RUSTSEC-2024-0436`
//! (`paste`) survived in `.cargo/audit.toml` long after the crate left the tree.
//!
//! Drift in either direction is a real problem, and neither is loud:
//! * an id in `deny.toml` only means a triaged advisory still fails `cargo
//!   audit`, so the gate reads as broken rather than as a decision;
//! * an id in `.cargo/audit.toml` only means an advisory is suppressed with its
//!   reasoning recorded in a file the person reading `deny.toml` never opens.
//!
//! An accepted advisory is one decision, so it belongs in both lists with a
//! justification beside it in both. This test is what makes that true rather
//! than aspirational.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn workspace_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("seance_tests sits directly under the workspace root")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The RUSTSEC ids inside the file's `ignore = [ ... ]` array.
///
/// Scoped to the array rather than the whole file on purpose: both files
/// discuss advisories at length in prose above the list, and an id mentioned in
/// a comment explaining why something is *not* ignored must not be read as an
/// entry.
fn ignored_advisories(contents: &str) -> BTreeSet<String> {
    let after = contents
        .split_once("ignore = [")
        .expect("the file declares an `ignore = [` array")
        .1;
    let body = after
        .split_once("\n]")
        .expect("the `ignore` array is closed by a `]` at the start of a line")
        .0;

    let mut ids = BTreeSet::new();
    for line in body.lines() {
        // Only quoted entries count. A commented-out id is not ignored, and a
        // reason mentioning a neighbouring advisory is not an entry either.
        let code = line.trim();
        if code.starts_with('#') {
            continue;
        }
        if let Some(rest) = code.split_once('"') {
            let id = rest.1.split('"').next().unwrap_or_default();
            if id.starts_with("RUSTSEC-") {
                ids.insert(id.to_string());
            }
        }
    }
    assert!(
        !ids.is_empty(),
        "no advisory ids were read; the file's shape must have changed"
    );
    ids
}

#[test]
fn the_two_advisory_ignore_lists_accept_exactly_the_same_advisories() {
    let deny = ignored_advisories(&workspace_file("deny.toml"));
    let audit = ignored_advisories(&workspace_file(".cargo/audit.toml"));

    let deny_only: Vec<&String> = deny.difference(&audit).collect();
    let audit_only: Vec<&String> = audit.difference(&deny).collect();

    assert!(
        deny_only.is_empty() && audit_only.is_empty(),
        "deny.toml and .cargo/audit.toml disagree about which advisories are accepted.\n  \
         only in deny.toml (so `cargo audit` still fails on them): {deny_only:?}\n  \
         only in .cargo/audit.toml (so the reasoning is invisible to `cargo deny`): {audit_only:?}\n\
         Accepting an advisory is one decision: record it in both files, with the reason in both."
    );
}

/// Every accepted advisory must carry a written reason. The lists are read by
/// whoever inherits the decision, and a bare id tells them nothing about
/// whether it still holds.
#[test]
fn every_accepted_advisory_carries_a_reason() {
    for file in ["deny.toml", ".cargo/audit.toml"] {
        let contents = workspace_file(file);
        let body = contents
            .split_once("ignore = [")
            .expect("the file declares an `ignore = [` array")
            .1
            .split_once("\n]")
            .expect("the `ignore` array is closed by a `]` at the start of a line")
            .0;

        // A reason is either a comment on the lines above the entry or a
        // trailing comment on the entry itself. Both forms are already in use.
        let mut carried_comment = false;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                carried_comment = true;
                continue;
            }
            if let Some(rest) = line.split_once('"') {
                let id = rest.1.split('"').next().unwrap_or_default();
                if id.starts_with("RUSTSEC-") {
                    let trailing = line.split_once('#').is_some();
                    assert!(
                        carried_comment || trailing,
                        "{file}: {id} is accepted with no reason recorded beside it"
                    );
                    carried_comment = false;
                }
            }
        }
    }
}
