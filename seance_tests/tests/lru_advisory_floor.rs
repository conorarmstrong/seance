//! Pin the `lru` version floor that RUSTSEC-2026-0253 established.
//!
//! `LruCache::pop()` in `lru` was not panic-safe: if a stored key's `Drop`
//! panicked mid-`pop`, the node was freed from the map but left linked in the
//! LRU list, and the next eviction wrote through the dangling pointer. Fixed in
//! `lru 0.18.2`.
//!
//! Séance's own three caches were on `lru 0.12`, which is under the fix. They
//! are now on `0.18.2`. The residual copy belongs to `tantivy`, which has never
//! published a release permitting `lru >= 0.18` (its highest declared
//! requirement, on tantivy 0.26, is `^0.16.3`), so the vulnerable version stays
//! in the lock until tantivy moves. That residue is accepted with a written
//! justification in `deny.toml` and `.cargo/audit.toml`.
//!
//! The danger of accepting it is that the acceptance is graph-wide: once the
//! advisory is ignored, a new workspace crate can quietly take `lru 0.12` again
//! and no gate says a word. These tests are what says it. They read `Cargo.lock`
//! — the resolved graph, not the declared requirement — so a transitive
//! reintroduction is caught too.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The `lru` release that carries the `pop()` panic-safety fix.
const FIXED_LRU: &str = "0.18.2";

/// No dependant is permitted to hold a pre-0.18.2 `lru`.
///
/// `tantivy` was the last one, pinned at `^0.12.0` in 0.22.1. It left when
/// `seance_search` moved to tantivy 0.27, and the RUSTSEC-2026-0253 ignores
/// in `deny.toml` and `.cargo/audit.toml` went with it. A crate that arrives
/// on a pre-fix `lru` needs its own justification before it is added here.
const PERMITTED_PRE_FIX_DEPENDANTS: &[&str] = &[];

fn workspace_lock() -> String {
    let lock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("seance_tests sits directly under the workspace root")
        .join("Cargo.lock");
    std::fs::read_to_string(&lock).unwrap_or_else(|e| panic!("reading {}: {e}", lock.display()))
}

/// Every `(dependant, lru version)` pair the resolved graph contains.
///
/// A `[[package]]` block's `dependencies` list names `"lru"` bare when only one
/// version is in the graph and `"lru <version>"` when several are, so both forms
/// have to be read. The bare form is resolved against the single `lru` package
/// entry; if there were several and a bare reference appeared, that would be a
/// lock we could not interpret and the test says so rather than guessing.
fn lru_dependants(lock: &str) -> Vec<(String, String)> {
    let mut versions: Vec<String> = Vec::new();
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut raw: Vec<(String, Option<String>)> = Vec::new();

    for block in lock.split("[[package]]") {
        let mut name = None;
        let mut version = None;
        let mut in_deps = false;
        for line in block.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("name = \"") {
                name = v.strip_suffix('"').map(str::to_string);
            } else if let Some(v) = line.strip_prefix("version = \"") {
                version = v.strip_suffix('"').map(str::to_string);
            } else if line.starts_with("dependencies = [") {
                in_deps = true;
            } else if in_deps {
                if line == "]" {
                    in_deps = false;
                } else if let Some(entry) = line.trim_end_matches(',').strip_prefix('"') {
                    let entry = entry.trim_end_matches('"');
                    let mut parts = entry.split(' ');
                    if parts.next() == Some("lru") {
                        let dependant = name.clone().expect("a package block names itself first");
                        raw.push((dependant, parts.next().map(str::to_string)));
                    }
                }
            }
        }
        if name.as_deref() == Some("lru") {
            versions.push(version.expect("an lru package block declares a version"));
        }
    }

    for (dependant, declared) in raw {
        let resolved = match declared {
            Some(v) => v,
            None => {
                assert_eq!(
                    versions.len(),
                    1,
                    "{dependant} names `lru` without a version while {} lru packages are in the \
                     lock; the lock cannot be read unambiguously",
                    versions.len()
                );
                versions[0].clone()
            }
        };
        pairs.push((dependant, resolved));
    }
    pairs
}

/// A resolved `lru` version as the three numbers that order it.
///
/// Cargo records resolved versions in full, so `major.minor.patch` is the only
/// shape this has to read. Anything else — a pre-release, a build suffix, a
/// two-component version — is refused by name rather than guessed at: calling an
/// uninterpreted version "under the fix" would be a false statement about a
/// release that may well carry it, and calling it "at or above" would be a
/// silent hole in the floor these tests exist to hold.
fn ordered_version(version: &str) -> [u64; 3] {
    let mut components = version.split('.');
    let mut ordered = [0u64; 3];
    for slot in ordered.iter_mut() {
        let component = components.next().filter(|c| !c.is_empty());
        *slot = component.and_then(|c| c.parse().ok()).unwrap_or_else(|| {
            panic!(
                "lru version {version:?} is not three whole numbers separated by dots, so this \
                 test cannot say whether it is at or above the fix in {FIXED_LRU}; read the lock \
                 and move the floor deliberately"
            )
        });
    }
    assert!(
        components.next().is_none(),
        "lru version {version:?} has more than three components, so this test cannot say whether \
         it is at or above the fix in {FIXED_LRU}; read the lock and move the floor deliberately"
    );
    ordered
}

/// Is this resolved `lru` version under the fix?
///
/// Ordering, not equality. The three manifests declare `lru = "0.18.2"`, a caret
/// requirement that permits every later 0.18, so a routine `cargo update` may
/// resolve above the fix at any time — and a release above the fix contains the
/// fix. Testing for equality would fail CI for the upgrade, and would do it by
/// asserting something untrue about the resolved version.
fn is_below_fix(version: &str) -> bool {
    ordered_version(version) < ordered_version(FIXED_LRU)
}

/// The `seance_*` crates the lock resolves onto a pre-fix `lru`, each rendered
/// as it appears in the failure message.
fn seance_crates_below_fix(lock: &str) -> Vec<String> {
    lru_dependants(lock)
        .into_iter()
        .filter(|(dependant, _)| dependant.starts_with("seance_"))
        .filter(|(_, version)| is_below_fix(version))
        .map(|(dependant, version)| format!("{dependant} -> lru {version}"))
        .collect()
}

/// Every crate in the lock — Séance's or anyone's — still on a pre-fix `lru`.
fn pre_fix_dependants(lock: &str) -> BTreeSet<String> {
    lru_dependants(lock)
        .into_iter()
        .filter(|(_, version)| is_below_fix(version))
        .map(|(dependant, _)| dependant)
        .collect()
}

/// Séance's own crates must be at or above the fix. This is the part of the
/// exposure the project controls, and it is the part the advisory ignore does
/// NOT cover.
#[test]
fn no_seance_crate_depends_on_lru_below_the_pop_panic_safety_fix() {
    let below = seance_crates_below_fix(&workspace_lock());

    assert!(
        below.is_empty(),
        "RUSTSEC-2026-0253 is fixed in lru {FIXED_LRU}; these workspace crates are under it: {below:?}"
    );
}

/// And the residue must stay exactly the residue that was reasoned about. A new
/// crate arriving on the vulnerable version would otherwise be invisible: the
/// advisory is ignored graph-wide, so no gate would report it.
#[test]
fn the_only_pre_fix_lru_left_is_the_one_that_was_justified() {
    let dependants = pre_fix_dependants(&workspace_lock());

    let permitted: BTreeSet<String> = PERMITTED_PRE_FIX_DEPENDANTS
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        dependants, permitted,
        "the set of crates still on a pre-{FIXED_LRU} lru changed. If a dependency was upgraded \
         out, shorten PERMITTED_PRE_FIX_DEPENDANTS and drop the RUSTSEC-2026-0253 ignores. If a \
         new one arrived, it needs its own justification before it is added here."
    );
}

/// A `Cargo.lock` fragment holding exactly the `(dependant, lru version)` edges
/// given.
///
/// The synthetic lock is deliberately preferred to the workspace's own for the
/// upgrade cases below: the resolved version of `lru` is decided by crates.io
/// and by whoever last ran `cargo update`, so a test that waited for the real
/// lock to move would assert nothing until the day it broke.
fn synthetic_lock(edges: &[(&str, &str)]) -> String {
    let mut lock = String::from("# This file is automatically @generated by Cargo.\nversion = 3\n");
    let versions: BTreeSet<&str> = edges.iter().map(|(_, version)| *version).collect();
    for version in versions {
        lock.push_str(&format!(
            "\n[[package]]\nname = \"lru\"\nversion = \"{version}\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        ));
    }
    for (dependant, version) in edges {
        lock.push_str(&format!(
            "\n[[package]]\nname = \"{dependant}\"\nversion = \"0.9.0\"\n\
             dependencies = [\n \"lru {version}\",\n]\n"
        ));
    }
    lock
}

/// A later `lru` carries the `pop()` fix as surely as 0.18.2 does, so a routine
/// `cargo update` must not be reported as having dropped Séance under the
/// advisory. Nothing about the workspace's lock decides this — the day lru
/// publishes 0.18.3 is not ours to choose — so the upgrade is put to the
/// classifier directly.
#[test]
fn an_lru_release_above_the_fix_is_not_reported_as_below_it() {
    for upgraded in ["0.18.3", "0.18.10", "0.19.0", "1.0.0"] {
        let lock = synthetic_lock(&[
            ("seance_api", upgraded),
            ("seance_core", upgraded),
            ("seance_memory", upgraded),
            ("tantivy", "0.12.5"),
        ]);

        assert!(
            seance_crates_below_fix(&lock).is_empty(),
            "lru {upgraded} is above the fix in {FIXED_LRU}; no Séance crate on it is under the \
             advisory: {:?}",
            seance_crates_below_fix(&lock)
        );
        assert_eq!(
            pre_fix_dependants(&lock),
            BTreeSet::from(["tantivy".to_string()]),
            "upgrading Séance's own crates to lru {upgraded} must not enlarge the pre-fix set"
        );
    }
}

/// The same upgrade, one step further on: when tantivy finally moves and a
/// single `lru` is left in the graph, Cargo names it in `dependencies` without a
/// version and the version comes from the package block. The residue is then
/// empty, which is the signal to delete the advisory ignores.
#[test]
fn a_single_upgraded_lru_named_without_a_version_leaves_no_residue() {
    let lock = "# This file is automatically @generated by Cargo.\nversion = 3\n\n\
                [[package]]\nname = \"lru\"\nversion = \"0.19.0\"\n\n\
                [[package]]\nname = \"seance_api\"\nversion = \"0.9.0\"\n\
                dependencies = [\n \"lru\",\n]\n\n\
                [[package]]\nname = \"tantivy\"\nversion = \"0.27.0\"\n\
                dependencies = [\n \"lru\",\n]\n";

    assert!(seance_crates_below_fix(lock).is_empty());
    assert!(
        pre_fix_dependants(lock).is_empty(),
        "with every dependant on lru 0.19.0 nothing is left under the fix"
    );
}

/// And the floor still holds downwards: the pre-fix version the advisory is
/// about must still be named, whoever holds it.
#[test]
fn an_lru_below_the_fix_is_still_named() {
    let lock = synthetic_lock(&[
        ("seance_db", "0.12.5"),
        ("seance_api", "0.18.1"),
        ("seance_core", FIXED_LRU),
        ("tantivy", "0.12.5"),
    ]);

    assert_eq!(
        seance_crates_below_fix(&lock),
        vec![
            "seance_db -> lru 0.12.5".to_string(),
            "seance_api -> lru 0.18.1".to_string(),
        ],
        "both 0.12.5 and 0.18.1 are under lru {FIXED_LRU}"
    );
    assert_eq!(
        pre_fix_dependants(&lock),
        BTreeSet::from([
            "seance_api".to_string(),
            "seance_db".to_string(),
            "tantivy".to_string(),
        ])
    );
}

/// A version string this test cannot order — a pre-release, a build suffix, a
/// two-component version — is refused by name rather than guessed at. Saying
/// "under the fix" about a version we did not understand would be a false
/// statement, and saying "at or above" about one would be a silent hole in the
/// floor; the honest answer is to stop and make a human read the lock.
#[test]
#[should_panic(expected = "lru version \"0.18.2-rc.1\"")]
fn a_version_that_cannot_be_ordered_is_refused_rather_than_guessed() {
    let lock = synthetic_lock(&[("seance_api", "0.18.2-rc.1")]);
    let _ = seance_crates_below_fix(&lock);
}
