//! Embed the git commit the binary was built from.
//!
//! The report stamps a commit for provenance. Asking `git` at run time answers
//! for whatever directory the tool happens to be run in — which is `unknown`
//! outside the repository and, worse, a *different* commit inside some other
//! one — so the value is captured here, at build time, from the tree the code
//! actually came from. `main.rs` uses this first and falls back to run-time
//! `git` only when it is empty, and the report says which it used.

use std::path::Path;
use std::process::Command;

fn main() {
    // Re-run on EVERY build, by depending on a path that never exists — the
    // same device `seance_cli/build.rs` uses, and for a sharper reason here.
    //
    // `--dirty` is a fact about the WORKING TREE, and cargo cannot watch a
    // working tree: nothing under `.git` changes when a tracked file is edited
    // in place. With only the refs below declared, cargo found every watched
    // path older than the cached output and replayed it, so a binary built from
    // an edited tree carried the previous run's CLEAN stamp. The report then
    // printed "Commit: <tag>-<hash> (embedded at build time)" — which
    // `CommitSource::BuildTime` documents as "the commit the code IS" — over
    // code that was not that commit, on an HMAC-signed document published as a
    // release artefact. Tags are unwatchable in the same way: adding one at HEAD
    // changes what `git describe` answers and moves no ref this script can name.
    //
    // The cost is one `git describe` per build of this leaf crate.
    println!("cargo:rerun-if-changed=always-rerun-validation-commit-stamp");

    // Declared as well, so the inputs this script actually reads are on the
    // record: the symbolic HEAD, the branch ref it names, and the packed refs
    // that ref may live in.
    let git_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.git");
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    println!(
        "cargo:rerun-if-changed={}",
        git_dir.join("packed-refs").display()
    );
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
        if let Some(reference) = head.trim().strip_prefix("ref: ") {
            println!(
                "cargo:rerun-if-changed={}",
                git_dir.join(reference).display()
            );
        }
    }

    // Short hash, "-dirty" if the tree had uncommitted changes. Empty — not a
    // placeholder — when git is unavailable, so the fallback can tell.
    let commit = Command::new("git")
        .args(["describe", "--always", "--dirty", "--abbrev=12"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    println!("cargo:rustc-env=SEANCE_VALIDATE_BUILD_COMMIT={commit}");
}
