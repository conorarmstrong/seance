use std::process::Command;

fn main() {
    // Capture the build time. Force this script to re-run on every build by
    // depending on a path that never exists, otherwise Cargo caches the build
    // script output and the timestamp goes stale across recompiles.
    println!("cargo:rerun-if-changed=always-rerun-build-timestamp");

    let build_timestamp = Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", build_timestamp);

    // Embed the git commit for provenance (short hash, "-dirty" if uncommitted).
    let git_commit = Command::new("git")
        .args(["describe", "--always", "--dirty", "--abbrev=12"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);
}
