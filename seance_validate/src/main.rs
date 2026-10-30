//! `seance-validate` — run the known-answer validation cases against a local
//! corpus and emit a reproducible, provenance-stamped report.
//!
//! Usage:
//!   seance-validate [--corpus <dir>] [--out <basepath>]
//!
//!   --corpus <dir>   corpus root holding one directory per image set —
//!                    dftt/, alihadi_ntfs/, oberon_linux_swap/, win11_bitlocker/
//!                    (default: current dir; see documentation/VALIDATION.md)
//!   --out <base>     write <base>.json and <base>.md (default: validation-report)
//!
//! # Exit code
//!
//! - `0` — at least one case was evaluated and none failed.
//! - `1` — at least one case FAILED.
//! - `2` — nothing was evaluated: every case was Skipped because its image was
//!   absent. Skips never fail a run that evaluated *something* (they are
//!   counted, so a reader knows coverage was incomplete), but a run that
//!   evaluated nothing established nothing, and exiting 0 would let it be
//!   quoted as a pass. The report's headline says NO COVERAGE in that case.
//!
//! # Commit provenance
//!
//! The commit is embedded at build time by `build.rs`. If the build carried
//! none, `git rev-parse` is asked in the run directory, and the report says so —
//! that names whichever repository the tool was run in, which is not
//! necessarily the one it was built from. Failing both, the commit is
//! `unknown`, and the report says that too.
//!
//! The build-time stamp used to be taken purely on trust: a binary built
//! somewhere else and run inside this repository printed its own build commit
//! with nothing indicating the surrounding tree was a different one (VAL-003).
//! The report now also records what `git describe` answers in the run
//! directory, when that is a repository, and says in words whether the two
//! agree — including that a disagreement means the binary was built elsewhere,
//! which is ordinary, and not that the validation is suspect.
//!
//! If SEANCE_VALIDATION_HMAC_KEY is set, an HMAC-SHA256 of the report is written
//! to <base>.hmac for tamper-evidence.

use seance_validate::{cases::cases, run_all, CommitSource, ValidationReport};
use std::path::PathBuf;
use std::process::Command;

/// Exit status when every case was skipped and nothing was evaluated.
const EXIT_NO_COVERAGE: i32 = 2;

/// What `git describe` answers in the directory the tool was run in.
///
/// `None` when that directory is not a git repository, or when git is
/// unavailable — in either case there is nothing to compare the build stamp
/// against, and the report prints no line rather than an empty one (VAL-003).
///
/// The command is **character-identical to the one `build.rs` runs**, including
/// `--dirty` and `--abbrev=12`. It has to be: comparing `git describe` output
/// against `git rev-parse` output, or a dirty stamp against a clean one, would
/// manufacture disagreements between two names for the same commit, and this
/// line exists to be believed.
fn run_directory_commit() -> Option<String> {
    Command::new("git")
        .args(["describe", "--always", "--dirty", "--abbrev=12"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The commit to stamp the report with, and where it came from.
fn git_commit() -> (String, CommitSource) {
    let built = env!("SEANCE_VALIDATE_BUILD_COMMIT");
    if !built.is_empty() {
        return (built.to_string(), CommitSource::BuildTime);
    }
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| (s, CommitSource::RuntimeGit))
        .unwrap_or_else(|| ("unknown".to_string(), CommitSource::Unknown))
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            Command::new("hostname")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() -> anyhow::Result<()> {
    let mut corpus_root = PathBuf::from(".");
    let mut out = PathBuf::from("validation-report");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--corpus" => {
                corpus_root = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--corpus needs a path"))?,
                )
            }
            "--out" => {
                out = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--out needs a path"))?,
                )
            }
            "-h" | "--help" => {
                print!("{}", include_str!("help.txt"));
                return Ok(());
            }
            other => anyhow::bail!("unknown argument: {other} (try --help)"),
        }
    }

    let all = cases();
    let results = run_all(&all, &corpus_root);
    let (commit, commit_source) = git_commit();
    let report = ValidationReport::new(
        env!("CARGO_PKG_VERSION"),
        commit,
        commit_source,
        chrono::Utc::now().to_rfc3339(),
        hostname(),
        corpus_root.display().to_string(),
        results,
    )
    .with_run_directory_commit(run_directory_commit());

    let json_path = out.with_extension("json");
    let md_path = out.with_extension("md");
    std::fs::write(&json_path, report.to_json_pretty())?;
    std::fs::write(&md_path, report.render_markdown())?;

    if let Ok(key) = std::env::var("SEANCE_VALIDATION_HMAC_KEY") {
        if !key.is_empty() {
            let sig = report.sign_hmac(key.as_bytes());
            std::fs::write(out.with_extension("hmac"), format!("{sig}\n"))?;
        }
    }

    let s = &report.summary;
    eprintln!(
        "validation: {} passed, {} failed, {} skipped (image absent), {} total",
        s.passed, s.failed, s.skipped, s.total
    );
    eprintln!("results digest: {}", report.results_digest);
    eprintln!(
        "commit: {} ({})",
        report.git_commit,
        report.git_commit_source.describe()
    );
    if let Some(note) = report.run_directory_note() {
        eprintln!("{}", note.trim_start_matches("- "));
    }
    eprintln!("wrote {} and {}", json_path.display(), md_path.display());

    if !report.passed() {
        std::process::exit(1);
    }
    if report.covered_nothing() {
        eprintln!(
            "validation: NO COVERAGE — every case was skipped because its image is absent \
             under {}; nothing was evaluated, so this run is not a pass",
            corpus_root.display()
        );
        std::process::exit(EXIT_NO_COVERAGE);
    }
    Ok(())
}
