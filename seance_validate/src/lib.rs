#![forbid(unsafe_code)]
//! Reproducible known-answer validation reporting.
//!
//! The evidentiary value of a forensic tool rests on documented known-answer
//! testing: run a known image, compare to its published ground truth. Running
//! those checks as `cargo test` proves they pass on the developer's machine but
//! produces no durable, shareable artifact — and worse, a corpus-gated test that
//! early-returns when its image is absent reports as "passed", so a plain test
//! run silently overcounts.
//!
//! This module produces an honest, reproducible artifact instead. Every case is
//! classified as exactly one of Pass / Fail / **Skipped (image absent)** — a
//! skip is never a pass — and the report is stamped with the tool version, the
//! git commit, and the SHA-256 of every image actually examined, so a third
//! party can reproduce and verify it. The report carries a `results_digest`
//! (stable across runs on the same corpus + code) and can be MAC-signed with a
//! key for tamper-evidence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub mod cases;
pub mod cftt;
pub mod manifest;

/// Outcome of one case's check against a *present* image.
pub enum CheckOutcome {
    /// Observed value matched the documented expected answer.
    Pass { actual: String },
    /// Observed value did not match the documented expected answer.
    Fail { actual: String },
}

/// A documented known-answer case. `check` runs the real pipeline against the
/// present image and reports what it observed; the framework handles presence,
/// hashing, and classification so a case body cannot accidentally count a skip
/// as a pass.
pub struct KnownAnswerCase {
    pub id: &'static str,
    pub description: &'static str,
    pub capability: &'static str,
    /// Image path relative to the corpus root.
    pub image_rel: &'static str,
    /// The published assertion this case grades, when it grades one — a CFTT
    /// identifier such as `SS-CA-02`. `None` for a case this project wrote
    /// itself, which is most of the existing set.
    pub assertion: Option<&'static str>,
    /// Human-readable documented expected answer (for the report).
    pub expected: &'static str,
    pub check: fn(&Path) -> anyhow::Result<CheckOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseStatus {
    Pass,
    Fail,
    /// The image was not present in the corpus; the case was not evaluated.
    Skipped,
    /// The tool does not offer the feature the assertion is conditional on.
    ///
    /// CFTT's own concept, from its specifications: "if a feature is not
    /// present, then requirements for those features will not be tested".
    /// Five of the eleven CFTT methodology families do not apply to Séance at
    /// all, because it performs no acquisition and is not a write blocker
    /// (`documentation/VALIDATION.md`, "CFTT methodologies").
    ///
    /// It exists because every other status is a false statement about such an
    /// assertion: `Pass` claims a test that never ran, `Fail` claims a defect,
    /// and `Skipped` claims the evidence was missing when it was the feature
    /// that was.
    NotApplicable,
    /// The run could not reach the question.
    ///
    /// This project's own invariant, which the three-status vocabulary had no
    /// way to record: "could not look" is not "not there". An assertion whose
    /// answer key is a template, or whose evidence this build cannot ingest,
    /// is unassessed — and recording it as `Fail` asserts a defect the run
    /// never established.
    NotAssessed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseResult {
    pub id: String,
    pub description: String,
    pub capability: String,
    pub image: String,
    /// SHA-256 of the image actually examined; None when skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<String>,
    pub status: CaseStatus,
    /// The published assertion this row grades, when it grades one —
    /// `SS-CA-02`, `FT-SS-07-Cyrillic`, `DFR-CR-01`.
    ///
    /// Absent rather than empty when there is none: an empty column reads as
    /// an assertion with no identifier, which is a different thing from a case
    /// this project wrote itself.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub assertion: Option<String>,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    /// The feature the assertion is conditional on is not offered.
    #[serde(default)]
    pub not_applicable: usize,
    /// The run could not reach the question.
    #[serde(default)]
    pub not_assessed: usize,
}

impl Summary {
    pub fn of(results: &[CaseResult]) -> Self {
        let mut s = Summary {
            total: results.len(),
            passed: 0,
            failed: 0,
            skipped: 0,
            not_applicable: 0,
            not_assessed: 0,
        };
        for r in results {
            match r.status {
                CaseStatus::Pass => s.passed += 1,
                CaseStatus::Fail => s.failed += 1,
                CaseStatus::Skipped => s.skipped += 1,
                // Neither counts towards a pass and neither fails the run.
                // Both are counted, because "2 skipped", "2 not applicable"
                // and "2 not assessed" are three different facts about a run.
                CaseStatus::NotApplicable => s.not_applicable += 1,
                CaseStatus::NotAssessed => s.not_assessed += 1,
            }
        }
        s
    }
}

/// How the report learned the commit it is stamped with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CommitSource {
    /// Captured by `build.rs` from the tree the binary was compiled from. This
    /// is the commit the code *is*.
    BuildTime,
    /// The build carried no commit, so `git rev-parse` was asked in the run
    /// directory. That names whatever repository the tool was run in, which is
    /// not necessarily the one it was built from.
    RuntimeGit,
    /// Neither was available. The commit is reported as `unknown`.
    #[default]
    Unknown,
}

impl CommitSource {
    /// One clause for the Markdown report.
    pub fn describe(self) -> &'static str {
        match self {
            CommitSource::BuildTime => "embedded at build time",
            CommitSource::RuntimeGit => {
                "from `git rev-parse` in the run directory, not embedded at build time; \
                 this may not be the commit the binary was built from"
            }
            CommitSource::Unknown => {
                "not embedded at build time and no git repository at the run directory"
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub tool: String,
    pub seance_version: String,
    pub git_commit: String,
    /// Where `git_commit` came from, so a reader knows how much to trust it.
    /// Absent from reports written before this field existed.
    #[serde(default)]
    pub git_commit_source: CommitSource,
    /// What `git describe` answers in the directory the tool was **run** in,
    /// when that directory is a git repository. `None` when it is not one, or
    /// when git is unavailable — outside a checkout there is nothing to compare
    /// against and no line is printed (VAL-003).
    ///
    /// This is provenance about the *surroundings*, never about the binary. It
    /// exists because the build-time stamp was taken on trust: a binary built
    /// elsewhere and run inside this repository printed its own build commit
    /// with nothing saying the tree around it was a different one. Recording
    /// both lets a reader see the disagreement — and lets the report say, in
    /// words, that a disagreement is normal rather than suspicious.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_directory_commit: Option<String>,
    /// RFC3339 UTC. Provenance only — excluded from `results_digest` so the
    /// digest is stable across runs on the same corpus + code.
    pub generated_at: String,
    pub host: String,
    pub corpus_root: String,
    pub summary: Summary,
    pub results: Vec<CaseResult>,
    /// SHA-256 (hex) over the canonical JSON of `results`. Two runs on the same
    /// corpus and code produce the same digest regardless of when they ran.
    pub results_digest: String,
}

impl ValidationReport {
    pub fn new(
        seance_version: impl Into<String>,
        git_commit: impl Into<String>,
        git_commit_source: CommitSource,
        generated_at: impl Into<String>,
        host: impl Into<String>,
        corpus_root: impl Into<String>,
        results: Vec<CaseResult>,
    ) -> Self {
        let summary = Summary::of(&results);
        let results_digest = digest_results(&results);
        ValidationReport {
            tool: "seance-validate".to_string(),
            seance_version: seance_version.into(),
            git_commit: git_commit.into(),
            git_commit_source,
            run_directory_commit: None,
            generated_at: generated_at.into(),
            host: host.into(),
            corpus_root: corpus_root.into(),
            summary,
            results,
            results_digest,
        }
    }

    /// Record what `git describe` answers in the run directory.
    ///
    /// Separate from [`Self::new`] because it is the only piece of the report
    /// that describes the machine rather than the run, and because a caller
    /// with nothing to say here — no repository, no git — should say nothing
    /// rather than pass a placeholder that would print as a comparison.
    #[must_use]
    pub fn with_run_directory_commit(mut self, commit: Option<String>) -> Self {
        self.run_directory_commit = commit.filter(|c| !c.is_empty());
        self
    }

    /// The sentence the report prints about the tree it was run in, if any.
    ///
    /// `None` — print nothing — in three cases, each for its own reason:
    ///
    /// * The run directory is not a git repository. There is nothing to compare.
    /// * The commit did not come from the build. When it came from run-time
    ///   `git` it *is* the run directory's commit, so a comparison would be a
    ///   tautology dressed as corroboration; when it is unknown there is
    ///   nothing to compare it to.
    ///
    /// When they disagree the wording is the substance of this, and it is
    /// chosen deliberately: **a disagreement is not an error.** Running a
    /// released binary inside an unrelated checkout is ordinary and correct, and
    /// a report that implied otherwise would train its reader to distrust a
    /// normal state — the same failure as a tool that cries tampering during
    /// ordinary use.
    pub fn run_directory_note(&self) -> Option<String> {
        let tree = self.run_directory_commit.as_deref()?;
        if self.git_commit_source != CommitSource::BuildTime {
            return None;
        }
        Some(if tree == self.git_commit {
            format!(
                "- Working tree: `{tree}` — the same commit, so this binary was built from the \
                 tree it ran in."
            )
        } else {
            format!(
                "- Working tree: `{tree}`, which is **not** the commit above. The report \
                 describes the binary, which was built elsewhere; running a released binary \
                 inside another checkout is ordinary and does not make this validation suspect. \
                 It does mean the surrounding tree is not evidence about the code that produced \
                 these results."
            )
        })
    }

    /// True when nothing FAILED. Skips (absent images) do not fail the run, but
    /// they are always reported so a reader knows coverage was incomplete.
    pub fn passed(&self) -> bool {
        self.summary.failed == 0
    }

    /// True when no case was evaluated at all — every one was Skipped, or
    /// there were none. Such a run examined no evidence and establishes
    /// nothing; it must not read as a pass, which is why the runner exits
    /// non-zero on it and the report's headline says so.
    pub fn covered_nothing(&self) -> bool {
        self.summary.passed == 0 && self.summary.failed == 0
    }

    /// HMAC-SHA256 (hex) over the canonical JSON of the whole report, for
    /// tamper-evidence. Uses the same primitive as the audit-log chain.
    pub fn sign_hmac(&self, key: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        let bytes = serde_json::to_vec(self).expect("report serializes");
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key size");
        mac.update(&bytes);
        hex(&mac.finalize().into_bytes())
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes")
    }

    pub fn render_markdown(&self) -> String {
        let s = &self.summary;
        let verdict = if !self.passed() {
            "FAIL"
        } else if self.covered_nothing() {
            "NO COVERAGE"
        } else {
            "PASS"
        };
        let mut md = String::new();
        md.push_str(&format!("# Séance validation report — {verdict}\n\n"));
        if self.covered_nothing() {
            md.push_str(
                "**No case was evaluated: every image was absent from the corpus. This run \
                 examined no evidence and is not a pass.**\n\n",
            );
        }
        md.push_str(&format!(
            "- Tool: `{}` v{}\n",
            self.tool, self.seance_version
        ));
        md.push_str(&format!(
            "- Commit: `{}` ({})\n",
            self.git_commit,
            self.git_commit_source.describe()
        ));
        if let Some(note) = self.run_directory_note() {
            md.push_str(&note);
            md.push('\n');
        }
        md.push_str(&format!("- Generated: {}\n", self.generated_at));
        md.push_str(&format!("- Host: {}\n", self.host));
        md.push_str(&format!("- Corpus root: `{}`\n", self.corpus_root));
        md.push_str(&format!(
            "- Results digest (SHA-256): `{}`\n\n",
            self.results_digest
        ));
        md.push_str(&format!(
            "**{} passed, {} failed, {} skipped (image absent), {} not applicable (feature not \
             offered), {} not assessed (run could not reach the question), {} total.**\n\n",
            s.passed, s.failed, s.skipped, s.not_applicable, s.not_assessed, s.total
        ));
        md.push_str("| Case | Assertion | Capability | Status | Expected | Observed |\n");
        md.push_str("|------|-----------|------------|--------|----------|----------|\n");
        for r in &self.results {
            let status = match r.status {
                CaseStatus::Pass => "PASS",
                CaseStatus::Fail => "FAIL",
                CaseStatus::Skipped => "skipped",
                CaseStatus::NotApplicable => "not applicable",
                CaseStatus::NotAssessed => "not assessed",
            };
            md.push_str(&format!(
                "| {} — {} | {} | {} | {} | {} | {} |\n",
                r.id,
                md_cell(&r.description),
                // A dash, not a blank: a blank cell reads as an assertion
                // whose identifier was lost.
                r.assertion.as_deref().unwrap_or("—"),
                r.capability,
                status,
                md_cell(&r.expected),
                md_cell(&r.actual),
            ));
        }
        md
    }
}

/// Escape a value for a single Markdown table cell.
fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// SHA-256 (hex) over the canonical JSON of the results array.
fn digest_results(results: &[CaseResult]) -> String {
    let bytes = serde_json::to_vec(results).expect("results serialize");
    hex(&Sha256::digest(&bytes))
}

/// SHA-256 (hex) of a file, streamed so a multi-GB image never loads at once.
pub fn sha256_file(path: &Path) -> anyhow::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Run one case against the corpus, classifying it Pass / Fail / Skipped. An
/// absent image is Skipped (never Pass); a parser error or a mismatch is Fail.
pub fn run_case(case: &KnownAnswerCase, corpus_root: &Path) -> CaseResult {
    let image = corpus_root.join(case.image_rel);
    let base = CaseResult {
        id: case.id.to_string(),
        description: case.description.to_string(),
        capability: case.capability.to_string(),
        image: case.image_rel.to_string(),
        image_sha256: None,
        status: CaseStatus::Skipped,
        assertion: case.assertion.map(str::to_string),
        expected: case.expected.to_string(),
        actual: String::new(),
    };

    if !image.exists() {
        return CaseResult {
            actual: "image not present in corpus".to_string(),
            ..base
        };
    }

    let image_sha256 = sha256_file(&image).ok();
    match (case.check)(&image) {
        Ok(CheckOutcome::Pass { actual }) => CaseResult {
            image_sha256,
            status: CaseStatus::Pass,
            actual,
            ..base
        },
        Ok(CheckOutcome::Fail { actual }) => CaseResult {
            image_sha256,
            status: CaseStatus::Fail,
            actual,
            ..base
        },
        Err(e) => CaseResult {
            image_sha256,
            status: CaseStatus::Fail,
            actual: format!("error running check: {e}"),
            ..base
        },
    }
}

/// Run every case against the corpus root.
pub fn run_all(cases: &[KnownAnswerCase], corpus_root: &Path) -> Vec<CaseResult> {
    cases.iter().map(|c| run_case(c, corpus_root)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &str, status: CaseStatus) -> CaseResult {
        CaseResult {
            id: id.to_string(),
            description: "d".to_string(),
            capability: "cap".to_string(),
            image: "img.dd".to_string(),
            image_sha256: Some("abc".to_string()),
            status,
            assertion: None,
            expected: "e".to_string(),
            actual: "a".to_string(),
        }
    }

    /// **`NotApplicable` is CFTT's own concept**, and it is not a pass.
    ///
    /// Five of the eleven CFTT methodology families do not apply to Séance at
    /// all — it performs no acquisition and is not a write blocker — and the
    /// specifications say so themselves: "if a feature is not present, then
    /// requirements for those features will not be tested". With only Pass,
    /// Fail and Skipped, such an assertion had to be forced into one of them,
    /// and every choice was a false statement: Pass claims a test that never
    /// ran, Fail claims a defect, Skipped claims the evidence was missing.
    #[test]
    fn a_not_applicable_case_is_neither_a_pass_nor_a_failure() {
        let s = Summary::of(&[
            result("1", CaseStatus::Pass),
            result("2", CaseStatus::NotApplicable),
            result("3", CaseStatus::NotApplicable),
        ]);
        assert_eq!(s.total, 3);
        assert_eq!(s.passed, 1, "a not-applicable case is never a pass");
        assert_eq!(s.failed, 0, "and never a failure");
        assert_eq!(s.skipped, 0, "and is not the same thing as a skip");
        assert_eq!(s.not_applicable, 2);
    }

    /// **`NotAssessed` is this project's own invariant**: the run could not
    /// reach the question. "Could not look" is not "not there", and with three
    /// statuses it had to be recorded as a Fail — which asserts a defect the
    /// run never established.
    #[test]
    fn a_not_assessed_case_is_neither_a_pass_nor_a_failure() {
        let s = Summary::of(&[
            result("1", CaseStatus::Fail),
            result("2", CaseStatus::NotAssessed),
        ]);
        assert_eq!(s.failed, 1, "only the real failure fails");
        assert_eq!(s.not_assessed, 1);
        assert_eq!(s.passed, 0);
        assert_eq!(s.skipped, 0);
    }

    /// Neither new status can turn a failing run into a passing one, and
    /// neither can rescue a run that established nothing.
    #[test]
    fn the_new_statuses_never_rescue_a_run() {
        let failing = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![
                result("1", CaseStatus::Fail),
                result("2", CaseStatus::NotApplicable),
                result("3", CaseStatus::NotAssessed),
            ],
        );
        assert!(!failing.passed());

        // A run of nothing but the two new statuses examined no evidence.
        let nothing = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![
                result("1", CaseStatus::NotApplicable),
                result("2", CaseStatus::NotAssessed),
            ],
        );
        assert!(
            nothing.covered_nothing(),
            "a run that only said \"does not apply\" and \"could not look\" \
             established nothing and must not read as a pass"
        );
        assert!(nothing.render_markdown().contains("NO COVERAGE"));
    }

    /// The headline counts each new status separately, because "2 skipped" and
    /// "2 not applicable" are different facts about a run.
    #[test]
    fn the_report_headline_counts_each_status_separately() {
        let md = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![
                result("1", CaseStatus::Pass),
                result("2", CaseStatus::Skipped),
                result("3", CaseStatus::NotApplicable),
                result("4", CaseStatus::NotAssessed),
            ],
        )
        .render_markdown();
        assert!(md.contains("1 passed"), "{md}");
        assert!(md.contains("1 skipped"), "{md}");
        assert!(md.contains("1 not applicable"), "{md}");
        assert!(md.contains("1 not assessed"), "{md}");
    }

    /// A case can name the published assertion it grades, so a row is
    /// traceable to somebody else's document rather than to this project's
    /// own wording.
    #[test]
    fn a_case_can_name_the_assertion_it_grades() {
        let mut r = result("SS-1", CaseStatus::Pass);
        r.assertion = Some("SS-CA-02".to_string());
        let md = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![r],
        )
        .render_markdown();
        assert!(md.contains("SS-CA-02"), "{md}");
    }

    /// And a case that names none says nothing about one, rather than an empty
    /// column that reads as an assertion with no identifier.
    #[test]
    fn a_case_with_no_assertion_serialises_without_the_field() {
        let r = result("1", CaseStatus::Pass);
        assert!(r.assertion.is_none());
        let json = serde_json::to_string(&r).expect("serialises");
        assert!(!json.contains("assertion"), "{json}");
    }

    /// **The committed report's digest is a claim, and it must survive the
    /// report gaining a field.**
    ///
    /// `documentation/VALIDATION.md` records
    /// `db6c238e9a006f29699414ab379e86a0f902c7b18bb9d097053e2d4936fe724e` as
    /// the results digest of the committed seven-case run, and a reader
    /// checking a release recomputes it. Adding `assertion` to `CaseResult`
    /// could have invalidated that claim silently — which is why the field is
    /// `skip_serializing_if = "Option::is_none"`: a case that names no
    /// published assertion serialises exactly as it did before.
    ///
    /// This reads the committed report and recomputes the digest through the
    /// current code, so the claim in the documentation is checked rather than
    /// remembered.
    #[test]
    fn the_committed_reports_digest_survives_the_new_fields() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the crate has a parent directory")
            .join("validation-report.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            // A checkout without the committed report is not a failure of
            // this claim; it is the absence of the thing the claim is about.
            eprintln!("skipped: {} is not present", path.display());
            return;
        };
        let report: ValidationReport =
            serde_json::from_str(&text).expect("the committed report deserialises");
        assert_eq!(
            digest_results(&report.results),
            "db6c238e9a006f29699414ab379e86a0f902c7b18bb9d097053e2d4936fe724e",
            "the digest recorded in documentation/VALIDATION.md must still be the digest of \
             the committed results under the CURRENT report shape"
        );
        assert_eq!(
            report.results_digest,
            digest_results(&report.results),
            "and the report must still agree with itself"
        );
        // And the older summary, which had three counters, reads back with the
        // two new ones at zero rather than refusing to parse.
        assert_eq!(report.summary.not_applicable, 0);
        assert_eq!(report.summary.not_assessed, 0);
        assert_eq!(report.summary.passed, 7);
    }

    #[test]
    fn summary_counts_each_status_and_skips_never_pass() {
        let results = vec![
            result("1", CaseStatus::Pass),
            result("2", CaseStatus::Fail),
            result("3", CaseStatus::Skipped),
            result("4", CaseStatus::Skipped),
        ];
        let s = Summary::of(&results);
        assert_eq!(s.total, 4);
        assert_eq!(s.passed, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.skipped, 2);
    }

    #[test]
    fn passed_is_true_with_skips_but_false_with_a_failure() {
        let ok = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![
                result("1", CaseStatus::Pass),
                result("2", CaseStatus::Skipped),
            ],
        );
        assert!(ok.passed(), "skips must not fail the run");
        let bad = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![result("1", CaseStatus::Fail)],
        );
        assert!(!bad.passed(), "a failure must fail the run");
    }

    fn report(results: Vec<CaseResult>, source: CommitSource) -> ValidationReport {
        ValidationReport::new("0.9.0", "abc", source, "t", "h", "root", results)
    }

    #[test]
    fn a_run_in_which_every_case_was_skipped_is_no_coverage_not_a_pass() {
        let all_skipped = report(
            vec![
                result("1", CaseStatus::Skipped),
                result("2", CaseStatus::Skipped),
            ],
            CommitSource::BuildTime,
        );
        assert!(all_skipped.passed(), "nothing failed");
        assert!(all_skipped.covered_nothing(), "but nothing was evaluated");
        let md = all_skipped.render_markdown();
        assert!(
            md.starts_with("# Séance validation report — NO COVERAGE"),
            "{md}"
        );
        assert!(md.contains("examined no evidence"), "{md}");

        let empty = report(vec![], CommitSource::BuildTime);
        assert!(empty.covered_nothing(), "an empty case set covers nothing");

        let one_ran = report(
            vec![
                result("1", CaseStatus::Pass),
                result("2", CaseStatus::Skipped),
            ],
            CommitSource::BuildTime,
        );
        assert!(!one_ran.covered_nothing());
        assert!(one_ran
            .render_markdown()
            .starts_with("# Séance validation report — PASS"));

        // A failure outranks the coverage headline.
        let failed = report(vec![result("1", CaseStatus::Fail)], CommitSource::BuildTime);
        assert!(failed
            .render_markdown()
            .starts_with("# Séance validation report — FAIL"));
    }

    /// VAL-003. The build stamp answers for the binary; it never answered for
    /// the tree the binary was run in, and nothing said so.
    #[test]
    fn a_working_tree_matching_the_build_commit_is_stated_as_matching() {
        let report = report(vec![result("1", CaseStatus::Pass)], CommitSource::BuildTime)
            .with_run_directory_commit(Some("abc".to_string()));

        let note = report.run_directory_note().expect("a note is printed");
        assert!(note.contains("`abc`"), "{note}");
        assert!(note.contains("the same commit"), "{note}");
        assert!(report.render_markdown().contains("the same commit"));
    }

    /// The case the entry was written about, and the one whose **wording** was
    /// the reason it needed a decision rather than just code: a released binary
    /// run inside an unrelated checkout is ordinary, and the report must not
    /// imply the results are in doubt.
    #[test]
    fn a_working_tree_at_another_commit_is_stated_as_normal_not_as_suspect() {
        let report = report(vec![result("1", CaseStatus::Pass)], CommitSource::BuildTime)
            .with_run_directory_commit(Some("deadbeef-dirty".to_string()));

        let note = report.run_directory_note().expect("a note is printed");
        assert!(note.contains("`deadbeef-dirty`"), "{note}");
        assert!(note.contains("not** the commit above"), "{note}");
        assert!(
            note.contains("does not make this validation suspect"),
            "a disagreement is not an error and the report has to say so: {note}"
        );
        assert!(
            note.contains("not evidence about the code"),
            "and it must still say what the disagreement does cost: {note}"
        );
        assert!(report.passed(), "the verdict is untouched by where it ran");
        assert!(report
            .render_markdown()
            .starts_with("# Séance validation report — PASS"));
    }

    /// Outside a repository there is nothing to compare, so nothing is said.
    /// An empty or absent value must never render as half a comparison.
    #[test]
    fn no_line_is_printed_when_the_run_directory_is_not_a_repository() {
        let none = report(vec![result("1", CaseStatus::Pass)], CommitSource::BuildTime)
            .with_run_directory_commit(None);
        assert!(none.run_directory_note().is_none());
        assert!(!none.render_markdown().contains("Working tree"));

        // An empty string is the same statement as absent, and is normalised to
        // it rather than printed as `` — the shape `git describe` returns when
        // it fails but exits 0.
        let empty = report(vec![result("1", CaseStatus::Pass)], CommitSource::BuildTime)
            .with_run_directory_commit(Some(String::new()));
        assert!(empty.run_directory_commit.is_none());
        assert!(empty.run_directory_note().is_none());
    }

    /// When the commit itself came from run-time git, the two values are the
    /// same by construction. Printing "the same commit" there would dress a
    /// tautology as corroboration.
    #[test]
    fn a_runtime_git_commit_is_not_corroborated_against_itself() {
        let runtime = report(
            vec![result("1", CaseStatus::Pass)],
            CommitSource::RuntimeGit,
        )
        .with_run_directory_commit(Some("abc".to_string()));
        assert!(runtime.run_directory_note().is_none());
        assert!(!runtime.render_markdown().contains("Working tree"));

        let unknown = report(vec![result("1", CaseStatus::Pass)], CommitSource::Unknown)
            .with_run_directory_commit(Some("abc".to_string()));
        assert!(unknown.run_directory_note().is_none());
    }

    /// The field reaches the JSON, and a report written before it existed still
    /// reads back — the same compatibility the commit-source field keeps.
    #[test]
    fn the_run_directory_commit_round_trips_and_older_reports_still_read() {
        let report = report(vec![result("1", CaseStatus::Pass)], CommitSource::BuildTime)
            .with_run_directory_commit(Some("abc".to_string()));
        let json = report.to_json_pretty();
        assert!(json.contains("\"run_directory_commit\": \"abc\""), "{json}");

        let back: ValidationReport = serde_json::from_str(&json).expect("round trips");
        assert_eq!(back.run_directory_commit.as_deref(), Some("abc"));

        // Absent from the JSON entirely when there is nothing to say, so an
        // older reader sees the document it always saw.
        let silent = report.clone().with_run_directory_commit(None);
        assert!(!silent.to_json_pretty().contains("run_directory_commit"));

        let old = silent.to_json_pretty();
        let parsed: ValidationReport = serde_json::from_str(&old).expect("reads back");
        assert!(parsed.run_directory_commit.is_none());
    }

    #[test]
    fn the_report_says_where_its_commit_came_from() {
        let results = vec![result("1", CaseStatus::Pass)];
        let built = report(results.clone(), CommitSource::BuildTime);
        assert!(built
            .render_markdown()
            .contains("- Commit: `abc` (embedded at build time)"));
        let runtime = report(results.clone(), CommitSource::RuntimeGit);
        assert!(runtime
            .render_markdown()
            .contains("not embedded at build time"));
        let unknown = report(results.clone(), CommitSource::Unknown);
        assert!(unknown.render_markdown().contains("no git repository"));

        // The source is in the JSON too, and an older report without it still
        // reads back (as Unknown).
        let json = built.to_json_pretty();
        assert!(
            json.contains("\"git_commit_source\": \"build-time\""),
            "{json}"
        );
        let without: ValidationReport =
            serde_json::from_str(&json.replace("\"git_commit_source\": \"build-time\",", ""))
                .expect("a report without the field still parses");
        assert_eq!(without.git_commit_source, CommitSource::Unknown);

        // Provenance is not part of the results digest.
        assert_eq!(built.results_digest, runtime.results_digest);
    }

    #[test]
    fn results_digest_is_stable_across_timestamp_and_host() {
        let results = vec![result("1", CaseStatus::Pass)];
        let a = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "MON",
            "hostA",
            "root",
            results.clone(),
        );
        let b = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "TUE",
            "hostB",
            "root",
            results,
        );
        assert_eq!(
            a.results_digest, b.results_digest,
            "same results must digest identically regardless of when/where the run happened"
        );
    }

    #[test]
    fn results_digest_changes_when_a_result_changes() {
        let a = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![result("1", CaseStatus::Pass)],
        );
        let b = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![result("1", CaseStatus::Fail)],
        );
        assert_ne!(a.results_digest, b.results_digest);
    }

    #[test]
    fn hmac_signature_is_deterministic_and_key_sensitive() {
        let r = ValidationReport::new(
            "0.9.0",
            "abc",
            CommitSource::BuildTime,
            "t",
            "h",
            "root",
            vec![result("1", CaseStatus::Pass)],
        );
        assert_eq!(r.sign_hmac(b"k1"), r.sign_hmac(b"k1"));
        assert_ne!(r.sign_hmac(b"k1"), r.sign_hmac(b"k2"));
    }

    #[test]
    fn absent_image_is_skipped_not_passed() {
        let case = KnownAnswerCase {
            id: "X",
            description: "d",
            capability: "cap",
            image_rel: "does/not/exist.dd",
            assertion: None,
            expected: "e",
            check: |_| {
                Ok(CheckOutcome::Pass {
                    actual: "unreached".into(),
                })
            },
        };
        let r = run_case(&case, Path::new("/nonexistent-corpus-root"));
        assert_eq!(r.status, CaseStatus::Skipped);
        assert!(r.image_sha256.is_none());
    }

    #[test]
    fn present_image_is_hashed_and_classified() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(dir.path().join("img.dd")).unwrap();
        f.write_all(b"hello").unwrap();
        drop(f);

        let pass_case = KnownAnswerCase {
            id: "P",
            description: "d",
            capability: "cap",
            image_rel: "img.dd",
            assertion: None,
            expected: "e",
            check: |_| {
                Ok(CheckOutcome::Pass {
                    actual: "5 bytes".into(),
                })
            },
        };
        let r = run_case(&pass_case, dir.path());
        assert_eq!(r.status, CaseStatus::Pass);
        // SHA-256("hello")
        assert_eq!(
            r.image_sha256.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );

        // A check that returns an error classifies as Fail, not a crash.
        let err_case = KnownAnswerCase {
            check: |_| anyhow::bail!("boom"),
            ..pass_case
        };
        let r = run_case(&err_case, dir.path());
        assert_eq!(r.status, CaseStatus::Fail);
        assert!(r.actual.contains("boom"));
    }
}
