//! The app-parser schema-drift corpus gates (ROADMAP §1.4a) must run in CI,
//! and `documentation/CI.md` must say which workflow runs them.
//!
//! The §1.4a corpus-diff tests read real stores that are not in the tree, and
//! each one skips — and passes — when its store is absent. Until this wiring,
//! no workflow named any of their variables, so every one of them printed its
//! skip line in CI and the badge covered none of them. These tests pin two
//! things a reviewer would otherwise have to re-derive from YAML:
//!
//! * the plaso-derived halves run in a hosted job, which clones plaso and
//!   refuses to go on if the stores the tests read by a bare `exists()` are
//!   missing;
//! * the CTF-derived halves run on the self-hosted corpus runner with
//!   `SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1`, so an absent store fails the job.
//!
//! And one doc-drift pin: the "No workflow sets any of the following" list in
//! `documentation/CI.md` may not name a variable a workflow sets.
//!
//! These are static checks over the workflow text. They cannot prove the
//! self-hosted runner exists or holds the trees (REL-001); they prove only that
//! a run of the workflow would ask for them.

use std::path::PathBuf;

fn workspace_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("seance_tests sits directly under the workspace root")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The jobs of a workflow, as `(job id, the job's text)`.
///
/// Textual rather than a YAML parse: the workflows use two-space indentation
/// for job ids under `jobs:`, and a job's body is every following line until
/// the next job id. That is all these checks need, and it keeps a YAML crate
/// out of the test dependencies.
fn jobs(workflow: &str) -> Vec<(String, String)> {
    let after_jobs = workflow
        .split_once("\njobs:\n")
        .expect("workflow has a top-level `jobs:` block")
        .1;
    let mut out: Vec<(String, String)> = Vec::new();
    for line in after_jobs.lines() {
        let is_job_id = line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
            && !line.trim_start().starts_with('#');
        if is_job_id {
            out.push((line.trim().trim_end_matches(':').to_string(), String::new()));
        } else if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// Does this text set `var`, as an `env:` key or a shell `export`?
fn sets_variable(text: &str, var: &str) -> bool {
    text.lines().map(str::trim_start).any(|l| {
        !l.starts_with('#')
            && (l.starts_with(&format!("{var}:"))
                || l.starts_with(&format!("export {var}="))
                || l.starts_with(&format!("{var}=")))
    })
}

/// The crates whose §1.4a corpus-diff tests read a plaso store.
const PLASO_CRATES: [&str; 6] = [
    "seance_plugin_browser_history",
    "seance_plugin_skype",
    "seance_plugin_android_sms",
    "seance_plugin_imessage",
    "seance_plugin_twitter",
    "seance_plugin_call_history",
];

/// The plaso stores the group C tests read by a bare `exists()` at the default
/// path, plus the ones the gated tests name. If any is missing the tests skip,
/// so the job has to check for them itself.
const PLASO_STORES: [&str; 6] = [
    "mmssms.db",
    "imessage_chat.db",
    "twitter_android.db",
    "contacts2.db",
    "skype_main.db",
    "chrome_history/History",
];

#[test]
fn the_plaso_app_schema_gates_run_in_a_hosted_job() {
    let workflow = workspace_file(".github/workflows/test.yml");
    let jobs = jobs(&workflow);
    let (id, job) = jobs
        .iter()
        .find(|(_, body)| body.contains("https://github.com/log2timeline/plaso"))
        .expect("a job in test.yml clones plaso for the app-schema corpus gates");

    assert!(
        job.contains("runs-on: ubuntu-latest"),
        "job `{id}` must run on a hosted runner"
    );
    assert!(
        job.contains("reference/plaso"),
        "job `{id}` must clone plaso into reference/plaso, the default path the \
         group C tests read"
    );
    for var in ["SEANCE_PLASO_TEST_DATA", "SEANCE_SKYPE_SAMPLES"] {
        assert!(
            sets_variable(job, var),
            "job `{id}` must set {var} (at reference/plaso/test_data)"
        );
    }
    for store in PLASO_STORES {
        assert!(
            job.contains(&format!("test -f \"reference/plaso/test_data/{store}\""))
                || job.contains(&format!("test -f reference/plaso/test_data/{store}")),
            "job `{id}` must refuse to continue when plaso's {store} is absent — the \
             tests that read it skip silently otherwise"
        );
    }
    for krate in PLASO_CRATES {
        assert!(
            job.contains(&format!("cargo test -p {krate}")),
            "job `{id}` must run the corpus gate in {krate}"
        );
    }
    // Either switch would fail this job on the CTF half by design: the same
    // tests read a plaso store and a CTF store, and the CTF trees cannot be on
    // a hosted runner. The enforcement here is the named-but-missing panic.
    for var in ["SEANCE_REQUIRE_CORPUS", "SEANCE_APP_SCHEMA_CORPUS_REQUIRED"] {
        assert!(
            !sets_variable(job, var),
            "job `{id}` must not set {var}: the CTF halves of the same tests \
             cannot be satisfied on a hosted runner"
        );
    }
}

/// Every CTF-derived variable the §1.4a gates read, and the `$CORPUS_ROOT`
/// entry the runner keeps it at.
const CTF_VARIABLES: [(&str, &str); 7] = [
    ("SEANCE_APP_SCHEMA_CORPUS", "app_schema_corpus"),
    ("SEANCE_ANDROID2022_TREE", "android2022/data"),
    ("SEANCE_CHROMEBOOK_TREE", "chromebook/decrypted"),
    ("SEANCE_MACOS2021_TREE", "macos2021/tree"),
    ("SEANCE_IOS2022_TREE", "ios2022ffs/tree"),
    ("SEANCE_SNAPCHAT_SAMPLES", "snapchat_samples"),
    ("SEANCE_SIGNAL_IOS_SQLITE", "signal_ios/signal.sqlite"),
];

#[test]
fn the_ctf_app_schema_gates_run_on_the_corpus_runner_and_fail_when_absent() {
    let workflow = workspace_file(".github/workflows/selfhosted-linux-ci.yml");
    let jobs = jobs(&workflow);
    let (_, job) = jobs
        .iter()
        .find(|(id, _)| id == "corpus-gates")
        .expect("selfhosted-linux-ci.yml has the corpus-gates job");

    assert!(
        job.contains("SEANCE_APP_SCHEMA_CORPUS_REQUIRED: \"1\"")
            || job.contains("export SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1"),
        "corpus-gates must set SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1, or an absent \
         app_schema_corpus store passes"
    );
    for (var, entry) in CTF_VARIABLES {
        assert!(
            job.contains(&format!("export {var}=\"$CORPUS_ROOT/{entry}\"")),
            "corpus-gates must export {var} at $CORPUS_ROOT/{entry}"
        );
    }

    let confirm = job
        .split("- name: ")
        .find(|step| step.starts_with("Confirm the corpora"))
        .expect("corpus-gates has its 'Confirm the corpora' step");
    for (_, entry) in CTF_VARIABLES {
        assert!(
            confirm.contains(entry),
            "the 'Confirm the corpora' step must check $CORPUS_ROOT/{entry}"
        );
    }
    for krate in [
        "seance_plugin_browser_history",
        "seance_plugin_contacts",
        "seance_plugin_installed_apps",
        "seance_plugin_android_apps",
        "seance_plugin_mobile_device",
        "seance_plugin_snapchat",
        "seance_plugin_signal",
        "seance_plugin_android_sms",
        "seance_plugin_imessage",
        "seance_plugin_twitter",
        "seance_plugin_call_history",
    ] {
        assert!(
            job.contains(&format!("cargo test -p {krate}")),
            "corpus-gates must run the CTF-derived corpus gate in {krate}"
        );
    }
}

#[test]
fn ci_md_lists_no_variable_a_workflow_sets() {
    let ci = workspace_file("documentation/CI.md");
    let list = ci
        .split_once("**No workflow sets any of the following**")
        .expect("CI.md keeps its 'No workflow sets any of the following' list")
        .1;
    // The list ends where its prose begins.
    let list = list
        .split_once("The tests behind them")
        .expect("the list is followed by 'The tests behind them'")
        .0;
    let named: Vec<&str> = list
        .split('`')
        .filter(|t| {
            t.starts_with("SEANCE_")
                && t.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        })
        .collect();
    assert!(!named.is_empty(), "the list names at least one variable");

    let workflows = [
        ".github/workflows/test.yml",
        ".github/workflows/selfhosted-linux-ci.yml",
        ".github/workflows/coverage.yml",
        ".github/workflows/fuzz.yml",
        ".github/workflows/audit.yml",
        ".github/workflows/release.yml",
    ];
    for wf in workflows {
        let text = workspace_file(wf);
        for var in &named {
            assert!(
                !sets_variable(&text, var),
                "documentation/CI.md says no workflow sets {var}, but {wf} does"
            );
        }
    }
}
