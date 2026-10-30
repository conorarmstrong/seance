//! Grade a CFTT Forensic String Search run (`ROADMAP` §5.2).
//!
//! ```sh
//! cargo run -p seance_validate --bin cftt-grade -- \
//!     --key  <win_string_doc.txt> \
//!     --results <results.json from scripts/cftt/run-string-search.sh> \
//!     --out  <basename>
//! ```
//!
//! Writes `<basename>.json` and `<basename>.md`.
//!
//! Two optional inputs check the key against the image before grading
//! (VAL-002):
//!
//! * `--image <ss-win-07-25-18.dd>` compares every row's term, in its stated
//!   encoding, with the image's bytes at its published offset. A row the image
//!   contradicts is graded "not assessed" as a fault in the key.
//! * `--key-files <key-files.json>` gives, per row, the file Sleuth Kit places
//!   at the row's offset. It is what attributes a miss to file recovery, and
//!   where the key's named file is not on the image the row is graded against
//!   the file at its offset instead, stated on the row and counted.
//!   Without it, a key name missing from the inventory is not attributed.
//!
//! And one names the published case each row serves:
//!
//! * `--cases <Expected Results by ID v1.1 9-27-19.docx>` (or its extracted
//!   `word/document.xml`), with `--cases-set win|unix` (default `win`), reads
//!   the data set's case table. Each row is graded once per FT-SS case that
//!   names it, and the report gains a per-case table. The headline still
//!   counts each key row once.
//!
//! # What this report may and may not be quoted for
//!
//! Running a published methodology in-house is **not** third-party validation.
//! NIST has not tested this tool. And the expectations here are verified
//! against the publisher while **the questions are not**: the answer key gives
//! the expected hit identifiers and never the query, so every term comes from
//! the data set's `string-search-test-cases.html`, which fails all three of the
//! publisher's hash algorithms. Both sentences are printed on the report rather
//! than left to a reader to remember.

use std::collections::BTreeMap;
use std::path::PathBuf;

use seance_validate::cftt::cases_map::{by_case, CaseMap, DataSet};
use seance_validate::cftt::dfr_grade::{grade_run, ClassRule, DfrGraded, ReportedDfr};
use seance_validate::cftt::dfr_layout::parse_layout;
use seance_validate::cftt::grade::{
    grade_with_inventory, GradeSummary, Graded, Recovered, ReportedHits,
};
use seance_validate::cftt::string_search::{
    parse_answer_key, verify_row, AnswerKey, RowVerdict, QUERY_PROVENANCE,
};
use seance_validate::CaseStatus;

fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--dfr") {
        return dfr_main(std::env::args().skip(2).collect());
    }
    if std::env::args().nth(1).as_deref() == Some("--mdt") {
        return mdt_main(std::env::args().skip(2).collect());
    }
    let mut key_path: Option<PathBuf> = None;
    let mut results_path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut ingest_incomplete = false;
    let mut inventory_path: Option<PathBuf> = None;
    let mut image_path: Option<PathBuf> = None;
    let mut key_files_path: Option<PathBuf> = None;
    let mut cases_path: Option<PathBuf> = None;
    let mut cases_set = DataSet::Windows;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" => key_path = args.next().map(PathBuf::from),
            "--results" => results_path = args.next().map(PathBuf::from),
            "--out" => out = args.next().map(PathBuf::from),
            "--ingest-incomplete" => ingest_incomplete = true,
            "--inventory" => inventory_path = args.next().map(PathBuf::from),
            "--image" => image_path = args.next().map(PathBuf::from),
            "--key-files" => key_files_path = args.next().map(PathBuf::from),
            "--cases" => cases_path = args.next().map(PathBuf::from),
            "--cases-set" => {
                cases_set = match args.next().as_deref() {
                    Some("win") | Some("windows") => DataSet::Windows,
                    Some("unix") => DataSet::Unix,
                    other => anyhow::bail!("--cases-set takes win or unix, not {other:?}"),
                }
            }
            other => anyhow::bail!("unknown option: {other}"),
        }
    }
    let (Some(key_path), Some(results_path), Some(out)) = (key_path, results_path, out) else {
        anyhow::bail!(
            "usage: cftt-grade --key <string_doc> --results <json> --out <basename> \
             [--inventory <json>] [--image <dd>] [--key-files <json>] \
             [--cases <Expected Results by ID .docx> [--cases-set win|unix]] [--ingest-incomplete]"
        );
    };

    let mut key = parse_answer_key(&std::fs::read_to_string(&key_path)?);

    // The key checked against the image's own bytes, so a row the evidence
    // contradicts is not counted against the tool.
    let mut row_checks: BTreeMap<&'static str, usize> = BTreeMap::new();
    if let Some(p) = &image_path {
        let mut img = std::io::BufReader::new(std::fs::File::open(p)?);
        for e in &mut key.expectations {
            let v = verify_row(e, &mut img);
            *row_checks
                .entry(match v {
                    RowVerdict::Verified => "verified",
                    RowVerdict::AtItsMarker => "at_its_marker",
                    RowVerdict::BytesDiffer { .. } => "contradicted_by_the_image",
                    RowVerdict::NotChecked(_) => "not_checked",
                })
                .or_default() += 1;
            e.image_check = Some(v);
        }
    }
    // The file at each row's offset, from Sleuth Kit.
    if let Some(p) = &key_files_path {
        let rows: Vec<KeyFile> = serde_json::from_str(&std::fs::read_to_string(p)?)?;
        for r in rows {
            let Some(image_file) = r.image_file else {
                continue;
            };
            for e in key
                .expectations
                .iter_mut()
                .filter(|e| e.id == r.id && e.term == r.term)
            {
                e.image_file = Some(image_file.clone());
            }
        }
    }
    let reported: BTreeMap<String, ReportedHits> = {
        let raw: BTreeMap<String, RawHits> =
            serde_json::from_str(&std::fs::read_to_string(&results_path)?)?;
        raw.into_iter().map(|(k, v)| (k, v.into())).collect()
    };

    // What the tool recovered, so a miss lands on the right half of it. With
    // no inventory no attribution is made either way, rather than one being
    // guessed.
    let recovered = match &inventory_path {
        Some(p) => {
            let names: Vec<String> = serde_json::from_str(&std::fs::read_to_string(p)?)?;
            Recovered::from_names(names)
        }
        None => Recovered::unknown(),
    };
    // The published case table, so each row says which FT-SS case it is
    // evidence for. Without it every row's case is left unstated.
    let tables = match &cases_path {
        Some(p) => Some(seance_validate::cftt::cases_map::load(p)?),
        None => None,
    };
    let case_map = tables.as_ref().map(|t| t.for_set(cases_set));
    if let Some(t) = &tables {
        anyhow::ensure!(
            t.rejected.is_empty(),
            "the case table has rows this grader could not read: {:?}",
            t.rejected
        );
    }
    let unresolved = case_map.map(|m| m.unresolved(&key)).unwrap_or_default();
    let grades = grade_all(&key, &reported, ingest_incomplete, &recovered, case_map);
    let per_case = rollup(&grades);
    // The headline and the failure list count each key row once; the
    // per-case table and the JSON rows carry one row per (key row, case).
    let distinct = distinct_rows(&grades);
    let summary = GradeSummary::of(&distinct);

    let json = serde_json::json!({
        "methodology": "NIST CFTT Forensic String Search",
        "answer_key": key_path.display().to_string(),
        "results": results_path.display().to_string(),
        "not_third_party_validation":
            "Running a published methodology in-house is not third-party validation. NIST has \
             not tested this tool.",
        "query_provenance": QUERY_PROVENANCE,
        "ingest_complete": !ingest_incomplete,
        "file_inventory": inventory_path.as_ref().map(|p| p.display().to_string()),
        "image_checked": image_path.as_ref().map(|p| p.display().to_string()),
        "row_checks": row_checks,
        "key_files": key_files_path.as_ref().map(|p| p.display().to_string()),
        "key_description": key.describe(),
        "summary": {
            "passed": summary.passed,
            "failed": summary.failed,
            "not_applicable": summary.not_applicable,
            "not_assessed": summary.not_assessed,
            "graded_against_the_file_at_the_offset": summary.substituted,
            "total": summary.total(),
            "statement": summary.describe(),
        },
        "case_table": cases_path.as_ref().map(|p| serde_json::json!({
            "path": p.display().to_string(),
            "data_set": cases_set.as_str(),
            "cases": case_map.map(|m| m.cases().len()),
            "entries": case_map.map(|m| m.entries.len()),
            "unresolved": unresolved.iter().map(|u| serde_json::json!({
                "case": u.entry.case, "id": u.entry.id, "query": u.entry.query, "why": u.why,
            })).collect::<Vec<_>>(),
            "note": "A key row a published case names is graded once per case that names it, \
                     so the per-case totals can sum to more than the row count.",
        })),
        "cases": per_case.iter().map(|(c, s)| (c.clone(), serde_json::json!({
            "passed": s.passed,
            "failed": s.failed,
            "not_applicable": s.not_applicable,
            "not_assessed": s.not_assessed,
            "total": s.total(),
        }))).collect::<serde_json::Map<_, _>>(),
        "rows": grades.iter().map(row_json).collect::<Vec<_>>(),
    });
    let json_path = out.with_extension("json");
    let md_path = out.with_extension("md");
    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&json_path, serde_json::to_string_pretty(&json)?)?;
    let mut md = render(&key, &distinct, &summary, ingest_incomplete);
    if case_map.is_some() {
        md.push_str(&render_cases(&per_case, &unresolved, cases_set));
    }
    std::fs::write(&md_path, md)?;
    println!("{}", summary.describe());
    println!("wrote {} and {}", json_path.display(), md_path.display());

    if summary.passed + summary.failed == 0 {
        std::process::exit(2);
    }
    Ok(())
}

/// One row of `key-files.json`: the file Sleuth Kit places at a key row's
/// offset, or `null` where it placed none.
#[derive(serde::Deserialize)]
struct KeyFile {
    id: String,
    term: String,
    #[serde(default)]
    image_file: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawHits {
    #[serde(default)]
    artifact_names: Vec<String>,
    #[serde(default)]
    offsets: Vec<u64>,
    #[serde(default)]
    search_incomplete: Option<String>,
}

impl From<RawHits> for ReportedHits {
    fn from(r: RawHits) -> Self {
        Self {
            artifact_names: r.artifact_names,
            offsets: r.offsets,
            search_incomplete: r.search_incomplete,
        }
    }
}

/// Grade every expectation.
///
/// **A term the runner never searched for is unassessed, not a miss.** That is
/// the one thing a grader must get right about its own input: an absent result
/// is the absence of a question, and reading it as a negative answer would
/// report defects for searches nobody ran.
fn grade_all(
    key: &AnswerKey,
    reported: &BTreeMap<String, ReportedHits>,
    ingest_incomplete: bool,
    recovered: &Recovered,
    cases: Option<&CaseMap>,
) -> Vec<Graded> {
    let not_searched = ReportedHits {
        search_incomplete: Some(
            "this term was not searched for in this run, so nothing about it was established"
                .to_string(),
        ),
        ..Default::default()
    };
    let partial = ReportedHits {
        search_incomplete: Some(
            "the ingest did not finish, so a term not found may simply not have been indexed yet"
                .to_string(),
        ),
        ..Default::default()
    };
    key.expectations
        .iter()
        .flat_map(|e| {
            let hits = match reported.get(&e.term) {
                Some(_) if ingest_incomplete => &partial,
                Some(h) => h,
                None => &not_searched,
            };
            // A row a published case names is graded once per case that
            // names it (id 2944 serves FT-SS-04 and FT-SS-10-Hex), rather
            // than one case being picked; a row no case names keeps `None`.
            let named = cases.map(|m| m.cases_for(e, key)).unwrap_or_default();
            if named.is_empty() {
                vec![grade_with_inventory(e, hits, None, recovered)]
            } else {
                named
                    .into_iter()
                    .map(|c| grade_with_inventory(e, hits, Some(c), recovered))
                    .collect()
            }
        })
        .collect()
}

/// One graded row per key row, for the headline: a row graded under two
/// cases is one expectation, and counting it twice would inflate the total.
fn distinct_rows(grades: &[Graded]) -> Vec<Graded> {
    let mut seen = std::collections::BTreeSet::new();
    grades
        .iter()
        .filter(|g| seen.insert((g.id.clone(), g.term.clone(), g.expected.clone())))
        .map(|g| Graded {
            assertion: None,
            ..g.clone()
        })
        .collect()
}

/// Per published case, the summary of its graded rows.
fn rollup(grades: &[Graded]) -> BTreeMap<String, GradeSummary> {
    by_case(grades, |g| g.assertion.as_deref())
        .into_iter()
        .map(|(case, rows)| {
            let owned: Vec<Graded> = rows.into_iter().cloned().collect();
            (case, GradeSummary::of(&owned))
        })
        .collect()
}

fn render_cases(
    per_case: &BTreeMap<String, GradeSummary>,
    unresolved: &[seance_validate::cftt::cases_map::Unresolved],
    set: DataSet,
) -> String {
    let mut md = format!(
        "## By published case ({} data set)\n\nFrom the data set's `Expected Results by ID` \
         table. A key row two cases name (id 2944: FT-SS-04 and FT-SS-10-Hex) is graded once \
         per case, so these totals can sum to more than the row count.\n\n\
         | Case | Passed | Failed | Not applicable | Not assessed | Total |\n|---|---|---|---|---|---|\n",
        set.as_str()
    );
    for (case, s) in per_case {
        let label = case.as_str();
        md.push_str(&format!(
            "| {label} | {} | {} | {} | {} | {} |\n",
            s.passed,
            s.failed,
            s.not_applicable,
            s.not_assessed,
            s.total()
        ));
    }
    md.push('\n');
    if !unresolved.is_empty() {
        md.push_str(&format!(
            "**{} case-table entries could not be placed on one key row** and grade nothing:\n\n",
            unresolved.len()
        ));
        for u in unresolved {
            md.push_str(&format!(
                "- {} id {}: {}\n",
                u.entry.case, u.entry.id, u.why
            ));
        }
        md.push('\n');
    }
    md
}

fn status_str(s: CaseStatus) -> &'static str {
    match s {
        CaseStatus::Pass => "PASS",
        CaseStatus::Fail => "FAIL",
        CaseStatus::Skipped => "skipped",
        CaseStatus::NotApplicable => "not applicable",
        CaseStatus::NotAssessed => "not assessed",
    }
}

fn row_json(g: &Graded) -> serde_json::Value {
    serde_json::json!({
        "id": g.id,
        "term": g.term,
        "assertion": g.assertion,
        "status": status_str(g.status),
        "expected": g.expected,
        "actual": g.actual,
        "graded_against": g.graded_against,
    })
}

fn render(
    key: &AnswerKey,
    grades: &[Graded],
    summary: &GradeSummary,
    ingest_incomplete: bool,
) -> String {
    let mut md = String::from("# CFTT Forensic String Search — run report\n\n");
    md.push_str(
        "> **This is not third-party validation.** Running a published methodology in-house is \
         not the same as being tested by the body that published it, and NIST has not tested \
         this tool.\n\n",
    );
    md.push_str(&format!("> **On the questions.** {QUERY_PROVENANCE}\n\n"));
    if ingest_incomplete {
        md.push_str(
            "> **The ingest did not finish.** Every expectation below is therefore unassessed: \
             a term not found may simply not have been indexed yet, and reading that as an \
             absence would report defects this run did not establish.\n\n",
        );
    }
    md.push_str(&format!("**{}**\n\n", summary.describe()));
    md.push_str(&format!("The answer key: {}\n\n", key.describe()));
    md.push_str("| Status | Count |\n|---|---|\n");
    md.push_str(&format!("| Passed | {} |\n", summary.passed));
    md.push_str(&format!("| Failed | {} |\n", summary.failed));
    md.push_str(&format!(
        "| Not applicable (feature not offered) | {} |\n",
        summary.not_applicable
    ));
    md.push_str(&format!(
        "| Not assessed (could not reach the question) | {} |\n",
        summary.not_assessed
    ));
    md.push_str(&format!(
        "| Of the assessed, graded against the file at the key's offset | {} |\n\n",
        summary.substituted
    ));

    let failures: Vec<&Graded> = grades
        .iter()
        .filter(|g| g.status == CaseStatus::Fail)
        .collect();
    md.push_str(&format!("## Failures ({})\n\n", failures.len()));
    if failures.is_empty() {
        md.push_str("None.\n\n");
    } else {
        md.push_str("| Hit | Term | Expected | Observed |\n|---|---|---|---|\n");
        for g in &failures {
            md.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                g.id,
                g.term.replace('|', "\\|"),
                g.expected.replace('|', "\\|"),
                g.actual.replace('|', "\\|")
            ));
        }
        md.push('\n');
    }

    for (label, status) in [
        ("Not applicable", CaseStatus::NotApplicable),
        ("Not assessed", CaseStatus::NotAssessed),
    ] {
        let rows: Vec<&Graded> = grades.iter().filter(|g| g.status == status).collect();
        if rows.is_empty() {
            continue;
        }
        let mut by_reason: BTreeMap<&str, usize> = BTreeMap::new();
        for g in &rows {
            *by_reason.entry(g.actual.as_str()).or_default() += 1;
        }
        md.push_str(&format!("## {label} ({})\n\n", rows.len()));
        for (reason, count) in by_reason {
            md.push_str(&format!("- **{count}×** {reason}\n"));
        }
        md.push('\n');
    }
    md
}

/// `cftt-grade --dfr --layout <layout.txt> --results <run.json> --out <base>
/// [--classes <rules.json>]`: grade a Deleted File Recovery run.
fn dfr_main(args: Vec<String>) -> anyhow::Result<()> {
    let mut layout_path: Option<PathBuf> = None;
    let mut results_path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut classes_path: Option<PathBuf> = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--layout" => layout_path = it.next().map(PathBuf::from),
            "--results" => results_path = it.next().map(PathBuf::from),
            "--out" => out = it.next().map(PathBuf::from),
            "--classes" => classes_path = it.next().map(PathBuf::from),
            other => anyhow::bail!("unknown option: {other}"),
        }
    }
    let (Some(layout_path), Some(results_path), Some(out)) = (layout_path, results_path, out)
    else {
        anyhow::bail!(
            "usage: cftt-grade --dfr --layout <setup-july-10-2012.pdf|layout.txt> \
             --results <run.json> --out <basename> [--classes <rules.json>]"
        );
    };
    let text = if layout_path.extension().is_some_and(|e| e == "pdf") {
        let o = std::process::Command::new("pdftotext")
            .arg("-layout")
            .arg(&layout_path)
            .arg("-")
            .output()?;
        anyhow::ensure!(
            o.status.success(),
            "pdftotext failed on {}",
            layout_path.display()
        );
        String::from_utf8(o.stdout)?
    } else {
        std::fs::read_to_string(&layout_path)?
    };
    let layout = parse_layout(&text);
    anyhow::ensure!(
        layout.rejected.is_empty(),
        "the layout has sections this grader could not read: {:?}",
        layout.rejected
    );
    let run = parse_dfr_results(&std::fs::read_to_string(&results_path)?)?;
    let rules: Vec<ClassRule> = match &classes_path {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
        None => Vec::new(),
    };
    let grades = grade_run(&layout, &run, &rules);
    let summary = dfr_summary(&grades);

    let json = serde_json::json!({
        "methodology": "NIST CFTT Deleted File Recovery (core assertions DFR-CR-01..04)",
        "not_third_party_validation":
            "Running a published methodology in-house is not third-party validation. NIST has \
             not tested this tool.",
        "truth": "NIST's layout document (setup-july-10-2012.pdf), parsed by seance_validate's \
                  dfr_layout; the rows it elides are counted and graded not assessed.",
        "assertions_paraphrased":
            "The DFR specification is not held on disk; DFR-CR-01..03 are this grader's reading \
             of it and DFR-CR-04 is quoted. DFR-RO-01..08 are not graded.",
        "layout": layout_path.display().to_string(),
        "results": results_path.display().to_string(),
        "classes": classes_path.as_ref().map(|p| p.display().to_string()),
        "summary": summary,
        "rows": grades.iter().map(|g| serde_json::json!({
            "image": g.image,
            "assertion": g.assertion,
            "file": g.file,
            "status": status_str(g.status),
            "expected": g.expected,
            "actual": g.actual,
            "class": g.class.as_ref().map(|(c, _)| c),
            "class_reason": g.class.as_ref().map(|(_, r)| r),
        })).collect::<Vec<_>>(),
    });
    let json_path = out.with_extension("json");
    let md_path = out.with_extension("md");
    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&json_path, serde_json::to_string_pretty(&json)?)?;
    std::fs::write(&md_path, render_dfr(&grades))?;
    println!(
        "{} passed, {} failed, {} not applicable, {} not assessed",
        summary["passed"], summary["failed"], summary["not_applicable"], summary["not_assessed"]
    );
    println!("wrote {} and {}", json_path.display(), md_path.display());
    Ok(())
}

/// `cftt-grade --mdt --key <expectations.json> --results <run.json>
/// --image-sha-before H --image-sha-after H --image-stat-before S
/// --image-stat-after S --out <base>`: grade the Mobile Device Data population.
fn mdt_main(args: Vec<String>) -> anyhow::Result<()> {
    use seance_validate::cftt::mdt::{
        grade, results_digest, summarise, ImageState, MdtKey, ReportedMdt,
    };
    let mut key_path: Option<PathBuf> = None;
    let mut results_path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut st = ImageState::default();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key" => key_path = it.next().map(PathBuf::from),
            "--results" => results_path = it.next().map(PathBuf::from),
            "--out" => out = it.next().map(PathBuf::from),
            "--image-sha-before" => st.sha256_before = it.next(),
            "--image-sha-after" => st.sha256_after = it.next(),
            "--image-stat-before" => st.stat_before = it.next(),
            "--image-stat-after" => st.stat_after = it.next(),
            other => anyhow::bail!("unknown option: {other}"),
        }
    }
    let (Some(key_path), Some(results_path), Some(out)) = (key_path, results_path, out) else {
        anyhow::bail!(
            "usage: cftt-grade --mdt --key <expectations.json> --results <run.json> \
             --image-sha-before <h> --image-sha-after <h> --image-stat-before <s> \
             --image-stat-after <s> --out <basename>"
        );
    };
    let key: MdtKey = serde_json::from_str(&std::fs::read_to_string(&key_path)?)?;
    let run: ReportedMdt = serde_json::from_str(&std::fs::read_to_string(&results_path)?)?;
    let rows = grade(&key, &run, &st);
    let digest = results_digest(&rows);
    let summary = summarise(&rows);
    let count = |s: CaseStatus| rows.iter().filter(|r| r.status == s).count();
    let json = serde_json::json!({
        "methodology": "NIST CFTT Mobile Device Data population (MDT-CA-02, CA-11, CA-12, CA-13 graded)",
        "not_third_party_validation":
            "Running a published methodology in-house is not third-party validation. NIST has \
             not tested this tool.",
        "truth": key.source,
        "image": key.image,
        "image_sha256_expected": key.image_sha256,
        "image_sha256_before": st.sha256_before,
        "image_sha256_after": st.sha256_after,
        "results_digest": digest,
        "summary": {
            "passed": count(CaseStatus::Pass),
            "failed": count(CaseStatus::Fail),
            "not_applicable": count(CaseStatus::NotApplicable),
            "not_assessed": count(CaseStatus::NotAssessed),
            "by_assertion": summary,
        },
        "rows": rows,
    });
    let json_path = out.with_extension("json");
    let md_path = out.with_extension("md");
    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&json_path, serde_json::to_string_pretty(&json)?)?;
    let mut md = String::from(
        "# CFTT Mobile Device Data (HTC Desire S) - run report\n\n> **This is not third-party \
         validation.** NIST has not tested this tool. The population PDF is a template; the \
         expectations are the handset's own stored values, decoded independently with TSK and \
         sqlite3.\n\n",
    );
    md.push_str(&format!("Results digest (SHA-256): `{digest}`\n\n"));
    md.push_str(
        "| Assertion | Subject | Status | Expected | Actual | Note |\n|---|---|---|---|---|---|\n",
    );
    let cell = |s: &str| s.replace('|', "\\|");
    for r in &rows {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.assertion,
            cell(&r.subject),
            status_str(r.status),
            cell(&r.expected),
            cell(&r.actual),
            cell(&r.note)
        ));
    }
    std::fs::write(&md_path, md)?;
    println!(
        "{} passed, {} failed, {} not applicable, {} not assessed",
        count(CaseStatus::Pass),
        count(CaseStatus::Fail),
        count(CaseStatus::NotApplicable),
        count(CaseStatus::NotAssessed)
    );
    println!("results_digest {digest}");
    println!("wrote {} and {}", json_path.display(), md_path.display());
    Ok(())
}

fn dfr_summary(grades: &[DfrGraded]) -> serde_json::Value {
    let count = |s: CaseStatus| grades.iter().filter(|g| g.status == s).count();
    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    for g in grades {
        if let Some((c, _)) = &g.class {
            *by_class.entry(format!("{c:?}")).or_default() += 1;
        }
    }
    serde_json::json!({
        "passed": count(CaseStatus::Pass),
        "failed": count(CaseStatus::Fail),
        "not_applicable": count(CaseStatus::NotApplicable),
        "not_assessed": count(CaseStatus::NotAssessed),
        "failures_by_class": by_class,
    })
}

fn render_dfr(grades: &[DfrGraded]) -> String {
    let mut md = String::from("# CFTT Deleted File Recovery — run report\n\n");
    md.push_str(
        "> **This is not third-party validation.** NIST has not tested this tool. The truth is \
         NIST's own layout document, parsed; rows that document elides are counted and graded \
         not assessed. DFR-CR-01..03 are paraphrased (the specification is not held here); \
         DFR-RO-01..08 are not graded.\n\n",
    );
    let mut images: BTreeMap<&str, [usize; 4]> = BTreeMap::new();
    for g in grades {
        let slot = images.entry(g.image.as_str()).or_default();
        slot[match g.status {
            CaseStatus::Pass => 0,
            CaseStatus::Fail => 1,
            CaseStatus::NotApplicable => 2,
            _ => 3,
        }] += 1;
    }
    md.push_str(
        "| Image | Passed | Failed | Not applicable | Not assessed |\n|---|---|---|---|---|\n",
    );
    for (img, c) in &images {
        md.push_str(&format!(
            "| {img} | {} | {} | {} | {} |\n",
            c[0], c[1], c[2], c[3]
        ));
    }
    let fails: Vec<&DfrGraded> = grades
        .iter()
        .filter(|g| g.status == CaseStatus::Fail)
        .collect();
    md.push_str(&format!("\n## Failures ({})\n\n", fails.len()));
    if fails.is_empty() {
        md.push_str("None.\n");
    } else {
        md.push_str("| Image | Assertion | File | Observed | Class |\n|---|---|---|---|---|\n");
        for g in fails {
            let (c, why) = g.class.as_ref().expect("every failure is classed");
            md.push_str(&format!(
                "| {} | {} | {} | {} | {c:?}: {why} |\n",
                g.image,
                g.assertion,
                g.file.as_deref().unwrap_or("-").replace('|', "\\|"),
                g.actual.replace('|', "\\|"),
            ));
        }
    }
    md
}

/// The runner's results file: one [`ReportedDfr`] per image. A record
/// without `ingest_complete` reads as not complete.
fn parse_dfr_results(json: &str) -> anyhow::Result<Vec<ReportedDfr>> {
    Ok(serde_json::from_str(json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_validate::cftt::cases_map::parse_case_table;

    /// The three key rows at id 2944 and one at 0896, quoted from
    /// `win_string_doc.txt`.
    const KEY: &str = "\
0896:DireWolf:9172152:17914:LIVE-Extinct-Lupus-fat-ascii.txt:fat32:utf-8
2944:fox:9692350:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
2944:panda tiger fox:9692338:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
2944:tiger:9692344:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
";
    /// Quoted from `Expected Results by ID v1.1 9-27-19.docx`, rendered.
    const CASES: &str = "\
MS Windows Data Set|
Case/String|Encoding|Active|Deleted|Unalloc|
FT-SS-01|
DireWolf | ascii | 0896 0898 0900 | 0897 0899 0901 | 0902|
FT-SS-04|
Panda and fox| ascii | 2944 2946 2948 | 2945 2947 2949 ||
FT-SS-10-Hex|
panda| ascii | 2944 2946 2948 | 2945 2947 2949 | 2950|
";

    fn reported() -> BTreeMap<String, ReportedHits> {
        ["DireWolf", "panda tiger fox", "tiger", "fox"]
            .into_iter()
            .map(|t| {
                (
                    t.to_string(),
                    ReportedHits {
                        artifact_names: vec!["LIVE-triple-fat-ascii.txt".into()],
                        ..Default::default()
                    },
                )
            })
            .collect()
    }

    #[test]
    fn grade_all_attaches_the_case_when_a_map_is_given() {
        let key = parse_answer_key(KEY);
        let map = parse_case_table(CASES).windows;
        let g = grade_all(&key, &reported(), false, &Recovered::unknown(), Some(&map));
        let of = |id: &str, term: &str| -> Vec<Option<String>> {
            g.iter()
                .filter(|r| r.id == id && r.term == term)
                .map(|r| r.assertion.clone())
                .collect()
        };
        assert_eq!(of("0896", "DireWolf"), [Some("FT-SS-01".to_string())]);
        // One key row, two published cases: two graded rows, neither picked.
        assert_eq!(
            of("2944", "panda tiger fox"),
            [
                Some("FT-SS-04".to_string()),
                Some("FT-SS-10-Hex".to_string())
            ]
        );
        // Neither case asks for tiger or fox alone.
        assert_eq!(of("2944", "tiger"), [None]);
        assert_eq!(of("2944", "fox"), [None]);
        assert_eq!(g.len(), 5);
    }

    #[test]
    fn the_headline_counts_each_key_row_once_when_a_map_is_given() {
        let key = parse_answer_key(KEY);
        let map = parse_case_table(CASES).windows;
        let g = grade_all(&key, &reported(), false, &Recovered::unknown(), Some(&map));
        assert_eq!(g.len(), 5, "one row per (key row, case)");
        assert_eq!(distinct_rows(&g).len(), 4, "one row per key row");
    }

    #[test]
    fn grade_all_without_a_map_leaves_assertion_none() {
        let key = parse_answer_key(KEY);
        let g = grade_all(&key, &reported(), false, &Recovered::unknown(), None);
        assert_eq!(g.len(), 4);
        assert!(g.iter().all(|r| r.assertion.is_none()));
    }

    #[test]
    fn the_per_case_rollup_counts_each_case_and_the_unnamed_rows() {
        let key = parse_answer_key(KEY);
        let map = parse_case_table(CASES).windows;
        let g = grade_all(&key, &reported(), false, &Recovered::unknown(), Some(&map));
        let r = rollup(&g);
        assert_eq!(r.get("FT-SS-04").map(|s| s.total()), Some(1));
        assert_eq!(r.get("FT-SS-10-Hex").map(|s| s.total()), Some(1));
        assert_eq!(r.get("FT-SS-01").map(|s| s.total()), Some(1));
        assert_eq!(
            r.get(seance_validate::cftt::cases_map::NO_CASE)
                .map(|s| s.total()),
            Some(2)
        );
    }

    const EXT_01: &str = include_str!("../../tests/fixtures/cftt_dfr/ext-01.txt");

    #[test]
    fn dfr_results_json_round_trips_into_reported_dfr() {
        let json = r#"[{"image":"dfr-01-ext.dd","ingest_complete":true,"entries":[
            {"name":"Bellatrix.txt","path":"/ext2/Bellatrix.txt","size":712,"deleted":true,
             "has_content":true,"sectors":[[7231,7232]]}]}]"#;
        let r = parse_dfr_results(json).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].ingest_complete);
        let e = &r[0].entries.as_ref().unwrap()[0];
        assert_eq!(e.name, "Bellatrix.txt");
        assert_eq!(e.sectors.as_deref(), Some(&[(7231, 7232)][..]));
        let back = serde_json::to_string(&r).unwrap();
        assert_eq!(parse_dfr_results(&back).unwrap(), r);
    }

    #[test]
    fn dfr_mode_rejects_results_without_an_ingest_complete_flag_as_not_assessed() {
        let json = r#"[{"image":"dfr-01-ext.dd","entries":[
            {"name":"Bellatrix.txt","deleted":true,"has_content":true}]}]"#;
        let r = parse_dfr_results(json).unwrap();
        assert!(!r[0].ingest_complete);
        let g = grade_run(&parse_layout(EXT_01), &r, &[]);
        assert!(!g.is_empty());
        assert!(
            g.iter().all(|x| x.status == CaseStatus::NotAssessed),
            "{g:#?}"
        );
    }

    #[test]
    fn a_reported_image_with_no_truth_section_is_one_not_assessed_row() {
        let r =
            parse_dfr_results(r#"[{"image":"dfr-99-ext.dd","ingest_complete":true,"entries":[]}]"#)
                .unwrap();
        let g = grade_run(&parse_layout(EXT_01), &r, &[]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].status, CaseStatus::NotAssessed);
        assert_eq!(g[0].image, "dfr-99-ext.dd");
    }

    /// Corpus-gated on `SEANCE_CFTT_DFR` (NIST's DFR directory) and
    /// `SEANCE_CFTT_DFR_RESULTS` (a `results.json` that
    /// `scripts/cftt/run-dfr.sh` wrote with dfr-01-ext.dd in it). It grades
    /// a recorded run; it does not ingest the image itself.
    #[test]
    fn dfr_01_ext_three_deleted_files_are_listed() {
        let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_CFTT_DFR") else {
            return;
        };
        let Ok(results) = std::env::var("SEANCE_CFTT_DFR_RESULTS") else {
            eprintln!("skipped: SEANCE_CFTT_DFR_RESULTS names no recorded run");
            return;
        };
        let out = std::process::Command::new("pdftotext")
            .arg("-layout")
            .arg(dir.join("setup-july-10-2012.pdf"))
            .arg("-")
            .output()
            .expect("pdftotext");
        let layout = parse_layout(&String::from_utf8(out.stdout).unwrap());
        let run: Vec<ReportedDfr> = parse_dfr_results(&std::fs::read_to_string(results).unwrap())
            .unwrap()
            .into_iter()
            .filter(|r| r.image.ends_with("dfr-01-ext.dd"))
            .collect();
        assert_eq!(run.len(), 1, "the recorded run has no dfr-01-ext.dd");
        let g = grade_run(&layout, &run, &[]);
        for f in ["Bellatrix.txt", "Bunda.txt", "Botein.txt"] {
            let r = g
                .iter()
                .find(|r| r.assertion == "DFR-CR-01" && r.file.as_deref() == Some(f))
                .unwrap();
            assert_eq!(r.status, CaseStatus::Pass, "{r:#?}");
        }
    }
}
