//! The CFTT String Search case table: which published test case (`FT-SS-01`
//! … `FT-SS-10-Regex`) asks for which hit ids (`ROADMAP` §5.2).
//!
//! The answer key (`win_string_doc.txt`) gives, per hit id, the term and where
//! it is, and **never which test case the hit serves**. That mapping is in the
//! data set's `Expected Results by ID v1.1 9-27-19.docx`: a table of
//! Case/String, Encoding, Active ids, Deleted ids and (on the Windows set)
//! Unalloc ids, for both the MS Windows and the UNIX data set. This module
//! reads that table, so a graded row can say which published case it is
//! evidence for.
//!
//! Two properties of the published table the reader has to hold:
//!
//! * **An id can serve more than one case.** Id 2944 is under `FT-SS-04`
//!   ("Panda and fox") and under `FT-SS-10-Hex` ("panda"). Each is its own
//!   graded row; neither is picked over the other.
//! * **An id can carry more than one term in the key.** Id 2944 is three key
//!   rows (`panda tiger fox`, `tiger`, `fox`). A case entry is attached only to
//!   the key row whose term holds every positive word of the case's query, so
//!   neither case above is graded on `tiger`, which neither asks for. Where no
//!   single row qualifies the entry is reported as unresolved, not guessed.
//!
//! The publisher's cells are kept as written: encodings appear as `ascii`,
//! `Ascii`, `U-16-le`, `utf-16-le` and a bare `UTF`, and are normalised only
//! for display ([`normalise_encoding`]); a bare `UTF` stays `UTF`, because the
//! table does not say which UTF it means.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use super::string_search::{AnswerKey, Expectation};

/// Which of the two published data sets a table section describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataSet {
    /// `ss-win-07-25-18.dd`, graded against `win_string_doc.txt`.
    Windows,
    /// `ss-unix-07-25-18.dd`, graded against `unix_string_doc.txt`.
    Unix,
}

impl DataSet {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Windows => "MS Windows",
            Self::Unix => "UNIX",
        }
    }
}

/// Which column of the case table an id was listed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaseLocus {
    Active,
    Deleted,
    Unalloc,
}

/// One id the case table lists under one case, query and encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseEntry {
    /// `FT-SS-04`, `FT-SS-07-Cyrillic` and so on, as published.
    pub case: String,
    /// The case's query as published, trailing space removed (a leading space
    /// is kept: `" Wolf"` is a different query from `"Wolf"`).
    pub query: String,
    /// The encoding cell as published.
    pub encoding: String,
    pub locus: CaseLocus,
    /// The hit id, four digits as published.
    pub id: String,
}

/// A table row the parser could not read. Reported, never dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedCaseRow {
    pub line: usize,
    pub raw: String,
    pub why: String,
}

/// The case table for one data set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaseMap {
    pub entries: Vec<CaseEntry>,
}

/// Both data sets' case tables, and what could not be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaseTables {
    pub windows: CaseMap,
    pub unix: CaseMap,
    pub rejected: Vec<RejectedCaseRow>,
}

impl CaseTables {
    pub fn for_set(&self, set: DataSet) -> &CaseMap {
        match set {
            DataSet::Windows => &self.windows,
            DataSet::Unix => &self.unix,
        }
    }
}

/// A case entry the key could not resolve to exactly one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    pub entry: CaseEntry,
    pub why: String,
}

impl CaseMap {
    /// The published case labels, in table order, each once.
    pub fn cases(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for e in &self.entries {
            if !out.contains(&e.case.as_str()) {
                out.push(&e.case);
            }
        }
        out
    }

    /// Every case that names this id, each once, in table order. By id alone:
    /// see [`Self::cases_for`] for the key-row-aware lookup a grader wants.
    pub fn cases_naming(&self, id: &str) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for e in self.entries.iter().filter(|e| e.id == id) {
            if !out.contains(&e.case.as_str()) {
                out.push(&e.case);
            }
        }
        out
    }

    /// Every entry of one case.
    pub fn entries_of(&self, case: &str) -> Vec<&CaseEntry> {
        self.entries.iter().filter(|e| e.case == case).collect()
    }

    /// The cases a key row serves: each case with an entry for the row's id
    /// whose query this row answers. Where the key has one row for the id, it
    /// answers every entry for that id; where it has several (id 2944), only
    /// the row whose term holds every positive word of the query does.
    pub fn cases_for(&self, row: &Expectation, key: &AnswerKey) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for e in self.entries.iter().filter(|e| e.id == row.id) {
            if out.contains(&e.case.as_str()) {
                continue;
            }
            if let Ok(hit) = resolve_entry(e, key) {
                if std::ptr::eq(hit, row) || (hit.id == row.id && hit.term == row.term) {
                    out.push(&e.case);
                }
            }
        }
        out
    }

    /// Entries that resolve to no key row, or to more than one.
    pub fn unresolved(&self, key: &AnswerKey) -> Vec<Unresolved> {
        self.entries
            .iter()
            .filter_map(|e| {
                resolve_entry(e, key).err().map(|why| Unresolved {
                    entry: e.clone(),
                    why,
                })
            })
            .collect()
    }
}

/// The one key row a case entry names: the only row with its id, or, where
/// the id carries several terms, the only one whose term holds every positive
/// word of the query. Anything else is an error that says why.
fn resolve_entry<'k>(entry: &CaseEntry, key: &'k AnswerKey) -> Result<&'k Expectation, String> {
    let rows: Vec<&Expectation> = key
        .expectations
        .iter()
        .filter(|k| k.id == entry.id)
        .collect();
    match rows.as_slice() {
        [] => Err(format!("the answer key has no row {}", entry.id)),
        [one] => Ok(one),
        several => {
            let words = positive_words(&entry.query);
            let answering: Vec<&&Expectation> = several
                .iter()
                .filter(|k| {
                    let term = k.term.to_lowercase();
                    !words.is_empty() && words.iter().all(|w| term.contains(w.as_str()))
                })
                .collect();
            match answering.as_slice() {
                [one] => Ok(one),
                [] => Err(format!(
                    "the key has {} rows at id {} and none holds every word of {:?}",
                    several.len(),
                    entry.id,
                    entry.query
                )),
                many => Err(format!(
                    "the key has {} rows at id {} that each hold every word of {:?}; not guessed",
                    many.len(),
                    entry.id,
                    entry.query
                )),
            }
        }
    }
}

/// `U-16-le` → `utf-16-le`, `Ascii` → `ascii`. A bare `UTF` is returned as
/// written, because the table does not say which UTF it means.
pub fn normalise_encoding(cell: &str) -> String {
    let c = cell.trim();
    let lower = c.to_ascii_lowercase();
    if c == "UTF" {
        return c.to_string();
    }
    match lower.strip_prefix("u-16-") {
        Some(rest) => format!("utf-16-{rest}"),
        None => lower,
    }
}

/// The words of a query a matching term must hold: annotations such as
/// `(NFD)` removed, `and` dropped, and a word after `not` excluded.
fn positive_words(query: &str) -> Vec<String> {
    // Drop parenthesised annotations: "Mäuse (NFD)" is the query "Mäuse".
    let mut plain = String::new();
    let mut depth = 0usize;
    for ch in query.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            c if depth == 0 => plain.push(c),
            _ => {}
        }
    }
    let mut out = Vec::new();
    let mut negate = false;
    for w in plain.split_whitespace() {
        let lw = w.to_lowercase();
        match lw.as_str() {
            "and" | "or" => {}
            "not" => negate = true,
            _ if negate => negate = false,
            _ => out.push(lw),
        }
    }
    out
}

/// Render `word/document.xml` as one line per table row, cells separated by
/// `|`, all tags dropped. This is the text form [`parse_case_table`] reads,
/// and the form the tests quote.
pub fn render_document_xml(xml: &str) -> String {
    let mut out = String::new();
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        out.push_str(&unescape(&rest[..lt]));
        let Some(gt) = rest[lt..].find('>') else {
            rest = "";
            break;
        };
        let tag = &rest[lt + 1..lt + gt];
        if tag == "/w:tc" {
            out.push('|');
        } else if tag == "/w:tr" {
            out.push('\n');
        }
        rest = &rest[lt + gt + 1..];
    }
    out.push_str(&unescape(rest));
    out
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Parse the rendered case table.
pub fn parse_case_table(text: &str) -> CaseTables {
    let mut out = CaseTables::default();
    let mut set: Option<DataSet> = None;
    let mut case: Option<String> = None;
    let mut query: Option<String> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = n + 1;
        let reject = |out: &mut CaseTables, why: &str| {
            out.rejected.push(RejectedCaseRow {
                line,
                raw: raw.to_string(),
                why: why.to_string(),
            })
        };
        if raw.contains("MS Windows Data Set") {
            (set, case, query) = (Some(DataSet::Windows), None, None);
            continue;
        }
        if raw.contains("UNIX Data Set") {
            (set, case, query) = (Some(DataSet::Unix), None, None);
            continue;
        }
        if raw.trim().is_empty() || raw.starts_with("Case/String|") {
            continue;
        }
        let mut cells: Vec<&str> = raw.split('|').collect();
        if cells.last().is_some_and(|c| c.trim().is_empty()) {
            cells.pop();
        }
        let first = cells.first().copied().unwrap_or("");
        if first.trim().starts_with("FT-SS-") && cells[1..].iter().all(|c| c.trim().is_empty()) {
            case = Some(first.trim().to_string());
            query = None;
            continue;
        }
        let (Some(set_now), Some(case_now)) = (set, case.clone()) else {
            reject(&mut out, "a row before any data set and case heading");
            continue;
        };
        let enc = cells.get(1).map(|c| c.trim()).unwrap_or("");
        if !first.trim().is_empty() {
            query = Some(first.trim_end().to_string());
            if enc.is_empty() && cells[1..].iter().all(|c| c.trim().is_empty()) {
                // The heading of a multi-encoding block; its rows follow.
                continue;
            }
        }
        let Some(query_now) = query.clone() else {
            reject(&mut out, "an encoding row with no query above it");
            continue;
        };
        if enc.is_empty() {
            reject(&mut out, "a row with ids and no encoding");
            continue;
        }
        let mut entries = Vec::new();
        let mut bad = None;
        for (col, locus) in [
            (2, CaseLocus::Active),
            (3, CaseLocus::Deleted),
            (4, CaseLocus::Unalloc),
        ] {
            for id in cells.get(col).copied().unwrap_or("").split_whitespace() {
                if id.len() == 4 && id.bytes().all(|b| b.is_ascii_digit()) {
                    entries.push(CaseEntry {
                        case: case_now.clone(),
                        query: query_now.clone(),
                        encoding: enc.to_string(),
                        locus,
                        id: id.to_string(),
                    });
                } else {
                    bad = Some(id.to_string());
                }
            }
        }
        if let Some(bad) = bad {
            reject(&mut out, &format!("{bad:?} is not a four-digit hit id"));
            continue;
        }
        if cells.len() > 5 {
            reject(
                &mut out,
                "more cells than Case/String, Encoding, Active, Deleted, Unalloc",
            );
            continue;
        }
        match set_now {
            DataSet::Windows => out.windows.entries.extend(entries),
            DataSet::Unix => out.unix.entries.extend(entries),
        }
    }
    out
}

/// Load the case table from the published `.docx`, from its extracted
/// `word/document.xml`, or from text already in the rendered form.
pub fn load(path: &Path) -> anyhow::Result<CaseTables> {
    let bytes = std::fs::read(path)?;
    let text = if bytes.starts_with(b"PK\x03\x04") {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        let mut xml = String::new();
        archive
            .by_name("word/document.xml")?
            .read_to_string(&mut xml)?;
        render_document_xml(&xml)
    } else {
        let s = String::from_utf8(bytes)?;
        if s.contains("<w:tr") {
            render_document_xml(&s)
        } else {
            s
        }
    };
    Ok(parse_case_table(&text))
}

/// Per-case rollup key: rows no case names go under this label.
pub const NO_CASE: &str = "(no published case names this row)";

/// Group graded rows by case label, keeping [`NO_CASE`] for rows with none.
pub fn by_case<T, F: Fn(&T) -> Option<&str>>(rows: &[T], case_of: F) -> BTreeMap<String, Vec<&T>> {
    let mut out: BTreeMap<String, Vec<&T>> = BTreeMap::new();
    for r in rows {
        out.entry(case_of(r).unwrap_or(NO_CASE).to_string())
            .or_default()
            .push(r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cftt::string_search::parse_answer_key;

    /// Quoted from `Expected Results by ID v1.1 9-27-19.docx` (NIST, public
    /// domain), rendered by [`render_document_xml`]: the Windows set's
    /// FT-SS-04 block, its FT-SS-07-Cyrillic block, FT-SS-10-Hex, and the
    /// start of the UNIX set.
    const EXCERPT: &str = "\
Expected ResultsData Set Version: 1-1, Revised 09-27-19Tested Tool: ___MS Windows Data Set|
Case/String|Encoding|Active|Deleted|Unalloc|
FT-SS-04|
Panda and fox| ascii | 2944 2946 2948 | 2945 2947 2949 ||
FT-SS-07-Cyrillic|
Сибирь |||||
| utf-16-be | 1187 1195 1203 | 1191 1199 1207 | 1211|
| utf-16-le | 1186 1194 1202 | 1190 1198 1206 | 1210|
| utf-8 | 1185 1193 1201 | 1189 1197 1205 | 1209|
FT-SS-10-Hex|
panda| ascii | 2944 2946 2948 | 2945 2947 2949 | 2950|
DONEUNIX Data Set|
Case/String|Enc|Active|Deleted|
FT-SS-04|
panda and fox|ascii|2952 2954 2956 2958|2953 2955 2957 2959|
";

    fn ids(m: &CaseMap, case: &str, locus: CaseLocus) -> Vec<String> {
        m.entries_of(case)
            .into_iter()
            .filter(|e| e.locus == locus)
            .map(|e| e.id.clone())
            .collect()
    }

    #[test]
    fn the_real_ft_ss_04_block_parses_into_one_case_with_active_and_deleted_ids() {
        let t = parse_case_table(EXCERPT);
        assert!(t.rejected.is_empty(), "{:?}", t.rejected);
        let w = &t.windows;
        assert_eq!(
            ids(w, "FT-SS-04", CaseLocus::Active),
            ["2944", "2946", "2948"]
        );
        assert_eq!(
            ids(w, "FT-SS-04", CaseLocus::Deleted),
            ["2945", "2947", "2949"]
        );
        assert!(ids(w, "FT-SS-04", CaseLocus::Unalloc).is_empty());
        assert!(w
            .entries_of("FT-SS-04")
            .iter()
            .all(|e| e.query == "Panda and fox" && e.encoding == "ascii"));
        // The UNIX set is its own table, with its own ids and no Unalloc column.
        assert_eq!(
            ids(&t.unix, "FT-SS-04", CaseLocus::Active),
            ["2952", "2954", "2956", "2958"]
        );
        assert_eq!(
            t.windows.cases(),
            ["FT-SS-04", "FT-SS-07-Cyrillic", "FT-SS-10-Hex"]
        );
    }

    #[test]
    fn an_id_under_two_cases_maps_to_both() {
        let t = parse_case_table(EXCERPT);
        assert_eq!(t.windows.cases_naming("2944"), ["FT-SS-04", "FT-SS-10-Hex"]);
        assert_eq!(t.windows.cases_naming("2950"), ["FT-SS-10-Hex"]);
        assert!(t.windows.cases_naming("0001").is_empty());
    }

    #[test]
    fn a_multi_encoding_case_keeps_each_encoding_row() {
        let t = parse_case_table(EXCERPT);
        let c = t.windows.entries_of("FT-SS-07-Cyrillic");
        assert_eq!(c.len(), 21, "three encodings x seven ids");
        assert!(c.iter().all(|e| e.query == "Сибирь"));
        let be: Vec<&str> = c
            .iter()
            .filter(|e| e.encoding == "utf-16-be")
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(be, ["1187", "1195", "1203", "1191", "1199", "1207", "1211"]);
        let e1211 = c.iter().find(|e| e.id == "1211").unwrap();
        assert_eq!(e1211.locus, CaseLocus::Unalloc);
    }

    /// The three key rows at id 2944, quoted from `win_string_doc.txt`.
    const KEY_2944: &str = "\
2944:fox:9692350:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
2944:panda tiger fox:9692338:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
2944:tiger:9692344:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
1187:Сибирь:9512324:18578:LIVE-Siberia-fat-utf-16-be.txt:fat32:utf-16-be
";

    #[test]
    fn a_shared_id_attaches_both_cases_to_the_row_that_answers_them_and_neither_to_tiger() {
        let t = parse_case_table(EXCERPT);
        let key = parse_answer_key(KEY_2944);
        let row = |term: &str| {
            key.expectations
                .iter()
                .find(|e| e.id == "2944" && e.term == term)
                .unwrap()
        };
        assert_eq!(
            t.windows.cases_for(row("panda tiger fox"), &key),
            ["FT-SS-04", "FT-SS-10-Hex"]
        );
        assert!(t.windows.cases_for(row("tiger"), &key).is_empty());
        assert!(t.windows.cases_for(row("fox"), &key).is_empty());
        let sib = key.expectations.iter().find(|e| e.id == "1187").unwrap();
        assert_eq!(t.windows.cases_for(sib, &key), ["FT-SS-07-Cyrillic"]);
    }

    #[test]
    fn an_entry_whose_id_the_key_lacks_is_reported_unresolved() {
        let t = parse_case_table(EXCERPT);
        let key = parse_answer_key(KEY_2944);
        let u = t.windows.unresolved(&key);
        assert!(u.iter().any(|u| u.entry.id == "2946"), "{u:?}");
        assert!(!u.iter().any(|u| u.entry.id == "2944"), "{u:?}");
    }

    #[test]
    fn positive_words_drop_connectives_negations_and_annotations() {
        assert_eq!(positive_words("Panda and fox"), ["panda", "fox"]);
        assert_eq!(positive_words("fox and not tiger"), ["fox"]);
        assert_eq!(positive_words("Mäuse (NFD)"), ["mäuse"]);
        assert_eq!(positive_words(" Wolf"), ["wolf"]);
    }

    #[test]
    fn encodings_are_normalised_for_display_and_a_bare_utf_is_left_alone() {
        assert_eq!(normalise_encoding(" U-16-le "), "utf-16-le");
        assert_eq!(normalise_encoding("Ascii"), "ascii");
        assert_eq!(normalise_encoding("UTF"), "UTF");
    }

    #[test]
    fn a_row_outside_any_case_is_rejected_not_dropped() {
        let t = parse_case_table("MS Windows Data Set|\nstray| ascii | 0001 ||\n");
        assert_eq!(t.rejected.len(), 1, "{:?}", t.rejected);
        let t = parse_case_table("MS Windows Data Set|\nFT-SS-01|\nx| ascii | 12ab ||\n");
        assert_eq!(t.rejected.len(), 1, "{:?}", t.rejected);
    }

    #[test]
    fn document_xml_renders_one_line_per_row_and_one_bar_per_cell() {
        let xml = "<w:tbl><w:tr><w:tc><w:p><w:r><w:t>FT-SS-04</w:t></w:r></w:p></w:tc></w:tr>\
                   <w:tr><w:tc><w:p><w:r><w:t>Panda and fox</w:t></w:r></w:p></w:tc>\
                   <w:tc><w:p><w:r><w:t xml:space=\"preserve\"> ascii </w:t></w:r></w:p></w:tc>\
                   <w:tc><w:p><w:r><w:t>2944</w:t></w:r></w:p></w:tc></w:tr></w:tbl>";
        assert_eq!(
            render_document_xml(xml),
            "FT-SS-04|\nPanda and fox| ascii |2944|\n"
        );
        assert_eq!(
            render_document_xml("<w:t>a &amp; b</w:t></w:tr>"),
            "a & b\n"
        );
    }

    /// Corpus-gated on `SEANCE_CFTT_SS`: the published .docx, read end to end,
    /// against the published key. Every id the Windows table names must be a
    /// row of `win_string_doc.txt`, and the case set is the 25 labels the
    /// table carries (measured 2026-09-26).
    #[test]
    fn every_id_in_the_case_map_exists_in_win_string_doc() {
        let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_CFTT_SS") else {
            return;
        };
        let d = dir
            .join("string-search-federated-testing-data-set-version-1-1-revised-september-27-2019");
        let docx = d.join("Expected Results by ID v1.1 9-27-19.docx");
        let key = d.join("win_string_doc.txt");
        if !docx.exists() || !key.exists() {
            panic!(
                "SEANCE_CFTT_SS is set but {} or {} is missing",
                docx.display(),
                key.display()
            );
        }
        let t = load(&docx).unwrap();
        assert!(t.rejected.is_empty(), "unread rows: {:?}", t.rejected);
        let key = parse_answer_key(&std::fs::read_to_string(key).unwrap());
        let w = &t.windows;
        assert_eq!(w.cases().len(), 25, "{:?}", w.cases());
        for c in [
            "FT-SS-01",
            "FT-SS-04",
            "FT-SS-09-Lost",
            "FT-SS-10-Hex",
            "FT-SS-10-Regex",
        ] {
            assert!(w.cases().contains(&c), "{c} missing");
        }
        let missing: Vec<&CaseEntry> = w
            .entries
            .iter()
            .filter(|e| !key.expectations.iter().any(|k| k.id == e.id))
            .collect();
        assert!(
            missing.is_empty(),
            "ids the key does not carry: {missing:?}"
        );
        assert!(w.unresolved(&key).is_empty(), "{:?}", w.unresolved(&key));
        assert_eq!(w.cases_naming("2944"), ["FT-SS-04", "FT-SS-10-Hex"]);
        assert!(!t.unix.entries.is_empty());
    }
}
