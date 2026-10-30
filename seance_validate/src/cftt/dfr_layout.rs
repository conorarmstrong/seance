//! Ground truth for the NIST CFTT Deleted File Recovery (DFR) images, read
//! from NIST's own layout document (`ROADMAP` §5.2).
//!
//! The source is `setup-july-10-2012.pdf` ("Test Images layout.docx",
//! 290 pages), turned into text with `pdftotext -layout`. It has one section
//! per test image (`1 Test Image ext-01` … `91 Test Image xfat-17`), and each
//! section states, in fixed text form: the DFR scenario (`DFR-01.  Recover one
//! non-fragmented file.`); a `Deleted files (N)` table of Name, Size,
//! F-Hd and F-Bks; the steps that built the image; the overwrites (`9
//! overwrites` then one `A x B: overlap - s - e` line each, or `No
//! overwrites`); a per-file `File: <name> <sectors> <intact>` line; a
//! `Summary:` line; how many deleted files still have metadata and which do
//! not; a layout history (which is where a file's partial last sector,
//! `TAIL/<stem>`, is recorded); and a `Sector List` of every file's sector
//! runs.
//!
//! **What this truth cannot say**, which the grader carries forward:
//!
//! * **NIST elided rows from its own document.** Long tables break off at
//!   `  ...` followed by `<N> omitted` (67 places, measured 2026-09-27). The
//!   rows are not in the published text, so a file among them has no name,
//!   size or sectors here. [`DfrImageTruth::omitted_deleted`] and
//!   [`DfrImageTruth::omitted_sectors`] count them; a grader must report such
//!   files as not assessed, never as found or missed.
//! * **The deleted-file table of `osx-04` lists placeholder names**
//!   (`/tmp/dfr-04/BeiJing.txt`); the non-Latin names the image really holds
//!   (`北京.txt`) are in its creation steps (`/tmp/BeiJing.txt => 北京.txt)`)
//!   and delete actions. [`DfrImageTruth::renamed`] carries that mapping.
//! * The document writes right-to-left names with Unicode embedding controls
//!   around them (U+202B … U+202C). Those are the PDF's rendering, not part of
//!   a file name, and [`strip_bidi_controls`] removes them.
//!
//! Sector numbers are as NIST states them: 512-byte sectors from the start of
//! the image (the layout's partition table gives partition starts in the same
//! units).

use std::collections::BTreeMap;

/// One row of a section's `Deleted files (N)` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfrDeleted {
    /// As written in the table. On `osx-04` a placeholder path; see
    /// [`DfrImageTruth::real_name`].
    pub name: String,
    pub size: u64,
    /// `(8+200)`: full sectors and bytes in the partial last one.
    pub full_sectors: u64,
    pub tail_bytes: u64,
    /// The `F-Hd` and `F-Bks` columns, kept as written; the document does
    /// not define them and this parser does not guess.
    pub f_hd: u64,
    pub f_bks: u64,
}

/// One `A x B: overlap - s - e[, s - e]` line: deleted file `victim`'s
/// sectors in `runs` were overwritten by `by`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfrOverwrite {
    pub victim: String,
    pub by: String,
    pub runs: Vec<(u64, u64)>,
}

/// The `Summary: a b c d` line: deleted files, then (by the arithmetic of
/// every section, a = b + c + d) intact, partly overwritten and wholly
/// overwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DfrSummary {
    pub files: u64,
    pub intact: u64,
    pub partial: u64,
    pub overwritten: u64,
}

/// The ground truth for one test image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DfrImageTruth {
    /// `ext-01`, `ntfs-11-compress`, `osx-04` — as the layout names it.
    pub image: String,
    /// `DFR-01` … `DFR-14`, or `None` for the sections with no scenario line
    /// (the active-file listings `ext-15` … `ext-17` and their kin).
    pub scenario: Option<String>,
    pub scenario_text: String,
    /// The `N files deleted` / `Deleted files (N)` count as declared.
    pub declared_deleted: u64,
    pub deleted: Vec<DfrDeleted>,
    /// Deleted-table rows NIST elided (`<N> omitted`).
    pub omitted_deleted: u64,
    /// Empty for `No overwrites`.
    pub overwrites: Vec<DfrOverwrite>,
    /// The `N overwrites` figure. It is **not** the number of lines NIST
    /// prints: long lists stop at 100 lines with no marker (`ext-10` declares
    /// 1451), and some sections print fewer lines than the figure for reasons
    /// the document does not give. So the overwrite lines are informative,
    /// and the per-file `File:` counts ([`Self::file_status`]) are what says
    /// how much of a deleted file survives.
    pub declared_overwrites: u64,
    /// Set when the lines printed are fewer than [`Self::declared_overwrites`].
    pub overwrites_incomplete: bool,
    /// `File: <name> <sectors> <intact sectors>`.
    pub file_status: BTreeMap<String, (u64, u64)>,
    pub summary: Option<DfrSummary>,
    /// `Metadata found N files, not found M`. **Not reliable on its own**:
    /// on `ext-04`, `fat-04` and `osx-04` it reads "found 0" and the next line
    /// reads "Metadata available for all deleted files" -- the count comes
    /// from matching placeholder names that are not on the image. Kept as
    /// written; the grader uses [`Self::without_metadata`].
    pub metadata_found: Option<u64>,
    pub metadata_not_found: Option<u64>,
    /// `Deleted files without metadata (cannot be found)`: the names NIST
    /// itself says a tool cannot find by metadata.
    pub without_metadata: Vec<String>,
    /// Entries of that list NIST's document elides (`<N> omitted`). While
    /// non-zero, a file absent from the visible list cannot be said to have
    /// metadata.
    pub without_metadata_omitted: u64,
    /// Every file's sector runs from the `Sector List`, with the partial last
    /// sector the layout history records as `TAIL/<stem>` merged in.
    pub sectors: BTreeMap<String, Vec<(u64, u64)>>,
    /// Sector-list rows NIST elided.
    pub omitted_sectors: u64,
    /// Files whose sector-list row NIST cut short -- an elision through the
    /// row (`… 1689040`, `30 omitted`, `1689055`) or a row ending
    /// `. . . + 1254 more`: their runs are not known and are not in
    /// [`Self::sectors`].
    pub incomplete_sectors: Vec<String>,
    /// `osx-04`: placeholder base name → the name on the image.
    pub renamed: BTreeMap<String, String>,
}

impl DfrImageTruth {
    /// The image file this section describes, as NIST ships it:
    /// `ext-01` → `dfr-01-ext.dd`, `ext-01-recycle` → `dfr-01-recycle-ext.dd`.
    pub fn dd_name(&self) -> String {
        let mut parts = self.image.splitn(3, '-');
        let fs = parts.next().unwrap_or("");
        let nn = parts.next().unwrap_or("");
        match parts.next() {
            Some(variant) => format!("dfr-{nn}-{variant}-{fs}.dd"),
            None => format!("dfr-{nn}-{fs}.dd"),
        }
    }

    /// The file system family: `ext`, `fat`, `ntfs`, `osx`, `xfat`.
    pub fn fs(&self) -> &str {
        self.image.split('-').next().unwrap_or("")
    }

    /// A deleted row's name as the image holds it: the base name, mapped
    /// through [`Self::renamed`] where the table lists a placeholder.
    pub fn real_name(&self, d: &DfrDeleted) -> String {
        let base = base_name(&d.name);
        self.renamed
            .get(base)
            .cloned()
            .unwrap_or_else(|| base.to_string())
    }

    /// Whether NIST says this deleted file cannot be found by metadata.
    pub fn is_without_metadata(&self, name: &str) -> bool {
        self.without_metadata.iter().any(|n| n == name)
    }

    /// Every sector a deleted file occupied, as runs.
    pub fn sectors_of(&self, name: &str) -> Option<&[(u64, u64)]> {
        self.sectors.get(base_name(name)).map(Vec::as_slice)
    }
}

/// A section the parser could not read consistently. Reported, never
/// dropped: the grader grades nothing on it and says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedSection {
    pub image: String,
    pub why: String,
}

/// Every section of the layout document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DfrLayout {
    pub images: Vec<DfrImageTruth>,
    pub rejected: Vec<RejectedSection>,
}

impl DfrLayout {
    pub fn image(&self, name: &str) -> Option<&DfrImageTruth> {
        self.images.iter().find(|i| i.image == name)
    }

    /// The truth for a shipped image file name (`dfr-01-ext.dd`).
    pub fn for_dd(&self, dd: &str) -> Option<&DfrImageTruth> {
        self.images.iter().find(|i| i.dd_name() == dd)
    }
}

/// Remove Unicode bidirectional embedding and isolate controls.
pub fn strip_bidi_controls(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .collect()
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Parse the `pdftotext -layout` text of the layout document.
pub fn parse_layout(text: &str) -> DfrLayout {
    let mut out = DfrLayout::default();
    let mut cur: Option<Section> = None;
    for line in text.lines() {
        if line.starts_with("Last save ") {
            continue; // the page footer
        }
        if let Some(image) = section_heading(line) {
            if let Some(done) = cur.take() {
                done.finish(&mut out);
            }
            cur = Some(Section::new(image));
            continue;
        }
        if let Some(sec) = cur.as_mut() {
            sec.line(line);
        }
    }
    if let Some(done) = cur.take() {
        done.finish(&mut out);
    }
    out
}

/// `12 Test Image ext-07-two` → `ext-07-two`. The table of contents
/// (`Test Image ext-01 ....... 3`) has no leading number and is not a heading.
fn section_heading(line: &str) -> Option<String> {
    let mut t = line.split_whitespace();
    let n = t.next()?;
    if !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if (t.next()?, t.next()?) != ("Test", "Image") {
        return None;
    }
    let image = t.next()?;
    if t.next().is_some() || !image.contains('-') {
        return None;
    }
    Some(image.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Other,
    Deleted,
    Overwrites,
    WithoutMetadata,
    Layout,
    SectorList,
}

struct Section {
    t: DfrImageTruth,
    state: State,
    table_declared: Option<u64>,
    omitted_overwrites: u64,
    after_elision: bool,
    sector_rows: Vec<(String, String)>,
    tails: Vec<(String, u64, u64)>,
    problems: Vec<String>,
}

fn ints(s: &str) -> Option<Vec<u64>> {
    s.split_whitespace().map(|w| w.parse().ok()).collect()
}

/// `a - b, c - d` or `a - b c - d` → runs, and whether the row ends in
/// NIST's `. . . + N more` (runs elided). `None` when it is not that form.
fn runs_of(s: &str) -> Option<(Vec<(u64, u64)>, bool)> {
    let flat = s.replace(',', " ");
    let (shown, cut) = match flat.split_once(". . .") {
        Some((shown, _)) => (shown.to_string(), true),
        None => (flat, false),
    };
    let w: Vec<&str> = shown.split_whitespace().collect();
    if w.is_empty() || !w.len().is_multiple_of(3) {
        return None;
    }
    let mut runs = Vec::new();
    for c in w.chunks(3) {
        if c[1] != "-" {
            return None;
        }
        runs.push((c[0].parse().ok()?, c[2].parse().ok()?));
    }
    Some((runs, cut))
}

fn merge(runs: &mut Vec<(u64, u64)>) {
    runs.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(runs.len());
    for &(s, e) in runs.iter() {
        match merged.last_mut() {
            Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    *runs = merged;
}

fn stem(name: &str) -> &str {
    name.rsplit_once('.').map_or(name, |(s, _)| s)
}

impl Section {
    fn new(image: String) -> Self {
        Self {
            t: DfrImageTruth {
                image,
                ..Default::default()
            },
            state: State::Other,
            table_declared: None,
            omitted_overwrites: 0,
            after_elision: false,
            sector_rows: Vec::new(),
            tails: Vec::new(),
            problems: Vec::new(),
        }
    }

    fn line(&mut self, line: &str) {
        let t = line.trim();
        if t.is_empty() {
            if self.state == State::WithoutMetadata {
                self.state = State::Other;
            }
            return;
        }
        // The scenario line directly after the heading.
        if self.t.scenario.is_none() && t.starts_with("DFR-") {
            if let Some((id, rest)) = t.split_once('.') {
                self.t.scenario = Some(id.to_string());
                self.t.scenario_text = rest.trim().to_string();
                return;
            }
        }
        if t == "..." {
            return;
        }
        if let Some(n) = t
            .strip_suffix(" omitted")
            .and_then(|n| n.parse::<u64>().ok())
        {
            match self.state {
                State::Deleted => self.t.omitted_deleted += n,
                State::SectorList => {
                    self.t.omitted_sectors += n;
                    // The row before the elision may be cut short, and a
                    // continuation after it belongs to a row nobody can see.
                    if let Some((name, _)) = self.sector_rows.pop() {
                        self.t.incomplete_sectors.push(name);
                    }
                    self.after_elision = true;
                }
                State::Overwrites => self.omitted_overwrites += n,
                State::WithoutMetadata => self.t.without_metadata_omitted += n,
                _ => {}
            }
            return;
        }
        if let Some(n) = t
            .strip_suffix(" files deleted")
            .and_then(|n| n.parse().ok())
        {
            self.t.declared_deleted = n;
            self.state = State::Other;
            return;
        }
        if t.starts_with("Deleted files without metadata") {
            self.state = State::WithoutMetadata;
            return;
        }
        if let Some(n) = t
            .strip_prefix("Deleted files (")
            .and_then(|r| r.strip_suffix(')'))
            .and_then(|n| n.parse().ok())
        {
            self.table_declared = Some(n);
            self.state = State::Deleted;
            return;
        }
        if t == "No overwrites" {
            self.state = State::Other;
            return;
        }
        if let Some(n) = t.strip_suffix(" overwrites").and_then(|n| n.parse().ok()) {
            self.t.declared_overwrites = n;
            self.state = State::Overwrites;
            return;
        }
        if let Some(rest) = t.strip_prefix("Summary:") {
            match ints(rest).as_deref() {
                Some(&[files, intact, partial, overwritten]) => {
                    self.t.summary = Some(DfrSummary {
                        files,
                        intact,
                        partial,
                        overwritten,
                    })
                }
                _ => self.problems.push(format!("unreadable summary line {t:?}")),
            }
            self.state = State::Other;
            return;
        }
        if let Some(rest) = t.strip_prefix("File: ") {
            // `File: <name> <sectors> <intact>`; the MAC-times block's
            // ``File: `name'`` has no numbers and is not this line.
            let w: Vec<&str> = rest.split_whitespace().collect();
            if w.len() >= 3 {
                if let (Ok(a), Ok(b)) = (w[w.len() - 2].parse(), w[w.len() - 1].parse()) {
                    let name = strip_bidi_controls(&w[..w.len() - 2].join(" "));
                    self.t.file_status.insert(name, (a, b));
                    self.state = State::Other;
                    return;
                }
            }
        }
        if let Some((_, rest)) = t.split_once(" Metadata found ") {
            // `ext-01 Metadata found 3 files, not found 0, total 3 deleted files`
            let nums: Vec<u64> = rest
                .split(|c: char| !c.is_ascii_digit())
                .filter_map(|w| w.parse().ok())
                .collect();
            if let [found, not_found, ..] = nums[..] {
                self.t.metadata_found = Some(found);
                self.t.metadata_not_found = Some(not_found);
            }
            self.state = State::Other;
            return;
        }
        if t == "Layout History" {
            self.state = State::Layout;
            return;
        }
        if t == "Sector List" {
            self.state = State::SectorList;
            return;
        }
        if t.starts_with("MAC times")
            || t.starts_with("File delete times")
            || t.starts_with("Steps to Create Image")
            || t.starts_with("Partition Table Layout")
            || t.starts_with("Metadata available")
            || t.starts_with("Active Files")
        {
            self.state = State::Other;
            return;
        }
        // `1  create  /tmp/Naan.txt => नान.txt)` — osx-04's real names.
        if let Some((l, r)) = t.split_once(" => ") {
            if let Some(ph) = l
                .split_whitespace()
                .last()
                .and_then(|p| p.strip_prefix("/tmp/"))
            {
                let real = strip_bidi_controls(r.trim().trim_end_matches(')'));
                self.t.renamed.insert(base_name(ph).to_string(), real);
                return;
            }
        }
        match self.state {
            State::Deleted => self.deleted_row(t),
            State::Overwrites => self.overwrite_row(t),
            State::WithoutMetadata => self
                .t
                .without_metadata
                .extend(t.split_whitespace().map(strip_bidi_controls)),
            State::Layout => {
                // `7232 - 7232   TAIL/Bellatrix TAIL/Bellatrix`
                let w: Vec<&str> = t.split_whitespace().collect();
                if w.len() >= 4 && w[1] == "-" {
                    if let (Ok(a), Ok(b)) = (w[0].parse(), w[2].parse()) {
                        if let Some(stem) = w[w.len() - 1].strip_prefix("TAIL/") {
                            self.tails.push((stem.to_string(), a, b));
                        }
                    }
                }
            }
            State::SectorList => {
                if t.as_bytes()[0].is_ascii_digit() {
                    // A row wrapped onto the next line -- unless an elision
                    // came between, when it is the tail of an unseen row.
                    if self.after_elision {
                        return;
                    }
                    if let Some(last) = self.sector_rows.last_mut() {
                        last.1.push(' ');
                        last.1.push_str(t);
                    }
                } else if let Some((name, runs)) = t.split_once(char::is_whitespace) {
                    self.after_elision = false;
                    self.sector_rows
                        .push((strip_bidi_controls(name), runs.trim().to_string()));
                }
            }
            State::Other => {}
        }
    }

    fn deleted_row(&mut self, t: &str) {
        if t.starts_with("Name ") && t.contains("F-Hd") {
            return;
        }
        // `<name> <size> (<full>+<tail>) <F-Hd> <F-Bks>`; a name may hold spaces.
        let parsed = (|| {
            let (head, paren) = t.split_once(" (")?;
            let (inside, after) = paren.split_once(')')?;
            let (full, tail) = inside.split_once('+')?;
            let (name, size) = head.trim_end().rsplit_once(char::is_whitespace)?;
            let hb = ints(after)?;
            let [f_hd, f_bks] = hb[..] else { return None };
            Some(DfrDeleted {
                name: strip_bidi_controls(name.trim()),
                size: size.parse().ok()?,
                full_sectors: full.trim().parse().ok()?,
                tail_bytes: tail.trim().parse().ok()?,
                f_hd,
                f_bks,
            })
        })();
        match parsed {
            Some(d) => self.t.deleted.push(d),
            None => self
                .problems
                .push(format!("unreadable deleted-file row {t:?}")),
        }
    }

    fn overwrite_row(&mut self, t: &str) {
        // `Bellatrix.txt x FumAlSamakah.txt: overlap - 10305 - 10310`
        let parsed = (|| {
            let (pair, span) = t.split_once(": overlap - ")?;
            let (victim, by) = pair.split_once(" x ")?;
            let (runs, cut) = runs_of(span)?;
            if cut {
                return None;
            }
            Some(DfrOverwrite {
                victim: strip_bidi_controls(victim.trim()),
                by: strip_bidi_controls(by.trim()),
                runs,
            })
        })();
        match parsed {
            Some(o) => self.t.overwrites.push(o),
            None => self.state = State::Other,
        }
    }

    fn finish(mut self, out: &mut DfrLayout) {
        for (name, text) in std::mem::take(&mut self.sector_rows) {
            match runs_of(&text) {
                // NIST printed the first runs and `. . . + N more`: the
                // file's sectors are not all known.
                Some((_, true)) => self.t.incomplete_sectors.push(name),
                Some((runs, false)) => self.t.sectors.entry(name).or_default().extend(runs),
                None => self
                    .problems
                    .push(format!("unreadable sector runs {text:?} for {name}")),
            }
        }
        // A tail belongs to the one listed file with that stem; where two
        // files share a stem (osx-01's Capella.TXT and Capella.txt) it is
        // not guessed.
        for (st, a, b) in std::mem::take(&mut self.tails) {
            let owners: Vec<String> = self
                .t
                .sectors
                .keys()
                .filter(|n| stem(n) == st)
                .cloned()
                .collect();
            if let [only] = owners.as_slice() {
                self.t.sectors.get_mut(only).unwrap().push((a, b));
            }
        }
        for runs in self.t.sectors.values_mut() {
            merge(runs);
        }
        let declared = self.table_declared.unwrap_or(self.t.declared_deleted);
        if self.t.declared_deleted == 0 {
            self.t.declared_deleted = declared;
        }
        let listed = self.t.deleted.len() as u64 + self.t.omitted_deleted;
        if listed != self.t.declared_deleted {
            self.problems.push(format!(
                "{} deleted rows read and {} elided, but the section declares {}",
                self.t.deleted.len(),
                self.t.omitted_deleted,
                self.t.declared_deleted
            ));
        }
        self.t.overwrites_incomplete =
            (self.t.overwrites.len() as u64 + self.omitted_overwrites) < self.t.declared_overwrites;
        if self.problems.is_empty() {
            out.images.push(self.t);
        } else {
            out.rejected.push(RejectedSection {
                image: self.t.image,
                why: self.problems.join("; "),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Quoted from NIST's `setup-july-10-2012.pdf` (public domain) through
    /// `pdftotext -layout`: the whole `ext-01` section.
    const EXT_01: &str = include_str!("../../tests/fixtures/cftt_dfr/ext-01.txt");
    /// The whole `ext-07` section: nine overwrites.
    const EXT_07: &str = include_str!("../../tests/fixtures/cftt_dfr/ext-07.txt");
    /// The `osx-01` and `osx-04` sections.
    const OSX: &str = include_str!("../../tests/fixtures/cftt_dfr/osx-01-04.txt");

    #[test]
    fn ext_01_section_yields_three_deleted_712_byte_files_with_their_sectors() {
        let l = parse_layout(EXT_01);
        assert!(l.rejected.is_empty(), "{:?}", l.rejected);
        let t = l.image("ext-01").expect("ext-01 parsed");
        assert_eq!(t.scenario.as_deref(), Some("DFR-01"));
        assert_eq!(t.dd_name(), "dfr-01-ext.dd");
        assert_eq!(t.fs(), "ext");
        let names: Vec<&str> = t.deleted.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["Bellatrix.txt", "Bunda.txt", "Botein.txt"]);
        assert!(t
            .deleted
            .iter()
            .all(|d| d.size == 712 && d.full_sectors == 1 && d.tail_bytes == 200));
        // The Sector List states the full sector; the layout history's
        // TAIL/<stem> row adds the partial one.
        assert_eq!(t.sectors_of("Bellatrix.txt"), Some(&[(7231, 7232)][..]));
        assert_eq!(t.sectors_of("Bunda.txt"), Some(&[(658406, 658407)][..]));
        assert_eq!(t.sectors_of("Botein.txt"), Some(&[(1319378, 1319379)][..]));
        assert_eq!(t.sectors_of("Algol.txt"), Some(&[(6207, 6207)][..]));
        assert!(t.overwrites.is_empty());
        assert_eq!(
            t.summary,
            Some(DfrSummary {
                files: 3,
                intact: 3,
                partial: 0,
                overwritten: 0
            })
        );
        assert_eq!(t.metadata_found, Some(3));
        assert!(t.without_metadata.is_empty());
    }

    #[test]
    fn a_section_with_overwrites_records_them() {
        let l = parse_layout(EXT_07);
        assert!(l.rejected.is_empty(), "{:?}", l.rejected);
        let t = l.image("ext-07").unwrap();
        assert_eq!(t.scenario.as_deref(), Some("DFR-07"));
        assert_eq!(t.declared_deleted, 15);
        assert_eq!(t.deleted.len(), 15);
        assert_eq!(t.declared_overwrites, 9);
        assert_eq!(t.overwrites.len(), 9);
        assert_eq!(
            t.overwrites[0],
            DfrOverwrite {
                victim: "Bellatrix.txt".into(),
                by: "FumAlSamakah.txt".into(),
                runs: vec![(10305, 10310)],
            }
        );
        assert_eq!(t.file_status.get("Diadem.TXT"), Some(&(8, 6)));
        assert_eq!(
            t.summary,
            Some(DfrSummary {
                files: 15,
                intact: 6,
                partial: 1,
                overwritten: 8
            })
        );
        assert_eq!(
            t.without_metadata,
            [
                "Bellatrix.txt",
                "Botein.txt",
                "Bunda.txt",
                "Canopus.txt",
                "Castor.txt",
                "Chort.txt"
            ]
        );
    }

    /// The plan read `osx-01` as "expect no recovery". NIST's layout says
    /// narrower: two of its four deleted files keep metadata, and it names the
    /// two that cannot be found. `osx-04` lists placeholder names whose real,
    /// non-Latin names come from its creation steps, and says no metadata was
    /// found for any of its 48.
    #[test]
    fn osx_01_names_its_unfindable_files_and_osx_04_maps_placeholders_to_real_names() {
        let l = parse_layout(OSX);
        assert!(l.rejected.is_empty(), "{:?}", l.rejected);
        let o1 = l.image("osx-01").unwrap();
        assert_eq!(o1.deleted.len(), 4);
        assert_eq!(o1.metadata_found, Some(2));
        assert_eq!(o1.metadata_not_found, Some(2));
        assert_eq!(o1.without_metadata, ["Bellatrix.TXT", "xBellatrix.txt"]);
        assert!(o1.is_without_metadata("xBellatrix.txt"));
        assert!(!o1.is_without_metadata("Beid.txt"));

        let o4 = l.image("osx-04").unwrap();
        assert_eq!(o4.scenario.as_deref(), Some("DFR-04"));
        assert_eq!(o4.deleted.len(), 48);
        assert_eq!(o4.metadata_found, Some(0));
        let beijing = o4
            .deleted
            .iter()
            .find(|d| d.name == "/tmp/dfr-04/BeiJing.txt")
            .unwrap();
        assert_eq!(o4.real_name(beijing), "北京.txt");
        let pakora = o4
            .deleted
            .iter()
            .find(|d| d.name.ends_with("/Pakora.txt"))
            .unwrap();
        // Right-to-left, with the PDF's embedding controls removed.
        assert_eq!(o4.real_name(pakora), "پکوڑا.txt");
        // The document elides 30 of its own sector-list rows here.
        assert_eq!(o4.omitted_sectors, 30);
        // The elision cut Couscous.txt's row short: its runs are not known.
        assert_eq!(o4.incomplete_sectors, ["Couscous.txt"]);
        assert_eq!(o4.sectors_of("Couscous.txt"), None);
        assert_eq!(
            o4.sectors_of("BeiJing.txt").map(<[_]>::len),
            Some(4),
            "a sector-list row wrapped over two lines is one row"
        );
    }

    #[test]
    fn elided_deleted_rows_are_counted_not_invented() {
        let text = "\
14 Test Image ext-09
DFR-09.   Recover large number of files no overwrite.
5 files deleted
             Deleted files (5)
Name            Size            F-Hd    F-Bks
xB0001-3.txt 4096 (8+0) 1         7
xB0002-3.txt 4096 (8+0) 1         7
  ...
2 omitted
xB0005-3.txt 4096 (8+0) 1         7
No overwrites
Summary: 5 5 0 0
";
        let l = parse_layout(text);
        assert!(l.rejected.is_empty(), "{:?}", l.rejected);
        let t = l.image("ext-09").unwrap();
        assert_eq!(t.deleted.len(), 3);
        assert_eq!(t.omitted_deleted, 2);
    }

    #[test]
    fn an_unparseable_section_is_reported_not_dropped() {
        let text = "\
1 Test Image ext-01
DFR-01.     Recover one non-fragmented file.
3 files deleted
               Deleted files (3)
Name            Size            F-Hd    F-Bks
Bellatrix.txt 712 (1+200) 1             0
Bunda.txt       seven hundred           0
";
        let l = parse_layout(text);
        assert!(l.image("ext-01").is_none());
        assert_eq!(l.rejected.len(), 1);
        assert_eq!(l.rejected[0].image, "ext-01");
    }

    #[test]
    fn bidi_controls_are_removed_and_nothing_else() {
        assert_eq!(
            strip_bidi_controls("\u{202b}پکوڑا\u{202c}.txt"),
            "پکوڑا.txt"
        );
        assert_eq!(strip_bidi_controls("Gefäß.txt"), "Gefäß.txt");
    }

    /// Corpus-gated on `SEANCE_CFTT_DFR` (the directory holding
    /// `setup-july-10-2012.pdf` and `dd/`). Runs `pdftotext -layout`, or reads
    /// `SEANCE_CFTT_DFR_LAYOUT_TXT` when set, and checks that every image on
    /// disk has exactly one truth section.
    #[test]
    fn every_one_of_the_90_images_on_disk_has_exactly_one_truth_section() {
        let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_CFTT_DFR") else {
            return;
        };
        let text = match std::env::var("SEANCE_CFTT_DFR_LAYOUT_TXT") {
            Ok(p) => std::fs::read_to_string(p).expect("layout text"),
            Err(_) => {
                let out = std::process::Command::new("pdftotext")
                    .arg("-layout")
                    .arg(dir.join("setup-july-10-2012.pdf"))
                    .arg("-")
                    .output()
                    .expect("SEANCE_CFTT_DFR is set, so pdftotext must be installed");
                assert!(out.status.success(), "pdftotext failed");
                String::from_utf8(out.stdout).unwrap()
            }
        };
        let layout = parse_layout(&text);
        assert!(layout.rejected.is_empty(), "{:#?}", layout.rejected);
        assert_eq!(layout.images.len(), 91, "the layout has 91 sections");
        let mut dds: Vec<String> = std::fs::read_dir(dir.join("dd"))
            .expect("SEANCE_CFTT_DFR/dd")
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.ends_with(".dd"))
            .collect();
        dds.sort();
        assert_eq!(dds.len(), 90);
        for dd in &dds {
            let n = layout.images.iter().filter(|i| &i.dd_name() == dd).count();
            assert_eq!(n, 1, "{dd}: {n} truth sections");
        }
        let sum = |f: fn(&DfrImageTruth) -> u64| layout.images.iter().map(f).sum::<u64>();
        eprintln!(
            "deleted listed {} elided {}; sector rows cut {}; overwrite lists short {}; \
             without metadata {}; sections with no scenario {}",
            sum(|t| t.deleted.len() as u64),
            sum(|t| t.omitted_deleted),
            sum(|t| t.incomplete_sectors.len() as u64),
            sum(|t| t.overwrites_incomplete as u64),
            sum(|t| t.without_metadata.len() as u64),
            sum(|t| t.scenario.is_none() as u64),
        );
        // Every section's arithmetic holds: listed + elided = declared.
        for t in &layout.images {
            assert_eq!(
                t.deleted.len() as u64 + t.omitted_deleted,
                t.declared_deleted,
                "{}",
                t.image
            );
        }
    }
}
