//! The in-run index of files recovered from the volume, used to answer "does
//! the thing this ASEP points at actually exist?".
//!
//! An autostart entry naming a program that is not on the disk is a materially
//! different fact from one naming a program that is. The honest way to answer
//! is to compare the ASEP's target against the files this ingest actually
//! enumerated — and to be exact about what that comparison can and cannot
//! prove.
//!
//! It cannot prove absence. The index is filled as the pipeline walks the
//! volume, so a target that has not been seen *yet* is indistinguishable from
//! one that is not there at all, and a case that ingested registry hives
//! without a filesystem has no index to compare against. Every answer this
//! module returns therefore carries the basis it was reached on, and the
//! "not found" answer is worded as *not observed*, never as *absent*. A record
//! that said "target does not exist" on the strength of a partial index would
//! be the kind of wrong answer that survives into a report.

use crate::normalize::{
    basename, is_executable_like, normalize_evidence_path, normalize_target, normalize_target_in,
    SearchContext, SearchDirectoryKind,
};
use std::collections::{HashMap, HashSet};

/// Ceiling on distinct basenames held in the executable index. A volume with
/// more than this many distinct executable names stops being indexed and the
/// cap is reported on every subsequent resolution.
pub const MAX_INDEXED_BASENAMES: usize = 400_000;

/// Ceiling on full paths retained per basename. Beyond this the basename is
/// still known (so "observed by name" still works) but the exact-path answer
/// for the surplus paths is lost, and the resolution says so through
/// [`TargetResolution::observed_paths_truncated`].
pub const MAX_PATHS_PER_BASENAME: usize = 8;

/// Ceiling on hive files whose own path is remembered, so a per-user hive can
/// be attributed to its profile.
pub const MAX_TRACKED_HIVES: usize = 4_096;

/// Ceiling on system-directory files whose creation time is remembered (`HUNT-276`).
pub const MAX_SYSTEM_CREATED: usize = 400_000;

/// Where the system's install time was read from, written beside it on every record.
pub const OS_INSTALL_BASIS: &str =
    "SOFTWARE hive Microsoft\\Windows NT\\CurrentVersion\\InstallDate";

/// Written instead of an install time when none had been read.
pub const OS_INSTALL_UNSEEN: &str =
    "no SOFTWARE hive InstallDate had been read when this entry was made";

/// How confidently an ASEP's target was located in the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    /// The entry names no image, so there is nothing to resolve.
    NotApplicable,
    /// A file was recovered at exactly the path the ASEP names.
    ObservedAtPath,
    /// No file was recovered at that path, but a file of the same name was
    /// recovered elsewhere. This is a weaker answer and is labelled as such.
    ObservedByNameOnly,
    /// The target's name was not seen anywhere in the files enumerated so far.
    /// This is not proof the file is absent from the volume.
    NotObserved,
    /// No filesystem was enumerated in this case, so the question cannot be
    /// asked at all. Distinct from [`TargetStatus::NotObserved`].
    NoFileIndex,
    /// The target contains an environment variable this build will not expand,
    /// so an exact-path comparison is meaningless. A name-level answer may
    /// still be reported alongside.
    UnresolvedVariable,
}

impl TargetStatus {
    /// Stable string form written into the record.
    pub fn as_str(self) -> &'static str {
        match self {
            TargetStatus::NotApplicable => "not_applicable",
            TargetStatus::ObservedAtPath => "observed_at_path",
            TargetStatus::ObservedByNameOnly => "observed_by_name_only",
            TargetStatus::NotObserved => "not_observed",
            TargetStatus::NoFileIndex => "no_file_index",
            TargetStatus::UnresolvedVariable => "unresolved_environment_variable",
        }
    }
}

/// The answer to "does this ASEP's target exist", with the basis it rests on.
#[derive(Debug, Clone)]
pub struct TargetResolution {
    /// The verdict.
    pub status: TargetStatus,
    /// A plain sentence stating what was compared and what that does and does
    /// not establish. Written verbatim into the record.
    pub basis: String,
    /// The normalised path used for the lookup, when one could be formed.
    pub lookup_path: Option<String>,
    /// The substitution applied to reach `lookup_path`, when any.
    pub expansion: Option<&'static str>,
    /// Up to [`MAX_PATHS_PER_BASENAME`] recovered paths that share the target's
    /// file name, for the name-only case.
    pub observed_paths: Vec<String>,
    /// Number of executable files indexed when the question was asked, so an
    /// examiner can see how much the answer is worth.
    pub index_size: usize,
    /// The index stopped accepting entries before the volume was exhausted.
    pub index_capped: bool,
    /// More than [`MAX_PATHS_PER_BASENAME`] files carried this target's name, so
    /// `observed_paths` is a subset and an exact-path match could not be ruled
    /// out. Without this flag a `ObservedByNameOnly` verdict reached because the
    /// path list was truncated would be indistinguishable from one reached
    /// because the file genuinely sits somewhere else.
    pub observed_paths_truncated: bool,
    /// For a bare program name, every search-path path that was tried, in
    /// order. Empty for a target that names its own path.
    pub search_path_candidates: Vec<String>,
    /// For a bare program name found on the search path, the directory that
    /// answered (`\Windows\System32`, the entry's working directory, …).
    /// `None` when none did.
    pub search_path_directory: Option<String>,
    /// For a bare program name, the extension rule applied
    /// ([`crate::normalize::SearchRule::as_str`]).
    pub search_rule: Option<&'static str>,
    /// For a bare program name, how `lookup_path` was reached: observed on the
    /// search path, or assumed from the search-path convention.
    pub search_path_resolution: Option<&'static str>,
    /// The creation time the file at `lookup_path` was recorded with, when the answer is an exact path match in
    /// a Windows system directory (`HUNT-276`). Whatever the file system called it: a $STANDARD_INFORMATION time
    /// is writable by the program it describes.
    pub target_created: Option<String>,
}

/// `search_path_resolution` when a recovered file answered a candidate.
pub const SEARCH_PATH_OBSERVED: &str = "observed_on_search_path";
/// `search_path_resolution` when the file answered in the working directory
/// the entry records (`HUNT-244`). Worded apart from
/// [`SEARCH_PATH_OBSERVED`]: `CreateProcess` searches the launching process's
/// current directory, not the new process's, so a copy there is where a
/// planted program would sit, not proof it is the one Windows loaded.
pub const SEARCH_PATH_OBSERVED_IN_WORKING_DIRECTORY: &str = "observed_in_working_directory";
/// `search_path_resolution` when no candidate was observed and `lookup_path` is
/// the first candidate by convention.
pub const SEARCH_PATH_CONVENTION: &str = "search_path_convention_not_observed";
/// `search_path_resolution` under [`crate::normalize::SearchRule::FullPathRequired`]
/// when a recovered file answered a candidate (`HUNT-249`). The source's
/// documented contract is a full path, so how its launcher resolves a bare
/// name is not documented: the file is a lead for the examiner, not the file
/// the launcher is established to load, and the status is
/// `observed_by_name_only`, never `observed_at_path`.
pub const SEARCH_PATH_LEAD_OBSERVED: &str = "lead_candidate_observed";
/// `search_path_resolution` under [`crate::normalize::SearchRule::FullPathRequired`]
/// when no candidate was observed (`HUNT-249`): `lookup_path` is the first
/// lead candidate, not a location any documented rule points at.
pub const SEARCH_PATH_LEAD_NOT_OBSERVED: &str = "lead_candidate_not_observed";

impl TargetResolution {
    fn new(status: TargetStatus, basis: String, index_size: usize, index_capped: bool) -> Self {
        Self {
            status,
            basis,
            lookup_path: None,
            expansion: None,
            observed_paths: Vec::new(),
            index_size,
            index_capped,
            observed_paths_truncated: false,
            search_path_candidates: Vec::new(),
            search_path_directory: None,
            search_rule: None,
            search_path_resolution: None,
            target_created: None,
        }
    }
}

/// Files seen during this ingest, indexed by executable basename.
#[derive(Debug, Default)]
pub struct EvidenceIndex {
    executables: HashMap<String, Vec<String>>,
    /// Basenames for which [`MAX_PATHS_PER_BASENAME`] was reached and at least
    /// one further distinct path was dropped.
    paths_capped: HashSet<String>,
    hive_paths: HashMap<uuid::Uuid, String>,
    /// Creation time as recorded, by normalised path, for executables in the Windows system directories only.
    system_created: HashMap<String, String>,
    /// The system's install time (seconds since the epoch) from the SOFTWARE hive.
    os_install: Option<i64>,
    executables_capped: bool,
    hives_capped: bool,
}

impl EvidenceIndex {
    /// Empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a file recovered from the volume.
    ///
    /// Only executable-like files are kept: an ASEP target is a program, and
    /// indexing every document on a multi-million-file volume would cost
    /// hundreds of megabytes to answer a question none of them can answer.
    /// Non-executable paths are dropped deliberately, which is why
    /// [`Self::resolve`] never reports "not observed" for a target whose
    /// extension it would not have indexed.
    pub fn note_file(&mut self, path: &str) {
        let name = basename(path);
        if name.is_empty() || !is_executable_like(name) {
            return;
        }
        let normalized = normalize_evidence_path(path);
        let key = name.to_ascii_lowercase();
        match self.executables.get_mut(&key) {
            Some(paths) => {
                if paths.iter().any(|p| p == &normalized) {
                    return;
                }
                if paths.len() < MAX_PATHS_PER_BASENAME {
                    paths.push(normalized);
                } else {
                    // A distinct path for a name we already know was dropped.
                    // Remember that, because from here on an exact-path answer
                    // for this name is a lower bound rather than a finding.
                    self.paths_capped.insert(key);
                }
            }
            None => {
                if self.executables.len() >= MAX_INDEXED_BASENAMES {
                    self.executables_capped = true;
                    return;
                }
                self.executables.insert(key, vec![normalized]);
            }
        }
    }

    /// Remember when a file was created, for an executable in a Windows system directory (`HUNT-276`).
    /// Called with the same path as [`Self::note_file`]; anywhere else, or with no time, it does nothing.
    pub fn note_created(&mut self, path: &str, created: Option<&str>) {
        let Some(created) = created.filter(|c| !c.is_empty()) else {
            return;
        };
        let name = basename(path);
        if name.is_empty() || !is_executable_like(name) {
            return;
        }
        let normalized = normalize_evidence_path(path);
        const SYSTEM_DIRS: [&str; 4] = [
            "/windows/system32/",
            "/windows/syswow64/",
            "/winnt/system32/",
            "/winnt/syswow64/",
        ];
        if !SYSTEM_DIRS.iter().any(|d| normalized.starts_with(d)) {
            return;
        }
        if self.system_created.len() < MAX_SYSTEM_CREATED {
            self.system_created
                .entry(normalized)
                .or_insert_with(|| created.to_string());
        }
    }

    /// Remember the install time the SOFTWARE hive records (seconds since the epoch). The first one read is
    /// kept: a case with two SOFTWARE hives has no single answer, and this does not pick between them.
    pub fn note_os_install(&mut self, epoch: i64) {
        self.os_install.get_or_insert(epoch);
    }

    /// The install time as RFC 3339, if one was read.
    pub fn os_install_time(&self) -> Option<String> {
        let t = chrono::DateTime::<chrono::Utc>::from_timestamp(self.os_install?, 0)?;
        Some(t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    }

    /// Remember the on-disk path of a registry hive file, keyed by the artifact
    /// id of the file entry it came from.
    ///
    /// The parsed-hive record carries only the hive's file name, so without
    /// this a per-user `NTUSER.DAT` could not be attributed to a profile and
    /// every user's Run keys would be reported against an anonymous "HKCU".
    pub fn note_hive_file(&mut self, id: uuid::Uuid, path: &str) {
        if self.hive_paths.len() >= MAX_TRACKED_HIVES {
            self.hives_capped = true;
            return;
        }
        self.hive_paths.insert(id, path.to_string());
    }

    /// The recorded path of a hive file, if it was seen.
    pub fn hive_path(&self, id: &uuid::Uuid) -> Option<&str> {
        self.hive_paths.get(id).map(String::as_str)
    }

    /// Whether the hive-path map stopped accepting entries.
    pub fn hives_capped(&self) -> bool {
        self.hives_capped
    }

    /// Number of distinct executable names indexed.
    pub fn executable_count(&self) -> usize {
        self.executables.len()
    }

    /// Resolve an ASEP target against the files enumerated so far.
    ///
    /// `image` is the target exactly as it was stored in evidence. Pass `None`
    /// when the entry names no image at all (a COM handler action, a catalog
    /// entry whose payload was not decoded) — the result then says
    /// "not applicable", which must not read the same as "not found".
    pub fn resolve(&self, image: Option<&str>) -> TargetResolution {
        self.resolve_in(image, &SearchContext::default())
    }

    /// [`Self::resolve`] under the source's own [`SearchContext`]: the
    /// extension rule its launcher applies and the working directory it
    /// records, both of which change where a bare program name is looked for
    /// (`HUNT-244`). A target that names its own path is unaffected.
    pub fn resolve_in(&self, image: Option<&str>, ctx: &SearchContext) -> TargetResolution {
        let size = self.executable_count();
        let capped = self.executables_capped;

        let Some(image) = image.map(str::trim).filter(|s| !s.is_empty()) else {
            return TargetResolution::new(
                TargetStatus::NotApplicable,
                "This entry does not name an image on disk, so there is no target to \
                 locate."
                    .to_string(),
                size,
                capped,
            );
        };

        if size == 0 {
            let mut res = TargetResolution::new(
                TargetStatus::NoFileIndex,
                "No executable files were enumerated in this case, so whether the target \
                 exists on the volume could not be checked. This is not a statement that \
                 the target is missing."
                    .to_string(),
                size,
                capped,
            );
            if let Some(t) = normalize_target_in(image, ctx) {
                if !t.search_path_candidates.is_empty() {
                    // Under `full_path_required` the candidates are leads,
                    // never the search-path convention (`HUNT-249` review).
                    res.search_path_resolution = Some(
                        if matches!(
                            t.search_rule,
                            crate::normalize::SearchRule::FullPathRequired(_)
                        ) {
                            SEARCH_PATH_LEAD_NOT_OBSERVED
                        } else {
                            SEARCH_PATH_CONVENTION
                        },
                    );
                    res.search_rule = Some(t.search_rule.as_str());
                    res.expansion = t.expansion;
                    res.search_path_candidates = t.search_path_candidates;
                }
                res.lookup_path = Some(t.lookup);
            }
            return res;
        }

        if let Some(target) = normalize_target_in(image, ctx) {
            if !target.search_path_candidates.is_empty() {
                return self.resolve_on_search_path(image, target, size, capped);
            }
        }

        let name_key = basename(image).trim().to_ascii_lowercase();
        let name_key = name_key.trim_matches('"').to_string();
        let observed: Vec<String> = self.executables.get(&name_key).cloned().unwrap_or_default();
        let paths_truncated = self.paths_capped.contains(&name_key);

        let Some(target) = normalize_target(image) else {
            let mut res = TargetResolution::new(
                TargetStatus::NotApplicable,
                "The stored target could not be reduced to a path.".to_string(),
                size,
                capped,
            );
            res.observed_paths = observed;
            res.observed_paths_truncated = paths_truncated;
            return res;
        };

        if target.has_unexpanded_variable {
            let status = if observed.is_empty() {
                TargetStatus::UnresolvedVariable
            } else {
                TargetStatus::ObservedByNameOnly
            };
            let basis = if observed.is_empty() {
                format!(
                    "The target contains an environment variable this build does not \
                     expand (no live environment to expand against), and no file named \
                     '{name_key}' was seen among the {size} executable names enumerated. \
                     The path was not compared."
                )
            } else {
                format!(
                    "The target contains an environment variable this build does not \
                     expand, so the full path was not compared. A file named '{name_key}' \
                     was recovered at {} location(s); that is a name match only.",
                    observed.len()
                )
            };
            let mut res = TargetResolution::new(status, basis, size, capped);
            res.lookup_path = Some(target.lookup);
            res.expansion = target.expansion;
            res.observed_paths = observed;
            res.observed_paths_truncated = paths_truncated;
            return res;
        }

        let exact = observed.iter().any(|p| p == &target.lookup);
        let (status, basis) = if exact {
            (
                TargetStatus::ObservedAtPath,
                format!(
                    "A file was recovered at '{}', the path this entry names.",
                    target.lookup
                ),
            )
        } else if !observed.is_empty() && paths_truncated {
            // More files carried this name than the index retains paths for, so
            // "the path does not match" is a claim the evidence does not support.
            (
                TargetStatus::ObservedByNameOnly,
                format!(
                    "Files named '{name_key}' were recovered, but more than \
                     {MAX_PATHS_PER_BASENAME} of them were seen and only the first \
                     {MAX_PATHS_PER_BASENAME} paths were retained. '{}' is not among the \
                     retained paths; whether a file was recovered at that exact path was \
                     therefore not established either way.",
                    target.lookup
                ),
            )
        } else if !observed.is_empty() {
            (
                TargetStatus::ObservedByNameOnly,
                format!(
                    "No file was recovered at '{}'. A file named '{name_key}' was \
                     recovered at {} other location(s); the name matches but the path \
                     does not.",
                    target.lookup,
                    observed.len()
                ),
            )
        } else {
            (
                TargetStatus::NotObserved,
                format!(
                    "No file named '{name_key}' was found among the {size} executable \
                     names enumerated from this evidence. Because the index is built as \
                     the volume is walked and holds only executable file types, this is \
                     not proof that the target is absent from the disk."
                ),
            )
        };

        let mut res = TargetResolution::new(status, basis, size, capped);
        if exact {
            res.target_created = self.system_created.get(&target.lookup).cloned();
        }
        res.lookup_path = Some(target.lookup);
        res.expansion = target.expansion;
        res.observed_paths = observed;
        res.observed_paths_truncated = paths_truncated;
        res
    }

    /// Resolve a bare program name against its search-path candidates
    /// (`HUNT-241`, `HUNT-244`). The first candidate a recovered file answers
    /// is the one reported, with the directory that answered; when none does,
    /// the answer is worded exactly as for any other unseen target — not
    /// observed, never absent — and `lookup_path` is marked as a convention.
    /// The basis names the directories tried and the extension rule applied.
    fn resolve_on_search_path(
        &self,
        image: &str,
        target: crate::normalize::TargetPath,
        size: usize,
        capped: bool,
    ) -> TargetResolution {
        let stored = image.trim().trim_matches('"');
        let candidates = target.search_path_candidates;
        let dirs = target.search_path_directories;
        let rule = target.search_rule;

        // Every distinct file name the search could land on (`cscript.com`,
        // `cscript.exe`, …), and what the index holds for each.
        let mut names: Vec<String> = Vec::new();
        for c in &candidates {
            let n = basename(c).to_string();
            if !names.contains(&n) {
                names.push(n);
            }
        }
        let mut observed: Vec<String> = Vec::new();
        let mut truncated = false;
        for n in &names {
            if let Some(paths) = self.executables.get(n) {
                for p in paths {
                    if !observed.contains(p) {
                        observed.push(p.clone());
                    }
                }
            }
            truncated |= self.paths_capped.contains(n);
        }
        let tried = candidates.join(", ");

        // Which directories were searched, and the rule — stated on every
        // answer, because both decide what "not on the search path" means.
        let mut method = String::new();
        if let Some(wd) = dirs
            .iter()
            .find(|d| d.kind == SearchDirectoryKind::WorkingDirectory)
        {
            method.push_str(&format!(
                " The entry's recorded working directory '{}' was tried before the system \
                 directories; CreateProcess documents searching the launching process's \
                 current directory, not the new process's, so a copy there is where a \
                 planted program would sit rather than proof it is the one loaded.",
                wd.display
            ));
        }
        if let Some(why) = &target.working_directory_not_tried {
            method.push(' ');
            method.push_str(why);
        }
        method.push_str(
            " The launching process's own directory, its current directory and PATH were \
             not modelled, so an earlier match there cannot be ruled out. ",
        );
        method.push_str(rule.statement());

        // Under `full_path_required` the launcher's resolution of a bare name
        // is not documented (`HUNT-249`), so the candidates are leads: a hit is
        // a name match at a lead location, never the file the launcher is
        // established to load, and no answer is worded as the search path.
        let lead = matches!(rule, crate::normalize::SearchRule::FullPathRequired(_));
        let candidate_word = if lead {
            "lead candidate"
        } else {
            "search-path candidate"
        };
        let (not_observed_label, truncated_miss) = if lead {
            (
                SEARCH_PATH_LEAD_NOT_OBSERVED,
                " among the retained paths (more copies were seen than are retained, so a \
                 match at a lead candidate was not ruled out)",
            )
        } else {
            (
                SEARCH_PATH_CONVENTION,
                " among the retained paths (more copies were seen than are retained, so a \
                 search-path match was not ruled out)",
            )
        };
        let truncated_hit = if truncated {
            " More copies of a candidate name were seen than the index retains paths for, \
             so an earlier candidate was not ruled out either."
        } else {
            ""
        };

        let answered = candidates.iter().find(|c| observed.contains(c)).cloned();
        let (status, basis, lookup, directory, resolution) =
            if let Some(hit) = answered.clone().filter(|_| lead) {
                let display = hit
                    .rsplit_once('/')
                    .and_then(|(d, _)| dirs.iter().find(|x| x.lookup == d))
                    .map(|d| d.display.clone());
                (
                    TargetStatus::ObservedByNameOnly,
                    format!(
                        "The entry names the bare program '{stored}'. A file of a candidate name \
                     was recovered at '{hit}' ({}), the first of the lead candidates tried \
                     ({tried}) that the evidence holds; it is a lead for the examiner, not a \
                     file the launcher is established to load.{method}{truncated_hit}",
                        display.as_deref().unwrap_or("system directory"),
                    ),
                    hit,
                    display,
                    SEARCH_PATH_LEAD_OBSERVED,
                )
            } else if let Some(hit) = answered {
                let dir = hit
                    .rsplit_once('/')
                    .and_then(|(d, _)| dirs.iter().find(|x| x.lookup == d));
                let in_wd = dir.is_some_and(|d| d.kind == SearchDirectoryKind::WorkingDirectory);
                let display = dir.map(|d| d.display.clone());
                (
                    TargetStatus::ObservedAtPath,
                    format!(
                        "The entry names the bare program '{stored}', which Windows resolves on \
                     the search path. A file was recovered at '{hit}' ({}), the first of the \
                     search-path candidates tried ({tried}) that the evidence holds.{method}\
                     {truncated_hit}",
                        display.as_deref().unwrap_or("search-path directory"),
                    ),
                    hit,
                    display,
                    if in_wd {
                        SEARCH_PATH_OBSERVED_IN_WORKING_DIRECTORY
                    } else {
                        SEARCH_PATH_OBSERVED
                    },
                )
            } else if !observed.is_empty() {
                (
                    TargetStatus::ObservedByNameOnly,
                    format!(
                        "The entry names the bare program '{stored}'. No file was recovered at \
                     any {candidate_word} ({tried}){}. A file of a candidate name was \
                     recovered at {} other location(s); the name matches but no candidate \
                     location does.{method}",
                        if truncated { truncated_miss } else { "" },
                        observed.len()
                    ),
                    target.lookup,
                    None,
                    not_observed_label,
                )
            } else {
                (
                    TargetStatus::NotObserved,
                    format!(
                        "The entry names the bare program '{stored}'. No file at any \
                     {candidate_word} ({tried}), nor any file of those names, was found among the \
                     {size} executable names enumerated from this evidence. Because the \
                     index is built as the volume is walked and holds only executable file \
                     types, this is not proof that the target is absent from the disk.{method}"
                    ),
                    target.lookup,
                    None,
                    not_observed_label,
                )
            };

        let mut res = TargetResolution::new(status, basis, size, capped);
        res.lookup_path = Some(lookup);
        res.expansion = target.expansion;
        res.observed_paths = observed;
        res.observed_paths_truncated = truncated;
        res.search_path_candidates = candidates;
        res.search_path_directory = directory;
        res.search_rule = Some(rule.as_str());
        res.search_path_resolution = Some(resolution);
        res
    }
}
