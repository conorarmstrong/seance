//! Choosing the symbol file that describes *this* kernel, and refusing every
//! other one.
//!
//! # Why this is the most dangerous step in discovery
//!
//! A wrong symbol table does not crash and does not look wrong. It produces a
//! complete process list with plausible PIDs, plausible names and plausible
//! timestamps, every one of them garbage, because
//! `_EPROCESS.UniqueProcessId` was read at the offset a *different* Windows
//! build uses. Nothing downstream can detect it: the bytes really were at that
//! address, and they really did parse.
//!
//! So selection here is on the CodeView **GUID and age** and nothing else.
//! Not the file name, not the Windows version, not the nearest build. The GUID
//! is what a PDB is; the age is which revision of that PDB. Two symbol files
//! with the same GUID and age describe the same bytes, and two with different
//! ones describe different kernels however similar their names.
//!
//! When nothing matches, this module returns the GUID that was wanted rather
//! than the closest thing it found. An examiner can take that GUID to a symbol
//! store and come back with the right file; an examiner handed a "close enough"
//! table comes back with a report that is wrong in a way no review will catch.
//!
//! # How the search is kept cheap
//!
//! Identifying an ISF means streaming and hashing the whole file, which is tens
//! of megabytes each. A symbol store laid out the conventional way names its
//! files `<pdb>/<GUID>-<age>.json.xz`, so any path containing the wanted
//! `GUID-age` is tried first. That is a *hint*, never a decision: the file is
//! still identified from its metadata before it is accepted, because a file's
//! name is not evidence of its contents.

use std::path::{Path, PathBuf};

pub use seance_memory::isf_files::{
    collect_isf_files, is_isf_file_name, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILES, ISF_SUFFIXES,
};
use seance_symbols::{identify_path, IdentifyOptions, IsfOs};

use crate::automagic::pe::PdbIdentity;

/// Files the search will fully identify when no name hint matched. Identifying
/// an ISF streams and hashes it, so an exhaustive pass over a large store is
/// expensive and is bounded.
pub const DEFAULT_MAX_IDENTIFIED: usize = 4_096;

/// One symbol file whose declared identity matches the kernel's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsfMatch {
    /// Where the file is.
    pub path: PathBuf,
    /// The PDB file name the ISF declares. Normally equal to the kernel's, but
    /// kept separately: a mismatch is worth showing an examiner even when the
    /// GUID and age agree.
    pub database: String,
    /// The GUID the ISF declares, uppercase.
    pub guid: String,
    /// The age the ISF declares.
    pub age: u32,
}

impl IsfMatch {
    /// The identity string this file will be admitted under.
    pub fn identifier(&self) -> String {
        format!("{}|{}|{}", self.database, self.guid, self.age)
    }
}

/// What one search of the symbol directories found, and what it could not do.
#[derive(Debug, Clone, Default)]
pub struct IsfSearchOutcome {
    /// Files whose GUID and age match, strongest first: an exact PDB-name match
    /// ahead of a file that agrees on identity but names itself differently.
    pub matches: Vec<IsfMatch>,
    /// Candidate files enumerated.
    pub files_seen: usize,
    /// Files actually opened and identified.
    pub files_identified: usize,
    /// Whether a cap stopped the search. A truncated search that found nothing
    /// has not shown that the symbols are absent.
    pub truncated: bool,
}

impl IsfSearchOutcome {
    /// Serializable form for the discovery artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "matches": self.matches.len(),
            "files_seen": self.files_seen,
            "files_identified": self.files_identified,
            "truncated": self.truncated,
        })
    }
}

/// The `GUID-age` fragment a conventional symbol store puts in the file name.
pub fn name_hint(want: &PdbIdentity) -> String {
    format!("{}-{}", want.guid.to_ascii_uppercase(), want.age)
}

/// The Windows CodeView identity an ISF declares, if it declares one.
///
/// Returns `None` for a file that is not a Windows ISF, that this reader cannot
/// parse, or whose metadata carries no PDB block. Never guesses: a file that
/// will not identify is not a candidate.
pub fn windows_identity_of(path: &Path) -> Option<(String, String, u32)> {
    let options = IdentifyOptions {
        // Nothing here needs a Linux or macOS banner, and capturing one costs a
        // buffer per file.
        banner_symbols: Vec::new(),
        ..IdentifyOptions::default()
    };
    let identity = identify_path(path, &options).ok()?;
    if identity.os != IsfOs::Windows {
        return None;
    }
    let triple = identity.identifier?;
    parse_windows_identifier(&triple)
}

/// Split `{database}|{GUID}|{age}` into its parts.
///
/// The age must parse as a number: an ISF whose age is not one has an identity
/// this crate cannot compare, and comparing it as a string would let `01` and
/// `1` be different symbol files for one kernel.
pub fn parse_windows_identifier(triple: &str) -> Option<(String, String, u32)> {
    let mut parts = triple.split('|');
    let database = parts.next()?.to_string();
    let guid = parts.next()?.to_ascii_uppercase();
    let age: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if database.is_empty() || guid.is_empty() {
        return None;
    }
    Some((database, guid, age))
}

/// Find every symbol file under `dirs` whose GUID and age are the kernel's.
///
/// Name-hinted files are identified first, so the conventional symbol-store
/// layout costs one file read rather than a sweep. When no hint matches, the
/// remaining files are identified up to `max_identified`, because an examiner
/// who dropped a correctly-built ISF under an arbitrary name should still get
/// their case done — just more slowly.
///
/// Matching is on GUID and age alone. The declared PDB name is recorded and
/// used only to order the results: a file that agrees on identity *and* names
/// itself the same as the kernel is offered before one that agrees on identity
/// only.
pub fn find_matching_isf(
    dirs: &[PathBuf],
    want: &PdbIdentity,
    max_files: usize,
    max_depth: usize,
    max_identified: usize,
) -> IsfSearchOutcome {
    let (files, truncated) = collect_isf_files(dirs, max_files, max_depth);
    let mut outcome = IsfSearchOutcome {
        files_seen: files.len(),
        truncated,
        ..IsfSearchOutcome::default()
    };

    let hint = name_hint(want);
    let wanted_guid = want.guid.to_ascii_uppercase();
    let (hinted, rest): (Vec<PathBuf>, Vec<PathBuf>) = files
        .into_iter()
        .partition(|path| path.to_string_lossy().to_ascii_uppercase().contains(&hint));

    for path in hinted.iter().chain(rest.iter()) {
        if outcome.files_identified >= max_identified {
            outcome.truncated = true;
            break;
        }
        outcome.files_identified += 1;
        let Some((database, guid, age)) = windows_identity_of(path) else {
            continue;
        };
        if guid != wanted_guid || age != want.age {
            continue;
        }
        outcome.matches.push(IsfMatch {
            path: path.clone(),
            database,
            guid,
            age,
        });
        // A hinted file that matched is the conventional answer; there is no
        // value in streaming the rest of the store to find another copy of the
        // same identity.
        if !outcome.matches.is_empty() && hinted.contains(path) {
            break;
        }
    }

    // Strongest first: identical PDB name, then anything else that shares the
    // identity. Stable within each group so the answer does not depend on
    // directory iteration order.
    let wanted_name = want.pdb.to_ascii_lowercase();
    outcome.matches.sort_by_key(|m| {
        let exact = m.database.to_ascii_lowercase() != wanted_name;
        (exact, m.path.clone())
    });
    outcome
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A throwaway directory that removes itself, so a test can lay out a
    /// symbol store on disk without leaving one behind.
    pub(crate) struct TempDir {
        pub path: PathBuf,
    }

    impl TempDir {
        pub(crate) fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("seance-automagic-{label}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("a writable temporary directory");
            Self { path }
        }

        pub(crate) fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let full = self.path.join(relative);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("a writable temporary directory");
            }
            std::fs::write(&full, contents).expect("a writable temporary file");
            full
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// A minimal but genuinely valid Windows ISF, declaring one PDB identity
    /// and just enough of a type database to compile.
    pub(crate) fn windows_isf(database: &str, guid: &str, age: u32) -> String {
        format!(
            r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "{guid}", "age": {age},
                         "database": "{database}", "machine_type": 34404}}}}
  }},
  "base_types": {{
    "pointer": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}},
    "unsigned long": {{"size": 4, "signed": false, "kind": "int", "endian": "little"}},
    "unsigned short": {{"size": 2, "signed": false, "kind": "int", "endian": "little"}},
    "unsigned char": {{"size": 1, "signed": false, "kind": "int", "endian": "little"}}
  }},
  "user_types": {{
    "_KUSER_SHARED_DATA": {{"size": 1024, "kind": "struct", "fields": {{
      "NtMajorVersion": {{"offset": 620, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "NtMinorVersion": {{"offset": 624, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "NtBuildNumber": {{"offset": 592, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "NtBuildLab": {{"address": 4096, "type": {{"kind": "base", "name": "unsigned char"}}}}
  }}
}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const GUID: &str = "AA1B2C3D4E5F60718293A4B5C6D7E8F9";

    fn want(pdb: &str, guid: &str, age: u32) -> PdbIdentity {
        PdbIdentity {
            pdb: pdb.to_string(),
            guid: guid.to_string(),
            age,
        }
    }

    #[test]
    fn an_isf_is_recognised_by_the_suffixes_this_crate_can_read() {
        assert!(is_isf_file_name("ntkrnlmp.json"));
        assert!(is_isf_file_name("AB-1.json.xz"));
        assert!(is_isf_file_name("AB-1.JSON.GZ"));
        assert!(!is_isf_file_name("ntkrnlmp.pdb"));
        assert!(!is_isf_file_name("readme.txt"));
        assert!(!is_isf_file_name("archive.json.bz2"));
    }

    #[test]
    fn a_windows_identity_triple_splits_into_database_guid_and_age() {
        assert_eq!(
            parse_windows_identifier("ntkrnlmp.pdb|aa1b|3"),
            Some(("ntkrnlmp.pdb".into(), "AA1B".into(), 3))
        );
        // An age that is not a number is not an age. Comparing it as a string
        // would make "01" and "1" different symbol files for one kernel.
        assert!(parse_windows_identifier("ntkrnlmp.pdb|AA1B|x").is_none());
        assert!(parse_windows_identifier("ntkrnlmp.pdb|AA1B").is_none());
        assert!(parse_windows_identifier("a|b|1|c").is_none());
        assert!(parse_windows_identifier("|AA1B|1").is_none());
    }

    #[test]
    fn the_symbol_file_matching_the_kernels_guid_and_age_is_found() {
        let dir = TempDir::new("match");
        dir.write(
            &format!("ntkrnlmp.pdb/{GUID}-1.json"),
            &windows_isf("ntkrnlmp.pdb", GUID, 1),
        );
        dir.write(
            "ntkrnlmp.pdb/0000000000000000000000000000FFFF-1.json",
            &windows_isf("ntkrnlmp.pdb", "0000000000000000000000000000FFFF", 1),
        );

        let outcome = find_matching_isf(
            std::slice::from_ref(&dir.path),
            &want("ntkrnlmp.pdb", GUID, 1),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert_eq!(outcome.matches.len(), 1, "{:?}", outcome.matches);
        assert_eq!(outcome.matches[0].guid, GUID);
        assert_eq!(outcome.matches[0].age, 1);
        assert_eq!(outcome.matches[0].database, "ntkrnlmp.pdb");
        assert_eq!(
            outcome.matches[0].identifier(),
            format!("ntkrnlmp.pdb|{GUID}|1")
        );
        assert!(!outcome.truncated);
    }

    #[test]
    fn a_file_with_the_right_guid_but_the_wrong_age_is_not_a_match() {
        // Age is part of identity, not a version hint. Two ages of one GUID are
        // different files with different layouts.
        let dir = TempDir::new("age");
        dir.write(
            &format!("ntkrnlmp.pdb/{GUID}-2.json"),
            &windows_isf("ntkrnlmp.pdb", GUID, 2),
        );
        let outcome = find_matching_isf(
            std::slice::from_ref(&dir.path),
            &want("ntkrnlmp.pdb", GUID, 1),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert!(outcome.matches.is_empty());
        assert_eq!(outcome.files_seen, 1);
    }

    #[test]
    fn a_file_named_for_the_right_guid_but_declaring_another_is_refused() {
        // The name is a hint for finding the file quickly, never evidence of
        // what is inside it. A store whose file names have drifted from their
        // contents must not silently load the wrong kernel's layouts.
        let dir = TempDir::new("liar");
        dir.write(
            &format!("ntkrnlmp.pdb/{GUID}-1.json"),
            &windows_isf("ntkrnlmp.pdb", "0000000000000000000000000000FFFF", 1),
        );
        let outcome = find_matching_isf(
            std::slice::from_ref(&dir.path),
            &want("ntkrnlmp.pdb", GUID, 1),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert!(outcome.matches.is_empty());
        assert_eq!(outcome.files_identified, 1, "the hinted file was opened");
    }

    #[test]
    fn a_correct_isf_under_an_unconventional_name_is_still_found() {
        let dir = TempDir::new("unconventional");
        dir.write(
            "some/where/kernel-symbols.json",
            &windows_isf("ntkrnlmp.pdb", GUID, 1),
        );
        let outcome = find_matching_isf(
            std::slice::from_ref(&dir.path),
            &want("ntkrnlmp.pdb", GUID, 1),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert_eq!(outcome.matches.len(), 1);
    }

    #[test]
    fn a_file_agreeing_on_identity_but_not_on_pdb_name_is_offered_after_an_exact_one() {
        let dir = TempDir::new("order");
        dir.write("a-other.json", &windows_isf("ntoskrnl.pdb", GUID, 1));
        dir.write("b-exact.json", &windows_isf("ntkrnlmp.pdb", GUID, 1));
        let outcome = find_matching_isf(
            std::slice::from_ref(&dir.path),
            &want("ntkrnlmp.pdb", GUID, 1),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert_eq!(outcome.matches.len(), 2);
        assert_eq!(outcome.matches[0].database, "ntkrnlmp.pdb");
        assert_eq!(outcome.matches[1].database, "ntoskrnl.pdb");
    }

    #[test]
    fn a_search_that_hits_its_identification_budget_says_so() {
        let dir = TempDir::new("budget");
        for index in 0..4 {
            dir.write(
                &format!("file{index}.json"),
                &windows_isf("ntkrnlmp.pdb", "0000000000000000000000000000FFFF", 1),
            );
        }
        let outcome = find_matching_isf(
            std::slice::from_ref(&dir.path),
            &want("ntkrnlmp.pdb", GUID, 1),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            2,
        );
        assert!(outcome.matches.is_empty());
        assert!(
            outcome.truncated,
            "a budget-limited search that found nothing must not read as an exhaustive one"
        );
        assert_eq!(outcome.files_identified, 2);
    }

    #[test]
    fn a_directory_that_cannot_be_read_does_not_fail_the_whole_search() {
        let dir = TempDir::new("partial");
        dir.write(
            &format!("ntkrnlmp.pdb/{GUID}-1.json"),
            &windows_isf("ntkrnlmp.pdb", GUID, 1),
        );
        let missing = dir.path.join("not-a-real-directory");
        let outcome = find_matching_isf(
            &[missing, dir.path.clone()],
            &want("ntkrnlmp.pdb", GUID, 1),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert_eq!(outcome.matches.len(), 1);
    }

    #[test]
    fn files_that_are_not_symbol_files_are_never_opened() {
        let dir = TempDir::new("noise");
        dir.write("ntkrnlmp.pdb", "not an ISF at all");
        dir.write("notes.txt", "nor is this");
        let outcome = find_matching_isf(
            std::slice::from_ref(&dir.path),
            &want("ntkrnlmp.pdb", GUID, 1),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert_eq!(outcome.files_seen, 0);
        assert_eq!(outcome.files_identified, 0);
        assert!(outcome.matches.is_empty());
    }

    #[test]
    fn the_search_outcome_serialises_the_facts_a_report_needs() {
        let outcome = IsfSearchOutcome {
            files_seen: 12,
            files_identified: 3,
            truncated: true,
            ..IsfSearchOutcome::default()
        };
        let json = outcome.to_json();
        assert_eq!(json["files_seen"], 12);
        assert_eq!(json["files_identified"], 3);
        assert_eq!(json["truncated"], true);
        assert_eq!(json["matches"], 0);
    }
}
