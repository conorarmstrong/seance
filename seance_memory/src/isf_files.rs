//! Finding the ISF symbol files in an examiner's symbol directories.
//!
//! The Linux, macOS and Windows analysis crates each carried a copy of this
//! walk (ROADMAP §5.11, measured by `scripts/clone-scan.py`). The copies agreed
//! except on one point: macOS sorted a search that stopped at its file cap and
//! the other two did not, so for the same image the pack chosen could depend on
//! how the file system happened to enumerate a directory. The shared walk sorts
//! in every case.

use std::path::PathBuf;

/// Suffixes an ISF is stored under. A file with any other name is not opened:
/// identifying every file in a symbol directory would stream gigabytes to learn
/// nothing.
pub const ISF_SUFFIXES: [&str; 3] = [".json", ".json.xz", ".json.gz"];

/// Directory levels the search descends. Symbol stores are shallow (a Windows
/// store is `<pdb>/<guid>-<age>/<file>`); the cap stops a symlink loop or a
/// pathological tree from becoming an unbounded walk.
pub const DEFAULT_MAX_DEPTH: usize = 8;

/// Files the search will enumerate. Reaching it marks the search truncated, so
/// "no symbols found" is never confused with "we stopped looking".
pub const DEFAULT_MAX_FILES: usize = 65_536;

/// Whether a file name looks like an ISF the analysis can read.
pub fn is_isf_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ISF_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

/// Enumerate candidate ISF files under `dirs`, sorted, and whether a cap
/// (`max_files` or `max_depth`) stopped the walk.
///
/// A directory that cannot be read is skipped rather than failing the search:
/// an examiner with three symbol directories, one on an unmounted share, should
/// still get their case done from the other two. The skip is visible only in
/// that fewer files were seen, which is why callers report `files_seen` beside
/// any "not found".
pub fn collect_isf_files(
    dirs: &[PathBuf],
    max_files: usize,
    max_depth: usize,
) -> (Vec<PathBuf>, bool) {
    let mut files = Vec::new();
    let mut truncated = false;
    // Explicit stack rather than recursion: a deep or cyclic tree must bound
    // the work, not the call stack.
    let mut stack: Vec<(PathBuf, usize)> = dirs.iter().map(|d| (d.clone(), 0usize)).collect();

    while let Some((dir, depth)) = stack.pop() {
        if depth > max_depth {
            truncated = true;
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            // Symlinks are not followed: a symbol directory is examiner-supplied
            // input, and a link out of it is a path this search has no reason to
            // take.
            if !kind.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !is_isf_file_name(name) {
                continue;
            }
            if files.len() >= max_files {
                // Sorted on this path too: a duplicate-banner rule that keeps
                // the first file in path order would otherwise pick a different
                // pack for the same image depending on directory order.
                files.sort();
                return (files, true);
            }
            files.push(path);
        }
    }
    files.sort();
    (files, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tree(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("seance_isf_files_{tag}_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("a/b")).unwrap();
        for f in [
            "z.json",
            "a/m.json.xz",
            "a/b/c.json.gz",
            "a/notes.txt",
            "a/b/ignored.bin",
        ] {
            fs::write(root.join(f), b"{}").unwrap();
        }
        root
    }

    #[test]
    fn only_isf_suffixes_are_candidates() {
        assert!(is_isf_file_name("Linux.JSON.XZ"));
        assert!(is_isf_file_name("a.json"));
        assert!(!is_isf_file_name("a.json.bak"));
        assert!(!is_isf_file_name("readme.txt"));
    }

    #[test]
    fn the_walk_finds_every_isf_below_a_directory_in_path_order() {
        let root = tree("all");
        let (files, truncated) = collect_isf_files(std::slice::from_ref(&root), 100, 8);
        assert!(!truncated);
        let names: Vec<_> = files
            .iter()
            .map(|p| {
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["a/b/c.json.gz", "a/m.json.xz", "z.json"]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_file_cap_says_it_stopped_and_still_returns_a_sorted_list() {
        let root = tree("cap");
        let (files, truncated) = collect_isf_files(std::slice::from_ref(&root), 2, 8);
        assert!(
            truncated,
            "a search that stopped is not a search that finished"
        );
        assert_eq!(files.len(), 2);
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(
            files, sorted,
            "the same image must pick the same pack every time"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_depth_cap_is_a_truncation_and_an_unreadable_directory_is_skipped() {
        let root = tree("depth");
        let (files, truncated) =
            collect_isf_files(&[root.clone(), root.join("does-not-exist")], 100, 1);
        assert!(truncated, "a.b is two levels down, past the cap of one");
        assert!(files.iter().any(|p| p.ends_with("a/m.json.xz")));
        assert!(!files.iter().any(|p| p.ends_with("c.json.gz")));
        let _ = fs::remove_dir_all(root);
    }
}
