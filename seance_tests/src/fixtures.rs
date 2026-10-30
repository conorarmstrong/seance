//! Where the file-level fixtures these tests read are looked for.
//!
//! The parser tests in this crate name their fixtures under `test_data/`, and
//! nearly every one of those files (`SAM`, `SYSTEM`, `SOFTWARE`, `example.lnk`,
//! `activity.sqlite`, `Downloads.plist`, `syslog.zip`, the browser histories,
//! the jump lists) is plaso's test corpus (Apache-2.0), which a checkout may
//! hold under `reference/plaso/test_data/` instead. Both directories are
//! gitignored; either is accepted, `test_data/` first.
//!
//! A test whose fixture is in neither place returns early after printing which
//! two places it looked, so `ok` on such a checkout means "nothing compared",
//! not "compared and agreed". A fixture that only ever lived in `test_data/`
//! (the `$LogFile` samples, the golden images) is unaffected: the fallback
//! only fires for a path that exists in the plaso tree.

use std::path::PathBuf;

/// The upstream copy of the fixtures named under `test_data/`.
const PLASO_TEST_DATA: &str = "reference/plaso/test_data";

/// The workspace root, whether cargo ran from it or from `seance_tests/`.
pub fn workspace_root() -> PathBuf {
    let cwd = std::env::current_dir().expect("a current directory");
    if cwd.ends_with("seance_tests") {
        cwd.parent()
            .expect("seance_tests sits in the workspace")
            .into()
    } else {
        cwd
    }
}

/// Resolve a fixture named as `test_data/<rest>`.
///
/// Returns the path to read, or `None` after printing a skip line naming
/// every place that was looked in.
pub fn resolve(relative: &str) -> Option<PathBuf> {
    let root = workspace_root();
    let primary = root.join(relative);
    if primary.exists() {
        return Some(primary);
    }
    let Some(rest) = relative.strip_prefix("test_data/") else {
        eprintln!(
            "skipping: fixture absent (gitignored corpus): {}",
            primary.display()
        );
        return None;
    };
    let plaso = root.join(PLASO_TEST_DATA).join(rest);
    if plaso.exists() {
        return Some(plaso);
    }
    eprintln!(
        "skipping: fixture absent from both gitignored corpora: {} and {}",
        primary.display(),
        plaso.display()
    );
    None
}
