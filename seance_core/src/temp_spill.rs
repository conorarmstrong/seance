//! A temporary file that removes itself when its handle is dropped.
//!
//! Several plugins stage an evidence artifact to a temp file so a C parser
//! (libesedb, libregf, …) can open it by path, then parse it. The obvious
//! `write` + best-effort `fs::remove_file(path)` at the end leaks the temp file
//! whenever anything between the two panics — and the orchestrator swallows
//! parser panics with `catch_unwind`, so the removal line is simply never
//! reached. Repeated over hostile or corrupt evidence, `/tmp` fills and later
//! ingestion fails.
//!
//! [`TempSpill`] moves the removal into `Drop`, so cleanup is guaranteed on
//! every exit path — normal return, `?`, or unwinding panic. It is format
//! agnostic (any extension), unlike the SQLite-specific spill in
//! `seance_sqlite_util`, so ESE and any other spill-to-parse plugin can share it.

use std::io;
use std::path::{Path, PathBuf};

/// A uniquely-named temporary file, removed from disk when dropped.
#[derive(Debug)]
pub struct TempSpill {
    path: PathBuf,
}

impl TempSpill {
    /// Build the unique temp path `seance_<tag>_<uuid>.<ext>` in the system temp
    /// dir. The uuid makes concurrent ingests collision-free.
    fn temp_path(tag: &str, ext: &str) -> PathBuf {
        std::env::temp_dir().join(format!("seance_{tag}_{}.{ext}", uuid::Uuid::new_v4()))
    }

    /// Spill `bytes` to a new uniquely-named temp file and return the guard.
    /// The file is removed when the returned [`TempSpill`] drops.
    pub fn write(bytes: &[u8], tag: &str, ext: &str) -> io::Result<TempSpill> {
        use std::io::Write;
        let path = Self::temp_path(tag, ext);
        // The spill holds reconstructed evidence content, and the temp dir is
        // shared: create it owner-only (not the umask's 0644) and refuse to
        // reuse a path that already exists. Later reopens by path keep the mode.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        // From here the file exists: build the guard first so a failed write
        // removes it instead of leaking it.
        let spill = TempSpill { path };
        file.write_all(bytes)?;
        Ok(spill)
    }

    /// The path of the spilled file, for handing to a path-based parser.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempSpill {
    fn drop(&mut self) {
        // Best-effort: the file may already be gone (e.g. a test removed it), and
        // there is nothing useful to do with an error while unwinding.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_path_holds_the_bytes() {
        let spill = TempSpill::write(b"hello ese", "unit", "dat").unwrap();
        assert_eq!(std::fs::read(spill.path()).unwrap(), b"hello ese");
        // The name is namespaced and carries the requested extension.
        let name = spill.path().file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("seance_unit_"), "namespaced name: {name}");
        assert!(name.ends_with(".dat"), "extension preserved: {name}");
    }

    #[cfg(unix)]
    #[test]
    fn a_spill_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let spill = TempSpill::write(b"evidence", "unit", "bin").unwrap();
        let mode = std::fs::metadata(spill.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "group/other must have no access: {mode:o}");
    }

    #[test]
    fn drop_removes_the_file() {
        let path = {
            let spill = TempSpill::write(b"transient", "unit", "bin").unwrap();
            let p = spill.path().to_path_buf();
            assert!(p.exists(), "the spill exists while the guard is alive");
            p
            // guard dropped here
        };
        assert!(
            !path.exists(),
            "the spill must be removed when the guard drops"
        );
    }

    #[test]
    fn drop_after_a_panic_still_removes_the_file() {
        // The whole reason this type exists: a panic between spill and parse must
        // not leak the temp file. Catch a panic that happens while a guard is
        // live, then confirm the file is gone.
        let captured = std::sync::Mutex::new(None);
        let result = std::panic::catch_unwind(|| {
            let spill = TempSpill::write(b"boom", "unit", "dat").unwrap();
            *captured.lock().unwrap() = Some(spill.path().to_path_buf());
            panic!("parser blew up");
        });
        assert!(result.is_err(), "the closure panicked");
        let path = captured.lock().unwrap().take().unwrap();
        assert!(
            !path.exists(),
            "a panic between spill and parse must not leak the temp file"
        );
    }

    #[test]
    fn two_spills_do_not_collide() {
        let a = TempSpill::write(b"a", "unit", "dat").unwrap();
        let b = TempSpill::write(b"b", "unit", "dat").unwrap();
        assert_ne!(a.path(), b.path(), "each spill gets a unique path");
    }
}
