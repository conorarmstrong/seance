//! Workspace-level lock that distinguishes a *stale* index lock (left by a
//! crashed or killed previous run) from a *live* one (another running Seance
//! instance). Blindly deleting Tantivy's writer lock is unsafe — its job is to
//! stop two writers from corrupting the index. This guard only clears leftover
//! locks once it has confirmed no other live Seance process owns the workspace.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Held for the lifetime of the process. Removes the pidfile on clean shutdown.
pub struct WorkspaceLock {
    pidfile: PathBuf,
}

impl WorkspaceLock {
    /// Take ownership of `workspace`. Errors (without touching anything) if a
    /// live Seance instance already owns it; otherwise reclaims a stale lock,
    /// clearing leftover search-index locks, and records our PID.
    ///
    /// Ownership is decided by an ATOMIC create of the pidfile, not by "read,
    /// then write". Two Seance processes starting together both used to see the
    /// same stale pidfile, both conclude the owner was dead, both clear the
    /// Tantivy writer lock and both proceed — two writers on one index, which
    /// is exactly the corruption that lock exists to prevent. Here only one
    /// creator can win, and reclaiming a stale pidfile goes through a rename
    /// that only one process can perform.
    pub fn acquire(workspace: &Path) -> Result<Self> {
        let pidfile = workspace.join("seance.pid");
        let me = std::process::id();

        // Bounded: each iteration either wins, loses to a live owner, or steals
        // one stale pidfile. Without a bound a pathological loop of crashing
        // starters could spin here forever.
        for _ in 0..8 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pidfile)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    file.write_all(me.to_string().as_bytes()).with_context(|| {
                        format!("Failed to write pidfile {}", pidfile.display())
                    })?;
                    drop(file);

                    // We own the workspace: clear any index lock a killed run
                    // left behind. This happens only on the winning path, so a
                    // process that lost the race never touches the index locks.
                    clear_stale_index_locks(workspace);
                    return Ok(Self { pidfile });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let owner = read_pid(&pidfile);
                    match owner {
                        Some(owner) if owner != me && pid_is_alive(owner) => {
                            bail!(
                                "Another Seance instance (PID {owner}) is already using this workspace:\n  \
                                 {}\n\n\
                                 Stop that instance, or start with a different --workspace.\n\
                                 If you are certain no Seance is running (e.g. after a crash), delete:\n  \
                                 {}",
                                workspace.display(),
                                pidfile.display(),
                            );
                        }
                        _ => {
                            // Stale (or ours from a previous run in this
                            // process). Claim it by RENAMING it aside: rename
                            // moves a specific directory entry, so if a
                            // competitor got there first ours fails with
                            // NotFound and we simply re-test the new pidfile.
                            let stolen = workspace.join(format!("seance.pid.stale.{me}"));
                            match fs::rename(&pidfile, &stolen) {
                                Ok(()) => {
                                    tracing::warn!(
                                        "Reclaiming workspace from a previous run (PID {} is no longer running)",
                                        owner.map(|p| p.to_string()).unwrap_or_else(|| "unknown".into())
                                    );
                                    let _ = fs::remove_file(&stolen);
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                    // Another starter claimed it first; loop and
                                    // re-evaluate against whatever it wrote.
                                }
                                Err(e) => {
                                    return Err(e).with_context(|| {
                                        format!(
                                            "Failed to reclaim stale pidfile {}",
                                            pidfile.display()
                                        )
                                    });
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("Failed to create pidfile {}", pidfile.display())
                    });
                }
            }
        }

        bail!(
            "Could not take the workspace lock at {} after repeated attempts; \
             another Seance instance appears to be starting at the same time.",
            pidfile.display()
        )
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.pidfile);
    }
}

fn read_pid(pidfile: &Path) -> Option<u32> {
    fs::read_to_string(pidfile).ok()?.trim().parse().ok()
}

/// True if a process with this PID currently exists.
#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    // kill(pid, 0) performs no signal, only permission/existence checks:
    // 0 => exists and signalable; EPERM => exists but owned by another user;
    // ESRCH => no such process.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// True if a process with this PID currently exists (Windows).
#[cfg(windows)]
fn pid_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // A running process returns exit code STILL_ACTIVE (259); once it exits,
    // GetExitCodeProcess returns its real code, so we can distinguish live from
    // dead-but-lingering handles. A PID that cannot be opened at all is gone,
    // except ERROR_ACCESS_DENIED (5), which means it exists under another user.
    const STILL_ACTIVE: u32 = 259;
    const ERROR_ACCESS_DENIED: i32 = 5;

    // SAFETY: FFI calls with a valid out-param; the handle is closed before we
    // return, on every path that opened one.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            // Could not open: dead process, or an existing one we may not touch.
            return std::io::Error::last_os_error().raw_os_error() == Some(ERROR_ACCESS_DENIED);
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(handle, &mut code);
        CloseHandle(handle);
        ok != 0 && code == STILL_ACTIVE
    }
}

#[cfg(not(any(unix, windows)))]
fn pid_is_alive(_pid: u32) -> bool {
    // No portable check on this platform; assume alive so we never clobber a
    // live index.
    true
}

fn clear_stale_index_locks(workspace: &Path) {
    let index_dir = workspace.join("search_index");
    for name in [".tantivy-writer.lock", ".tantivy-meta.lock"] {
        let lock = index_dir.join(name);
        if lock.exists() {
            match fs::remove_file(&lock) {
                Ok(()) => tracing::info!("Cleared stale index lock {}", lock.display()),
                Err(e) => tracing::warn!("Could not clear stale lock {}: {e}", lock.display()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{pid_is_alive, WorkspaceLock};

    #[test]
    fn current_process_is_alive() {
        assert!(pid_is_alive(std::process::id()));
    }

    #[test]
    fn absent_pid_is_not_alive() {
        // BUG-097: a PID that does not name a live process must report dead so a
        // stale pidfile can be reclaimed after a crash (previously always-true on
        // non-Unix). This value is effectively never a running process on any OS.
        assert!(!pid_is_alive(0x7FFF_FFFE));
    }

    fn temp_workspace(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "seance_wslock_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn a_workspace_owned_by_another_live_process_is_refused() {
        // The whole point of the lock: a second live starter must not take a
        // workspace already in use, or two Tantivy writers corrupt one index.
        // PID 1 (init/launchd) is always running and is never this test.
        let dir = temp_workspace("live");
        std::fs::write(dir.join("seance.pid"), "1").unwrap();
        assert!(
            WorkspaceLock::acquire(&dir).is_err(),
            "a live owner must not be displaced by a second start"
        );
        // The refusal must leave the existing owner's pidfile untouched.
        assert_eq!(
            std::fs::read_to_string(dir.join("seance.pid"))
                .unwrap()
                .trim(),
            "1"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn releasing_the_lock_lets_the_workspace_be_taken_again() {
        let dir = temp_workspace("release");
        let first = WorkspaceLock::acquire(&dir).expect("first acquire must succeed");
        drop(first);
        WorkspaceLock::acquire(&dir).expect("released workspace must be reclaimable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_pidfile_is_reclaimed() {
        // Crash recovery: the pidfile names a process that no longer exists.
        let dir = temp_workspace("stale");
        std::fs::write(dir.join("seance.pid"), "2147483646").unwrap();
        let lock = WorkspaceLock::acquire(&dir).expect("a stale lock must be reclaimable");
        let recorded = std::fs::read_to_string(dir.join("seance.pid")).unwrap();
        assert_eq!(
            recorded.trim(),
            std::process::id().to_string(),
            "the reclaiming process must own the pidfile"
        );
        drop(lock);
        assert!(
            !dir.join("seance.pid").exists(),
            "a clean shutdown removes the pidfile"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_pidfile_is_treated_as_stale_not_as_a_live_owner() {
        // A truncated/garbage pidfile (killed mid-write) names nobody; it must
        // not lock the workspace out permanently.
        let dir = temp_workspace("garbage");
        std::fs::write(dir.join("seance.pid"), "not-a-pid").unwrap();
        let lock = WorkspaceLock::acquire(&dir).expect("garbage pidfile must be reclaimable");
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
