//! Unlock-to-read: keys derived from an examiner's password, held in process
//! memory so a locked artifact's content can be read after the run that first
//! opened it (`BUG-026`; owner decision of 2026-09-26 on key retention).
//!
//! # The discipline
//!
//! - **Explicit and audited.** An entry is put here only by the unlock route
//!   (`POST …/artifacts/{id}/unlock`) after the password has been checked,
//!   and only once the audit row naming the *kind* has been written. It is
//!   taken out by `DELETE` on the same route, by deleting the case, by
//!   expiry, or by a restart. The first three are audited (`unlock_forgotten`
//!   with `reason=lock`, `case_delete` or `expired`); a restart leaves no row
//!   because the process that held the keys is gone. The audit never carries
//!   the secret or the keys.
//! - **Scoped.** An entry is keyed by `(case_id, source)`, where `source`
//!   is the canonical path of the evidence it opens. The same backup
//!   ingested into another case is locked there until it is unlocked there.
//! - **Short-lived.** Every entry expires after the keyring's TTL (default
//!   8 hours, `SEANCE_UNLOCK_TTL_SECS`). An expired entry is never
//!   returned; every lookup, insert, removal and per-case count drops
//!   expired entries first ([`Keyring::len`] does not), and the
//!   unlock route's expiry sweep ([`Keyring::sweep_at`], at most a minute
//!   apart) drops them when nothing else touches the keyring and reports each
//!   one for its audit row. So an expired entry can stay in memory for up to
//!   one sweep interval past its expiry, never longer.
//! - **Memory only.** The keyring is not `Serialize` or `Clone`, its `Debug`
//!   prints a count, and nothing here writes to the database, an export, a
//!   backup of the case or a log. The values it holds zero their key bytes
//!   when the last handle drops (for iOS backups, `ClassKey`'s `Drop`).
//!
//! # What it cannot promise
//!
//! A read that is under way when an entry is removed keeps its own handle
//! (and the per-file key it unwrapped) until that read's data source is
//! dropped. Process memory can be swapped to disk or captured in a core dump
//! like any other; this module does not lock pages.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Default lifetime of an unlock: 8 hours.
pub const DEFAULT_TTL: Duration = Duration::from_secs(8 * 60 * 60);

/// The environment variable that overrides [`DEFAULT_TTL`], in seconds.
pub const TTL_ENV: &str = "SEANCE_UNLOCK_TTL_SECS";

struct Entry<T> {
    value: Arc<T>,
    expires_at: Instant,
}

struct Inner<T> {
    entries: HashMap<(Uuid, String), Entry<T>>,
    /// `(case, source)` of every entry dropped by expiry and not yet handed
    /// to [`Keyring::sweep_at`] for its audit row.
    expired: Vec<(Uuid, String)>,
}

impl<T> Inner<T> {
    /// Drop (and so zero, once no read holds a handle) every entry expired at
    /// `now`, queueing each for its audit row.
    fn purge(&mut self, now: Instant) {
        let gone: Vec<(Uuid, String)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for k in gone {
            self.entries.remove(&k);
            self.expired.push(k);
        }
    }
}

/// Keys held for reading, per `(case, source)`, each with an expiry.
///
/// Every operation drops the entries that have expired, and the unlock route
/// runs a periodic sweep ([`Self::sweep_at`]) so an expired entry is dropped
/// even when nothing else touches the keyring.
pub struct Keyring<T> {
    ttl: Duration,
    inner: Mutex<Inner<T>>,
}

impl<T> std::fmt::Debug for Keyring<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("ttl", &self.ttl)
            .field("entries", &self.len())
            .finish()
    }
}

impl<T> Keyring<T> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                expired: Vec::new(),
            }),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<T>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Hold `value` for `(case_id, source)` until `now + ttl`, replacing any
    /// earlier entry. Returns the expiry.
    pub fn insert_at(&self, case_id: Uuid, source: &str, value: T, now: Instant) -> Instant {
        let expires_at = now + self.ttl;
        let mut inner = self.lock();
        inner.purge(now);
        inner.entries.insert(
            (case_id, source.to_string()),
            Entry {
                value: Arc::new(value),
                expires_at,
            },
        );
        expires_at
    }

    /// [`Self::insert_at`] with the current time.
    pub fn insert(&self, case_id: Uuid, source: &str, value: T) -> Instant {
        self.insert_at(case_id, source, value, Instant::now())
    }

    /// The value held for exactly this case and source, if it has not
    /// expired. Every expired entry is dropped here first.
    pub fn get_at(&self, case_id: Uuid, source: &str, now: Instant) -> Option<Arc<T>> {
        let mut inner = self.lock();
        inner.purge(now);
        inner
            .entries
            .get(&(case_id, source.to_string()))
            .map(|e| Arc::clone(&e.value))
    }

    /// [`Self::get_at`] with the current time.
    pub fn get(&self, case_id: Uuid, source: &str) -> Option<Arc<T>> {
        self.get_at(case_id, source, Instant::now())
    }

    /// Forget the entry for this case and source. `true` if one was held and
    /// had not expired (an expired one is dropped and reported by the sweep).
    pub fn remove(&self, case_id: Uuid, source: &str) -> bool {
        let mut inner = self.lock();
        inner.purge(Instant::now());
        inner
            .entries
            .remove(&(case_id, source.to_string()))
            .is_some()
    }

    /// How many unexpired entries are held for `case_id`.
    pub fn held_for_case(&self, case_id: Uuid) -> usize {
        let mut inner = self.lock();
        inner.purge(Instant::now());
        inner.entries.keys().filter(|(c, _)| *c == case_id).count()
    }

    /// Forget every entry for `case_id`. Returns how many unexpired ones were
    /// held.
    pub fn clear_case(&self, case_id: Uuid) -> usize {
        let mut inner = self.lock();
        inner.purge(Instant::now());
        let before = inner.entries.len();
        inner.entries.retain(|(c, _), _| *c != case_id);
        before - inner.entries.len()
    }

    /// Drop every entry expired at `now` and hand back the `(case, source)`
    /// of each entry forgotten by expiry since the last sweep — whichever
    /// operation dropped it — so the caller can audit each forget.
    pub fn sweep_at(&self, now: Instant) -> Vec<(Uuid, String)> {
        let mut inner = self.lock();
        inner.purge(now);
        std::mem::take(&mut inner.expired)
    }

    /// Put back forgets whose audit row could not be written, so the next
    /// sweep tries again.
    pub fn requeue_unaudited(&self, forgotten: Vec<(Uuid, String)>) {
        self.lock().expired.extend(forgotten);
    }

    /// How many entries are held, without dropping expired ones first.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The TTL this process uses: [`TTL_ENV`] if it parses as a positive number
/// of seconds, else [`DEFAULT_TTL`].
pub fn configured_ttl() -> Duration {
    std::env::var(TTL_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_TTL)
}

/// The process-wide keyring for unlocked iOS backups. Empty at start-up:
/// nothing survives a restart.
pub fn ios_backups() -> &'static Keyring<seance_plugin_ios_backup::UnlockedBackup> {
    static RING: OnceLock<Keyring<seance_plugin_ios_backup::UnlockedBackup>> = OnceLock::new();
    RING.get_or_init(|| Keyring::new(configured_ttl()))
}

/// The key a backup directory is held under: its canonical path when it can
/// be resolved, else the path as recorded.
pub fn source_key(path: &std::path::Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Secret(#[allow(dead_code)] [u8; 4]);
    impl std::fmt::Debug for Secret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("<redacted>")
        }
    }

    const BACKUP: &str = "/evidence/backup-1";

    #[test]
    fn a_stored_key_is_returned_only_for_its_case_and_backup() {
        let ring = Keyring::new(Duration::from_secs(60));
        let (case_a, case_b) = (Uuid::new_v4(), Uuid::new_v4());
        let now = Instant::now();
        ring.insert_at(case_a, BACKUP, Secret(*b"key!"), now);
        assert!(ring.get_at(case_a, BACKUP, now).is_some());
        assert!(ring.get_at(case_b, BACKUP, now).is_none(), "another case");
        assert!(
            ring.get_at(case_a, "/evidence/backup-2", now).is_none(),
            "another backup"
        );
    }

    #[test]
    fn an_expired_entry_is_not_returned() {
        let ring = Keyring::new(Duration::from_secs(60));
        let case = Uuid::new_v4();
        let now = Instant::now();
        let expires = ring.insert_at(case, BACKUP, Secret(*b"key!"), now);
        assert_eq!(expires, now + Duration::from_secs(60));
        assert!(ring
            .get_at(case, BACKUP, now + Duration::from_secs(59))
            .is_some());
        assert!(ring
            .get_at(case, BACKUP, now + Duration::from_secs(60))
            .is_none());
        assert!(ring.is_empty(), "an expired entry is dropped, not kept");
    }

    #[test]
    fn a_removed_or_cleared_entry_is_forgotten() {
        let ring = Keyring::new(Duration::from_secs(60));
        let (case, other) = (Uuid::new_v4(), Uuid::new_v4());
        let now = Instant::now();
        ring.insert_at(case, BACKUP, Secret(*b"key!"), now);
        ring.insert_at(case, "/b2", Secret(*b"key!"), now);
        ring.insert_at(other, BACKUP, Secret(*b"key!"), now);
        assert!(ring.remove(case, BACKUP));
        assert!(!ring.remove(case, BACKUP), "a second lock finds nothing");
        assert_eq!(ring.clear_case(case), 1);
        assert!(
            ring.get_at(other, BACKUP, now).is_some(),
            "other cases untouched"
        );
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn an_expired_entry_is_dropped_by_an_insert_not_only_by_a_lookup() {
        let ring = Keyring::new(Duration::from_secs(60));
        let (case, other) = (Uuid::new_v4(), Uuid::new_v4());
        let t0 = Instant::now();
        ring.insert_at(case, BACKUP, Secret(*b"key!"), t0);
        ring.insert_at(
            other,
            BACKUP,
            Secret(*b"key!"),
            t0 + Duration::from_secs(61),
        );
        assert_eq!(ring.len(), 1, "the expired entry is no longer held");
    }

    #[test]
    fn an_expired_entry_is_dropped_by_a_remove_or_a_case_clear() {
        // A zero TTL: every entry has expired by the next operation.
        let ring = Keyring::new(Duration::ZERO);
        let (case, other) = (Uuid::new_v4(), Uuid::new_v4());
        ring.insert(case, BACKUP, Secret(*b"key!"));
        ring.insert(other, BACKUP, Secret(*b"key!"));
        assert!(!ring.remove(case, "/elsewhere"));
        assert!(ring.is_empty(), "remove drops expired entries");
        ring.insert(case, BACKUP, Secret(*b"key!"));
        assert_eq!(
            ring.clear_case(other),
            0,
            "an expired entry is not counted as held"
        );
        assert!(ring.is_empty(), "clear_case drops expired entries");
    }

    #[test]
    fn every_forget_by_expiry_is_reported_once_for_the_audit() {
        let ring = Keyring::new(Duration::from_secs(60));
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let t0 = Instant::now();
        ring.insert_at(a, BACKUP, Secret(*b"key!"), t0);
        ring.insert_at(b, "/b2", Secret(*b"key!"), t0);
        // A lookup after expiry drops both; the sweep still reports both.
        assert!(ring
            .get_at(a, BACKUP, t0 + Duration::from_secs(61))
            .is_none());
        let mut gone = ring.sweep_at(t0 + Duration::from_secs(61));
        gone.sort();
        let mut want = vec![(a, BACKUP.to_string()), (b, "/b2".to_string())];
        want.sort();
        assert_eq!(gone, want);
        assert!(
            ring.sweep_at(t0 + Duration::from_secs(62)).is_empty(),
            "reported once"
        );
        // A forget whose audit failed is reported again.
        ring.requeue_unaudited(vec![(a, BACKUP.to_string())]);
        assert_eq!(ring.sweep_at(t0 + Duration::from_secs(63)).len(), 1);
    }

    #[test]
    fn an_explicit_remove_is_not_reported_as_an_expiry() {
        let ring = Keyring::new(Duration::from_secs(60));
        let case = Uuid::new_v4();
        let t0 = Instant::now();
        ring.insert_at(case, BACKUP, Secret(*b"key!"), t0);
        assert!(ring.remove(case, BACKUP));
        assert!(ring.sweep_at(t0 + Duration::from_secs(61)).is_empty());
    }

    #[test]
    fn debug_output_never_contains_key_bytes() {
        let ring = Keyring::new(Duration::from_secs(60));
        ring.insert_at(Uuid::new_v4(), BACKUP, Secret(*b"k3y!"), Instant::now());
        let dbg = format!("{ring:?}");
        assert!(!dbg.contains("k3y"), "{dbg}");
        assert!(!dbg.contains(BACKUP), "not even the source path: {dbg}");
        assert!(dbg.contains("entries: 1"), "{dbg}");
    }

    /// Compile-time: the keyring is neither `Serialize` nor `Clone`. If either
    /// is ever derived, the trait call below becomes ambiguous and this module
    /// stops compiling (the `static_assertions::assert_not_impl_any` trick).
    #[test]
    fn the_keyring_type_is_not_serialize_or_clone() {
        trait AmbiguousIfImpl<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
        struct IsSerialize;
        impl<T: ?Sized + serde::Serialize> AmbiguousIfImpl<IsSerialize> for T {}
        struct IsClone;
        impl<T: Clone> AmbiguousIfImpl<IsClone> for T {}
        <Keyring<Secret> as AmbiguousIfImpl<_>>::check();
    }
}
