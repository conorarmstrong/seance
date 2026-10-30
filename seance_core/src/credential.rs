//! A secret supplied by an examiner for **one** locked artifact, for **one**
//! module run (`HUNT-120`, `HUNT-171`, `HUNT-227`).
//!
//! # Why this exists
//!
//! A BitLocker or LUKS volume, a password-protected 7z, the Signal for iOS
//! store, an encrypted iOS backup, a Signal for Android backup and a WhatsApp
//! `crypt14` backup whose key file is not in the case all reach a
//! case as a record saying *this is encrypted and was not
//! read*. Until this module, the only way to hand the decryptor a credential
//! was a process flag or environment variable read when the server started, so
//! acting on a locked volume the case already reported meant restarting the
//! server and ingesting the evidence again. (The two backups had a per-run
//! route of their own, `run_module`'s `secrets` map, which merged a plain
//! string into artifact metadata and was never zeroed or audited for its
//! outcome; `SEC-204` moved them here and retired it.)
//!
//! # The channel
//!
//! The credential does **not** travel in artifact metadata, in the process
//! environment, or in anything serialised. The API builds a [`RunCredential`]
//! bound to one artifact, hands it to the orchestrator inside the ad-hoc
//! request (a field serde skips), and the orchestrator makes it visible to the
//! module for the duration of that one `process` call only, through
//! [`scoped`]. A module asks for it with [`for_artifact`], naming the artifact
//! it is processing and the kinds it can use; any other artifact, any other
//! kind, any other run gets `None`.
//!
//! The module reports what happened — [`RunCredential::accepted`] or
//! [`RunCredential::rejected`] — and the orchestrator acts on that report: an
//! accepted credential's records are persisted and supersede the locked
//! statement; a rejected one's are **not**, so the record saying the artifact
//! is locked still stands, and the job and the audit log say the secret was
//! refused.
//!
//! # What is held, and for how long
//!
//! The secret is a [`zeroize::Zeroizing`] string, zeroed when the last handle
//! to the [`RunCredential`] drops — which the orchestrator arranges straight
//! after the module returns. `Debug` prints the kind and never the value; there
//! is no `Display`, `Clone` or `Serialize`. What this cannot promise, and the
//! documentation says so: the HTTP request body the secret arrived in is freed
//! by the web framework, not zeroed; and the keys a decryptor *derives* from it
//! (a volume's FVEK, a LUKS master key) live inside the decrypting data source
//! for as long as the pipeline is still reading that volume.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

/// What kind of secret an examiner supplied. The kind — never the value — is
/// what the audit log, the job row and the processing log name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// A BitLocker user password.
    BitlockerPassword,
    /// A BitLocker 48-digit recovery password.
    BitlockerRecoveryPassword,
    /// A LUKS passphrase (LUKS1 or LUKS2).
    LuksPassphrase,
    /// A 7z archive password (AES-256 + SHA-256).
    SevenZipPassword,
    /// The Signal for iOS SQLCipher 4 raw key spec (the keychain item
    /// `GRDBDatabaseCipherKeySpec`), as `x'<hex>'` or bare hex.
    SignalIosKeySpec,
    /// An encrypted iTunes / Finder iOS backup's password (`SEC-204`).
    IosBackupPassword,
    /// The 30-digit passphrase of a Signal for Android `.backup` file
    /// (`SEC-204`).
    SignalBackupPassphrase,
    /// The key that opens a WhatsApp Android `crypt14` backup, for a backup
    /// whose key file is not in the case (an SD card seized without its
    /// phone; ROADMAP §5.7, owner decision (c) part b): the key file's bytes
    /// as hex, or the bare 32-byte key as 64 hex digits.
    WhatsappKey,
    /// The login password of a macOS `kych` keychain (`HUNT-111`, ROADMAP
    /// §3.1). It opens the keychain's `DbBlob`; it does not reveal any item.
    MacosKeychainPassword,
    /// The `/var/db/SystemKey` of a Mac, as hex of its 48 bytes: the key that
    /// opens `System.keychain`, which has no password (`HUNT-111`). It opens
    /// the keychain's `DbBlob`; it does not reveal any item.
    MacosSystemKey,
}

impl CredentialKind {
    /// Every kind, in the order the API documents them.
    pub const ALL: &'static [CredentialKind] = &[
        CredentialKind::BitlockerPassword,
        CredentialKind::BitlockerRecoveryPassword,
        CredentialKind::LuksPassphrase,
        CredentialKind::SevenZipPassword,
        CredentialKind::SignalIosKeySpec,
        CredentialKind::IosBackupPassword,
        CredentialKind::SignalBackupPassphrase,
        CredentialKind::WhatsappKey,
        CredentialKind::MacosKeychainPassword,
        CredentialKind::MacosSystemKey,
    ];

    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BitlockerPassword => "bitlocker_password",
            Self::BitlockerRecoveryPassword => "bitlocker_recovery_password",
            Self::LuksPassphrase => "luks_passphrase",
            Self::SevenZipPassword => "sevenz_password",
            Self::SignalIosKeySpec => "signal_ios_key_spec",
            Self::IosBackupPassword => "ios_backup_password",
            Self::SignalBackupPassphrase => "signal_backup_passphrase",
            Self::WhatsappKey => "whatsapp_key",
            Self::MacosKeychainPassword => "macos_keychain_password",
            Self::MacosSystemKey => "macos_system_key",
        }
    }

    /// Parse a wire name. Unknown names are `None`, never a default.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == s)
    }

    /// The module that consumes this kind of secret.
    pub fn module_id(self) -> &'static str {
        match self {
            Self::BitlockerPassword | Self::BitlockerRecoveryPassword => {
                "plugin.crypto.bitlocker_decryptor"
            }
            Self::LuksPassphrase => "plugin.crypto.luks_decryptor",
            Self::SevenZipPassword => "container.7z_expander",
            Self::SignalIosKeySpec | Self::SignalBackupPassphrase => "plugin.messaging.signal",
            Self::IosBackupPassword => "plugin.mobile.ios_backup",
            Self::WhatsappKey => "plugin.messaging.whatsapp",
            Self::MacosKeychainPassword | Self::MacosSystemKey => "macos.keychain",
        }
    }

    /// What to call it, in an examiner's words.
    pub fn label(self) -> &'static str {
        match self {
            Self::BitlockerPassword => "BitLocker password",
            Self::BitlockerRecoveryPassword => "BitLocker recovery password",
            Self::LuksPassphrase => "LUKS passphrase",
            Self::SevenZipPassword => "7z password",
            Self::SignalIosKeySpec => "Signal for iOS key spec",
            Self::IosBackupPassword => "iOS backup password",
            Self::SignalBackupPassphrase => "Signal backup passphrase",
            Self::WhatsappKey => "WhatsApp backup key",
            Self::MacosKeychainPassword => "macOS keychain password",
            Self::MacosSystemKey => "macOS SystemKey",
        }
    }
}

/// What a module did with the credential it was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialOutcome {
    /// The secret opened the artifact.
    Accepted,
    /// The secret was tried and refused. `reason` is the module's own
    /// statement and must never contain the secret.
    Rejected { reason: String },
}

/// One examiner-supplied secret, bound to one artifact.
///
/// Redacted in `Debug`; not `Clone`, `Display` or `Serialize`; the value is
/// zeroed when the last `Arc` to it drops.
pub struct RunCredential {
    artifact_id: Uuid,
    kind: CredentialKind,
    secret: Zeroizing<String>,
    requested_by: String,
    outcome: Mutex<Option<CredentialOutcome>>,
}

impl RunCredential {
    /// Take ownership of `secret`. The caller's `String` is moved in, so no
    /// second un-zeroed copy is left behind by this call.
    pub fn new(
        artifact_id: Uuid,
        kind: CredentialKind,
        secret: String,
        requested_by: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id,
            kind,
            secret: Zeroizing::new(secret),
            requested_by: requested_by.into(),
            outcome: Mutex::new(None),
        }
    }

    pub fn artifact_id(&self) -> Uuid {
        self.artifact_id
    }

    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// The user the audit log attributes the attempt to.
    pub fn requested_by(&self) -> &str {
        &self.requested_by
    }

    /// The secret itself. Named so that every read of it is easy to find: a
    /// caller must not log it, format it, copy it into a record or keep it
    /// past the call it needs it for.
    pub fn expose_secret(&self) -> &str {
        &self.secret
    }

    /// The module opened the artifact with this secret.
    pub fn accepted(&self) {
        self.set(CredentialOutcome::Accepted);
    }

    /// The module tried this secret and it did not open the artifact.
    /// `reason` must not contain the secret.
    pub fn rejected(&self, reason: impl Into<String>) {
        self.set(CredentialOutcome::Rejected {
            reason: reason.into(),
        });
    }

    /// What the module reported; `None` when it never used the secret.
    pub fn outcome(&self) -> Option<CredentialOutcome> {
        self.outcome
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set(&self, outcome: CredentialOutcome) {
        *self.outcome.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
    }
}

impl std::fmt::Debug for RunCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunCredential")
            .field("artifact_id", &self.artifact_id)
            .field("kind", &self.kind.as_str())
            .field("secret", &format_args!("<redacted>"))
            .field("requested_by", &self.requested_by)
            .finish()
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<RunCredential>>> = const { RefCell::new(None) };
}

/// Restores the previous credential when the scope ends, panic or not.
struct ScopeGuard(Option<Arc<RunCredential>>);

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let previous = self.0.take();
        CURRENT.with(|c| *c.borrow_mut() = previous);
    }
}

/// Run `f` with `credential` visible to [`for_artifact`] on this thread, and
/// only for the length of `f`.
pub fn scoped<R>(credential: Option<Arc<RunCredential>>, f: impl FnOnce() -> R) -> R {
    let previous = CURRENT.with(|c| std::mem::replace(&mut *c.borrow_mut(), credential));
    let _guard = ScopeGuard(previous);
    f()
}

/// The credential supplied for `artifact_id`, if this run carries one of one
/// of `kinds`.
///
/// Bound to the artifact: a module processing anything else — a child it is
/// about to emit, another volume in the same image — gets `None`.
pub fn for_artifact(artifact_id: Uuid, kinds: &[CredentialKind]) -> Option<Arc<RunCredential>> {
    CURRENT.with(|c| {
        c.borrow()
            .as_ref()
            .filter(|cred| cred.artifact_id == artifact_id && kinds.contains(&cred.kind))
            .cloned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "correct horse battery staple";

    #[test]
    fn debug_never_prints_the_secret() {
        let c = RunCredential::new(
            Uuid::new_v4(),
            CredentialKind::LuksPassphrase,
            SECRET.into(),
            "erin",
        );
        let shown = format!("{c:?}");
        assert!(!shown.contains(SECRET), "{shown}");
        assert!(shown.contains("luks_passphrase"), "{shown}");
    }

    #[test]
    fn a_credential_is_visible_only_to_its_artifact_its_kinds_and_its_scope() {
        let target = Uuid::new_v4();
        let other = Uuid::new_v4();
        let c = Arc::new(RunCredential::new(
            target,
            CredentialKind::SevenZipPassword,
            SECRET.into(),
            "erin",
        ));
        assert!(for_artifact(target, &[CredentialKind::SevenZipPassword]).is_none());
        scoped(Some(c.clone()), || {
            assert!(for_artifact(target, &[CredentialKind::SevenZipPassword]).is_some());
            assert!(for_artifact(other, &[CredentialKind::SevenZipPassword]).is_none());
            assert!(for_artifact(target, &[CredentialKind::LuksPassphrase]).is_none());
        });
        assert!(
            for_artifact(target, &[CredentialKind::SevenZipPassword]).is_none(),
            "the credential must not outlive the run it was scoped to"
        );
    }

    #[test]
    fn a_panicking_module_does_not_leave_the_credential_in_scope() {
        let target = Uuid::new_v4();
        let c = Arc::new(RunCredential::new(
            target,
            CredentialKind::LuksPassphrase,
            SECRET.into(),
            "erin",
        ));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scoped(Some(c.clone()), || panic!("module fault"))
        }));
        assert!(r.is_err());
        assert!(for_artifact(target, &[CredentialKind::LuksPassphrase]).is_none());
    }

    #[test]
    fn the_outcome_is_what_the_module_reported() {
        let c = RunCredential::new(
            Uuid::new_v4(),
            CredentialKind::BitlockerPassword,
            SECRET.into(),
            "erin",
        );
        assert_eq!(c.outcome(), None);
        c.rejected("no volume master key could be unlocked");
        assert!(matches!(
            c.outcome(),
            Some(CredentialOutcome::Rejected { .. })
        ));
        c.accepted();
        assert_eq!(c.outcome(), Some(CredentialOutcome::Accepted));
    }

    #[test]
    fn the_backup_passwords_are_credential_kinds_bound_to_their_parsers() {
        // SEC-204: the iOS backup password and the Signal Android backup
        // passphrase used to travel in run_module's plain `secrets` map.
        assert_eq!(
            CredentialKind::parse("ios_backup_password").map(|k| k.module_id()),
            Some("plugin.mobile.ios_backup")
        );
        assert_eq!(
            CredentialKind::parse("signal_backup_passphrase").map(|k| k.module_id()),
            Some("plugin.messaging.signal")
        );
    }

    #[test]
    fn the_whatsapp_key_is_a_credential_kind_bound_to_the_whatsapp_parser() {
        // ROADMAP §5.7, owner decision (c) part b: a crypt14 backup seized
        // without the phone that holds its key file.
        assert_eq!(
            CredentialKind::parse("whatsapp_key").map(|k| k.module_id()),
            Some("plugin.messaging.whatsapp")
        );
    }

    #[test]
    fn the_macos_keychain_password_is_a_credential_kind_bound_to_the_keychain_parser() {
        let k = CredentialKind::parse("macos_keychain_password").expect("a kind");
        assert_eq!(k.module_id(), "macos.keychain");
        assert_eq!(k.label(), "macOS keychain password");
    }

    #[test]
    fn the_macos_system_key_is_a_credential_kind_bound_to_the_keychain_parser() {
        let k = CredentialKind::parse("macos_system_key").expect("a kind");
        assert_eq!(k.module_id(), "macos.keychain");
        assert_eq!(k.label(), "macOS SystemKey");
    }

    #[test]
    fn every_kind_round_trips_its_wire_name() {
        for k in CredentialKind::ALL {
            assert_eq!(CredentialKind::parse(k.as_str()), Some(*k));
        }
        assert_eq!(CredentialKind::parse("password"), None);
    }
}
