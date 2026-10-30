#![forbid(unsafe_code)]
//! A narrow, profile-gated password-recovery engine.
//!
//! Séance already decrypts with a *known* secret — BitLocker password/recovery
//! key, LUKS passphrase, iOS backup password — so the KDFs exist. Cracking is
//! nothing more than iterating candidate secrets through those same KDFs, so this
//! crate adds **no new cryptography**: it defines a [`Verifier`] trait that an
//! existing decryptor implements ("does this candidate produce a valid header"),
//! a set of candidate generators ([`candidates`]), and an [`Engine`] that streams
//! candidates through a verifier.
//!
//! # Why it is off by default
//!
//! A forensic tool that cracks passwords by default is a liability — in a
//! contested matter, "the tool tried to break the encryption" invites a fight
//! that "the examiner supplied the key" never has. So the engine refuses to run
//! unless a [`Profile`] explicitly enables it, and it reports the number of
//! attempts and the outcome so the caller can write every run to the HMAC audit
//! chain.
//!
//! # Grading
//!
//! A recovered password is [`Outcome::Recovered`] and is *Validated* evidence —
//! it decrypted the target, which is proof. A run that exhausts its candidates is
//! [`Outcome::Exhausted`]; a disabled engine is [`Outcome::Refused`]. There is no
//! path by which a guess becomes a recovered password without the verifier
//! confirming it against real ciphertext.
//!
//! # Out of scope, deliberately
//!
//! GPU/OpenCL acceleration, distributed cracking, and any locked-mobile-device or
//! exploit-based passcode bypass. That last is *acquisition*, which Séance does
//! not do (see `documentation/COMPARISON.md`).

pub mod candidates;

pub use candidates::{rule_mutations, Dictionary, Mask};

/// A target that can confirm whether a candidate secret is correct.
///
/// The implementor is an existing decryptor: it runs its KDF on the candidate and
/// checks the result against ciphertext it holds (a volume header MAC, a keystore
/// verifier blob). Returning `true` means the candidate decrypts the target — a
/// fact, not a heuristic.
pub trait Verifier {
    /// A short, stable name for the target, for audit records (`"luks2"`,
    /// `"ios-backup"`, …).
    fn target(&self) -> &str;

    /// Whether `candidate` is the correct secret for this target.
    fn verify(&self, candidate: &str) -> bool;
}

/// Whether the cracker may run, and its bounds. Constructed disabled; a caller
/// must opt in explicitly, which is the whole safety story.
#[derive(Debug, Clone)]
pub struct Profile {
    enabled: bool,
    /// Hard ceiling on candidates tried, so a run cannot spin forever. `None`
    /// means "no cap" and is only reachable once enabled.
    max_attempts: Option<u64>,
}

impl Default for Profile {
    /// The default is **disabled** — the safe state.
    fn default() -> Self {
        Self {
            enabled: false,
            max_attempts: Some(0),
        }
    }
}

impl Profile {
    /// Explicitly enable cracking for this case. Naming this at the call site is
    /// the audit-visible act of turning the capability on.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            max_attempts: None,
        }
    }

    /// Cap the number of candidates tried.
    pub fn with_max_attempts(mut self, max: u64) -> Self {
        self.max_attempts = Some(max);
        self
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// The result of a cracking run — everything the audit log needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The secret was found. Evidence grade: Validated (it decrypted the target).
    Recovered {
        password: String,
        /// How many candidates were tried before the hit (1-based).
        attempts: u64,
    },
    /// Every candidate was tried, none worked.
    Exhausted { attempts: u64 },
    /// The engine was not enabled. No candidate was ever tried.
    Refused,
}

impl Outcome {
    /// The evidence grade wire name for this outcome, or `None` when nothing was
    /// established (exhausted/refused).
    pub fn grade(&self) -> Option<&'static str> {
        match self {
            Outcome::Recovered { .. } => Some("validated"),
            _ => None,
        }
    }
}

/// The cracking engine.
pub struct Engine {
    profile: Profile,
}

impl Engine {
    pub fn new(profile: Profile) -> Self {
        Self { profile }
    }

    /// Run `candidates` through `verifier`, stopping at the first hit, the
    /// attempt cap, or exhaustion. Refuses immediately if the profile is
    /// disabled — no candidate is generated or tried.
    pub fn crack<I, V>(&self, candidates: I, verifier: &V) -> Outcome
    where
        I: IntoIterator<Item = String>,
        V: Verifier + ?Sized,
    {
        if !self.profile.enabled {
            return Outcome::Refused;
        }
        let cap = self.profile.max_attempts;
        let mut attempts: u64 = 0;
        for candidate in candidates {
            if let Some(max) = cap {
                if attempts >= max {
                    break;
                }
            }
            attempts += 1;
            if verifier.verify(&candidate) {
                return Outcome::Recovered {
                    password: candidate,
                    attempts,
                };
            }
        }
        Outcome::Exhausted { attempts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verifier standing in for a real decryptor: the "correct" password is a
    /// fixed value, exactly as a header MAC would confirm.
    struct KnownSecret(&'static str);
    impl Verifier for KnownSecret {
        fn target(&self) -> &str {
            "test-target"
        }
        fn verify(&self, candidate: &str) -> bool {
            candidate == self.0
        }
    }

    #[test]
    fn disabled_engine_refuses_and_tries_nothing() {
        let engine = Engine::new(Profile::default());
        // Even with the correct password present, a disabled engine never tries.
        let out = engine.crack(vec!["hunter2".to_string()], &KnownSecret("hunter2"));
        assert_eq!(out, Outcome::Refused);
        assert_eq!(out.grade(), None);
    }

    #[test]
    fn recovers_from_a_dictionary_and_reports_attempts() {
        let engine = Engine::new(Profile::enabled());
        let words = vec!["a".to_string(), "b".to_string(), "hunter2".to_string()];
        let out = engine.crack(Dictionary::new(words), &KnownSecret("hunter2"));
        assert_eq!(
            out,
            Outcome::Recovered {
                password: "hunter2".to_string(),
                attempts: 3
            }
        );
        assert_eq!(out.grade(), Some("validated"));
    }

    #[test]
    fn recovers_a_pin_via_mask() {
        let engine = Engine::new(Profile::enabled());
        let mask = Mask::parse("?d?d?d?d").unwrap();
        let out = engine.crack(mask, &KnownSecret("0042"));
        match out {
            Outcome::Recovered { password, attempts } => {
                assert_eq!(password, "0042");
                assert_eq!(attempts, 43); // 0000..0042 inclusive = 43rd candidate
            }
            other => panic!("expected recovery, got {other:?}"),
        }
    }

    #[test]
    fn recovers_via_rule_mutation_of_a_wordlist_entry() {
        // The realistic case: the base word is on the disk, the actual password
        // is a common mutation of it.
        let engine = Engine::new(Profile::enabled());
        let base = "summer";
        let candidates = rule_mutations(base);
        let out = engine.crack(candidates, &KnownSecret("Summer2024"));
        assert!(matches!(out, Outcome::Recovered { .. }));
    }

    #[test]
    fn exhaustion_is_reported_with_the_attempt_count() {
        let engine = Engine::new(Profile::enabled());
        let words = vec!["x".to_string(), "y".to_string()];
        let out = engine.crack(Dictionary::new(words), &KnownSecret("z"));
        assert_eq!(out, Outcome::Exhausted { attempts: 2 });
    }

    #[test]
    fn attempt_cap_bounds_the_run() {
        let engine = Engine::new(Profile::enabled().with_max_attempts(10));
        let mask = Mask::parse("?d?d?d?d").unwrap(); // 10000 candidates
        let out = engine.crack(mask, &KnownSecret("9999"));
        // Capped at 10 tries, so the (10001st) correct one is never reached.
        assert_eq!(out, Outcome::Exhausted { attempts: 10 });
    }

    /// An end-to-end check that a *real KDF* verifier composes: derive a key with
    /// PBKDF2-like salted SHA-256 hashing and confirm the candidate reproduces a
    /// stored digest. This is the shape every real decryptor's verify() takes.
    #[test]
    fn composes_with_a_kdf_style_verifier() {
        use sha2::{Digest, Sha256};

        struct SaltedDigest {
            salt: [u8; 4],
            expected: [u8; 32],
        }
        impl SaltedDigest {
            fn derive(salt: &[u8; 4], pw: &str) -> [u8; 32] {
                // Stand-in KDF: many rounds of salted SHA-256 (the real thing is
                // PBKDF2/Argon2, already in the decryptor crates).
                let mut h = Sha256::new();
                h.update(salt);
                h.update(pw.as_bytes());
                let mut out: [u8; 32] = h.finalize().into();
                for _ in 0..5000 {
                    out = Sha256::digest(out).into();
                }
                out
            }
        }
        impl Verifier for SaltedDigest {
            fn target(&self) -> &str {
                "salted-digest"
            }
            fn verify(&self, candidate: &str) -> bool {
                SaltedDigest::derive(&self.salt, candidate) == self.expected
            }
        }

        let salt = [0xde, 0xad, 0xbe, 0xef];
        let real_password = "correct horse";
        let verifier = SaltedDigest {
            salt,
            expected: SaltedDigest::derive(&salt, real_password),
        };
        let engine = Engine::new(Profile::enabled());
        let words = vec![
            "wrong".to_string(),
            "battery".to_string(),
            "correct horse".to_string(),
        ];
        let out = engine.crack(Dictionary::new(words), &verifier);
        assert_eq!(
            out,
            Outcome::Recovered {
                password: "correct horse".to_string(),
                attempts: 3
            }
        );
    }
}
