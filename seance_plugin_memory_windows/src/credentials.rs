//! Credential material held in RAM: the local accounts, the LSA secrets and
//! the cached domain logons, located and counted.
//!
//! # What this stage does, and the one thing it deliberately does not
//!
//! Windows keeps its credential stores in registry hives that are loaded into
//! kernel memory for the whole life of the machine: `SAM` holds the local
//! accounts and their password hashes, `SECURITY` holds the LSA secrets — which
//! include service account passwords in reversibly encrypted form — and the
//! cached domain logons that let a laptop authenticate offline. All three are
//! in a memory image whether or not the files on disk are readable, which is
//! why an examiner asks for them.
//!
//! This stage **locates and inventories** that material. It does not decrypt
//! it. The hashes in `SAM\Domains\Account\Users\<RID>\V` are encrypted under
//! the machine's boot key with RC4 or, from Windows 10 1607, AES, and the LSA
//! secrets under a key derived from the same; recovering the plaintext is a
//! cryptographic operation this crate does not perform.
//!
//! That distinction is the whole reason this module exists rather than the
//! stage simply being absent. A credentials view that reports nothing because
//! nothing ran is indistinguishable, in a report, from a credentials view that
//! ran and found the machine had no accounts and no secrets — and one of those
//! is a claim about the suspect's machine that nobody made. Every survey this
//! module produces says, in the artifact, that the material was located and not
//! decrypted, and [`CredentialSurvey::is_complete`] is therefore never true.
//!
//! # What an examiner still gets
//!
//! * Which of the three hives are loaded, and at what `_CMHIVE` — the
//!   provenance every later answer rests on.
//! * The local account names and their relative identifiers, read from
//!   `SAM\Domains\Account\Users\Names`, whose subkey names are the account
//!   names in clear and whose default value's *type number* is the account's
//!   RID. Nothing there is encrypted, so an inventory of who had an account on
//!   the machine is available without any key at all.
//! * The names of the LSA secrets under `SECURITY\Policy\Secrets`, which say
//!   what kinds of credential the machine was storing — `DPAPI_SYSTEM`,
//!   `$MACHINE.ACC`, a service account's `_SC_<service>` — without saying what
//!   they are.
//! * How many cached domain logons are present under `SECURITY\Cache`.
//!
//! # What a wrong answer looks like
//!
//! An empty account list rendered as "this machine had no local accounts". A
//! `SAM` hive that could not be opened and an inventory of zero accounts must
//! never reach a report the same way, which is why every listing here carries
//! the reason it is short.

use std::collections::BTreeSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::Incomplete;

use crate::profile::WindowsProfile;
use crate::registry::error::RegistryError;
use crate::registry::hivelist::{list_hives, HiveListing};
use crate::registry::key::CellReader;
use crate::registry::printkey::{print_key, KeyListing};
use crate::registry::space::{locate_bin_space, BinSpace, HiveSpace};

/// The hive holding the local accounts.
pub const HIVE_SAM: &str = "SAM";

/// The hive holding the LSA secrets and the cached domain logons.
pub const HIVE_SECURITY: &str = "SECURITY";

/// The key whose subkeys are the local account names, in clear.
pub const KEY_USER_NAMES: &str = "SAM\\Domains\\Account\\Users\\Names";

/// The key whose subkeys are the relative identifiers, in hexadecimal.
pub const KEY_USERS: &str = "SAM\\Domains\\Account\\Users";

/// The key whose subkeys name the LSA secrets.
pub const KEY_SECRETS: &str = "Policy\\Secrets";

/// The key whose values hold the cached domain logons.
pub const KEY_CACHE: &str = "Cache";

/// Ceiling on account names read out of one hive.
///
/// A machine with more local accounts than this has something wrong with it,
/// and the cap is reported rather than silently ending the list.
pub const MAX_ACCOUNTS: usize = 4_096;

/// Ceiling on LSA secrets read out of one hive.
pub const MAX_SECRETS: usize = 4_096;

/// What stops a credential survey before it can produce anything worth reading.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The hive list itself could not be walked, so no hive could be looked
    /// for. Returning an empty survey would say the machine had no `SAM`.
    #[error(
        "the loaded-hive list could not be walked, so neither the SAM nor the SECURITY hive could \
         be looked for: {0}"
    )]
    HiveList(#[source] RegistryError),
}

impl CredentialError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            CredentialError::HiveList(_) => "hive_list",
        }
    }
}

/// One of the credential hives, and whether it is in this image.
#[derive(Debug, Clone)]
pub struct CredentialHive {
    /// The file name the hive is loaded from: `SAM` or `SECURITY`.
    pub name: &'static str,
    /// The `_CMHIVE`, when a hive with that name is loaded.
    pub cmhive: Option<u64>,
    /// Where the hive's bins were read from, when it was opened.
    pub bin_source: Option<String>,
    /// Whether the bins were read from where this build keeps them.
    ///
    /// `false` means an unreadable key in this hive is unexplained: it may be a
    /// page that was never captured, or the wrong address space.
    pub bin_source_authoritative: bool,
    /// Why the hive is not usable, when it is not.
    pub detail: Option<String>,
}

impl CredentialHive {
    /// Whether the hive was found and opened.
    pub fn is_available(&self) -> bool {
        self.cmhive.is_some() && self.detail.is_none()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hive": self.name,
            "cmhive": self.cmhive,
            // Exact beside the number: a `_CMHIVE` is a kernel address above
            // 2^53, and JSON numbers are IEEE doubles, so the numeric form can
            // reach a client rounded by up to a kilobyte.
            "cmhive_hex": self.cmhive.map(|address| format!("{address:#x}")),
            "bin_source": self.bin_source,
            "bin_source_authoritative": self.bin_source_authoritative,
            "available": self.is_available(),
            "detail": self.detail,
        })
    }
}

/// One local account, as the `SAM` hive names it.
#[derive(Debug, Clone)]
pub struct LocalAccount {
    /// The account name, which is the subkey's own name and is not encrypted.
    pub name: String,
    /// The relative identifier, from the type number of the key's default
    /// value — where Windows stores it. `None` when the key had no default
    /// value or its type could not be read, which is a fact about the read and
    /// not an account without a RID.
    pub rid: Option<u32>,
    /// Whether a key named for this relative identifier exists under
    /// [`KEY_USERS`], where Windows keeps the account itself.
    ///
    /// `Some(true)` is the RID corroborated by a second, independent place in
    /// the hive. `Some(false)` is a type number that names no account — a
    /// damaged or forged field read as a RID. `None` is "not checked": no RID
    /// was read, or the RID-named keys could not be listed. It is never
    /// defaulted to `true`, because the whole point of the field is that the
    /// type-number trick has no redundancy of its own.
    pub rid_corroborated: Option<bool>,
    /// `LastWriteTime` of the account's name key, as a raw Windows FILETIME.
    ///
    /// Left raw: converting a value that is not a time would put a date in the
    /// record the machine never held.
    pub last_write_filetime: i64,
    /// Everything odd about the account that did not disqualify it.
    pub notes: Vec<String>,
}

impl LocalAccount {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "rid": self.rid,
            "rid_corroborated": self.rid_corroborated,
            "last_write_filetime": self.last_write_filetime,
            "notes": self.notes,
        })
    }
}

/// One named LSA secret. The name only: the value is encrypted.
#[derive(Debug, Clone)]
pub struct NamedSecret {
    /// The secret's name, which is the subkey's own name.
    pub name: String,
    /// `LastWriteTime` of the secret's key, as a raw Windows FILETIME.
    pub last_write_filetime: i64,
}

impl NamedSecret {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "last_write_filetime": self.last_write_filetime,
        })
    }
}

/// One listing this survey attempted, and what became of it.
#[derive(Debug, Clone)]
pub struct ListingStatus {
    /// The key path that was resolved.
    pub key: &'static str,
    /// Whether the key was reached and enumerated in full.
    pub complete: bool,
    /// Why it was not, when it was not.
    pub detail: Option<String>,
}

impl ListingStatus {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "key": self.key,
            "complete": self.complete,
            "detail": self.detail,
        })
    }
}

/// Sentence stating what this stage does with what it finds.
///
/// Carried on every survey, in the artifact, so that a report cannot present a
/// credentials section without it.
pub const DECRYPTION_STATEMENT: &str =
    "this inventory lists the credential stores; it does not itself decrypt them. Local-account \
     NT hashes ARE recovered separately (see the recovered-credential records / \
     credentials_recovered) for the modern AES form. What is still not decrypted here: the LSA \
     secrets under SECURITY\\Policy\\Secrets, the cached domain logons, and any account stored in \
     the older RC4 form — those are located but their values are not recovered";

/// Everything one image's credential stores hold, short of their plaintext.
#[derive(Debug, Clone)]
pub struct CredentialSurvey {
    /// The two hives this stage reads, found or not.
    pub hives: Vec<CredentialHive>,
    /// The local accounts named in the `SAM` hive.
    pub accounts: Vec<LocalAccount>,
    /// The named LSA secrets in the `SECURITY` hive.
    pub secrets: Vec<NamedSecret>,
    /// How many cached domain logon values are present.
    pub cached_logons: usize,
    /// One entry per key path this survey tried to resolve.
    pub listings: Vec<ListingStatus>,
    /// Whether a cap ended a listing early.
    pub truncated: bool,
}

impl CredentialSurvey {
    /// Whether this stage recovered everything it exists to recover.
    ///
    /// **Never true.** The inventory can be complete; the credentials are not
    /// recovered, because this crate does not decrypt them. A stage that could
    /// return `true` here would let a report say "credentials: complete" over a
    /// section that contains no credential.
    pub fn is_complete(&self) -> bool {
        self.incomplete().is_empty()
    }

    /// Whether the inventory itself — which hives, which accounts, which
    /// secrets — was established in full.
    ///
    /// Distinct from [`CredentialSurvey::is_complete`]: this is the question
    /// "is this every local account on the machine", which is answerable, and
    /// that one is "were the credentials recovered", which is not.
    pub fn inventory_is_complete(&self) -> bool {
        !self.truncated
            && self.hives.iter().all(CredentialHive::is_available)
            && self.hives.iter().all(|hive| hive.bin_source_authoritative)
            && self.listings.iter().all(|listing| listing.complete)
    }

    /// Everything a report must declare about this survey.
    ///
    /// Always contains the statement that nothing was decrypted, whatever else
    /// it contains.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = vec![Incomplete::new(
            IncompleteReason::UnresolvedStructure,
            DECRYPTION_STATEMENT.to_string(),
        )];
        for hive in &self.hives {
            if let Some(detail) = &hive.detail {
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!("the {} hive: {detail}", hive.name),
                ));
            } else if !hive.bin_source_authoritative {
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the {} hive's bins were not read from where this build keeps them, so a \
                         key it could not reach may be present and unread rather than absent",
                        hive.name
                    ),
                ));
            }
        }
        for listing in &self.listings {
            if let Some(detail) = &listing.detail {
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!("'{}' was not enumerated in full: {detail}", listing.key),
                ));
            }
        }
        if self.truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                "a listing stopped at its cap, so the entries above are a floor rather than a \
                 total"
                    .to_string(),
            ));
        }
        out
    }

    /// Why the inventory is short, when it is.
    ///
    /// Distinct from [`CredentialSurvey::incomplete`], which always leads with
    /// "nothing was decrypted": that sentence is about the *capability* and is
    /// true of every survey this module has ever produced. This one is about
    /// the *listing*, and it is empty exactly when "these are all the local
    /// accounts on this machine" is a statement the survey can support.
    pub fn inventory_incomplete_reason(&self) -> Option<String> {
        if self.inventory_is_complete() {
            return None;
        }
        let mut reasons: Vec<String> = Vec::new();
        for hive in &self.hives {
            if let Some(detail) = &hive.detail {
                reasons.push(format!("the {} hive: {detail}", hive.name));
            } else if !hive.bin_source_authoritative {
                reasons.push(format!(
                    "the {} hive's bins were not read from where this build keeps them",
                    hive.name
                ));
            }
        }
        for listing in &self.listings {
            if let Some(detail) = &listing.detail {
                reasons.push(format!("'{}': {detail}", listing.key));
            }
        }
        if self.truncated {
            reasons.push("a listing stopped at its cap".to_string());
        }
        if reasons.is_empty() {
            reasons.push(
                "the inventory was not established in full and no reason was recorded".to_string(),
            );
        }
        Some(reasons.join("; "))
    }

    /// Serializable form for the credentials artifact.
    ///
    /// Inventory-first on purpose. `plaintext_recovered` and
    /// `credentials_recovered` lead because the one claim this stage must never
    /// be read as making is that it recovered a password: it located the stores
    /// and listed what is in them, and every field below describes a listing
    /// rather than a secret.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "inventory_only": true,
            "plaintext_recovered": false,
            "credentials_recovered": 0,
            "decryption": DECRYPTION_STATEMENT,
            "hives": self.hives.iter().map(CredentialHive::to_json).collect::<Vec<_>>(),
            "accounts": self.accounts.iter().map(LocalAccount::to_json).collect::<Vec<_>>(),
            "account_count": self.accounts.len(),
            "secrets": self.secrets.iter().map(NamedSecret::to_json).collect::<Vec<_>>(),
            "secret_count": self.secrets.len(),
            "cached_logons": self.cached_logons,
            "listings": self.listings.iter().map(ListingStatus::to_json).collect::<Vec<_>>(),
            "truncated": self.truncated,
            "inventory_complete": self.inventory_is_complete(),
            // The standard pair, beside the stage's own vocabulary: a consumer
            // that reads only `inventory_incomplete` still learns that the
            // account list is a floor, and one that reads the reason learns
            // which hive or key was not enumerated.
            "inventory_incomplete": !self.inventory_is_complete(),
            "inventory_incomplete_reason": self.inventory_incomplete_reason(),
            "complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Caps for one credential survey.
#[derive(Debug, Clone)]
pub struct CredentialConfig {
    /// Ceiling on account names reported.
    pub max_accounts: usize,
    /// Ceiling on LSA secret names reported.
    pub max_secrets: usize,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            max_accounts: MAX_ACCOUNTS,
            max_secrets: MAX_SECRETS,
        }
    }
}

/// Locate and inventory this image's credential material — the whole
/// `credentials` stage.
///
/// This is the entry point an orchestrator calls, and it is the reason the
/// stage exists at all: without it the coverage view reports `did_not_run` with
/// no record saying so, and an examiner reading a report with an empty
/// credentials section cannot tell "checked, nothing there" from "never
/// looked".
///
/// # What an examiner learns
///
/// Which credential hives are resident, which local accounts existed and with
/// which relative identifiers, and what kinds of secret the machine was
/// storing. Not one password, hash or secret value: see
/// [`DECRYPTION_STATEMENT`], which travels in every artifact this produces.
///
/// # Errors
///
/// [`CredentialError::HiveList`] when the loaded-hive list cannot be walked at
/// all, which is the one failure that makes the whole question unanswerable. A
/// hive that is not loaded, or that will not open, is not an error — it is a
/// [`CredentialHive`] with the reason on it.
pub fn survey_credentials(
    profile: &WindowsProfile,
    config: &CredentialConfig,
) -> Result<CredentialSurvey, CredentialError> {
    let listing = list_hives(profile).map_err(CredentialError::HiveList)?;
    // One process-list walk for the whole survey rather than one per hive: from
    // Windows 10 17063 the bins live in the Registry process, and finding it is
    // the expensive part.
    let bins = locate_bin_space(profile);

    let mut survey = CredentialSurvey {
        hives: Vec::new(),
        accounts: Vec::new(),
        secrets: Vec::new(),
        cached_logons: 0,
        listings: Vec::new(),
        truncated: false,
    };

    let sam = open_named_hive(profile, &listing, &bins, HIVE_SAM);
    if let Some(reader) = &sam.1 {
        read_accounts(reader, config, &mut survey);
    } else {
        survey.listings.push(ListingStatus {
            key: KEY_USER_NAMES,
            complete: false,
            detail: Some(format!(
                "the {HIVE_SAM} hive was not available, so the local accounts were not listed and \
                 an empty list here is not a machine without accounts"
            )),
        });
    }
    survey.hives.push(sam.0);

    let security = open_named_hive(profile, &listing, &bins, HIVE_SECURITY);
    if let Some(reader) = &security.1 {
        read_secrets(reader, config, &mut survey);
        read_cache(reader, &mut survey);
    } else {
        for key in [KEY_SECRETS, KEY_CACHE] {
            survey.listings.push(ListingStatus {
                key,
                complete: false,
                detail: Some(format!(
                    "the {HIVE_SECURITY} hive was not available, so this key was not enumerated \
                     and an empty list here is not a machine without stored secrets"
                )),
            });
        }
    }
    survey.hives.push(security.0);

    Ok(survey)
}

/// Find one named hive on the listing and open it.
fn open_named_hive(
    profile: &WindowsProfile,
    listing: &HiveListing,
    bins: &BinSpace,
    name: &'static str,
) -> (CredentialHive, Option<CellReader>) {
    let found = listing.hives.iter().find(|hive| {
        hive.name
            .file_name()
            .is_some_and(|file| file.eq_ignore_ascii_case(name))
    });
    let Some(record) = found else {
        return (
            CredentialHive {
                name,
                cmhive: None,
                bin_source: None,
                bin_source_authoritative: true,
                detail: Some(format!(
                    "no hive named {name} is on the loaded-hive list{}",
                    if listing.is_complete() {
                        ""
                    } else {
                        ", and the list itself was not walked in full, so this is not evidence \
                         that the hive was not loaded"
                    }
                )),
            },
            None,
        );
    };

    let hive = match HiveSpace::open_with_bin_space(profile, record.address, bins) {
        Ok(hive) => hive,
        Err(err) => {
            return (
                CredentialHive {
                    name,
                    cmhive: Some(record.address),
                    bin_source: None,
                    bin_source_authoritative: true,
                    detail: Some(format!(
                        "the hive at {:#x} could not be opened: {err}",
                        record.address
                    )),
                },
                None,
            )
        }
    };
    let source = hive.bin_source().clone();
    let reader = match CellReader::new(Arc::clone(&hive)) {
        Ok(reader) => reader,
        Err(err) => {
            return (
                CredentialHive {
                    name,
                    cmhive: Some(record.address),
                    bin_source: Some(source.as_str().to_string()),
                    bin_source_authoritative: source.is_authoritative(),
                    detail: Some(format!(
                        "the hive at {:#x} opened and its cells could not be read: {err}",
                        record.address
                    )),
                },
                None,
            )
        }
    };

    (
        CredentialHive {
            name,
            cmhive: Some(record.address),
            bin_source: Some(source.as_str().to_string()),
            bin_source_authoritative: source.is_authoritative(),
            detail: None,
        },
        Some(reader),
    )
}

/// Resolve one key, or record why it could not be resolved.
fn listing_of(
    reader: &CellReader,
    key: &'static str,
    survey: &mut CredentialSurvey,
) -> Option<KeyListing> {
    match print_key(reader, Some(key)) {
        Ok(listing) => {
            let detail =
                (!listing.subkeys.is_complete() || !listing.values.is_complete()).then(|| {
                    listing
                        .subkeys
                        .incomplete
                        .iter()
                        .chain(listing.values.incomplete.iter())
                        .map(|entry| entry.detail.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                });
            survey.listings.push(ListingStatus {
                key,
                complete: detail.is_none(),
                detail,
            });
            Some(listing)
        }
        Err(err) => {
            survey.listings.push(ListingStatus {
                key,
                complete: false,
                detail: Some(err.to_string()),
            });
            None
        }
    }
}

/// The local accounts, from the subkeys of `…\Users\Names`.
///
/// Each subkey's name is the account name in clear, and the *type number* of
/// its default value is the account's relative identifier — which is where
/// Windows stores it, and why nothing has to be decrypted to answer "who had an
/// account on this machine".
fn read_accounts(reader: &CellReader, config: &CredentialConfig, survey: &mut CredentialSurvey) {
    let Some(names) = listing_of(reader, KEY_USER_NAMES, survey) else {
        return;
    };
    // The second place the same RID is written: `…\Users` holds one subkey per
    // account, named for the RID in eight hexadecimal digits. A type number is
    // a byte field with no redundancy — a damaged or forged one still reads as
    // a plausible RID — so every RID this stage reports is checked against
    // that list, and one that is not there says so on the row.
    let (rid_keys, rid_keys_listed) = match listing_of(reader, KEY_USERS, survey) {
        Some(users) => (
            users
                .subkeys
                .keys
                .iter()
                .filter_map(|key| rid_from_key_name(&key.name.text))
                .collect::<BTreeSet<u32>>(),
            users.subkeys.is_complete(),
        ),
        None => (BTreeSet::new(), false),
    };
    for key in &names.subkeys.keys {
        if survey.accounts.len() >= config.max_accounts {
            survey.truncated = true;
            break;
        }
        let values = reader.values(key);
        let mut notes = Vec::new();
        if !values.is_complete() {
            notes.push(
                "this account's key could not be read in full, so its relative identifier may be \
                 missing rather than absent"
                    .to_string(),
            );
        }
        let rid = values
            .values
            .iter()
            .find(|value| value.is_default())
            .map(|value| value.raw_type);
        if rid.is_none() {
            notes.push(
                "this account's key has no default value, which is where Windows keeps the \
                 relative identifier"
                    .to_string(),
            );
        }
        let rid_corroborated = corroborate_rid(rid, &rid_keys, rid_keys_listed, &mut notes);
        survey.accounts.push(LocalAccount {
            name: key.name.text.clone(),
            rid,
            rid_corroborated,
            last_write_filetime: key.last_write_time,
            notes,
        });
    }
}

/// Decide whether a RID read from a default value's type number is borne out
/// by the RID-named keys under [`KEY_USERS`], recording the reason either way.
///
/// Never answers `Some(true)` without having seen the key: an unlisted or
/// partially listed `…\Users` yields `None`, so "not checked" and "checked and
/// present" cannot render the same way in a report.
fn corroborate_rid(
    rid: Option<u32>,
    rid_keys: &BTreeSet<u32>,
    rid_keys_listed: bool,
    notes: &mut Vec<String>,
) -> Option<bool> {
    let rid = rid?;
    if !rid_keys_listed {
        notes.push(format!(
            "the RID-named keys under {KEY_USERS} could not be listed in full, so this relative \
             identifier rests on the default value's type number alone and was not corroborated"
        ));
        return None;
    }
    let found = rid_keys.contains(&rid);
    if !found {
        notes.push(format!(
            "the relative identifier {rid} was read from the type number of this account's \
             default value, and no key named for it exists under {KEY_USERS}, so the type number \
             is a damaged or planted field rather than this account's RID"
        ));
    }
    Some(found)
}

/// The relative identifier a `…\Users` subkey is named for.
///
/// Windows names each account's key with its RID in eight uppercase
/// hexadecimal digits. Anything else under that key — `Names`, most obviously —
/// is not an account and must not be read as one.
fn rid_from_key_name(name: &str) -> Option<u32> {
    if name.len() != 8 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(name, 16).ok()
}

/// The named LSA secrets, from the subkeys of `Policy\Secrets`.
fn read_secrets(reader: &CellReader, config: &CredentialConfig, survey: &mut CredentialSurvey) {
    let Some(secrets) = listing_of(reader, KEY_SECRETS, survey) else {
        return;
    };
    for key in &secrets.subkeys.keys {
        if survey.secrets.len() >= config.max_secrets {
            survey.truncated = true;
            break;
        }
        survey.secrets.push(NamedSecret {
            name: key.name.text.clone(),
            last_write_filetime: key.last_write_time,
        });
    }
}

/// Whether a value name under `SECURITY\Cache` is a cached logon.
///
/// The cached credentials are `NL$1`, `NL$2`, … — the prefix followed by a
/// decimal index and nothing else. Two other values live under the same key and
/// are **not** logons: `NL$Control`, which holds the cache policy, and
/// `NL$IterationCount`, which holds the MSCACHEv2 iteration count. Counting
/// every name that starts with `NL$` inflates the count by one or two and puts
/// domain accounts on a machine that never had them, which in a report is a
/// statement about who had logged on to the suspect's laptop.
fn is_cached_logon(name: &str) -> bool {
    let Some(index) = name.strip_prefix("NL$") else {
        return false;
    };
    !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
}

/// How many cached domain logons the `SECURITY` hive holds.
///
/// The `NL$n` values under `Cache` are the cached credentials themselves and
/// are encrypted; counting them says how many domain accounts had logged on to
/// this machine, which is a finding on its own.
fn read_cache(reader: &CellReader, survey: &mut CredentialSurvey) {
    let Some(cache) = listing_of(reader, KEY_CACHE, survey) else {
        return;
    };
    survey.cached_logons = cache
        .values
        .values
        .iter()
        .filter(|value| is_cached_logon(&value.name.text.to_ascii_uppercase()))
        .count();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_support::xp_profile;

    #[test]
    fn a_survey_that_found_no_credential_hive_says_so_rather_than_listing_no_accounts() {
        // The failure this whole module exists to prevent: an empty credentials
        // section that reads as "checked, nothing there". This fixture has no
        // SAM and no SECURITY hive, so every list is empty — and every list
        // carries the reason it is.
        let profile = xp_profile();
        let survey = survey_credentials(&profile, &CredentialConfig::default())
            .expect("the hive list walks");

        assert!(survey.accounts.is_empty());
        assert!(survey.secrets.is_empty());
        assert_eq!(survey.cached_logons, 0);
        assert!(!survey.inventory_is_complete());

        for hive in &survey.hives {
            assert!(!hive.is_available(), "{hive:?}");
            assert!(
                hive.detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("loaded-hive list")),
                "{hive:?}"
            );
        }
        assert!(survey
            .listings
            .iter()
            .any(|listing| listing.key == KEY_USER_NAMES && !listing.complete));
        assert!(survey
            .listings
            .iter()
            .any(|listing| listing.key == KEY_SECRETS && !listing.complete));
    }

    #[test]
    fn a_credential_survey_is_never_complete_because_nothing_is_decrypted() {
        // A stage that could report itself complete would let a report print
        // "credentials: complete" over a section holding no credential.
        let profile = xp_profile();
        let survey = survey_credentials(&profile, &CredentialConfig::default())
            .expect("the hive list walks");

        assert!(!survey.is_complete());
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail == DECRYPTION_STATEMENT));

        let json = survey.to_json();
        assert_eq!(json["complete"], false);
        assert_eq!(json["plaintext_recovered"], false);
        assert_eq!(json["decryption"], DECRYPTION_STATEMENT);
        assert_eq!(json["account_count"], 0);
        assert_eq!(json["hives"][0]["hive"], HIVE_SAM);
        assert_eq!(json["hives"][0]["available"], false);
        assert_eq!(json["hives"][1]["hive"], HIVE_SECURITY);
    }

    #[test]
    fn only_the_numbered_cache_entries_are_counted_as_cached_logons() {
        // `NL$Control` and `NL$IterationCount` live under the same key as the
        // cached credentials and are not credentials. Counting them puts one or
        // two domain accounts on a machine that never had them, and the count
        // reaches a report as "offline domain logons".
        for name in ["NL$1", "NL$2", "NL$10", "NL$25"] {
            assert!(is_cached_logon(name), "{name}");
        }
        for name in [
            "NL$Control",
            "NL$IterationCount",
            "NL$",
            "NL$1A",
            "NL",
            "Something",
        ] {
            assert!(!is_cached_logon(name), "{name}");
        }
    }

    #[test]
    fn a_short_inventory_carries_the_standard_flag_and_the_reason_for_it() {
        // "These are all the local accounts on this machine" is a claim only a
        // complete inventory supports, and a consumer reading the standard
        // keys must be able to tell that this one does not.
        let profile = xp_profile();
        let survey = survey_credentials(&profile, &CredentialConfig::default())
            .expect("the hive list walks");
        let json = survey.to_json();

        assert_eq!(json["inventory_complete"], false);
        assert_eq!(json["inventory_incomplete"], true);
        assert_eq!(json["inventory_only"], true);
        assert_eq!(json["credentials_recovered"], 0);
        let reason = json["inventory_incomplete_reason"]
            .as_str()
            .expect("a short inventory states why it is short");
        assert!(reason.contains("hive"), "{reason}");
    }

    #[test]
    fn only_an_eight_hex_digit_key_under_users_is_an_account() {
        assert_eq!(rid_from_key_name("000001F4"), Some(500));
        assert_eq!(rid_from_key_name("000003E9"), Some(1001));
        // `Names` is a subkey of `…\Users` and is not an account.
        assert_eq!(rid_from_key_name("Names"), None);
        assert_eq!(rid_from_key_name("1F4"), None);
        assert_eq!(rid_from_key_name("000001F4A"), None);
        assert_eq!(rid_from_key_name("0000_1F4"), None);
        assert_eq!(rid_from_key_name(""), None);
    }

    #[test]
    fn a_rid_that_names_no_account_key_is_reported_as_uncorroborated() {
        // The RID comes from the *type number* of a default value: a byte field
        // with no checksum, no length and no redundancy. A damaged or planted
        // one still reads as a plausible RID, and a report that prints it
        // beside the account name asserts an identity the hive does not carry.
        // The account's own key under `…\Users` is the second witness.
        let keys: BTreeSet<u32> = [500, 501].into_iter().collect();

        let mut notes = Vec::new();
        assert_eq!(
            corroborate_rid(Some(500), &keys, true, &mut notes),
            Some(true)
        );
        assert!(notes.is_empty(), "{notes:?}");

        let mut notes = Vec::new();
        assert_eq!(
            corroborate_rid(Some(9999), &keys, true, &mut notes),
            Some(false),
            "a RID with no key of its own is not corroborated"
        );
        assert!(
            notes.iter().any(|note| note.contains("9999")
                && note.contains(KEY_USERS)
                && note.contains("damaged")),
            "the row must say why: {notes:?}"
        );

        // Not checked is never rendered as checked-and-present.
        let mut notes = Vec::new();
        assert_eq!(corroborate_rid(Some(500), &keys, false, &mut notes), None);
        assert!(
            notes.iter().any(|note| note.contains("not corroborated")),
            "{notes:?}"
        );

        let mut notes = Vec::new();
        assert_eq!(corroborate_rid(None, &keys, true, &mut notes), None);
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn an_account_row_carries_whether_its_rid_was_corroborated() {
        let account = LocalAccount {
            name: "Administrator".to_string(),
            rid: Some(500),
            rid_corroborated: Some(false),
            last_write_filetime: 0,
            notes: Vec::new(),
        };
        assert_eq!(account.to_json()["rid_corroborated"], false);

        let unchecked = LocalAccount {
            rid_corroborated: None,
            ..account
        };
        assert!(unchecked.to_json()["rid_corroborated"].is_null());
    }

    #[test]
    fn the_key_paths_are_the_ones_windows_actually_uses() {
        // A path typed wrong yields "key not found", which renders as a machine
        // with no accounts unless it is read as the failure it is.
        assert_eq!(KEY_USERS, "SAM\\Domains\\Account\\Users");
        assert!(KEY_USER_NAMES.starts_with(KEY_USERS));
        assert!(KEY_USER_NAMES.ends_with("Names"));
        assert_eq!(KEY_SECRETS, "Policy\\Secrets");
        assert_eq!(KEY_CACHE, "Cache");
    }
}
