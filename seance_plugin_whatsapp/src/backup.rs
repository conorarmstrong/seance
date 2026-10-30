//! WhatsApp Android encrypted backups in ingest (ROADMAP §5.7; owner decision
//! of 2026-09-26, (c) part a: automatic pairing with the key file).
//!
//! # What reaches this module
//!
//! - A file whose name ends `.cryptNN` — `msgstore.db.crypt14`,
//!   `msgstore-2024-07-26.1.db.crypt14`, `wa.db.crypt15`,
//!   `stickers.backup.crypt15`. Generations 14 and 15 are decrypted; which
//!   one a file is comes from its header, not its name. Every other
//!   generation (`crypt12` and older, which this build has no decryptor for)
//!   is refused **by name, with a record**, never skipped silently.
//! - The key files, recognised by their place: `key` (crypt14) and
//!   `encrypted_backup.key` (crypt15, the end-to-end root key) in a
//!   `com.whatsapp/files` directory. A crypt14 key is tried only on crypt14
//!   backups and a crypt15 root only on crypt15 ones.
//! - A crypt15 backup that holds a ZIP archive (a multi-file or incremental
//!   backup) has the archive filed beneath it as a file, for the archive
//!   expander; it is held in memory only and is not served after the run.
//!
//! # Pairing
//!
//! The key and the backups it opens are about seven directories apart on an
//! Android file system (`/data/data/com.whatsapp/files/key` against
//! `/data/media/0/Android/media/com.whatsapp/WhatsApp/Databases/`), further
//! than a data source's bounded ancestor lookup reaches, and a file inside a
//! disk image has no tree lookup at all. So they are paired **across the
//! case**, in whichever order ingest delivers them: each key read is held for
//! its case, each backup no held key opens is held until one does. A key is
//! tried only on a backup whose header names the key's own server salt, so a
//! key from another install (an earlier one, another phone in the same case)
//! is refused before any decryption, and the GCM tag is checked before a byte
//! of plaintext is released.
//!
//! A backup read before its key is recorded as awaiting it (`AwaitingKey`,
//! content incomplete). When the key arrives the decrypted store is filed
//! under the backup and its `Decrypted` record supersedes that statement.
//!
//! # What it cannot do
//!
//! The pairing lives in this process's memory (the owner's key-retention
//! decision of 2026-09-26): a key is held for its case only, for the unlock
//! lifetime ([`key_ttl`], 8 hours or `SEANCE_UNLOCK_TTL_SECS`) or until a
//! restart, zeroed when dropped, and never written to a record, an export or
//! a log. A backup whose key is only in evidence ingested after that, or in
//! another case, stays `AwaitingKey`. At most [`MAX_PENDING_PER_CASE`] backups and
//! [`MAX_KEYS_PER_CASE`] keys are held per case; past that a backup is
//! recorded as not held for pairing. A backup larger than
//! [`MAX_BACKUP_BYTES`] is not read.
//!
//! The key's bytes are never written to a record; the key file is named by its
//! path and SHA-256.

use crate::crypt14::{self, Crypt14Error, Key, KeyKind, Payload};
use crate::WhatsAppParser;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::credential::{self, CredentialKind, RunCredential};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::io::IncompleteReason;
use seance_core::module::ForensicsModule;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Record type of every backup statement: awaiting, refused, decrypted, key.
pub(crate) const BACKUP_TYPE: &str = "WhatsAppBackup";

/// Backups held per case while no key has opened them.
pub(crate) const MAX_PENDING_PER_CASE: usize = 64;

/// Keys held per case.
pub(crate) const MAX_KEYS_PER_CASE: usize = 16;

/// The largest backup read into memory for decryption.
pub(crate) const MAX_BACKUP_BYTES: u64 = 1024 * 1024 * 1024;

/// The largest key file read (the real one is 158 bytes).
const MAX_KEY_BYTES: u64 = 4096;

/// If `artifact` is a backup or the key file, what this module files for it.
/// `None` leaves the artifact to the message-store path.
pub(crate) fn route(parser: &WhatsAppParser, artifact: &Artifact) -> Option<Vec<Artifact>> {
    if seance_sqlite_util::is_directory_entry(artifact) {
        return None;
    }
    let name = meta_str(artifact, "name").unwrap_or_default();
    if let Some(generation) = backup_generation(&name) {
        return Some(match generation {
            14 | 15 => on_backup(parser, artifact, generation),
            other => vec![not_decrypted(artifact, other, &refused_generation(other))],
        });
    }
    if is_key_file(artifact) {
        return Some(on_key(parser, artifact));
    }
    None
}

/// `NN` of a name ending `.cryptNN`.
fn backup_generation(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    let (_, tail) = lower.rsplit_once(".crypt")?;
    if tail.is_empty() || tail.len() > 3 || !tail.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    tail.parse().ok()
}

/// A file named `key` (crypt14) or `encrypted_backup.key` (crypt15) in a
/// `com.whatsapp/files` directory.
fn is_key_file(artifact: &Artifact) -> bool {
    let name = meta_str(artifact, "name").unwrap_or_default();
    if name != "key" && name != "encrypted_backup.key" {
        return false;
    }
    let path = meta_str(artifact, "path")
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    path.ends_with(&format!("com.whatsapp/files/{name}"))
}

fn meta_str(artifact: &Artifact, key: &str) -> Option<String> {
    artifact
        .metadata
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Where the file sits, for the record: its path, else its name.
fn location(artifact: &Artifact) -> String {
    meta_str(artifact, "path")
        .or_else(|| meta_str(artifact, "name"))
        .unwrap_or_else(|| artifact.id.to_string())
}

fn refused_generation(generation: u32) -> String {
    format!(
        "it is a crypt{generation} backup, and this build decrypts crypt14 and crypt15 \
         backups only, so it was not decrypted"
    )
}

/// The scheme name a key opens, for records.
fn key_scheme(key: &Key) -> &'static str {
    match key.kind {
        KeyKind::Crypt14File => "crypt14",
        KeyKind::Crypt15Root => "crypt15",
        KeyKind::Bare => "crypt14 or crypt15",
    }
}

/// A key read from the evidence, held for its case until `held_until`.
struct HeldKey {
    path: String,
    sha256: String,
    key: Key,
    held_until: Instant,
}

/// A backup no held key has opened yet.
struct Pending {
    backup: Artifact,
    generation: u32,
    server_salt: Option<[u8; 32]>,
}

#[derive(Default)]
struct CaseState {
    keys: Vec<HeldKey>,
    pending: Vec<Pending>,
}

fn pairing() -> &'static Mutex<HashMap<Uuid, CaseState>> {
    static PAIRING: OnceLock<Mutex<HashMap<Uuid, CaseState>>> = OnceLock::new();
    PAIRING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How long a key read from the evidence is held for pairing: the unlock
/// lifetime of the owner's key-retention decision of 2026-09-26 (8 hours,
/// or `SEANCE_UNLOCK_TTL_SECS`).
pub(crate) fn key_ttl() -> Duration {
    std::env::var("SEANCE_UNLOCK_TTL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(8 * 60 * 60))
}

impl CaseState {
    /// Drop (and so zero) the keys whose time is up at `now`.
    fn forget_expired(&mut self, now: Instant) {
        self.keys.retain(|k| k.held_until > now);
    }
}

/// Forget the keys of `case` whose time is up at `now` (a test's clock).
#[cfg(test)]
pub(crate) fn forget_expired_in(case: Uuid, now: Instant) {
    let mut state = pairing().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = state.get_mut(&case) {
        c.forget_expired(now);
    }
}

/// The pairing state, with every case's expired keys already dropped.
fn lock_pairing() -> std::sync::MutexGuard<'static, HashMap<Uuid, CaseState>> {
    let mut state = pairing().lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    for c in state.values_mut() {
        c.forget_expired(now);
    }
    state
}

/// Read a whole source, refusing one larger than `cap`.
fn read_capped(artifact: &Artifact, cap: u64) -> Result<Vec<u8>, String> {
    let Some(data) = artifact.data.as_ref() else {
        return Err("no data source was attached to the file, so its bytes were not read".into());
    };
    let size = data.size();
    if size > cap {
        return Err(format!(
            "the file is {size} bytes, past the {cap}-byte ceiling this build reads for it"
        ));
    }
    let mut buf = vec![0u8; size as usize];
    let mut at = 0usize;
    while at < buf.len() {
        match data.read_at(at as u64, &mut buf[at..]) {
            Ok(0) => {
                return Err(format!(
                    "the file declares {size} bytes and only {at} could be read"
                ))
            }
            Ok(n) => at += n,
            Err(e) => return Err(format!("the file could not be read at offset {at}: {e}")),
        }
    }
    Ok(buf)
}

fn sha256(bytes: &[u8]) -> String {
    seance_core::hashing::compute_hashes(bytes).sha256
}

fn record(parent: &Artifact, parent_id: Uuid, metadata: Value) -> Artifact {
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}

/// The statement for a backup whose messages are not in the case.
fn incomplete(backup: &Artifact, status: &str, detail: String, extra: Value) -> Artifact {
    let loc = location(backup);
    let mut m = json!({
        "type": BACKUP_TYPE,
        "status": status,
        "name": format!("WhatsApp backup ({status}): {loc}"),
        "backup_path": loc,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::Encrypted.as_str(),
        "content_incomplete_detail": detail,
        "message": detail,
    });
    if let (Some(obj), Value::Object(more)) = (m.as_object_mut(), extra) {
        obj.extend(more);
    }
    record(backup, backup.id, m)
}

fn not_decrypted(backup: &Artifact, generation: u32, why: &str) -> Artifact {
    let loc = location(backup);
    incomplete(
        backup,
        "NotDecrypted",
        format!(
            "`{loc}` is an encrypted WhatsApp backup and {why}. None of its messages is in \
             this case from this file; their absence here is not evidence they were absent \
             from the device"
        ),
        // The scheme names what a supplied key could answer: a crypt14 or
        // crypt15 statement that a key would open carries its scheme (see
        // `awaiting_extra`); one that could not be read or parsed carries
        // none, so the attention queue offers no key field for it.
        if generation == 14 || generation == 15 {
            json!({"backup_generation": generation})
        } else {
            json!({"backup_generation": generation, "scheme": format!("crypt{generation}")})
        },
    )
}

/// Whether a held key is tried on a backup.
#[derive(PartialEq, Eq)]
enum Fit {
    /// Tried; the GCM tag decides.
    Try,
    /// A crypt14 key whose server salt is not the backup's: refused, with a
    /// record, before any decryption.
    SaltRefuses,
    /// A key of the other scheme (a crypt14 `key` and a crypt15 backup, or
    /// the reverse). Not tried and not recorded against the backup: a phone
    /// that made both kinds holds both keys, and neither is a wrong key for
    /// the other's backups.
    OtherScheme,
}

fn fit(key: &Key, generation: u32, salt: Option<[u8; 32]>) -> Fit {
    match (generation, key.kind) {
        (15, KeyKind::Crypt14File) => Fit::OtherScheme,
        (15, _) => Fit::Try,
        (_, KeyKind::Crypt15Root) => Fit::OtherScheme,
        _ => match (key.server_salt, salt) {
            (Some(ours), Some(theirs)) if ours != theirs => Fit::SaltRefuses,
            // A key or a header with no salt cannot be refused by it; the
            // GCM tag decides.
            _ => Fit::Try,
        },
    }
}

fn on_backup(parser: &WhatsAppParser, backup: &Artifact, named: u32) -> Vec<Artifact> {
    let bytes = match read_capped(backup, MAX_BACKUP_BYTES) {
        Ok(b) => b,
        Err(why) => {
            return vec![not_decrypted(
                backup,
                named,
                &format!("was not read: {why}"),
            )]
        }
    };
    let header = match crypt14::parse_header(&bytes) {
        Ok(h) => h,
        Err(e) => {
            return vec![not_decrypted(
                backup,
                named,
                &format!("its crypt{named} header would not read ({e})"),
            )]
        }
    };
    // The header, not the name, says which scheme the file is.
    let generation = header.generation;

    // A key the examiner supplied for this backup and this run is tried
    // first, and only it: this run is their question about that key.
    if let Some(cred) = credential::for_artifact(backup.id, &[CredentialKind::WhatsappKey]) {
        return with_supplied_key(parser, backup, &bytes, &header, &cred);
    }

    // Held across the decryption below, so a key read on another worker
    // cannot slip between "no key opens it" and "held as pending" and leave
    // the pair unmade. Only backup and key files take this lock.
    let mut state = lock_pairing();
    let case = state.entry(backup.case_id).or_default();
    let candidates: Vec<(String, String, Key)> = case
        .keys
        .iter()
        .filter(|k| fit(&k.key, generation, header.server_salt) == Fit::Try)
        .map(|k| (k.path.clone(), k.sha256.clone(), k.key.clone()))
        .collect();
    let refused_by_salt: Vec<(String, String)> = case
        .keys
        .iter()
        .filter(|k| fit(&k.key, generation, header.server_salt) == Fit::SaltRefuses)
        .map(|k| (k.path.clone(), k.sha256.clone()))
        .collect();

    let mut out = Vec::new();
    for (path, digest, key) in &candidates {
        let origin = KeyOrigin::Evidence {
            path,
            sha256: digest,
        };
        match decrypt_into_records(parser, backup, &bytes, key, &origin, false) {
            Ok(records) => return records,
            Err(e) => out.push(key_refused(backup, path, digest, &e)),
        }
    }
    for (path, digest) in &refused_by_salt {
        out.push(key_refused(
            backup,
            path,
            digest,
            &Crypt14Error::KeyMismatch,
        ));
    }

    let loc = location(backup);
    let version = header
        .app_version
        .clone()
        .map(|v| format!(" by WhatsApp {v}"))
        .unwrap_or_default();
    if case.pending.len() >= MAX_PENDING_PER_CASE {
        out.push(incomplete(
            backup,
            "NotDecrypted",
            format!(
                "`{loc}` is an encrypted crypt{generation} WhatsApp backup made{version}. No \
                 key read from this case's evidence opens it, and {MAX_PENDING_PER_CASE} backups are \
                 already held in this case awaiting a key, so this one was not held for a key \
                 read later. None of its messages is in this case from this file"
            ),
            awaiting_extra(&header),
        ));
        return out;
    }
    case.pending.push(Pending {
        backup: backup.clone(),
        generation,
        server_salt: header.server_salt,
    });
    let opens_with = if generation == 15 {
        "the end-to-end backup key the user set up on the phone: the 64-digit key it showed, \
         also held as `/data/data/com.whatsapp/files/encrypted_backup.key`"
    } else {
        "the key file `/data/data/com.whatsapp/files/key` of the install that made it"
    };
    out.push(incomplete(
        backup,
        "AwaitingKey",
        format!(
            "`{loc}` is an encrypted crypt{generation} WhatsApp backup made{version}. It opens \
             only with {opens_with}, and \
             no such key had been read from this case's evidence when this backup was. If one \
             is read later in this run, the decrypted store is filed under this backup and \
             this statement is superseded; if none is, none of its messages is in this case \
             from this file, and their absence here is not evidence they were absent from the \
             device. A key for it held outside this evidence can be supplied for this \
             backup as the `whatsapp_key` credential"
        ),
        awaiting_extra(&header),
    ));
    out
}

/// What a crypt14 statement a key would answer carries: the scheme, and the
/// credential kind that opens it (the attention queue offers that field).
fn awaiting_extra(header: &crypt14::Header) -> Value {
    json!({
        "backup_generation": header.generation,
        "app_version": header.app_version,
        "scheme": format!("crypt{}", header.generation),
        "credential_kind": CredentialKind::WhatsappKey.as_str(),
    })
}

/// Where the key that opened a backup came from.
enum KeyOrigin<'a> {
    /// The key file read from the case's evidence.
    Evidence { path: &'a str, sha256: &'a str },
    /// Supplied by an examiner for this backup and this run.
    Credential { sha256: &'a str },
}

impl KeyOrigin<'_> {
    fn source(&self) -> &'static str {
        match self {
            Self::Evidence { .. } => "evidence",
            Self::Credential { .. } => "credential",
        }
    }
    fn path(&self) -> Option<&str> {
        match self {
            Self::Evidence { path, .. } => Some(path),
            Self::Credential { .. } => None,
        }
    }
    fn sha256(&self) -> &str {
        match self {
            Self::Evidence { sha256, .. } | Self::Credential { sha256 } => sha256,
        }
    }
    /// "with …", for a sentence.
    fn describe(&self) -> String {
        match self {
            Self::Evidence { path, sha256 } => {
                format!("the key file `{path}` (SHA-256 {sha256})")
            }
            Self::Credential { sha256 } => format!(
                "a key supplied by an examiner for this backup and this run as the \
                 `whatsapp_key` credential (SHA-256 of what was supplied {sha256}; the key \
                 itself is not recorded)"
            ),
        }
    }
}

/// Decode a `whatsapp_key` secret: hex digits, spaces and case ignored. The
/// error never repeats the secret.
fn decode_supplied_key(secret: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = secret
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let hex_value = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.iter().all(|&b| hex_value(b).is_some())
    {
        return Err(format!(
            "what was supplied is not hex ({} character(s) once spaces are removed); the \
             `whatsapp_key` credential is the key file's bytes as hex, or the bare 32-byte key \
             (a crypt15 backup's 64-digit key) as 64 hex digits",
            digits.len()
        ));
    }
    Ok(digits
        .chunks(2)
        .filter_map(|p| Some(hex_value(p[0])? << 4 | hex_value(p[1])?))
        .collect())
}

/// Open `backup` with the key an examiner supplied, and report the outcome to
/// the credential. A key that does not open it is rejected and nothing it
/// produced is persisted; the earlier statement stands.
fn with_supplied_key(
    parser: &WhatsAppParser,
    backup: &Artifact,
    bytes: &[u8],
    header: &crypt14::Header,
    cred: &RunCredential,
) -> Vec<Artifact> {
    let loc = location(backup);
    let refuse = |why: String| {
        cred.rejected(format!(
            "the supplied WhatsApp backup key did not open `{loc}`: {why}"
        ));
        vec![not_decrypted(
            backup,
            header.generation,
            &format!("the key supplied for it did not open it: {why}"),
        )]
    };
    // Zeroed when this call returns, like the credential it came from.
    let raw = match decode_supplied_key(cred.expose_secret()) {
        Ok(r) => zeroize::Zeroizing::new(r),
        Err(why) => return refuse(why),
    };
    let key = match crypt14::parse_key(&raw) {
        Ok(k) => k,
        Err(e) => {
            return refuse(format!(
                "it decodes to {} byte(s), which is neither a bare 32-byte key nor a key \
                 file that reads ({e})",
                raw.len()
            ))
        }
    };
    match fit(&key, header.generation, header.server_salt) {
        Fit::Try => {}
        Fit::SaltRefuses => return refuse(Crypt14Error::KeyMismatch.to_string()),
        Fit::OtherScheme => {
            let e = if header.generation == 15 {
                Crypt14Error::Crypt14KeyOnCrypt15
            } else {
                Crypt14Error::Crypt15KeyOnCrypt14
            };
            return refuse(e.to_string());
        }
    }
    let digest = sha256(&raw);
    let origin = KeyOrigin::Credential { sha256: &digest };
    match decrypt_into_records(parser, backup, bytes, &key, &origin, true) {
        Ok(records) => {
            cred.accepted();
            // Opened: no key read later in this run is to file it again.
            let mut state = lock_pairing();
            if let Some(case) = state.get_mut(&backup.case_id) {
                case.pending.retain(|p| p.backup.id != backup.id);
            }
            records
        }
        Err(e) => refuse(e.to_string()),
    }
}

fn key_refused(backup: &Artifact, key_path: &str, key_sha256: &str, e: &Crypt14Error) -> Artifact {
    let loc = location(backup);
    record(
        backup,
        backup.id,
        json!({
            "type": BACKUP_TYPE,
            "status": "KeyRefused",
            "name": format!("WhatsApp backup key refused: {loc}"),
            "backup_path": loc,
            "key_path": key_path,
            "key_sha256": key_sha256,
            "refusal": e.to_string(),
            "message": format!(
                "The key file `{key_path}` (SHA-256 {key_sha256}) was tried on `{loc}` and \
                 refused: {e}. Nothing was decrypted with it."
            ),
        }),
    )
}

fn on_key(parser: &WhatsAppParser, key_entry: &Artifact) -> Vec<Artifact> {
    let path = location(key_entry);
    let bytes = match read_capped(key_entry, MAX_KEY_BYTES) {
        Ok(b) => b,
        Err(why) => return vec![key_unreadable(key_entry, &path, &why)],
    };
    let key = match crypt14::parse_key(&bytes) {
        Ok(k) => k,
        Err(e) => return vec![key_unreadable(key_entry, &path, &e.to_string())],
    };
    let digest = sha256(&bytes);

    // Take the backups this key may open out of the held set, and decrypt
    // them outside the lock.
    let (opens, others, held) = {
        let mut state = lock_pairing();
        let case = state.entry(key_entry.case_id).or_default();
        let held = if case.keys.len() < MAX_KEYS_PER_CASE {
            case.keys.push(HeldKey {
                path: path.clone(),
                sha256: digest.clone(),
                key: key.clone(),
                held_until: Instant::now() + key_ttl(),
            });
            true
        } else {
            false
        };
        let (opens, stay): (Vec<Pending>, Vec<Pending>) = case
            .pending
            .drain(..)
            .partition(|p| fit(&key, p.generation, p.server_salt) == Fit::Try);
        let others: Vec<Artifact> = stay
            .iter()
            .filter(|p| fit(&key, p.generation, p.server_salt) == Fit::SaltRefuses)
            .map(|p| p.backup.clone())
            .collect();
        case.pending = stay;
        (opens, others, held)
    };

    let mut out = Vec::new();
    let mut decrypted = 0usize;
    let mut back_to_pending = Vec::new();
    for p in opens {
        // It was read once when it arrived; a second read that fails is
        // stated as such and the backup stays awaiting a key.
        let bytes = match read_capped(&p.backup, MAX_BACKUP_BYTES) {
            Ok(b) => b,
            Err(why) => {
                out.push(not_decrypted(
                    &p.backup,
                    p.generation,
                    &format!("could not be read again when its key arrived: {why}"),
                ));
                back_to_pending.push(p);
                continue;
            }
        };
        let origin = KeyOrigin::Evidence {
            path: &path,
            sha256: &digest,
        };
        match decrypt_into_records(parser, &p.backup, &bytes, &key, &origin, true) {
            Ok(records) => {
                decrypted += 1;
                out.extend(records);
            }
            Err(e) => {
                out.push(key_refused(&p.backup, &path, &digest, &e));
                back_to_pending.push(p);
            }
        }
    }
    for backup in &others {
        out.push(key_refused(
            backup,
            &path,
            &digest,
            &Crypt14Error::KeyMismatch,
        ));
    }
    if !back_to_pending.is_empty() {
        let mut state = lock_pairing();
        state
            .entry(key_entry.case_id)
            .or_default()
            .pending
            .extend(back_to_pending);
    }

    let scheme = key_scheme(&key);
    let hours = key_ttl().as_secs() / 3600;
    let held_note = if held {
        format!(
            "It is held in this process's memory, for this case only, for {hours} hour(s) or \
             until a restart, whichever comes first, and tried on every {scheme} backup read \
             in that time; it is never written to the case, an export or a log."
        )
    } else {
        "It was not held for backups read after it: this case already holds the most keys this \
         build keeps."
            .to_string()
    };
    out.push(record(
        key_entry,
        key_entry.id,
        json!({
            "type": BACKUP_TYPE,
            "status": "KeyFound",
            "name": format!("WhatsApp backup key: {path}"),
            "key_path": path,
            "key_sha256": digest,
            "key_version": key.key_version,
            "key_scheme": scheme,
            "backups_decrypted": decrypted,
            "message": format!(
                "The WhatsApp {scheme} backup key file `{path}` (SHA-256 {digest}) was read. \
                 It decrypted {decrypted} backup(s) held when it was read. {held_note} The \
                 key itself is not recorded."
            ),
        }),
    ));
    out
}

fn key_unreadable(key_entry: &Artifact, path: &str, why: &str) -> Artifact {
    record(
        key_entry,
        key_entry.id,
        json!({
            "type": BACKUP_TYPE,
            "status": "KeyUnreadable",
            "name": format!("WhatsApp backup key (unreadable): {path}"),
            "key_path": path,
            "message": format!(
                "`{path}` is where WhatsApp keeps its backup key, and it did not read as one: \
                 {why}. No backup in this case was decrypted with it."
            ),
        }),
    )
}

/// The decrypted store, as the message-store path reads it.
///
/// A backup is one file: whatever write-ahead log the phone's store had when
/// the backup was made is inside it or gone, and no `-wal` of the backup
/// exists to be missed. So this source says it can look for siblings and
/// finds none, which the stager reads as "no WAL" rather than "a WAL that
/// could not be reached" (a WAL-mode `wa.db` otherwise drew a record saying
/// committed rows were missing).
#[derive(Debug)]
struct BackupPlaintext(ByteSliceDataSource);

impl DataSource for BackupPlaintext {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.0.size()
    }
    fn resident_bytes(&self) -> Option<&[u8]> {
        self.0.resident_bytes()
    }
    fn supports_siblings(&self) -> bool {
        true
    }
}

/// Decrypt `bytes` with `key` and parse the store it holds, filing every
/// record under the backup and stamping it with where it came from.
fn decrypt_into_records(
    parser: &WhatsAppParser,
    backup: &Artifact,
    bytes: &[u8],
    key: &Key,
    origin: &KeyOrigin<'_>,
    supersedes: bool,
) -> Result<Vec<Artifact>, Crypt14Error> {
    let key_path = origin.path();
    let key_sha256 = origin.sha256();
    let key_source = origin.source();
    let opened = crypt14::decrypt_backup(bytes, key)?;
    let loc = location(backup);
    let name = meta_str(backup, "name").unwrap_or_else(|| loc.clone());
    let backup_sha256 = sha256(bytes);
    let generation = opened.header.generation;
    let app_version = opened.header.app_version.clone();
    // `null` when the file carries no MD5 to check (a multi-file crypt15).
    let checksum_ok = if opened.checksum_present {
        json!(opened.checksum_ok)
    } else {
        Value::Null
    };
    let checksum = match (opened.checksum_present, opened.checksum_ok) {
        (true, true) => "the file's own trailing MD5 matches",
        (true, false) => "the file's own trailing MD5 does NOT match, though the GCM tag verified",
        (false, _) => "the file carries no trailing MD5 (a multi-file backup does not)",
    };
    let database = match opened.payload {
        Payload::Database(db) => db,
        Payload::Archive(zip) => {
            return Ok(archive_records(
                backup,
                ArchiveOpened {
                    zip,
                    generation,
                    inflated: opened.inflated,
                    app_version,
                    backup_sha256,
                    checksum_ok,
                    checksum,
                },
                origin,
                supersedes,
            ))
        }
    };
    let db_len = database.len();
    let db_sha256 = sha256(&database);

    // The store is parsed by the message-store path, as the backup's own
    // child: same id, the decrypted bytes, and a name the store gate opens
    // ("whatsapp" in it) while schema detection decides the platform.
    let mut inner_meta = backup.metadata.clone();
    if let Some(obj) = inner_meta.as_object_mut() {
        obj.insert(
            "name".into(),
            json!(format!("{name} (decrypted WhatsApp backup)")),
        );
    }
    let mut inner = Artifact::new(
        backup.case_id,
        ArtifactType::FileEntry,
        Some(Arc::new(BackupPlaintext(ByteSliceDataSource::new(database))) as Arc<dyn DataSource>),
        inner_meta,
    );
    inner.id = backup.id;
    let parsed = parser
        .process(&inner)
        .map_err(|e| Crypt14Error::NotCrypt14(format!("the decrypted store did not parse: {e}")))?;

    let stamp = json!({
        "backup_path": loc,
        "backup_sha256": backup_sha256,
        "key_path": key_path,
        "key_sha256": key_sha256,
        "key_source": key_source,
        "decrypted_sha256": db_sha256,
        "checksum_ok": checksum_ok,
    });
    let mut out: Vec<Artifact> = parsed
        .into_iter()
        .map(|mut a| {
            if let Some(obj) = a.metadata.as_object_mut() {
                obj.insert("provenance".into(), json!("decrypted_backup"));
                obj.insert("decrypted_backup".into(), stamp.clone());
            }
            a
        })
        .collect();
    let messages = out
        .iter()
        .filter(|a| a.metadata["type"] == "WhatsApp")
        .count();
    let held = if messages == 0 {
        " It holds no message store this parser reads (a `wa.db` backup is the contacts \
         store), so no message is filed from it."
    } else {
        ""
    };
    let mut summary = json!({
        "type": BACKUP_TYPE,
        "status": "Decrypted",
        "name": format!("WhatsApp backup (decrypted): {loc}"),
        "backup_generation": generation,
        "payload": "sqlite",
        "backup_path": loc,
        "backup_sha256": backup_sha256,
        "key_path": key_path,
        "key_sha256": key_sha256,
        "key_source": key_source,
        "decrypted_sha256": db_sha256,
        "decrypted_bytes": db_len,
        "checksum_ok": checksum_ok,
        "app_version": app_version,
        "records_filed": out.len(),
        "message": format!(
            "`{loc}` was decrypted with {key}: the GCM tag verified and {checksum}. The {db_len}-byte store (SHA-256 {db_sha256}) was \
             parsed and {n} record(s) filed under this backup, each stamped \
             `provenance: decrypted_backup`.{held} A backup is a copy the phone made earlier, \
             so its messages may repeat those of the live store.",
            n = out.len(),
            key = origin.describe(),
        ),
    });
    if supersedes {
        if let Some(obj) = summary.as_object_mut() {
            obj.insert("supersedes_status".into(), json!("AwaitingKey"));
        }
    }
    out.push(record(backup, backup.id, summary));
    Ok(out)
}

/// What a backup that holds a ZIP archive decrypted to.
struct ArchiveOpened {
    zip: Vec<u8>,
    generation: u32,
    inflated: bool,
    app_version: Option<String>,
    backup_sha256: String,
    checksum_ok: Value,
    checksum: &'static str,
}

/// A backup that holds a ZIP archive (a multi-file backup such as
/// `stickers.backup.crypt15`, or an incremental one): the archive is filed as
/// a file beneath the backup, for the archive expander to open, with a
/// `Decrypted` statement saying so.
///
/// The archive's metadata is made fresh, never copied from the backup: the
/// backup's own location (`data_runs`, `source_path`, ...) would make the
/// content resolver serve the ciphertext as the archive. With none, the
/// archive and its entries are read during this run only, and the resolver
/// refuses them afterwards rather than serving the wrong bytes.
fn archive_records(
    backup: &Artifact,
    a: ArchiveOpened,
    origin: &KeyOrigin<'_>,
    supersedes: bool,
) -> Vec<Artifact> {
    let loc = location(backup);
    let base = meta_str(backup, "name").unwrap_or_else(|| loc.clone());
    let stem = base
        .rsplit_once(".crypt")
        .map(|(s, _)| s.to_string())
        .unwrap_or(base);
    let zip_name = format!("{stem} (decrypted).zip");
    let zip_len = a.zip.len();
    let zip_sha256 = sha256(&a.zip);
    let stamp = json!({
        "backup_path": loc,
        "backup_sha256": a.backup_sha256,
        "key_path": origin.path(),
        "key_sha256": origin.sha256(),
        "key_source": origin.source(),
        "decrypted_sha256": zip_sha256,
        "checksum_ok": a.checksum_ok,
    });
    let file = Artifact::new(
        backup.case_id,
        ArtifactType::FileEntry,
        Some(Arc::new(ByteSliceDataSource::new(a.zip)) as Arc<dyn DataSource>),
        json!({
            "name": zip_name,
            "path": format!("{loc} (decrypted).zip"),
            "size": zip_len,
            "sha256": zip_sha256,
            "provenance": "decrypted_backup",
            "decrypted_backup": stamp,
        }),
    )
    .with_parent(backup.id);
    let how = if a.inflated {
        "inflated from its zlib stream"
    } else {
        "stored as it is"
    };
    let mut summary = json!({
        "type": BACKUP_TYPE,
        "status": "Decrypted",
        "name": format!("WhatsApp backup (decrypted): {loc}"),
        "backup_generation": a.generation,
        "payload": "zip",
        "backup_path": loc,
        "backup_sha256": a.backup_sha256,
        "key_path": origin.path(),
        "key_sha256": origin.sha256(),
        "key_source": origin.source(),
        "decrypted_sha256": zip_sha256,
        "decrypted_bytes": zip_len,
        "checksum_ok": a.checksum_ok,
        "app_version": a.app_version,
        "records_filed": 1,
        "message": format!(
            "`{loc}` was decrypted with {key}: the GCM tag verified and {checksum}. It holds \
             a ZIP archive ({how}; {zip_len} bytes, SHA-256 {zip_sha256}), not a message \
             store: a multi-file or incremental backup. The archive is filed beneath this \
             backup as `{zip_name}` for the archive expander to open, stamped \
             `provenance: decrypted_backup`. It exists only in memory: its bytes and its \
             entries' can be read during this run, and are refused, not served, afterwards.",
            key = origin.describe(),
            checksum = a.checksum,
        ),
    });
    if supersedes {
        if let Some(obj) = summary.as_object_mut() {
            obj.insert("supersedes_status".into(), json!("AwaitingKey"));
        }
    }
    let summary = record(backup, backup.id, summary);
    vec![file, summary]
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::artifact::ArtifactType;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::module::ForensicsModule;
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    const BACKUP: &[u8] = include_bytes!("../tests/fixtures/synthetic_msgstore.db.crypt14");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/synthetic.key");
    const OTHER_KEY: &[u8] = include_bytes!("../tests/fixtures/synthetic_other_install.key");

    const BACKUP_PATH: &str =
        "/data/media/0/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt14";
    const KEY_PATH: &str = "/data/data/com.whatsapp/files/key";

    fn entry(case_id: Uuid, path: &str, bytes: &[u8]) -> Artifact {
        let name = path.rsplit('/').next().unwrap();
        Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes.to_vec())) as Arc<dyn DataSource>),
            json!({"name": name, "path": path, "size": bytes.len()}),
        )
    }

    fn run(a: &Artifact) -> Vec<Artifact> {
        WhatsAppParser.process(a).expect("process")
    }

    fn of_status<'a>(out: &'a [Artifact], status: &str) -> Vec<&'a Artifact> {
        out.iter()
            .filter(|a| a.metadata["type"] == BACKUP_TYPE && a.metadata["status"] == status)
            .collect()
    }

    fn messages(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["type"] == "WhatsApp")
            .collect()
    }

    fn sha256(b: &[u8]) -> String {
        seance_core::hashing::compute_hashes(b).sha256
    }

    #[test]
    fn a_crypt15_backup_whose_header_will_not_read_is_recorded_not_decrypted() {
        let case = Uuid::new_v4();
        let a = entry(
            case,
            "/sdcard/WhatsApp/Databases/msgstore.db.crypt15",
            b"\x00\x01anything",
        );
        let out = run(&a);
        let refused = of_status(&out, "NotDecrypted");
        assert_eq!(refused.len(), 1, "one refusal record: {out:#?}");
        let r = &refused[0].metadata;
        assert_eq!(refused[0].parent_id, Some(a.id));
        assert_eq!(r["backup_generation"], 15);
        assert_eq!(r["content_incomplete"], true);
        assert_eq!(r["content_incomplete_reason"], "encrypted");
        assert!(
            r["content_incomplete_detail"]
                .as_str()
                .unwrap()
                .contains("crypt15"),
            "the refusal names the generation"
        );
        // A header that does not read is not one a key would answer.
        assert!(r["credential_kind"].is_null());
        assert!(messages(&out).is_empty());
    }

    #[test]
    fn an_older_generation_is_refused_by_name_with_a_record() {
        let a = entry(
            Uuid::new_v4(),
            "/sdcard/WhatsApp/Databases/msgstore.db.crypt12",
            b"x",
        );
        let out = run(&a);
        let refused = of_status(&out, "NotDecrypted");
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].metadata["backup_generation"], 12);
    }

    #[test]
    fn a_backup_read_before_its_key_awaits_it_and_is_decrypted_when_the_key_arrives() {
        let case = Uuid::new_v4();
        let backup = entry(case, BACKUP_PATH, BACKUP);
        let first = run(&backup);
        let awaiting = of_status(&first, "AwaitingKey");
        assert_eq!(awaiting.len(), 1, "{first:#?}");
        assert_eq!(awaiting[0].parent_id, Some(backup.id));
        assert_eq!(awaiting[0].metadata["content_incomplete"], true);
        assert!(messages(&first).is_empty());

        let key = entry(case, KEY_PATH, KEY);
        let second = run(&key);
        let found = of_status(&second, "KeyFound");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].parent_id, Some(key.id));
        assert_eq!(found[0].metadata["key_sha256"], sha256(KEY));
        assert_eq!(found[0].metadata["backups_decrypted"], 1);

        let decrypted = of_status(&second, "Decrypted");
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].parent_id, Some(backup.id));
        assert_eq!(decrypted[0].metadata["supersedes_status"], "AwaitingKey");
        assert_eq!(decrypted[0].metadata["key_path"], KEY_PATH);
        assert_eq!(decrypted[0].metadata["checksum_ok"], true);

        let msgs = messages(&second);
        assert_eq!(msgs.len(), 3, "the three messages the backup holds");
        for m in &msgs {
            assert_eq!(m.parent_id, Some(backup.id));
            assert_eq!(m.metadata["provenance"], "decrypted_backup");
            let d = &m.metadata["decrypted_backup"];
            assert_eq!(d["backup_path"], BACKUP_PATH);
            assert_eq!(d["backup_sha256"], sha256(BACKUP));
            assert_eq!(d["key_path"], KEY_PATH);
            assert_eq!(d["key_sha256"], sha256(KEY));
        }
        let mut texts: Vec<&str> = msgs
            .iter()
            .filter_map(|m| m.metadata["text"].as_str())
            .collect();
        texts.sort();
        assert_eq!(
            texts,
            [
                "Synthetic backup message one",
                "Synthetic backup message three",
                "Synthetic backup message two"
            ]
        );

        // The AES key (the last 32 bytes of the key file) is on no record.
        let aes_hex: String = KEY[KEY.len() - 32..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let all = serde_json::to_string(
            &first
                .iter()
                .chain(second.iter())
                .map(|a| a.metadata.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(!all.contains(&aes_hex), "the key is never on a record");
    }

    #[test]
    fn a_key_read_first_opens_the_backup_when_it_arrives() {
        let case = Uuid::new_v4();
        let key = entry(case, KEY_PATH, KEY);
        let first = run(&key);
        assert_eq!(
            of_status(&first, "KeyFound")[0].metadata["backups_decrypted"],
            0
        );

        let backup = entry(case, BACKUP_PATH, BACKUP);
        let second = run(&backup);
        assert!(of_status(&second, "AwaitingKey").is_empty());
        assert_eq!(of_status(&second, "Decrypted").len(), 1);
        assert_eq!(messages(&second).len(), 3);
    }

    #[test]
    fn a_key_from_another_install_is_refused_by_its_salt_and_the_backup_keeps_waiting() {
        let case = Uuid::new_v4();
        let backup = entry(case, BACKUP_PATH, BACKUP);
        run(&backup);
        let other = entry(case, KEY_PATH, OTHER_KEY);
        let out = run(&other);
        assert!(of_status(&out, "Decrypted").is_empty());
        assert!(messages(&out).is_empty());
        let refused = of_status(&out, "KeyRefused");
        assert_eq!(refused.len(), 1, "{out:#?}");
        assert_eq!(refused[0].parent_id, Some(backup.id));
        assert_eq!(refused[0].metadata["key_sha256"], sha256(OTHER_KEY));

        // The right key, arriving after, still opens it.
        let out = run(&entry(case, KEY_PATH, KEY));
        assert_eq!(of_status(&out, "Decrypted").len(), 1);
    }

    #[test]
    fn pairing_is_scoped_to_the_case() {
        run(&entry(Uuid::new_v4(), KEY_PATH, KEY));
        let out = run(&entry(Uuid::new_v4(), BACKUP_PATH, BACKUP));
        assert_eq!(of_status(&out, "AwaitingKey").len(), 1);
        assert!(messages(&out).is_empty());
    }

    #[test]
    fn a_file_named_key_elsewhere_is_not_the_whatsapp_key() {
        let out = run(&entry(
            Uuid::new_v4(),
            "/data/data/com.other/files/key",
            KEY,
        ));
        assert!(out.is_empty(), "{out:#?}");
    }

    #[test]
    fn a_key_file_that_will_not_parse_is_recorded() {
        let out = run(&entry(Uuid::new_v4(), KEY_PATH, b"not a key"));
        assert_eq!(of_status(&out, "KeyUnreadable").len(), 1, "{out:#?}");
    }

    // ---- ROADMAP §5.7, owner decision (c) part b: the `whatsapp_key`
    // credential, for a backup seized without the phone holding its key.

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Run the parser on `backup` with `secret` supplied for it as a
    /// `whatsapp_key` credential, as the credential route does.
    fn run_with_key(
        backup: &Artifact,
        secret: &str,
    ) -> (
        Vec<Artifact>,
        Option<seance_core::credential::CredentialOutcome>,
    ) {
        use seance_core::credential::{self, CredentialKind, RunCredential};
        let cred = Arc::new(RunCredential::new(
            backup.id,
            CredentialKind::WhatsappKey,
            secret.to_string(),
            "examiner",
        ));
        let out = credential::scoped(Some(cred.clone()), || run(backup));
        (out, cred.outcome())
    }

    fn all_metadata(out: &[Artifact]) -> String {
        serde_json::to_string(&out.iter().map(|a| a.metadata.clone()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn a_supplied_key_file_opens_a_backup_whose_key_is_not_in_the_case() {
        use seance_core::credential::CredentialOutcome;
        let backup = entry(Uuid::new_v4(), BACKUP_PATH, BACKUP);
        let (out, outcome) = run_with_key(&backup, &hex(KEY));
        assert_eq!(outcome, Some(CredentialOutcome::Accepted), "{out:#?}");
        assert!(of_status(&out, "AwaitingKey").is_empty());
        let decrypted = of_status(&out, "Decrypted");
        assert_eq!(decrypted.len(), 1, "{out:#?}");
        let d = &decrypted[0].metadata;
        assert_eq!(decrypted[0].parent_id, Some(backup.id));
        assert_eq!(d["key_source"], "credential");
        assert_eq!(d["key_sha256"], sha256(KEY), "the key file's own hash");
        assert!(d["key_path"].is_null(), "a supplied key has no path");
        assert_eq!(d["supersedes_status"], "AwaitingKey");
        let msgs = messages(&out);
        assert_eq!(msgs.len(), 3);
        for m in &msgs {
            assert_eq!(m.metadata["provenance"], "decrypted_backup");
            assert_eq!(m.metadata["decrypted_backup"]["key_source"], "credential");
        }
        let all = all_metadata(&out);
        assert!(!all.contains(&hex(KEY)), "the secret is on no record");
        assert!(
            !all.contains(&hex(&KEY[KEY.len() - 32..])),
            "nor the AES key"
        );
    }

    #[test]
    fn a_supplied_bare_key_of_64_hex_digits_opens_the_backup() {
        use seance_core::credential::CredentialOutcome;
        let aes = &KEY[KEY.len() - 32..];
        let backup = entry(Uuid::new_v4(), BACKUP_PATH, BACKUP);
        // Upper case and spaced, as it may be read off a screen.
        let spaced: String = hex(aes)
            .to_ascii_uppercase()
            .as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let (out, outcome) = run_with_key(&backup, &spaced);
        assert_eq!(outcome, Some(CredentialOutcome::Accepted), "{out:#?}");
        assert_eq!(of_status(&out, "Decrypted").len(), 1);
        assert_eq!(messages(&out).len(), 3);
        assert_eq!(
            of_status(&out, "Decrypted")[0].metadata["key_sha256"],
            sha256(aes)
        );
    }

    #[test]
    fn a_supplied_key_from_another_install_is_rejected_and_nothing_is_decrypted() {
        use seance_core::credential::CredentialOutcome;
        let backup = entry(Uuid::new_v4(), BACKUP_PATH, BACKUP);
        let (out, outcome) = run_with_key(&backup, &hex(OTHER_KEY));
        match outcome {
            Some(CredentialOutcome::Rejected { reason }) => {
                assert!(!reason.contains(&hex(OTHER_KEY)), "{reason}");
            }
            other => panic!("expected a rejection, got {other:?}: {out:#?}"),
        }
        assert!(of_status(&out, "Decrypted").is_empty());
        assert!(messages(&out).is_empty());
    }

    #[test]
    fn a_supplied_secret_that_is_not_a_key_is_rejected_without_echoing_it() {
        use seance_core::credential::CredentialOutcome;
        let backup = entry(Uuid::new_v4(), BACKUP_PATH, BACKUP);
        for secret in ["hunter2 is my password", "abc", "00ff"] {
            let (out, outcome) = run_with_key(&backup, secret);
            match outcome {
                Some(CredentialOutcome::Rejected { reason }) => {
                    assert!(!reason.contains(secret), "{reason}");
                }
                other => panic!("{secret}: expected a rejection, got {other:?}"),
            }
            assert!(messages(&out).is_empty());
            assert!(!all_metadata(&out).contains(secret));
        }
    }

    #[test]
    fn a_backup_opened_by_a_supplied_key_is_no_longer_held_for_pairing() {
        let case = Uuid::new_v4();
        let backup = entry(case, BACKUP_PATH, BACKUP);
        assert_eq!(of_status(&run(&backup), "AwaitingKey").len(), 1);
        let (out, _) = run_with_key(&backup, &hex(KEY));
        assert_eq!(of_status(&out, "Decrypted").len(), 1);
        // The key file read later has nothing left to open: the store is not
        // filed twice.
        let later = run(&entry(case, KEY_PATH, KEY));
        assert!(of_status(&later, "Decrypted").is_empty(), "{later:#?}");
        assert_eq!(
            of_status(&later, "KeyFound")[0].metadata["backups_decrypted"],
            0
        );
    }

    #[test]
    fn an_awaiting_statement_names_the_credential_that_would_open_it() {
        let out = run(&entry(Uuid::new_v4(), BACKUP_PATH, BACKUP));
        let awaiting = of_status(&out, "AwaitingKey");
        assert_eq!(awaiting[0].metadata["scheme"], "crypt14");
        assert_eq!(awaiting[0].metadata["credential_kind"], "whatsapp_key");
        // A crypt15 is answered by the same credential kind (its 64-digit
        // root key).
        let out = run(&entry(
            Uuid::new_v4(),
            "/sdcard/WhatsApp/Databases/msgstore.db.crypt15",
            C15_STORE,
        ));
        let awaiting = of_status(&out, "AwaitingKey");
        assert_eq!(awaiting[0].metadata["scheme"], "crypt15");
        assert_eq!(awaiting[0].metadata["credential_kind"], "whatsapp_key");
    }

    // ---- crypt15 in ingest (ROADMAP §5.7; owner decision (c) of 2026-09-26
    // extended to crypt15 on 2026-09-27). Synthetic fixtures from
    // tests/fixtures/make_synthetic_crypt15.py; tests/real_crypt15.rs grades
    // the real backups.
    const C15_STORE: &[u8] = include_bytes!("../tests/fixtures/synthetic_msgstore.db.crypt15");
    const C15_STICKERS: &[u8] =
        include_bytes!("../tests/fixtures/synthetic_stickers.backup.crypt15");
    const C15_ZIP: &[u8] = include_bytes!("../tests/fixtures/synthetic_crypt15_archive.zip");
    const C15_KEY: &[u8] = include_bytes!("../tests/fixtures/synthetic_encrypted_backup.key");
    const C15_PATH: &str =
        "/data/media/0/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15";
    const C15_KEY_PATH: &str = "/data/data/com.whatsapp/files/encrypted_backup.key";

    fn c15_root_hex() -> String {
        hex(&C15_KEY[C15_KEY.len() - 32..])
    }

    #[test]
    fn a_crypt15_read_before_its_key_awaits_it_and_opens_when_the_key_arrives() {
        let case = Uuid::new_v4();
        let backup = entry(case, C15_PATH, C15_STORE);
        let first = run(&backup);
        let awaiting = of_status(&first, "AwaitingKey");
        assert_eq!(awaiting.len(), 1, "{first:#?}");
        assert_eq!(awaiting[0].metadata["backup_generation"], 15);
        assert_eq!(awaiting[0].metadata["content_incomplete"], true);
        assert!(messages(&first).is_empty());

        let key = entry(case, C15_KEY_PATH, C15_KEY);
        let second = run(&key);
        let found = of_status(&second, "KeyFound");
        assert_eq!(found.len(), 1, "{second:#?}");
        assert_eq!(found[0].metadata["key_scheme"], "crypt15");
        assert_eq!(found[0].metadata["backups_decrypted"], 1);
        let decrypted = of_status(&second, "Decrypted");
        assert_eq!(decrypted.len(), 1, "{second:#?}");
        let d = &decrypted[0].metadata;
        assert_eq!(decrypted[0].parent_id, Some(backup.id));
        assert_eq!(d["backup_generation"], 15);
        assert_eq!(d["supersedes_status"], "AwaitingKey");
        assert_eq!(d["key_path"], C15_KEY_PATH);
        assert_eq!(d["checksum_ok"], true);
        let msgs = messages(&second);
        assert_eq!(msgs.len(), 2, "{second:#?}");
        for m in &msgs {
            assert_eq!(m.parent_id, Some(backup.id));
            assert_eq!(m.metadata["provenance"], "decrypted_backup");
        }
        let all = all_metadata(&first) + &all_metadata(&second);
        assert!(
            !all.contains(&c15_root_hex()),
            "the root key is on no record"
        );
    }

    #[test]
    fn a_crypt15_key_read_first_opens_the_backup_when_it_arrives() {
        let case = Uuid::new_v4();
        run(&entry(case, C15_KEY_PATH, C15_KEY));
        let out = run(&entry(case, C15_PATH, C15_STORE));
        assert!(of_status(&out, "AwaitingKey").is_empty(), "{out:#?}");
        assert_eq!(of_status(&out, "Decrypted").len(), 1);
        assert_eq!(messages(&out).len(), 2);
    }

    #[test]
    fn keys_of_the_other_scheme_are_not_tried_and_leave_no_refusal() {
        let case = Uuid::new_v4();
        // A crypt14 key file and a crypt14 backup, a crypt15 key and backup,
        // in one case: each pair opens, neither key is offered to the other.
        run(&entry(case, KEY_PATH, KEY));
        run(&entry(case, C15_KEY_PATH, C15_KEY));
        let c15 = run(&entry(case, C15_PATH, C15_STORE));
        assert_eq!(of_status(&c15, "Decrypted").len(), 1, "{c15:#?}");
        assert!(of_status(&c15, "KeyRefused").is_empty(), "{c15:#?}");
        let c14 = run(&entry(case, BACKUP_PATH, BACKUP));
        assert_eq!(of_status(&c14, "Decrypted").len(), 1, "{c14:#?}");
        assert!(of_status(&c14, "KeyRefused").is_empty(), "{c14:#?}");
    }

    #[test]
    fn a_wrong_crypt15_root_is_refused_by_the_tag_and_the_backup_keeps_waiting() {
        let case = Uuid::new_v4();
        let backup = entry(case, C15_PATH, C15_STORE);
        run(&backup);
        let mut wrong = C15_KEY.to_vec();
        let last = wrong.len() - 1;
        wrong[last] ^= 1;
        let out = run(&entry(case, C15_KEY_PATH, &wrong));
        assert!(of_status(&out, "Decrypted").is_empty());
        let refused = of_status(&out, "KeyRefused");
        assert_eq!(refused.len(), 1, "{out:#?}");
        assert_eq!(refused[0].parent_id, Some(backup.id));
        assert!(refused[0].metadata["refusal"]
            .as_str()
            .unwrap()
            .contains("GCM tag"));
        // The right key, after, still opens it.
        let out = run(&entry(case, C15_KEY_PATH, C15_KEY));
        assert_eq!(of_status(&out, "Decrypted").len(), 1, "{out:#?}");
    }

    #[test]
    fn a_crypt15_zip_payload_is_filed_as_the_decrypted_archive() {
        let case = Uuid::new_v4();
        run(&entry(case, C15_KEY_PATH, C15_KEY));
        let path =
            "/data/media/0/Android/media/com.whatsapp/WhatsApp/Backups/stickers.backup.crypt15";
        let backup = entry(case, path, C15_STICKERS);
        let out = run(&backup);
        let decrypted = of_status(&out, "Decrypted");
        assert_eq!(decrypted.len(), 1, "{out:#?}");
        let d = &decrypted[0].metadata;
        assert_eq!(d["payload"], "zip");
        assert!(d["checksum_ok"].is_null(), "no MD5 trailer to check");
        assert_eq!(d["decrypted_sha256"], sha256(C15_ZIP));
        let files: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(files.len(), 1, "{out:#?}");
        let f = files[0];
        assert_eq!(f.parent_id, Some(backup.id));
        assert!(f.metadata["name"].as_str().unwrap().ends_with(".zip"));
        assert_eq!(f.metadata["provenance"], "decrypted_backup");
        // No location of the backup's own is carried over: the content
        // resolver must not serve the ciphertext as the archive.
        for field in [
            "data_runs",
            "source_path",
            "offset_bytes",
            "resident_data_b64",
        ] {
            assert!(f.metadata.get(field).is_none(), "{field}");
        }
        let data = f.data.as_ref().expect("the archive's bytes");
        let mut buf = vec![0u8; data.size() as usize];
        data.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, C15_ZIP);
    }

    #[test]
    fn a_supplied_crypt15_root_of_64_hex_digits_opens_the_backup() {
        use seance_core::credential::CredentialOutcome;
        let backup = entry(Uuid::new_v4(), C15_PATH, C15_STORE);
        let (out, outcome) = run_with_key(&backup, &c15_root_hex().to_ascii_uppercase());
        assert_eq!(outcome, Some(CredentialOutcome::Accepted), "{out:#?}");
        let decrypted = of_status(&out, "Decrypted");
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].metadata["key_source"], "credential");
        assert_eq!(messages(&out).len(), 2);
        assert!(!all_metadata(&out).contains(&c15_root_hex()));
    }

    #[test]
    fn a_supplied_wrong_key_for_a_crypt15_is_rejected_and_recorded_not_decrypted() {
        use seance_core::credential::CredentialOutcome;
        let backup = entry(Uuid::new_v4(), C15_PATH, C15_STORE);
        for secret in [hex(&[0x11; 32]), hex(KEY)] {
            let (out, outcome) = run_with_key(&backup, &secret);
            assert!(
                matches!(outcome, Some(CredentialOutcome::Rejected { .. })),
                "{outcome:?}"
            );
            let refused = of_status(&out, "NotDecrypted");
            assert_eq!(refused.len(), 1, "{out:#?}");
            assert_eq!(refused[0].metadata["backup_generation"], 15);
            assert!(messages(&out).is_empty());
        }
    }

    #[test]
    fn a_held_key_is_forgotten_when_its_time_is_up() {
        let case = Uuid::new_v4();
        run(&entry(case, C15_KEY_PATH, C15_KEY));
        forget_expired_in(
            case,
            std::time::Instant::now() + key_ttl() + std::time::Duration::from_secs(1),
        );
        let out = run(&entry(case, C15_PATH, C15_STORE));
        assert_eq!(of_status(&out, "AwaitingKey").len(), 1, "{out:#?}");
    }
}
