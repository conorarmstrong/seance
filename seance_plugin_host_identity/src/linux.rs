//! The identity files of a Linux system.
use std::collections::BTreeMap;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;

/// Ceiling on an identity file. The largest of these on a real system is
/// `/etc/passwd` on a host with thousands of accounts, and that is still well
/// inside this.
const MAX_IDENTITY_BYTES: usize = 1024 * 1024;

/// Ceiling on accounts carried into one record.
const MAX_ACCOUNTS: usize = 2_000;

/// Which identity file a path is, if it is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityFile {
    /// `/etc/os-release` or `/usr/lib/os-release`.
    OsRelease,
    /// `/etc/lsb-release`.
    LsbRelease,
    /// `/etc/hostname`.
    Hostname,
    /// `/etc/machine-id` or `/var/lib/dbus/machine-id`.
    MachineId,
    /// `/etc/timezone`.
    Timezone,
    /// `/etc/passwd`.
    Passwd,
}

/// Recognise an identity file by its **path**, not its name alone.
///
/// `hostname`, `timezone` and `passwd` are ordinary words: a name-only match
/// would claim a shell script, a manual page or a metasploit module as a
/// statement about the host. The path these files live at is what makes them
/// the system's own, so the path is what is matched, as a suffix so that an
/// image mounted under a prefix still matches.
pub fn identity_file(path: &str) -> Option<IdentityFile> {
    let normalised = path.replace('\\', "/");
    let lower = normalised.to_ascii_lowercase();
    let ends = |suffix: &str| lower == suffix.trim_start_matches('/') || lower.ends_with(suffix);
    if ends("/etc/os-release") || ends("/usr/lib/os-release") {
        return Some(IdentityFile::OsRelease);
    }
    if ends("/etc/lsb-release") {
        return Some(IdentityFile::LsbRelease);
    }
    if ends("/etc/hostname") {
        return Some(IdentityFile::Hostname);
    }
    if ends("/etc/machine-id") || ends("/var/lib/dbus/machine-id") {
        return Some(IdentityFile::MachineId);
    }
    if ends("/etc/timezone") {
        return Some(IdentityFile::Timezone);
    }
    if ends("/etc/passwd") {
        return Some(IdentityFile::Passwd);
    }
    None
}

/// Parse `KEY=value` release text, unquoting values the way the shell does.
pub fn parse_release(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        if value.is_empty() {
            continue;
        }
        out.insert(key.trim().to_ascii_uppercase(), value.to_string());
    }
    out
}

/// One account line of `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// Parse `/etc/passwd`. Lines that are not seven colon-separated fields are
/// counted by the caller's `unparsed_lines`, never dropped silently.
pub fn parse_passwd(bytes: &[u8]) -> (Vec<PasswdEntry>, usize) {
    let mut out = Vec::new();
    let mut unparsed = 0usize;
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 {
            unparsed += 1;
            continue;
        }
        let (Ok(uid), Ok(gid)) = (fields[2].parse::<u32>(), fields[3].parse::<u32>()) else {
            unparsed += 1;
            continue;
        };
        if out.len() >= MAX_ACCOUNTS {
            break;
        }
        out.push(PasswdEntry {
            name: fields[0].to_string(),
            uid,
            gid,
            gecos: fields[4].to_string(),
            home: fields[5].to_string(),
            shell: fields[6].to_string(),
        });
    }
    (out, unparsed)
}

/// Is this account a person's, rather than a service's?
///
/// The convention every mainstream distribution follows is uid 0 for root and
/// uid >= 1000 for people, with `nobody` at 65534. The rule is a convention, so
/// the record carries every account and only *marks* these; nothing is hidden.
pub fn is_login_account(entry: &PasswdEntry) -> bool {
    (entry.uid == 0 || entry.uid >= 1000) && entry.uid != 65534
}

/// The facts read out of `os-release`, in the order a summary presents them.
const OS_RELEASE_FACTS: &[(&str, &[&str])] = &[
    ("os_name", &["NAME"]),
    ("os_version", &["VERSION"]),
    ("version_id", &["VERSION_ID"]),
    ("codename", &["VERSION_CODENAME", "UBUNTU_CODENAME"]),
    ("os_id", &["ID"]),
    ("os_like", &["ID_LIKE"]),
    ("pretty_name", &["PRETTY_NAME"]),
    ("build_id", &["BUILD_ID"]),
    ("variant", &["VARIANT"]),
];

/// The same facts as an LSB release file names them.
const LSB_FACTS: &[(&str, &[&str])] = &[
    // `DISTRIB_ID` is the vendor's name for the distribution ("Ubuntu"), which
    // is `os-release`'s `NAME`, not its lower-case `ID` ("ubuntu"). Reading it
    // as the latter reported every Ubuntu machine as two files disagreeing
    // about what it runs.
    ("os_name", &["DISTRIB_ID"]),
    ("version_id", &["DISTRIB_RELEASE"]),
    ("codename", &["DISTRIB_CODENAME"]),
    ("pretty_name", &["DISTRIB_DESCRIPTION"]),
];

fn fact_from(values: &BTreeMap<String, String>, keys: &[&str]) -> Option<(String, String)> {
    for key in keys {
        if let Some(value) = values.get(*key) {
            if !value.is_empty() {
                return Some((value.clone(), (*key).to_string()));
            }
        }
    }
    None
}

/// A single-line identity file's content, if it holds one plausible line.
fn single_line(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().find(|l| !l.trim().is_empty())?.trim();
    if line.len() > 255 || line.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    Some(line.to_string())
}

/// Reads the identity files of a Linux system into host facts.
#[derive(Debug, Default)]
pub struct LinuxHostParser;

impl LinuxHostParser {
    pub fn new() -> Self {
        Self
    }
}

/// What one identity file yielded.
struct Reading {
    facts: serde_json::Map<String, serde_json::Value>,
    sources: serde_json::Map<String, serde_json::Value>,
    extra: serde_json::Map<String, serde_json::Value>,
}

fn read_identity(kind: IdentityFile, bytes: &[u8]) -> Option<Reading> {
    let mut facts = serde_json::Map::new();
    let mut sources = serde_json::Map::new();
    let mut extra = serde_json::Map::new();
    match kind {
        IdentityFile::OsRelease | IdentityFile::LsbRelease => {
            let values = parse_release(bytes);
            let table = if kind == IdentityFile::OsRelease {
                OS_RELEASE_FACTS
            } else {
                LSB_FACTS
            };
            for (fact, keys) in table {
                if let Some((value, key)) = fact_from(&values, keys) {
                    facts.insert((*fact).to_string(), json!(value));
                    sources.insert((*fact).to_string(), json!(key));
                }
            }
            if facts.is_empty() {
                return None;
            }
        }
        IdentityFile::Hostname => {
            let value = single_line(bytes)?;
            facts.insert("host_name".into(), json!(value));
            sources.insert("host_name".into(), json!("file contents"));
        }
        IdentityFile::MachineId => {
            let value = single_line(bytes)?;
            // A machine id is 32 hex characters. Anything else at that path is
            // not one, and claiming it would put an invented identity on the
            // summary.
            if value.len() != 32 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            facts.insert("machine_id".into(), json!(value));
            sources.insert("machine_id".into(), json!("file contents"));
        }
        IdentityFile::Timezone => {
            let value = single_line(bytes)?;
            if !value.contains('/') {
                return None;
            }
            facts.insert("timezone".into(), json!(value));
            sources.insert("timezone".into(), json!("file contents"));
        }
        IdentityFile::Passwd => {
            let (entries, unparsed) = parse_passwd(bytes);
            if entries.is_empty() {
                return None;
            }
            let logins: Vec<serde_json::Value> = entries
                .iter()
                .filter(|e| is_login_account(e))
                .map(|e| {
                    json!(format!(
                        "{} (uid {}, {}, {})",
                        e.name, e.uid, e.home, e.shell
                    ))
                })
                .collect();
            if logins.is_empty() {
                return None;
            }
            facts.insert("user_account".into(), json!(logins));
            sources.insert("user_account".into(), json!("passwd entry"));
            extra.insert("accounts_read".into(), json!(entries.len()));
            extra.insert("unparsed_lines".into(), json!(unparsed));
        }
    }
    Some(Reading {
        facts,
        sources,
        extra,
    })
}

fn source_kind(kind: IdentityFile) -> &'static str {
    match kind {
        IdentityFile::OsRelease => "os_release",
        IdentityFile::LsbRelease => "lsb_release",
        IdentityFile::Hostname => "hostname",
        IdentityFile::MachineId => "machine_id",
        IdentityFile::Timezone => "timezone",
        IdentityFile::Passwd => "passwd",
    }
}

fn title(kind: IdentityFile) -> &'static str {
    match kind {
        IdentityFile::OsRelease => "Linux host facts from os-release",
        IdentityFile::LsbRelease => "Linux host facts from lsb-release",
        IdentityFile::Hostname => "Linux host name",
        IdentityFile::MachineId => "Linux machine id",
        IdentityFile::Timezone => "Linux system time zone",
        IdentityFile::Passwd => "Linux accounts from passwd",
    }
}

/// The record for an identity file that was acquired only in part.
///
/// Its path says it carries the host's identity and its bytes could not confirm
/// it. Saying nothing would leave the host summary silent about the one file
/// that would have filled it in.
fn unread_identity_file(
    artifact: &Artifact,
    kind: IdentityFile,
    path: &str,
    read: usize,
) -> Artifact {
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "HostDeviceInfo",
            "platform": "linux",
            "subtype": "identity_unread",
            "name": format!("{}, not read in full", title(kind)),
            "source_file": path,
            "source_kind": source_kind(kind),
            "facts": {},
            "fact_sources": {},
            CONTENT_INCOMPLETE: true,
            CONTENT_INCOMPLETE_REASON: IncompleteReason::ShortRead.as_str(),
            "content_incomplete_detail": format!(
                "only {read} byte(s) of this file were acquired, and nothing in them states \
                 this host's identity, so whether it does could not be established from what \
                 is here"
            ),
        }),
    )
    .with_parent(artifact.id)
}

impl ForensicsModule for LinuxHostParser {
    fn id(&self) -> &str {
        "plugin.linux.host_facts"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .or_else(|| artifact.metadata.get("name").and_then(|v| v.as_str()))
            .unwrap_or("");
        let Some(kind) = identity_file(path) else {
            return Ok(Vec::new());
        };
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let size = data.size() as usize;
        let want = size.min(MAX_IDENTITY_BYTES);
        let mut buf = vec![0u8; want];
        let read = data
            .read_at(0, &mut buf)
            .map_err(|e| ModuleError::ParsingError(format!("reading {path}: {e}")))?;
        buf.truncate(read);
        let truncated = size > MAX_IDENTITY_BYTES || read < want;

        let Some(reading) = read_identity(kind, &buf) else {
            if truncated {
                return Ok(vec![unread_identity_file(artifact, kind, path, read)]);
            }
            debug!("{path} does not state a Linux host fact; not claiming it");
            return Ok(Vec::new());
        };

        let mut metadata = json!({
            "type": "HostDeviceInfo",
            "platform": "linux",
            "name": title(kind),
            "source_file": path,
            "source_kind": source_kind(kind),
            "facts": reading.facts,
            // Which key each fact was read from. `VERSION_ID` and
            // `DISTRIB_RELEASE` are different statements by different files and
            // an examiner quoting one has to be able to say which.
            "fact_sources": reading.sources,
        });
        {
            let object = metadata.as_object_mut().expect("object literal");
            for (key, value) in reading.extra {
                object.insert(key, value);
            }
            if truncated {
                object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
                object.insert(
                    CONTENT_INCOMPLETE_REASON.to_string(),
                    json!(IncompleteReason::ShortRead.as_str()),
                );
                object.insert(
                    "content_incomplete_detail".to_string(),
                    json!(format!(
                        "only the first {read} byte(s) of this file were read, so anything \
                         after that point is not in this record"
                    )),
                );
            }
        }

        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(artifact.id)])
    }
}

#[cfg(test)]
#[path = "tests_linux.rs"]
mod tests;
