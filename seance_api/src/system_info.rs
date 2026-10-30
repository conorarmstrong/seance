//! Consolidate scattered Windows registry facts into one "System Info" summary
//! (§2.6). The registry plugin already parses the raw keys into `RegistryHive`
//! records (each carrying an `all_values` array of `{key_path, value_name,
//! value_data}`) and `UsbDevice` records; this is the compilation over them.
//!
//! Extraction is pure and unit-tested here; the HTTP handler only fetches the
//! records and calls [`extract_system_info`].

use serde_json::{json, Value};
use std::collections::BTreeSet;

/// `(key_path, value_name, value_data)` of one `all_values` entry.
fn entry_parts(v: &Value) -> Option<(&str, &str, &str)> {
    Some((
        v.get("key_path")?.as_str()?,
        v.get("value_name")?.as_str()?,
        v.get("value_data")?.as_str()?,
    ))
}

/// The `controlsetNNN` component of a key path, lower-cased, if it has one.
///
/// A SYSTEM hive holds several control sets: the one Windows booted from plus
/// the previous configuration(s). Only `Select\Current` says which is live, so
/// the component alone is not authority — it is the label the resolution below
/// compares against.
fn control_set_of(key_path: &str) -> Option<String> {
    let lc = key_path.to_ascii_lowercase();
    let idx = lc.find("controlset")?;
    let digits: String = lc[idx + "controlset".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        return None;
    }
    Some(format!("controlset{digits}"))
}

/// One hive record's values, with the control set that hive says is current.
struct HiveValues<'a> {
    /// How this hive is named to the examiner when hives disagree.
    label: String,
    /// `SYSTEM`, `SOFTWARE`, … as the parser named it.
    hive_type: String,
    /// `live`, `regback` or `unknown`, as the parser judged from the path.
    /// A RegBack copy is the same machine at an earlier time, not a second
    /// witness, and is weighed accordingly (HUNT-062).
    role: String,
    entries: Vec<&'a Value>,
    /// `controlsetNNN` from this hive's `Select\Current`, lower-cased. `None`
    /// when the hive carries no resolvable `Select\Current` — which is normal
    /// for SOFTWARE/NTUSER and is a gap, not a licence to guess, for SYSTEM.
    current_control_set: Option<String>,
}

/// The outcome of looking one field up inside a single hive.
struct FieldLookup {
    value: Option<String>,
    /// What the examiner needs told when the lookup could not answer cleanly.
    note: Option<String>,
}

impl<'a> HiveValues<'a> {
    fn new(label: String, hive_type: String, role: String, entries: Vec<&'a Value>) -> Self {
        let current_control_set = Self::resolve_select_current(&entries);
        Self {
            label,
            hive_type,
            role,
            entries,
            current_control_set,
        }
    }

    fn is_backup(&self) -> bool {
        self.role == "regback"
    }

    /// `SYSTEM\Select\Current` → `controlsetNNN`.
    ///
    /// The value is rendered by the registry plugin as `"0x00000001 (1)"`; a
    /// bare decimal is accepted too. Anything else resolves to `None` rather
    /// than a guessed control set.
    fn resolve_select_current(entries: &[&'a Value]) -> Option<String> {
        entries.iter().find_map(|v| {
            let (kp, vn, data) = entry_parts(v)?;
            if !vn.eq_ignore_ascii_case("Current") {
                return None;
            }
            let kp_lc = kp.to_ascii_lowercase();
            // The `Select` key itself, not some other key with "select" in it.
            if !(kp_lc.ends_with("\\select") || kp_lc == "select") {
                return None;
            }
            let n = dword_decimal(data).or_else(|| data.trim().parse::<i64>().ok())?;
            if !(1..=999).contains(&n) {
                return None;
            }
            Some(format!("controlset{n:03}"))
        })
    }

    /// Every `(value_data, control_set)` in this hive whose key is the one
    /// asked for and which carries the named value.
    ///
    /// `key_suffix` matches the **end** of the key path, on a component
    /// boundary — not any position in it. Windows puts the machine-identity
    /// values in named leaf keys, and a descendant of one of those keys is a
    /// different key describing something else. Matching anywhere read them as
    /// the same key: `Windows NT\CurrentVersion` also matched
    /// `Windows NT\CurrentVersion\NtVdm64\ACMSETUP12`, whose `ProductName` is
    /// "Microsoft Setup for Windows", so a domain controller that plainly says
    /// `ProductName = Windows Server 2012 R2 Standard Evaluation` reported its
    /// OS as unknown with a note that the hive disagreed with itself
    /// (HUNT-055). A false absence on the machine-identity screen is the same
    /// class of error as a wrong answer, and this one hid a value that was
    /// right there.
    fn matches(&self, key_suffix: &str, value_name: &str) -> Vec<(&'a str, Option<String>)> {
        let key_lc = key_suffix.to_ascii_lowercase();
        self.entries
            .iter()
            .filter_map(|v| {
                let v: &'a Value = v;
                let (kp, vn, data) = entry_parts(v)?;
                if !vn.eq_ignore_ascii_case(value_name) {
                    return None;
                }
                let kp_lc = kp.to_ascii_lowercase();
                // The whole path, or a path ending in `\<suffix>`. The boundary
                // check keeps `…\MyCurrentVersion` from passing as
                // `…\CurrentVersion`.
                let ends_here = kp_lc == key_lc
                    || (kp_lc.ends_with(&key_lc)
                        && kp_lc.as_bytes()[kp_lc.len() - key_lc.len() - 1] == b'\\');
                if !ends_here {
                    return None;
                }
                // The 32-bit view of a 64-bit machine's registry is a
                // redirected MIRROR of the native key, not a second opinion
                // about it. `Wow6432Node\Microsoft\Windows NT\CurrentVersion`
                // ends in the same key name, and on both DFIR Madness machines
                // its `InstallDate` is 0 while the native key holds the real
                // one — so the resolver saw a disagreement, refused to pick, and
                // suppressed a date that was right there. The competing value
                // was a Unix epoch of zero: 1970-01-01, the shape of wrong
                // answer that is worst to publish (HUNT-059).
                if kp_lc.contains("\\wow6432node\\") {
                    return None;
                }
                // A blank value is Windows saying the setting was never filled
                // in, so it is an absence, not an answer. Rendered as a value it
                // put an empty "Last logon" row on the domain controller's
                // System Info page, which reads as a recorded fact with nothing
                // in it rather than as nothing recorded (HUNT-057).
                if data.trim().is_empty() {
                    return None;
                }
                Some((data, control_set_of(kp)))
            })
            .collect()
    }

    /// This hive's answer for one field, scoped to the control set the hive
    /// says is current.
    ///
    /// The rules, in order:
    /// 1. a match inside the current control set wins;
    /// 2. a match that lives under NO control set (SOFTWARE-style paths) is
    ///    used when every such match agrees;
    /// 3. a match that exists only in a NON-current control set is NOT returned
    ///    — it describes a configuration the machine was not running — but it is
    ///    reported as a note, because "we found it in ControlSet002" and "it is
    ///    not in this hive" are different findings;
    /// 4. disagreeing matches with no `Select\Current` to arbitrate return
    ///    nothing plus a note; a silent first-wins pick is the defect this
    ///    replaces (B3-017).
    fn lookup(&self, key_suffix: &str, value_name: &str) -> FieldLookup {
        let matches = self.matches(key_suffix, value_name);
        if matches.is_empty() {
            return FieldLookup {
                value: None,
                note: None,
            };
        }

        if let Some(current) = &self.current_control_set {
            let in_current: BTreeSet<&str> = matches
                .iter()
                .filter(|(_, cs)| cs.as_deref() == Some(current.as_str()))
                .map(|(d, _)| *d)
                .collect();
            if in_current.len() == 1 {
                return FieldLookup {
                    value: in_current.iter().next().map(|s| s.to_string()),
                    note: None,
                };
            }
            if in_current.len() > 1 {
                return FieldLookup {
                    value: None,
                    note: Some(format!(
                        "{}: {value_name} appears more than once inside the current control set \
                         ({current}) with different data; no single value can be attributed",
                        self.label
                    )),
                };
            }
            // Nothing in the current control set. Values that live outside any
            // control set are still usable; values in another control set are
            // not current and are reported rather than presented.
            let outside: BTreeSet<&str> = matches
                .iter()
                .filter(|(_, cs)| cs.is_none())
                .map(|(d, _)| *d)
                .collect();
            if outside.len() == 1 {
                return FieldLookup {
                    value: outside.iter().next().map(|s| s.to_string()),
                    note: None,
                };
            }
            let other_sets: BTreeSet<String> = matches
                .iter()
                .filter_map(|(_, cs)| cs.clone())
                .filter(|cs| cs != current)
                .collect();
            if !other_sets.is_empty() {
                return FieldLookup {
                    value: None,
                    note: Some(format!(
                        "{}: {value_name} is present only in non-current control set(s) {} — the \
                         current set per Select\\Current is {current}, so the value is not the \
                         configuration this machine was running",
                        self.label,
                        other_sets.into_iter().collect::<Vec<_>>().join(", ")
                    )),
                };
            }
            return FieldLookup {
                value: None,
                note: Some(format!(
                    "{}: {value_name} appears with conflicting data outside any control set",
                    self.label
                )),
            };
        }

        // No `Select\Current` in this hive. Unambiguous data is still usable;
        // data spread across control sets is not, because nothing here says
        // which set the machine booted.
        let distinct: BTreeSet<&str> = matches.iter().map(|(d, _)| *d).collect();
        if distinct.len() == 1 {
            return FieldLookup {
                value: distinct.iter().next().map(|s| s.to_string()),
                note: None,
            };
        }
        let sets: Vec<String> = matches
            .iter()
            .filter_map(|(_, cs)| cs.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        FieldLookup {
            value: None,
            note: Some(format!(
                "{}: {value_name} differs between {} and this hive has no readable \
                 Select\\Current to say which is the running configuration",
                self.label,
                if sets.is_empty() {
                    "several keys".to_string()
                } else {
                    sets.join(", ")
                }
            )),
        }
    }
}

/// The record of how one field was resolved, accumulated while building the
/// summary.
#[derive(Default)]
struct Provenance {
    notes: Vec<String>,
    conflicts: Vec<Value>,
}

/// Resolve one field across every hive in the case.
///
/// A case can hold several SYSTEM hives — one per imaged machine, or a live
/// hive plus a VSS copy. Taking the first match makes one machine's computer
/// name, timezone or shutdown time the answer for the whole case, which in a
/// multi-image case attributes one machine's identity to another. When the
/// hives disagree this returns `None` and files the disagreement, so the
/// summary shows "not determined" with the competing values beside it rather
/// than an authoritative-looking wrong one (B3-017).
fn resolve_field(
    hives: &[HiveValues<'_>],
    field: &str,
    key_suffix: &str,
    value_name: &str,
    prov: &mut Provenance,
) -> Option<String> {
    let mut answers: Vec<(String, String)> = Vec::new(); // (hive label, value)
    let mut backup_answers: Vec<(&HiveValues<'_>, String)> = Vec::new();
    for hive in hives {
        let found = hive.lookup(key_suffix, value_name);
        if let Some(note) = found.note {
            if !prov.notes.contains(&note) {
                prov.notes.push(note);
            }
        }
        if let Some(value) = found.value {
            if hive.is_backup() {
                backup_answers.push((hive, value));
            } else {
                answers.push((hive.label.clone(), value));
            }
        }
    }
    // A RegBack copy is the same machine at an earlier time. Where a live
    // hive of the same type answered, the backup's answer is an earlier state
    // of the same fact — recorded as a note when it differs, never as a
    // contradicting witness. Only when no live hive of that type answered does
    // the backup answer for it, and then it says so. On the NIST Data Leakage
    // image the live SYSTEM's last shutdown was refused because the RegBack
    // copy, a day older, disagreed with it (HUNT-062).
    for (backup, value) in backup_answers {
        let live_of_same_type = hives.iter().any(|h| {
            !h.is_backup()
                && h.hive_type == backup.hive_type
                && h.lookup(key_suffix, value_name).value.is_some()
        });
        if live_of_same_type {
            let disagrees = !answers.iter().any(|(_, v)| *v == value);
            if disagrees {
                let note = format!(
                    "{}: the RegBack copy holds {value_name} = {value:?}, an earlier state of the \
                     same machine; the live hive's value is reported",
                    backup.label
                );
                if !prov.notes.contains(&note) {
                    prov.notes.push(note);
                }
            }
        } else {
            let note = format!(
                "{}: {value_name} is reported from the RegBack copy because no live {} hive \
                 in this case carries it; it is the state at the last backup, not at acquisition",
                backup.label, backup.hive_type
            );
            if !prov.notes.contains(&note) {
                prov.notes.push(note);
            }
            answers.push((backup.label.clone(), value));
        }
    }
    let distinct: BTreeSet<&str> = answers.iter().map(|(_, v)| v.as_str()).collect();
    match distinct.len() {
        0 => None,
        1 => answers.into_iter().next().map(|(_, v)| v),
        _ => {
            prov.conflicts.push(json!({
                "field": field,
                "value_name": value_name,
                "values": answers
                    .iter()
                    .map(|(label, v)| json!({ "hive": label, "value": v }))
                    .collect::<Vec<_>>(),
                "detail": format!(
                    "{} hives in this case report different {field} values; this summary reports \
                     none of them as the answer, because attributing one machine's identity to \
                     another would be a court-facing error",
                    answers.len()
                ),
            }));
            None
        }
    }
}

/// The final path component of a Windows path (`C:\Users\alice` -> `alice`).
fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The decimal a DWORD/QWORD display string carries: `"0x60b5... (1622505600)"`
/// -> `1622505600`. The registry plugin renders integers this way.
fn dword_decimal(s: &str) -> Option<i64> {
    let start = s.find('(')? + 1;
    let end = s[start..].find(')')? + start;
    s[start..end].trim().parse::<i64>().ok()
}

/// RFC3339 for a Unix-seconds value (e.g. a decoded `InstallDate` DWORD).
fn unix_to_rfc3339(secs: i64) -> Option<String> {
    if secs <= 0 {
        return None;
    }
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.to_rfc3339())
}

/// Decode a REG_BINARY FILETIME rendered by the registry plugin as
/// space-separated little-endian hex bytes (`"a1 b2 .. h8"`) -> RFC3339.
fn filetime_from_hex(s: &str) -> Option<String> {
    let bytes: Vec<u8> = s
        .split_whitespace()
        .map(|h| u8::from_str_radix(h, 16))
        .collect::<Result<_, _>>()
        .ok()?;
    if bytes.len() < 8 {
        return None;
    }
    let ft = u64::from_le_bytes(bytes[..8].try_into().ok()?);
    seance_core::time::filetime_to_rfc3339(ft)
}

/// Build the consolidated System Info object from the case's `RegistryHive`
/// records (`hives`, each the record's metadata) and `UsbDevice` records (`usb`).
///
/// Every field is best-effort: absent registry data yields `null`, never a
/// fabricated value. Two rules keep the machine identity honest:
///
/// - values under a SYSTEM hive's control sets are read from the set that
///   hive's `Select\Current` names, so a computer name or timezone left over in
///   `ControlSet002` is never presented as the running configuration; and
/// - each hive is resolved on its own, and a field the hives disagree about is
///   reported as `null` with the competing values in `identity_conflicts`.
///
/// What an examiner learns: the identity of THE machine this evidence came
/// from. A wrong answer — one image's computer name shown for another's, or a
/// stale control set's timezone used to place an event in local time — is a
/// court-facing error, so an unresolvable field says so instead of picking.
///
/// `unparsed` carries the case's `RegistryHiveUnparsed` records. A machine whose
/// hives were all refused produced exactly the same empty page as a machine with
/// no registry at all (`HUNT-054`), so the hives that could not be read are
/// named here with the reader's reason. An empty list means every hive the case
/// holds was parsed — not that nobody looked.
pub fn extract_system_info(
    hives: &[Value],
    usb: &[Value],
    unparsed: &[Value],
    accounts_detail: &[Value],
) -> Value {
    // Keep the hives separate: flattening them is what let one machine's
    // identity answer for another (B3-017).
    let views: Vec<HiveValues<'_>> = hives
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let hive_type = h
                .get("hive_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown hive");
            let entries: Vec<&Value> = h
                .get("all_values")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().collect())
                .unwrap_or_default();
            let role = h
                .get("hive_role")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            // Named by where it came from when that is known: "SYSTEM #21" tells
            // an examiner nothing about which of three SYSTEM hives it is.
            let label = match h.get("source_path").and_then(|v| v.as_str()) {
                Some(p) if !p.is_empty() => format!("{hive_type} ({p})"),
                _ => format!("{hive_type} #{}", i + 1),
            };
            HiveValues::new(label, hive_type.to_string(), role, entries)
        })
        .collect();

    let mut prov = Provenance::default();
    let mut find =
        |field: &str, kc: &str, vn: &str| resolve_field(&views, field, kc, vn, &mut prov);

    // OS identity — SOFTWARE\Microsoft\Windows NT\CurrentVersion.
    let os = json!({
        "product_name": find("os.product_name", "Windows NT\\CurrentVersion", "ProductName"),
        "release_id": find("os.release_id", "Windows NT\\CurrentVersion", "DisplayVersion")
            .or_else(|| find("os.release_id", "Windows NT\\CurrentVersion", "ReleaseId")),
        "current_version": find("os.current_version", "Windows NT\\CurrentVersion", "CurrentVersion"),
        "build": find("os.build", "Windows NT\\CurrentVersion", "CurrentBuildNumber")
            .or_else(|| find("os.build", "Windows NT\\CurrentVersion", "CurrentBuild")),
        "registered_owner": find("os.registered_owner", "Windows NT\\CurrentVersion", "RegisteredOwner"),
        "registered_organization":
            find("os.registered_organization", "Windows NT\\CurrentVersion", "RegisteredOrganization"),
        // InstallDate is a DWORD of Unix seconds; decode to a wall-clock string
        // rather than surfacing the raw "0x.. (n)" display value.
        "install_date": find("os.install_date", "Windows NT\\CurrentVersion", "InstallDate")
            .and_then(|s| dword_decimal(&s))
            .and_then(unix_to_rfc3339),
    });

    // Machine identity — SYSTEM hive, current control set only.
    let computer_name = find(
        "computer_name",
        "ComputerName\\ComputerName",
        "ComputerName",
    );
    let timezone = find("timezone", "TimeZoneInformation", "TimeZoneKeyName")
        .or_else(|| find("timezone", "TimeZoneInformation", "StandardName"));
    // ShutdownTime is a REG_BINARY FILETIME; decode the hex bytes to a timestamp.
    let last_shutdown = find("last_shutdown", "Control\\Windows", "ShutdownTime")
        .and_then(|s| filetime_from_hex(&s));
    // Winlogon's last interactive logon and the domain it authenticated
    // against (`LIVE-029`). Both are single-valued machine identity, so they go
    // through the same resolution as the computer name: a hive that disagrees
    // is a conflict, never a coin toss.
    //
    // `DefaultUserName` is what Winlogon pre-fills at the next logon, which is
    // the last account to log on interactively — not proof of who was at the
    // keyboard, and the screen says so.
    let last_logon_user = find(
        "last_logon_user",
        "Windows NT\\CurrentVersion\\Winlogon",
        "DefaultUserName",
    );
    let logon_domain = find(
        "logon_domain",
        "Windows NT\\CurrentVersion\\Winlogon",
        "DefaultDomainName",
    );
    // The network's own name for the machine's domain or workgroup, from the
    // TCP/IP parameters in the running control set.
    let network_domain = find("network_domain", "Tcpip\\Parameters", "Domain")
        .or_else(|| find("network_domain", "Tcpip\\Parameters", "NV Domain"));

    // User accounts — SOFTWARE ProfileList (SID -> profile path -> username).
    // This is a union over every hive: a profile list is an inventory, not a
    // single-valued identity, so hives add to it rather than contradict one
    // another. `profile_source_hives` records how many contributed, so a case
    // holding two machines' hives does not read as one machine's user list.
    let mut users: Vec<String> = Vec::new();
    let mut user_hives = 0usize;
    for view in &views {
        let mut from_this: Vec<String> = view
            .entries
            .iter()
            .filter_map(|v| {
                let (kp, vn, data) = entry_parts(v)?;
                (vn.eq_ignore_ascii_case("ProfileImagePath")
                    && kp.to_ascii_lowercase().contains("profilelist"))
                .then(|| basename(data).to_string())
            })
            .collect();
        if !from_this.is_empty() {
            user_hives += 1;
        }
        users.append(&mut from_this);
    }
    users.sort();
    users.dedup();

    // Local accounts — SAM\Domains\Account\Users\Names\<account>.
    //
    // A profile list and an account list are different populations and were
    // being shown as one (`LIVE-029`): a machine with five SAM accounts
    // reported "4 user accounts" because only four had ever logged on and
    // received a profile directory. Under-reporting an account inventory loses
    // evidence, so both are carried, separately labelled.
    //
    // The names are the KEY components, not values: SAM stores each account as
    // a subkey whose name is the account name, so this reads the key path. Like
    // the profile list it is an inventory and unions across hives.
    const SAM_USERS_PREFIX: &str = "sam\\domains\\account\\users\\names\\";
    let mut accounts: Vec<String> = Vec::new();
    let mut account_hives = 0usize;
    for view in &views {
        let mut from_this: Vec<String> = view
            .entries
            .iter()
            .filter_map(|v| {
                let (kp, _, _) = entry_parts(v)?;
                let lc = kp.to_ascii_lowercase();
                let idx = lc.find(SAM_USERS_PREFIX)? + SAM_USERS_PREFIX.len();
                let name = kp[idx..].trim_matches('\\');
                // Only the immediate child: `...\Names\Administrator` is an
                // account, anything deeper is not.
                (!name.is_empty() && !name.contains('\\')).then(|| name.to_string())
            })
            .collect();
        if !from_this.is_empty() {
            account_hives += 1;
        }
        accounts.append(&mut from_this);
    }
    accounts.sort();
    accounts.dedup();

    // The per-account detail from the SAM `F` and `V` values (ROADMAP §2.6).
    // A DIFFERENT population from the names above: the name index is every
    // account SAM knows, and a `LocalAccount` record exists only where the
    // walk reached the account's own key. Reporting one count would make the
    // other read as a loss, so both are reported and the difference is said.
    let local_accounts: Vec<Value> = accounts_detail.to_vec();
    let named_only = accounts.len().saturating_sub(local_accounts.len());
    let local_accounts_note = (!local_accounts.is_empty() || !accounts.is_empty())
        .then(|| {
            format!(
                "{} account(s) are in this machine's SAM name index and {} of them have their \
                 own account key read, which is what carries the RID, the last logon and whether \
                 the account is enabled.{}",
                accounts.len(),
                local_accounts.len(),
                if named_only > 0 && !local_accounts.is_empty() {
                    format!(
                        " The other {named_only} are named in the index and their detail was not \
                         read here -- that is this build's reach, not an absence in the account."
                    )
                } else {
                    String::new()
                }
            )
        })
        .filter(|_| !local_accounts.is_empty() || !accounts.is_empty());

    json!({
        "os": os,
        "computer_name": computer_name,
        "timezone": timezone,
        "last_shutdown": last_shutdown,
        "last_logon_user": last_logon_user,
        "logon_domain": logon_domain,
        "network_domain": network_domain,
        "users": users,
        "profile_source_hives": user_hives,
        "sam_accounts": accounts,
        "sam_source_hives": account_hives,
        "local_accounts": local_accounts,
        "local_accounts_note": local_accounts_note,
        "usb_devices": usb,
        "hive_count": hives.len(),
        // Hives the case holds and could not read. Without this, "this machine
        // has no registry" and "its registry would not parse" render alike.
        "unparsed_hives": unparsed
            .iter()
            .map(|u| json!({
                "hive": u.get("hive_type").and_then(|v| v.as_str()).unwrap_or("unknown hive"),
                "error": u.get("parse_error").and_then(|v| v.as_str()),
                "hive_dirty": u.get("hive_dirty").and_then(|v| v.as_bool()),
                "replay_reason": u.get("replay_reason").and_then(|v| v.as_str()),
            }))
            .collect::<Vec<_>>(),
        // Which control set each hive says was running, so the reader can see
        // the scoping that produced the fields above.
        "control_sets": views
            .iter()
            .filter_map(|v| v.current_control_set.as_ref().map(|cs| json!({
                "hive": v.label,
                "current_control_set": cs,
            })))
            .collect::<Vec<_>>(),
        // Non-empty means a field above is null BECAUSE the evidence disagrees,
        // not because the data was absent. The two must never look alike.
        "identity_conflicts": prov.conflicts,
        "identity_notes": prov.notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val(key_path: &str, name: &str, data: &str) -> Value {
        json!({ "key_path": key_path, "value_name": name, "value_data": data })
    }

    /// A key with no value of its own, which is how SAM records an account: the
    /// account name IS the subkey name.
    fn key(key_path: &str) -> Value {
        json!({ "key_path": key_path, "value_name": "", "value_data": "" })
    }

    /// HUNT-055. The machine-identity values live in named leaf keys, and a
    /// descendant of one of those keys is a different key about something else.
    /// The container was matched anywhere in the path, so
    /// `Windows NT\CurrentVersion\NtVdm64\ACMSETUP12` — a 16-bit-setup
    /// compatibility entry shipped with Windows, whose `ProductName` is
    /// "Microsoft Setup for Windows" — answered for the OS. On the DFIR Madness
    /// domain controller nine such keys disagreed with the real one, so the OS
    /// read as unknown on a hive that plainly names it.
    ///
    /// Against the unfixed code `product_name` is null and a note claims the
    /// hive disagrees with itself.
    #[test]
    fn a_descendant_key_does_not_answer_for_the_key_that_was_asked_for() {
        let software = json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "all_values": [
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName",
                    "Windows Server 2012 R2 Standard Evaluation"),
                // The exact shapes off that machine.
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NtVdm64\\ACMSETUP12",
                    "ProductName", "Microsoft Setup for Windows"),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NtVdm64\\INSTALLSHIELD5",
                    "ProductName", "InstallShield*"),
                // A key whose name merely ENDS in the same word is not it either.
                val("SOFTWARE\\Vendor\\MyCurrentVersion", "ProductName", "Something Else"),
            ],
        });
        let info = extract_system_info(&[software], &[], &[], &[]);
        assert_eq!(
            info["os"]["product_name"],
            "Windows Server 2012 R2 Standard Evaluation"
        );
        assert_eq!(
            info["identity_notes"],
            json!([]),
            "the hive does not disagree with itself; only the matcher did"
        );
        assert_eq!(info["identity_conflicts"], json!([]));
    }

    /// HUNT-059. On a 64-bit machine the registry has a second, redirected view
    /// of the same logical key for 32-bit callers. It is a mirror, not a second
    /// opinion — but it ends in the same key name, so it read as one. On both
    /// DFIR Madness machines the mirror's `InstallDate` is 0 while the native
    /// key holds the real one, so the resolver saw a disagreement, refused to
    /// pick, and suppressed a date that was right there. Had it picked the
    /// other way it would have published 1970-01-01 as the install date.
    ///
    /// Against the unfixed code `install_date` is null and a note claims the
    /// hive disagrees with itself.
    #[test]
    fn the_wow64_mirror_of_a_key_is_not_a_second_opinion_about_it() {
        let software = json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "all_values": [
                // 2020-09-17T16:43:59Z, as the plugin renders a DWORD.
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate",
                    "0x5f63924f (1600361039)"),
                val("SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion",
                    "InstallDate", "0x00000000 (0)"),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName",
                    "Windows Server 2012 R2 Standard Evaluation"),
            ],
        });
        let info = extract_system_info(&[software], &[], &[], &[]);
        assert_eq!(
            info["os"]["install_date"], "2020-09-17T16:43:59+00:00",
            "the native key's date, not a refusal and not the mirror's zero"
        );
        assert_eq!(info["identity_notes"], json!([]));
        assert_eq!(info["identity_conflicts"], json!([]));
    }

    /// HUNT-057. `DefaultUserName` is present and empty on a machine nobody has
    /// logged into interactively since the last flush. Rendered as a value it
    /// put an empty "Last logon" row on the page, which reads as a recorded
    /// fact with nothing in it rather than as nothing recorded.
    ///
    /// Against the unfixed code `last_logon_user` is `""`.
    #[test]
    fn a_value_that_is_present_and_blank_is_an_absence_not_an_answer() {
        let software = json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "all_values": [
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    "DefaultUserName", ""),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    "RegisteredOrganization", "   "),
            ],
        });
        let info = extract_system_info(&[software], &[], &[], &[]);
        assert!(
            info["last_logon_user"].is_null(),
            "got {:?}",
            info["last_logon_user"]
        );
        assert!(info["os"]["registered_organization"].is_null());
    }

    #[test]
    fn extracts_os_machine_and_users() {
        let software = json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "all_values": [
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", "Windows 10 Pro"),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber", "19045"),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion", "22H2"),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "RegisteredOwner", "Examiner"),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1", "ProfileImagePath", "C:\\Users\\alice"),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-2", "ProfileImagePath", "C:\\Users\\bob"),
            ],
        });
        let system = json!({
            "type": "RegistryHive",
            "hive_type": "SYSTEM",
            "all_values": [
                val("SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "DESKTOP-ABC"),
                val("SYSTEM\\ControlSet001\\Control\\TimeZoneInformation", "TimeZoneKeyName", "GMT Standard Time"),
            ],
        });
        let usb = vec![json!({ "type": "UsbDevice", "serial": "0123456789" })];

        let info = extract_system_info(&[software, system], &usb, &[], &[]);
        assert_eq!(info["os"]["product_name"], "Windows 10 Pro");
        assert_eq!(info["os"]["build"], "19045");
        assert_eq!(info["os"]["release_id"], "22H2");
        assert_eq!(info["os"]["registered_owner"], "Examiner");
        assert_eq!(info["computer_name"], "DESKTOP-ABC");
        assert_eq!(info["timezone"], "GMT Standard Time");
        assert_eq!(info["users"], json!(["alice", "bob"]));
        assert_eq!(info["usb_devices"].as_array().unwrap().len(), 1);
        assert_eq!(info["hive_count"], 2);
    }

    #[test]
    fn decodes_install_date_dword_and_shutdown_filetime() {
        // InstallDate is a DWORD of Unix seconds, rendered "0x.. (n)".
        // 1_622_505_600 == 2021-06-01T00:00:00Z.
        let install = "0x60b56d80 (1622505600)";
        // ShutdownTime is REG_BINARY FILETIME (LE hex). 2010-01-01T00:00:00Z.
        let ft: u64 = 129_067_776_000_000_000;
        let ft_hex = ft
            .to_le_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let software = json!({
            "type": "RegistryHive",
            "all_values": [
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate", install),
                val("SYSTEM\\ControlSet001\\Control\\Windows", "ShutdownTime", &ft_hex),
            ],
        });
        let info = extract_system_info(&[software], &[], &[], &[]);
        assert!(
            info["os"]["install_date"]
                .as_str()
                .unwrap()
                .starts_with("2021-06-01"),
            "install date should decode to a wall clock, got {:?}",
            info["os"]["install_date"]
        );
        assert!(
            info["last_shutdown"]
                .as_str()
                .unwrap()
                .starts_with("2010-01-01"),
            "shutdown time should decode from FILETIME hex, got {:?}",
            info["last_shutdown"]
        );
    }

    /// HUNT-062. The NIST Data Leakage image holds the live SYSTEM hive and
    /// its RegBack copy from a day earlier. Their `ShutdownTime` differs, as
    /// it must — the backup is the same machine at an earlier time — and the
    /// resolver counted the backup as a second machine, refused the field, and
    /// suppressed the answer the published key gives to the second.
    ///
    /// Against the unfixed code `last_shutdown` is null and a conflict is filed.
    #[test]
    fn a_regback_copy_is_an_earlier_state_of_the_same_machine_not_a_second_witness() {
        // FILETIMEs as the plugin renders REG_BINARY: 2015-03-25T15:31:05Z live,
        // 2015-03-24T21:07:29Z in the backup.
        let live = json!({
            "type": "RegistryHive", "hive_type": "SYSTEM", "hive_role": "live",
            "source_path": "/Windows/System32/config/SYSTEM",
            "all_values": [
                val("SYSTEM\\Select", "Current", "0x00000001 (1)"),
                val("SYSTEM\\ControlSet001\\Control\\Windows", "ShutdownTime", "57 a9 48 b5 10 67 d0 01"),
            ],
        });
        let backup = json!({
            "type": "RegistryHive", "hive_type": "SYSTEM", "hive_role": "regback",
            "source_path": "/Windows/System32/config/RegBack/SYSTEM",
            "all_values": [
                val("SYSTEM\\Select", "Current", "0x00000001 (1)"),
                val("SYSTEM\\ControlSet001\\Control\\Windows", "ShutdownTime", "98 78 5c 89 76 66 d0 01"),
            ],
        });
        let info = extract_system_info(&[backup.clone(), live.clone()], &[], &[], &[]);
        assert_eq!(
            info["last_shutdown"], "2015-03-25T15:31:05.232008700+00:00",
            "the live hive answers; got {:?}",
            info["last_shutdown"]
        );
        assert_eq!(
            info["identity_conflicts"],
            json!([]),
            "a backup is not a conflict"
        );
        let notes = info["identity_notes"].as_array().unwrap();
        assert!(
            notes.iter().any(|n| n.as_str().unwrap().contains("RegBack")
                && n.as_str().unwrap().contains("earlier state")),
            "the backup's value is on the record as an earlier state: {notes:?}"
        );

        // Two LIVE hives that disagree are still two machines.
        let other_machine = json!({
            "type": "RegistryHive", "hive_type": "SYSTEM", "hive_role": "live",
            "source_path": "/Windows/System32/config/SYSTEM",
            "all_values": [
                val("SYSTEM\\Select", "Current", "0x00000001 (1)"),
                val("SYSTEM\\ControlSet001\\Control\\Windows", "ShutdownTime", "98 78 5c 89 76 66 d0 01"),
            ],
        });
        let info = extract_system_info(&[live, other_machine], &[], &[], &[]);
        assert!(info["last_shutdown"].is_null());
        assert_eq!(info["identity_conflicts"].as_array().unwrap().len(), 1);

        // Only a backup: it answers, and the note says the answer is the
        // state at the last backup.
        let info = extract_system_info(&[backup], &[], &[], &[]);
        assert_eq!(info["last_shutdown"], "2015-03-24T21:07:29.045724+00:00");
        assert!(info["identity_notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap().contains("no live SYSTEM hive")));
    }

    #[test]
    fn missing_data_is_null_not_fabricated() {
        let info = extract_system_info(&[], &[], &[], &[]);
        assert!(info["os"]["product_name"].is_null());
        assert!(info["computer_name"].is_null());
        assert_eq!(info["users"], json!([]));
        assert_eq!(info["hive_count"], 0);
        assert_eq!(info["identity_conflicts"], json!([]));
    }

    /// HUNT-054. A domain controller imaged while running produced a System Info
    /// page identical to one for a machine with no registry at all: every field
    /// null, no accounts, no explanation. The hives were there and had been
    /// refused. A blank page and a page that says why must never look alike.
    ///
    /// Against the unfixed code there is no `unparsed_hives` key to read.
    #[test]
    fn hives_the_parser_refused_are_named_rather_than_leaving_the_page_blank() {
        let refused = json!({
            "type": "RegistryHiveUnparsed",
            "hive_type": "SOFTWARE",
            "parse_error": "Failed to parse hive: the base block checksum does not verify",
            "hive_dirty": true,
            "replay_reason": "sequence_gap",
        });
        let info = extract_system_info(&[], &[], &[refused], &[]);

        assert_eq!(info["hive_count"], 0);
        let listed = info["unparsed_hives"].as_array().expect("a list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["hive"], "SOFTWARE");
        assert_eq!(listed[0]["hive_dirty"], true);
        assert_eq!(listed[0]["replay_reason"], "sequence_gap");
        assert!(
            listed[0]["error"]
                .as_str()
                .is_some_and(|e| e.contains("checksum")),
            "the reader's own reason is what tells a corrupt hive from an unflushed one"
        );

        // The counterpart: a case whose hives all parsed says so with an empty
        // list, so the key is never read as "nobody looked".
        assert_eq!(
            extract_system_info(&[], &[], &[], &[])["unparsed_hives"],
            json!([])
        );
    }

    /// B3-017: machine identity was the FIRST matching value in a flattened
    /// pool, so a stale control set could answer for the running one. What an
    /// examiner learns: the configuration the machine was actually running.
    /// `Select\Current` is the only thing that says which set that is.
    #[test]
    fn the_current_control_set_wins_over_a_stale_one() {
        let system = json!({
            "type": "RegistryHive",
            "hive_type": "SYSTEM",
            "all_values": [
                // The stale set is listed FIRST: first-wins would take it.
                val("ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "OLD-NAME"),
                val("ROOT\\ControlSet002\\Control\\ComputerName\\ComputerName", "ComputerName", "LIVE-NAME"),
                val("ROOT\\ControlSet001\\Control\\TimeZoneInformation", "TimeZoneKeyName", "Pacific Standard Time"),
                val("ROOT\\ControlSet002\\Control\\TimeZoneInformation", "TimeZoneKeyName", "GMT Standard Time"),
                val("ROOT\\Select", "Current", "0x00000002 (2)"),
            ],
        });
        let info = extract_system_info(&[system], &[], &[], &[]);
        assert_eq!(info["computer_name"], "LIVE-NAME");
        assert_eq!(info["timezone"], "GMT Standard Time");
        assert_eq!(
            info["control_sets"],
            json!([{ "hive": "SYSTEM #1", "current_control_set": "controlset002" }])
        );
    }

    /// A value surviving only in a non-current control set describes a
    /// configuration the machine was not running. It is not the answer, and it
    /// is not silence either.
    #[test]
    fn a_value_only_in_a_non_current_control_set_is_not_presented_as_current() {
        let system = json!({
            "type": "RegistryHive",
            "hive_type": "SYSTEM",
            "all_values": [
                val("ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "OLD-NAME"),
                val("ROOT\\Select", "Current", "0x00000002 (2)"),
            ],
        });
        let info = extract_system_info(&[system], &[], &[], &[]);
        assert!(
            info["computer_name"].is_null(),
            "a stale control set must not answer for the running machine"
        );
        let notes = info["identity_notes"].as_array().unwrap();
        assert!(
            notes.iter().any(|n| n
                .as_str()
                .unwrap()
                .contains("present only in non-current control set")),
            "the examiner is told the value exists but is not current: {notes:?}"
        );
    }

    /// A case can hold several machines' SYSTEM hives. Picking one silently
    /// attributes one machine's identity to another; the summary must refuse
    /// and show the disagreement.
    #[test]
    fn hives_that_disagree_yield_no_answer_and_a_recorded_conflict() {
        let hive = |name: &str, tz: &str| {
            json!({
                "type": "RegistryHive",
                "hive_type": "SYSTEM",
                "all_values": [
                    val("ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", name),
                    val("ROOT\\ControlSet001\\Control\\TimeZoneInformation", "TimeZoneKeyName", tz),
                    val("ROOT\\Select", "Current", "0x00000001 (1)"),
                ],
            })
        };
        let info = extract_system_info(
            &[
                hive("DESKTOP-ONE", "GMT Standard Time"),
                hive("LAPTOP-TWO", "Pacific Standard Time"),
            ],
            &[],
            &[],
            &[],
        );
        assert!(
            info["computer_name"].is_null(),
            "two machines' names must not collapse into one authoritative answer"
        );
        assert!(info["timezone"].is_null());
        let conflicts = info["identity_conflicts"].as_array().unwrap();
        let names: Vec<&str> = conflicts
            .iter()
            .map(|c| c["field"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"computer_name"), "got {names:?}");
        assert!(names.contains(&"timezone"), "got {names:?}");
        let cn = conflicts
            .iter()
            .find(|c| c["field"] == "computer_name")
            .unwrap();
        let values: Vec<&str> = cn["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["value"].as_str().unwrap())
            .collect();
        assert_eq!(values, vec!["DESKTOP-ONE", "LAPTOP-TWO"]);
        assert_eq!(cn["values"][0]["hive"], "SYSTEM #1");
        assert_eq!(cn["values"][1]["hive"], "SYSTEM #2");
    }

    /// Hives that AGREE are not a conflict: two copies of the same machine's
    /// hive (live plus a VSS snapshot) must still answer.
    #[test]
    fn hives_that_agree_still_produce_an_answer() {
        let hive = json!({
            "type": "RegistryHive",
            "hive_type": "SYSTEM",
            "all_values": [
                val("ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "DESKTOP-ABC"),
                val("ROOT\\Select", "Current", "0x00000001 (1)"),
            ],
        });
        let info = extract_system_info(&[hive.clone(), hive], &[], &[], &[]);
        assert_eq!(info["computer_name"], "DESKTOP-ABC");
        assert_eq!(info["identity_conflicts"], json!([]));
    }

    /// `sam_accounts` is a list of names. A local account has a RID, a last
    /// logon and whether it is enabled, and until `LocalAccount` records
    /// existed none of that reached this page: the roadmap item names exactly
    /// the RID and the last-login time as what was unread.
    ///
    /// The names list stays, because it is the wider population — an account
    /// whose `F` and `V` keys the walk did not reach is in the name index and
    /// has no `LocalAccount` record.
    #[test]
    fn local_accounts_carry_the_rid_and_the_last_logon_and_the_names_list_stays() {
        let hives = vec![json!({
            "hive_type": "SAM",
            "all_values": [
                key("SAM\\SAM\\Domains\\Account\\Users\\Names\\Administrator"),
                key("SAM\\SAM\\Domains\\Account\\Users\\Names\\Guest"),
                key("SAM\\SAM\\Domains\\Account\\Users\\Names\\Preston"),
            ],
        })];
        let accounts = vec![
            json!({
                "type": "LocalAccount",
                "username": "Administrator",
                "rid": 500,
                "last_logon": "2010-11-20T21:48:12.569244+00:00",
                "login_count": 6,
                "account_enabled": false,
            }),
            json!({
                "type": "LocalAccount",
                "username": "Guest",
                "rid": 501,
                "last_logon": null,
                "last_logon_absent_reason":
                    "Not recorded: this field is zero in the account's F value",
                "login_count": 0,
                "account_enabled": false,
            }),
        ];
        let info = extract_system_info(&hives, &[], &[], &accounts);

        // The names list is unchanged: three accounts are in the index.
        assert_eq!(
            info["sam_accounts"],
            json!(["Administrator", "Guest", "Preston"])
        );
        let detail = info["local_accounts"].as_array().expect("the detail list");
        assert_eq!(detail.len(), 2);
        assert_eq!(detail[0]["rid"], json!(500));
        assert_eq!(detail[0]["username"], "Administrator");
        assert_eq!(detail[0]["last_logon"], "2010-11-20T21:48:12.569244+00:00");
        // Guest's absence stays an absence, with its reason, and does not
        // become an empty string that reads as a recorded blank.
        assert!(detail[1]["last_logon"].is_null());
        assert!(detail[1]["last_logon_absent_reason"].is_string());

        // And the page says how the two populations differ, so "3 accounts,
        // 2 with detail" is not read as a parse that lost one.
        let note = info["local_accounts_note"].as_str().unwrap_or("");
        assert!(
            note.contains('3') && note.contains('2'),
            "both counts: {note}"
        );
    }

    /// A case with no SAM detail says nothing about accounts rather than
    /// reporting an empty inventory.
    #[test]
    fn no_local_account_records_yields_no_detail_and_no_note() {
        let info = extract_system_info(&[], &[], &[], &[]);
        assert_eq!(info["local_accounts"], json!([]));
        assert!(
            info["local_accounts_note"].is_null(),
            "with no accounts in either population there is nothing to reconcile"
        );
    }

    /// SAM accounts and profile directories are different populations, and the
    /// screen used to show only the second under the heading "user accounts"
    /// (`LIVE-029`). A machine with five local accounts, four of which had ever
    /// logged on, reported four — under-reporting an inventory on a
    /// court-facing screen.
    #[test]
    fn sam_accounts_are_read_from_the_key_names_and_kept_apart_from_profiles() {
        let hives = vec![json!({
            "hive_type": "SAM",
            "all_values": [
                key("SAM\\SAM\\Domains\\Account\\Users\\Names"),
                key("SAM\\SAM\\Domains\\Account\\Users\\Names\\Administrator"),
                key("SAM\\SAM\\Domains\\Account\\Users\\Names\\Guest"),
                key("SAM\\SAM\\Domains\\Account\\Users\\Names\\Mr. Evil"),
                // Groups and aliases are not user accounts.
                key("SAM\\SAM\\Domains\\Account\\Groups\\Names\\None"),
                key("SAM\\SAM\\Domains\\Account\\Aliases\\Names\\HelpServicesGroup"),
                // Anything below an account is not itself an account.
                key("SAM\\SAM\\Domains\\Account\\Users\\Names\\Guest\\Something"),
            ],
        })];
        let info = extract_system_info(&hives, &[], &[], &[]);
        assert_eq!(
            info["sam_accounts"],
            json!(["Administrator", "Guest", "Mr. Evil"])
        );
        assert_eq!(info["sam_source_hives"], 1);
        // And the profile list stays its own answer.
        assert_eq!(info["users"], json!([]));
    }

    /// Winlogon's pre-filled user and domain, resolved like any other machine
    /// identity field so a second hive that disagrees is a conflict rather than
    /// a guess.
    #[test]
    fn the_last_interactive_logon_and_its_domain_are_reported() {
        let hives = vec![json!({
            "hive_type": "SOFTWARE",
            "all_values": [
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    "DefaultUserName", "Mr. Evil"),
                val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    "DefaultDomainName", "N-1A9ODN6ZXK4LQ"),
            ],
        })];
        let info = extract_system_info(&hives, &[], &[], &[]);
        assert_eq!(info["last_logon_user"], "Mr. Evil");
        assert_eq!(info["logon_domain"], "N-1A9ODN6ZXK4LQ");
    }

    /// An empty TCP/IP domain is absent, not an answer of "".
    #[test]
    fn a_blank_network_domain_reads_as_absent() {
        let hives = vec![json!({
            "hive_type": "SYSTEM",
            "all_values": [
                val("SYSTEM\\ControlSet001\\Select", "Current", "0x1 (1)"),
                val("SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters", "Domain", ""),
            ],
        })];
        let info = extract_system_info(&hives, &[], &[], &[]);
        assert!(
            info["network_domain"].is_null(),
            "{}",
            info["network_domain"]
        );
    }

    /// The profile list is an inventory, so it unions across hives — but the
    /// summary records how many hives contributed, so a two-machine case does
    /// not read as one machine with twice the users.
    #[test]
    fn profile_lists_union_but_report_how_many_hives_contributed() {
        let mk = |user: &str| {
            json!({
                "type": "RegistryHive",
                "hive_type": "SOFTWARE",
                "all_values": [
                    val("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1",
                        "ProfileImagePath", &format!("C:\\Users\\{user}")),
                ],
            })
        };
        let info = extract_system_info(&[mk("alice"), mk("bob")], &[], &[], &[]);
        assert_eq!(info["users"], json!(["alice", "bob"]));
        assert_eq!(info["profile_source_hives"], 2);
    }

    #[test]
    fn select_current_parsing_is_strict() {
        let resolve = |entries: &[Value]| {
            let refs: Vec<&Value> = entries.iter().collect();
            HiveValues::resolve_select_current(&refs)
        };

        let good = [val("ROOT\\Select", "Current", "0x00000003 (3)")];
        assert_eq!(resolve(&good), Some("controlset003".to_string()));

        // A key that merely contains "select" is not the Select key.
        let other = [val("ROOT\\ControlSet001\\SelectedProfile", "Current", "1")];
        assert_eq!(resolve(&other), None);

        // Junk data resolves to nothing rather than a guessed control set.
        let junk = [val("ROOT\\Select", "Current", "not a number")];
        assert_eq!(resolve(&junk), None);
    }

    #[test]
    fn control_set_component_is_recognised() {
        assert_eq!(
            control_set_of("ROOT\\ControlSet001\\Control"),
            Some("controlset001".to_string())
        );
        assert_eq!(control_set_of("SOFTWARE\\Microsoft"), None);
    }
}
