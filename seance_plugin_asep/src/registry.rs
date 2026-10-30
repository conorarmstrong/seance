//! Enumeration of registry-backed autostart extensibility points over an
//! already-parsed hive record.
//!
//! The input is the `RegistryHive` `ParsedRecord` the registry plugin emits: a
//! flat `all_values` array of `{key_path, value_name, value_data, value_type}`.
//! Nothing is re-read from the hive file, so this module cannot see anything
//! the registry parser did not already surface — which is why the coverage
//! record states the value counts it worked from.
//!
//! Matching is by case-insensitive key-path suffix and segment, so one rule
//! covers the `HKLM`- and `HKCU`-rooted spellings, the `Wow6432Node` 32-bit
//! view, every `ControlSet`, and the synthetic root name an offline hive
//! carries. Matching on a literal absolute path would silently miss most of a
//! real machine's autostart entries — the failure this module exists to
//! prevent.

use crate::coverage::HiveScanSummary;
use crate::normalize::{
    basename, ends_with_key, is_under_system_directory, key_lower_into, last_segment,
    multi_sz_elements, normalize_target, parse_dword, segment_after, split_command,
    tail_after_segment,
};
use crate::record::{AsepEntry, LocationKind, ReadStatus};
use crate::rules::HiveKind;
use crate::services::{absorb_value, ServiceMap};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Ceiling on registry values examined per hive. A hive holding more than this
/// stops the scan and sets the coverage record's `scan_capped` flag, so counts
/// are reported as lower bounds rather than as totals.
pub const MAX_VALUES_SCANNED: usize = 2_000_000;

/// Ceiling on entries emitted per hive.
pub const MAX_ENTRIES_PER_HIVE: usize = 50_000;

/// Ceiling on distinct service keys accumulated per hive.
pub const MAX_SERVICE_KEYS: usize = 50_000;

/// Ceiling on COM class registrations remembered for resolving shell
/// extensions and browser helper objects back to a DLL.
pub const MAX_CLSID_REGISTRATIONS: usize = 500_000;

/// Run-key suffixes, matched as whole-segment suffixes so `Wow6432Node` and
/// per-user spellings are covered by the same rule.
const RUN_KEY_SUFFIXES: &[(&str, &str)] = &[
    ("currentversion\\run", "run"),
    ("currentversion\\runonce", "runonce"),
    ("currentversion\\runonceex", "runonceex"),
    ("currentversion\\runservices", "runservices"),
    ("currentversion\\runservicesonce", "runservicesonce"),
    ("policies\\explorer\\run", "policy_run"),
];

/// What the enumeration produced for one hive.
#[derive(Debug)]
pub struct RegistryScanOutput {
    /// Entries in the order they were found.
    pub entries: Vec<AsepEntry>,
    /// Coverage bookkeeping for the hive.
    pub summary: HiveScanSummary,
}

/// Everything the enumeration needs about the hive it is scanning.
pub struct RegistryScanInput<'a> {
    /// Hive name recorded by the registry plugin.
    pub hive_name: &'a str,
    /// Classified hive.
    pub hive_kind: HiveKind,
    /// The hive file's own path, when it was seen during ingest.
    pub hive_path: Option<String>,
    /// Profile the hive belongs to, for per-user hives.
    pub user: Option<String>,
    /// `all_values` from the parsed hive record.
    pub values: &'a [Value],
    /// `total_values` as the registry plugin reported it.
    pub values_total: usize,
    /// `total_keys` as the registry plugin reported it, recorded on the
    /// coverage record so the scale of the hive is visible.
    pub keys_total: usize,
}

struct ComRegistration {
    clsid: String,
    server_kind: &'static str,
    image: String,
    key_path: String,
}

struct ComReference {
    category: &'static str,
    handler_kind: &'static str,
    entry_name: String,
    key_path: String,
    clsid: String,
}

/// Enumerate every autostart location this build knows about in one hive.
pub fn scan(input: &RegistryScanInput) -> RegistryScanOutput {
    let mut summary = HiveScanSummary::new(input.hive_name.to_string(), input.hive_kind);
    summary.hive_path = input.hive_path.clone();
    summary.user = input.user.clone();
    summary.values_total = input.values_total.max(input.values.len());
    summary.keys_total = input.keys_total;

    let mut entries: Vec<AsepEntry> = Vec::new();
    let mut services: ServiceMap = ServiceMap::new();
    let mut clsid_servers: BTreeMap<String, ComRegistration> = BTreeMap::new();
    let mut com_references: Vec<ComReference> = Vec::new();
    let mut pending_appinit: Vec<(String, String, String)> = Vec::new();
    let mut appinit_load_flag: Option<u32> = None;
    let mut system_dir_com_servers: usize = 0;
    let mut service_keys_capped = false;
    let mut clsid_capped = false;

    let scope = input.hive_kind.scope().to_string();
    let mut key_buf = String::new();

    // Bound the pass up front rather than counting inside it, so the number of
    // values examined is a stated fact on the coverage record instead of an
    // inference from where a loop happened to stop.
    let to_scan = input.values.len().min(MAX_VALUES_SCANNED);
    summary.scan_capped = input.values.len() > MAX_VALUES_SCANNED;
    summary.values_scanned = to_scan;

    for value in input.values.iter().take(to_scan) {
        let Some(key_path) = value.get("key_path").and_then(Value::as_str) else {
            continue;
        };
        let value_name = value
            .get("value_name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let value_data = value
            .get("value_data")
            .and_then(Value::as_str)
            .unwrap_or("");

        key_lower_into(key_path, &mut key_buf);
        let k = key_buf.as_str();
        let last = last_segment(k);
        let parent = segment_from_end(k, 1);
        let vn_owned = value_name.to_ascii_lowercase();
        let vn = vn_owned.as_str();

        // The AppInit list is only honoured when LoadAppInit_DLLs is non-zero.
        // The flag can appear before or after the list in the value array, so
        // the list is held back and finished once the whole hive is read.
        if vn == "loadappinit_dlls" {
            appinit_load_flag = parse_dword(value_data);
            continue;
        }

        // --- Winsock provider catalogs (they live under \Services\) ---
        if parent == "catalog_entries" && k.contains("\\winsock2\\parameters\\") {
            push(
                &mut entries,
                &mut summary,
                winsock_entry(key_path, value_name, value_data, &scope, input),
            );
            continue;
        }

        // --- Services and drivers ---
        if matches!(
            vn,
            "start" | "type" | "imagepath" | "displayname" | "objectname"
        ) || matches!(last, "parameters" | "networkprovider")
        {
            if let Some(name) = segment_after(k, "\\services\\") {
                let map_key = service_key(k, name);
                if services.len() < MAX_SERVICE_KEYS || services.contains_key(&map_key) {
                    let tail = tail_after_segment(k, "\\services\\");
                    absorb_value(
                        &mut services,
                        &map_key,
                        original_segment(key_path, k, name),
                        &service_key_path(key_path, k, name),
                        control_set_of(k),
                        tail,
                        value_name,
                        value_data,
                    );
                } else {
                    service_keys_capped = true;
                }
                continue;
            }
        }

        // --- Image File Execution Options ---
        if vn == "debugger" && k.contains("\\image file execution options\\") {
            push(
                &mut entries,
                &mut summary,
                ifeo_entry(k, key_path, value_name, value_data, &scope, input, false),
            );
            continue;
        }
        if vn == "monitorprocess" && k.contains("\\silentprocessexit\\") {
            push(
                &mut entries,
                &mut summary,
                ifeo_entry(k, key_path, value_name, value_data, &scope, input, true),
            );
            continue;
        }

        // --- COM class registrations ---
        if matches!(
            last,
            "inprocserver32" | "localserver32" | "inprochandler32" | "inprocserver"
        ) && (vn == "(default)" || vn.is_empty())
        {
            let image = value_data.trim();
            let clsid = segment_after(k, "\\clsid\\").filter(|_| !image.is_empty());
            if let Some(clsid) = clsid {
                if clsid_servers.len() < MAX_CLSID_REGISTRATIONS {
                    clsid_servers.insert(
                        clsid.to_string(),
                        ComRegistration {
                            clsid: original_segment(key_path, k, clsid).to_string(),
                            server_kind: com_server_kind(last),
                            image: image.to_string(),
                            key_path: key_path.to_string(),
                        },
                    );
                } else {
                    clsid_capped = true;
                }
            }
            continue;
        }

        // --- Installed shim databases (T1546.011) ---
        if let Some(kind) = installed_sdb(k) {
            push(
                &mut entries,
                &mut summary,
                installed_sdb_entry(kind, key_path, value_name, value_data, &scope, input),
            );
            continue;
        }

        // --- Default file associations (T1546.001) ---
        if let Some(kind) = file_association(parent, last) {
            push(
                &mut entries,
                &mut summary,
                file_association_entry(kind, key_path, value_name, value_data, &scope, input),
            );
            continue;
        }

        // --- Shell extensions and browser helper objects (CLSID references) ---
        if let Some((category, handler_kind)) = shell_handler(parent, last) {
            if let Some((clsid, from_value_name)) = clsid_reference(value_data, value_name, last) {
                let entry_name = if from_value_name {
                    value_name.to_string()
                } else {
                    original_segment(key_path, k, last).to_string()
                };
                com_references.push(ComReference {
                    category,
                    handler_kind,
                    entry_name,
                    key_path: key_path.to_string(),
                    clsid,
                });
            }
            continue;
        }

        // --- Winlogon ---
        if last == "winlogon" && ends_with_key(k, "currentversion\\winlogon") {
            if let Some(built) = winlogon_entries(key_path, value_name, value_data, &scope, input) {
                for e in built {
                    push(&mut entries, &mut summary, Some(e));
                }
            }
            continue;
        }
        if vn == "dllname" && k.contains("\\winlogon\\notify\\") {
            push(
                &mut entries,
                &mut summary,
                winlogon_notify_entry(k, key_path, value_name, value_data, &scope, input),
            );
            continue;
        }

        // --- Run keys ---
        if matches!(
            last,
            "run" | "runonce" | "runonceex" | "runservices" | "runservicesonce"
        ) {
            if let Some(kind) = RUN_KEY_SUFFIXES
                .iter()
                .find(|(suffix, _)| ends_with_key(k, suffix))
                .map(|(_, kind)| *kind)
            {
                push(
                    &mut entries,
                    &mut summary,
                    run_key_entry(key_path, value_name, value_data, kind, &scope, input),
                );
                continue;
            }
        }

        // --- Startup folder redirection ---
        if matches!(last, "user shell folders" | "shell folders")
            && matches!(vn, "startup" | "common startup")
        {
            push(
                &mut entries,
                &mut summary,
                shell_folder_entry(key_path, value_name, value_data, &scope, input),
            );
            continue;
        }

        // --- AppInit / AppCert ---
        if vn == "appinit_dlls" && ends_with_key(k, "currentversion\\windows") {
            for dll in split_dll_list(value_data) {
                pending_appinit.push((key_path.to_string(), value_name.to_string(), dll));
            }
            continue;
        }
        if last == "appcertdlls" && k.contains("\\session manager\\") {
            push(
                &mut entries,
                &mut summary,
                simple_entry(
                    "appcert_dlls",
                    value_name,
                    key_path,
                    value_name,
                    value_data,
                    "Loaded into every process at the point it calls CreateProcess.",
                    &scope,
                    input,
                ),
            );
            continue;
        }

        // --- Session Manager execute lists and KnownDLLs ---
        if last == "session manager"
            && matches!(
                vn,
                "bootexecute" | "setupexecute" | "s0initialcommand" | "execute"
            )
        {
            for element in multi_sz_elements(value) {
                push(
                    &mut entries,
                    &mut summary,
                    boot_execute_entry(key_path, value_name, &element, &scope, input),
                );
            }
            continue;
        }
        if last == "knowndlls" && k.contains("\\session manager\\") {
            push(
                &mut entries,
                &mut summary,
                simple_entry(
                    "known_dlls",
                    value_name,
                    key_path,
                    value_name,
                    value_data,
                    "Mapped from the \\KnownDlls object directory at process start for \
                     every process that loads this DLL by name, in place of any copy on \
                     the search path.",
                    &scope,
                    input,
                ),
            );
            continue;
        }

        // --- LSA packages ---
        if matches!(last, "lsa" | "osconfig") && k.contains("\\control\\lsa") {
            let category = match vn {
                "authentication packages" => Some("lsa_authentication_package"),
                "notification packages" => Some("lsa_notification_package"),
                "security packages" => Some("lsa_security_package"),
                _ => None,
            };
            if let Some(category) = category {
                for element in multi_sz_elements(value) {
                    push(
                        &mut entries,
                        &mut summary,
                        lsa_entry(category, key_path, value_name, &element, &scope, input),
                    );
                }
                continue;
            }
        }

        // --- Active Setup ---
        if vn == "stubpath" && k.contains("\\installed components\\") {
            push(
                &mut entries,
                &mut summary,
                active_setup_entry(k, key_path, value_name, value_data, &scope, input),
            );
            continue;
        }

        // --- Print monitors and print processors ---
        if vn == "driver" && k.contains("\\print\\monitors\\") {
            let name = segment_after(k, "\\print\\monitors\\").unwrap_or(last);
            push(
                &mut entries,
                &mut summary,
                simple_entry(
                    "print_monitor",
                    original_segment(key_path, k, name),
                    key_path,
                    value_name,
                    value_data,
                    "Loaded by the print spooler service (spoolsv.exe, running as SYSTEM) \
                     when the spooler starts at boot.",
                    &scope,
                    input,
                ),
            );
            continue;
        }
        if vn == "driver" && k.contains("\\print processors\\") {
            let name = segment_after(k, "\\print processors\\").unwrap_or(last);
            push(
                &mut entries,
                &mut summary,
                simple_entry(
                    "print_processor",
                    original_segment(key_path, k, name),
                    key_path,
                    value_name,
                    value_data,
                    "Loaded by the print spooler service when a print job is processed.",
                    &scope,
                    input,
                ),
            );
            continue;
        }

        // --- netsh helpers ---
        if last == "netsh" && k.contains("\\microsoft\\netsh") {
            push(
                &mut entries,
                &mut summary,
                simple_entry(
                    "netsh_helper",
                    value_name,
                    key_path,
                    value_name,
                    value_data,
                    "Loaded into netsh.exe every time netsh runs.",
                    &scope,
                    input,
                ),
            );
            continue;
        }

        // --- WMI auto-recover MOFs ---
        if last == "cimom" && vn == "autorecover mofs" {
            for element in multi_sz_elements(value) {
                let label = basename(&element).to_string();
                push(
                    &mut entries,
                    &mut summary,
                    simple_entry(
                        "wmi_mof_autorecover",
                        &label,
                        key_path,
                        value_name,
                        &element,
                        "Recompiled into the WMI repository whenever the repository is \
                         rebuilt, restoring whatever classes, event filters and consumers \
                         the MOF defines.",
                        &scope,
                        input,
                    ),
                );
            }
            continue;
        }

        // --- Scheduled task registrations (TaskCache tree) ---
        if vn == "id" && k.contains("\\taskcache\\tree\\") {
            push(
                &mut entries,
                &mut summary,
                Some(task_registration_entry(
                    k, key_path, value_data, &scope, input,
                )),
            );
            continue;
        }
    }

    // AppInit entries, now that the LoadAppInit_DLLs flag has been seen (or
    // definitively not seen) anywhere in the hive.
    for (key_path, value_name, dll) in &pending_appinit {
        push(
            &mut entries,
            &mut summary,
            appinit_entry(key_path, value_name, dll, &scope, input, appinit_load_flag),
        );
    }

    // Services, once every value under each service key has been folded in.
    for (_, acc) in std::mem::take(&mut services) {
        let network_path = acc.network_provider_path.clone();
        let key_path = acc.key_path.clone();
        let name = acc.name.clone();
        let mut entry = acc.into_entry();
        entry.hive = Some(input.hive_name.to_string());
        entry.scope = scope.clone();
        entry.user = input.user.clone();
        push(&mut entries, &mut summary, Some(entry));

        if let Some(path) = network_path {
            let mut np = AsepEntry::new(
                "network_provider",
                name,
                format!("{key_path}\\NetworkProvider"),
                LocationKind::RegistryKey,
            );
            np.value_name = Some("ProviderPath".to_string());
            np.hive = Some(input.hive_name.to_string());
            np.scope = scope.clone();
            np.user = input.user.clone();
            set_command(&mut np, &path);
            np.runs_when = "Loaded by the multi-provider router at logon to handle network \
                            authentication and drive mapping."
                .to_string();
            np.enabled = Some(true);
            np.enabled_basis = "The service registers a network provider path.".to_string();
            np.installed_time_unavailable_reason = Some(crate::KEY_TIME_UNAVAILABLE);
            push(&mut entries, &mut summary, Some(np));
        }
    }

    // COM class registrations. For a machine-wide hive only servers outside the
    // system directories are listed; the in-System32 ones were examined and
    // deliberately excluded, and the exclusion count is reported so the
    // omission is stated rather than silent.
    let per_user_classes = matches!(input.hive_kind, HiveKind::UsrClass | HiveKind::NtUser);
    for reg in clsid_servers.values() {
        // A bare server name's System32 lookup is a search-path convention,
        // not an observed location, so it is never excluded on it (`HUNT-241`).
        let outside = normalize_target(&reg.image)
            .map(|t| !t.search_path_candidates.is_empty() || !is_under_system_directory(&t.lookup))
            .unwrap_or(true);
        if !outside && !per_user_classes {
            system_dir_com_servers = system_dir_com_servers.saturating_add(1);
            continue;
        }
        push(
            &mut entries,
            &mut summary,
            Some(com_entry(reg, per_user_classes, &scope, input)),
        );
    }

    // Shell extensions / BHOs, resolved against the class registrations found
    // in the same hive.
    for reference in &com_references {
        let resolved = clsid_servers.get(&reference.clsid.to_ascii_lowercase());
        push(
            &mut entries,
            &mut summary,
            Some(com_reference_entry(reference, resolved, &scope, input)),
        );
    }

    if service_keys_capped {
        summary.entries_capped = true;
        summary.note(
            "service",
            format!(
                "More than {MAX_SERVICE_KEYS} distinct service keys were present; the \
                 surplus was not accumulated and this count is a lower bound."
            ),
        );
    }
    if clsid_capped {
        summary.note(
            "com_server",
            format!(
                "More than {MAX_CLSID_REGISTRATIONS} COM class registrations were present; \
                 the surplus was not indexed, so some shell extensions may report their \
                 server as unresolved."
            ),
        );
    }
    if system_dir_com_servers > 0 {
        summary.note(
            "com_server",
            format!(
                "{system_dir_com_servers} COM class registrations were examined and \
                 excluded from the listing because their server resolves inside \
                 \\Windows\\System32 or \\Windows\\SysWOW64. Only servers outside those \
                 directories are listed."
            ),
        );
    }

    RegistryScanOutput { entries, summary }
}

// --- entry constructors ------------------------------------------------------

fn push(entries: &mut Vec<AsepEntry>, summary: &mut HiveScanSummary, entry: Option<AsepEntry>) {
    let Some(entry) = entry else { return };
    if entries.len() >= MAX_ENTRIES_PER_HIVE {
        summary.entries_capped = true;
        return;
    }
    summary.count(entry.category);
    entries.push(entry);
}

/// Build an installed-shim-database entry.
///
/// # What it reports and what it will not conclude
///
/// The database's path, description, type and install time, and — for the
/// `Custom` form — the executable the shim is applied to.
///
/// **It does not call an entry malicious or even unusual.** Windows registers
/// its own stock databases through the same keys, so presence is not the
/// technique. And it does not correlate a `DatabasePath` against the
/// `ShimDatabase` records the `.sdb` parser produces: that link is recorded as
/// a **field**, so a reader can follow it, and drawing a conclusion from it is
/// the findings layer's business and needs a measured false-positive rate.
fn installed_sdb_entry(
    kind: InstalledSdbKind,
    key_path: &str,
    value_name: &str,
    value_data: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    let vn = value_name.trim().to_ascii_lowercase();
    let data = value_data.trim();

    match kind {
        InstalledSdbKind::Registration => {
            // One entry per registration, built from its DatabasePath. The
            // other values ride along as observations rather than spawning
            // entries of their own.
            if vn != "databasepath" || data.is_empty() {
                return None;
            }
            let mut entry = base(
                "installed_sdb",
                data.to_string(),
                key_path,
                value_name,
                scope,
                input,
            );
            set_command(&mut entry, data);
            entry.extra.insert("database_path".to_string(), json!(data));
            entry.extra.insert(
                "registration_form".to_string(),
                json!("InstalledSDB: the database's own registration"),
            );
            // The link to the parsed database, as a field and not a finding.
            entry.observe(
                "database_path_recorded",
                format!(
                    "The registry names {data} as an installed shim database. A ShimDatabase \
                     record whose source path is that file is the same database read from \
                     disk; this build records the path and draws no conclusion from the two \
                     matching or not matching."
                ),
            );
            entry.observe(
                "presence_is_not_the_technique",
                "Windows registers its own stock shim databases through this key, so an entry \
                 here is not by itself application shimming. What is reported is the path, the \
                 description and the install time.",
            );
            Some(entry)
        }
        InstalledSdbKind::AppliedTo { executable } => {
            // The default value's data is the install FILETIME; the key name
            // carries the GUID and the executable.
            if !(vn.is_empty() || vn == "(default)") {
                return None;
            }
            let mut entry = base(
                "installed_sdb",
                executable.clone(),
                key_path,
                value_name,
                scope,
                input,
            );
            entry
                .extra
                .insert("applied_to_executable".to_string(), json!(executable));
            entry.extra.insert(
                "registration_form".to_string(),
                json!("Custom: a shim database applied to one executable"),
            );
            match crate::normalize::parse_qword(data) {
                Some(filetime) => {
                    entry
                        .extra
                        .insert("install_filetime_raw".to_string(), json!(filetime));
                    entry.extra.insert(
                        "installed".to_string(),
                        json!(seance_core::time::filetime_to_rfc3339(filetime)),
                    );
                }
                None if data.is_empty() => {}
                None => {
                    // Absent because it would not read, not absent because it
                    // was not there.
                    entry.observe(
                        "install_time_unreadable",
                        format!(
                            "This key's default value is the install time as a 64-bit \
                             FILETIME, and this build could not read it from {data:?}. The \
                             time is absent from this record and present in the registry."
                        ),
                    );
                }
            }
            entry.observe(
                "applied_to_recorded",
                format!(
                    "A shim database is registered against {executable} on this machine. The \
                     key names the executable and the database's GUID; which database file \
                     that GUID is depends on the InstalledSDB registration of the same GUID."
                ),
            );
            Some(entry)
        }
    }
}

/// Build a file-association entry.
///
/// Every refusal here is deliberate, and each is the difference between a
/// reading and an accusation:
///
/// * **No record says "hijack".** That is a comparison against a default, and
///   there is no baseline in the evidence to make it against.
/// * **The hash is reported as present and unverified**, so a reader knows the
///   check exists and was not made rather than assuming it passed. It is a MAC
///   over the SID, the extension and the ProgId, and cannot be recomputed
///   offline.
/// * **`OpenWithProgids` is not the association in force** — it lists the
///   candidates offered in the Open With dialog — and says so, because reading
///   it as the default would name the wrong program.
fn file_association_entry(
    kind: FileAssociationKind,
    key_path: &str,
    value_name: &str,
    value_data: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    let (extension, in_force) = match &kind {
        FileAssociationKind::UserChoice(ext) => (ext.clone(), true),
        FileAssociationKind::OpenWithProgids(ext) => (ext.clone(), false),
    };
    let vn = value_name.trim().to_ascii_lowercase();

    // `UserChoice` carries `ProgId` and `Hash`. The hash is a fact about the
    // key, observed below, not an entry of its own.
    if in_force && vn != "progid" {
        return None;
    }

    let progid = if in_force {
        value_data.trim().to_string()
    } else {
        // `OpenWithProgids` stores each candidate as a VALUE NAME, with empty
        // or binary data, so the name is the ProgId.
        value_name.trim().to_string()
    };
    if progid.is_empty() {
        return None;
    }

    let mut entry = base(
        "file_association",
        format!("{extension} -> {progid}"),
        key_path,
        value_name,
        scope,
        input,
    );
    entry
        .extra
        .insert("extension".to_string(), json!(extension));
    entry.extra.insert("prog_id".to_string(), json!(progid));
    entry
        .extra
        .insert("association_in_force".to_string(), json!(in_force));
    entry.extra.insert("hijack_claim".to_string(), json!(false));

    if in_force {
        entry.observe(
            "association_in_force",
            format!(
                "UserChoice names {progid} as the application that opens {extension} for this \
                 user. This is the association in force."
            ),
        );
        // Stated on every UserChoice entry, so the absence of a verdict is
        // never read as a passing one.
        entry
            .extra
            .insert("hash_verified".to_string(), json!("not verifiable offline"));
        entry.observe(
            "userchoice_hash_not_verified",
            "UserChoice carries a Hash value: a MAC over the user's SID, the extension and \
             the ProgId, which Windows verifies at logon. It cannot be recomputed from an \
             image, so a tampered association cannot be distinguished here from a legitimate \
             one. The check exists and was not made.",
        );
    } else {
        entry.observe(
            "association_candidate_only",
            format!(
                "OpenWithProgids offers {progid} as a candidate for {extension} in the Open \
                 With dialog. It is NOT the association in force — reading it as the default \
                 would name the wrong program."
            ),
        );
    }
    // The claim this entry refuses to make, said in words rather than left to
    // the absence of a field.
    entry.observe(
        "no_hijack_claim",
        "Whether this association differs from the system default is a comparison against a \
         baseline that is not in this evidence. Windows writes UserChoice whenever a user \
         picks an application in the Open With dialog, so the presence of this key is the \
         ordinary state of the system and is not by itself a persistence finding.",
    );
    Some(entry)
}

fn base(
    category: &'static str,
    entry_name: impl Into<String>,
    key_path: &str,
    value_name: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> AsepEntry {
    let mut entry = AsepEntry::new(category, entry_name, key_path, LocationKind::RegistryKey);
    entry.value_name = if value_name.is_empty() {
        None
    } else {
        Some(value_name.to_string())
    };
    entry.hive = Some(input.hive_name.to_string());
    entry.scope = scope.to_string();
    entry.user = input.user.clone();
    entry.installed_time_unavailable_reason = Some(crate::KEY_TIME_UNAVAILABLE);
    entry
}

fn set_command(entry: &mut AsepEntry, command: &str) {
    let command = command.trim();
    if command.is_empty() {
        return;
    }
    entry.command = Some(command.to_string());
    if let Some(split) = split_command(command) {
        entry.image = Some(split.image);
        entry.arguments = split.arguments;
        entry.split_basis = Some(split.basis);
    }
}

#[allow(clippy::too_many_arguments)]
fn simple_entry(
    category: &'static str,
    entry_name: &str,
    key_path: &str,
    value_name: &str,
    value_data: &str,
    runs_when: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    if value_data.trim().is_empty() {
        return None;
    }
    let label = if entry_name.trim().is_empty() {
        "(unnamed value)"
    } else {
        entry_name
    };
    let mut entry = base(category, label, key_path, value_name, scope, input);
    set_command(&mut entry, value_data);
    entry.runs_when = runs_when.to_string();
    entry.enabled = Some(true);
    entry.enabled_basis =
        "The value is present; Windows honours it whenever the mechanism runs.".to_string();
    Some(entry)
}

/// Whether the bare-name rule seen on the observed build covers this Run key:
/// `Run` under `HKLM\SOFTWARE` or a user hive, and `RunOnce` under `HKLM`.
/// `Wow6432Node`, `Policies\Explorer\Run`, `RunOnceEx`, the RunServices keys and
/// `HKCU\RunOnce` were not tested and keep the default.
fn run_key_rule_observed(key_path: &str, kind: &str, hive: HiveKind) -> bool {
    if key_path.to_ascii_lowercase().contains("wow6432node") {
        return false;
    }
    matches!(
        (kind, hive),
        ("run", HiveKind::Software | HiveKind::NtUser) | ("runonce", HiveKind::Software)
    )
}

fn run_key_entry(
    key_path: &str,
    value_name: &str,
    value_data: &str,
    kind: &'static str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    if value_data.trim().is_empty() {
        return None;
    }
    let mut entry = base(
        "run_key",
        if value_name.is_empty() {
            "(unnamed value)"
        } else {
            value_name
        },
        key_path,
        value_name,
        scope,
        input,
    );
    set_command(&mut entry, value_data);
    if run_key_rule_observed(key_path, kind, input.hive_kind) {
        entry.search_context.rule =
            crate::normalize::SearchRule::Observed(crate::normalize::ObservedLauncher::RunKey);
    }
    let who = match (input.hive_kind, input.user.as_deref()) {
        (HiveKind::NtUser | HiveKind::UsrClass, Some(user)) => format!("when {user} logs on"),
        (HiveKind::NtUser | HiveKind::UsrClass, None) => {
            "when the owner of this user profile logs on".to_string()
        }
        _ => "at logon, for every user of this machine".to_string(),
    };
    entry.runs_when = match kind {
        "runonce" | "runonceex" => format!(
            "Runs once {who}, after which Windows deletes the value. A value still present \
             has not run yet."
        ),
        "runservices" | "runservicesonce" => format!(
            "Runs at boot before the shell starts (legacy RunServices list), and again \
             {who} on systems that still honour the key."
        ),
        "policy_run" => format!("Runs {who}, from the Explorer policy Run list."),
        _ => format!("Runs {who}, started by Explorer as that user."),
    };
    entry.enabled = Some(true);
    entry.enabled_basis = "The value is present under a Run key.".to_string();
    entry.put("run_key_kind", json!(kind));
    Some(entry)
}

fn shell_folder_entry(
    key_path: &str,
    value_name: &str,
    value_data: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    let folder = value_data.trim();
    if folder.is_empty() {
        return None;
    }
    let mut entry = base(
        "startup_folder_redirect",
        value_name,
        key_path,
        value_name,
        scope,
        input,
    );
    entry.command = Some(folder.to_string());
    entry.image = Some(folder.to_string());
    entry.runs_when = format!(
        "At logon Windows runs everything in '{folder}', which this value nominates as the \
         {} Startup folder.",
        if value_name.eq_ignore_ascii_case("Common Startup") {
            "all-users"
        } else {
            "per-user"
        }
    );
    entry.enabled = Some(true);
    entry.enabled_basis =
        "The value is present and names the folder Windows will read at logon.".to_string();
    let normalized = folder.to_ascii_lowercase().replace('\\', "/");
    if !normalized.contains("start menu/programs/startup") {
        entry.observe(
            "startup_folder_not_default_location",
            format!(
                "The Startup folder is set to '{folder}', which is not the default \
                 ...\\Start Menu\\Programs\\Startup path."
            ),
        );
    }
    Some(entry)
}

fn winlogon_entries(
    key_path: &str,
    value_name: &str,
    value_data: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<Vec<AsepEntry>> {
    let vn = value_name.to_ascii_lowercase();
    let data = value_data.trim();
    if data.is_empty() {
        return None;
    }
    let (category, default, runs_when): (&'static str, Option<&str>, &str) = match vn.as_str() {
        "shell" => (
            "winlogon_shell",
            Some("explorer.exe"),
            "Winlogon starts this as the user's shell immediately after logon. Every \
             element listed runs; Windows ships with explorer.exe alone.",
        ),
        "userinit" => (
            "winlogon_userinit",
            Some("userinit.exe"),
            "Winlogon runs this immediately after a user authenticates, before the shell \
             starts. Every element listed runs.",
        ),
        "taskman" => (
            "winlogon_other",
            None,
            "Started in place of Task Manager when the user asks for it.",
        ),
        "ginadll" => (
            "winlogon_other",
            None,
            "Loaded into winlogon.exe at boot as the interactive logon interface (Windows \
             XP and Server 2003 only).",
        ),
        "appsetup" => (
            "winlogon_other",
            None,
            "Run by Winlogon at logon, before the shell starts.",
        ),
        "vmapplet" => (
            "winlogon_other",
            None,
            "Run by Winlogon when the virtual-memory applet is invoked during setup.",
        ),
        "uihost" => (
            "winlogon_other",
            None,
            "Loaded by Winlogon as the logon user-interface host at boot.",
        ),
        _ => return None,
    };

    // Shell and Userinit are comma-separated lists. Each element is a separate
    // thing that runs, so reporting the raw list as a single entry would bury an
    // appended command — which is exactly the shape this ASEP is abused in.
    let elements: Vec<String> = if matches!(category, "winlogon_shell" | "winlogon_userinit") {
        data.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        vec![data.to_string()]
    };
    if elements.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(elements.len());
    for (idx, element) in elements.iter().enumerate() {
        let mut entry = base(category, value_name, key_path, value_name, scope, input);
        set_command(&mut entry, element);
        if category == "winlogon_userinit" {
            entry.search_context.rule = crate::normalize::SearchRule::Observed(
                crate::normalize::ObservedLauncher::WinlogonUserinit,
            );
        }
        entry.runs_when = runs_when.to_string();
        entry.enabled = Some(true);
        entry.enabled_basis = format!("The Winlogon {value_name} value names this.");
        entry.put("winlogon_value", json!(value_name));
        entry.put("winlogon_element_index", json!(idx));
        entry.put("winlogon_element_count", json!(elements.len()));
        entry.put("winlogon_full_value", json!(data));
        if let Some(default) = default {
            entry.put("windows_default", json!(default));
            let image = entry.image.clone().unwrap_or_else(|| element.clone());
            let matches_default = basename(&image).eq_ignore_ascii_case(default);
            if !matches_default {
                entry.observe(
                    "differs_from_windows_default",
                    format!(
                        "The value Windows ships for Winlogon {value_name} is '{default}'; \
                         this element names '{element}'."
                    ),
                );
            }
            if elements.len() > 1 {
                entry.observe(
                    "additional_element_in_list",
                    format!(
                        "Winlogon {value_name} holds {} comma-separated elements; Windows \
                         ships with one.",
                        elements.len()
                    ),
                );
            }
        }
        out.push(entry);
    }
    Some(out)
}

fn winlogon_notify_entry(
    key_lower: &str,
    key_path: &str,
    value_name: &str,
    value_data: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    if value_data.trim().is_empty() {
        return None;
    }
    let package = segment_after(key_lower, "\\winlogon\\notify\\").unwrap_or("(unnamed package)");
    let package_original = original_segment(key_path, key_lower, package).to_string();
    let mut entry = base(
        "winlogon_notify",
        package_original.clone(),
        key_path,
        value_name,
        scope,
        input,
    );
    set_command(&mut entry, value_data);
    entry.runs_when =
        "Loaded into winlogon.exe and called on logon, logoff, screen lock, unlock and \
         shutdown events (honoured by Windows 7 and earlier)."
            .to_string();
    entry.enabled = Some(true);
    entry.enabled_basis = "The notification package names a DLL.".to_string();
    entry.put("winlogon_notify_package", json!(package_original));
    Some(entry)
}

#[allow(clippy::too_many_arguments)]
fn ifeo_entry(
    key_lower: &str,
    key_path: &str,
    value_name: &str,
    value_data: &str,
    scope: &str,
    input: &RegistryScanInput,
    silent_exit: bool,
) -> Option<AsepEntry> {
    if value_data.trim().is_empty() {
        return None;
    }
    let marker = if silent_exit {
        "\\silentprocessexit\\"
    } else {
        "\\image file execution options\\"
    };
    let hijacked = segment_after(key_lower, marker).unwrap_or("(unnamed image)");
    let hijacked_original = original_segment(key_path, key_lower, hijacked).to_string();
    let mut entry = base(
        "ifeo_debugger",
        hijacked_original.clone(),
        key_path,
        value_name,
        scope,
        input,
    );
    set_command(&mut entry, value_data);
    // Microsoft's service-debugging guidance says to set the `Debugger` value
    // to the debugger's full path (`HUNT-249`); no general specification of the
    // value was found, so the rule is the one observed on a live build
    // (`LAUNCH-1`). No documentation or observation covers `MonitorProcess`.
    if !silent_exit {
        entry.search_context.rule = crate::normalize::SearchRule::Observed(
            crate::normalize::ObservedLauncher::IfeoDebugger,
        );
    }
    entry.runs_when = if silent_exit {
        format!("Whenever {hijacked_original} exits, Windows starts this command.")
    } else {
        format!(
            "Whenever {hijacked_original} is launched, Windows starts this command instead \
             and hands it the original command line. {hijacked_original} itself only runs \
             if this command chooses to start it."
        )
    };
    entry.enabled = Some(true);
    entry.enabled_basis = if silent_exit {
        "A SilentProcessExit MonitorProcess is set for this image.".to_string()
    } else {
        "A Debugger value is set for this image.".to_string()
    };
    entry.put("ifeo_hijacked_image", json!(hijacked_original));
    entry.put(
        "ifeo_mechanism",
        json!(if silent_exit {
            "silent_process_exit_monitor"
        } else {
            "debugger"
        }),
    );
    Some(entry)
}

fn appinit_entry(
    key_path: &str,
    value_name: &str,
    dll: &str,
    scope: &str,
    input: &RegistryScanInput,
    load_flag: Option<u32>,
) -> Option<AsepEntry> {
    if dll.trim().is_empty() {
        return None;
    }
    let label = basename(dll).to_string();
    let mut entry = base("appinit_dlls", label, key_path, value_name, scope, input);
    set_command(&mut entry, dll);
    entry.runs_when =
        "Loaded into every process that links user32.dll, at process start.".to_string();
    match load_flag {
        Some(0) => {
            entry.enabled = Some(false);
            entry.enabled_basis =
                "LoadAppInit_DLLs is 0, so Windows does not load this list.".to_string();
        }
        Some(v) => {
            entry.enabled = Some(true);
            entry.enabled_basis = format!("LoadAppInit_DLLs is {v}, so this list is loaded.");
        }
        None => {
            entry.enabled = None;
            entry.enabled_basis =
                "No LoadAppInit_DLLs flag was found in this hive, so whether the list is \
                 honoured could not be determined."
                    .to_string();
        }
    }
    entry.put("appinit_load_flag", json!(load_flag));
    Some(entry)
}

fn boot_execute_entry(
    key_path: &str,
    value_name: &str,
    element: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    let element = element.trim();
    if element.is_empty() {
        return None;
    }
    let mut entry = base("boot_execute", element, key_path, value_name, scope, input);
    set_command(&mut entry, element);
    entry.runs_when = "Run by the session manager (smss.exe) during boot, before Windows \
                       starts and before any user logs on."
        .to_string();
    entry.enabled = Some(true);
    entry.enabled_basis = format!("The {value_name} list names this command.");
    if value_name.eq_ignore_ascii_case("BootExecute") {
        entry.put("windows_default", json!("autocheck autochk *"));
        if !element.eq_ignore_ascii_case("autocheck autochk *") {
            entry.observe(
                "differs_from_windows_default",
                format!(
                    "The BootExecute list Windows ships is 'autocheck autochk *'; this \
                     element is '{element}'."
                ),
            );
        }
    }
    Some(entry)
}

fn lsa_entry(
    category: &'static str,
    key_path: &str,
    value_name: &str,
    element: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    let element = element.trim();
    if element.is_empty() {
        return None;
    }
    let mut entry = base(category, element, key_path, value_name, scope, input);
    set_command(&mut entry, element);
    entry.runs_when = match category {
        "lsa_authentication_package" => {
            "Loaded into LSASS at boot as an authentication package; it participates in \
             every logon."
        }
        "lsa_notification_package" => {
            "Loaded into LSASS at boot and called with the new password whenever a \
             password is set or changed."
        }
        _ => "Loaded into LSASS at boot as a security support provider.",
    }
    .to_string();
    entry.enabled = Some(true);
    entry.enabled_basis = format!("The {value_name} list names this package.");
    entry.observe(
        "package_name_not_a_path",
        "LSA package values name a DLL without a path; Windows loads it from the system \
         directory.",
    );
    Some(entry)
}

fn active_setup_entry(
    key_lower: &str,
    key_path: &str,
    value_name: &str,
    value_data: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    if value_data.trim().is_empty() {
        return None;
    }
    let component =
        segment_after(key_lower, "\\installed components\\").unwrap_or("(unnamed component)");
    let component_original = original_segment(key_path, key_lower, component).to_string();
    let mut entry = base(
        "active_setup",
        component_original.clone(),
        key_path,
        value_name,
        scope,
        input,
    );
    set_command(&mut entry, value_data);
    entry.runs_when = "Runs once for each user, at that user's next logon, whenever the \
                       version recorded for that user is behind the machine's."
        .to_string();
    entry.enabled = Some(true);
    entry.enabled_basis = "A StubPath is set for this component.".to_string();
    entry.put("active_setup_component", json!(component_original));
    Some(entry)
}

fn winsock_entry(
    key_path: &str,
    value_name: &str,
    value_data: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> Option<AsepEntry> {
    let label = basename(key_path).to_string();
    let mut entry = base(
        "winsock_provider",
        label,
        key_path,
        value_name,
        scope,
        input,
    );
    entry.runs_when = "Loaded into any process that creates a socket through the Winsock \
                       catalog, at the point the socket is created."
        .to_string();
    entry.enabled = Some(true);
    entry.enabled_basis =
        "A catalog entry is present under the Winsock provider catalog.".to_string();
    entry.read_status = ReadStatus::Unread(
        "The Winsock catalog entry is a binary WSAPROTOCOL_INFO structure. This build \
         records that the entry exists but does not decode the provider DLL path out of \
         it, so what would load is not stated here."
            .to_string(),
    );
    entry.incomplete_reason =
        Some("Winsock catalog payload not decoded; presence recorded only.".to_string());
    // The binary payload was never decoded, so the provider DLL is unknown: an
    // unresolved structure, not a cap (B3-025).
    entry.incomplete_code = Some(seance_core::io::IncompleteReason::UnresolvedStructure);
    entry.put("winsock_value_rendering", json!(value_data));
    Some(entry)
}

fn com_entry(
    reg: &ComRegistration,
    per_user_classes: bool,
    scope: &str,
    input: &RegistryScanInput,
) -> AsepEntry {
    let mut entry = base(
        "com_server",
        reg.clsid.clone(),
        &reg.key_path,
        "(Default)",
        scope,
        input,
    );
    set_command(&mut entry, &reg.image);
    entry.runs_when = format!(
        "Loaded into any process that instantiates COM class {} ({}).",
        reg.clsid, reg.server_kind
    );
    entry.enabled = Some(true);
    entry.enabled_basis = "The class is registered with a server path.".to_string();
    entry.put("com_clsid", json!(reg.clsid));
    entry.put("com_server_kind", json!(reg.server_kind));
    entry.put(
        "com_listing_filter",
        json!(
            "Machine-wide COM servers that resolve inside \\Windows\\System32 or \
             \\Windows\\SysWOW64 are examined but not listed; per-user class \
             registrations are always listed."
        ),
    );
    if per_user_classes {
        entry.observe(
            "per_user_class_registration",
            "This class is registered in the per-user class store, which Windows consults \
             before the machine-wide registration of the same class.",
        );
    } else {
        entry.observe(
            "server_outside_system_directories",
            "The registered server resolves outside \\Windows\\System32 and \
             \\Windows\\SysWOW64.",
        );
    }
    entry
}

fn com_reference_entry(
    reference: &ComReference,
    resolved: Option<&ComRegistration>,
    scope: &str,
    input: &RegistryScanInput,
) -> AsepEntry {
    let mut entry = base(
        reference.category,
        reference.entry_name.clone(),
        &reference.key_path,
        "(Default)",
        scope,
        input,
    );
    entry.runs_when = if reference.category == "browser_helper_object" {
        "Loaded into Internet Explorer every time it starts.".to_string()
    } else {
        format!(
            "Loaded into explorer.exe, and into any process hosting the shell, when the \
             shell handles a matching object ({}).",
            reference.handler_kind
        )
    };
    entry.enabled = Some(true);
    entry.enabled_basis = "The handler is registered and names a COM class.".to_string();
    entry.put("com_clsid", json!(reference.clsid));
    entry.put("shell_handler_kind", json!(reference.handler_kind));

    match resolved {
        Some(reg) => {
            set_command(&mut entry, &reg.image);
            entry.put("com_server_key", json!(reg.key_path));
            entry.put("com_server_kind", json!(reg.server_kind));
        }
        None => {
            entry.read_status = ReadStatus::Unread(format!(
                "COM class {} is registered as a handler here, but no server registration \
                 for it was found in this hive, so what would load could not be \
                 established. The class may be registered in a hive that was not ingested.",
                reference.clsid
            ));
            entry.observe(
                "com_server_unresolved",
                format!(
                    "No InprocServer32, LocalServer32 or InprocHandler32 registration for \
                     {} was present in this hive.",
                    reference.clsid
                ),
            );
        }
    }
    entry
}

fn task_registration_entry(
    key_lower: &str,
    key_path: &str,
    task_id: &str,
    scope: &str,
    input: &RegistryScanInput,
) -> AsepEntry {
    let tree_tail = tail_after_marker(key_lower, "\\taskcache\\tree\\").unwrap_or("");
    let name = basename(key_path).to_string();
    let mut entry = base(
        "scheduled_task_registration",
        name,
        key_path,
        "Id",
        scope,
        input,
    );
    entry.runs_when = format!(
        "A scheduled task is registered under the Task Scheduler path \\{tree_tail}. Its \
         triggers and actions live in the task XML under \\Windows\\System32\\Tasks, not \
         in this key, so when it runs cannot be stated from the registry alone."
    );
    entry.enabled = None;
    entry.enabled_basis =
        "The registration record does not carry the task's enabled state; that is in the \
         task XML."
            .to_string();
    entry.put("task_tree_path", json!(format!("\\{tree_tail}")));
    entry.put("task_id", json!(task_id.trim()));
    entry.observe(
        "registration_only",
        "This is the registry-side registration of a task. If no matching task XML was \
         recovered, the task existed but its definition was not found in this evidence.",
    );
    entry
}

// --- small helpers -----------------------------------------------------------

fn com_server_kind(last: &str) -> &'static str {
    match last {
        "localserver32" => "out-of-process server",
        "inprochandler32" => "in-process handler",
        _ => "in-process server",
    }
}

/// Map a shell-handler key shape to `(category, handler kind)`.
fn shell_handler(parent: &str, last: &str) -> Option<(&'static str, &'static str)> {
    match parent {
        "contextmenuhandlers" => Some(("shell_extension", "context menu handler")),
        "propertysheethandlers" => Some(("shell_extension", "property sheet handler")),
        "copyhookhandlers" => Some(("shell_extension", "copy hook handler")),
        "dragdrophandlers" => Some(("shell_extension", "drag-and-drop handler")),
        "columnhandlers" => Some(("shell_extension", "column handler")),
        "shelliconoverlayidentifiers" => Some(("shell_extension", "icon overlay handler")),
        "shellserviceobjects" => Some(("shell_extension", "shell service object")),
        "shellexecutehooks" => Some(("shell_extension", "ShellExecute hook")),
        "sharedtaskscheduler" => Some(("shell_extension", "shared task scheduler entry")),
        "browser helper objects" => Some(("browser_helper_object", "browser helper object")),
        _ => match last {
            "shellexecutehooks" => Some(("shell_extension", "ShellExecute hook")),
            "sharedtaskscheduler" => Some(("shell_extension", "shared task scheduler entry")),
            _ => None,
        },
    }
}

/// Recognise an installed-shim-database key.
///
/// Two locations, both plain key walks over `SOFTWARE`:
/// `…\AppCompatFlags\InstalledSDB\{GUID}`, whose values name the database, and
/// `…\AppCompatFlags\Custom\<exe>\{GUID}.sdb`, whose **key name** names the
/// executable the shim is applied to and whose default value is the install
/// time.
fn installed_sdb(lower_key: &str) -> Option<InstalledSdbKind> {
    if lower_key.contains(r"\appcompatflags\installedsdb\") {
        return Some(InstalledSdbKind::Registration);
    }
    if let Some(rest) = lower_key.split(r"\appcompatflags\custom\").nth(1) {
        // `<exe>\{guid}.sdb` — the executable is the first segment.
        let mut parts = rest.split('\\');
        let exe = parts.next()?;
        if exe.is_empty() {
            return None;
        }
        return Some(InstalledSdbKind::AppliedTo {
            executable: exe.to_string(),
        });
    }
    None
}

/// Which of the two shim-database keys.
enum InstalledSdbKind {
    /// `InstalledSDB\{GUID}` — the database's own registration.
    Registration,
    /// `Custom\<exe>\{GUID}.sdb` — a database applied to one executable.
    AppliedTo { executable: String },
}

/// Recognise a file-association key, returning the extension it governs.
///
/// `…\Explorer\FileExts\<.ext>\UserChoice` (value `ProgId`) and
/// `…\Explorer\FileExts\<.ext>\OpenWithProgids`.
///
/// # The whole of this matcher is what it does NOT conclude
///
/// "Hijack" is a comparison against a default, and there is no baseline in the
/// evidence. Windows writes `UserChoice` every time a user picks an application
/// in the Open With dialog, so the key's presence is the ordinary state of the
/// system: one real Windows 7 user hive carries `UserChoice` for 17 extensions
/// and 138 `OpenWithProgids` candidates, counted through this project's own
/// reader. A classifier that fired on presence would fire 155 times on that one
/// hive, which is `HUNT-122` verbatim.
///
/// So this reports the association and the ProgId it names, and the word
/// "hijack" never reaches a record.
fn file_association(parent: &str, last: &str) -> Option<FileAssociationKind> {
    // `FileExts\<.ext>\UserChoice`: the parent segment is the extension.
    let ext_of = |seg: &str| {
        seg.starts_with('.')
            .then(|| seg.to_string())
            .filter(|e| e.len() > 1)
    };
    match last {
        "userchoice" => ext_of(parent).map(FileAssociationKind::UserChoice),
        "openwithprogids" => ext_of(parent).map(FileAssociationKind::OpenWithProgids),
        _ => None,
    }
}

/// Which of the two file-association keys, and the extension it governs.
enum FileAssociationKind {
    /// `UserChoice` — the association actually in force.
    UserChoice(String),
    /// `OpenWithProgids` — the candidates offered, not the one in force.
    OpenWithProgids(String),
}

/// Find the CLSID a handler registration names.
///
/// Handlers register the class three different ways depending on the key: as
/// the default value's data, as the value's *name* (SharedTaskScheduler,
/// ShellExecuteHooks), or as the key's own name (browser helper objects).
/// Returns the lowercased CLSID and whether it came from the value name, which
/// decides how the entry is labelled.
fn clsid_reference(value_data: &str, value_name: &str, last: &str) -> Option<(String, bool)> {
    if is_clsid(value_data) {
        return Some((value_data.trim().to_ascii_lowercase(), false));
    }
    if is_clsid(value_name) {
        return Some((value_name.trim().to_ascii_lowercase(), true));
    }
    if is_clsid(last) {
        return Some((last.trim().to_ascii_lowercase(), false));
    }
    None
}

fn is_clsid(s: &str) -> bool {
    let t = s.trim();
    t.len() == 38 && t.starts_with('{') && t.ends_with('}')
}

/// Split an `AppInit_DLLs` value, which is a space- or comma-separated list.
fn split_dll_list(value: &str) -> Vec<String> {
    value
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn segment_from_end(lower: &str, back: usize) -> &str {
    lower.rsplit('\\').nth(back).unwrap_or("")
}

fn control_set_of(lower: &str) -> Option<&str> {
    lower
        .split('\\')
        .find(|s| s.starts_with("controlset") || *s == "currentcontrolset")
}

fn service_key(lower: &str, name: &str) -> String {
    match lower.find("\\services\\") {
        Some(pos) => {
            let end = pos
                .saturating_add("\\services\\".len())
                .saturating_add(name.len());
            lower.get(..end).unwrap_or(lower).to_string()
        }
        None => lower.to_string(),
    }
}

/// The `...\Services\<name>` prefix of the original-case key path.
fn service_key_path(key_path: &str, lower: &str, name: &str) -> String {
    let end = match lower.find("\\services\\") {
        Some(pos) => pos
            .saturating_add("\\services\\".len())
            .saturating_add(name.len()),
        None => return key_path.to_string(),
    };
    key_path.get(..end).unwrap_or(key_path).to_string()
}

/// Recover the original casing of a lowercased key segment.
///
/// Registry key names are case-preserving and an examiner comparing this report
/// against RegEdit should see the casing the machine actually used. Falls back
/// to the lowercased form whenever the byte ranges do not line up, so the value
/// is always something that was read out of the hive, never invented.
fn original_segment<'a>(key_path: &'a str, lower: &str, segment_lower: &'a str) -> &'a str {
    if key_path.len() != lower.len() {
        return segment_lower;
    }
    let Some(offset) = lower.find(segment_lower) else {
        return segment_lower;
    };
    let end = offset.saturating_add(segment_lower.len());
    key_path.get(offset..end).unwrap_or(segment_lower)
}

/// Everything after `marker`, keeping all further segments.
fn tail_after_marker<'a>(lower: &'a str, marker: &str) -> Option<&'a str> {
    let pos = lower.find(marker)?;
    let start = pos.checked_add(marker.len())?;
    lower.get(start..)
}

/// The system's install time, seconds since the epoch, from the SOFTWARE hive's
/// `Microsoft\Windows NT\CurrentVersion\InstallDate` (`HUNT-276`). A `REG_DWORD`, rendered
/// `0x... (decimal)`; a bare decimal is accepted too. `None` when the hive holds no such value.
pub fn os_install_epoch(values: &[Value]) -> Option<i64> {
    values.iter().find_map(|v| {
        let key = v.get("key_path")?.as_str()?;
        let name = v.get("value_name")?.as_str()?;
        if !name.eq_ignore_ascii_case("InstallDate")
            || !key
                .to_ascii_lowercase()
                .ends_with("\\microsoft\\windows nt\\currentversion")
        {
            return None;
        }
        let rendered = v.get("value_data")?.as_str()?.trim();
        let epoch = rendered.parse::<i64>().ok().or_else(|| {
            rendered
                .rsplit_once('(')
                .and_then(|(_, rest)| rest.strip_suffix(')'))
                .and_then(|n| n.trim().parse::<i64>().ok())
        })?;
        // 0 is "never set" (a setup-time backup hive records it), not 1970.
        (epoch > 0).then_some(epoch)
    })
}
