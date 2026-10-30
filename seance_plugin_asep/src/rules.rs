//! The ASEP category table: every place this build knows Windows will execute
//! something at boot or logon, what backs it, and which ATT&CK technique it
//! corresponds to.
//!
//! This table is the completeness contract. An examiner asks "what runs at boot
//! on this machine" once, and the answer must not silently omit a family of
//! autostart locations. So the table is enumerated explicitly and *every* entry
//! in it is reported for every hive examined — as entries found, as examined
//! and empty, as not applicable to the hive in hand, or as unexamined with a
//! reason. A category that quietly never appears in the output is the failure
//! this module exists to prevent.
//!
//! Nothing here asserts that an entry is malicious. An ASEP is a fact about how
//! the machine is configured; whether a particular one is unwanted is the
//! examiner's determination.

/// Which hive a registry-backed category can live in.
///
/// Used to distinguish "we looked in this hive and found none" from "this hive
/// cannot hold that category, so its absence here says nothing".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiveKind {
    /// `HKLM\SOFTWARE`.
    Software,
    /// `HKLM\SYSTEM` (control sets, services, session manager).
    System,
    /// A per-user `NTUSER.DAT` (including `DEFAULT`, the `.DEFAULT` profile).
    NtUser,
    /// A per-user `UsrClass.dat` (`HKCU\Software\Classes`).
    UsrClass,
    /// A hive this build does not recognise as an ASEP carrier (SAM, SECURITY,
    /// COMPONENTS, BCD...). Categories are reported as unexamined for these,
    /// never as empty.
    Other,
}

impl HiveKind {
    /// Classify a hive from the name the registry plugin recorded (which is the
    /// uppercased file name of the hive it parsed).
    pub fn from_hive_name(name: &str) -> HiveKind {
        let n = name.trim().to_ascii_uppercase();
        let base = n.rsplit(['\\', '/']).next().unwrap_or(n.as_str());
        if base.starts_with("SOFTWARE") {
            HiveKind::Software
        } else if base.starts_with("SYSTEM") {
            HiveKind::System
        } else if base.starts_with("NTUSER") || base.starts_with("DEFAULT") {
            HiveKind::NtUser
        } else if base.starts_with("USRCLASS") {
            HiveKind::UsrClass
        } else {
            HiveKind::Other
        }
    }

    /// The registry root this hive is mounted under on a live system.
    pub fn scope(self) -> &'static str {
        match self {
            HiveKind::Software | HiveKind::System => "HKLM",
            HiveKind::NtUser | HiveKind::UsrClass => "HKCU",
            HiveKind::Other => "unknown",
        }
    }

    /// Stable string form written into records.
    pub fn as_str(self) -> &'static str {
        match self {
            HiveKind::Software => "SOFTWARE",
            HiveKind::System => "SYSTEM",
            HiveKind::NtUser => "NTUSER",
            HiveKind::UsrClass => "USRCLASS",
            HiveKind::Other => "OTHER",
        }
    }
}

/// Where a category's evidence comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategorySource {
    /// Read out of a parsed registry hive.
    Registry,
    /// Read off the filesystem (task XML, Startup-folder contents).
    FileSystem,
    /// Read from the WMI CIM repository (`OBJECTS.DATA`) by a record-level
    /// scan, when that file is in the evidence.
    WmiRepository,
}

/// One ASEP family: where it lives, what it means, and how it maps to ATT&CK.
#[derive(Debug, Clone, Copy)]
pub struct CategoryInfo {
    /// Stable machine id written into every record (`run_key`, `service`, ...).
    pub id: &'static str,
    /// Human label for the UI and the report.
    pub label: &'static str,
    /// ATT&CK technique id, or `None` where no technique maps cleanly.
    pub technique: Option<&'static str>,
    /// ATT&CK technique name matching `technique`.
    pub technique_name: Option<&'static str>,
    /// Set when the technique is an approximation, so the report does not
    /// over-claim a mapping the ATT&CK matrix does not actually make.
    pub technique_note: Option<&'static str>,
    /// Where the evidence is read from.
    pub source: CategorySource,
    /// Hives that can carry this category. Empty for non-registry categories.
    pub hives: &'static [HiveKind],
    /// The concrete locations consulted, for the "we looked here" statement.
    pub locations: &'static [&'static str],
    /// Set when this build can only partially read the category, e.g. it can
    /// see that an entry is present but cannot decode its binary payload.
    /// Reaches the record and the coverage report.
    pub partial_reason: Option<&'static str>,
    /// Set when this build cannot read the category at all. Such a category is
    /// reported as unexamined, never as empty.
    pub unexamined_reason: Option<&'static str>,
}

/// The ATT&CK tactic every category in this table belongs to.
pub const MITRE_TACTIC: &str = "TA0003 Persistence";

/// Every ASEP category this build knows about.
pub const CATEGORIES: &[CategoryInfo] = &[
    CategoryInfo {
        id: "run_key",
        label: "Run / RunOnce key",
        technique: Some("T1547.001"),
        technique_name: Some("Registry Run Keys / Startup Folder"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::NtUser],
        locations: &[
            r"...\Microsoft\Windows\CurrentVersion\Run",
            r"...\Microsoft\Windows\CurrentVersion\RunOnce",
            r"...\Microsoft\Windows\CurrentVersion\RunServices",
            r"...\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            r"...\Microsoft\Windows\CurrentVersion\RunOnceEx",
            r"...\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"...\Wow6432Node\... (32-bit views of all of the above)",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "startup_folder",
        label: "Startup folder item",
        technique: Some("T1547.001"),
        technique_name: Some("Registry Run Keys / Startup Folder"),
        technique_note: None,
        source: CategorySource::FileSystem,
        hives: &[],
        locations: &[
            r"...\Start Menu\Programs\Startup\ (per user)",
            r"\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\ (all users)",
            r"\Documents and Settings\...\Start Menu\Programs\Startup\ (legacy)",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "startup_folder_redirect",
        label: "Startup folder redirection",
        technique: Some("T1547.001"),
        technique_name: Some("Registry Run Keys / Startup Folder"),
        technique_note: Some(
            "Redirecting a shell folder does not itself execute code; it moves the \
             directory Windows reads at logon.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::NtUser],
        locations: &[
            r"...\CurrentVersion\Explorer\User Shell Folders\Startup",
            r"...\CurrentVersion\Explorer\Shell Folders\Startup",
            r"...\CurrentVersion\Explorer\User Shell Folders\Common Startup",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "winlogon_shell",
        label: "Winlogon Shell",
        technique: Some("T1547.004"),
        technique_name: Some("Winlogon Helper DLL"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::NtUser],
        locations: &[r"...\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "winlogon_userinit",
        label: "Winlogon Userinit",
        technique: Some("T1547.004"),
        technique_name: Some("Winlogon Helper DLL"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::NtUser],
        locations: &[r"...\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "winlogon_notify",
        label: "Winlogon notification package",
        technique: Some("T1547.004"),
        technique_name: Some("Winlogon Helper DLL"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software],
        locations: &[r"...\Windows NT\CurrentVersion\Winlogon\Notify\<package>\DllName"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "winlogon_other",
        label: "Winlogon Taskman / GinaDLL / AppSetup",
        technique: Some("T1547.004"),
        technique_name: Some("Winlogon Helper DLL"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::NtUser],
        locations: &[
            r"...\Windows NT\CurrentVersion\Winlogon\Taskman",
            r"...\Windows NT\CurrentVersion\Winlogon\GinaDLL",
            r"...\Windows NT\CurrentVersion\Winlogon\AppSetup",
            r"...\Windows NT\CurrentVersion\Winlogon\VmApplet",
            r"...\Windows NT\CurrentVersion\Winlogon\UIHost",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "ifeo_debugger",
        label: "Image File Execution Options debugger",
        technique: Some("T1546.012"),
        technique_name: Some("Image File Execution Options Injection"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software],
        locations: &[
            r"...\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger",
            r"...\Image File Execution Options\<exe>\GlobalFlag + ...\SilentProcessExit\<exe>\MonitorProcess",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "appinit_dlls",
        label: "AppInit_DLLs",
        technique: Some("T1546.010"),
        technique_name: Some("AppInit DLLs"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software],
        locations: &[
            r"...\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
            r"...\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "appcert_dlls",
        label: "AppCertDlls",
        technique: Some("T1546.009"),
        technique_name: Some("AppCert DLLs"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[r"...\Control\Session Manager\AppCertDlls\*"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "boot_execute",
        label: "Session Manager BootExecute",
        technique: Some("T1547"),
        technique_name: Some("Boot or Logon Autostart Execution"),
        technique_note: Some(
            "ATT&CK has no sub-technique for Session Manager BootExecute; mapped to the \
             parent technique.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[
            r"...\Control\Session Manager\BootExecute",
            r"...\Control\Session Manager\SetupExecute",
            r"...\Control\Session Manager\S0InitialCommand",
            r"...\Control\Session Manager\Execute",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "known_dlls",
        label: "KnownDLLs",
        technique: Some("T1574.001"),
        technique_name: Some("DLL Search Order Hijacking"),
        technique_note: Some(
            "KnownDLLs is a mapping table, not an autostart. It is enumerated because an \
             added or redirected entry changes what every process loads.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[r"...\Control\Session Manager\KnownDLLs\*"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "active_setup",
        label: "Active Setup installed component",
        technique: Some("T1547.014"),
        technique_name: Some("Active Setup"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::NtUser],
        locations: &[r"...\Microsoft\Active Setup\Installed Components\<guid>\StubPath"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "service",
        label: "Service or driver",
        technique: Some("T1543.003"),
        technique_name: Some("Create or Modify System Process: Windows Service"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[
            r"...\ControlSet***\Services\<name> (Start, Type, ImagePath, ObjectName)",
            r"...\ControlSet***\Services\<name>\Parameters\ServiceDll",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "lsa_authentication_package",
        label: "LSA authentication package",
        technique: Some("T1547.002"),
        technique_name: Some("Authentication Package"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[r"...\Control\Lsa\Authentication Packages"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "lsa_notification_package",
        label: "LSA notification package",
        technique: Some("T1547.002"),
        technique_name: Some("Authentication Package"),
        technique_note: Some(
            "Notification packages are loaded by LSASS on password change; ATT&CK groups \
             them with authentication packages.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[r"...\Control\Lsa\Notification Packages"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "lsa_security_package",
        label: "LSA security support provider",
        technique: Some("T1547.005"),
        technique_name: Some("Security Support Provider"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[
            r"...\Control\Lsa\Security Packages",
            r"...\Control\Lsa\OSConfig\Security Packages",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "print_monitor",
        label: "Print monitor",
        technique: Some("T1547.010"),
        technique_name: Some("Port Monitors"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[r"...\Control\Print\Monitors\<name>\Driver"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "print_processor",
        label: "Print processor",
        technique: Some("T1547.012"),
        technique_name: Some("Print Processors"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[r"...\Control\Print\Environments\<env>\Print Processors\<name>\Driver"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "netsh_helper",
        label: "Netsh helper DLL",
        technique: Some("T1546.007"),
        technique_name: Some("Netsh Helper DLL"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software],
        locations: &[r"...\SOFTWARE\Microsoft\NetSh\*"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "winsock_provider",
        label: "Winsock layered service provider",
        technique: Some("T1547"),
        technique_name: Some("Boot or Logon Autostart Execution"),
        technique_note: Some(
            "ATT&CK has no sub-technique for Winsock LSPs; mapped to the parent technique.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[
            r"...\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\*",
            r"...\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\*",
        ],
        partial_reason: Some(
            "Winsock catalog entries are binary WSAPROTOCOL_INFO structures. This build \
             records that a catalog entry is present and its key, but does not decode the \
             provider DLL path out of the binary value.",
        ),
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "network_provider",
        label: "Network provider",
        technique: Some("T1547"),
        technique_name: Some("Boot or Logon Autostart Execution"),
        technique_note: Some(
            "ATT&CK has no sub-technique for network providers; mapped to the parent \
             technique.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::System],
        locations: &[r"...\Services\<name>\NetworkProvider\ProviderPath"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "com_server",
        label: "COM server outside the system directories",
        technique: Some("T1546.015"),
        technique_name: Some("Component Object Model Hijacking"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::UsrClass, HiveKind::NtUser],
        locations: &[
            r"...\Classes\CLSID\<clsid>\InprocServer32",
            r"...\Classes\CLSID\<clsid>\LocalServer32",
            r"...\Classes\CLSID\<clsid>\InprocHandler32",
            r"...\Wow6432Node\Classes\CLSID\<clsid>\*Server32",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "shell_extension",
        label: "Shell extension",
        technique: Some("T1546.015"),
        technique_name: Some("Component Object Model Hijacking"),
        technique_note: None,
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::UsrClass, HiveKind::NtUser],
        locations: &[
            r"...\shellex\ContextMenuHandlers\<name>",
            r"...\shellex\PropertySheetHandlers\<name>",
            r"...\Explorer\ShellIconOverlayIdentifiers\<name>",
            r"...\Explorer\ShellServiceObjects\<clsid>",
            r"...\Explorer\ShellExecuteHooks\<clsid>",
            r"...\Explorer\SharedTaskScheduler\<clsid>",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "browser_helper_object",
        label: "Browser Helper Object",
        technique: Some("T1546.015"),
        technique_name: Some("Component Object Model Hijacking"),
        technique_note: Some(
            "Also relevant to T1176 Browser Extensions; the loading mechanism is COM, so \
             the COM technique is used.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::Software, HiveKind::NtUser],
        locations: &[r"...\Explorer\Browser Helper Objects\<clsid>"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "scheduled_task",
        label: "Scheduled task",
        technique: Some("T1053.005"),
        technique_name: Some("Scheduled Task"),
        technique_note: None,
        source: CategorySource::FileSystem,
        hives: &[],
        locations: &[
            r"\Windows\System32\Tasks\** (Task Scheduler 2.0 XML)",
            r"\Windows\Tasks\*.job (Task Scheduler 1.0 binary)",
        ],
        partial_reason: Some(
            "Task Scheduler 1.0 `.job` files are a binary format this build does not \
             decode; each one found is reported as an unread entry rather than omitted.",
        ),
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "scheduled_task_registration",
        label: "Scheduled task registration (TaskCache)",
        technique: Some("T1053.005"),
        technique_name: Some("Scheduled Task"),
        technique_note: Some(
            "The registration record proves a task exists even when its XML file was not \
             recovered; the actions live in the XML.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::Software],
        locations: &[r"...\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\**"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "wmi_mof_autorecover",
        label: "WMI auto-recover MOF",
        technique: Some("T1546.003"),
        technique_name: Some("Windows Management Instrumentation Event Subscription"),
        technique_note: Some(
            "Auto-recover MOFs are recompiled into the WMI repository when it is rebuilt; \
             they are the registry-visible part of WMI persistence.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::Software],
        locations: &[r"...\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs"],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "installed_sdb",
        label: "Installed shim database",
        technique: Some("T1546.011"),
        technique_name: Some("Event Triggered Execution: Application Shimming"),
        technique_note: Some(
            "A shim database registered here is applied by the operating system to the \
             executables it matches, and a shim can inject a DLL into a process the shimmed \
             program starts. Windows registers its own stock databases this way too, so the \
             presence of an entry is not by itself the technique -- what is reported is the \
             database's path, its description and when it was installed.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::Software],
        locations: &[
            r"...\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{GUID}",
            r"...\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\<exe>\{GUID}.sdb",
        ],
        partial_reason: None,
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "file_association",
        label: "Default file association",
        technique: Some("T1546.001"),
        technique_name: Some("Event Triggered Execution: Change Default File Association"),
        technique_note: Some(
            "Presence here is NOT the technique. Windows writes UserChoice every time a user \
             picks an application in the Open With dialog, so the key is normal on every \
             machine: one real Windows 7 user hive (NTUSER-WIN7.DAT) carries UserChoice for \
             17 extensions and 138 OpenWithProgids candidates, counted through this reader. \
             What is reported is the association and the ProgId it names; whether it is a \
             hijack is a comparison against a default that is not in the evidence.",
        ),
        source: CategorySource::Registry,
        hives: &[HiveKind::NtUser, HiveKind::UsrClass, HiveKind::Software],
        locations: &[
            r"...\Microsoft\Windows\CurrentVersion\Explorer\FileExts\<.ext>\UserChoice (ProgId)",
            r"...\Microsoft\Windows\CurrentVersion\Explorer\FileExts\<.ext>\OpenWithProgids",
            r"Software\Classes\<ProgId>\shell\open\command (the command a ProgId resolves to)",
        ],
        partial_reason: Some(
            "UserChoice carries a Hash value -- a MAC over the user's SID, the extension and \
             the ProgId, which Windows verifies and which cannot be recomputed offline. So a \
             tampered association cannot be distinguished here from a legitimate one, and no \
             record claims it can. Each entry states whether the hash is present and that it \
             was not verified.",
        ),
        unexamined_reason: None,
    },
    CategoryInfo {
        id: "wmi_event_subscription",
        label: "WMI event subscription",
        technique: Some("T1546.003"),
        technique_name: Some("Windows Management Instrumentation Event Subscription"),
        technique_note: None,
        source: CategorySource::WmiRepository,
        hives: &[],
        locations: &[
            r"\Windows\System32\wbem\Repository\OBJECTS.DATA (__EventFilter, __EventConsumer subclasses, __FilterToConsumerBinding)",
            r"\WINDOWS\system32\wbem\Repository\FS\OBJECTS.DATA (the form observed on Windows XP)",
        ],
        partial_reason: Some(
            "OBJECTS.DATA is read by a record-level scan of its pages for the instance \
             records of the subscription classes. When the page mapping (MAPPING1/2/3.MAP, \
             or OBJECTS.MAP on XP) is beside the file, the pages are walked through it: a \
             record running past its page is read whole, a record in a page no logical \
             page maps to is reported as a superseded copy, and a record no descriptor table \
             lists is residue even in a mapped page. When it is not, whether a record \
             found was the one the repository currently mapped is not established. When the index \
             (INDEX.BTR) beside the file is also read (only where the page mapping is \
             MAPPINGn.MAP), it is walked from its root: a record a mapped page lists and the \
             index does not name is deleted or unlinked, not in force. Without it, or with an \
             OBJECTS.MAP mapping, whether the repository still resolved the record is not \
             established. Every record says which applied; the coverage record \
             for OBJECTS.DATA gives the mapping used or why none was, the bytes scanned and \
             the records matched, decoded and undecodable.",
        ),
        unexamined_reason: None,
    },
];

/// Look up a category by its stable id.
///
/// Returns `None` only for an id that is not in the table, which is a
/// programming error rather than an evidence condition — the emitter asserts
/// against it in tests so a category can never reach a record without its
/// ATT&CK mapping and its "where we looked" statement.
pub fn category(id: &str) -> Option<&'static CategoryInfo> {
    CATEGORIES.iter().find(|c| c.id == id)
}

/// True when a registry-backed category can appear in the given hive.
pub fn applies_to_hive(info: &CategoryInfo, hive: HiveKind) -> bool {
    info.source == CategorySource::Registry && info.hives.contains(&hive)
}
