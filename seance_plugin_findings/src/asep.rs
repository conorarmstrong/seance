//! Persistence in a place nothing ordinarily persists from (§2.2, detection 4).
//!
//! `seance_plugin_asep` enumerates every autostart extensibility point it can
//! reach and deliberately **does not accuse**: its records carry neutral
//! observations and no score, because whether an autostart entry is unwanted is
//! the examiner's call. That is the right division, and this module is the
//! other half of it — the place where the judgement is made, labelled, and
//! ranked.
//!
//! # What is judged, and what is read
//!
//! Read from the ASEP record: the category, the image path as stored, the
//! normalised lookup path, whether the target was found on the volume, and how
//! much of the volume had been enumerated when that question was asked. All of
//! it established by the enumerator.
//!
//! Judged here: whether the directory the image sits in is one that software
//! installs into. That is not a parsing question — no parser can answer it —
//! and it is graded in three tiers rather than two, because the tiers have
//! genuinely different false-positive rates:
//!
//! * **[`Confidence::Notable`]** for directories nothing installs into:
//!   temporary directories, the recycle bin, the root of the volume,
//!   `\Users\Public`, a browser cache. A program that runs at boot from
//!   `\AppData\Local\Temp` was not put there by an installer.
//! * **[`Confidence::Weak`]** for user-writable directories that legitimate
//!   software uses constantly — `\AppData\Roaming`, `\AppData\Local`,
//!   `\ProgramData`, a user's profile. Teams, Spotify, Dropbox, Slack and every
//!   Electron application in existence persist from exactly there, so this
//!   fires on healthy machines and is ranked where it belongs.
//! * **nothing at all** for the system and program directories, and for
//!   anything this build cannot resolve to a path — an unexpanded environment
//!   variable, a bare DLL name that Windows resolves from the system directory.
//!   A classification of a path we do not have is a guess with a sentence
//!   attached.
//!
//! The second detection here is the inverse: persistence pointing at a file
//! that was not recovered. It is [`Confidence::Weak`] and only raised at all
//! when the file index was complete enough for the answer to mean anything,
//! because an uninstaller that deletes the image and leaves the run key behind
//! produces it on every machine that has ever had software removed.

use crate::prelude::*;

/// The record type the ASEP enumerator writes.
const ASEP_RECORD_TYPE: &str = "AsepEntry";

/// The module id, written once so every finding cites the same source.
const ASEP_MODULE_ID: &str = "plugin.findings.asep";

/// How a directory rates as a place to install software.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Location {
    /// A system or program directory: where software belongs.
    Standard,
    /// User-writable and used by a great deal of legitimate software.
    UserWritable(&'static str),
    /// Nothing installs into it.
    Unexpected(&'static str),
}

/// Directories nothing ordinarily persists from, longest-prefix first so
/// `/users/x/appdata/local/temp` is not read as `/users/x/appdata/local`.
///
/// Matched against the ASEP record's normalised lookup path: lower-case,
/// forward slashes, drive letter removed, leading separator guaranteed.
const UNEXPECTED: &[(&str, &str)] = &[
    ("/appdata/local/temp/", "the user's temporary directory"),
    (
        "/appdata/local/microsoft/windows/inetcache/",
        "the Internet Explorer / Edge download cache",
    ),
    (
        "/appdata/local/microsoft/windows/temporary internet files/",
        "the Internet Explorer cache",
    ),
    ("/windows/temp/", "the system temporary directory"),
    ("/winnt/temp/", "the system temporary directory"),
    ("/winnt/debug/", "the Windows debug directory"),
    ("/temp/", "a temporary directory"),
    ("/tmp/", "a temporary directory"),
    ("/$recycle.bin/", "the recycle bin"),
    ("/recycler/", "the recycle bin"),
    ("/perflogs/", "the performance-log directory"),
    ("/users/public/", "the Public user profile"),
    ("/downloads/", "a downloads directory"),
    ("/windows/debug/", "the Windows debug directory"),
];

/// User-writable directories a great deal of legitimate software uses.
const USER_WRITABLE: &[(&str, &str)] = &[
    ("/appdata/roaming/", "the user's roaming application data"),
    ("/appdata/local/", "the user's local application data"),
    (
        "/programdata/",
        "the machine-wide application data directory",
    ),
    ("/users/", "a user profile"),
    // The pre-Vista profile root, long and short.
    ("/documents and settings/", "a user profile"),
    ("/docume~1/", "a user profile"),
];

/// Where software belongs. Checked first, so a program directory nested under
/// a user profile — which no ordinary install produces, but which exists — is
/// not reported twice.
const STANDARD: &[&str] = &[
    "/windows/system32/",
    "/windows/syswow64/",
    "/program files/",
    "/program files (x86)/",
    "/windows/",
    "/programdata/microsoft/windows/start menu/",
    // The Windows directory on 2000 and XP installs upgraded rather than
    // clean-installed.
    "/winnt/",
    // **8.3 short names.** The registry is full of them: on an XP install the
    // Active Setup, COM server and shell-extension paths are written
    // `C:\PROGRA~1\...` as often as not, and a classifier that did not fold
    // them graded 42 genuine Program Files entries as "outside the system and
    // program directories" on the CFReDS Hacking Case.
    //
    // `progra~1` means "the first directory whose name begins with `progra`",
    // not literally Program Files, so this is a convention rather than a
    // certainty. It is accepted in this direction deliberately: being wrong
    // here SUPPRESSES a lead, and a heuristic that errs towards silence is the
    // only kind that belongs in a triage list.
    "/progra~1/",
    "/progra~2/",
    // **The Startup folder is where startup items belong.** The
    // `startup_folder_redirect` values name it by design, and grading the
    // default location as "a user profile" put five rows on the Hacking Case's
    // triage list that said nothing more than "Windows is installed". Where a
    // redirect points somewhere else, `seance_plugin_asep` says so itself with
    // its `startup_folder_not_default_location` observation — this classifier
    // has no business repeating that judgement from the path alone.
    "/documents and settings/all users/start menu/programs/startup/",
    "/appdata/roaming/microsoft/windows/start menu/programs/startup/",
    "/programdata/microsoft/windows/start menu/programs/startup/",
];

/// A path that is the per-user Startup folder, or something inside it.
///
/// The profile name is arbitrary, so this cannot be a prefix match like the
/// entries above: `/documents and settings/mr. evil/start menu/programs/startup`
/// and `/users/jsmith/appdata/roaming/microsoft/windows/start menu/programs/startup`
/// are both the default location for their era.
///
/// Matched against the **whole path** rather than its parent directory,
/// because a `startup_folder_redirect` value names the folder itself — the
/// folder is the target, not a file in it — while a shortcut inside it names a
/// file. Both are the default location.
fn is_a_startup_folder(path: &str) -> bool {
    path.contains("/start menu/programs/startup")
}

/// Whether the value the entry stored is a **path** at all.
///
/// The guard the classifier could not do without, and the run that found that
/// out is on the record. `normalize_target` guarantees its output a leading
/// `/`, so a bare program name arrives as `/regsvr32.exe` — shaped exactly like
/// a file at the root of the volume. On the CFReDS Hacking Case that produced
/// **742 leads**: COM in-process servers (470), `KnownDLLs` (80), shell
/// extensions (65), netsh helpers, Winlogon notify packages, print monitors and
/// LSA packages, every one of them a DLL Windows resolves **by name from the
/// system directory**. `seance_plugin_asep` says exactly that itself, in its
/// `package_name_not_a_path` observation; this classifier ignored it.
///
/// So the RAW value is consulted rather than the normalised one: a path carries
/// a separator or a drive letter, a bare token carries neither. That keeps a
/// genuine `C:\dropper.exe` classifiable — the case the root-of-volume arm
/// exists to catch — while declining the name Windows is going to resolve for
/// itself.
///
/// `None` (the entry recorded no image at all) is not a path.
fn is_a_path(raw: Option<&str>) -> bool {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    // The **first token only**, and the reason is a second false positive from
    // the same run: `BootExecute` holds `autoconv \??\Volume{…} /fs:ntfs`, whose
    // *argument* carries separators while the image — `autoconv` — does not.
    // Reading the whole string called that a path and reported a lead about the
    // root of the volume. An image is the first whitespace-delimited token
    // unless it was quoted, and a quoted path keeps its quotes here, so
    // trimming them is what makes the token the image in both spellings.
    let first = raw
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches('"');
    if first.is_empty() {
        return false;
    }
    let bytes = first.as_bytes();
    let drive_letter =
        bytes.first().is_some_and(u8::is_ascii_alphabetic) && bytes.get(1) == Some(&b':');
    drive_letter || first.contains('\\') || first.contains('/')
}

/// Classify the directory an image sits in.
///
/// `None` when no claim may be made: an unexpanded environment variable, a
/// value that is not a path at all ([`is_a_path`]), or one that will not reduce
/// to a directory and a file.
fn classify(lookup: &str, raw_image: Option<&str>) -> Option<Location> {
    let p = lookup.trim();
    if p.is_empty() || p.contains('%') || !p.starts_with('/') {
        return None;
    }
    // Before anything is read off the normalised form: was it a path?
    if !is_a_path(raw_image) {
        return None;
    }
    let (dir, file) = p.rsplit_once('/')?;
    if file.is_empty() {
        return None;
    }
    let dir = format!("{dir}/");

    if dir == "/" {
        return Some(Location::Unexpected("the root of the volume"));
    }
    // The unexpected directories are tested BEFORE the standard ones, and the
    // order matters: `\Windows\Temp` and `\Windows\Debug` both sit under
    // `\Windows`, so checking "is this a system directory" first would swallow
    // them and the interesting tier would be empty on exactly the machines it
    // exists for. The same rule makes `\Program Files\App\temp` a temporary
    // directory rather than a program directory, which is the reading intended:
    // an install directory is where a program lives, not where it persists from.
    if let Some((_, what)) = UNEXPECTED.iter().find(|(pre, _)| dir.contains(*pre)) {
        return Some(Location::Unexpected(what));
    }
    if STANDARD.iter().any(|s| dir.starts_with(s)) || is_a_startup_folder(p) {
        return Some(Location::Standard);
    }
    if let Some((_, what)) = USER_WRITABLE.iter().find(|(pre, _)| dir.starts_with(*pre)) {
        return Some(Location::UserWritable(what));
    }
    // Somewhere else entirely: a directory at the top level of the volume that
    // is neither Windows nor Program Files. Plenty of software is installed to
    // one deliberately (`C:\Tools`, a game library), so this is the weak tier.
    Some(Location::UserWritable(
        "a directory outside the system and program directories",
    ))
}

/// Raises leads from an `AsepEntry` record.
#[derive(Debug, Default)]
pub struct AsepFindings;

impl AsepFindings {
    pub fn new() -> Self {
        Self
    }

    /// The findings for one ASEP record, or none.
    pub fn findings_for(&self, artifact: &Artifact) -> Vec<Finding> {
        if meta_str(artifact, "type").as_deref() != Some(ASEP_RECORD_TYPE) {
            return Vec::new();
        }
        // An entry the enumerator could not read has no image to judge, and the
        // record already says so. Raising a finding from it would be a claim
        // about a value nobody has seen.
        if meta_str(artifact, "read_status").as_deref() == Some("unread") {
            return Vec::new();
        }

        let mut out = Vec::new();
        if let Some(f) = self.unexpected_location(artifact) {
            out.push(f);
        }
        if let Some(f) = self.absent_target(artifact) {
            out.push(f);
        }
        if let Some(f) = self.unrecognised_system_service(artifact) {
            out.push(f);
        }
        out
    }

    /// Where the entry says its image lives, and what to call it.
    fn image(&self, artifact: &Artifact) -> Option<(String, String)> {
        let lookup = meta_str(artifact, "target_lookup_path")?;
        let shown = meta_str(artifact, "image_path")
            .or_else(|| meta_str(artifact, "command"))
            .unwrap_or_else(|| lookup.clone());
        Some((lookup, shown))
    }

    /// What this entry is, in the enumerator's own words.
    fn what(&self, artifact: &Artifact) -> String {
        meta_str(artifact, "category_label")
            .or_else(|| meta_str(artifact, "category"))
            .unwrap_or_else(|| "an autostart entry".to_string())
    }

    /// Shared evidence: the address of the persistence and what it runs.
    fn base_evidence(&self, artifact: &Artifact) -> Vec<EvidenceItem> {
        let mut evidence = Vec::new();
        for key in [
            "category",
            "asep_location",
            "asep_value_name",
            "image_path",
            "command",
            "arguments",
            "scope",
            "user",
            "runs_when",
            "mitre_technique",
            "installed_time",
        ] {
            if let Some(v) = meta_str(artifact, key) {
                evidence.push(EvidenceItem::new(key, v));
            }
        }
        if let Some(b) = artifact.metadata.get("enabled").and_then(|v| v.as_bool()) {
            evidence.push(EvidenceItem::new("enabled", b.to_string()));
        }
        evidence
    }

    /// Persistence whose image sits somewhere software is not installed.
    fn unexpected_location(&self, artifact: &Artifact) -> Option<Finding> {
        let (lookup, shown) = self.image(artifact)?;
        // The RAW value decides whether there is a path to classify; see
        // `is_a_path`. `command` is deliberately not a fallback: a command line
        // is not a path either, and `image_path` is where the enumerator puts
        // an image when it could separate one from the arguments.
        let location = classify(&lookup, meta_str(artifact, "image_path").as_deref())?;
        let (what_dir, confidence) = match location {
            Location::Standard => return None,
            Location::Unexpected(what) => (what, Confidence::Notable),
            Location::UserWritable(what) => (what, Confidence::Weak),
        };
        let what = self.what(artifact);

        let mut evidence = self.base_evidence(artifact);
        evidence.push(EvidenceItem::new("target_lookup_path", lookup.clone()));
        if let Some(v) = meta_str(artifact, "target_path_expansion") {
            evidence.push(EvidenceItem::new("target_path_expansion", v));
        }

        // The weak tier fires on healthy machines and says so; the notable tier
        // names what an ordinary install would have done instead.
        let qualification = match location {
            Location::Unexpected(_) => format!(
                "This does not establish that the entry is unwanted, or that it ever ran. \
                 Séance judged the directory, not the program: an installer that ran from a \
                 temporary copy, a portable application a user placed there deliberately, and \
                 software a vendor genuinely ships this way all produce the same record. \
                 Whether {what_dir} is an unreasonable place for this particular program to \
                 run from is the examiner's determination. Nothing here examined the image \
                 itself, its signature, or any evidence that it executed."
            ),
            _ => format!(
                "This is a weak lead and is ranked last accordingly. {} is user-writable and a \
                 very large amount of ordinary software persists from it — messaging clients, \
                 updaters and most applications packaged for per-user install — so this \
                 finding is expected on a healthy machine and means little on its own. It is \
                 here because it is cheap to check and because it is worth reading beside a \
                 finding about the same image. Nothing here examined the image, its signature \
                 or any evidence that it executed.",
                capitalise(what_dir),
            ),
        };

        Some(Finding {
            kind: "persistence_in_unexpected_location".to_string(),
            title: format!("{} runs {shown} from {what_dir}", capitalise(&what)),
            subject_artifact: subject_of(artifact),
            confidence,
            observation: format!(
                "{what} at {} names the image {shown}, which resolves to {lookup} — inside \
                 {what_dir} rather than a system or program directory.",
                meta_str(artifact, "asep_location").unwrap_or_else(|| "this location".into()),
            ),
            evidence,
            inference: match location {
                Location::Unexpected(_) => Some(
                    "Software installed by an installer runs from the directory it was \
                     installed into. Persistence pointing somewhere else is persistence that \
                     was not set up by an install."
                        .to_string(),
                ),
                // No inference on the weak tier: any reading of it would be
                // this tool's invention, and the honest answer is that the
                // location means very little.
                _ => None,
            },
            qualification,
            device_offset: device_offset_of(artifact),
            source_module: ASEP_MODULE_ID.to_string(),
        })
    }

    /// An auto-start own-process service whose image is spelled as a literal
    /// drive-letter path into `System32` or `SysWOW64` (HUNT-276).
    ///
    /// Installed Windows and vendor services write `ImagePath` as a
    /// `%SystemRoot%\system32\...` expandable string; a literal `C:\Windows\
    /// System32\x.exe` was the only own-process auto-start spelling of it seen on the Case 001 machines.
    /// That is the whole signal, so it is a weak lead and no stronger: see the
    /// measurement in VALIDATION.md "HUNT-276 / C001-FIND-1 re-measure".
    fn unrecognised_system_service(&self, artifact: &Artifact) -> Option<Finding> {
        if meta_str(artifact, "category").as_deref() != Some("service") {
            return None;
        }
        let start = artifact.metadata.get("service_start_type")?.as_u64()?;
        let kind = artifact.metadata.get("service_type")?.as_u64()?;
        // Automatic start, own-process (0x10) user-mode service: the shape that
        // was measured. Drivers, shared-process hosts, manual and disabled starts
        // are out.
        if start != 2 || kind & 0x10 == 0 || kind & 0x3 != 0 {
            return None;
        }
        // Only a target that was found. Anything else is a question not asked.
        if meta_str(artifact, "target_exists").as_deref() != Some("observed_at_path") {
            return None;
        }
        let raw = meta_str(artifact, "image_path")?;
        let image = raw.trim().trim_matches('"');
        let lower = image.to_ascii_lowercase();
        let b = lower.as_bytes();
        let literal = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
        let in_system_dir = lower[if literal { 2 } else { 0 }..]
            .starts_with("\\windows\\system32\\")
            || lower[if literal { 2 } else { 0 }..].starts_with("\\windows\\syswow64\\");
        if !literal || !in_system_dir || !lower.ends_with(".exe") {
            return None;
        }
        // The host process every shared service runs in; always spelled
        // literally by some installers and never the implant itself.
        if lower.ends_with("\\svchost.exe") {
            return None;
        }
        // A file the file system says was created before the SOFTWARE hive says setup finished is part of the
        // install, not a service added after it (`HUNT-276`: Microsoft's own MSDTC on a clean Server 2003).
        // Both times must be present and read; otherwise nothing is compared and the lead stands.
        if created_before_install(artifact) {
            return None;
        }
        // A service in the setup-time copy of the SYSTEM hive under \Windows\repair was registered during setup, so it
        // predates the install whichever order the hives were read in; the live hive is judged on its own.
        if meta_str(artifact, "hive_path").is_some_and(|p| {
            let p = p.replace('\\', "/").to_ascii_lowercase();
            p.starts_with("/windows/repair/") || p.starts_with("/winnt/repair/")
        }) {
            return None;
        }

        let what = self.what(artifact);
        let name = meta_str(artifact, "entry_name").unwrap_or_else(|| "(unnamed)".into());
        let account =
            meta_str(artifact, "service_account").unwrap_or_else(|| "(not recorded)".into());
        let mut evidence = self.base_evidence(artifact);
        for key in [
            "service_start_type",
            "service_type",
            "service_account",
            "target_exists",
            "target_created",
            "os_install_time",
            "os_install_time_basis",
        ] {
            if let Some(v) = artifact.metadata.get(key) {
                let v = v
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string());
                evidence.push(EvidenceItem::new(key, v));
            }
        }

        Some(Finding {
            kind: "service_binary_unrecognised_in_system_directory".to_string(),
            title: format!("Service {name} runs {image} from the Windows system directory"),
            subject_artifact: subject_of(artifact),
            confidence: Confidence::Weak,
            observation: format!(
                "{what} {name} starts automatically as {account} and names the image {image}, \
                 written as a literal drive-letter path into the Windows system directory, and \
                 a file was recovered at that path."
            ),
            evidence,
            inference: None,
            qualification: "Séance did not examine the file, its signature or its hash. The rule \
                compares how the image path is spelled and where it points, nothing more. Windows \
                components and vendor services also live in System32, and most stock ones are \
                written with %SystemRoot%, but not all: the rule raised a lead on a clean \
                Windows Server 2003 R2 SP2 x64 install, for Microsoft's own MSDTC service, which \
                is spelled with a literal path. This rule exists because the implant service was \
                a literal drive-letter path in the two Case 001 images, and that also \
                means it is trivially evaded by writing the path with %SystemRoot%. Measured over \
                the images held at 2026-10-22 it raised one lead on each of the two Case 001 \
                machines (the known implant), none on the LoneWolf Windows 10 workstation \
                (776 services), a fresh Windows 11 install or a fresh Windows Server 2022 \
                install, and one false lead (three rows, two control sets) on the clean Server \
                2003, so it is ranked weak and will stay weak. Where the record carries both \
                the file's creation time and the system's install time (the SOFTWARE hive's \
                InstallDate) and the file was created first, no lead is raised, which removes \
                that false lead; a file's creation time is a $STANDARD_INFORMATION time that the \
                program it describes can set, so an implant with a back-dated creation time is \
                not seen either. Where either time is missing the lead is raised as before, and the record says whether the install time had been read when the entry was made. A service read from the setup-time copy of the SYSTEM hive under \\Windows\\repair is not raised either: it was registered during setup, and that copy is read before the SOFTWARE hive holds the install time."
                .to_string(),
            device_offset: device_offset_of(artifact),
            source_module: ASEP_MODULE_ID.to_string(),
        })
    }

    /// Persistence pointing at a file that was not recovered.
    fn absent_target(&self, artifact: &Artifact) -> Option<Finding> {
        // Only the one status means "looked for it and did not find it". Every
        // other value — no file index, a name-only match, an unexpanded
        // variable — is a question that was not asked.
        if meta_str(artifact, "target_exists").as_deref() != Some("not_observed") {
            return None;
        }
        // The index holds executable-like files only and can fill up. Either
        // condition makes "not observed" an artefact of the search rather than
        // a fact about the volume, and the enumerator records both.
        if artifact
            .metadata
            .get("target_index_capped")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return None;
        }
        let indexed = artifact
            .metadata
            .get("target_index_executable_names")
            .and_then(|v| v.as_u64())
            .filter(|n| *n > 0)?;

        let (lookup, shown) = self.image(artifact)?;
        let what = self.what(artifact);
        let basis = meta_str(artifact, "target_exists_basis");

        let mut evidence = self.base_evidence(artifact);
        evidence.push(EvidenceItem::new("target_exists", "not_observed"));
        evidence.push(EvidenceItem::new("target_lookup_path", lookup.clone()));
        evidence.push(EvidenceItem::new(
            "target_index_executable_names",
            indexed.to_string(),
        ));
        if let Some(b) = &basis {
            evidence.push(EvidenceItem::new("target_exists_basis", b.clone()));
        }

        Some(Finding {
            kind: "persistence_target_not_recovered".to_string(),
            title: format!(
                "{} points at a file that was not recovered: {shown}",
                capitalise(&what)
            ),
            subject_artifact: subject_of(artifact),
            // Weak, and the qualification explains why: every machine that has
            // ever had software uninstalled has some of these.
            confidence: Confidence::Weak,
            observation: format!(
                "{what} names the image {shown}, and no file was recovered at {lookup} among \
                 the {indexed} executable names enumerated from this evidence."
            ),
            evidence,
            inference: None,
            qualification: format!(
                "This does not establish that the file is absent from the volume, and it is \
                 ranked last because the ordinary cause is mundane: an uninstaller that \
                 removes a program's files and leaves its autostart entry behind produces \
                 exactly this, on every machine that has had software removed. Séance \
                 compared against the {indexed} executable-like files it enumerated — not the \
                 whole volume, and not non-executable targets — so an unreadable or \
                 unallocated region, a second volume, or a file this build does not treat as \
                 executable would all leave the target unseen. The enumerator's own basis is \
                 in the evidence above and is the sentence to quote."
            ),
            device_offset: device_offset_of(artifact),
            source_module: ASEP_MODULE_ID.to_string(),
        })
    }
}

/// Upper-case the first character, for a title built from a label.
fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

impl ForensicsModule for AsepFindings {
    fn id(&self) -> &str {
        ASEP_MODULE_ID
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::ParsedRecord]
    }

    /// Reads no bytes at all, only the metadata the ASEP enumerator wrote.
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        emit(artifact, self.findings_for(artifact))
    }
}

/// Whether the record's file was created at or before the time the system finished installing. False when
/// either time is missing or does not parse: nothing is then compared.
fn created_before_install(artifact: &Artifact) -> bool {
    let parse = |key: &str| {
        let text = meta_str(artifact, key)?;
        chrono::DateTime::parse_from_rfc3339(text.trim()).ok()
    };
    match (parse("target_created"), parse("os_install_time")) {
        (Some(created), Some(installed)) => created <= installed,
        _ => false,
    }
}
