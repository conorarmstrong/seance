//! Path, registry-key and command-line normalisation shared by every ASEP rule.
//!
//! Every function here is pure and total: it is fed strings that came out of
//! evidence (registry value data, reconstructed filesystem paths, shortcut
//! targets) and must never panic, never index out of bounds and never invent a
//! value it did not read.
//!
//! What an examiner gets from this module is the ability to compare an ASEP's
//! stored target — which may be quoted, drive-lettered, `\??\`-prefixed,
//! `%SystemRoot%`-relative or plain sloppy — against the paths actually
//! recovered from the volume. A wrong answer here looks like an autostart entry
//! whose target is reported as "not observed on this volume" when the file is
//! sitting right there under a different spelling of the same path, or the
//! reverse: a target claimed present because two unrelated files share a name.
//! Both are load-bearing in a report, so every transformation this module
//! applies is recorded alongside the result rather than applied silently.

/// Executable-ish extensions. A file with one of these is a plausible ASEP
/// target and is worth indexing for the "does the target exist" question; a
/// `.docx` is not.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "com", "bat", "cmd", "scr", "ps1", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "cpl", "ocx", "msc", "jar", "pif", "hta", "msi", "efi", "drv",
];

/// Extensions that terminate the image portion of an unquoted command line.
/// Ordered longest-first is unnecessary — the earliest boundary in the string
/// wins — but every entry must be a real Windows executable extension, because
/// finding one is what licences the split.
const COMMAND_BOUNDARY_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".scr", ".ps1", ".vbs", ".js", ".cpl", ".ocx",
    ".msc", ".jar", ".pif", ".hta", ".msi",
];

/// Lowercase a registry key path into a caller-owned buffer, normalising every
/// separator to `\`.
///
/// Registry key paths arrive from the hive walker with `\` separators, but the
/// same helpers are used against filesystem-derived strings, so both are
/// accepted. Comparisons downstream are all done against the result of this
/// function; comparing a raw key path would make matching depend on the casing
/// the installer happened to use.
///
/// The buffer is caller-owned so that a scan over hundreds of thousands of
/// registry values allocates once rather than once per value.
pub fn key_lower_into(key_path: &str, out: &mut String) {
    out.clear();
    for ch in key_path.chars() {
        if ch == '/' {
            out.push('\\');
        } else if ch.is_ascii_uppercase() {
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii() {
            out.push(ch);
        } else {
            for lower in ch.to_lowercase() {
                out.push(lower);
            }
        }
    }
}

/// True when `lower` ends with `suffix_lower` on a **whole key segment**
/// boundary.
///
/// Suffix matching is what lets one rule cover `HKLM\SOFTWARE\Microsoft\...\Run`,
/// its `Wow6432Node` twin and the `CMI-CreateHive{...}`-rooted form an offline
/// hive actually presents. A naive `ends_with` would also match a key literally
/// named `...\NotRun`, which would put a fabricated entry in the report.
pub fn ends_with_key(lower: &str, suffix_lower: &str) -> bool {
    if suffix_lower.is_empty() || !lower.ends_with(suffix_lower) {
        return false;
    }
    let idx = lower.len().saturating_sub(suffix_lower.len());
    idx == 0 || lower.as_bytes().get(idx.saturating_sub(1)) == Some(&b'\\')
}

/// The single key segment that immediately follows `marker_lower`.
///
/// Used to pull `<ServiceName>` out of `...\Services\<ServiceName>\Parameters`
/// and `<clsid>` out of `...\CLSID\{...}\InprocServer32`. Returns `None` when
/// the marker is absent or is the last thing in the path — never an empty
/// string, because "" and "absent" must not be confusable.
pub fn segment_after<'a>(lower: &'a str, marker_lower: &str) -> Option<&'a str> {
    let pos = lower.find(marker_lower)?;
    let start = pos.checked_add(marker_lower.len())?;
    let rest = lower.get(start..)?;
    let seg = match rest.find('\\') {
        Some(end) => rest.get(..end)?,
        None => rest,
    };
    if seg.is_empty() {
        None
    } else {
        Some(seg)
    }
}

/// Everything after `marker_lower` and the segment that follows it, i.e. the
/// tail below `...\Services\<name>`. `None` when there is no tail.
pub fn tail_after_segment<'a>(lower: &'a str, marker_lower: &str) -> Option<&'a str> {
    let pos = lower.find(marker_lower)?;
    let start = pos.checked_add(marker_lower.len())?;
    let rest = lower.get(start..)?;
    let end = rest.find('\\')?;
    let tail = rest.get(end.checked_add(1)?..)?;
    if tail.is_empty() {
        None
    } else {
        Some(tail)
    }
}

/// The last `\`-separated segment of a key path (the key's own name).
pub fn last_segment(lower: &str) -> &str {
    lower.rsplit('\\').next().unwrap_or(lower)
}

/// Strip one layer of matching double quotes, plus surrounding whitespace.
pub fn strip_quotes(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t.get(1..t.len().saturating_sub(1)).unwrap_or(t).trim()
    } else {
        t
    }
}

/// How the image was separated from its arguments, recorded on every entry.
///
/// An examiner reading `image_path` needs to know whether the split was
/// unambiguous (the command quoted its image, or ended it with a real
/// executable extension) or whether the whole string was kept because no
/// boundary could be found. Presenting a guessed split as a certain one is how
/// `C:\Program Files\Foo\bar.exe` becomes the non-existent `C:\Program`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitBasis {
    /// The image was wrapped in double quotes.
    QuotedImage,
    /// The image ended at a recognised executable extension.
    ExecutableExtension,
    /// The first space-delimited token is a bare program name — no directory,
    /// drive or extension — and a later token ends in an executable extension:
    /// the name is the image, resolved on the search path, and the rest are its
    /// arguments (`cscript KernCap.vbs`). `CreateProcess` tries the shortest
    /// space-delimited prefix first, so this is the one Windows would run.
    BareProgramName,
    /// No boundary was found; the entire value is reported as the image and no
    /// arguments are claimed.
    WholeValueNoBoundary,
}

impl SplitBasis {
    /// Stable string form written into the record.
    pub fn as_str(self) -> &'static str {
        match self {
            SplitBasis::QuotedImage => "quoted_image",
            SplitBasis::ExecutableExtension => "executable_extension_boundary",
            SplitBasis::BareProgramName => "bare_program_name_first_token",
            SplitBasis::WholeValueNoBoundary => "whole_value_no_boundary_found",
        }
    }
}

/// An ASEP command line split into the image that would execute and its
/// arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSplit {
    /// The image, exactly as stored in evidence (quotes removed, nothing else).
    pub image: String,
    /// Arguments, or `None` when there are none or none could be identified.
    pub arguments: Option<String>,
    /// Why the split fell where it did.
    pub basis: SplitBasis,
}

/// Split an ASEP command line into image and arguments without ever guessing at
/// a space.
///
/// Returns `None` for an empty or whitespace-only value: an ASEP value that
/// holds nothing is not an entry, and emitting one with an empty image would
/// put a phantom autostart in the report.
pub fn split_command(raw: &str) -> Option<CommandSplit> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            let image = rest.get(..end)?.trim().to_string();
            if image.is_empty() {
                return None;
            }
            let args = rest
                .get(end.checked_add(1)?..)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            return Some(CommandSplit {
                image,
                arguments: args,
                basis: SplitBasis::QuotedImage,
            });
        }
        // An unterminated quote is malformed; fall through and treat the whole
        // value as the image rather than inventing a closing quote.
    }

    let lower = trimmed.to_ascii_lowercase();
    let mut boundary: Option<usize> = None;
    for ext in COMMAND_BOUNDARY_EXTENSIONS {
        let mut from = 0usize;
        while let Some(rel) = lower.get(from..).and_then(|s| s.find(ext)) {
            let start = from.checked_add(rel)?;
            let end = start.checked_add(ext.len())?;
            let next = lower.as_bytes().get(end).copied();
            let terminates = match next {
                None => true,
                Some(b) => b == b' ' || b == b'\t' || b == b'"',
            };
            if terminates {
                boundary = Some(match boundary {
                    Some(existing) => existing.min(end),
                    None => end,
                });
                break;
            }
            from = end;
        }
    }

    // A boundary past the first token, where that token is a bare program name
    // (no directory separator, drive colon or dot): the name is the image and
    // the extension belongs to an argument. `C:\Program Files\…` is untouched —
    // its first token carries a separator.
    if let (Some(end), Some(space)) = (boundary, trimmed.find([' ', '\t'])) {
        let first = trimmed.get(..space)?;
        let bare = !first.contains(['\\', '/', ':', '.', '"', '%']);
        if bare && space < end {
            return Some(CommandSplit {
                image: first.to_string(),
                arguments: trimmed
                    .get(space..)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                basis: SplitBasis::BareProgramName,
            });
        }
    }

    match boundary {
        Some(end) => {
            let image = trimmed.get(..end)?.trim().to_string();
            if image.is_empty() {
                return None;
            }
            let args = trimmed
                .get(end..)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            Some(CommandSplit {
                image,
                arguments: args,
                basis: SplitBasis::ExecutableExtension,
            })
        }
        None => Some(CommandSplit {
            image: trimmed.to_string(),
            arguments: None,
            basis: SplitBasis::WholeValueNoBoundary,
        }),
    }
}

/// A target path reduced to the form used to look it up against the files
/// recovered from the volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPath {
    /// Volume-relative, `/`-separated, lowercase.
    pub lookup: String,
    /// The substitution that was applied to get there, if any. Recorded so the
    /// report never presents an expanded path as the stored one.
    pub expansion: Option<&'static str>,
    /// The path still contains a `%VARIABLE%` that could not be resolved
    /// without a live environment. A full-path comparison is meaningless when
    /// this is set.
    pub has_unexpanded_variable: bool,
    /// Set when the image is a bare program name (`cscript`, `rundll32.exe`):
    /// no directory, drive or variable, so Windows finds it on the search path
    /// rather than at the volume root. Holds every volume-relative path the
    /// search would try, in order ([`TargetPath::search_path_directories`]
    /// outer, the [`SearchRule`]'s extensions inner for a name with no
    /// extension of its own). `lookup` is then the first candidate, which is a
    /// **convention**, not an observation, until the file index answers
    /// (`HUNT-241`).
    pub search_path_candidates: Vec<String>,
    /// For a bare program name, the directories tried, in order (`HUNT-244`):
    /// the entry's working directory when the source records one, then
    /// [`SEARCH_PATH_DIRECTORIES`].
    pub search_path_directories: Vec<SearchDirectory>,
    /// The rule that chose the extensions appended to a bare name.
    pub search_rule: SearchRule,
    /// Why a working directory the source recorded was not tried, when it was
    /// not (an unexpanded variable, or no path could be formed from it).
    pub working_directory_not_tried: Option<String>,
}

/// The directories a bare program name is resolved against, in the order
/// tried, as (volume-relative lookup prefix, display form). This is the
/// system part of the Windows search order — `System32`, its WOW64 twin, then
/// the Windows directory. The launching process's own directory, its current
/// directory and the `PATH` variable are not modelled: they need a live
/// process and environment the evidence does not hold. A working directory
/// the entry itself records is tried before these (`HUNT-244`, see
/// [`SearchContext`]).
pub const SEARCH_PATH_DIRECTORIES: &[(&str, &str)] = &[
    ("/windows/system32", "\\Windows\\System32"),
    ("/windows/syswow64", "\\Windows\\SysWOW64"),
    ("/windows", "\\Windows"),
];

/// The default `PATHEXT` executable extensions, in their default order,
/// appended to a bare name that carries no executable extension of its own.
/// This is the command shell's rule ([`SearchRule::ShellPathext`]).
pub const PATHEXT_DEFAULT: &[&str] = &[".com", ".exe", ".bat", ".cmd"];

/// Which rule decides the extensions appended to a bare program name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchRule {
    /// The command shell's rule: a name with no executable extension is tried
    /// with each [`PATHEXT_DEFAULT`] extension in turn. Applied to every
    /// source whose launcher is not known to call `CreateProcess` directly;
    /// whether that launcher applies `PATHEXT` is not established.
    #[default]
    ShellPathext,
    /// `CreateProcess`'s rule: a file name with no extension has `.exe`
    /// appended, and nothing else is tried; a name with any extension is taken
    /// as it is. Applied where the source's properties are documented as
    /// `CreateProcess` parameters (a WMI `CommandLineEventConsumer`).
    CreateProcessExeOnly,
    /// The source's documented contract is a fully qualified path, so a bare
    /// program name is outside it and how its launcher resolves one is not
    /// documented (`HUNT-249`). The shell's [`PATHEXT_DEFAULT`] list is still
    /// tried, as leads for the examiner, never as the launcher's rule.
    FullPathRequired(FullPathSource),
    /// The launcher's rule was observed by running it on a live Windows
    /// (`HUNT-249`, `tests/fixtures/launcher_rules/`): one build, stated in
    /// the record, so a match is the file that launcher would start there.
    Observed(ObservedLauncher),
}

/// A launcher whose bare-name rule was observed on Windows 11 25H2, build
/// 26200.6584 (`HUNT-249`, `documentation/VALIDATION.md` `LAUNCH-1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedLauncher {
    /// The service control manager starting an own-process service's
    /// `ImagePath`: `.exe` only.
    ServiceOwnProcess,
    /// An Image File Execution Options `Debugger`, started in place of an
    /// image launched through `CreateProcess`: `.exe` only.
    IfeoDebugger,
    /// An element of Winlogon's `Userinit` list: `.exe` only.
    WinlogonUserinit,
    /// Explorer's `Run` and `runonce.exe`'s `RunOnce` processing:
    /// [`RUN_KEY_EXTENSIONS`].
    RunKey,
    /// Task Scheduler's `Exec` action `Command`: [`PATHEXT_WINDOWS_DEFAULT`].
    TaskExec,
}

impl ObservedLauncher {
    /// The sentence the basis carries: what was run, on which build, and what
    /// was not tested. Every statement ends by bounding itself to that build.
    fn statement(self) -> &'static str {
        match self {
            ObservedLauncher::ServiceOwnProcess => {
                "On Windows 11 build 26200.6584 the service control manager started an \
                 own-process service whose ImagePath was a bare name only from a .exe copy; \
                 .com, .bat, .cmd and .vbs copies failed with error 2. Other Windows \
                 versions were not tested, and a share-process service was not run."
            }
            ObservedLauncher::IfeoDebugger => {
                "On Windows 11 build 26200.6584 an Image File Execution Options Debugger \
                 holding a bare name was started only from a .exe copy when the target was \
                 launched through CreateProcess; .com, .bat and .cmd copies failed. A target \
                 launched through ShellExecute was not tested, and other Windows versions \
                 were not tested."
            }
            ObservedLauncher::WinlogonUserinit => {
                "On Windows 11 build 26200.6584 a bare element of Winlogon's Userinit list \
                 ran only from a .exe copy; .com, .bat, .cmd, .vbs, .js and .ps1 copies \
                 failed with Winlogon event 4006. Winlogon's Shell value was not tested. \
                 Other Windows versions were not tested."
            }
            ObservedLauncher::RunKey => {
                "On Windows 11 build 26200.6584 Explorer (Run) and runonce.exe (RunOnce) \
                 started a bare name from .com, .exe, .bat, .cmd and, under HKLM Run, .pif \
                 copies, .com first, and also resolved App Paths; .vbs, .js and .lnk \
                 copies did not run. The place of .pif in the order, .pif under the other \
                 keys, and other Windows versions were not tested."
            }
            ObservedLauncher::TaskExec => {
                "On Windows 11 build 26200.6584 Task Scheduler searched a bare Exec command \
                 with the machine's PATHEXT, here assumed to be the Windows default because \
                 the machine's own value, kept in the SYSTEM hive, is not read: .com, .exe, \
                 .bat, .cmd, .vbs and .js ran; .ps1, .pif and .lnk did not, and App Paths \
                 was not consulted. Other Windows versions were not tested."
            }
        }
    }

    /// The candidate file names for a lowercase bare program name.
    fn names_for(self, name: &str) -> Vec<String> {
        let with = |exts: &[&str]| exts.iter().map(|e| format!("{name}{e}")).collect();
        match self {
            ObservedLauncher::ServiceOwnProcess
            | ObservedLauncher::IfeoDebugger
            | ObservedLauncher::WinlogonUserinit
                if name.contains('.') =>
            {
                vec![name.to_string()]
            }
            ObservedLauncher::ServiceOwnProcess
            | ObservedLauncher::IfeoDebugger
            | ObservedLauncher::WinlogonUserinit => vec![format!("{name}.exe")],
            _ if is_executable_like(name) => vec![name.to_string()],
            ObservedLauncher::RunKey => with(RUN_KEY_EXTENSIONS),
            ObservedLauncher::TaskExec => with(PATHEXT_WINDOWS_DEFAULT),
        }
    }
}

/// The extensions Explorer and `runonce.exe` were seen to try for a bare name
/// in a `Run`/`RunOnce` value, in the precedence seen; `.pif` ran but its place
/// in the order was not tested, so it is tried last (`HUNT-249`).
pub const RUN_KEY_EXTENSIONS: &[&str] = &[".com", ".exe", ".bat", ".cmd", ".pif"];

/// Windows' default system `PATHEXT` value, in its order. Task Scheduler was
/// seen to search a bare `Exec` command with the machine's `PATHEXT`
/// (`HUNT-249`); the machine's own value, kept in the SYSTEM hive, is not read.
pub const PATHEXT_WINDOWS_DEFAULT: &[&str] = &[
    ".com", ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc", ".cpl",
];

/// A source whose Microsoft documentation requires a fully qualified path
/// (`HUNT-249`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullPathSource {
    /// A service's `ImagePath`: `CreateService` documents `lpBinaryPathName`,
    /// which it stores as `ImagePath`, as "the fully qualified path to the
    /// service binary file".
    ServiceImagePath,
    /// A driver's `ImagePath` (`HUNT-249` review): the same `CreateService`
    /// contract, but a driver is loaded by the kernel, not the service control
    /// manager, so the statement names the launcher accordingly.
    DriverImagePath,
    /// An `ImagePath` whose `Type` does not say whether it is a service or a
    /// driver, so the launcher is named as either.
    UnknownTypeImagePath,
    /// An Image File Execution Options `Debugger` value. The only Microsoft
    /// pages found are service-debugging guidance: "Debugging a Service" says
    /// to use "the full path to the debugger", and "Preparing to Debug the
    /// Service Application" "the full path and file name". No general
    /// specification of the value was found, and the statement names that
    /// scope.
    IfeoDebugger,
}

impl SearchRule {
    /// Stable string form written into the record.
    pub fn as_str(self) -> &'static str {
        match self {
            SearchRule::ShellPathext => "shell_pathext",
            SearchRule::CreateProcessExeOnly => "create_process_exe_only",
            SearchRule::FullPathRequired(_) => "full_path_required",
            SearchRule::Observed(ObservedLauncher::RunKey) => "observed_run_key",
            SearchRule::Observed(ObservedLauncher::TaskExec) => "observed_task_pathext",
            SearchRule::Observed(_) => "observed_exe_only",
        }
    }

    /// The sentence the basis carries, naming the rule.
    pub fn statement(self) -> &'static str {
        match self {
            SearchRule::ShellPathext => {
                "The extensions tried are the command shell's PATHEXT list (.com, .exe, \
                 .bat, .cmd); whether this entry's launcher applies that list, rather than \
                 CreateProcess's .exe only, is not established."
            }
            SearchRule::CreateProcessExeOnly => {
                "The extension rule applied is CreateProcess's: a name with no extension \
                 has only .exe appended; the shell's PATHEXT list does not apply."
            }
            SearchRule::FullPathRequired(FullPathSource::ServiceImagePath) => {
                "Microsoft documents a service's ImagePath (CreateService's \
                 lpBinaryPathName) as the fully qualified path to the service binary, so a \
                 bare program name is outside that contract, and how the service control \
                 manager resolves one is not documented. The candidates are the system \
                 directories with the command shell's PATHEXT list (.com, .exe, .bat, .cmd) \
                 appended, tried as leads for the examiner, not as the launcher's rule."
            }
            SearchRule::FullPathRequired(FullPathSource::DriverImagePath) => {
                "Microsoft documents a service or driver's ImagePath (CreateService's \
                 lpBinaryPathName) as the fully qualified path to the binary, so a bare \
                 program name is outside that contract. This entry is a driver, whose image \
                 the kernel loads, and how a bare name is resolved there is not \
                 documented. The \
                 candidates are \\Windows\\System32\\drivers and the system directories \
                 with .sys and the command shell's PATHEXT list (.com, .exe, .bat, .cmd) \
                 appended, tried as leads for the examiner, not as the launcher's rule."
            }
            SearchRule::FullPathRequired(FullPathSource::UnknownTypeImagePath) => {
                "Microsoft documents a service or driver's ImagePath (CreateService's \
                 lpBinaryPathName) as the fully qualified path to the binary, so a bare \
                 program name is outside that contract. This entry's Type does not say \
                 whether it is a service, launched by the service control manager, or a \
                 driver, loaded by the kernel, and how either resolves a bare name is not \
                 documented. The candidates are \\Windows\\System32\\drivers and the system \
                 directories with .sys and the command shell's PATHEXT list (.com, .exe, \
                 .bat, .cmd) appended, tried as leads for the examiner, not as the \
                 launcher's rule."
            }
            SearchRule::FullPathRequired(FullPathSource::IfeoDebugger) => {
                "Microsoft's service-debugging guidance (\"Debugging a Service\", \
                 \"Preparing to Debug the Service Application\") says to set an Image File \
                 Execution Options Debugger value to the full path to the debugger; no \
                 general specification of the value was found. A bare program name is \
                 outside that guidance, and how Windows resolves one is not documented. The \
                 candidates are the system directories with the command shell's PATHEXT \
                 list (.com, .exe, .bat, .cmd) appended, tried as leads for the examiner, \
                 not as the launcher's rule."
            }
            SearchRule::Observed(launcher) => launcher.statement(),
        }
    }

    /// The candidate file names for a lowercase bare program name.
    fn names_for(self, name: &str) -> Vec<String> {
        match self {
            SearchRule::ShellPathext if is_executable_like(name) => vec![name.to_string()],
            SearchRule::ShellPathext => PATHEXT_DEFAULT
                .iter()
                .map(|ext| format!("{name}{ext}"))
                .collect(),
            SearchRule::CreateProcessExeOnly if name.contains('.') => vec![name.to_string()],
            SearchRule::CreateProcessExeOnly => vec![format!("{name}.exe")],
            // A driver's leads try `.sys` first (`HUNT-249` review): the
            // PATHEXT list alone never names a kernel driver.
            SearchRule::FullPathRequired(src)
                if src.tries_driver_leads() && !is_executable_like(name) =>
            {
                std::iter::once(format!("{name}.sys"))
                    .chain(PATHEXT_DEFAULT.iter().map(|ext| format!("{name}{ext}")))
                    .collect()
            }
            SearchRule::FullPathRequired(_) => SearchRule::ShellPathext.names_for(name),
            SearchRule::Observed(launcher) => launcher.names_for(name),
        }
    }

    /// The expansion recorded for a bare program name under this rule. Under
    /// `full_path_required` the launcher's resolution is undocumented, so the
    /// expansion names lead candidates, never the search path (`HUNT-249`
    /// review).
    pub fn bare_name_expansion(self) -> &'static str {
        match self {
            SearchRule::FullPathRequired(src) if src.tries_driver_leads() => {
                FULL_PATH_DRIVER_LEAD_EXPANSION
            }
            SearchRule::FullPathRequired(_) => FULL_PATH_LEAD_EXPANSION,
            _ => BARE_NAME_EXPANSION,
        }
    }
}

impl FullPathSource {
    /// True when the entry is, or may be, a kernel driver, whose leads add
    /// `\Windows\System32\drivers` and `.sys`.
    pub fn tries_driver_leads(self) -> bool {
        matches!(
            self,
            FullPathSource::DriverImagePath | FullPathSource::UnknownTypeImagePath
        )
    }
}

/// The lead directory added for a driver: where drivers usually sit. It is a
/// lead, not the kernel's documented rule for a bare name.
pub const DRIVER_LEAD_DIRECTORY: (&str, &str) =
    ("/windows/system32/drivers", "\\Windows\\System32\\drivers");

/// What a source says about how its bare program name would be searched for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchContext {
    /// The extension rule.
    pub rule: SearchRule,
    /// The working directory the source records for the new process, verbatim
    /// (a WMI consumer's `WorkingDirectory`). Tried before the system
    /// directories, because it is where a copy planted beside the work would
    /// sit — `CreateProcess` documents searching the *launching* process's
    /// current directory, not the new one's, so a match there is reported as
    /// found in the working directory, never as the copy Windows loaded.
    pub working_directory: Option<String>,
}

/// Where a search-path directory came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchDirectoryKind {
    /// The working directory the entry records.
    WorkingDirectory,
    /// One of [`SEARCH_PATH_DIRECTORIES`].
    SystemDirectory,
}

/// One directory a bare program name is searched in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDirectory {
    /// Volume-relative, `/`-separated, lowercase.
    pub lookup: String,
    /// The form shown to an examiner (`\Windows\System32`, or the working
    /// directory as stored).
    pub display: String,
    pub kind: SearchDirectoryKind,
}

/// The display form of the search-path directory a volume-relative path sits
/// directly in, when it is one of [`SEARCH_PATH_DIRECTORIES`].
pub fn search_path_directory_of(lookup: &str) -> Option<&'static str> {
    let (dir, _) = lookup.rsplit_once('/')?;
    SEARCH_PATH_DIRECTORIES
        .iter()
        .find(|(prefix, _)| *prefix == dir)
        .map(|(_, display)| *display)
}

/// The directories searched for a bare name under `ctx`, with the reason a
/// recorded working directory was not usable, when it was not.
fn search_directories(ctx: &SearchContext) -> (Vec<SearchDirectory>, Option<String>) {
    let mut dirs = Vec::with_capacity(SEARCH_PATH_DIRECTORIES.len().saturating_add(1));
    let mut not_tried = None;
    if let Some(wd) = ctx
        .working_directory
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        // The directory is reduced exactly as a stored path is; a `\\` the
        // repository stores doubled collapses to one separator.
        match normalize_target(wd) {
            Some(t) if t.has_unexpanded_variable => {
                not_tried = Some(format!(
                    "The recorded working directory '{wd}' contains an environment variable \
                     this build does not expand, so it was not searched."
                ));
            }
            Some(t) if t.search_path_candidates.is_empty() && t.lookup != "/" => {
                if !SEARCH_PATH_DIRECTORIES.iter().any(|(p, _)| *p == t.lookup) {
                    dirs.push(SearchDirectory {
                        lookup: t.lookup,
                        display: wd.replace("\\\\", "\\"),
                        kind: SearchDirectoryKind::WorkingDirectory,
                    });
                }
            }
            _ => {
                not_tried = Some(format!(
                    "No volume path could be formed from the recorded working directory \
                     '{wd}', so it was not searched."
                ));
            }
        }
    }
    if let SearchRule::FullPathRequired(src) = ctx.rule {
        if src.tries_driver_leads() {
            let (prefix, display) = DRIVER_LEAD_DIRECTORY;
            dirs.push(SearchDirectory {
                lookup: prefix.to_string(),
                display: display.to_string(),
                kind: SearchDirectoryKind::SystemDirectory,
            });
        }
    }
    for (prefix, display) in SEARCH_PATH_DIRECTORIES {
        dirs.push(SearchDirectory {
            lookup: (*prefix).to_string(),
            display: (*display).to_string(),
            kind: SearchDirectoryKind::SystemDirectory,
        });
    }
    (dirs, not_tried)
}

/// The search-path candidates for a lowercase bare program name.
fn search_path_candidates_for(
    name: &str,
    rule: SearchRule,
    dirs: &[SearchDirectory],
) -> Vec<String> {
    let names = rule.names_for(name);
    let mut out = Vec::with_capacity(dirs.len().saturating_mul(names.len()));
    for dir in dirs {
        for n in &names {
            out.push(format!("{}/{n}", dir.lookup));
        }
    }
    out
}

/// [`normalize_target`] under a source's own [`SearchContext`] (`HUNT-244`).
/// Differs only for a bare program name, whose candidates then follow the
/// context's extension rule and begin with its working directory.
pub fn normalize_target_in(image: &str, ctx: &SearchContext) -> Option<TargetPath> {
    let mut t = normalize_target(image)?;
    if t.search_path_candidates.is_empty() {
        return Some(t);
    }
    let name = strip_quotes(image).to_ascii_lowercase();
    let (dirs, not_tried) = search_directories(ctx);
    t.search_path_candidates = search_path_candidates_for(&name, ctx.rule, &dirs);
    t.lookup = t.search_path_candidates.first()?.clone();
    t.search_path_directories = dirs;
    t.search_rule = ctx.rule;
    t.expansion = Some(ctx.rule.bare_name_expansion());
    t.working_directory_not_tried = not_tried;
    Some(t)
}

/// Reduce an ASEP target to a volume-relative lookup key.
///
/// The stored value is never modified; this is only the key used to ask "did we
/// recover a file at that path". The substitutions applied are the fixed
/// Windows conventions (`\??\`, `\SystemRoot\`, `%SystemRoot%`, `%windir%`, a
/// drive letter, a `System32\`-relative path) and each one is reported in
/// [`TargetPath::expansion`]. Anything else containing a `%` is flagged rather
/// than guessed at, because there is no live environment to expand against and
/// a fabricated expansion would make the existence answer worthless. A bare
/// program name is given its search-path candidates in
/// [`TargetPath::search_path_candidates`] instead of a volume-root path.
pub fn normalize_target(image: &str) -> Option<TargetPath> {
    let raw = strip_quotes(image);
    if raw.is_empty() {
        return None;
    }

    // A bare program name — no separator, drive colon, variable or space — is
    // not a file at the volume root: Windows resolves it on the search path.
    // Every candidate is carried so the file index can say which one answered.
    if !raw.contains(['\\', '/', ':', '%', ' ', '\t', '"']) {
        let name = raw.to_ascii_lowercase();
        let rule = SearchRule::default();
        let (search_path_directories, _) = search_directories(&SearchContext::default());
        let search_path_candidates =
            search_path_candidates_for(&name, rule, &search_path_directories);
        let lookup = search_path_candidates.first()?.clone();
        return Some(TargetPath {
            lookup,
            expansion: Some(BARE_NAME_EXPANSION),
            has_unexpanded_variable: false,
            search_path_candidates,
            search_path_directories,
            search_rule: rule,
            working_directory_not_tried: None,
        });
    }

    let mut s: String = raw
        .chars()
        .map(|c| {
            if c == '\\' {
                '/'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();

    let mut expansion: Option<&'static str> = None;

    if let Some(rest) = s.strip_prefix("/??/") {
        s = rest.to_string();
        expansion = Some("stripped_nt_object_prefix_\\??\\");
    }

    if let Some(rest) = s.strip_prefix("/systemroot/") {
        s = format!("/windows/{rest}");
        expansion = Some("\\SystemRoot\\ -> \\Windows\\");
    } else if let Some(rest) = s.strip_prefix("%systemroot%/") {
        s = format!("/windows/{rest}");
        expansion = Some("%SystemRoot% -> \\Windows");
    } else if let Some(rest) = s.strip_prefix("%windir%/") {
        s = format!("/windows/{rest}");
        expansion = Some("%windir% -> \\Windows");
    } else if s.starts_with("system32/") || s.starts_with("syswow64/") {
        s = format!("/windows/{s}");
        expansion = Some("System32-relative -> \\Windows\\System32");
    }

    // Drop a drive letter: the volume the ASEP names is the volume we parsed.
    let bytes = s.as_bytes();
    let has_drive_letter =
        bytes.first().is_some_and(u8::is_ascii_alphabetic) && bytes.get(1) == Some(&b':');
    if has_drive_letter {
        s = s.get(2..).unwrap_or("").to_string();
    }

    let has_unexpanded_variable = s.contains('%');

    // Collapse repeated separators and guarantee a leading one so
    // `windows/system32/x.exe` and `/windows//system32/x.exe` compare equal.
    let mut collapsed = String::with_capacity(s.len().saturating_add(1));
    let mut prev_sep = false;
    for ch in s.chars() {
        if ch == '/' {
            if !prev_sep {
                collapsed.push('/');
            }
            prev_sep = true;
        } else {
            collapsed.push(ch);
            prev_sep = false;
        }
    }
    let collapsed = collapsed.trim_end_matches('/').to_string();
    if collapsed.is_empty() {
        return None;
    }
    let lookup = if collapsed.starts_with('/') {
        collapsed
    } else {
        format!("/{collapsed}")
    };

    Some(TargetPath {
        lookup,
        expansion,
        has_unexpanded_variable,
        search_path_candidates: Vec::new(),
        search_path_directories: Vec::new(),
        search_rule: SearchRule::default(),
        working_directory_not_tried: None,
    })
}

/// The expansion recorded for a bare program name.
pub const BARE_NAME_EXPANSION: &str = "bare program name -> Windows search path \
     (the entry's working directory when recorded, then \\Windows\\System32, \
     \\Windows\\SysWOW64, \\Windows; extensions per target_search_rule)";

/// The expansion recorded for a bare program name under `full_path_required`
/// (`HUNT-249` review): the launcher's resolution is not documented, so the
/// candidates are named as leads and never as the search path.
pub const FULL_PATH_LEAD_EXPANSION: &str = "bare program name outside the documented \
     full-path contract; how the launcher resolves it is not documented -> lead \
     candidates only (\\Windows\\System32, \\Windows\\SysWOW64, \\Windows; \
     extensions .com, .exe, .bat, .cmd)";

/// [`FULL_PATH_LEAD_EXPANSION`] for an entry that is, or may be, a driver.
pub const FULL_PATH_DRIVER_LEAD_EXPANSION: &str = "bare program name outside the \
     documented full-path contract; how the launcher resolves it is not documented -> \
     lead candidates only (\\Windows\\System32\\drivers, \\Windows\\System32, \
     \\Windows\\SysWOW64, \\Windows; extensions .sys, .com, .exe, .bat, .cmd)";

/// Reduce a filesystem path recovered from the volume to the same shape
/// [`normalize_target`] produces, so the two can be compared.
pub fn normalize_evidence_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len().saturating_add(1));
    let mut prev_sep = false;
    for ch in path.chars() {
        let ch = if ch == '\\' { '/' } else { ch };
        if ch == '/' {
            if !prev_sep {
                out.push('/');
            }
            prev_sep = true;
        } else {
            for lower in ch.to_lowercase() {
                out.push(lower);
            }
            prev_sep = false;
        }
    }
    let trimmed = out.trim_end_matches('/');
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// The final `/`- or `\`-separated component of a path.
pub fn basename(path: &str) -> &str {
    let after_slash = path.rsplit('/').next().unwrap_or(path);
    after_slash.rsplit('\\').next().unwrap_or(after_slash)
}

/// True when the name ends in an extension that Windows can execute or load.
pub fn is_executable_like(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((_, ext)) => {
            let ext = ext.to_ascii_lowercase();
            EXECUTABLE_EXTENSIONS.contains(&ext.as_str())
        }
        None => false,
    }
}

/// True when a normalised lookup path sits under `\Windows\System32` or
/// `\Windows\SysWOW64`.
///
/// This is the boundary the COM-hijack rule uses. It is a location fact, not a
/// judgement: plenty of legitimate COM servers ship outside System32.
pub fn is_under_system_directory(lookup: &str) -> bool {
    lookup.starts_with("/windows/system32/") || lookup.starts_with("/windows/syswow64/")
}

/// A `REG_MULTI_SZ` value's elements, from the hive record's value entry.
///
/// Since `HUNT-159` the registry plugin publishes the elements as the array
/// `value_data_list`, and that is read where present (`HUNT-208`): the
/// rendering joins them with `" | "`, which an element may itself contain.
/// A record written by an older build carries only the rendering, which is
/// split with [`split_multi_sz`] — ambiguous for an element that holds the
/// separator. Either way, an element that is empty after trimming is dropped
/// rather than emitted as a nameless package.
pub fn multi_sz_elements(value: &serde_json::Value) -> Vec<String> {
    if let Some(list) = value
        .get("value_data_list")
        .and_then(serde_json::Value::as_array)
    {
        return list
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    split_multi_sz(
        value
            .get("value_data")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
    )
}

/// Split a `REG_MULTI_SZ` value as the registry plugin renders it (`a | b | c`)
/// back into its elements, dropping empties.
///
/// Only for a record that carries no `value_data_list` (an older build's):
/// the split is ambiguous where an element contains `" | "`. Re-splitting is
/// how `BootExecute` and the LSA package lists become one entry per package
/// instead of one blob. An element that is empty after trimming is dropped
/// rather than emitted as a nameless package.
pub fn split_multi_sz(value: &str) -> Vec<String> {
    value
        .split(" | ")
        .flat_map(|s| s.split('\0'))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse the decimal tail out of the registry plugin's DWORD rendering
/// (`"0x00000002 (2)"`), falling back to a bare decimal string.
///
/// Returns `None` when the value is not a number at all — a service whose
/// `Start` value is corrupt must be reported as "start type unreadable", never
/// as `0` (which would read as "boot start", the most alarming answer there is).
pub fn parse_dword(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if let Some(v) = parenthesised_decimal(trimmed) {
        return Some(v);
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex.trim(), 16).ok();
    }
    trimmed.parse::<u32>().ok()
}

/// The decimal inside the trailing `(N)` of a rendered DWORD.
/// Parse a rendered `REG_QWORD` — `0x%016x (n)` — into a `u64`.
///
/// The registry plugin renders typed values before ASEP sees them, so a
/// 64-bit value arrives as text. `parse_dword` cannot be widened to cover it:
/// an install FILETIME does not fit in 32 bits, and a `u32` parse of one
/// silently yields `None`, which would read as "no install time recorded"
/// rather than "this build could not read it" (`ROADMAP` §1.7).
pub fn parse_qword(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    // The parenthesised decimal first: it is what the renderer writes last and
    // is unambiguous.
    if let (Some(open), Some(close)) = (trimmed.rfind('('), trimmed.rfind(')')) {
        if open < close {
            if let Some(inner) = trimmed.get(open + 1..close) {
                if let Ok(v) = inner.trim().parse::<u64>() {
                    return Some(v);
                }
            }
        }
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        // The hex half may be followed by the parenthesised form.
        let hex = hex.split_whitespace().next().unwrap_or(hex);
        return u64::from_str_radix(hex.trim(), 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn parenthesised_decimal(trimmed: &str) -> Option<u32> {
    let open = trimmed.rfind('(')?;
    let close = trimmed.rfind(')')?;
    if open >= close {
        return None;
    }
    trimmed
        .get(open.checked_add(1)?..close)?
        .trim()
        .parse::<u32>()
        .ok()
}

/// What a PowerShell `-EncodedCommand` argument in an ASEP command line holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodedCommand {
    /// The argument decoded as PowerShell decodes it: base64 of UTF-16LE text.
    Decoded {
        /// The parameter exactly as written (`-enc`, `-e`, `/EncodedCommand`).
        parameter: String,
        /// The decoded script text.
        script: String,
    },
    /// An encoded-command parameter was found, but its argument did not decode;
    /// the reason says why. Nothing is published as the script.
    Undecodable {
        /// The parameter exactly as written.
        parameter: String,
        /// Why the argument could not be decoded.
        reason: String,
    },
}

/// Find a PowerShell `-EncodedCommand` parameter in `command` and decode its
/// argument. `None` when the command runs no `powershell`/`pwsh` image or
/// passes it no encoded-command parameter.
///
/// The rule is PowerShell's own: a parameter is named by any prefix of
/// `EncodedCommand` (`-e`, `-enc`, …) or its alias `-ec`, with `-` or `/`, in
/// any case; its argument is base64 of UTF-16LE text. Only parameters after
/// the PowerShell image are considered, so `cmd /C powershell -enc …` is read
/// and `cmd -enc …` is not. The first such parameter is decoded; nothing is
/// guessed when it does not decode.
pub fn powershell_encoded_command(command: &str) -> Option<EncodedCommand> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let ps_at = tokens.iter().position(|t| is_powershell_image(t))?;
    let rest = &tokens[ps_at + 1..];
    let (i, parameter) = rest.iter().enumerate().find_map(|(i, t)| {
        let name = t.strip_prefix('-').or_else(|| t.strip_prefix('/'))?;
        let name = name.to_ascii_lowercase();
        let hit = name == "ec" || (!name.is_empty() && "encodedcommand".starts_with(&name));
        hit.then(|| (i, t.to_string()))
    })?;
    let undecodable = |reason: &str| {
        Some(EncodedCommand::Undecodable {
            parameter: parameter.clone(),
            reason: reason.to_string(),
        })
    };
    let Some(arg) = rest.get(i + 1) else {
        return undecodable("the encoded-command parameter has no argument after it");
    };
    let arg = arg.trim_matches(|c| c == '"' || c == '\'');
    let Some(bytes) = decode_base64(arg) else {
        return undecodable("the argument is not valid base64");
    };
    if bytes.len() % 2 != 0 {
        return undecodable(
            "the argument decodes to an odd number of bytes, so it is not UTF-16LE text",
        );
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    match String::from_utf16(&units) {
        Ok(script) => Some(EncodedCommand::Decoded { parameter, script }),
        Err(_) => undecodable("the argument decodes to bytes that are not valid UTF-16LE text"),
    }
}

/// `powershell`, `pwsh`, with or without a directory, quotes or `.exe`.
fn is_powershell_image(token: &str) -> bool {
    let t = token.trim_matches(|c| c == '"' || c == '\'');
    let base = t
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(t)
        .to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    base == "powershell" || base == "pwsh"
}

/// Strict RFC 4648 base64 (standard alphabet, optional `=` padding). `None`
/// on any character outside the alphabet or a length no encoder produces.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let body = s.trim_end_matches('=');
    if s.len() - body.len() > 2 || body.len() % 4 == 1 || body.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in body.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}
