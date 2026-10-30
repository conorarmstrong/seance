//! The forensic module set, and the one place it is registered.
//!
//! # Why this exists (LIVE-005)
//!
//! Séance ships two binaries that both run an orchestrator over evidence:
//! `seance` (`seance_cli`, which serves the UI and also runs `seance scan`) and
//! `seance_api` (the standalone server). Each used to enumerate the module set
//! by hand, in its own `main.rs`, and the two lists had drifted badly:
//!
//! * the API server registered **no memory module at all**, so a RAM capture
//!   ingested through it was stored and then examined by nothing — no image
//!   record, no profile, no analysis stages, and no error, because nothing
//!   subscribed to the artifact. Every stage reported `did_not_run` forever and
//!   an examiner read the empty result as a capture that held nothing;
//! * it also registered no APFS, FAT, XFS, btrfs, HFS+, ISO9660 or F2FS reader,
//!   so an image with any of those filesystems produced a partition and no
//!   files;
//! * and none of the LUKS/BitLocker decryptors, the messaging parsers
//!   (Signal, Telegram, Viber, Kik, Skype, WeChat, LINE, Messenger, Instagram,
//!   Snapchat, Twitter), the browser/cache readers, the iOS artifact readers,
//!   the Windows timeline, ASEP, `$Secure:$SDS`, utmp, or the desktop-artifact
//!   readers.
//!
//! Adding a module to one list and not the other is silent by construction:
//! nothing fails, the ingest "succeeds", and the missing analysis is
//! indistinguishable from analysis that found nothing. Two hand-written lists
//! cannot be kept in step by care alone, so there is now exactly one:
//! [`build_module_set`], registered by exactly one function,
//! [`register_all_modules`], which both binaries call.
//!
//! `seance_api/tests/module_registration_is_shared.rs` fails the build if
//! either `main.rs` grows a `register_module(` call of its own.
//!
//! # Deliberate exclusions
//!
//! There are no per-binary exclusions: both entry points run the identical set,
//! and the only things that differ between them are *inputs* to that set (the
//! search index they write to, the unlock secrets the operator supplied, the
//! optional carver definitions and YARA rules). Anything that must differ per
//! host belongs here, named and reasoned, not in a second list.
//!
//! There are no module-level exclusions either, and there used to be one:
//! `seance_plugin_memory_macos` was a workspace member registered by neither
//! binary, on the reasoning that it has never been validated against a real
//! macOS capture and registering it would put its results in front of an
//! examiner. That reasoning had the sign backwards. Withholding it did not stop
//! a Mac capture reaching an examiner — it stopped the *analysis* reaching one,
//! so the case held the format-layer facts (this is a memory image, this is its
//! size) and said nothing at all about processes or kernel extensions. Silence
//! is not a caveat. It is indistinguishable from a capture that held nothing,
//! and it is the failure mode the whole of this file exists to prevent.
//!
//! The tier is registered, and the disclosure travels on the evidence instead:
//! every record it emits carries `validated_against_real_capture: false`,
//! `validation_state` and an examiner-facing `validation_notice`, applied last
//! in the one function that stamps its records so no stage can weaken it
//! (`seance_plugin_memory_macos::unvalidated`). `seance_api::memory` reads that
//! marker back out and states it on the coverage row, so an examiner reading
//! "the process list ran and is complete" reads, in the same row, that no
//! capture of a real Mac has ever tested the code that produced it. An image
//! with no Darwin banner produces nothing at all, so no Windows or Linux
//! capture grows a macOS failure record.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use tracing::info;

use seance_core::module::ForensicsModule;
use seance_core::orchestrator::Orchestrator;
// The two halves of what a memory pattern scan needs: an engine that scans an
// address space chunk by chunk, and the account it gives of what it refused.
use seance_memory::scan::{Scanner as MemoryScanner, ScannerDiagnostics};

use seance_container_aff4::Aff4ContainerModule;
use seance_container_archive::{
    Bzip2ExpanderModule, GzipExpanderModule, Ole2ExpanderModule, SevenZipExpanderModule,
    TarExpanderModule, XzExpanderModule,
};
#[cfg(feature = "e01")]
use seance_container_e01::E01ContainerModule;
use seance_container_sparseimage::SparseImageContainerModule;
use seance_container_vdisk::{
    Qcow2ContainerModule, VhdContainerModule, VhdxContainerModule, VmdkContainerModule,
};
use seance_container_zip::ZipContainerModule;
use seance_plugin_amcache::AmcacheParser;
use seance_plugin_android_apps::{AndroidCalendarParser, GoogleKeepParser};
use seance_plugin_android_backup::AndroidBackupModule;
use seance_plugin_android_sms::AndroidSmsParser;
use seance_plugin_apfs::ApfsParser;
use seance_plugin_badclus::BadClusParser;
use seance_plugin_browser_history::BrowserHistoryParser;
use seance_plugin_btrfs::BtrfsParser;
use seance_plugin_call_history::CallHistoryParser;
use seance_plugin_carver::{FileCarver, UnallocatedCarver};
use seance_plugin_contacts::ContactsParser;
use seance_plugin_directory::DirectoryWalkerModule;
use seance_plugin_email::EmailParser;
use seance_plugin_evtx::EvtxParser;
use seance_plugin_ext4::Ext4Parser;
use seance_plugin_f2fs::F2fsParser;
use seance_plugin_fat::FatParser;
use seance_plugin_file_analysis::{encryption::EncryptionDetector, FileAnalyzer};
use seance_plugin_hfsplus::HfsPlusParser;
use seance_plugin_host_identity::{LinuxHostParser, MacHostParser};
use seance_plugin_i30::I30Parser;
use seance_plugin_imessage::IMessageParser;
use seance_plugin_installed_apps::{InstalledAppsParser, MacInstalledAppsParser};
use seance_plugin_ios_backup::{IosBackupManifestParser, IosBackupParser};
use seance_plugin_iso9660::Iso9660Parser;
use seance_plugin_jumplists::JumpListParser;
use seance_plugin_lnk::LnkParser;
use seance_plugin_logfile::LogFileParser;
use seance_plugin_macos_artifacts::{
    AppleMailParser, AslParser, BomParser, DataProtectionKeychainParser, InstallHistoryParser,
    KeychainParser, KnowledgeCParser, LaunchdPersistenceParser, NotificationsParser, OpenBsmParser,
    QuarantineParser, SpotlightStoreParser, TccParser, UnifiedLogCatalogueParser, UnifiedLogParser,
    UnifiedLogTimesyncParser, WifiKnownNetworksParser,
};
use seance_plugin_media::MediaPropertiesModule;
use seance_plugin_mft::MftParser;
use seance_plugin_mobile_device::{
    AndroidAccountsParser, AndroidBluetoothParser, AndroidPropertiesParser, AndroidSettingsParser,
    AndroidTelephonyParser,
};
use seance_plugin_ocr::OcrParser;
use seance_plugin_partition::{FilesystemDetector, PartitionParser};
use seance_plugin_pcap::PcapParser;
use seance_plugin_plist::PlistParser;
use seance_plugin_prefetch::PrefetchParser;
use seance_plugin_recyclebin::RecycleBinParser;
use seance_plugin_registry::RegistryParser;
use seance_plugin_sdb::SdbParser;
use seance_plugin_setupapi::SetupApiParser;
use seance_plugin_shellbags::ShellBagsPlugin;
use seance_plugin_shimcache::ShimcacheParser;
use seance_plugin_signal::SignalParser;
use seance_plugin_sqlite::SqliteParser;
#[cfg(feature = "esedb")]
use seance_plugin_srum::SrumParser;
use seance_plugin_stickynotes::StickyNotesParser;
#[cfg(feature = "esedb")]
use seance_plugin_sum::SumParser;
use seance_plugin_udf::UdfParser;
use seance_plugin_usnjrnl::UsnJrnlParser;
use seance_plugin_vss::VssEnumerator;
use seance_plugin_whatsapp::WhatsAppParser;
use seance_plugin_xfs::XfsParser;

/// Volume- and backup-unlock secrets supplied by the operator for this run.
///
/// These are handed straight to the decryptor modules and held in process
/// memory for the lifetime of the run. They are deliberately NOT attached to
/// the evidence artifact's metadata: that metadata is persisted verbatim to
/// `artifacts.metadata_json` and served back by the artifact-detail API, so a
/// passphrase routed through it would outlive the process, sit next to the
/// evidence it unlocks, and appear in every DB backup and export.
///
/// [`Default`] is the honest empty case: no secret was supplied, so an
/// encrypted volume or backup takes the "present but not extracted" path and
/// says so, rather than being silently absent.
#[derive(Default)]
pub struct UnlockSecrets {
    pub luks_passphrase: Option<String>,
    pub bitlocker_password: Option<String>,
    pub bitlocker_recovery_key: Option<String>,
    pub ios_backup_password: Option<String>,
}

/// Redacting `Debug`: the whole point of holding these in memory is that they
/// never reach a log line, a panic message or a persisted record.
impl std::fmt::Debug for UnlockSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockSecrets")
            .field("luks_passphrase", &self.luks_passphrase.is_some())
            .field("bitlocker_password", &self.bitlocker_password.is_some())
            .field(
                "bitlocker_recovery_key",
                &self.bitlocker_recovery_key.is_some(),
            )
            .field("ios_backup_password", &self.ios_backup_password.is_some())
            .finish()
    }
}

/// Everything the module set needs that differs between runs.
///
/// This is the ONLY thing that may differ between the two binaries. If a new
/// host-specific knob is needed it belongs here, so the set of modules stays
/// identical by construction.
pub struct ModuleSetOptions {
    /// Index the [`seance_search::SearchIndexer`] writes into.
    pub search_service: Arc<seance_search::SearchService>,
    /// Contents of a user-supplied carving-definitions JSON file, if any.
    pub carver_defs: Option<String>,
    /// Secrets for the LUKS / BitLocker / iOS-backup decryptors.
    pub unlock: UnlockSecrets,
    /// Rule file for the YARA scanner. `None` leaves the scanner unregistered
    /// (see [`build_module_set`]).
    pub yara_rules: Option<PathBuf>,
    /// One regular expression to search **memory** for, over each process's own
    /// address space and the kernel's — upstream's `regexscan` and
    /// `vadregexscan`.
    ///
    /// Memory only, and deliberately: the file-content search an examiner wants
    /// over artifacts is `seance_search`'s, which indexes text and understands
    /// encodings. This is a byte match over an assembled address space, and the
    /// record it produces says what that means.
    pub memory_regex: Option<String>,
    /// The strings file and radix named by `SEANCE_MEMORY_STRINGS` and
    /// `SEANCE_MEMORY_STRINGS_RADIX`.
    ///
    /// `None` leaves the memory tier's `strings_map` stage reporting that it
    /// did not run. A file that is named and will not read, or a radix that is
    /// named and is not one of the three, **aborts the run**: a stage that
    /// silently reported "nothing was named" would hide the examiner's typo,
    /// and an empty table of offsets reads as an image with nothing in it.
    pub memory_strings: Option<(PathBuf, String)>,
}

/// Says what was configured without saying what any secret is: `UnlockSecrets`
/// prints only whether each was supplied, and the carver definitions print as a
/// size rather than as their contents.
impl std::fmt::Debug for ModuleSetOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleSetOptions")
            .field(
                "carver_defs_bytes",
                &self.carver_defs.as_ref().map(|d| d.len()),
            )
            .field("unlock", &self.unlock)
            .field("yara_rules", &self.yara_rules)
            // The pattern itself, not a redaction: an operator-supplied regex
            // is not a secret, and a run that searched for the wrong thing is
            // a question this line has to be able to answer.
            .field("memory_regex", &self.memory_regex)
            .field("memory_strings", &self.memory_strings)
            .finish_non_exhaustive()
    }
}

impl ModuleSetOptions {
    /// The default run: an index to write to, no custom carver definitions, no
    /// unlock secrets, no YARA rules.
    pub fn new(search_service: Arc<seance_search::SearchService>) -> Self {
        Self {
            search_service,
            carver_defs: None,
            unlock: UnlockSecrets::default(),
            yara_rules: None,
            memory_strings: None,
            memory_regex: None,
        }
    }

    /// The YARA rule path named by `SEANCE_YARA_RULES`, if it is set to a
    /// non-empty value.
    ///
    /// Both binaries read the same variable, so an examiner's rule set applies
    /// wherever they run Séance. A blank value is treated as unset rather than
    /// as the path `""`, which would fail to load and abort the run.
    pub fn yara_rules_from_env() -> Option<PathBuf> {
        match std::env::var("SEANCE_YARA_RULES") {
            Ok(path) if !path.trim().is_empty() => Some(PathBuf::from(path.trim())),
            _ => None,
        }
    }

    /// The memory regular expression named by `SEANCE_MEMORY_REGEX`, if it is
    /// set to a non-empty value.
    ///
    /// **One pattern, not a list.** A separator would have to be a character a
    /// regular expression cannot contain, and there is no such character; a
    /// list separated by one that can appear would silently cut a pattern in
    /// half and search for the halves. An examiner who wants several writes
    /// `(a|b)`, which is what the syntax is for.
    ///
    /// The value is **not** trimmed beyond its outer whitespace being
    /// significant to a regex: leading and trailing blanks are kept, because
    /// `\s+$` means something. A value that is only whitespace is treated as
    /// unset.
    pub fn memory_regex_from_env() -> Option<String> {
        match std::env::var("SEANCE_MEMORY_REGEX") {
            Ok(pattern) if !pattern.trim().is_empty() => Some(pattern),
            _ => None,
        }
    }

    /// The strings file named by `SEANCE_MEMORY_STRINGS`, and the radix named
    /// by `SEANCE_MEMORY_STRINGS_RADIX`.
    ///
    /// The file is the examiner's own output from `strings -t d` over the raw
    /// image: lines of an offset and the text found there. Séance runs no
    /// `strings` of its own, so with nothing named the memory tier's
    /// `strings_map` stage reports that it did not run.
    ///
    /// **The radix is stated, not guessed.** `strings -t x` writes hexadecimal,
    /// and a hexadecimal file read as decimal does not fail cleanly: every line
    /// containing a letter is rejected, and the rest parse into frames
    /// gigabytes from the truth with nothing on the row to show it. Default
    /// `decimal`, which is `-t d`; `hex` and `octal` are the other two.
    pub fn memory_strings_from_env() -> Option<(PathBuf, String)> {
        let path = match std::env::var("SEANCE_MEMORY_STRINGS") {
            Ok(path) if !path.trim().is_empty() => PathBuf::from(path.trim()),
            _ => return None,
        };
        let radix = std::env::var("SEANCE_MEMORY_STRINGS_RADIX")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "decimal".to_string());
        Some((path, radix))
    }
}

/// Modules the product registers **only when an examiner configures them**.
///
/// [`build_module_set`] with no options does not produce these: the YARA
/// scanner is registered only when a rule set is named, and the memory pattern
/// scan only when a rule set or a pattern is. They are nonetheless part of the
/// product — an examiner asks what the YARA scanner does, and the method-
/// statement register has to be able to answer.
///
/// So the register is rendered over the built set **plus** these, and the gate
/// that refuses a statement for a module the product does not have accepts
/// them. That gate exists to stop a *stale* statement outliving its module;
/// refusing a true statement for a module whose registration is conditional is
/// not what it is for.
///
/// Hand-maintained and **checked**: `the_opt_in_ids_are_exactly_what_naming_a_pattern_adds`
/// builds the set with every knob turned on and asserts the difference is
/// exactly this list, so an id that stops being registered — or a new opt-in
/// module — fails there rather than quietly widening the register.
pub const OPT_IN_MODULE_IDS: &[&str] = &["plugin.detection.yara", "plugin.memory.pattern_scan"];

/// Every module id the product can register, given the ids it registers by
/// default.
///
/// The register and its gate both use this rather than the default set, for the
/// reason [`OPT_IN_MODULE_IDS`] gives.
pub fn registrable_module_ids(default_ids: &[String]) -> Vec<String> {
    let mut ids = default_ids.to_vec();
    for id in OPT_IN_MODULE_IDS {
        if !ids.iter().any(|have| have == id) {
            ids.push((*id).to_string());
        }
    }
    ids
}

/// Build a [`FileCarver`] with optional custom signatures, falling back to the
/// built-in set (with a logged error) if the definitions are malformed.
fn make_file_carver(defs: Option<&str>) -> FileCarver {
    match defs {
        Some(d) => FileCarver::with_custom_defs(d).unwrap_or_else(|e| {
            tracing::error!("Invalid custom carver defs, using built-in signatures only: {e}");
            FileCarver::new()
        }),
        None => FileCarver::new(),
    }
}

/// [`UnallocatedCarver`] counterpart of [`make_file_carver`].
fn make_unallocated_carver(defs: Option<&str>) -> UnallocatedCarver {
    match defs {
        Some(d) => UnallocatedCarver::with_custom_defs(d).unwrap_or_else(|e| {
            tracing::error!("Invalid custom carver defs, using built-in signatures only: {e}");
            UnallocatedCarver::new()
        }),
        None => UnallocatedCarver::new(),
    }
}

/// The complete forensic module set, in registration order.
///
/// Modules that support cancellation or progress reporting are wired to
/// `orchestrator`'s handles, which is why this takes the orchestrator it is
/// destined for rather than returning a free-standing list.
///
/// Fails closed on YARA: when `opts.yara_rules` names a rule file that will not
/// load, this returns `Err` and the caller must abort the run. Continuing
/// without the scanner would produce a case in which "YARA found nothing" and
/// "no rules were loaded" are the same empty result — opposite claims. When no
/// rule file is named at all the scanner is simply not registered, because a
/// scanner with no rules can never match anything.
pub fn build_module_set(
    orchestrator: &Orchestrator,
    opts: ModuleSetOptions,
) -> anyhow::Result<Vec<Arc<dyn ForensicsModule>>> {
    let ModuleSetOptions {
        search_service,
        carver_defs: carver_defs_json,
        unlock,
        yara_rules,
        memory_strings,
        memory_regex,
    } = opts;
    let carver_defs = carver_defs_json.as_deref();

    // The YARA rule set is compiled here, before the module list is built,
    // because TWO drivers share it: the file scanner registered at the end of
    // this function, and the memory analysis's pattern-scan stage. One
    // compiled set behind both is the point -- compiling twice would be two
    // rule sets, and a rule the engine treated differently in one of them
    // would make the file scan and the memory scan disagree about what was
    // looked for.
    //
    // Fails closed exactly as it did when this lived at the bottom: a rule set
    // that was NAMED and will not load ends the run. See the doc comment.
    let yara: Option<Arc<seance_plugin_yara::YaraScanner>> = match &yara_rules {
        Some(path) => Some(Arc::new(
            seance_plugin_yara::YaraScanner::from_rule_path(path).with_context(|| {
                format!(
                    "YARA rules at {} could not be loaded (named by SEANCE_YARA_RULES)",
                    path.display()
                )
            })?,
        )),
        None => None,
    };
    // What the memory tier is asked to search for. Empty when nothing was
    // named, which is what makes its pattern-scan stage report that it did not
    // run rather than that it found nothing.
    let mut memory_patterns: Vec<seance_plugin_memory_windows::pattern_scan::PatternSet> = yara
        .as_ref()
        .map(|rules| {
            let scanner = Arc::new(seance_plugin_yara::memory::MemoryYaraScanner::new(
                "yara.memory",
                Arc::clone(rules),
            ));
            vec![seance_plugin_memory_windows::pattern_scan::PatternSet {
                kind: "yara",
                source: yara_rules
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                pattern_names: rules.rule_identifiers(),
                diagnostics: Some(Arc::clone(&scanner) as Arc<dyn ScannerDiagnostics>),
                scanner: scanner as Arc<dyn MemoryScanner>,
                scope_note: Some(seance_plugin_yara::memory::CONDITION_SCOPE.to_string()),
            }]
        })
        .unwrap_or_default();

    // A regular expression over the same two address spaces: upstream's
    // `regexscan` and `vadregexscan`. Fails closed for the same reason a rule
    // file does -- the operator asked for this pattern by writing it, and a run
    // that searched for nothing because it would not compile must not look like
    // a run that searched and found nothing.
    if let Some(pattern) = memory_regex.as_deref() {
        let scanner = seance_memory::scan::RegexScanner::new("regex.memory", pattern)
            .with_context(|| {
                format!("SEANCE_MEMORY_REGEX is not a pattern this build can compile: {pattern:?}")
            })?;
        info!("Memory regular expression compiled: {pattern:?}.");
        memory_patterns.push(seance_plugin_memory_windows::pattern_scan::PatternSet {
            kind: "regex",
            source: pattern.to_string(),
            pattern_names: vec![pattern.to_string()],
            diagnostics: None,
            scanner: Arc::new(scanner) as Arc<dyn MemoryScanner>,
            scope_note: Some(seance_plugin_memory_windows::pattern_scan::REGEX_SCOPE.to_string()),
        });
    }

    // The examiner's strings file, read here for the same reason the rule set
    // is compiled here: a file that was NAMED and will not read must end the
    // run. A stage that quietly reported "nothing was named" would hide a
    // mistyped path, and an empty table of offsets reads as an image with
    // nothing in it.
    let strings_source = match memory_strings.as_ref() {
        Some((path, radix)) => {
            let radix = seance_plugin_memory_windows::strings_map::Radix::parse(radix)
                .with_context(|| {
                    format!(
                        "SEANCE_MEMORY_STRINGS_RADIX is {radix:?}, which is not one of decimal, hex or octal -- and a strings file read in the wrong radix names frames gigabytes from the truth without failing"
                    )
                })?;
            let file = std::fs::File::open(path).with_context(|| {
                format!(
                    "the strings file at {} could not be opened (named by SEANCE_MEMORY_STRINGS)",
                    path.display()
                )
            })?;
            let source = seance_plugin_memory_windows::strings_map::StringsSource::read(
                path.display().to_string(),
                radix,
                file,
            )
            .with_context(|| {
                format!(
                    "the strings file at {} could not be read (named by SEANCE_MEMORY_STRINGS)",
                    path.display()
                )
            })?;
            info!(
                "Strings file read: {} offsets from {} lines of {} ({}), {} malformed.",
                source.len(),
                source.lines_read,
                path.display(),
                radix.as_str(),
                source.malformed_lines,
            );
            Some(source)
        }
        None => None,
    };

    // One list, two consumers: the Windows tier's per-process stage and the
    // image-level scan below. Cloning a `PatternSet` clones two `Arc`s and the
    // names, not the compiled engine, so both drive the same rules.
    let image_patterns = memory_patterns.clone();

    let mut modules: Vec<Arc<dyn ForensicsModule>> = vec![
        Arc::new(PartitionParser),
        Arc::new(FilesystemDetector),
        Arc::new(
            MftParser::new()
                .with_cancellation(orchestrator.cancellation_handle())
                .with_progress(orchestrator.progress_reporter("plugin.ntfs.mft_parser")),
        ),
        Arc::new(seance_plugin_ical::ICalParser::new()),
        Arc::new(AndroidCalendarParser),
        // "Whose phone is this?" — the first question asked of a mobile
        // exhibit, and until HUNT-079 there was no surface that answered it.
        // A folder of files is evidence too: an unpacked extraction, a Takeout,
        // a logical acquisition, a mounted share (HUNT-096).
        Arc::new(DirectoryWalkerModule::new()),
        Arc::new(AndroidPropertiesParser::new()),
        // The other half of the question: the device's own settings (what it
        // calls itself, and whether its clock was its own), the accounts signed
        // in to it, and the SIMs that carried its number.
        Arc::new(AndroidSettingsParser::new()),
        Arc::new(AndroidAccountsParser::new()),
        Arc::new(AndroidTelephonyParser::new()),
        // What the phone has been near: a car, a watch, a speaker.
        Arc::new(AndroidBluetoothParser::new()),
        // The same question of a Linux exhibit: what the machine is called,
        // which distribution it runs, and who has an account on it — and of a
        // Mac: its build, and the two different names it answers to.
        Arc::new(LinuxHostParser::new()),
        Arc::new(MacHostParser::new()),
        // How long a recording runs, and when the device says it was made.
        Arc::new(MediaPropertiesModule::new()),
        Arc::new(GoogleKeepParser),
        Arc::new(LogFileParser),
        Arc::new(I30Parser),
        Arc::new(UsnJrnlParser),
        Arc::new(BadClusParser),
        // Application-compatibility shim databases (ROADMAP §1.7). A custom .sdb
        // installed with sdbinst.exe is a documented persistence technique.
        Arc::new(SdbParser),
        // The setupapi device-install logs (ROADMAP §2.6): the second and
        // independent source for when a device was first connected, beside
        // the registry's device-property keys.
        Arc::new(SetupApiParser),
        // Sticky Notes, both formats (ROADMAP §2.6). Every record it emits
        // carries a never-validated stamp: no note of either format existed on
        // the machine this was written on, and the stamp comes off when a
        // comparison against real notes is recorded in VALIDATION.md.
        Arc::new(StickyNotesParser),
        Arc::new(PcapParser),
        Arc::new(ShellBagsPlugin),
        Arc::new(LnkParser),
        Arc::new(JumpListParser),
        #[cfg(feature = "esedb")]
        Arc::new(SrumParser),
        // Reads the same ESE files as SRUM and self-selects on the UAL schema,
        // so a non-UAL database produces nothing here.
        #[cfg(feature = "esedb")]
        Arc::new(SumParser),
        Arc::new(BrowserHistoryParser),
        Arc::new(ZipContainerModule),
        #[cfg(feature = "e01")]
        Arc::new(E01ContainerModule),
        Arc::new(Aff4ContainerModule),
        Arc::new(GzipExpanderModule),
        Arc::new(Bzip2ExpanderModule),
        Arc::new(XzExpanderModule),
        Arc::new(SevenZipExpanderModule),
        Arc::new(TarExpanderModule),
        Arc::new(Ole2ExpanderModule),
        Arc::new(VhdContainerModule),
        Arc::new(VhdxContainerModule),
        Arc::new(VmdkContainerModule),
        Arc::new(Qcow2ContainerModule),
        Arc::new(SparseImageContainerModule),
        Arc::new(
            Ext4Parser::new()
                .with_cancellation(orchestrator.cancellation_handle())
                .with_progress(orchestrator.progress_reporter("plugin.fs.ext4")),
        ),
        Arc::new(ApfsParser),
        Arc::new(VssEnumerator),
        Arc::new(RegistryParser),
        Arc::new(EvtxParser),
        Arc::new(PrefetchParser),
        Arc::new(AmcacheParser),
        Arc::new(ShimcacheParser),
        Arc::new(RecycleBinParser),
        Arc::new(
            make_file_carver(carver_defs)
                .with_cancellation(orchestrator.cancellation_handle())
                .with_progress(orchestrator.progress_reporter("plugin.carver")),
        ),
        Arc::new(
            make_unallocated_carver(carver_defs)
                .with_cancellation(orchestrator.cancellation_handle())
                .with_progress(
                    orchestrator.progress_reporter("plugin.recovery.unallocated_carver"),
                ),
        ),
        Arc::new(FileAnalyzer),
        Arc::new(seance_plugin_hash::FileHasher::new()),
        Arc::new(seance_plugin_exif::ExifParser::new()),
        Arc::new(seance_plugin_perceptual::PerceptualHasher),
        Arc::new(EncryptionDetector),
        Arc::new(EmailParser),
        Arc::new(SqliteParser),
        Arc::new(PlistParser),
        Arc::new(FatParser),
        Arc::new(XfsParser),
        Arc::new(BtrfsParser),
        Arc::new(HfsPlusParser),
        Arc::new(Iso9660Parser),
        Arc::new(UdfParser),
        Arc::new(F2fsParser),
        Arc::new(seance_plugin_squashfs::SquashFsParser),
        // Unlock secrets travel in process memory on the module itself, never
        // through artifact metadata (which is persisted and API-readable).
        // With no secret neither decryptor unlocks anything, but each still
        // reports a volume of its scheme as detected-and-not-unlocked, with
        // the incompleteness pair the attention queue reads (HUNT-196).
        Arc::new(seance_plugin_luks::LuksDecryptor::with_passphrase(
            unlock.luks_passphrase,
        )),
        Arc::new(seance_plugin_bitlocker::BitlockerDecryptor::from_secrets(
            unlock.bitlocker_password,
            unlock.bitlocker_recovery_key,
        )),
        Arc::new(IMessageParser),
        Arc::new(WhatsAppParser),
        Arc::new(AndroidSmsParser),
        Arc::new(InstalledAppsParser),
        // The same question of a Mac: what is installed, and at what version.
        // A Mac states it in each application bundle's own Info.plist
        // (HUNT-110).
        Arc::new(MacInstalledAppsParser::new()),
        Arc::new(AndroidBackupModule),
        Arc::new(SignalParser),
        // The password reaches the parser through process memory only, exactly
        // like the LUKS and BitLocker secrets above. Without one, an encrypted
        // backup takes the honest "present but not extracted" path; with one,
        // its files are decrypted and enter the case.
        match unlock.ios_backup_password {
            Some(password) => {
                Arc::new(IosBackupParser::with_password(password)) as Arc<dyn ForensicsModule>
            }
            None => Arc::new(IosBackupParser::new()),
        },
        // The backup parser above walks a directory on this machine. A phone
        // backed up to a laptop that was then imaged has no such directory, so
        // its manifest is read from the evidence instead: whose phone it was,
        // and when (HUNT-108).
        Arc::new(IosBackupManifestParser::new()),
        Arc::new(CallHistoryParser),
        Arc::new(ContactsParser),
        // macOS behavioural / provenance artifacts.
        Arc::new(QuarantineParser),
        Arc::new(TccParser),
        Arc::new(LaunchdPersistenceParser),
        Arc::new(WifiKnownNetworksParser),
        Arc::new(InstallHistoryParser),
        Arc::new(KnowledgeCParser),
        // Mail's own index of every message it has seen. An index, not the
        // mail: on a machine whose mail was server-hosted it is frequently the
        // only record of who wrote to whom on the disk, and a deleted
        // message's row survives here after its .emlx is gone.
        Arc::new(AppleMailParser),
        Arc::new(NotificationsParser),
        // The Apple System Log store, which is where macOS's wtmpx went:
        // every boot, shutdown, console login, logout and SSH session with
        // the address it came from, under com.apple.system.utmpx and
        // com.apple.system.lastlog. /var/run/utmpx holds only the sessions
        // open at acquisition, so this is the history.
        Arc::new(AslParser),
        // An encrypted store with a CLEARTEXT index: which services and
        // accounts the person held credentials for, and since when, without a
        // password. Every secret is reported as locked, with what a lawful
        // recovery attempt needs and nothing decrypted.
        Arc::new(KeychainParser),
        // The iOS-style keychain macOS also keeps. It names no account and no
        // service -- every such attribute is a SHA-1 -- but it names the
        // application that owns each secret, the protection class, and every
        // device the Apple ID's keychain circle has held.
        Arc::new(DataProtectionKeychainParser),
        // The login, authentication and administration history macOS keeps.
        // `utmpx` holds only the sessions open at acquisition time and there
        // is no macOS `btmp`, so this is where "who logged in last Tuesday,
        // and who tried and failed" is answered.
        Arc::new(OpenBsmParser),
        Arc::new(BomParser),
        Arc::new(UnifiedLogParser),
        Arc::new(UnifiedLogCatalogueParser),
        Arc::new(UnifiedLogTimesyncParser),
        Arc::new(SpotlightStoreParser),
        Arc::new(OcrParser),
        Arc::new(seance_plugin_office::OfficeParser),
        Arc::new(seance_plugin_viber::ViberParser),
        Arc::new(seance_plugin_kik::KikParser),
        Arc::new(seance_plugin_skype::SkypeParser),
        Arc::new(seance_plugin_chrome_cache::ChromeCacheParser),
        Arc::new(seance_plugin_leveldb::LevelDbStorageParser),
        // The findings / triage layer (§2.2): reads what the parsers concluded
        // and raises ranked leads. Detects nothing itself, so it must run
        // after the parsers whose records it reads — which the pipeline
        // guarantees, since a finding subscribes to their output.
        //
        // Every detection here needs a line in `FINDING_DETECTIONS`, or an
        // empty triage list cannot say what this build looked for;
        // `findings_detections_match_registered_modules` fails if one is
        // added without it.
        Arc::new(seance_plugin_findings::TimestompFindings::new()),
        Arc::new(seance_plugin_findings::PeFindings::new()),
        Arc::new(seance_plugin_findings::AsepFindings::new()),
        Arc::new(seance_plugin_findings::HiveFindings::new()),
        // The kernel-side tamper leads. Reads the `tamper_checks` stage's own
        // record: every signal on it was decided by that stage, whose seven
        // groups each had their clean-capture false-positive count measured
        // before they shipped. Nothing here re-derives one.
        Arc::new(seance_plugin_findings::KernelTamperFindings::new()),
        // The third ESE reader; off with `esedb` like SRUM and UAL (REL-003).
        #[cfg(feature = "esedb")]
        Arc::new(seance_plugin_webcache::WebCacheParser),
        Arc::new(seance_plugin_wechat::WeChatParser),
        Arc::new(seance_plugin_line::LineParser),
        Arc::new(seance_plugin_fbmessenger::FbMessengerParser),
        Arc::new(seance_plugin_telegram::TelegramParser),
        Arc::new(seance_plugin_instagram::InstagramParser),
        Arc::new(seance_plugin_snapchat::SnapchatParser),
        Arc::new(seance_plugin_twitter::TwitterParser),
        Arc::new(seance_plugin_pe::PeSignatureParser),
        Arc::new(seance_plugin_ios_artifacts::VoicemailParser),
        // Voice Memos recordings (CloudRecordings.db, wherever the release
        // keeps it), with the audio file each names looked for beside it.
        Arc::new(seance_plugin_ios_artifacts::VoiceMemosParser),
        Arc::new(seance_plugin_ios_artifacts::CalendarDbParser),
        Arc::new(seance_plugin_ios_artifacts::NotesParser),
        // Where the phone was, from the cache the system keeps for itself.
        Arc::new(seance_plugin_ios_artifacts::RoutinedLocationParser),
        Arc::new(seance_plugin_ios_artifacts::PhotosParser),
        Arc::new(seance_plugin_ios_artifacts::PowerLogParser),
        // Safari's three stores are three files: saved bookmarks, the open
        // tabs (SafariTabs.db on iOS 15+, BrowserState.db before it) and the
        // recent searches, which iOS keeps in the app's preferences plist
        // rather than a database.
        Arc::new(seance_plugin_ios_artifacts::SafariBookmarksParser),
        Arc::new(seance_plugin_ios_artifacts::SafariTabsParser),
        Arc::new(seance_plugin_ios_artifacts::SafariSearchesParser),
        // HealthKit samples from healthdb_secure.sqlite, with the source
        // device name resolved from the healthdb.sqlite beside it.
        Arc::new(seance_plugin_ios_artifacts::HealthKitParser),
        Arc::new(seance_plugin_clipboard::ClipboardParser),
        // BITS job queues (qmgr0/1.dat): every job's URL, local path, owner
        // and times; credentials reported present, never decrypted.
        Arc::new(seance_plugin_bits::BitsParser),
        // The RDP client's bitmap cache: each tile a PNG child for the
        // gallery, plus cache-order collages that say they are not screens.
        Arc::new(seance_plugin_rdp_cache::RdpCacheParser),
        // The Windows Search index: self-selects on the Search property table,
        // so every other ESE database produces nothing here.
        #[cfg(feature = "esedb")]
        Arc::new(seance_plugin_winsearch_edb::WinSearchParser),
        // Windows wireless profiles: which networks the machine was configured
        // to join, and the key where the file holds it in the clear.
        Arc::new(seance_plugin_wlan::WlanProfiles),
        Arc::new(seance_plugin_win_timeline::ActivitiesCacheParser),
        // Memory captures: identifies the image, decodes its physical address
        // space and attaches it, so the carver, hasher and search read RAM
        // content directly.
        Arc::new(seance_memory::MemoryImageModule),
        // Analysis proper over that address space: discovers the directory
        // table base, kernel base and matching symbols, then reads processes,
        // modules, network state and registry hives out of kernel memory. Runs
        // on the record the stage above emits, so it never re-detects a format
        // that has already been decoded.
        Arc::new(
            seance_plugin_memory_windows::windows_memory_module_configured(
                memory_patterns,
                strings_source,
            ),
        ),
        // The Linux member of the same tier, over the same record. It locates
        // the kernel by its banner rather than by a debugger data block, since
        // Linux publishes nothing about its own page tables. Both tiers see
        // every memory image and each returns nothing for one that is not its
        // operating system, so registering both costs a banner sweep and gains
        // Linux captures.
        Arc::new(seance_plugin_memory_linux::linux_memory_module()),
        // The macOS member: the Darwin banner, the kernel slide recovered from
        // it, `allproc`, the Mach task queue, the difference between those two
        // listings, and the loaded kernel extensions.
        //
        // It has never been run against a real Mac capture, and it says so on
        // every record it emits rather than being withheld. Withholding it made
        // a Mac capture silent, and silence reads as "nothing was running" --
        // the one claim that is never safe. An examiner can discount a result
        // labelled unvalidated; they cannot discount a result they were never
        // shown. See the module docs above.
        Arc::new(seance_plugin_memory_macos::macos_memory_module()),
        // Linux login accounting: utmp/wtmp/btmp. Failed logins from btmp are
        // among the highest-value records in an intrusion case.
        Arc::new(seance_plugin_utmp::UtmpParser),
        // NTFS $Secure:$SDS — the owner, group and full DACL of every file on
        // the volume, which is where "who could read this" is answered.
        Arc::new(seance_plugin_secure_sds::SecureSdsParser),
        // Windows autostart extensibility points: everything that runs at boot
        // or logon, enumerated by category so an omission is visible.
        Arc::new(seance_plugin_asep::AsepEnumerator::new()),
        Arc::new(seance_plugin_desktop_artifacts::ShellHistoryParser),
        Arc::new(seance_plugin_desktop_artifacts::LinuxTrashParser),
        Arc::new(seance_plugin_desktop_artifacts::RecentFilesParser),
        Arc::new(seance_plugin_desktop_artifacts::ThumbnailsParser),
        Arc::new(seance_plugin_thumbcache::ThumbcacheParser),
        Arc::new(seance_plugin_fsevents::FsEventsParser),
        Arc::new(seance_plugin_dsstore::DSStoreParser),
        // bulk_extractor-style feature extraction over the byte stream. The two
        // automatic members recover AES keys from RAM and sweep unallocated
        // space and memory for selectors (email/URL/card/SSN/IBAN/VIN/GPS); the
        // two opt-in members carve packets to pcap and decode-and-rescan encoded
        // spans. All emit ParsedRecord/FileEntry artifacts, so their results
        // reach the analysis, search, timeline and file-grid views unchanged.
        Arc::new(seance_plugin_bulk::AesKeyScanner),
        Arc::new(seance_plugin_bulk::BulkFeatureScanner),
        Arc::new(seance_plugin_bulk::NetworkPacketCarver),
        Arc::new(seance_plugin_bulk::DecodeRescan),
        Arc::new(seance_search::SearchIndexer::new(search_service)),
    ];

    // YARA hunting is examiner-directed and opt-in, so the scanner is only
    // registered when a rule set has actually been pointed at. Registering it
    // with no rules would put a module in the list that can never match
    // anything, which reads to an examiner as "YARA found nothing" rather than
    // "no rules were loaded" -- opposite claims. A rule set that WAS named and
    // would not load is an error, not an absence: the operator asked for it by
    // path, so the run ends here rather than quietly hunting for nothing.
    if let (Some(path), Some(scanner)) = (yara_rules.as_ref(), yara) {
        info!(
            "YARA rules loaded from {}: {} rule(s). The same compiled set searches memory \
             through the Windows analysis's pattern-scan stage.",
            path.display(),
            scanner.rule_count()
        );
        modules.push(scanner);
    } else {
        info!("No YARA rule set named (SEANCE_YARA_RULES unset); the scanner is not registered.");
    }

    // The same patterns over an image's OWN address space -- upstream's
    // `yarascan` over the physical layer. It is the only route for a capture
    // with no page tables to plan from: a reconstructed hibernation file, a
    // swap area, an acquisition whose operating system could not be profiled.
    // It runs beside the Windows tier's per-process scan rather than instead of
    // it, because a match in a process's own space carries the allocation that
    // held it and a match in an image's space cannot.
    //
    // `ImagePatternScan::new` returns `None` for an empty set list, so a
    // deployment that named nothing does not carry the module at all: a module
    // that is registered, reports success and searches for nothing reads to an
    // examiner as "searched, nothing found".
    match seance_memory::patterns::ImagePatternScan::new(image_patterns) {
        Some(scan) => modules.push(Arc::new(scan)),
        None => info!(
            "No memory patterns named; the image pattern scan is not registered (as the \
             per-process one reports that it did not run)."
        ),
    }

    Ok(modules)
}

/// Register the complete module set on `orchestrator`.
///
/// This is the only function in the workspace that calls
/// [`Orchestrator::register_module`] for the product's module set, and both
/// binaries call it. See the module-level documentation for why.
///
/// Returns the number of modules registered, so a caller can log it and an
/// operator can see at a glance that the pipeline is populated.
pub fn register_all_modules(
    orchestrator: &mut Orchestrator,
    opts: ModuleSetOptions,
) -> anyhow::Result<usize> {
    let modules = build_module_set(orchestrator, opts)?;
    let count = modules.len();
    info!("Starting module registration...");
    for module in modules {
        orchestrator.register_module(module);
    }
    info!("Module registration complete. {count} modules registered");
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ids of the module set the product actually builds.
    ///
    /// Built through the real [`build_module_set`], on a real orchestrator, so a
    /// module that is written, compiled, tested and never put in the list fails
    /// here rather than in a case six months later.
    fn built_module_ids() -> Vec<String> {
        let index = tempfile::tempdir().expect("temp dir for the search index");
        let search_service = Arc::new(
            seance_search::SearchService::new(index.path()).expect("search service for the test"),
        );
        let orchestrator = Orchestrator::new(None, 8);
        let modules: Vec<Arc<dyn ForensicsModule>> =
            build_module_set(&orchestrator, ModuleSetOptions::new(search_service))
                .expect("the module set must build with no YARA rules named");
        modules.iter().map(|m| m.id().to_string()).collect()
    }

    /// The default set **plus** the modules an examiner's configuration adds.
    /// See [`OPT_IN_MODULE_IDS`].
    fn registrable_ids() -> Vec<String> {
        crate::modules::registrable_module_ids(&built_module_ids())
    }

    /// A rule set on disk, so the opt-in modules can actually be built.
    fn a_rule_set() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir for the rules");
        std::fs::write(
            dir.path().join("rules.yar"),
            "rule anything { strings: $a = \"FORENSIC\" condition: $a }",
        )
        .expect("write a rule");
        dir
    }

    /// **The opt-in list is checked against what configuring actually adds.**
    /// A hand-maintained list of module ids is exactly the kind of thing that
    /// rots, so it is not trusted: this builds the set with every knob turned
    /// on and asserts the difference is that list and nothing else.
    #[test]
    fn the_opt_in_ids_are_exactly_what_naming_a_pattern_adds() {
        let index = tempfile::tempdir().expect("temp dir for the search index");
        let search_service = Arc::new(
            seance_search::SearchService::new(index.path()).expect("search service for the test"),
        );
        let orchestrator = Orchestrator::new(None, 8);
        let rules = a_rule_set();

        let mut options = ModuleSetOptions::new(search_service);
        options.yara_rules = Some(rules.path().to_path_buf());
        options.memory_regex = Some("FORENSIC-W1[0-9]".to_string());
        let configured: Vec<String> = build_module_set(&orchestrator, options)
            .expect("a named rule set and pattern build")
            .iter()
            .map(|m| m.id().to_string())
            .collect();

        let default = built_module_ids();
        let mut added: Vec<&String> = configured
            .iter()
            .filter(|id| !default.iter().any(|have| have == *id))
            .collect();
        added.sort();
        let mut expected: Vec<String> = crate::modules::OPT_IN_MODULE_IDS
            .iter()
            .map(|id| (*id).to_string())
            .collect();
        expected.sort();
        assert_eq!(
            added.into_iter().cloned().collect::<Vec<String>>(),
            expected,
            "OPT_IN_MODULE_IDS must name exactly the modules a configuration adds"
        );
    }

    /// **A method statement for a module the product no longer has fails
    /// here.** That is the direction that rots: a module is renamed or
    /// retired, its statement stays, and the register describes a method the
    /// product does not have. Somebody will read it out.
    #[test]
    fn every_method_statement_describes_a_module_the_product_builds() {
        let ids = registrable_ids();
        for described in crate::method_statements::described_ids() {
            assert!(
                ids.iter().any(|id| id == described),
                "documentation/METHOD_STATEMENTS.md carries a method statement for {described:?} \
                 and the product builds no module with that id. A stale method statement is \
                 worse than a missing one: it will be read out."
            );
        }
    }

    /// The register on disk is what this code generates from the module set the
    /// product builds — so its headline count is a statement about the
    /// product, and a module added without regenerating it fails here rather
    /// than leaving the file quietly wrong.
    #[test]
    fn the_committed_register_matches_the_module_set() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the crate has a parent directory")
            .join("documentation/METHOD_STATEMENTS.md");
        let Ok(on_disk) = std::fs::read_to_string(&path) else {
            eprintln!("skipped: {} is not present", path.display());
            return;
        };
        let generated = crate::method_statements::render_register(&registrable_ids());
        assert_eq!(
            on_disk, generated,
            "documentation/METHOD_STATEMENTS.md is generated from the module set. Regenerate it \
             with `cargo run -p seance_api --bin method-statements` (or the test's own output) \
             rather than editing it: its headline counts how many of the product's modules have \
             a statement, and a hand-edited file makes that a claim about the file."
        );
    }

    /// Every written statement says what its module CANNOT do, and what it
    /// refuses. A statement that lists only capabilities is a brochure, and
    /// the whole point of the register is the other half.
    #[test]
    fn every_written_statement_says_what_the_module_cannot_do() {
        for s in crate::method_statements::STATEMENTS {
            for (field, text) in [
                ("reads", s.reads),
                ("produces", s.produces),
                ("cannot", s.cannot),
                ("refuses", s.refuses),
            ] {
                assert!(
                    text.len() > 60,
                    "{}'s `{field}` is {} characters. A method statement is read aloud; a \
                     phrase is not one.",
                    s.module_id,
                    text.len()
                );
            }
            assert!(
                s.cannot.contains("cannot") || s.cannot.contains("not"),
                "{}'s `cannot` must state a limit in words: {:?}",
                s.module_id,
                s.cannot
            );
            assert!(
                s.refuses.contains("refuse"),
                "{}'s `refuses` must name the refusal: {:?}",
                s.module_id,
                s.refuses
            );
        }
    }

    /// And no two statements describe the same module.
    #[test]
    fn no_module_has_two_method_statements() {
        let mut seen = std::collections::BTreeSet::new();
        for id in crate::method_statements::described_ids() {
            assert!(seen.insert(id), "two method statements for {id:?}");
        }
    }

    /// A memory capture of any operating system Séance claims to read must reach
    /// an analysis that can read it.
    ///
    /// The macOS entry is the one this test was written for: the tier existed,
    /// compiled and passed its own tests while being registered by neither
    /// binary, so a Mac capture was identified as a memory image and then
    /// examined by nothing. Every stage reported `did_not_run`, which is the
    /// same thing a case shows for a machine that was running nothing at all.
    /// Named by their crates' own `MODULE_ID` constants, so a rename on either
    /// side fails the build instead of quietly emptying the set.
    #[test]
    fn a_capture_of_each_supported_operating_system_reaches_a_memory_analysis() {
        let ids = built_module_ids();
        for id in [
            seance_plugin_memory_windows::MODULE_ID,
            seance_plugin_memory_linux::MODULE_ID,
            seance_plugin_memory_macos::MODULE_ID,
        ] {
            assert!(
                ids.iter().any(|registered| registered == id),
                "no module with id {id:?} is registered, so a capture of that operating system \
                 is stored, identified, and analysed by nothing -- an outcome an examiner cannot \
                 tell apart from a capture that held no processes. Registered ids: {ids:?}"
            );
        }
    }

    /// Every iOS artifact parser the crate exports is in the product's set.
    ///
    /// The four Safari and HealthKit parsers were written, tested against the
    /// Magnet 2022 iPhone 8 fixtures and never put in the list, so the product
    /// could not reach them while their crate claimed them as shipped. Named by
    /// the modules' own `id()`s, so a rename fails here rather than quietly
    /// dropping one.
    #[test]
    fn every_ios_artifact_parser_the_crate_exports_is_registered() {
        let ids = built_module_ids();
        let exported: [Arc<dyn ForensicsModule>; 11] = [
            Arc::new(seance_plugin_ios_artifacts::VoicemailParser),
            Arc::new(seance_plugin_ios_artifacts::VoiceMemosParser),
            Arc::new(seance_plugin_ios_artifacts::CalendarDbParser),
            Arc::new(seance_plugin_ios_artifacts::NotesParser),
            Arc::new(seance_plugin_ios_artifacts::RoutinedLocationParser),
            Arc::new(seance_plugin_ios_artifacts::PhotosParser),
            Arc::new(seance_plugin_ios_artifacts::PowerLogParser),
            Arc::new(seance_plugin_ios_artifacts::SafariBookmarksParser),
            Arc::new(seance_plugin_ios_artifacts::SafariTabsParser),
            Arc::new(seance_plugin_ios_artifacts::SafariSearchesParser),
            Arc::new(seance_plugin_ios_artifacts::HealthKitParser),
        ];
        for module in exported {
            let id = module.id();
            assert!(
                ids.iter().any(|registered| registered == id),
                "seance_plugin_ios_artifacts exports {id:?} and the product registers no module \
                 with that id, so the store it reads is raw-dumped and its records never appear. \
                 Registered ids: {ids:?}"
            );
        }
    }

    /// The macOS tier is registered *and* still says it has never been
    /// validated.
    ///
    /// The two halves are one decision. Registering it without the marker would
    /// put process listings nobody has checked in front of an examiner as
    /// ordinary findings; the marker without the registration is what the
    /// product had, and it disclosed nothing because there was nothing to
    /// disclose it on.
    #[test]
    fn the_macos_tier_is_registered_under_a_marker_that_says_it_is_unvalidated() {
        let macos = seance_plugin_memory_macos::MODULE_ID;
        let ids = built_module_ids();
        assert!(
            ids.iter().any(|id| id == macos),
            "the macOS memory tier is not in the module set"
        );

        let stamp = seance_plugin_memory_macos::unvalidated_stamp();
        assert_eq!(
            stamp["validated_against_real_capture"],
            serde_json::json!(false),
            "the macOS tier is registered but no longer marks its records unvalidated; either it \
             has been validated against a real capture (in which case say so here and in the \
             help) or the marker has been lost"
        );
        assert!(
            stamp["validation_notice"]
                .as_str()
                .is_some_and(|n| !n.is_empty()),
            "the marker carries no sentence for an examiner to read"
        );
    }
}
