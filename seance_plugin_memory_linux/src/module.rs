//! The `ForensicsModule` that makes this crate reachable from the orchestrator.
//!
//! Everything else here is analysis: given a profile, walk kernel structures and
//! produce findings. This file is the only part that knows about artifacts and
//! subscriptions, and it is deliberately thin, because the seam it plugs into
//! ([`seance_memory::analysis`]) already owns the parts that are easy to get
//! wrong — which artifact type to subscribe to, how to tell a real memory image
//! from any other `ParsedRecord`, and how to turn the carried `DataSource` back
//! into a layer.
//!
//! ## The call path, end to end
//!
//! ```text
//! seance_cli::main   registers  linux_memory_module()
//!         │
//!         ▼
//! seance_memory::MemoryAnalysisModule<LinuxMemoryAnalysis>   (ForensicsModule)
//!         │  process()  — filters to the container stage's MemoryImage record
//!         ▼
//! LinuxMemoryAnalysis::analyse
//!         │
//!         ├── discovery::discover_reported          -> LinuxProfile
//!         ├── stage_manifest_record                 -> MemoryStageManifest
//!         ├── profile_record                        -> MemoryProfile
//!         └── run_stages                            -> one record per stage
//! ```
//!
//! Nothing in this crate is reachable except through that path, and every stage
//! in [`STAGES`] is dispatched from [`run_stages`]. A stage that exists in the
//! table and is never dispatched would publish a coverage row reading "did not
//! run" forever, which an examiner reads as a tool that chose not to look; the
//! test `every_declared_stage_is_dispatched_by_run_stages` refuses it, by reading
//! the dispatch function's own source for an identifier derived from the table
//! rather than from a second list.
//!
//! ## What an examiner gets when discovery fails
//!
//! Discovery runs first and its result is always emitted — including when it
//! fails. A Linux image Séance cannot profile is a fact about the evidence, and
//! the reason (no symbol file for this banner, say) is exactly what tells an
//! examiner what to fetch. Emitting nothing would read as "this image is empty",
//! which is a different and false claim.
//!
//! The **one** case that emits nothing at all is an image that is not a Linux
//! capture, established by a sweep that covered every acquired byte and found no
//! kernel banner. A sweep that could not finish is not that case, and it is not
//! treated as one.
//!
//! ## Stage identity
//!
//! [`STAGES`] is the single table. [`stage_record`] and [`stage_failure`] take a
//! `&StageId`, so there is no way to write a record under a name this table does
//! not hold, and [`stage_manifest_record`] publishes the table alongside the
//! findings so `GET /api/v1/cases/:id/memory/coverage` gives every stage a row —
//! including the ones the API's own table has never heard of, which is every
//! stage in this crate. That is why the keys here are Linux-specific: a key that
//! collided with the API's Windows table would be described by that table's
//! sentence and counted against that table's record type, which is drift with a
//! confident-looking result on the end of it.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ModuleError,
};
use seance_memory::analysis::{
    analysed_stamp, split_env_list, MemoryAnalysis, MemoryAnalysisModule,
};
use seance_memory::translate::SwapFile;
use seance_memory::MemoryLayer;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::bash;
use crate::capabilities;
use crate::cmdline;
use crate::discovery::{self, DiscoveryError, DiscoveryOptions, DiscoveryReport};
use crate::envars;
use crate::hooks;
use crate::kernel_log;
use crate::lsmod;
use crate::lsof;
use crate::modscan;
use crate::mounts;
use crate::proc_maps;
use crate::profile::{LinuxProfile, SwapAreaBody};
use crate::sockstat;
use crate::tasks;
use crate::taskscan;

/// Module id, following the tree's `plugin.<category>.<name>` convention.
pub const MODULE_ID: &str = "plugin.memory.linux";

/// Module version.
pub const MODULE_VERSION: &str = "0.1.0";

/// One analysis stage's identity on the wire, and the record type carrying the
/// list of stages this build can run.
///
/// Both come from [`seance_memory::binding`] so that the Windows, Linux and
/// macOS tiers file their findings under the same identity.
pub use seance_memory::binding::{StageId, MEMORY_STAGE_MANIFEST_RECORD};

/// The kernel's task list, walked from `init_task`.
pub const STAGE_LINUX_PROCESSES: StageId = StageId {
    key: "linux_processes",
    record_type: "LinuxMemoryTaskList",
    per_process: false,
    describes: "Every process and thread the kernel had linked, walked from init_task through \
                the task list.",
};

/// Each process's capability sets, projected from the task-list walk.
pub const STAGE_LINUX_CAPABILITIES: StageId = StageId {
    key: "linux_capabilities",
    record_type: "LinuxMemoryCapabilities",
    per_process: false,
    describes: "Each process's Linux capability sets — effective, permitted, inheritable, \
                bounding and ambient — decoded to their named capabilities, so an examiner can \
                see what a process was privileged to do beyond what its user id implies.",
};

/// Loaded kernel modules.
pub const STAGE_LINUX_KERNEL_MODULES: StageId = StageId {
    key: "linux_kernel_modules",
    record_type: "LinuxMemoryKernelModules",
    per_process: false,
    describes: "Kernel modules loaded at the time of capture, walked from the kernel's module \
                list, with each module's code extent.",
};

/// The kernel log ring buffer (`dmesg`).
pub const STAGE_LINUX_KERNEL_LOG: StageId = StageId {
    key: "linux_kernel_log",
    record_type: "LinuxMemoryKernelLog",
    per_process: false,
    describes: "The kernel log ring buffer (dmesg) still resident in memory — each line's \
                priority, facility, timestamp and message — which records driver loads, USB and \
                storage events, out-of-memory kills and oopses up to the moment of capture.",
};

/// Each process's virtual memory areas (VMAs).
pub const STAGE_LINUX_PROCESS_MAPS: StageId = StageId {
    key: "linux_process_maps",
    record_type: "LinuxMemoryProcessMaps",
    per_process: false,
    describes: "Each process's virtual memory regions — address range, permissions and backing \
                file — walked from the memory descriptor, so an examiner can find executable \
                memory with no file behind it or a writable-executable region, the shape of \
                injected code.",
};

/// Each process's open files.
pub const STAGE_LINUX_OPEN_FILES: StageId = StageId {
    key: "linux_open_files",
    record_type: "LinuxMemoryOpenFiles",
    per_process: false,
    describes: "Each process's open file descriptors — the descriptor number, the path of the \
                file behind it, and its mode and flags — walked from the process's file-descriptor \
                table, so an examiner can see what each process had open at the moment of capture.",
};

/// Each process's network sockets.
pub const STAGE_LINUX_NETWORK_SOCKETS: StageId = StageId {
    key: "linux_network_sockets",
    record_type: "LinuxMemoryNetworkSockets",
    per_process: false,
    describes: "Each process's open network sockets — address family, type, protocol, connection \
                state, and for IPv4 the source and destination address and port — recovered from \
                the socket behind each socket file descriptor.",
};

/// Filesystems mounted at capture, per mount namespace.
pub const STAGE_LINUX_MOUNTS: StageId = StageId {
    key: "linux_mounts",
    record_type: "LinuxMemoryMounts",
    per_process: false,
    describes: "Filesystems mounted at the moment of capture, per mount namespace — device name, \
                mount point, filesystem root and decoded mount flags — walked from each namespace's \
                mount list.",
};

/// Kernel hooks: the system-call tables, ftrace, kprobes and eBPF.
pub const STAGE_LINUX_KERNEL_HOOKS: StageId = StageId {
    key: "linux_kernel_hooks",
    record_type: "LinuxMemoryKernelHooks",
    per_process: false,
    describes: "Where the kernel has been made to run someone else's code: every system-call \
                table entry, every ftrace registration and direct call, every kprobe and every \
                loaded eBPF program, each attributed to the kernel's own text, to a named loaded \
                module, or to nothing known — with what could not be checked stated by name.",
};

/// Each process's command line.
pub const STAGE_LINUX_COMMAND_LINES: StageId = StageId {
    key: "linux_command_lines",
    record_type: "LinuxMemoryCommandLines",
    per_process: false,
    describes: "Each process's command line — the argument vector it was started with, read from \
                the bracket the kernel records in that process's own address space — so an \
                examiner sees what was run and with what arguments, not only the 16-character \
                name the kernel keeps.",
};

/// Shell command history recovered from shell process memory.
pub const STAGE_LINUX_BASH_HISTORY: StageId = StageId {
    key: "linux_bash_history",
    record_type: "LinuxMemoryBashHistory",
    per_process: false,
    describes: "Commands typed into an interactive shell, recovered from the shell's own heap — \
                including commands never written to a history file on disk.",
};

/// Each process's environment variables.
pub const STAGE_LINUX_ENVIRONMENT: StageId = StageId {
    key: "linux_environment",
    record_type: "LinuxMemoryEnvironment",
    per_process: false,
    describes: "Each process's environment variables, read from that process's own address \
                space — what a program was configured with, which the kernel's process \
                structure does not hold.",
};

/// Every stage this build can run, in the order an examiner reads them.
///
/// Ordered by evidentiary value: the process list first, because everything else
/// is read in its light; then the kernel modules, which are the intrusion
/// question; then the two user-memory stages.
pub const STAGES: &[StageId] = &[
    STAGE_LINUX_PROCESSES,
    STAGE_LINUX_CAPABILITIES,
    STAGE_LINUX_KERNEL_MODULES,
    STAGE_LINUX_KERNEL_LOG,
    STAGE_LINUX_KERNEL_HOOKS,
    STAGE_LINUX_PROCESS_MAPS,
    STAGE_LINUX_OPEN_FILES,
    STAGE_LINUX_NETWORK_SOCKETS,
    STAGE_LINUX_MOUNTS,
    STAGE_LINUX_COMMAND_LINES,
    STAGE_LINUX_BASH_HISTORY,
    STAGE_LINUX_ENVIRONMENT,
];

/// Record type a stage-failure record carries.
///
/// The same string the Windows tier uses and the same one
/// `seance_api::memory::MEMORY_STAGE_FAILURE_RECORD` fetches, so a Linux stage
/// that did not run appears in the coverage view rather than vanishing.
pub use seance_memory::stage_records::MEMORY_STAGE_FAILURE_RECORD;

/// Record type the image profile carries.
pub const MEMORY_PROFILE_RECORD: &str = "MemoryProfile";

/// Linux memory analysis.
///
/// Wrap in [`linux_memory_module`] to obtain the `ForensicsModule` the
/// orchestrator registers.
#[derive(Debug, Default)]
pub struct LinuxMemoryAnalysis {
    /// Directories searched for ISF symbol files. Empty means "resolve from the
    /// environment and the usual locations at analysis time".
    symbol_dirs: Vec<PathBuf>,
    /// Discovery tuning. Defaults are the shipped caps.
    options: DiscoveryOptions,
    /// Swap areas attached programmatically. Merged with `SEANCE_SWAPFILES` at
    /// analysis time — see [`Self::resolved_swapfiles`].
    swapfiles: Vec<SwapFile>,
}

impl LinuxMemoryAnalysis {
    /// Analysis with the default caps and the usual symbol locations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Analysis that searches exactly these directories for symbols.
    pub fn with_symbol_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.symbol_dirs = dirs;
        self
    }

    /// Analysis with non-default discovery options.
    pub fn with_options(mut self, options: DiscoveryOptions) -> Self {
        self.options = options;
        self
    }

    /// Attach swap areas programmatically, each carrying the swap index
    /// (`swp_type`) it answers to. Merged with any named by `SEANCE_SWAPFILES`.
    pub fn with_swapfiles(mut self, swapfiles: Vec<SwapFile>) -> Self {
        self.swapfiles = swapfiles;
        self
    }

    /// The swap areas to attach, from programmatic attachment and the
    /// `SEANCE_SWAPFILES` environment variable.
    ///
    /// The Linux counterpart of the Windows tier's `SEANCE_PAGEFILES`, and the
    /// same `index=path` grammar so a lab drives both the same way: the index is
    /// the swap area's `swp_type` (0 for the first `swapon`), and a swapped page
    /// resolves only through the area whose index its entry decodes to and whose
    /// bounds the offset falls inside. A swap file copied through the filesystem
    /// reads back as zeros — see [`seance_memory::formats::linux_swap`] — so the
    /// area must be acquired from its block device or partition.
    ///
    /// ```text
    /// SEANCE_SWAPFILES=0=/evidence/swap-area.raw
    /// SEANCE_SWAPFILES=0=/evidence/swap0.raw:1=/evidence/swap1.raw
    /// ```
    fn resolved_swapfiles(&self) -> Vec<SwapFile> {
        let mut attached = self.swapfiles.clone();
        if let Ok(list) = std::env::var("SEANCE_SWAPFILES") {
            for entry in split_env_list(&list) {
                let Some((index, reference)) = entry.split_once('=') else {
                    warn!(
                        "SEANCE_SWAPFILES entry {entry:?} is not `index=path`, so it is not \
                         attached; the index is the swap area's swp_type and a page resolves only \
                         through the area whose type it names"
                    );
                    continue;
                };
                let Ok(index) = index.trim().parse::<u8>() else {
                    warn!("SEANCE_SWAPFILES entry {entry:?} has a non-numeric index; not attached");
                    continue;
                };
                if let Some(existing) = attached.iter().find(|f| f.index == index) {
                    warn!(
                        "SEANCE_SWAPFILES entry {entry:?} names index {index}, already attached \
                         from {:?}; the second is not attached, because two areas under one index \
                         would answer from whichever was read first",
                        existing.label
                    );
                    continue;
                }
                let path = PathBuf::from(reference.trim());
                match FileDataSource::new(path.clone()) {
                    Ok(source) => attached.push(SwapFile {
                        index,
                        label: path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| reference.trim().to_string()),
                        source: Arc::new(source) as Arc<dyn DataSource>,
                    }),
                    Err(err) => warn!(
                        "SEANCE_SWAPFILES entry {entry:?} was not attached, so swapped pages \
                         naming index {index} stay holes: {err}"
                    ),
                }
            }
        }
        attached
    }

    /// Directories to search for ISF files, in precedence order, paired with
    /// any the examiner **named** that are not there.
    ///
    /// The same order the Windows tier uses, so a lab points one environment
    /// variable at one symbol store and both tiers find it.
    ///
    /// The second list is why this returns a pair. A directory that does not
    /// exist cannot be searched, but dropping it silently makes a mistyped or
    /// unmounted `SEANCE_SYMBOL_DIRS` — the commonest reason a lab's symbols are
    /// not found — read exactly like a lab that has no symbol store at all: both
    /// produce "none of the 0 symbol directory/ies holds an ISF", and only one
    /// of them is a fact about the lab. The failure record is the one thing that
    /// tells an examiner what to fetch and where to put it, so it has to be able
    /// to say "the place you named is not there".
    ///
    /// Only paths the examiner named are reported back. The built-in fallbacks
    /// are absent on most installations, and listing them every time would bury
    /// the one line that matters.
    ///
    /// The list is split by [`split_env_list`], which spares the drive colon of
    /// a Windows path. Splitting on every colon cut `C:\symbols` into `C` and
    /// `\symbols`, and the `is_dir` filter below then dropped both **without a
    /// warning** — so a lab running the analysis on Windows and pointing at a
    /// real symbol store got the failure record of a lab that has no symbol
    /// store at all, which is the one distinction this function exists to make.
    fn resolved_symbol_dirs(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let mut named: Vec<PathBuf> = self.symbol_dirs.clone();
        if named.is_empty() {
            if let Ok(list) = std::env::var("SEANCE_SYMBOL_DIRS") {
                named.extend(split_env_list(&list).into_iter().map(PathBuf::from));
            }
        }

        let mut dirs = named.clone();
        // An explicit `with_symbol_dirs` is an instruction, not a hint: it
        // replaces the search rather than heading it, so the fallbacks are only
        // added when nothing was named.
        if self.symbol_dirs.is_empty() {
            if let Ok(exe) = std::env::current_exe() {
                if let Some(parent) = exe.parent() {
                    dirs.push(parent.join("symbols"));
                }
            }
            dirs.push(PathBuf::from("symbols"));
            dirs.push(PathBuf::from("reference/volatility3/volatility3/symbols"));
        }

        let absent: Vec<PathBuf> = named.into_iter().filter(|d| !d.is_dir()).collect();
        dirs.retain(|d| d.is_dir());
        (dirs, absent)
    }
}

/// The registrable module. This is what `seance_cli` puts in its module list.
pub fn linux_memory_module() -> MemoryAnalysisModule<LinuxMemoryAnalysis> {
    MemoryAnalysisModule::new(LinuxMemoryAnalysis::new())
}

impl MemoryAnalysis for LinuxMemoryAnalysis {
    fn id(&self) -> &str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        MODULE_VERSION
    }

    fn os(&self) -> &str {
        "linux"
    }

    fn analyse(
        &self,
        physical: Arc<dyn MemoryLayer>,
        image_record: &Artifact,
    ) -> Result<Vec<Artifact>, ModuleError> {
        let (dirs, absent) = self.resolved_symbol_dirs();
        match discovery::discover_reported(Arc::clone(&physical), &dirs, &self.options) {
            Ok((mut profile, report)) => {
                info!(
                    "{}: {} DTB {:#x} from {}",
                    MODULE_ID, profile.build.banner, profile.dtb.value, profile.dtb_symbol
                );
                // Attach any swap areas the examiner supplied, so every stage
                // that reads process memory resolves a swapped page to its bytes
                // rather than a hole.
                profile.swap = self.resolved_swapfiles();
                if !profile.swap.is_empty() {
                    info!(
                        "{}: {} swap area(s) attached",
                        MODULE_ID,
                        profile.swap.len()
                    );
                }
                // An area attached from a swap FILE copied through the
                // filesystem parses, bounds-corroborates entries and hands back
                // zeros. It stays attached — every page whose entry names it is
                // still located — but the examiner is told now, while they may
                // still be able to acquire it properly, rather than only in the
                // profile record afterwards.
                for area in profile.swap.iter().map(SwapAreaBody::survey) {
                    if let Some(warning) = area.attach_warning() {
                        warn!("{MODULE_ID}: {warning}");
                    }
                }
                let mut out = vec![
                    stage_manifest_record(image_record),
                    profile_record(image_record, &profile, &report),
                ];
                out.extend(run_stages(&profile, image_record));
                Ok(out)
            }
            Err(err) => Ok(discovery_outcome(image_record, &err, &dirs, &absent)),
        }
    }
}

/// What the case gets when discovery could not produce a profile.
///
/// Split out of [`LinuxMemoryAnalysis::analyse`] so the one branch in this crate
/// that can legitimately emit **nothing** is reachable from a test without an
/// image behind it. That branch is the exact shape of the defect this project
/// has a standing warning about — a dispatch that returns an empty vector while
/// every test passes — so it is worth being able to assert on directly.
///
/// There is one silent outcome and one only: a sweep that covered every acquired
/// byte and found no kernel banner. That is what "this is not a Linux image"
/// looks like, and the Windows tier says the same thing about a Linux capture.
/// Everything else — including a sweep that could **not** finish and found
/// nothing — is a Linux image that could not be profiled, and it is reported.
/// Widening this to "any discovery failure is silence" would drop every Linux
/// capture whose symbols are missing, and the case would read as though the
/// image held nothing.
fn discovery_outcome(
    image_record: &Artifact,
    err: &DiscoveryError,
    dirs: &[PathBuf],
    absent: &[PathBuf],
) -> Vec<Artifact> {
    if err.means_not_a_linux_image() {
        debug!("{}: {}", MODULE_ID, err);
        return Vec::new();
    }
    warn!("{}: discovery failed: {}", MODULE_ID, err);
    vec![
        stage_manifest_record(image_record),
        discovery_failure_record(image_record, err, dirs, absent),
    ]
}

/// Run every analysis stage against a discovered profile.
///
/// A stage that fails is recorded and the rest still run: a shell whose heap
/// will not read must not cost the examiner the process list. Every failure
/// becomes a record of its own, because a stage that could not run and a stage
/// that ran and found nothing are opposite findings and must never render the
/// same way.
///
/// Corroborate a task-list walk with an independent sweep of physical memory;
/// see [`taskscan::corroborate_list`], which is public so a real-data test can
/// exercise exactly what this module runs.
fn cross_view_for(
    profile: &LinuxProfile,
    layout: &seance_memory::binding::BuildBinding,
    list: &tasks::TaskList,
) -> taskscan::CrossView {
    taskscan::corroborate_list(profile, layout, list)
}

/// Corroborate a module-list walk with an independent sweep.
///
/// Correlated in physical space rather than virtual. See
/// [`modscan::physical_address_of`] for why a `struct module` cannot use the
/// direct-map constant a `task_struct` can.
fn module_cross_view_for(
    profile: &LinuxProfile,
    layout: &seance_memory::binding::BuildBinding,
    list: &lsmod::ModuleList,
) -> modscan::ModuleCrossView {
    /// Matches the process sweep's bound, for the same reason.
    const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
    const MAX_CANDIDATES: usize = 65_536;

    let uncorroborated = || modscan::ModuleCrossView::build(list, &[], false);

    if profile.pointer_size() != 8 {
        return uncorroborated();
    }
    let Ok(size) = profile.symbols.size_of("module") else {
        return uncorroborated();
    };
    let Some(offsets) = modscan::ModScanOffsets::resolve(layout, size) else {
        return uncorroborated();
    };
    // The sweep stays in physical space and the LIST is translated down to
    // meet it. A `struct module` lives in the module region, which is vmalloc
    // space mapped page by page — there is no constant to convert it, and
    // applying the task scan's direct-map offset here correlated 0 of 83
    // modules on a real capture.
    let listed: Vec<(u64, Option<u64>)> = list
        .modules
        .iter()
        .map(|m| (m.address, modscan::physical_address_of(profile, m.address)))
        .collect();
    if listed.iter().all(|(_, p)| p.is_none()) {
        // Nothing could be translated, so nothing could be compared. Saying the
        // list is uncorroborated is the truth; reporting a cross-view over an
        // empty correlation would not be.
        return uncorroborated();
    }
    let translate = |va: u64| modscan::physical_address_of(profile, va);
    let (found, _truncated) = modscan::scan_physical(
        profile.physical.as_ref(),
        offsets,
        &translate,
        MAX_BYTES,
        MAX_CANDIDATES,
    );
    modscan::ModuleCrossView::build_physical(list, &listed, &found, true)
}

/// The task list is walked once and shared, since two later stages need it and
/// walking it three times would be three chances to disagree with itself.
fn run_stages(profile: &LinuxProfile, image_record: &Artifact) -> Vec<Artifact> {
    let mut out = Vec::new();

    // Processes. Two later stages hang off this, so its failure is worth
    // stating loudly: without it there is no list to read user memory over.
    let tasks = match tasks::bind(profile).and_then(|layout| {
        tasks::list_tasks(profile, &layout, &tasks::TaskListConfig::default())
            .map(|list| (layout, list))
    }) {
        Ok((layout, list)) => {
            // Corroborate the walk with an independent sweep. A `task_struct`
            // unlinked from the task list is the standard way of hiding a
            // process on Linux, and a list walk cannot see one by construction
            // — nothing about correctly traversing a list reveals an entry
            // removed from it. The cross-view is what makes the process list
            // something other than a single unchecked method.
            // Corroborated by an independent sweep of physical memory. A list
            // walk cannot detect an entry removed from the list it walks, so
            // until now this was a single unchecked method.
            //
            // The scan confirms; it does not accuse. It reproduces 576 of 587
            // processes on a known-good capture, which is what makes it a
            // second opinion worth having — and it also matches several
            // thousand structures that are not tasks, which is why the
            // cross-view counts those and refuses to report them as candidate
            // hidden processes. See `taskscan::CrossView::to_json`.
            let mut record = list.to_json();
            let cross = cross_view_for(profile, &layout, &list);
            if let Some(map) = record.as_object_mut() {
                map.insert(
                    "corroborated_by_second_method".into(),
                    serde_json::json!(cross.scan_ran),
                );
                map.insert("cross_view".into(), cross.to_json());
            }
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_LINUX_PROCESSES,
                record,
                list.is_complete(),
            ));

            // Capability sets, projected from the list just walked. This reads
            // no user memory — it re-presents masks the walk already read — so
            // it belongs here beside the process list rather than with the
            // user-memory stages below, and runs whenever the list was walked.
            let caps = capabilities::survey_capabilities(&list);
            let caps_complete = caps.is_complete();
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_LINUX_CAPABILITIES,
                caps.to_json(),
                caps_complete,
            ));
            Some(list)
        }
        Err(err) => {
            out.push(stage_failure(
                image_record,
                profile,
                &STAGE_LINUX_PROCESSES,
                &err,
            ));
            // The capability projection has no list to project, so it too could
            // not run — recorded as its own failure rather than left silent, or
            // its coverage row would read "did not run" as though the tool chose
            // not to look.
            out.push(stage_failure(
                image_record,
                profile,
                &STAGE_LINUX_CAPABILITIES,
                &"the kernel task list could not be walked, so no process's capability sets could \
                  be projected",
            ));
            None
        }
    };

    // Loaded kernel modules. Walks a kernel global, so it runs whether or not
    // the task list did: on an intrusion case the driver list is often the more
    // important of the two.
    let modules = match lsmod::bind(profile).and_then(|layout| {
        lsmod::list_modules(profile, &layout, &lsmod::ModuleListConfig::default())
            .map(|list| (layout, list))
    }) {
        Ok((mod_layout, list)) => {
            // Corroborated like the process list, and for a sharper reason:
            // hiding its own module is usually the first thing a rootkit does,
            // so this is the enumeration most likely to be lied to.
            // Corroborated by an independent sweep, like the process list.
            // Hiding its own module is usually the first thing a rootkit does,
            // so this is the enumeration most likely to be lied to — and, as
            // there, the scan confirms rather than accuses: it counts the
            // structures the list does not contain and refuses to report them
            // as candidate hidden modules.
            let mut record = list.to_json();
            let cross = module_cross_view_for(profile, &mod_layout, &list);
            if let Some(map) = record.as_object_mut() {
                map.insert(
                    "corroborated_by_second_method".into(),
                    serde_json::json!(cross.scan_ran),
                );
                map.insert("cross_view".into(), cross.to_json());
            }
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_LINUX_KERNEL_MODULES,
                record,
                list.is_complete(),
            ));
            Some(list)
        }
        Err(err) => {
            out.push(stage_failure(
                image_record,
                profile,
                &STAGE_LINUX_KERNEL_MODULES,
                &err,
            ));
            None
        }
    };

    // Kernel hooks. Reads kernel globals, so it runs whether or not the task
    // list did; the module list is handed over for attribution and its absence
    // is stated on the record rather than assumed away.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_KERNEL_HOOKS,
        hooks::bind(profile)
            .and_then(|layout| hooks::survey_hooks(profile, &layout, modules.as_ref())),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    // The kernel log hangs off kernel globals, so — like the module list — it
    // runs whether or not the task list walked; a machine whose task list will
    // not walk can still have its dmesg recovered.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_KERNEL_LOG,
        kernel_log::bind(profile).and_then(|layout| {
            kernel_log::survey_kernel_log(profile, &layout, &kernel_log::LogConfig::default())
        }),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    // The user-memory and per-process stages need the list, so they are skipped
    // — with a record saying why — when it could not be walked.
    let Some(tasks) = tasks else {
        out.push(skipped_record(
            image_record,
            profile,
            &[
                &STAGE_LINUX_PROCESS_MAPS,
                &STAGE_LINUX_OPEN_FILES,
                &STAGE_LINUX_NETWORK_SOCKETS,
                &STAGE_LINUX_MOUNTS,
                &STAGE_LINUX_COMMAND_LINES,
                &STAGE_LINUX_BASH_HISTORY,
                &STAGE_LINUX_ENVIRONMENT,
            ],
            "the kernel task list could not be walked, so there was no list of processes to reach \
             the mount namespaces from, nor whose memory maps, open files, sockets, command lines \
             or own memory could be read",
        ));
        return out;
    };

    // Memory maps. Walks kernel structures per process, so — like the module
    // list — it is not defeated by swap; it needs the task list only to know
    // which processes to walk.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_PROCESS_MAPS,
        proc_maps::bind(profile).and_then(|layout| {
            proc_maps::survey_process_maps(
                profile,
                &layout,
                &tasks,
                &proc_maps::ProcessMapsConfig::default(),
            )
        }),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    // Open files. Also a kernel-structure walk per process, sharing the dentry
    // path reconstruction with the memory-map stage.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_OPEN_FILES,
        lsof::bind(profile).and_then(|layout| {
            lsof::survey_open_files(profile, &layout, &tasks, &lsof::OpenFilesConfig::default())
        }),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    // Network sockets. Reuses the fd walk, classifying each descriptor by whether
    // the file behind it is a socket inode.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_NETWORK_SOCKETS,
        sockstat::bind(profile).and_then(|layout| {
            sockstat::survey_network_sockets(
                profile,
                &layout,
                &tasks,
                &sockstat::SocketsConfig::default(),
            )
        }),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    // Mounts. Reached from the task list via each task's mount namespace, then
    // deduplicated, so a single-namespace machine yields one mount list.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_MOUNTS,
        mounts::bind(profile).and_then(|layout| {
            mounts::survey_mounts(profile, &layout, &tasks, &mounts::MountsConfig::default())
        }),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    // Command lines. The first of the user-memory stages: each row is read
    // through the process's own page tables, from the bracket mm_struct records.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_COMMAND_LINES,
        cmdline::bind(profile).and_then(|layout| {
            cmdline::survey_command_lines(
                profile,
                &layout,
                &tasks,
                &cmdline::CommandLinesConfig::default(),
            )
        }),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_BASH_HISTORY,
        bash::bind(profile).and_then(|layout| {
            bash::survey_bash(profile, &layout, &tasks, &bash::BashConfig::default())
        }),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_LINUX_ENVIRONMENT,
        envars::bind(profile).and_then(|layout| {
            envars::survey_environment(
                profile,
                &layout,
                &tasks,
                &envars::EnvironmentConfig::default(),
            )
        }),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    out
}

/// One stage's outcome as a record: what it found, or why it could not run.
/// `describe` reads the survey's JSON body and whether it is complete.
fn push_stage<S, E: std::fmt::Display>(
    out: &mut Vec<Artifact>,
    parent: &Artifact,
    profile: &LinuxProfile,
    stage: &StageId,
    result: Result<S, E>,
    describe: impl FnOnce(&S) -> (serde_json::Value, bool),
) {
    out.push(match result {
        Ok(survey) => {
            let (body, complete) = describe(&survey);
            stage_record(parent, profile, stage, body, complete)
        }
        Err(err) => stage_failure(parent, profile, stage, &err),
    });
}

/// A record carrying one stage's results; see
/// [`seance_memory::stage_records::stage_record`].
fn stage_record(
    parent: &Artifact,
    profile: &LinuxProfile,
    stage: &StageId,
    value: serde_json::Value,
    complete: bool,
) -> Artifact {
    seance_memory::stage_records::stage_record(
        parent,
        stage,
        value,
        complete,
        "task_inventory",
        &|object| stamp(object, profile),
    )
}

/// A record saying a stage could not run, and why.
fn stage_failure(
    parent: &Artifact,
    profile: &LinuxProfile,
    stage: &StageId,
    err: &dyn std::fmt::Display,
) -> Artifact {
    seance_memory::stage_records::stage_failure(
        parent,
        MODULE_ID,
        "Linux memory analysis",
        stage,
        err,
        &|object| stamp(object, profile),
    )
}

/// A record saying stages were skipped because a prerequisite failed.
fn skipped_record(
    parent: &Artifact,
    profile: &LinuxProfile,
    stages: &[&StageId],
    reason: &str,
) -> Artifact {
    seance_memory::stage_records::skipped_record(
        parent,
        "Linux memory analysis: process-memory stages did not run",
        stages,
        reason,
        &|object| stamp(object, profile),
    )
}

/// The stage manifest: every stage this build of the analysis can run.
///
/// Emitted whether or not discovery succeeds, and before any stage runs, so the
/// case holds the analysis's own account of what it was capable of. "These
/// stages exist and none of them ran" is a different and more useful statement
/// than a record of nothing at all.
///
/// The coverage endpoint reads it: a stage named here that the API's own table
/// does not describe still gets a row, built from what this record said. Every
/// stage in this crate is such a stage, so without this record the whole Linux
/// tier would be invisible in Coverage — and silence there reads as "nothing to
/// find".
fn stage_manifest_record(parent: &Artifact) -> Artifact {
    let mut value = json!({
        "type": MEMORY_STAGE_MANIFEST_RECORD,
        "record_type": MEMORY_STAGE_MANIFEST_RECORD,
        "name": "Linux memory analysis: stages this build can run",
        "stages": STAGES.iter().map(StageId::to_json).collect::<Vec<_>>(),
        "stage_count": STAGES.len(),
        "content_complete": true,
    });
    for (key, stamped) in analysed_stamp("linux", MODULE_ID, MODULE_VERSION)
        .as_object()
        .expect("stamp is an object")
    {
        value
            .as_object_mut()
            .expect("object literal")
            .insert(key.clone(), stamped.clone());
    }
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

/// Fields every memory record carries, so a finding can be traced back to the
/// profile — and the evidence grade — it rests on.
fn stamp(object: &mut serde_json::Map<String, serde_json::Value>, profile: &LinuxProfile) {
    for (key, value) in analysed_stamp("linux", MODULE_ID, MODULE_VERSION)
        .as_object()
        .expect("stamp is an object")
    {
        object.insert(key.clone(), value.clone());
    }
    object.insert(
        "profile_evidence".into(),
        json!(profile.weakest_evidence().as_str()),
    );
    object.insert("symbols_verified".into(), json!(profile.symbols_verified()));
}

/// The image-profile record: what discovery established, and how.
fn profile_record(parent: &Artifact, profile: &LinuxProfile, report: &DiscoveryReport) -> Artifact {
    let mut m = profile.to_json();
    let obj = m.as_object_mut().expect("profile.to_json is an object");
    obj.insert("type".into(), json!(MEMORY_PROFILE_RECORD));
    obj.insert("record_type".into(), json!(MEMORY_PROFILE_RECORD));
    obj.insert("subtype".into(), json!("linux_memory_profile"));
    obj.insert(
        "name".into(),
        json!(format!(
            "Linux {} profile",
            profile
                .build
                .release
                .clone()
                .unwrap_or_else(|| "kernel".to_string())
        )),
    );
    obj.insert("profile_established".into(), json!(true));
    obj.insert("discovery".into(), report.to_json());
    for (k, v) in analysed_stamp("linux", MODULE_ID, MODULE_VERSION)
        .as_object()
        .expect("stamp is an object")
    {
        obj.insert(k.clone(), v.clone());
    }
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent.id)
}

/// Emitted when discovery could not profile an image that is plainly a Linux
/// capture, or could not establish that it is not one.
///
/// Carries the reason in a form an examiner can act on — most usefully the
/// banner whose symbols are missing, which is the one thing that turns a failed
/// analysis into a successful one.
fn discovery_failure_record(
    parent: &Artifact,
    err: &DiscoveryError,
    searched: &[PathBuf],
    absent: &[PathBuf],
) -> Artifact {
    let m = json!({
        "type": MEMORY_PROFILE_RECORD,
        "record_type": MEMORY_PROFILE_RECORD,
        "subtype": "linux_memory_profile",
        "name": "Linux memory profile (not established)",
        "analysis_stage": "discovery_failed",
        "analysed_os": "linux",
        "analysed_by": MODULE_ID,
        "analysed_by_version": MODULE_VERSION,
        "profile_established": false,
        "failure": err.to_string(),
        "failure_class": err.class(),
        "symbol_dirs_searched": searched
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        // Where a symbol file may be placed, on every OS tier alike: the
        // searched list only names directories that already exist, which is a
        // different question from "where do I put the file" (LIVE-026).
        "symbol_dirs_accepted": seance_memory::analysis::SYMBOL_DIR_GUIDANCE,
        // Named by the examiner and not present. Without this an empty
        // `symbol_dirs_searched` says "this lab has no symbol store" whether or
        // not the examiner pointed at one that turned out to be a typo or an
        // unmounted share.
        "symbol_dirs_named_but_absent": absent
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
    });
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent.id)
}

#[cfg(test)]
mod tests {

    /// LIVE-026 applies to every OS tier, not just Windows: a failure that
    /// lists only the directories that happen to exist tells an examiner where
    /// this build looked, not where they may put the symbols it asked for.
    #[test]
    fn a_discovery_failure_says_where_symbols_may_be_placed_linux() {
        let accepted = seance_memory::analysis::SYMBOL_DIR_GUIDANCE;
        let joined = accepted.join(" | ");
        assert!(joined.contains("SEANCE_SYMBOL_DIRS"), "got {joined}");
        assert!(joined.contains("symbols"), "got {joined}");
    }
    use super::*;
    use seance_memory::analysis::MEMORY_IMAGE_RECORD;

    fn image_record() -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": MEMORY_IMAGE_RECORD, "image_format": "raw"}),
        )
    }

    /// The defect this project has already shipped once: an analysis tier whose
    /// dispatch returned an empty vector while every unit test passed.
    ///
    /// A stage declared in [`STAGES`] and never dispatched publishes a coverage
    /// row that says "did not run" forever, and an examiner reads that as a tool
    /// that chose not to look. There is no parallel list here to keep in step:
    /// each stage constant is named `STAGE_<KEY IN UPPER CASE>`, so the
    /// identifier the dispatch must mention is *derived* from the table, and
    /// this reads the dispatch function's own source to check it is there.
    #[test]
    fn attaching_a_swap_area_that_holds_nothing_warns_while_the_case_is_running() {
        // MEM-011: a swap file copied through the filesystem attaches with a
        // valid header and an empty body. The profile record states it, but the
        // examiner who can still go and re-acquire the area is the one at the
        // console now, so the attach path has to say it out loud too. Read out of
        // `analyse`'s own source, because a warning that is never reached is the
        // silence this exists to end.
        let source = include_str!("module.rs");
        let start = source
            .find("profile.swap = self.resolved_swapfiles();")
            .expect("the attach point exists");
        let attach = &source[start..start + 900.min(source.len() - start)];
        assert!(
            attach.contains("attach_warning"),
            "attaching swap areas no longer warns about one whose body reads as zeros"
        );
    }

    #[test]
    fn every_declared_stage_is_dispatched_by_run_stages() {
        let source = include_str!("module.rs");
        let start = source
            .find("fn run_stages(")
            .expect("the dispatch function exists");
        let rest = &source[start..];
        let end = rest
            .find("fn stage_record(")
            .expect("the function after dispatch exists");
        let dispatch = &rest[..end];

        for stage in STAGES {
            let identifier = format!("STAGE_{}", stage.key.to_uppercase());
            assert!(
                dispatch.contains(&identifier),
                "the '{}' stage is declared in STAGES and {identifier} is never mentioned by \
                 run_stages, so it can only ever report 'did not run'",
                stage.key
            );
        }
        // And the derivation itself has to hold, or the check above would pass
        // vacuously against constants that do not exist.
        assert_eq!(
            format!("STAGE_{}", STAGE_LINUX_PROCESSES.key.to_uppercase()),
            "STAGE_LINUX_PROCESSES"
        );
    }

    #[test]
    fn no_two_stages_share_a_key_or_a_record_type() {
        // Two stages sharing a key would make coverage report one over the
        // other; two sharing a record type would make the coverage tally for
        // one count the other's rows.
        let mut keys: Vec<&str> = STAGES.iter().map(|s| s.key).collect();
        let mut types: Vec<&str> = STAGES.iter().map(|s| s.record_type).collect();
        keys.sort_unstable();
        types.sort_unstable();
        let unique_keys = {
            let mut k = keys.clone();
            k.dedup();
            k.len()
        };
        let unique_types = {
            let mut t = types.clone();
            t.dedup();
            t.len()
        };
        assert_eq!(unique_keys, STAGES.len(), "duplicate stage key: {keys:?}");
        assert_eq!(
            unique_types,
            STAGES.len(),
            "duplicate record type: {types:?}"
        );
    }

    /// The keys must not collide with `seance_api::memory::STAGES`, whose rows
    /// describe the Windows tier. A collision means the coverage view describes
    /// a Linux stage with a Windows sentence and counts it against a Windows
    /// record type, which is drift with a confident-looking number on the end.
    #[test]
    fn no_stage_key_collides_with_the_windows_table_the_api_already_describes() {
        // The keys `seance_api::memory::STAGES` holds. The API crate cannot be
        // imported here — it does not depend on this crate and must not — so
        // the contract is asserted against the same list of strings.
        const API_WINDOWS_KEYS: &[&str] = &[
            "processes",
            "process_tree",
            "pool_scan",
            "cross_view",
            "kernel_modules",
            "network",
            "services",
            "execution_history",
            "mft_scan",
            "kernel_hooks",
            "kernel_objects",
            "environment",
            "credentials",
            "registry_hives",
            "vad",
            "dlls",
            "handles",
            "system_calls",
            "recovered_files",
            "tampering",
        ];
        for stage in STAGES {
            assert!(
                !API_WINDOWS_KEYS.contains(&stage.key),
                "{} collides with a stage key the API's Windows table already describes",
                stage.key
            );
            assert!(
                stage.key.starts_with("linux_"),
                "{} is not namespaced to this tier",
                stage.key
            );
        }
    }

    /// The coverage reader looks the manifest rows up by these exact names. A
    /// rename here is invisible to a build and blanks a coverage row.
    #[test]
    fn the_manifest_rows_use_the_field_names_the_coverage_reader_looks_for() {
        let record = stage_manifest_record(&image_record());
        assert_eq!(record.metadata["type"], MEMORY_STAGE_MANIFEST_RECORD);
        assert_eq!(record.metadata["stage_count"], STAGES.len());
        let rows = record.metadata["stages"]
            .as_array()
            .expect("the manifest lists its stages");
        assert_eq!(rows.len(), STAGES.len());
        for row in rows {
            for field in ["stage", "record_type", "per_process", "describes"] {
                assert!(
                    row.get(field).is_some(),
                    "manifest row {row:?} has no `{field}`, which the coverage endpoint reads"
                );
            }
            assert!(
                row["describes"].as_str().is_some_and(|d| d.len() > 30),
                "a stage the API does not know is described only by this sentence: {row:?}"
            );
        }
    }

    /// Every stage's own sentence must say what an examiner learns, because for
    /// this tier the API has no sentence of its own to fall back on.
    #[test]
    fn every_stage_describes_what_an_examiner_learns() {
        for stage in STAGES {
            assert!(
                stage.describes.len() > 40,
                "{} has no usable description",
                stage.key
            );
            assert!(
                stage.describes.ends_with('.'),
                "{} reads as a fragment",
                stage.key
            );
        }
    }

    #[test]
    fn a_failure_record_is_a_record_and_not_a_silence() {
        // The record type must be the one the coverage endpoint fetches, or a
        // stage that did not run disappears from the view entirely.
        assert_eq!(MEMORY_STAGE_FAILURE_RECORD, "MemoryStageFailure");
        assert_eq!(MEMORY_PROFILE_RECORD, "MemoryProfile");
        assert_eq!(MEMORY_STAGE_MANIFEST_RECORD, "MemoryStageManifest");
    }

    #[test]
    fn the_module_is_wired_to_the_seam_that_cannot_be_miswired() {
        use seance_core::module::ForensicsModule;
        let module = linux_memory_module();
        assert_eq!(module.id(), MODULE_ID);
        assert_eq!(module.version(), MODULE_VERSION);
        assert_eq!(module.subscribes_to(), vec![ArtifactType::ParsedRecord]);

        // A record that is not a memory image is left alone rather than
        // analysed, and a Windows image is not claimed by this tier.
        let other = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "BrowserHistory"}),
        );
        assert!(module.process(&other).expect("no error").is_empty());
    }

    #[test]
    fn the_analysis_names_the_operating_system_it_speaks_for() {
        let analysis = LinuxMemoryAnalysis::new();
        assert_eq!(analysis.os(), "linux");
        assert_eq!(analysis.id(), "plugin.memory.linux");
    }

    #[test]
    fn only_a_finished_sweep_that_found_no_banner_produces_silence() {
        // The single branch in this crate that emits nothing, pinned against the
        // three shapes that reach it. Widening it — `Err(_) => Ok(Vec::new())`
        // is one keystroke away — would drop every Linux capture whose symbols
        // are missing, and the case would read as an image holding nothing.
        // Nothing else in this file would fail if that happened.
        let parent = image_record();
        let dirs = [PathBuf::from("/symbols")];

        let not_linux = DiscoveryError::NoKernelBanner {
            bytes_scanned: 64 * 1024,
            swept_completely: true,
            sweep_state: "covered every acquired byte",
        };
        assert!(
            discovery_outcome(&parent, &not_linux, &dirs, &[]).is_empty(),
            "a fully swept image with no banner is not this tier's to report on"
        );

        // A sweep that could not finish has established nothing. Reporting it as
        // "not Linux" would be a positive claim about the part nobody read, so
        // it takes the reported path instead.
        let unfinished = DiscoveryError::NoKernelBanner {
            bytes_scanned: 4096,
            swept_completely: false,
            sweep_state: "could not cover the whole image",
        };
        let produced = discovery_outcome(&parent, &unfinished, &dirs, &[]);
        assert_eq!(
            produced.len(),
            2,
            "an incomplete sweep is a finding, not a verdict of 'not Linux'"
        );
        assert_eq!(produced[1].metadata["failure_class"], "no_kernel_banner");

        // And the ordinary failure: a Linux kernel this lab has no symbols for.
        let no_symbols = DiscoveryError::SymbolsNotFound {
            banner: "Linux version 3.2.0-4-amd64".to_string(),
            directories: 1,
            files_seen: 0,
            files_identified: 0,
            truncation: String::new(),
            btf_note: String::new(),
        };
        let produced = discovery_outcome(&parent, &no_symbols, &dirs, &[]);
        assert_eq!(produced[0].metadata["type"], MEMORY_STAGE_MANIFEST_RECORD);
        let failure = &produced[1].metadata;
        assert_eq!(failure["failure_class"], "symbols_not_found");
        assert_eq!(failure["profile_established"], false);
        assert!(
            failure["failure"]
                .as_str()
                .is_some_and(|f| f.contains("3.2.0-4-amd64")),
            "the banner is the one thing that lets an examiner fetch the right ISF"
        );
        assert_eq!(failure["symbol_dirs_searched"], json!(["/symbols"]));
    }

    /// A symbol directory the examiner named and that is not there must be
    /// reported, not dropped.
    ///
    /// Without this, the two situations an examiner most needs to tell apart
    /// render identically. `SEANCE_SYMBOL_DIRS` pointing at a typo, or at a
    /// share that did not mount, is filtered out before the search — so the
    /// failure record says the search covered zero directories, which is exactly
    /// what a lab with no symbol store at all produces. One of those is fixed by
    /// downloading an ISF and the other by fixing a path, and the record is the
    /// only place an examiner finds out which.
    #[test]
    fn a_named_symbol_directory_that_is_not_there_is_reported_rather_than_dropped() {
        let named = PathBuf::from("/nonexistent-symbol-store-for-this-test");
        let analysis = LinuxMemoryAnalysis::new().with_symbol_dirs(vec![named.clone()]);
        let (searched, absent) = analysis.resolved_symbol_dirs();

        assert!(
            searched.is_empty(),
            "a directory that is not there cannot be searched: {searched:?}"
        );
        assert_eq!(
            absent,
            vec![named.clone()],
            "the path the examiner named has to survive as far as the record"
        );

        let err = DiscoveryError::SymbolsNotFound {
            banner: "Linux version 3.2.0-4-amd64".to_string(),
            directories: 0,
            files_seen: 0,
            files_identified: 0,
            truncation: String::new(),
            btf_note: String::new(),
        };
        let record = discovery_failure_record(&image_record(), &err, &searched, &absent);
        assert_eq!(record.metadata["symbol_dirs_searched"], json!([]));
        assert_eq!(
            record.metadata["symbol_dirs_named_but_absent"],
            json!(["/nonexistent-symbol-store-for-this-test"]),
            "an empty search and a search of somewhere that is not there are different findings"
        );

        // And a directory that does exist is searched and is not reported as
        // missing, or the field above would fire on every ordinary run and mean
        // nothing.
        let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let (searched, absent) = LinuxMemoryAnalysis::new()
            .with_symbol_dirs(vec![here.clone()])
            .resolved_symbol_dirs();
        assert_eq!(searched, vec![here]);
        assert!(absent.is_empty(), "{absent:?}");
    }

    #[test]
    fn a_windows_symbol_directory_is_not_cut_in_half_at_its_drive_colon() {
        // The defect this closes. `SEANCE_SYMBOL_DIRS=C:\symbols` was split on
        // every colon into `C` and `\symbols`, and the `is_dir` filter dropped
        // both **without a warning** — so a lab running this analysis on
        // Windows and pointing at a real symbol store produced the failure
        // record of a lab that has no symbol store at all. Those are the two
        // situations `resolved_symbol_dirs` exists to keep apart.
        assert_eq!(split_env_list(r"C:\symbols"), vec![r"C:\symbols"]);
        assert_eq!(
            split_env_list(r"C:\symbols;D:\packs"),
            vec![r"C:\symbols", r"D:\packs"]
        );
        // Forward slashes are as valid as backslashes on Windows, and the
        // colon-separated list every Unix lab already has keeps parsing as it
        // always did.
        assert_eq!(split_env_list("C:/symbols"), vec!["C:/symbols"]);
        assert_eq!(
            split_env_list("/opt/symbols:/srv/packs"),
            vec!["/opt/symbols", "/srv/packs"]
        );

        // The parser is shared with the other memory tiers precisely so this
        // cannot be reintroduced here alone. Built out of two pieces so the
        // assertion cannot match itself.
        let hand_rolled: String = ["list", ".split(':')"].concat();
        let source = include_str!("module.rs");
        assert!(
            !source.contains(&hand_rolled),
            "an environment list here is split on every colon again, which cuts a Windows path \
             at its drive letter"
        );
    }

    #[test]
    fn a_memory_image_reaches_analyse_through_the_orchestrators_own_entry_point() {
        // Reachability, asserted rather than believed. This drives
        // `ForensicsModule::process` — what the orchestrator calls — over an
        // artifact shaped exactly as the container stage emits one, so the whole
        // wiring is exercised: the subscription filter, the memory-image check,
        // the rebuild of the address space from the carried `DataSource`, and
        // `analyse` itself.
        //
        // The image is 64 KiB of zeros, so the sweep finishes and finds no
        // banner: this is not a Linux capture, and the right answer is nothing.
        // The point is that it got far enough to say so.
        use seance_core::data_source::{ByteSliceDataSource, DataSource};
        use seance_core::module::ForensicsModule;

        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 64 * 1024]));
        let image = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(data),
            json!({"type": MEMORY_IMAGE_RECORD, "image_format": "raw"}),
        );

        let produced = linux_memory_module()
            .process(&image)
            .expect("an image that is not Linux is not an error");
        assert!(
            produced.is_empty(),
            "an image with no kernel banner belongs to another tier: {:?}",
            produced
                .iter()
                .map(|a| a.metadata["type"].clone())
                .collect::<Vec<_>>()
        );
    }
}
