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
//! ## What an examiner gets
//!
//! Discovery runs first and always emits its result, including when it fails.
//! A memory image Séance cannot analyse is a fact about the evidence, and the
//! reason — no directory table base found, or symbols missing for a named PDB
//! GUID — is exactly what tells an examiner what to do next. Emitting nothing
//! would read as "this image is empty", which is a different and false claim.
//!
//! Symbol files are located in this order, first hit wins:
//!
//! 1. `SEANCE_SYMBOL_DIRS`, a separated list, for an examiner pointing at a
//!    curated pack.
//! 2. `<exe dir>/symbols` and `./symbols`, for a normal install.
//! 3. `reference/volatility3/volatility3/symbols`, which is where the parity
//!    oracle in this repository already fetches them to.
//!
//! Every list here is separated by `:` or `;`, and a colon that opens a Windows
//! drive path — `C:\symbols` — is part of the path rather than a separator. The
//! parser is [`seance_memory::analysis::split_env_list`], shared with the other
//! OS tiers so the same list means the same thing whichever of them reads it.
//!
//! # tcpip.sys symbols
//!
//! `SEANCE_MEM_TCPIP_ISF` names one ISF file describing tcpip.sys's types.
//! Nothing else can supply them: `_TCP_ENDPOINT` and its neighbours are not in
//! `ntoskrnl`'s PDB, so the symbol table discovery matches to the image cannot
//! describe them, and the network stage refuses by name rather than reporting a
//! machine with no connections. Unset is the ordinary case and is a statement
//! about the symbol pack, not about the evidence.
//!
//! Discovery proves the kernel's symbols against the kernel's own CodeView GUID
//! and age. Nothing proves this file — the tcpip.sys build the image loaded is
//! what decides which one is right — so rows read through it carry that on the
//! record.
//!
//! # Directory table base
//!
//! `SEANCE_MEM_DTB` supplies one, in hex (`0x1ae000`) or decimal, for an image
//! whose page directory the sweep cannot find. It is still proved by finding a
//! kernel through it, and it is recorded as supplied rather than discovered.
//!
//! # Pagefiles
//!
//! `SEANCE_PAGEFILES` attaches one or more, so a page the kernel swapped out
//! resolves to bytes instead of a `swapped_out` hole. Each entry is
//! `index=path`, where the index is the one Windows assigns in `PagingFiles`
//! order and a software PTE names:
//!
//! ```text
//! SEANCE_PAGEFILES=0=/evidence/pagefile.sys
//! SEANCE_PAGEFILES=0=/evidence/pagefile.sys:1=/evidence/pagefile2.sys
//! SEANCE_PAGEFILES=0=C:\evidence\pagefile.sys;1=D:\evidence\pagefile2.sys
//! ```
//!
//! `SEANCE_CASE_PAGEFILES` names one the **case already holds** rather than a
//! path on this host, in the same `index=reference` form:
//!
//! ```text
//! SEANCE_CASE_PAGEFILES=0=pagefile.sys
//! ```
//!
//! A reference is resolved through [`seance_memory::analysis::CaseEvidence`]
//! against the case the image record belongs to — by default
//! [`seance_memory::analysis::EvidenceBesideImage`], which reaches evidence
//! sitting beside the capture in the case's evidence tree and refuses anything
//! outside it. This is the one that matters in practice: a capture and the
//! machine's `pagefile.sys` are ordinarily acquired together into one evidence
//! folder, and before this variable existed there was no way to name the second
//! one except by typing a host path that has nothing to do with the case.
//! A reference that cannot be resolved is **refused by name**; it never falls
//! back to a host path, because the examiner would then be handed a different
//! file's bytes with nothing in the case saying so.
//!
//! **Both are unset by default, and nothing is discovered.** A pagefile beside
//! a memory image is a *second evidence item* whose pages were written before
//! the capture — possibly long before. Reaching for one unasked would fold
//! another file's bytes into what a report calls this machine's memory, with
//! that decision recorded nowhere.
//!
//! The index is required rather than inferred from order because supplying a
//! file under the wrong one does not fail: it answers with another file's
//! bytes. On a smeared capture, entries whose index bits decoded to garbage
//! name pagefiles that do not exist, and those pages stay holes rather than
//! being answered from whichever file happens to be attached. For the same
//! reason an index that is already attached is never attached twice: two files
//! under one index would make every PTE naming it answer from whichever was
//! read first, silently.

// These test modules assert relationships between *compile-time constants* --
// MAX_SUBKEYS > MAX_INDEX_CELLS, MIN_CREATE_FILETIME < MAX_CREATE_FILETIME, a
// stage's declared record type. Clippy sees both sides are const and calls the
// assertion constant; that is exactly the point. They exist so that changing
// one bound in isolation fails, and deleting them would remove the guard rather
// than satisfy it.
#![allow(clippy::assertions_on_constants)]

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::ModuleError,
};
use seance_memory::analysis::{
    analysed_stamp, split_env_list, CaseEvidence, EvidenceBesideImage, MemoryAnalysis,
    MemoryAnalysisModule,
};
use seance_memory::translate::SwapFile;
use seance_memory::MemoryLayer;
use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

use crate::{
    amcache, big_pool, console_history, credential_decrypt, credentials, device_tree, dump,
    environment, handles, hive_cell_routines, hollow, jobs, kernel_hooks, mbr_scan, mftscan,
    modules, netscan, objects, pattern_scan, poolscan, process, processor_blocks, psxview,
    recovered, registry, scheduled_tasks, services, strings_map, syscalls, tamper, truecrypt, vad,
    version_info, virtual_map,
};
use serde_json::json;
use tracing::{info, warn};

use crate::automagic::{self, DiscoveryError, DiscoveryOptions, DiscoveryReport};
use crate::profile::WindowsProfile;

/// Module id, following the tree's `plugin.<category>.<name>` convention.
pub const MODULE_ID: &str = "plugin.memory.windows";

/// Module version.
pub const MODULE_VERSION: &str = "0.1.0";

/// Record type carrying the list of stages this build can run, and one stage's
/// identity on the wire.
///
/// Both were declared in this file. They are re-exported from
/// [`seance_memory::binding`] so the Linux and macOS tiers file their findings
/// under the same identity and the build binding can name a stage in a failure
/// without depending on any one OS crate. Every use site in this crate keeps
/// naming them `module::StageId` and `module::MEMORY_STAGE_MANIFEST_RECORD`.
///
/// # Why the manifest exists
///
/// `seance_api::memory::get_memory_coverage` has its own stage table, because
/// the API crate deliberately does not depend on the analysis crates. Two
/// tables drift, and when they did the Coverage lens went silent about seven
/// stages that ran — silence an examiner reads as "nothing to find". Coverage
/// now reads this record and gives a row to every stage named in [`STAGES`],
/// describing an unfamiliar one in the analysis's own words. A stage added to
/// [`STAGES`] therefore reaches the examiner on the day it is added.
///
/// # The consumer, so this can be checked rather than believed
///
/// `GET /api/v1/cases/:id/memory/coverage` (routed in `seance_api::lib` to
/// `seance_api::memory::get_memory_coverage`) fetches records of this type and
/// hands them to `seance_api::memory::declared_stages`, which reads each entry
/// of the `stages` array by the field names [`StageId::to_json`] writes:
/// `stage`, `record_type`, `per_process` and `describes`. Renaming any of them
/// on that side does not fail a build; it makes the coverage row for a stage
/// the API does not know about silently disappear, or arrive with nothing said
/// about what the stage establishes. That contract is asserted by
/// `tests::the_manifest_rows_use_the_field_names_the_coverage_reader_looks_for`.
pub use seance_memory::binding::{StageId, MEMORY_STAGE_MANIFEST_RECORD};

/// The active process list, walked from the kernel's links.
pub const STAGE_PROCESSES: StageId = StageId {
    key: "processes",
    record_type: "MemoryProcessList",
    per_process: false,
    describes: "The active process list, walked from the kernel's process links.",
};

/// Parent/child structure derived from the process list.
pub const STAGE_PROCESS_TREE: StageId = StageId {
    key: "process_tree",
    record_type: "MemoryProcessTree",
    per_process: false,
    describes: "Parent/child structure derived from the process list.",
};

/// Each process's command line, read from its own address space.
///
/// Image-wide rather than per process: one row per process, all in one record,
/// because a command-line table is read end to end and no route serves it by
/// PID.
pub const STAGE_COMMAND_LINES: StageId = StageId {
    key: "command_lines",
    record_type: "MemoryCommandLines",
    per_process: false,
    describes: "Each process's command line, read from that process's own address space — the \
                arguments a program was started with, which the kernel's process structure does \
                not hold.",
};

/// Process objects found by scanning the kernel pool.
pub const STAGE_POOL_SCAN: StageId = StageId {
    key: "pool_scan",
    record_type: "MemoryPoolScan",
    per_process: false,
    describes: "Process objects found by scanning the kernel pool, including any the active list \
                no longer points at.",
};

/// Which listing saw each process, and which did not.
pub const STAGE_CROSS_VIEW: StageId = StageId {
    key: "cross_view",
    record_type: "MemoryCrossView",
    per_process: false,
    describes: "Which listing saw each process and which did not — the concealment table.",
};

/// The kernel's own loaded modules.
pub const STAGE_KERNEL_MODULES: StageId = StageId {
    key: "kernel_modules",
    record_type: "MemoryKernelModules",
    per_process: false,
    describes: "Loaded kernel drivers.",
};

/// Network endpoints and connections.
pub const STAGE_NETWORK: StageId = StageId {
    key: "network",
    record_type: "MemoryNetwork",
    per_process: false,
    describes: "Network endpoints and connections recovered from memory.",
};

/// Windows services as they stood in memory.
pub const STAGE_SERVICES: StageId = StageId {
    key: "services",
    record_type: "MemoryServices",
    per_process: false,
    describes: "Windows services, one listing per services.exe in the image.",
};

/// Amcache and the AppCompatCache, from the hives in RAM.
pub const STAGE_EXECUTION_HISTORY: StageId = StageId {
    key: "execution_history",
    record_type: "MemoryExecutionHistory",
    per_process: false,
    describes: "Execution history held in RAM: the Amcache hive and the AppCompatCache \
                (Shimcache).",
};

/// MFT records recovered from pool memory.
pub const STAGE_MFT_SCAN: StageId = StageId {
    key: "mft_scan",
    record_type: "MemoryMftRecords",
    per_process: false,
    describes: "Master File Table records recovered from pool memory, which can predate what is \
                on disk.",
};

/// Callbacks, the SSDT and driver IRP tables.
pub const STAGE_KERNEL_HOOKS: StageId = StageId {
    key: "kernel_hooks",
    record_type: "MemoryKernelHooks",
    per_process: false,
    describes: "Kernel hooking and persistence: notification callbacks, the system service \
                descriptor table and driver IRP tables.",
};

/// Executive objects still in pool.
pub const STAGE_KERNEL_OBJECTS: StageId = StageId {
    key: "kernel_objects",
    record_type: "MemoryKernelObjects",
    per_process: false,
    describes: "Executive objects still in pool memory: open files, mutants and symbolic links.",
};

/// Sessions, desktops and per-process environment blocks.
pub const STAGE_ENVIRONMENT: StageId = StageId {
    key: "environment",
    record_type: "MemoryEnvironment",
    per_process: false,
    describes: "Terminal-services sessions, window stations and desktops, and each process's \
                environment block.",
};

/// The credential stores, located and inventoried.
pub const STAGE_CREDENTIALS: StageId = StageId {
    key: "credentials",
    record_type: "MemoryCredentials",
    per_process: false,
    // `DOC-005`, the second copy. That defect was a sentence here ending "The
    // material is not decrypted, so no password, hash or secret value is
    // recovered" — true until `MEM-008` added boot-key recovery and SAM
    // decryption, false after, and read off a court-facing screen as a false
    // absence. It was corrected in `seance_api::memory`'s stage table on
    // 2026-09-06 and **this copy was not brought along**, so the false sentence
    // went on travelling in the `MemoryStageManifest` record stored in the
    // case — which is precisely the record an examiner reads for a stage the
    // API's own table does not describe. Corrected 2026-09-15; the two texts
    // now say the same thing, and a test in `seance_api` pins the other one.
    describes: "The credential stores held in RAM — SAM, LSA secrets and cached domain logons — \
                located and inventoried: which stores are resident, which local accounts exist \
                and what the secrets are called. Where the SYSTEM and SAM hives are both \
                resident, the boot key is recovered and the local-account NT hashes are \
                decrypted out of them, one record per account; LSA secrets and cached domain \
                logons are decrypted the same way. Each recovered value is released only \
                through the audited reveal, which records who asked.",
};

/// Registry hives mapped into kernel memory.
pub const STAGE_REGISTRY_HIVES: StageId = StageId {
    key: "registry_hives",
    record_type: "MemoryRegistryHives",
    per_process: false,
    describes: "Registry hives mapped into kernel memory, including volatile hives that exist \
                nowhere on disk.",
};

/// Each process's virtual address descriptors.
pub const STAGE_VAD: StageId = StageId {
    key: "vad",
    record_type: "MemoryProcessVads",
    per_process: true,
    describes: "Each process's virtual address descriptors.",
};

/// Each process's loaded user-mode modules, and the unlinked cross-reference.
///
/// Keyed `dlls` rather than `process_modules`: that is the key the API's
/// coverage table and the Process Inspector's DLLs tab have always used, and
/// the emitter naming it differently is precisely the drift this type exists to
/// prevent.
pub const STAGE_DLLS: StageId = StageId {
    key: "dlls",
    record_type: "MemoryProcessModules",
    per_process: true,
    describes: "Each process's loaded user-mode modules, cross-referenced against its mapped \
                memory to find modules unlinked from the loader's lists.",
};

/// Each process's handle table.
pub const STAGE_HANDLES: StageId = StageId {
    key: "handles",
    record_type: "MemoryProcessHandles",
    per_process: true,
    describes: "Each process's handle table.",
};

/// System-call stub evasion.
pub const STAGE_SYSTEM_CALLS: StageId = StageId {
    key: "system_calls",
    record_type: "MemorySystemCalls",
    per_process: false,
    describes: "System-call stubs that do not enter the kernel the way this build's ntdll does — \
                the shape of a user-mode hook or a direct-syscall loader.",
};

/// Files reconstructed out of the cache manager's pages.
pub const STAGE_RECOVERED_FILES: StageId = StageId {
    key: "recovered_files",
    record_type: "MemoryRecoveredFiles",
    per_process: false,
    describes: "Files the cache manager still held in RAM, reconstructed and handed to the \
                ordinary file parsers.",
};

/// Process-image tampering signals.
pub const STAGE_TAMPERING: StageId = StageId {
    key: "tampering",
    record_type: "MemoryProcessTampering",
    per_process: false,
    describes: "Process-image tampering signals: hollowing, ghosting and unbacked executable \
                memory.",
};

/// Threads that started running outside anything the loader mapped
/// (MEM-024, upstream's `suspicious_threads`).
///
/// Image-wide rather than per process: one record carries every process on the
/// shared list, judged, declared out of scope, or skipped with its error.
pub const STAGE_SUSPICIOUS_THREADS: StageId = StageId {
    key: "suspicious_threads",
    record_type: "MemorySuspiciousThreads",
    per_process: false,
    describes: "Where each live user thread started running: its StartAddress and \
                Win32StartAddress placed in the VAD that covers them, and reported when that \
                range is backed by no file, was not created PAGE_EXECUTE_WRITECOPY, or maps an \
                application executable that is not the process's own. A range whose protection \
                or file could not be read is a gap, not a finding; a start in no range is \
                counted and not attributed.",
};

/// The device tree (`ROADMAP` §5.3, upstream's `devicetree`).
///
/// Where a filter driver inserted itself: which driver owns which device, and
/// what is attached on top. The drivers come from the `kernel_hooks` stage's
/// own pool sweep rather than a second one, for the same reason its module map
/// is shared.
pub const STAGE_DEVICE_TREE: StageId = StageId {
    key: "device_tree",
    record_type: "MemoryDriverDevices",
    per_process: false,
    describes: "The device tree: which driver owns which device, what is attached above each \
                device, and which of those attachments are by a driver other than the one \
                owning the device beneath -- which is what a filter driver is.",
};

/// Job objects and their members (`ROADMAP` §5.3, upstream's `joblinks`).
///
/// One record per **distinct** `_EJOB`, naming every process that pointed at
/// it — where upstream prints one row per process and repeats the job's members
/// under each. See `jobs` for why.
pub const STAGE_JOBS: StageId = StageId {
    key: "jobs",
    record_type: "MemoryJobs",
    per_process: false,
    describes: "Job objects and the processes confined to them: the kernel's own member list \
                beside its process counters, and any member the active process list does not \
                hold.",
};

/// Kernel-side tamper checks (`ROADMAP` §5.3).
///
/// Seven groups in one stage, not seven stages: `GroupStatus` already carries
/// per-group ran / did-not-run / found / capped, so the API's stage table gains
/// one row and the Findings lens gains one source rather than seven.
///
/// **Not every group's detection is written**: [`tamper::IMPLEMENTED_GROUPS`]
/// is the list, and every group not on it reports that it did not run with its
/// own reason — so that a group landing later cannot have the earlier silence
/// read as evidence the kernel was clean.
pub const STAGE_TAMPER_CHECKS: StageId = StageId {
    key: "tamper_checks",
    record_type: "MemoryTamperChecks",
    per_process: false,
    describes: "Kernel-side tamper checks: unloaded drivers, per-processor timers, threads with \
                debug registers, suspended threads, orphan kernel threads, a patched ETW write \
                path and a skeleton key.",
};

/// Examiner-supplied patterns over memory (`ROADMAP` §5.3, upstream's
/// `yarascan`, `vadyarascan`, `regexscan` and `vadregexscan`).
///
/// The one stage that searches for something this product did not choose, and
/// so the one stage that can have nothing to search for: with no rule set and
/// no pattern named it reports that it **did not run**, with that reason,
/// rather than an empty match list that reads identically to a scan which had
/// a pattern and found nothing.
pub const STAGE_PATTERN_SCAN: StageId = StageId {
    key: "pattern_scan",
    record_type: "MemoryPatternScan",
    per_process: false,
    describes: "Examiner-supplied YARA rules and patterns over each process's own address space \
                and the kernel's, with every match attributed to the allocation that held it. \
                Runs only when a rule set or pattern was named; it searches for nothing of its \
                own.",
};

/// `strings` over memory: the reverse of every other stage's question.
///
/// Every other stage starts from a structure and reads outward. This starts
/// from a **physical** offset the examiner brought and asks which address
/// spaces reach it, which needs a reverse mapping built across every process's
/// page tables. Like the pattern scan it searches for nothing of its own, so
/// with no strings file named it reports that it did not run.
const STAGE_STRINGS_MAP: StageId = StageId::new(
    "strings_map",
    "MemoryStringsMap",
    false,
    "Physical offsets from the examiner's own run of `strings` over the image, each attributed \
     to every address space whose page tables reach it and to the virtual address it has there. \
     Séance runs no `strings` of its own and searches for nothing: with no file named the stage \
     reports that it DID NOT RUN. A frame reached through the kernel's shared half is one owner \
     naming the spaces that reach it, not one finding per process; an offset no walked space \
     maps is never called free, because the PFN database is not read and a frame on the free \
     list still holds its last contents.",
);

/// The processor control regions (`ROADMAP` §5.3, upstream's `kpcrs`).
pub const STAGE_PROCESSOR_BLOCKS: StageId = StageId::new(
    "processor_blocks",
    "MemoryProcessorBlocks",
    false,
    "The processor control regions: one record per processor the KiProcessorBlock array names, \
     each held to its own self-pointers and its own number, with the thread and process it was \
     running at capture. The kernel's processor count is compared with the array, never \
     preferred to it.",
);

/// The big-page pool tracker (`ROADMAP` §5.3, upstream's `bigpools`).
pub const STAGE_BIG_POOL: StageId = StageId::new(
    "big_pool",
    "MemoryBigPool",
    false,
    "The big-page pool table: every allocation of a page or more, by tag and size, with freed \
     slots told apart from live ones by type and the kernel's own in-use counter compared with \
     the walk. Per-tag totals are exact even where the published rows are capped.",
);

/// The kernel's system virtual-address map (`ROADMAP` §5.3, upstream's
/// `virtmap`).
pub const STAGE_VIRTUAL_MAP: StageId = StageId::new(
    "virtual_map",
    "MemoryVirtualMap",
    false,
    "The kernel's system virtual-address regions -- pools, driver images, the PFN database, \
     the system cache -- as MiState assigns them, each named from the build's own enumeration, \
     with the kernel's load address placed in one as the check that the map was read right.",
);

/// Each hive's cell routines (`ROADMAP` §5.3, upstream's `getcellroutine`).
pub const STAGE_HIVE_CELL_ROUTINES: StageId = StageId::new(
    "hive_cell_routines",
    "MemoryHiveCellRoutines",
    false,
    "Each loaded registry hive's GetCellRoutine and ReleaseCellRoutine pointers, placed: at a \
     named kernel function, inside the kernel at an offset from one, inside another loaded \
     module, or in no loaded module. A routine outside the kernel is where a registry-hiding \
     hook lives; 'in no module' is claimed only when the module list was walked whole.",
);

/// Version resources of loaded images (`ROADMAP` §5.3, upstream's `verinfo`).
pub const STAGE_VERSION_INFO: StageId = StageId::new(
    "version_info",
    "MemoryVersionInfo",
    false,
    "The version resource of every kernel module and every process's loaded DLLs, read from the \
     image bytes in memory: file and product version, company, original file name. An image \
     whose headers could not be read is reported as unreadable, never as an image with no \
     version.",
);

/// Boot sectors in physical memory (`ROADMAP` §5.3, upstream's `mbrscan`).
pub const STAGE_MBR_SCAN: StageId = StageId::new(
    "mbr_scan",
    "MemoryMbrScan",
    false,
    "Every 512-byte-aligned sector of physical memory ending in 55 AA, decoded as a partition \
     table and held to six checks, each reported: a well-formed MBR or GPT protective MBR is \
     a partition table the machine held in memory -- a disk it read, or a disk image it \
     handled; the bytes do not say which. A sector failing the checks is reported with the \
     checks it failed and nothing more is claimed of it (a filesystem's own boot sector ends \
     in the same two bytes and fails them). The boot code is hashed, not judged.",
);

/// Scheduled tasks from the in-memory SOFTWARE hive (`ROADMAP` §5.3,
/// upstream's `scheduled_tasks`).
pub const STAGE_SCHEDULED_TASKS: StageId = StageId::new(
    "scheduled_tasks",
    "MemoryScheduledTasks",
    false,
    "Every task registered in the TaskCache of the SOFTWARE hive in RAM: its path, author, the \
     actions it runs (decoded from the Actions blob), its creation and last-run times and last \
     result (from DynamicInfo), and when it fires (each trigger decoded from the Triggers blob: \
     kind, start, repetition, enabled; an unknown kind stops the decode and is named).",
);

/// TrueCrypt/VeraCrypt (`ROADMAP` §5.3, upstream's `truecryptmaster` family).
pub const STAGE_TRUECRYPT: StageId = StageId::new(
    "truecrypt",
    "MemoryTrueCrypt",
    false,
    "Whether a TrueCrypt or VeraCrypt driver is on the loaded-module list and, when it is, a \
     sweep of the kernel's non-paged pool for verified AES key schedules, recorded by address, \
     size and key hash with adjacent AES-256 pairs reported as a POSSIBLE XTS pair and \
     labelled an inference. The driver's own key container is not decoded.",
);

/// Console command history (`ROADMAP` §5.3, the question upstream's `cmdscan` asks).
pub const STAGE_CONSOLE_HISTORY: StageId = StageId::new(
    "console_history",
    "MemoryConsoleHistory",
    false,
    "The command lines held in each console host's heap (`conhost.exe`, `OpenConsole.exe`): the \
     lines typed at a console, in stored order, with the client application they were kept for. \
     The history layout was derived in-house on one build of the host (Windows 11 26200.6584) \
     and a host built differently yields nothing rather than something wrong, so finding none \
     is not evidence that nothing was typed. The screen buffer (what a command printed) is not \
     read.",
);

/// Every stage this build can run, in the order an examiner reads them.
///
/// [`run_stages`] emits nothing that is not in here — [`stage_record`] and
/// [`stage_failure`] take a `&StageId`, so there is no way to write a record
/// under a stage name this table does not hold — and [`stage_manifest_record`]
/// publishes the table alongside the analysis, so the case itself records what
/// this build could have run. Adding a stage here is therefore enough to make
/// it visible in Coverage; see [`MEMORY_STAGE_MANIFEST_RECORD`] for how that
/// record reaches the endpoint that reads it.
pub const STAGES: &[StageId] = &[
    STAGE_PROCESSES,
    STAGE_PROCESS_TREE,
    STAGE_COMMAND_LINES,
    STAGE_POOL_SCAN,
    STAGE_CROSS_VIEW,
    STAGE_KERNEL_MODULES,
    STAGE_NETWORK,
    STAGE_SERVICES,
    STAGE_EXECUTION_HISTORY,
    STAGE_MFT_SCAN,
    STAGE_KERNEL_HOOKS,
    STAGE_KERNEL_OBJECTS,
    STAGE_ENVIRONMENT,
    STAGE_CREDENTIALS,
    STAGE_REGISTRY_HIVES,
    STAGE_VAD,
    STAGE_DLLS,
    STAGE_HANDLES,
    STAGE_SYSTEM_CALLS,
    STAGE_RECOVERED_FILES,
    STAGE_TAMPERING,
    STAGE_SUSPICIOUS_THREADS,
    STAGE_TAMPER_CHECKS,
    STAGE_JOBS,
    STAGE_DEVICE_TREE,
    STAGE_PATTERN_SCAN,
    STAGE_STRINGS_MAP,
    STAGE_PROCESSOR_BLOCKS,
    STAGE_BIG_POOL,
    STAGE_VIRTUAL_MAP,
    STAGE_HIVE_CELL_ROUTINES,
    STAGE_VERSION_INFO,
    STAGE_MBR_SCAN,
    STAGE_SCHEDULED_TASKS,
    STAGE_TRUECRYPT,
    STAGE_CONSOLE_HISTORY,
];

/// The stages that walk the shared active process list, and so are named in
/// the one record saying they did not run when that list could not be walked.
const STAGES_NEEDING_THE_PROCESS_LIST: &[&StageId] = &[
    &STAGE_COMMAND_LINES,
    &STAGE_VAD,
    &STAGE_DLLS,
    &STAGE_HANDLES,
    &STAGE_SYSTEM_CALLS,
    &STAGE_TAMPERING,
    &STAGE_SUSPICIOUS_THREADS,
    &STAGE_RECOVERED_FILES,
    &STAGE_JOBS,
    &STAGE_VERSION_INFO,
    &STAGE_CONSOLE_HISTORY,
];

/// Windows memory analysis.
///
/// Wrap in [`windows_memory_module`] to obtain the `ForensicsModule` the
/// orchestrator registers.
#[derive(Debug)]
pub struct WindowsMemoryAnalysis {
    /// Directories searched for ISF symbol files. Empty means "resolve from the
    /// environment and the usual locations at analysis time".
    symbol_dirs: Vec<PathBuf>,
    /// Discovery tuning. Defaults are the shipped caps.
    options: DiscoveryOptions,
    /// How a second evidence item the case holds — a pagefile named by
    /// `SEANCE_CASE_PAGEFILES` — is reached.
    ///
    /// Held rather than taken per call because one analysis serves every case
    /// in the process; the *case* comes from the image record at resolution
    /// time, which is what keeps one case's reference from opening another
    /// case's evidence.
    case_evidence: Arc<dyn CaseEvidence>,
    /// What the examiner asked to be looked for in memory, and the engines that
    /// look. Empty is the ordinary case and means the pattern-scan stage
    /// reports that it did not run, with that reason.
    ///
    /// Supplied rather than constructed here: this crate knows how to search an
    /// address space and deliberately does not know what a YARA rule is. The
    /// registration site — `seance_api::modules` — has both, and hands the
    /// same compiled rule set to this stage and to the file scanner.
    pattern_sets: Vec<seance_memory::patterns::PatternSet>,
    /// The examiner's strings file, or `None` where none was named — which is
    /// what makes the `strings_map` stage report that it did not run rather
    /// than that no offset had an owner.
    strings_source: Option<crate::strings_map::StringsSource>,
}

impl Default for WindowsMemoryAnalysis {
    fn default() -> Self {
        Self {
            symbol_dirs: Vec::new(),
            options: DiscoveryOptions::default(),
            // The resolver that needs nothing wired up: evidence beside the
            // capture in the case's own evidence tree, which is how a memory
            // image and its pagefile are ordinarily acquired.
            case_evidence: Arc::new(EvidenceBesideImage),
            pattern_sets: Vec::new(),
            strings_source: None,
        }
    }
}

impl WindowsMemoryAnalysis {
    /// Analysis with the default caps and the usual symbol locations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Analysis that searches exactly these directories for symbols.
    pub fn with_symbol_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.symbol_dirs = dirs;
        self
    }

    /// Analysis with non-default discovery options — an examiner-supplied
    /// directory table base, say.
    pub fn with_options(mut self, options: DiscoveryOptions) -> Self {
        self.options = options;
        self
    }

    /// Analysis that reaches case-held evidence through `evidence` rather than
    /// through the default [`EvidenceBesideImage`].
    ///
    /// A deployment that stores ingested evidence in a database supplies its
    /// own resolver here, and `SEANCE_CASE_PAGEFILES` then reaches a pagefile
    /// extracted from a disk image as readily as one acquired beside the
    /// capture. Nothing else about the analysis changes: `SwapFile.source` is
    /// an `Arc<dyn DataSource>` and has never cared where the bytes came from.
    pub fn with_case_evidence(mut self, evidence: Arc<dyn CaseEvidence>) -> Self {
        self.case_evidence = evidence;
        self
    }

    /// Analysis that searches memory for the patterns in `sets` as well.
    ///
    /// With none, the pattern-scan stage reports that it did not run because
    /// nothing was named. Séance ships no rules, and a stage that searched for
    /// something nobody asked for would be asserting maliciousness on an
    /// examiner's behalf.
    pub fn with_pattern_sets(mut self, sets: Vec<seance_memory::patterns::PatternSet>) -> Self {
        self.pattern_sets = sets;
        self
    }

    /// Analysis that attributes the physical offsets in `source` as well.
    ///
    /// `None` is the ordinary case and means the `strings_map` stage reports
    /// that it did not run. Parsed at the registration site, like a rule set,
    /// so a file the examiner NAMED and that will not read fails the run
    /// instead of reaching here as an absence.
    pub fn with_strings_source(
        mut self,
        source: Option<crate::strings_map::StringsSource>,
    ) -> Self {
        self.strings_source = source;
        self
    }

    /// Directories to search for ISF files, in precedence order.
    fn resolved_symbol_dirs(&self) -> Vec<PathBuf> {
        if !self.symbol_dirs.is_empty() {
            return self.symbol_dirs.clone();
        }
        let mut dirs = Vec::new();
        if let Ok(list) = std::env::var("SEANCE_SYMBOL_DIRS") {
            dirs.extend(split_env_list(&list).into_iter().map(PathBuf::from));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                dirs.push(parent.join("symbols"));
            }
        }
        dirs.push(PathBuf::from("symbols"));
        dirs.push(PathBuf::from("reference/volatility3/volatility3/symbols"));
        dirs.retain(|d| d.is_dir());
        dirs
    }

    /// Pagefiles the examiner named, from both variables.
    ///
    /// `SEANCE_PAGEFILES` names paths on this host; `SEANCE_CASE_PAGEFILES`
    /// names evidence the case already holds, resolved against the image record
    /// so a reference is always read in the case the image belongs to. Host
    /// entries are read first, so an index named in both keeps the host file
    /// and the case reference is reported as the duplicate it is.
    ///
    /// A malformed entry, or one naming a file that cannot be opened, is
    /// skipped with a warning rather than failing the analysis: the memory
    /// image is still readable without it, and refusing to run at all would
    /// turn a mistyped path into no evidence examined. The warning names the
    /// entry, so a run that quietly recovered nothing from swap says why.
    fn resolved_pagefiles(&self, image_record: &Artifact) -> Vec<SwapFile> {
        let mut attached: Vec<SwapFile> = Vec::new();
        if let Ok(list) = std::env::var(PAGEFILES_VAR) {
            attach_pagefiles(PAGEFILES_VAR, &list, &mut attached, host_pagefile);
        }
        if let Ok(list) = std::env::var(CASE_PAGEFILES_VAR) {
            attach_pagefiles(CASE_PAGEFILES_VAR, &list, &mut attached, |reference| {
                self.case_evidence
                    .open(image_record, reference)
                    .map(|source| (reference.to_string(), source))
            });
        }
        attached
    }
}

/// Names a pagefile by a path on the host running the analysis.
const PAGEFILES_VAR: &str = "SEANCE_PAGEFILES";

/// Names a pagefile the case already holds, resolved through
/// [`CaseEvidence`].
const CASE_PAGEFILES_VAR: &str = "SEANCE_CASE_PAGEFILES";

/// Parse one `index=reference` list and attach what `open` can resolve.
///
/// `open` turns one reference into `(label, source)` — the label being what a
/// report calls the file — or into the reason it could not, which is what the
/// warning carries. Split out of [`WindowsMemoryAnalysis::resolved_pagefiles`]
/// so both variables go through one parser: the index handling below is the
/// part that must not differ between them, since a pagefile attached under the
/// wrong index answers with another file's bytes rather than failing.
fn attach_pagefiles(
    variable: &str,
    list: &str,
    attached: &mut Vec<SwapFile>,
    open: impl Fn(&str) -> Result<(String, Arc<dyn DataSource>), String>,
) {
    for entry in split_env_list(list) {
        let Some((index, reference)) = entry.split_once('=') else {
            warn!(
                "{variable} entry {entry:?} is not `index=path`, so it is not attached; the index \
                 is required because a pagefile supplied under the wrong one answers with another \
                 file's bytes rather than failing"
            );
            continue;
        };
        let Ok(index) = index.trim().parse::<u8>() else {
            warn!("{variable} entry {entry:?} has a non-numeric index, so it is not attached");
            continue;
        };
        // Two files under one index is not a merge and cannot be one: every
        // software PTE naming that index would answer from whichever was
        // attached first, and the examiner would have no way to tell which.
        if let Some(existing) = attached.iter().find(|file| file.index == index) {
            warn!(
                "{variable} entry {entry:?} names index {index}, which is already attached from \
                 {:?}; the second file is not attached, because two files under one index would \
                 make every page naming it answer from whichever was read first",
                existing.label
            );
            continue;
        }
        match open(reference.trim()) {
            Ok((label, source)) => attached.push(SwapFile {
                index,
                label,
                source,
            }),
            Err(err) => warn!(
                "{variable} entry {entry:?} was not attached, so swapped pages naming index \
                 {index} stay holes: {err}"
            ),
        }
    }
}

/// Open a pagefile named by a path on this host, as `SEANCE_PAGEFILES` does.
fn host_pagefile(reference: &str) -> Result<(String, Arc<dyn DataSource>), String> {
    let path = PathBuf::from(reference);
    let source = seance_core::data_source::FileDataSource::new(path.clone())
        .map_err(|err| format!("{} could not be opened: {err}", path.display()))?;
    let label = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    Ok((label, Arc::new(source) as Arc<dyn DataSource>))
}

/// The directory table base `SEANCE_MEM_DTB` names, when the examiner set one.
///
/// The escape hatch discovery has always documented and nothing shipped could
/// reach: a hypervisor-saved state whose page directory is outside the swept
/// window, or a capture so smeared that the self-reference test cannot see it.
/// The value is still proved by finding a kernel through it, so a wrong one
/// produces a failure rather than a wrong answer.
///
/// A value that is not a number is an error rather than an ignored setting.
/// Falling back to the sweep would analyse a different address space from the
/// one the examiner named, and the report would carry no sign of it.
fn supplied_dtb() -> Result<Option<u64>, DiscoveryError> {
    match std::env::var("SEANCE_MEM_DTB") {
        Ok(raw) => parse_supplied_dtb(&raw),
        Err(_) => Ok(None),
    }
}

/// Read `SEANCE_MEM_DTB`'s value: hex with an `0x` prefix, or decimal.
fn parse_supplied_dtb(raw: &str) -> Result<Option<u64>, DiscoveryError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let parsed = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse::<u64>(),
    };
    match parsed {
        Ok(0) => Err(DiscoveryError::Configuration {
            detail: "SEANCE_MEM_DTB is 0, which names no page table".to_string(),
        }),
        Ok(dtb) => Ok(Some(dtb)),
        Err(err) => Err(DiscoveryError::Configuration {
            detail: format!(
                "SEANCE_MEM_DTB is {raw:?}, which is not a physical address in hex or decimal: \
                 {err}"
            ),
        }),
    }
}

/// The tcpip.sys type table `SEANCE_MEM_TCPIP_ISF` names, when the examiner set
/// one.
///
/// `Ok(None)` is the ordinary case: the network stage then refuses by name and
/// the examiner is told a tcpip symbol pack is what is missing, which is a fact
/// about what the lab fetched rather than about the machine's network activity.
///
/// A file that is set and will not compile is an error rather than a fall back
/// to the kernel table. Falling back would refuse the stage with "the symbol
/// table has no `_TCP_ENDPOINT` type", sending an examiner to fetch a pack they
/// have already fetched while the real fault — this file — went unnamed.
/// Name the symbol pack the network stage needs, so the refusal can be acted on.
///
/// `_TCP_ENDPOINT`, `_TCP_LISTENER` and `_UDP_ENDPOINT` live in **tcpip.sys**'s
/// symbols, not the kernel's, and this stage refuses — by design — to guess
/// their layout. That refusal was honest and not actionable: it said the
/// examiner was blocked and not on what, so the one command that would unblock
/// them could not be formed (HUNT-058). The kernel path has always named its
/// requirement exactly ("ntkrnlmp.pdb GUID … age …"), which is what
/// `seance fetch-symbols` consumes; this does the same for tcpip.sys, read from
/// its loaded image's CodeView record.
///
/// Returns a sentence to append to the refusal, beginning with a space. An
/// identity that cannot be established is stated as an absence rather than
/// omitted: "we cannot name it" and "there is nothing to name" are different
/// facts, and a missing sentence reads as the second.
fn tcpip_symbol_hint(
    kernel_space: &dyn seance_memory::layer::MemoryLayer,
    kernel_modules: &Result<modules::KernelModules, modules::ModulesError>,
) -> String {
    const TCPIP: &str = "tcpip.sys";

    let Ok(mods) = kernel_modules else {
        return format!(
            " The types it needs are {TCPIP}'s. The kernel's loaded-module list could not be \
             walked on this image, so {TCPIP}'s symbol identity cannot be named here."
        );
    };
    let Some(entry) = mods.modules.iter().find(|m| {
        m.base_name
            .name()
            .is_some_and(|n| n.eq_ignore_ascii_case(TCPIP))
    }) else {
        return format!(
            " The types it needs are {TCPIP}'s, and no module named {TCPIP} is in this image's \
             loaded-module list ({} module(s) were walked), so its symbol identity cannot be \
             named here.",
            mods.modules.len()
        );
    };
    let Some(base) = entry.base else {
        return format!(
            " The types it needs are {TCPIP}'s. Its loader entry at {:#x} is in this image, but \
             the entry's DllBase could not be read, so its symbol identity cannot be named here.",
            entry.entry
        );
    };

    match crate::automagic::pe::read_pe_image(kernel_space, base) {
        Ok(image) => format!(
            " The types it needs are {TCPIP}'s, loaded here at {base:#x} as {} GUID {} age {}. \
             Fetch that pack with `seance fetch-symbols --guid {} --age {} --into symbols \
             --allow-network` and point SEANCE_MEM_TCPIP_ISF at it.",
            image.pdb.pdb, image.pdb.guid, image.pdb.age, image.pdb.guid, image.pdb.age
        ),
        Err(err) => format!(
            " The types it needs are {TCPIP}'s, loaded here at {base:#x}, but its CodeView \
             record could not be read ({err}), so the symbol pack cannot be named here."
        ),
    }
}

fn resolved_tcpip_symbols() -> Result<Option<Arc<SymbolTable>>, String> {
    let Ok(raw) = std::env::var("SEANCE_MEM_TCPIP_ISF") else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(raw);
    match SymbolTable::compile_path(
        &path,
        &DecompressLimits::default(),
        &CompileOptions::default(),
    ) {
        Ok(table) => Ok(Some(Arc::new(table))),
        Err(err) => Err(format!(
            "SEANCE_MEM_TCPIP_ISF names {}, which could not be read as a tcpip.sys symbol table, \
             so the network stage did not run: {err}",
            path.display()
        )),
    }
}

/// The registrable module. This is what `seance_cli` puts in its module list.
pub fn windows_memory_module() -> MemoryAnalysisModule<WindowsMemoryAnalysis> {
    MemoryAnalysisModule::new(WindowsMemoryAnalysis::new())
}

/// The same module, searching memory for `sets` as well.
///
/// The registration site passes the rule set it compiled for the file scanner,
/// so one compiled set stands behind both. See
/// [`WindowsMemoryAnalysis::with_pattern_sets`].
pub fn windows_memory_module_with_patterns(
    sets: Vec<seance_memory::patterns::PatternSet>,
) -> MemoryAnalysisModule<WindowsMemoryAnalysis> {
    MemoryAnalysisModule::new(WindowsMemoryAnalysis::new().with_pattern_sets(sets))
}

/// The analysis with everything an examiner can configure: the patterns to
/// search for, and the strings file whose physical offsets to attribute.
///
/// Both are `None`/empty in the ordinary case, and each makes its own stage
/// report that it did not run rather than that it found nothing.
pub fn windows_memory_module_configured(
    sets: Vec<seance_memory::patterns::PatternSet>,
    strings: Option<crate::strings_map::StringsSource>,
) -> MemoryAnalysisModule<WindowsMemoryAnalysis> {
    MemoryAnalysisModule::new(
        WindowsMemoryAnalysis::new()
            .with_pattern_sets(sets)
            .with_strings_source(strings),
    )
}

impl MemoryAnalysis for WindowsMemoryAnalysis {
    fn id(&self) -> &str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        MODULE_VERSION
    }

    fn os(&self) -> &str {
        "windows"
    }

    fn analyse(
        &self,
        physical: Arc<dyn MemoryLayer>,
        image_record: &Artifact,
    ) -> Result<Vec<Artifact>, ModuleError> {
        let dirs = self.resolved_symbol_dirs();
        // An explicitly-supplied set wins; otherwise take whatever the
        // environment names. Attaching none is the ordinary case and leaves
        // swapped pages as the honest holes they were.
        let mut options = self.options.clone();
        if options.pagefiles.is_empty() {
            options.pagefiles = self.resolved_pagefiles(image_record);
        }
        if options.dtb.is_none() {
            match supplied_dtb() {
                Ok(dtb) => options.dtb = dtb,
                // Refusing the whole analysis is the point. An examiner who
                // named a directory table base and silently got the swept one
                // instead would read a profile of an address space they did not
                // ask for, with nothing in the case saying so.
                Err(err) => {
                    warn!("{}: {}", MODULE_ID, err);
                    return Ok(vec![
                        stage_manifest_record(image_record),
                        discovery_failure_record(image_record, &err, &dirs),
                    ]);
                }
            }
        }
        for file in &options.pagefiles {
            info!(
                "{MODULE_ID}: pagefile {} attached as index {}; pages it holds are not what was \
                 in RAM at acquisition and may predate it",
                file.label, file.index
            );
        }
        match automagic::discover_reported(Arc::clone(&physical), &dirs, &options) {
            Ok((profile, report)) => {
                info!(
                    "{}: {} kernel at {:#x}, DTB {:#x} ({})",
                    MODULE_ID,
                    profile.build.pdb,
                    profile.kernel_base.value,
                    profile.dtb.value,
                    profile.dtb.evidence.as_str()
                );
                let mut out = vec![
                    stage_manifest_record(image_record),
                    profile_record(image_record, &profile, &report),
                ];
                out.extend(run_stages(
                    &profile,
                    image_record,
                    &self.pattern_sets,
                    self.strings_source.as_ref(),
                ));
                Ok(out)
            }
            Err(err) => {
                // Not an Err: a Windows image Séance cannot profile is a finding
                // about the evidence, and the reason is what tells an examiner
                // what to fetch. Returning Err here would abort the artifact and
                // leave the case silent about an image that plainly exists.
                //
                // The manifest still goes out: "these stages exist and none of
                // them ran" is a different and more useful statement than a
                // coverage view with no stages on it at all.
                warn!("{}: discovery failed: {}", MODULE_ID, err);
                Ok(vec![
                    stage_manifest_record(image_record),
                    discovery_failure_record(image_record, &err, &dirs),
                ])
            }
        }
    }
}

/// Run every analysis stage against a discovered profile.
///
/// A stage that fails is recorded and the rest still run: a registry hive that
/// will not parse must not cost the examiner the process list. Every failure
/// becomes a record of its own, because a stage that could not run and a stage
/// that ran and found nothing are opposite findings and must never render the
/// same way.
///
/// The process list is fetched first and shared, since four later stages need
/// it and walking it four times would be four chances to disagree with itself.
#[allow(clippy::too_many_arguments)]
fn run_stages(
    profile: &WindowsProfile,
    image_record: &Artifact,
    pattern_sets: &[seance_memory::patterns::PatternSet],
    strings_source: Option<&crate::strings_map::StringsSource>,
) -> Vec<Artifact> {
    let mut out = Vec::new();

    // Processes. Everything downstream hangs off this, so its failure is worth
    // stating loudly: without it there is no list to walk modules, handles or
    // hollowing over.
    let processes = match process::ProcessSymbols::from_profile(profile).and_then(|symbols| {
        process::list_processes(profile, &symbols, &process::ProcessListConfig::default())
            .map(|list| (symbols, list))
    }) {
        Ok((symbols, list)) => {
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_PROCESSES,
                list.to_json(),
                list.is_complete(),
            ));
            // Two facts, neither implying the other, and the artifact needs
            // both. `ProcessTree::is_complete` is the tree's own verdict: it
            // covers edges that rest on a reused process id, cycles and
            // unverified links, and `build_tree` documents that a caller must
            // ask it rather than reach back to the list — stamping the tree
            // from `list.is_complete()` alone called a hierarchy of ambiguous
            // edges complete whenever the walk happened to finish. The
            // inventory is the other half: a parent the list never reached
            // makes its children render as roots, so "this process was launched
            // by nothing" is a claim about a list, not about the machine.
            let tree = process::build_tree(&list);
            let mut tree_json = tree.to_json();
            let inventory = list.inventory();
            inventory.stamp(&mut tree_json);
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_PROCESS_TREE,
                tree_json,
                tree.is_complete() && inventory.is_complete(),
            ));
            Some((symbols, list))
        }
        Err(err) => {
            out.push(stage_failure(image_record, profile, &STAGE_PROCESSES, &err));
            None
        }
    };

    // Pool scan: the processes the linked list no longer points at. Runs
    // whether or not the list walk succeeded, because it is the stage that
    // answers "what is the list hiding".
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_POOL_SCAN,
        poolscan::PoolSymbols::from_profile(profile).and_then(|symbols| {
            poolscan::pool_scan(
                profile,
                &symbols,
                &poolscan::builtin_constraints_for(&[*b"Proc"]),
                &poolscan::PoolScanConfig::default(),
            )
        }),
        |outcome| (outcome.to_json(), outcome.is_complete()),
    );

    // Cross-view: which listing saw each process, and which did not.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_CROSS_VIEW,
        psxview::PsXViewSymbols::from_profile(profile)
            .and_then(|s| psxview::cross_view(profile, &s, &psxview::PsXViewConfig::default())),
        |view| (view.to_json(), view.is_complete()),
    );

    // Kernel drivers, network state, services and registry hives are all
    // machine-wide rather than per-process.
    // Kept rather than consumed: the network stage's refusal has to name the
    // symbol pack it needs, and tcpip.sys's identity is read from this list
    // (HUNT-058).
    let kernel_modules = modules::ModuleSymbols::from_profile(profile).and_then(|s| {
        modules::list_kernel_modules(profile, &s, &modules::ModuleWalkConfig::default())
    });
    match &kernel_modules {
        Ok(mods) => out.push(stage_record(
            image_record,
            profile,
            &STAGE_KERNEL_MODULES,
            mods.to_json(),
            mods.is_complete(),
        )),
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_KERNEL_MODULES,
            err,
        )),
    }

    // The full survey, not the pool sweep alone: scanning finds endpoints the
    // live tables no longer link to, and walking the tables finds the ones the
    // scanner's constraints reject. Reporting only one silently drops whatever
    // the other would have found.
    //
    // Which decoder runs is the build's decision, made once in `NetworkPlan`:
    // Vista and later have the TcpE/TcpL/UdpA objects, Windows XP has
    // _ADDRESS_OBJECT and _TCPT_OBJECT under TCPA and TCPT, and the two share no
    // structure at all. A build with neither still refuses by name rather than
    // returning an empty table, because an empty table reads as a machine that
    // had no network activity.
    //
    // tcpip.sys's types are not in `ntoskrnl`'s PDB, so the symbol table
    // discovery matched to this image cannot describe a `_TCP_ENDPOINT` at all.
    // `SEANCE_MEM_TCPIP_ISF` is how a lab that fetched tcpip.pdb supplies it;
    // without it the refusal below is about the symbol pack, not the machine.
    let network = match resolved_tcpip_symbols() {
        Ok(tcpip) => netscan::NetworkPlan::from_profile_with_tcpip(profile, tcpip)
            .and_then(|plan| {
                netscan::survey_network_with(
                    profile,
                    &plan,
                    &netscan::NetscanConfig::default(),
                    &netscan::NetstatConfig::default(),
                )
            })
            .map_err(|err| err.to_string()),
        Err(err) => Err(err),
    };
    let network = network.map_err(|err| {
        format!(
            "{err}{}",
            tcpip_symbol_hint(profile.kernel_space.as_ref(), &kernel_modules)
        )
    });
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_NETWORK,
        network,
        |net| (net.to_json(), net.is_complete()),
    );

    // The survey runs the scan AND the list walk and diffs them: a service the
    // scan finds but the list does not has been unlinked, and running the scan
    // alone cannot produce that finding at all.
    match services::ServiceSymbols::from_profile(profile).and_then(|s| {
        services::survey_services(profile, &s, &services::ServiceScanConfig::default())
    }) {
        // One listing per `services.exe` in the image. Normally there is
        // exactly one, but a machine running containers has several, and
        // merging them would lose which host each service belongs to.
        Ok(listings) => out.extend(listings.iter().map(|listing| {
            stage_record(
                image_record,
                profile,
                &STAGE_SERVICES,
                listing.to_json(),
                listing.is_complete(),
            )
        })),
        Err(err) => out.push(stage_failure(image_record, profile, &STAGE_SERVICES, &err)),
    }

    // Execution history held in RAM: the Amcache hive and the AppCompatCache.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_EXECUTION_HISTORY,
        amcache::AmcacheSymbols::from_profile(profile).and_then(|s| {
            amcache::collect_execution_history(profile, &s, &amcache::AmcacheConfig::default())
        }),
        |history| (history.to_json(), history.is_complete()),
    );

    // MFT records recovered from pool memory, which can predate what is on disk.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_MFT_SCAN,
        mftscan::MftScanSymbols::from_profile(profile).and_then(|s| {
            mftscan::scan_mft_records(profile, &s, &mftscan::MftScanConfig::default())
        }),
        |mft| (mft.to_json(), mft.is_complete()),
    );

    // Kernel hooking and persistence: callbacks, the SSDT, driver IRP tables.
    //
    // Its module map is captured for the tamper stage below rather than walked
    // twice: two independent walks are two chances for two records to disagree
    // about which driver owns an address, which `ModuleMap::from_listing`
    // exists to prevent.
    let mut hook_modules: Option<std::sync::Arc<kernel_hooks::ModuleMap>> = None;
    // And its unattributed pointers, for the same reason: the tamper stage
    // asks the unloaded-driver table whether any of them falls in the range of
    // a driver the kernel has unloaded, which is the possibility the hook
    // stage names and cannot answer from the loaded-module map alone.
    let mut hook_candidates: Vec<(String, u64)> = Vec::new();
    // And its driver objects, for the device tree: a second pool sweep is a
    // second chance for two records to disagree about which drivers the
    // machine has.
    let mut hook_drivers: Vec<kernel_hooks::drivers::DriverRecord> = Vec::new();
    match kernel_hooks::KernelHookSymbols::from_profile(profile).and_then(|s| {
        kernel_hooks::examine_kernel_hooks(profile, &s, &kernel_hooks::KernelHookConfig::default())
    }) {
        Ok(hooks) => {
            hook_modules = Some(std::sync::Arc::clone(&hooks.modules));
            hook_candidates = hooks.unattributed_candidates();
            hook_drivers = hooks.drivers.clone();
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_KERNEL_HOOKS,
                hooks.to_json(),
                hooks.is_complete(),
            ))
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_KERNEL_HOOKS,
            &err,
        )),
    }

    // The device tree (ROADMAP §5.3). Runs off the driver objects the hook
    // stage already swept for; a driver list that is empty because that sweep
    // failed produces a record saying so rather than a tree with no filters in
    // it.
    match device_tree::DeviceTreeSymbols::from_profile(profile) {
        Ok(symbols) => {
            let tree = device_tree::survey_devices(profile, &symbols, &hook_drivers);
            let mut value = tree.to_json();
            if hook_drivers.is_empty() {
                if let Some(object) = value.as_object_mut() {
                    object.insert(
                        "driver_sweep_note".into(),
                        json!(
                            "The kernel-hook stage's driver sweep produced no driver object, so \
                             there was nothing to build a device tree from. This is the absence \
                             of a driver list, NOT a machine whose drivers own no devices and \
                             not an absence of filter drivers."
                        ),
                    );
                    object.insert("content_complete".into(), json!(false));
                }
            }
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_DEVICE_TREE,
                value,
                tree.is_complete() && !hook_drivers.is_empty(),
            ));
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_DEVICE_TREE,
            &err,
        )),
    }

    // The processor control regions (ROADMAP §5.3, `kpcrs`): what each
    // processor was running at capture, with the array checked against the
    // kernel's own count rather than either trusted.
    match processor_blocks::ProcessorSymbols::from_profile(profile) {
        Ok(symbols) => {
            let survey = processor_blocks::survey_processors(profile, &symbols);
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_PROCESSOR_BLOCKS,
                survey.to_json(),
                survey.is_complete(),
            ));
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_PROCESSOR_BLOCKS,
            &err,
        )),
    }

    // The big-page pool table (ROADMAP §5.3, `bigpools`).
    match big_pool::BigPoolSymbols::from_profile(profile) {
        Ok(symbols) => {
            let survey =
                big_pool::survey_big_pool(profile, &symbols, &big_pool::BigPoolConfig::default());
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_BIG_POOL,
                survey.to_json(),
                survey.is_complete(),
            ));
        }
        Err(err) => out.push(stage_failure(image_record, profile, &STAGE_BIG_POOL, &err)),
    }

    // The system virtual-address map (ROADMAP §5.3, `virtmap`). Its non-paged
    // pool region is what the TrueCrypt sweep below is scoped to, so the
    // survey is kept rather than consumed.
    let virtual_map = match virtual_map::VirtualMapSymbols::from_profile(profile) {
        Ok(symbols) => {
            let survey = virtual_map::survey_virtual_map(profile, &symbols);
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_VIRTUAL_MAP,
                survey.to_json(),
                survey.is_complete(),
            ));
            Some(survey)
        }
        Err(err) => {
            out.push(stage_failure(
                image_record,
                profile,
                &STAGE_VIRTUAL_MAP,
                &err,
            ));
            None
        }
    };

    // Each hive's cell routines (ROADMAP §5.3, `getcellroutine`), placed
    // against the same module map the hook and tamper stages use.
    match hive_cell_routines::HiveCellRoutineSymbols::from_profile(profile) {
        Ok(symbols) => {
            let fallback;
            let map: &kernel_hooks::ModuleMap = match &hook_modules {
                Some(map) => map,
                None => {
                    fallback = kernel_hooks::ModuleMap::from_profile(profile);
                    &fallback
                }
            };
            let survey = hive_cell_routines::survey_hive_cell_routines(profile, &symbols, map);
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_HIVE_CELL_ROUTINES,
                survey.to_json(),
                survey.is_complete(),
            ));
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_HIVE_CELL_ROUTINES,
            &err,
        )),
    }

    // TrueCrypt/VeraCrypt (ROADMAP §5.3). The driver's presence comes from the
    // kernel module list already walked; the sweep, when the driver is there,
    // is scoped to the non-paged pool region the virtual map named.
    {
        let (candidates, list_complete) = match &kernel_modules {
            Ok(list) => (
                list.modules
                    .iter()
                    .map(|m| truecrypt::DriverCandidate {
                        name: m.base_name.name().map(str::to_string),
                        base: m.base,
                        size: m.size_of_image,
                    })
                    .collect::<Vec<_>>(),
                list.is_complete(),
            ),
            Err(_) => (Vec::new(), false),
        };
        let loader_entries: Vec<u64> = kernel_modules
            .as_ref()
            .map(|list| list.modules.iter().map(|m| m.entry).collect())
            .unwrap_or_default();
        let region = virtual_map.as_ref().and_then(|map| {
            crate::virtual_map::pool_sweep_region(&map.regions, &loader_entries).map(
                |(r, basis)| truecrypt::SweepRegion {
                    layer: Arc::clone(&profile.kernel_space),
                    base: r.base,
                    bytes: r.bytes,
                    description: match basis {
                        crate::virtual_map::PoolRegionBasis::Label => format!(
                            "the MiVaNonPagedPool region at {:#018x} ({} bytes), from the virtual-address map",
                            r.base, r.bytes
                        ),
                        crate::virtual_map::PoolRegionBasis::LoaderEntries => format!(
                            "the region at {:#018x} ({} bytes) that holds the loader entries, which are non-paged pool allocations; the virtual-address map names it {} and names a different region MiVaNonPagedPool",
                            r.base,
                            r.bytes,
                            r.type_name.as_deref().unwrap_or("nothing")
                        ),
                    },
                },
            )
        });
        let survey = truecrypt::survey_truecrypt(
            &candidates,
            list_complete,
            region,
            &truecrypt::TrueCryptConfig::default(),
        );
        out.push(stage_record(
            image_record,
            profile,
            &STAGE_TRUECRYPT,
            survey.to_json(),
            survey.is_complete(),
        ));
    }

    // Boot sectors in physical memory (ROADMAP §5.3, `mbrscan`).
    {
        let scan = mbr_scan::scan_for_mbrs(
            profile.physical.as_ref(),
            &mbr_scan::MbrScanConfig::default(),
        );
        out.push(stage_record(
            image_record,
            profile,
            &STAGE_MBR_SCAN,
            scan.to_json(),
            scan.is_complete(),
        ));
    }

    // Kernel-side tamper checks (ROADMAP §5.3). Deliberately here, before the
    // process list is required below, so the two kernel-side groups still run
    // on an image whose process list could not be walked.
    //
    // `tamper::IMPLEMENTED_GROUPS` is the list of groups whose detection is
    // written; the rest report that they did not run, with their own reason,
    // so that a group landing later cannot have the earlier silence read as
    // evidence the kernel was clean.
    let tamper_config = tamper::TamperConfig {
        modules: hook_modules,
        candidates: hook_candidates,
        ..tamper::TamperConfig::defaults()
    };
    // The process list is passed rather than re-walked, and passed as an
    // `Option`: the three thread groups need it, and the kernel-side groups
    // must still run on an image whose list could not be walked.
    match tamper::examine_tamper(
        profile,
        &tamper_config,
        processes.as_ref().map(|(_, list)| list),
    ) {
        Ok(checks) => out.push(stage_record(
            image_record,
            profile,
            &STAGE_TAMPER_CHECKS,
            checks.to_json(),
            // Complete only when nothing is outstanding. While any group's
            // detection is unwritten the outcome carries an `Incomplete`, and
            // a stage that reported itself complete on that would be
            // publishing a negative result it never established.
            checks.incomplete.is_none(),
        )),
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_TAMPER_CHECKS,
            &err,
        )),
    }

    // Executive objects still in pool: open files, mutants, symbolic links.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_KERNEL_OBJECTS,
        objects::ObjectSymbols::from_profile(profile).and_then(|s| {
            objects::scan_objects(profile, &s, &objects::ObjectScanConfig::default())
        }),
        |objs| (objs.to_json(), objs.is_complete()),
    );

    // Sessions, desktops and per-process environment blocks.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_ENVIRONMENT,
        environment::EnvironmentSymbols::from_profile(profile).and_then(|s| {
            environment::survey_environment(profile, &s, &environment::EnvironmentConfig::default())
        }),
        |env| (env.to_json(), env.is_complete()),
    );

    // Credentials recoverable from the hives held in memory: the inventory of
    // stores (which hives, which accounts, which secrets), and — new for
    // MEM-008 — the decrypted local-account NT hashes, each as its own audited
    // MemoryCredential record the reveal endpoint serves.
    match credentials::survey_credentials(profile, &credentials::CredentialConfig::default()) {
        Ok(creds) => {
            let recovered = credential_decrypt::recover_sam_hashes(profile);
            let hashes: Vec<_> = recovered
                .credentials
                .iter()
                .filter(|c| c.nt_hash.is_some())
                .collect();

            // The inventory record still describes the stores; it now also
            // states how many account hashes were decrypted out of them and
            // whether the boot key was recovered, so the section is not read as
            // "nothing decrypted" when values are present in the records below.
            let mut inventory = creds.to_json();
            if let Some(object) = inventory.as_object_mut() {
                object.insert("credentials_recovered".into(), json!(hashes.len()));
                object.insert("plaintext_recovered".into(), json!(!hashes.is_empty()));
                object.insert(
                    "boot_key_recovered".into(),
                    json!(recovered.boot_key.is_some()),
                );
                object.insert(
                    "lsa_secrets_recovered".into(),
                    json!(recovered.lsa_secrets.len()),
                );
                object.insert(
                    "cached_logons_recovered".into(),
                    json!(recovered.cached_logons.len()),
                );
                if let Some(reason) = &recovered.unavailable {
                    object.insert("decryption_unavailable".into(), json!(reason));
                }
                if let Some(note) = &recovered.security_note {
                    object.insert("security_hive_note".into(), json!(note));
                }
            }
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_CREDENTIALS,
                inventory,
                creds.is_complete(),
            ));

            // One audited value record per recovered account.
            for cred in hashes {
                let mut value = json!({
                    // The type the reveal endpoint (seance_api) audits.
                    "type": "MemoryCredential",
                    "record_type": "MemoryCredential",
                    "stage": STAGE_CREDENTIALS.key,
                    "source": "sam",
                    "username": cred.username,
                    "rid": cred.rid,
                    "format": "nt_hash",
                    "value": cred.nt_hash,
                });
                if let Some(object) = value.as_object_mut() {
                    if let Some(note) = &cred.note {
                        object.insert("note".into(), json!(note));
                    }
                    stamp(object, profile);
                }
                out.push(
                    Artifact::new(
                        image_record.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        value,
                    )
                    .with_parent(image_record.id),
                );
            }

            // One audited value record per decrypted LSA secret.
            for secret in &recovered.lsa_secrets {
                let mut value = json!({
                    "type": "MemoryCredential",
                    "record_type": "MemoryCredential",
                    "stage": STAGE_CREDENTIALS.key,
                    "source": "lsa_secret",
                    "username": secret.name,
                    "format": "lsa_secret",
                    "length": secret.length,
                    "value": secret.value,
                });
                if let Some(object) = value.as_object_mut() {
                    stamp(object, profile);
                }
                out.push(
                    Artifact::new(
                        image_record.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        value,
                    )
                    .with_parent(image_record.id),
                );
            }

            // One audited value record per cached domain logon (DCC2).
            for logon in &recovered.cached_logons {
                let mut value = json!({
                    "type": "MemoryCredential",
                    "record_type": "MemoryCredential",
                    "stage": STAGE_CREDENTIALS.key,
                    "source": "cached_domain_logon",
                    "username": logon.username,
                    "domain": logon.domain,
                    "format": "dcc2",
                    "iterations": logon.iterations,
                    "value": format!("$DCC2${}#{}#{}", logon.iterations, logon.username, logon.dcc2_hash),
                });
                if let Some(object) = value.as_object_mut() {
                    stamp(object, profile);
                }
                out.push(
                    Artifact::new(
                        image_record.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        value,
                    )
                    .with_parent(image_record.id),
                );
            }
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_CREDENTIALS,
            &err,
        )),
    }

    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_REGISTRY_HIVES,
        registry::list_hives(profile),
        |hives| (hives.to_json(), hives.is_complete()),
    );

    // Scheduled tasks from the SOFTWARE hive in RAM (ROADMAP §5.3). Never
    // fails as a whole: a hive that is not loaded is a record saying so.
    {
        let survey = scheduled_tasks::survey_scheduled_tasks(profile);
        out.push(stage_record(
            image_record,
            profile,
            &STAGE_SCHEDULED_TASKS,
            survey.to_json(),
            survey.is_complete(),
        ));
    }

    // Examiner-supplied patterns over memory (ROADMAP §5.3). Deliberately
    // above the process-list requirement: the kernel's own space is searched
    // whether or not the process list walked, and the survey states which of
    // the two routes it managed. The process list is passed rather than
    // re-walked, for the same reason the tamper checks take it.
    //
    // With no rule set and no pattern named there is nothing to search for, and
    // that is reported as the stage not having run. An empty match list from a
    // scan that never had a pattern is indistinguishable, on screen, from an
    // empty match list from a scan that had one.
    if pattern_sets.is_empty() {
        out.push(stage_failure(
            image_record,
            profile,
            &STAGE_PATTERN_SCAN,
            &"no YARA rule set and no pattern was named for this run, so nothing was searched \
              for in memory. Séance ships no rules of its own: a match is only ever as good as \
              the rule behind it, and a tool used in evidence has no business asserting what to \
              hunt for on an examiner's behalf. Point SEANCE_YARA_RULES at a rule file or \
              directory to search. Nothing here is a statement about what this image holds.",
        ));
    } else {
        match pattern_scan::PatternScanSymbols::from_profile(profile) {
            Ok(symbols) => {
                let survey = pattern_scan::scan_patterns(
                    profile,
                    &symbols,
                    processes.as_ref().map(|(_, list)| list),
                    pattern_sets,
                    &pattern_scan::PatternScanConfig::default(),
                );
                out.push(stage_record(
                    image_record,
                    profile,
                    &STAGE_PATTERN_SCAN,
                    survey.to_json(),
                    survey.is_complete(),
                ));
            }
            Err(err) => out.push(stage_failure(
                image_record,
                profile,
                &STAGE_PATTERN_SCAN,
                &err,
            )),
        }
    }

    // `strings` over memory (ROADMAP §5.3). Above the process-list
    // requirement for the same reason the pattern scan is: the kernel's own
    // address space holds paged pool and the file cache, and an offset in
    // either belongs to no process at all, so the stage still answers when the
    // list did not walk — and says on the record how many processes it walked
    // against how many were listed.
    //
    // With no strings file named there is nothing to look up. That is reported
    // as the stage not having run, because a table of offsets with no owners
    // and a run that was never given a file look identical on screen.
    if strings_source.is_none() {
        // A `MemoryStageFailure`, exactly as the pattern scan emits with no
        // rule named -- not a record with `stage_ran: true` and an empty
        // table. Coverage reads `stage_ran`, so a record here would have the
        // coverage view report a stage that ran and found no owners, which is
        // the opposite of what happened and contradicts the stage's own
        // description and every document that describes it.
        out.push(stage_failure(
            image_record,
            profile,
            &STAGE_STRINGS_MAP,
            &"no strings file was named for this run, so no physical offset was looked up. Séance runs no `strings` of its own: the minimum length, the encodings and the scope are an examiner's decisions, not a tool's. Run `strings -t d` over the image and name the file with SEANCE_MEMORY_STRINGS. Nothing here is a statement about what this image holds.",
        ));
    } else {
        match modules::ModuleSymbols::from_profile(profile) {
            Ok(module_symbols) => {
                match strings_map::map_strings(
                    profile,
                    &module_symbols,
                    processes.as_ref().map(|(_, list)| list),
                    strings_source,
                    &strings_map::StringsMapConfig::default(),
                ) {
                    Ok(mapped) => out.push(stage_record(
                        image_record,
                        profile,
                        &STAGE_STRINGS_MAP,
                        mapped.to_json(),
                        mapped.is_complete(),
                    )),
                    Err(err) => out.push(stage_failure(
                        image_record,
                        profile,
                        &STAGE_STRINGS_MAP,
                        &err,
                    )),
                }
            }
            Err(err) => out.push(stage_failure(
                image_record,
                profile,
                &STAGE_STRINGS_MAP,
                &err,
            )),
        }
    }

    // The per-process stages. They need the list, so they are skipped — with a
    // record saying why — when it could not be walked.
    let Some((process_symbols, list)) = processes else {
        out.push(skipped_record(
            image_record,
            profile,
            STAGES_NEEDING_THE_PROCESS_LIST,
            "the active process list could not be walked, so there was no list of processes to \
             examine",
        ));
        return out;
    };

    // Command lines. The arguments a program was started with are not in the
    // kernel structure at all — they are in the process's own user address
    // space, reached through its directory table base — so this is the only
    // stage that can answer "what was this svchost.exe actually running", which
    // is the whole question an examiner has about svchost.exe.
    //
    // Never fails as a whole: every way of not getting an answer is a variant
    // on the row, so a process whose PEB was paged out is reported as unknown
    // rather than as having been started with no arguments.
    {
        let listing = process::read_command_lines(profile, &process_symbols, &list);
        let mut value = listing.to_json();
        let inventory = list.inventory();
        inventory.stamp(&mut value);
        out.push(stage_record(
            image_record,
            profile,
            &STAGE_COMMAND_LINES,
            value,
            listing.is_complete() && inventory.is_complete(),
        ));
    }

    // Job objects. One record per distinct `_EJOB`, which is how a sandbox
    // shows up in memory -- and the reverse, a process that ought to be in a
    // job and is not.
    push_stage(
        &mut out,
        image_record,
        profile,
        &STAGE_JOBS,
        jobs::JobSymbols::from_profile(profile)
            .and_then(|symbols| jobs::survey_jobs(profile, &symbols, &list)),
        |survey| (survey.to_json(), survey.is_complete()),
    );

    // Version resources (ROADMAP §5.3, `verinfo`): the kernel's modules and
    // every process's DLLs, read from the bytes in memory.
    {
        let survey = version_info::survey_version_info(
            profile,
            kernel_modules.as_ref().map_err(|err| err.to_string()),
            Some(&list),
            &version_info::VersionInfoConfig::default(),
        );
        out.push(stage_record(
            image_record,
            profile,
            &STAGE_VERSION_INFO,
            survey.to_json(),
            survey.is_complete(),
        ));
    }

    // Console command history (ROADMAP §5.3): each console host's heap, swept
    // for the history vector. Needs the process list for the hosts and the VAD
    // symbols for their allocations.
    match vad::VadSymbols::from_profile(profile) {
        Ok(vad_symbols) => {
            let survey = console_history::survey_console_history(
                profile,
                &process_symbols,
                &vad_symbols,
                &list,
                &console_history::ConsoleHistoryConfig::default(),
            );
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_CONSOLE_HISTORY,
                survey.to_json(),
                survey.is_complete(),
            ));
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_CONSOLE_HISTORY,
            &err,
        )),
    }

    match vad::VadSymbols::from_profile(profile) {
        Ok(symbols) => out.extend(per_process_vads(profile, &symbols, &list, image_record)),
        Err(err) => out.push(stage_failure(image_record, profile, &STAGE_VAD, &err)),
    }

    // DLLs and the unlinked-module cross-reference, per process. This is the
    // stage that answers "was a module hidden from the loader lists", which the
    // kernel-driver walk above cannot: it needs the PEB lists AND the VAD tree
    // for every process, compared against each other.
    match modules::ModuleSymbols::from_profile(profile) {
        Ok(symbols) => {
            let survey = modules::survey_process_modules(
                profile,
                &symbols,
                &list,
                &modules::ModuleSurveyConfig::default(),
            );
            out.extend(per_process_modules(profile, &survey, image_record));
        }
        Err(err) => out.push(stage_failure(image_record, profile, &STAGE_DLLS, &err)),
    }

    match handles::HandleSymbols::from_profile(profile) {
        Ok(symbols) => out.extend(per_process_handles(profile, &symbols, &list, image_record)),
        Err(err) => out.push(stage_failure(image_record, profile, &STAGE_HANDLES, &err)),
    }

    // System-call evasion. Runs on the shared process list like the other
    // per-process stages; refuses on a 32-bit image, where the kernel is not
    // entered by a `syscall` instruction and the question does not arise.
    match syscalls::SyscallSymbols::from_profile(profile) {
        Ok(symbols) => {
            let scan = syscalls::scan_processes(
                profile,
                &symbols,
                &list,
                &syscalls::SyscallConfig::default(),
            );
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_SYSTEM_CALLS,
                scan.to_json(),
                scan.is_complete(),
            ));
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_SYSTEM_CALLS,
            &err,
        )),
    }

    // Files the cache manager still held, handed back to the ordinary parsers.
    // A recovered `places.sqlite` reaches the browser-history parser, a
    // recovered hive reaches the registry parser — the same path a file
    // extracted from a disk image takes. Only whole reconstructions are handed
    // on; the reason is in `recovered`'s module docs.
    match dump::DumpSymbols::from_profile(profile) {
        Ok(symbols) => {
            match recovered::survey_recovered_files(
                image_record,
                profile,
                &symbols,
                &recovered::RecoveredFileConfig::default(),
            ) {
                Ok((survey, mut produced)) => {
                    out.push(stage_record(
                        image_record,
                        profile,
                        &STAGE_RECOVERED_FILES,
                        survey.to_json(),
                        survey.is_complete(),
                    ));
                    out.append(&mut produced);
                }
                Err(err) => out.push(stage_failure(
                    image_record,
                    profile,
                    &STAGE_RECOVERED_FILES,
                    &err,
                )),
            }
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_RECOVERED_FILES,
            &err,
        )),
    }

    match hollow::HollowSymbols::from_profile(profile) {
        Ok(symbols) => {
            let scan = hollow::examine_processes(
                profile,
                &symbols,
                &list,
                &hollow::HollowConfig::for_profile(profile),
            );
            out.push(stage_record(
                image_record,
                profile,
                &STAGE_TAMPERING,
                scan.to_json(),
                scan.is_complete(),
            ));
        }
        Err(err) => out.push(stage_failure(image_record, profile, &STAGE_TAMPERING, &err)),
    }

    // Suspicious threads (MEM-024): where each live user thread started, placed
    // in its own process's VAD tree. The hollowing stage above checks the VAD
    // at the image base; this one checks where the threads actually run.
    match psxview::SuspiciousThreadSymbols::from_profile(profile) {
        Ok(symbols) => {
            let survey = psxview::survey_suspicious_threads(
                profile,
                &symbols,
                &list,
                &psxview::SuspiciousThreadsConfig::for_profile(profile),
            );
            out.push(suspicious_threads_record(image_record, profile, &survey));
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_SUSPICIOUS_THREADS,
            &err,
        )),
    }

    out
}

/// The suspicious-thread stage's record, from its survey.
fn suspicious_threads_record(
    image_record: &Artifact,
    profile: &WindowsProfile,
    survey: &psxview::SuspiciousThreadsSurvey,
) -> Artifact {
    stage_record(
        image_record,
        profile,
        &STAGE_SUSPICIOUS_THREADS,
        survey.to_json(),
        survey.is_complete(),
    )
}

/// Emit one record per process for a stage that examines each process on its
/// own, and one failure record for each process it could not examine.
///
/// The single seam every per-process stage goes through, so that the three
/// things such a record must carry cannot be got right in one stage and
/// forgotten in the next:
///
/// * **which process it belongs to** ([`tag_process`]) — a per-process record
///   with no process on it is unattributable;
/// * **the inventory of the list it came from** — these records describe the
///   processes the walk reached, and nothing in a per-process record can say
///   that the list stopped before reaching others. A stage that examined every
///   process it was handed reports `content_complete: true` over a list that
///   never reached the process doing the hiding, and "there is no record for
///   that PID" then reads as a process examined and found unremarkable rather
///   than one nothing looked at;
/// * **its own verdict**, conjoined with the inventory's, so completeness is
///   never claimed on the strength of only one of the two.
///
/// A process that will not examine is recorded as a failure against that
/// process rather than aborting the stage: one unreadable process must not cost
/// the other hundred.
///
/// `examine` returns the record body and that body's own completeness, or the
/// reason this process could not be examined.
fn per_process_records(
    profile: &WindowsProfile,
    list: &process::ProcessList,
    image_record: &Artifact,
    stage: &StageId,
    examine: impl Fn(&process::ProcessRecord) -> Result<(serde_json::Value, bool), String>,
) -> Vec<Artifact> {
    let inventory = list.inventory();
    list.processes
        .iter()
        .map(|entry| match examine(entry) {
            Ok((mut value, complete)) => {
                tag_process(&mut value, entry);
                inventory.stamp(&mut value);
                stage_record(
                    image_record,
                    profile,
                    stage,
                    value,
                    complete && inventory.is_complete(),
                )
            }
            Err(reason) => {
                let mut record = stage_failure(image_record, profile, stage, &reason);
                tag_process(&mut record.metadata, entry);
                inventory.stamp(&mut record.metadata);
                record
            }
        })
        .collect()
}

/// Walk every process's VAD tree, one record per process.
fn per_process_vads(
    profile: &WindowsProfile,
    symbols: &vad::VadSymbols,
    list: &process::ProcessList,
    image_record: &Artifact,
) -> Vec<Artifact> {
    // Bound to the profile, so every allocation's protection can be named.
    // `VadWalkConfig::default()` leaves the kernel's protection table unread
    // and every range then reports its protection as uninterpretable -- with a
    // note blaming the image for a table nobody asked for.
    let config = vad::VadWalkConfig::for_profile(profile);
    per_process_records(
        profile,
        list,
        image_record,
        &STAGE_VAD,
        |entry| match vad::list_vads(profile, symbols, entry.address, &config) {
            Ok(tree) => Ok((tree.to_json(), tree.is_complete())),
            Err(err) => Err(err.to_string()),
        },
    )
}

/// Read every process's handle table, one record per process.
fn per_process_handles(
    profile: &WindowsProfile,
    symbols: &handles::HandleSymbols,
    list: &process::ProcessList,
    image_record: &Artifact,
) -> Vec<Artifact> {
    let config = handles::HandleWalkConfig::default();
    per_process_records(profile, list, image_record, &STAGE_HANDLES, |entry| {
        match handles::list_handles(profile, symbols, entry.address, &config) {
            Ok(table) => Ok((table.to_json(), table.is_complete())),
            Err(err) => Err(err.to_string()),
        }
    })
}

/// One record per process for the module stage, plus one failure per process
/// nothing could be read for.
///
/// The survey is image-wide, but the Process Inspector asks "what did *this*
/// PID load", and an endpoint that has to search a nested `processes[]` array
/// for a PID cannot say whether a PID it did not find was absent or unexamined.
/// Emitting per process makes the two different records: a process that was
/// examined has a `MemoryProcessModules` tagged with its id, and a process that
/// could not be is a failure tagged with its id and the reason.
///
/// A survey that examined nothing at all still emits a failure, because an
/// empty stage would otherwise read as a machine whose processes had loaded no
/// modules — which is never true of a running Windows machine.
fn per_process_modules(
    profile: &WindowsProfile,
    survey: &modules::ModuleSurvey,
    image_record: &Artifact,
) -> Vec<Artifact> {
    let mut out = Vec::new();
    for entry in &survey.processes {
        let mut value = entry.to_json();
        if let Some(object) = value.as_object_mut() {
            // The per-process record inherits the survey's verdict on the list
            // it walked: every module of every process examined is still a
            // floor when the process list itself stopped short.
            object.insert(
                "vad_symbols_unavailable".into(),
                json!(survey.vad_symbols_unavailable),
            );
        }
        survey.inventory.stamp(&mut value);
        out.push(stage_record(
            image_record,
            profile,
            &STAGE_DLLS,
            value,
            entry.is_complete() && survey.inventory.is_complete(),
        ));
    }
    for skipped in &survey.skipped {
        let mut record = stage_failure(image_record, profile, &STAGE_DLLS, &skipped.reason);
        if let Some(object) = record.metadata.as_object_mut() {
            object.insert("process_address".into(), json!(skipped.process));
            object.insert(
                "process_address_hex".into(),
                json!(format!("{:#x}", skipped.process)),
            );
            if let Some(pid) = skipped.pid {
                object.insert("pid".into(), json!(pid));
            }
            if let Some(name) = &skipped.name {
                object.insert("process_name".into(), json!(name));
            }
        }
        out.push(record);
    }
    if out.is_empty() {
        out.push(stage_failure(
            image_record,
            profile,
            &STAGE_DLLS,
            &"no process on the active list could be examined for loaded modules, so nothing here \
              is evidence that any process had none",
        ));
    }
    out
}

/// Stamp which process a per-process record belongs to.
fn tag_process(value: &mut serde_json::Value, entry: &process::ProcessRecord) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    object.insert("process_address".into(), json!(entry.address));
    // Exact form beside the number. JSON numbers are IEEE doubles and every x64
    // kernel address is above 2^53, so the numeric form can arrive at a client
    // rounded by up to a kilobyte. A pointer quoted in a report has to be the
    // pointer that was read.
    object.insert(
        "process_address_hex".into(),
        json!(format!("{:#x}", entry.address)),
    );
    if let Some(pid) = entry.pid.known() {
        object.insert("pid".into(), json!(pid));
    }
    if let Some(name) = entry.image_file_name.known() {
        object.insert("process_name".into(), json!(name));
    }
}

/// One stage's outcome as a record: what it found, or why it could not run.
/// `describe` reads the survey's JSON body and whether it is complete.
fn push_stage<S, E: std::fmt::Display>(
    out: &mut Vec<Artifact>,
    parent: &Artifact,
    profile: &WindowsProfile,
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
    profile: &WindowsProfile,
    stage: &StageId,
    value: serde_json::Value,
    complete: bool,
) -> Artifact {
    seance_memory::stage_records::stage_record(
        parent,
        stage,
        value,
        complete,
        "process_inventory",
        &|object| stamp(object, profile),
    )
}

/// A record saying a stage could not run, and why.
fn stage_failure(
    parent: &Artifact,
    profile: &WindowsProfile,
    stage: &StageId,
    err: &dyn std::fmt::Display,
) -> Artifact {
    seance_memory::stage_records::stage_failure(
        parent,
        MODULE_ID,
        "Memory analysis",
        stage,
        err,
        &|object| stamp(object, profile),
    )
}

/// A record saying stages were skipped because a prerequisite failed.
fn skipped_record(
    parent: &Artifact,
    profile: &WindowsProfile,
    stages: &[&StageId],
    reason: &str,
) -> Artifact {
    seance_memory::stage_records::skipped_record(
        parent,
        "Memory analysis: per-process stages did not run",
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
/// The coverage endpoint reads it: a stage named here that the API's own stage
/// table does not describe still gets a row, built from what this record said.
/// That is what stops a stage added to [`STAGES`] from being invisible to an
/// examiner until somebody remembers to edit the API as well.
fn stage_manifest_record(parent: &Artifact) -> Artifact {
    let mut value = json!({
        "type": MEMORY_STAGE_MANIFEST_RECORD,
        "record_type": MEMORY_STAGE_MANIFEST_RECORD,
        "name": "Memory analysis: stages this build can run",
        "stages": STAGES.iter().map(StageId::to_json).collect::<Vec<_>>(),
        "stage_count": STAGES.len(),
        "content_complete": true,
    });
    for (key, stamped) in analysed_stamp("windows", MODULE_ID, MODULE_VERSION)
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
fn stamp(object: &mut serde_json::Map<String, serde_json::Value>, profile: &WindowsProfile) {
    for (key, value) in analysed_stamp("windows", MODULE_ID, MODULE_VERSION)
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
fn profile_record(
    parent: &Artifact,
    profile: &WindowsProfile,
    report: &DiscoveryReport,
) -> Artifact {
    let mut m = profile.to_json();
    let obj = m.as_object_mut().expect("profile.to_json is an object");
    obj.insert("type".into(), json!("MemoryProfile"));
    obj.insert("subtype".into(), json!("windows_memory_profile"));
    obj.insert(
        "name".into(),
        json!(format!(
            "Windows {}.{} profile ({})",
            profile.build.major, profile.build.minor, profile.build.pdb
        )),
    );
    obj.insert("discovery".into(), report.to_json());
    // This record supersedes the "profile not established" one an earlier pass
    // left behind, so a case that has since been given its symbols does not
    // show both answers with nothing saying which is current (HUNT-090).
    for (k, v) in
        seance_memory::analysis::analysed_profile_stamp("windows", MODULE_ID, MODULE_VERSION)
            .as_object()
            .expect("stamp is an object")
    {
        obj.insert(k.clone(), v.clone());
    }
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent.id)
}

/// Emitted when discovery could not profile an image that is plainly a memory
/// capture.
///
/// Carries the reason in a form an examiner can act on — most usefully the PDB
/// GUID whose symbols are missing, which is the one thing that turns a failed
/// analysis into a successful one, and the directories where a symbol file may
/// be placed.
fn discovery_failure_record(
    parent: &Artifact,
    err: &DiscoveryError,
    searched: &[PathBuf],
) -> Artifact {
    let m = json!({
        "type": "MemoryProfile",
        "subtype": "windows_memory_profile",
        "name": "Windows memory profile (not established)",
        "analysis_stage": "discovery_failed",
        "analysed_os": "windows",
        "analysed_by": MODULE_ID,
        "analysed_by_version": MODULE_VERSION,
        "profile_established": false,
        "failure": err.to_string(),
        "symbol_dirs_searched": searched
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        // Only directories that EXIST are searched, so on a machine with none
        // of them the list is short or empty and reads as "this build looks in
        // one odd place". Saying where symbols may be placed is what turns the
        // record into an instruction (LIVE-026).
        "symbol_dirs_accepted": seance_memory::analysis::SYMBOL_DIR_GUIDANCE,
    });
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::module::ForensicsModule;

    /// LIVE-026: a failure that lists only the directories that happen to exist
    /// tells an examiner where this build looked, not where they may put the
    /// symbols it asked for. On a shipped install the only existing directory
    /// was a repository-relative developer path, which reads as a broken build
    /// rather than as a missing file.
    #[test]
    fn a_discovery_failure_says_where_symbols_may_be_placed() {
        let parent = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({}),
        );
        let record = discovery_failure_record(
            &parent,
            &DiscoveryError::Configuration {
                detail: "ntkrnlmp.pdb GUID ABC age 1".to_string(),
            },
            &[PathBuf::from("reference/volatility3/volatility3/symbols")],
        );

        let accepted = record.metadata["symbol_dirs_accepted"]
            .as_array()
            .expect("guidance present");
        let joined = accepted
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" | ");

        assert!(joined.contains("SEANCE_SYMBOL_DIRS"), "got {joined}");
        assert!(joined.contains("symbols"), "got {joined}");
        // The searched list is still reported: what was tried and what is
        // accepted are different facts and both matter.
        assert!(record.metadata["symbol_dirs_searched"].is_array());
    }

    #[test]
    fn the_module_carries_the_conventional_id() {
        let m = windows_memory_module();
        assert_eq!(m.id(), "plugin.memory.windows");
        assert!(m.id().starts_with("plugin."));
    }

    #[test]
    fn the_module_subscribes_to_the_record_the_container_stage_emits() {
        let m = windows_memory_module();
        assert_eq!(m.subscribes_to(), vec![ArtifactType::ParsedRecord]);
    }

    #[test]
    fn explicit_symbol_dirs_win_over_the_environment() {
        let a = WindowsMemoryAnalysis::new().with_symbol_dirs(vec![PathBuf::from("/nonexistent")]);
        assert_eq!(
            a.resolved_symbol_dirs(),
            vec![PathBuf::from("/nonexistent")]
        );
    }

    #[test]
    fn a_windows_pagefile_entry_is_not_cut_in_half_at_its_drive_colon() {
        // `0=C:\evidence\pagefile.sys` split on every colon yields `0=C` — an
        // index naming the relative path `C` — and an orphan with no `=` at
        // all. Both are dropped with a warning, so an examiner who set the
        // variable correctly on Windows got no pagefile attached and a report
        // whose swapped pages all stayed holes.
        assert_eq!(
            split_env_list(r"0=C:\evidence\pagefile.sys"),
            vec![r"0=C:\evidence\pagefile.sys"]
        );
        assert_eq!(
            split_env_list(r"0=C:\evidence\pagefile.sys;1=D:\evidence\pagefile2.sys"),
            vec![
                r"0=C:\evidence\pagefile.sys",
                r"1=D:\evidence\pagefile2.sys"
            ]
        );
        // Forward slashes are as valid as backslashes on Windows.
        assert_eq!(
            split_env_list("0=C:/evidence/pagefile.sys"),
            vec!["0=C:/evidence/pagefile.sys"]
        );
    }

    #[test]
    fn a_windows_symbol_directory_survives_the_symbol_dir_list() {
        // These fragments never even warn: the `is_dir` filter drops `C` and
        // `\symbols` silently, so the run looks like one where no symbol
        // directory was set at all.
        assert_eq!(split_env_list(r"C:\symbols"), vec![r"C:\symbols"]);
        assert_eq!(
            split_env_list(r"C:\symbols;D:\packs"),
            vec![r"C:\symbols", r"D:\packs"]
        );
    }

    #[test]
    fn a_colon_separated_unix_list_keeps_parsing_exactly_as_it_always_has() {
        // The fix must not cost the separator every list in the field uses.
        assert_eq!(
            split_env_list("0=/evidence/pagefile.sys:1=/evidence/pagefile2.sys"),
            vec!["0=/evidence/pagefile.sys", "1=/evidence/pagefile2.sys"]
        );
        assert_eq!(
            split_env_list("/opt/symbols:/srv/packs"),
            vec!["/opt/symbols", "/srv/packs"]
        );
        // A drive path beside a Unix path: only the drive colon is spared.
        assert_eq!(
            split_env_list(r"C:\symbols:/opt/symbols"),
            vec![r"C:\symbols", "/opt/symbols"]
        );
        // Empty entries are typos, not requests to open the current directory.
        assert_eq!(split_env_list(""), Vec::<&str>::new());
        assert_eq!(split_env_list("::"), Vec::<&str>::new());
        assert_eq!(split_env_list(" /opt/symbols : "), vec!["/opt/symbols"]);
    }

    /// An image record whose address space is the file at `path`, which is what
    /// the container stage produces for a capture ingested as a loose file.
    fn image_backed_by(path: PathBuf) -> Artifact {
        let source: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::FileDataSource::new(path).expect("the image file exists"),
        );
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(source),
            json!({"type": "MemoryImage", "image_format": "raw"}),
        )
    }

    #[test]
    fn a_pagefile_the_case_holds_beside_the_image_attaches_without_a_host_path() {
        // The gap this closes. A pagefile is ordinarily acquired into the same
        // evidence folder as the capture, and until now the only way to attach
        // one was to type an absolute path on whichever host happened to be
        // running the analysis — so a pagefile that existed only inside the
        // case could not be named at all, and every page the kernel had swapped
        // out stayed a hole while the examiner had the file in hand.
        use crate::automagic::isf::test_support::TempDir;

        let dir = TempDir::new("case-pagefile");
        let image_path = dir.write("memdump.raw", "not really a capture");
        dir.write("pagefile.sys", "swapped-out bytes");
        let image = image_backed_by(image_path);

        let mut attached = Vec::new();
        attach_pagefiles(CASE_PAGEFILES_VAR, "0=pagefile.sys", &mut attached, |r| {
            EvidenceBesideImage
                .open(&image, r)
                .map(|source| (r.to_string(), source))
        });

        assert_eq!(
            attached.len(),
            1,
            "a pagefile beside the image in the case is evidence this analysis can reach"
        );
        assert_eq!(attached[0].index, 0);
        assert_eq!(attached[0].label, "pagefile.sys");
        let mut buf = vec![0u8; b"swapped-out bytes".len()];
        attached[0]
            .source
            .read_at(0, &mut buf)
            .expect("the attached pagefile reads");
        assert_eq!(&buf[..], b"swapped-out bytes");
    }

    #[test]
    fn a_case_reference_outside_the_case_is_refused_rather_than_read_off_the_host() {
        // `SEANCE_CASE_PAGEFILES` names evidence, not a path. A reference that
        // climbs out of the image's own directory must refuse: falling back to
        // the host filesystem would attach a file the case never held and
        // report its pages as this machine's swapped memory.
        use crate::automagic::isf::test_support::TempDir;

        let dir = TempDir::new("case-escape");
        let image_path = dir.write("evidence/memdump.raw", "not really a capture");
        dir.write("elsewhere.sys", "another machine's pages");
        let image = image_backed_by(image_path);

        let mut attached = Vec::new();
        attach_pagefiles(
            CASE_PAGEFILES_VAR,
            "0=../elsewhere.sys",
            &mut attached,
            |r| {
                EvidenceBesideImage
                    .open(&image, r)
                    .map(|source| (r.to_string(), source))
            },
        );
        assert!(
            attached.is_empty(),
            "a reference outside the case is not evidence: {:?}",
            attached.iter().map(|f| f.label.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_default_resolver_reaches_evidence_the_case_holds_beside_the_image() {
        // Reachability, asserted rather than believed: the shipped analysis has
        // a resolver, so `SEANCE_CASE_PAGEFILES` works with nothing wired up.
        // A deployment that keeps evidence in a database replaces it through
        // `with_case_evidence`.
        let analysis = WindowsMemoryAnalysis::new();
        assert!(
            analysis
                .case_evidence
                .describes()
                .contains("beside the memory image"),
            "{}",
            analysis.case_evidence.describes()
        );
    }

    #[test]
    fn two_pagefiles_under_one_index_do_not_both_attach() {
        // A software PTE names one index. Two files under it would make every
        // page naming that index answer from whichever was attached first, and
        // nothing in the case would say a second file had been passed over.
        use seance_core::data_source::ByteSliceDataSource;

        let mut attached = Vec::new();
        attach_pagefiles(PAGEFILES_VAR, "0=first:0=second", &mut attached, |r| {
            Ok((
                r.to_string(),
                Arc::new(ByteSliceDataSource::new(r.as_bytes().to_vec())) as Arc<dyn DataSource>,
            ))
        });
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].label, "first");

        // A second, different index is still attached: the guard is about a
        // collision, not about attaching only one file.
        attach_pagefiles(PAGEFILES_VAR, "1=second", &mut attached, |r| {
            Ok((
                r.to_string(),
                Arc::new(ByteSliceDataSource::new(r.as_bytes().to_vec())) as Arc<dyn DataSource>,
            ))
        });
        assert_eq!(attached.len(), 2);
        assert_eq!(attached[1].index, 1);
    }

    #[test]
    fn an_examiner_can_name_the_directory_table_base_the_sweep_cannot_find() {
        // Discovery has always documented a supplied base as the escape hatch
        // for an image whose page directory sits outside the swept window, and
        // nothing in the shipped binary could reach it: the module read only
        // SEANCE_SYMBOL_DIRS and SEANCE_PAGEFILES.
        assert_eq!(parse_supplied_dtb("0x1ae000").expect("hex"), Some(0x1ae000));
        assert_eq!(parse_supplied_dtb("0X1AE000").expect("hex"), Some(0x1ae000));
        assert_eq!(
            parse_supplied_dtb(" 1757184 ").expect("decimal"),
            Some(1757184)
        );
        assert_eq!(parse_supplied_dtb("").expect("unset"), None);
    }

    #[test]
    fn a_directory_table_base_that_is_not_a_number_refuses_rather_than_being_ignored() {
        // Ignoring it would analyse the swept address space while the examiner
        // believed they had named a different one, and nothing in the case
        // would say so.
        let err = parse_supplied_dtb("1ae000").expect_err("no 0x prefix, not decimal either");
        assert!(err.to_string().contains("1ae000"), "{err}");
        assert!(
            parse_supplied_dtb("0x0").is_err(),
            "zero names no page table"
        );
        assert!(parse_supplied_dtb("first one").is_err());
    }

    #[test]
    fn every_stage_identity_is_unique_in_both_its_key_and_its_record_type() {
        // Two stages sharing a key would make coverage report one over the
        // other; two sharing a record type would make one stage's rows count as
        // the other's, so a stage that never ran could read as complete.
        for stage in STAGES {
            assert_eq!(
                STAGES.iter().filter(|s| s.key == stage.key).count(),
                1,
                "duplicate stage key {}",
                stage.key
            );
            assert_eq!(
                STAGES
                    .iter()
                    .filter(|s| s.record_type == stage.record_type)
                    .count(),
                1,
                "duplicate record type {}",
                stage.record_type
            );
            assert!(
                !stage.key.is_empty() && !stage.describes.is_empty(),
                "{stage:?}"
            );
            assert!(
                stage.record_type.starts_with("Memory"),
                "{} does not follow the Memory* record naming",
                stage.record_type
            );
        }
    }

    #[test]
    fn the_manifest_publishes_every_stage_this_build_can_run() {
        // The manifest must name every stage in the table, so the case records
        // what this build could have run rather than only what it managed to
        // produce. A manifest short of a stage is a stage that can run and
        // leave no trace of having been possible.
        let image = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "MemoryImage"}),
        );
        let manifest = stage_manifest_record(&image);

        assert_eq!(manifest.metadata["type"], json!("MemoryStageManifest"));
        assert_eq!(manifest.metadata["stage_count"], json!(STAGES.len()));
        assert_eq!(manifest.parent_id, Some(image.id));
        let declared = manifest.metadata["stages"].as_array().expect("an array");
        assert_eq!(declared.len(), STAGES.len());
        for stage in STAGES {
            let row = declared
                .iter()
                .find(|row| row["stage"] == json!(stage.key))
                .unwrap_or_else(|| panic!("{} is missing from the manifest", stage.key));
            assert_eq!(row["record_type"], json!(stage.record_type));
            assert_eq!(row["per_process"], json!(stage.per_process));
        }
    }

    #[test]
    fn the_manifest_rows_use_the_field_names_the_coverage_reader_looks_for() {
        // `seance_api::memory::declared_stages` reads each manifest row by
        // these four names. It cannot be imported here — the API does not
        // depend on this crate, and must not — so the contract is pinned on
        // this side against the same literals.
        //
        // Nothing fails to compile when one of them is renamed. What happens
        // instead is quieter: `declared_stages` skips a row missing `stage` or
        // `record_type`, so a stage this build runs and the API does not know
        // about vanishes from Coverage entirely; and a row missing `describes`
        // arrives with the endpoint's placeholder text, telling the examiner
        // nothing about what the stage establishes. Both read to an examiner as
        // "there was nothing to find here".
        let image = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "MemoryImage"}),
        );
        let manifest = stage_manifest_record(&image);
        let rows = manifest.metadata["stages"].as_array().expect("an array");
        assert!(!rows.is_empty());

        for row in rows {
            let row = row.as_object().expect("each manifest row is an object");
            for field in ["stage", "record_type", "per_process", "describes"] {
                assert!(
                    row.contains_key(field),
                    "manifest row {row:?} has no `{field}`, which the coverage endpoint reads"
                );
            }
            assert!(row["stage"].is_string(), "{row:?}");
            assert!(row["record_type"].is_string(), "{row:?}");
            assert!(row["per_process"].is_boolean(), "{row:?}");
            assert!(
                row["describes"].as_str().is_some_and(|d| !d.is_empty()),
                "a stage with no description reaches the examiner as a blank row: {row:?}"
            );
        }
    }

    /// Stage keys `seance_api::memory::STAGES` has no row of its own for.
    ///
    /// Coverage still lists them: the endpoint reads the manifest record this
    /// module emits and gives every stage named there a row, described in the
    /// analysis's own words. What such a stage does not get is the API's
    /// richer spec — the extra record types that also count as the stage
    /// having run, and the alternative `stage` labels its failures can carry.
    ///
    /// Empty is the goal. A key listed here is a note that
    /// `seance_api::memory::STAGES` is owed a row, not permission to skip one.
    ///
    /// The eight §5.3 stages that landed together (`processor_blocks` through
    /// `truecrypt`) are listed here because `seance_api` belongs to another
    /// change; each is owed a row there.
    const STAGES_THE_API_TABLE_DOES_NOT_DESCRIBE: &[&str] = &[
        "command_lines",
        "processor_blocks",
        "big_pool",
        "virtual_map",
        "hive_cell_routines",
        "version_info",
        "mbr_scan",
        "scheduled_tasks",
        "truecrypt",
        "console_history",
    ];

    /// The keys `seance_api::memory::STAGES` has a row for, in sorted order.
    ///
    /// The API cannot be imported here — it does not depend on this crate, and
    /// must not — so the contract is written out on both sides and asserted
    /// against the same strings.
    const KEYS_THE_API_TABLE_DESCRIBES: &[&str] = &[
        "credentials",
        "cross_view",
        "device_tree",
        "dlls",
        "environment",
        "execution_history",
        "handles",
        "jobs",
        "kernel_hooks",
        "kernel_modules",
        "kernel_objects",
        "mft_scan",
        "network",
        "pattern_scan",
        "pool_scan",
        "process_tree",
        "processes",
        "recovered_files",
        "registry_hives",
        "services",
        "strings_map",
        "suspicious_threads",
        "system_calls",
        "tamper_checks",
        "tampering",
        "vad",
    ];

    #[test]
    fn the_stages_the_analysis_emits_are_the_stages_the_api_keys_coverage_on() {
        // The drift this whole table exists to stop, written down as an
        // assertion: these are the keys `seance_api::memory::STAGES` looks for.
        // The API cannot be imported here — it does not depend on this crate,
        // and must not — so the contract is asserted on both sides against the
        // same list of strings. A key changed on one side without the other
        // fails here or in `seance_api`, instead of silently reporting a stage
        // that ran as one that did not.
        //
        // A stage the API table does not yet describe is excluded here and
        // named in `STAGES_THE_API_TABLE_DOES_NOT_DESCRIBE` instead, so the
        // comparison below stays an exact statement about the API's table
        // rather than a list that has quietly grown past it.
        let mut keys: Vec<&str> = STAGES
            .iter()
            .map(|stage| stage.key)
            .filter(|key| !STAGES_THE_API_TABLE_DOES_NOT_DESCRIBE.contains(key))
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, KEYS_THE_API_TABLE_DESCRIBES);

        // Every excluded key must actually be a stage this build runs.
        // Otherwise the exclusion list becomes a place where a deleted stage
        // can hide, and the comparison above would stop catching its removal.
        for key in STAGES_THE_API_TABLE_DOES_NOT_DESCRIBE {
            assert!(
                STAGES.iter().any(|stage| stage.key == *key),
                "{key} is excused from the API comparison but is not a stage this build runs"
            );
            // And an exclusion must not outlive the debt it records. Once the
            // API is given a row for the stage — which is when the key above
            // is added to `KEYS_THE_API_TABLE_DESCRIBES` — a stale entry here
            // would go on excusing a stage the comparison is meant to cover,
            // and the drift guard would quietly stop guarding it.
            assert!(
                !KEYS_THE_API_TABLE_DESCRIBES.contains(key),
                "{key} is excused from the API comparison but the API table now describes it; \
                 delete it from STAGES_THE_API_TABLE_DOES_NOT_DESCRIBE"
            );
        }
    }

    #[test]
    fn the_command_line_stage_is_in_the_table_that_dispatch_reads() {
        // The failure this closes. `read_command_lines`, `CommandLineRecord`
        // and the whole `CommandLine` enum existed with rustdoc describing what
        // an examiner learns from them, and no product path called any of it:
        // `run_stages` had no command-line stage, so an examiner asking what a
        // process was started with got nothing at all — not an empty answer, no
        // answer. A stage in this table is emitted by `run_stages` and named in
        // the manifest, which is what makes the tier reachable.
        assert!(STAGES
            .iter()
            .any(|stage| stage.key == STAGE_COMMAND_LINES.key));
        assert_eq!(STAGE_COMMAND_LINES.record_type, "MemoryCommandLines");
        assert!(!STAGE_COMMAND_LINES.per_process);
    }

    #[test]
    fn the_suspicious_thread_stage_is_in_the_table_that_dispatch_reads() {
        // MEM-024. `suspicious_threads` was written and unit-tested, and no
        // product path called it: an examiner asking which threads started in
        // injected memory got no answer at all. A stage in this table is
        // emitted by `run_stages` and named in the manifest.
        assert!(STAGES
            .iter()
            .any(|stage| stage.key == STAGE_SUSPICIOUS_THREADS.key));
        assert_eq!(STAGE_SUSPICIOUS_THREADS.key, "suspicious_threads");
        assert_eq!(
            STAGE_SUSPICIOUS_THREADS.record_type,
            "MemorySuspiciousThreads"
        );
        assert!(!STAGE_SUSPICIOUS_THREADS.per_process);
    }

    #[test]
    fn a_failed_process_walk_names_the_suspicious_thread_stage_as_skipped() {
        // Without its name on the skipped record, a capture whose process list
        // could not be walked shows this stage as simply absent -- which the
        // Coverage view renders as "did not run" with no reason.
        let record = skipped_record(
            &image_record(),
            &crate::handles::test_support::win10_profile(),
            STAGES_NEEDING_THE_PROCESS_LIST,
            "the list could not be walked",
        );
        let stages = record.metadata["stages"].as_array().expect("an array");
        assert!(stages.contains(&json!("suspicious_threads")), "{stages:?}");
    }

    fn survey_over(
        list: &process::ProcessList,
        stop: hollow::ScanStop,
    ) -> psxview::SuspiciousThreadsSurvey {
        psxview::SuspiciousThreadsSurvey {
            processes: Vec::new(),
            out_of_scope: Vec::new(),
            out_of_scope_total: 1,
            skipped: Vec::new(),
            skipped_total: 0,
            stop,
            protections_available: true,
            inventory: list.inventory(),
        }
    }

    #[test]
    fn the_suspicious_thread_record_carries_the_surveys_completeness() {
        let profile = crate::handles::test_support::win10_profile();
        let whole = list_stopping(seance_memory::object::ListStop::Wrapped);
        let record = suspicious_threads_record(
            &image_record(),
            &profile,
            &survey_over(&whole, hollow::ScanStop::Exhausted),
        );
        assert_eq!(
            record.metadata["record_type"],
            json!("MemorySuspiciousThreads")
        );
        assert_eq!(record.metadata["stage"], json!("suspicious_threads"));
        assert_eq!(record.metadata["content_complete"], json!(true));

        let capped = suspicious_threads_record(
            &image_record(),
            &profile,
            &survey_over(&whole, hollow::ScanStop::CapReached { cap: 1 }),
        );
        assert_eq!(
            capped.metadata["content_complete"],
            json!(false),
            "a survey that stopped at its cap is not a total"
        );

        let short = list_stopping(seance_memory::object::ListStop::CapReached { cap: 1 });
        let floor = suspicious_threads_record(
            &image_record(),
            &profile,
            &survey_over(&short, hollow::ScanStop::Exhausted),
        );
        assert_eq!(floor.metadata["content_complete"], json!(false));
        assert_eq!(floor.metadata["process_inventory_incomplete"], json!(true));
    }

    #[test]
    fn a_per_process_stage_is_keyed_the_way_the_pid_endpoint_searches() {
        // The DLL stage is served per PID, so its records must be per process
        // and its key must be the one the route uses. When it was image-wide
        // under `process_modules`, the endpoint reported the stage as having
        // run and then 404'd every PID in it.
        assert!(STAGE_DLLS.per_process);
        assert_eq!(STAGE_DLLS.key, "dlls");
        assert_eq!(STAGE_DLLS.record_type, "MemoryProcessModules");
        for stage in [STAGE_VAD, STAGE_HANDLES] {
            assert!(stage.per_process, "{}", stage.key);
        }
    }

    /// One process on a list, so the only thing that varies below is whether
    /// the list that produced it was walked to the end.
    fn one_process() -> process::ProcessRecord {
        process::ProcessRecord {
            address: 0x8000,
            direction: process::WalkDirection::Forward,
            pid: process::Field::Known(712),
            ppid: process::Field::Known(4),
            image_file_name: process::Field::Known("svchost.exe".to_string()),
            image_name_well_formed: true,
            threads: process::Field::NotApplicable,
            handles: process::Field::NotApplicable,
            session_id: process::Field::NotApplicable,
            wow64: process::Field::NotApplicable,
            create_time: process::ProcessTime::NotRecorded,
            exit_time: process::ProcessTime::NotRecorded,
            peb: process::Field::NotApplicable,
            notes: Vec::new(),
        }
    }

    fn list_stopping(stop: seance_memory::object::ListStop) -> process::ProcessList {
        process::ProcessList {
            head: 0x900,
            links_offset: 24,
            processes: vec![one_process()],
            forward_stop: stop,
            backward_stop: None,
        }
    }

    fn image_record() -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "MemoryImage"}),
        )
    }

    #[test]
    fn a_per_process_record_taken_from_a_short_list_does_not_claim_completeness() {
        // The join every per-process stage rests on. The examination below is
        // flawless and identical in both halves — it is the LIST that differs.
        // Without the inventory on the record, a VAD or handle stage that read
        // every process it was handed stamps `content_complete: true` over a
        // walk that never reached the process doing the hiding, and an examiner
        // reads "nothing unusual mapped on this machine" from a stage that
        // never saw it.
        let profile = crate::handles::test_support::win10_profile();
        let parent = image_record();
        let examined = |_: &process::ProcessRecord| -> Result<(serde_json::Value, bool), String> {
            Ok((json!({"regions": []}), true))
        };

        let whole = per_process_records(
            &profile,
            &list_stopping(seance_memory::object::ListStop::Wrapped),
            &parent,
            &STAGE_VAD,
            examined,
        );
        assert_eq!(whole.len(), 1);
        let body = &whole[0].metadata;
        assert_eq!(body["content_complete"], json!(true));
        assert_eq!(body["process_inventory"]["complete"], json!(true));
        assert_eq!(body["process_inventory"]["count_is_floor"], json!(false));
        assert_eq!(body["pid"], json!(712));

        let capped = per_process_records(
            &profile,
            &list_stopping(seance_memory::object::ListStop::CapReached { cap: 1 }),
            &parent,
            &STAGE_VAD,
            examined,
        );
        let body = &capped[0].metadata;
        assert_eq!(
            body["content_complete"],
            json!(false),
            "a flawless examination over a short list is not a total"
        );
        assert_eq!(body["content_incomplete"], json!(true));
        assert_eq!(body["process_inventory_incomplete"], json!(true));
        assert_eq!(body["process_inventory"]["count_is_floor"], json!(true));
        // And the standard reason key names the list, not a fault in this
        // stage: an examiner sent looking for a broken VAD walk would find
        // nothing wrong with it.
        let reason = body["content_incomplete_reason"]
            .as_str()
            .expect("a reason is stated");
        assert!(
            reason.contains("active process list"),
            "the reason must name the truncated list: {reason}"
        );
    }

    #[test]
    fn a_process_that_could_not_be_examined_still_carries_its_list_inventory() {
        // The failure path. "This process could not be read" and "the list
        // never reached the others" are different holes, and a record that
        // stated only the first would let an examiner conclude the rest of the
        // machine was covered.
        let profile = crate::handles::test_support::win10_profile();
        let parent = image_record();
        let records = per_process_records(
            &profile,
            &list_stopping(seance_memory::object::ListStop::CapReached { cap: 1 }),
            &parent,
            &STAGE_HANDLES,
            |_| Err("the handle table pointer could not be read".to_string()),
        );

        let body = &records[0].metadata;
        assert_eq!(body["type"], json!("MemoryStageFailure"));
        assert_eq!(body["stage"], json!("handles"));
        assert_eq!(body["pid"], json!(712));
        assert_eq!(body["process_inventory_incomplete"], json!(true));
        assert_eq!(body["content_complete"], json!(false));
    }

    #[test]
    fn resolved_symbol_dirs_only_offers_directories_that_exist() {
        // Handing a non-existent path to the ISF search would make "symbols not
        // found" ambiguous between "not installed" and "looked in the wrong
        // place". Only real directories are reported as searched.
        let dirs = WindowsMemoryAnalysis::new().resolved_symbol_dirs();
        assert!(dirs.iter().all(|d| d.is_dir()), "{dirs:?}");
    }
}

#[cfg(test)]
mod tcpip_hint_tests {
    use super::*;
    use crate::automagic::pe::test_support::PeBuilder;
    use crate::modules::{KernelModules, LoadedModule, ModulesError, NameField};
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::layer::MemoryLayer;
    use seance_memory::object::ListStop;
    use seance_memory::PhysicalLayer;

    fn layer_of(bytes: Vec<u8>) -> Arc<dyn MemoryLayer> {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        Arc::new(PhysicalLayer::raw(source).expect("non-empty"))
    }

    fn empty_layer() -> Arc<dyn MemoryLayer> {
        layer_of(vec![0u8; 4096])
    }

    fn module(name: Option<&str>, base: Option<u64>) -> LoadedModule {
        LoadedModule {
            entry: 0xffff_8000_0000_1000,
            base,
            size_of_image: Some(0x1000),
            full_path: NameField::Empty,
            base_name: match name {
                Some(n) => NameField::Name(n.to_string()),
                None => NameField::Unavailable("not read".into()),
            },
            load_order: 0,
            notes: vec![],
        }
    }

    fn listing(modules: Vec<LoadedModule>) -> KernelModules {
        KernelModules {
            head: 0,
            entry_type: "_KLDR_DATA_TABLE_ENTRY".into(),
            modules,
            stop: ListStop::Wrapped,
            notes: vec![],
            notes_total: 0,
        }
    }

    /// HUNT-058. `_TCP_ENDPOINT` lives in tcpip.sys's symbols, and the stage
    /// refuses — correctly — to guess its layout. The refusal was honest and
    /// unactionable: the examiner was told they were blocked and not on what,
    /// so the one command that would unblock them could not be formed. The
    /// kernel path has always named its requirement exactly; this one now does
    /// too, from tcpip.sys's own CodeView record.
    #[test]
    fn the_refusal_names_the_pack_to_fetch() {
        let image = PeBuilder {
            pdb_name: "tcpip.pdb",
            age: 3,
            ..PeBuilder::default()
        }
        .build();
        let layer = layer_of(image);
        let mods = Ok(listing(vec![module(Some("tcpip.sys"), Some(0))]));

        let hint = tcpip_symbol_hint(&*layer, &mods);
        assert!(hint.contains("tcpip.pdb"), "{hint}");
        assert!(hint.contains("age 3"), "{hint}");
        // The command has to be formable from the sentence alone.
        assert!(hint.contains("seance fetch-symbols --guid"), "{hint}");
        assert!(hint.contains("--age 3"), "{hint}");
        assert!(hint.contains("SEANCE_MEM_TCPIP_ISF"), "{hint}");
    }

    /// Each way the identity cannot be established is STATED. A missing
    /// sentence reads as "there was nothing to name", which is a different
    /// fact from "we could not name it".
    #[test]
    fn an_identity_that_cannot_be_established_is_said_so() {
        let layer = empty_layer();

        let walk_failed: Result<KernelModules, ModulesError> =
            Err(ModulesError::unsupported("no PsLoadedModuleList"));
        let hint = tcpip_symbol_hint(&*layer, &walk_failed);
        assert!(hint.contains("could not be walked"), "{hint}");
        assert!(hint.contains("cannot be named here"), "{hint}");

        // Walked, but tcpip.sys is not in it.
        let without = Ok(listing(vec![module(Some("ntfs.sys"), Some(0x1000))]));
        let hint = tcpip_symbol_hint(&*layer, &without);
        assert!(hint.contains("no module named tcpip.sys"), "{hint}");
        assert!(hint.contains("1 module(s) were walked"), "{hint}");

        // Present, but the entry's DllBase was never acquired.
        let baseless = Ok(listing(vec![module(Some("tcpip.sys"), None)]));
        let hint = tcpip_symbol_hint(&*layer, &baseless);
        assert!(hint.contains("DllBase could not be read"), "{hint}");

        // Present with a base, but nothing readable as a PE there.
        let unreadable = Ok(listing(vec![module(Some("tcpip.sys"), Some(0))]));
        let hint = tcpip_symbol_hint(&*layer, &unreadable);
        assert!(hint.contains("CodeView"), "{hint}");
        assert!(hint.contains("cannot be named here"), "{hint}");
    }
}
