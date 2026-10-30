//! HTTP surface for memory analysis.
//!
//! Everything the memory analysis emits is a `ParsedRecord`, so the generic
//! `/cases/:id/records?type=` endpoint can already hand a client the raw rows.
//! What it cannot do is answer the three questions an examiner actually asks of
//! a memory image:
//!
//! 1. **What is this image, and how sure are we?** The directory table base,
//!    the kernel base and the symbol table each carry an evidence grade. A
//!    process list resting on a scanned-but-unvalidated DTB is a different
//!    exhibit from one resting on a confirmed DTB, and the difference has to be
//!    on the screen, not buried in a metadata blob.
//! 2. **Which stages ran?** A stage that could not run and a stage that ran and
//!    found nothing are opposite findings. Both look like an empty array in the
//!    generic endpoint. Here they never do.
//! 3. **What does one view say that another does not?** Cross-view concealment
//!    is a join across listings; doing it client-side means fetching every row.
//!
//! ## The rule every response in this module obeys
//!
//! No endpoint returns `200` with an empty list when the truth is "this stage
//! did not run". Every response carries `stage_ran`, a `status` of `complete` /
//! `incomplete` / `failed` / `did_not_run`, and `count_is_floor`. A stage that
//! stopped early returns the rows it did produce *and* says the count is a
//! floor. An examiner who quotes a count from this API can tell from the same
//! payload whether the count is a total or a lower bound.
//!
//! A wrong answer here is not a cosmetic bug: it is a report that says "no
//! hidden processes" when the truth is "the pool scan never ran".
//!
//! ## Validation is reported separately from completeness
//!
//! "Did the stage finish?" and "has the code that ran it ever been tested
//! against a real capture?" are different questions, and a stage can answer yes
//! to the first and no to the second. The macOS tier is exactly that case: its
//! structure walks come from Apple's kernel symbol definitions and no capture of
//! a real Mac has ever tested them, so it stamps every record it emits with
//! `validated_against_real_capture: false` and a sentence saying why. Coverage
//! reads that marker back and states it on the row —
//! `analysis_declares_itself_unvalidated`, `unvalidated_records` and
//! `validation_notice` — because an unvalidated process list is
//! indistinguishable from a validated one by inspection, and that difference is
//! the whole question in a report. `false` there means no record said it was
//! unvalidated; it is never an assertion that a tier *was* validated.
//!
//! ## What produces the records
//!
//! The container stage emits one `MemoryImage` record per decoded image. Every
//! analysis record hangs off that image record as its parent, so `parent_id` is
//! the image id throughout, and the `?image=` query parameter scopes any
//! endpoint here to a single image by filtering on that subtree.
//!
//! ## One capture per answer
//!
//! A case can hold several memory captures, and every listing here describes
//! one machine at one instant: process ids, handle tables and the cross-view
//! concealment table are all per-capture. A listing that spanned two captures
//! would present two machines as one, so an unscoped request against a case
//! holding more than one image is **refused** rather than merged. See
//! [`resolve_scope`]. Only `/images` is case-wide, because that is the endpoint
//! that tells a client which ids exist.
//!
//! ## Where the stage list comes from
//!
//! [`STAGES`] is this crate's own table of the stages it knows how to describe.
//! It is deliberately not the authority on which stages *exist*: the analysis
//! emits a `MemoryStageManifest` record naming every stage the build it ran can
//! run, and [`get_memory_coverage`] lists any stage from that manifest which
//! this table has never heard of rather than dropping it. A stage added to the
//! analysis therefore appears in coverage on the day it is added, and the worst
//! case is a row without the sentence describing it — never a stage that ran
//! and reports nothing.

use axum::{
    extract::{Path, Query as AxumQuery, State},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tracing::error;
use uuid::Uuid;

use seance_core::artifact::Artifact;
use seance_core::db::DatabaseConnection;

use crate::{ApiError, AppState};

/// Record type the container stage emits for a decoded memory image.
///
/// Duplicated as a string rather than imported from `seance_memory` because the
/// API crate deliberately does not depend on the memory crates: the wire
/// contract here is the record type name in the database, not a Rust type.
pub const MEMORY_IMAGE_RECORD: &str = "MemoryImage";

/// Record type carrying the discovered image profile (or the reason discovery
/// failed).
pub const MEMORY_PROFILE_RECORD: &str = "MemoryProfile";

/// Record type carrying "this stage did not run, and here is why".
pub const MEMORY_STAGE_FAILURE_RECORD: &str = "MemoryStageFailure";

/// Record type carrying one credential **value** recovered from memory.
///
/// One record per credential, carrying a `value` a client can ask to have
/// revealed through [`reveal_memory_credential`], which is the audited path such
/// a value travels by.
///
/// **`seance_plugin_memory_windows` emits these.** Its credentials stage
/// recovers the boot key from the `SYSTEM` hive resident in the image and
/// decrypts the local-account NT hashes out of `SAM`, one `MemoryCredential`
/// record per account, plus one per decrypted LSA secret. That is `MEM-008`,
/// verified against a corpus whose `analyst` password is known: the recovered
/// hash equals `MD4(UTF-16LE(password))`.
///
/// This comment used to say the opposite — "Nothing in the tree emits one today
/// … the Windows credentials stage … does not decrypt them" — and had done since
/// before `MEM-008` landed. It was read as current, and the stage description
/// below carried the same claim onto the coverage screen (`DOC-005`).
pub const MEMORY_CREDENTIAL_RECORD: &str = "MemoryCredential";

/// Record type carrying the credential **inventory**: which stores are
/// resident, which local accounts exist, what the LSA secrets are called, and
/// how many cached domain logons there are.
///
/// A different claim from [`MEMORY_CREDENTIAL_RECORD`] and deliberately kept
/// apart from it. "The SAM was read and these accounts exist" and "this
/// account's hash was recovered" are different findings, and a credentials
/// screen that showed the first as the second would report a recovery nobody
/// made.
pub const MEMORY_CREDENTIAL_INVENTORY_RECORD: &str = "MemoryCredentials";

/// Record type naming every stage the analysis that ran can run.
///
/// The analysis publishes its own stage table with each image. Coverage reads
/// it so a stage this crate's [`STAGES`] does not describe is still listed:
/// being unknown to the API is not evidence that a stage did not run.
pub const MEMORY_STAGE_MANIFEST_RECORD: &str = "MemoryStageManifest";

// Fetch bounds. Evidence-derived row counts are attacker-influenced (a crafted
// image can produce a great many records), so every fetch is bounded and every
// bound that bites is reported on the response rather than silently applied.

/// Most records one listing endpoint will return in a single response.
const LIST_FETCH_CAP: usize = 200;

/// Most per-process records scanned while looking for one PID.
const PER_PROCESS_SCAN_CAP: usize = 5_000;

/// Most stage-failure records fetched for a coverage or stage view.
const FAILURE_FETCH_CAP: usize = 2_000;

/// Most rows of one record type examined when tallying coverage. Counts stay
/// exact regardless (they come from the database), but completeness can only be
/// judged on rows actually examined, and the coverage response says so.
const COVERAGE_TALLY_CAP: usize = 500;

/// One analysis stage: the record type it emits when it works, and the `stage`
/// labels its failure records carry when it does not.
///
/// The failure labels are a list because a stage can be reported failed under
/// more than one name: the process tree is skipped when the *process list* walk
/// fails, so a tree failure surfaces under `processes`.
#[derive(Debug, Clone, Copy)]
pub struct StageSpec {
    /// Stable key used in the coverage response and in route names. Must match
    /// the `stage` field the analysis stamps on the records it emits.
    pub key: &'static str,
    /// `type` / `record_type` of the records this stage emits on success.
    pub record_type: &'static str,
    /// Further record types that belong to this stage.
    ///
    /// A stage can produce more than one shape of record over its life — the
    /// credentials stage inventories the stores today and may recover values
    /// tomorrow — and both shapes are that stage running. Counting only the
    /// primary type would report a stage that ran under the other shape as
    /// having done nothing.
    pub also_record_types: &'static [&'static str],
    /// `stage` values on failure records that mean this stage did not run.
    ///
    /// A list because a stage can be reported failed under more than one name,
    /// and because a label the analysis has since stopped using still names
    /// records already in a case database.
    pub failure_stages: &'static [&'static str],
    /// Whether the stage emits one record per process (and so tags them with a
    /// PID) rather than one record for the image.
    pub per_process: bool,
    /// What an examiner learns from this stage, in one sentence, for the UI.
    pub describes: &'static str,
}

/// Every stage the memory analysis can run, in the order an examiner reads them.
///
/// The coverage endpoint walks this table, so a stage missing from it would be
/// invisible to the examiner even when it failed — which is exactly the failure
/// mode this whole module exists to prevent. Adding a stage to the analysis
/// means adding a row here.
pub const STAGES: &[StageSpec] = &[
    StageSpec {
        key: "processes",
        record_type: "MemoryProcessList",
        // The Linux tier walks the same concept through `init_task`, and emits
        // its own record type. Without it here the coverage table reported
        // "processes: did not run" for a Linux capture whose task list held 133
        // entries -- the stage had run, in full, and the examiner was told the
        // opposite. The macOS tier walks `allproc` and is here for exactly the
        // same reason.
        //
        // macOS's *second* listing, the Mach task queue (`macos_task_processes`
        // / `MemoryMacTaskList`), has no row of its own in this table on
        // purpose: it is neither this stage nor `pool_scan`, which is a scan of
        // pool memory rather than a second linked list, and filing it under
        // either would misdescribe it. It reaches coverage through the stage
        // manifest the analysis publishes, with the analysis's own sentence.
        also_record_types: &["LinuxMemoryTaskList", "MemoryMacProcessList"],
        failure_stages: &["processes", "linux_processes", "macos_processes"],
        per_process: false,
        describes: "The active process list, walked from the kernel's process links.",
    },
    StageSpec {
        key: "process_tree",
        record_type: "MemoryProcessTree",
        also_record_types: &[],
        failure_stages: &["process_tree", "processes"],
        per_process: false,
        describes: "Parent/child structure derived from the process list.",
    },
    StageSpec {
        key: "pool_scan",
        record_type: "MemoryPoolScan",
        also_record_types: &[],
        failure_stages: &["pool_scan"],
        per_process: false,
        describes: "Process objects found by scanning the kernel pool, including any the \
                    active list no longer points at.",
    },
    StageSpec {
        key: "cross_view",
        record_type: "MemoryCrossView",
        // macOS compares `allproc` against the Mach task queue and emits its own
        // record type for the difference. It is the same finding — which listing
        // saw a process and which did not — so it belongs on this row rather
        // than leaving the concealment table reading "did not run" on a capture
        // where two listings were in fact compared.
        also_record_types: &["MemoryMacProcessCrossView"],
        failure_stages: &["cross_view", "macos_process_cross_view"],
        per_process: false,
        describes: "Which listing saw each process and which did not — the concealment table.",
    },
    StageSpec {
        key: "kernel_modules",
        record_type: "MemoryKernelModules",
        also_record_types: &["LinuxMemoryKernelModules", "MemoryMacKernelExtensions"],
        failure_stages: &[
            "kernel_modules",
            "linux_kernel_modules",
            "macos_kernel_extensions",
        ],
        per_process: false,
        describes: "Loaded kernel drivers, on Linux the loaded kernel modules, and on macOS the \
                    loaded kernel extensions.",
    },
    StageSpec {
        key: "network",
        record_type: "MemoryNetwork",
        also_record_types: &[],
        failure_stages: &["network"],
        per_process: false,
        describes: "Network endpoints and connections recovered from memory.",
    },
    StageSpec {
        key: "services",
        record_type: "MemoryServices",
        also_record_types: &[],
        failure_stages: &["services"],
        per_process: false,
        describes: "Windows services, one listing per services.exe in the image.",
    },
    StageSpec {
        key: "execution_history",
        record_type: "MemoryExecutionHistory",
        also_record_types: &["LinuxMemoryBashHistory"],
        failure_stages: &["execution_history", "linux_bash_history"],
        per_process: false,
        describes: "Execution history held in RAM: on Windows the Amcache hive and the \
                    AppCompatCache (Shimcache), on Linux the shell history still resident in \
                    each process.",
    },
    StageSpec {
        key: "mft_scan",
        record_type: "MemoryMftRecords",
        also_record_types: &[],
        failure_stages: &["mft_scan"],
        per_process: false,
        describes: "Master File Table records recovered from pool memory, which can predate \
                    what is on disk.",
    },
    StageSpec {
        key: "kernel_hooks",
        record_type: "MemoryKernelHooks",
        also_record_types: &[],
        failure_stages: &["kernel_hooks"],
        per_process: false,
        describes: "Kernel hooking and persistence: notification callbacks, the system service \
                    descriptor table and driver IRP tables.",
    },
    StageSpec {
        key: "kernel_objects",
        record_type: "MemoryKernelObjects",
        also_record_types: &[],
        failure_stages: &["kernel_objects"],
        per_process: false,
        describes: "Executive objects still in pool memory: open files, mutants and symbolic \
                    links.",
    },
    StageSpec {
        key: "environment",
        record_type: "MemoryEnvironment",
        also_record_types: &["LinuxMemoryEnvironment"],
        failure_stages: &["environment", "linux_environment"],
        per_process: false,
        describes: "Each process's environment, and on Windows the terminal-services \
                    sessions, window stations and desktops alongside it.",
    },
    StageSpec {
        key: "credentials",
        // The inventory describes the stores; a MemoryCredential record carries
        // one decrypted value. Both are this stage having run, and the inventory
        // states how many values came out of it (`credentials_recovered`), so a
        // reader is not left to infer it from the record count.
        record_type: MEMORY_CREDENTIAL_INVENTORY_RECORD,
        also_record_types: &[MEMORY_CREDENTIAL_RECORD],
        failure_stages: &["credentials"],
        per_process: false,
        // DOC-005. This sentence ended "The material is not decrypted, so no
        // password, hash or secret value is recovered" for as long as that was
        // true and for a while after it stopped being: MEM-008 added boot-key
        // recovery and SAM decryption, and this text was not brought with it. It
        // is served to the memory coverage screen, so an examiner reading a case
        // that held decrypted NT hashes was told none had been recovered — a
        // false absence on a court-facing surface, and in the direction that
        // loses evidence rather than inventing it.
        describes: "The credential stores held in RAM — SAM, LSA secrets and cached domain \
                    logons — located and inventoried: which stores are resident, which local \
                    accounts exist and what the secrets are called. Where the SYSTEM and SAM \
                    hives are both resident, the boot key is recovered and the local-account NT \
                    hashes are decrypted out of them, one record per account; LSA secrets and \
                    cached domain logons are decrypted the same way. Each recovered value is \
                    released only through the audited reveal, which records who asked. The \
                    inventory states how many values were recovered and whether the boot key \
                    was, so a case where nothing decrypted says so rather than looking like one \
                    that was never asked.",
    },
    StageSpec {
        key: "registry_hives",
        record_type: "MemoryRegistryHives",
        also_record_types: &[],
        failure_stages: &["registry_hives"],
        per_process: false,
        describes: "Registry hives mapped into kernel memory, including volatile hives that \
                    exist nowhere on disk.",
    },
    StageSpec {
        key: "vad",
        record_type: "MemoryProcessVads",
        also_record_types: &[],
        failure_stages: &["vad"],
        per_process: true,
        describes: "Each process's virtual address descriptors.",
    },
    StageSpec {
        key: "dlls",
        record_type: "MemoryProcessModules",
        also_record_types: &[],
        // `process_modules` is the label an earlier build of the analysis
        // stamped on this stage's failures. Records carrying it are already in
        // case databases, and dropping the label would leave those stages
        // reported as never run with no reason attached.
        failure_stages: &["dlls", "process_modules"],
        per_process: true,
        describes: "Each process's loaded user-mode modules, cross-referenced against its \
                    mapped memory to find modules unlinked from the loader's lists.",
    },
    StageSpec {
        key: "handles",
        record_type: "MemoryProcessHandles",
        also_record_types: &[],
        failure_stages: &["handles"],
        per_process: true,
        describes: "Each process's handle table.",
    },
    StageSpec {
        key: "system_calls",
        record_type: "MemorySystemCalls",
        also_record_types: &[],
        failure_stages: &["system_calls"],
        per_process: false,
        describes: "System-call stubs that do not enter the kernel the way this build's ntdll \
                    does — the shape of a user-mode hook or a direct-syscall loader.",
    },
    StageSpec {
        key: "recovered_files",
        record_type: "MemoryRecoveredFiles",
        also_record_types: &[],
        failure_stages: &["recovered_files"],
        per_process: false,
        describes: "Files the cache manager still held in RAM, reconstructed and handed to the \
                    ordinary file parsers.",
    },
    StageSpec {
        key: "tampering",
        record_type: "MemoryProcessTampering",
        also_record_types: &[],
        failure_stages: &["tampering"],
        per_process: false,
        describes: "Process-image tampering signals: hollowing, ghosting and unbacked \
                    executable memory.",
    },
    StageSpec {
        key: "device_tree",
        record_type: "MemoryDriverDevices",
        also_record_types: &[],
        failure_stages: &["device_tree"],
        per_process: false,
        describes: "The device tree: which driver owns which device, what is attached above \
                    each, and which of those attachments are by a driver other than the one \
                    owning the device beneath -- which is what a filter driver is. An \
                    attachment is not by itself a finding: a volume encryptor, an antivirus and \
                    a USB class filter all attach.",
    },
    StageSpec {
        key: "jobs",
        record_type: "MemoryJobs",
        also_record_types: &[],
        failure_stages: &["jobs"],
        per_process: false,
        describes: "Job objects and the processes confined to them -- how a sandbox, a packaged \
                    app and a container show up in memory. One record per DISTINCT job object, \
                    naming every process that pointed at it, with the kernel's own member list \
                    beside its process counters: a job whose counter exceeds its list is either \
                    mid-teardown or has had a member unlinked, and both numbers are reported \
                    rather than one preferred.",
    },
    StageSpec {
        key: "pattern_scan",
        record_type: "MemoryPatternScan",
        also_record_types: &[],
        failure_stages: &["pattern_scan"],
        per_process: false,
        describes: "Examiner-supplied YARA rules and patterns over each process's own address \
                    space and the kernel's, with every match attributed to the allocation that \
                    held it -- private executable memory and the read-only section of a mapped \
                    system DLL are different findings for the same bytes. Séance ships NO rules: \
                    this stage searches for nothing of its own, and reports that it did not run \
                    when no rule set or pattern was named. A YARA rule's condition is evaluated \
                    over one chunk of the address space at a time rather than over a file, which \
                    the record states on itself.",
    },
    StageSpec {
        key: "strings_map",
        record_type: "MemoryStringsMap",
        also_record_types: &[],
        failure_stages: &["strings_map"],
        per_process: false,
        describes: "`strings` over memory, which is the reverse of every other stage's \
                    question: the examiner runs `strings -t d` over the raw image themselves and \
                    names the file, and each PHYSICAL offset in it is attributed to every \
                    address space whose page tables reach that frame, with the virtual address \
                    it has in each. Séance runs no `strings` of its own and searches for nothing: \
                    with no file named the stage reports that it DID NOT RUN, which is not a \
                    statement about what the image holds. A frame reached through the kernel's \
                    shared half is ONE owner naming the spaces that reach it, not one finding \
                    per process. An offset no walked address space maps is never called free: \
                    the PFN database is not read, a frame on the free or standby list still \
                    holds the last bytes written to it, and where any address space could not be \
                    walked whole the row says nothing at all rather than reporting no owner.",
    },
    StageSpec {
        key: "suspicious_threads",
        record_type: "MemorySuspiciousThreads",
        also_record_types: &[],
        failure_stages: &["suspicious_threads"],
        per_process: false,
        describes: "Where each live user thread started running: its StartAddress and \
                    Win32StartAddress placed in the VAD that covers them, reported when that \
                    range is backed by no file, was not created PAGE_EXECUTE_WRITECOPY, or maps \
                    an application executable that is not the process's own. A range whose \
                    protection or file could not be read is a GAP, not a finding; a start in no \
                    range is counted and not attributed; a process with fewer than five ranges \
                    is not judged. A kernel start on a thread whose _KTHREAD.SystemThread is set \
                    is counted apart (whether it lies in a loaded module is the tamper_checks \
                    orphan-thread group's question); on any other thread it is judged by \
                    neither stage, and the process is incomplete. Out of scope, with the \
                    reason, are processes with a null Peb (System, Registry, Memory \
                    Compression -- and a WSL1 pico process, whose user threads are then not \
                    judged) and processes that had already exited. Private executable memory is also where a JIT runs, so a \
                    private-region start is a place to look, not a verdict.",
    },
    StageSpec {
        key: "tamper_checks",
        record_type: "MemoryTamperChecks",
        also_record_types: &[],
        failure_stages: &["tamper_checks"],
        per_process: false,
        describes: "Kernel-side tamper checks: unloaded drivers, per-processor timers, threads \
                    with debug registers, suspended threads, orphan kernel threads, a patched \
                    ETW write path and a skeleton key. NOT EVERY GROUP'S DETECTION IS WRITTEN: \
                    the record's own `groups_implemented` names the ones that are, and every \
                    other group reports that it did not run with its own reason -- so that a \
                    group landing later cannot have the earlier silence read as evidence the \
                    kernel was clean. Named rather than counted here deliberately: a number in \
                    this sentence would be a number somebody has to remember to change.",
    },
];

/// Look a stage up by key. Returns `None` for a key not in [`STAGES`].
fn stage(key: &str) -> Option<&'static StageSpec> {
    STAGES.iter().find(|s| s.key == key)
}

/// The `?image=<uuid>` scope shared by every listing endpoint.
///
/// Optional only for a case holding at most one memory image. A case holding
/// two is refused without it — see [`resolve_scope`] for why a merged listing
/// is not a listing at all.
#[derive(Debug, Default, Deserialize)]
pub struct MemoryScopeQuery {
    /// Artifact id of the `MemoryImage` record to restrict results to.
    pub image: Option<Uuid>,
}

// --- fetching -------------------------------------------------------------

/// Rows of one record type, with the exact database count beside them so a
/// truncated fetch can be reported as truncated rather than passed off as the
/// whole set.
struct StageRows {
    records: Vec<Artifact>,
    /// Exact number of records of this type in scope, from the database.
    total: i64,
    /// True when `total` exceeds the rows actually returned.
    truncated: bool,
}

/// Fetch one record type out of the database, bounded by `max_records`.
///
/// One database round trip, not one per page. An `?image=`-scoped fetch drags a
/// recursive walk of that image's artifact subtree behind every statement it
/// issues, so asking for the bounded set in small bites multiplied the walk by
/// the page count: the memory views page the same scope for every stage, and
/// `/memory/coverage` on a real capture stopped returning at all. The bound and
/// the rows held in memory are the same as the paged loop's — only the number
/// of walks changes.
///
/// Truncation is derived from the database's own count rather than from "did
/// the fetch come back short", so a response can never claim completeness it has
/// not established.
async fn fetch_records(
    state: &AppState,
    case_id: Uuid,
    record_type: &str,
    image_id: Option<Uuid>,
    max_records: usize,
) -> Result<StageRows, ApiError> {
    let limit = u32::try_from(max_records).unwrap_or(u32::MAX);
    let (records, total) = state
        .db
        .list_records_by_type(case_id, record_type, image_id, 1, limit)
        .await
        .map_err(|e| {
            error!("memory: failed to list {record_type} records: {e}");
            ApiError::InternalServerError(format!("Failed to load {record_type} records"))
        })?;

    let truncated = (records.len() as i64) < total;
    Ok(StageRows {
        records,
        total,
        truncated,
    })
}

/// Fetch every record type belonging to one stage, merged.
///
/// A stage whose records come in more than one shape is still one stage: the
/// counts add up and the response is truncated if any of the fetches was. A
/// caller that read only the primary type would report a stage that ran under
/// the other shape as having produced nothing.
async fn fetch_stage_records(
    state: &AppState,
    case_id: Uuid,
    spec: &StageSpec,
    image_id: Option<Uuid>,
    max_records: usize,
) -> Result<StageRows, ApiError> {
    let mut merged = fetch_records(state, case_id, spec.record_type, image_id, max_records).await?;
    for record_type in spec.also_record_types {
        let extra = fetch_records(
            state,
            case_id,
            record_type,
            image_id,
            max_records.saturating_sub(merged.records.len()),
        )
        .await?;
        merged.total = merged.total.saturating_add(extra.total);
        merged.truncated |= extra.truncated;
        merged.records.extend(extra.records);
    }
    // The per-type caps can each be satisfied while the merged set is short of
    // the merged total, and a response that did not say so would present a
    // floor as a count.
    merged.truncated |= (merged.records.len() as i64) < merged.total;
    Ok(merged)
}

/// Confirm an artifact id names a `MemoryImage` record in this case.
///
/// Cross-case ids are reported as not found rather than forbidden: telling a
/// caller "that exists, just not here" leaks the existence of another case's
/// evidence.
async fn require_memory_image(
    state: &AppState,
    case_id: Uuid,
    image_id: Uuid,
) -> Result<Artifact, ApiError> {
    let artifact = state
        .db
        .get_artifact(image_id)
        .await
        .map_err(|e| {
            error!("memory: failed to load artifact {image_id}: {e}");
            ApiError::InternalServerError("Failed to load memory image record".to_string())
        })?
        .filter(|a| a.case_id == case_id)
        .ok_or_else(|| {
            ApiError::ResourceNotFound(format!("No memory image {image_id} in this case"))
        })?;

    if metadata_type(&artifact.metadata) != Some(MEMORY_IMAGE_RECORD) {
        return Err(ApiError::InvalidRequest(format!(
            "Artifact {image_id} is not a memory image record"
        )));
    }
    Ok(artifact)
}

/// Resolve the `?image=` scope, validating it when present and **requiring it**
/// when the case holds more than one memory image.
///
/// A process list is a statement about one machine at one instant. A case can
/// hold two captures — two machines, or the same machine twice — and PIDs are
/// per-machine: PID 712 in one capture and PID 712 in another are unrelated
/// processes that happen to share a number. A response that merged both would
/// show one process list, one handle table for PID 712, one concealment table,
/// and every one of those is a claim about a machine that does not exist. The
/// cross-view stage is worst affected, because its entire value is the
/// disagreement between listings, and a merge manufactures disagreements out of
/// two machines that never disagreed about anything.
///
/// So an unscoped request against a multi-image case is refused, naming the
/// images, rather than answered with a merge. An empty result and "you have not
/// said which capture you mean" must never render the same, and a listing
/// spanning two captures is the second one dressed as the first.
///
/// A case with one image, or none, is unaffected: there is nothing to conflate.
async fn resolve_scope(
    state: &AppState,
    case_id: Uuid,
    query: &MemoryScopeQuery,
) -> Result<Option<Uuid>, ApiError> {
    match query.image {
        Some(image_id) => {
            require_memory_image(state, case_id, image_id).await?;
            Ok(Some(image_id))
        }
        None => {
            let images =
                fetch_records(state, case_id, MEMORY_IMAGE_RECORD, None, LIST_FETCH_CAP).await?;
            if images.total > 1 {
                let named = images
                    .records
                    .iter()
                    .map(|a| {
                        let name = a
                            .metadata
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("unnamed capture");
                        format!("{} ({name})", a.id)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(ApiError::InvalidRequest(format!(
                    "This case holds {} memory captures, so this listing needs an \
                     '?image=<id>' scope. Process ids are per-capture, and a response \
                     spanning two captures would present two machines as one. The captures \
                     are: {named}",
                    images.total
                )));
            }
            Ok(None)
        }
    }
}

// --- metadata readers -----------------------------------------------------

/// The `type` a record declares. Records written by the memory analysis always
/// set it; anything else is not one of ours.
fn metadata_type(metadata: &Value) -> Option<&str> {
    metadata.get("type").and_then(Value::as_str)
}

/// Completeness a record declares.
///
/// `None` means the record did not say. That is treated as "not established",
/// never as complete: a stage whose emitter forgot the flag must not be
/// reported to an examiner as having produced a total.
fn declared_complete(metadata: &Value) -> Option<bool> {
    metadata.get("content_complete").and_then(Value::as_bool)
}

/// One metadata field, or JSON null when the record did not carry it.
///
/// Null here always means "the analysis did not state this". It never means the
/// value was zero, empty or false.
fn field(metadata: &Value, key: &str) -> Value {
    metadata.get(key).cloned().unwrap_or(Value::Null)
}

/// PID a per-process record is tagged with, when the analysis could read one.
fn record_pid(metadata: &Value) -> Option<u64> {
    metadata.get("pid").and_then(Value::as_u64)
}

/// What the analysis behind a set of records says about its own validation.
///
/// # Why this crosses the wire
///
/// An analysis tier that has never been run against a real capture of its
/// operating system stamps every record it emits with
/// `validated_against_real_capture: false` and a sentence explaining it. The
/// macOS tier is one: its structure walks are derived from Apple's kernel symbol
/// definitions alone, and no Mac capture has ever tested them.
///
/// A process list produced by that code looks exactly like a process list
/// produced by code validated against a hundred images — same columns, same
/// plausible pids, same plausible names — so an examiner reading a coverage
/// table showing "processes: complete" cannot tell the difference. That
/// difference is the whole question in a report, so the marker is read back out
/// of the records and stated on the row rather than being left in a metadata
/// blob only the raw-record endpoint serves.
///
/// Nothing here ever asserts the opposite. A record that carries no marker made
/// no statement about validation, and this reports exactly that: it does not
/// promote silence into a claim that the analysis *was* validated.
#[derive(Debug, Default, Clone)]
struct ValidationClaim {
    /// How many records declared the analysis behind them has never been
    /// validated against a real capture.
    marked: usize,
    /// The analysis's own sentence, quoted rather than paraphrased.
    notice: Option<String>,
}

/// Whether a record declares that the analysis that produced it has never been
/// validated against a real capture of the operating system it read.
///
/// Only an explicit `false` counts. A record that carries no such key made no
/// statement, and this must not turn silence into either answer.
fn declares_unvalidated(metadata: &Value) -> bool {
    let stated = metadata.get("validated_against_real_capture");
    stated.and_then(Value::as_bool) == Some(false)
}

/// The examiner-facing sentence such a record carries, when it carries one.
fn validation_notice(metadata: &Value) -> Option<String> {
    let notice = metadata.get("validation_notice");
    notice.and_then(Value::as_str).map(str::to_string)
}

impl ValidationClaim {
    /// Fold one record's metadata into the claim.
    fn observe(&mut self, metadata: &Value) {
        if !declares_unvalidated(metadata) {
            return;
        }
        self.marked = self.marked.saturating_add(1);
        if self.notice.is_none() {
            self.notice = validation_notice(metadata);
        }
    }

    /// Fold in every record of a set.
    fn observe_all<'a>(&mut self, records: impl IntoIterator<Item = &'a Artifact>) {
        for record in records {
            self.observe(&record.metadata);
        }
    }

    /// Take on another claim's findings, for the case-wide summary.
    fn absorb(&mut self, other: &ValidationClaim) {
        self.marked = self.marked.saturating_add(other.marked);
        if self.notice.is_none() {
            self.notice.clone_from(&other.notice);
        }
    }

    /// Whether anything here declared itself unvalidated.
    fn declares_unvalidated(&self) -> bool {
        self.marked > 0
    }

    /// The sentence, or JSON null when no record carried one.
    fn notice_json(&self) -> Value {
        match &self.notice {
            Some(notice) => json!(notice),
            None => Value::Null,
        }
    }
}

/// One stage the analysis says it can run, as its manifest describes it.
#[derive(Debug, Clone)]
struct DeclaredStage {
    /// `type` / `record_type` of the records the stage emits on success.
    record_type: String,
    /// Whether it emits one record per process.
    per_process: bool,
    /// The analysis's own sentence about what the stage establishes.
    describes: String,
    /// What the manifest that declared this stage says about its own
    /// validation.
    ///
    /// Read from the manifest and not only from the result rows, because the
    /// manifest is emitted whether or not the analysis went on to establish
    /// anything: a tier that ran, failed discovery and produced no rows must
    /// still say that its results — had there been any — rest on code no
    /// capture has tested.
    validation: ValidationClaim,
}

/// Every stage named by the analysis's own manifest records, keyed by stage.
///
/// The manifest is how a stage this crate has never heard of still reaches the
/// examiner. A malformed or absent manifest yields an empty map, and coverage
/// then describes only the stages [`STAGES`] knows — which is what every case
/// analysed before manifests existed will produce.
fn declared_stages(records: &[Artifact]) -> std::collections::BTreeMap<String, DeclaredStage> {
    let mut out = std::collections::BTreeMap::new();
    for record in records {
        let Some(rows) = record.metadata.get("stages").and_then(Value::as_array) else {
            continue;
        };
        // The marker sits on the manifest record itself, not on its per-stage
        // rows, so it is read once and carried onto every stage that manifest
        // declares.
        let mut validation = ValidationClaim::default();
        validation.observe(&record.metadata);
        for row in rows {
            let (Some(key), Some(record_type)) = (
                row.get("stage").and_then(Value::as_str),
                row.get("record_type").and_then(Value::as_str),
            ) else {
                continue;
            };
            out.insert(
                key.to_string(),
                DeclaredStage {
                    record_type: record_type.to_string(),
                    per_process: row
                        .get("per_process")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    describes: row
                        .get("describes")
                        .and_then(Value::as_str)
                        .unwrap_or(
                            "The analysis declares this stage and did not say what it \
                             establishes.",
                        )
                        .to_string(),
                    validation: validation.clone(),
                },
            );
        }
    }
    out
}

/// Whether a stage-failure record covers `stage`.
///
/// Failure records name a single `stage`; the "these stages were skipped
/// because a prerequisite failed" record names several under `stages`. Missing
/// either form would hide a stage that did not run.
fn failure_covers(metadata: &Value, stage: &str) -> bool {
    if metadata.get("stage").and_then(Value::as_str) == Some(stage) {
        return true;
    }
    metadata
        .get("stages")
        .and_then(Value::as_array)
        .is_some_and(|stages| stages.iter().any(|s| s.as_str() == Some(stage)))
}

/// Whether a failure record covers any of a stage's failure labels.
fn failure_covers_spec(metadata: &Value, spec: &StageSpec) -> bool {
    spec.failure_stages
        .iter()
        .any(|stage| failure_covers(metadata, stage))
}

/// Render one stage-failure record for the wire.
fn failure_json(artifact: &Artifact) -> Value {
    let m = &artifact.metadata;
    json!({
        "id": artifact.id,
        "image_id": artifact.parent_id,
        "name": field(m, "name"),
        "stage": field(m, "stage"),
        "stages": field(m, "stages"),
        "failure": field(m, "failure"),
        "pid": field(m, "pid"),
        "process_name": field(m, "process_name"),
        "profile_evidence": field(m, "profile_evidence"),
    })
}

/// Render one result record for the wire, keeping the analysis metadata intact
/// under `data` so nothing is lost in translation.
fn record_json(artifact: &Artifact) -> Value {
    json!({
        "id": artifact.id,
        "image_id": artifact.parent_id,
        "data": artifact.metadata,
    })
}

// --- stage envelopes ------------------------------------------------------

/// What one stage's response says about itself.
///
/// `DidNotRun` is the value this whole module exists to make expressible: it is
/// not "found nothing", and a UI must not render it as an empty table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageStatus {
    /// Ran, and every record it produced declared itself complete.
    Complete,
    /// Ran, but stopped early, partly failed, or did not declare completeness.
    Incomplete,
    /// Produced no results at all; failure records say why.
    Failed,
    /// Neither a result nor a failure was recorded. Nothing ran.
    DidNotRun,
}

impl StageStatus {
    /// Stable identifier for the wire and for UI switch statements.
    fn as_str(self) -> &'static str {
        match self {
            StageStatus::Complete => "complete",
            StageStatus::Incomplete => "incomplete",
            StageStatus::Failed => "failed",
            StageStatus::DidNotRun => "did_not_run",
        }
    }

    /// Sentence an examiner can read without knowing the vocabulary. Shown
    /// verbatim, so it must never overstate what was established.
    fn meaning(self) -> &'static str {
        match self {
            StageStatus::Complete => {
                "The stage ran and every record it produced reported itself complete."
            }
            StageStatus::Incomplete => {
                "The stage ran but stopped early, partly failed, or did not state its \
                 completeness. Treat every count here as a floor, not a total."
            }
            StageStatus::Failed => {
                "The stage produced no results. The entries under 'failures' are the reasons \
                 it could not run, not findings about the evidence."
            }
            StageStatus::DidNotRun => {
                "No result and no failure was recorded for this stage. It did not run. This is \
                 not a finding that there was nothing to find."
            }
        }
    }
}

/// Counts derived from a set of result records.
struct RowTally {
    /// Rows that declared `content_complete: false`.
    incomplete: usize,
    /// Rows that declared no completeness at all.
    ungraded: usize,
}

/// Tally completeness declarations across result records.
fn tally_rows(records: &[Artifact]) -> RowTally {
    let mut tally = RowTally {
        incomplete: 0,
        ungraded: 0,
    };
    for record in records {
        match declared_complete(&record.metadata) {
            Some(true) => {}
            Some(false) => tally.incomplete = tally.incomplete.saturating_add(1),
            None => tally.ungraded = tally.ungraded.saturating_add(1),
        }
    }
    tally
}

/// Decide a stage's status from its counts.
///
/// `examined_all_rows` is false when the completeness of some rows was not
/// looked at (the coverage tally caps rows); in that case the stage can never
/// be called complete, because completeness was not established for every row.
fn stage_status(
    total: i64,
    tally: &RowTally,
    failures: usize,
    truncated: bool,
    examined_all_rows: bool,
) -> StageStatus {
    if total <= 0 {
        return if failures == 0 {
            StageStatus::DidNotRun
        } else {
            StageStatus::Failed
        };
    }
    if tally.incomplete > 0 || tally.ungraded > 0 || failures > 0 || truncated || !examined_all_rows
    {
        StageStatus::Incomplete
    } else {
        StageStatus::Complete
    }
}

/// Build the response body for one stage.
///
/// Every field an examiner needs to judge the numbers is present whatever the
/// outcome: a caller never has to infer "did not run" from an absent key.
fn stage_envelope(
    spec: &StageSpec,
    image_id: Option<Uuid>,
    rows: &StageRows,
    failures: &[&Artifact],
    failures_truncated: bool,
) -> Value {
    let tally = tally_rows(&rows.records);
    let status = stage_status(rows.total, &tally, failures.len(), rows.truncated, true);
    let count_is_floor = rows.truncated
        || tally.incomplete > 0
        || tally.ungraded > 0
        || !failures.is_empty()
        || failures_truncated;
    // Completeness and validation are different questions, and the answer to
    // one says nothing about the other: a stage can walk every entry in a list
    // (complete) using code no capture of that operating system has ever tested
    // (unvalidated). So this never touches `status`; it travels beside it.
    let mut validation = ValidationClaim::default();
    validation.observe_all(&rows.records);
    validation.observe_all(failures.iter().copied());

    json!({
        "stage": spec.key,
        "record_type": spec.record_type,
        "record_types": std::iter::once(spec.record_type)
            .chain(spec.also_record_types.iter().copied())
            .collect::<Vec<_>>(),
        "describes": spec.describes,
        "per_process": spec.per_process,
        "image_id": image_id,
        "scoped_to_image": image_id.is_some(),
        "stage_ran": rows.total > 0,
        "status": status.as_str(),
        "status_meaning": status.meaning(),
        "record_count": rows.total,
        "records_returned": rows.records.len(),
        "records_truncated": rows.truncated,
        "rows_incomplete": tally.incomplete,
        "rows_completeness_ungraded": tally.ungraded,
        "count_is_floor": count_is_floor,
        // Whether the tier that produced these rows says it has never been run
        // against a real capture of the operating system it read. `false` means
        // no record said so; it is not an assertion that any tier was
        // validated.
        "analysis_declares_itself_unvalidated": validation.declares_unvalidated(),
        "unvalidated_records": validation.marked,
        "validation_notice": validation.notice_json(),
        "failures": failures.iter().map(|a| failure_json(a)).collect::<Vec<_>>(),
        "failures_truncated": failures_truncated,
        "records": rows.records.iter().map(record_json).collect::<Vec<_>>(),
    })
}

/// Fetch a stage's results and the failure records that explain its absence,
/// and package both.
async fn load_stage(
    state: &AppState,
    case_id: Uuid,
    spec: &StageSpec,
    image_id: Option<Uuid>,
) -> Result<Value, ApiError> {
    let rows = fetch_stage_records(state, case_id, spec, image_id, LIST_FETCH_CAP).await?;
    let failures = fetch_records(
        state,
        case_id,
        MEMORY_STAGE_FAILURE_RECORD,
        image_id,
        FAILURE_FETCH_CAP,
    )
    .await?;
    let matching: Vec<&Artifact> = failures
        .records
        .iter()
        .filter(|a| failure_covers_spec(&a.metadata, spec))
        .collect();
    Ok(stage_envelope(
        spec,
        image_id,
        &rows,
        &matching,
        failures.truncated,
    ))
}

// --- profile / evidence ---------------------------------------------------

/// Whether a profile record represents an established profile.
///
/// Discovery failure records carry the same `type` on purpose — an image Séance
/// could not profile is a finding — so presence of a `MemoryProfile` record is
/// not on its own evidence that a profile exists.
fn profile_established(metadata: &Value) -> bool {
    if metadata.get("profile_established").and_then(Value::as_bool) == Some(false) {
        return false;
    }
    metadata.get("analysis_stage").and_then(Value::as_str) != Some("discovery_failed")
}

/// Whether the symbol table passed every admission gate.
///
/// Three-valued on purpose. `None` means the record did not say, which must
/// render differently from "not verified": one is an unanswered question, the
/// other is an answer.
fn symbols_verified(metadata: &Value) -> Option<bool> {
    if let Some(flag) = metadata.get("symbols_verified").and_then(Value::as_bool) {
        return Some(flag);
    }
    metadata
        .get("symbols_state")
        .and_then(Value::as_str)
        .map(|state| state == "Verified")
}

/// Grade one fact in the profile: its value, and how that value was arrived at.
///
/// A fact with a value but no grade is reported as ungraded rather than assumed
/// good. An examiner reading "confirmed" on a fact nobody graded would be
/// reading a claim the tool never made.
fn graded_fact(metadata: &Value, fact: &str, value_key: &str, evidence_key: &str) -> Value {
    let value = metadata.get(value_key).cloned().unwrap_or(Value::Null);
    let present = !value.is_null();
    let evidence = metadata.get(evidence_key).and_then(Value::as_str);
    json!({
        "fact": fact,
        "present": present,
        "value": value,
        "evidence": evidence,
        "graded": present && evidence.is_some(),
    })
}

/// The evidence block: the honesty surface of the profile screen.
///
/// `weakest_evidence` is the grade of the weakest fact the whole analysis rests
/// on. Every process, handle and connection reported for this image inherits
/// it, so it belongs at the top of the screen and not in a tooltip.
fn evidence_block(metadata: &Value) -> Value {
    let weakest = metadata.get("weakest_evidence").and_then(Value::as_str);
    let verified = symbols_verified(metadata);
    let facts = vec![
        graded_fact(metadata, "directory_table_base", "dtb", "dtb_evidence"),
        graded_fact(
            metadata,
            "kernel_base",
            "kernel_base",
            "kernel_base_evidence",
        ),
        graded_fact(metadata, "kdbg", "kdbg", "kdbg_evidence"),
    ];
    let ungraded = facts
        .iter()
        .filter(|f| f["present"] == Value::Bool(true) && f["graded"] == Value::Bool(false))
        .count();

    json!({
        "weakest_evidence": weakest,
        "weakest_evidence_known": weakest.is_some(),
        "symbols_verified": verified,
        "symbols_verified_known": verified.is_some(),
        "symbols_state": field(metadata, "symbols_state"),
        "symbols_provenance": field(metadata, "symbols_sha256"),
        "facts": facts,
        "ungraded_facts": ungraded,
        "note": "Every finding for this image rests on these facts. The weakest grade here is \
                 the ceiling on the confidence of everything downstream.",
    })
}

/// Summarise an image's analysis state from its profile record, if any.
///
/// Three states, deliberately distinct: the analysis never ran, it ran and
/// could not establish a profile, or it ran and did. Collapsing the first two
/// would tell an examiner the image was unanalysable when in fact nobody tried.
fn analysis_state(profile: Option<&Artifact>) -> (&'static str, &'static str) {
    match profile {
        None => (
            "not_analysed",
            "No memory analysis has run against this image. The image is decoded and its \
             content is searchable, but no processes, modules or connections have been \
             extracted.",
        ),
        Some(p) if !profile_established(&p.metadata) => (
            "discovery_failed",
            "Analysis ran but could not establish an image profile, so no kernel structures \
             could be walked. The reason names what is missing.",
        ),
        Some(_) => (
            "analysed",
            "An image profile was established and the analysis stages ran. See the coverage \
             endpoint for which of them completed.",
        ),
    }
}

// --- handlers -------------------------------------------------------------

/// `GET /api/v1/cases/:id/memory/images`
///
/// Every memory image in the case, with what the container stage established
/// about it and whether analysis has run.
///
/// An examiner learns which images exist, how much of each is really
/// addressable, and — the part that matters — whether the absence of processes
/// for an image means "not analysed", "could not be profiled" or "analysed".
/// A wrong answer here would let a report imply an image was examined when the
/// analysis never touched it.
pub async fn list_memory_images(
    Path(case_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let images = fetch_records(&state, case_id, MEMORY_IMAGE_RECORD, None, LIST_FETCH_CAP).await?;
    let profiles =
        fetch_records(&state, case_id, MEMORY_PROFILE_RECORD, None, LIST_FETCH_CAP).await?;
    let failures = fetch_records(
        &state,
        case_id,
        MEMORY_STAGE_FAILURE_RECORD,
        None,
        FAILURE_FETCH_CAP,
    )
    .await?;

    let items: Vec<Value> = images
        .records
        .iter()
        .map(|image| {
            let profile = profiles
                .records
                .iter()
                .find(|p| p.parent_id == Some(image.id));
            let (state_key, state_meaning) = analysis_state(profile);
            let failure_count = failures
                .records
                .iter()
                .filter(|f| f.parent_id == Some(image.id))
                .count();
            let m = &image.metadata;

            json!({
                "image_id": image.id,
                // The evidence this capture was decoded FROM — the raw image, or
                // the file inside a filesystem the dump was found in. The
                // navigator hides ParsedRecord children, so an examiner browsing
                // the physical tree sees that file and never this record; without
                // the link back there is no route from the evidence they are
                // looking at to the analysis of it.
                "source_artifact_id": image.parent_id,
                "name": field(m, "name"),
                "image_format": field(m, "image_format"),
                "architecture": field(m, "architecture"),
                "addressable_bytes": field(m, "addressable_bytes"),
                "file_bytes": field(m, "file_bytes"),
                "declared_size": field(m, "declared_size"),
                "size_mismatch": m.get("size_mismatch").and_then(Value::as_bool).unwrap_or(false),
                "decode_failed": m.get("decode_failed").and_then(Value::as_bool).unwrap_or(false),
                // Absent means the container stage did not say, which is not
                // the same as "complete" and must not be shown as such.
                "content_complete": declared_complete(m),
                "content_complete_known": declared_complete(m).is_some(),
                "incomplete": field(m, "incomplete"),
                "analysis_state": state_key,
                "analysis_state_meaning": state_meaning,
                "profile": profile.map(|p| json!({
                    "record_id": p.id,
                    "established": profile_established(&p.metadata),
                    "analysed_os": field(&p.metadata, "analysed_os"),
                    "analysed_by": field(&p.metadata, "analysed_by"),
                    "pdb": field(&p.metadata, "pdb"),
                    "nt_build": field(&p.metadata, "nt_build"),
                    "weakest_evidence": field(&p.metadata, "weakest_evidence"),
                    "symbols_verified": symbols_verified(&p.metadata),
                    "failure": field(&p.metadata, "failure"),
                })),
                "stage_failures": failure_count,
            })
        })
        .collect();

    Ok(Json(json!({
        "case_id": case_id,
        "images": items,
        "image_count": images.total,
        "images_truncated": images.truncated,
        // A truncated profile or failure fetch means the per-image summaries
        // above may understate; say so rather than let the UI trust them.
        "summaries_complete": !(profiles.truncated || failures.truncated),
    })))
}

/// `GET /api/v1/cases/:id/memory/profile/:img`
///
/// The full image profile: directory table base, kernel base, build, symbol
/// provenance — and the evidence grade on each of those facts.
///
/// This is the screen where honesty lives. `weakest_evidence` and
/// `symbols_verified` are surfaced at the top level as well as inside the
/// evidence block, because everything else the analysis reports for this image
/// is only as good as they are. When no profile record exists the response says
/// the analysis has not run; it never returns a blank profile, which would read
/// as "we looked and there was nothing there".
pub async fn get_memory_profile(
    Path((case_id, image_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let image = require_memory_image(&state, case_id, image_id).await?;
    let profiles = fetch_records(
        &state,
        case_id,
        MEMORY_PROFILE_RECORD,
        Some(image_id),
        LIST_FETCH_CAP,
    )
    .await?;

    let profile = profiles.records.first();
    let (state_key, state_meaning) = analysis_state(profile);

    let body = match profile {
        None => json!({
            "case_id": case_id,
            "image_id": image_id,
            "image": image.metadata,
            "analysis_state": state_key,
            "analysis_state_meaning": state_meaning,
            "profile_established": false,
            "profile": Value::Null,
            "evidence": Value::Null,
            "discovery": Value::Null,
        }),
        Some(p) => {
            let established = profile_established(&p.metadata);
            // Grading a profile that was never established would put evidence
            // labels on facts that do not exist.
            let evidence = if established {
                evidence_block(&p.metadata)
            } else {
                Value::Null
            };
            json!({
                "case_id": case_id,
                "image_id": image_id,
                "image": image.metadata,
                "analysis_state": state_key,
                "analysis_state_meaning": state_meaning,
                "record_id": p.id,
                "profile_established": established,
                "profile": p.metadata,
                // Promoted out of the blob deliberately: these two decide how
                // much weight every other memory finding can carry.
                "weakest_evidence": field(&p.metadata, "weakest_evidence"),
                "symbols_verified": symbols_verified(&p.metadata),
                "symbols_verified_known": symbols_verified(&p.metadata).is_some(),
                // Promoted for the same reason, one question further back:
                // evidence grades say how firmly this profile was established,
                // and this says whether the tier that established it has ever
                // been tested against a real capture of the operating system it
                // read. A confirmed DTB found by code nobody has ever checked is
                // still a confirmed DTB, and it is not the same exhibit.
                "analysis_declares_itself_unvalidated": declares_unvalidated(&p.metadata),
                "validation_notice": validation_notice(&p.metadata),
                "evidence": evidence,
                "discovery": field(&p.metadata, "discovery"),
                "failure": field(&p.metadata, "failure"),
                "symbol_dirs_searched": field(&p.metadata, "symbol_dirs_searched"),
                "profiles_returned": profiles.records.len(),
                "profiles_total": profiles.total,
            })
        }
    };
    Ok(Json(body))
}

/// `GET /api/v1/cases/:id/memory/processes`
///
/// The process list and the tree built from it, each with its own completeness
/// verdict.
///
/// They are returned together because they answer one question and fail
/// together: a tree with no list behind it is not a shorter tree, it is no tree
/// at all. An examiner reading a tree here can see from `list.status` whether
/// the list it was built from was itself a floor.
pub async fn get_memory_processes(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let image_id = resolve_scope(&state, case_id, &query).await?;
    let list_spec = stage("processes").expect("the processes stage is in STAGES");
    let tree_spec = stage("process_tree").expect("the process_tree stage is in STAGES");

    let list = load_stage(&state, case_id, list_spec, image_id).await?;
    let tree = load_stage(&state, case_id, tree_spec, image_id).await?;

    Ok(Json(json!({
        "case_id": case_id,
        "image_id": image_id,
        "list": list,
        "tree": tree,
    })))
}

/// Serve one per-process stage for one PID.
///
/// Distinguishes three things an empty answer could otherwise conflate: the
/// stage never ran, the stage ran and this PID is not among the processes it
/// covered, and the search for this PID stopped before it had seen everything.
/// Only the middle case is a 404 — and only when the scan was exhaustive,
/// because a 404 after a truncated scan would assert an absence nobody
/// established.
///
/// `scan_cap` bounds how many of the stage's records are examined while looking
/// for this PID. Handlers pass [`PER_PROCESS_SCAN_CAP`]; it is a parameter so
/// the stopped-early path can be exercised without fabricating thousands of
/// records.
async fn per_process_stage(
    state: &AppState,
    case_id: Uuid,
    pid: u64,
    spec: &StageSpec,
    query: &MemoryScopeQuery,
    scan_cap: usize,
) -> Result<Json<Value>, ApiError> {
    let image_id = resolve_scope(state, case_id, query).await?;

    let scanned = fetch_records(state, case_id, spec.record_type, image_id, scan_cap).await?;
    let matched: Vec<Artifact> = scanned
        .records
        .iter()
        .filter(|a| record_pid(&a.metadata) == Some(pid))
        .cloned()
        .collect();

    let failures = fetch_records(
        state,
        case_id,
        MEMORY_STAGE_FAILURE_RECORD,
        image_id,
        FAILURE_FETCH_CAP,
    )
    .await?;
    // A failure with no PID is a stage-wide failure: it explains this PID's
    // absence just as much as a failure tagged with it.
    let matching_failures: Vec<&Artifact> = failures
        .records
        .iter()
        .filter(|a| failure_covers_spec(&a.metadata, spec))
        .filter(|a| match record_pid(&a.metadata) {
            None => true,
            Some(tagged) => tagged == pid,
        })
        .collect();

    let stage_ran_at_all = scanned.total > 0;
    let nothing_for_this_pid = matched.is_empty() && matching_failures.is_empty();
    if nothing_for_this_pid && stage_ran_at_all && !scanned.truncated {
        return Err(ApiError::ResourceNotFound(format!(
            "The {} stage ran for this image but produced no record for PID {}. That PID is not \
             among the processes it covered.",
            spec.key, pid
        )));
    }

    let rows = StageRows {
        total: matched.len() as i64,
        truncated: false,
        records: matched,
    };
    let mut body = stage_envelope(
        spec,
        image_id,
        &rows,
        &matching_failures,
        failures.truncated,
    );

    // The envelope's `stage_ran` describes the rows handed back, which for a
    // per-process view are one PID's. Two extra facts keep the PID view honest:
    // whether the stage produced anything at all, and whether the search for
    // this PID was exhaustive.
    if let Some(object) = body.as_object_mut() {
        object.insert("pid".into(), json!(pid));
        object.insert("stage_ran".into(), json!(stage_ran_at_all));
        object.insert("stage_records_total".into(), json!(scanned.total));
        object.insert("search_exhaustive".into(), json!(!scanned.truncated));
        object.insert("records_scanned".into(), json!(scanned.records.len()));
        if scanned.truncated {
            // The scan stopped before it had seen every record of this type, so
            // even a hit here may not be all of this PID's rows.
            object.insert("count_is_floor".into(), json!(true));
        }
        if scanned.truncated && rows.total == 0 {
            // Neither "this PID has none" nor "the stage did not run": we
            // stopped looking. Saying either would assert something nobody
            // established.
            object.insert("status".into(), json!("not_determined"));
            object.insert(
                "status_meaning".into(),
                json!(
                    "The search for this PID stopped at the scan cap before it had seen every \
                     record, so the absence of a result here is not evidence that the PID has \
                     none."
                ),
            );
        }
    }
    Ok(Json(body))
}

/// `GET /api/v1/cases/:id/memory/processes/:pid/vads`
///
/// One process's virtual address descriptors: what is mapped where, with what
/// protection, and backed by which file.
///
/// An examiner uses this to find executable private memory — code with no file
/// behind it. A response that showed an empty region list for a process whose
/// VAD walk failed would be read as "nothing unusual mapped", so this endpoint
/// reports the walk's failure instead.
pub async fn get_process_vads(
    Path((case_id, pid)): Path<(Uuid, u64)>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let spec = stage("vad").expect("the vad stage is in STAGES");
    per_process_stage(&state, case_id, pid, spec, &query, PER_PROCESS_SCAN_CAP).await
}

/// `GET /api/v1/cases/:id/memory/processes/:pid/handles`
///
/// One process's handle table: the objects it held open, with their types and
/// names.
///
/// An examiner uses this to tie a process to files, keys and other processes it
/// touched. An empty table shown for a process whose handle walk failed would
/// suggest the process touched nothing, so a failed walk is reported as such.
pub async fn get_process_handles(
    Path((case_id, pid)): Path<(Uuid, u64)>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let spec = stage("handles").expect("the handles stage is in STAGES");
    per_process_stage(&state, case_id, pid, spec, &query, PER_PROCESS_SCAN_CAP).await
}

/// `GET /api/v1/cases/:id/memory/processes/:pid/modules`
///
/// One process's loaded user-mode modules.
///
/// An examiner uses this to spot a module loaded from an unexpected path, or
/// one present in memory but unlinked from the loader lists. The Windows
/// analysis emits one `MemoryProcessModules` record per process, tagged with
/// that process's id, so a PID with no record here is one the module walk did
/// not cover — which this endpoint reports as such, never as an empty module
/// list, since that would assert the process had loaded nothing at all.
pub async fn get_process_modules(
    Path((case_id, pid)): Path<(Uuid, u64)>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let spec = stage("dlls").expect("the dlls stage is in STAGES");
    per_process_stage(&state, case_id, pid, spec, &query, PER_PROCESS_SCAN_CAP).await
}

/// Serve one image-wide stage by key. The key always comes from a route
/// constant, never from user input.
async fn image_stage(
    state: &AppState,
    case_id: Uuid,
    key: &str,
    query: &MemoryScopeQuery,
) -> Result<Json<Value>, ApiError> {
    let spec = stage(key).ok_or_else(|| {
        error!("memory: route asked for unknown stage '{key}'");
        ApiError::InternalServerError("Unknown memory analysis stage".to_string())
    })?;
    let image_id = resolve_scope(state, case_id, query).await?;
    Ok(Json(load_stage(state, case_id, spec, image_id).await?))
}

/// `GET /api/v1/cases/:id/memory/network`
///
/// Network endpoints and connections recovered from memory, including sockets
/// closed before the capture whose pool allocations survive.
///
/// An examiner learns which process held which port. An empty list where the
/// scan never ran would read as "this machine had no network activity", which
/// is why the status field is not optional.
pub async fn get_memory_network(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "network", &query).await
}

/// `GET /api/v1/cases/:id/memory/services`
///
/// Windows service records as they stood in memory, one listing per
/// `services.exe` in the image.
///
/// An examiner compares these against the registry's view: a service present in
/// memory and absent from the registry, or with a different binary, is the
/// finding. A missing stage must not be mistaken for "no services".
pub async fn get_memory_services(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "services", &query).await
}

/// `GET /api/v1/cases/:id/memory/registry/hives`
///
/// Registry hives mapped into kernel memory, including volatile hives that
/// exist nowhere on disk.
///
/// An examiner learns which hives can be read straight out of the capture. A
/// hive list that silently omitted the hives whose enumeration failed would
/// send them looking on disk for something the image did hold.
pub async fn get_memory_registry_hives(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "registry_hives", &query).await
}

/// `GET /api/v1/cases/:id/memory/tampering`
///
/// Process-image tampering signals: hollowing, ghosting, and executable memory
/// with no file behind it.
///
/// This endpoint's empty state is the most dangerous one in the module. "No
/// tampering signals" and "the tampering scan did not run" would both be an
/// empty array, and the first is an exculpatory finding. The status field makes
/// them different answers.
pub async fn get_memory_tampering(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "tampering", &query).await
}

/// `GET /api/v1/cases/:id/memory/tamper-checks`
///
/// The kernel-side tamper checks (`ROADMAP` §5.3): unloaded drivers, the
/// per-processor timer tables, threads carrying debug registers, suspended
/// threads, orphan kernel threads, a patched ETW write path and a skeleton key.
///
/// **Every group's detection is written**, and a group that does not run on a
/// given image says which of three things stopped it: this build's symbols do
/// not carry what it needs, there was no process list to walk, or a structure
/// would not read. Those are different sentences and the record carries
/// whichever is true — conflating them would let one read to an examiner as
/// another. The record's own `groups_implemented` names the groups whose
/// detection exists, rather than this prose stating a number.
///
/// This endpoint's empty state is the dangerous one, for the same reason
/// `tampering`'s is: an empty answer about kernel tampering reads as an
/// exculpatory finding. So the record states, in words, that nothing here is a
/// statement about whether the kernel was tampered with.
pub async fn get_memory_tamper_checks(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "tamper_checks", &query).await
}

/// `GET /api/v1/cases/:id/memory/suspicious-threads`
///
/// Where each live user thread started running (MEM-024, upstream's
/// `suspicious_threads`): its two start addresses placed in the VAD that
/// covers them. One image-wide record naming every process judged, every one
/// out of scope (a null Peb, or already exited) and every one whose
/// analysis failed, with the error.
///
/// Its empty state is an exculpatory-looking one, so `did_not_run` and a
/// record with no findings are served differently, and a record whose survey
/// was partial carries `content_complete: false` with the reasons.
pub async fn get_memory_suspicious_threads(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "suspicious_threads", &query).await
}

/// `GET /api/v1/cases/:id/memory/device-tree`
///
/// Where a filter driver inserted itself (`ROADMAP` §5.3): which driver owns
/// which device, and what is attached on top of each.
///
/// The attachment is the point. Windows lets a driver put its own device object
/// above another driver's so that every request passes through it first — which
/// is how a volume encryptor, an antivirus and a USB class filter work, and how
/// a rootkit intercepts disk, keyboard or network I/O without patching any code.
/// **An attachment is not by itself a finding**, and the record says so.
///
/// An attachment stack that could not be walked to its end is stated as such,
/// because something may be attached above the point it stopped — which is
/// exactly what this endpoint is read for.
pub async fn get_memory_device_tree(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "device_tree", &query).await
}

/// `GET /api/v1/cases/:id/memory/jobs`
///
/// Job objects and the processes confined to them (`ROADMAP` §5.3): how a
/// sandbox, a packaged app and a container show up in memory — and the reverse,
/// a process that ought to be in a job and is not.
///
/// **One record per distinct `_EJOB`**, naming every process that pointed at
/// it. Upstream's `joblinks` prints one row per process that has a job and
/// repeats the job's members under each, so its row count is higher for the
/// same machine; two rows for one kernel object would be two answers to one
/// question.
///
/// The job's own `ActiveProcesses` counter and the walk of its member list are
/// **both** reported. A job whose counter exceeds its list is either
/// mid-teardown or has had a member unlinked, and preferring one number
/// silently would hide exactly that.
pub async fn get_memory_jobs(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "jobs", &query).await
}

/// `GET /api/v1/cases/:id/memory/pattern-scan`
///
/// Where an examiner's own YARA rules and patterns matched in memory
/// (`ROADMAP` §5.3): upstream's `yarascan`, `vadyarascan`, `regexscan` and
/// `vadregexscan`, over each process's own address space through the
/// translation this build recovered, and over the kernel's.
///
/// **Every match carries the allocation it was found in.** The same bytes in
/// private, executable, unbacked memory and in the read-only section of a
/// mapped system DLL are different findings, and the difference is in the
/// virtual address descriptor rather than in the bytes — so a row without one
/// would be a row an examiner cannot act on.
///
/// ## Two empty states, and they mean opposite things
///
/// This endpoint's empty answer is the most dangerous in the memory tier,
/// because a rule set is brought in the belief that it detects something:
///
/// * **no rule set or pattern was named** — the stage reports that it *did not
///   run*, with that reason. Séance ships no rules of its own, so this is the
///   ordinary state of a case nobody pointed at a rule file, and it says
///   nothing whatever about the image;
/// * **a rule set ran and matched nothing** — an answer about *that* rule set,
///   over the memory this capture holds and this build could read. The record
///   says so in words, beside the bytes it examined and the bytes it could not.
///
/// A response that rendered the two the same way would let "we never looked"
/// read as "we looked and it is clean".
///
/// ## What a YARA condition means here
///
/// A rule is evaluated against one **chunk** of the address space at a time,
/// not against a file. An individual string match is reliable and is what these
/// rows are; a condition joining two strings fires only where both fall in the
/// same chunk, `filesize` is meaningless, and a count counts within a chunk.
/// The record carries that statement on itself rather than leaving an examiner
/// to assume whole-file semantics they would get from `yara` on the command
/// line.
pub async fn get_memory_pattern_scan(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "pattern_scan", &query).await
}

/// `GET /api/v1/cases/:id/memory/strings-map`
///
/// `strings` over memory: which address spaces reach each physical offset the
/// examiner's own strings file names.
///
/// ## Three states, and none of them may look like another
///
/// **The stage did not run** because no strings file was named — Séance runs no
/// `strings` of its own and chooses nothing to search for. **It ran and an
/// offset has owners.** **It ran and an offset has none**, which is reported
/// only where every address space was walked whole, and even then says what it
/// does not claim: the PFN database is not read here, a frame on the free or
/// standby list still holds the last bytes written to it, and a mapping that
/// existed at another instant is not in this image. Where any space could not
/// be walked the row claims nothing at all.
///
/// ## Why the radix is on the record
///
/// `strings -t x` writes hexadecimal offsets, and a hexadecimal file read as
/// decimal does not fail cleanly: lines with a letter in them are rejected, and
/// the rest parse into frames gigabytes from the truth with nothing on the row
/// to show it. So the radix is stated by the examiner rather than guessed, and
/// the proportion of lines rejected under it is published beside the answer.
pub async fn get_memory_strings_map(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "strings_map", &query).await
}

/// `GET /api/v1/cases/:id/memory/crossview`
///
/// The concealment table: which listing saw each process, and which did not.
///
/// A process visible to the pool scan but missing from the active list is the
/// classic sign of a rootkit unlinking itself. The value of this view is
/// entirely in the disagreements, so a listing that failed to run must be shown
/// as failed rather than as a column of "not seen" — the latter would
/// manufacture a concealment finding out of a broken stage.
pub async fn get_memory_crossview(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    image_stage(&state, case_id, "cross_view", &query).await
}

/// `POST /api/v1/cases/:id/memory/credentials/:record/reveal`
///
/// Hand back one recovered credential's value, and record that it was revealed.
///
/// Revealing a secret recovered from a suspect's memory is an evidential act,
/// not a display preference, so it is a server round trip rather than a
/// client-side toggle. The audit event is written **before** the value is
/// returned and is mandatory: if the hash-chained audit log cannot record the
/// reveal, the reveal does not happen. An examiner asked in court who saw this
/// value and when must be able to answer from the log, and a reveal that left no
/// trace would make that answer wrong rather than merely incomplete.
///
/// A record that carries no value is an error naming the missing field, never a
/// `200` with an empty string: an empty string on screen reads as "the
/// credential was blank", which is a finding nobody made.
///
/// ## What this route does *not* imply
///
/// The Windows credentials stage recovers values. It decrypts the local
/// account NT hashes out of the SAM and the LSA secrets, and emits one
/// [`MEMORY_CREDENTIAL_RECORD`] with a `value` for each. It also emits a
/// [`MEMORY_CREDENTIAL_INVENTORY_RECORD`], which lists accounts, secret names
/// and cache counts and carries no `value`. This route refuses the inventory
/// record. That refusal is the correct answer: a tool used in evidence must
/// not imply a recovery the record does not hold.
pub async fn reveal_memory_credential(
    Path((case_id, record_id)): Path<(Uuid, Uuid)>,
    Extension(user): Extension<crate::auth::AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let artifact = state
        .db
        .get_artifact(record_id)
        .await
        .map_err(|e| {
            error!("memory: failed to load credential record {record_id}: {e}");
            ApiError::InternalServerError("Failed to load credential record".to_string())
        })?
        // Cross-case ids are "not found" rather than "forbidden", for the same
        // reason as everywhere else here: confirming another case holds a
        // credential is itself a disclosure.
        .filter(|a| a.case_id == case_id)
        .ok_or_else(|| {
            ApiError::ResourceNotFound(format!("No credential record {record_id} in this case"))
        })?;

    if metadata_type(&artifact.metadata) == Some(MEMORY_CREDENTIAL_INVENTORY_RECORD) {
        // The commonest way this route can be called wrongly, and the one whose
        // answer must not be a bare "not a credential record": the record is
        // the credential *inventory*, which is what the credentials stage
        // produces, and it holds no secret because nothing decrypted one.
        return Err(ApiError::InvalidRequest(format!(
            "Record {record_id} is a credential inventory, not a recovered credential. The \
             credentials stage located and listed this machine's credential stores — which \
             accounts exist, what the LSA secrets are called, how many cached domain logons \
             there are — and did not decrypt any of them, so there is no value to reveal."
        )));
    }
    if metadata_type(&artifact.metadata) != Some(MEMORY_CREDENTIAL_RECORD) {
        return Err(ApiError::InvalidRequest(format!(
            "Artifact {record_id} is not a recovered-credential record"
        )));
    }

    let value = artifact
        .metadata
        .get("value")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "Credential record {record_id} carries no 'value' field, so there is nothing to \
                 reveal. This is not a credential whose value was empty."
            ))
        })?
        .to_string();

    // Mandatory, not best effort. The `?` here is the whole point: a failed
    // audit write aborts before the value leaves the process.
    crate::audit_required(
        &state,
        Some(case_id),
        &user.0,
        "memory_credential_revealed",
        Some("memory_credential"),
        Some(record_id),
        Some(&format!(
            "account={} format={}",
            artifact
                .metadata
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or("not recorded"),
            artifact
                .metadata
                .get("hash_format")
                .and_then(Value::as_str)
                .unwrap_or("not stated"),
        )),
    )
    .await?;

    Ok(Json(json!({
        "value": value,
        // The audit writer does not return the row id it wrote, so none is
        // claimed here. The event is in the case audit log against the
        // examiner's account; saying otherwise would be an id nobody could look
        // up.
        "audit_event_id": Value::Null,
    })))
}

/// `GET /api/v1/cases/:id/memory/coverage`
///
/// Which analysis stages ran, which did not, and why.
///
/// Built from the stage-failure records the analysis emits alongside its
/// results, plus the presence and completeness of each stage's own records. An
/// examiner uses this to know the shape of the hole in their analysis before
/// they write a conclusion that depends on a stage which never executed. A
/// wrong answer here — a stage reported as run when it was skipped — is how a
/// report ends up asserting an absence that was never tested for.
pub async fn get_memory_coverage(
    Path(case_id): Path<Uuid>,
    AxumQuery(query): AxumQuery<MemoryScopeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let image_id = resolve_scope(&state, case_id, &query).await?;

    let failures = fetch_records(
        &state,
        case_id,
        MEMORY_STAGE_FAILURE_RECORD,
        image_id,
        FAILURE_FETCH_CAP,
    )
    .await?;

    // What the analysis says it can run, which is not the same as what this
    // build of the API knows how to describe.
    let manifest = fetch_records(
        &state,
        case_id,
        MEMORY_STAGE_MANIFEST_RECORD,
        image_id,
        LIST_FETCH_CAP,
    )
    .await?;
    let declared = declared_stages(&manifest.records);

    let mut stages = Vec::with_capacity(STAGES.len());
    let mut counts: Map<String, Value> = Map::new();
    let mut totals = [0usize; 4]; // complete, incomplete, failed, did_not_run
                                  // Case-wide roll-up of every "this analysis has never been validated"
                                  // marker found below, so a client that renders one banner over the coverage
                                  // table does not have to walk every row to know whether to show it.
    let mut case_validation = ValidationClaim::default();

    for spec in STAGES {
        let rows = fetch_stage_records(&state, case_id, spec, image_id, COVERAGE_TALLY_CAP).await?;
        let matching: Vec<&Artifact> = failures
            .records
            .iter()
            .filter(|a| failure_covers_spec(&a.metadata, spec))
            .collect();
        let tally = tally_rows(&rows.records);
        let mut validation = ValidationClaim::default();
        validation.observe_all(&rows.records);
        validation.observe_all(matching.iter().copied());
        case_validation.absorb(&validation);
        // Completeness can only be judged on rows we looked at. When the tally
        // cap bit, say so instead of extrapolating from the sample.
        let examined_all = !rows.truncated;
        let status = stage_status(rows.total, &tally, matching.len(), false, examined_all);
        match status {
            StageStatus::Complete => totals[0] = totals[0].saturating_add(1),
            StageStatus::Incomplete => totals[1] = totals[1].saturating_add(1),
            StageStatus::Failed => totals[2] = totals[2].saturating_add(1),
            StageStatus::DidNotRun => totals[3] = totals[3].saturating_add(1),
        }

        stages.push(json!({
            "stage": spec.key,
            "record_type": spec.record_type,
            "record_types": std::iter::once(spec.record_type)
                .chain(spec.also_record_types.iter().copied())
                .collect::<Vec<_>>(),
            "describes": spec.describes,
            "per_process": spec.per_process,
            // Whether the analysis that ran against this image says it has this
            // stage at all. `false` on a build whose analysis predates the
            // stage, where "did not run" is a fact about the build.
            "declared_by_analysis": declared.contains_key(spec.key),
            "described_by_api": true,
            // Orthogonal to `status`: this says whether the code that produced
            // the rows has ever been tested against a real capture of the
            // operating system it read. `false` means no record here declared
            // itself unvalidated -- it is not an assertion that any tier was
            // validated, which is a claim only a tier can make about itself.
            "analysis_declares_itself_unvalidated": validation.declares_unvalidated(),
            "unvalidated_records": validation.marked,
            "validation_notice": validation.notice_json(),
            "stage_ran": rows.total > 0,
            "status": status.as_str(),
            "status_meaning": status.meaning(),
            "record_count": rows.total,
            "rows_examined": rows.records.len(),
            "completeness_established_for_all_rows": examined_all,
            "rows_incomplete": tally.incomplete,
            "rows_completeness_ungraded": tally.ungraded,
            // `failures.truncated` belongs in the floor, not in `stage_status`'s
            // `truncated` parameter. The failure fetch is capped once across
            // every stage, so a stage whose failures all sit past the cap sees
            // an empty `matching` and would otherwise report Complete inside an
            // envelope that says the coverage is not established. Feeding it to
            // `stage_status` instead would degrade *every* stage to Incomplete
            // the moment the cap bit — a different and untrue claim about the
            // stages that were fully accounted for.
            "count_is_floor": tally.incomplete > 0
                || tally.ungraded > 0
                || !examined_all
                || !matching.is_empty()
                || failures.truncated,
            // While true, an empty `failures` below means "none within the
            // first FAILURE_FETCH_CAP records", not "none".
            "failures_truncated": failures.truncated,
            "failures": matching.iter().map(|a| failure_json(a)).collect::<Vec<_>>(),
        }));
        counts.insert(spec.key.to_string(), json!(status.as_str()));
    }

    // Stages the analysis declares and this build of the API cannot describe.
    // They get a row built from what the manifest said, because a stage absent
    // from coverage is a stage whose silence reads as "nothing to find" — and
    // that silence is exactly what this endpoint exists to prevent. Without
    // this, adding a stage to the analysis and forgetting to add it to STAGES
    // would hide it, which is how the DLL, credentials and Amcache stages came
    // to run and report nothing.
    for (key, spec) in &declared {
        if stage(key).is_some() {
            continue;
        }
        let rows = fetch_records(
            &state,
            case_id,
            &spec.record_type,
            image_id,
            COVERAGE_TALLY_CAP,
        )
        .await?;
        let matching: Vec<&Artifact> = failures
            .records
            .iter()
            .filter(|a| failure_covers(&a.metadata, key))
            .collect();
        let tally = tally_rows(&rows.records);
        // Seeded from the manifest that declared the stage, so a tier that ran
        // and produced no rows at all still states what its results would have
        // rested on.
        let mut validation = spec.validation.clone();
        validation.observe_all(&rows.records);
        validation.observe_all(matching.iter().copied());
        case_validation.absorb(&validation);
        let examined_all = !rows.truncated;
        let status = stage_status(rows.total, &tally, matching.len(), false, examined_all);
        match status {
            StageStatus::Complete => totals[0] = totals[0].saturating_add(1),
            StageStatus::Incomplete => totals[1] = totals[1].saturating_add(1),
            StageStatus::Failed => totals[2] = totals[2].saturating_add(1),
            StageStatus::DidNotRun => totals[3] = totals[3].saturating_add(1),
        }
        stages.push(json!({
            "stage": key,
            "record_type": spec.record_type,
            "record_types": [spec.record_type.clone()],
            "describes": spec.describes,
            "per_process": spec.per_process,
            "declared_by_analysis": true,
            // The one thing a client must know about this row: the sentence
            // above came from the analysis, not from this build of the API, and
            // there is no route dedicated to it.
            "described_by_api": false,
            "analysis_declares_itself_unvalidated": validation.declares_unvalidated(),
            "unvalidated_records": validation.marked,
            "validation_notice": validation.notice_json(),
            "stage_ran": rows.total > 0,
            "status": status.as_str(),
            "status_meaning": status.meaning(),
            "record_count": rows.total,
            "rows_examined": rows.records.len(),
            "completeness_established_for_all_rows": examined_all,
            "rows_incomplete": tally.incomplete,
            "rows_completeness_ungraded": tally.ungraded,
            // `failures.truncated` belongs in the floor, not in `stage_status`'s
            // `truncated` parameter. The failure fetch is capped once across
            // every stage, so a stage whose failures all sit past the cap sees
            // an empty `matching` and would otherwise report Complete inside an
            // envelope that says the coverage is not established. Feeding it to
            // `stage_status` instead would degrade *every* stage to Incomplete
            // the moment the cap bit — a different and untrue claim about the
            // stages that were fully accounted for.
            "count_is_floor": tally.incomplete > 0
                || tally.ungraded > 0
                || !examined_all
                || !matching.is_empty()
                || failures.truncated,
            // While true, an empty `failures` below means "none within the
            // first FAILURE_FETCH_CAP records", not "none".
            "failures_truncated": failures.truncated,
            "failures": matching.iter().map(|a| failure_json(a)).collect::<Vec<_>>(),
        }));
        counts.insert(key.clone(), json!(status.as_str()));
    }

    // Failures naming a stage this build does not know about would otherwise
    // vanish. An unrecognised stage that did not run is still a stage that did
    // not run, so it is listed rather than dropped.
    let unattributed: Vec<Value> = failures
        .records
        .iter()
        .filter(|a| !STAGES.iter().any(|s| failure_covers_spec(&a.metadata, s)))
        .filter(|a| !declared.keys().any(|key| failure_covers(&a.metadata, key)))
        .map(failure_json)
        .collect();

    Ok(Json(json!({
        "case_id": case_id,
        "image_id": image_id,
        "scoped_to_image": image_id.is_some(),
        "stages": stages,
        "status_by_stage": counts,
        "summary": {
            "complete": totals[0],
            "incomplete": totals[1],
            "failed": totals[2],
            "did_not_run": totals[3],
            "total_stages": stages.len(),
        },
        "stages_declared_by_analysis": declared.len(),
        "analysis_declared_its_stages": !manifest.records.is_empty(),
        "unattributed_failures": unattributed,
        "failures_truncated": failures.truncated,
        "coverage_complete": !failures.truncated && !manifest.truncated,
        // Case-wide roll-up of the per-row markers. True when at least one
        // analysis that touched this capture states it has never been run
        // against a real capture of the operating system it read — the macOS
        // tier says this of itself today. It is a statement about the tool, not
        // about the evidence, and it cannot be inferred from any status above.
        "unvalidated_analysis_present": case_validation.declares_unvalidated(),
        "unvalidated_analysis_notice": case_validation.notice_json(),
        "note": "A stage listed as 'did_not_run' produced neither a result nor a failure. \
                 Nothing about the evidence follows from its silence.",
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::artifact::ArtifactType;
    use seance_db::SqliteConnection;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    // --- pure helpers -----------------------------------------------------

    fn rows(records: Vec<Artifact>, total: i64, truncated: bool) -> StageRows {
        StageRows {
            records,
            total,
            truncated,
        }
    }

    fn record(metadata: Value) -> Artifact {
        Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, metadata)
    }

    #[test]
    fn a_stage_with_neither_a_result_nor_a_failure_reports_that_it_did_not_run() {
        let tally = tally_rows(&[]);
        let status = stage_status(0, &tally, 0, false, true);
        assert_eq!(status, StageStatus::DidNotRun);
        assert!(status.meaning().contains("did not run"));
    }

    #[test]
    fn a_stage_with_only_a_failure_record_reports_failed_rather_than_empty() {
        let tally = tally_rows(&[]);
        assert_eq!(stage_status(0, &tally, 1, false, true), StageStatus::Failed);
    }

    #[test]
    fn a_stage_whose_rows_declared_completeness_reports_complete() {
        let records = vec![record(json!({"content_complete": true}))];
        let tally = tally_rows(&records);
        assert_eq!(
            stage_status(1, &tally, 0, false, true),
            StageStatus::Complete
        );
    }

    #[test]
    fn a_row_that_stopped_early_makes_the_whole_stage_incomplete() {
        let records = vec![
            record(json!({"content_complete": true})),
            record(json!({"content_complete": false})),
        ];
        let tally = tally_rows(&records);
        assert_eq!(tally.incomplete, 1);
        assert_eq!(
            stage_status(2, &tally, 0, false, true),
            StageStatus::Incomplete
        );
    }

    #[test]
    fn a_row_that_never_declared_completeness_is_not_treated_as_complete() {
        // Fail closed: a missing flag is an unanswered question, and answering
        // it "complete" would let a report quote the count as a total.
        let records = vec![record(json!({"name": "no flag here"}))];
        let tally = tally_rows(&records);
        assert_eq!(tally.ungraded, 1);
        assert_eq!(
            stage_status(1, &tally, 0, false, true),
            StageStatus::Incomplete
        );
    }

    #[test]
    fn a_stage_with_results_and_a_failure_is_incomplete_not_complete() {
        let records = vec![record(json!({"content_complete": true}))];
        let tally = tally_rows(&records);
        assert_eq!(
            stage_status(1, &tally, 1, false, true),
            StageStatus::Incomplete
        );
    }

    #[test]
    fn a_stage_whose_rows_were_not_all_examined_can_never_report_complete() {
        let records = vec![record(json!({"content_complete": true}))];
        let tally = tally_rows(&records);
        assert_eq!(
            stage_status(900, &tally, 0, false, false),
            StageStatus::Incomplete
        );
    }

    #[test]
    fn a_failure_record_naming_one_stage_covers_only_that_stage() {
        let m = json!({"stage": "network"});
        assert!(failure_covers(&m, "network"));
        assert!(!failure_covers(&m, "services"));
    }

    #[test]
    fn a_failure_record_naming_several_skipped_stages_covers_each_of_them() {
        // The "prerequisite failed, these were skipped" record uses `stages`,
        // not `stage`. Missing it would hide four stages that did not run.
        let m = json!({"stages": ["vad", "dlls", "handles", "tampering"]});
        for s in ["vad", "dlls", "handles", "tampering"] {
            assert!(failure_covers(&m, s), "{s}");
        }
        assert!(!failure_covers(&m, "network"));
    }

    #[test]
    fn a_process_tree_failure_is_recognised_under_the_process_list_stage_name() {
        // The tree is skipped when the list walk fails, and that failure is
        // recorded against "processes". A tree view that ignored it would show
        // "did not run" with no reason attached.
        let spec = stage("process_tree").unwrap();
        assert!(failure_covers_spec(&json!({"stage": "processes"}), spec));
        assert!(failure_covers_spec(&json!({"stage": "process_tree"}), spec));
    }

    #[test]
    fn every_stage_key_is_unique_and_resolvable() {
        for spec in STAGES {
            assert!(stage(spec.key).is_some(), "{}", spec.key);
            assert_eq!(
                STAGES.iter().filter(|s| s.key == spec.key).count(),
                1,
                "duplicate stage key {}",
                spec.key
            );
            assert!(!spec.failure_stages.is_empty(), "{}", spec.key);
        }
    }

    #[test]
    fn an_ungraded_fact_is_reported_as_ungraded_rather_than_confirmed() {
        let m = json!({"dtb": 0x1ad000u64});
        let fact = graded_fact(&m, "directory_table_base", "dtb", "dtb_evidence");
        assert_eq!(fact["present"], json!(true));
        assert_eq!(fact["graded"], json!(false));
        assert_eq!(fact["evidence"], Value::Null);
    }

    #[test]
    fn an_absent_fact_is_reported_as_absent_rather_than_ungraded_with_a_value() {
        let m = json!({"kdbg": Value::Null});
        let fact = graded_fact(&m, "kdbg", "kdbg", "kdbg_evidence");
        assert_eq!(fact["present"], json!(false));
        assert_eq!(fact["value"], Value::Null);
    }

    #[test]
    fn the_evidence_block_counts_facts_that_carry_a_value_but_no_grade() {
        let m = json!({
            "dtb": 0x1ad000u64,
            "dtb_evidence": "confirmed",
            "kernel_base": 0xfffff80000000000u64,
            "weakest_evidence": "confirmed",
        });
        let block = evidence_block(&m);
        assert_eq!(block["ungraded_facts"], json!(1));
        assert_eq!(block["weakest_evidence"], json!("confirmed"));
        assert_eq!(block["weakest_evidence_known"], json!(true));
    }

    #[test]
    fn a_profile_that_never_stated_its_weakest_evidence_says_so_rather_than_guessing() {
        let block = evidence_block(&json!({"dtb": 1u64, "dtb_evidence": "scanned"}));
        assert_eq!(block["weakest_evidence"], Value::Null);
        assert_eq!(block["weakest_evidence_known"], json!(false));
    }

    #[test]
    fn symbol_verification_is_unknown_when_the_profile_does_not_say() {
        assert_eq!(symbols_verified(&json!({})), None);
        let block = evidence_block(&json!({}));
        assert_eq!(block["symbols_verified"], Value::Null);
        assert_eq!(block["symbols_verified_known"], json!(false));
    }

    #[test]
    fn symbol_verification_is_derived_from_the_symbol_state_when_the_flag_is_absent() {
        assert_eq!(
            symbols_verified(&json!({"symbols_state": "Verified"})),
            Some(true)
        );
        assert_eq!(
            symbols_verified(&json!({"symbols_state": "Unverified"})),
            Some(false)
        );
    }

    #[test]
    fn an_explicit_verification_flag_wins_over_the_state_string() {
        let m = json!({"symbols_verified": false, "symbols_state": "Verified"});
        assert_eq!(symbols_verified(&m), Some(false));
    }

    #[test]
    fn a_discovery_failure_record_is_not_mistaken_for_an_established_profile() {
        let failed = json!({
            "profile_established": false,
            "analysis_stage": "discovery_failed",
            "failure": "no directory table base found",
        });
        assert!(!profile_established(&failed));
        let ok = json!({"analysis_stage": "analysed", "dtb": 1u64});
        assert!(profile_established(&ok));
    }

    #[test]
    fn an_image_with_no_profile_record_reads_as_not_analysed_not_as_unanalysable() {
        let (key, meaning) = analysis_state(None);
        assert_eq!(key, "not_analysed");
        assert!(meaning.contains("No memory analysis has run"));
    }

    #[test]
    fn an_image_whose_discovery_failed_reads_differently_from_one_never_analysed() {
        let failed = record(json!({"profile_established": false}));
        let (key, _) = analysis_state(Some(&failed));
        assert_eq!(key, "discovery_failed");
        assert_ne!(key, analysis_state(None).0);
    }

    #[test]
    fn the_envelope_marks_the_count_as_a_floor_when_a_row_stopped_early() {
        let spec = stage("cross_view").unwrap();
        let records = vec![record(json!({"content_complete": false}))];
        let body = stage_envelope(spec, None, &rows(records, 1, false), &[], false);
        assert_eq!(body["status"], json!("incomplete"));
        assert_eq!(body["count_is_floor"], json!(true));
        assert_eq!(body["stage_ran"], json!(true));
    }

    #[test]
    fn the_envelope_never_reports_a_missing_stage_as_an_empty_complete_result() {
        let spec = stage("tampering").unwrap();
        let body = stage_envelope(spec, None, &rows(Vec::new(), 0, false), &[], false);
        assert_eq!(body["status"], json!("did_not_run"));
        assert_eq!(body["stage_ran"], json!(false));
        assert_eq!(body["records"], json!([]));
        assert!(body["status_meaning"]
            .as_str()
            .unwrap()
            .contains("not a finding that there was nothing to find"));
    }

    #[test]
    fn the_envelope_reports_a_truncated_fetch_as_a_floor() {
        let spec = stage("network").unwrap();
        let records = vec![record(json!({"content_complete": true}))];
        let body = stage_envelope(spec, None, &rows(records, 900, true), &[], false);
        assert_eq!(body["records_truncated"], json!(true));
        assert_eq!(body["count_is_floor"], json!(true));
        assert_eq!(body["record_count"], json!(900));
        assert_eq!(body["records_returned"], json!(1));
    }

    // --- DB-backed handler tests -----------------------------------------

    async fn test_state() -> (AppState, Uuid, Arc<SqliteConnection>) {
        let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
        db.initialize().await.unwrap();
        let case_id = db.create_case("Memory API Test", "Examiner").await.unwrap();

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let (event_tx, _event_rx) = tokio::sync::broadcast::channel(16);
        let (task_tx, _task_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ad_hoc_tx, _ad_hoc_rx) = tokio::sync::mpsc::channel(4);
        let (status_tx, _status_rx) = tokio::sync::broadcast::channel(16);
        let active_tasks = Arc::new(AtomicUsize::new(0));

        let state = AppState {
            db: db.clone(),
            // A counted submitter over the test channel; the counter is the test's own
            // because nothing here submits through it.
            orchestrator_sender: seance_core::orchestrator::TaskSubmitter::new(
                tx,
                std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            ),
            ad_hoc_sender: ad_hoc_tx,
            event_sender: event_tx.clone(),
            status_sender: status_tx,
            active_tasks: active_tasks.clone(),
            search_service: None,
            ingestion_service: seance_core::ingestion::IngestionService::new(
                Some(db.clone()),
                task_tx,
                event_tx,
                active_tasks,
            ),
            module_registry: vec![],
            signing_config: None,
            evidence_roots: crate::EvidenceRootPolicy::unrestricted(),
            cancellation: seance_core::orchestrator::CancellationHandle::new(),
        };
        (state, case_id, db)
    }

    /// Insert a decoded memory image record and return its artifact id.
    async fn insert_image(db: &Arc<SqliteConnection>, case_id: Uuid) -> Uuid {
        let image = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": MEMORY_IMAGE_RECORD,
                "subtype": "memory_image",
                "name": "Memory image (raw)",
                "image_format": "raw",
                "addressable_bytes": 4096u64,
                "file_bytes": 4096u64,
                "content_complete": true,
            }),
        );
        let id = image.id;
        db.record_artifact(&image).await.unwrap();
        id
    }

    /// Insert a child record of the image.
    async fn insert_child(
        db: &Arc<SqliteConnection>,
        case_id: Uuid,
        image_id: Uuid,
        metadata: Value,
    ) -> Uuid {
        let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(image_id);
        let id = artifact.id;
        db.record_artifact(&artifact).await.unwrap();
        id
    }

    fn established_profile() -> Value {
        json!({
            "type": MEMORY_PROFILE_RECORD,
            "name": "Windows 10.0 profile (ntkrnlmp.pdb)",
            "analysis_stage": "analysed",
            "analysed_os": "windows",
            "analysed_by": "plugin.memory.windows",
            "dtb": 0x1ad000u64,
            "dtb_evidence": "confirmed",
            "kernel_base": 0xfffff80000000000u64,
            "kernel_base_evidence": "validated",
            "kdbg": Value::Null,
            "kdbg_evidence": Value::Null,
            "pdb": "ntkrnlmp.pdb",
            "nt_build": 19041,
            "symbols_state": "Verified",
            "weakest_evidence": "validated",
        })
    }

    #[tokio::test]
    async fn listing_images_reports_an_image_nobody_analysed_as_not_analysed() {
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;

        let Json(body) = list_memory_images(Path(case_id), State(state))
            .await
            .unwrap();
        assert_eq!(body["image_count"], json!(1));
        assert_eq!(body["images"][0]["analysis_state"], json!("not_analysed"));
        assert_eq!(body["images"][0]["profile"], Value::Null);
        assert_eq!(body["summaries_complete"], json!(true));
    }

    /// The evidence navigator hides ParsedRecord children, so an examiner
    /// browsing image -> partition -> filesystem -> file sees the RAM capture as
    /// a file and never sees this record. Without the link back, there is no
    /// route from the evidence they are looking at to the analysis of it, and
    /// they must leave the tree and re-find the same file in a dropdown.
    #[tokio::test]
    async fn an_image_names_the_evidence_it_was_decoded_from() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;

        let Json(body) = list_memory_images(Path(case_id), State(state))
            .await
            .unwrap();
        let listed = &body["images"][0];
        assert_eq!(listed["image_id"], json!(image));
        assert!(
            listed.get("source_artifact_id").is_some(),
            "the field must be present even when null, or a client cannot tell \
             'no link recorded' from 'this build does not report one'"
        );
        assert_ne!(
            listed["source_artifact_id"], listed["image_id"],
            "the source is the evidence the capture came from, never the record itself"
        );
    }

    #[tokio::test]
    async fn listing_images_separates_a_failed_discovery_from_an_unanalysed_image() {
        let (state, case_id, db) = test_state().await;
        let analysed = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            analysed,
            json!({
                "type": MEMORY_PROFILE_RECORD,
                "name": "Windows memory profile (not established)",
                "analysis_stage": "discovery_failed",
                "profile_established": false,
                "failure": "symbols for PDB GUID ABCD are not installed",
            }),
        )
        .await;
        insert_image(&db, case_id).await;

        let Json(body) = list_memory_images(Path(case_id), State(state))
            .await
            .unwrap();
        let images = body["images"].as_array().unwrap();
        assert_eq!(images.len(), 2);
        let failed = images
            .iter()
            .find(|i| i["analysis_state"] == json!("discovery_failed"))
            .expect("the failed image is listed");
        assert_eq!(failed["profile"]["established"], json!(false));
        assert!(failed["profile"]["failure"]
            .as_str()
            .unwrap()
            .contains("symbols"));
        assert!(images
            .iter()
            .any(|i| i["analysis_state"] == json!("not_analysed")));
    }

    #[tokio::test]
    async fn the_profile_endpoint_rejects_an_image_id_belonging_to_another_case() {
        let (state, case_id, db) = test_state().await;
        let other_case = db.create_case("Other", "Examiner").await.unwrap();
        let foreign = insert_image(&db, other_case).await;

        let err = get_memory_profile(Path((case_id, foreign)), State(state))
            .await
            .expect_err("a cross-case image id must not resolve");
        assert!(matches!(err, ApiError::ResourceNotFound(_)));
    }

    #[tokio::test]
    async fn the_profile_endpoint_rejects_an_artifact_that_is_not_a_memory_image() {
        let (state, case_id, db) = test_state().await;
        let not_an_image = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "WhatsApp", "name": "message"}),
        );
        db.record_artifact(&not_an_image).await.unwrap();

        let err = get_memory_profile(Path((case_id, not_an_image.id)), State(state))
            .await
            .expect_err("a non-image artifact must be refused");
        assert!(matches!(err, ApiError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn the_profile_endpoint_says_analysis_never_ran_rather_than_returning_a_blank_profile() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;

        let Json(body) = get_memory_profile(Path((case_id, image)), State(state))
            .await
            .unwrap();
        assert_eq!(body["analysis_state"], json!("not_analysed"));
        assert_eq!(body["profile_established"], json!(false));
        assert_eq!(body["profile"], Value::Null);
        assert_eq!(body["evidence"], Value::Null);
        assert!(body["analysis_state_meaning"]
            .as_str()
            .unwrap()
            .contains("No memory analysis has run"));
    }

    #[tokio::test]
    async fn the_profile_endpoint_surfaces_the_weakest_evidence_and_symbol_verification() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(&db, case_id, image, established_profile()).await;

        let Json(body) = get_memory_profile(Path((case_id, image)), State(state))
            .await
            .unwrap();
        assert_eq!(body["analysis_state"], json!("analysed"));
        assert_eq!(body["profile_established"], json!(true));
        assert_eq!(body["weakest_evidence"], json!("validated"));
        assert_eq!(body["symbols_verified"], json!(true));
        assert_eq!(body["symbols_verified_known"], json!(true));
        assert_eq!(body["evidence"]["ungraded_facts"], json!(0));
        let facts = body["evidence"]["facts"].as_array().unwrap();
        let dtb = facts
            .iter()
            .find(|f| f["fact"] == "directory_table_base")
            .unwrap();
        assert_eq!(dtb["evidence"], json!("confirmed"));
        assert_eq!(dtb["graded"], json!(true));
        let kdbg = facts.iter().find(|f| f["fact"] == "kdbg").unwrap();
        assert_eq!(kdbg["present"], json!(false));
    }

    #[tokio::test]
    async fn a_stage_that_never_ran_is_not_served_as_an_empty_result() {
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;

        let Json(body) = get_memory_network(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("did_not_run"));
        assert_eq!(body["stage_ran"], json!(false));
        assert_eq!(body["record_count"], json!(0));
    }

    #[tokio::test]
    async fn a_stage_that_ran_and_found_nothing_reads_differently_from_one_that_did_not_run() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemoryNetwork",
                "stage": "network",
                "stage_ran": true,
                "content_complete": true,
                "connections": [],
            }),
        )
        .await;

        let Json(body) = get_memory_network(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("complete"));
        assert_eq!(body["stage_ran"], json!(true));
        assert_eq!(body["count_is_floor"], json!(false));
        assert_eq!(body["records"][0]["data"]["connections"], json!([]));
    }

    #[test]
    fn the_suspicious_thread_description_names_every_out_of_scope_reason_as_observed() {
        // Review of MEM-024: the description gave one reason, as an inference
        // ("no user address space ... kernel threads"), and left out the
        // exited processes the survey also sets aside.
        let spec = STAGES
            .iter()
            .find(|s| s.key == "suspicious_threads")
            .expect("a row");
        assert!(spec.describes.contains("null Peb"), "{}", spec.describes);
        assert!(spec.describes.contains("exited"), "{}", spec.describes);
        assert!(
            spec.describes.contains("SystemThread"),
            "{}",
            spec.describes
        );
        assert!(!spec.describes.contains("their threads are kernel threads"));
    }

    #[tokio::test]
    async fn the_suspicious_thread_stage_is_served_as_not_run_until_its_record_exists() {
        // MEM-024: the analysis existed and nothing served it. Before the
        // record exists the answer is "did not run", never an empty list of
        // findings; after, it is the record.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;

        let Json(body) = get_memory_suspicious_threads(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state.clone()),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("did_not_run"));
        assert_eq!(body["stage_ran"], json!(false));

        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemorySuspiciousThreads",
                "stage": "suspicious_threads",
                "stage_ran": true,
                "content_complete": true,
                "evidence_count": 1,
                "processes": [],
            }),
        )
        .await;
        let Json(body) = get_memory_suspicious_threads(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("complete"));
        assert_eq!(body["stage_ran"], json!(true));
        assert_eq!(body["records"][0]["data"]["evidence_count"], json!(1));
    }

    #[tokio::test]
    async fn a_failed_stage_serves_the_reason_it_could_not_run() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_STAGE_FAILURE_RECORD,
                "stage": "services",
                "stage_ran": false,
                "content_complete": false,
                "failure": "_SERVICE_RECORD is absent from this symbol table",
            }),
        )
        .await;

        let Json(body) = get_memory_services(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("failed"));
        assert_eq!(body["stage_ran"], json!(false));
        assert!(body["failures"][0]["failure"]
            .as_str()
            .unwrap()
            .contains("_SERVICE_RECORD"));
    }

    #[tokio::test]
    async fn the_crossview_endpoint_marks_a_capped_scan_as_a_floor() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemoryCrossView",
                "stage": "cross_view",
                "content_complete": false,
                "content_incomplete": true,
                "processes": [{"pid": 4, "seen_by": ["pslist"]}],
            }),
        )
        .await;

        let Json(body) = get_memory_crossview(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("incomplete"));
        assert_eq!(body["count_is_floor"], json!(true));
        assert_eq!(body["rows_incomplete"], json!(1));
    }

    #[tokio::test]
    async fn the_process_endpoint_returns_the_list_and_the_tree_with_separate_verdicts() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemoryProcessList",
                "stage": "processes",
                "content_complete": true,
                "processes": [{"pid": 4, "image_file_name": "System"}],
            }),
        )
        .await;

        let Json(body) = get_memory_processes(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["list"]["status"], json!("complete"));
        // The tree stage emitted nothing, and that must not read as "this
        // machine had a flat process tree".
        assert_eq!(body["tree"]["status"], json!("did_not_run"));
    }

    #[tokio::test]
    async fn an_image_scope_hides_another_images_records() {
        let (state, case_id, db) = test_state().await;
        let first = insert_image(&db, case_id).await;
        let second = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            first,
            json!({"type": "MemoryNetwork", "stage": "network", "content_complete": true}),
        )
        .await;

        let Json(scoped) = get_memory_network(
            Path(case_id),
            AxumQuery(MemoryScopeQuery {
                image: Some(second),
            }),
            State(state.clone()),
        )
        .await
        .unwrap();
        assert_eq!(scoped["status"], json!("did_not_run"));
        assert_eq!(scoped["scoped_to_image"], json!(true));

        let Json(first_scoped) = get_memory_network(
            Path(case_id),
            AxumQuery(MemoryScopeQuery { image: Some(first) }),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(first_scoped["status"], json!("complete"));
    }

    #[tokio::test]
    async fn a_single_image_case_still_answers_without_a_scope() {
        // The refusal below must not cost the ordinary case its unscoped
        // listing: with one capture there is nothing to conflate.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({"type": "MemoryNetwork", "stage": "network", "content_complete": true}),
        )
        .await;

        let Json(body) = get_memory_network(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("complete"));
        assert_eq!(body["scoped_to_image"], json!(false));
    }

    #[tokio::test]
    async fn an_unscoped_listing_of_a_two_capture_case_is_refused_rather_than_merged() {
        // Two captures, each with its own PID 712. Merged, they read as one
        // machine that ran the process twice — or, on the cross-view table, as
        // a machine disagreeing with itself. The refusal names the captures so
        // the caller can pick one.
        let (state, case_id, db) = test_state().await;
        let first = insert_image(&db, case_id).await;
        let second = insert_image(&db, case_id).await;
        for image in [first, second] {
            insert_child(
                &db,
                case_id,
                image,
                json!({
                    "type": "MemoryProcessList",
                    "stage": "processes",
                    "content_complete": true,
                    "processes": [{"pid": 712, "image_file_name": "svchost.exe"}],
                }),
            )
            .await;
        }

        let err = get_memory_processes(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state.clone()),
        )
        .await
        .expect_err("a listing spanning two captures must not be served");
        match err {
            ApiError::InvalidRequest(msg) => {
                assert!(msg.contains("?image="), "{msg}");
                assert!(msg.contains(&first.to_string()), "{msg}");
                assert!(msg.contains(&second.to_string()), "{msg}");
            }
            other => panic!("expected an invalid-request refusal, got {other:?}"),
        }

        // Scoped, each capture answers for itself.
        let Json(body) = get_memory_processes(
            Path(case_id),
            AxumQuery(MemoryScopeQuery { image: Some(first) }),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["list"]["record_count"], json!(1));
        assert_eq!(body["image_id"], json!(first));
    }

    #[tokio::test]
    async fn a_pid_view_of_a_two_capture_case_is_refused_rather_than_merged() {
        // The sharpest form of the merge: two unrelated processes that share a
        // number, served as one process's handle table.
        let (state, case_id, db) = test_state().await;
        let first = insert_image(&db, case_id).await;
        let second = insert_image(&db, case_id).await;
        for image in [first, second] {
            insert_child(
                &db,
                case_id,
                image,
                json!({
                    "type": "MemoryProcessHandles",
                    "stage": "handles",
                    "content_complete": true,
                    "pid": 712u64,
                    "handles": [],
                }),
            )
            .await;
        }

        let err = get_process_handles(
            Path((case_id, 712u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state.clone()),
        )
        .await
        .expect_err("one PID cannot answer for two captures");
        assert!(matches!(err, ApiError::InvalidRequest(_)));

        let Json(body) = get_process_handles(
            Path((case_id, 712u64)),
            AxumQuery(MemoryScopeQuery {
                image: Some(second),
            }),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["records_returned"], json!(1));
        assert_eq!(body["records"][0]["image_id"], json!(second));
    }

    #[tokio::test]
    async fn unscoped_coverage_of_a_two_capture_case_is_refused() {
        // Coverage is per-capture too: a stage that ran on one image and failed
        // on the other has no single status.
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;
        insert_image(&db, case_id).await;

        let err = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .expect_err("coverage across two captures is not one coverage report");
        assert!(matches!(err, ApiError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn the_image_list_stays_case_wide_so_a_client_can_learn_the_scopes() {
        // The one endpoint that must keep answering unscoped: it is how a
        // caller discovers the ids the refusal above asks for.
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;
        insert_image(&db, case_id).await;

        let Json(body) = list_memory_images(Path(case_id), State(state))
            .await
            .unwrap();
        assert_eq!(body["image_count"], json!(2));
        assert_eq!(body["images"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_unknown_image_scope_is_refused_rather_than_silently_ignored() {
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;

        let err = get_memory_network(
            Path(case_id),
            AxumQuery(MemoryScopeQuery {
                image: Some(Uuid::new_v4()),
            }),
            State(state),
        )
        .await
        .expect_err("an unknown image scope must not fall back to the whole case");
        assert!(matches!(err, ApiError::ResourceNotFound(_)));
    }

    #[tokio::test]
    async fn per_process_vads_serve_only_the_requested_pid() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        for pid in [4u64, 512u64] {
            insert_child(
                &db,
                case_id,
                image,
                json!({
                    "type": "MemoryProcessVads",
                    "stage": "vad",
                    "content_complete": true,
                    "pid": pid,
                    "process_name": format!("proc{pid}"),
                    "vads": [{"start": 0x1000u64}],
                }),
            )
            .await;
        }

        let Json(body) = get_process_vads(
            Path((case_id, 512u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["pid"], json!(512));
        assert_eq!(body["records_returned"], json!(1));
        assert_eq!(body["records"][0]["data"]["process_name"], json!("proc512"));
        assert_eq!(body["status"], json!("complete"));
        assert_eq!(body["search_exhaustive"], json!(true));
    }

    #[tokio::test]
    async fn a_pid_absent_from_a_stage_that_ran_is_a_not_found_and_says_why() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemoryProcessHandles",
                "stage": "handles",
                "content_complete": true,
                "pid": 4u64,
                "handles": [],
            }),
        )
        .await;

        let err = get_process_handles(
            Path((case_id, 9999u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .expect_err("an absent pid must not return an empty handle table");
        match err {
            ApiError::ResourceNotFound(msg) => {
                assert!(msg.contains("9999"), "{msg}");
                assert!(msg.contains("not among the processes"), "{msg}");
            }
            other => panic!("expected a not-found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_pid_view_of_a_stage_that_never_ran_reports_did_not_run_rather_than_not_found() {
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;

        let Json(body) = get_process_handles(
            Path((case_id, 4u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("did_not_run"));
        assert_eq!(body["stage_ran"], json!(false));
        assert_eq!(body["stage_records_total"], json!(0));
    }

    #[tokio::test]
    async fn per_process_modules_report_that_the_stage_did_not_run_not_an_empty_module_list() {
        // Nothing emitted a module record for this image at all. An empty array
        // here would assert the process loaded no DLLs, which is never true of
        // a live Windows process.
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;

        let Json(body) = get_process_modules(
            Path((case_id, 4u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["record_type"], json!("MemoryProcessModules"));
        assert_eq!(body["status"], json!("did_not_run"));
        assert!(body["status_meaning"]
            .as_str()
            .unwrap()
            .contains("not a finding that there was nothing to find"));
    }

    #[tokio::test]
    async fn the_module_stage_serves_the_pid_the_analysis_tagged_its_record_with() {
        // The contract the analysis and this endpoint have to agree on. The
        // stage is per-process and keyed `dlls`; when the analysis emitted one
        // image-wide record under `process_modules` instead, this endpoint saw
        // the records, matched no PID, and refused every PID in the image with
        // "not among the processes it covered" while that PID's DLLs sat inside
        // the record it had just read.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        for pid in [4u64, 1234u64] {
            insert_child(
                &db,
                case_id,
                image,
                json!({
                    "type": "MemoryProcessModules",
                    "stage": "dlls",
                    "content_complete": true,
                    "pid": pid,
                    "process_name": format!("proc{pid}"),
                    "modules": [{"name": "ntdll.dll", "base": 0x7ffe0000u64}],
                }),
            )
            .await;
        }

        let Json(body) = get_process_modules(
            Path((case_id, 1234u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("complete"));
        assert_eq!(body["pid"], json!(1234));
        assert_eq!(body["records_returned"], json!(1));
        assert_eq!(
            body["records"][0]["data"]["modules"][0]["name"],
            json!("ntdll.dll")
        );
    }

    #[tokio::test]
    async fn a_module_failure_recorded_under_the_analysis_old_stage_label_still_explains_the_gap() {
        // Records written by an earlier build carry `process_modules`. A case
        // opened after the rename must still show why the stage did not run,
        // rather than "did not run" with no reason attached.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_STAGE_FAILURE_RECORD,
                "stage": "process_modules",
                "failure": "_PEB_LDR_DATA is absent from this symbol table",
            }),
        )
        .await;

        let Json(body) = get_process_modules(
            Path((case_id, 4u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("failed"));
        assert!(body["failures"][0]["failure"]
            .as_str()
            .unwrap()
            .contains("_PEB_LDR_DATA"));
    }

    #[tokio::test]
    async fn a_stage_wide_failure_explains_every_pids_absence() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_STAGE_FAILURE_RECORD,
                "stage": "vad",
                "failure": "_MMVAD_SHORT has no VadNode member on this build",
            }),
        )
        .await;

        let Json(body) = get_process_vads(
            Path((case_id, 4u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status"], json!("failed"));
        assert!(body["failures"][0]["failure"]
            .as_str()
            .unwrap()
            .contains("VadNode"));
    }

    #[tokio::test]
    async fn a_per_process_failure_is_served_against_its_own_pid_only() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_STAGE_FAILURE_RECORD,
                "stage": "vad",
                "pid": 512u64,
                "failure": "VAD tree for this process would not walk",
            }),
        )
        .await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemoryProcessVads",
                "stage": "vad",
                "content_complete": true,
                "pid": 4u64,
                "vads": [],
            }),
        )
        .await;

        let Json(other) = get_process_vads(
            Path((case_id, 4u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state.clone()),
        )
        .await
        .unwrap();
        assert_eq!(other["failures"], json!([]));
        assert_eq!(other["status"], json!("complete"));

        let Json(failed) = get_process_vads(
            Path((case_id, 512u64)),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(failed["status"], json!("failed"));
        assert_eq!(failed["failures"][0]["pid"], json!(512));
    }

    #[tokio::test]
    async fn coverage_names_every_stage_and_why_each_one_did_not_run() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemoryProcessList",
                "stage": "processes",
                "content_complete": true,
                "processes": [{"pid": 4}],
            }),
        )
        .await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_STAGE_FAILURE_RECORD,
                "stage": "pool_scan",
                "failure": "pool header layout unknown for this build",
            }),
        )
        .await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_STAGE_FAILURE_RECORD,
                "stages": ["vad", "dlls", "handles", "tampering"],
                "failure": "the active process list could not be walked",
            }),
        )
        .await;

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();

        assert_eq!(
            body["stages"].as_array().unwrap().len(),
            STAGES.len(),
            "every stage must be listed, including the ones that never ran"
        );
        assert_eq!(body["status_by_stage"]["processes"], json!("complete"));
        assert_eq!(body["status_by_stage"]["pool_scan"], json!("failed"));
        for skipped in ["vad", "dlls", "handles", "tampering"] {
            assert_eq!(
                body["status_by_stage"][skipped],
                json!("failed"),
                "{skipped}"
            );
        }
        assert_eq!(body["status_by_stage"]["network"], json!("did_not_run"));
        assert_eq!(body["summary"]["total_stages"], json!(STAGES.len()));
        assert_eq!(body["coverage_complete"], json!(true));
        assert_eq!(body["unattributed_failures"], json!([]));
    }

    #[tokio::test]
    async fn coverage_lists_a_failure_naming_a_stage_this_build_does_not_know() {
        // A stage added to the analysis but not to STAGES would otherwise fail
        // silently and invisibly.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_STAGE_FAILURE_RECORD,
                "stage": "some_future_stage",
                "failure": "not implemented on this build",
            }),
        )
        .await;

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        let orphans = body["unattributed_failures"].as_array().unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0]["stage"], json!("some_future_stage"));
    }

    #[tokio::test]
    async fn coverage_scoped_to_an_image_ignores_another_images_failures() {
        let (state, case_id, db) = test_state().await;
        let first = insert_image(&db, case_id).await;
        let second = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            first,
            json!({
                "type": MEMORY_STAGE_FAILURE_RECORD,
                "stage": "network",
                "failure": "tcpip symbols missing",
            }),
        )
        .await;

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery {
                image: Some(second),
            }),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status_by_stage"]["network"], json!("did_not_run"));
        assert_eq!(body["scoped_to_image"], json!(true));
    }

    #[tokio::test]
    async fn a_pid_search_that_stopped_early_says_so_instead_of_reporting_an_absence() {
        // The scan cap is the one place this endpoint can be wrong in the
        // dangerous direction: reporting "no record for this PID" when it
        // simply stopped looking. That must never be a 404 and never a
        // "did_not_run".
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        for pid in 1..=3u64 {
            insert_child(
                &db,
                case_id,
                image,
                json!({
                    "type": "MemoryProcessVads",
                    "stage": "vad",
                    "content_complete": true,
                    "pid": pid,
                }),
            )
            .await;
        }

        let spec = stage("vad").unwrap();
        let Json(body) =
            per_process_stage(&state, case_id, 3, spec, &MemoryScopeQuery::default(), 1)
                .await
                .expect("a truncated search must not be reported as a missing PID");

        assert_eq!(body["status"], json!("not_determined"));
        assert_eq!(body["search_exhaustive"], json!(false));
        assert_eq!(body["count_is_floor"], json!(true));
        assert_eq!(body["stage_records_total"], json!(3));
        assert_eq!(body["records_scanned"], json!(1));
        assert!(body["status_meaning"]
            .as_str()
            .unwrap()
            .contains("stopped at the scan cap"));
    }

    // --- credential reveal ------------------------------------------------

    fn examiner() -> Extension<crate::auth::AuthenticatedUser> {
        Extension(crate::auth::AuthenticatedUser("examiner".to_string()))
    }

    async fn insert_credential(
        db: &Arc<SqliteConnection>,
        case_id: Uuid,
        image_id: Uuid,
        metadata: Value,
    ) -> Uuid {
        insert_child(db, case_id, image_id, metadata).await
    }

    #[tokio::test]
    async fn revealing_a_credential_records_the_reveal_before_it_returns_the_value() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        let record_id = insert_credential(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_CREDENTIAL_RECORD,
                "username": "Administrator",
                "hash_format": "NT",
                "value": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }),
        )
        .await;

        let Json(body) =
            reveal_memory_credential(Path((case_id, record_id)), examiner(), State(state.clone()))
                .await
                .unwrap();
        assert_eq!(body["value"], json!("31d6cfe0d16ae931b73c59d7e0c089c0"));

        let events = db.get_audit_log(case_id, 50, 0).await.unwrap();
        let reveal = events
            .iter()
            .find(|e| e["action"] == json!("memory_credential_revealed"))
            .expect("the reveal must be in the audit log");
        assert_eq!(reveal["user_id"], json!("examiner"));
        assert_eq!(reveal["resource_id"], json!(record_id.to_string()));
        assert!(reveal["details"]
            .as_str()
            .unwrap()
            .contains("account=Administrator"));
    }

    #[tokio::test]
    async fn a_credential_record_with_no_value_is_an_error_rather_than_an_empty_reveal() {
        // An empty string on screen reads as "the credential was blank", which
        // is a finding nobody made.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        let record_id = insert_credential(
            &db,
            case_id,
            image,
            json!({"type": MEMORY_CREDENTIAL_RECORD, "username": "svc", "value": ""}),
        )
        .await;

        let err = reveal_memory_credential(Path((case_id, record_id)), examiner(), State(state))
            .await
            .expect_err("a valueless record must not reveal an empty string");
        match err {
            ApiError::InvalidRequest(msg) => assert!(msg.contains("nothing to reveal"), "{msg}"),
            other => panic!("expected an invalid request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_reveal_refuses_an_artifact_that_is_not_a_credential_record() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        let not_a_credential = insert_child(
            &db,
            case_id,
            image,
            json!({"type": "MemoryNetwork", "value": "secret"}),
        )
        .await;

        let err =
            reveal_memory_credential(Path((case_id, not_a_credential)), examiner(), State(state))
                .await
                .expect_err("only credential records may be revealed");
        assert!(matches!(err, ApiError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn a_reveal_of_another_cases_credential_is_not_found_rather_than_forbidden() {
        let (state, case_id, db) = test_state().await;
        let other_case = db.create_case("Other", "Examiner").await.unwrap();
        let other_image = insert_image(&db, other_case).await;
        let foreign = insert_credential(
            &db,
            other_case,
            other_image,
            json!({"type": MEMORY_CREDENTIAL_RECORD, "value": "aa"}),
        )
        .await;

        let err = reveal_memory_credential(Path((case_id, foreign)), examiner(), State(state))
            .await
            .expect_err("a cross-case credential must not resolve");
        assert!(matches!(err, ApiError::ResourceNotFound(_)));
    }

    #[tokio::test]
    async fn coverage_reports_the_credential_stage_as_not_run_when_nothing_recovered_credentials() {
        // The distinction the credentials view depends on: no credential record
        // and no credential stage is "nothing tried", which must not render as
        // "this capture held no credential".
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status_by_stage"]["credentials"], json!("did_not_run"));
    }

    #[tokio::test]
    async fn coverage_reports_the_credential_stage_as_complete_once_it_emits_a_record() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_credential(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_CREDENTIAL_RECORD,
                "content_complete": true,
                "username": "Administrator",
                "value": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }),
        )
        .await;

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(body["status_by_stage"]["credentials"], json!("complete"));
    }

    /// The ordinary record listing must not hand out a recovered credential's
    /// value.
    ///
    /// `SEC-003` stopped the search snippet printing it and the register then
    /// said nothing printed it outside the audited reveal. That was false at
    /// the API layer: `GET /cases/:id/records?type=MemoryCredential` — the
    /// request the credentials screen itself makes — returned `metadata.value`
    /// verbatim to any case reader, with no audit row, and the screen's mask
    /// sat over a body that already held the hash. The reveal endpoint reads
    /// the artifact from the database directly, so withholding here costs the
    /// audited path nothing.
    #[tokio::test]
    async fn the_record_listing_withholds_a_recovered_credentials_value() {
        const HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_CREDENTIAL_RECORD,
                "record_type": MEMORY_CREDENTIAL_RECORD,
                "stage": "credentials",
                "source": "sam",
                "username": "analyst",
                "rid": 1001,
                "format": "nt_hash",
                "value": HASH,
            }),
        )
        .await;

        let Json(body) = crate::get_records_by_type(
            Path(case_id),
            AxumQuery(crate::RecordsQuery {
                record_type: Some(MEMORY_CREDENTIAL_RECORD.to_string()),
                page: 1,
                page_size: 50,
                source_id: None,
                q: None,
                q_keys: None,
                sort: None,
                order: None,
                include_superseded: false,
            }),
            State(state),
        )
        .await
        .unwrap();

        let serialised = body.to_string();
        assert!(
            !serialised.contains(HASH),
            "the recovered hash reached the record listing, bypassing the audited reveal: \
             {serialised}"
        );
        // Withheld, not deleted: the finding survives and says what it is.
        assert!(serialised.contains("analyst"), "{serialised}");
        assert!(serialised.contains("nt_hash"), "{serialised}");
        assert!(
            serialised.contains(crate::CREDENTIAL_VALUE_WITHHELD),
            "a reader must be told a value exists and how to obtain it: {serialised}"
        );
    }

    #[tokio::test]
    async fn the_credential_inventory_the_analysis_emits_counts_as_the_credential_stage_running() {
        // The record the Windows credentials stage actually produces. Keying
        // the stage on the per-credential type alone reported `did_not_run`
        // after a successful run, so the credentials screen said nothing had
        // read the SAM when the SAM had been read and listed.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_CREDENTIAL_INVENTORY_RECORD,
                "stage": "credentials",
                "content_complete": false,
                "inventory_complete": true,
                "inventory_incomplete": false,
                "plaintext_recovered": false,
                "account_count": 3,
            }),
        )
        .await;

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();
        assert_ne!(
            body["status_by_stage"]["credentials"],
            json!("did_not_run"),
            "a stage that ran must never report that it did not"
        );
        assert_eq!(body["status_by_stage"]["credentials"], json!("incomplete"));
        let stage = body["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["stage"] == json!("credentials"))
            .expect("the credentials stage is listed");
        assert_eq!(stage["record_count"], json!(1));
        // DOC-005. This assertion used to require the description to contain
        // "not decrypted", which held the false sentence in place: `MEM-008`
        // added boot-key recovery and SAM decryption, and the text and this test
        // both went on describing the product as it had been. A regression test
        // defending a wrong claim is worse than none — it makes correcting the
        // claim look like breaking the build.
        let describes = stage["describes"].as_str().expect("a description");
        assert!(
            describes.contains("decrypted"),
            "the stage description must say what the stage does, which includes decrypting the \
             local-account hashes where the hives are resident: {describes}"
        );
        assert!(
            !describes.contains("not decrypted") && !describes.contains("no password"),
            "and it must not carry the older sentence denying it: {describes}"
        );
        // **And the other copy of the same sentence.** `DOC-005` was corrected
        // here in 2026-09-06 and NOT in the analysis's own stage table, so the
        // false claim went on travelling in the `MemoryStageManifest` record
        // stored in every case — the record an examiner reads for a stage this
        // table does not describe. Corrected 2026-09-15; both copies are now
        // pinned from one place, because the defect was that they were not.
        let analysis = seance_plugin_memory_windows::module::STAGES
            .iter()
            .find(|stage| stage.key == "credentials")
            .expect("the analysis declares a credentials stage");
        assert!(
            analysis.describes.contains("decrypted")
                && !analysis.describes.contains("not decrypted")
                && !analysis.describes.contains("no password"),
            "the stage manifest the analysis publishes into the case must not deny the \
             decryption the stage performs: {}",
            analysis.describes
        );
        assert!(
            describes.contains("audited reveal"),
            "a description that says values are recovered must also say they are released only \
             through the audited path, or it reads as though the screen shows them: {describes}"
        );
    }

    #[tokio::test]
    async fn revealing_a_credential_inventory_record_says_nothing_was_decrypted() {
        // The wording matters as much as the refusal: an examiner who clicks
        // reveal on the inventory must learn that no secret was recovered, not
        // that they picked the wrong kind of artifact.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        let record_id = insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_CREDENTIAL_INVENTORY_RECORD,
                "stage": "credentials",
                "account_count": 3,
                "plaintext_recovered": false,
            }),
        )
        .await;

        let err = reveal_memory_credential(Path((case_id, record_id)), examiner(), State(state))
            .await
            .expect_err("an inventory record holds no secret to reveal");
        match err {
            ApiError::InvalidRequest(msg) => {
                assert!(msg.contains("did not decrypt"), "{msg}");
                assert!(msg.contains("inventory"), "{msg}");
            }
            other => panic!("expected an invalid request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn coverage_lists_a_stage_the_analysis_declares_and_this_build_cannot_describe() {
        // The drift guard. A stage added to the analysis and not to STAGES
        // would otherwise be invisible: no row, no status, no failure — exactly
        // the silence that reads as "nothing to find". The manifest the
        // analysis emits is what keeps the row on the screen.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_STAGE_MANIFEST_RECORD,
                "stages": [
                    {
                        "stage": "gpu_memory",
                        "record_type": "MemoryGpu",
                        "per_process": false,
                        "describes": "Whatever the video driver still held.",
                    },
                    {
                        "stage": "network",
                        "record_type": "MemoryNetwork",
                        "per_process": false,
                        "describes": "Network endpoints.",
                    },
                ],
            }),
        )
        .await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemoryGpu",
                "stage": "gpu_memory",
                "content_complete": true,
                "surfaces": [],
            }),
        )
        .await;

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();

        assert_eq!(body["status_by_stage"]["gpu_memory"], json!("complete"));
        let row = body["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["stage"] == json!("gpu_memory"))
            .expect("a stage the analysis declares is listed even when unknown here");
        assert_eq!(row["described_by_api"], json!(false));
        assert_eq!(row["declared_by_analysis"], json!(true));
        assert_eq!(row["record_count"], json!(1));
        assert_eq!(body["summary"]["total_stages"], json!(STAGES.len() + 1));
        assert_eq!(body["analysis_declared_its_stages"], json!(true));
        // The stage this build does know is not duplicated by the manifest.
        assert_eq!(
            body["stages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["stage"] == json!("network"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn every_stage_the_windows_analysis_emits_has_a_row_in_this_table() {
        // The other half of the contract asserted in
        // `seance_plugin_memory_windows::module`. The handlers here know an
        // analysis only by the record-type strings it writes to the database, so
        // the same list of keys is asserted on both sides. A key renamed on one
        // side without the other fails here, rather than serving `did_not_run`
        // over a stage that ran.
        for key in [
            "credentials",
            "cross_view",
            "dlls",
            "environment",
            "execution_history",
            "device_tree",
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
        ] {
            assert!(
                stage(key).is_some(),
                "the analysis emits stage '{key}' and this table has no row for it, so coverage \
                 would report it as never run"
            );
        }
        assert_eq!(STAGES.len(), 26);
    }

    // --- the macOS tier ---------------------------------------------------

    /// The record type the macOS tier stamps on one stage's results, taken from
    /// that crate's own table rather than from a string copied into this file.
    fn macos_record_type(key: &str) -> &'static str {
        seance_plugin_memory_macos::STAGES
            .iter()
            .find(|stage| stage.key == key)
            .unwrap_or_else(|| panic!("the macOS tier declares no stage named {key}"))
            .record_type
    }

    /// A record shaped the way the macOS tier emits them: the stage's own fields
    /// plus the marker it stamps on every artifact, applied last, exactly as
    /// `seance_plugin_memory_macos::module::stamp` does.
    fn macos_record(mut value: Value) -> Value {
        let object = value.as_object_mut().expect("object literal");
        for (key, marker) in seance_plugin_memory_macos::unvalidated_stamp()
            .as_object()
            .expect("the stamp is an object")
        {
            object.insert(key.clone(), marker.clone());
        }
        value
    }

    #[test]
    fn the_macos_record_types_this_table_folds_in_are_the_ones_that_tier_emits() {
        // The failure this guards against is silent and total: a record type
        // misspelled here counts nothing, so a Mac capture whose process list
        // was walked in full reports "processes: did not run" — the opposite of
        // the truth, in the row an examiner reads first. The strings therefore
        // come from the analysis crate's own stage table, not from this file.
        //
        // `None` means the stage is deliberately not folded into a Windows or
        // Linux row and reaches coverage through the analysis's stage manifest
        // instead: the Mach task queue is a second linked list, not a pool scan
        // and not the `allproc` walk, and filing it under either would
        // misdescribe what an examiner is reading.
        let mapping: &[(&str, Option<&str>)] = &[
            ("macos_processes", Some("processes")),
            ("macos_process_cross_view", Some("cross_view")),
            ("macos_kernel_extensions", Some("kernel_modules")),
            ("macos_task_processes", None),
        ];
        assert_eq!(
            mapping.len(),
            seance_plugin_memory_macos::STAGES.len(),
            "the macOS tier has gained or lost a stage; decide here which coverage row counts it \
             before it ships, because an unmapped stage is one nothing counts"
        );

        for &(key, row) in mapping {
            let declared = seance_plugin_memory_macos::STAGES
                .iter()
                .find(|stage| stage.key == key)
                .unwrap_or_else(|| panic!("the macOS tier declares no stage named {key}"));
            let Some(row) = row else {
                continue;
            };
            let spec = stage(row).unwrap_or_else(|| panic!("no coverage row named {row}"));
            assert!(
                spec.record_type == declared.record_type
                    || spec.also_record_types.contains(&declared.record_type),
                "the '{row}' row counts {:?} and {:?}, none of which is the {:?} the macOS \
                 {key} stage emits",
                spec.record_type,
                spec.also_record_types,
                declared.record_type
            );
            assert!(
                spec.failure_stages.contains(&key),
                "the '{row}' row does not recognise a failure labelled {key:?}, so a macOS stage \
                 that could not run would report as never having existed"
            );
        }
    }

    #[tokio::test]
    async fn a_macos_capture_reports_the_stages_that_ran_and_says_the_tier_is_unvalidated() {
        // Two defects in one test, because they are one decision.
        //
        // 1. The macOS tier was registered by neither binary, so a Mac capture
        //    was identified as a memory image and then examined by nothing.
        //    Registered, it emits these records; this table has to count them,
        //    or the analysis runs and its results are hidden one layer up.
        // 2. Nothing that tier produces has ever been checked against a capture
        //    of a real Mac. A process list from unvalidated code is
        //    indistinguishable from one from validated code by inspection, so
        //    the marker it stamps on every record has to survive the trip
        //    through this endpoint and be stated on the row.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;

        // The profile the tier establishes before any stage runs.
        insert_child(
            &db,
            case_id,
            image,
            macos_record(json!({
                "type": MEMORY_PROFILE_RECORD,
                "subtype": "macos_memory_profile",
                "name": "macOS (Darwin 19.6.0) memory profile",
                "analysis_stage": "analysed",
                "analysed_os": "macos",
                "analysed_by": "plugin.memory.macos",
                "profile_established": true,
                "weakest_evidence": "validated",
                "symbols_state": "Verified",
            })),
        )
        .await;

        // The manifest the tier publishes before any stage runs.
        insert_child(
            &db,
            case_id,
            image,
            macos_record(json!({
                "type": MEMORY_STAGE_MANIFEST_RECORD,
                "record_type": MEMORY_STAGE_MANIFEST_RECORD,
                "name": "macOS memory analysis: stages this build can run",
                "stages": seance_plugin_memory_macos::STAGES
                    .iter()
                    .map(|stage| stage.to_json())
                    .collect::<Vec<_>>(),
                "stage_count": seance_plugin_memory_macos::STAGES.len(),
                "content_complete": true,
            })),
        )
        .await;

        for (key, extra) in [
            ("macos_processes", json!({"process_count": 87})),
            ("macos_process_cross_view", json!({"processes": []})),
            ("macos_kernel_extensions", json!({"kext_count": 41})),
        ] {
            let mut record = macos_record(json!({
                "type": macos_record_type(key),
                "record_type": macos_record_type(key),
                "stage": key,
                "stage_ran": true,
                "content_complete": true,
            }));
            let object = record.as_object_mut().expect("object literal");
            for (name, value) in extra.as_object().expect("object literal") {
                object.insert(name.clone(), value.clone());
            }
            insert_child(&db, case_id, image, record).await;
        }

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state.clone()),
        )
        .await
        .unwrap();

        let row = |stage: &str| -> Value {
            body["stages"]
                .as_array()
                .expect("an array of stage rows")
                .iter()
                .find(|row| row["stage"] == json!(stage))
                .unwrap_or_else(|| panic!("coverage has no row for {stage}"))
                .clone()
        };

        // The walks that ran are reported as having run. Before the macOS
        // record types were counted, every one of these read "did_not_run" —
        // which is what a coverage table shows for a machine that was running
        // nothing.
        for stage in ["processes", "cross_view", "kernel_modules"] {
            assert_eq!(
                body["status_by_stage"][stage],
                json!("complete"),
                "the {stage} row does not count the records the macOS tier emitted"
            );
            assert_eq!(row(stage)["stage_ran"], json!(true), "{stage}");
        }

        // ...and every one of them says whose code produced it.
        for stage in ["processes", "cross_view", "kernel_modules"] {
            let row = row(stage);
            assert_eq!(
                row["analysis_declares_itself_unvalidated"],
                json!(true),
                "the {stage} row does not carry the macOS tier's unvalidated marker, so an \
                 examiner reads 'complete' with nothing beside it"
            );
            assert!(
                row["validation_notice"]
                    .as_str()
                    .is_some_and(|notice| notice.contains("never been run against a real")),
                "the {stage} row quotes no notice: {}",
                row["validation_notice"]
            );
        }

        // The Mach task queue has no row of its own in STAGES and still reaches
        // the examiner, through the manifest, with the disclosure attached even
        // though it produced no rows to carry one.
        let tasks = row("macos_task_processes");
        assert_eq!(tasks["declared_by_analysis"], json!(true));
        assert_eq!(tasks["described_by_api"], json!(false));
        assert_eq!(tasks["status"], json!("did_not_run"));
        assert_eq!(tasks["analysis_declares_itself_unvalidated"], json!(true));

        assert_eq!(body["unvalidated_analysis_present"], json!(true));
        assert!(body["unvalidated_analysis_notice"]
            .as_str()
            .is_some_and(|notice| !notice.is_empty()));

        // The listing endpoint discloses it too: an examiner reading the
        // process list never has to go back to coverage to learn what produced
        // it.
        let Json(processes) = get_memory_processes(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state.clone()),
        )
        .await
        .unwrap();
        let list = &processes["list"];
        assert_eq!(list["status"], json!("complete"));
        assert_eq!(list["analysis_declares_itself_unvalidated"], json!(true));

        // And so does the profile screen, which is the first thing read of a
        // capture and the place its evidence grades are promoted out of the
        // metadata blob. "Established, on validated evidence, by a tier no
        // capture has ever tested" is one sentence, and all of it has to be
        // visible at once.
        let Json(profile) = get_memory_profile(Path((case_id, image)), State(state))
            .await
            .unwrap();
        assert_eq!(profile["profile_established"], json!(true));
        assert_eq!(profile["weakest_evidence"], json!("validated"));
        assert_eq!(
            profile["analysis_declares_itself_unvalidated"],
            json!(true),
            "the profile screen states the evidence grade and not the fact that \
             nothing has ever tested the code behind it"
        );
        assert!(profile["validation_notice"]
            .as_str()
            .is_some_and(|notice| notice.contains("never been run against a real")));
    }

    #[tokio::test]
    async fn a_capture_whose_analysis_claimed_nothing_is_not_labelled_unvalidated() {
        // The other direction, and the more dangerous one to get wrong: this
        // endpoint must not invent a validation state. A record that carries no
        // marker made no statement, and the row says only that — never that the
        // tier behind it *was* validated, which is a claim only a tier can make
        // about itself.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": "MemoryProcessList",
                "stage": "processes",
                "content_complete": true,
                "processes": [{"pid": 4, "image_file_name": "System"}],
            }),
        )
        .await;

        let Json(body) = get_memory_coverage(
            Path(case_id),
            AxumQuery(MemoryScopeQuery::default()),
            State(state),
        )
        .await
        .unwrap();

        let row = body["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["stage"] == json!("processes"))
            .expect("a processes row");
        assert_eq!(row["status"], json!("complete"));
        assert_eq!(row["analysis_declares_itself_unvalidated"], json!(false));
        assert_eq!(row["unvalidated_records"], json!(0));
        assert_eq!(row["validation_notice"], Value::Null);
        assert_eq!(body["unvalidated_analysis_present"], json!(false));
        assert_eq!(body["unvalidated_analysis_notice"], Value::Null);
    }

    // --- route registration ----------------------------------------------

    /// Build the real application router so the tests below exercise the same
    /// dispatch a client would.
    fn test_router(state: AppState) -> axum::Router {
        crate::router_with_auth(
            state,
            Some(crate::AuthConfig {
                jwt_secret: "memory-route-test".to_string(),
                admin_username: "admin".to_string(),
                admin_password_hash: String::new(),
                enabled: false,
            }),
        )
    }

    async fn get(router: &axum::Router, uri: &str) -> axum::http::StatusCode {
        use tower::util::ServiceExt;
        router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn every_memory_route_is_mounted_on_the_application_router() {
        // The failure this guards against is the one that costs a whole tier:
        // handlers written, unit-tested and never reachable because nothing
        // registered them. A 404 here means the seam is broken.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        let router = test_router(state);

        for uri in [
            format!("/api/v1/cases/{case_id}/memory/images"),
            format!("/api/v1/cases/{case_id}/memory/profile/{image}"),
            format!("/api/v1/cases/{case_id}/memory/processes"),
            format!("/api/v1/cases/{case_id}/memory/processes/4/vads"),
            format!("/api/v1/cases/{case_id}/memory/processes/4/handles"),
            format!("/api/v1/cases/{case_id}/memory/processes/4/modules"),
            format!("/api/v1/cases/{case_id}/memory/network"),
            format!("/api/v1/cases/{case_id}/memory/services"),
            format!("/api/v1/cases/{case_id}/memory/registry/hives"),
            format!("/api/v1/cases/{case_id}/memory/tampering"),
            format!("/api/v1/cases/{case_id}/memory/suspicious-threads"),
            format!("/api/v1/cases/{case_id}/memory/crossview"),
            format!("/api/v1/cases/{case_id}/memory/coverage"),
        ] {
            let status = get(&router, &uri).await;
            assert_eq!(
                status,
                axum::http::StatusCode::OK,
                "{uri} is not reachable through the router"
            );
        }
    }

    #[tokio::test]
    async fn the_credential_reveal_route_is_mounted_and_reachable_by_post() {
        // The reveal button in the UI posts here. A route that is written but
        // never mounted would leave every credential permanently unrevealable
        // while looking like a finished feature.
        use tower::util::ServiceExt;
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        let record_id = insert_child(
            &db,
            case_id,
            image,
            json!({
                "type": MEMORY_CREDENTIAL_RECORD,
                "username": "Administrator",
                "value": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }),
        )
        .await;
        let router = test_router(state);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri(format!(
                        "/api/v1/cases/{case_id}/memory/credentials/{record_id}/reveal"
                    ))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "the reveal route is not reachable through the router"
        );
    }

    #[tokio::test]
    async fn a_non_numeric_pid_is_rejected_by_the_router_rather_than_matched_as_a_process() {
        let (state, case_id, db) = test_state().await;
        insert_image(&db, case_id).await;
        let router = test_router(state);

        let status = get(
            &router,
            &format!("/api/v1/cases/{case_id}/memory/processes/notapid/vads"),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_fetch_that_hits_its_cap_reports_truncation_rather_than_a_short_total() {
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        for pid in 0..5u64 {
            insert_child(
                &db,
                case_id,
                image,
                json!({
                    "type": "MemoryProcessVads",
                    "stage": "vad",
                    "content_complete": true,
                    "pid": pid,
                }),
            )
            .await;
        }

        let rows = fetch_records(&state, case_id, "MemoryProcessVads", Some(image), 2)
            .await
            .unwrap();
        assert_eq!(rows.total, 5);
        assert_eq!(rows.records.len(), 2);
        assert!(rows.truncated, "a capped fetch must say the rest exist");
    }

    #[tokio::test]
    async fn a_scoped_fetch_walks_the_image_subtree_once_however_many_records_it_returns() {
        // The scoped fetch used to page in 50-row bites, and each page cost two
        // recursive walks of the image's subtree. On a real capture that is what
        // made /memory/coverage take longer than five minutes and the Memory
        // page never leave its skeleton state: the answers were right, just
        // unreachable. Pin the walk count, because a timeout is the only other
        // way this regression announces itself.
        let (state, case_id, db) = test_state().await;
        let image = insert_image(&db, case_id).await;
        for pid in 0..120u64 {
            insert_child(
                &db,
                case_id,
                image,
                json!({
                    "type": "MemoryProcess",
                    "stage": "processes",
                    "content_complete": true,
                    "pid": pid,
                }),
            )
            .await;
        }

        let before = db.scoped_record_walks();
        let rows = fetch_records(&state, case_id, "MemoryProcess", Some(image), 200)
            .await
            .unwrap();

        assert_eq!(rows.records.len(), 120);
        assert_eq!(rows.total, 120);
        assert!(!rows.truncated);
        assert_eq!(
            db.scoped_record_walks() - before,
            1,
            "one fetch must be one walk of the subtree, whatever the row count"
        );
    }
}

// --- layer export (ROADMAP §5.3, the `layerwriter` equivalent) --------------
//
// An examiner who needs a memory image in another tool's hands — a plugin
// Séance does not have, a second opinion — needs the *decoded* physical layer,
// not the acquisition container: a hibernation file's pages decompressed, a
// crash dump's runs laid out at their physical addresses, a LiME file's
// segments in place. Such a file must put something at every address, so the
// unacquired ranges are written as zero fill, and the fill leaves with a
// manifest that lists it (`seance_memory::export`). The two routes below are
// one export: `manifest` states the holes, `raw` streams the bytes, and the raw
// response names the manifest it belongs to by SHA-256 so the pair cannot be
// mismatched without it showing.

/// `?start=&end=` on the layer-export routes: a sub-range of the layer's
/// address space, in bytes (decimal), `end` exclusive. Absent means the whole
/// layer. A range that runs past the layer is refused, never clipped: the file
/// is always the size that was asked for.
#[derive(Debug, Default, Deserialize)]
pub struct LayerRangeQuery {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

/// Everything both layer-export routes need, established before a byte moves.
struct PreparedLayerExport {
    layer: std::sync::Arc<dyn seance_memory::MemoryLayer>,
    plan: seance_memory::export::ExportPlan,
    manifest: Value,
    manifest_sha256: String,
    image_format: String,
}

/// Decode the image record's evidence again with the reader the ingest used,
/// check it still decodes to the space the record describes, and plan the
/// export of the requested range.
async fn prepare_layer_export(
    state: &AppState,
    case_id: Uuid,
    image_id: Uuid,
    range: &LayerRangeQuery,
) -> Result<PreparedLayerExport, ApiError> {
    use seance_memory::export::plan_export;

    let image = require_memory_image(state, case_id, image_id).await?;
    let image_format = image
        .metadata
        .get("image_format")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::ValidationError(format!(
                "Memory image {image_id} does not record the format it was decoded as, so its \
                 layer cannot be rebuilt for export"
            ))
        })?
        .to_string();
    let format = seance_memory::MemoryImageFormat::from_str(&image_format).ok_or_else(|| {
        ApiError::ValidationError(format!(
            "Memory image {image_id} records a format this build does not read ({image_format})"
        ))
    })?;
    let recorded_span = image
        .metadata
        .get("addressable_bytes")
        .and_then(Value::as_u64);

    // The record holds no bytes; its evidence does. The same resolution a
    // module re-run uses (HUNT-103).
    let resolved = crate::content_resolver::resolve_artifact_content_through_parent(
        &state.db,
        &state.evidence_roots,
        case_id,
        image_id,
    )
    .await?;
    let source_sha256 = resolved.sha256.clone();
    let source = resolved.source;
    let (start, end) = (range.start, range.end);

    let (layer, plan) = tokio::task::spawn_blocking(move || {
        let layer = seance_memory::open_physical_layer(format, &source).map_err(|e| {
            ApiError::ValidationError(format!(
                "The evidence behind memory image {image_id} no longer decodes as \
                 {image_format}: {e}"
            ))
        })?;
        let span = layer.max_address().saturating_add(1);
        if let Some(recorded) = recorded_span {
            if recorded != span {
                return Err(ApiError::ValidationError(format!(
                    "The evidence behind memory image {image_id} now decodes to {span} bytes \
                     of address space, but the record says {recorded}. The file under the \
                     record is not the one that was analysed, so it is not exported as if it \
                     were."
                )));
            }
        }
        let plan = plan_export(layer.as_ref(), start.unwrap_or(0), end).map_err(|e| match e {
            seance_memory::export::ExportError::Range { .. } => {
                ApiError::InvalidRequest(format!("{e}; the layer spans 0..{span} (end exclusive)"))
            }
            other => ApiError::ValidationError(other.to_string()),
        })?;
        Ok((layer, plan))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Layer export task failed: {e}")))??;

    let image_format = format.as_str().to_string();
    let mut manifest = plan.manifest_json();
    if let Some(obj) = manifest.as_object_mut() {
        obj.insert(
            "source".into(),
            json!({
                "case_id": case_id,
                "image_id": image_id,
                "image_format": image_format,
                "layer": "physical address space, decoded from the acquisition format",
                "evidence_sha256": source_sha256,
            }),
        );
    }
    let manifest_sha256 = {
        use sha2::Digest;
        let bytes = serde_json::to_vec(&manifest).map_err(|e| {
            ApiError::InternalServerError(format!("Failed to serialise the manifest: {e}"))
        })?;
        format!("{:x}", sha2::Sha256::digest(&bytes))
    };
    Ok(PreparedLayerExport {
        layer,
        plan,
        manifest,
        manifest_sha256,
        image_format,
    })
}

/// `GET /api/v1/cases/:id/memory/layer/:img/manifest`
///
/// The hole manifest of the image's decoded physical layer (or of
/// `?start=&end=` within it): every range of the export that will be fill
/// rather than acquired bytes, with its reason, and the totals. Writes nothing
/// and discloses no evidence bytes, so it is not audited. `manifest_sha256` is
/// the digest the raw export names in `X-Layer-Manifest-Sha256`; it is the
/// SHA-256 of `manifest` serialised exactly as this response carries it.
pub async fn get_memory_layer_manifest(
    Path((case_id, image_id)): Path<(Uuid, Uuid)>,
    AxumQuery(range): AxumQuery<LayerRangeQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let prepared = prepare_layer_export(&state, case_id, image_id, &range).await?;
    Ok(Json(json!({
        "case_id": case_id,
        "image_id": image_id,
        "image_format": prepared.image_format,
        "manifest": prepared.manifest,
        "manifest_sha256": prepared.manifest_sha256,
        "raw": format!("/api/v1/cases/{case_id}/memory/layer/{image_id}/raw"),
    })))
}

/// A `Write` that hands each chunk to the response body through a bounded
/// channel, so a 64 GiB layer is never more than a few chunks in memory.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx
            .blocking_send(Ok(axum::body::Bytes::copy_from_slice(buf)))
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the client stopped reading the export",
                )
            })?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `GET /api/v1/cases/:id/memory/layer/:img/raw`
///
/// The image's decoded physical layer (or `?start=&end=` within it) as a raw
/// file: file offset = address − start, acquired bytes where the acquisition
/// has them, zero fill where the manifest says it has none. Streamed in 1 MiB
/// chunks through a bounded channel. `Content-Length` is the planned size;
/// `X-Layer-Hole-Count`, `X-Layer-Hole-Bytes` and `X-Layer-Manifest-Sha256`
/// tie the file to its manifest.
///
/// A read that fails inside a range the manifest calls acquired aborts the
/// transfer instead of filling it, so the client sees a body shorter than
/// `Content-Length` — a fragment, never a file whose manifest understates its
/// holes. Audited as `memory_layer_exported` before the first byte leaves.
pub async fn get_memory_layer_raw(
    Path((case_id, image_id)): Path<(Uuid, Uuid)>,
    AxumQuery(range): AxumQuery<LayerRangeQuery>,
    Extension(user): Extension<crate::auth::AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<axum::response::Response, ApiError> {
    let prepared = prepare_layer_export(&state, case_id, image_id, &range).await?;
    let plan = prepared.plan.clone();

    crate::audit_required(
        &state,
        Some(case_id),
        &user.0,
        "memory_layer_exported",
        Some("memory_image"),
        Some(image_id),
        Some(&format!(
            "format={} range={:#x}..{:#x} bytes={} hole_bytes={} holes={} manifest_sha256={}",
            prepared.image_format,
            plan.start,
            plan.end,
            plan.total_bytes(),
            plan.hole_bytes(),
            plan.holes.len(),
            prepared.manifest_sha256
        )),
    )
    .await?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let layer = prepared.layer;
    let writer_plan = plan.clone();
    tokio::task::spawn_blocking(move || {
        let mut sink = ChannelWriter { tx: tx.clone() };
        if let Err(e) = seance_memory::export::write_export(layer.as_ref(), &writer_plan, &mut sink)
        {
            error!("memory: layer export of image {image_id} stopped: {e}");
            let _ = tx.blocking_send(Err(std::io::Error::other(e.to_string())));
        }
    });
    let body = async_stream::stream! {
        while let Some(chunk) = rx.recv().await {
            let failed = chunk.is_err();
            yield chunk;
            if failed {
                break;
            }
        }
    };

    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", plan.total_bytes().to_string())
        .header(
            "Content-Disposition",
            format!(
                "attachment; filename=\"memory_layer_{image_id}_{:x}-{:x}.raw\"",
                plan.start, plan.end
            ),
        )
        .header("X-Layer-Start", plan.start.to_string())
        .header("X-Layer-End", plan.end.to_string())
        .header("X-Layer-Hole-Count", plan.holes.len().to_string())
        .header("X-Layer-Hole-Bytes", plan.hole_bytes().to_string())
        .header("X-Layer-Manifest-Sha256", prepared.manifest_sha256)
        .body(axum::body::Body::from_stream(body))
        .map_err(|e| ApiError::InternalServerError(format!("Failed to build response: {e}")))
}
