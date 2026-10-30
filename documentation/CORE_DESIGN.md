# Seance Core Design & API Specification

**System:** Seance Digital Forensics Platform
**Architecture:** Zero-Copy, Pub-Sub Event Loop
**Status:** Core Specification

This document defines the core architecture, data models, module interfaces, and the public API of the Seance platform. It serves as the **Single Source of Truth** for the backend engine.

---

## 1. System Architecture

Seance is designed as a centralized **Service** (Daemon) that exposes a REST API. All user interaction (GUI, REPL, CLI) occurs strictly through this API.

### 1.1 Core Components
*   **Orchestrator:** The central engine managing the processing DAG. It handles multiple concurrent **Cases** and manages the task queue.
    **File hashes reach their file through the artifact writer.** A `file_hash` record is
    never persisted: its digests (or `hash_skipped` reason) are buffered and applied to the
    parent file's row on the writer's flush, retried while that row is not yet saved, for at
    most 60 attempts (~30 s). On giving up, the writer logs `EVIDENCE LOSS`, writes a
    processing-log row (status `error`) against the file carrying the digests, and holds the
    outcome in memory keyed by the file's artifact id — at most 65,536 files
    (`MAX_LATE_HASHES`). Every batch the writer saves afterwards is checked against that store:
    a held outcome whose file is in the batch is merged into that record and written by the
    same insert, in the same transaction, then dropped, and a second processing-log row
    (status `complete`) says the error row is superseded. Past the cap, across a
    restart, or when the record never arrives, the error row is the only record of the digests.
*   **Workspace:** All working files (databases, search indices) are stored in a defined `workspace` directory.
*   **Database Layer:** Persistence via **SQLite** (sqlx). **PostgreSQL** (Enterprise) is planned, not yet implemented.
*   **Search Engine:** Tantivy-based full-text search index over **artifacts**. Not timeline
    events: the orchestrator persists a `TimelineEvent` and never re-dispatches it, so the
    indexer never sees one, and `documentation/VALIDATION.md` measures the resulting gap
    (3,256 documents on the run recorded there).
    A schema change (a new indexed field) makes an existing on-disk index unreadable, and the
    service recovers by **wiping and rebuilding it from empty** — which would otherwise make
    every search answer "no matches" for a case full of evidence. So a service that rebuilt
    marks every search it serves `index_incomplete` with its counts as a floor, for the life of
    the process, until each case is re-indexed via `POST /cases/{id}/search/backfill`. It cannot
    know which cases have since been backfilled, so it over-discloses rather than under-.

### 1.2 Data Abstraction (Zero-Copy)
To allow efficient processing of massive forensic images without copying data:
*   **`DataSource` (Trait):** The fundamental contract (`read_at`, `size`). A source that
    knows its neighbours (a host file, a ZIP entry) says so with `supports_siblings()` and
    opens them two ways: `open_sibling(suffix)` for a name-suffixed neighbour (`-wal`,
    `.LOG1`) and `open_relative(path)` for one at a `/`-separated path relative to the
    source's own directory (`54/54e5…` beside an iOS backup's `Manifest.db`).
    A relative path that is absolute, climbs (`..`), or has an empty or `.` component is
    refused. Every other source returns `None` and `supports_siblings()` false, so "not
    there" and "could not look" stay distinguishable. A third, bounded reach —
    `open_from_ancestor(levels, path)`, answered where `supports_ancestors()` is true —
    climbs at most `MAX_ANCESTOR_LEVELS` (3) directories from the source's own directory
    and then descends a plain relative path, never a free walk. It exists so an Apple
    unified log reaches the rest of its tree (`../<XX>/…`, `../dsc/…`, `../timesync/…` in a
    `.logarchive`; `../../uuidtext/…` under `/var/db/diagnostics`; ROADMAP §1.6). A host
    file and a ZIP entry (and the API's content-resolver wrapper) answer it, a ZIP entry
    never climbing above its archive's root; every other source — a file inside a disk
    image included — answers `None` with `supports_ancestors()` false, and the caller says
    "tree not reachable, not decoded". A source that is nothing but bytes
    answers `resident_bytes()`, so the task queue can park those bytes on disk when it
    spills the artifact rather than holding them in memory behind the spill.
*   **`SiblingBundleSource` and `attach_sibling_bundles`:** a file inside a disk image has
    no path of its own, so a filesystem walker attaches its neighbours from the directory
    listing it already holds. Sidecars (`-wal`, `-journal`, `.LOG1/2`, `.LOG`) answer
    `open_sibling`; two named groups answer `open_relative` by bare file name,
    case-insensitively: Chrome's block files `data_N` in one directory, and a
    CIM repository's `OBJECTS.DATA`, `INDEX.BTR`, `MAPPING1/2/3.MAP`, `MAPPING.VER`,
    `INDEX.MAP` and `OBJECTS.MAP` in a `wbem/Repository` or `wbem/Repository/FS` directory.
    Deleted entries are never attached, and a name that occurs twice in one
    directory is attached to neither.
*   **`WindowSource`:** A view into a subset of a parent Source (offsets shifted). **No copying**.
*   **`SourceCursor`:** Adapter to standard `std::io::Read + Seek` for stream-based parsers.

### 1.2a The memory governor (`seance_core::memory_guard`)
The task queue bounds what is *queued*; nothing in the pipeline bounds what the workers
*hold*. The governor is the safety net under that: a process that is about to outgrow its
host must stop by its own decision, with a record, and not by the kernel's `SIGKILL`.

*   **Contract.** `MemoryGuard` is configured once per orchestrator from
    `SEANCE_MEMORY_LIMIT` (size, percent of `MemAvailable`, or `off`; default the smaller of
    the cgroup limit and 75% of `MemTotal`) and `SEANCE_MEMORY_GRACE_SECS` (default 30). A
    monitor task samples `/proc` and the cgroup files every 250 ms into a three-state
    `Pressure` (`Ok`/`High`/`Critical`, with hysteresis) that workers read with one atomic
    load. Each worker calls `admit()` after it pops a task: free at `Ok`, one task at a time
    at `High` (so the run never wedges waiting on something only a running task could clear),
    closed at `Critical`. At `High` the queue's resident window shrinks
    (`TaskQueue::set_window`, 64 artifacts) so new work spills at once; nothing is ever
    discarded.
*   **Stopping.** `Critical` with work outstanding for the grace period cancels every case
    that has work in the queue, through the same `CancellationHandle` an examiner's cancel
    uses. The terminal event is `ProcessingCancelled` (never `ProcessingComplete`), the
    ingest run closes as `cancelled`, and each source is stamped `inventory_incomplete` and
    `content_incomplete` with `incomplete_detail` = `MemoryStop::message(tasks_done)`:
    `stopped: memory limit reached at N GiB ..., N tasks done ... re-ingest with a higher
    SEANCE_MEMORY_LIMIT or fewer SEANCE_WORKERS`. A stop that precedes a case's first
    processed artifact is still recorded (otherwise the next start would sweep it as
    "interrupted" with no reason).
*   **What it counts.** Anonymous plus shared resident memory of the process, not
    file-backed pages (a large mapped image would otherwise read as a leak); the tightest
    cgroup limit on the process's cgroup or any ancestor; and host `MemAvailable`, which only
    counts once the process itself holds 1 GiB (`MIN_OWN_FOOTPRINT`).
*   **Observability.** Pressure transitions are logged at `warn` (up) and `info` (down);
    the run-end `memory governor:` line reports peak anonymous and resident memory, time at
    each state and stops. `Orchestrator::memory_guard()` exposes `pressure()` and `stats()`.
    `SEANCE_OOM_SCORE_ADJ` (opt-in, raise-only) sets `/proc/self/oom_score_adj`.
*   **Limits.** Sampling is periodic and cooperative. A single module that allocates past the
    budget between two samples is not caught, and memory a running module already holds is not
    reclaimed by pausing others. Platforms without `/proc` get no governor (logged once).
    Operator guidance is in `DEPLOYMENT.md`, "Memory limits, and not being OOM-killed".

### 1.3 Memory layers, and the `mapping()` contract

A `MemoryLayer` is a `DataSource` whose offsets are *memory addresses*. Beyond
reading, it can be asked to **project**: `mapping(offset, length)` returns the
runs that back an address range, which is what lets a caller ask "is this page
actually in the evidence?" without reading it, and what lets a virtual layer
agree with itself about where a page lives.

One property of that contract has caused a whole-subsystem failure and is worth
stating outside the code:

> **A returned run may begin below `offset` and may end above `offset + length`.**

A layer over a *compressed* acquisition has no choice. Its runs are
`Encoding::Encoded`, and an encoded run means "`mapped_length` bytes at
`mapped_offset` decode, as a single unit, to `length` bytes". Clipping such a run
to a sub-range would describe a blob that decodes to a different length than it
claims, and a caller slicing on that would cut in the wrong place. So the run
describes the whole frame, however few bytes were asked for.

**Therefore `covered_len(&runs) == length` is not the way to ask whether a
request was backed.** Summing run lengths answers a different question — how much
address space the runs describe, wherever it lies — and against unclipped runs it
both over-reports and says nothing about *which* bytes are present. It can be
false for a range that is entirely there, and true for one with a gap in the
middle.

Ask with **`MemoryLayer::is_valid`**, or with **`backed_len(&runs, start, len)`**
where the runs are already in hand. `backed_len` walks the requested interval:
a run beginning below the request or ending above it backs the part it covers,
and a gap stops the walk *where the gap starts*, which is what lets a caller
report a hole at the first unbacked byte rather than at a position implied by
arithmetic. `covered_len` remains, for the question it actually answers, and its
documentation says what it is not for.

A layer may override `is_valid` to answer from its own index without building a
run list — AVML and QEMU both do, and it is cheaper. That is an **optimisation
of a definition**, not a replacement for it: the override must agree with
`backed_len` over `mapping`, and each of those two layers carries a test that it
does, because two independent paths to one answer drift silently and only one of
them reaches the examiner.

This is not hypothetical. `VirtualLayer::require_acquired` summed lengths, and a
64-byte read inside a 64 KiB compressed frame was told the coverage was 65,536,
refused for not being 64, and reported a hole 64 KiB past the address asked for.
The effect was that **no Linux memory image in the format `avml` writes by
default could be profiled at all** — the final step of the page-table proof reads
the kernel banner back through the proved tables, and that read returned a hole
while the translation underneath it was entirely correct.

Both sides were individually right: the layer returned exactly what it documents,
and the caller asked a well-formed question. That is why unit tests on either
side could not see it, and why the contract belongs in a design document and not
only in a doc comment on the function that honours it.

**Translation regimes.** A `VirtualLayer` is built
over one `PagingSpec`, and a `PagingSpec` is one `PagingMode` under one
`PteSemantics`. `PagingMode::Arm64(Arm64Regime)`
adds VMSAv8-64 stage-1 translation with the regime — granule (4 / 16 / 64 KiB),
`TTBR0` or `TTBR1`, and a 25..=48-bit width — fixed by a checked `const`
constructor, so **each ARM64 regime is its own `VirtualLayer`**, canonical only in
its own half of the address space, and a walker never guesses which table a
tagged or out-of-half address belongs to. Both the upward walk and the downward
enumeration ask one classifier, `PagingSpec::classify(entry, level) ->
Option<EntryKind>` (`Invalid` / `Table` / `Leaf { frame, size_log2, no_execute }`
/ `Unnameable { detail }`), driven by the level's `LeafRule`, in place of reading
bit 7, bit 1 or bit 12 themselves. The layer's metadata names the regime
(`arm64_granule`, `arm64_ttbr`, `arm64_va_bits`) and `PagingSpec::min_virtual_address`
gives the half's floor. The full contract — what is refused (FEAT_LPA/LPA2
descriptors, reserved encodings), what is deliberately not claimed (a Linux swap
entry versus `PROT_NONE`, any Windows-on-ARM64 PTE convention beyond build 28000's, `MEM-ARM-8`), and that every
ARM64 fixture is synthetic because no ARM64 capture exists here — is in
[MEMORY_BUILD_BINDING.md](MEMORY_BUILD_BINDING.md), beside the binding it
sits under. A regime can also be built from a recorded
`TCR_EL1` (`Arm64Regime::from_tcr_el1`), which enforces `IPS` (an output address above it
is refused as an Address size fault), honours `TBIn` for a tagged pointer, and folds
hierarchical `PXNTable`/`UXNTable` into `no_execute` unless `HPDn` disables them; `DS = 1`
(LPA2) is refused by name. Linux discovery now offers the arm64 kernel regimes to its
banner proof (`LINUX_DESIGN.md`); Windows discovery does not run on the primitive. No
ARM64 image has been analysed end to end, because no arm64 symbol table is held. On Intel,
`no_execute` is the leaf's XD OR'd with every non-leaf entry's XD above it (SDM 4.6), as
the hardware applies it.

---

## 2. The Artifact System

The **Artifact** is the universal currency exchanged between modules.

### 2.1 Artifact Structure
```rust
pub struct Artifact {
    pub id: Uuid,
    pub case_id: Uuid,          // Links artifact to a specific investigation
    pub parent_id: Option<Uuid>, // Chain of custody / Lineage
    pub artifact_type: ArtifactType,
    pub data: Option<Arc<dyn DataSource>>, // Lazy Data Source (Zero-Copy)
    pub metadata: serde_json::Value,       // Structured metadata
}
```

### 2.2 Artifact Types

The artifact type hierarchy follows the natural forensic processing flow:

**Evidence Levels (Processing Order):**
*   `Container`: Forensic containers that wrap other data (E01, ZIP, TAR, AFF4, 7Z, RAR)
*   `RawEvidence`: Raw storage devices or disk images (DD, VHD, VMDK, physical disks)
*   `Partition`: Defined region of a disk (MBR partition, GPT partition)
*   `FileSystem`: Identified filesystem (NTFS, Ext4, FAT32, APFS, HFS+, exFAT)
*   `FileEntry`: File record with metadata (path, timestamps, permissions)
*   `FileContent`: The actual bytestream content of a file

**Regions (byte windows handed to carving and scanning):**
*   `UnallocatedSpace`: Space a partition table leaves between partitions, or a run of clusters
    a filesystem's own allocation map calls free (`seance_core::free_space`)
*   `SlackSpace`: The unused tail of one live file's last allocated cluster — from the file's
    logical end to the end of that cluster — published by the NTFS, FAT, exFAT, ext4, HFS+ and APFS parsers
    (`seance_core::slack`). Parented to the `FileSystem`; `offset_bytes` and
    `size_bytes` are in the volume's coordinates, as a free region's are, and the region names
    its owner (`parent_file`, `parent_path`, `owner_artifact_id`) and carries
    `source: "file_slack"`, `region_kind: "slack"` and a `slack_means` sentence. It is its own
    type, not a tagged `UnallocatedSpace`, because slack is allocated: no free-space total may
    count it. One per live file whose tail holds any non-zero byte, at most 250,000 per volume,
    with one `slack_space_summary` `ParsedRecord` per volume counting what was offered, emitted,
    all-zero, unreadable and past the ceiling, and `files_not_located`: live files with a tail
    that were never offered because the parser could not locate it (compressed or encrypted
    runs, a run list or chain incomplete or shorter than the file). `offered` equals
    emitted + all-zero + unreadable + past-ceiling.

**Artifact Types (Analysis Results):**
*   `SystemArtifact`: Forensically interesting system files ($MFT, Registry, EVTX, SQLite databases, Plists, etc.)
*   `ParsedRecord`: Parsed structured records (chat messages, browser history entries, email messages)
*   `TimelineEvent`: Final normalized events for timeline UI

**Subtypes (Optimization):**
Artifacts can include an optional `subtype` field in their metadata for fast-path filtering:
*   Container subtypes: `"e01"`, `"zip"`, `"tar"`, `"aff4"`
*   Partition subtypes: `"ntfs"`, `"linux"`, `"fat32"`, `"swap"`
*   FileSystem subtypes: `"ntfs"`, `"ext4"`, `"fat32"`, `"apfs"`, `"exfat"`, `"iso9660"`, `"udf"`
    (the partition layer lowercases the detected name; this list is illustrative, not exhaustive).
    A disc carrying both `iso9660` and `udf` (a UDF bridge) gets one `FileSystem` artifact for each,
    both stamped `udf_bridge: true`. It gets no `filesystem_overlap` / `hidden` / `overlap_warning`
    keys, because the pair is by design and not one filesystem hiding another.

Modules check the subtype field first to skip processing instantly without I/O operations.

### 2.3 Record contracts that carry a forensic distinction by type

A handful of `ParsedRecord` shapes exist so that a claim about the evidence
cannot be lost by a consumer forgetting to check one flag. They are listed here
because the distinction is the contract; the per-platform design documents
describe what each parser reads.

**Recovered against live, by `type`.** A record recovered from space the live
structure no longer vouches for is a **different type** from its live
counterpart, never the live type with a boolean:

| Live | Recovered | Producer | The distinction it carries |
|---|---|---|---|
| `EvtxLogEntry` | `EvtxRecoveredLogEntry` | `plugin.windows.evtx_parser` | `recovered: true`, `recovery_source` in `carved_chunk` / `chunk_slack` / `loose_record`, the chunk's offset, header state and both CRC32 states, `partial` with `incomplete_substitutions` by index, `rendered_with_borrowed_template` with the `borrowed_template` block, `record_id_also_read_live`. One `EvtxRecoveryStatus` per input: `bytes_declared` / `bytes_scanned` / `short_read`, every chunk, record, loose-record and template tally, every ceiling under `limits` with a `*_bound_hit` beside it, a `chunk_listing` by offset with its own bound and omitted count, `inventory_incomplete`, `content_incomplete` with its reason list, `counts_are_floor`. |
| `RegistryKey` / `RegistryValue` | `RecoveredRegistryKey` / `RecoveredRegistryValue` (and a `Recovered Registry Key Last Written` timeline event) | `plugin.windows.registry_parser` | `evidence_state: recovered`, `recovered_from: "unallocated hive cell"`, `bin_offset`; on a key `key_path` with `key_path_is_inference: true`, `key_path_complete`, `key_path_parent_offset_unresolved`, `key_path_basis`, the subkey and value counts *as declared*, `live_namesake` with a note; on a value `data_basis` (inline, from a still-allocated cell that may have been reused, or unread with the reason) and `tombstoned`. The hive record's `recovered_cells` summary carries `examined_cap` (200,000) / `examined_capped` and `records_cap` (50,000) / `records_capped`. |
| `AsepEntry` | `RecoveredAsepEntry` | `seance_plugin_asep` | An autostart entry whose `evidence_state` is `recovered`: one read from an unallocated hive cell, or a WMI subscription record found in `OBJECTS.DATA` bytes no page descriptor references. A WMI record a descriptor does reference is an `AsepEntry` in state `allocated_record`; with no page mapping beside the file `repository_liveness` is `not_established`; with the mapping and `INDEX.BTR` it is `indexed` or `listed_not_indexed` (the latter, `evidence_state: unlinked`, is published as `RecoveredAsepEntry` too), and with the mapping alone `in_mapped_page_index_not_read`. |
| `JumpListStream` | `JumpListCarvedShortcut` | `plugin.windows.jumplist_parser` | `recovery_method: ole_directory` against `signature_carve`: a shortcut the container's directory names against one found by scanning bytes. |

**A histogram that states its own ceilings.** `FeatureHistogramSummary`
(`plugin.bulk.features`, subtype `summary`, one per scan that found at least one
hit): `total_hits` (every hit, dropped ones included), `distinct_values`,
`hits_dropped`, `capped` with `max_distinct_values` (100,000) named on the
record, `top_n` (100) and `top` (up to 100 `{kind, value, count}`, most common
first, ties by kind then value), `top_omitted` = `distinct_values − top.len()`,
`by_kind` (`{kind: {hits, distinct_values}}`, hits summing to `total_hits`),
`bytes_scanned` (the bytes the sweep actually covered, not its limit),
`source_size`, `scan_capped`, `short_read` (some range below the limit would not
read; when set, `content_incomplete: true` with reason `short_read` and a
`content_incomplete_detail`), `unreadable_ranges`
(each `{offset, length}` the source would not deliver, byte-exact, at most
1,024 listed), `unreadable_range_count`, `unreadable_ranges_listed_all` and
`unreadable_bytes`. The sweep steps over an unreadable range
(a gap in a memory image, a bad sector) and resumes on its far side, so
`bytes_scanned` is every readable byte, not a prefix; the same coverage fields
are on `FeatureSummary`, `RecoveredKeySummary` and `NetworkCarveSummary`), and a
`note` that, when capped, states the ceiling and the exact number of hits not
tallied and that the distinct total is a floor. The report renders it under
those rules (`REPORTING_DESIGN.md`).

**A parser saying it may be behind the app.** Every SQLite app parser declares
the schema version range it was validated on and resolves each column it reads
through a candidate list; the disclosure is a `ParsedRecord` whose `status`
names what was found. Every record, whichever shape, speaks **one vocabulary**
(`ROADMAP` §5.11): `subtype: "parser_stale"`,
`warning_class: "ParserStaleWarning"`, and the same `status` for the same
finding — `SchemaOutsideValidated` (newer or older is in the sentence),
`SchemaVersionNotRecorded`, `SchemaVersionUndetermined`, `SchemaFieldsUnresolved`,
and, where a shape can reach them, `SchemaNotRanged` (no range declared),
`SchemaOptionalFieldsUnresolved` and `SchemaTableAbsent`. A record claims
incompleteness by its `content_incomplete` pair, never by its subtype. The
per-app `<App>Incomplete` record type is kept where a shape has it. One further
status is emitted for a different finding: `SchemaUndetermined`
is the catalogue-probe marker of `seance_sqlite_util::SchemaProbe` (WhatsApp,
iMessage, Android apps), filed under the parser's `<App>Incomplete` type with
`subtype: "parse_incomplete"` and both incompleteness pairs, when a table or
column probe would not answer. It says the store's structure could not be read,
not anything about its version, and it is outside the vocabulary above. Four shapes
remain, because their fields differ, and each is one shared module in
`seance_sqlite_util::adopt`: `app_marker`, `note_marker` and `stale_marker`
and `inline_marker` (iMessage passes
its `_ClientVersion` range to it):

| Shape (crates) | `type` / `subtype` | Statuses | Fields |
|---|---|---|---|
| WhatsApp, Telegram, Signal, Viber, Kik (`adopt::app_marker`) | the parser's own `<App>Incomplete` / `parser_stale` | `SchemaNotRanged`, `SchemaOutsideValidated`, `SchemaVersionNotRecorded`, `SchemaVersionUndetermined`, `SchemaOptionalFieldsUnresolved`, `SchemaFieldsUnresolved` — only the last stamps `content_incomplete` (reason `unvalidated`) | `app`, `source_table`, `schema_version_locator` (`user_version` / `coredata_model`), `schema_version_seen` / `schema_version_recorded` / `schema_version_detail`, `schema_version_supported` + `schema_version_evidence` or the unranged reason, `schema_unresolved_fields`, `records_recovered`, `message`, `detail`. **All five are `Unranged`**: no readable real database of any of them is held, so no range was invented. Signal emits one per message table walked. |
| Snapchat, Skype, LINE, WeChat, Instagram (`adopt::note_marker`) | `<App>Incomplete` / `parser_stale`, a disclosure and a claim alike | disclosures `SchemaOutsideValidated`, `SchemaVersionNotRecorded`, `SchemaVersionUndetermined`, `SchemaNotRanged`, `SchemaOptionalFieldsUnresolved` (no `content_incomplete`); claims `SchemaFieldsUnresolved`, `SchemaTableAbsent` | `app`, `store`, `table`, `schema_version_seen` / `schema_version_not_recorded` / `schema_version_undetermined`, `schema_version_supported` + `schema_version_evidence` or `schema_unranged_reason`, `schema_unresolved_fields`, `records_recovered`, `detail`. Snapchat `arroyo.db` 102..=102 and `main.db` Friend 427..=427; Skype 66..=66; LINE, WeChat, Instagram unranged. |
| Android SMS, call history, iMessage, Twitter, Messenger (`adopt::inline_marker`; Messenger uses only its field-drift marker) | `ParserStaleWarning` / `parser_stale` | `SchemaOutsideValidated`, `SchemaVersionNotRecorded`, `SchemaVersionUndetermined`, `SchemaFieldsUnresolved` | `app`, `supported_range`, `seen_schema_version` (on the version statuses), `source_table`, `unresolved_fields`, `records_recovered` (on the field status), `content_incomplete_reason` / `_detail` (on the claiming statuses only — `SchemaOutsideValidated` is a disclosure and carries neither), `detail`, `name`, and `validated_against` naming the evidence file(s) on every version status that states a range. Ranges: `mmssms.db` `user_version` 57..=67, `calllog.db` 5..=5, `contacts2.db` calls 1..=1, iMessage `_ClientVersion` 9005..=15009, Twitter main DB 7..=59; Messenger, Twitter search DB and iOS `CallHistory.storedata` (Core Data, no numeric version) have no window. |
| Contacts, installed apps, browser history, Android apps, mobile device (`adopt::stale_marker`), and the iOS Safari and HealthKit readers through `check_schema_version` | `ParserStaleWarning` / `parser_stale` | `SchemaOutsideValidated`, `SchemaVersionNotRecorded`, `SchemaVersionUndetermined`, `SchemaFieldsUnresolved` | `app`, `store`, `parser_record_type`, `supported_range`, `validated_against`, `seen_schema_version`, `chromium_last_compatible_version` (Chrome), `source_table`, `unresolved_fields`, `present_columns`, `records_recovered`, `message`, `detail`, and the incompleteness pair on `SchemaVersionUndetermined`, `SchemaFieldsUnresolved`, and on `SchemaOutsideValidated` **only** for a Chromium store whose own `meta.last_compatible_version` is past the validated maximum (the store states that a reader written for this parser's schemas cannot read it). Locators: `PRAGMA user_version`, Chromium `meta.version`, Apple `_SqliteDatabaseProperties._ClientVersion`, FrontBoard `schema(version)`. |

Two rules every shape honours: `PRAGMA
user_version` **0 is "not recorded"** — SQLite's unset default, and what every
genuine Chromium, Apple Core Data and Skype store here reads — never "older than
the range"; and a version outside the range is a **disclosure**, while only a
required column no candidate resolved, or an absent table, is a claim of
incompleteness. Most validated ranges are a
single point because one to four real stores are held per app, so a claim on
every newer version would mark stores whose every column still resolves as
incomplete — with one exception, the Chromium `last_compatible_version` floor
above. The shared `seance_sqlite_util::stale` path honours the first
rule too: `check_schema_version` returns a
`SchemaVersionCheck` whose version is `Found`, `NotRecorded` (0) or
`Undetermined` (the pragma would not read), and its `marker` files a
`ParserStaleWarning` / `parser_stale` record for every answer but an in-range
version — `SchemaOutsideValidated` (no claim: a disclosure),
`SchemaVersionNotRecorded` (no claim) or
`SchemaVersionUndetermined` (reason `unresolved_structure`) — with `status`,
`schema_version_locator`, `supported_range`, `validated_against`, `message`,
`detail` and `name`. The iOS Safari and HealthKit readers use it; the four
groups above still wrap `StaleWarning` in their own records (their unification
is `ROADMAP` §5.11). `TempDb::stamp_incompleteness` does not overwrite a
`content_incomplete_reason` a record already carried: the record's reason stays
primary, both are listed in `content_incomplete_reasons`, and the spill's
reason is appended to the record's `content_incomplete_detail`.

---

## 3. Module Interface (Plugins)

Modules are stateless workers implementing the `ForensicsModule` trait.

### 3.1 Trait Definition
```rust
pub trait ForensicsModule: Send + Sync {
    fn id(&self) -> &str;
    fn version(&self) -> &str;
    fn subscribes_to(&self) -> Vec<ArtifactType>;
    fn input_capability(&self) -> InputCapability;
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError>;
    // Optional; the default calls `process` and sinks nothing.
    fn process_streaming(
        &self,
        artifact: &Artifact,
        sink: &mut dyn FnMut(Vec<Artifact>),
    ) -> Result<Vec<Artifact>, ModuleError>;
}
```

**Streaming output.** `process` returns one `Vec` for the whole artifact, so a
module that walks a whole volume holds everything it found until the walk ends: memory that scales
with the evidence, not the work in flight. A module whose output is large and independent of the
rest of its own output overrides `process_streaming` and passes each full batch to `sink`. The
orchestrator dispatches a sunk batch exactly as a returned one (persisted; re-queued unless it is a
`TimelineEvent`) and counts it in the module's yield. A sunk batch is final and must not need any
later whole-set step of the module's own, and must not contain `file_hash` records. The hand-over
is bounded: the sink waits when the artifact writer has more than four messages pending, so a
module that outruns the database stops instead of piling output up. A failed module keeps the
batches it already sunk, and a dispatch that has streamed is not retried (a retry would record
them twice). The MFT parser streams its timeline events; every other module keeps `process`.

### 3.2 Input Capabilities

**Advisory, not dispatch.** The orchestrator does not read `input_capability()`
and prepares nothing on a module's behalf: every module receives the artifact's
`DataSource` as it is and arranges its own access. The value documents how a
module intends to read, and tests assert it, but nothing branches on it — see
the note on `InputCapability` in `seance_core/src/module.rs`, which is the
authority.

*   `Stream`: the module reads through a `SourceCursor` (Read + Seek). Declared by
    ZIP, registry and most file parsers.
*   `RandomAccess`: the module reads the raw `DataSource` at offsets. Declared by
    the file-system parsers.
*   `SqliteVfs`: **deprecated, declared by nothing.** No VFS shim exists.
    SQLite-backed parsers declare `Stream` and spill to a temporary file through
    `seance_sqlite_util::TempDb`.
*   `FilePath`: the module needs a real path because it hands the data to a
    library that only opens files. **The framework does not spill for it**: the
    module either refuses without a `path` in the artifact's metadata
    (`seance_container_e01` and `seance_container_aff4` both do, and neither
    spills anything) or writes and removes the temporary file itself
    (`seance_plugin_ios_backup`, the spill exemplar).

### 3.3 Execution Control (Profiles & Ad-Hoc)
To prevent "greedy" processing (e.g., carving 2TB of unallocated space when unwanted), Seance uses **Ingestion Profiles**.

*   **Ingestion Profile:** A per-case `IngestionProfile` naming a **whitelist**
    of module IDs to run automatically. Two built-ins ship — `triage` (fast,
    essential modules) and `deep` (all modules) — plus user-defined `custom`
    profiles. Profiles are stored per case and managed through the profiles API
    (`/api/v1/cases/{id}/profiles`). Module IDs must match each module's
    `ForensicsModule::id()` exactly. Server-level configuration (bind address,
    workspace, secrets) is supplied via environment variables — see
    `DEPLOYMENT.md`.
*   **Ad-Hoc Execution:** Users can manually trigger specific modules on individual artifacts via the API/GUI.
    *   *Single Item:* "Run Carving on this Partition only."
    *   *Bulk Type:* "Run Carving on all Partitions in this case."
    *   *Across a restart:* an ad-hoc job is a row in `ad_hoc_jobs` and an entry in the
        orchestrator's in-memory queue. The queue does not survive the process. When an
        orchestrator starts it marks every job still `pending` or `running` — created at or
        before its own start — as `failed`, with a message saying the process stopped before
        the job finished and that jobs are not resumed
        (`DatabaseConnection::fail_interrupted_jobs`, called from `Orchestrator::run`). A
        job shown as running is therefore one the running server is doing.


### 3.4 Detection modules, and the two that cannot be modules

A **detection module** raises an investigative lead instead of transcribing an
artifact. `seance_plugin_findings` holds them, and the contract is narrower than
`ForensicsModule` alone:

*   **It detects nothing.** Every signal a lead rests on is already established
    by the parser that read the format — the MFT parser weighed the `$SI`/`$FN`
    asymmetry against the copies and renames that produce it innocently, the PE
    plugin checked Authenticode and measured section entropy, ASEP categorised
    the autostart. A detection module reads what a parser **concluded** and
    raises a lead. A second implementation of a signal would drift from the
    first, and the first is the one with a measured false-positive rate; two
    numbers for one fact, from one tool, is indefensible on the stand.
*   **It subscribes to `ParsedRecord` and reads no bytes.** `InputCapability` has
    no variant for "metadata only" (and is advisory rather than dispatched, §3.2),
    so these declare `Stream` and open nothing.
*   **Its output is an ordinary `ParsedRecord`** whose `type` is `Finding`, so a
    lead reaches the database, the search index, the record viewers and the
    pivot through the paths that already exist. `Finding::to_metadata` is the
    only writer, so a new detection cannot ship without its grade or its
    qualification.

**Two of the detections are not modules, and cannot be.** "Is this program's
file anywhere on the volume" and "does the MFT still describe the file the
journal deleted" are questions about the *whole case*. A module sees artifacts
as they are produced, so one resolving the first against an index built as the
walk proceeds would answer from whatever had been walked when the prefetch file
happened to be parsed — and "no file entry for this program" would be true of
most of a healthy `System32` until the walk finished. A false absence is the
defect class this project treats as HIGH. So those two run over the completed
populations when the triage list is requested, the way the Connections and
Duplicates views already do, and the rules themselves
(`seance_plugin_findings::cross_view`) are pure functions over the populations
rather than over a case. The cost is stated rather than hidden: those rows are
not artifacts, so they do not reach search, the timeline or the pivot, and the
response marks them `persisted: false`.

---

## 4. REST API Specification

**Base URL:** `http://localhost:8080/api/v1`
**Content-Type:** `application/json`

### 4.1 Case Management
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases` | List all cases. |
| `POST` | `/cases` | Create a new case. Body: `{"name": "Case 1", "examiner_name": "..."}` |
| `GET` | `/cases/{id}` | Get case details and stats. |
| `PUT` | `/cases/{id}` | Update case metadata. |
| `DELETE` | `/cases/{id}` | Delete case and all associated artifacts. Returns `202 Accepted` with `{"case_id", "status": "deleting"}`: the case is marked at once — gone from `GET /cases`, and every `/cases/{id}/…` route answers 404 — and its rows are removed in the background in batches, then its search documents, then the `case_deleted` audit row. A deletion a restart interrupts resumes at the next startup. |

### 4.1a Identity and display preference
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/auth/me` | Who this session is, and how they want to see it. Carries `theme` alongside `username`, `role` and `must_change_password`. |
| `PUT` | `/auth/theme` | Remember this user's chosen skin. Body: `{"theme": "<skin>:<mode>"}`, or `{"theme": null}` to go back to following the build's default. |

Three things about `theme` are decisions rather than details.

**It rides on `/auth/me` rather than having a `GET` of its own.** The request that
says who you are says how you want to see it, so a client reconciles its cached
copy with no extra round trip — and paints the examiner's own palette on the
first frame rather than the default swapped a moment later.

**The server validates the shape and not the catalogue.** `<skin>` is 1–32
characters of `[a-z0-9-]` and `<mode>` is exactly `light` or `dark`; which skins
exist is the web UI's knowledge, because it holds the palettes. A server that
also held the list would need a redeploy to add a skin, and would reject a newer
client's perfectly good choice in the meantime. A client that reads back a skin
it does not recognise falls back to the default, which is what it does for a
user who never chose. What the server *is* answerable for is that a value it
stores and hands back to every session that user opens cannot be unbounded and
cannot carry anything but a name.

**`null` and "the default" are different answers.** `null` means the user has
never chosen and follows whatever this build ships; a stored value that happens
to name the current default means they chose it, and it stays chosen if the
default ever moves.

**Session invalidation is three stamps on the user row**, and the middleware refuses a
token whose `iat` is at or before any of them: `password_changed_at` (credential rotation), `sessions_invalid_before` (stamped on deactivation and never cleared, so
reactivating an account restores the account and not its sessions, and stamped at
creation to the second *before* it, so a deleted-then-re-created username cannot revive
tokens minted for the old account while a token minted in the row's own first second is
still accepted), and per-token revocation on logout. `<=` rather than `<` in every case,
because both sides are whole seconds and a token minted in the same second as the stamp cannot
be told from one minted just before it. The SSE `/events` stream re-runs the same check on its
periodic tick and ends the stream on failure, so a revoked or deactivated session does not keep
receiving events for the life of a connection it opened while it was live.

`PUT /auth/theme` writes against the **authenticated** identity. There is no
user field in the body, so it cannot be pointed at another account. The
bootstrap administrator (the env-admin identity, which has no row in `users`)
gets a `409 NO_USER_RECORD` saying there is nowhere to store a preference,
rather than a success that silently forgets.

### 4.2 Ingestion
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/cases/{id}/ingest` | Ingest data source. Body: `{"path": "...", "artifact_type": "RawEvidence"}`, plus `memory_image: true` (or `memory_image_format`) to declare a headerless capture of physical memory — without it the memory pipeline does not claim the source, because a file name is not evidence. The response is `{artifact_id, status}` and, when there is something the operator must act on, `notes`: a memory-shaped source ingested without that declaration is named there, since otherwise the case fills with nothing and the reason reaches only the server log. A body naming `artifact_type: "RawEvidence"` no longer overrides the file's own signature: a source whose bytes name a container (E01, ZIP, …) is ingested as that container, and a headerless raw image stays `RawEvidence`. Omit `artifact_type` to let detection decide throughout. |
| `GET` | `/cases/{id}/stats/sources` | The root data sources with the artifact count derived from each. Per row: `source_artifact_id`, `name`, `name_resolved` (false when the root walk did not return the source's own record, so `name` is the bare id), `artifact_count`, `integrity_state` and `acquisition_error` (absent for a source that carries no acquisition state), `acquisition_note` (the sentence the count has to be read against: a count of 0 beside `verifying` means not processed yet, and beside `acquisition_failed` means the exhibit is held without a baseline), and `processing_state` with `processing_note` (set when the walk was `interrupted` or `cancelled`, so the count is what was recorded before it stopped). The names come from a drained root walk and the response states when that walk was not whole. The counts come from their own aggregate query. There is no separate sources listing route. |
| `GET` | `/cases/{id}/acquisitions` | Ingest attempts for this case: running now, unresolved, and failed — see below. |

**The ingest audit vocabulary is three actions.**
The API does not write the legacy event `evidence_ingested` before the acquisition
hash runs, because on a case where the hash then failed it would assert an ingest
that never completed. The vocabulary is:

| Action | Written by | Witnesses |
| :--- | :--- | :--- |
| `evidence_ingest_requested` | the API, at request time, naming the requester | that an ingest was **asked for**. Mandatory. |
| `evidence_ingest_completed` | the background task in `seance_core::ingestion` | that it finished. |
| `evidence_ingest_failed` | the same task | that it failed, with the detail. |

The two outcome events pair with the request by `resource_id` (the artifact ID),
which is what lets an attempt with no outcome be told apart from one that
finished. **`evidence_ingested` is still read** — attempts recorded by an older
build are part of the case and must not vanish — but only ever as "an ingest was
requested", which is all it ever witnessed.

`GET /cases/{id}/acquisitions` is the endpoint that answers what a client not
connected at the time cannot: acquisition hashing of a large exhibit produces no
completed evidence while it runs, and its progress went out only on the live
event stream. It reports three populations, separately because they are known in
different ways — `in_flight` (attempts **this server process** is carrying, with
live progress), `unresolved` (a request with nothing on the record after it: no
outcome event, no acquisition baseline, not running here) and `failed` (failure
on the record, newest first). An `unresolved` entry says which kind of unknown it
is: `no_outcome_recorded` — a build that would have written an outcome and did
not, which is what a server stopped mid-acquisition leaves behind — or
`predates_outcome_events`, a request under the old name by a build that wrote no
outcome events at all, where the silence says nothing whatsoever. Attempts
resolved by an outcome event or by a recorded `evidence_acquisition_hashed`
baseline appear in none of the three and are counted, so the populations still
add up. The scans are bounded, and the response states whether a scan **filled
its window** — a full scan proves older events exist that it did not read, so no
count in the response may be read as a case total. The audit log remains the
complete record.

Acquisition is the hash; **processing is the walk**, and the same response
carries `processing_runs`: one row per ingest run from the
`ingest_runs` table — `source_artifact_id`, `source_label`, `started_at`,
`finished_at`, `status` (`running` · `completed` · `cancelled` ·
`interrupted`), `artifacts_recorded`, `detail` — newest first, with
`processing_runs_unfinished` counting the cancelled and interrupted ones. A row
is opened when a root exhibit is queued and closed when the orchestrator goes
idle for its case; a row still `running` when the server next starts was left
by a stopped process and is marked `interrupted`, with the source's subtree
count as it stood. The source artifact is then stamped `processing_state`
plus the standard `inventory_incomplete` / `content_incomplete` pair with
reason `ingest_interrupted` and an `incomplete_detail` sentence, so the
incompleteness census, the report's Limitations and every screen that offers
the source say the walk did not end. `GET /cases/{id}/stats/sources` carries
`processing_state` and `processing_note` on each row for the same reason: the
artifact count beside an interrupted source is what was recorded before it
stopped, not what the source holds. A source with no run recorded — ingested
before runs existed — carries neither field, which is not a statement that its
walk finished.
`GET /cases/{id}/source_kinds` reads the same walk state for the mobile
source-type label (ROADMAP §1.4) — the root's `processing_state` stamp first,
the ingest-run table only for a root without one — and states the absence of every mobile marker
(`none_recognised`) only for a source whose walk `completed` and that has
records under it; a source with no recorded run is `not_assessed`.

### 4.3 Artifacts & Content
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/artifacts/{id}` | Get artifact details. A file carried in a backup container gets a `metadata.provenance` block, resolved from its parent container artifact first and from the container name second. When the name matches containers with different origins the block carries `origin_ambiguous: true` and a `note` instead of an app or correspondent. |
| `GET` | `/cases/{id}/artifacts/{id}/children` | List child artifacts. Params: `page`, `page_size`. |
| `GET` | `/cases/{id}/artifacts/{id}/content` | Download/Stream content. |
| `GET` | `/cases/{id}/artifacts/{id}/hex` | Get hex dump. Params: `offset`, `limit`. |
| `POST` | `/cases/{id}/sqlite/query` | One read-only SQL statement over the **staged copy** of a SQLite database artifact, never the evidence file (`ROADMAP` §1.3). Body: `artifact_id`, `sql`, `max_rows` (default 1,000, at most 10,000), `timeout_ms` (default and ceiling 10,000). The artifact's bytes and its `-wal` sibling, where the source can reach one, are staged to a temporary file exactly as the SQLite parsers stage theirs (512 MiB ceiling; a larger file is staged as a prefix and the answer says `content_incomplete: "cap_reached"`), the copy is opened `SQLITE_OPEN_READONLY` under an authorizer that admits only reads, and the statement runs under the row ceiling and timeout. Response: `columns`, `rows`, `row_count`, `row_cap`, `capped` (at least one more row existed), `elapsed_ms`, `timeout_ms`, `read_only: true`, `source: "staged_copy"`, `artifact_id`, `database`, `content_incomplete`, `wal_incomplete` — every attestation a screen may print is a field, not a convention. Integers past 2⁵³ travel as strings. Refusals carry codes the editor keys on: `sql_not_single_statement`, `sql_not_readonly`, `sql_error`, `sql_timeout` (400) and `not_a_sqlite_database` (404 — a record with no bytes of its own, or a file not starting with the SQLite header). Every run, answered or refused, is audited with the statement (first 2,000 characters) and its outcome. |
| `GET` | `/cases/{case_id}/files` | The case-wide file grid (filtered/sorted/paged). |
| `GET` | `/cases/{case_id}/sources/{source_id}/files` | The same grid, scoped to one source. |

**`unique_only` on the file-listing endpoints (§2.8).** `?unique_only=true` lists
only the files the case can **demonstrate** are one of a kind: their SHA-256 is
carried by no other artifact in the case.

Uniqueness is decided by that hash, so a file is one of *three* things — shown
unique, shown duplicated, or carrying no hash and therefore neither — which is
why `seance_db::UniqueFilter` has three variants rather than being a bool. The
third is the one that must not be folded into either answer: listing an unhashed
file under "unique only" presents an unknown as a finding, and dropping it
silently makes the grid's count read as *the* unique files in the case when it is
a floor on them. So those files are excluded, and the response carries a `unique`
block — `unassessable` plus the sentence a screen shows — counted over the same
scope and the same filters as the listing, not an approximation of them. An
absent block means the filter was not applied, never that it was applied and set
nothing aside.

**`filter_id` on the two file-listing endpoints.** Either grid may be opened on a
**saved compound filter**: `?filter_id={uuid}` resolves the filter to a set of
artifact ids **through the same evaluator `GET /filters/{id}/apply` runs**, and
the grid then lists exactly that set — with the grid's own paging, sort,
selection and export, which the apply endpoint's listing never had. One evaluator
rather than two is the point: a grid and an apply that disagreed about what a
filter means would put two different populations on screen under one name. Every
other parameter still applies and **narrows** the result further; nothing widens
it, so the case scope holds.

A filtered grid is a population-defining instrument pointed at rows an examiner
will bulk-tag, export and testify about, so the response carries a `filter` block
rather than a bare count. Three different things can make it short of the
filter's real matches, they are repaired by three different actions, and so they
are three fields and not one `incomplete` flag:

* `scan_complete: false` — the scan stopped at its ceiling. Matches past it were
  never examined and `matched` is a lower bound.
* `population_capped` — the matches exist and were counted, but the grid holds
  only the first `population_cap` of them.
* `undecodable` — rows inside the scan that could not be evaluated. The filter
  was never tested against them, so they are neither matches nor established
  non-matches, and no amount of paging recovers them.

`matched` counts artifacts of **every** type; `listed` is how many of them this
grid can show, since a file grid shows `FileEntry` rows only. A filter that also
matched registry records or messages legitimately lists fewer rows than it
matched, and the difference is stated rather than left to look like rows going
missing. `inventory_incomplete` plus `inventory_incomplete_reason` (a closed
vocabulary) roll the three up for a client that only needs to know whether to
draw a warning; a client that needs to say *why* reads the three. The block is
**absent** when no filter was applied — absence never means "a filter was applied
and everything was fine".

### 4.4 Timeline & Analysis
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/timeline` | Get timeline events. Params: `filter`, `modules`, `search`. |
| `GET` | `/cases/{id}/search` | Full-text search. Params: `q`, `limit`, `offset` **or** `cursor`, `types`, `extensions`, `regex`, `fuzzy`. `q` is matched **exact-form**: no Unicode normalisation is applied to it or to the index, so a precomposed (NFC) `mañana` does not find the decomposed (NFD) spelling or the reverse. In a structured query the tokenizer splits a decomposed word at its combining mark. |
| `GET` | `/cases/{id}/search/export/json` | Stream the whole match set as JSON. Same parameters as the search. |
| `GET` | `/cases/{id}/search/export/csv` | The same, as CSV. |
| `POST` | `/cases/{id}/search/sweep` | The case-wide **byte** sweep (`ROADMAP` §1.2): every byte-bearing artifact of the case in id order, regions named by type, ceilings echoed, a resume cursor, and `complete` only when nothing was cut short. Body and answer described under **The case-wide byte sweep** below. |
| `POST` | `/cases/{id}/search/reindex` | Recompute display names for documents already in this case's search index. Owner or admin. Params: `force`. Returns `{"repair_id": "...", "status": "running"}`. |
| `POST` | `/cases/{id}/search/backfill` | Index the artifacts this case has in the **database** and not in the search index. Owner or admin. Params: `force`. Returns `{"backfill_id": "...", "status": "running", "artifacts": n, "note": "..."}`. Outcome in the audit log: `search_index_backfill_completed`, `_stopped` (a cancel or shutdown ended it part-way) or `_failed`. A document added here carries the artifact's **metadata only** — an artifact loaded from the database has no data source, so the text extracted from a file's bytes at ingest is not reconstructed (`B5-001`). The note says so, and so does every audit record the pass writes. |
| `POST` | `/cases/{id}/artifacts/{artifact_id}/credential` | Supply a secret for **one** locked artifact the case already reports. Body `{"kind", "secret"}`; `kind` is `bitlocker_password`, `bitlocker_recovery_password`, `luks_passphrase`, `sevenz_password`, `signal_ios_key_spec` (`x'…'` or bare hex), `ios_backup_password`, `signal_backup_passphrase` (a Signal for Android `.backup`'s 30 digits) or `whatsapp_key` (a WhatsApp `crypt14` backup's key file as hex, or the bare 32-byte key as 64 hex digits; a `crypt15` backup's 64-digit end-to-end root key, or its `encrypted_backup.key` as hex — for a backup whose key file is not in the case, ROADMAP §5.7) or `macos_keychain_password` (a macOS `kych` keychain's login password; it opens the `DbBlob` and reports `password_state`, and reveals no item) or `macos_system_key` (the 48 bytes of a Mac's `/var/db/SystemKey` as hex, for `System.keychain`; same outcome), and names the module that runs: `plugin.crypto.bitlocker_decryptor`, `plugin.crypto.luks_decryptor`, `container.7z_expander`, `plugin.messaging.signal` (both Signal kinds), `plugin.mobile.ios_backup`, `plugin.messaging.whatsapp`, `macos.keychain`. The target is the artifact the locked thing **is** — a volume, a file, or a **directory** (an iOS backup folder, resolved from its `path` exactly as `run_module` resolves one); a target whose bytes or folder cannot be found gets a failed job saying so and the `credential_supplied` row notes it was not run. This is the **only** route a secret reaches an ad-hoc run by: `POST …/run_module` refuses a `secrets` map with `400`, naming this route and echoing only the key names. Returns `{job_id, status, kind, module_id, note}`; an unknown kind or an empty secret is `400` and echoes nothing. **Authorised** like every write route (a `read_write` or `owner` grant; the artifact is scoped to the case, else `404`). **Audited by kind, never by value:** `credential_supplied` (user, artifact, kind, module, job) is written *before* the run is queued — if the audit log refuses the row, nothing runs — and the orchestrator writes `credential_outcome` (`accepted`, `rejected` with the module's reason, `not_used`, `module_error`) when the module returns. **Held for one run:** the secret is moved into a zeroizing `seance_core::credential::RunCredential` bound to that artifact (redacted `Debug`, no `Clone`/`Serialize`), carried in an `AdHocRequest` field serde skips, visible to the module only for its one `process` call through a thread-scoped channel — never merged into artifact metadata, the job row, the processing log or any record — and dropped, zeroing it, as soon as the module returns. What it cannot promise: the HTTP body buffer is freed, not zeroed; a library may keep its own copy for the call (the 7z reader's UTF-16 password); and keys *derived* from the secret live in a decrypting data source while the pipeline reads that volume. **Lifecycle:** an accepted secret's records are persisted like any re-run's — the decrypted volume (with a `VolumeDecryption` `Unlocked` record), the 7z's entries, the Signal store's or backup's messages, an iOS backup's files (with an `IosBackupInfo` `decrypted` record) beneath the artifact — and the earlier locked record is superseded; a rejected one records **nothing** new, the job fails saying the locked record still stands. A volume decrypted in memory cannot be re-read from the evidence afterwards (the key is not retained), so the content resolver refuses it and everything beneath it rather than serving ciphertext. |
| `POST` / `DELETE` | `/cases/{id}/artifacts/{artifact_id}/unlock` | **Unlock an encrypted iOS backup for reading**, and lock it again. The credential route above opens a backup for one run; afterwards the password is gone and the files of an encrypted backup — whose only bytes on disk are ciphertext — are refused by stream, hex, download, export and re-hash, the refusal naming this route. `POST` body `{"kind": "ios_backup_password", "secret"}` for a backup (the volume kinds `bitlocker_password`, `bitlocker_recovery_password` and `luks_passphrase` are described below; any other kind, an empty secret or one over 4,096 characters is `400` and echoes nothing). The target is the backup folder, the parser's `IosBackupInfo` record or any backup file — anything recording the backup directory (`backup_path`, or `path` on the folder), checked against the evidence roots exactly as the content resolver checks it. The route writes `unlock_supplied` (kind) — if the audit log refuses it nothing is tried — checks the password against the keybag through the ingest parser's own code (`seance_plugin_ios_backup::unlock_backup`: keybag, passcode key, class-key unwrap, `Manifest.db` decryption), then writes `unlock_outcome` (`accepted` with `expires_in_secs`, `rejected`, `not_encrypted` or `error`). Only after an accepted row is written are the unwrapped class keys put in the process-memory keyring (`seance_api::backup_keyring`), keyed by `(case_id, canonical backup path)`, for the TTL: **8 hours by default, `SEANCE_UNLOCK_TTL_SECS`**. While held, `direct_backup_file_source` opens each file of that backup to its plaintext through the same per-file step ingest uses (`IosBackupParser::open_encrypted_file`); a file ingest could not open (no per-file key, no protection class, no class key) is refused here too, and the same backup in another case stays refused. Returns `{status: "unlocked", kind, expires_in_secs, file_count, note}`; a wrong password is `400` saying the password was refused and that the check cannot tell a wrong password from a corrupt wrapped class key. `DELETE` forgets the keys for this case and backup, writes `unlock_forgotten` (`reason=lock; held=true/false`), and clears the resolver's container/decompressed/VSS source caches, which could otherwise keep plaintext decompressed or opened from a backup file (a gzip, a zip inside it) alive after the lock; case delete and expiry clear them too. Deleting the case forgets them too, after writing `unlock_forgotten` (`reason=case_delete; held=N`, resource the case; if that row cannot be written the delete fails with the case whole). An expired unlock is never returned; every keyring lookup, insert, removal and per-case count drops expired entries, and an expiry sweep (started with the first unlock, every `min(TTL, 60 s)`) drops them when nothing else does and writes `unlock_forgotten` (`reason=expired`, user `system`, resource the case; a row that cannot be written is retried next sweep). A restart forgets them with no row. **Authorised** like every write route (`read_write` or `owner`). **Memory only:** the password is moved into a zeroizing holder and dropped when the check returns; the keyring is not `Clone`/`Serialize`, its `Debug` prints a count, and the class keys zero on drop — neither the password nor a key reaches the database, a job row, an audit row, a response, an export, a backup of the case or a log. What it cannot promise: the HTTP body buffer is freed, not zeroed; the passcode key derived during the check, a whole-file read's unwrapped per-file key and a streaming read's AES schedule are ordinary buffers for that step or read; an expired key stays in memory for up to one sweep interval; the check writes the decrypted `Manifest.db` (names, domains, wrapped per-file keys) to a temporary file, as ingest does, deleted when it returns; process memory can be swapped or dumped (pages are not locked); a read under way when the backup is locked finishes with its own handle. **BitLocker and LUKS volumes:** with kind `bitlocker_password`, `bitlocker_recovery_password` or `luks_passphrase`, the target is the locked volume, the decrypted volume recorded beneath it (`bitlocker_decrypted` / `luks_decrypted`) or anything beneath that (`content_resolver::decrypted_volume_above`). The locked volume's content is resolved, the kind's family is checked (`is_bitlocker` / `is_luks`; the other family or no volume is `400`, `unlock_outcome` `not_applicable`, the secret untried), `unlock_supplied` (`kind; volume=<id>`) is written, then `unlock_bitlocker` / `unlock_luks` run on it: `rejected`, `not_decryptable` (keys recovered, cipher not decryptable in this build) or `error` hold nothing; `accepted` (`expires_in_secs`) puts the decrypting view in `seance_api::unlocked_volumes::volumes()`, keyed by `(case_id, "volume:<locked id>")`, same TTL. While held, the resolver's step for a decrypted volume serves that view instead of refusing, so the volume and every file, partition or window beneath it read as plaintext; in another case it stays refused. Returns `{status: "unlocked", kind, volume_artifact_id, expires_in_secs, note}`. `DELETE` on any of those targets forgets it (`unlock_forgotten`, `kind; reason=lock; held; volume`); `DELETE` on something never unlocked answers `was_unlocked: false`. Case delete (`kind=volume; reason=case_delete`) and the same expiry sweep (`kind=volume; reason=expired; source=volume:<id>`) forget it too, and every forget clears the resolver's container/decompressed/VSS source caches, which could otherwise keep the view and its key alive. The FVEK (or diffuser AES/tweak keys) and the LUKS master key are zeroizing and wiped when the view drops; the stretched password key, VMK, LUKS slot key and merge candidates are ordinary buffers for the length of the check. The ancestors route marks a decrypted volume with `decrypted_volume: "bitlocker" | "luks"` so a client can offer the unlock beneath it. |
| `POST` | `/cases/{id}/keychain/{record_id}/reveal` | **Reveal one iOS backup keychain item's secret** (the `MemoryCredential` audited-reveal discipline, re-derived on reveal). An `IosKeychainItem` record carries its attributes and `secret_state: withheld`, never the secret, so no listing, `GET`, search snippet or export can carry it and it is never at rest. This route loads the record (another case's id is `404`), refuses anything that is not an `IosKeychainItem` with `state: read` and `secret_state: withheld` (`400`, saying why — a device-bound item, one that did not authenticate, one with no secret), finds the backup by the record's `backup_path` (checked against the evidence roots) in the unlock keyring, and refuses with the unlock route named when the backup is not unlocked for reading in this case. It then re-derives the secret through `UnlockedBackup::keychain_secret` — the record's `source_file_id`, `table` and `index_in_table`, with its `persistent_ref` required to match — writes the mandatory audit row `ios_keychain_secret_revealed` (resource `ios_keychain_item`, the record id; details `table`, `access_group`, `service` — never the value; a failed write is `500` and nothing is returned), and returns `{value, encoding: "utf8" | "hex", audit_event_id: null}`. A decryption that fails is `400` and is not audited as a reveal. **Authorised** like every write route (`read_write` or `owner`). |
| `GET` | `/cases/{id}/attention` | The queue of **recoverable** problems (§2.11): content that is present in the evidence and encrypted, grouped by what reports it and by scheme — LUKS and BitLocker both report through `VolumeDecryption` and need different answers. Each group carries `problem`, `guidance` and an `action` the client switches on: `supply_secret` (the module takes a secret for one artifact and one run, so a field and a button are the whole answer; `route` names the endpoint and it is always `credential` — `POST …/credential` above, for the BitLocker and LUKS decryptors, the 7z expander, the Signal parser and the iOS backup parser — and `alternatives` lists other kinds the same row accepts, a BitLocker volume's password beside its recovery password), `supply_at_startup` (the credential is read once at process start, so the row names the flag and the `SEANCE_*` variable and **no field is offered**, because one that could not reach the decryptor would have an examiner concluding their password was wrong; no remedy uses it now, and the variant stays for clients), or `unsupported` (this build cannot read it at all — the entries of a content-encrypted 7z, whose content no password brings into the case because 7z content is not extracted). A group this build has no instruction for is **still listed**, with `unrecognised_note` and no invented action. `examples[].target_id` is the artifact a module would run on — the status record's parent, since a status record has no bytes. Superseded records leave the queue: a later run that did read the content answered the earlier statement. `scope_note` travels with every response, because this is **not** the completeness record and an empty queue would otherwise read as a complete examination — the report's Result Completeness section is where what could not be read is counted. No route serves that census on its own. |
| `GET` | `/cases/{id}/findings` | The ranked triage list (§2.2): the jump from "2M parsed objects" to "the things that look wrong, most confident first". Every row is an **investigative lead** — Séance's own claim about the evidence, not a transcription of it — and carries the `observation` it rests on separately from any `inference` drawn from it, plus a `qualification` stating what it does not establish; `grade` is always `investigative_lead`. Rows are ordered by `confidence_rank` (strong, notable, weak) then kind then name, and counted in `by_confidence` and `by_kind`. Two things travel with every response because a bare list would mislead: `detections` names **what this build can even look for**, so an empty list cannot read as "nothing is wrong"; and `cross_view` reports whether the two detections that need the whole case at once (execution of an absent or deleted binary, a USN delete the MFT contradicts) were **run**, what they were compared against, and every cap that bit. Those two are computed when the list is requested rather than raised during ingest, so their rows carry `persisted: false` and no `artifact_id` — open the `subject_artifact_id` they name. `?source_id=` scopes the claims to one acquisition and never the population they are compared against. |
| `POST` | `/cases/{id}/pivots` | Pin a pivot answer to the case (§5.13), so "everything that touches this address" reaches the report instead of being re-derived by hand while writing it. Body: `value` (required), `note`. Runs the pivot now and **stores the answer** with the examiner and the moment; the report renders that snapshot and separately re-runs the same value, so a case that has grown since shows both figures rather than quietly reporting a different one. Pinning the same value twice refreshes the pin **in place**, keeping its id, because it is the same assertion and a report that cited it still cites the same pin. Audited as `pivot_pinned` — mandatory, since a pin the report carries with nothing in the log saying who made it is a claim with no author. |
| `GET` | `/cases/{id}/pivots` | The case's pinned values, most recently pinned first, each with its snapshot: `total_matches`, `grouped`, `truncated` and the per-kind `groups` verbatim as the pivot returned them. A `truncated` snapshot's per-kind counts are a **sample** and do not add up to its total. |
| `DELETE` | `/cases/{id}/pivots/{pivot_id}` | Unpin. `404` when there was nothing to remove, rather than a success that did nothing. Audited as `pivot_unpinned`: removing something the report carried is as significant as adding it. |
| `GET` | `/cases/{id}/stats/apps` | "What is on this device" (§2.12): parsed records grouped by the **application** they came from, largest first, each group carrying the record types behind it and **how it was attributed** — the record *named* the app (SRUM's `app`, the Windows Timeline's `application`, a macOS `bundle_id`) or its *type* is an app (the messengers and browsers, which carry no app field). Those are different confidences and are not merged. Records belonging to no application — file entries, registry keys, network flows — are counted in `unattributed` and **never distributed among the apps**, so the per-app figures plus the unattributed equal `total_records` and the view is a breakdown of the case it names. `?source_id=` scopes it to one acquisition. |
| `GET` | `/cases/{id}/records` | List `ParsedRecord`s of one type. Params: `type` (required), `page`, `page_size`, `source_id`, `q`, `q_keys`, `sort`, `order`, `include_superseded`. Records a later run of the same module answered are left out unless `include_superseded=true`; the response's `superseded_total` says how many were left out (`null` when they were asked for, and never to be rendered as zero). A `MemoryCredential`'s `value` is served as the withheld marker; the value itself is released only by the audited reveal. That is true of every API path that serialises a record, reads and exports alike. It is a statement about what the API *serves*, not about the workspace, where the value is also in the search index in the clear. |
| `GET` | `/cases/{id}/records/export/csv` | The same population, as CSV, under the same withholding. Params: as above, plus `columns`. |
| `GET` | `/cases/{id}/conversations` | The exchanges one messaging record type holds, newest first, each with its thread key, a label, a message count, the newest message's time and a preview. Params: `type` (required; a type that is not a messaging record type with conversations, `CallLog` included, is refused with `400`). `unthreadable` counts records of that type the grouping could not place in **any** exchange, and `unthreadable_note` says what that means: for the chat channels it is always `0` (their key expressions end in a literal, so every record groups somewhere), and for `EmailMessage` it is the messages carrying none of `Message-ID`, `In-Reply-To` or `References`. Those messages are real and reachable as records, are **not** counted in the threads above, and each carries its own `email_thread_unavailable_reason`; without the count the thread list would read as the whole of the mailbox (§5.14). |
| `GET` | `/cases/{id}/conversations/messages` | One exchange's messages, newest first, with the attachments belonging to exactly those messages. Params: `type`, `key` (both required; `type` is validated as on `/conversations`), `limit`, and the scrollback cursor `before` + `before_id` — **both halves or neither**, because resuming on the ordering value alone silently drops every message sharing it. `has_more` comes from a `LIMIT+1` probe rather than from the page having come back full; `undecodable` counts messages this page fetched but could not decode, which must never render as a gap in the conversation. Email records are ordered on `date_epoch` (unix seconds, published beside the RFC 3339 string) because casting an ISO string to an integer yields its *year*. |
| `GET` | `/cases/{id}/pivot` | The universal pivot: every artifact in the case that references `?value=`, grouped by the kind of record each is (`NetworkFlow`, `DnsResolution`, `RegistryHive`, `FileEntry`, …), largest group first, with up to six sample hits per group. Matches are found through the search index; the kind of each is read from its stored record `type`, falling back to the coarse `artifact_type`. `total_matches` is the exact case-wide count for the value; `grouped` is how many were grouped and `truncated` is true when a very common value exceeds the grouping cap, so the per-kind counts are never read as the whole when they are a sample. Powers the click-to-pivot on the Entities screen. | The record kind is **indexed** (`record_kind`, the same `COALESCE(metadata.type, artifact_type)` discriminator the database computes), so a pivot groups its hits from the index alone rather than taking every hit id back to the database in chunked `id IN (...)` queries; a document indexed before that field existed carries none, and only those few ids are asked of the database, so a partially-rebuilt index still groups correctly instead of lumping everything under one blank kind.
| `GET` | `/cases/{id}/comms/ranking` | Most-contacted counterparties, ranked over every communications record in the case. Params: `channel`, `q`, `limit`. |
| `GET` | `/cases/{id}/comms/histogram` | Communications volume over time, bucketed in SQL over every record in the case. Params: `channel`, `q`, `contact`, `buckets`. Returns bars plus the census that accounts for every record they do not include. |
| `GET` | `/cases/{id}/system_info` | Windows machine facts compiled from every parsed registry hive. Params: `source_id` to scope to one acquisition. Single-valued identity fields (computer name, timezone, last shutdown, `last_logon_user` and `logon_domain` from Winlogon, `network_domain` from TCP/IP) are resolved per hive and reported as `null` with `identity_conflicts` when hives disagree. **Two account populations, kept apart**: `sam_accounts` is every local account in SAM, `users` is the profile directories in `ProfileList` — an account that never logged on appears in the first and not the second, so reporting only the second under-counts the inventory. `unparsed_hives` names every hive the case holds and the reader refused, with its error, because a machine whose hives would not parse otherwise compiles to the same empty page as a machine with no registry. Each field is read from the key that *ends* in the named container, not any key containing it, so a descendant key cannot answer for its parent, a value that is present and blank reads as absent rather than as an empty answer, the `Wow6432Node` redirected view is skipped because it mirrors the native key rather than offering a second opinion about it, and a `RegBack` copy is weighed as an earlier state of the same machine — never a contradicting witness — with its value filed as a note when it differs from the live hive. |
| `GET` | `/cases/{id}/device_info` | Mobile device facts — "whose phone is this?". Compiled from records the parsers already wrote: `MobileDeviceInfo` (Android property files) and `IosBackupInfo` (the iOS backup manifest, which names the device in the clear whether or not the backup is unlocked). Params: `source_id` to scope to one acquisition. Every fact carries every reading of it with the file and the property/plist key it came from, and `agreed: false` where the sources gave more than one value — a device whose partitions disagree is a finding, not a tie to break, so nothing is reconciled. `incomplete` names each source that was not read whole, because a fact missing from a truncated property file is one that was never reached rather than one the device did not hold. A fact a device can legitimately have several of — accounts, SIM numbers, ICCIDs — is marked `multi_valued` and lists every value without counting as a disagreement. |
| `GET` | `/cases/{id}/source_kinds` | The mobile source-type triage label per evidence source (ROADMAP §1.4). Params: `source_id` to scope to one root. Compiled from **marker records** the parsers already wrote — never from the source's name — listed case-wide per type (`source_kind::MARKERS`: `MobileDeviceInfo`/`BluetoothPairing` with `platform: android`, `AndroidSmsSummary`, `AndroidCalendarSummary`, `AndroidNote`, `InstalledAppSummary` from `packages.xml`/`packages.list`, `AndroidBackupSummary`/`AndroidBackupWarning`, `PowerLogSummary`/`CachedLocationSummary` only where the store sat at its iOS path, `IosBackupInfo`), each attributed to its root by the upward parent walk (64 deep, stopping at a parent in another case). Per row: `label` (`android_device`, `android_backup`, `ios_device`, `ios_backup`, `mixed`, `none_recognised`, `not_assessed`), `kinds`, `basis` (per kind the marker count and up to five quoted records with the field that corroborated them and their file), `assessed`, `not_assessed_reason`, `walk_state`, `has_records`, `capped`. `none_recognised` needs a completed walk, records under the source, no capped marker listing (`MARKER_LISTING_CAP` 2,000 per type, named in `capped_types`) and no `IosArtifactParseStatus` (a mobile store that could not be read) under it, and no marker record anywhere in the case left untraced to its source (a missing parent, a parent in another case, or a chain deeper than 64: such a record may be any source's, so every source is then `not_assessed` naming the count — kept on a `source_id`-scoped request too); a kind found is reported whatever the walk state. Response-level `looked_for` names the whole vocabulary with each marker's `requires_field` and `requires_path_containing`, `unattributed` counts the marker (or unread-store) records whose root could not be reached, `unattributed_candidates` every listed record whose root could not be reached, markers or not, and `roots_listed_whole` says whether the root walk ended. Its own endpoint so `/stats/sources` never pays for it. |
| `GET` | `/cases/{id}/timeline/histogram` | Event-count histogram for the current filters. Params: the timeline filters plus `buckets` (10–500, default 120) and `focus`. **`focus=auto`** narrows the drawn window to where the events are and re-queries it at a bucket width chosen for that window, so one artefactual 1980 timestamp cannot set the resolution for a whole case; the response then carries `focus: {from, to, events_before, events_after}` naming what was left out, while `min_ts`/`max_ts` keep describing the **whole** extent. Absent the parameter the answer is over the whole extent and `focus` is null. |
| `GET` | `/cases/{id}/timeline/swimlanes` | The same histogram split per source module, ordered by volume, with overflow folded into an `Other` lane. Same params, and `focus=auto` derives its window from the summed lanes so this chart and the histogram above it share one axis. |
| `GET` | `/cases/{id}/timeline/export/json`, `/export/csv`, `/export/pdf` | Export the timeline, one literal path per format. The CSV and JSON stream the whole filtered set and end with a verdict row; the PDF is bounded and says so. Same filter params as the listing. |
| `GET` | `/cases/{id}/timeline/export/body` | The case's files as a Sleuth Kit `mactime` body file: one row per `FileEntry` with its own MAC times, streamed, `#` preamble and verdict lines that `mactime` skips. A **file** export, so it takes none of the timeline filters and says so in its preamble. `Content-Type: text/plain`. |
| `GET` | `/cases/{id}/timeline/export/body_events` (`ROADMAP` §5.12) | The timeline's events — memory events included — as a Sleuth Kit `mactime` body file, `timeliner --create-bodyfile` parity. One row per event with its one time in the column its kind names (created/started → `crtime`, accessed → `atime`, exited/closed/changed → `ctime`, else `mtime`; the other three are 0); every timeline filter the other exports take applies; streamed, with the population in `#` preamble lines and a `# ### END OF EXPORT ### VERDICT:` last line counting events. The file-list body file is `/timeline/export/body`. |
| `GET` | `/cases/{id}/timeline/export/sqlite` (`ROADMAP` §3.7) | The same filtered event set as one SQLite database, built in a single pass and streamed back once committed: a `timeline` table in the MemProcFS-Analyzer column set (`DATE`, `TYPE`, `ACTION`, `SUBJECT`, `DESC`), plus a `DEVICE_OFFSET` column MemProcFS's own schema has no room for, and an `export_meta` table stating whether the walk reached the end and how many rows it wrote. `Content-Type: application/vnd.sqlite3`. |

Several of those rows carry claims an examiner could misread, so what they do and
do not cover is spelled out here rather than compressed into the table.

*   **Every search states what it could reach: `universe`.** Each page of `GET /cases/{id}/search`, and the head of both
    exports (a `universe` object in the JSON, a `# search_universe` preamble line
    in the CSV), carries the statement `seance_search::search_universe()` builds
    from the indexer's own constants: `statement` (one paragraph, fit to quote),
    `content_artifact_types` (`FileEntry`, `FileContent` — the only types whose
    bytes are read), `content_bytes_per_artifact` (16 MiB), `min_run_chars` (4),
    `utf8`, `utf16`, `not_covered`, `byte_sweep_route` and `matching`
    (case-insensitive, otherwise exact-form). It is there on a zero-hit page
    above all, because "no hits" is only "absent" within it. The statement does
    not claim every artifact: `not_covered` names `TimelineEvent` artifacts,
    which the orchestrator does not re-dispatch to the indexer and which enter
    the index only through the backfill (`POST /cases/{id}/search/backfill`,
    `seance_search::scope::NOT_DISPATCHED_TO_INDEXER`); the file text of any
    document the backfill adds (metadata only); and a case ingested
    without the indexer. In UTF-16 the index takes ASCII, the Latin-1
    letters U+00C0–U+00FE (less `×`, `÷`) and one single-block alphabet per run
    (Greek, Cyrillic, Cyrillic Supplement/Armenian/Hebrew, Arabic, kana from
    U+3041), and splits a word where its alphabet changes; no other script
    (Latin Extended, Indic, Thai) is taken. Because the kana block's high byte
    is ASCII `0`, 8-bit hex text such as `0D0A0D0A` is byte-identical to UTF-16
    kana and is indexed as kana (not measured); CJK ideographs and Hangul
    in UTF-16 are **not indexed**, by decision, and the statement says so and
    names `POST /cases/{id}/search/sweep`, which searches them.
    **The statement is per case and per match mode.**
    Those coverage figures are this build's text extractor
    (`seance_search::TEXT_EXTRACTOR_VERSION`, currently 2); a case an
    earlier build ingested holds text that build read, which in UTF-16 was ASCII
    only. The index keeps `seance_text_extractor.json` in its directory, naming
    per case the extractor versions that built its file documents and whether
    the index already held unrecorded ones when the first version was
    recorded. `SearchService::search_universe_for_case` builds the statement
    from it: `index_text_extractor` is `current`, `earlier` (some or all file
    documents were built by an earlier build — the statement says the UTF-16
    coverage does not hold for them, that the backfill cannot repair that
    because it adds metadata only, and that a re-ingest does),
    `no_file_documents`, or `not_assessed` when the index could not be counted;
    `index_text_extractor_versions` lists the recorded versions and
    `text_extractor_version` this build's. `matching` follows the mode: a fuzzy
    search is stated as approximate at the clamped edit distance, a regex search
    as a case-insensitive pattern. `known_false_matches` names the kana/hex
    residue above. A downgrade (a later build's record read by an earlier
    build) is not detected.
*   **Paging a search: `offset` and `cursor` are not interchangeable, and a
    request carrying both is refused.** They name different places, and a client
    that believes it asked for one and is served the other has been told a
    falsehood about which matches are on screen. `offset` is random access into
    the enumeration and is capped at `SEARCH_MAX_OFFSET` (100,000), because the
    server serves it by walking; the cap is reported back as `max_offset`.
    `cursor` is the position a previous page reached, has **no** cap, and is the
    only route to the deep end of a large result set — it names a *position*
    rather than a distance from the start, so the engine resumes rather than
    re-walking. Before it existed, the result set stopped at `limit` and nothing
    in the product could ask for what came after it: an examiner under an
    obligation to review every hit was told how many they had not seen and given
    no way to see them.
*   **A cursor is refused rather than approximated.** It is valid only against
    the `index_snapshot` it was minted under and the query it was minted for.
    Handing it back with either changed is answered with error code
    `SEARCH_CURSOR_REFUSED` and a `details.refusal` of `malformed`,
    `query_changed` (both `400`) or `index_moved` (`409`) — never a `500`. An
    examiner whose walk was interrupted by an ingest commit needs to be told
    that, not handed a correlation id. `next_cursor: null` is a claim, not a
    shrug: it means the engine reached the end of the result set.
*   **A jump the routing cannot reach is refused, not served empty.** Under an
    extension filter the ranked routing post-filters a bounded candidate
    window, and the scan routing has a per-page budget, so the deepest `offset`
    a jump can land on is a property of the data and is usually far below
    `max_offset`. Such a jump is answered with `SEARCH_OFFSET_UNREACHABLE`
    (`400`) carrying `details.offset`, `details.reachable`,
    `details.deepest_offset`, `details.examined` and `details.cause`; the
    message states that the match set does **not** end there and names the
    cursor and the export as the routes that reach it. `reachable` is a
    **count of rows** and `deepest_offset` is the deepest offset that will
    actually be served, which is one less — both are sent because a client
    given only the count renders it as a position and tells the examiner the
    offset just refused is the one that works. `cause` is
    `extension_post_filter` or `scan_budget`, and the message differs between
    them: a scan-budget refusal involves no extension filter and nothing
    ranked, so the extension sentence would be false of it. The
    first page is never refused: with no survivor in the window it is served
    empty with a `next_cursor`, so a walk can begin.
*   **`total_count` bounds the count, not the walk.** `count_is_lower_bound`
    means "at least N" and has three causes — a scan stopping at its per-page
    document/wall-clock budget, an extension post-filter running over a full
    candidate window, and `index_incomplete`. Only the last means rows are
    genuinely unreachable: the indexing writer failed to add documents, so those
    artifacts are unsearchable by any page, walk or export until the index is
    repaired. The first two floor the count while the enumeration still reaches
    every match, because each page resumes strictly after the last document it
    examined. A client deciding whether an exhibit is short reads
    `index_incomplete`; a client reporting prevalence reads
    `count_is_lower_bound`.
*   **The search audit detail records the slice, and the route.** "I searched for
    the term" and "I looked at matches 1,001 to 1,100 of at least 34,000" are
    different claims and only the second can be checked afterwards, so
    `search_executed` carries the range, the total, whether the total was a
    floor, and **which route reached the page** — `cursor` or `offset`. The two
    are the same enumeration and not the same guarantee: a cursor page is pinned
    to the index snapshot the walk began on and would have been refused had it
    moved, while an offset page is a fresh jump into whatever the index is now.
*   **The search exports walk the whole match set, and hold one snapshot while
    they do it.** They take the same parameters as the interactive search — one
    parser serves both — so the exhibit cannot be a different population from the
    screen it was taken from. There is **no row ceiling**: the export walks by
    cursor rather than taking one capped page, and the file says so in as many
    words rather than leaving a reader to infer it from silence. A searcher is
    **pinned** before the first page and moved into the response body, so every
    row comes from the snapshot named in the preamble and neither an ingest
    commit nor a background segment merge can interrupt the walk. The pin's
    lifetime *is* the body's: a client that disconnects drops the body, which
    drops the pin, which releases the segment files. A pin left unread longer
    than the server holds one open is reclaimed, which bounds the disk a stalled
    download can hold on an evidence volume.
*   **A purge stops the walk rather than being read through.** The held snapshot
    still contains, in full, any artifact removed from the index after it was
    taken, so continuing would write destroyed evidence into the exhibit. The
    walk stops and the final row names the purge; rows written before it landed
    may still include artifacts it removed, and the file says that too.
*   **Every search export ends with a verdict row, including a complete one.**
    This inverts the convention the rest of the reporting follows, where a file
    speaks only on bad news, and the inversion is forced by streaming: a body
    assembled in memory is either sent whole or not sent at all, so there silence
    can safely mean "complete", while a body streamed row by row can stop at any
    byte and leave the examiner a file that is byte-for-byte a shorter complete
    one. Ending every export with a verdict makes the **absence** of the verdict
    the signal — the only signal that survives the file being saved to disk and
    opened a week later, long after the HTTP status has gone. A note before the
    first row tells the reader that, because a warning that appears only at the
    bottom cannot warn about a download that never reached the bottom.
*   **The verdict keeps two facts apart that must never be merged.** "The total I
    printed is a lower bound" and "rows are missing from this file" are different
    claims. There are three verdicts: **COMPLETE**; **COMPLETE, STATED TOTAL WAS
    A FLOOR** — the walk ran to the end, so its row count *is* the exact size of
    the match set and the preamble's "at least N" was the lower bound it stood in
    for; and **INCOMPLETE**, which is reached only by `index_incomplete` or by a
    walk that did not finish. The JSON tail publishes the facts separately —
    `complete`, `walk_reached_end`, `index_missing_documents`,
    `stated_total_was_floor`, `stopped_because`, `rows` — so no client has to
    infer one from another.
*   **The response headers state what is knowable before the first row, and
    refuse to state what is not.** `X-Export-Index-Snapshot`, `X-Export-Total`
    and `X-Export-Total-Is-Floor` are all known when the walk begins.
    Completeness is not, and the walk can fail at any byte after the headers are
    sent, so this export deliberately does **not** carry the records export's
    `X-Export-Incomplete`: it sends `X-Export-Completeness:
    stated-in-final-row` and points the caller at the verdict instead of making
    a promise before the facts are in.
*   **Two audit records, because the request and the outcome are known at
    different times.** `search_exported` is written before the first byte, when
    nothing is yet known about how the export will end; a second record carries
    the outcome — rows written, whether it completed, and why it stopped —
    written in band before the verdict row goes out, so a client that waited for
    the file waited for the record too. An export abandoned mid-download still
    leaves that second record, because otherwise the only evidence of the
    interruption lives in a file the examiner may discard.
*   **Records listing: `q` requires `q_keys`, and the refusal is the point.**
    A term with no keys is refused rather than guessed at, because guessing which
    keys a term applies to would make the matched population depend on what a
    parser happened to write rather than on what was asked. `q_keys` is a
    parameter and not a server-side registry because the client already holds
    that list — it is what the table renders its columns from — and two lists
    that must agree are two lists that will drift. Matching is stated, not
    assumed: `q_match: "ascii_case_insensitive_substring"`, because SQLite's
    `LIKE` folds ASCII case only, so `STRASSE` matches `strasse` and `Straße`
    does not match `STRASSE`, and an examiner reading a result set has to know
    which rule produced it. The response names **three** populations rather than
    one number: `total` (type ∧ scope ∧ search — the `T` in the "N of T" line
    above the table), `type_total` (the type's own population, unsearched), and
    `unfilterable_metadata` (records whose metadata will not parse and which
    therefore could not be tested against the term — `null`, not `0`, when no
    term was given, since nothing read the JSON and nothing established a zero).
    `order_by` says whether the rows are ordered by a metadata key or by
    **ingest** order, because ingest order is not the records' own event time and
    a table presenting it as "most recent" would state a chronology the evidence
    never claimed.
*   **The records CSV export takes the same parameters as the listing**, so the
    file matches what the examiner was looking at. An export that quietly held
    the type's whole population, or a different slice of it, is a worse exhibit
    than none: it is one that will be tendered as "the messages mentioning the
    dock" while holding something else. It is bounded at
    `RECORDS_EXPORT_MAX_ROWS` and the ceiling is never silent — the file carries
    a notice row saying how many of how many it holds. A **second, separate**
    notice covers unreadable metadata, because the two shortfalls are repaired by
    different actions: a truncated export is missing rows that still exist and
    can be fetched by narrowing the query, while a row whose metadata will not
    parse was never testable and no export will ever contain it.
*   **Search-index repair** (`POST /cases/{id}/search/reindex`): recomputes the
    display names of the documents a case **already has** in the index, from the
    metadata stored alongside them. It does not discover artifacts that were
    never indexed — an ingest that dropped documents leaves a short index and it
    is still short afterwards; only re-ingesting the evidence adds them. That
    limit is written into every audit record the operation leaves, so
    "reindexed" in the audit trail cannot be read as a claim that the case's
    search coverage was made whole. Gated on owner-or-admin, the same gate
    `DELETE /cases/{id}` applies, because the operation rewrites documents an
    examiner searches against.
*   **Search-index backfill** (`POST /cases/{id}/search/backfill`): the other
    half, and the half no operation could do before. It walks the **artifact
    table** by id — keyset paging, a thousand rows at a time, because a case of
    580,394 artifacts makes an `OFFSET` sweep cost the square of the case — asks
    the index which of each page it already holds, and indexes the rest. What it
    adds is built from the database row, so it carries the artifact's metadata
    and **not** the text extracted from the file's bytes at ingest: a backfilled
    file is findable by name, path and metadata, and a keyword inside it is not
    answered until the evidence is re-ingested. That limit is in the response's
    `note` and in all three audit records. Progress is reported per page on the
    status bus as `search.index_backfill`, and a case cancel or a shutdown stops
    the sweep between pages, leaving what it has already added in place — and
    recorded as `search_index_backfill_stopped`, **not** as completed, because
    "examined 0; 0 added" filed as a completion reads as *the case was walked
    and nothing was missing*. The index is committed every twenty pages, which
    is the only backpressure this path has: the writer's queue is unbounded and
    a keyset walk produces documents far faster than the writer consumes them.
    Each add replaces any document already carrying that artifact id, because
    the decision to add was taken from a *committed* view of the index and an
    ingest running on the same case may hold documents it has not committed
    yet; appending would leave one artifact with two documents.

    The two operations share their per-case in-flight guard — either being
    unfinished refuses the other — their `?force=true` escape and their
    process-wide slot count: two long sequential passes over one case feeding
    one index writer are the same resource whichever is running.
*   **The response is a receipt, not an outcome.** A 580k-document case will not
    finish inside the request timeout, so the repair runs in the background and
    the `200` reports `status: "running"`. The audit log is where the outcome
    lands: `search_index_repair_requested` before any document is touched, then
    exactly one of `search_index_repair_completed` — carrying the renamed, total
    and undecodable document counts — or `search_index_repair_failed`. One
    repair per case at a time; a second is refused with `INVALID_REQUEST` while
    the first has recorded no terminal event. `?force=true` (or `?force=1`)
    overrides that refusal, which is what rescues a case whose server was killed
    mid-repair and whose outcome will therefore never be written.
*   **No job row, by design.** Neither the repair nor the backfill creates an
    `ad_hoc_jobs` row
    and so never appears in `GET /cases/{id}/jobs`: that table's
    `target_artifact_id` is `NOT NULL` with a foreign key to `artifacts`, and a
    case-wide repair has no artifact to point at. There is no nullable column
    the operation could occupy instead. The audit log is the record of
    completion.
*   **Communications ranking** (`GET /cases/{id}/comms/ranking`): the
    most-contacted counterparties, ordered in SQL over every communications
    record in the case. The comms page can only rank what it downloaded, which
    is capped at twenty pages of a hundred records per type, and an order
    computed over a 2,000-record slice is wrong rather than merely incomplete —
    that is the whole reason this endpoint exists. Params: `channel` (one
    ParsedRecord type from `seance_db::COMMS_RECORD_TYPES`; an unrecognised one
    is an error, never an empty answer that would read on screen as "this case
    holds no messages of that kind"), `q` (case-insensitive substring on the
    counterparty) and `limit`. The SQL behind it is
    `Database::comms_contact_ranking`; the HTTP route is `get_comms_contact_ranking`
    in `seance_api`, and it sits behind the same per-case access middleware as
    every other `/cases/{id}/...` route. `limit` is clamped to 1..=200 with a
    default of 20, and the applied cap is stated back in the response's `limit`
    field, so a truncated table cannot be read as a complete one.
*   **Each ranking field names its own population.** `contacts` and
    `distinct_contacts` answer the search: both respect `q`, and
    `distinct_contacts` is the exact number of matching correspondents,
    untruncated by `limit`, which is what lets a capped `contacts` be read as a
    sample of a known whole. `has_more` is decided by a `LIMIT + 1` probe, so a
    full page is not by itself evidence that more exist. `by_type` and the four
    `*_records` counts describe the **case**: they are narrowed by `channel`
    only and never by `q`, because a channel tile that shrank while an examiner
    typed would read as evidence disappearing. `total_records` accounts for
    every record read — `sum(by_type) + summary_records + unrankable_records +
    records_without_counterparty` — where `by_type` counts only the rankable
    records, those carrying a counterparty, and `summary_records` counts the
    parser-emitted tally rows that are counts *of* messages rather than
    messages.
*   **Communications histogram** (`GET /cases/{id}/comms/histogram`): volume over
    time, bucketed server-side so the shape is drawn from every record rather than
    from the slice the page could download. Bars are epoch-floor-aligned and the
    unit is in the field name (`bucket_start_secs`, `min_ts_secs`) — the buckets are
    **not** calendar-aligned, since the friendly widths include 30.4375 days.
*   **A bar is a claim about when something happened, so the census accounts for
    every record the bars leave out.** Six ordered classes, each a different finding
    and never summed together: `unreadable_metadata` (the stored JSON does not
    parse), `not_a_message` (a summary row, or a parser status stub standing for a
    database that failed to open), `unplaceable_absent` (no time key at all),
    `unplaceable_value` (a key was there and no reading of it is admissible),
    `placed_by_rescue` and `placed_as_written`. They sum to `matched_records`, and
    the bars sum to the last two.
*   **`placed_by_rescue` is the honest middle.** A value placed only by assuming
    which unit the parser wrote is a weaker fact than one read to contract. Such
    records are drawn AND counted separately, rather than silently guessed at or
    silently dropped — `rescued_count` travels on every bucket.
*   **`total_records` is narrowed by `channel` alone and never by `q`**, for the
    same reason the ranking's census is: a figure that shrank while an examiner
    typed would read as evidence disappearing. `matched_records` is the population
    the bars describe.
*   **The empty extent still carries the whole census.** `buckets: []` alone cannot
    tell "this case holds no communications" from "it holds thousands, none of which
    carries a readable time" — so every count is present on that path too, and the
    two states are distinguishable from the payload.
*   **One known divergence, stated rather than hidden.** The server places
    timestamps by the same procedure as the browser, pinned by a shared 47-row
    corpus that both test suites read. SQLite's date functions parse ISO-8601 only,
    so an RFC-2822 `Date:` header the browser can place is `unplaceable_value` here
    — the chart understates email volume wherever a parser passed such a header
    through as written, and the census says so rather than dropping the record.
*   **Records with no counterparty are reported, not ranked.**
    `records_without_counterparty` counts call-log rows the device recorded with
    no number at all, for which the call-history parser writes the literal
    contact `Unknown`. Ranking those would seat a phantom party named "Unknown"
    at the top of a table presented as exact, so they are counted and named as
    what they are instead. It is held apart from `unrankable_records`, which
    counts records carrying none of the counterparty keys the viewer reads:
    "the device positively recorded an unidentified call" and "we could not read
    a counterparty out of this record" are different facts about the evidence
    and must never be the same number.

*   **The case-wide byte sweep** (`ROADMAP` §1.2). `seance_search::sweep` scans an ordered stream of
    `SweepTarget { artifact_id, artifact_type, name, path, region, declared_size,
    content_hash, source }` objects with an aho-corasick automaton in chunks,
    reporting every overlapping occurrence exactly once across chunk edges. A
    `SweepRequest` carries a `SearchScope` (artifact types, extensions, path
    prefix, path glob whose `*` does not cross `/`, and `regions` from the five
    `RegionKind`s `live` / `slack` / `unallocated` / `recovered` / `raw`, all
    admitted by default so that excluding one is a deliberate act), `SweepBounds`
    (`max_hits` 10,000 and `max_bytes` 4 GiB by default, `chunk_bytes` 1 MiB) and
    an optional `SweepCursor { artifact_id, offset }` to resume from. Patterns are
    `bytes` or `text`, the latter compiled to UTF-8, UTF-16LE and UTF-16BE plus
    any named single-byte code page (at most 1,024 pattern bytes, 4,096 needles).
    The `SweepResponse` echoes the scope and a `scope_statement`,
    `regions_searched` / `regions_not_searched`, `objects_offered` /
    `objects_searched` (and per region), exclusions counted by reason, `bytes_scanned`
    against `bytes_declared`, each hit with its region, offset, length, pattern and
    the encodings consistent with its bytes, a UTF-16 hit's opposite-endian twin
    one byte away folded into it as `endian_aliases` rather than reported as a hit
    of its own (`hits_endian_ambiguous`, `endian_aliases_folded`), a `Grouping` by
    object content hash, `short_reads` and `read_failures` per object, objects whose
    source is larger than their `declared_size` listed under `beyond_declared_size`
    with the bytes not searched, `hit_cap_reached` / `byte_cap_reached` with the
    ceilings, a `next_cursor` that loses and repeats nothing, and `complete` set
    **only** when the stream was exhausted with no ceiling, short read or read
    error — with a `coverage_statement` in words. A cursor is refused when it names
    an object the stream lacks; it is valid only against the same case, scope and
    ordering. The engine is graded on NIST CFTT's string-search image
    (`TESTING.md`, `SEANCE_CFTT_STRING_SEARCH`).

    **`POST /cases/{id}/search/sweep`** runs it over a case (callers: the
    Search screen's `ByteSweepPanel` and the REPL's `/sweep`, both of which forward the
    answer without adding a claim). Body: `patterns`
    (at least one `{kind: bytes|text, value}`), `codepages` (WHATWG labels for
    single-byte code pages, beside UTF-8 / UTF-16LE / UTF-16BE), `scope`, `bounds`
    and `resume` (all three serde-default, the last a cursor an earlier call
    returned). Every artifact of the case that carries bytes is offered in id
    order with its region named **by type**: a file's live content is `live`; a
    carved file — from anywhere, slack included — or one reconstructed from a
    deleted entry is `recovered`; `UnallocatedSpace` is `unallocated`;
    `SlackSpace` is `slack`; a raw
    image, partition, file system or container is `raw` and is offered only when
    the scope admits `raw` (`raw_objects_not_offered` counts the rest). Parsed
    records, timeline events and directories carry no bytes of their own and are
    counted in `objects_without_bytes`, never offered — a directory being **any**
    artifact whose metadata says `is_directory`, whatever its type, which
    includes the root a directory ingest records as `RawEvidence` with no
    `source_path` (`sweep_region_of` tests the flag before the type; classifying
    that root `raw` would have resolved it, failed, and listed it under
    `read_failures` on every default-scope sweep of a directory-ingested case).
    **Slack is what the file-system parsers published:** the
    `SlackSpace` regions of NTFS, FAT, exFAT, ext4, HFS+ and APFS live files whose tail held a non-zero byte.
    The route computes no slack window itself, so slack on any other file system, an all-zero
    tail, and a file past the per-volume ceiling are not searched, and `slack_statement` says
    so beside the `slack` count. Bytes are resolved through the
    content resolver a few objects ahead of the sweep so a ceiling bounds the
    I/O; an object whose bytes cannot be resolved is offered with a source that
    fails with the reason, so it lands in `read_failures` rather than being
    passed over. The route clamps `max_hits` to 10,000, `max_bytes` to 1 GiB and
    `chunk_bytes` to 4 KiB..=8 MiB and echoes the ceilings (`max_hits_ceiling`,
    `max_bytes_ceiling`, `chunk_bytes`); a call that pulls `objects_ceiling`
    (50,000) objects cuts the stream, sets `object_stream_cut`, marks itself
    incomplete and hands back a cursor at the first object not pulled. The
    response is the engine's `SweepResponse` flattened with those route fields.
    Two sweeps run per process at once (a third waits for a slot). A pattern
    set or a scope that will not compile is a 400 with the compiler's reason.
    Every call that reaches the handler leaves one `search_sweep_executed` audit
    record naming its patterns (each truncated to 200 characters) and its
    outcome — `ok` with the counts, `refused` for a pattern set or a scope that
    does not compile (the record is written before the 400 is sent), or
    `failed` when the sweep itself errs (a resume cursor the case does not hold,
    or the store failing under the walk); what the extractors and the auth layer
    refuse before the handler — a body that does not deserialise, a missing or
    invalid token — is not recorded here. The web UI has no surface for it yet.

### 4.4a Case reports

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/export/html`, `/export/pdf`, `/export/rtf`, `/export/xml`, `/export/docx` | The case report, one `ReportData` rendered five ways with the same sections in the same order (`REPORTING_DESIGN.md`). All five take the `ReportExtras` the API gathers beside it — the communications network and the feature histograms — through `render_*_with`. DOCX: `Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `Content-Disposition: attachment; filename="report_<case>.docx"`, audited as `case_report_exported` with `format: docx`. |
| `GET` | `/cases/{id}/export/xlsx` | The workbook report. |
| `GET` | `/cases/{id}/export/kml`, `/export/geojson` | Geolocation fixes for mapping tools. |
| `POST` | `/cases/{id}/export/files` | File export. |

### 4.4b Memory layer export (`layerwriter` equivalent)

A memory image's **decoded physical layer** as a raw, address-aligned file, and the manifest that
says which of its bytes are fill (`ROADMAP` §5.3). The layer is rebuilt from the `MemoryImage`
record's evidence by the reader the ingest used (`seance_memory::open_physical_layer`), so a
hibernation file comes out decompressed, a crash dump's runs at their physical addresses and a
LiME file's segments in place. Both routes take `?start=&end=` (decimal bytes, `end` exclusive);
a range that runs past the layer is refused with `400`, never clipped. An image whose evidence
now decodes to a different span from the record's `addressable_bytes`, or does not decode at all,
is refused with `422`. A non-`MemoryImage` id is `400`; an id outside the case is `404`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/memory/layer/{image}/manifest` | The hole manifest (`seance_memory::export::ExportPlan::manifest_json`): `start`, `end`, `total_bytes`, `backed_bytes`, `hole_bytes`, `hole_count`, `fill_byte` (0), `holes[]` of `{start, file_offset, length, reason}`, a `statement` to read aloud, and `source` (`case_id`, `image_id`, `image_format`, the evidence's stored `evidence_sha256`). Beside it, `manifest_sha256`: SHA-256 of `manifest` serialised as the response carries it. Not audited: it discloses no evidence bytes. |
| `GET` | `/cases/{id}/memory/layer/{image}/raw` | The raw file, `application/octet-stream`, streamed in 1 MiB chunks through a bounded channel. `Content-Length` is the planned size; `X-Layer-Start`, `X-Layer-End`, `X-Layer-Hole-Count`, `X-Layer-Hole-Bytes` and `X-Layer-Manifest-Sha256` (equal to the manifest route's `manifest_sha256`) tie it to its manifest. Audited as `memory_layer_exported` before the first byte. A read that fails inside a range the manifest calls acquired **aborts the transfer** rather than filling it, so the client receives fewer bytes than `Content-Length`: a fragment, never a file whose manifest understates its holes. |

What it does not do: it exports the **physical** layer only. A translated virtual layer (a process
or kernel address space) is exportable through the library (`seance_memory::export` takes any
`MemoryLayer`) but has no route. The output carries no hash of its own in the response; the
client hashes what it received.

### 4.5 The review ledger

What has been looked at, and by whom. This is the first question the next
examiner asks, and it is a **server-side, per-examiner** record: the ledger used
to live in browser storage, where the answer is correct for exactly one person on
exactly one machine while the case it describes outlives both. On a handover,
examiner B opened examiner A's case and was told nothing in it had ever been
looked at.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/cases/{case_id}/artifact_reviews` | Record a batch of marks for the authenticated examiner. Body: `{"marks": [{"artifact_id": "...", "state": "opened" \| "reviewed" \| "unreviewed"}]}` |
| `GET` | `/cases/{case_id}/artifact_reviews/ids` | The artifact ids in one state. Params: `state` (`reviewed` default, or `opened`), `examiner`, `limit`. |
| `GET` | `/cases/{case_id}/artifact_reviews/stats` | Per-examiner and case-wide roll-up, with the population it counts. |
| `GET` | `/cases/{case_id}/artifact_reviews/history` | The append-only transition history. Params: `artifact_id`, `examiner`, `limit`. |

*   **`opened` and `reviewed` are two assertions, stored as two columns and never
    summed.** Opening a row is not clearing it. Were they one flag, a scroll past
    a row would become evidence that the row was examined. Every reviewed row is
    also an opened row, so the two counts overlap by construction, and the stats
    response says so (`reviewed_is_subset_of_opened`) rather than letting a
    client add them into a total that double-counts every cleared artifact.
*   **A batch, and it is refused rather than truncated.** Openings arrive in
    bursts as an examiner scrolls a grid, which is what pushed this into the
    browser in the first place. Over `REVIEW_BATCH_MAX` (1,000) marks the request
    is refused **in full** and nothing is recorded: a truncated batch would leave
    the browser believing it had recorded openings the server never saw, with no
    way to find out which. An unknown `state` word is likewise refused, not read
    as `opened` — that would file an assertion the client did not make.
*   **The response counts transitions, not marks received**, so a client
    re-sending the same openings on every scroll can *see* that nothing happened
    rather than infer it from a success code: `openings_recorded`,
    `reviews_recorded`, `reviews_withdrawn`, `unchanged`, and `rejected` — named
    ids, not a smaller success count, because a caller given only a total has no
    way to know which marks were refused.
*   **`examiner` absent asks the question of the whole case.** "Has *anybody*
    opened this?" is what a handover needs; one examiner's ledger is a different
    question. The response repeats back which was asked (`examiner`, `scope`) so
    the two cannot be mistaken for each other.
*   **The stats endpoint names the population it counts.** A panel printing "412
    reviewed" with no denominator is a number an examiner cannot act on and a
    court cannot check; one printing "412 of 4,012,345" while the denominator
    secretly means something else is worse. So `population` carries `total`,
    `name` (`artifacts_in_case`), a `label`, `exact`, and
    `includes_non_reviewable_rows: true` — the count includes containers,
    filesystems and partitions that nobody opens individually, which makes a
    ratio against it a **floor** on coverage rather than a measure of it.
    Case-wide figures count **distinct artifacts**, not ledger rows: two
    examiners opening one artifact is one artifact that has been looked at, and
    summing the per-examiner columns would say two.
*   **The history is what survives a withdrawal.** The state table holds the
    current state, and a current-state table cannot answer "what did the previous
    examiner do, and did they change their mind?". Withdrawing a review clears
    `reviewed_at`; if that were the only record, a review made and then retracted
    would be indistinguishable from one never made — and in chain-of-custody
    data that difference is exactly what a handover, or a cross-examination,
    turns on. So a withdrawal **appends** rather than erasing. What is recorded
    is state transitions, not activity: a repeat opening changes nothing and
    writes nothing, so the table is bounded by the ledger's size plus the number
    of review changes, not by how far anybody scrolled.
*   **This is deliberately not the hash-chained `audit_log`.** That log is read
    start-to-finish by an examiner, and per-artifact openings arriving in bursts
    of hundreds would bury every deliberate act in it. The audit log gets one
    summarising `artifact_reviews_recorded` entry per batch; the per-artifact
    detail lives in `artifact_review_events`, written inside the same transaction
    as the ledger and therefore not losable while the ledger stands.

### 4.5a Examiner assignment and personal bookmarks (§3.15)

Two pieces of case-workflow state beside the ledger, in
`seance_db/src/assignments.rs` and `seance_api/src/assignments.rs`. All routes
are case-scoped, so `case_access_middleware` has already refused a caller with
no grant, and a `read_only` caller any non-GET request.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/cases/{case_id}/assignments` | Owner or admin only. Body: `{"assignee_user_id", "artifact_ids": [...], "note"?, "due_at"?}` (`due_at` Unix seconds, refused in full if not in the future). `201` with the assignment and its progress. `400`, with nothing recorded, when the assignee holds `read_only` or no grant, is deactivated or does not exist, when no ids are named, when more than `ASSIGNMENT_ITEMS_MAX` (10,000) are named (refused in full, never truncated), or when any id is not an artifact of this case. Audited as `assignment_created`. The assignment is written before its audit entry, as elsewhere in the API, so a `500` from a failed audit write can follow a stored assignment: a client must treat a `5xx` as "may have been recorded" (the Assign panel does), and only a `4xx` as "nothing recorded". |
| `GET` | `/cases/{case_id}/assignments` | Every assignment, active and withdrawn, newest first, each with `progress`, `due_at`, `reassigned_from` and `overdue` (derived at read time from the assignee's own reviews: past due, items unreviewed, not withdrawn — never stored). `?mine=true` keeps the caller's own. |
| `GET` | `/cases/{case_id}/assignments/{assignment_id}/queue` | The assigned items the assignee has **not** reviewed, paged (`limit` up to 1,000, `offset`), as a bounded list (`has_more`, `undecodable`), each with the assignee's own `opened_at` or `null`. |
| `POST` | `/cases/{case_id}/assignments/{assignment_id}/withdraw` | Owner or admin. Sets `withdrawn_at`/`withdrawn_by`; the assignment and its items are kept. `409` if already withdrawn. Audited as `assignment_withdrawn`. |
| `POST` | `/cases/{case_id}/assignments/{assignment_id}/reassign` | Owner or admin. Body: `{"assignee_user_id", "note"?, "due_at"?}`. In one transaction the assignment is withdrawn (kept, marked) and a new one is recorded over the **same items** with `reassigned_from` set; the assignee rules of a fresh assignment apply (`400`, source untouched, for a `read_only` or deactivated assignee). `201` with the new assignment; `409` if the source was already withdrawn; `404` if not in the case. Audited as `assignment_reassigned` on the new assignment. |
| `GET` | `/cases/{case_id}/personal_bookmarks` | The **caller's own** personal bookmarks, paged. No route lists anybody else's, admins included. Each item carries `in_shared_set`: true only while the shared bookmark it was promoted to still exists, which is exactly when the report carries it. `promoted_at` alone does not mean that — the shared bookmark may have been deleted since, and the mark is then excluded again and may be promoted again. |
| `POST` | `/cases/{case_id}/personal_bookmarks` | Create or update the caller's mark on one artifact: `{"artifact_id", "note"?}`. `400` if the artifact is not in the case. Not audited: a private scratch mark is not an act on the case record. |
| `DELETE` | `/cases/{case_id}/personal_bookmarks/{id}` | The caller's own only; `404` otherwise. |
| `POST` | `/cases/{case_id}/personal_bookmarks/{id}/promote` | Write a shared bookmark (`artifact_bookmarks`) carrying the note, attributed to the caller. `409 SHARED_BOOKMARK_EXISTS` when the artifact already has a shared bookmark (never overwritten), `409 ALREADY_PROMOTED` when its shared bookmark still exists. Audited as `personal_bookmark_promoted`. |
| `GET` | `/cases/{case_id}/bookmarks/categories` | The case's bookmark folders with `bookmark_count` and `parent_id` (`null` at the top level). |
| `POST` | `/cases/{case_id}/bookmarks/categories` | Create a folder: `{"name", "color"?, "parent_id"?}`. `parent_id` nests it under a folder of the **same case**. `400`, nothing written, for a parent that does not exist in the case or a result deeper than five levels (`CATEGORY_DEPTH_MAX`). Names are unique per case. |
| `PUT` | `/cases/{case_id}/bookmarks/categories/{id}` | `{"name"?, "color"?, "parent_id"?, "move_to_root"?}`. `parent_id` moves the folder under another; `move_to_root: true` moves it to the top level; both together are `400`. `400`, nothing changed, for a move under itself or one of its own subfolders (a cycle) or past the depth bound; a refused move leaves the name and colour unchanged too. |
| `DELETE` | `/cases/{case_id}/bookmarks/categories/{id}` | Deletes the folder; its bookmarks become uncategorised and its **subfolders move to the top level**. |

*   **Progress is derived, never stored.** `case_assignments` /
    `case_assignment_items` (migration 0043) hold who was asked to look at
    which explicit artifact ids; progress is read at request time from
    `artifact_reviews` rows whose `examiner` is the assignee's username. A
    colleague's review of an assigned item does not count toward the
    assignee's progress and does not remove it from the queue.
    `opened_by_assignee` and `reviewed_by_assignee` overlap and are never
    summed.
*   **A `read_only` examiner cannot be assigned work**, because they cannot
    record a review. Admins can be assigned (they bypass `case_access`).
*   **A withdrawal is recorded, not deleted.** Deleting the assignee's user
    cascades their assignments, as `case_access` does.
*   **Personal bookmarks** (`personal_bookmarks`, migration 0044) are a separate table, not a visibility
    column on `artifact_bookmarks`, so no reader of the shared set — the
    report, the CSV/JSON export, the bookmark grid — can pick one up by
    forgetting a `WHERE` clause. The report's Findings / Bookmarks section
    states how many exist and are not in the shared set
    (`ReportData::personal_bookmarks_excluded`); a promoted mark whose shared
    bookmark was later deleted counts as excluded again. They need a user row:
    the env-bootstrap admin and auth-disabled `local` identity get `403`.

### 4.6 Specialized Viewers
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/artifacts/{id}/conversation` | Get chat threads/messages. |
| `GET` | `/cases/{id}/artifacts/{id}/registry` | Get registry keys/values. |

### 4.6a Artifact, source and hash-set routes

#### Artifact routes: provenance, location and content search

Shared behaviour: every route sits under `/cases/{id}`, so a user needs a grant on the case or the admin role. Every `GET` here needs read access. A `POST` or `DELETE` needs `read_write` or `owner`, enforced for the whole case prefix before the handler runs, so a `read_only` user is refused with `403` even on a `POST` that changes nothing. An artifact id from another case is `404`, never an answer. None of the `GET` routes in this group writes an audit row.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/ancestors` | **Ancestor chain of an artifact**, root first and ending with the artifact itself. Returns a bare array of `{id, name, artifact_type}`. `name` is the metadata name, else the artifact type. A level that is a decrypted BitLocker or LUKS volume also carries `decrypted_volume: "bitlocker" \| "luks"`, so a client can offer the unlock. The walk stops at 64 levels, and at any parent that belongs to another case, with no flag saying it stopped early. `404` when the artifact is not in the case. |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/physical-location` | **Where the content sits on the backing device image**, traced through the whole container and filesystem chain. Returns `{device, extents, precision, note, truncated, logical_size, located_bytes, sector_size, chain}`. Each extent has `device_offset` that is null for a hole, `length`, `sector`, `sparse` and `source`. `precision` is the worst case on the path: `exact`, `encrypted`, `compressed` or `synthetic`. Compressed and encrypted files report where the stored clusters are, not where a logical byte is. Reconstructed, resident and in-memory content has no single device range, and `note` says so rather than inventing an offset. `truncated: true` means the file's data runs were cut, so the extent list is incomplete. `sector` is null for extents held in an auxiliary source such as a pagefile. `404` when the artifact is not in the case. `400` when the chain is too deep, the content cannot be read, or the stored data runs are invalid. |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/allocation_map` | **Allocation bitmap of a filesystem artifact**, written at parse time. Returns `{allocation_bitmap_b64, allocation_clusters_per_bucket, allocation_total_clusters, allocation_cluster_size}`, copied from the stored `allocation_map` child record. A field the parser did not write comes back null. `404` when the artifact has no allocation map. The route does not check that the artifact is a filesystem, so any artifact without the child record answers `404` too. Filesystems whose parser writes no map have nothing to show. |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/deletion-impact` | **What deleting an artifact would remove**, so the confirmation can name the cost. Returns `{artifact_count, timeline_event_count}`. The artifact count includes the artifact itself and every descendant in the same case. The timeline count covers events attached to any of them. Read only, and the delete route itself writes the audit rows. `404` when the artifact is not in the case. |

#### Artifact routes: processing and integrity history

Shared behaviour: read access. `404` when the artifact is not in the case. No audit rows. These routes report what the case database recorded and say nothing about runs that were never logged.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/processing-history` | **Which modules ran on this artifact**, newest first. Query: `limit` defaults to 1,000, which is also the maximum, and the minimum is 1. `offset` defaults to 0. Rows written by a folded zero-yield run are expanded to one entry per module. Returns `{items, limit, offset, has_more, truncated, count_is_lower_bound, undecodable, inventory_incomplete, inventory_incomplete_reason}`. Read `has_more` before concluding that a module never ran. `count_is_lower_bound` is true when the page stopped at the limit. `undecodable` counts stored rows this build could not read, and paging does not repair it. |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/jobs` | **Ad hoc module jobs that targeted this artifact**, newest first. Returns a bare array of `{id, case_id, module_id, target_artifact_id, status, artifacts_produced, error_message, created_at, completed_at}`. There is no paging and no cap. It lists jobs started through the run-module routes only. Normal ingest processing appears in `processing-history`. |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/integrity` | **Every hash verification recorded for this artifact**, newest first. Returns a bare array of `{id, timestamp, computed_md5, computed_sha1, computed_sha256, expected_md5, expected_sha1, expected_sha256, status, details}`. `status` is `verified`, `mismatch`, `no_baseline` (no acquisition or container hash to compare against) or `incomplete`. `incomplete` means the whole object could not be read, so the digests cover a fragment and must not be quoted as a verification. Recomputed hashes are non-authoritative, and the acquisition baseline is not replaced. The route is `GET` only. A check is started by `POST .../verify`. No cap. |
| `POST` | `/cases/{case_id}/artifacts/{artifact_id}/verify` | **Re-hash an artifact's content and record the comparison.** Starts a background job `verify.integrity` and returns `{job_id, status: "running"}` at once. The content is resolved first, so an artifact whose content cannot be resolved, or that lies outside the evidence roots, is refused in the request and starts no job. The job streams the content through MD5, SHA-1 and SHA-256, reports byte progress on the event stream, and compares against the acquisition baseline first and the container's stored hashes second. The stored baseline is never modified. The result is one `integrity_checks` row, read back through `GET .../integrity`. A read that ends short of the declared size is recorded as `incomplete` with the hashed and declared byte counts and fails the job, so a partial read is never reported as verified. Writes `evidence_verified` with the status. Needs `read_write` or `owner`. `404` when the artifact is not in the case. |

#### Artifact routes: content inspection

Shared behaviour: read access. Content is read through the same resolver as the content, hex and download routes. Evidence outside the allowed roots, content that is encrypted at rest, and content that cannot be read are refused the same way here. No audit rows.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/byte-search` | **Search the artifact's bytes for a hex pattern**, returning match offsets so a hit can open in the hex view. Query: `pattern` is required hex bytes. Spaces, colons and commas are ignored, and at most 4,096 bytes are allowed. An empty pattern, an odd digit count or a non-hex pair is `400`. `limit` defaults to 1,000, maximum 10,000. Returns `{pattern_bytes, total_size, offsets, truncated, scanned_size, incomplete}`. Offsets are ascending and a match across a read boundary is found once. `truncated: true` means the limit was reached and more matches may exist. `incomplete: true` means the content ended before `total_size`, so there is no proof of absence past `scanned_size`. This searches raw bytes only. It does not search UTF-16 or code-page text, and it runs on one artifact at a time. The case-wide search is a separate route. `404` when the artifact is not in the case. |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/thumbnail` | **PNG preview of an image or video artifact.** Query: `size` defaults to 256 and is clamped to 64 through 512. Images are decoded when the content is PNG, JPEG, GIF, BMP, WebP or HEIC, and HEIC needs a build with the heic feature. Content above 64 MiB is refused with `413`, except video, which is previewed from one keyframe where the build has video thumbnails. A short read is refused with `500` rather than rendered, because a half image would pass for the whole file. When the file cannot be decoded, the route serves the device's own cached preview if the evidence holds one. That response carries the header `X-Thumbnail-Source: device-cache`, and so does a keyframe taken from a video. A client must say the image is not the file's own pixels. `404` when the content is not a supported image and no preview exists. |

#### Source routes: layout and size

Shared behaviour: read access, no audit rows. Both read what the parsers already stored. Neither reads evidence bytes.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cases/{case_id}/sources/{source_id}/disk_map` | **Disk layout under a source**: partitions, unallocated gaps and filesystems ordered by offset. Returns `{total_bytes, regions}`. Each region has `artifact_id`, `artifact_type`, `parent_id`, `offset_bytes`, `size_bytes`, `name`, `scheme` and `fs_type`. `total_bytes` is the source's recorded size, else the furthest region end, else 0. The regions are only what the partition and filesystem parsers produced. A gap they did not record does not appear, and offsets or sizes can be null. `404` when the source artifact is not in the case. |
| `GET` | `/cases/{case_id}/sources/{source_id}/dir_sizes` | **One directory level of sizes for the treemap.** Query: `path` is the parent directory with no trailing slash. Empty or absent means the filesystem root. Returns `{path, total_size, children}`, where each child is `{name, path, size, file_count, is_dir}`, largest first. A directory's size is the sum of every file beneath it, with no depth limit. Only non-directory file entries that have a stored path are counted, and a file with no recorded size counts as 0. Matching on `path` is case sensitive. Unlike `disk_map` this route does not check the source. An unknown source or path answers `200` with an empty `children` list, so empty does not prove the directory is empty. |

#### Case routes: file lookup and duplicates

Shared behaviour: read of case data. The duplicate routes work only on hashes already stored. A file that was never hashed, or has no perceptual hash, is not assessed, so absence from a group is not proof of uniqueness. No audit rows.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/cases/{case_id}/files/resolve` | **Turn backup-relative paths into the artifacts that hold the files**, so a chat attachment can open its media. Body: `{"paths": ["Library/SMS/Attachments/..."]}`, at most 2,000 paths, more is `400`. A leading `~/` is stripped for matching, and the answer uses the spelling the caller sent. Returns `{matches}`, a map from requested path to artifact id. A path with no match is absent from the map. A request path also matches a stored path that ends with it at a folder boundary, which covers apps that store a path relative to their own container. Only file entries match, never directories. If two files share a path, one id is returned and the other is not reported. The route changes nothing but is a `POST`, so a `read_only` user is refused with `403`. |
| `GET` | `/cases/{id}/duplicates` | **Groups of artifacts that share a SHA-256**, largest first. Returns `{groups, group_count, redundant_copies, truncated}`. Each group is `{hash, count, members}` and each member is `{id, name, path, artifact_type}`. Only the 500 largest groups are returned, and `truncated: true` means at least that many exist. Each group lists at most 100 members. `count` is the true group size and can exceed the members shown. `redundant_copies` sums count minus one over the groups returned, so it is a floor when `truncated` is true. Artifacts with no stored SHA-256 are not grouped. |
| `GET` | `/cases/{id}/near_duplicate_images` | **Clusters of visually similar images** by PDQ perceptual-hash distance, to collapse re-encoded, resized or lightly edited copies for review. Query: `threshold` is the Hamming distance in bits, default 31, capped at 256. Returns `{groups, group_count, threshold, images_scanned, scan_truncated, grade, note}`. A group is `{count, members}` and a member is `{record_id, image_artifact_id, pdq_hex}`. Groups hold two or more images. Linking is transitive, so two members of a group can be farther apart than the threshold. Only the 10,000 most recently created perceptual-hash records are compared. `scan_truncated: true` means older ones were not. A record whose hash does not parse is skipped without being counted. `grade` is always `scanned`, and the note says each group is a lead for human review and not an identification. |

#### Hash sets: hits and lookup

Shared behaviour: read access. Matching is on the lower-cased hex value, against the MD5, SHA-1 and SHA-256 stored for each artifact, whatever algorithm the set declares. No audit rows.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cases/{id}/hash_hits` | **Case-wide list of artifacts that match a hash-set entry.** Query: `hash_set_id` restricts to one set, and a set from another case simply matches nothing and is not `404`. `page` defaults to 1. `page_size` defaults to 100 and is clamped to 1 through 500. Returns `{hits, total, page, page_size}`. A hit is `{artifact_id, name, path, hash_set_id, hash_set_name, matched_hash, algorithm}`, ordered by name. There is one row per artifact, set and matched hash, so one file that matches in two sets or on two digests counts twice in `total`. Only artifacts that have been hashed can hit. An unhashed artifact is not assessed and shows no hit. |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/hash_check` | **Hash-set matches for one artifact.** Looks up the MD5, SHA-1 and SHA-256 recorded in the artifact's metadata, in the case's own sets. Returns a bare array of `{hash_value, hash_set_name, hash_set_id, set_type, product_name}`, which may hold several entries. An empty array means no match, or no hash recorded for the artifact. The response cannot tell those apart. `404` when the artifact is not in the case. A database fault is `500`, so a failure never reads as no match. |

#### Hash sets: management and VICS interchange

Shared behaviour: a set belongs to one case, and `set_type` is `known` or `notable`. Writes need `read_write` or `owner`. The audit row is written after the change and is best effort, so a failed audit write does not fail the request. `GET .../vics_export` also writes one.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cases/{case_id}/hash_sets` | **List the case's hash sets.** Returns a bare array of `{id, case_id, name, description, set_type, hash_algorithm, entry_count, imported_at}`. No paging. |
| `POST` | `/cases/{case_id}/hash_sets` | **Create an empty hash set.** Body: `{"name", "description"?, "set_type"?, "hash_algorithm"?}`. `set_type` defaults to `known` and `hash_algorithm` to `md5`. Case and spacing are folded, and `sha-1` or `sha_1` is accepted as `sha1`. An unknown `set_type` or algorithm is `400`. Returns `{id, status: "created"}`. Writes `hash_set_created` with the name. Entries come from the import routes. |
| `POST` | `/cases/{case_id}/hash_sets/{hash_set_id}/import` | **Load entries into a set from a file.** Multipart form with a `file` field. The file must be UTF-8 text of at most 32 MiB, and at most four imports run at once, so extra ones wait. Two layouts are detected. An NSRL file is recognised by a quoted `"SHA-1"` or `"MD5"` header, and the column for the set's declared algorithm is read by header name. Otherwise the file is plain lines of `hash[,product]`, and blank lines, `#` comments and a leading line starting with `hash` are skipped. A row that is not a hex digest of the declared length is rejected and counted. Digests are stored lower case and duplicates are ignored. Returns `{imported, total_parsed, hash_algorithm, rejected}`. `imported` counts new rows only. `400` for no file, bad UTF-8, an oversize file, an NSRL file without the needed column, or no valid row at all, and nothing is imported. `404` when the set is not in the case. Writes `hash_set_imported` with the counts. |
| `DELETE` | `/cases/{case_id}/hash_sets/{hash_set_id}` | **Delete a hash set** and its entries, which are removed with it. Returns `{status: "deleted"}`. `404` when the set is not in the case. Writes `hash_set_deleted` only when a set was removed. Hits that came from the set no longer appear in later results, and a report already issued keeps what it printed. |
| `POST` | `/cases/{case_id}/hash_sets/vics_import` | **Create a set from a Project VIC or CAID VICS JSON document.** Body: `{"name", "vics_json"}`, where `vics_json` is the raw document text. A document that does not parse is `400`. The set is `notable` if any media carries a pertinent category, 1 or 2, and `known` otherwise, so one pertinent file makes the whole set notable. Each media object stores one entry per digest present, MD5 and SHA-1, with its category and full attribute bundle kept for export. Hex is lower-cased. The set's `hash_algorithm` label is `sha1` only if most entries are 40 hex long, and matching goes by value, not by label. Returns `{id, status: "imported", set_type, entries_imported, media_skipped_no_hash}`. Media with neither digest are skipped and counted. A document with no usable media is `400`. The set row is created before its entries, so a failure while storing entries can leave an empty set behind. No import slot or 32 MiB check applies, only the global request body limit. Writes `vics_hash_set_imported` with the name. |
| `GET` | `/cases/{case_id}/hash_sets/{hash_set_id}/vics_export` | **Export a set as a VICS JSON document.** Returns `{value: [media...]}`, entries ordered by hash. A set imported from VICS returns its preserved attributes. An entry with none becomes a minimal media record. A media object stored under both digests appears once, keyed by media id, else by its digest pair. A 40-hex entry is written as SHA-1. VICS has no SHA-256 field, so a 64-hex entry is written into the MD5 field, and a partner tool will not match it correctly. Entries without a category export without one. The whole set is built in memory with no cap. `404` when the set is not in the case. Writes `vics_hash_set_exported` even though the method is `GET`. |

### 4.6b Memory analysis routes

These routes read the records the memory stages wrote. They run no analysis.

#### Memory analysis views

Shared behaviour. Every route here is read only and needs any grant on the case, or the admin role. Every route except `images` takes `?image=<id>`, the artifact id of a `MemoryImage` record. An id outside the case is `404`. An id that is not a `MemoryImage` is `400`. With no `image` and more than one memory image in the case, the route refuses with `400` and names the captures, because process ids are per capture and a merged answer would describe two machines as one. A case with one image or none needs no scope. Nothing here is audited. Every stage view returns one envelope: `stage`, `record_type`, `record_types`, `describes`, `per_process`, `image_id`, `stage_ran`, `status` of `complete`, `incomplete`, `failed` or `did_not_run`, `status_meaning`, `record_count`, `records_returned`, `records_truncated`, `rows_incomplete`, `rows_completeness_ungraded`, `count_is_floor`, `analysis_declares_itself_unvalidated`, `unvalidated_records`, `validation_notice`, `failures[]`, `failures_truncated` and `records[]` of `{id, image_id, data}`. A stage with no result and no failure is `did_not_run`, never an empty `200` that reads as a clean finding. At most 200 records are returned per request and at most 2000 failure records are read. `record_count` is the database count and is exact. `count_is_floor` is true when rows were cut, when any row said it was incomplete or did not say, or when a failure record covers the stage. A record that does not state `content_complete` is counted as ungraded and never as complete. The unvalidated fields are separate from `status`: they say a record declared that the code behind it has never been run against a real capture of that operating system, and `false` means no record said so, not that the code was validated. Any other error is `500`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/memory/images` | Every memory image in the case. This is the one case-wide route and takes no `image` parameter. Each item gives `image_id`, `source_artifact_id` the evidence it was decoded from, `name`, `image_format`, `architecture`, `addressable_bytes`, `file_bytes`, `declared_size`, `size_mismatch`, `decode_failed`, `content_complete` with `content_complete_known`, `incomplete`, `stage_failures` and `analysis_state`. The state is `not_analysed`, `discovery_failed` or `analysed`, each with a meaning sentence, so an image nobody analysed is never shown as one that could not be profiled. A `profile` object gives `established`, `analysed_os`, `analysed_by`, `pdb`, `nt_build`, `weakest_evidence`, `symbols_verified` and `failure`. Images, profiles and failure records are read up to 200, 200 and 2000. The response carries `image_count`, `images_truncated` and `summaries_complete`. When `summaries_complete` is false, the per image profile and failure counts may understate. |
| `GET` | `/cases/{id}/memory/profile/{image}` | The profile of one image, where the image id is in the path. A missing or foreign image is `404`, and an id that is not a `MemoryImage` is `400`. With no profile record the body says `analysis_state: not_analysed` and `profile_established: false`, with `profile`, `evidence` and `discovery` null, and never returns a blank profile. Otherwise it returns the first profile record as `profile`, plus `weakest_evidence`, `symbols_verified`, `symbols_verified_known`, `analysis_declares_itself_unvalidated`, `validation_notice`, `discovery`, `failure` and `symbol_dirs_searched`. When the profile was established, `evidence.facts[]` grades the directory table base, kernel base and kdbg as `{fact, present, value, evidence, graded}`. A fact with a value and no grade is `graded: false` and is never assumed good. `weakest_evidence` is the ceiling on every other finding for the image. A discovery failure returns `evidence: null`. If several profile records exist only the first is shown, and `profiles_returned` and `profiles_total` say so. |
| `GET` | `/cases/{id}/memory/coverage` | Which analysis stages ran, which did not and why. Returns `stages[]`, one entry per stage this build describes plus any stage the analysis declared in its own manifest and this build has no row for, which is marked `described_by_api: false`. Each entry has the stage envelope fields without `records`, plus `declared_by_analysis`, `rows_examined` and `completeness_established_for_all_rows`. Completeness is judged on at most 500 rows per record type. When that cap bites the stage is `incomplete` and `count_is_floor` is true, though `record_count` stays exact. The body also has `status_by_stage`, `summary` with counts of complete, incomplete, failed and did_not_run and `total_stages`, `stages_declared_by_analysis`, `analysis_declared_its_stages`, `unattributed_failures[]`, `failures_truncated`, `coverage_complete`, `unvalidated_analysis_present` and `unvalidated_analysis_notice`. `coverage_complete` is false when the failure or manifest fetch was cut. An empty `failures` then means none within the first 2000, not none. |
| `GET` | `/cases/{id}/memory/processes` | The process list and the process tree for one image, as `{case_id, image_id, list, tree}`. Each of `list` and `tree` is a full stage envelope with its own `status`, so a tree built over a list that was a floor can be seen to be one. The list merges the Windows, Linux and macOS process record shapes into one stage, and its failures may be filed under any of three stage names. A tree failure is also reported under the process list failure when the list walk failed. Rows beyond 200 are cut and flagged. |
| `GET` | `/cases/{id}/memory/processes/{pid}/vads` | The virtual address descriptors of one process in one image. The `{pid}` is a decimal number. The envelope holds only the records tagged with that pid, and adds `pid`, `stage_ran` for the whole stage, `stage_records_total`, `records_scanned` and `search_exhaustive`. At most 5000 records of the stage are scanned for the pid. `404` is returned only when the stage ran, the scan was exhaustive and neither a record nor a covering failure exists for the pid. If the scan was cut and nothing matched, the answer is `200` with `status: not_determined` and `count_is_floor: true`, because the absence was not established. A stage that never ran is `200` with `did_not_run`. A stage failure with no pid applies to every pid. |
| `GET` | `/cases/{id}/memory/processes/{pid}/handles` | The handle table of one process, with the same scoping, scan cap of 5000, `404` rule and `not_determined` rule as the vads route. |
| `GET` | `/cases/{id}/memory/processes/{pid}/modules` | The loaded user mode modules of one process, cross referenced against its mapped memory to find modules unlinked from the loader lists. Same scoping, scan cap of 5000, `404` rule and `not_determined` rule as the vads route. A pid with no record is reported as not covered and never as a process that loaded nothing. |
| `GET` | `/cases/{id}/memory/network` | Network endpoints and connections recovered from memory, as one stage envelope. The scan can include sockets closed before the capture whose pool allocations survive. An empty `records` with `did_not_run` says nothing about network activity on the machine. |
| `GET` | `/cases/{id}/memory/services` | Windows services as they stood in memory, one listing per `services.exe` in the image, as one stage envelope. The listing is for comparison with the registry. A stage that did not run is not a finding of no services. |
| `GET` | `/cases/{id}/memory/registry/hives` | Registry hives mapped into kernel memory, including volatile hives that exist on no disk, as one stage envelope. Hives whose enumeration failed appear under `failures` and are not silently left out. |
| `GET` | `/cases/{id}/memory/tampering` | Process image tampering signals such as hollowing, ghosting and executable memory with no file behind it, as one stage envelope. `did_not_run` and `complete` with no records are different answers. Only the second is a finding that no signal was seen. |
| `GET` | `/cases/{id}/memory/tamper-checks` | The kernel side tamper checks: unloaded drivers, per processor timers, threads with debug registers, suspended threads, orphan kernel threads, a patched ETW write path and a skeleton key. One stage envelope. Each record names the groups whose detection exists in `groups_implemented`, and every other group states its own reason for not running. The record says that an empty answer is not a statement that the kernel was untampered. |
| `GET` | `/cases/{id}/memory/suspicious-threads` | Where each live user thread started running. Its two start addresses are placed in the virtual address descriptor that covers them. One image wide record names every process judged, every process out of scope and every process whose analysis failed with its error. Out of scope means a null PEB or an exited process. A range whose protection or file could not be read is a gap, and a private region start is a place to look, not a verdict. A partial survey carries `content_complete: false` with the reasons. One stage envelope. |
| `GET` | `/cases/{id}/memory/device-tree` | The driver and device tree: which driver owns which device and what is attached above each. One stage envelope. An attachment is not by itself a finding, since volume encryptors, antivirus and USB class filters all attach. An attachment stack that could not be walked to its end is stated as such, because something may sit above the point it stopped. |
| `GET` | `/cases/{id}/memory/jobs` | Job objects and the processes confined to them, as one stage envelope. There is one record per distinct job object, naming every process that pointed at it. The job's own active process counter and its walked member list are both reported. A counter above the list means a job mid teardown or one with an unlinked member. |
| `GET` | `/cases/{id}/memory/pattern-scan` | Matches of the examiner's own YARA rules and patterns over each process address space and the kernel's, as one stage envelope. Each match carries the allocation it was found in. The product ships no rules. When no rule set or pattern was named the stage is `did_not_run`, which says nothing about the image. A rule set that ran and matched nothing is a statement about that rule set only. A condition is evaluated per chunk of address space and not per file, so `filesize` is meaningless and a condition joining two strings fires only when both fall in one chunk. |
| `GET` | `/cases/{id}/memory/strings-map` | For each physical offset in the examiner's own `strings` output, the address spaces whose page tables reach that frame, with the virtual address in each. One stage envelope. With no strings file named the stage is `did_not_run`. A frame reached through the kernel shared half is one owner naming the spaces. An offset no walked space maps is never called free, because the page frame database is not read and a free or standby frame still holds old bytes. Where any space could not be walked whole, the row claims nothing. The radix of the file is stated by the examiner and the share of rejected lines is published beside the answer. |
| `GET` | `/cases/{id}/memory/crossview` | The concealment table: which listing saw each process and which did not. One stage envelope. The macOS comparison of the process list against the Mach task queue is filed under the same stage. A listing that failed to run is shown as failed and not as a column of not seen, so a broken stage cannot produce a concealment finding. |

#### Memory credential reveal

A `MemoryCredential` record is served everywhere as the withheld marker, as `GET /cases/{id}/records` documents. This route is the one way its value leaves the server.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/cases/{id}/memory/credentials/{record}/reveal` | Return the value of one recovered credential and record that it was revealed. No body. Needs a `read_write` or `owner` grant, or the admin role, as every write route does. The record must belong to the case, else `404`. Refused with `400` and no audit row when the record is a `MemoryCredentials` inventory, which lists stores and accounts and holds no value, when it is any other record type, or when it carries no non empty `value`. Each message names the cause, and a blank value is never returned as a `200`. The audit row is mandatory and written before the value is returned: action `memory_credential_revealed`, resource `memory_credential`, the record id, and details `account=<username> format=<hash_format>` with `not recorded` or `not stated` when absent, never the value. If the audit write fails the route returns `500` and the value is not sent. The response is `{value, audit_event_id}`. `audit_event_id` is always null, because the audit writer returns no row id, so the event is found in the case audit log under the caller's account. |

### 4.7 Real-Time Events (SSE)
**Endpoint:** `GET /api/v1/events`
**Payloads:** `OrchestratorEvent` variants, internally tagged by an `event_type`
field (flat shape — the tag sits alongside the data fields). Key types:
*   `PhaseProgress`: periodic progress with `tasks_completed`/`tasks_total`,
    `rate_per_sec`, `eta_seconds`, `discovering`, `active_modules`.
*   `ModuleProgress`: per-module progress (`units_done`/`units_total`, `unit`).
*   `AcquisitionHashProgress`: acquisition-hash `bytes_done`/`bytes_total` during ingest.
*   `ProcessingComplete` / `ProcessingCancelled`: pipeline reached idle / was cancelled.
*   `IngestCompleted` / `IngestFailed`: a background ingest job finished.
*   `ModuleStarted` / `ModuleCompleted` / `ModuleError`: per-module lifecycle.

### 4.8 Processing status

**Endpoint:** `GET /api/v1/status` (authenticated; not under `/cases/{id}`, and
the REPL's `/status` prints its JSON as received).

*   `active_tasks` is the number of outstanding tasks across **every** case this
    instance serves, and `scope: "process"` says so; a client must not present it
    as the open case's progress when another case is also ingesting. The
    frontend's run-end reconciliation refuses to draw a conclusion from any
    `scope` but `process`, which is why the field keeps its name.
*   `cases` is the per-case breakdown from the orchestrator's `CaseTaskCensus`,
    an object keyed by case id whose entries are `{"active_tasks": n}` — that
    case's own queued plus in-flight artifacts. A case holding nothing is
    **absent, not zero**.
*   `unattributed_tasks` is `active_tasks` less the sum of `cases`, saturating at
    zero: work the process counts that no case can yet claim — an ingest still
    hashing and probing its image before its first artifact exists, or a
    submission not yet pumped from the channel into the queue. It is why a case
    absent from `cases` may still have work in flight. The two readings are taken
    at different instants, so a unit can shift between them.
*   The census reaches the route as the `seance_api::ProcessingCensus` axum
    `Extension`, which the `seance_api` server binary and the CLI's embedded server
    both layer. An embedding that did not layer it answers `cases: null`,
    `unattributed_tasks: null` and a `cases_unavailable` reason — a count the route
    could not take is never served as an empty map.

### 4.9 Routes no screen or REPL command calls

Each route below is served, authorised and
tested at route level (`seance_api/tests/`: `users_rbac_test.rs` and
`case_access_api_test.rs` for the user, grant and `default_case` routes;
`timeline_recent_route_test.rs` for `timeline/recent`, pinning the server-clock
window, the three accepted periods and the `400` for any other;
`new_capabilities_test.rs` for the whole-source carve), and **API only: no
screen or REPL command calls it**. That is a decision per
route, not an oversight: a script or an API client reaches it; an examiner working
from the web UI or the terminal does not. The two §5.12 routes that did get a
control are listed after the table.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/users` | Create a user. **Admin only.** Body `{"username", "password", "role"}`, `role` is `admin` or `examiner`. API only: no screen or REPL command calls it. |
| `GET` | `/users` | List every user. **Admin only.** API only: no screen or REPL command calls it. |
| `DELETE` | `/users/{id}` | Hard-delete a user; the user's case grants go with it (`case_access` cascades). **Admin only.** Refuses to delete the last admin. API only: no screen or REPL command calls it. |
| `POST` | `/users/{id}/deactivate` | Deactivate a user and stamp `sessions_invalid_before`, so the user's open sessions end and reactivation does not revive them (§4.1a). **Admin only.** Refuses to deactivate the last admin. API only: no screen or REPL command calls it. |
| `PUT` | `/users/{id}/role` | Change a user's role to `admin` or `examiner`. **Admin only.** Refuses to demote the last admin. API only: no screen or REPL command calls it. |
| `POST` | `/cases/{id}/access` | Grant a user `read_only`, `read_write` or `owner` access to a case. **Admin or case owner.** API only: no screen or REPL command calls it. `GET` on the same path, the grant listing, does have callers: the search page's index-repair check and the assignment panel. |
| `DELETE` | `/cases/{id}/access/{user_id}` | Revoke a user's access to a case. **Admin or case owner.** API only: no screen or REPL command calls it. |
| `GET` | `/cases/default_case` | The caller's newest accessible case, and **creates** one named `Default Case` when the caller can reach none. A scripting convenience, so it is not idempotent in the way a `GET` usually is. API only: no screen or REPL command calls it. |
| `GET` | `/cases/{id}/timeline/recent/{period}` | Timeline events whose time falls in the last `period`, which must be `24h`, `7d` or `30d`; anything else is refused with `400`. **The window is measured back from the server's wall clock at the moment of the request (`Utc::now()`), not from any time in the evidence**, so on a case acquired a month ago `24h` returns events the evidence dates to the last day before *now* — usually none, and never "the last day of activity on the device". Bounded at 5,000 events; the body carries the cap as `limit` and whether it bound as `truncated`, with `from_ts`/`to_ts` naming the window used. API only: no screen or REPL command calls it, and it is kept off the screens deliberately, because a list of "recent" events on an evidence screen would be read as recent on the device. |
| `POST` | `/cases/{case_id}/sources/{source_id}/carve` | Whole-source deep carve: queues the opt-in `plugin.recovery.file_carver` as one ad-hoc job per `FileSystem` and `UnallocatedSpace` descendant of the source, and returns `{job_ids, targets}`. A target whose content cannot be resolved still gets a tracked job that records why it was not carved. Long, heavy, and writes carved files into the case, so it waits on a confirmation design before it gets a control. API only: no screen or REPL command calls it. |

The two §5.12 routes that now have a caller:

*   `GET /cases/{id}/timeline/export/body` (§4.4) — the Files page's **Export
    whole case as mactime body file** button, which says beside it that the file
    is every file in the case, from every source, and ignores the page's filters;
    and the REPL's `/export timeline body`. The client reads the verdict
    comment the file ends with and quotes it: it reports the file saved only
    when the verdict is `COMPLETE`; a file whose verdict is `INCOMPLETE` (the
    `FileEntry` set changed while the walk ran, or the walk stopped early), or
    that arrived without the verdict line, is shown as an error; a cancelled
    save dialog is stated as having written nothing.
*   `GET /cases/{case_id}/timeline/related/{artifact_id}` — the artifact page's
    **Timeline** tab. It returns `{events, truncated, cap}`: the artifact's own
    events, its parent's and its children's first, newest first, with its
    siblings' filling what is left of the 2,000-event cap. The response does not
    say which artifact is a child and which a sibling, so the tab labels those rows
    "child or sibling" and links to the artifact; when `truncated` is true it says
    the list stops at the cap and is not the whole history.

### 4.10 Further routes

Paths are relative to `/api/v1` except `healthz` and `readyz`, which are served at the root. The sign-in, server, job, count, timeline, bookmark, filter, profile and audit routes below are grouped by subject.

#### Sign-in and session

Shared behaviour: `login` and `logout` are not behind the auth or case checks. When auth is enabled the outer CSRF layer still applies to every POST, so each needs the `seance_csrf` cookie echoed in an `X-CSRF-Token` header or it gets `403 CSRF_VALIDATION_FAILED`. The cookie is set by any earlier GET.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/login` | Sign in. Body `{"username", "password"}`. Answers `200` with `token`, `expires_at`, `username`, `role`, `must_change_password` and `user_id`, and sets an `HttpOnly`, `SameSite=Strict` session cookie that lasts 24 hours. `429 RATE_LIMIT_EXCEEDED` after 5 attempts a minute for one username or 50 a minute across all names, checked before the password is tested. `401 INVALID_CREDENTIALS` is one answer for an unknown user, a wrong password and a deactivated account, so the three cannot be told apart. While the users table is empty the configured bootstrap admin is accepted and `user_id` is absent. A token with `must_change_password` true can reach only the caller's own password route and `/auth/` routes, and every other route answers `403 PASSWORD_CHANGE_REQUIRED`. No audit row is written for a successful or a failed login. |
| `POST` | `/auth/logout` | End the session. No body. The token is read from the `Authorization: Bearer` header or the cookie, its `jti` is stored in the revoked-token table so a restart does not revive it, and the cookie is cleared. An audit row `session_logout` is written with no case, best effort. A request with no token or a bad token still answers `200 {"message"}` because there is nothing to revoke. If the revocation cannot be stored the cookie is still cleared but the answer is `500 REVOCATION_FAILED`, and the token stays valid until it expires. |
| `POST` | `/users/{id}/password` | Change a password. Body `{"password", "current_password"?}`. A password shorter than 8 bytes is `400`. Changing your own password needs `current_password` and a wrong one is `403`, unless the account is under forced rotation. An admin resetting someone else needs no current password. A non-admin naming another user gets `404`, as does any unknown id. The change clears `must_change_password` and stamps the time, so every token issued before it is refused, the caller's own included, and the user signs in again. Answers `{"id", "password_changed": true}`. The audit row `user_password_changed` is mandatory and carries no case. If it fails the answer is `500` after the new hash is already stored. |

#### Server and discovery

Shared behaviour: `version`, `modules`, `evidence-roots` and `filesystem/browse` need a signed-in user. `healthz` and `readyz` do not. None of these write an audit row.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/healthz` | Non-api. Liveness probe. Always `200` with the plain text `ok` while the process serves. It needs no credentials and checks nothing else. |
| `GET` | `/readyz` | Non-api. Readiness probe. `200` with `ready` when the database answers a case listing, else `503` with `not ready`. It needs no credentials. It does not test the search index, the orchestrator or disk space, so `ready` says the database is reachable and nothing more. |
| `GET` | `/version` | Build identity. Answers `{"version", "name"}`, both taken from the `seance_api` package at compile time. The version is the single product version. |
| `GET` | `/modules` | The module registry held in memory since start. Optional `artifact_type` keeps modules whose `subscribes_to` contains exactly that string. Each entry is `{"id", "version", "subscribes_to", "execution_mode"}`. No paging and no cap. It says what is registered, not what is enabled for any case. See the profile routes for that. |
| `GET` | `/evidence-roots` | The directories the server may read evidence from, for the ingest browser. Query `case_id` is required, `400` when missing or not a UUID. Answers `{"restricted", "roots"}`, where `restricted` is true when an allowlist is in force. The caller needs a grant on the named case, `403` otherwise, and must be an admin, `403` otherwise, unless the server runs with `SEANCE_EXAMINER_HOST_FS` set to true. |
| `GET` | `/filesystem/browse` | List one directory on the server. Query `case_id` is required, `path` defaults to `.`. The empty path, `~` and `.` all mean the first evidence root when one is set, else the home directory or the working directory. Same two gates as `evidence-roots`. A path outside the evidence roots or one that does not exist is `400`, and so is a path that is not a directory. Answers `current_path`, `parent_path` and `entries` with `name`, `path`, `is_dir`, `size` for files only and `modified` as UTC to the second. Directories come first, then names without regard to case. The whole directory is returned with no paging. `parent_path` is not checked against the roots, so following it can be refused. |

#### Processing and jobs

Shared behaviour: the POST routes need a write grant on the case. Jobs are rows in the ad hoc job table. `status` is one of `pending`, `running`, `complete`, `failed`. Times are epoch seconds.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/cases/{case_id}/analyze` | Run one module over every parsed record of one type. Body `{"module_id", "record_type"}`, both required after trimming, else `400`. Targets are the case's `ParsedRecord` rows of that type, at most 5000. `truncated` is true when more matched than were queued. Answers `{"job_ids", "targets", "truncated"}`. One job is created and queued per target. The handler does not check `module_id` against the registry, and it does not attach the target's bytes, unlike `run_module_batch`. If the runner refuses a request that job is marked `failed` and the answer is `500`, with earlier jobs left queued. The audit row `category_analysis_requested` is mandatory and is written after the jobs are queued. |
| `POST` | `/cases/{case_id}/run_module_batch` | Run one module over a named list of artifacts. Body `{"module_id", "artifact_ids"}`, both required and non-empty, else `400`. Ids are de-duplicated and cut to 5000. `truncated` is true when the cut happened and the cut ids are not counted in `skipped`. An id that is not an artifact of this case is skipped and counted in `skipped`. A target whose content cannot be resolved gets a job already recorded as `failed` with the reason, and that job is still in `job_ids` and `targets`. Answers `{"job_ids", "targets", "skipped", "truncated"}`. The audit row `batch_module_requested` is mandatory and counts the jobs created. |
| `POST` | `/cases/{id}/processing/cancel` | Ask the orchestrator to stop dispatching work for this case. No body. It sets a per-case cancel flag and does nothing else, so modules already running finish and flush. Other cases are not touched. Answers `{"cancelling": true}` every time, including when nothing was running. A later ingest on the same case clears the flag. The audit row `processing_cancelled` is best effort. |
| `GET` | `/cases/{case_id}/jobs` | The case's ad hoc jobs, newest first. Query `limit` defaults to and is capped at 500, `offset` defaults to 0. A value that is not a number is ignored. Answers `items` with `id`, `case_id`, `module_id`, `target_artifact_id`, `status`, `artifacts_produced`, `error_message`, `created_at`, `completed_at`, plus the shared paging fields `limit`, `offset`, `has_more`, `truncated`, `count_is_lower_bound`, `undecodable`, `inventory_incomplete`, `inventory_incomplete_reason`. A job row with a status this build cannot read is counted in `undecodable` and left out, never shown as failed. |
| `GET` | `/cases/{case_id}/jobs/{job_id}` | One job in the shape above. `404` when the id is unknown or belongs to another case. |

#### Case summaries and counts

Shared behaviour: all are reads, so a read grant is enough. The handlers do not look the case up. An admin naming an unknown case gets an empty answer, not `404`. A case being deleted answers `404` for every route. None write an audit row.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/stats` | Artifact totals. Answers `{"total_artifacts", "artifact_counts_by_type"}`, counting every artifact row of every type, so directories and parsed records count as one each. The `ETag` is a hash of the body and a matching `If-None-Match` gets `304`. |
| `GET` | `/cases/{id}/recent` | The 50 most recently created artifacts of any type. The number is fixed and there are no parameters. Each entry is `{"id", "artifact_type", "display_name", "created_at"}`. |
| `GET` | `/cases/{id}/stats/file_sizes` | File size histogram. Answers `{"buckets": [{"pow2", "count"}]}`. Bucket `p` holds files from `2^p` bytes up to but not including `2^p * 2`, and bucket 0 holds sizes 0 and 1. Empty buckets are left out. Only `FileEntry` rows that are not directories and record a size are counted, so a file with no recorded size is in no bucket. |
| `GET` | `/cases/{id}/stats/media_counts` | Counts for the navigator. Answers `{"pictures", "videos", "audio", "documents", "geolocation"}`. The first four match file names against a fixed extension list on `FileEntry` rows that are not directories. A renamed file lands in the wrong group and a file with an unlisted extension in none. `geolocation` counts artifacts carrying both coordinates, and an EXIF record only when it states `has_gps`. |
| `GET` | `/cases/{id}/record_types` | Parsed record types with counts. Optional `source_id` limits it to that source's subtree. Answers `{"record_types": [{"type", "count"}]}`, largest first. Only `ParsedRecord` rows are counted. A record that names its kind under `subtype`, `record_type` or `analysis_type` is grouped under that name. A malformed `source_id` is `400`. |
| `GET` | `/cases/{id}/analysis/tree` | The navigator tree. Answers a root `Analysis` node with children `User Activity`, `System Configuration`, `Security & Logs`, `Filesystem` and `Other Records`. Each node has `id`, `name`, `node_type`, `count`, `children`. Counts group artifact rows by type, and parsed records by their `type` field. The first four groups cover prefetch and timeline artifacts, registry hives, EVTX entries and file entries. Every other record type is listed under `Other Records` so the root total is the whole case. The `Timeline Events` node counts artifacts of that type, not rows in the timeline table. |
| `GET` | `/cases/{id}/entities` | Indicators mined from parsed record text. The scan reads the 100,000 newest parsed records and nothing older. Kinds are `email`, `messaging_id`, `url`, `ipv4`, `mac`, `eth`, `btc`, `credit_card`, `phone`. Card numbers pass a plausibility check and are returned whole, as digits. Answers `entities` with `kind`, `value`, `count` and up to 5 sample `artifact_ids`, `counts_by_kind`, `scanned_records` and `truncated`. Entities are cut to the 2000 most frequent. `truncated` is true when the scan hit its row limit or distinct values were cut, and in that case every count is a floor. `counts_by_kind` counts distinct values before the cut. |
| `GET` | `/cases/{id}/geo/points` | GPS points for the map. Items are `{"id", "type", "lat", "lon", "camera", "timestamp", "sourceName", "imageId"}`, with the paging fields beside them. Above 200,000 GPS-tagged records the route refuses with `507 RESULT_TOO_LARGE` and names the KML and GeoJSON exports, rather than draw a subset. Under the limit `has_more` is always false. `undecodable` counts records that carry a fix but could not become a point, so a map with a non-zero value is missing fixes. An EXIF record counts only when it states `has_gps`. |
| `GET` | `/cases/{id}/graph/communications` | Communication network from parsed messages, call logs and email. Nodes are `{"id", "label", "kind", "weight"}` and edges `{"source", "target", "weight"}`, heaviest first. Messaging fans out from one device node. Email links senders and recipients. Only the 250 heaviest nodes are kept and edges to dropped nodes go with them. Email aggregation reads at most 50,000 rows. `truncated` is true when either limit bit. `total_participants` is the count before the cut. `unusable_email_records` counts email rows that gave no edge. `records_without_counterparty` counts call-log rows with no number, which have no node. A graph with non-zero values is not the whole contact network. |
| `GET` | `/cases/{id}/conversations/search` | Find messages in one chat type. Query `type` and `q` are both required, else `400`. `type` must be a messaging type with conversations, and `CallLog` is refused with `400`. `limit` defaults to 100 and is capped at 200. The match is a substring on the message text, newest first, and case-blind for ASCII letters only. Answers `hits` with `id`, `thread_key`, `text`, `date`, plus the shared paging fields. A full page means more may exist, and `count_is_lower_bound` says so. `undecodable` is `null` because this query cannot report dropped rows, and `null` is not zero. |

#### Timeline extras

Shared behaviour: reads need a read grant, writes need a write grant. The swimlane route and the timeline export routes already have rows under the timeline section. Those rows cover `export/json`, `export/csv`, `export/pdf`, `export/body`, `export/body_events` and `export/sqlite`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/timeline/activity` | Pattern-of-life heatmap. Answers `{"cells": [{"dow", "hour", "count"}], "total", "max"}`. `dow` is 0 for Sunday through 6, `hour` is 0 to 23, both in UTC. Only cells with events are listed. Events with a timestamp at or before the epoch are left out because zero is mostly a missing date, and the response does not say how many were left out. So `total` can be lower than the case's timeline count. There are no filter parameters. |
| `GET` | `/cases/{id}/timeline/modules` | Event count per source module, over the whole case with no filters. Answers one JSON object mapping module id to count. Key order is not defined. |
| `GET` | `/cases/{case_id}/timeline/schema` | The JSON fields found in timeline event details, for building filters. It reads the 1000 newest events only. Answers `available_fields` with `path`, `field_type`, `frequency`, `sample_value`, most frequent first, plus `sampled`, `sample_size`, `total_events` and `undecodable_events`. Only top level keys appear, as `$.key`. When `sampled` is true a rare field may be missing and each `frequency` is a count inside the sample. `field_type` comes from the first non-null sample value. |
| `GET` | `/cases/{case_id}/timeline/tags` | Every tag in the case, newest first, with no paging and no cap. Each is `{"id", "case_id", "event_id", "examiner", "note", "created_at"}`. |
| `POST` | `/cases/{case_id}/timeline/tags/{event_id}` | Tag one event. Body `{"event_id", "note"?}`. The field `event_id` must be present or the body is refused with `422`, and the path value is the one used. The id must be an artifact of this case, else `404`. Re-tagging keeps the original examiner and time and only changes the note, and a missing note never erases one. Answers the tag. The audit row `timeline_tag_created` is best effort. |
| `PUT` | `/cases/{case_id}/timeline/tags/{event_id}` | Replace the note on an existing tag. Body `{"note"}`. `404` when the event has no tag. The examiner and time stay as first recorded. This route writes no audit row. |
| `DELETE` | `/cases/{case_id}/timeline/tags/{event_id}` | Remove a tag. Answers `{"success": true}`, or `404` when there is none. The audit row `timeline_tag_deleted` is best effort. |
| `GET` | `/cases/{case_id}/virtual_columns` | Column definitions for the timeline grid. The five built in columns come first, `vc_resource_path`, `vc_file_size`, `vc_user`, `vc_process`, `vc_hash`, then the case's own. Each is `{"id", "name", "description", "type", "sources", "default_visible", "built_in"}`, where `type` is `string`, `integer`, `timestamp` or `boolean` and `sources` is an ordered list of JSON paths tried in turn. |
| `POST` | `/cases/{case_id}/virtual_columns` | Add a column. Body is a full definition. `name` must not be blank, `sources` needs at least one path, every path must start with `$` and hold only letters, digits and `$ . _ [ ]`, and `built_in` true is refused. All of these are `400`. The `id` is chosen by the caller and is unique across all cases, so a repeat id is a `500`, not a `409`. Answers the definition. The audit row `virtual_column_created` is best effort and holds the column id. |
| `PUT` | `/cases/{case_id}/virtual_columns/{column_id}` | Replace a column. Body is a full definition whose `id` must equal the path, else `400`. Same validation as create, and built in columns are refused. The handler does not check that a row changed, so an unknown id answers `200` with the body and still writes the audit row `virtual_column_updated`. Nothing is saved in that case. |
| `DELETE` | `/cases/{case_id}/virtual_columns/{column_id}` | Delete a column. `204` on success, `400` for a built in id, `404` when the case has no such column. The audit row `virtual_column_deleted` is best effort. |

#### Bookmarks

Shared behaviour: reads need a read grant, writes need a write grant. The folder routes under `/bookmarks/categories` have their own rows. A bookmark is one per artifact per case. The shared paging fields are `limit`, `offset`, `has_more`, `truncated`, `count_is_lower_bound`, `undecodable`, `inventory_incomplete`, `inventory_incomplete_reason`. Bookmark objects are `{"id", "case_id", "artifact_id", "category_id", "category_name", "category_color", "note", "examiner", "created_at", "updated_at"}`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{case_id}/bookmarks` | Page of bookmarks, most recently updated first. Query `category` is a folder id, and an empty or malformed value is ignored so the whole list comes back. `limit` defaults to and is capped at 1000, `offset` defaults to 0. Each item is `{"bookmark", "artifact_type", "artifact_name", "source_path"?, "source_offset"?}`. A bookmark whose artifact no longer exists is not listed. The paging fields say whether the list was cut or rows could not be decoded, and a list with either is not the whole set the examiner marked. |
| `POST` | `/cases/{case_id}/bookmarks` | Bookmark an artifact. Body `{"artifact_id", "category_id"?, "note"?}`. `404` when the artifact or the folder is not in this case. Bookmarking an artifact already marked updates it in place. It keeps the id, the creation time and the first examiner, and a missing note or folder leaves the stored value alone. Answers the bookmark with `200`. The examiner is the signed-in user. The audit row `bookmark_created` is best effort and is written again on a repeat. |
| `GET` | `/cases/{case_id}/bookmarks/ids` | Ids of all bookmarked artifacts, as a bare JSON array, so a grid can show a marker. No paging and no cap, and no disclosure fields. |
| `GET` | `/cases/{case_id}/bookmarks/{artifact_id}` | The bookmark on one artifact, `404` when there is none. |
| `PUT` | `/cases/{case_id}/bookmarks/{artifact_id}` | Set the folder and note. Body `{"category_id"?, "note"?}`. Unlike create, this replaces both values, so a field left out is cleared to null. `404` when the folder is not in this case or the artifact has no bookmark. Answers the bookmark. The audit row `bookmark_updated` is best effort. |
| `DELETE` | `/cases/{case_id}/bookmarks/{artifact_id}` | Remove the bookmark. Answers `{"success": true}` or `404`. The audit row `bookmark_deleted` is best effort. |
| `GET` | `/cases/{case_id}/bookmarks/export/json` | Download every bookmark. The audit row `bookmarks_exported` is mandatory and is written first, so it exists even if the export then fails. The export walks every page, up to a budget of 1000 pages. Body holds `case_id`, `exported_at`, `categories`, `bookmarks`, the paging fields and `export_incomplete_notice`, which is `null` when whole. Headers `X-Export-Incomplete` and `X-Export-Undecodable` repeat the shortfall. When the budget ran out or rows could not be decoded the file says so and must not be tendered as complete. |
| `GET` | `/cases/{case_id}/bookmarks/export/csv` | The same set as CSV with columns `Artifact ID`, `Artifact Type`, `Artifact Name`, `Category`, `Note`, `Examiner`, `Created At`, `Updated At`. `Category` is the full folder path. Times are RFC 3339. Values are guarded against spreadsheet formulas. A shortfall becomes a final notice row and the same two headers. Source path and offset are not in the CSV. The audit row `bookmarks_exported` is mandatory and written first. |

#### Saved filters

Shared behaviour: reads need a read grant, writes need a write grant. Predefined filters have no case, appear in every case and cannot be deleted. A filter that belongs to another case answers `404` as if absent.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{case_id}/filters` | Predefined filters first, then the case's own, each group by name. Each is `{"id", "case_id", "name", "description", "filter", "is_predefined", "created_at", "updated_at"}`. A stored filter whose JSON cannot be read is listed with `filter` set to `{"error": "corrupt filter JSON"}`. |
| `POST` | `/cases/{case_id}/filters` | Save a filter. Body `{"name", "description"?, "filter"}`. `name` and `filter` are required. `filter` is a tagged object with `type` of `simple`, `compound` or `not`. A `simple` filter has `field`, `operator` and `value`. The operators are `eq`, `neq`, `gt`, `lt`, `gte`, `lte`, `contains`, `starts_with`, `ends_with`, `in`, `exists`. A `compound` filter has `logic` of `and` or `or` and a list of `conditions`. Nesting beyond 32 levels is refused. All of these are `400`. Names are not checked for being blank or unique. Answers `{"id", "name", "description", "filter"}`. The audit row `filter_created` is best effort and holds the name. |
| `GET` | `/cases/{case_id}/filters/{filter_id}` | One filter in the list shape. `404` when absent or owned by another case. A stored filter whose JSON is corrupt gives `500` here, unlike the list. |
| `DELETE` | `/cases/{case_id}/filters/{filter_id}` | Delete a filter. Answers `{"deleted": true}`. `404` when absent or owned by another case, and `400` for a predefined filter. The audit row `filter_deleted` is best effort. |
| `GET` | `/cases/{case_id}/filters/{filter_id}/apply` | Run a saved filter. Query `parent_id` limits it to the direct children of that artifact, and a malformed value is ignored so the whole case is scanned. `limit` defaults to 100 and is capped at 10,000, `offset` defaults to 0, and a value that is not a number falls back to the default. The scan covers artifacts of every type, in storage order, and stops after 500,000 rows. Each call rescans from the start whatever the offset. Answers `results` with `id`, `parent_id`, `artifact_type`, `metadata`, with unlock secrets removed, plus `total`, `limit`, `offset`, `filter_name`, `scan_complete`, `undecodable`, `inventory_incomplete`, `inventory_incomplete_reason`. When `scan_complete` is false `total` is a floor and the rest of the case was never examined. `undecodable` rows were neither matched nor ruled out, and paging does not recover either gap. The reason is `capped`, `undecodable_rows` or `capped_and_undecodable_rows`. A stored filter that fails validation is `400`. This route writes no audit row. |

#### Ingest profiles

Shared behaviour: reads need a read grant, writes need a write grant. A profile picks which modules run on new work. An empty `enabled_modules` means every module, and a module named in `disabled_modules` never runs, even if enabled. A case with no active profile runs every module. There is no route to read or edit one profile by id.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{case_id}/profiles` | The case's profiles. Each is `{"id", "case_id", "name", "description", "enabled_modules", "disabled_modules", "is_active", "created_at"}`. No paging. |
| `POST` | `/cases/{case_id}/profiles` | Create a profile without activating it. Body needs all four of `name`, `description`, `enabled_modules`, `disabled_modules`, else `422`. Module ids are checked against the registry but unknown ones are kept, and the answer carries a `warnings` list saying that an unknown enabled id will never run and an unknown disabled id has no effect. Answers the profile fields flat. The audit row `profile_created` is best effort and holds the name. |
| `GET` | `/cases/{case_id}/profiles/active` | The active profile, or JSON `null` with `200` when none is set. |
| `POST` | `/cases/{case_id}/profiles/{profile_id}/activate` | Make one profile active and all others inactive, in one transaction. `404` when the profile is not in this case, and nothing changes. Answers `{"status": "ok", "warnings"}` where warnings name unknown module ids. The orchestrator rereads the active profile at most every 2 seconds, so the change reaches work not yet dispatched. Nothing already produced is undone or rerun. The audit row `profile_activated` is best effort. |
| `DELETE` | `/cases/{case_id}/profiles/{profile_id}` | Delete a profile. `204`, or `404` when it is not in this case. Deleting the active profile leaves the case with none, so all modules run. The audit row `profile_deleted` is best effort. |

#### Audit log

Shared behaviour: the audit log is scoped by the case id on each row. Events with no case never appear here, and that includes sign-in, sign-out and user changes. Reading the log writes no audit row.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{id}/audit_log` | Page of the case's audit events, newest first. Query `limit` defaults to 100 and is clamped to 1 to 1000, `offset` is clamped to 0 or more. `user`, `action` and `resource_type` are exact matches. `from` and `to` are RFC 3339 bounds, both inclusive, and a bad value is `400`. Answers `events` with `id`, `timestamp`, `user_id`, `action`, `resource_type`, `resource_id`, `details`, plus `total` for the active filters, `limit` and `offset`. A resource id that is not a UUID is shown as a marker, never blank. |
| `GET` | `/cases/{id}/audit_log/verify` | Check the tamper-evident hash chain. The chain spans the whole installation, so a break found here is not about this case alone, and the body says `scope: instance`. It reads every audit row, so the cost grows with the log. Answers `valid`, `checked`, `broken_at`, `break_reason`, `head_id`, `head_hash`, `tamper_evident`, `keyed_rows`, `unkeyed_rows`, `tamper_evident_from`, `tamper_evidence_note` and `completeness`. On an unkeyed chain `valid` means internally consistent, not unaltered, and `tamper_evident` says which. To detect deleted entries pass both `expected_head_id` and `expected_head`, recorded earlier from this route. One without the other is `400`, as is an id that is not a whole number. `completeness.verdict` is `not_checked`, `intact`, `intact_then_broken`, `chain_broken`, `truncated` or `diverged`. |
| `POST` | `/cases/{id}/export/audit_log/csv` | Download the log as CSV. It needs a write grant because it is a POST. No body. Filters `user`, `action`, `resource_type`, `from`, `to` come from the query string and work as above, but `limit` and `offset` are ignored. The file holds the newest 100,000 matching events, newest first, so the oldest are the ones dropped, and a final notice row says how many matched. Columns are `timestamp`, `user_id`, `action`, `resource_type`, `resource_id`, `details`, with values guarded against spreadsheet formulas. The audit row `audit_log_exported` is mandatory and written before the filters are checked, so it exists even when a bad bound then gives `400`. |

---

## 5. Error Handling

All API errors return a standardized JSON object:
```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested artifact could not be found.",
    "details": { ... }
  }
}
```

**Common Codes:**
*   `INVALID_REQUEST` (400)
*   `SEARCH_CURSOR_REFUSED` (400 / 409) — a search cursor this server declines to
    serve; `details.refusal` is `malformed`, `query_changed` or `index_moved`.
    Deliberately not a `500`: the walk was refused for a reason the client can
    act on, and reporting it as a server fault would tell the examiner the wrong
    thing about their own result set.
*   `SEARCH_OFFSET_UNREACHABLE` (400) — a search `offset` this routing cannot
    jump to on this data; `details` carries `offset`, `reachable` (a count
    of rows), `deepest_offset` (that count minus one — the deepest offset
    actually served), `examined`, and `cause` (`extension_post_filter` or
    `scan_budget`).
    Not the end of the result set: walk by `cursor`, or export.
*   `RESOURCE_NOT_FOUND` (404)
*   `JOB_FAILED` (500)
*   `SYSTEM_OVERLOAD` (503)

---

## 6. Security

*   **Authentication:** JWT-based login with bcrypt-hashed credentials, **on by
    default** (`SEANCE_AUTH_ENABLED`). CSRF protection and per-username login
    rate limiting are enforced. Roles: `admin`, `examiner`. Every token carries
    a `jti`; logout records it in `revoked_tokens` and the auth middleware
    refuses a revoked token for the rest of its lifetime, so a session cannot
    outlive its own logout.
*   **Transport:** The server speaks plain HTTP; terminate TLS at a reverse
    proxy and set `SEANCE_COOKIE_SECURE=true`. Startup aborts on a non-loopback
    bind while auth is disabled.
*   **Evidence access:** Filesystem reads are confined to `SEANCE_EVIDENCE_ROOTS`
    (fail-closed to the working directory when unset).
*   **Per-case access:** every `/cases/{id}/...` route passes through a
    fail-closed access middleware; grants are rows in `case_access`.
*   **Audit chain:** the audit log is a hash chain, and it is **tamper-evident
    only when keyed** — `SEANCE_AUDIT_HMAC_KEY` turns it into HMAC-SHA256, and
    unset it is a plain SHA-256 chain that anyone with database write access can
    rewrite and recompute. Because the chain is the custody record, startup
    **aborts on a non-loopback bind while the chain is unkeyed** (opt-out:
    `SEANCE_AUDIT_UNKEYED_OK=true`), exactly as it does with auth disabled. The
    key is never generated or persisted by the server. Each row records the
    fingerprint of the key it was written under (`audit_log.key_fingerprint`,
    NULL when unkeyed), so a rotation (`SEANCE_AUDIT_HMAC_KEY_PREVIOUS`) keeps
    old rows verifiable. The verification result carries `tamper_evident`
    (a key is configured **and** every checked row was keyed), `keyed_rows`,
    `unkeyed_rows`, `tamper_evident_from` (the id of the first row from which a
    pass is evidence of no alteration) and `break_reason`, and callers must
    publish them beside `valid`: on an unkeyed row `valid` means "internally
    consistent", **not** "unaltered", and a verdict that cannot tell those
    apart is the one an examiner would quote in court. An unkeyed row that
    follows a keyed one is a break, never a downgrade.
*   **Audit-chain completeness:** `GET /cases/{id}/audit_log/verify` also
    publishes the chain **head** (`head_id`, `head_hash`) and a `completeness`
    object. A hash chain proves the entries it holds are unaltered and ordered;
    it cannot prove none were deleted from the end, because a truncated chain
    still verifies. The endpoint therefore accepts an operator's externally
    recorded anchor as `?expected_head_id=<id>&expected_head=<hash>` and answers
    `verdict`: `not_checked` (no anchor supplied), `intact` (the anchored entry
    verifies and the chain is unbroken), `intact_then_broken` (the anchored
    entry verifies and the chain verified through it, but is broken at a later
    entry — `broken_at` names it, and nothing from there on is covered),
    `chain_broken` (the chain is broken at or before the anchor, so the anchor
    cannot be relied on), `truncated` (the anchored entry is gone) or `diverged`
    (present but rewritten). `intact` in the payload is true only for the
    `intact` verdict. Half an anchor is a `400`.
*   **Scope:** See `DEPLOYMENT.md` for the full security posture and environment
    variable reference.

---

## 7. Implementation Status

- [x] **Orchestrator:** Task queue, Pub/Sub event loop.
- [x] **Zero-Copy:** `DataSource` trait, `WindowSource` implementation.
- [x] **Database:** SQLite persistence layer. Migrations live in
      `seance_db/migrations/`, numbered 0001 to 0047; the newest is
      `0047_hash_set_entries_lower_index`, which adds `idx_hash_set_entries_lower_hash` on
      `LOWER(hash_value)` so a case-insensitive hash-set match seeks instead of scanning
      the entries table. `0042_artifact_children_created_index` adds
      `idx_artifacts_children_created` on `artifacts(case_id, parent_id, created_at, id)`
      so the evidence-tree child listing seeks the parent's run and pages in index order
      instead of walking the whole case and sorting. The plan test
      `child_listing_seeks_the_parent_and_pages_in_index_order` pins it.
- [x] **Search:** Tantivy index integration, cursor paging with no depth ceiling,
      and snapshot-pinned streaming exports that end with a completeness verdict.
- [x] **API:** Axum-based REST endpoints.
- [x] **SSE:** Real-time event streaming.
- [x] **Authentication:** JWT login, bcrypt credentials, CSRF, login rate limiting.
- [x] **Per-case access control:** `case_access` rows and a fail-closed
      middleware on every `/cases/{id}/...` route.
- [x] **Review ledger:** server-side, per-examiner, with an append-only
      transition history (§4.5).
- [ ] **PostgreSQL:** Enterprise DB support.
