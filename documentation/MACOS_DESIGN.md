# macOS Forensics Extension Design

**Target:** macOS Workstations (Intel & Apple Silicon M1/M2/M3)
**Architecture:** Modular Seance Plugins (implementing `ForensicsModule`)
**Status:** Partially Implemented. Shipped and registered in `seance_api::modules`: APFS + HFS+ filesystem parsing, plist parsing, `seance_plugin_fsevents`, `seance_plugin_dsstore`, the whole of `seance_plugin_macos_artifacts` (quarantine, TCC, launchd persistence, Wi-Fi known networks, install history, knowledgeC, Notification Center, BOM receipts, unified logs, Spotlight store, Apple Mail's Envelope Index) and `seance_plugin_memory_macos`, registered and stamped unvalidated on every record it emits. Design-only: iCloud, AirDrop reconstruction, Apple-silicon security, and FileVault decryption.

`seance_plugin_memory_macos` is registered (`seance_api/src/modules.rs`, right after
the Linux tier). Withholding it would make a Mac capture *silent*, and silence reads as
"nothing was running", the one claim that is never safe. An examiner can discount a result
labelled unvalidated. They cannot discount a result they were never shown. User activity,
unified logs, persistence and knowledgeC ship in `seance_plugin_macos_artifacts`.

This document outlines the architecture for extending Seance with comprehensive macOS forensics capabilities, rivaling commercial tools like Cellebrite Inspector, BlackBag (Cellebrite) MacQuisition, and Magnet AXIOM.

---

## 1. Core Filesystem Support

### `seance_plugin_apfs`
**Responsibility:** Parsing the Apple File System (APFS), the default for modern macOS.
- **Subscribes To:** `ArtifactType::FileSystem`, gated on `metadata["subtype"] == "apfs"`.
- **Input Capability:** `InputCapability::RandomAccess`
- **Output:** `ArtifactType::FileEntry`, one `ArtifactType::FileSystem` per volume, and a
  `ParsedRecord` of subtype `parse_incomplete` where the walk fell short. There is no
  `ArtifactType::Snapshot`.
- **Features:**
    - [x] **Container Superblock:** Parse `NXSB` and checkpoint mapping.
    - [x] **Volume Superblock:** Identify volumes (System, Data, Preboot, Recovery).
    - [x] **B-Tree Traversal:** Parse Object Map B-Trees to locate inodes.
    - [x] **Five timestamps, not four.** Beside
      the inode's `created` / `modified` / `changed` / `accessed`, every `FileEntry` carries
      `date_added` — `j_drec_val_t.date_added`, the instant the entry was added to its
      directory, which lives on the **directory record** and not on the inode. It is decoded
      through the same validity helper as the other four and is **omitted, not zeroed**, for
      an entry with no directory record of its own (the volume root). A hard-linked file has
      one inode and several directory entries, each with its own `date_added`; the one
      published is the canonical (first-discovered) entry's — the same entry whose name and
      path the `FileEntry` carries — not an independently chosen one.
    - [~] **Snapshots:** The object map's `om_snap_count` is **read and published**
      (`snapshot_count`, `snapshots_enumerated: false`), and a volume carrying
      snapshots is stamped incomplete with reason `apfs_snapshots_not_enumerated`.
      Only the live tree is walked, so content that exists **only** in a snapshot —
      including anything deleted since it was taken — is not in the case, and the
      record says so rather than letting the volume read as fully enumerated
      Mounting and browsing snapshots is **not** implemented.
    - [ ] **Firmlinks:** Not implemented — the synthesised System+Data root is not
      resolved.
    - [ ] **Decryption:** **Not implemented.** An encrypted FileVault volume is
      detected, emitted with `encrypted: true` and skipped; per-file-encrypted
      extents are emitted as holes with `content_encrypted: true` and an
      `encrypted_extent_count`. No recovery key or password path exists.

### `seance_plugin_hfsplus` (Legacy)
**Responsibility:** Parsing HFS+ and HFSX (Mac OS Extended) for older drives and DMGs.
- **Subscribes To:** `ArtifactType::FileSystem`, gated on `subtype == "hfsplus"` or a
  `filesystem_type` of HFS+, HFSPLUS or HFSX.
- **What it reads** (`seance_plugin_hfsplus/src/lib.rs`, against Apple TN1150):
    - The volume header at offset 1024, `H+` / `HX`.
    - Each file record's `UF_COMPRESSED` flag, which is the one byte that
      distinguishes an empty file from a compressed one.
    - The catalog B-tree, reconstructed from the catalog fork's extents: one
      `FileEntry` per file and folder, with **three** of the five catalog dates
      (u32 seconds since 1904, GMT) — `createDate`, `contentModDate` and
      `accessDate` — and the file id. `attributeModDate` and `backupDate` are
      in the record and are not published, so **no entry carries a backup
      date**.
    - The data fork's extents, attached to each regular file as a content
      `DataSource`, so the file's bytes are readable.
- **What it does not read, and the gap is stated because this page is what an
  examiner consults to know what the build reaches**:
    - **No extended attributes and no resource forks.** The attributes B-tree
      is not read at all, so a resource fork's contents — where classic Mac
      applications and some document formats keep real data — are not
      recovered and are not listed. ≈ 2 d.
    - **No journal.** `.journal` / `.journal_info_block` are not parsed, so a
      transaction that had not yet been checkpointed is not recoverable here.
      ≈ 3 d.
    - **Free space is not published as carvable regions**, the way the four
      filesystems in §5.4 do. The allocation file is read only by the deleted-entry
      recovery pass below. ≈ 1 d.
    - **File slack is published**: the unused tail of a
      live file's last allocation block becomes a `SlackSpace` region when it holds
      a non-zero byte, located from the fork's whole-block extents and not from
      the trimmed `data_runs`; a compressed file and one whose extents continue in
      the overflow tree are counted as not located. Graded on the HFS+ partition
      of the CFTT string-search unix image (`VALIDATION.md` `HFS-SLACK-1`). APFS
      publishes it too, from its whole-block extents (`VALIDATION.md` `APFS-SLACK-1`).
    - **The extents-overflow B-tree is not followed.** Only a fork's first
      eight extents, the ones in the catalog record, are read — so **any file
      fragmented beyond eight extents is content-incomplete**, and a catalog
      whose own overflow records matter is a prefix listing. This is the
      largest of the gaps on this list.
      ≈ 2 d.
    - **HFS+ compression (`decmpfs`) is not decoded.** A compressed file's
      data lives in the `com.apple.decmpfs` extended attribute or the resource
      fork, and neither is read. Such a file is recognised, from the
      `UF_COMPRESSED` bit in its own catalog record's
      `permissions.ownerFlags`, and stamped `compression: hfsplus_decmpfs`
      with `content_incomplete` and reason `compressed`, so it is not
      published as a complete zero-byte file. Its bytes are still
      not recovered and its real length, which is in the decmpfs header, is
      still unknown: the size on the record is the data fork's, which is zero.
      Decoding it is ≈ 2 d and `seance_plugin_apfs` already has the
      decompressors (`decmpfs.rs`, `lzvn.rs`) to borrow.
    - **An HFSX volume is stamped `HFS+`**, so the case does not distinguish
      the case-sensitive variant from the case-insensitive one.
- **Deleted-entry recovery (`ROADMAP` §5.6).** The live-tree walk
  above reads only live catalog records. A separate unallocated-space
  pass recognises an orphaned catalog leaf node — one sitting entirely in blocks the
  volume's allocation-file bitmap marks free — through the same record decoder the live
  walk uses, and reconstructs a deleted file's name and, where its data-fork blocks are
  confirmed still unallocated, its content. A block since reallocated to something else is
  reported as `content_not_recoverable_reallocated`, never substituted with the new
  occupant's bytes; one that is itself out of bounds or inconsistent is reported
  `content_not_recoverable_unreadable`. Requires the allocation-file fork
  (`VolumeHeader::allocation_fork`, TN1150 offset 112); absent or unreadable, the pass
  does not run rather than guess "free" for blocks it never checked.

---

## 2. System Configuration & Identity

### `seance_plugin_host_identity` — macOS half
**Responsibility:** The machine's own identity — "whose Mac is this?".
- **Subscribes To:** `ArtifactType::FileEntry` / `FileContent`, matched on **path**
- **Input Capability:** `InputCapability::RandomAccess`
- **Output:** `ParsedRecord` of type `HostDeviceInfo`, `platform: "macos"`, in the same
  `facts` / `fact_sources` shape the Android property records use, so
  `GET /cases/{id}/device_info` folds it with the phones and the System Info screen renders a
  "Mac" card
- **Files read:**
    - `/System/Library/CoreServices/SystemVersion.plist` — `os_name` (`ProductName`),
      `os_version` (`ProductVersion`), `build_id` (`ProductBuildVersion`)
    - `/Library/Preferences/SystemConfiguration/preferences.plist` — `host_name`
      (`System.Network.HostNames.LocalHostName`), `computer_name` (`System.System.ComputerName`)
      and `dns_host_name` (`System.System.HostName`)
- **Rules:**
    - The computer name and the local host name are different strings — "Eli's Mac mini"
      against `Elis-Mac-mini` on the Magnet 2021 image — and are reported as different facts,
      never collapsed into one "name".
    - Matched by path, because `preferences.plist` is one of the commonest file names on a Mac;
      the path suffix is matched, so a volume-UUID prefix still resolves.
    - XML and Apple binary property lists alike. A file at one of these paths that does not
      parse, or that parses and states none of the identity keys, is recorded as unread rather
      than passed over.

### `seance_plugin_installed_apps::macos`
**Responsibility:** What is installed on the machine.
- **Subscribes To:** `ArtifactType::FileEntry` / `FileContent` — a bundle's
  `Contents/Info.plist`
- **Output:** `ParsedRecord` of type `InstalledApp`, `platform: "macOS"`
- **What it reads:** `CFBundleIdentifier`, `CFBundleDisplayName` / `CFBundleName`,
  `CFBundleShortVersionString`, `CFBundleVersion`, `CFBundleExecutable`,
  `LSMinimumSystemVersion`, `DTSDKName`, and the bundle path.
- **Rules:**
    - Only the bundle's top level is an application. Safari's XPC services and frameworks each
      carry an `Info.plist`; counting them would make one application read as thirty.
    - `installed_in` (`system` / `applications` / `user`) is written only when the path in the
      case says so. A subtree ingested on its own gives `/Safari.app/Contents/Info.plist`, which
      states nothing about where the folder sat, and answering "elsewhere" there would be a
      finding drawn from silence.
    - A bundle with no identifier is named by its folder; one whose `Info.plist` will not parse
      is still inventoried, with the reason — it is installed either way.

### `seance_plugin_macos_config` (planned — the rest of §2)
**Responsibility:** Extracting the remaining system configuration.
- **Subscribes To:** `ArtifactType::FileEntry` (Plists)
- **Input Capability:** `InputCapability::Stream`
- **Output:** `ArtifactType::SystemArtifact`
- **Target Files:** (the identity plists above are covered by `seance_plugin_host_identity`)
    - `/Library/Preferences/SystemConfiguration/preferences.plist` (Network services).
    - `/private/var/db/SystemPolicyConfiguration/KextPolicy` (Kernel Extensions).
    - **NVRAM:** Extract variables like `boot-args` and `csr-active-config` (SIP status).

---

## 3. User Activity & Artifacts

### `seance_plugin_fsevents`
**Responsibility:** Parsing filesystem events database (historical file operations).
- **Subscribes To:** `ArtifactType::FileEntry` (`.fseventsd/sl-*`)
- **Input Capability:** `InputCapability::Stream` (GZIP support required)
- **Output:** `ArtifactType::TimelineEvent`
- **Features:**
    - Parse GZIP-compressed pages.
    - Map Event IDs to timestamps.
    - Reconstruct file deletion, creation, and renaming history.

### `seance_plugin_spotlight`
**Responsibility:** Parsing Spotlight index databases.
- **Subscribes To:** `ArtifactType::FileEntry` (`.Spotlight-V100/Store-V2/.../store.db`)
- **Output:** `ArtifactType::ParsedRecord`
- **Selected by** the `8tsd` magic, not the name: `store.db` is one of the most-reused
  file names on a disk.
- **Shipped** as `seance_plugin_macos_artifacts::SpotlightStoreParser`
  (`macos.spotlight_store`). What it reads, and what it does not:

| Block | Id | Status |
|-------|----|--------|
| Property table | `0x11` | **Decoded.** Every attribute the store's index held, with the property and value type the table declares for it. 130 named plus 6 of Apple's `_kMDXXXX___DUMMY` placeholders on the corpus's larger store; 53 plus 6 on its smaller one |
| Category table | `0x21` | **Decoded, and read as the two tables it is.** Entries separated by the bytes `0x16 0x02` are localised display names, not content types: 397 content types against 3,703 localisation strings out of 4,100 entries |
| Index tables | `0x81` | Counted and walked. The id lists in them point at item ids; resolving them is not done |
| Item records | `0x09`, `0x4009` | **Decompressed and decoded.** These are **zlib streams beginning at block offset 20**, with the uncompressed length at offset 16 counting those twenty bytes. All 74 in the larger store inflate. The records inside tile the inflated bytes exactly — 14,934 records, no remainder — and each yields its item id, parent, flag byte, index time and **every metadata attribute it carries** |
| Item map | `2mbd`, page 1 | Read for one purpose: it **lists the store's item blocks**, which is a second, independent statement of that population against the page scan. Both corpus stores: the scan and the map name the same pages |
| — | `0x41` | Not decoded. Empty in both corpus stores, so not even measurable |

**The attribute stream.** After the fixed fields, each record carries pairs of a
*delta* added to a running property id and a value whose shape comes from the type that
id declares. There is no terminator and no padding — the stream ends when the record
does — so **one value read at the wrong width desynchronises everything after it**,
which makes exact tiling the test the value encodings have to pass. All 14,936 records
across both stores tile, with **428,124 values decoded** and nothing left over.

Every number in the format is **big-endian behind a leading-ones length byte** (UTF-8's
length trick applied to an integer). A little-endian reading of the same bytes yields
plausible nonsense; the big-endian reading is what makes sibling item ids come out
consecutive — `c1 33 ac` and `c1 33 ad` are 78,764 and 78,765 — and every index time
land in the acquisition window.

**One `SpotlightItem` per indexed file or folder**, carrying the name, the path
assembled from the parent chain, the content type and its whole type tree, the
localised kind, both sizes, the owning uid and gid, where a download came from, the
creation / modification / added / last-used dates, the use count, the bundle
identifier and version — and every other attribute the record holds under its own
`kMDItem…` name.

**What is still not established, stated rather than papered over:**

* the **widest number form** (`0xff` and eight bytes): its byte count is pinned, its
  value is not, and it occurs **once** in the corpus — a value read through it is
  emitted flagged, not quoted;
* the record's **flag byte** (five values occur) and the **unnamed number** before the
  parent reference (0 to 190,374) — both published as what was seen;
* `value_type`'s bits other than `0x02` (a list) and `0x80` (localised): a decoder
  ignoring the rest tiles every record;
* the **leading byte** of each localised-label entry, and the meaning of the `0x16 0x02`
  separator itself;
* nine of the 33 value shapes rest on **one to five observations plus plausibility
  rather than on tiling** — the integer and date arrays, the two float types, the
  blobs. Tiling is a razor for the frequent pairs and nearly blind for the rare ones.

**A path cannot always be assembled.** 967 of the larger store's items name a parent
the store does not hold, because a volume's index is split across stores. Those are
reported **without** an absolute path, not with a partial one dressed as absolute.

**Two records can carry one item id** — four pairs do — where the store kept a
superseded version beside the current one. Both are emitted with their own index times,
because deduplicating on the id alone picks the older stub.

**An id means nothing outside its own store.** The two stores on the corpus machine
hold 44 property ids in common that carry different values, because the tables are
built up per volume as Spotlight meets things. Every record names the store it came
from for that reason.

### `macos.unifiedlog_catalogue` — `/var/db/uuidtext`

A unified-log message on disk is not text. The `.tracev3` firehose records a
*reference* — a binary image and an offset into it — plus the arguments, and the
words come from a **format string** in this tree. Two file kinds hold them:

| Kind | Magic | Layout | The check it passes |
|---|---|---|---|
| Per-image entry, `uuidtext/<2 hex>/<30 hex>` | `0x66778899` | 16-byte header (`magic`, `major`, `minor`, `range_count`), `range_count` × (`u32 offset`, `u32 size`), each range's bytes in order, then the binary's path as the one NUL-terminated string left | **The tail holds exactly one NUL.** 274 of 274 on the corpus |
| Shared cache, `uuidtext/dsc/<32 hex>` | `hcsd` | 16-byte header (`magic`, `u16` major, `u16` minor, `range_count`, `image_count`); **version 1** (to Big Sur): `range_count` × 16-byte ranges (image index, range start, data offset, size), `image_count` × 28-byte images (load address, size, 16-byte UUID, path offset); **version 2** (Monterey and later): 24-byte ranges (64-bit range start, data offset, size, 64-bit image index) and 32-byte images (64-bit load address, then the same); then the strings and paths | **The image table ends at exactly the byte the first range's data begins at** — 27,300 in both Magnet-corpus caches — and every range data offset lands in the string area. All ten caches in the six Mandiant archives (five v1, five v2) pass |

Selection is **by magic alone**: every file in the tree is named in hexadecimal,
so there is no name to select on.

**Why it is read on its own.** It is what a `.tracev3` is decoded against — a
reader that cannot read it produces no log text however well it walks the
firehose. And it is an **inventory of the code on the machine that logs**: every
binary with its path, its UUID and its load address. That survives the log
files. **On the corpus image the `diagnostics` tree holds no `.tracev3` at all**
while this tree is intact, so the catalogue is the only thing left on it saying
what was running — and it is why §1.6's per-message decode cannot be graded here.

**A catalogue is not a log, and every record says so.** It holds the sentences
the OS *would* have substituted arguments into. Nothing here is evidence that
any of them was written, and a catalogue entry is **not** a record that the
binary ran.

**An entry file's UUID is its file name, not its content.** The 32 hex digits a
log reference resolves through are the directory name plus the file name; they
are nowhere in the file. A copy under another name cannot be matched to a log
reference, and the record says that rather than omitting the field.

**274 files are 262 binaries.** Twelve paths appear twice under two different
UUIDs — two builds of the same binary. Nine are Bluetooth and power components
(`bluetoothd`, `IOBluetoothFamily` and its four plug-ins, `BluetoothReporter`,
`powerd`, `pmset`) and two are `templateMigrator` and `recoveryos_agent`: the
shape of an OS update, or a recovery variant beside the installed one.

**The format strings are counted, not emitted.** 848,768 across the corpus tree.
They are Apple's own source text, so each image's count and a bounded sample are
reported and the strings are read in full for a decoder's use. 33 of the corpus
cache's 527 images have no format strings at all; that count is published,
because a log reference into one of them will not resolve here.

Graded as `MACOS-UUIDTEXT-1` in `documentation/VALIDATION.md`.

### `seance_plugin_macos_user_activity`
**Responsibility:** Extracting user-centric artifacts.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Output:** `ArtifactType::TimelineEvent`
- **Target Artifacts:**
    - **Quarantine Events:** `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` (Downloaded file history).
    - **Recent Items:** `~/Library/Application Support/com.apple.sharedfilelist/*.sfl2` (Recent documents/apps).
    - **Dock:** `~/Library/Preferences/com.apple.dock.plist`.
    - **QuickLook:** `/var/folders/.../com.apple.QuickLook.thumbnailcache/index.sqlite` (Thumbnails of viewed files).
    - **Terminal History:** `~/.zsh_history`, `~/.bash_history` (with timestamp recovery).

---

## 4. Log Analysis (Unified Logging)

### `seance_plugin_unified_logs`
**Responsibility:** Parsing the binary Unified Logging format (`.tracev3`).
- **Subscribes To:** `ArtifactType::FileEntry` (`/var/db/diagnostics/*`)
- **Input Capability:** `InputCapability::RandomAccess` (Complex binary + UUID mapping)
- **Output:** `ArtifactType::TimelineEvent`
- **Claiming a file:** a `.tracev3` name, or the header tag (`0x1000`) **plus**
  corroboration — at least one Catalog (`0x600b`) or Chunkset (`0x600d`) chunk.
  The tag alone is four bytes spelling the integer 4096, which opens many
  unrelated binaries: on DFRWS 2021's Raspberry Pi image it claimed the Pi
  firmware `sw_bundle_init.bin` as three Apple Unified Logs with nothing in
  them. A file the OS itself named `.tracev3` is still reported
  whatever it holds, because there the claim rests on that name and a truncated
  log is a finding rather than a false positive.
- **As built.** What ships is narrower than the design below, and
  every record says where it stops (`messages_decoded`, `catalogue_tree`,
  `content_incomplete`):
    - `macos.unifiedlog` (`tracev3.rs`) walks the chunk framing, reads every
      **catalog** (UUID table, subsystem strings, process entries with pid,
      euid, main and shared-cache UUIDs, sub-chunk table — and checks the
      catalog's own arithmetic), **decompresses every chunkset** (LZ4 `bv41`,
      raw `bv4-`, to `bv4$`), counts the entries inside by kind, and parses
      every **firehose** entry to its tracepoints (`firehose.rs`) — kind,
      thread, continuous time, where the format string lives, and the
      argument items, with private arguments read from the entry's private
      region where the machine recorded them and reported as withheld where
      it did not. The record carries the counts: tracepoints by kind, format
      string locations, the entries the log's own loss records say it dropped,
      and the processes and subsystems the catalogs name.
    - `macos.unifiedlog_timesync` (`timesync.rs`) reads the `timesync`
      database: one record per boot with its UUID, mach timebase, boot time
      and every continuous-time → wall-clock anchor.
    - `unifiedlog_resolve.rs` is the **resolver and formatter** — a tracepoint's
      reference followed through the same machine's `uuidtext` entries and
      `dsc` caches (versions 1 and 2), and a printf-style renderer with Apple's
      `%{public}`/`%{private}` annotations.
    - **Wired into the case** (`unifiedlog_decode.rs`) through the core's bounded
      `DataSource::open_from_ancestor` (at most three directories up, then a
      plain relative path). A `.tracev3` read from loose
      files or a ZIP finds its catalogue by name — `../<XX>/<rest>` and
      `../dsc/<UUID>` in a `.logarchive`, `../../uuidtext/…` under
      `/var/db/diagnostics` — and its boot in `../timesync/` (a file at the
      tree's root, such as `logdata.LiveData.tracev3`, looks beside itself
      instead: `catalogue_tree.levels_up` says which), whose sequence
      names are **probed** (0 upward, stopping after 16 misses, at most 256), so a
      timesync file far off the sequence is not seen. Each tracepoint becomes a
      `unifiedlog_message` record under the file's record: rendered `message`,
      `format_string`, pid/euid, process and image paths and UUIDs, subsystem and
      category, level, and `timestamp_rfc3339` with `time_source` —
      `timesync` when the file's boot is in the timesync database, else
      `tracev3_header` from the file's own clock anchor; every record carries
      `dated`, and one neither source can date has no timestamp and says it
      could not be dated in `content_incomplete`. A `%c` argument that is not a
      Unicode scalar value is shown as `<invalid character 0x…>` and counted as
      rendered raw. An unresolved reference
      carries `resolved: false`, its `unresolved_reason` and
      `content_incomplete`, never an empty message; a loss record carries
      `lost_entries`. At most 150,000 message records per file are emitted; the
      counts on the file's `messages` block stay whole past the cap. Parsed
      catalogue files are shared across the files of one tree through a
      process-wide cache (1 GiB budget), keyed by path.
    - **Inside a disk image** (`LogTreeSource`, `data_source.rs`). The APFS and
      HFS+ walkers call `attach_sibling_bundles`, which indexes the volume's
      listing and hands each `.tracev3` a source that climbs and lists within
      that listing (same bounded `open_from_ancestor`, plain relative paths
      only). This is unit-tested on listings; **no image held here carries a
      macOS log tree, so it has not been run on a real one.**
    - **What is not decoded.** A `.tracev3` whose source is not a mounted-volume
      listing (a raw container with no walker) says **"tree not reachable, not
      decoded"** and emits no message. A loose file whose tree is absent says the catalogue was
      not found and emits none either.
    - **Oversize, statedump and simpledump** (`firehose.rs`,
      `unifiedlog_dumps.rs`). An oversize entry (0x6002) holds the arguments of
      a tracepoint too large for its firehose entry; it is joined back by
      (first process id, second process id, `data_ref`) once the whole file is
      read, and the message says `arguments_from_oversize`. One whose entry is
      not in the same file (the log may write it to another) keeps its
      arguments missing and says so — across the Big Sur archive 1,259 are
      joined and 23 are not. A statedump (0x6003) and a simpledump (0x6004) are
      messages of their own (`activity_type` `statedump`/`simpledump`): a
      simpledump's subsystem and text; a statedump's title, object type,
      decoder library and data — a property list decoded to JSON, a protocol
      buffer or custom object kept as `data_hex` (first 4,096 bytes) with
      `data_decoded: false`, never rendered as text. With them the module's
      entries per archive equal Mandiant's pinned totals (High Sierra 569,796;
      Big Sur 747,616; Monterey 2,397,109).
    - A format string's width or precision is clamped to 4,096: it comes from
      the catalogue (evidence), and an unbounded one asked for gigabytes of
      padding or panicked the formatter (the `unifiedlog_tracev3` fuzz
      target covers it).
    - Big Sur `Persist/0000000000000004.tracev3` decoded where it lies: 110,836
      resolved, 108 dynamic-format, 8 unresolved (offset 0x422304 outside its
      entry's ranges) and 1 loss record — 110,953 records, Mandiant's count for the
      file; the first message reads `opendirectoryd (build 796.100) launched...`,
      dated `2022-01-16T03:32:13.964503310Z` through timesync and within 2 s of
      the file's own header clock. The same file laid out as a live
      `/var/db/diagnostics` decodes the same through the two-level climb.
    - **Measured on the six Mandiant archives** (High Sierra → Tahoe, 125
      `.tracev3`): every chunkset decompresses, every catalog tiles, all
      9,900,644 firehose tracepoints read whole. Tracepoints plus statedump and
      simpledump entries equal the per-archive totals Mandiant's tests pin
      (High Sierra 569,796; Big Sur 747,616; Monterey 2,397,109), and Big Sur's
      747,294 tracepoints are the figure those tests quote from Apple's own
      `log raw-dump`. On Tahoe this reader counts one entry fewer (4,288,583
      vs 4,288,584), not yet attributed. Resolved against each archive's own
      tree, the unresolved references by reason equal Mandiant's in all six
      (e.g. Big Sur: 54 offsets outside their entry's ranges; Tahoe: 647 bad
      shared-cache offsets, 268 bad offsets, 2 absent entries). These are a
      **comparison** with another reading, not validation against ground truth.
    - One corpus file (`big_sur_public_private_data_mix`'s
      `Special/0000000000000008.tracev3`) lays 132 chunkset entries out with
      no padding after them; the walk follows them and counts them
      (`entries_without_padding`) rather than breaking.
    - **Screens.** `UnifiedLogMessage` has its own viewer (time, type,
      level, process, subsystem, message and the clock that dated it); a row that
      is not resolved, could not be dated, is a loss record or holds undecoded
      statedump data says so in its row title and shows no invented text.
      `UnifiedLog` (the per-file record) has one too, saying "counted, not
      decoded" when its tree was not reachable.
    - **Magnet 2021 macOS image.** The extracted tree
      (`~/ctf-evidence/macos2021/tree`) holds **no `.tracev3` at all** and no
      `private/var/db/diagnostics`; only two **empty** directories (Preboot
      `PreLoginData/diagnostics/timesync` and `Templates/Data/private/var/db/diagnostics`). Any
      unified-log question set against that image is therefore **not answerable
      from held evidence**; nothing was decoded from it and nothing is claimed.
      The decoder is graded on the Mandiant archives only (comparison, above).
- **Features (design):**
    - **DSC Mapping:** Map UUIDs to shared cache strings (dyld_shared_cache) — *wired: each message resolves through its own tree's `dsc`/`uuidtext` (loose files and ZIPs; inside an APFS or HFS+ image through the volume listing, not yet run on a real image).*
    - **Timesync:** Handle `timesync` files for accurate boot-relative timestamps — *wired: each message is dated through its boot's anchors (`time_source` `timesync`), else by the file header and says so.*
    - **Signpost Analysis:** Visualize performance and activity intervals.
    - **Private arguments:** Read from the entry's private region where the machine recorded one. Where it did not, the argument renders as `<private>`. No key is involved and nothing recovers a value the machine withheld.
    - **Key Events:** USB insertion, Sudo usage, Screen lock/unlock, AirDrop transfers.

---

## 5. Persistence & Malware

### `seance_plugin_macos_persistence`
**Responsibility:** Detecting macOS-specific persistence mechanisms.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Output:** `ArtifactType::PersistenceMechanism`
- **Target Mechanisms:**
    - **LaunchDaemons/Agents:** `/Library/LaunchDaemons`, `~/Library/LaunchAgents` (Parse Plists).
    - **Cron:** `/usr/lib/cron/tabs/*`.
    - **Periodic Tasks:** `/etc/periodic/*`.
    - **Login Items:** `BackgroundItems.btm` (Ventura+).
    - **Emond:** `/etc/emond.d/` (Event Monitor Daemon - Legacy/Malware).

---

## 6. Enterprise & Commercial Features (Advanced)

To rival top-tier commercial tools, Seance must handle Apple's proprietary ecosystem features:

### `seance_plugin_apple_silicon_security`
**Responsibility:** Handling T2/M1/M2/M3 security features.
- **Features:**
    - **Volume Key Recovery:** Interface with `libfvde` to unlock APFS volumes using recovery keys or keychain dumps.
    - **Secure Enclave Analysis:** Identify Biometric (TouchID/FaceID) usage logs (not the bio-data itself, but the *events*).
    - **System Policy Analysis:** Parse `LocalPolicy` to detect reduced security modes (Permissive Security) often used by attackers.

### `seance_plugin_icloud_forensics`
**Responsibility:** Analyzing iCloud synchronization artifacts.
- **Subscribes To:** `ArtifactType::FileEntry` (`~/Library/Mobile Documents`, `CloudDocs`)
- **Features:**
    - **Synced Files:** Differentiate between "on-disk" and "cloud-only" (stub) files.
    - **CloudTabs:** Parse `CloudTabs.db` to see open Safari tabs on other devices.
    - **Find My:** Analyze location beacons and device tracking logs.

### `seance_plugin_airdrop_analysis`
**Responsibility:** Detailed reconstruction of AirDrop transfers.
- **Subscribes To:** `ArtifactType::FileEntry` (Unified Logs)
- **Features:**
    - **Sender/Receiver ID:** Extract Apple ID hashes and device names.
    - **Transfer Status:** Success/Failure/Declined.
    - **File Metadata:** Filenames and types transferred.
    - **Protocol Analysis:** Distinguish between "Everyone" and "Contacts Only" discovery modes.

### `seance_plugin_knowledgec`
**Responsibility:** Parsing the `knowledgeC.db` (CoreDuet) database.
- **Subscribes To:** `ArtifactType::FileEntry` (`/var/db/CoreDuet/Knowledge/knowledgeC.db`)
- **Output:** `ArtifactType::TimelineEvent` (High fidelity user activity)
- **Features:**
    - **App Usage:** Exact duration of app focus (foreground time).
    - **Web Usage:** Safari history synced across devices.
    - **Device State:** Plugged in, Locked, Screen On/Off.
    - **Audio/Media:** Now Playing info.

---

## What actually shipped, and under which crate

The crate names proposed above were mostly not the names used. Everything in
this table is registered in `seance_api::modules`; the left column is the name
this document proposed, so a reader looking for it can find it.

| Proposed here | Shipped as | Reads |
|---|---|---|
| `seance_plugin_macos_user_activity` (Quarantine) | `seance_plugin_macos_artifacts::QuarantineParser` | `com.apple.LaunchServices.QuarantineEventsV2` — downloading app, direct data URL, referring page, each timestamped |
| — (not proposed) | `…::TccParser` | `TCC.db`, system and per-user — which app was granted or denied camera, microphone, screen recording, full-disk access, automation |
| `seance_plugin_macos_persistence` | `…::LaunchdPersistenceParser` | LaunchAgents / LaunchDaemons job plists. Self-selects by **content** (a `.plist` carrying a `Label`), not by path |
| — (not proposed) | `…::WifiKnownNetworksParser` | `com.apple.wifi.known-networks.plist` and the legacy `com.apple.airport.preferences.plist` — every network joined, with `AddedAt` / last-joined: a movement trail |
| — (not proposed) | `…::InstallHistoryParser` | `/Library/Receipts/InstallHistory.plist` — the system-wide software-provenance timeline |
| `seance_plugin_knowledgec` | `…::KnowledgeCParser` | `knowledgeC.db` `ZOBJECT` — app focus with durations, lock/unlock, backlight, Now Playing, Safari history. **Also serves iOS**, which carries the same file |
| — (not proposed) | `…::NotificationsParser` | `usernoted` `db2/db` — delivered notifications, including the title/body/subtitle out of the binary-plist blob, so iMessage/Slack/Teams alerts that flashed on screen are recoverable |
| — (not proposed) | `…::BomParser` | `/var/db/receipts/*.bom` — what a package actually installed, at file granularity (format verified against hogliux/bomutils) |
| `seance_plugin_unified_logs` | `…::UnifiedLogParser` (`tracev3.rs`) | `*.tracev3`: chunk framing, catalogs, decompressed chunksets and every firehose tracepoint counted; each message **rendered and dated** as a `unifiedlog_message` record when the file's tree is reachable (loose files, ZIP entries, and APFS/HFS+ volume listings — the last not yet run on a real image) — see §4 |
| — (not proposed) | `…::UnifiedLogTimesyncParser` (`timesync.rs`) | `/var/db/diagnostics/timesync/*.timesync` — one record per boot: UUID, timebase, boot time, and the continuous-time → wall-clock anchors a decoder dates entries through |
| — (not proposed) | `…::UnifiedLogCatalogueParser` (`uuidtext.rs`) | `/var/db/uuidtext` — the unified log's **format-string catalogue**, in both forms: per-image entries (magic `0x66778899`) and the `dsc` shared caches (magic `hcsd`). An **inventory of the code on the machine that logs**, which survives the log files — see below |
| `seance_plugin_spotlight` | `…::SpotlightStoreParser` | `.Spotlight-V100/Store-V2/store.db` — the metadata index, **including for files since deleted**. One record per indexed file or folder with its path, content type, sizes, owner, download source and dates; plus the store's own property and category vocabularies. 14,934 items off the corpus's larger store, and **8,782 of the 8,797 decoded sizes match the actual file on the mounted image** — see below |
| — (not proposed) | `…::AppleMailParser` | `~/Library/Mail/V*/MailData/Envelope Index` — Mail's own index of every message it has seen: sender, recipients by header, subject, mailbox URL, the sent / received / last-viewed dates, read, flagged and **deleted** state, size, attachment names and Mail's one-line snippet. An **index, not the mail**: no bodies and no RFC 5322 headers, which the records say on themselves rather than rendering as a message whose body was empty. See below for what it has and has not been proven against |
| — (not proposed) | `seance_plugin_utmp::UtmpParser` | `/private/var/run/utmpx` — who was logged in when the image was taken, at the console and on each terminal, with the boot that preceded them. The same crate that reads Linux `utmp`/`wtmp`/`btmp`; see below for the layout and for what macOS does **not** keep |
| — (not proposed) | `…::OpenBsmParser` | `/var/audit/*` — the OpenBSM audit trail: **the login history macOS actually keeps.** Every record carries the event, the account (by number), the process, the audit session, the terminal port, the remote address, whether the system said yes or no, and the code-signing identity of the binary that asked. A refused authentication is additionally emitted as a `FailedLogin`, the same record type `btmp` produces, so "was there a brute force" is one screen on both platforms |
| — (not proposed) | `…::KeychainParser` | `login.keychain-db`, `System.keychain`, `*.keychain` — an **encrypted store with a cleartext index**. Which services and accounts the person held credentials for and since when, without a password; certificates carried out whole because they are not encrypted; every secret reported as locked with what a lawful recovery attempt needs |
| — (not proposed) | `…::DataProtectionKeychainParser` | `keychain-2.db` — the iOS-style keychain macOS keeps as well. It names **no account and no service** (every such attribute is a SHA-1) but it names the application that owns each secret, the protection class and the sync view — and `ckdevicestate` names **every device the Apple ID's keychain circle has held**, which answered the last open question on the 2021 macOS CTF key |
| `seance_plugin_macos_config` | not built as a crate | Generic plist parsing covers the files; no dedicated extractor |

## macOS login accounting: one file, and the three Linux ones do not apply

macOS keeps the `utmpx` half of the login-accounting family and nothing else.
`/private/var/run/utmpx` holds the sessions open *now*; there is no `btmp`
equivalent at all, and since 10.5 there is no on-disk `wtmpx` or `lastlogx`
either — Apple moved login and logout history into the Apple System Log, which
this module does not read. So on a macOS image this reader answers "who was
logged in when the image was taken", and **not** "who logged in last Tuesday".
That is a limit of the evidence, not of the parser, and the artifacts say so by
carrying `source_file: utmp` (sessions open at acquisition) rather than `wtmp`.

### The record

`struct utmpx` is 628 bytes and is a different record from either Linux layout,
not a variant of one: the strings come **first** and are far longer (`ut_user`
is 256 bytes against glibc's 32), `ut_type` sits at 296 rather than at 0, and
there is no `ut_addr_v6`, no `ut_session` and no `ut_exit`. Read at glibc's
offsets a Darwin record takes its record type out of the middle of a username.

The offsets in `DARWIN_UTMPX_628` (`seance_plugin_utmp/src/record.rs`) were
derived from the real `/private/var/run/utmpx` in the Magnet 2021 macOS image —
2,512 bytes, exactly four records — and each is corroborated by something in
the file rather than assumed. `308 + 256 + 64 = 628` accounts for every byte;
`tv_sec` is a **32-bit** `time_t` at 300, identified by scanning for a
plausible-range value that agreed with the file's own mtime; and the four
records read as one coherent session (boot with `ut_pid` 1, a `console` login,
then `ttys000` for the same user, in that order).

Three consequences are deliberate and are pinned by tests:

* **No remote address is reported.** Where glibc keeps `ut_addr_v6`, Darwin has
  `ut_pad[16]`. Reading it would be invisible on the common case — an all-zero
  pad decodes to "no address" — and would produce one confident, fictional
  remote host on the first record whose pad was not zero. A macOS login over
  SSH is attributed by `ut_host`, and where that is empty the honest answer is
  that the file does not say.
* **`ut_id` is opaque bytes, not a string.** The corpus's `console` record holds
  `2f 00 01 01`; as text that is the single character `/`, and the bytes after
  the NUL fail the text-cleanliness check — which would flag the one login
  record an examiner most wants as anomalous. A non-textual id is rendered as
  `0x2f000101` instead, and its cleanliness is not a sanity signal.
* **The signature record is provenance, not an event.** Every macOS `utmpx`
  opens with a `SIGNATURE` record carrying the literal `utmpx-1.00` and every
  numeric field, timestamp included, zero. It is reported as `format_version` on
  the status row — the only corroboration of a chosen layout in this family that
  comes from content rather than from field plausibility — and it reaches no
  timeline.

### The `ut_type` enumeration is part of the layout

Two records can share a stride and still disagree about what a field *means*.
Darwin's enumeration **swaps `OLD_TIME` and `NEW_TIME`** relative to
`utmp(5)` — three and four mean opposite things — and adds `SIGNATURE` (10) and
`SHUTDOWN_TIME` (11), which Linux has not got. A macOS clock-change record read
against `utmp(5)` therefore reports the wall clock as having moved in the wrong
direction, with no visible symptom; and a Linux-only reading rejects the first
record of every macOS `utmpx` as out of range.

The enumeration therefore travels with the layout as a `TypeDialect`, is named
on every artifact as `record_type_dialect`, and a Darwin-only value carried by a
glibc file is still reported as anomalous.

Provenance, since these differ in what backs them. Two are **corroborated on
disk**: `SIGNATURE` = 10 by the corpus file's own first record, and
`SHUTDOWN_TIME` = 11 by the Apple System Log stores in `/var/log/asl`, which
carry the same login-accounting records as text and write
`SHUTDOWN_TIME: <seconds> <microseconds>` beside `ut_type = 11` — four times on
this image, with `USER_PROCESS`/`DEAD_PROCESS` likewise beside 7 and 8. The
`OLD_TIME`/`NEW_TIME` swap is still taken from Apple's `<utmpx.h>`, whose
lineage is NetBSD's — the `utmpx(5)` man page shipped on macOS is NetBSD's file,
copyright notice and all — because the corpus holds no macOS clock-change
record. That is stated in the code and pinned by a test, so a future change to
the mapping fails loudly rather than quietly.

## The Apple System Log: where macOS's `wtmpx` went

`utmpx(5)` on macOS says it plainly: *"Traditionally, separate files would be
used to store the running log of the logins and logouts (`wtmpx`), and the last
login of each user (`lastlogx`). With the availability of the Apple system log
facility these separate files can be replaced with log entries, which are
automatically generated when `utmpx` entries are written."*

That is the answer to the gap the previous two sections describe. `/var/run/utmpx`
holds only the sessions open at acquisition; there is no `btmp` and no on-disk
`wtmpx`. The **history** is in `/var/log/asl/*.asl`, under the facilities
`com.apple.system.utmpx` and `com.apple.system.lastlog`, as text records
carrying the very `struct utmpx` members the binary reader decodes.
`AslParser` (`macos.asl`) reads it.

What that recovers on the corpus image, from eleven stores:

| Figure | Result |
|---|---|
| Message records | 7,022, plus 5,774 string records |
| Login-history records | **32** — 19 `utmpx` and 13 `lastlog` |
| Boots / clean shutdowns | 6 / 4 |
| Login sessions reconstructed | Console, `ttys000` and `ttys001`, all `eliflatt` |
| Sessions naming a remote address | **3**, from `184.171.155.71` and `184.171.149.230` — and with both ends recorded, so the longest is stated as a duration of hours rather than bounded |
| Stores that did not tile exactly | 0 |
| `next`/`prev` chain breaks | 0 of 7,022 |

The store spells out
`SHUTDOWN_TIME:` beside `ut_type = 11`, so a value the binary reader had taken
from Apple's header is observed; and the `console` record's `ut_id` is the
four opaque bytes `2f 00 01 01`, which Apple's own logger renders as
`0x2f 0x00 0x01 0x01` — the same choice `seance_plugin_utmp` made
independently.

### The format, and what corroborates it

An 80-byte header, then a flat sequence of records: `u16` type, `u32` length,
payload. Type 1 is a string; type 0 is a message. Messages are a **doubly
linked list** through their first and last eight bytes, and a message's string
fields are eight-byte slots that either carry a big-endian offset of a string
record or, when the high bit of the first byte is set, the string **inline** in
the slot itself — which is how nine thousand of the corpus's references are
stored.

Four independent checks fix the layout, and all four hold across the whole
corpus:

1. the records tile exactly from offset 80 to the last byte of every file, with
   no unknown record type;
2. the header's `first` field equals the offset of the first message, in every
   file;
3. a message's length is exactly `116 + 8 × its own key/value slot count` in
   every one of the 7,022 — which is what fixes the fixed part at 60 bytes, the
   six reference slots at 48 and the trailing `prev` at 8;
4. the `next`/`prev` chain agrees with file order in both directions, with no
   break.

Field meanings come from content, not assumption: the first record's `time`
equals the header's, its `pid` 1191 matches the `objc[1191]` in its own message
text, and its `uid` 501 and `gid` 20 are the account's. Two fields are read as
**access control** rather than identity — a read-uid of `-1` (anyone) and a
read-gid of 80 (`admin`) in all 7,022 records, which is what a default ASL read
policy looks like — and the `-1` is reported absent rather than as uid
4294967295.

### Four refusals

* **No resynchronisation**, and **no skipping an unknown record type** even
  though its length is known: a store holding a third record type is not the
  format this reader was shown, and reading past it would be reading it against
  a guess. The walk stops and the remaining bytes are reported with the reason.
* **No session across stores.** A login is paired with a logout inside one
  store, on the terminal the records name. A login whose logout is in the next
  day's store is `gone_no_logout` / `end_of_file`, with no duration; a logout
  whose login is in the previous day's is counted, never given an invented
  start.
* **The session's own time, not the message's.** `ut_tv.tv_sec` is when the
  event happened; the message is timed when `syslogd` wrote it. The two differ
  by seconds in the corpus and by minutes in one case, so the session carries
  its own time and the message keeps its own beside it.
* **The `AUX.<date>/` directories are not read.** They hold the payloads some
  messages point at.

The pairing rules are not this reader's own: they are
`seance_login_sessions::SessionPairer`, the engine `seance_plugin_utmp` pairs a
binary `wtmp` with (`ROADMAP` §5.11). What stays here
is the classification of Darwin's textual `ut_type` values — `USER_PROCESS` (7)
opens, `DEAD_PROCESS` (8) closes, `BOOT_TIME` (2) and `SHUTDOWN_TIME` (11)
bound. It stops opening sessions at the cap, like the
`wtmp` reader; the status row's `utmpx_records_unpaired` still counts both an
unpaired logout and a record of a type or time it cannot read.

One classification difference is deliberate: the `wtmp` reader treats a record
with an empty `ut_user` on a terminal as a logout whatever its type, because
Linux login programs write logouts that way. The textual `utmpx` records carry
an explicit `ut_type`, and this reader has seen no Darwin logout written
without `DEAD_PROCESS`, so it reads the type only.

## The keychain: an encrypted store with a cleartext index

The classic `kych` keychain — the CDSA/`securityd` database, which macOS 11
still uses for the login and system keychains — encrypts each item's **secret**
and leaves each item's **attributes** in the clear. The service, the account,
the label, the description, the comment and the creation and modification dates
sit in the file as plain text.

So a keychain nobody can open still answers *"which services and accounts did
this person hold credentials for, and since when"*. On the corpus image, with no
password supplied:

| From | What it says |
|---|---|
| `login.keychain-db`, service `iCloud` | `PrintName` **`e.flatt610@gmail.com`** — the account's Apple ID — with Apple account number `20118734345`, stored 2021-02-12 |
| service `iOS Backup`, creator `aapl` | An iOS backup was made on this machine, keyed `518e8d766f9b3e76db216f35fdb6b0604e50f61b` |
| `System.keychain`, service `AirPort` | A stored **wireless network password** for SSID `Guest`, description "AirPort network password" — a network this machine had credentials for |
| `System.keychain`, two X.509 records | `com.apple.systemdefault` and `com.apple.kerberos.kdc`, carried out as `.cer` artifacts because a certificate in a keychain is **not** encrypted |
| 52 items in the login keychain | 23 generic passwords, 23 symmetric keys, 3 public and 3 private keys — every one with its secret reported `locked` |

### The schema is read from the file, not hard-coded

A keychain carries its own relational schema: `CSSM_DL_DB_SCHEMA_INFO` names
every relation and `CSSM_DL_DB_SCHEMA_ATTRIBUTES` declares every attribute of
every relation with its storage format. The reader reads both and decodes each
record by the file's own declaration.

That is not a stylistic preference. The two corpus keychains disagree with each
other — eleven relations against twelve, eighty index declarations against
ninety — and a table hard-coded for one mis-attributes the other. More
sharply: **the password relations number their attributes by four-character
code**, so declaration order and numeric order are different, and a reader that
sorted by id would read every value at the wrong offset *while still producing
entirely legible output* — an account where a date belongs, a service where an
account belongs. That is pinned by
`the_attribute_order_is_the_schemas_own_and_not_the_attribute_ids`.

Reading the schema also settled a fact worth having: the `CSSM_DL_DB_SCHEMA_*`
relation ids are **1 = ATTRIBUTES and 2 = INDEXES**, the reverse of the order
the tables appear in. The attributes relation is therefore located by *name*.

### What the file corroborates about itself

Every step is checked against the file's own arithmetic rather than taken on
trust: the header's `schemaOffset` plus the schema's `schemaSize` lands at the
end of the file; each attribute offset resolves inside its own record; the
attribute data begins exactly where the item's payload ends
(`24 + 4 × attributes + dataSize`), leaving no slack for a different header;
and each table's `recordCount` equals the number of live records found.

That last check is load-bearing. A table's record-number array mixes zeros for
unused slots, **free-list links** (odd values, being offsets into the array
itself with the low bit set) and **live record offsets** (even, and at or past
the table's first-record offset). Telling the second from the third is the one
rule here that a wrong reading would get wrong while still producing plausible
records — so when the count it yields disagrees with the table's own, the
disagreement is reported on the status row and the items carry the caveat.

### Nothing is decrypted and nothing is guessed

Every item's payload is classified from its own first four bytes, not from its
relation: `ssgp` for a password's wrapped secret, the `0xFADE0711` blob magic
for a wrapped key, and no wrapper at all for a certificate's raw DER. A wrapped
payload is reported `locked` with the sentence *"An absent password here is NOT
evidence that the item held none"*. A payload that carries **neither** tag where
one is expected is reported as its own state rather than folded into "locked":
a secret stored unwrapped would be a finding, and so would a payload this
reader has misidentified.

The status row carries what a **lawful password-recovery attempt** needs, in one
place: the `DbBlob`'s PBKDF2 salt and CBC initialisation vector, the iteration
count the format fixes at 1,000 (it is not stored in the file, so it is stated
rather than left to be assumed), the cipher, and the **offset** of the wrapped
master key. The wrapped key is named by offset rather than copied into a record
that ends up in a report. Where no `DbBlob` is found, that is said — and said as
a statement about the file rather than about the items, whose secrets remain
unread either way.

### Still missing

**Decryption.** With a keychain password, or `/var/db/SystemKey` for the system
keychain, the master key unwraps and each item's secret decrypts. The first step
is wired and graded: a password supplied as the `macos_keychain_password`
credential is checked against the `DbBlob` (PBKDF2-HMAC-SHA1, 3DES-CBC), the
status record says `password_state: accepted` or the run is rejected, and the
master key is zeroed and never written. It is graded on two real openwall
keychains with published passwords (`VALIDATION.md` `KEYCHAIN-1`). `System.keychain`
has no password: the `macos_system_key` credential (the 48 bytes of `/var/db/SystemKey`
as hex, bytes 8 to 32 being the 3DES key that unwraps the `DbBlob` with no PBKDF2) opens
it the same way, and the reveal request takes `{"system_key": "<hex>"}` in place of
`{"password": ...}`. Graded on the macOS 11.2.1 `System.keychain` and `SystemKey` of the
Hickman Big Sur image (`tests/keychain_system_key.rs`). The second
step, decrypting an item under that key, is graded on one keychain (`VALIDATION.md` `KEYCHAIN-2`): moond4rk/keychainbreaker's `test.keychain-db`, made by
macOS's `security` command, with a published password and answer. A password item is
matched to its symmetric key record by the 20-byte label, the item key is unwrapped under
the master key and the secret decrypts: four items of four, `password#123` each. A
decrypted item is marked `secret_state: withheld` with its length and the secret is in no
record, export or index; it is released by an audited reveal route (below). Private keys stay locked, `/var/db/SystemKey` is not
accepted, and the item-key layout is graded on this one file from one macOS version.

## The other keychain, and what it refuses to name

macOS 11 keeps **two** keychains and they are different databases with different
honesty. The classic `kych` file above is an encrypted store with a cleartext
index. `~/Library/Keychains/<UUID>/keychain-2.db` — the iOS-style
data-protection keychain, read by `DataProtectionKeychainParser`
(`macos.keychain_data_protection`) — is not.

**Measured on the real file** (4.7 MB, schema 11.9): every one of the `acct`,
`svce`, `srvr`, `path`, `atyp` and `sdmn` values is exactly twenty bytes of
non-text. They are SHA-1 hashes of the attribute — 128 of 128 generic items and
158 of 158 internet items, with no exceptions — and even the `cert` table's
subject, issuer and serial are hashed, with its data a wrapped blob rather than
the DER the classic keychain holds. **So this reader reports no account and no
service**, and emits those fields under names ending `_sha1` so that nothing
downstream can render a hash where an examiner reads a username.

What it does state, because these columns are text:

* the **access group** — which application or daemon owns the secret. Fourteen
  distinct ones on the corpus file's generic items, including
  `com.apple.cloudd`, `com.apple.security.sos`, `com.apple.continuity.unlock`
  and `InternetAccounts`. This is the useful answer here, and it is precisely
  what the hashed attributes were hashed to hide;
* the **protection class**, decoded — and the `…ThisDeviceOnly` classes are
  load-bearing, because an item in one never syncs to iCloud Keychain. An item
  in `aku`, `cku` or `dku` **is** written to an encrypted backup, wrapped there
  under a key derived from the device's hardware UID, so it can be restored only
  to the same device (the Hickman iOS 17 backup carries 715 such items, all in
  these three classes). An item in `akpu` (`WhenPasscodeSetThisDeviceOnly`) is
  **not** backed up at all: that class exists only in the system keybag, not in
  a backup or escrow keybag, and its class key is discarded if the passcode is
  removed (Apple Platform Security, "Keychain data class protections"). Either
  way its absence from iCloud Keychain, or from a backup where that applies, is
  explained rather than notable, and the note says which case the item is in.
  Each such item carries `this_device_only: true` and a
  `this_device_only_note` saying so, and the status row counts them as
  `items_this_device_only`;
* the **sync view** — which iCloud keychain view an item syncs in (`Manatee`,
  `PCS-MasterKey`, `AutoUnlock`, `ApplePay`, `Home`);
* the dates, the sync and tombstone flags, and the UUID. A tombstone is a
  deletion that syncs, so its presence is the record of an item removed.

### `ckdevicestate`: the devices the account trusted

One table is entirely in the clear, and it is worth the most. `ckdevicestate`
records, per CloudKit zone, every device the Apple ID's keychain circle has
held: its identifier, its OS and build, its Secure Object Sync circle status,
its Octagon peer id and status, its key state and its current top-level keys.

On the corpus image that is 36 rows naming **three devices** — `macOS 20.3.0
(20D74)`, `iphone 20.3.0 (18D52)` and `watch 19.6.0 (17U63)` — two of which are
not in the image at all. Of the 36, **29 read `kSOSCCInCircle` and 7 read
`kSOSCCError`**: the status is per zone rather than per device, and reporting
only the healthy value would hide that seven of the account's keychain zones
were not syncing.

It is also **the answer to the last open question on the 2021 macOS CTF key**:
the Mac's own Octagon peer id,
`SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=`. `VALIDATION.md`'s
`MAC-1` is 14 of 14, and `MACOS-KEYCHAIN-2` records the answer — it is the **Mac's** keychain,
not the backed-up phone's, and the backup in that image is encrypted anyway.

### Nothing here becomes readable with a password

This is the one difference from the classic keychain that matters most. There,
a keychain password or `/var/db/SystemKey` would unwrap the master key. Here
each payload is wrapped under a class key from the **device keybag**, which is
protected by hardware an image does not carry — so every item is reported
locked and the record says that no password would open it, rather than leaving
an examiner to look for one.

## The audit trail: where the macOS login history is

`utmpx` answers "who was logged in when the image was taken". It cannot answer
"who logged in last Tuesday, and who tried and failed", because macOS keeps no
`btmp` and no on-disk `wtmpx`. `OpenBsmParser` reads the file that does:
`/var/audit/<start>.<end>`, plus the `.not_terminated` trail still being written
and the `.crash_recovery` ones `auditd` leaves behind.

What it gets, on the corpus image: eighteen accepted SSH logins for `uid 501`
from three addresses, **two refused SSH password attempts** from
`184.171.155.71` on 2021-03-25, ten loginwindow logins, ten logouts, six
power-offs, 182 password verifications of which 107 were refused, and the
creation and modification of accounts and groups — 4,327 records in all. The
first record of the `.not_terminated` trail is timed 1617653090, two seconds
after the `BOOT_TIME` in `utmpx`: the two artefacts corroborate each other
without either being consulted for the other.

### The format validates itself, and that is how it is read

A trail is a flat sequence of records; a record is a sequence of
length-prefixed tokens. Two independent facts bracket every record: the
**header** token states the record's total byte count, and the **trailer**
token, which ends every record, carries the magic `0xB105` and *repeats* that
count. So record boundaries are never guessed, and a record whose tokens do not
tile exactly into the space between its header and its trailer is reported as
unresolved rather than believed.

That check is what makes the remaining token lengths safe. A mistake in any one
of them shifts everything after it, and the trailer then fails to land on the
last seven bytes. The lengths themselves were checked against the nine real
trails: **4,327 records, and the walk ends exactly on the trailer in every one,
with no unknown token and no length that overruns.** The nine token types those
records use are corroborated 4,327 times over; the rest are from OpenBSM's
`bsm/libbsm.h` and are guarded by the tiling check.

It is also why the reader **self-selects by content**. A file whose first record
validates on both counts is a trail whatever it is called — including one carved
out of free space — and a file that does not is passed over in silence, unless
it sits where trails live, in which case a refusal record says so. A wiped
`/var/audit` entry is a finding, not an absence.

There is deliberately **no resynchronisation**. Scanning forward for the next
plausible header would turn a fragment of some other file into a set of
confident audit records. A trail whose records stop tiling stops being read, and
the remaining bytes are reported as a count with the reason.

### A failed login is a refused *credential*, not a refused operation

The `FailedLogin` line is drawn on whether **a secret was offered**, and
deliberately not on the audit class. The `aa` class holds Security Server
*authorization* decisions as well — `AUE_ssauthorize`, `AUE_ssauthmech`,
`AUE_ssconn`: "is this process allowed to do X" — which is policy, not
credentials, and which fails routinely. Across these nine trails, on a machine
nobody attacked, those two events fail **387 times**. Drawing the line on the
class would have put 387 rows on the screen an examiner reads to answer "was
there a brute force" and buried the two attempts that were real.

So the reader carries a per-event `credential_attempt` flag (`AUE_openssh`,
`AUE_auth_user`, `AUE_lw_login`, `AUE_sudo`, `AUE_su`, and the rest of the
events at which a password or key is presented), and 109 of the 4,327 records
become `FailedLogin` rows. The other 388 refusals are still counted, as
`other_refused_operations` on the status row with a note saying what they are,
so "no failed logins" is never read as "nothing was refused". Every refusal
also remains an `AuditEvent` with `outcome: failed`, searchable and on the
timeline. All of this is pinned by
`a_refused_security_server_authorization_is_not_a_failed_login` and by the
corpus test's three counts.

### Three refusals to invent

* **No sessions.** BSM records events. A loginwindow login and the logout that
  ended it are written by *different processes* — pid 107 and pid 150 on this
  image — so pairing them would be inference dressed as a record. No duration
  is reported, and the status row says why.
* **No account name.** The trail identifies an account by number (`auid`,
  `euid`, `ruid`). `sshd`'s own message, `invalid password for user eliflatt`,
  is quoted verbatim as the text token it is and **not parsed** into a `user`
  field: its wording is specified nowhere, and resolving 501 to a name needs a
  file this reader is not handed. The viewer shows the number.
* **No event name for a number outside the table.** Event identifiers and their
  symbols are shipped for the login, authentication and administration classes —
  the whole surface a login question is answered from, and every one of the
  twenty-one identifiers the corpus uses. An event outside it is reported by
  number, marked `unmapped`, with the note that its class, which is what decides
  whether it is a login record, is unknown. Where Apple's own table gives one
  number two names (6168 is both `AUE_shutdown` and `AUE_poweroff`), both are
  shown and neither is presented as the event's name.

The header's second time field is **milliseconds**, which is measured rather
than assumed: across the 4,327 records its maximum is 998 and it never reaches
1,000, where a microsecond field would have spread to 999,999. A value at or
past a full second is therefore out of range for the field and is reported as
absent rather than folded into the timestamp, which would move the event.

### Still missing

The Apple System Log (`/var/log/asl/*.asl`) carries the same login history in
a second place and is neither parsed nor carved — the carver's `ASL` signature
is Adobe Layer Style (`8BSL`) and can never match an Apple System Log store.
That is `ROADMAP` §1.6's remaining bullet.

## Apple Mail's index: read against Apple's schema, not against Apple's data

`AppleMailParser` is the one artifact reader here whose joins have never been
run over rows Apple wrote, and it says so on every record
(`basis: "schema_verified_rows_unverified"`).

**What is Apple's.** The schema. `tests/fixtures/envelope_index_v8_schema.sql`
is `sqlite3 ".schema"` from a real macOS 11 `Envelope Index` — Mail V8, database
version 4.30006, framework 3654.60.0.2.21 — out of the Magnet Virtual Summit
2021 macOS CTF image, and every test builds its database from that DDL. The
column names, the foreign keys and the `UNIQUE(address, comment)` and
`UNIQUE(url)` constraints the fixture has to honour are therefore Apple's, which
is what `documentation/TESTING.md`'s rule about using at least one input this
project did not write asks for.

**What is not.** The rows. That database's tables are **empty** — Mail was
opened on the machine and no account ever synced — so no message row here has
come from a mailbox Apple populated, and the field mapping is unconfirmed on
real mail. It ships anyway, for the reason the memory tier above ships
unvalidated: an examiner can discount a result that states what it has not been
proven against, and cannot discount one they were never shown.

**Two things it will not assert.** The **timestamp basis**: `date_sent`,
`date_received` and `date_last_viewed` are integers, read as Unix epoch seconds
because that is what Mail writes in every version examined — but with no
populated database to confirm it against, `date_basis` names the assumption on
every record rather than presenting the instant as established. A date read
under Core Data's 2001 epoch instead, which `knowledgeC.db` a few files away
really does use, would be 31 years out and would look entirely ordinary. And the
**`Message-ID`**: `messages.message_id` is an *integer hash* in this schema, not
the header, so it is published as `message_id_hash` with that said on it and the
field that elsewhere holds an RFC 5322 `Message-ID` is left absent.

**Why the index is worth reading without the mail.** On a machine whose mail was
server-hosted it is frequently the only record on the disk of who wrote to whom,
when, about what and with which files attached — and a message whose `.emlx` is
gone can still have its row, which is why `deleted` is on the record. The
reading pane shows Mail's own snippet where there is one, labelled as a preview
and not as the body, because on such a machine that snippet is often the only
text of the message that survives.

**The `.emlx` files themselves (§3.10).** Where the message file is
still on disk the email parser (`plugin.email.parser`) reads it, not this
reader. An `.emlx` is a decimal byte count on its own line, exactly that many
bytes of RFC 5322 message, then an XML plist. The count bounds the message, so
the plist never reaches the body. The plist's `date-received`,
`date-last-viewed`, `date-sent`, `flags`, `conversation-id`, `remote-id` and
`original-mailbox` go on the message record as `emlx_*` keys. `flags` is
published **raw and not decoded**, because its bit layout is Apple-private and
no file held here confirms a description of it. This index reports read,
flagged and deleted state for its own rows, but the two readers are not joined:
an index row names no `.emlx` and an `.emlx` record names no index row, so
matching them is the examiner's own search. A `.partial.emlx` is one Mail did not download
whole. Each part left as a stub (`X-Apple-Content-Length`, empty body) is looked
for beside it by name as `<id>.<section>.emlxpart`, and a part that is found is
put back before the message is parsed, so its attachment is extracted. Each
part's outcome is in `emlx_parts`: `reunited`, `absent`, or `source_cannot_look`
where the source cannot open a neighbouring file. **Only a host directory and a
ZIP entry can.** A file served out of an APFS, HFS+, NTFS or ext4 file system in
a disk image reports `supports_siblings() = false`, so on a Mac's disk image —
the commonest shape of this evidence — every stub part is `source_cannot_look`
and no attachment is extracted from it; the record says "could not look", not
"absent". Anything not reunited is named in `attachment_absent_reason` and marks
the record `content_incomplete`. A `.emlx` whose name was lost is recognised by
its wrapper: the count line, and `<?xml` at the counted offset (one five-byte
read there when it lies past the 1,024-byte probe).
This was checked against three files Apple Mail wrote (two PRONOM_Research
samples held locally, and the MIT hoover-testdata partial message with its part
file, committed).

## How the macOS readers report what they could not read

These are the cases where a macOS reader could not read what it was given. Each says so on a record, with a reason, and never returns an empty list.

| Module | Behaviour |
|---|---|
| `macos.apple_mail` (`mail.rs`) | The cap marker and the `ParseFailed` record keep `subtype: parse_incomplete`; the messages alone carry `apple_mail_index`. |
| `macos.knowledgec` (`knowledgec.rs`) | Both are `type: "KnowledgeCParseStatus"`, `subtype: parse_incomplete`, which the Records view files under "What could not be read". |
| `macos.install_history` (`install_history.rs`) | A `SoftwareInstallIncomplete` marker with `status` `ParseFailed`, `UnexpectedLayout` or `EntriesUnreadable` (with `entries_unreadable` / `entries_total`) and reason `unresolved_structure`. An empty array still yields nothing: the file itself records no install. |
| `macos.launchd_persistence` (`launchd.rs`) | The cap is 64 MiB. A short or over-cap plist whose recorded path is outside every `LaunchAgents`/`LaunchDaemons` directory is passed over without a marker; inside them, or with no path at all, the marker stays. Graded on the Magnet 2021 image's `/System/Library/LaunchDaemons`: every plist a job or nothing, no marker. |
| `macos.notifications` (`notifications.rs`) | A bare `db` needs `usernoted` in its `path` (else `parent_path`); with neither, only a file whose first 16 bytes are the SQLite header is spilled. An absent blob carries `content_note`; a blob that will not parse, or a key whose value is not text, carries `content_incomplete` / `unresolved_structure` and a detail naming the keys. In an `NSKeyedArchiver` blob a `UID` that names a string in `$objects` is followed. The `ParseFailed` record is `type: "NotificationParseStatus"`. Graded on plaso's real `mac_notificationcenter.db`: six records, every title and body decoded, no stamp. |
| `macos.wifi_known_networks` (`wifi.rs`) | A `WifiNetworkIncomplete` marker with `status` `ParseFailed` or `UnexpectedLayout` and reason `unresolved_structure`. A dictionary with no network entries still yields nothing. |

The unified log is decoded per message for loose files and ZIP entries; see §4 "As built".

**Validated schema versions (`ROADMAP` §1.4a).** The macOS stores read by the
shared SQLite parsers declare the version they were validated against, each endpoint
read from a real file, and file a `ParserStaleWarning` outside it while still parsing:
Safari `History.db` `PRAGMA user_version` **13..=16** — 13 from plaso's `History.db`, 15
from the Magnet 2021 macOS tree (`Users/eliflatt/Library/Safari/History.db`, 203 visits),
16 from the iOS 15 device; FrontBoard `applicationState.db` `schema.version` **1..=1** in
the macos2021 tree (2 bundle ids — the main file is one 4,096-byte page and the inventory
lives in its 98,912-byte `-wal`, so a reader that does not stage the sidecar declares the
store empty). `PRAGMA user_version` is 0 on every Apple store measured and is read as "not
recorded", never as version 0.

## Memory analysis: registered, and unvalidated on purpose

`seance_plugin_memory_macos` runs **four stages, and no more**:

| Stage | What it establishes |
|---|---|
| `macos_processes` | The BSD process list, from `allproc` |
| `macos_task_processes` | The Mach task queue, resolved to processes |
| `macos_process_cross_view` | Which listing saw each process |
| `macos_kernel_extensions` | Loaded kexts, from the `kmod` chain |

A stage that could not be written with confidence from the symbol definitions
alone is **absent, not guessed**: an absent stage is honest, and a guessed one
puts a plausible wrong answer in a case file. There is no network state, no
handle or module enumeration beyond kexts, and no credential store.

**Not one result has ever been compared against a capture of a real Mac.** The
tier was derived from 129 Apple Kernel Debug Kit symbol packs and from
Volatility 3's macOS plugins read as source. Every artifact it emits therefore
carries `validated_against_real_capture: false` plus a validation state and an
examiner-facing notice, applied by a single private `stamp()` that runs **last**,
and that marker survives the trip through the API: `/memory/coverage`,
`/memory/profile` and every stage envelope carry
`analysis_declares_itself_unvalidated`, `unvalidated_records` and
`validation_notice`. `seance_api::modules::tests::the_macos_tier_is_registered_under_a_marker_that_says_it_is_unvalidated`
pins the two halves together so nobody can register-and-unmark without
validating.

An image with no Darwin banner produces zero artifacts, so a Windows or Linux
capture never grows a spurious macOS failure.

**Symbol-pack bounds:** 64-bit OS X 10.8 through macOS 10.15.4, x86 only. No Big
Sur, no macOS 12–15, no Apple silicon; twelve 32-bit packs (10.6.4–10.7.5) carry
no `version.constant_data` and can never be selected, because the banner symbol
is the only macOS identification path. A capture outside those bounds produces a
record naming the kernel build it wanted rather than a guess. See
`documentation/MEMORY_BUILD_BINDING.md`.

## Implementation Roadmap

### Phase 1: Foundation
- [x] **APFS Support:** `seance_plugin_apfs` (Read-only; encrypted FileVault volumes are detected and reported `encrypted: true` with the filesystem walk skipped, and per-extent-encrypted files have their encrypted extents emitted as holes rather than served as ciphertext — not decrypted. See `documentation/Container_Formats.md`).
- [x] **Apple `.sparseimage`:** `seance_container_sparseimage` — what FUJI / RECON / ASLA write — is read as an ordinary disk. An encrypted Apple disk image (`encrcdsa`) is detected at ingest and stamped as present-but-never-opened rather than ingesting as an empty undetermined blob.
- [~] **System Config:** Generic plist parsing shipped as `seance_plugin_plist` (an `NSKeyedArchiver` archive is resolved and classified from its own `$top` and root class; archives nested inside `NSData` values share one per-file budget and the eight-level nesting bound); a dedicated macOS system-config extractor (`seance_plugin_macos_config`) is not a separate crate. NVRAM / `csr-active-config` (SIP status) and `KextPolicy` are **not** parsed.

### Phase 2: User Activity
- [x] **FSEvents:** `seance_plugin_fsevents`. `.DS_Store` alongside it as `seance_plugin_dsstore`.
- [x] **User Activity:** shipped as `seance_plugin_macos_artifacts` — quarantine, TCC, Wi-Fi known networks, install history, notifications, BOM receipts. **Recent Items (`*.sfl2`), the Dock plist and the QuickLook thumbnail cache remain open.**

### Phase 3: Logs & Persistence
- [x] **Unified Logs:** `seance_plugin_macos_artifacts::UnifiedLogParser` (framing, catalogs, chunkset decompression, tracepoint parsing and counts) and `UnifiedLogTimesyncParser` (the timesync database). Per-message text, DSC/`uuidtext` resolution, dating through timesync, oversize arguments within the same file, and statedump/simpledump entries are in the case for a `.tracev3` read from loose files or a ZIP; a `.tracev3` in an APFS or HFS+ image is handed its tree from the volume listing (unit-tested, not yet run on a real image), a source with no listing is inventoried only and says "tree not reachable, not decoded", and a statedump's protocol-buffer or custom-object data is kept as bytes, not decoded (§4). Private arguments are read only where the machine recorded them; nothing withheld is recovered.
- [x] **Persistence:** `seance_plugin_macos_artifacts::LaunchdPersistenceParser` (LaunchAgents/LaunchDaemons). **Cron tabs, `/etc/periodic`, `BackgroundItems.btm` and emond remain open.**
- [x] **Spotlight:** `seance_plugin_macos_artifacts::SpotlightStoreParser`. Tables whole
  and the per-item metadata decoded — name, path, content type, sizes, owner, download
  source and dates. Graded as `MACOS-SPOTLIGHT-1`. What is read but **not interpreted**
  is listed above.

### Phase 4: Commercial Grade
- [x] **CoreDuet:** `seance_plugin_macos_artifacts::KnowledgeCParser`.
- [~] **Memory:** `seance_plugin_memory_macos` registered, four stages, never validated against a real capture — see above.
- [ ] **iCloud:** `seance_plugin_icloud_forensics`.
- [ ] **AirDrop reconstruction:** `seance_plugin_airdrop_analysis`.
- [ ] **Apple Silicon / FileVault key recovery:** `seance_plugin_apple_silicon_security`. No `libfvde` interface exists; FileVault volumes are reported, not opened.

