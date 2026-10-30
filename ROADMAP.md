# Roadmap

What is still to do, in the order it is to be done. Everything here is open work.
Open defects are in [`BUGS.md`](BUGS.md). The product as it stands is described in
`README.md` and `documentation/`.

## How to read this

| Part | Holds |
|---|---|
| **I. Priorities** | Every open item, in tiers, each with an estimate, the evidence it is graded against, and what done means |
| **II. Sprints** | The order the tiers are taken in, sized to about ten developer-days each |
| **III. Blocked on evidence** | Work that cannot start until something is obtained or made, what exactly, and an estimate for the work once it is held, outside the tier totals |
| **IV. Engineering debt** | Blocks nothing, compounds if left, and the rules the work is held to |
| **V. Decisions on record** | Investigated and declined, or settled, so it is not re-proposed |
| **VI. Strategic position** | Which product this is and who it is for |
| **Evidence held** | The corpus layout `seance-validate` and CI mean when they say "the corpus" |

### Labelling

- **`§n.n`** is an item's stable identifier. It never changes. A retired id is
  never reissued, because source comments and design documents cite the ids of
  shipped work. New items take the next unused number in their series, or the
  next unused `§5.x`. A section number that source code or a design document
  cites and this roadmap does not define names work that has shipped. It is not
  reissued.
- **`Pn`** is a priority tier. **`Sn`** is a sprint. An item keeps its `§` number
  when it moves between tiers or sprints.
- **Owner to decide** marks an item whose first step is a choice by the owner.
  Both outcomes are sized, and the item waits until the choice is made.
- **`HUNT-nnn`**, **`HIVE-nnn`**, **`MEM-nnn`**, **`BUG-nnn`** and the other
  prefixes are defect ids, minted in `BUGS.md` and never reused.
- Part III rows carry the id of the item they block, where one exists.

### Estimates

Every item carries an estimate in **developer-days (d)**: one engineer. The
number covers code, tests, the documents the documentation map obliges, the
online help. An estimate is
a size, not a date. A sprint closes on its exit criterion.

An estimate marked **≈** is sized from the outside, for a format nobody here has
opened or a task that depends on a decision. It is re-sized when its sprint is
opened.

---

# Part I. Priorities

The order of the tiers is the order of the work. Within a tier, items are listed
in the order to take them. Work that cannot start for want of evidence is in
Part III, so that a tier stays a list of things somebody could begin today.

| Tier | What qualifies | Total |
|---|---|---:|
| **P0. Open defects** | A result is wrong, unverifiable or unsafe on a surface someone relies on | 10.75 d |
| **P2. Measured against public keys** | Depth that a published answer key or test method says is missing, on evidence already graded | 26.25 d |
| **P3. Parity with the tool left open** | The reason an examiner still runs a second tool beside this one | 152.85 d |
| **P5. Substrate and debt** | Blocks nothing today and compounds | 33.7 d |
| **P6. Parked** | Needs a customer, a partner, a licence or a decision before it is worth a day | 448.0 d and more |

P0, P2, P3 and P5 sum to 223.55 d. P6 is the sum of its stated sizes, and rows
marked with a plus are open-ended.

## P0. Open defects

The live register is `BUGS.md`. This lists the open entries with an estimate for
what is left. Read the entry before starting, because its last status is its
current one.

| ID | Defect | Est. |
|---|---|---:|
| `MEM-043` (LOW) | ARM64 translation. Discovery does not offer an LPA2 regime. The 4K LPA2 layout and `DS = 1` under a 64 KiB granule are refused by name. Windows ARM64 PTE conventions are read for builds 28000 and 26300 only. The prototype field, `ProtoIndex`, is not decoded. TBI is decoded and unit tested, and no real capture has exercised a tagged pointer. No hardware capture exists | 3 d |
| `MEM-044` (LOW) | VeraCrypt and TrueCrypt in memory. 48 product builds on four OS builds are graded. Left: re-run VeraCrypt 1.15 on the second OS build, the remaining 1.22 to 1.26 updates where an installer exists, and Camellia and Kuznyechik cascades below 1.22 | 1 d |
| `HUNT-278` (LOW) | FAT recovery. Left: macOS, other cameras and real phone drivers | 0.5 d |
| `HUNT-195`, `HUNT-280`, `HUNT-111`, `MEM-059` (LOW) | Left: a real subscription record no index names, which needs a rebuilt Server 2003 guest (`HUNT-195`). A Unicode PST libpff can recover from (`HUNT-280`). A Monterey or later volume that holds a `System.keychain` (`HUNT-111`). An XP x64 capture (`MEM-059`) | 0.5 d each, 2 d |
| `MEM-020` (MEDIUM) | Kernel-side tamper signals. Real malware captures are used and graded. Synthesising a kernel driver to make a signal fire stays rejected. The user-mode groups have planted true positives. Rustock-23, Rustock.C, BlackEnergy 2.1 and ZeroAccess ran on a network-less Server 2003 R2 SP2 guest and none fires, because none ran code outside a module. Left: a capture of a sample that runs code from unbacked memory, such as Rustock.B or TDL3 and TDL4, to grade `timers` and `unloadedmodules` as signals. The Art of Memory Forensics images carry timer answers and are available on request only. A Skeleton Key patch in `lsass` to grade `skeleton_key_check`, which is an antivirus risk and whose `CSystems` route runs on no build. The ETW check's firing rate on a genuine compromise is unmeasured. On XP the ETW and Skeleton Key checks cannot assess a process and orphan threads stay an observation. No such capture is held | 1 d |
| `HUNT-293` (HIGH) | Spotlight header platform claim. `ios_store` is inferred from an empty property chain head, so a per-user CoreSpotlight or helpd index on macOS is named iOS and the record name gains an iOS suffix. Replace the boolean with a store flavour and say nothing about the operating system the file came from | 0.5 d |
| `HUNT-294` (LOW) | A `packages.xml` element that carries the same attribute twice is not surfaced. Most attributes resolve last wins and `userId` and `sharedUserId` resolve first wins. Pick one rule, apply it to every attribute, and publish `duplicate_attributes` per record with a count on the summary | 0.25 d |
| `HUNT-283` (HIGH) | VICS export places a SHA-256 digest in the `md5` field when a set has no attribute bundle, so a partner tool matches on the wrong key. VICS has no SHA-256 field. Omit the entry and count it, or refuse the set, and say which. Test: a SHA-256 set exported with no bundle leaves the digest in neither `md5` nor `sha1` | 0.5 d |
| `HUNT-284` (MEDIUM) | `PUT` virtual column returns 200 and writes a `virtual_column_updated` audit row for an unknown id, another case's id or a built-in id, because the handler discards the `Ok(false)` result. Return 404 and write no row | 0.25 d |
| `HUNT-285` (MEDIUM) | The timeline activity heatmap drops events at or before the epoch and reports `total` with no excluded count. `count_timeline_activity_excluded` exists and no handler calls it. Return the count and show it on the heatmap | 0.5 d |
| `HUNT-286` (MEDIUM) | Editing a timeline tag note writes no audit row, where create and delete do. Take the authenticated user and write `timeline_tag_updated`. Test: one row naming the examiner and the event | 0.25 d |
| `HUNT-287` (LOW) | Creating a virtual column with a duplicate id returns 500. `ApiError` has no conflict variant and the primary key is not scoped to the case. Return 409 and decide whether ids are per case | 0.25 d |
| `HUNT-288` (LOW) | `run_module_batch` counts a job that never ran in `targets`. Return a separate `failed` count and keep `targets` to queued jobs. Shares the handler with `HUNT-289` and with §5.52 | 0.25 d |
| `HUNT-289` (MEDIUM) | `analyze_category` and `run_module_batch` write the mandatory audit row after queueing, so a failed audit write leaves running jobs with no row. Write it before the first job is queued | 0.25 d |
| `HUNT-290` (LOW) | A failed VICS import leaves an empty hash set that lists as imported. Create the set and its entries in one transaction, or delete the set on failure | 0.25 d |

`HUNT-291` and `HUNT-292` are sized in §3.8 and counted in P3, not here.

**P0 total: 3 + 1 + 0.5 + 2 + 1 + 0.5 + 0.25 + 0.5 + 0.25 + 0.5 + 0.25 + 0.25 + 0.25 + 0.25 + 0.25 = 10.75 d.**

**The register is the authority.** `BUGS.md` holds the last status of every entry above.

## P2. Measured against public keys

Depth that a published answer key, or a published test methodology, says is
missing, on evidence the product has already been graded against. An item is
here because a number says so.

### §2.6 Windows system information  9.0 d

Graded against the NIST CFReDS Data Leakage key: 60 questions, Windows 7. The run
is recorded in `VALIDATION.md` as `LEAK-2`, over 2,261,987 artifacts, graded
column by column against the key. The criterion is not met. 36 questions are
answered in full, 21 in part and 3 not at all. The 24 gap questions are listed
row by row in `LEAK-2`.

- **The 24 gap questions.** Closing them is the work. It is sized from the
  outside until a few are opened. ≈ 6 d
- **USB connection time from three sources, joined.** One canonical device
  instance id shared by the `Enum\USBSTOR` key, the `Properties` FILETIMEs and
  `setupapi.dev.log`, including the `SWD\WPDBUSENUM\_??_USBSTOR#` wrapped form.
  A `UsbDevice` record then carries each first-connection source side by side
  and names which is earliest. setupapi times stay local and unconverted. 1.5 d
- **Pin the published answers.** The Hacking Case Q14 address 192.168.1.111 is
  found only in `ControlSet002`'s copy of the interface. The Lone Wolf USB
  sources and the Data Leakage rm#1 and rm#2 serials are checked for agreement.
  Both go in gated tests. 0.5 d
- **The System Info screen.** It compiles `NetworkInterface` per control set,
  Windows Search configuration stated as configuration with `DataDirectory`
  unexpanded, MountedDevices letters stated as assignments and not presence, and
  the USB time columns, through the existing control-set and hive-disagreement
  rules. Q9, Q22 and Q42 to Q43 are then answered from the screen and not from the
  records list. 1 d
- **Sticky Notes.** The Windows 7 `.snt` reader is graded on the case's real
  `StickyNotes.snt` (`SNT-1`). The Windows 10 `plum.sqlite` reader is graded on a
  store made in the lab with the real Sticky Notes 6.1.4.0 (`PLUM-1`). That is
  real software and not a real machine, so the reader keeps its unverified stamp
  until a store from an examined machine is compared. 0 d of unblocked work

**Done when** the key answers 55 of 60 from a screen and the run is recorded in
`documentation/VALIDATION.md`.

### §5.2 Third-party validation  8.5 d

The CFTT runner and graders are built and run: `CFTT-DFR-1` over all 90 images,
`CFTT-SS-1` and `-2`, `CFTT-FC-1`. The comparison matrix row for NIST validation
stays unticked, because a tick means NIST tested the tool. The separately named
row for a methodology run in full and published is earned only when a family's
whole assertion set has been graded. None has been.

- **Mobile core.** The grader `seance_validate/src/cftt/mdt.rs`, the runner
  `scripts/cftt/run-mobile.sh` and the key fixture exist. Only `MDT-CA-02`,
  `MDT-CA-11`, `MDT-CA-12` and `MDT-CA-13` are graded, because the published key
  for the cheapest image is a population template with placeholders. Every other
  case is `NotAssessed` with that reason. Left: run it on the held handset image,
  record `CFTT-MDT-1` in `VALIDATION.md`, and have a second reader check the
  fixture against the PDF, non-ASCII and blank-name rows first. 0.5 d
- **File carving beyond L0.** Only L0 is run, `CFTT-FC-1`, 29 of 30 found. Run
  L1 to L5 through `scripts/cftt/run-file-carving.py` and record each as
  `CFTT-FC-n`. Map to `FC-CA-*` once the specification text is held. Fragment
  reordering, `FC-CA-09`, stays out of scope. 2 d
- **SQLite family, `SFT-*`.** The data is generated by the specification's own
  `sqlite3` actions and needs no corpus. `Header` in `seance_plugin_sqlite` does
  not parse the read and write version bytes at offsets 18 and 19 that
  `SFT-CA-04` and `SFT-CA-05` ask for. Fetch the specification text first. 3 d
- **Windows Registry family, `WRT-*`.** Four hive archives, some deliberately
  manipulated to hide objects. The registry reader already writes
  `inventory_incomplete` with an `IncompleteReason`. Fetch the specification text
  first. 3 d

The `DFR-RO-*` cases are in Part III.

**Graded against** NIST's published layout and expected results for each family,
and the handset's own stored values for the mobile core.

**Done when** the mobile core run is recorded, L1 to L5 are recorded, `SFT-*` and
`WRT-*` are graded or `NotAssessed` with the reason, and the matrix says what ran.

### §1.6 The unified log  3.0 d

Per-message decode ships in `seance_plugin_macos_artifacts`: `tracev3`,
`firehose`, `unifiedlog_decode`, `unifiedlog_resolve`, `timesync`. One dated
`unifiedlog_message` record per message, format strings resolved against the
same machine's `uuidtext` and `dsc`, oversize entries joined from other
`.tracev3` files of the tree. It is graded as `MACOS-UNIFIEDLOG-1` on the
Mandiant logarchives. The record cap is 150,000 per file and is stated on the
record. Not done:

- **No message text has been compared with Apple's `log show`.** Tahoe's count
  is one entry short of Mandiant's. This is a comparison and not an answer key. 1 d
- **A second, independent oracle.** Extract the tree of plaso's
  `unified_logging1.dmg` outside the repository, credit plaso by name in
  `VALIDATION.md`, and grade the Persist 83,000 and Signpost 2,466 messages. This
  gives an order-independent known answer that Mandiant's counts do not. It
  depends on the owner accepting plaso's published values as known answers. 1 d
- **Apple System Log carving.** The module reads live `/var/log/asl` files. A
  deleted `.asl` in unallocated space is not carved. `seance_carving` has no
  `ASL DB` signature, and `formats/asl.rs` is the renamed Adobe Layer Style
  signature. Add an `Apple System Log` signature that walks the record chain for
  size. Graded on the Magnet 2021 `asl` stores, 11 files and 7,022 records,
  carved from a synthetic unallocated region with a count equal to the parser's.
  If the owner judges it not worth a day it moves to P6. 1 d

A `.tracev3` inside a real disk image and Spotlight `Store-V2` are in Part III.
Statedump data and `<private>` arguments are in Part V.

**Graded against** the Magnet 2021 macOS image and the Mandiant logarchives.
`MACOS_DESIGN.md` states the coverage and its bound. The timesync sentence in
`METHOD_STATEMENTS.md` is generated from `method_statements.rs` and is
regenerated with it.

**Done when** the three comparisons are recorded in `VALIDATION.md`.

### §1.5 iOS backup, what stays unread  0 d

Notes, Voicemail, Photos, Calendar, Reminders, PowerLog, `routined`, Safari,
HealthKit, Voice Memos, voicemail audio and note attachments ship. So do the
keychain items of an encrypted backup, with class keys exposed and an audited
reveal, graded as `IOS-KEYCHAIN-1` on the Hickman iOS 17 Finder backup.
Hardware-bound classes on a full-file-system extraction stay closed, because the
keys are in the device and not in the image. What is left is in Part III, in
§5.27, §5.33 and the Part V rows for iOS.

### §1.4 Mobile, packages.xml provenance  1.0 d

The mobile source-type triage label ships, graded as `SRCKIND-1`. `packages.xml`
install provenance ships and is graded as `ANDROID-PKG-1` and `AND-1`. What is
left:

- `packageSource`, `installerUid`, `installOriginator` and
  `installerAttributionTag` are written by Android 13 and later and are not
  read. `packageSource` 0 is `UNSPECIFIED` and must not count as recorded. 0.5 d
- The summary states no `sdkVersion`, no `fingerprint` or `buildFingerprint`, no
  `install_time_source`, and not which provenance attributes the release does not
  write. 0.25 d
- Per-user install time in `package-restrictions.xml` is not parsed. It needs
  that member from the Hickman full-file-system zip. 0.25 d

A `<package>` element that repeats an attribute is `HUNT-294` in P0.

**Graded against** the Hickman Pixel 7a `packages.xml`, 369 packages, with an
independent count from `abx_count.py`. The sdk-28 Pixel 3 file carries
`fingerprint` and not `buildFingerprint`, so assert the first and the absence of
the second.

**Done when** each attribute is read or its absence on that release is stated on
the record, and `ANDROID_DESIGN.md` says so.

The LINE, Telegram TL, Facebook `msys` and Signal-for-Android decodes are in
Part III.

### §1.4a App-parser schema-drift defence, run it on a runner  0.5 d

Twenty parsers adopt the defence. A version beyond the validated range is a
disclosure and not an incompleteness claim. The CI jobs `app-schema-corpus` in
`test.yml` and `corpus-gates` in `selfhosted-linux-ci.yml` exist and are pinned
by `ci_corpus_wiring_test.rs`. They have not been run on a runner that holds the
evidence. Run them there and record the result. Enforcement and publication of
the validated ranges are §5.26. A device sample for each unranged app is in
Part III.

### §5.15 Oracle runs for shipped parsers  4.25 d

Four shipped parsers have never been compared with an independent tool.

- **Login accounting.** `VALIDATION.md` records a wtmp count from the Magnet
  2022 image and no comparison. Capture `wtmp`, `btmp` and `lastlog` on a lab
  Linux VM, with failures in the btmp, and run `last -aiFw`, `lastb` and
  `lastlog` as oracle. 1.0 d
- **`$Secure:$SDS`.** Run MFTECmd `--sds`, Secure2Csv or an independent Python
  decoder over the real `$SDS` of `HD001_MFT.dat`. Compare descriptor count,
  owner, group and ACE lists. 0.5 d
- **ASEP.** Compare `AsepEntry` output with `autorunsc` on DFIR Madness Case 001,
  `DC01-autorunsc.zip` and `DESKTOP-SDN1RPT-autorunsc.zip`. Per category, list
  the entries Séance reports that `autorunsc` does not and the converse, with a
  reason for each delta. Record which categories are better or worse than the
  reference tool. 1.5 d
- **Registry replay.** The replay engine is checked on synthetic fixtures and
  Marvin32 vectors only, and no real dirty hive has been replayed. Make one in the
  win11 lab by copying `SYSTEM` or `NTUSER.DAT` with `.LOG1` and `.LOG2` from a
  running guest through a VSS snapshot. Ingest it as a disk image, so the
  sibling-bundle path runs, and compare entries applied, post-replay sequence
  numbers and every changed value with yarp `recover_auto()`. A clean hive grades
  the byte-identical negative. 1.25 d, of which 0.25 d is the Part III evidence
  row and the `VALIDATION.md` entry

**Done when** each comparison is a `VALIDATION.md` entry with every delta explained.

**P2 total: 9.0 + 8.5 + 3.0 + 1.0 + 0.5 + 4.25 = 26.25 d** (§2.6, §5.2, §1.6, §1.4, §1.4a, §5.15).

## P3. Parity with the tool left open

Each item here is a reason an examiner keeps a second tool running beside this
one. None changes the claim the product makes. All narrow that reason.

### §5.3 Windows memory, the Volatility plugins with no answer here  7.5 d

Kernel dumps
and the odds and ends ship, and so does console history. `console_history.rs`
recognises `_CONSOLE_INFORMATION` and its command buffers. The layout was derived
in-house from a capture for one build, Windows 11 26200.6584, and is graded
against the commands the VM was driven to type (`CON-1`). Still without an
answer:

- **`consoles`**, the screen buffer and not only the command history, and
  **`OpenConsole.exe`**. A name-filtered host search is a false absence on a
  modern machine. Pinning it wants two captures, one forced to legacy
  `conhost.exe` and one on Windows Terminal. `~/win11-lab/vm/` can make them.
  ≈ 2 d, plus the captures
- **Another build.** About 2.5 d per build, derived the same way. Upstream's
  per-build packs are VSL-licensed and are not transcribed, so every further
  build is a derivation. An uncatalogued host yields nothing and the stage does
  not say `build not catalogued`. That wording is part of the next build. 2.5 d
- **`userassist` on memory-resident hives.** The memory registry route lists
  hives and exposes no value bytes. Feed the in-memory NTUSER hive's
  `UserAssist\{GUID}\Count` values to the decoder in `userassist.rs`. Graded on
  the Lone Wolf `memdump.mem` against the disk UserAssist of the same machine.
  1.5 d
- **`statistics`.** One walk of the kernel layer that counts `TranslateError`
  variants and large pages, published as a coverage record that
  `MemoryOverviewPage` can show. Graded on `memory-unlocked.raw` against the
  translation layer's own run table. No upstream output is transcribed. 1 d
- **`pe_symbols`.** Export reading exists in `dump.rs::read_exports`. Expose it
  as a record per module with addressed lookup. 0.5 d

`windows` (`tagWND`) waits on a route decision recorded in Part V. It is 8 to 15 d
if taken and is not in the estimate above.

Clean-room throughout. Volatility's VSL forbids even result-parsing wrappers.
**Graded against `test_data/win11_bitlocker/memory-unlocked.raw`**, build 26200,
and not against Lone Wolf or Magnet 2020, where upstream's virtual layer yields
zero processes. A rule's clean-capture false-positive count is measured on it
before the rule ships. Each landed plugin moves from not answered to answered in
and `documentation/COMPARISON.md` says the new thing.

**Done when** each plugin is answered in `COMPARISON.md` with its module named.

### §5.42 Registry replay, name the keys it changed and say so in reports  1.75 d

Transaction-log replay ships, with provenance, a banner and a replay timeline
event. Three gaps remain.

- **What changed.** Nothing computes which keys a replay altered.
  `changed_key_paths` in `reglog.rs` is declared and never written, so
  `replay_changed_keys_computed` is always false and the method statement says
  so. The API and the banner already consume the list. Map the patched
  `[file_offset, size)` regions to NK cells with the bounds-checked cell walker,
  cap at 500 paths, fill the list. Graded on a dirty hive with logs, where an
  independent decoder, yarp `recover_auto()` diffed, lists the same keys. 1.0 d
- **Reports.** `seance_reporting` says nothing about replay. Add a Logs replayed
  cell to the registry section and a report-level caution when any hive was dirty
  and unrecovered, from the existing `logs_replayed`, `hive_dirty` and
  `replay_reason` keys. Update `REPORTING_DESIGN.md`. Graded by a report built
  from a case that holds a dirty, unrecovered hive. 0.5 d
- **The suppressed log file.** A `.LOG1` or `.LOG2` yields no record, so its file
  page gives no hint it was replayed. Add a one-line note naming the hive it was
  replayed into, or stating that no dirty hive was found. 0.25 d

**Done when** a replayed hive's report and banner list the keys it changed.

### §5.43 Login accounting, findings, user names and the report  4.5 d

`FailedLogin`, `LastLogin`, `BootEvent` and `LoginSession` records ship, and so do
their viewers. Three gaps.

- **Findings.** No lead comes from `btmp`, and a clock change raises no
  timeline-trust flag. Add a Weak lead for N failures from one source in a window,
  with the thresholds stated on the record, and a lead when a `NEW_TIME` and
  `OLD_TIME` pair shifts the clock, each with a generated Limitations entry.
  Graded against `lastb -aiF` on a real `btmp`. 1.5 d
- **`lastlog` user names.** `LastLogin.user` is always null. Join the UID to the
  username at view time from the same volume's passwd accounts, name the passwd
  artifact on the row, and leave null when the volume has none. 0.5 d
- **Report and view.** The viewers are plain rich viewers with source host
  dimensions. There is no report section, no uptime bracket, and no click from a
  source address to every other artifact that names it. Add a Logins and Sessions
  section to the report: sessions with duration and status, boot and shutdown
  brackets, failed attempts counted by source and by target with the thresholds
  stated, and `gone_no_logout` called out. In the viewers add the boot-bracket
  strip and a source-address pivot to search. Summary tiles and top-N lists are
  computed over the loaded pages with `truncated` shown. Graded by a report built
  from the Magnet 2022 image's `wtmp` and the §5.15 lab capture. Update
  `REPORTING_DESIGN.md`. 2.5 d

**Done when** the findings and the names read from the grading in §5.15 and a
report states logins and sessions.

### §5.44 NTFS ownership beyond the file page  4.0 d

The `$SDS` decoder, mirror recovery and the file page "Owner and permissions"
join ship. No record, report, export or REPL command carries the join.

- **The file grid.** Resolve the owner SID per file in one place, either an owner
  column or a join at query time. Add sort, filter, an owners breakdown, the grid
  column and the CSV column. Keep the volume-scoped parentage rule, because
  security ids on two volumes are unrelated. Graded on `ntfs_index`, where id 262
  is Administrators. 2.5 d
- **Reports and exports.** A descriptor section and an Owner column in the file
  sections. 0.75 d
- **An Analysis viewer for `NtfsSecurityDescriptor`.** The record types fall to
  the generic table. Reuse the `OwnershipSection` DACL renderer so there is one
  ACE table. 0.75 d

**Done when** an examiner can sort and filter files by owner and a report states it.

### §5.17 Autostart, the view and the timestamps  9.0 d

`seance_plugin_asep` ships 30 categories, WMI subscriptions, MITRE mapping on each
record, a coverage record with examined, unexamined and not-applicable, a target
existence index, findings leads and timeline events. Entries render in the
generic record table.

- **A persistence view.** A page, or an Analysis viewer per the navigation rule in
  Part V, that groups `AsepEntry` by category with coverage shown beside it, so
  that checked and empty is distinct from not checked. MITRE ids are copyable
  text, because the product is air-gapped. A deep link goes to the registry key.
  Graded on Case 001, whose `autorunsc` output lists the implant `coreupdater`.
  5.5 d
- **Registry key last-write as `installed_time`.** The registry plugin stamps
  `last_written` on every `all_keys` element and the ASEP reader does not use it.
  `KEY_TIME_UNAVAILABLE` says the record carries no per-key last-write times,
  which `last_written` contradicts. Take the key's last write with
  `source: key_last_written`, in the no-earlier-than and no-later-than wording of
  `WMI-5`, and apply the hive replay stamp. Graded by the Case 001 `coreupdater`
  service key against the `autorunsc` Time column. 1.0 d
- **TaskCache to task XML.** `scheduled_task_registration` and the task XML
  `RegistrationInfo/URI` are not joined. Join by tree path and flag registered but
  definition not recovered, and definition present but never registered. 0.5 d
- **A report section.** Grouped by category, carrying the coverage statement and
  naming the categories not examined. 1.0 d
- **A known-good toggle.** The view hides Microsoft and known-good entries on a
  stated, conservative rule: an image under `System32` or `SysWOW64` with a
  default value. Scope, user and category filters are kept in the URL.
  `seance_plugin_asep` carries no `known_good`, `suspicion` or `signer` field, so
  the rule is computed in the view and states itself. 1.0 d

**Done when** `coreupdater` is visible in the view with its key time and a report
section lists the categories examined and not examined.

### §5.18 Linux memory, the detectors and depth with no answer here  29.5 d

The Linux tier ships twelve stages, including the syscall table, ftrace, kprobes
and eBPF hooks, `modscan` and `taskscan`. These Volatility Linux plugins have no
answer. Positives need a rootkit sample, and detection parity is untestable on a
clean image, so grade the negative on the held Oberon and Noble captures and a
hand-built fixture, and state any positive as ungraded.

- **Process depth.** Boot wall-clock time from `timekeeper` first, because it
  turns every process start into a date and unblocks the rest. Then `ptrace`
  relationships, kernel-thread entry points, the `pid` IDR cross-view, and mapped
  ELF and `link_map` lists. Graded on `forensic_corpora/oberon_linux_swap` and
  the Noble 6.8 capture against `ps` and `/proc` ground truth recorded at
  capture. ≈ 6 d
- **Kernel stack walk.** For each task, scan `THREAD_SIZE` bytes of kernel stack
  for return addresses, resolve each through kallsyms and the module map, and mark
  every frame heuristic. Cap the output and say so. A frame in no module or in
  unbacked memory is a weak lead with the WHY and NOT PROOF wording. Graded on the
  Oberon and Noble captures, where a clean image must raise zero leads. 2 d
- **VMA scans.** `vmaregexscan` and `vmayarascan`. Reuse the Windows scan plan
  over `proc_maps.rs` VMAs, with each match's VMA on the record. 1.5 d
- **Network and kernel state.** The `net_device` list with addresses and the
  promiscuous flag per namespace, a physical `sock` sweep for sockets no FD table
  reaches, the `iomem` tree and framebuffer export. Publish `kallsyms` as
  per-subsystem counts and an anomaly set, and not as 100,000 records. ≈ 5 d
- **Page cache and module extraction.** Walk superblocks to inodes with cached
  pages and hand recovered files back as `FileEntry` artifacts through the
  `recovered.rs` seam the Windows tier uses. Holes are marked and never zero
  filled. A dentry path never becomes a filesystem path on the examiner's host.
  Add module ELF rebuild. ≈ 5 d
- **Rootkit and hook detectors.** `check_idt`, `check_afinfo`, `check_creds`,
  `check_modules` against sysfs `module_kset`, `modxview`, `netfilter`,
  `keyboard_notifiers`, `tty_check`, `process_spoofing`, `tracing.tracepoints`,
  `tracing.perf_events` and Linux `malfind`. Each is stamped with what it could
  not read. ≈ 10 d

**Done when** each plugin is answered in `COMPARISON.md` with its module named
and its clean-capture false-positive count recorded.

### §5.19 Memory to disk correlation  6.0 d

For each loaded module and file handle, a status of `on_disk`, `not_on_disk` or
`not_checked` against the case's `FileEntry` set. Match path and name and compare
size of image and the PE version resource. Also the in-memory hive against the
on-disk hive, process create time against Prefetch, Amcache and EVTX 4688, and
command history against shell history. Never a byte comparison, because a mapped
image legitimately differs from its file through relocations, the IAT,
copy-on-write and paged-out sections. `not_checked` when no disk evidence is in
the case is an absence and not a pass. `hollow.rs` today compares VAD and PEB
final path components only. Memory `$MFT` records, from `mftscan`, are also
compared with the parsed `$MFT` by record number and name, which is 1.0 d of the
estimate. Graded on DFIR Madness Case 001, the desktop memory beside its E01.

**Done when** the memory screens show the status per module and `COMPARISON.md` says so.

### §5.20 A memory section in the generated report  8.0 d

`ReportData` has no memory field. The only memory text is the Linux symbol-source
qualification. Add fields and rendering in HTML, PDF, DOCX and XLSX for image and
integrity, the layer stack and DTB method, symbol identity with SHA-256, smear
signals, the process inventory, findings with why and not-proof wording, and a
Limitations paragraph generated from the confidence axes. Credentials are
excluded by default. Update `REPORTING_DESIGN.md` and the report method
statements in the same change. Graded on the Windows 11 and Oberon captures.

**Done when** a report built from a memory case states what was and was not examined.

### §5.21 Memory screens for the newer stages  2.85 d

- **Pattern scan, device tree and jobs have no page.** They reach the API and the
  generic memory record surface only. Add a pattern-scan page with rule hits and
  their owning VAD, refused chunks, coverage figures kept apart, and a did not
  run state when no rule set is set. Add a device-tree view, where attachment is
  not a finding, and a jobs view with `ActiveProcesses` beside the walked
  members. Graded by the Windows 11 26200 known answers: 8 `FORENSIC-W11`
  addresses, 245 devices and 113 attachments, 21 jobs. Update `HelpPage.tsx`. 2 d
- **Provision the oracle.** `documentation/TESTING.md` does not name the `pefile`
  and `yara-x==1.19.*` installs the Volatility oracle needs. 0.1 d
- **The tamper stage on the Findings lens and the Overview.** Both read only the
  `tampering` stage and not `tamper_checks`. The Overview empty state says that
  image hollowing, process ghosting and unbacked executable memory are all it
  covers. Add a second source to both screens with a named did not run or
  unreadable state per source. Graded by component tests with the clean-capture
  counts, 0 of 209 timers and 0 of 1,514 threads, and one planted finding from
  `win11_tamper_plant.rs`. Update `HelpPage.tsx` and `HELP_SYNC.md`. 0.75 d

### §3.8 Swap areas and memory-image sweeps  2.75 d

Hole-aware sweeps, selectors over a reconstructed hibernation image, and YARA and
examiner patterns over an image's own address space ship. Six things remain.

- **Defect `HUNT-291`: an ad-hoc re-run reads the compressed file.** Re-running
  the memory analysis on a loaded `MemoryImage` record analyses the parent's raw
  bytes and not the reconstructed layer. `physical_layer_for` wraps whatever
  source it is given, and `has_own_content` is false for the record, so resolution
  pops to the parent. Add `layer_for_record`, which compares `source.size()` with
  the record's `addressable_bytes` and `file_bytes` and re-opens the format or
  refuses. Graded by a hibernation record round-tripped through the database. 0.5 d
- **Defect `HUNT-292`: memory hits are labelled as device offsets.**
  `plugin.bulk.features` emits `device_offset` for a physical address, and
  `device_offset_of` in the findings plugin attaches it to findings as a disk
  location. Emit `physical_address` and `image_format` for memory sources, and
  `swap_area_index` and `swap_offset` for swap. Keep `device_offset` for disk.
  Tested through findings. 0.25 d
- **Swap areas as artifacts.** An attached swap area or pagefile never becomes an
  artifact, so selectors, YARA and patterns cannot sweep it. Add a shared
  `swap_source_record` in `seance_memory::analysis`, emitted by both tiers, with
  identity from `LinuxSwapHeader` and a statement that nothing in it is
  attributable to a process. Accept `swap_area` in `BulkFeatureScanner` and
  `ImagePatternScan`. Graded on `linux-lab/swap-area.raw`, the SWAPMARK known
  answer, and the `win11-lab` pagefile. 0.75 d
- **Swap re-runs.** `SwapFile` in `seance_memory/src/translate/virt.rs` carries an
  index, a label and a source and no acquisition path, so a swap record cannot say
  what file it was and an ad-hoc re-run cannot resolve it through the
  evidence-root policy that `SEANCE_CASE_PAGEFILES` uses. Widen it with the
  acquisition path, stamp it as `source_path` on the swap record, and route
  re-runs through `CaseEvidence`. 0.5 d
- **A selector baseline over memory blobs.** The selector sweep runs
  automatically over memory, and `VALIDATION.md` holds no per-kind hit count for
  it. Record the `BulkFeatureScanner` hit count per kind over `hiberfil.sys` and
  `swap-area.raw`, and name any selector excluded over memory with the reason.
  0.25 d
- **A real-corpus gated test of the selector sweep.** Run `BulkFeatureScanner`
  over `hibernation::open(hiberfil.sys)` and assert `bytes_scanned` equals the sum
  of mapped runs, with unread bytes attributable to holes. It needs 8.5 GB of host
  headroom. 0.5 d

The `LINUX_DESIGN.md` swap-area claim and the Capabilities sweep claim are
re-checked when the swap work lands.

### §2.13 Registry key permissions  1.75 d

The decode of the `sk` security cell ships and is graded on twelve real hives. The
selected key's owner and DACL appear on no screen, so a widened ACL is findable
only in the raw hive record.

- Add a `security` field to the registry endpoint, gated on an always-emitted
  `security_descriptor_count`, so that legacy records say not read and a hive
  whose descriptors all failed says could not be read. Add a Registry-tab panel
  with the four DACL states plus not read, and the help text. Claim owner, DACL
  and SACL enumeration only and never effective access. `COMPARISON.md` says that
  in-memory hives carry no key security. Graded by the SAM root key, readable by
  `BUILTIN\Users` with 0x00020019 while its 64 child keys are not, and the
  289-descriptor SOFTWARE hive. `VALIDATION.md` states that the decode is single
  source, with no second registry-ACL tool. Add the Registry row to
  `UI_TESTING.md` and the registry-ACL claim to `COMPARISON.md`. 1.25 d
- **Optional, decide it.** One `RegistryKeySecurity` record per distinct
  descriptor, with owner, DACL, `keys_referencing`, `unique_to_one_key` and
  `key_paths` capped at 50 with the total, so that the single-key descriptor
  population is searchable case-wide. 0.5 d

### §2.14 Registry certificate store  2.0 d

Nothing decodes `SystemCertificates\*\Certificates`. A rogue root CA is T1553.004.
Add a blob-TLV decoder in `seance_plugin_registry` that emits a `Certificate`
record with SHA-1, subject and store, with a flag for a non-Microsoft root. Disk
first, then the in-memory hive route through `registry.rs`. Graded on a hive from
an image with a known added root, and a hive with only stock roots grades the
negative.

### §3.10 Email remainder  5.75 d

`.emlx`, the macOS Mail V8 `Envelope Index`, deleted-mail recovery for PST and OST
versions 14, 15, 23 and 36, and the native version 36 OST reader ship. Left:

- **The iOS `Envelope Index`.** `AppleMailParser` reads macOS V8 only. On a file
  with no `messages` table, such as the iPhone 8 index whose schema lives only in
  the `-wal`, it returns nothing, which reads as no mail on the device. An iOS
  index that carries `messages` has no `addresses` or `subjects` tables, so the V8
  join fails into `ParseFailed`. Pick a variant by probing, `addresses` for macOS
  V8 and `message_data` for iOS, and read only probed columns. When the file is
  identified by name and its schema is absent, emit a `schema_undetermined` record
  that names the missing `-wal`. Emit a status record that the iOS body store,
  `Protected Index`, was identified and is not read. Graded on the iPhone 8 index
  staged with and without its WAL. Both are empty, so this grades schema and
  refusal and not row recovery. 2.25 d
- **Conversation view.** `thread.rs` has three bases and no store conversation
  id, so Envelope Index records never reach the conversation view. Add a fourth
  basis `applemail:conv:<id>`, noting it is the client's own namespace, and stamp
  it from `conversation_id >= 0`. It needs the stamp helper moved to a shared
  crate. 0.5 d
- **Stores over 512 MiB.** PST, OST and mbox over `MAX_EMAIL_FILE_SIZE` are
  refused with a `not_parsed` marker, and smaller stores are read whole into
  memory. Read through `SourceCursor`. Measure messages per minute and peak RSS on
  the 16.9 GB version 23 mailbox against the current path and record both. Graded
  by the held Enron mailboxes and the large PST, counts only. 1.5 d
- **Non-mail items.** Appointments, contacts, tasks, `IPM.Configuration.*` and the
  Sync Issues logs are published as e-mail messages. Add an item-kind field from
  `PidTagMessageClass` and count each kind in the walk summary. Graded on the
  suspect OST and the Enron mailboxes against libpff `pffexport` item types. 0.5 d
- **Compressed RTF.** LZFu bodies, `PidTagRtfCompressed` 0x1009, publish an empty
  body with `body_source: rtf_not_decoded`. Decode MS-OXRTFCP and reuse
  `seance_plugin_stickynotes/src/rtf.rs` for text, keeping the raw RTF beside it.
  Graded against libpff on the three Sync Issues logs and any store with RTF-only
  messages. 1.0 d

Populated-store known answers and deleted-row carving are in Part III.

### §4.9 Network, streamed capture read  3.0 d

A capture over 256 MiB is read as a prefix, `STAGING_CAP_BYTES`, because the read
is not streamed through `SourceCursor`. Replace the prefix with a streaming block
walk, keeping reassembly's aggregate budget. Graded by a synthetic 2 GiB capture
walked under a memory ceiling, and by the Case 001 capture still giving 411,797
packets and 34,047 tuples.

### §4.10 Network anomalies, statistics and bytes over time  5.0 d

- **Anomalies.** A graded record: strong for absences, that is segments not
  captured, snaplen cuts and abandoned reassembly, and weak for retransmissions
  and resets. The facts exist as counters and there is no grading record. 3 d
- **Protocol breakdown.** Per capture, by what the bytes proved and never by port.
  Included in the heading estimate.
- **Bytes over time.** A bucketed byte series per external peer on the Timeline
  page. 2 d

Graded on Nitroba, 43 gap streams and one ARP conflict, and on Case 001.

### §4.11 Network, follow a stream into decode and rescan  3.0 d

HTTP bodies are handed on as `FileEntry`. A reassembled non-HTTP stream, such as
the Case 001 command channel on 443 that is not TLS, is not offered to the
base64, gzip and XOR child-buffer machinery or to the carvers. Graded by a stream
that carries a gzip or base64 payload on a nonstandard port.

### §5.22 `$LogFile`, multi-page records, operation codes and the circular log  ≈ 4 d

`seance_plugin_logfile` stops its walk at the first record that spills past its
page and flags it `multi_page`, so transactions that cross pages are not read. It
also walks pages in file order. `$LogFile` is a circular log. The restart area's
`current_lsn` and each client's `oldest_lsn` are parsed and unused, so a stale
record can be published beside a live one with nothing marking it.

- Reassemble across pages by LSN, add a test per documented redo and undo
  operation code, and grade against a real `$LogFile` from CFReDS or the win11
  lab. The estimate depends on a ground-truth tool such as LogFileParser output.
  ≈ 3 d
- Order records by LSN and not by page offset. Use the restart area's bounds to
  mark a record `before_oldest_lsn` or `after_current_lsn` and not live, and state
  on the status record that the log is circular and which pages wrapped. Graded on
  a hand-built wrapped log and on the real `$LogFile` above. 1.0 d

### §5.23 Allocation maps for XFS, btrfs, APFS, HFS+ and F2FS  8.0 d

These five parse files and emit no allocation bitmap, so the disk map shows no
used and free pattern and unallocated-only carving has no free regions on them.
Each reuses `seance_core::free_space::AllocationBitmap`. XFS free-space B-trees
and the btrfs extent tree are the hard two. XFS 2 d, btrfs 3 d, APFS 2 d, HFS+
0.5 d, F2FS 0.5 d. Graded against each filesystem's own tool listing of free
extents.

### §5.24 Search shows the index state  1.0 d

While an ingest or reindex runs, results can be partial and the Search page does
not say so. Show index state and how partial it is in the results banner, so that
a zero-hit result is not read as absence.

### §5.25 Screens for the registry execution artifacts  1.5 d

`UserAssistEntry`, `BamEntry`, `MuiCacheEntry` and `RdpDestinationEntry` have no
tailored viewer, and UserAssist and BAM are not Execution page sources. Add the
viewers: sortable run count, focus time and last executed for UserAssist, per SID
for BAM, MUICache labelled not-execution, and outgoing RDP labelled destination
entered and not connection made. Add UserAssist and BAM to the Execution page
with their basis shown. Extend `execution_claim` so they can raise the cross-view
finding with the correct `ClaimBasis`. Add help entries read against the
handlers. Graded by `help-coverage.test.ts`, by `scripts/viewer-coverage.sh`
falling by four, and by the UI harness record-type matrix.

### §5.45 Memory events on the case timeline  3.0 d

No memory stage emits a `TimelineEvent`. Process create and exit, driver unload,
session start, module load, command executed and file accessed stay inside memory
records, so a Prefetch run and the same process's create time are never on one
axis. `seance_reporting/src/body_file.rs` already accepts memory-sourced events,
so only the producer is missing. `COMPARISON.md` lists `timeliner` as not
answered, and the comment in `seance_memory/src/analysis.rs` that says memory
emits no `TimelineEvent` is rewritten when this lands.

Each memory stage that carries a real time emits a `TimelineEvent` with
`source_module` `plugin.memory.<stage>`, a `memory` provenance chip, and an
acquisition bracket event pair. A zero or unset time emits nothing and never an
epoch. The record keeps `incomplete`, so a timeline row inherits the confidence
chip. The timeline column definitions in `virtual_columns.rs` gain the chip.
Graded on Windows 11 build 26200 and Oberon: row counts per stage equal the dated
records, and a Prefetch run and the same process's create time are both present
for one executable. Update `COMPARISON.md`.

**Done when** one timeline view shows a disk artifact and a memory fact for the
same executable.

### §5.46 Carving a memory image  4.5 d

A memory image is emitted as `RawEvidence` plus a `ParsedRecord`.
`seance_plugin_carver` subscribes to `FileSystem` and `UnallocatedSpace` only, so
no signature carve runs over a capture. If one did, `read_full` in
`seance_carving/src/engine.rs` breaks on an error and treats zero bytes read as
the end of input, so the carve would stop at the first unmapped range and report
success. `CarvedFile` has no incompleteness field. `seance_memory/src/module.rs`
stamps every image record with a statement that the content is searchable,
carvable and hashable, and promises carving documents and images out of RAM. Only
the bulk selectors meet it.

- Emit an `UnallocatedSpace` child over the physical layer, or add `RawEvidence`
  memory images to the carver's subscription behind a subtype gate. Check whether
  string search over a capture is wired and record the answer. 2 d
- Make `read_full` tell a `MemoryHole` from the end of input and skip the hole.
  Add `CarvedFile.incomplete` and `spanned_holes`, and never set `validated: true`
  across a hole. 2 d
- Until the carve lands, change the `analysis_note` to say what runs. Record the
  result in `COMPARISON.md`. 0.5 d

Graded on `win11_bitlocker/memory-unlocked.raw` and Lone Wolf `memdump.mem`. A
planted JPEG that straddles a hole is reported as spanning it, and a carve past
the first hole finds the files that a carve of the same bytes written zero-filled
also finds.

### §5.47 LA57 five-level paging on a real capture  1.0 d

The walker, the Windows self-reference test, the Linux depth proof and
`Intel32eLa57` exist and have met synthetic tables only. Nothing in
`VALIDATION.md` or `KNOWN_ANSWERS.md` records a real capture. Boot a 5-level Linux
kernel under QEMU with `-cpu max,la57=on`, capture, record `pgtable_l5_enabled`,
and grade the depth proof, the process list and the layout constants that move,
`page_offset_base`, `vmalloc_base` and `vmemmap_base`, against `ps` ground truth.
A 4-level kernel on the same CPU grades the negative. Windows has no published
depth method and stays refused by name. Obtainable in-house.

### §5.48 Symbol management  6.0 d

The product finds symbol files through `SEANCE_SYMBOL_DIRS`, the `symbols`
directory beside the executable and a CLI fetch verb. No API route or screen
imports an ISF, lists candidates with their validity and identity, or shows a
duplicate-identifier conflict. For Linux the degraded panel names nothing, because
`DegradedModePanel.tsx` extracts a Windows PDB name, GUID and age only.

- `GET /memory/symbols` lists candidates with identity, validity gate results and
  SHA-256. A `POST` imports an ISF, plain, compressed or zipped, through the
  existing Stage A validation. Duplicate-identifier conflicts are shown and never
  resolved silently. 2 d
- A symbols settings page. 3 d
- A Linux degraded-mode recipe from the banner: the distro and kernel, the exact
  `dwarf2json` invocation, and the debug package name for Debian and Ubuntu
  `-dbgsym`, RHEL `kernel-debuginfo`, SUSE and Arch, each marked likely and never
  guessed, with the banner and the command copyable. Recipe table and tests. 1 d

Update `REPL_DESIGN.md`, `HelpPage.tsx` and `CORE_DESIGN.md`.

### §5.50 Reference-tool CSV profiles  1.0 d

The Analysis CSV export writes the record's metadata keys. No export follows the
column order of the tool an examiner diffs against. Give each record type that has
a reference-tool oracle a named CSV profile in that tool's column order: WxTCmd
Activity and PackageId, `last -aiFw` and `lastb`, Autorunsc `-c`, and MFTECmd
`--sds`. An examiner can then diff the product against the tool in a spreadsheet.
Graded by the column headers of each profile against the oracle's own output.

### §5.51 MBR on 4096-byte sectors  1.0 d

`seance_plugin_partition` fixes the sector size at 512 on the MBR branch, beside a
GPT branch that detects 512 and 4096. A legacy MBR on a 4096-byte-sector image is
parsed with every LBA multiplied by 512, so partition offsets and sizes are wrong
and the filesystem parsers read the wrong bytes or find nothing. Probe for 4096
when the 512 reading puts a partition start where no boot sector or filesystem
signature sits and the 4096 reading does. Record the chosen `sector_size` and the
basis on the partition record. When both fit or neither does, keep 512 and say the
sector size was assumed. Graded on a `mkfs`-built 4Kn MBR image, a loop device made
with `--sector-size 4096`, and by the existing 512 images unchanged. Update
`Container_Formats.md`.

### §5.52 File grid, act on a selection  1.5 d

A selection in the file grid offers ZIP export and nothing else. The timeline has
bulk tag, and the Gallery has bulk bookmark and run module. Add Bookmark selected
with a category, Tag selected, and Run module on selected, with the module list
from `GET /modules?artifact_type=FileEntry` through the existing
`run_module_batch` route. Use the same bounded concurrency and case scoping as the
timeline bulk tag. Update `HelpPage.tsx`. Graded by component tests and the UI
harness interaction matrix.

### §5.62 PDF document metadata  2.0 d

`seance_plugin_office` reads Office document properties. No plugin parses a PDF,
so its author, creation tool and dates are read nowhere, and `seance_carving`
only finds the file. Add a reader for the Info dictionary and the XMP packet:
title, author, creator application, producer, creation and modification dates,
page count and the encryption flag. Emit one record joined to its `FileEntry`.
A date is the file's own claim and never the time of authorship. Walk
incremental updates, so that an earlier Info dictionary is reported beside the
current one. An encrypted PDF whose strings cannot be read says so and emits no
empty fields. Add a fuzz target to `fuzz/Cargo.toml`, `fuzz.yml` and
`SECURITY.md`. Update `COMPARISON.md` and the Office
metadata row in the design documents. Graded against a `qpdf` or `exiftool`
listing of a set of PDFs that includes an incrementally updated one and an
encrypted one.

**Done when** the listing and the records agree field for field on that set.

### §5.63 Browser cache bodies  4.0 d

`seance_plugin_chrome_cache` recovers the cached URL of each Chrome and Edge
entry and states that it recovers no content. Firefox `cache2` and Safari
`Cache.db` have no reader. The response body a browser stored is therefore
produced for no browser. Emit each body as a `FileEntry` artifact with its URL,
status, response headers and content encoding, decoded once with a size cap and
the encoding stated. A truncated or partial body is flagged incomplete.

- **Chromium.** Simple Cache and blockfile response bodies, from the stream
  addresses the blockfile path does not read today. 2 d
- **Firefox.** `cache2` entries, body and metadata. 1.5 d
- **Safari.** `Cache.db` and `fsCachedData`. 0.5 d

Graded on cache directories made in the lab by fetching files of known SHA-256,
where each recovered body must hash to the served bytes. Update the crate
documentation of `seance_plugin_chrome_cache`, `COMPARISON.md`.

**Done when** a body fetched in the lab is recovered with the served hash from
each of the four browsers.

### §5.67 Related artifacts, the pivot from one record to the rest  10.0 d

`GET /cases/:id/pivot` answers "everything that touches this value" by a text
search grouped by record kind, and the pivot drawer is reachable from many
viewers. Nothing answers "everything related to this artifact". Following a
deleted file through its Recycle Bin entry, its `$R` file, its file entry, its
USN journal entries, its LNK and its Explorer history takes five searches, and
no page shows the rest. The Connections page is the communication graph and is
not this. Build a relation index at ingest and on demand: normalised path, file
reference as MFT record plus sequence, SHA-256, account or SID, URL host and
process name. Add `GET /cases/:id/artifacts/:artifact_id/related`, answering by
relation kind. Each link carries the rule that made it, such as "same path",
"same file reference" or "names this path". A link with no stated rule is not
emitted. Add a Related panel to the artifact page and to the row inspector of
every record viewer, and a graph view seeded from any node. Cap the fan-out and
state the cap when it bites. Update `HelpPage.tsx`, `CORE_DESIGN.md`,
`REPORTING_DESIGN.md` and `COMPARISON.md`.

- **Relation index and endpoint.** 5 d
- **Panel on the artifact page and the row inspector.** 2.5 d
- **Graph view seeded from a node.** 2.5 d

Graded on DFIR Madness Case 001, where the Recycle Bin entry `$IU2L112.txt`,
the `$R` file, the `SECRET_beth.txt` and `Beth_Secret.txt` file entries, the USN
entries, the LNK and the Explorer visits must all appear from any one of them.

**Done when** the Related panel on `Beth_Secret.txt` lists the other records of
that chain, each with its rule, from the screen alone.

### §5.68 A findings-first dashboard  4.0 d

`GET /cases/:id/findings` and the Findings page carry the ranked detections.
The dashboard shows artifact counts, a size histogram, an activity chart, the
sources, recent activity, jobs and the attention queue, and no finding reaches
it. A strong timestomp signal, flows to an external host, a deleted file in the
Recycle Bin under a user path, internet RDP logons and removable devices are all
in the case and none is on the first screen. Add a fixed set of named,
documented rules that count over the case, with the query that reproduces each:
strong indicators, external-network flows by volume, deleted items under user
paths, external logons, removable devices and hash-set hits. Encrypted stores
not opened and incomplete parses already reach the attention queue and are
linked from it. Add dashboard tiles that open the records viewer filtered to
the rule. Each tile states the rule it counted, so the number is quotable. A
zero states which rules ran. Update `HelpPage.tsx`, `REPORTING_DESIGN.md` and
the Part V entry on the case-level staleness banner.

**Done when** Case 001 shows its timestomp finding, its external flows, its
Recycle Bin entry from `\FileShare\Secret`, its RDP logons and its two USB
devices as tiles, each opening the filtered viewer with the same count.

### §5.69 Record viewers, server-side aggregates  4.0 d

The Windows Event Log viewer's tiles, histogram and top-ten bars are computed in
the browser over the 200 rows loaded and say so. An examiner asking how many 4624
logons there are, from which addresses, gets the loaded rows and not the case's
126,259. `getAllRecords` stops at 8 pages of 100, and Part V holds the client path
until a measured case shows it wrong. Case 001 is that case. Add a summary route
for one record type that returns counts, a time histogram and top-N values for
named fields over the whole case, filtered the same way as the list. Switch the
Windows Event Log viewer to it first, then the network flow, logon and browser
history viewers. Keep the `truncated` statement for every viewer still on the
client path. Update `HelpPage.tsx`, `CORE_DESIGN.md` and the aggregate entry in
Part V.

**Done when** the Event Log viewer's 4624 count and top addresses match a
database count over all rows of Case 001.

**P3 total: 7.5 + 1.75 + 4.5 + 4.0 + 9.0 + 29.5 + 6.0 + 8.0 + 2.85 + 2.75 + 1.75 + 2.0 + 5.75 + 3.0 + 5.0 + 3.0 + 4.0 + 8.0 + 1.0 + 1.5 + 3.0 + 4.5 + 1.0 + 6.0 + 1.0 + 1.0 + 1.5 + 2.0 + 4.0 + 10.0 + 4.0 + 4.0 = 152.85 d**
(§5.3, §5.42, §5.43, §5.44, §5.17, §5.18, §5.19, §5.20, §5.21, §3.8, §2.13, §2.14, §3.10, §4.9, §4.10, §4.11, §5.22, §5.23, §5.24, §5.25, §5.45, §5.46, §5.47, §5.48, §5.50, §5.51, §5.52, §5.62, §5.63, §5.67, §5.68, §5.69).

## P5. Substrate and debt

### §5.9 `seance_hive`, what the reader still owes  1.0 d

Layered keys, minor version 6, are interpreted and graded on the Nano Server
hives. Subkey leaf indexes are read in place and `ri` index records stay eager by
decision. A single differencing hive is reported as what it is. Still owed:

- **A consumer of the merged view.** Nothing builds the merge of a base hive and
  the layers above it, because that needs the chain discovered in the case, a
  container image's `Hives/*_Delta` beside its base hive. Not startable here. How
  a case presents the layers of one image, one tree or one per layer, is not known
  from anything held, and a discovery rule written without it would be a guess
  about the evidence. ≈ 1 d once such a case is held

### §5.26 Schema-drift defence, enforce it  1.1 d

Follows §1.4a. 27 crates depend on `seance_sqlite_util` and nothing stops a 28th
from opening an app database with no defence.

- **A registry test.** A test in `seance_tests` reads each workspace `Cargo.toml`,
  finds crates that depend on `seance_sqlite_util`, and requires each to appear in
  a registry, with the crate, the validated range or the unranged reason, and the
  database it was read from, or in an exclusion list with a reason. Graded by a
  synthetic crate missing from both, which must fail. 0.5 d
- **A NULL-substitution lint.** Hand-rolled `"NULL"` fallbacks remain in
  `seance_plugin_android_apps`, `seance_plugin_browser_history`,
  `seance_plugin_contacts` and `seance_plugin_imessage`. Classify each as optional
  or required through `FieldMap`. A required field that no candidate resolved must
  produce the `SchemaFieldsUnresolved` claim and never a silent NULL. Add a
  `scripts/forensic-lint.sh` rule that fails on a bare `"NULL"` fallback outside
  `seance_sqlite_util`, with a self-test of one positive catch and one honoured
  `forensic-lint: allow`, so that the rule cannot stop catching silently. Graded
  by a store with a renamed required column. 0.6 d

### §5.27 Fuzz targets for untrusted-input decoders  1.75 d

Seven decoders read attacker-authored bytes and have no fuzz target. Each target
is 0.25 d.

- `fuzz/fuzz_targets/ios_notes_proto.rs` drives the Notes protobuf decoder, which
  inflates gzip and walks a hand-rolled varint protobuf from note blobs. Seed from
  the two real Magnet 2022 note blobs.
- `fuzz/fuzz_targets/sdb_parser.rs` drives the `.sdb` walker. Seed with truncated
  and mutated headers and not whole files, because the stock databases are
  Microsoft's.
- `fuzz/fuzz_targets/pcap_parser.rs` drives `seance_plugin_pcap`: container,
  HTTP, TLS, X.509, reassembly and decode. Seed with the first MiB of the Nitroba
  and Case 001 captures and a truncated pcapng.
- `fuzz/fuzz_targets/openbsm_parser.rs` drives `openbsm.rs`. Seed with a real trail.
- `fuzz/fuzz_targets/asl_parser.rs` drives the Apple System Log reader. Seed with
  a real `.asl`.
- `fuzz/fuzz_targets/spotlight_store.rs` drives `spotlight.rs`, one of the largest
  evidence-controlled decoders. Seed with the 1.4 MB store.
- `fuzz/fuzz_targets/secdesc_parser.rs` drives the descriptor decoder in
  `seance_core::secdesc`, shared by `$SDS` and the registry `sk` cell. Seed with
  the two SAM descriptors and one SYSTEM mandatory-label descriptor.

Sticky Notes `rtf.rs` and the WLAN profile XML reader are candidates for a later
target. Add each target to `fuzz/Cargo.toml`, the `fuzz.yml` set and the target
list in `SECURITY.md`. Graded by a clean bounded run.

### §5.28 CI wiring for evidence-gated checks  2.5 d

- **The UI harness.** `scripts/ui-tests` runs by hand only. Add a `ui-harness` job
  to `test.yml` with a pinned browser, using the 316 KB golden multi-partition
  image as the first target, and make a failure fail the pull request. Add a
  nightly schedule for the full integration run. Decide the existing 60 percent
  coverage floor in `.tarpaulin.toml`: either gate it or remove the claim. 2 d
- **The `.sdb` corpus gate.** Extract the seven stock databases from the Windows
  11 ARM64 install media into `win11_bitlocker/sdb/`, record SHA-256 in
  `PROVENANCE.md`, export `SEANCE_SDB_SAMPLES` in `corpus-gates`, and add a
  `VALIDATION.md` entry with the counts: 923,418 tags and 344,727 string
  references. 0.5 d

### §5.29 An OpenAPI document  4.0 d

`utoipa` is a dependency and only `auth.rs` uses it. No specification is
generated or served. Annotate the handlers, serve `/api/v1/openapi.json`, and
add a CI check that every registered route appears in the document.

### §5.30 A per-run context for `ForensicsModule::process`  3.5 d

`process()` takes no context, so the orchestrator cannot inject a progress
reporter or a cancellation handle at dispatch. `seance_plugin_carver/src/lib.rs`
carries a `TODO(orchestrator-context)` for the workaround. Add a defaulted
`process_with_context` that carries both, adopt it in the carver, and remove the
TODO. 2 d

The first adopter after the carver is `MemoryAnalysisModule` for each OS, which
runs for tens of minutes with no cancellation and no named stage.
`ModuleProgress` carries `units_done`, `units_total` and `unit` and no stage label,
and cancellation is checked between modules only. Add `ModuleProgress.stage` as an
optional string, which is a wire-format change, so the SSE reducer in the frontend
changes in the same commit, and a cancellation check between stages. Graded by
cancelling a Windows 11 analysis mid-run and finding no partial record that claims
completeness. 1.5 d

### §5.31 Lint hygiene  5.0 d

- Deny `clippy::unwrap_used` in non-test code. About 122 residual sites are all
  infallible `try_into` or regex literals, so convert them to a helper or add a
  justified allow. 1.5 d
- Enable `missing_docs` as a warning on `seance_core` and `seance_api` public
  items. 0.5 d
- Replace `Result<_, String>` at crate boundaries. About 230 sites. The
  replacement error carries the file, the offset and what was expected, so a
  failure says where it stopped. Included in the estimate. 2.5 d
- Audit the 54 non-test `#[allow(dead_code)]`, 22 in apfs, 10 in btrfs, 10 in
  fat and exfat and 6 in `seance_plugin_macos_artifacts`, with a one-line reason
  each or removal. 0.5 d

### §5.32 Fixtures and a plugin testing guide  1.5 d

- **Synthetic ext4 edge fixtures.** 48-bit physical extent addresses, an htree
  directory of more than 1,000 entries, and hash collisions. Generate them with
  `scripts/synth`, `mke2fs` and `debugfs`, and assert against `debugfs` output. 1 d
- **A testing section in `documentation/MODULE_DEVELOPMENT.md`.** The `DataSource`
  doubles in `seance_core::test_support`, the corpus gate and
  `SEANCE_REQUIRE_CORPUS`, the fuzz-target artifact-shape guard, and the
  forensic-lint classes. 0.5 d

### §5.33 Documentation owed for shipped parsers  1.35 d

- Document `seance_plugin_sdb` in `WINDOWS_DESIGN.md`, add a `COMPARISON.md` row
  for shim databases graded on stock databases only. 0.25 d
- State UserAssist, BAM and MUICache in `COMPARISON.md` and
  `README.md`. 0.25 d
- Correct the documents that still describe shipped iOS parsers as not shipped:
  the crate doc of `seance_plugin_ios_artifacts` and `IPHONE_DESIGN.md`. 0.25 d
- Write the method statement for `plugin.ios.voice_memos`, the one registered
  module without one, and regenerate `METHOD_STATEMENTS.md`. 0.25 d
- State in `VALIDATION.md` that the BSM and ASL checks are graded on
  self-consistency, because no external `praudit` or `syslog` oracle was
  available. 0.1 d
- Write into `REPORTING_DESIGN.md` the report wording for three limits: an audit
  trail's silence is bounded by `audit_control`, a Spotlight item is an index entry
  and not proof that a file exists now, and an unresolved unified-log message is
  not an empty one. 0.25 d

### §5.34 Logical lens categories for Videos, Documents and File Transfers  3.0 d

Extend `media_counts` into a `GET /cases/:id/categories` rollup, one GROUP BY over
the `FileEntry` extension, add the buckets to `categories.ts`, and embed the
existing record or file viewers. File Transfers needs a parsed source first and is
not in the estimate.

### §5.35 Saved searches  1.0 d

Reuse `components/SavedViewsMenu` on the Search page to store the query, mode,
type filter and limit per case.

### §5.53 Close the viewer gap  4.0 d

`scripts/viewer-coverage.sh` reports 248 emitted record types, 127 with a tailored
viewer, 16 served by dedicated pages and 94 without. `UI_TESTING.md` treats a record type in the generic table
as a defect. Types that shipped parsers created and that are still generic
include `ShimDatabase`, `MemoryKernelTimer`, `MemoryTamperChecks`,
`MemorySkeletonKeyCheck`, `MemorySuspiciousThreads`,
`MemoryUnloadedDriverRangeHit`, `MemoryEtwExport`, `MemoryProcessorBlock`,
`MemoryJob`, `MemoryDriverDevices`, `VoicemailAudioOrphan`, `AndroidNote`,
`NtfsFileName`, `NtfsIndexEntry`, `UalClientAccess` and `UalRoleAccess`.
`PhotoAlbum`, `NotesFolder`, `HealthWorkout` and `VoiceMemo` appear in no
frontend source file and the script does not list them. Viewers that other items
here add are not counted.

For each of the 94 types, add a tailored viewer or add a one-line reason to the
gap table in `UI_TESTING.md`. The 4 d covers the 16 types named above. The rest is open-ended and is taken as the types are touched.
Graded by `scripts/viewer-coverage.sh --count` falling, and by a CI trend check.

### §5.54 Case database upgrade test and migration policy  1.5 d

Every test applies the migrations to an empty database. Nothing opens a case
database written by an earlier build and brings it forward. Freeze a database file
made with this release's migration set as a fixture, seed it with a case,
artifacts, timeline events, a bookmark, an audit chain and a hash set, and open it
with every later build. Assert the counts, that the audit chain still verifies,
and that the new indexes exist. State in `DEPLOYMENT.md` that migrations are
forward-only, that an applied migration file is never edited because sqlx checks
its checksum, and that a downgrade is unsupported. Graded by the test failing when
an applied migration is edited.

### §5.55 Custom ingestion profile editor  1.5 d

An examiner cannot define a custom ingestion profile in the web UI. They can list,
activate and delete one, and create one from the REPL or the API. `createProfile`
in `frontend/src/api/resources.ts` has no caller. Add a settings panel that lists
the registered modules from `GET /modules`, groups them by category, and posts
`createProfile` with the enabled and disabled lists. Show the module count and the
`profileScope` population statement, so that an examiner sees what a profile will
not run. Update `HelpPage.tsx`. Graded by a component test that creates a profile
and then ingests with it.

### §5.65 Carving signature selection per ingest profile  1.0 d

Custom carving definitions can be added through `carver_defs`. No profile can
switch a built-in signature off, so an examiner who does not want a class of file
carved cannot say so. Add a disabled-signature list to the ingestion profile,
honour it in `seance_plugin_carver`, and list the signatures that ran and those
disabled in the report's method section. Update `REPORTING_DESIGN.md`, and
`HelpPage.tsx` if the profile editor of §5.55 exposes it. Graded by a profile that
disables JPEG and finds none on an image that holds one, while the default
profile finds it.

**P5 total: 1.0 + 1.1 + 1.75 + 2.5 + 4.0 + 3.5 + 5.0 + 1.5 + 1.35 + 3.0 + 1.0 + 4.0 + 1.5 + 1.5 + 1.0 = 33.7 d**
(§5.9, §5.26, §5.27, §5.28, §5.29, §5.30, §5.31, §5.32, §5.33, §5.34, §5.35, §5.53, §5.54, §5.55, §5.65).

## P6. Parked

Listed so that leaving each out is a decision. An item moves up when the
condition beside it is met. Sizes are outside estimates.

| Item | What | Condition | Est. |
|---|---|---|---:|
| §2.15 | Video keyframes and thumbnails. HEIC and HEIF pixel decode, where EXIF reads and the image does not decode. Video GPS, where `mvhd` creation time ships in `seance_plugin_media` | Someone asks. The decoders are a dependency decision | 6 d |
| §2.16 | PhotoDNA and ONNX **providers**, out-of-process over a documented line-framed protocol, the pattern `seance_container_e01` uses for libewf. PhotoDNA cannot be vendored under any licence and no defensible open training data exists for a classifier. Build the boundary and the ranking UI, ship no model. Output is a lead and never a finding | A lab with a licence or a model | 10 d |
| §2.9 | VeraCrypt and TrueCrypt volume decryption 8, Intel FileVault2 8 for software-encrypted APFS only, iOS and Office crack verifiers 5, an API and UI crack trigger 2, GPU 10, per-document encrypted-file flagging 2, iOS Screen Time passcode 2 | A case that needs one. The cracker engine and the CLI verbs exist | 37 d |
| §3.2 | Linux `auth.log` and syslog, crontab, shadow, the systemd journal, dpkg and rpm history | A Linux case that turns on them | 6 d |
| §3.3 | Discord, Slack Desktop, Signal Desktop | Same | 6 d |
| §3.4 | Dropbox, OneDrive, Google Drive, iCloud sync databases | Same | 6 d |
| §3.5 | Credential stores, payment apps, P2P, social and notes apps, game chat, health, wearable and vehicle, crypto-wallet files, audio as a media class | A persona decision, Part VI | ≈ 20 d |
| §3.17 | An EFilter-style query engine over artifact types | A persona decision | 20 d |
| §3.8a | Windows ARM64 memory. Two real Windows 11 ARM64 captures are held, builds 28000 and 26300, and the translation is graded. Missing: a DTB discovery route, because the x64 self-reference and low stub do not exist there, and the Windows plugin refuses an ARM64 image | A decision to support Windows on ARM64 | ≈ 5 d |
| §3.8b | macOS memory breadth. These 20 macOS plugins have no answer: `psaux`, `malfind`, `proc_maps`, `bash`, `netstat`, `ifconfig`, `socket_filters`, `lsof`, `list_files`, `mount`, `vfsevents`, `check_syscall`, `check_trap_table`, `check_sysctl`, `kauth_scopes`, `kauth_listeners`, `trustedbsd`, `timers`, `kevents`, `dmesg`. The tier has four stages, every record is stamped unvalidated, and unvalidated stages multiply what an examiner must discount | A real Mac capture, the one in Part III | ≈ 20 d |
| §3.9 | Portable-case bundle. L01 and E01 creation. Concordance and EDRM load files | An e-discovery customer | 18 d |
| §3.11 | Crypto transaction-hash entities. Offline reverse-geocoding. Chat to media linking. Chat and activity to file linking, best effort and no link when uncertain, where the Windows Timeline `content_uri` is kept as text only | Someone asks | 6.5 d |
| §3.12 | A Python plugin binding with `pyo3` and pluggable exporters | A third-party plugin author | 20 d |
| §3.13 | RAID 5EE, which has no `mdadm` ground truth. Windows dynamic disks, LDM. A byte-for-byte diff of the reassembled stream against a live `mdadm` array, which is doable with root and loop devices in 1 d | A case | 6 d |
| §3.14 | Cross-case search and cross-case duplicates | A multi-case lab | 15 d |
| §3.16 | EnCase Ex01, Lx01 and X-Ways containers. Ex01 is EWF-family | A case that arrives in one | 4 d |
| §4.1 | Local imaging and live RAM capture, and a remote collection agent. **Live RAM capture is the one row worth re-opening.** A signed driver on Windows, or `/proc/kcore` or a LiME-style module on Linux, writing the format this product's own analysis reads. Shipping a kernel-level tool changes what the project is responsible for | An owner's decision | 30 d and more |
| §4.4 | iCloud, M365, Google Workspace, Slack and S3 acquisition | A customer. Holding credentials is an operational liability | 40 d and more |
| §4.5 | Bates numbering, privilege tagging, production sets with redaction | An e-discovery customer | 20 d |
| §4.6 | Cellebrite UFED, GrayKey and Oxygen outputs. SIM. Physical `.bin`. UFDR ships | A case that arrives in one | 10 d |
| §4.7 | A read-only FUSE and WebDAV mount of the derived-artifact tree | A lab that needs to point other tools at the tree | 10 d |
| §4.8 | The uniform `mapping()` contract at every layer. `backed_len` and the corrected default are done | A new layer that needs it | 15 d |
| §4.12 | Network field-to-byte provenance. Each decoded field carries a capture offset and length and links to the hex viewer. Graded by re-reading the cited bytes | A case that turns on it | 4 d |
| §4.13 | SMB object export. DNS over TCP. HTTP/2 and HTTP/3. QUIC. mDNS. The pcapng Name Resolution Block and Decryption Secrets Block, which are counted by type and not read. A secrets block with a TLS key log would unlock TLS content and sits behind the credential route | A case that turns on one of them | 8 d |
| §5.5 | ReiserFS, UFS, QNX | A case | 4 d each, 12 d |
| §5.36 | Memory layers and comparison. A Xen `dump-core` layer, 2 d. `vmscan` for VMCS discovery and nested guests, 5 d. A diff of two captures of one host, 6 d | A Xen image. A nested-guest capture. Two captures of one machine, which the Windows 11 BitLocker VM can make | 13 d |
| §5.37 | Cloud service audit logs as offline exports: CloudTrail, Azure activity, M365 unified audit log. A new module producing timeline events with actor, source IP and operation. Graded on a public sample set. No account access, so none of the credential liability of §4.4 | A cloud or IR case, or a persona decision | 6 d |
| §5.38 | Scale and stress tests. Synthetic generators for MFT at 100k to 1M records, a 10k-entry ext4 directory and a 100k htree. A sparse 2 TiB raw file with a GPT at the head and a filesystem near the end, ingested under a memory ceiling, asserting that the partition walk reads only the table and the run completes, with peak RSS recorded. E01 read benchmarks at 100 GB, 1 TB and 2 TB, each stated as not measured until an image can be built. Stress tests for 10 or more concurrent cases, 100 or more ad-hoc jobs, concurrent HTTP ingests, queue overflow, disk full during spill and ingest, and database pool exhaustion. A database batch-insert Criterion bench | A production report of exhaustion, or a scale claim made in a document | 8 d |
| §5.39 | ASEP Winsock LSP catalog, decoding the provider path out of `WSAPROTOCOL_INFO`, 1 d. A signer join from PE records, second pass, `unknown` unless a real Authenticode record is matched by full path, 1 d | A case that turns on either | 2 d |
| §5.40 | Carving utmp records from unallocated space. Needs a lab-made deleted wtmp to grade | A case where wtmp was deleted and the layout is recoverable from slack | 2 d |
| §5.41 | A trustee access index and lens over every ACE trustee, for the question which files can Everyone write. It must not claim who could read without evaluating inheritance, deny ordering and group membership | An examiner asks | 2 d |
| §5.49 | Bespoke memory lenses, **owner to decide**. The Memory section ships eight lenses: Overview, Image, Processes, Network, Handles, Services and hives, Credential stores and Findings. Designed and not built: a VAD ribbon, a region viewer with hole banding and entropy, lifetime lanes with a time axis, connection lanes, an IRP matrix, a handle graph and the force-graph generalisation it needs, a memory map page over `physical_map`, which answers which offset in the E01 holds a RAM address and has no consumer in the frontend, a Modules page with the agreement matrix, a kernel hooks page, and Linux and macOS lenses for mounts, `kmsg`, netfilter, ftrace and tracepoint tables. Build in this order, each with the four-state test and the honesty assertions: map and coverage page 3 d, region viewer with VAD ribbon 5 d, kernel hooks page with IRP matrix 4 d, modules page 3 d, lifetime and connection lanes 4 d, handle graph 5 d. Or record in Part V that the generic stage tables are the design, which is 0.25 d | The owner chooses | 24 d |
| §5.56 | Pre-BTF Linux symbols. A kernel with no BTF, before 5.2 in practice, and no published ISF ends at `SymbolsNotFound`. Either native DWARF to ISF with `gimli` and `object`, neither of which is a direct dependency of any workspace crate and both of which are in `Cargo.lock` only as transitive dependencies, so that adding either directly is vetted like any new dependency, or invariant-scan layout inference stamped inferred on every record | A case with a pre-5.2 kernel and no published symbols | 18 d |
| §5.57 | Tunnel decapsulation. IP-in-IP, 6in4, GRE and VXLAN, with a depth cap of 2, the outer and inner flow both recorded, the outer addressed as the tunnel and never merged into the inner flow, and a depth beyond the cap a named shortfall. A tunnelled channel today appears as one opaque flow between two tunnel endpoints | A case with tunnelled traffic | 3 d |
| §5.58 | Note edit history. Field 5 of the NoteStore body protobuf is the repeated per-edit record with Unix-second timestamps, and it is walked past. Decode it into an `edit_times` list on `Note` and a timeline event per edit, stated as the editor's device clock. Field meaning other than the timestamp stays unread. Graded on the two Magnet 2022 blobs and the Hickman iOS 17 backup's 13 notes | An examiner asks | 1 d |
| §5.59 | **Owner to decide.** `EvtxRecoveredLogEntry` chunk carving over hibernation and pagefile sweeps, graded on `win11-lab/hiber` where the VM wrote known events. `seance_plugin_evtx` subscribes to `FileEntry`, `SystemArtifact` and `ParsedRecord` only. Or record in Part V that it is declined | The owner chooses | ≈ 1.5 d |
| §5.60 | **Owner to decide.** Search option parity: match case and whole word, which the published methodology asks for, and an index-coverage statement for CJK. Regex mode is fixed case-insensitive. Or record in Part V that the gap is declined | The owner chooses | 1.5 d |
| §5.61 | Visualization layers. Allocation map overlays for the selected file's cluster runs, carved-file positions and `$BadClus` ranges, each toggled and labelled, which needs absolute-offset composition for carved files, and the timeline histogram stacked by module or event type with a legend. `seance_plugin_badclus` already persists the ranges | An examiner asks, or §5.23 lands | 2.5 d |
| §5.64 | OCR over PDF pages and Office embedded images. `seance_plugin_ocr` reads raster images and nothing hands it a PDF page or an Office image. It needs a PDF rasteriser dependency decision. Graded on a scanned PDF of known text | Someone asks | ≈ 4 d |
| §5.66 | Report previews. A thumbnail beside each image bookmark in the HTML, DOCX and PDF reports, which embed SVG figures only today. The thumbnail is a derived copy and names its source file and hash | Someone asks | 2 d |
| none | The APFS edge-axis fixtures: non-4K blocks, `decmpfs`, snapshots, Fusion | A Mac with root, or a captured image | 3 d |

**P6 total: 448.0 d and more.** The plus rows are §4.1 and §4.4.

---

# Part II. Sprints

A sprint is a bounded scope with an exit criterion, sized to about ten
developer-days. It closes when its criterion is met. Items keep their `§`
numbers.

| Sprint | Goal | Carries | Days | Cumulative |
|---|---|---|---:|---:|
| **S1** | Open defects | P0 | 10.75 | 10.75 |
| **S2** | Windows system information, measured | §2.6 | 9.0 | 19.75 |
| **S3** | Validated by someone else's method | §5.2, §1.4a | 9.0 | 28.75 |
| **S4** | Oracle runs, the unified log, Android provenance and owed documents | §5.15, §1.6, §1.4, §1.5, §5.33 | 9.6 | 38.35 |
| **S5** | Apple Mail, the schema registry and fuzzing | §3.10, §5.26, §5.27 | 8.6 | 46.95 |
| **S6** | CI, fixtures, the upgrade test and the run context | §5.28, §5.32, §5.9, §5.54, §5.30 | 10.0 | 56.95 |
| **S7** | Persistence and registry replay | §5.17, §5.42 | 10.75 | 67.7 |
| **S8** | Login accounting, registry screens and CSV profiles | §5.43, §5.50, §2.13, §2.14 | 9.25 | 76.95 |
| **S9** | Ownership, execution screens, the file grid and profiles | §5.44, §5.25, §5.52, §5.55, §5.51 | 9.5 | 86.45 |
| **S10** | Windows memory plugins and their screens | §5.3, §5.21 | 10.35 | 96.8 |
| **S11** | Memory sweeps, disk correlation and LA57 | §3.8, §5.19, §5.47 | 9.75 | 106.55 |
| **S12** | Memory carving, `$LogFile` and search | §5.46, §5.22, §5.24, §5.35 | 10.5 | 117.05 |
| **S13** | Memory report and timeline | §5.20, §5.45 | 11.0 | 128.05 |
| **S14** | Linux memory, process depth | §5.18 process depth, VMA scans and kernel stack walk | 9.5 | 137.55 |
| **S15** | Linux memory, state and page cache | §5.18 network and kernel state, page cache | 10.0 | 147.55 |
| **S16** | Linux memory, detectors | §5.18 rootkit and hook detectors | 10.0 | 157.55 |
| **S17** | Network | §4.9, §4.10, §4.11 | 11.0 | 168.55 |
| **S18** | Documents, browser cache and carving selection | §5.62, §5.63, §5.65 | 7.0 | 175.55 |
| **S19** | Allocation maps | §5.23 | 8.0 | 183.55 |
| **S20** | Symbols and categories | §5.48, §5.34 | 9.0 | 192.55 |
| **S21** | API document and the viewer gap | §5.29, §5.53 | 8.0 | 200.55 |
| **S22** | Lint hygiene | §5.31 | 5.0 | 205.55 |
| **S23** | Related artifacts | §5.67 | 10.0 | 215.55 |
| **S24** | The findings dashboard and server-side aggregates | §5.68, §5.69 | 8.0 | 223.55 |

**223.55 developer-days** in the sprint table for one engineer, before P6. This
equals P0 10.75 + P2 26.25 + P3 152.85 + P5 33.7. Every item of Part I appears in
exactly one sprint, except §5.18, which is split across S14 to S16 by its bullets.
The order front-loads the defects and the public-key measurements. Parity and
reach work follows. Debt is last because none of it changes an answer.

### Exit criteria

- **S1.** Each P0 entry is closed in `BUGS.md` or its remaining dimension is named
  there with the evidence it needs. `HUNT-283` to `HUNT-290`, `HUNT-293` and
  `HUNT-294` are closed with a test each.
- **S2.** The Data Leakage key answers 55 of 60 from a screen, and every new
  record type has a viewer.
- **S3.** The mobile core run, L1 to L5, `SFT-*` and `WRT-*` are recorded. The
  corpus-gated schema tests run every adopted parser on a runner that holds the
  evidence.
- **S4.** The four oracle runs of §5.15 and the three unified-log comparisons are
  in `VALIDATION.md`. The `packages.xml` attributes are read or stated absent. The
  owed documents are written.
- **S5.** The iOS index is refused loudly when its schema is absent. The registry
  test and the lint exist. Every new fuzz target runs clean.
- **S6.** The UI harness job exists. The upgrade test fails when an applied
  migration is edited. The memory pipeline reports a stage and can be cancelled.
- **S7.** The Case 001 implant is visible in the persistence view with its key
  time. A replayed hive's report lists the keys it changed.
- **S8.** A report states logins and sessions, and a `btmp` raises its lead. A
  key's owner and DACL appear on the Registry tab. Each reference-tool CSV profile
  matches its oracle's headers.
- **S9.** Files sort by owner. The registry execution artifacts have viewers. A
  file grid selection can be bookmarked, tagged and run through a module. A custom
  profile can be made in the UI. A 4096-byte-sector MBR image reads.
- **S10.** Each plugin moves to answered in `COMPARISON.md` with its module named,
  graded on `test_data/win11_bitlocker/memory-unlocked.raw` and not on Lone Wolf
  or Magnet 2020.
- **S11.** A re-run on a reconstructed image reads the reconstructed layer. A
  module is shown as on disk, not on disk or not checked. A real 5-level capture is
  graded.
- **S12.** A planted file that straddles a hole is reported as spanning it. A
  wrapped `$LogFile` marks its stale records. The Search page says when the index
  is partial.
- **S13.** A generated report states what a memory image did and did not show. One
  timeline view shows a disk artifact and a memory fact for the same executable.
- **S14 to S16.** The item's own done-when, with clean-capture false-positive
  counts recorded.
- **S17.** A multi-gigabyte capture is read whole. Anomalies carry a grade.
- **S18.** A PDF's metadata matches a `qpdf` listing. A body fetched in the lab
  is recovered with the served hash. A profile that disables a signature carves
  none of that class.
- **S19 to S24.** Each item's own done-when.

---

# Part III. Blocked on evidence this project cannot produce

In each case the code is the easy part and the verification is impossible
without something that has to be obtained or made. Each entry names exactly
what. The last column is the estimate for the work once the evidence is held. It
is outside the tier totals, and an entry that repeats a P0 item is not additional.

| Item | Needs | Notes | Est. once held |
|---|---|---|---|
| **ARM64 memory analysis on hardware** (§3.8a, `MEM-043`) | A capture from ARM64 Linux or Windows hardware | Linux discovery over the translation core is graded on QEMU-emulated dumps, `MEM-ARM-1` to `MEM-ARM-11`: 4, 16 and 64 KiB granules, FreeBSD, NetBSD, HelenOS, and two real Windows 11 ARM64 captures. They are real page tables written by a real kernel and not hardware. Cannot be produced on an Apple silicon Mac: under Virtualization.framework, SIP withholds the VM's task port from `task_for_pid` even as root, and `saveMachineStateTo` writes a host-key-encrypted file. Do not retry blindly. Windows ARM64 discovery is parked in P6 | 3 d, the `MEM-043` figure |
| **TrueCrypt and VeraCrypt in memory** (`MEM-044`) | A capture with `truecrypt.sys` or `veracrypt.sys` loaded and a volume mounted | 48 product builds on four OS builds are graded. Left: builds not captured. **Obtainable in-house:** the same VM, with the oracle `scripts/oracle/vc_header_keys_all.py`, half a day each | 0.5 d per build |
| **iOS: Photos faces, the positive branch of deleted notes, and messaging attachment media bytes** (§1.5) | An iOS extraction in which each of those tables holds at least one row | On the one device held, Magnet 2022 iPhone 8, iOS 15, `ZDETECTEDFACE` and `ZPERSON` hold 0 rows, `ZMARKEDFORDELETION` holds 0, and messaging attachment media is not graded. Each is counted and reported unread. None is decoded from a spec | ≈ 2 d |
| **App parsers with no validated schema range** (§1.4a) | A real, readable store of each: WhatsApp `msgstore.db` and `ChatStorage.sqlite`, Telegram `cache4.db`, Signal plaintext, Viber, Kik-Android, LINE, WeChat `EnMicroMsg.db`, Instagram `direct.db`, Facebook Messenger, a Twitter `<uid>-search.db`. A decision on a Core Data version signal for iOS stores, among them `CallHistory.storedata`, Photos, Notes and knowledgeC | Each declares itself unranged with the reason on the record, and the column map still catches a renamed field. The iOS Signal store is held with its key. It decrypts and reaches the parser through the credential route, and its schema is read. It holds no messages, so message rows are graded only on a store this project built | 0.25 d per app |
| **An NTFS volume on which Windows itself marked a bad cluster** | One | The reader is graded on a real volume whose `$Bad` runs were rewritten by hand the way chkdsk marks them. The corpus VM can mark a cluster | 0.5 d |
| **User data on any Apple silicon or T2 Mac image** | Live or logical collection from the running machine with admin credentials. An acquisition and not a decryption | The Data volume is hardware-encrypted and the key is in the Secure Enclave. Scheduling APFS decryption work buys nothing on current hardware | 0 d, an acquisition and not a build |
| **Windows clipboard history** (`seance_plugin_clipboard`) | One Windows 11 image with clipboard history enabled and one pinned item | Written to the published layout and unit-tested on synthesised input. No real store has been parsed and the `metadata.json` field names are unverified. **Obtainable in-house:** the Windows 11 QEMU VM the BitLocker corpus was built from, half a day | 0.5 d |
| **Windows Timeline on a real `ActivitiesCache.db`** (`seance_plugin_win_timeline`) | One real store, from kacos2000's published samples or made in the win11 lab VM, which also supplies the clipboard store | The parser has only run on synthesised input. Compare with WxTCmd's two CSVs and Plaso `windows_timeline` on Id, Executable, ActivityType, DisplayText, times and Duration, and record counts by ActivityType in `VALIDATION.md`. This also settles the unverified Payload and ClipboardPayload key names. 0.5 d once a sample is held | 0.5 d |
| **Custom shim database and its install key** (`seance_plugin_sdb`) | One `C:\Windows\AppPatch\Custom\{guid}.sdb` made with Compatibility Administrator and installed with `sdbinst -q`, plus the same machine's `SOFTWARE` hive | The parser reads seven stock databases exactly and the `installed_sdb` ASEP category is unit-tested on built values. Neither has met an attacker-style shim. Capture from the win11-lab VM, about 5 minutes. Also unseen: SDB major version 2 from XP, and any `TAG_PATCH` 0x7005 blob. Patch opcodes are counted and named and deliberately not interpreted. Records from a major version other than 3 are stamped `Unvalidated`. All seven held databases are Windows 11 ARM64 build 28000.1 and the golden counts are keyed to each file's SHA-256, so an x64 `sysmain.sdb` is a second witness and never a substitute. It is obtainable in the lab VM | 0.5 d, and 0.25 d for the x64 witness |
| **Outgoing RDP `CertHash` and `MRU1+` ordering** | A hive that holds them | The three real NTUSER.DAT held have neither | 0.25 d |
| **BitLocker AES-CBC without diffuser, and non-512-byte XTS** | A volume encrypted that way | Windows 8 and later does not produce one. Both refuse and do not mis-decrypt | ≈ 0.5 d |
| **macOS memory tier against a real capture** | A real Mac memory capture | Passes against Apple's 10.12.3 KDK. Registered, and every record is stamped `validated_against_real_capture: false`. The same Apple silicon wall applies to anything modern | ≈ 3 d |
| **Linux `dmesg` structured and ringbuffer paths** | A 3.5 to 5.10 capture and a 5.10 or later capture | The pre-3.5 flat ring is corpus-validated. The structured path is synthetic-only. The 5.10 or later ring is refused by name | ≈ 1 d |
| **LINE, Telegram TL, Facebook `msys`** | A real device sample of each | Handled honestly today: parsed when already decrypted, flagged when encrypted, reduced to a timeline when only the text is serialised | ≈ 1 d each |
| **Signal for Android** | A full-file-system extraction with its keystore exported | `signal.db` is SQLCipher under a keystore key. It is reported as not read and not as absent | ≈ 2 d |
| **Android 14 `installInitiator` and `updateOwner`** (§1.4) | A second Android 14 or later image whose device writes them | Implemented and ungraded. The 2022 image held writes neither | 0.25 d |
| **DFTT #10 overlapping filesystems** | The public image, not in this tree | The overlap is pinned on a synthetic overlay. Re-confirm against #10 when acquired. A download and not a build | 0.25 d |
| **APFS file content on the golden image** | A real Mac, `hdiutil` or `diskutil apfs` | Writing files into APFS is not possible rootless on Linux. The golden image covers APFS structurally | ≈ 1 d |
| **A Monterey or later `System.keychain`** (`HUNT-111`) | A macOS 12 to 14 volume with its `System.keychain` and `/var/db/SystemKey` | One macOS 11.2.1 pair is held and graded. Running macOS under KVM stays out, because Apple's licence restricts it to Apple hardware | 0.5 d, the `HUNT-111` figure |
| **A `.tracev3` inside a real macOS image** (§1.6) | An APFS or HFS+ image, or a full-disk acquisition, whose `/private/var/db/diagnostics`, `uuidtext` and `dsc` survive | Reach is verified on listings only. Graded by the message count the same tree gives when read loose, with Mandiant's pinned totals as oracle. The Magnet 2021 image has none and the Ventura VM disk has an encrypted Data volume. ≈ 0.5 d once an image is held | ≈ 0.5 d |
| **Spotlight `Store-V2`** (§1.6) | Another macOS image | Four things are read and not interpreted: the `0x41` block, the other bits of `value_type` and the record flag byte, and the widest number form. Each needs a store the two held are not. 0 d of unblocked work | ≈ 1 d |
| **Apple Mail row-level known answers, and deleted rows carved from the `Envelope Index` freelist or WAL** (§3.10) | A populated macOS or iOS Mail store with deletions, such as a macOS VM with an IMAP account | Both held indexes have 0 rows. `.emlx` samples exist. Index rows are graded only against schema-built fixtures, `basis: schema_verified_rows_unverified`. Carved rows would be 2 to 3 d | 0.5 d, and 2 to 3 d for carved rows |
| **A second Outlook 2013 or later producer with ground truth** (§3.10) | A licensed Outlook and an account | Three version 36 stores are held, none from a second independent install with known answers. Do not fabricate one with a writer of our own | 0.5 d |
| **`DFR-RO-*` and the DFR specification text** (§5.2) | The specification text | The `RO` cases are ungraded and the assertions are paraphrased from the layout document. Obtain the text, then grade | ≈ 1 d |
| **A dirty registry hive with both transaction logs** (§5.15) | A running Windows guest, and its `SYSTEM` or `NTUSER.DAT` with `.LOG1` and `.LOG2` copied through a VSS snapshot | **Obtainable in-house:** the win11 lab VM, ingested as a disk image so that the sibling-bundle path runs. The real-hive test asserts only `hive_dirty` and `recovered: false`, and the one dirty hive held, the Case 001 `NTUSER.DAT`, had no logs taken | included in §5.15 |

---

# Part IV. Engineering debt

Blocks no feature and produces no wrong answer today, but compounds if left. The
sized items are in P5. This part holds what is not a backlog item.

## Built but unwired, the rule

Complete, tested and reachable by nobody is a recurring shape here. The rule is
cheaper than the tickets: **nothing lands without a caller, and a crate-level
`dead_code` allow is a refactor that was not finished.**

## Standing

- **The registers.** `BUGS.md` holds open defects. This file holds what is next.
  A second file that can disagree with either is the failure the documentation
  map exists to prevent.

## Engineering rules not yet enforced

No test, `scripts/forensic-lint.sh` step or CI job enforces these. Review holds
them.

1. A sweep is `grep -rn <the thing>` over the crate with every hit read, and adding a safe helper is not a sweep.
2. A new check or comparison is run against a clean, stock capture and its false-positive count is recorded before it ships, because fixtures written by the same author agree with the reader by construction.
3. A module that subscribes to a type and reads a field is pinned by a test that runs the producer and finds the field where the consumer looks.
4. Every completeness or truncation flag reaches a person in the report and in the frontend, and a completeness section renders always and not only on bad news.
5. A negative result is a statement about the search, so record the offsets and places examined, and high entropy means not plaintext and never not readable.
6. Evidence is marked not held only after every corpus root on disk is listed, with `fls` inside images, and the check is quoted.
7. A known-answer key is checked by its primary claim, the offset, with an independent tool, and the run's outputs are kept.
8. Frontend state or a query keyed on a case, source or artifact uses `useEntityScopedState` or `useEntityScopedQuery`, so that it cannot outlive the entity.
9. A cross-view or correlation test asserts the correlation itself and never a bound that holds when nothing correlates, such as `rows.len() >= list.len()`.
10. An enumeration's `complete` means the walk ended and not that the list is every object, so state the method and whether a second method corroborated it.
11. A view whose purpose is to show everything wraps and does not truncate, any unavoidable cut is marked, and widths are measured in terminal cells.
12. An environmental failure is never reported as a statement about the evidence, and a test that mutates process-wide state such as `TMPDIR` lives in its own integration-test binary.

Smaller rules, held the same way:

- A corroborating sweep counts what it cannot place and never reports it as an
  accusation, and a scan-only candidate carries every innocent reading beside the
  alarming one.
- A comparison on a fixed-width field is measured against a real, boring
  population before it is trusted. Where two member names share an offset, the
  discriminator is part of what must be bound.
- A bit position or magic is meaningful only with the structure it sits in.
  Carvers read the field that distinguishes formats sharing a container header,
  such as `ftyp` or `RSTR`, and validate with a type list and not a character
  class.
- A file path named in a note is a claim about an OS version. `BrowserState.db`
  and `RecentSearches.plist` belong to iOS releases before 15 and not to 15.
- A `.lock().unwrap()` on a derived-data cache is
  `unwrap_or_else(|e| e.into_inner())`. An intermittent test goes in the defect
  register.
- Do not call a file stale without opening it. Write the cannot and refuses
  paragraph of a method statement first.

---

# Part V. Decisions on record

Investigated and declined, or settled. A negative result is the cheapest thing to
lose and the most tedious to rediscover. A row marked **owner to confirm** is the
recommended position and is not yet taken.

## Ruled out, code reuse

The reuse audit found no single 1000-plus line duplicate. Kept so it is not
re-searched:

| Candidate | Evidence | Why not |
|---|---|---|
| memory `modules.rs` vs `services.rs` | Same ~5,099 LOC, different MD5 | LDR and VAD vs SCM heap, different algorithms |
| memory `dump.rs`, ~7.3k | No large intra-file clones | Five extract paths plus tests. Shared style only |
| Disk Amcache vs memory `amcache_hive.rs` | Sequence ratio ~0.007 | File hive vs VA cell reader |
| Disk registry vs memory registry | Structural review | Contiguous hive vs cell-index map |
| FAT vs exFAT parsers | Overall ratio ~0.20 | Residual walk and emit ~150 to 250 lines. Run helpers already shared |
| BitLocker vs LUKS `xts` and `source` | Diff review | ~100 to 150 shared AES-XTS at most |
| `seance_api` / `seance_db` | N-grams and structure | Thin handlers. Export pairs ~150 each |
| Frontend HelpPage, MediaGallery, MessagingViewer | Structure | Unique content or already factories |
| Comms, Execution and aggregate viewers | Line counts | ~400 to 500 combined |
| A single filesystem-plugin merge | Domain | Format-specific. Emission helpers only |

## Ruled out, performance

From a sweep against a real ingest of 830k artifacts and a 1.6 GB database. Three
of the four are posture decisions dressed as performance, because each changes
what the tool can attest:

| Not done | Why not |
|---|---|
| Bound the orchestrator task queue | Unbounded by design. A bounded `send().await` blocks a worker that is both producer and consumer, ext4 emitting 80k or more `FileEntry`s, and the deadlock is silent |
| Sample or drop `processing_log` rows | The log is the audit trail. Dropping successful per-module-run records changes what the tool can attest about how each artifact was processed |
| Regex search: pre-narrow by a required literal | A slightly wrong literal extraction silently excludes documents. A search that can miss is worse than a slow one |
| Audit writes behind a background flusher | A crash or a full queue loses hash-chained provenance entries never persisted |
| Profile and fix `.clone()` hotspots in `seance_db` and the parsers | No measurable endpoint. The orchestrator hotspot is covered by the `receiver_count()>0` gate. Profile first with `cargo flamegraph` and act on a number |
| An LRU cache for file-type detection | No measurement says it matters |
| A shared FileClassifier module or per-parser header cache. **Owner to confirm** | Classification once saves at most 10 to 15 percent of runtime, because I/O is not the bottleneck. It adds module-ordering and database-update semantics, and a classification error could skip a file silently, which is a forensic false negative. Re-open only if a profile on network or encrypted storage shows header reads above 50 percent |
| Allocation, string-building and capacity-hint passes, and a magic-number sweep | No measured endpoint names an allocation cost, the same ground as the `.clone()` row. Re-open with a flamegraph that does. Review requires a named constant for any new bound or size that is reachable from evidence |

Deferred for ordinary engineering reasons: keyset pagination, which conflicts with
jump-to-page; `Arc<Artifact>` through the broadcast path, because the
`receiver_count()>0` gate already removes the clone for headless ingest; a shared
whole-file content buffer, because the 64 KiB LRU already achieves read-once; ext4
inode buffer reuse, retained so in-inode xattrs parse without a re-read; and
`page_size=8192`, which needs `VACUUM` on existing databases.

## Architecture decisions to revisit, each with its growth condition

- **SQLite as the primary store.** A multi-examiner lab wants Postgres. The
  `DatabaseConnection` trait was shaped to allow it.
- **`ForensicsModule::process` is synchronous.** I/O-bound plugins, cloud and
  network, would want async. It is a refactor across every plugin.
- **Tantivy is single-node.** Horizontal scale means OpenSearch or similar.
- **Plugins are in-process Rust.** A WASM runtime would open a third-party
  ecosystem at the cost of a sandbox boundary to design.
- **Single-process orchestrator.**
- **Evidence is never memory-mapped, and no crate uses unsafe code.** Evidence is
  read with buffered reads. Every crate forbids `unsafe_code` except
  `seance_container_e01`, which keeps libewf out of process. A derived cache may
  reconsider mapping only with a measured load time and a documented exemption.
- **Aggregates are computed on the client, with the truncation stated.** Summary
  tiles and top-N lists for a single record type are computed over the loaded
  pages with `truncated` shown, because `getAllRecords` stops at 8 pages of 100. A
  server-side summary endpoint is added only after a measured case where the
  client path is wrong or slow. §5.69 is that case.

Settled and not to be reopened: Rust for the whole stack; the `ForensicsModule`
boundary; the artifact graph plus orchestrator; content-based detection with a
filename fallback; separate API, REPL, CLI and SPA surfaces; the React SPA.

## Clean-room, and which licences permit what

Volatility's VSL forbids even result-parsing wrappers. Rekall's core and
MemProcFS and LeechCore are GPL or AGPL and are ideas-only. Only Rekall's EFilter,
EVTXtract and bulk_extractor's PD and MIT core are safe to adapt as code. What is
answered against upstream is in `documentation/COMPARISON.md` with the parity
evidence. What is not is §5.3 and §5.18, and each moves to `COMPARISON.md` as it
lands.

| Decision | State |
|---|---|
| Console and win32k layouts are derived in-house one build at a time, and upstream's per-build packs are not transcribed. Whether bare offsets may be taken from them has not been ruled, and the working assumption is that they may not | decided |
| `windows` (`tagWND`) is not walked, and whether to build it is for the owner to confirm. `DesktopSurvey::Unsupported` and `windows_enumerated: false` are the answer today. No source of win32k type information exists here or from Microsoft: `tagWND` is absent from the public kernel ISF, win32k ships as a public PDB with names and no layouts, and upstream's GUI packs are VSL-licensed. Delivering it needs one of two routes: a win32k ISF for the exact build by means the licence permits, or an in-house derivation for one build, as the console layout is. Either route plus the chain itself costs 8 to 15 d. It never moves to answered in `COMPARISON.md` without one of the two | owner to confirm |
| `skeleton_key_check` runs on its export-prologue route only. The `CSystems` descriptor route is declined, because Microsoft publishes `cryptdll.pdb` as a public PDB with names and no layouts | decided |
| No parity harness is shipped. Volatility is read by hand as a behavioural oracle. No wrapper that runs it or parses its output is built, distributed or kept in the tree. `scripts/oracle/*.py` are independent decoders | owner to confirm |
| No interactive object browser over an arbitrary type and address, volshell, is built. The examiner's route to an uncovered structure is the hex viewer and the stage records' provenance. Build is about 3 d if the owner reverses it | owner to confirm |
| The 28 Volatility deprecation rename classes are not ported. The product has no plugin-name compatibility surface | decided |

## Memory evidence

| Decision | State |
|---|---|
| Memory evidence is read-only and unmapped is not zero. No layer is written to. A read of an unmapped range is an error naming the hole and never a run of zeros. A dump keeps its holes with a hole manifest, and a hit inside a padded range is discarded | decided |
| Fail closed on an unrecognised layout. An unknown crash-dump type, an ARM64 image whose tables prove under no offered regime, a 32-bit kernel and a `printk_ringbuffer` kernel are refused by name and not parsed best-effort | decided |
| No live acquisition and no remote URL evidence. `leechcore://`, `s3://` and `gs://` memory sources are declined. The evidence path is an acquired image with acquisition-time hashing. Live RAM capture is the P6 §4.1 owner decision | decided |
| Memory hits are located by physical address and never by device offset. A sweep that read less than it names must say so. Selector sweeps run automatically, and key and packet sweeps are opt-in | decided |
| Module-to-disk comparison is by path, name, size of image and version resource only. A mapped image legitimately differs from its file. `not_checked` is shown when no disk evidence is held | decided |
| No kernel driver is synthesised to make a tamper signal fire. Real malware captures taken in a network-less guest are graded, and four are. A positive that no held capture supplies is stated as ungraded | decided |
| Recovered credentials render masked. A reveal is a server round trip that writes an audit event, and if the audit write fails the value stays masked. Reports exclude credentials by default | decided |
| Whether an export that carries a recovered credential should demand a second authentication | not decided |
| There is no run-a-plugin button. The battery runs at ingest. Upstream plugin options such as `--threads`, `--include-corrupt`, `--show-all-dirty-pages`, `--no_registry`, the kallsyms families and `--dump` resolve to always-on behaviour recorded on the row, or to an explicit opt-in per artifact for dumps. A request for a per-plugin switch is a request to change this | decided |
| A zero or unset FILETIME, boot time or Unix time produces an absent key, never 1601 or 1970 and never the boot instant. A record with `incomplete` set never renders as fully confident. A hole in a re-served dump reads as an error and never as zeros. These are invariant tests that gate independently of parity | decided |
| The Microsoft symbol server is contacted only when the examiner asks for that run. Every fetch is audit-logged with URL, bytes and SHA-256 and never overwrites a file already in the symbol directory. Fetched PDBs are converted locally and are not redistributed, and no per-build ISF is bundled. A symbol table is matched on PDB GUID and age, or on banner plus BTF corroboration, and never on a near name | decided |
| A row that Volatility drops because a field would not read is emitted with `incomplete[]` and `unread_fields[]` naming the field and the reason. A row it drops for a plausibility filter, `plausible_name` or `plausible_endpoint`, is kept and the predicate is a facet on the row. Smear is never presented as absence | decided |

## Windows, Linux and registry

| Decision | State |
|---|---|
| Replay parses only the recovered hive. A second on-disk `RegistryHive` for a before and after diff was rejected, because it doubles records and clutters the UI. The replay stamp records the on-disk sequence numbers and last written time instead | decided |
| A case-level banner that the evidence may be stale waits for the findings layer. The per-record badge and the hive finding ship | owner to confirm |
| One Timeline event per Windows activity, at `StartTime`. No second `EndTime` event, because it doubles rows. End and duration live in `full_details` | decided |
| No first-class Activity navigation item. The `ActivityType` label table is community-derived, advisory, and the raw code is always kept | decided |
| A failed login is reported only from a file detected as `btmp`. A structurally valid `utmp` that is not detected as `btmp` is read with `wtmp` semantics. A failed login is never fabricated | decided |
| No raw per-record `UtmpEntry` type. Interpreted records and timeline events only | decided |
| No `$SII` or `$SDH` index parsing. A linear `$SDS` scan suffices | decided |
| Integrity level is not a file-grid badge. It stays in the Security section until an examiner asks | decided |
| Local wall-clock times are never coerced to UTC. Scheduled-task `Date` and `StartBoundary` carry `timezone: local`, UTC-native sources never set it, and setupapi times are published exactly as written with no offset claimed and no timeline event raised | decided |
| Never claim signed without an Authenticode record. Never claim a persistence target is absent from a partial index. Say not observed | decided |
| Autoruns' 200 or more locations are not matched. Sidebar gadgets, codecs and the full Winsock binary decode are declined, and the coverage record names what is not read | decided |
| New top-level navigation is for cross-type investigator workflows only. A single record type gets an Analysis viewer | decided |
| Registry key security is reported and never judged. No effective-access computation and no finding is raised from an ACL. A descriptor carried by exactly one key is a lead with an innocent explanation. No ACL shown never reads as anyone may write | decided |
| MUICache and MRU entries are never execution evidence. An MRU entry has no time of its own, so there is one timeline event per key and never per entry. Outgoing RDP records a destination entered and not a connection made | decided |
| An interface configuration found only in a non-current control set is reported, labelled with its control set, and never suppressed. A DHCP lease field is shown as a time only when obtained plus lease equals terminates | decided |
| Multi-megabyte real hives stay uncommitted. Known-answer tests are corpus-gated | owner to confirm |
| The OST reader is in-house, `seance_plugin_email::ost4k`, and not a vendored copy of Microsoft's `outlook-pst`. `vendor/` stays for fail-closed patches only | decided |
| A deleted-mail claim is made only for items recovered from unallocated space and marked `recovered`. Messages still in Deleted Items are live items | decided |
| Decrypting a Windows Wi-Fi `keyMaterial` from on-disk hives is declined. The record names the master-key GUID and what decryption would need. No image pairs those hives with a known passphrase to grade a decryption against. If wanted it is 3 to 5 d | decided |
| `ut_tv.tv_sec` and `ll_time` are read as unsigned 32-bit, so the ceiling is 2106-02-07 and a system running past 2038 reads as a date between 2038 and 2106. Recognised layouts are glibc `utmp` at 384 bytes, musl `utmpx` at 400, Darwin `utmpx` at 628 and glibc `lastlog` at 292. Any other layout is refused and never guessed. The role, wtmp, btmp or utmp, comes from the file name only, because it cannot be read from content, and a nameless valid file is treated as wtmp | decided |
| A CSV export for a record type that has a reference-tool oracle follows that tool's column order as a named profile, so that an examiner can diff the two. The persistence view's known-good rule is conservative and states itself: an image under `System32` or `SysWOW64` with a default value | decided |
| A format identifiable from its first 512 bytes gets a `DetectedFileType` variant, for example `ScheduledTaskXml`. A format that needs more, or a record-size and field-sanity test, is detected inside its plugin by a cheap name pre-filter and then an authoritative structural verify. A file with the right name and the wrong structure is rejected, and a renamed file with the right structure is read | decided |

## Mobile, macOS and schema drift

| Decision | State |
|---|---|
| Statedump protocol-buffer data stays as bytes. A schema-less decode would print field numbers whose meaning the tool would be inventing. The record keeps `data_hex`. A schema for a named statedump type is the only thing that would change this | decided |
| `<private>` in the unified log is unrecoverable. Apple substitutes the literal at write time and the argument bytes are not in the `.tracev3`. De-obfuscation is ruled out, and a private argument is reported as the writer's redaction | decided |
| Hardware-bound keychain classes on a full-file-system extraction stay closed. A decoder is not written for an artifact no held image contains an instance of. The table is counted and reported unread, with the zero stated | decided |
| The iOS known answers, Safari 6, 4, 3 and 3, notes 4 items, HealthKit 688, live as fixture tests in `seance_plugin_ios_artifacts/tests/magnet2022_ios15_test.rs` and are not duplicated as `seance_validate` cases, because the 8.7 GB archive is not provisioned on CI. Revisit if a runner holds `ios2022ffs/` | owner to confirm |
| A vendor-exported keychain plist or password list, GrayKey `_keychain.plist` and `_passwords.txt`, is out of scope until §4.6 is taken. A tool's output is not device data and is ingested only as a file. If the owner reverses it, it is about 1.5 d, gradeable against the Magnet 2022 pair of 353 genp, 130 inet, 6 cert and 30 keys | owner to confirm |
| A schema version beyond a parser's validated range is a disclosure and never a `content_incomplete` claim. Only an unresolved required column or an absent table claims incompleteness. The one exception is Chromium `last_compatible_version`. Reversing it is a one-function change in `seance_sqlite_util::adopt`, and it would flood the case census | decided |
| A validated range is never widened to a version not read out of a store this project opened | decided |
| The app-version tracking cadence row stays unticked. The product declares being behind and does not chase schemas | decided |
| `packages.xml` `sdkVersion` is the release that last wrote the package database and not the running build, so a mismatch is a reflash signal and is never smoothed. An EXE's `<version>` is accepted only at depth 1 | decided |
| A missing installer in `packages.xml` is never classified as a sideload by the parser. The record carries `no_installer_recorded`, which is a signal and not a proof, and a sideload lead belongs in `seance_plugin_findings` with a grade. `isOrphaned` is reported and not interpreted | decided |
| An audit trail's silence is bounded by `audit_control`, which is `flags:lo,aa` on the reference image. A Spotlight item is an index entry and is not evidence that a file exists now. An unresolved unified-log message is not an empty one. The report wording for all three is owed in §5.33 | decided |

## Network

| Decision | State |
|---|---|
| A flow is never labelled TLS, HTTP or DNS by its port. A protocol is named only when its own bytes prove it, and an unread flow says contents not identified | decided |
| Names and locations come from the capture only. No address is resolved with the examination host's resolver and none is geolocated. A name beside an address is one the capture's own DNS response proved | decided |
| Flows are the unit and not packets. There is no packet list as the primary view. Packets are counted and reachable through their flow | decided |
| Header values, including `Cookie` and `Authorization`, are copied onto `HttpTransaction` records | decided |

## Validation and testing

| Decision | State |
|---|---|
| Running a published CFTT methodology is not third-party validation. The comparison row for NIST CFTT validation stays unticked and no document may claim otherwise. A separately named run in-house row is the most the runs support | decided |
| The mobile core grades only `MDT-CA-02`, `MDT-CA-11`, `MDT-CA-12` and `MDT-CA-13`. NIST's key is a population template with placeholders, so every other case is `NotAssessed` with that reason | decided |
| `MDT-AO-*` and the five acquisition families, disk imaging, media preparation, hardware and software write block, and cloud extraction, are not applicable. Séance performs no acquisition | decided |
| Automated benchmark regression gating is declined. CI timing variance makes it noisy. Benchmarks are run by hand | decided |
| An 80 percent coverage gate is declined. The tarpaulin link crashes the runner, so coverage stays informational | decided |
| README and documentation prose examples are not tested. CI runs doc tests and the README holds only run commands | decided |
| No SLA exists for performance, so no benchmark is held to one | decided |
| Third-party reference data from plaso, Mandiant or NIST is read as documentation. Its values are a known answer only after the owner accepts them and the source is credited by name in `VALIDATION.md`. No plaso code or `.yaml` is copied into the tree, formats are derived from the libyal dtformats specifications that the yaml cites, and extracted trees live outside the repository | decided |
| A run over the DFR set takes one image at a time: fetch, decompress, ingest, grade, delete. The disk figures are 184 GB free and 96 GB if the images are held together | decided |
| A coverage upload to Codecov or Coveralls is not wired. The tarpaulin job is `continue-on-error` and coverage stays informational | owner to confirm |
| String search takes the Latin-1 letters and one single-block alphabet per run in its UTF-16 passes, and CJK ideographs and Hangul stay out. The index matches exact form, so an NFC query does not find NFD text. Both are recorded in `VALIDATION.md` | decided |

## The comparison matrix, rows without a full tick

`documentation/COMPARISON.md` is the matrix. No count of its partial and
not-supported rows is typed here, because nothing gates such a number against the
document. The rows that are **decisions and not backlog**:

- **Vendor support, training, certification.** There is no vendor. `COMPARISON.md` says a
  supplier is needed for support and not for permission to run the software.
- **Established court precedent, vendor testimony support.** These accrue when an
  examiner takes a finding into a proceeding and it survives. What can be built
  for them is §5.2.
- **Disk imaging, mobile extraction, locked-device access, cloud acquisition.**
  Hardware, write-blocker and exploit territory. These are in the Deliberately out
  of scope list below and are not P6. This product ingests what those tools produce. Live
  RAM capture is the one row worth re-opening, and it is an owner's decision.
- **Breadth of app coverage, app-version tracking cadence.** A headcount question
  and not an engineering one. The cadence is what §1.4a buys the infrastructure
  for, and the breadth behind it is a staffing decision nobody has taken.
- **Project VIC and CAID interoperability, PhotoDNA near-duplicate matching.**
  Both need a licence or a membership before a line is worth writing. Parked in P6.

**The macOS group's seven competitor columns are `?`, and that is research and not
engineering.** The Séance column is verified the way every other row is. The other
seven have never been read against those products' documentation. A `?` is not a
`·`, and several of those cells will be ticks, AXIOM's in particular. The page says
so. Filling them in is half a day of reading datasheets and belongs with §5.2.

**The rule:** the matrix is a public claim. A row that changes here changes there
in the same piece of work.

## Deliberately out of scope

Multi-pass brute-force carving of fragmented files, which is research-level;
write-blocker integration, which is driver work; hardware imaging dongles, which
are a partnership and not a product; 3D and VR timeline visualisation; checkm8,
on-device and cloud-pull mobile acquisition, which is exploit territory. Ingest
what other tools produce.

---

# Part VI. Strategic position

## Which product this is

**Tested against real evidence:** the memory tier, with Volatility parity on
Windows XP, 10 and 11 and Debian, and a Linux capture that profiles itself; NTFS
and the Windows artifact set; the CFReDS Hacking Case and Data Leakage cases; the
Magnet 2019 to 2022 CTF images across Windows, Android, iOS, macOS, Linux and
Chromebook; DFIR Madness Case 001; Nitroba. **Synthetic testing only:** most
filesystem parsers, email, most mobile chat plugins. **Absent:** acquisition of any
kind, volume-encryption password recovery beyond the CLI crackers, e-discovery
production, SIEM, SOAR and EDR integration.

Séance is closest to the incumbents on **analysis** and furthest on
**acquisition**, and is ahead of all of them on stating what it did not do.

## Pick a persona rather than chasing the matrix

| Persona | Prioritise | Skip |
|---|---|---|
| Law enforcement | Mobile coverage, CSAM matching, NIST validation, timeline, encryption, court reporting | Cloud forensics, SIEM |
| Corporate IR and SOC | Live collection, cloud, SIEM and SOAR, triage, timeline | NIST, CSAM, vehicle |
| E-discovery and legal | Email breadth, document forensics, production export, legal hold | Live collection, IoT, malware |
| Insider threat | USB history, chat, email, browser depth, OCR, time correlation | Vehicle, IoT, crypto |
| IR consultancies | Live collection, memory forensics, YARA, IOC matching, multi-OS triage | Court reporting, mobile, e-discovery |

Court reporting and the memory tier are built, which weights the first and last
rows. The tiers above are cut for them: P2 serves law enforcement and P3 serves
IR. **The P6 table is what choosing them means.** §3.17, §4.4 and §4.5 stay parked
until the persona changes.

## A condition on inference features

Entity extraction and translation produce derived text a reader can check against
the source. Summarisation, relationship inference, anomaly detection and ranked
findings produce **opinion**: a claim about what the evidence means, reached by a
process that cannot be shown to a court step by step. Anything from the second
group uses the existing machinery. It carries an `Evidence` grade and a
`MethodQualification` that reaches the report's Limitations section. The model and
version are recorded. The output is labelled inference and not observation, and is
never rendered beside a parsed artifact as though the two were established the same
way. `documentation/REPORTING_DESIGN.md` is where the wording lives. The findings
layer is the worked example every later item follows: a grade on every row, and a
generated Limitations entry stating what a rule-produced claim is worth.

## How the memory subsystem was written

The memory subsystem was written from primary specifications: the Intel SDM and
AMD APM for paging, the Arm ARM for AArch64, Microsoft-documented structures and
the PDB and MSF formats, published open formats for ELF, LiME, AVML, Snappy and
ISF, and the analysed operating system's own kernel structure definitions.
Volatility is a behavioural oracle read by hand. It is never copied from, linked,
wrapped or shipped. The method was put to counsel and confirmed acceptable. The
standing obligation is that the built artefact keeps matching it. Review rejects
any change that copies upstream source, constant tables, ISFs or data files. Any
parity run stays in the development test suite and records expected output as
static fixtures, and CI never executes Volatility.

## Positioning

- **Editions map to a build order.** Matching Belkasoft *X Computer* needs only
  local imaging. *X Forensic* and *Corporate* are the big lifts: cloud, IR,
  cross-case.
- **Filter UX is a strength.** Every filtered view states the population it
  searched, which no rival does.
- **Low hardware footprint.** The Rust core runs multithreaded on modest machines
  where rivals want high-end hardware. Sell it beside the triage story.
- **Licence discipline.** MIT throughout. Nothing GPL is linked and nothing VSL is
  wrapped.

---

# Evidence held

Outside the repository, none of it in git. `seance-validate --corpus` and the
`corpus-gates` CI job mean this layout when they say "the corpus".
`test_data/README.md` gives the file layout inside each directory. **The root has
to be set explicitly on a development machine.** `CORPUS_ROOT` defaults to
`/srv/seance-corpora`, which exists on the CI runner and not here, so
`SEANCE_CORPUS_ROOT=~/forensic_corpora` is what a local run needs.

| Set | Directory | What it exercises |
|---|---|---|
| CFReDS Hacking Case | `4Dell_Latitude_CPi.E01` and `.E02` plus `TestAnswers.pdf`, with underscores because the tests open it by that name | E01, NTFS, registry. Ground truth published |
| CFReDS UTF-8 | `Cfreds-utf-8.E01`, `Cfreds001A001.dd` | Non-ASCII filenames. Fast smoke test |
| Ali Hadi NTFS case | `NTFS-HiddenFiles.E01` plus FTK log | E01 decode byte for byte against published MD5 and SHA-1 |
| Lone Wolf 2018 | `LoneWolf.E01` to `E09`, `memdump.mem`, `pagefile.sys` | Win10 disk, memory and pagefile from one machine at one moment |
| Volatility symbol pack | `windows.zip`, 3,014 ISFs | The second prerequisite for Windows memory analysis |
| DFTT test images | `dftt/` with `1-extend-part/`, `5-fat-daylight/`, `9-fat-label/` | `seance_validate` cases `DFTT-1`, `DFTT-5`, `DFTT-9`. The numbers are NIST's, so they are not a range |
| Oberon Linux memory and swap | `oberon_linux_swap/`, kernel `6.8.0-1061-aws`, `PROVENANCE.md` | `MEM-1`. The Linux swap and BTF and kallsyms paths |
| Windows 11 25H2 BitLocker corpus | `win11_bitlocker/`, built under QEMU with an emulated TPM | `BL-1`, `MEM-2`. The XTS-AES-256 unlock, crash-dump and hibernation decode. Also the VM that can supply a clipboard store, a Windows Timeline store and `sysmain.sdb` |
| `dfir_ntfs` fixtures | `reference/dfir_ntfs/test_data/`, gitignored: FAT12, FAT16, FAT32 and five exFAT raw volumes with `fls`-style listings beside them | The FAT-family readers and free-space regions. `exfat_lin_part.raw` puts its volume at 0x100000 inside a partitioned image, which settles volume-relative against image-relative addressing |
| macOS Ventura VM disk | `test_data/mac/macos_ventura_vm.raw`, not held on every machine | The macOS disk tiers only. Its Data volume is hardware-encrypted |
| CTF corpus | Digital Corpora's Magnet mirror, 2018 to 2022, Nitroba, NIST CFReDS, and `cftt_string_search/`, under `~/forensic_corpora/` with a `PROVENANCE.md` each | Every grading run in `documentation/VALIDATION.md`. Includes DFIR Madness Case 001 with DC01 and desktop E01s, memory, pcap and autorunsc output; the NIST DFR set; the Data Leakage case; the Mandiant unified-log set; the Hickman iOS 17, Android 14 and macOS 11.2.1 images; Magnet 2020 Windows, which is Windows 7 SP1 build 7601 although its PROVENANCE says Windows 10, which the SOFTWARE hive contradicts; BelkaCTF 6; and the `.emlx` samples |
