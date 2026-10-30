# BUGS.md - the live defect register

This is the register of what is open in Séance: defects and limitations still to be
decided or closed. A defect that is fixed, or a limitation that is decided and accepted,
is removed from this file. Planned work is in [`ROADMAP.md`](ROADMAP.md).

Séance's screens and exported files are quoted under oath, so a claim made about this code
must stay checkable. Each entry says what is wrong or unknown, what evidence or decision
would close it, and where it stands now.

## Conventions

### Severities

| Level | Meaning |
|-------|---------|
| **HIGH** | Security compromise, admin lockout, or forensically wrong bytes/digests |
| **MEDIUM** | Incorrect or incomplete results on common paths; multi-user custody gaps |
| **LOW** | Edge cases, operator footguns, stale docs |

A false statement or a false absence on a court-facing surface is HIGH whether or not any
byte was wrong.

### IDs

`HUNT-nnn` general; `MEM-nnn` memory. An ID is never reused. Mint the next one from the
highest number ever used.

### Status vocabulary

| Status | Meaning |
|--------|---------|
| **OPEN** | Confirmed and not yet closed. The fix direction is stated. What is missing is the work or the evidence, not a decision. |
| **NEEDS DECISION** | The defect is real, but every way of closing it changes a shipped contract or needs an owner choice. |

An entry states its current status once, at the top.

---

## Open

Twenty entries: `HUNT-195`, `MEM-043`, `MEM-044`, `MEM-020`, `MEM-059`, `HUNT-278`,
`HUNT-280`, `HUNT-111` and `HUNT-283` to `HUNT-294`. `ROADMAP.md` carries the estimate on
each open item that has one.

### HUNT-195 - What the WMI subscription scan does not establish  *(LOW)*

**Status: OPEN.**

The scan decodes `CommandLineEventConsumer` and `ActiveScriptEventConsumer` records from a
real repository, walks the index (a second decoder, python-cim 1.1, lists the same ten
records on the Windows 11 lab repository), and treats a record's header time as the
repository's previous commit, not as a creation time. See `WMI-1` to `WMI-12` in
`documentation/VALIDATION.md`.

What stays open:

- **`listed_not_indexed` / `evidence_state: unlinked` is pinned on a synthetic index only.**
  No real subscription record is listed by a mapped page and named by no index key. The 4
  (Flare) and 23 (Perseverance) unindexed descriptors read as system class definitions
  (`WMI-11`), not instances.
- **Real deletion and power cuts do not produce the state.** A subscription made and deleted
  on Windows Server 2003 R2 leaves no such descriptor: WMI rewrites the page without it and
  the deleted records survive as unreferenced bytes, published as `recovered`
  (`WMI-10`). Twelve hard power cuts, five of them inside a commit, leave either the last
  commit or uncommitted pages, never a descriptor without its key (`WMI-12`). WMI writes a
  batch to new pages and commits once.
- **How the state could arise.** Only from a write that updates `OBJECTS.DATA` and not
  `INDEX.BTR`: a copy of the repository taken between two page writes by a tool that does
  not stop the service, a damaged index, or deliberate editing of the index file.
- **Not decoded or not read:** the dynamic-property instance form, and `MAPPING.VER` (a
  little-endian 1 on the Server 2003 install). The record-time explanation rests on three
  waves on one machine and one build.

**What would close it:** a repository where a descriptor outlives its index key. The
testable route is to copy `FS\*` repeatedly while a loop of `Put_` runs, without stopping
the service, and look for a descriptor with no key. That needs a Server 2003 guest, which
is not held; the malware captures in `forensic_corpora/lab_w2k3x86_malware` remain.

### MEM-043 - What the ARM64 translation core does not do, and that no capture from hardware has exercised it  *(LOW)*

**Status: OPEN.** Listed so that no document claims ARM64 memory analysis beyond this.

Current position. The translation core builds the regime from a raw `TCR_EL1` (`IPS`
enforced, `TBI0`/`TBI1`, `PXNTable`/`UXNTable` folded, `HPDn` aware). Linux discovery offers
seven arm64 kernel regimes in `PAGING_MODES` beside the two Intel depths
(`seance_plugin_memory_linux/src/discovery.rs`). 4, 16 and 64 KiB kernels have been walked
leaf by leaf against independent oracles (`MEM-ARM-1` to `MEM-ARM-11` in
`documentation/VALIDATION.md`). `TCR_EL1.DS = 1` under a 16 KiB granule is decoded and
agrees with an independent walker on a real `-cpu max` capture (`MEM-ARM-7`). Two Windows 11
ARM64 builds, 28000 and 26300, are read and graded (`MEM-ARM-8`, `MEM-ARM-11`). Every
capture is QEMU-emulated.

What stays open:

- **No ARM64 hardware capture exists.** Searches of generic sources, Zenodo, Figshare, DFRWS
  and the MMUShell dataset's other archives found no public memory image from real ARM64
  hardware. All of MMUShell's archives are QEMU configurations. Every ARM64 fixture and
  result is synthetic or emulated.
- **No real table has an address bit above 47.** The high-bit decode, a 64 GiB block and
  the `IPS` check against a 52-bit frame are pinned on synthetic tables only. An LPA2
  frame above 2^50 whose bits 49:48 are clear cannot be told from the descriptor alone
  without a recorded `TCR_EL1`; no image records `TCR_EL1.DS` or `ID_AA64MMFR0_EL1.PARange`.
- **LPA2 is refused by name in two layouts:** the 4 KiB LPA2 layout, which needs a level
  above the four this build walks, and `DS = 1` under a 64 KiB granule. Linux discovery
  offers no LPA2 regime, which it would have to prove without registers. An Embox 64 KiB
  `TCR_EL1` with `T0SZ` = 0 is refused by name.
- **TBI** is decoded into the regime and covered by unit tests. No real capture has exercised a tagged pointer, so it is not claimed as verified on evidence.
- **Windows-on-ARM64 coverage is two builds.** Other builds differ: the pagefile index sits
  at bits 17:14 on build 28000 and bits 9:6 on build 26300, so no pagefile index is stated
  on ARM64 and the offset is. `ProtoIndex` is not decoded to an address, so a shared
  Windows ARM64 page stays an unfollowed prototype. No Windows ARM64 discovery exists; the
  Windows plugin refuses an arm64 image.
- **Not set by design:** swap and `PROT_NONE` are not separable under Linux semantics, as
  each marker bit is a swap-offset bit under the other layout. `APTable` is not reported, as
  the crate reports no access permission. Both are decided limits, stated here so they are
  not raised again.

**What would close it:** an ARM64 hardware capture, a real table with an address bit above
47, and further Windows-on-ARM64 builds. See `ROADMAP.md` Part III and P6.

### MEM-044 - The `truecrypt` sweep reads recorded builds only, and a Camellia table by its `ke` subkeys only  *(LOW)*

**Status: OPEN.**

The sweep recognises AES, Serpent, Twofish, Camellia and Kuznyechik and decodes the
containers of every volume and cascade of them. It is graded on real captures of 48
product builds, TrueCrypt 6.0 to 7.2 and VeraCrypt 1.0e to 1.26.30, against headers known
independently (`MEM-VC-2` to `MEM-VC-15` in `documentation/VALIDATION.md`). Four layouts
read: TrueCrypt 6.0 to 7.2 and VeraCrypt 1.0e (`+0x08`, 5,324 bytes), VeraCrypt 1.0f to
1.18 (`+0x0c`, 5,324), VeraCrypt 1.19 to 1.26.24 (`+0x0c`, 5,304) and VeraCrypt 1.26.29
(`+0x10`, 5,304). VeraCrypt 1.26.7 to 1.26.24 are hybrids of the 1.25.9 layout with
1.26.29's cipher ids. Four OS builds are graded: Windows 11 26200, Windows Server 2022
20348, Windows Server 2019 17763 and Windows 10 1607 14393.

What stays open:

- **Builds not captured.** VeraCrypt 1.0a to 1.0d are unsigned downloads with no hash list
  and cannot be verified. VeraCrypt 1.20 and 1.24-Update3 have no Windows installer or
  bundle in their SourceForge folders. 1.26.25 to 1.26.27, 1.26.19 and 1.26.21 have no
  Windows file there. VeraCrypt 1.15 is obtainable (`VeraCrypt_1.15_Bundle.7z`, signed;
  `VeraCrypt Setup 1.15.exe` SHA-256
  `a7640d284a779d84112734e8dd43c51fc9703762f2e498f8b334c15e830a2010`, equal to the
  release's sums list), but its capture run hung before any volume mounted and was stopped.
  It needs a re-run. The geometry change from 1.26.24 to 1.26.29 is bracketed between 1.26.28
  Beta4 and 1.26.29.
- **Camellia and Kuznyechik cascades below 1.22** are not captured.
- **A Camellia table is verified by its three `ke` subkey pairs only.** That is a 128-bit
  check.
- **Other OS builds** than the four above. On Windows Server 2022 the `SystemVaRegions`
  array reads four junk entries, which nothing here depends on. One VeraCrypt version on
  the second build is also open.

**What would clear it:** one capture per missing version, about 0.25 d each, and disk for
the captures at 8 GB each.

### MEM-020 - The kernel-side tamper signals have no true positive from code outside a module  *(MEDIUM)*

**Status: OPEN.**

All seven of `ROADMAP` §5.3's tamper groups are implemented: `unloadedmodules`, `timers`,
`debugregisters`, `suspended_threads`, `orphan_kernel_threads`, `etwpatch` and
`skeleton_key_check`. Each has its clean-capture false-positive count measured: 0 of 209
timer DPC routines outside a loaded module; 9 unloaded drivers, all of which attribute; 0
threads claiming live debug registers; 0 orphan candidates from 1,514 threads; 0 signals
from 491 ETW export prologues over 123 processes; 0 from the one `lsass.exe`
(`seance_memory/tests/KNOWN_ANSWERS.md`). A clean capture cannot show the converse, a check
that is too strict to fire when something is wrong.

What has fired on evidence where the answer is known:

- `orphan_kernel_threads` on the Cookbook's `tigger.vmem` publishes the three threads
  Volatility's `windows.orphan_kernel_threads` prints, one of them Michael Ligh's published
  answer exactly (Tid 1648, Pid 4, `_ETHREAD` 0xff1f92b0, start 0xf2edd150, outside every
  module). It is an observation, not a graded finding, because XP declares no
  `_ETHREAD.StartAddressInvalid`. Unloaded drivers match Volatility on every name, range and
  slot on all four XP images (`MEM-XP-2`).
- On a Windows 11 lab VM tampered from user mode by `test_data/win11_tamper_plant/plant.ps1`,
  `etwpatch` (both patch shapes, and a machine-wide patch across 107 of 130 processes),
  `debugregisters` and `suspended_threads` fire as claimed (`MEM-W11-TAMPER`,
  `MEM-W11-TAMPER-2`; synthetic, stated as such; pinned by `tests/win11_tamper_plant.rs`).
- Four real malware captures on a network-less 32-bit Windows Server 2003 R2 SP2 guest are
  graded against two clean controls in `w2k3x86_malware.rs`: Rustock-23, Rustock.C,
  BlackEnergy 2.1 and ZeroAccess (`MEM-KERN-1`). All seven groups ran on every capture and
  none claims anything. The malware left traces the module tables show: BlackEnergy adds a
  listed module `0000224A`, ZeroAccess leaves `ipnat.sys` in the unloaded-driver table,
  Rustock.C and .NFE load as ordinary modules. No sample put code outside a module. The
  other four captures of the six Rustock variants, BlackEnergy 2.1 and ZeroAccess run were read but are not pinned by a test,
  and Rustock.E crashed the guest. An idle control unloads nothing in 150 s.

What is still open:

- **No true positive for `timers` or `unloadedmodules` as a signal.** What is measured is
  that the groups do not fire over real malware that stays inside its modules, not that
  they would find a hidden driver. Stuxnet and Zeus are also graded for timers, with 0
  routines outside every module on each (`MEM-XP-1`).
- **`skeleton_key_check` has not fired.** It needs an lsass `cryptdll` patch, which is an
  antivirus risk. Its `CSystems` route does not run on any build, because nobody publishes
  that descriptor's layout. That is scope, stated on every record.
- **The ETW check's modal route** is shown working on a minority patch and on the
  machine-wide patch. Its real-world firing rate on a genuine compromise is unmeasured.
- **On XP,** the ETW and Skeleton Key checks cannot assess any process, and orphan threads
  stay an observation.

No row is rendered as a verdict. A routine in no loaded module is a signal only when the
module map is authoritative, and a range hit against an unloaded driver is published with
both sides and an explicit `is_a_verdict: false`, because a freed range may have been reused
by anything. The unvalidated part is the rate at which the signal fires when something is
wrong, not what a record claims.

**What would clear it:** a capture of a sample that runs code from unbacked memory, on a
Windows build the symbols cover. Rustock.B and TDL3 or TDL4 are the classic cases and are
not in the public sets held. The Art of Memory Forensics images carry timer answers and are
available on request only. Synthesizing a kernel driver stays rejected.

### MEM-059 - Windows XP x64 itself has no capture  *(LOW)*

**Status: OPEN.**

Windows XP Professional x64 shares the 3790 kernel with Server 2003 x64. A Windows Server
2003 R2 SP2 x64 capture, made from Microsoft's evaluation media, is graded (`MEM-XP-6`):
the declared 24-byte `_KTIMER_TABLE_ENTRY`, 512 buckets and the encoded DPC fields give the
same 211 timers as an independent Volatility 2 walk, with no code change. Vista SP2 x86
non-PAE is graded against Volatility 2 (`MEM-XP-5`). The table form is therefore graded, but
XP x64 itself is not.

No public XP x64 memory capture exists. Volatility lists 64-bit XP as supported and hosts no
x64 sample but a Windows 7 one. The Art of Memory Forensics images are not hosted. The
Internet Archive holds XP x64 and Server 2003 x64 install media, with volume-licence keys
posted beside the ISOs that are not licensed to this project and are not used. Microsoft's
own XP x64 trial ISO (`ARMPXEVL_EN.iso`, held) asks for a key it does not carry.

**What would clear it:** a licensed XP x64 install or a capture of one, about 0.25 d.

### HUNT-278 - FAT and exFAT directory recovery: what no evidence held here can move  *(LOW)*

**Status: OPEN.**

Deleted-directory recovery is graded on volumes written by Windows 11 (`WIN11-FAT-1`: Windows
zero-fills a deleted directory), Linux `vfat` and `exfat` (`LINUX-FAT-1`: a deleted exFAT
directory is followed through the stale FAT chain, and a FAT long name cut by a cluster
boundary is joined to its head or flagged `long_name_possibly_truncated`), FreeBSD, OpenBSD
and NetBSD (`BSD-FAT-1`, `BSD-FAT-2`), Haiku (`BSD-FAT-3`), ReactOS 0.4.16 (`BSD-FAT-4`),
Android-x86 9.0-r2 (`BSD-FAT-5`) and a Canon PowerShot SD800IS card (`CAMERA-FAT-1`), all in
`documentation/VALIDATION.md`. The drivers differ in what they leave. Some zero-fill, some
free the chain and keep the slots, and some interleave directory and data clusters.

What stays open:

- **Other drivers.** macOS itself, another camera's firmware and a real Android device are
  unverified. No public volume with a deleted multi-cluster directory from any of them is
  held. The NPS Canon cards hold deleted files in a live directory and no deleted
  directory. Camera-card and FAT CTF images found are floppy or disk partitions or written
  by tools, not firmware. macOS cannot be installed under KVM, as Apple's licence restricts
  it to Apple hardware. **What would close it:** a volume from each holding a deleted
  multi-cluster directory and a shrunk one, graded as the others were, about 0.5 d each once
  an image exists.

Decided limits, stated so they are not raised again. In each, the volume no longer holds
the link and every way of closing it would state a membership the evidence does not show.
All remain published, flagged and not placed.

- A FreeBSD deleted directory's later clusters have no FAT chain and no `.` entry. They are
  recovered whole-named as headless clusters, not placed under a parent by adjacency.
- A cluster that begins inside an exFAT entry set, as FUSE exFAT leaves them, is skipped by
  the orphan scan.
- A FAT directory grown against ascending cluster order, or two deleted directories
  interleaved, is joined to a name tail only on the checksum and first-byte agreement,
  which a false match can satisfy once in 256. The join is flagged as inferred. No driver
  tested writes a directory that way.
- A deleted exFAT directory's stale chain whose later cluster was reallocated stops short,
  flagged, at that cluster. The listing is a prefix.

### HUNT-280 - Deleted-mail recovery from older PST/OST stores: what no evidence here can move  *(LOW)*

**Status: OPEN.**

`ROADMAP` §3.10 reads deleted-mail recovery for versions 14, 15 and 23
(`seance_plugin_email::pst512`). The ANSI layout (version 14) is graded on a real Outlook
2000 mailbox against libpff. Version 23 live reading is graded on a real store with 543
items.

What stays open:

- **No deletion in a Unicode store is corroborated by libpff.** The three messages
  recovered from the plaso store sit in Deleted Items with no live node entry. Their
  existence rests on this reader alone. libpff 20260926 `pffexport -m recovered`, built
  from the release tarball (SHA-256
  `81a8cf42e69509938bb75ca74471094d3cbd17506f3d84d0e2c1253035960c23`, detached signature
  not checkable), completes on all eleven Unicode public stores held and recovers nothing
  from any of them, so it neither corroborates nor contradicts those three. An older libpff
  stopped on the plaso store at offset 356864. The invocation was not validated on a store
  where libpff does recover something, so zero is the observed answer, not a proven one.
  A private 16.9 GB Unicode mailbox gave the same answer from both readers: no recovery. It
  corroborates no deletion.
  **What would close it:** a Unicode store libpff can recover from, or an independent walk
  of this file's pages. libpff ships no test data, and no public store held, of 43 (32
  version 23, 3 version 36, 8 version 14), beyond the plaso one holds a deletion.
- **Version 15 has no sample at all.** It shares the ANSI path by the specification.
- **Recipient tables** are read for versions 14, 15, 23 and 36 and graded against libpff on
  public stores (`PST-PUBLIC-2`, and `PST-PUBLIC-4` for subnode row matrices of 82 to 384
  recipients). Attachments are read by property context only. Unmet: a matrix in more than
  three subnode blocks, and a subnode matrix in a version 14 or 36 store.
- **Cyclic ("high") encryption is decoded on synthetic re-encodings only**
  (`PST-CYCLIC-1`). No store written by Outlook with it is held or public. All 171 Enron
  stores checked permute. What is graded is the algorithm of MS-PST 5.2 against libpff on
  re-encoded copies, which cannot show that Outlook-written stores follow the specification.
- **A deletion that left no stale node entry is not found.** The Jean mailbox's 196 other
  messages have none. Cutting one from the live tree recovers nothing, because the live
  block tree still names its block. Pinned by
  `a_deletion_that_left_no_stale_entry_is_not_recovered_and_that_is_the_limit`.
- **A fragment can be an earlier state of a live message.** The one real fragment, an
  unsent draft of Sent Items message `0x2027C4` seven seconds before the sent copy, is
  flagged when it shares its subject and delivery time with a live message. The identity
  rule shared with the version 36 recovery (class, subject, submit and delivery time)
  cannot link it. A message without a subject, or with neither time, has no identity and
  is never merged. The real-corpus counts were not re-run with that rule. The Jean store
  is `SEANCE_PST14_CORPUS` and the Unicode one `SEANCE_PST23_CORPUS`. Neither is in the
  repository.
- **113 slots in the Jean mailbox carry a valid block signature and a failing CRC**
  (damaged or partly overwritten blocks). They are counted and located
  (`unreferenced_blocks_unvalidated`), not listed as messages. Only the 1,550 that validate
  are read.

### HUNT-111 - macOS keychain is graded on few volumes, and Monterey or later is unmet  *(LOW)*

**Status: OPEN.**

The macOS classic keychain (`macos.keychain`) and the data-protection keychain
(`macos.keychain_data_protection`) are read: the `kych` cleartext index, every item's
service, account, label, description, comment and dates, `keychain-2.db` items with access
group, protection class and sync view, and `ckdevicestate`. The master key unwrap works from
a keychain password or from `/var/db/SystemKey`. A password is supplied as the
`macos_keychain_password` credential and a SystemKey as `macos_system_key`. A decrypted
item is marked `secret_state: withheld` and its secret is held nowhere. `POST
/api/v1/cases/{case}/keychain/{item}/reveal` re-derives one item's secret, audited before
release, and the Inspector has a reveal panel with password and SystemKey options.

Evidence: the openwall sample keychains (`KEYCHAIN-1`); `testdata/test.keychain-db` from
moond4rk/keychainbreaker, whose four `ssgp` items decrypt to the published secret
(`KEYCHAIN-2`); Josh Hickman's macOS 11.2.1 `System.keychain` with its 48-byte `SystemKey`,
graded against chainbreaker 3.0.3 and an independent unwrap (`KEYCHAIN-3`); the iOS backup
keychain (`IOS-KEYCHAIN-1`); and the Magnet 2021 Mac image (`MAC-1`, 14 of 14). Secrets in
the data-protection keychain stay unreadable from an image, because the class keys live in
hardware.

What stays open:

- **No Monterey-or-later volume has been graded.** One `System.keychain` and `SystemKey` are
  held, from macOS 11.2.1. No public macOS 12, 13 or 14 disk image with a `System.keychain`
  was found. The Magnet 2021 CTF image predates macOS 12 and is not linked from public
  pages. A TryHackMe room uses macOS 15.1.1 with no download. Running macOS under KVM stays
  out, as Apple's licence restricts it to Apple hardware.

Decided limit: a 28-byte zero-ciphertext `ssgp` payload (`LocalBeaconStoreKey`, label 20
bytes and IV 8 bytes with no ciphertext) is reported undecrypted and claims no secret. A
3DES-CBC encryption with padding is at least one 8-byte block, so that payload is not an
encryption of anything. chainbreaker prints it as empty. Pinned by
`the_items_decrypt_to_what_chainbreaker_lists`.

**What would close it:** a macOS 12 or later keychain volume with its SystemKey or a known
password.

### HUNT-283 - VICS export places a SHA-256 digest in the MD5 field  *(HIGH)*

**Status: OPEN.**

`export_vics_hash_set` in `seance_api/src/lib.rs` rebuilds a minimal media record for a set
that has no preserved attribute bundle. It starts from `VicsMedia::from_md5`, then moves
the digest to `sha1` only when the value is 40 hex characters. A 64-hex SHA-256 digest
falls through and is exported in the `md5` field. A partner tool matches on the wrong key.
VICS has no SHA-256 field.

**What would close it:** a test that builds a SHA-256 hash set with no attribute bundle, exports it, and asserts
the digest is not in `md5` or `sha1`. The export must either omit the entry and count it,
or refuse the set, and say which.

### HUNT-284 - PUT virtual column reports success for an unknown id  *(MEDIUM)*

**Status: OPEN.**

`update_virtual_column` in `seance_api/src/lib.rs` discards the result of
`SqliteConnection::update_virtual_column`, which returns `Ok(false)` when no row matched
the id, the case or the built-in rule. The handler returns 200 with the body and records a
`virtual_column_updated` audit row for a change that was never written.

**What would close it:** an API test that PUTs an unknown id, another case's id and a built-in id. Each must
return 404 and write no audit row.

### HUNT-285 - Timeline activity heatmap drops events at or before the epoch without saying so  *(MEDIUM)*

**Status: OPEN.**

`SqliteConnection::get_timeline_activity` in `seance_db/src/lib.rs` filters on
`timestamp > 0`. `get_timeline_activity` in `seance_api/src/lib.rs` returns `cells`,
`total` and `max` with no count of the events left out. The count exists as
`count_timeline_activity_excluded` and no handler calls it. An examiner reads `total` as
the number of timed events in the case.

**What would close it:** return the excluded count in the response and show it on the heatmap. Test: a case with
events at 0 and below the epoch returns that count and the screen states it.

### HUNT-286 - Editing a timeline tag note writes no audit row  *(MEDIUM)*

**Status: OPEN.**

`update_timeline_tag_note` in `seance_api/src/lib.rs` takes no authenticated user and
records no audit event. `create_timeline_tag` and `delete_timeline_tag` both do. A finding
note can be rewritten with no trace of who did it.

**What would close it:** take the `AuthenticatedUser`, write a `timeline_tag_updated` audit row, and test that a
PUT leaves exactly one such row naming the examiner and the event.

### HUNT-287 - Creating a virtual column with a duplicate id returns 500  *(LOW)*

**Status: OPEN.**

`create_virtual_column` in `seance_api/src/lib.rs` maps every database error to
`InternalServerError`. `virtual_columns.id` is the table's primary key in
`seance_db/migrations/0008_virtual_columns.sql`, so a repeat id fails the insert. The
primary key is not scoped to the case, so an id used in another case fails too. `ApiError`
has no conflict variant.

**What would close it:** check for the id first or classify the constraint error, return 409, and decide whether
ids are per case. Test: two creates with one id return 201 then 409.

### HUNT-288 - run_module_batch counts jobs that never ran in targets  *(LOW)*

**Status: OPEN.**

`run_module_batch` in `seance_api/src/lib.rs` pushes the id of the failed job made by
`record_unresolved_content_job` into `job_ids`, and returns `targets: job_ids.len()`. The
field is documented as the artifacts a job was actually enqueued for. A target whose
content could not be resolved is counted there and not in `skipped`.

**What would close it:** return a separate `failed` count, keep `targets` to queued jobs, and test a batch that
holds one unresolvable artifact.

### HUNT-289 - analyze and run_module_batch write the mandatory audit row after queueing  *(MEDIUM)*

**Status: OPEN.**

`analyze_category` and `run_module_batch` in `seance_api/src/lib.rs` create and queue the
jobs first and call `audit_required` last. If the audit write fails the request returns an
error while the jobs are already running, with no audit row. The rule for a mandatory row
is that the action does not happen without it.

**What would close it:** write the audit row before the first job is queued, and test with an audit write that
fails: no job exists and the request errors.

### HUNT-290 - A failed VICS import can leave an empty hash set  *(LOW)*

**Status: OPEN.**

`import_vics_hash_set` in `seance_api/src/lib.rs` creates the hash set, then stores the
entries. If `import_vics_entries` fails the handler returns 500 and does not remove the
set. The case keeps an empty set that lists as imported from VICS.

**What would close it:** create the set and its entries in one transaction, or delete the set on failure. Test
with an entry store that fails: no set remains.

### HUNT-291 - Re-running memory analysis on a loaded image record reads the compressed file  *(MEDIUM)*

**Status: OPEN.**

`run_module_on_artifact` in `seance_api/src/lib.rs` resolves a `MemoryImage` record through its
parent with `resolve_artifact_content_through_parent`. The source it attaches is the
parent's raw bytes. `physical_layer_for` in `seance_memory/src/analysis.rs` wraps whatever
source it is given, so a hibernation file or other container is analysed undecoded.
`prepare_layer_export` in `seance_api/src/memory.rs` re-opens the format and compares the
span with `addressable_bytes`. The ad-hoc re-run does neither.

**What would close it:** a `layer_for_record` that re-opens the recorded `image_format`, checks the span against
`addressable_bytes` and `file_bytes`, and refuses on a mismatch. Test: a hibernation record
round-tripped through the database and re-run gives the same result as at ingest.

### HUNT-292 - Memory hits are labelled device_offset where the value is a physical address  *(MEDIUM)*

**Status: OPEN.**

`seance_plugin_bulk/src/lib.rs` emits `device_offset` for hits found in a memory image,
and for swap, where the value is an address in the decoded address space or an offset in
a swap area. `device_offset_of` in `seance_plugin_findings/src/lib.rs` reads that key and
attaches it to the finding as a location on the backing device.

**What would close it:** emit `physical_address` and `image_format` for memory and `swap_area_index` and
`swap_offset` for swap, keep `device_offset` for disk, and test through findings that a
memory hit carries no device offset.

### HUNT-293 - Spotlight header names a macOS CoreSpotlight store as iOS  *(HIGH)*

**Status: OPEN.**

`read_header` in `seance_plugin_macos_artifacts/src/spotlight.rs` sets `ios_store` to
true when the first chain head is zero, which is the store with no property block. The
flag is published as `ios_store` in the header record and appends ` (iOS)` to the record
name. A per-user CoreSpotlight or helpd index on macOS has no property block either. The
two such stores in the Magnet 2021 macOS image
(`Users/eliflatt/Library/Metadata/CoreSpotlight/index.spotlightV3/store.db`, flags
`0x10801`, all five block numbers 0) satisfy the test and are named iOS. The test
`a_store_with_no_property_block_is_reported_as_the_ios_shape` pins the inference.

**What would close it:** replace the boolean with a `store_flavour`: `spotlight_volume`
when the property chain is present, and `corespotlight_index` when flags and chains match
the `0x10801` shape, with a statement that the header does not say which operating system
the file came from. Drop the suffix from the name. Test: the two Magnet 2021 CoreSpotlight
stores give `corespotlight_index` and the 1.4 MB Data-volume store gives `spotlight_volume`.

### HUNT-294 - Duplicate packages.xml attributes are not surfaced and resolve inconsistently  *(LOW)*

**Status: OPEN.**

In `seance_plugin_installed_apps/src/lib.rs` a `<package>` element that carries the same
attribute twice is resolved by the order of the match arms. `name`, `codePath`, `version`,
`ft`, `it`, `ut`, `installer`, `installInitiator`, `updateOwner` and `isOrphaned` take the
last value. `userId` and `sharedUserId` share one variable and take the first. The count
of duplicates that the XML guard can report is not read, so nothing tells the examiner a
record had one.

**What would close it:** pick one rule, first wins, and apply it to every attribute.
Publish `duplicate_attributes` on each record and a count on the summary from the guard.
Test: a crafted element with a repeated `installer` gives the first value and a count of one.
