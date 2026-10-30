# Features

What Séance does, by area. The README carries a short summary; this is the full account.

## Architecture
- **Zero-Copy Design**: Efficient memory usage with lazy-loaded data sources
- **Modular Plugin System**: Extensible `ForensicsModule` trait with content-based detection
- **Centralized Orchestrator**: Async task management with work-stealing parallelism
- **Bounded Memory, Spill to Disk**: the task queue holds 10,000 artifacts in
  memory (`DEFAULT_QUEUE_CAPACITY`, overridable per orchestrator) and spills the
  overflow to disk rather than growing without limit, so a producer that outruns
  the per-core worker threads on a large image costs disk rather than RAM
- **Memory governor**: `SEANCE_MEMORY_LIMIT` (default the smaller of the cgroup limit and
  75% of RAM) slows ingest at 85% of the budget and, if 95% does not recover, stops the run
  cleanly with every source marked incomplete and the reason recorded, instead of being
  killed by the kernel (see `documentation/DEPLOYMENT.md`)
- **REST API**: Full-featured HTTP API (Axum) with JWT authentication
- **Web UI**: React + TypeScript single-page app for case management and analysis
  (see `frontend/`). Every data table is one tab stop with roving-tabindex
  arrow-key navigation, so a screen reader announces the row an examiner has
  arrived at rather than a highlight moving under a mouse; the trees follow the
  WAI-ARIA tree pattern through one shared keyboard implementation; long tables
  hold their rows without rendering them all. Colour contrast is enforced by a
  test that derives what it checks from the stylesheets — compositing translucent
  layers onto their inherited grounds and checking hover states, which is where
  the last failures were, rather than checking a hand-maintained list of pairs
- **Themes**: six skins — Opus, Candle, Win11, Nature, Cyber, Relax — each in a light
  and a dark mode, alongside the default — **Opus light**, a neutral daylight
  ground — chosen per examiner and stored against their account so the choice
  follows them to another workstation. Candle is the palette this product
  shipped with before that, kept whole. Every one is held to the same WCAG AA
  contrast floor as the default palette by the same instrument: the palettes are
  data rather than stylesheets precisely so that one contrast guard can measure
  every one of them, and adding a skin whose ink drifts under the floor on one
  surface fails the build
- **REPL Interface**: Interactive command-line interface
- **Full-Text Search**: Tantivy-powered search with regex support, cursor paging
  with no depth ceiling, and exports that walk the whole match set. Every search
  states what the index reaches (`universe`): metadata of the artifacts ingest
  indexes (timeline events only after a backfill), the first 16 MiB of file bytes, and — in UTF-16 — ASCII and Latin-1 letters,
  Greek, Cyrillic, Armenian/Hebrew, Arabic and kana; no other script (Latin
  Extended, Indic, Thai, CJK and Hangul included), which the byte sweep searches
- **Case-wide byte sweep**: the evidence bytes themselves, not the index — live
  files, file slack (where the NTFS, FAT, exFAT, ext4, HFS+ and APFS parsers publish it),
  unallocated space, recovered content and raw images, each hit named by region.
  Text as UTF-8, UTF-16LE/BE and named code pages, hex byte patterns, every
  ceiling a number, a resume cursor, and `complete` only when nothing was cut.
  From the Search screen's *Byte sweep of the evidence bytes* panel, the REPL's
  `/sweep`, or `POST /api/v1/cases/:id/search/sweep`

## Container Formats
- **E01/EWF**: Production-ready EnCase image support with multi-segment handling, automatic decompression, and libewf run in a separate process by default. Ten header values (case number, description, examiner, evidence number, notes, acquisition date, imaging software and operating system, drive serial number and model), the sector geometry and the acquisition MD5/SHA-1 are read. A logical evidence file (`.L01`) is never served as a disk image: its entry tree is walked through libewf and each entry published as a file with its bytes; `.Lx01` is not read
- **AFF4**: Advanced Forensic Format 4 detection with ZIP container and RDF metadata parsing
- **Virtual disks**: VMDK, VHD, VHDX, QCOW2 (`seance_container_vdisk`)
- **Apple `.sparseimage`**: the single-file sparse disk image that FUJI, RECON and ASLA produce when imaging a Mac — band map decoded, unwritten bands read as zeros, truncated bands fail closed (`seance_container_sparseimage`)
- **ZIP**: Archive extraction with recursive processing
- **Optical disc images (ISO 9660 and UDF)**: ISO 9660 with Joliet and Rock Ridge (`seance_plugin_iso9660`), and UDF (`seance_plugin_udf`) on a physical partition, on burned CD-R/DVD-R/BD-R (VAT), on rewritable media (sparable) and at UDF 2.50+ (metadata partition), with 512-, 2,048- and 4 KiB sectors. Graded on a real UDF 1.02 disc; the VAT, sparable, metadata and non-2,048-byte paths (UDF 1.50, 2.01, 2.50) are graded only on self-made volumes, not on a real burned or Blu-ray disc. A UDF-bridge disc — every Windows install ISO — is read through both halves and is not reported as a hidden filesystem. A partition map of another kind is refused by name. On multisession write-once media the newest VAT (the last session) is read and earlier VATs are located, not walked; a multisession disc not joined by a VAT is read only as the session its anchor names

## File Carving
- **Standalone Carving Engine**: PhotoRec-inspired architecture with pluggable signature registry
- **361 File Signatures**: covering every format PhotoRec carves by default (351 of its 352; the one left out, its `dovecot` layout, PhotoRec itself ships disabled) and more, each implemented in Rust from the format's own documentation, spanning images and RAW camera formats, video/audio, archives and compression, Office/design documents, databases, disk/VM images, executables and bytecode, fonts, CAD/3D, and forensic artifacts. Magic byte sequences are facts fixed by the specifications; the validation is this project's own, and every signature has unit tests.
- **Double-Buffered Scanning**: Block-by-block scan with header/data/file check callbacks
- **Free clusters, from the filesystem's own bitmap**: on NTFS, `$Bitmap`'s free
  runs become regions the carver reads automatically — the free space *inside* a
  volume, which is where nearly everything an examiner carves for is, and which
  no region covered before. A cluster the bitmap calls free is not a cluster
  nothing was written to (that is the reason to carve it) and not one nothing
  holds now (a shadow copy may); the tail of a bitmap read short is **not**
  reported as free, because a zero bit means free and carving that tail would
  report unallocated space nobody assessed. Every ceiling reports the bytes of
  free space it declined
- **File slack, as its own region**: on NTFS, FAT, exFAT, ext4, HFS+ and APFS, the unused tail of
  each live file's last cluster — from the file's logical end to the end of that
  cluster — is published as a `SlackSpace` region when it holds any non-zero
  byte, carved automatically (every carve says `carving_source: slack` and names
  the file whose slack held it) and offered to the byte sweep as `slack`. It is
  its own type because slack is allocated, not free space. Graded on DFTT #2 and
  #3 (`documentation/VALIDATION.md`, `SLACK-1`). A carve from slack is shorter
  than one cluster, and no other file system's slack is produced
- **A region that was carved and held nothing says so**, with the bytes it
  scanned, so "examined and empty" is not the same absence as "never examined"
  (except a slack region, which gets no per-region summary; its volume's
  `slack_space_summary` counts the regions)
- **UI Integration**: Carved files toggle in the file system browser

## Feature Extraction (bulk_extractor-style)
Beyond reconstructing whole files, Séance sweeps the raw byte stream —
unallocated space and decoded memory — for what file parsers never reach, each
recorded with its device offset and surfaced as records in the analysis, search
and timeline views (`seance_bulk` + `seance_plugin_bulk`):
- **Feature selectors** over all bytes: email, URL, IPv4, MAC, payment card
  (Luhn + IIN gated), SSN, IBAN (mod-97), VIN, GPS, Bitcoin.
- **AES keys from RAM**: key schedules verified in a memory image (FIPS-197
  checked), emitted as `RecoveredKey` records that can feed the decryptors when
  no password is known.
- **Network packet carving** (opt-in): IP packets recovered from memory or
  evidence and reassembled into a `.pcap` in the file browser.
- **Decode-and-rescan** (opt-in): base64/gzip/XOR spans lifted into child
  buffers the whole pipeline re-examines.

## RAID / LVM reconstruction
`seance assemble-raid` rebuilds RAID 0/1/5/6 or JBOD from member images into one
logical image the normal `scan` path examines. RAID 5 reconstructs one dead
member from parity; **RAID 6 reconstructs any two lost members** using the Q
syndrome (Reed-Solomon over GF(2⁸)). Linux `md` superblocks and LVM2 metadata are
parsed for auto-detection, and a volume group spanning **multiple physical
volumes** is mapped across all of them (`seance_container_raid`). `seance
scan-raid` goes further: it assembles the array **virtually and scans it
in-ingest**, streaming the reconstructed device straight into the pipeline with
**no second copy written to disk**. A truncated member surfaces as a short read,
never as zero-filled "evidence". A member image scanned on its own is flagged: a
Linux `md` superblock with no partition table emits a **`RaidMember`** record
pointing at the reconstruction commands, so it is never read as a structureless
disk.

## Findings — the fifteen things that look wrong, ranked

The jump from "two million parsed objects" to somewhere to start. **Nine
rule-based checks** over what the parsers already established, each raised as an
**investigative lead** with a byte offset and the values it rests on, ranked by
how much room there is for an innocent explanation:

- NTFS `$STANDARD_INFORMATION` timestamps inconsistent with `$FILE_NAME` in a
  way no copy, move or rename produces
- an Authenticode signature whose digest is not the digest of the file's bytes
- a Windows executable held in an alternate data stream, or carved out of
  another file's slack (NTFS, FAT, exFAT, ext4, HFS+ and APFS slack)
- a section whose entropy is indistinguishable from compressed or encrypted data
- an autostart entry whose image sits in a directory software is not installed
  into, or whose image was not recovered at all
- a program a **prefetch** file records as having been run with **no file entry
  anywhere** in the case, or with only deleted ones
- a file **Amcache** records Windows as having catalogued with no file entry
  anywhere, or with only deleted ones — reported separately from the two above,
  because Amcache records that Windows *saw* the file and not that it ran
- a USN journal delete for a file reference the MFT still describes as in use at
  the same sequence number

Every lead is set out in three parts that are never merged: the
**observation** — the invariant that broke, stated as a fact you can check
against the artifact it names; **what it may indicate**, labelled as Séance's
reading and not a fact; and **what it does not establish**, with the ordinary
causes that produce the same pattern. A finding with nothing to qualify has not
been thought about, so the qualification is not optional and is never hidden
behind a control.

Reachable at `GET /api/v1/cases/{id}/findings`, on the **Findings** screen, and
in the report's own **Investigative Leads** section — separate from
`Findings / Bookmarks`, which is what the examiner marked — with a Limitations
entry stating what a rule-generated claim is worth.

The list is short on purpose. The naive timestomp rule measured
**4,054 of 25,018 files on a stock Windows XP install**, and a triage list that
fires on a sixth of a clean disk buries the one file that matters, so only an
indicator no ordinary operation produces raises anything. Every response also
names **what this build can look for at all**: "no findings" and "nothing here
looks for that" are different answers, and only one of them is about the
evidence.

## Filtering, and narrowing the case to a period

Every grid carries a **filter box** that narrows the rows as you type — plain
case-insensitive substring over the columns the grid shows, and deliberately
not fuzzy: a filter whose rule you cannot state is one whose result you cannot
defend. The count beside it always says **what it searched**, because most
grids here are paged or capped and the box narrows what is *loaded* rather than
the case. Where that is so it says the filter did not search the rest, and that
a row missing from the list is not a row the case does not hold. For a
case-wide search there is `Search`.

The activity chart at the top of every case page is a **control**. Click a bar
and the case narrows to that period; the window follows you from screen to
screen, which is why it states three things in full rather than leaving them to
be inferred: what the window is (UTC), which screens it is in force on — so a
screen outside that list is visibly outside it — and that those screens are
showing a *subset* while it is in force. A window you set on a screen itself,
by brushing the timeline's own chart, wins over it, and the timeline says which
of the two narrowed it. It is remembered per case and never follows you into
another one.

## Needs attention — the problems you can still act on

A case can hold an honest statement with no visible next step: *"this iOS
backup is encrypted and no password was provided: no files from it are in this
case."* `GET /api/v1/cases/{id}/attention` and the dashboard's **Needs
attention** panel are that next step — the problems someone can still do
something about, each carrying what to do.

What the queue *refuses* to offer is the point. A field that cannot reach the
decryptor is worse than no field, because an examiner who types a correct
password into it concludes the password is wrong. So each problem is graded:

- **a field and a button** where the module takes a secret for one artifact:
  the encrypted iOS backup, and a locked BitLocker or LUKS
  volume, a 7z whose header is encrypted and the Signal for iOS store, whose
  secret goes to `POST /api/v1/cases/{id}/artifacts/{id}/credential` (or the
  REPL's `/unlock`). The module runs again on that artifact alone: if the secret
  opens it, what it held appears beneath it and the "locked" record is
  superseded; if not, the job says so and nothing in the case changes. The
  secret is held in memory for that one job, zeroed after the credential route's
  run, and never reaches the case database, an export or the audit log — which
  records who supplied which *kind* of secret, and what happened. An encrypted
  iOS backup's files can also be **read again after ingest**: the password is
  not kept, so their content is refused until an examiner unlocks the backup
  for reading (`POST /api/v1/cases/{id}/artifacts/{id}/unlock`, the Inspector's
  *Unlock to read*), which holds its class keys in server memory for that case
  only, until locked again, the case is deleted or the server restarts, or it
  expires (8 hours by default, `SEANCE_UNLOCK_TTL_SECS`; dropped from memory
  within a minute of expiry, and each forget but a restart audited). The same
  password opens the phone's **keychain** the backup carries
  (`keychain-backup.plist`): each item's access group, account, service,
  server, label and dates reach the case, the items locked to the phone's
  hardware (the `ThisDeviceOnly` classes) are listed as such, and **every
  secret is withheld** — no saved password, token or key is stored, shown,
  exported or searchable. One item's secret can be revealed while the backup
  is unlocked for reading (`POST /api/v1/cases/{id}/keychain/{record}/reveal`):
  it is re-derived from the backup, and the audit row naming who revealed which
  item is written before the value is returned;
- **the environment variable to set, and no field**, where a credential can
  only be read once when the process starts (no remedy in this build is of that
  kind any more; the startup flags remain for a whole run);
- **nothing, said plainly**, where this build cannot read the content at all
  (an encrypted `adb backup`, or the entries of a content-encrypted 7z, whose
  content no password brings into the case), so nobody hunts for a field that
  was never there.

A blockage the build has no instruction for is still listed, with no invented
action. And an empty queue means *nothing recoverable is outstanding*, never
that the examination was complete: what could not be read is counted in the
completeness census and in the report, and every response says so.

## Pivot, and pinning what it found

The pivot — "show me everything that touches this IP / hash / account" — groups
every artifact in the case that references a value by the kind of record each
is: *6 network flows, 2 DNS resolutions, 1 registry hive*. It is reachable from
every identifier the UI shows and from `GET /api/v1/cases/{id}/pivot?value=`.

An answer can be **pinned to the case**, which puts it in the report under
**Values Traced Across the Evidence** — in HTML, in the PDF, and as a `Traced
Values` sheet in the XLSX. Pinning records the answer *as it stands*, with the
examiner and the moment; both the pin and its removal are mandatory audit
events.

The report then carries **two** answers for every pinned value: what the pivot
said when it was pinned, and what the same value says at the time the report is
produced. A report showing only the first would describe a case that has since
grown; one showing only the second would quietly say something different from
what the examiner saw. Where they differ, the report says so. A value that
could not be re-checked is reported as *not re-checked* and never as a zero,
and a capped answer says its per-kind counts are a sample rather than a total.

## Email read as an exchange

Email has no conversation field the way a chat does. It has a chain: each
message names its parent in `In-Reply-To` and, by RFC 5322 convention, carries
its whole ancestry in `References`. Séance walks that chain when it parses the
message and publishes the root as the thread key, so a mailbox is read as
exchanges rather than one record at a time — for `.eml`, Apple Mail `.emlx` and `mbox`, and for
`.msg` and `PST`/`OST`, whose stores keep the same three headers. Outlook 2013
and later write their offline stores as format version 36 (4 KiB pages,
zlib-compressed blocks), which the linked PST library refuses; Séance reads
those with its own reader, validated on the NIST Data Leakage suspect's
mailbox, and its summary says how many pages and blocks it walked and names
any it could not — including a file whose tail was never initialised on disk.
The space neither B-tree references is then walked again with the allocation
map ignored, and deleted messages found there are published marked
`recovered` from `unallocated` space, with their page and block offsets and
how complete each is (`complete`, `partial`, or a node entry whose data is
gone) — on the Data Leakage mailbox that recovers the message NIST's key marks
"Recovered Item from unused area of OST file". Versions 14, 15 and 23 are walked the same way by a reader of their own
512-byte-page layout (`seance_plugin_email::pst512`): the ANSI layout is graded on a real Outlook 2000
mailbox against what libpff reads from it; the Unicode layout is pinned on a real, empty store only, and no
Unicode message has yet been recovered from real evidence.

Each message says **how** it was placed in the exchange, because a grouping
whose basis is not visible is one an examiner cannot test:

- **`references_root`** — the message names its own thread root. The strong case.
- **`in_reply_to`** — no `References`, so it is grouped by the parent it names.
  A reply to a reply then keys on *its* parent, so a longer exchange can appear
  as more than one thread; the pane says so above the messages rather than
  letting a fragment read as the whole.
- **`own_message_id`** — no parent, so as far as the evidence shows it begins a
  thread. A thread of one means no reply was recovered, not that none was sent.
- **no key at all** — none of the three headers. The message belongs to no
  exchange the evidence can address. It is collected under "Not in any
  exchange", the pane states that being collected together is not a claim about
  belonging together, and `GET /cases/{id}/conversations` counts it in
  `unthreadable` so the thread list cannot read as the whole of the mailbox.

**Subject lines are not used.** "Re: invoice" is not evidence that two messages
are the same exchange, and a rule that treated it as evidence would put two
unrelated people's mail into one conversation and present it as a recovered
thread.

## CSAM triage — Project VIC / CAID (VICS)
Import a VIC/CAID hash set in VICS 2.0 JSON (REST or the hash-sets page); each
media hash keeps its category and attributes, a pertinent set is flagged
notable, and the set exports back to VICS-compatible JSON for a lossless round
trip (`seance_vics`). Every decodable image is given an open **PDQ perceptual
hash** plus **aHash/dHash/pHash** companions (`seance_plugin_perceptual`) for
cross-tool matching, and **near-duplicate images are grouped** by PDQ distance
across the API (`/near_duplicate_images`), the REPL (`/duplicates near`) and the
GUI Duplicates page — a run of re-encodes collapses into one group to review. The
gallery has a **Safe view** (blur/greyscale, revealed on hover or focus) to
protect examiners from unbidden exposure. It is **off by default and remembered
per browser**: most cases are ordinary disk images where blurring every
thumbnail is friction, and an examiner who wants the protection is the one who
knows they want it. Because it defaults off, the choice persisting is the
safeguard — turn it on once and it stays on, across cases and reloads. Pluggable PhotoDNA/ONNX back-ends are in the crate; real
VIC/CAID data and CSAM-trained models are never shipped.

## Password recovery
`seance crack-luks`, `seance crack-bitlocker` and `seance crack-zip` recover a
passphrase by dictionary and/or mask — off by default, and proven by the real
unlock rather than guessed (`seance_crack`). `crack-zip` covers both ZIP schemes,
traditional ZipCrypto and WinZip AES-128/256, verifying a candidate by a full
decrypt with the CRC/HMAC intact. The crackers are CLI-only (a passphrase stays
in process memory, never over HTTP or on disk), but an encrypted ZIP is flagged
during a scan with an **`EncryptedArchive`** record — so the API, TUI and GUI show
that an archive is protected and how to recover it.

## A volume nobody can unlock is a finding, not a silence
The common case in casework is an encrypted volume nobody has the key to, and
that used to produce nothing at all: the BitLocker module returned early on the
missing credential *before* it asked whether the volume was BitLocker, so a
locked volume was byte-for-byte indistinguishable from an unencrypted one — the
examiner was told there was nothing there. Nothing else in the tree covers this
for BitLocker To Go, whose boot sector is a genuine FAT32 BPB reading `MSWIN4.1`
precisely so that legacy Windows sees a FAT32 disk.

BitLocker leaves its three FVE metadata blocks **unencrypted**, so a locked
volume can be made to describe itself with no credential at all. Séance now
records the cipher, the volume identifier — rendered in the mixed-endian GUID
form `manage-bde` output and recovery-key escrow records use, so it can actually
be searched for — and the list of key protectors, which is what an examiner would
have to obtain to open it. With them goes the sentence that matters: *the
absence of files under this volume is a missing key, not evidence that the volume
was empty or unencrypted.* A volume declaring a sector size this build does not
decrypt at is reported as detected and left undecrypted rather than decrypted
wrongly, because a 4Kn volume decrypted as if it were 512n produces bytes for
every sector and correct bytes for none — and a carver will happily produce
"recovered files" from the result.

## NTFS Forensics
- **MFT Parser**: Master File Table analysis with attribute parsing and data run extraction
- **$LogFile Parser**: Transaction log parsing for NTFS journaling
- **$I30 Parser**: Directory index analysis (active + slack space)
- **$UsnJrnl Parser**: USN Change Journal with timeline integration
- **$BadClus Parser**: Bad cluster analysis
- **VSS Enumerator**: Volume Shadow Copy snapshot analysis with block-level redirection

## Windows Artifact Parsers
- **Registry Parser**: Windows Registry hive parsing (SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT), including `.LOG1`/`.LOG2` transaction-log replay and unflushed hives lifted from a running machine
- **Prefetch Parser**: Application execution artifacts with timeline events
- **EVTX Parser**: Windows Event Log analysis
- **LNK Parser**: Windows shortcut file analysis with timeline events
- **Jump Lists Parser**: `automaticDestinations-ms` read through the OLE directory, each
  shortcut stream decoded with its `DestList` entry beside it — MRU position (stream order,
  basis stated), last recorded time, pin state, DROIDs and host — and the application named
  for the 41 AppIDs the build can compute (19 cross-checked against a published ID). The
  Windows 10 field other tools call an access count is published as the unknown field it is
  (`offset_116_unknown_possibly_access_count`), never as a count. The signature carve is the
  fallback for an unreadable directory and the only path for `customDestinations-ms`;
  in a readable file the free sectors and mini-sectors are scanned too, and a shortcut
  the directory no longer references is carved and labelled `unreferenced_sector_carve`
- **ShellBags Parser**: folder browsing history from `BagMRU`. No existence check, so nothing
  in the output says whether a folder still exists
- **Amcache Parser**: file **presence** from Amcache.hve — what Windows catalogued, with its
  SHA-1 — plus the Windows 7 `RecentFileCache.bcf` format. Not execution: the keys read carry
  no run count and no last-run time
- **Shimcache Parser**: AppCompatCache extraction from the SYSTEM hive (Vista/2008, Win7,
  Win8.0, Win8.1 and Win10/11 layouts). An entry means Windows looked at the file; the
  execution flag is read only on the Win7 and Vista layouts and is `null` elsewhere
- **Recycle Bin Parser**: Deleted file metadata from $I files (v1/v2) and legacy INFO2
- **SRUM Parser**: Full record extraction from all 5 SRUM table types with ID resolution
- **SUM / User Access Logs Parser**: `System32\LogFiles\SUM\*.mdb` — per-client
  account, IP address, access counts and active days per server role, plus system
  identity, DNS and virtual-machine records. Windows Server retains this for up to
  three years, long after the Security event log has rolled, which makes it the
  surviving record of authentication in most server intrusion cases. Tables are
  identified by schema rather than name. On the one real file checked (DFIR Madness
  Case 001's domain controller) the client table is `CLIENTS` with the role in a
  `RoleGuid` column, not one table per role GUID as this line once said. A `Current.mdb`
  shut down dirty can read 0 rows while its `Svc.log` transaction log, which is not
  replayed, holds the clients; the record says so (`VALIDATION.md` `UAL-1`).

- **BITS job queues** (`seance_plugin_bits`): `qmgr0.dat` / `qmgr1.dat`
  (Windows XP to 8.1, Server 2003 to 2012 R2) — each job's name, owner SID,
  state, source URL, local and temporary paths, byte counts and times.
  Credentials and custom headers are DPAPI blobs, reported present and never
  decrypted. File records left past the live queue by earlier states of the
  file are carved and labelled stale, never reported as jobs. The Windows 10+
  ESE queue (`qmgr.db`) is read table by table, but its transaction logs are
  not replayed: a database imaged from a running machine is reported dirty and
  incomplete, not as an empty queue, and file records in pages no row holds
  are carved and labelled.

- **RDP bitmap cache** (`seance_plugin_rdp_cache`): `Terminal Server
  Client\Cache\Cache####.bin` — every tile the Remote Desktop client kept
  becomes a PNG in the gallery, with one cache-order collage per file that
  says it is not a reconstruction. Legacy `bcache*.bmc` files are recognised, not
  decoded.

- **Windows Search index** (`seance_plugin_winsearch_edb`): `Windows.edb` in
  its Windows 7 (`SystemIndex_0A`) and Windows 10 (`SystemIndex_PropertyStore`)
  layouts — per item the path, size, times, owner and, for Outlook items, sender,
  recipients, subject and dates, with the auto-summary decoded where its encoding
  is one this build reads and named where it is not. Transaction logs are not
  replayed; Windows 11's SQLite `Windows.db` is refused by name.

- **Clipboard history** (`seance_plugin_clipboard`): the pinned items Windows
  writes under `%LOCALAPPDATA%\Microsoft\Windows\Clipboard`. Reports the
  inventory, when each item was pinned, which clipboard format it held (the
  payload filenames are the format name in base64 — `VGV4dA==` is `Text`,
  `Qml0bWFw` is `Bitmap`), and which account it was protected to, read from the
  encrypted blob's own unencrypted header. **It does not decrypt the payloads**:
  Windows protects them with CNG DPAPI, and recovering the text needs key
  material the artifact does not contain. Every record says so, and says that
  most clipboard history never reaches disk at all — it lives in the `cbdhsvc`
  service's memory and is cleared on sign-out, so absence here is not evidence
  that nothing was copied

- **Wireless profiles** (`seance_plugin_wlan`): the XML the WLAN service writes
  under `%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\{interface}\` — one
  file per configured network, recognised by its root element and namespace
  rather than by its path, so an exported copy or one carved out of unallocated
  space reads the same. Each gives the SSID, whether the network was hidden
  (`nonBroadcast`), the authentication and encryption configured, whether the
  machine joined it automatically (`connectionMode`), and the interface GUID the
  profile sat under, which is how two adapters' profiles are told apart. A
  profile list is a list of the places a machine has been — an SSID is
  geolocatable through the public wardriving databases — and it is the strongest
  available statement of *intent*: `auto` means the machine would join whenever
  it was in range, and somebody put it there. The pre-shared key is reported as
  what it is: **in the clear** where the file holds it that way (what `netsh wlan
  export profile key=clear` and some deployment tooling write), and where it is
  DPAPI-protected the record **names the master key GUID it was encrypted under
  and does not decrypt it** — a record that simply omitted the key would read as
  a profile that had none. **The XML carries no timestamps at all**, so nothing
  in a profile places a join on the timeline, and every record says so. *When*
  comes from two other readers, both of which ship: the `NetworkList` registry
  keys (`seance_plugin_registry::networklist`) give the first and last time the
  machine was on each network — as local times with the zone offset **measured**
  against each profile key's own last-written timestamp rather than assumed, and
  with no instant claimed at all where that measurement fails — and the
  `Microsoft-Windows-WLAN-AutoConfig/Operational` channel gives every
  connection, attempt and failure as its own event

## Linux Forensics
- **Ext4 Parser**: Full Ext4 filesystem parsing (inode table, directory entries, extent trees, journal)
- **SquashFS Reader**: read-only compressed filesystem (Android system partitions, live-CD/appliance/firmware images) — superblock, metadata blocks, inode/directory tree and regular-file extraction
- **Process capabilities**: the Linux memory tier decodes each process's `cred.cap_*` sets to named capabilities (e.g. `CAP_SYS_ADMIN`), validated against a real capture

## macOS Forensics
- **Filesystems & images**: APFS (container and volume, with cloned blocks) and HFS+; FSEvents, `.DS_Store`; Apple `.sparseimage` disk images. **APFS snapshots are counted, not walked** — a file that exists only in a snapshot, including anything deleted since one was taken, is absent from the case, and every volume record stamps `snapshots_enumerated: false` with the reason. HFS+ reads the catalog and each file's first eight extents; the extents-overflow tree is not followed, so a file fragmented past eight is content-incomplete
- **Download provenance**: quarantine (`LSQuarantineEventsV2`) — the app that downloaded a file, its source URL and referring page, timestamped
- **Privacy grants**: TCC (`TCC.db`) — which app was allowed camera/mic/screen/full-disk access and why (`auth_value`/`auth_reason` decoded, legacy `allowed` schema too)
- **Persistence**: launchd `LaunchAgents`/`LaunchDaemons` — what runs at login/boot and its trigger (the macOS counterpart to the Windows ASEP sweep)
- **Activity & history**: knowledgeC app-usage timeline, Wi-Fi joined-network history, software install history, package BOM inventories, and Notification Center message content
- **Keychains, both of them**: `login.keychain-db` and `System.keychain` are an encrypted store with a **cleartext index** — which services and accounts the person held credentials for and since when, read without a password, with certificates carried out whole and every secret reported as locked alongside what a lawful recovery attempt needs; a keychain password supplied for the run decrypts the password items' secrets (graded on one macOS-made keychain, four of four), and each is marked withheld rather than shown; the secret is released one record at a time by an audited API reveal that takes the password again and keeps it nowhere (Inspector, with a password field). `keychain-2.db`, the iOS-style keychain macOS keeps as well, names **no account and no service** (every such attribute is a SHA-1, and the reader says so rather than rendering a hash as a username) but names the application that owns each secret, the protection class, and **every device the Apple ID's keychain circle has held** — including devices the image does not contain. Nothing is decrypted and no password is tried
- **Login history**: `utmpx` for the sessions open when the image was taken; the **Apple System Log** (`/var/log/asl/*.asl`), which is where macOS's `wtmpx` went — every boot, shutdown, console login, logout and SSH session with the address it came from; and the OpenBSM audit trail (`/var/audit/*`) for who was refused and what was administered — logins, logouts, refused passwords and keys, account and group changes, each with the account, the process, the remote address, whether the system said yes or no, and the code-signing identity of the binary that asked. macOS has no `btmp` and, since 10.5, no on-disk `wtmpx`, so the trail is the only place the history is
- **Spotlight index** (`.Spotlight-V100/Store-V2/store.db`): decoded per item — the path, content type, sizes, owner, download source and dates of every file the index saw, **including files since deleted**. 14,934 items off the graded macOS image, with 8,782 of 8,797 decoded sizes matching the actual file on the mounted volume (`MACOS-SPOTLIGHT-1`)
- **Unified log catalogue** (`/var/db/uuidtext`, both the per-image entries and the `dsc` shared caches): the machine's **inventory of code that logs** — 262 binaries with their paths, UUIDs and load addresses, and 848,768 format strings counted, off the graded macOS image (`MACOS-UUIDTEXT-1`). A catalogue is not a log, and every record says so
- **Unified logs** (`.tracev3`): read to their entries and counted — every catalog (processes, subsystems), every chunkset decompressed, every firehose tracepoint parsed and counted by kind, format-string location and the log's own loss records — and, **when the file is read from loose files or a ZIP** (a collected `.logarchive`, or `/var/db/diagnostics` beside `/var/db/uuidtext`), **each message decoded** against the file's own `uuidtext`/`dsc` tree and dated through its `timesync` database, one record per message (at most 150,000 per file; the counts stay whole). An unresolved message says why rather than showing empty text. Oversize arguments are joined back within the file, and statedump and simpledump entries become messages of their own (a statedump's protocol-buffer or custom-object data is kept as bytes and said to be undecoded). A `.tracev3` **inside an APFS or HFS+ disk image** is handed the `uuidtext`, `dsc` and `timesync` files listed from the same volume; that is unit-tested on listings but has not been run on a real image (none held here carries a macOS log tree). A source with no such listing is counted, not decoded, and its record says "tree not reachable, not decoded". The **timesync** database is also read as one record per boot with its clock anchors

## Memory Forensics
- **Windows and Linux address spaces**: page-table translation with build-variant
  member binding, so a structure member that moved between kernel releases is
  resolved from symbols rather than a constant
- **Analysis stages**: process list and cross-view, pool scanning, VADs, modules,
  handles, services, registry hives, credentials, command lines, execution
  history, kernel objects/modules/hooks, syscalls, process tampering, recovered
  files and MFT records
- **Pattern scanning**: your own YARA rules — or one regular expression — over
  each process's address space and the kernel's, matches attributed to the
  allocation that held them: its range, protection, whether it is private and
  the file behind it. Also over an image's own space, which is the only route
  for a reconstructed hibernation file or a swap area. Séance ships no rules,
  and with none named the stage reports that it did not run rather than
  reporting nothing found
- **`strings` over memory**: bring your own `strings -t d` output over the raw
  capture, and each **physical** offset is attributed to every address space
  whose page tables reach that frame, with the virtual address it has in each.
  Two processes mapping one frame name both. It does not call an unowned offset
  *free memory*: where any address space could not be walked whole the row says
  nothing, and on a real Windows capture that is most of them — so the record
  names each space and why rather than rounding to a negative. The radix is
  stated, never guessed, because a hexadecimal file read as decimal parses into
  frames gigabytes from the truth without failing
- **Layer export (`layerwriter`)**: a memory image's decoded physical layer —
  a hibernation file decompressed, a crash dump's runs at their addresses —
  streamed out as an address-aligned raw file, with a hole manifest listing
  every range that is zero fill rather than acquired bytes. The raw response
  names its manifest by SHA-256, and a read failure inside a range the
  manifest calls acquired aborts the transfer rather than filling it
  (`GET …/memory/layer/{image}/manifest` and `…/raw`; `/memory layer` in the
  REPL). Physical layer only
- **Volatility 3 parity tests**: expected values come from running Volatility
  against the same image, never from Séance. Windows XP, 10 and 11, and Debian
- **Compressed captures read correctly through page tables**: a compressed
  acquisition describes each frame as one encoded block, so a run returned for a
  64-byte request covers the whole 64 KiB frame. Coverage is checked across the
  requested interval rather than by summing run lengths, which had refused pages
  the evidence fully contained and made Linux discovery fail on every
  Snappy-compressed AVML capture — the format `avml` writes by default
- **Pagefile support**: attach `pagefile.sys` with `SEANCE_PAGEFILES=0=/path`
  and a page the kernel swapped out resolves to bytes instead of a hole. Never
  discovered automatically — a pagefile is a second evidence item whose contents
  predate the capture, so naming it is the examiner's decision
- **Self-describing Linux captures**: a kernel carries a description of its own
  data structures (BTF, distro default from ~2020) and its own symbol table
  (kallsyms, universal). Séance recovers both from the capture and compiles them
  into a symbol table through the same validation an ISF file gets — so the
  layout comes from the build being analysed and cannot be another's. Verified
  against a host's own `/proc/kallsyms`: 202,525 symbols, every address as the
  kernel printed it. **When no symbol file describes the kernel, this is what
  discovery falls back to**, so a custom build or an appliance nobody publishes
  symbols for is analysable rather than a dead end — and every surface that
  reports the result says the layouts came from the evidence and that nothing
  independent corroborates them. A lab whose procedure requires a validated
  symbol file can refuse image-derived symbols and get the old failure
- **BTF layout corroboration**: an ISF is matched to an image by its kernel
  banner, and a banner is not unique to a build — two kernels from one
  distribution and version can share one and lay their structures out
  differently. Séance cross-checks the matched symbol file against the type
  information the kernel carries about *itself* (BTF, present on distro kernels
  from roughly 2020) and fails the symbols when they disagree. It is the only
  check whose reference came out of the evidence rather than out of another
  file's name. It runs only against a symbol *file*: a table recovered from the
  image's own BTF would be compared against the BTF it was built from, which
  agrees with itself by construction, so the gate is recorded as not applicable
  with the reason rather than allowed to pass and imply a corroboration that
  never happened
- **Linux swap areas**: the swap header is read — version, page size (established
  from where the `SWAPSPACE2` magic sits, not assumed), usable page count, bad
  pages, label, and the UUID that ties a recovered area to `/etc/fstab` or
  `swapon --show`. See the acquisition warning below before copying one
- **Honest absence**: a page that is not in the capture is reported as a typed
  hole naming *why* — unmapped, not present, swapped out, or suppressed by the
  Windows 10 uniform-table heuristic — and never as zeros
- **Obtaining symbols on request**: `seance fetch-symbols` gets the PDB a Windows
  image needs from a symbol server, converts it to ISF, and writes it where
  discovery already looks. Nothing is requested without `--allow-network`;
  without it the command prints what it would fetch and stops. Reaching the
  network during an examination is a decision about the lab, not a convenience —
  some are air-gapped by policy, and elsewhere an outbound request from an
  analysis workstation is itself an event someone has to account for. The URL,
  any redirect, the byte count and the SHA-256 of both the PDB and the ISF are
  printed: a symbol table determines what the analysis says about the image, so
  it is an input to the findings in the same way the image is. The downloaded
  PDB is not kept unless `--keep-pdb` is given. Linux and macOS have no upstream
  symbol server, so `--isf` fetches a prebuilt pack instead, and that weaker
  guarantee says so — with no requested GUID to check against, verification
  establishes only that what arrived is an ISF

```bash
# What it would fetch, and from where. No request is made.
seance fetch-symbols --guid 2203ABCD…416D --age 1

# Fetch, verify, convert, and write into ./symbols
seance fetch-symbols --guid 2203ABCD…416D --age 1 --allow-network

# A lab mirror instead of Microsoft's server
seance fetch-symbols --guid … --age 1 --allow-network --source https://symbols.lab.internal

# Linux/macOS: a prebuilt ISF by its path in the pack
seance fetch-symbols --isf linux/debian-5.10.0-21-amd64.json.xz --allow-network
```

> ### ⚠️ Acquiring a Linux swap *file*: `cp` gives you zeros
>
> A Linux swap **file** is normally created with `fallocate`, which on ext4
> leaves its extents flagged `unwritten`. ext4 short-circuits reads of those
> extents to zeros — while the swap subsystem writes pages through the block
> layer straight to the underlying disk blocks, bypassing that bookkeeping
> entirely and never clearing the flag.
>
> **So `cp /swapfile evidence/` produces a file of zeros, with no error.**
>
> Measured on a live Ubuntu host with 4.5 GiB of swap in use: one extent read
> through the filesystem returned **0** non-zero bytes per mebibyte; the same
> physical blocks read from the block device returned **724,505**.
>
> The trap is worse than it first appears, because the header page *is* readable
> — `mkswap` writes it through the filesystem, so its extent is not `unwritten`.
> The resulting copy therefore **identifies as a valid swap area, passes a header
> check, and contains nothing**. It looks acquired.
>
> **Acquire it correctly** by reading the physical extents from the block device
> and reassembling them at their logical offsets:
>
> ```bash
> filefrag -v /swapfile     # physical_offset and length of each extent
> # then read those block ranges from the backing device (e.g. /dev/nvme0n1p1)
> # and write each at its logical offset in the output
> ```
>
> A swap **partition** is unaffected — it *is* the block device. Séance
> documents this in `seance_memory::formats::linux_swap`, where an implementer
> meets it.

## Network captures — pcap and pcapng

A capture is recognised **by content, not by name** (`seance_plugin_pcap`):
classic pcap and pcapng, Ethernet, `LINKTYPE_RAW` and Linux SLL frames decoded
down to TCP and UDP, with DNS read out of UDP port 53 — questions, answers and
the response code. It reports **flows rather than packets**, because hundreds of
thousands of packets are a list to scroll and the conversations are something to
investigate. A link type this build does not decode is refused **by number**, so
the packets behind it are stated rather than quietly absent, and a capture that
was detected and then could not be read leaves a refusal record rather than
nothing.

Beyond the addresses, what the conversations were **saying**:

- **TCP reassembly that never closes a gap.** A reassembled stream is a list of
  contiguous runs at their true offsets, not one buffer. A hole left by a
  snaplen, a dropped packet or a capture that started mid-connection is named
  and never filled — with zeros or anything else — and never closed by joining
  its two sides, because either would put bytes in a report that were not on the
  wire. A parser is only offered the bytes before the first gap. Two segments
  claiming the same offsets with **different bytes** — the mechanism behind a
  whole family of intrusion-detection evasions — keep the first bytes seen, and
  the conflict and the offset it happened at are recorded rather than silently
  resolved one way.
- **HTTP/1.x, recognised by its own first bytes on any port.** Keying off port
  80 would miss the C2 that talks HTTP on 8443 and would try to parse the binary
  protocol that happens to be on 80. The request line, headers, decoded query
  string and posted form fields, and the status line and headers that answered.
  A response is paired to a request **by order**, which is how HTTP/1.1 answers
  on one connection; every transaction carries the basis it was paired on, and
  one paired over a stream with a hole says the pairing may be wrong.
- **Message bodies handed on as files.** A body becomes a child `FileEntry` of
  its transaction — so the chain of custody reads capture, then the exchange that
  carried the object, then the object, and the modules that examine a file on
  disk examine this one too. It is **inflated** where the wire carried `gzip` or
  `deflate`, with what was on the wire named either way; a coding this build
  does **not** decode — `br` and `zstd`, which most current servers prefer — is
  kept as the wire bytes, stamped `compressed`, and is not the object, so the
  index and the detectors see the compressed stream rather than the page. A body
  that reached a ceiling or whose stream ended inside the capture is marked as
  the prefix it is.
- **TLS, read up to the change of cipher and not one byte past it.** The server
  name the client asked for (SNI) — frequently the only place a domain appears
  when the name was resolved elsewhere or over an encrypted resolver — the JA3
  fingerprint over the exact ciphers, extensions, groups and point formats
  offered, in order, the ALPN offered and selected, the version and cipher
  agreed, and known-weak ciphers counted and flagged. Everything after the
  cipher changes is counted so the reader knows the conversation continued, and
  is never parsed: a handshake message read out of ciphertext is noise presented
  as evidence.
- **The certificate the server presented**, with its subject, issuer, validity
  window, alternative names and SHA-256, and a timeline event at each end of
  that window — read as what a host **claimed** to be. No signature is verified,
  no chain is built, no trust store is consulted and no clock is compared, and
  the record carries `signature_verified: false` as a stated field rather than a
  silence. A certificate that cannot be walked end to end is refused rather than
  half-read. **From TLS 1.3 the certificate is encrypted**, so a session without
  one is reported as *not visible in this version of the protocol* rather than as
  a server that presented none — two different statements, and only one of them
  is about the server.
- **ARP, the only record of which hardware answered for which address** — and
  the only place a host that sent no IP traffic at all appears. Address to
  hardware address with the times each claim was seen, and an address claimed by
  two hardware addresses raised as **contested**: the signature of ARP cache
  poisoning, and equally of a failover pair, a DHCP lease handed on, a replaced
  network card or a host moved between hypervisors. ARP does not authenticate — a
  reply is believed because it arrived — so every row is an announcement, the
  record carries the claims and their times and reaches no verdict, and addresses
  only ever *asked* about are listed apart from those anyone claimed.

Not read, and said so on the record: HTTP/2 and HTTP/3 — whose connection
preface **is** recognised, so a capture of HTTP/2 is counted as traffic that was
not read rather than producing no records and no explanation — anything inside
TLS beyond the handshake, and a `CONNECT` tunnel's payload, which is neither
parsed nor handed on as the body of the response that opened it. Every ceiling
this build applies — the streams it holds, the transactions and sessions it
records, the bytes it will reassemble, hold as bodies or inflate — is named on
the capture record with what it cut, so a capture the parser read only part of
is never presented as the whole of the traffic.

## Cross-Platform Parsers
- **Browser History Parser**: Chrome/Edge, Firefox and Safari history; downloads, bookmarks, cookies, saved-login metadata, typed form values, Firefox session restore and the Chrome extension inventory. Safari is history only — there is no `Downloads.plist` or `Bookmarks.plist` reader
- **SQLite Parser**: Generic SQLite database analysis — schema extraction and a full table walk to a 50,000-record cap per table (not a sample), plus deleted-row, freelist, WAL and rolled-back-journal recovery
- **Plist Parser**: macOS/iOS property list parsing (binary and XML formats)

## Data Management
- **SQLite Database**: Persistent artifact storage with batch inserts and WAL mode
- **Parent-Child Lineage**: Full artifact provenance tracking (chain of custody)
- **Timeline Events**: Normalized temporal analysis across all parsers
- **Full-Text Search**: Tantivy index with regex, file extension filtering, and
  snippet generation. Every match is reachable: a page is addressed by `offset`
  or continued by an opaque `cursor`, and the cursor route has no depth ceiling,
  so match 1,001 — and match 1,000,001 — can be opened rather than merely
  counted. A search's audit record names the slice that was put on screen
  ("matches 1,001–1,100 of at least 34,000") and which route reached it
- **Search exports that state their own population**: the JSON and CSV exports
  walk the entire match set by cursor rather than taking one capped page, holding
  **one pinned index snapshot** open from the first row to the last — so an
  ingest commit or a background index merge cannot splice a second result set
  onto the end of the first. Every export ends with a verdict row saying whether
  the file holds the whole match set, **including** a complete one: a streamed
  download that stops halfway leaves a file byte-for-byte indistinguishable from
  a shorter complete one, so the absence of that final row is what tells a reader
  they are holding a fragment. A purge landing mid-export stops the walk rather
  than reading destroyed evidence out of the held snapshot
- **A review ledger, server-side and per examiner**: what has been opened and
  what has been cleared, kept as two separate assertions and never summed —
  opening a row is not clearing it. It answers for the case rather than for one
  browser, which is what a handover needs: the previous ledger was
  browser-local, so examiner B inheriting examiner A's case was told nothing in
  it had ever been looked at. Withdrawing a review appends to an append-only
  history rather than erasing, because a review made and retracted must not look
  like one never made, and every count is published beside the population it is
  counted against
- **Examiner assignment and personal bookmarks**: a case owner assigns an
  explicit set of artifacts to a named examiner who can record reviews
  (`read_only` examiners are refused); the examiner's "My queue" and its
  progress count only their own reviews. An assignment can carry a due date
  (**overdue** is worked out from the examiner's own reviews each time, never
  stored) and can be reassigned, which withdraws it — kept on the record — and
  gives the same records to another examiner. A personal bookmark is a private
  scratch mark that never reaches a report — the report states how many were
  excluded — and adding one to the shared bookmarks is an audited step
- **Timeline exports**: CSV, JSON, PDF, a SQLite database, and a Sleuth Kit
  `mactime` body file of the timeline's events — memory events included — beside
  the Files page's body file of every file; each streamed export ends with a
  line saying whether it holds everything it claimed to
- **Shadow-copy versions are parsed, not just listed**: SQLite databases,
  registry hives, event logs, shortcuts, prefetch files and jump lists inside a
  Volume Shadow Copy are read, and everything they yield is labelled as a
  shadow-copy version so it cannot be mistaken for the live volume
- **Hash Sets**: MD5/SHA1/SHA256 computation with known-file hash set management
- **Court-Standard Reports**: HTML, PDF (optionally signed), RTF, XML, DOCX,
  XLSX, CSV, KML and GeoJSON. Every report states that its times are UTC, carries a declaration and
  statement of truth, names the examiner and the report reference, and defines the
  terms whose misreading would change a conclusion. Sections that could not be
  read in full say so: a listing marked incomplete is never presented as the whole
  of what the evidence held.
