# Séance vs. the commercial forensic suites

**Séance's rows are verified against the source tree. A capability claimed here is one the code will assert.**

This compares Séance with the six suites it would actually be weighed against in
a lab procurement, plus Autopsy as the open-source incumbent.

## How to read this, and what it is not

**The Séance column is the only one verified by running the software.** It comes
from the source tree, the test suite, and the corpora in `test_data/` — where a
capability is marked present, something exercises it.

**Every other column is compiled from vendor documentation, release notes and
practitioner reports** (sources at the end). Those columns carry the failure mode
of all such comparisons: vendors publish what they do well, rarely what they do
not, and a feature named on a datasheet may be a checkbox or may be
best-in-field. Where a source could not settle a question, the cell says `?`
rather than guessing — an unverified cell is *not* evidence of absence.

**Version drift is the other hazard.** These products ship several times a year.
A cell that is right today may be wrong in a quarter, particularly the mobile
and cloud rows, where the entire competitive game is played.

Nothing here is a benchmark. Two tools that both parse `$UsnJrnl` get the same
tick and may differ wildly in completeness, speed, and how they behave on damaged
input. **Depth is invisible in a matrix**, and depth is usually what decides
which tool an examiner reaches for.

| Symbol | Meaning |
|---|---|
| ✅ | Supported |
| ⚠️ | Partial, conditional, or via a separate product/add-on |
| ❌ | Not supported |
| ? | Could not be established from available sources |

Column keys: **Séa** Séance · **AXM** Magnet AXIOM · **CB** Cellebrite Inseyets
(UFED + Physical Analyzer) · **FTK** Exterro FTK · **EnC** OpenText EnCase
Forensic · **XW** X-Ways Forensics · **BKS** Belkasoft X Forensic ·
**Aut** Autopsy / The Sleuth Kit.

---

## 1. Acquisition — Séance does none of it

This is the single largest gap and it is architectural, not an oversight.
Séance is an *analysis* platform: it examines images that something else
acquired. Every commercial suite here also acquires, and for mobile work the
acquisition capability *is* the product.

| Capability | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Disk imaging / cloning (create E01, dd) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Live RAM capture | ❌ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Remote / enterprise endpoint collection | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ✅ | ❌ |
| Mobile logical / backup extraction | ❌ | ✅ | ✅ | ⚠️ | ⚠️ | ❌ | ✅ | ❌ |
| Mobile full-file-system extraction | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| iOS bootloader exploit (checkm8) | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Locked-device access / passcode bypass | ❌ | ⚠️ | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| Android EDL / MTK / rooted physical | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Cloud account acquisition (tokens, warrants) | ❌ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ❌ |
| Drones, vehicles, GPS, IoT | ❌ | ⚠️ | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ |

⚠️ notes: enterprise collection is a separate SKU for most vendors (AXIOM Cyber,
FTK Enterprise/Central, EnCase Endpoint Investigator, Cellebrite Endpoint
Inspector). FTK and EnCase ingest *others'* mobile extractions rather than
performing their own.

**Practical consequence.** Séance cannot be the only tool in a lab that seizes
devices. It sits downstream of FTK Imager, `dc3dd`, a Tableau bridge, or a
Cellebrite/GrayKey extraction. That is a real limitation, and it is worth being
plain that it is unlikely to change: mobile exploit acquisition is a
continuously-funded arms race against device vendors, not a feature.

---

## 2. Evidence containers accepted

| Format | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Raw / dd / split raw | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| E01 / EWF (incl. multi-segment) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| EnCase logical evidence file (`.L01`) — entries enumerated, bytes served | ✅ | ✅ | ? | ✅ | ✅ | ✅ | ? | ✅ |
| EnCase logical evidence file, EWF2 (`.Lx01`) | ❌ | ? | ? | ? | ✅ | ? | ? | ? |
| AFF4 (Map + ImageStream, chunked) | ✅ | ? | ❌ | ⚠️ | ⚠️ | ❌ | ? | ⚠️ |
| VMDK / VHD / VHDX / QCOW2 | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| VDI (VirtualBox) | ❌ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| ZIP / tar / gzip / bzip2 / xz / archives, recursive | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| 7z — member listing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| 7z — member **content** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Cellebrite UFDR | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ❌ |
| GrayKey extraction | ❌ | ✅ | ⚠️ | ✅ | ❌ | ❌ | ✅ | ❌ |
| Volume Shadow Copies — snapshot store enumerated, each snapshot served as a volume stream | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Volume Shadow Copies — a snapshot's files: its `$MFT` diffed against the live one, each differing record published with its content served from the snapshot (not a full file-system walk) | ⚠️ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| RAID / LVM / dynamic disk reconstruction | ⚠️ | ⚠️ | ❌ | ⚠️ | ✅ | ✅ | ⚠️ | ❌ |

**Archives ⚠️, and 7z content ❌.** What the code asserts: ZIP members are extracted with content; **7z members are listed
metadata-only** — `sevenz.rs` attaches no data to any entry (solid folders have
no per-entry random access) and the content resolver has no
7z arm, so nothing inside a 7z is hashed, typed, scanned or indexed. A concatenated
xz is refused whole and says so. Gzip and bzip2 expand every member of a concatenated stream and
record bytes after the last one, and a tar member's size is taken
from its PAX record. A GNU sparse tar member is served as its
packed bytes, so everything after its first hole is at the wrong offset.
`Container_Formats.md` carries the detail.

**L01 rows.** An `.L01` entry tree is walked through
libewf's `file_entry` API (in the isolated helper by default) and every entry is
published as a file whose bytes are read by libewf, graded in `VALIDATION.md`
§L01-1 on the five EnCase 7.4.1.10 `.L01`s of Digital Corpora's 2012 National
Gallery iPhone: all 59,687 entries `ewfinfo` lists appear at the same path, and all
30 camera-roll JPEGs of an independent zip export of the phone match an entry by
size and MD5. What it does not do: read the data EnCase stores against directory
entries (a property record per photo on that phone), vouch for the bytes of an
entry flagged sparse, or read an `.Lx01` — none is public to test against. The
competitor cells are the vendors' documented support, not tested here, and `?` where
that support was not established.

**VSS is two rows.** The snapshot store is parsed —
catalog, store, block descriptors, each snapshot as a `VssSnapshot` record whose
reconstructed volume is served as a whole-volume stream on request — but **no
module subscribes to that record as a file system**: the NTFS parser takes
`FileSystem` / `FileEntry` / `RawEvidence` / `SystemArtifact` artifacts, and a
`VssSnapshot` is a `ParsedRecord`. So no file inside a shadow copy is listed,
hashed or searched, and "the file as it was before the change" is not a question
this build answers. The first row's claim is
graded block-by-block against `dfir_ntfs`'s published hashes through a source that
answers 4 KiB per call.

**VSS second row ⚠️.** Each rebuilt snapshot's `$MFT` is
parsed with the MFT module's own code and compared with the live volume's; every record
that differs — a reused slot, a file deleted since, a changed size, name, parent or timestamp —
is published as a `VssPriorVersion` record parented to its snapshot, and its content is served
from the rebuilt snapshot, not the live volume (graded in `VALIDATION.md`, VSS-1: a deleted
file's snapshot bytes served while its live clusters hold another file). ⚠️, not ✅, because the
suites in the other columns mount a snapshot and walk it; this does not: nothing is read from a
snapshot's `$I30`, `$UsnJrnl`, `$LogFile` or unallocated space, and a file unchanged since the
snapshot is not listed from it. That walk is not built.

**The `$MFT` row.** The table is read through its own run list and nothing else.
Séance does **not** recover orphaned MFT records from free space or diff areas as a separate
record type; no column in this document credits it with that.

⚠️ Séance/UFDR: a UFDR is a ZIP, and Séance expands it so the mobile parsers
read the device files inside. It does **not** consume Cellebrite's `report.xml`
decode model — so you get Séance's interpretation of the raw files, not
Cellebrite's.

**RAID ⚠️:** `seance assemble-raid` reconstructs RAID
0/1/5/6 and JBOD from member images with `md`-superblock and LVM2
auto-detection, presenting one logical image the normal scan path examines.
**RAID 6 recovers any two lost members** via the Q syndrome (Reed-Solomon
over GF(2⁸)), and **multi-PV LVM** volume groups are mapped across all their
physical volumes. Assembly is also **in-ingest and virtual**:
`seance scan-raid` reconstructs the array in memory and streams it straight into
the pipeline with **no second copy written to disk** (geometry auto-detected from
the `md` superblock, or `--level` for a foreign array) — validated end-to-end by
scanning a FAT filesystem split across two members. Still short of ✅: it does not
do RAID 5EE (a hardware-controller layout `mdadm` cannot even create, so no
ground truth to validate against) or Windows dynamic disks (LDM). The depth gap
to X-Ways/EnCase is those two layouts, not the parity maths or materialisation.

---

## 3. File systems

| File system | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| NTFS | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| FAT12/16/32, exFAT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ext2 / ext3 / ext4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| XFS — live tree | ✅ | ⚠️ | ❌ | ⚠️ | ✅ | ✅ | ⚠️ | ❌ |
| XFS — deleted-entry recovery (names from directory free space, freed inodes from the inode B+tree; no content — the kernel clears a freed inode's extents) | ⚠️ | ⚠️ | ❌ | ⚠️ | ✅ | ✅ | ⚠️ | ❌ |
| Btrfs — live tree (no deleted recovery: no free-space, stale-generation, log-tree or backup-root reading) | ✅ | ⚠️ | ❌ | ? | ⚠️ | ✅ | ? | ❌ |
| F2FS (modern Android) — live tree (only set dentry-bitmap bits are read; no deleted recovery) | ✅ | ✅ | ✅ | ? | ? | ❌ | ✅ | ❌ |
| APFS | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| HFS+ / HFSX | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ISO9660 / Joliet / Rock Ridge (NM, PX, TF, SL, CE and CL/RE read; zisofs `ZF` and sparse `SF` files named, not decoded) | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| UDF — physical, VAT, sparable and metadata partitions, 512/2,048/4,096-byte sectors, incl. both halves of a UDF-bridge disc (real-disc grading on 1.02 only; 1.50/2.01/2.50 graded on self-made volumes; earlier VAT states located, not walked; no deleted-file recovery beyond FIDs marked deleted) | ⚠️ | ⚠️ | ❌ | ✅ | ✅ | ✅ | ? | ❌ |
| SquashFS (Android system / appliance / firmware) — as a file, a raw image, or a partition (found only at offset 0; gzip-compressed blocks only) | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ |
| ReiserFS / Reiser4 / UFS / QNX | ❌ | ❌ | ❌ | ⚠️ | ⚠️ | ✅ | ❌ | ⚠️ |
| YAFFS2 (legacy Android NAND) | ❌ | ⚠️ | ✅ | ❌ | ❌ | ❌ | ⚠️ | ✅ |

**XFS, Btrfs, F2FS, ISO9660 and SquashFS.** XFS recovers names from directory free
space and freed inodes from the inode B+tree, graded on a real Linux 6.8 volume with 13
deletions: 10 names with their inode numbers, 3 nameless freed inodes, nothing live
misreported. Content is not recovered, because that kernel zeroes a freed inode's extent
list, so the deleted row is ⚠️. A failed XFS root inode sets `inventory_incomplete` on the
`FileSystem` record. Btrfs and F2FS make no deleted-recovery claim. ISO9660 reads Rock
Ridge, graded on discs written by `xorriso -as mkisofs -R`, including a deep-relocation
disc and a zisofs disc. A Rock Ridge tree is walked in preference to Joliet, as the Linux
kernel does. A SquashFS in a partition is probed and walked. SquashFS stays ⚠️ because
only gzip-compressed blocks are decoded and a volume is found only at offset 0.

**UDF ⚠️** (`seance_plugin_udf`). The reader handles UDF on a physical (Type 1)
partition, which covers authored DVDs and both halves of a UDF-bridge disc. It is graded
on a real disc, Microsoft's Windows 11 25H2 ISO, where it lists the 976 files and 94
folders 7-Zip lists and serves the 6.2 GB `install.wim` whole (`UDF-BRIDGE-1`). Real-disc
grading is on UDF 1.02 only. The reader also resolves VAT, sparable and metadata partition
maps and reads 512- and 4,096-byte-sector volumes. Those paths are graded byte-exact on
**self-made** UDF 1.50, 2.01 and 2.50 volumes written by NetBSD `makefs` and `mkudffs`
(`UDF-VARIANTS-1`), not on a real burned, rewritable or Blu-ray disc. On multisession
write-once media the newest VAT is read and earlier VATs are only located. A multisession
disc not joined by a VAT is not detected. Nothing deleted is recovered beyond the
directory entries marked deleted.

Séance's set is strong on what is actually deployed today and thin on the long
tail. **X-Ways remains the breadth leader** and is the tool to reach for when a
QNX or Reiser4 volume lands on the bench.

---

## 4. Encryption

| Capability | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| BitLocker — password / recovery key | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ |
| BitLocker — XTS-AES-256 (Win10/11 default) | ✅ | ✅ | ? | ✅ | ✅ | ⚠️ | ✅ | ? |
| BitLocker To Go | ✅ | ✅ | ? | ✅ | ✅ | ⚠️ | ✅ | ? |
| LUKS1 / LUKS2 | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ❌ | ⚠️ | ❌ |
| FileVault / encrypted APFS | ⚠️ | ✅ | ⚠️ | ✅ | ✅ | ❌ | ✅ | ❌ |
| VeraCrypt / TrueCrypt volumes | ⚠️ | ⚠️ | ❌ | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| iOS backup password | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ⚠️ |
| Encrypted app databases (WhatsApp, Signal) | ⚠️ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ⚠️ |
| Password recovery / cracking engine | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| **AES key recovery from a memory image** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ |

Séance's caveats, stated exactly:

- **LUKS ✅ is the unlock.** A LUKS
  volume in a run with no passphrase is reported as a `VolumeDecryption` record
  with the incompleteness pair and reaches the Needs attention queue. That queue row,
  and the equivalent BitLocker row,
  takes the credential for that one volume after ingest (`POST
  /cases/{id}/artifacts/{id}/credential`, or the REPL's `/unlock`) and re-runs
  the decryptor on it. Graded on `bdetogo.raw` (BitLocker password), the Windows 11
  XTS-AES-256 volume (recovery password) and LUKS1/LUKS2 volumes formatted by
  `cryptsetup`, each with a wrong secret rejected and the locked record left
  standing. Files beneath a volume decrypted in memory are refused after the
  run (the key is not retained) rather than served as ciphertext, **until an
  examiner unlocks the volume for reading** (`POST …/unlock`): the
  key is re-derived and held in process memory for that case with a TTL
  (8 h default), audited by kind, never on disk. Graded on `bdetogo.raw`
  through the API; the LUKS path on a `cryptsetup` volume at unit level.
- **FileVault / encrypted APFS ⚠️** — Séance *detects* encrypted APFS extents and
  reports each one as ciphertext with its `crypto_id`. It does **not** decrypt
  them. It never presents ciphertext as though it were file content.
- **VeraCrypt ⚠️, and narrower than "detection".** The
  detector has no VeraCrypt check, so a container surfaces only as the
  generic `Unknown (high entropy)` lead every high-entropy file gets — a lead
  that does not assert `is_encrypted` and is not counted as an encrypted file
  There is no
  VeraCrypt-specific finding, no mounting, no decryption. What *is* specific is
  in the memory tier: the `truecrypt` stage decides whether `truecrypt.sys` /
  `veracrypt.sys` was loaded and, when it was, sweeps non-paged pool for AES key
  schedules (§6) — graded on one capture with one mounted AES volume,
  where both master keys were among the schedules reported; the driver's key
  container is not decoded and VeraCrypt's schedules are not told from others'.
- **Encrypted app databases ⚠️.** Signal Android
  `.backup` files are decrypted (`seance_plugin_signal::decrypt_backup`: the
  250,000-round SHA-512 stretch, HKDF, AES-256-CTR frames, truncated HMAC, SQL
  replay), validated by a round trip against a mirror of Signal's exporter but
  not yet against a real Signal-produced backup. WhatsApp is parsed **only once
  already decrypted** — `msgstore.db` and `ChatStorage.sqlite` — with one exception:
  ingest decrypts a `crypt14` backup when the phone's key file
  (`/data/data/com.whatsapp/files/key`) is in the same case, graded on the real
  Pixel 7a backups (`VALIDATION.md` `WHATSAPP-CRYPT14-1`), and a `crypt14` seized
  without its phone opens with the key supplied as the `whatsapp_key` credential
  (the key file as hex, or the bare key as 64 hex digits; same real backups).
  A `crypt15` (end-to-end encrypted) backup is decrypted the same
  way with its root key (`files/encrypted_backup.key` in the case, or the 64 digits
  supplied as `whatsapp_key`), graded byte for byte on published backups and their
  published plaintexts (`WHATSAPP-CRYPT15-1`), though no crypt15 holding real
  message rows has been graded. `crypt12` is refused by name, a crypt15 root behind
  a backup password cannot be recovered offline, and the parsed store itself is
  unranged, so the row is not ✅. Signal
  iOS (`grdb/signal.sqlite`, SQLCipher 4 with a 32-byte plaintext header) is
  reported `StoreEncrypted`. Its header bytes 60..63 are ciphertext, not a
  schema version. `seance_sqlcipher` decrypts it (SQLCipher 4 raw key, HMAC-SHA512, WAL
  included) under the raw key spec the device's keychain export carries — graded on
  the real store, every page and frame authenticating — and the spec, supplied for that file from the Needs attention queue,
  reaches the Signal parser, which reads Signal for iOS's GRDB schema into
  messages, conversations and contacts. That reader is graded **structurally
  only**: the one real store held has no messages, so no app-written message row
  has been read, and it states no message direction. The key is supplied, not
  found in the case's keychain automatically.
- **Cracking engine ⚠️.** `seance crack-luks`,
  `crack-bitlocker` and `crack-zip` recover a passphrase by dictionary/mask, off
  by default and proven by the real unlock (a decrypt with the CRC/HMAC intact),
  `crack-zip`
  covers both ZIP schemes — traditional ZipCrypto and WinZip AES-128/256. Still
  narrower than FTK's PRTK/DNA or a Passware integration: CLI, CPU (no GPU), and
  no iOS-backup/Office verifiers yet. Kept CLI-only on purpose — a candidate
  passphrase lives only in process memory, never sent over HTTP or persisted.
- **AES key recovery from RAM ✅ — apparently unique here.** Séance verifies AES
  key schedules in a memory image (FIPS-197 checked) and emits them as records
  that can feed the decryptors when no password is known — the bulk_extractor
  `scan_aes` capability, which the disk-forensics suites do not offer. Belkasoft's
  memory tier carves artifacts but is marked ⚠️ as it is not documented to
  recover key schedules.

Séance's BitLocker path is built against a
purpose-built Windows 11 corpus and unlocks the modern default
(XTS-AES-256, Win8+ VBR layout, relocated volume header) end-to-end into a
decrypted NTFS volume. LUKS1/LUKS2 are native, which is unusual — most of this
field treats Linux full-disk encryption as an afterthought.

---

## 5. Windows artifacts

This is the area of closest parity; every suite here covers the core well.

| Artifact | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Registry hives (SAM/SECURITY/SOFTWARE/SYSTEM/NTUSER) | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| $MFT, $UsnJrnl | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ |
| $LogFile — operation codes, LSNs and targets only (no names, timestamps, redo/undo payloads or transaction reassembly) | ⚠️ | ⚠️ | ❌ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ |
| $I30 — live index entries | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ |
| $I30 — deleted names from index **slack** (stale copies of live names are not yet told apart) | ⚠️ | ⚠️ | ❌ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ |
| $BadClus | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ |
| Registry — deleted and moved keys and values recovered from hive **unallocated cells**, typed apart from live | ✅ | ? | ? | ? | ? | ? | ? | ? |
| Prefetch | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| EVTX event logs | ✅ | ✅ | ❌ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ |
| EVTX — **recovered** records: carved chunks, chunk slack, headerless chunks, borrowed templates, partial XML, each typed apart from live | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| LNK shortcuts | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Jump Lists — the embedded shortcuts | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Jump Lists — the `DestList` stream (MRU order, last recorded time, pin state, DROIDs, host; application named for known AppIDs) | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| ShellBags | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Amcache / Shimcache — what Windows catalogued or examined | ✅ | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| SRUM — the ID map and four provider tables opened by name (network data and connectivity, application resource use, energy); other provider tables are not enumerated | ✅ | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ | ✅ | ❌ |
| Recycle Bin ($I/$R, legacy INFO2) | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Windows Timeline / ActivitiesCache | ✅ | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| Thumbcache | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **SUM / User Access Logs** (Server, ~3yr retention) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Clipboard history (pinned items) — inventory and formats; the timestamp is the first of eleven candidate field names that interprets, from no published schema and no held Windows 11 image | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| Persistence — **WMI event subscriptions** (`__EventFilter`, consumers, bindings) read from `OBJECTS.DATA` by record scan | ✅ | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ | ✅ | ❌ |
| Windows Search index (`Windows.edb`) — Windows 7 and 10 layouts, 46 properties per item (not all the indexer stored; a count libesedb cannot fully walk is stated as a floor) incl. Outlook mail and IE entries; encoded summaries decoded where the form is read, named where not; logs not replayed; Windows 11 `Windows.db` refused | ⚠️ | ? | ? | ? | ? | ? | ? | ? |
| RDP bitmap cache — `Cache####.bin` tiles into the gallery, cache-order collages (no screen reconstruction); legacy `.bmc` not decoded | ⚠️ | ? | ? | ? | ? | ? | ? | ? |
| BITS job queue — binary `qmgr0/1.dat` (pre-Windows 10): jobs, URLs, paths, owner, two times; credentials present, never decrypted; stale file records carved and labelled. Windows 10+ `qmgr.db`: tables walked, **job header only — files and times not read**, file rows not linked to jobs, **transaction logs not replayed** (a dirty database is reported incomplete), unreferenced file records carved | ⚠️ | ? | ? | ? | ? | ? | ? | ? |

**SUM/UAL is a genuine and unusual differentiator.** Windows Server retains
per-client account, IP and access counts for up to three years — long after the
Security event log has rolled — which makes it the surviving authentication
record in most server-intrusion cases. Séance identifies the tables by schema
rather than name, because UAL names them after role GUIDs. No other tool
surveyed here parses it natively.

Clipboard ⚠️: Séance reports the inventory, formats and protecting account, and
states plainly that it **cannot** decrypt the payloads (CNG DPAPI) and that most
clipboard history never reaches disk at all. `metadata.rs` records that no source sets out the schema and no
Windows 11 image is held, and the timestamp published is the first of eleven
guessed field names that interprets — a reading, not a decode, and the crate
carries no `unvalidated` marker the way the macOS-memory reader does, and the
`plum.sqlite` sticky-notes reader does for every schema version other than the one
lab-made `user_version` 13 database it has been compared against. `BUGS.md` holds it.

**Windows rows and what they assert.**
`$I30` slack is read from the end of the
used entries to the allocated size, as dfir_ntfs reads it, and graded through the
MFT parser on dfir_ntfs's real `ntfs_index.raw`, where it recovers the deleted
`BBBBBBBBBBBBB-del.txt` from `test_dir`'s slack. It is ⚠️ because
a stale copy of a live entry is published the same as a deleted name.
`$BadClus` reads `$Bad`'s raw runs, published separately from its
logical extent, and was graded on a real volume whose `$Bad` mapping pairs were
rewritten the way chkdsk marks two clusters. No volume Windows itself
marked is held. `$LogFile`: what is published is the operation code and name, LSN, page
number, target attribute / VCN / LCN, transaction id and record type; no file
name, no MFT record number, no timestamp, no redo/undo payload, no timeline
event. SRUM: `SruDbIdMapTable` plus four provider GUIDs are opened by name and
nothing else is enumerated. EVTX recovery (`seance_plugin_evtx::recovery`:
`ElfChnk` chunks carved by signature anywhere in the input with
header and data CRC32 verified separately, a relaxed walker that trusts neither
`free_space_offset` nor the header tables, chunk slack decoded against a poisoned
window so a reference into rewritten bytes fails rather than fabricates, and
every record typed `EvtxRecoveredLogEntry` with its `recovery_source`; on plaso's
`System2.evtx` it discloses the 89 records the intact walk lost to a truncated
tail chunk, and on `system.evtx` 79 stale records from chunk 14's slack), the
`DestList` stream (below), and registry recovery (`seance_plugin_registry::recovered`:
freed `nk` / `vk` cells walked from the hive's unallocated
space, published as `RecoveredRegistryKey` / `RecoveredRegistryValue` and a
`Recovered Registry Key Last Written` event, never merged with live records, a
key's path stated as an inference from a parent offset that may have been
reused, with `examined_cap` 200,000 cells and `records_cap` 50,000 disclosed by
number; plaso's `SAM` gives three keys and three inline values as the known
answer). WMI: `seance_plugin_asep::wmi` scans `OBJECTS.DATA` page by page,
decodes the instance records of `__EventFilter`, `__FilterToConsumerBinding` and
the consumer classes against the **class definitions found in the same file**
(the two real repositories held carry two different `ActiveScriptEventConsumer`
definitions, so a coded table would have been wrong), and states on every record
whether `INDEX.BTR` and `MAPPING*.MAP` were read. Without them, a record found is one that
exists in the file, not one the repository necessarily still indexes, and a
definition whose descriptor runs past its page is skipped with its instances
reported undecodable. No real `ActiveScriptEventConsumer` **instance** is held, so
that class decodes through the same definition-driven path that is validated on real
`__EventFilter`, binding, `CommandLineEventConsumer` and `NTEventLogEventConsumer`
instances, and says so. Two real `CommandLineEventConsumer`s are graded: Windows 7's
stock `BVTConsumer` in the NIST Data Leakage repository (`WMI-1` in
`VALIDATION.md`) and an attacker-planted one, the HTB Business CTF 2022 "Perseverance"
repository's `Windows Update` consumer, filter and binding, which agrees with the
published write-up and an independent `dissect.cim` parse (`WMI-3`). Liveness is not
established. A PowerShell `-EncodedCommand` argument on any autostart record is decoded
and published beside the command.
The page mapping is read when it sits beside
`OBJECTS.DATA`: `MAPPING1/2/3.MAP`, or `OBJECTS.MAP` on XP, chosen by highest
sequence number among the well-formed files. Through it every page-spanning
record on the whole Lone Wolf, Data Leakage and CFReDS XP repositories is read
whole (364, 180 and 84; the XP ones match their stored CRC-32s, which the scan
checks and counts itself), and a record a descriptor table lists in
a page the mapping no longer uses is published as `superseded` under
`RecoveredAsepEntry` (`WMI-2`). A binding resolves to the current copy of its
filter and consumer where one was found, and says so when only a superseded or
residue copy was. Without `INDEX.BTR`, a record its
mapped page's descriptor table lists is current on that table, not on the index;
a record no descriptor lists, even in a mapped page, or one in a trailing
part-page no mapping entry covers, is residue and is never called current or in
force. A mapping file present twice in its directory is withheld, reported as
withheld, not as absent. Without the mapping each record says which
applied. `INDEX.BTR` is read when it sits beside `OBJECTS.DATA` in a
`MAPPINGn.MAP` repository, walked as a tree from its root. On four real repositories (three
Flare Windows 7 and the Perseverance Windows 10 one) the references it names equal an
independent reader's exactly and every subscription record found in a mapped page is named by
it; 4, 4, 4 and 23 descriptors a current page lists are named by no key. A record listed but not
indexed is published as `unlinked`; none is held, so that is pinned on a synthetic
index. The Windows XP and Server 2003 indexes are read and equal python-cim's on a real repository each (`WMI-8`, `WMI-9`).

---

## 5a. macOS artifacts

**Numbered `5a` rather than `6` because the sections after it are cited.**

**Read the `?` column-by-column, not row-by-row.** The Séance column is
verified the same way as every other section — from the source tree, the tests
and the corpora. The other seven **have not been researched for these rows**,
so they say `?`, which under this document's own rule is *not* evidence of
absence: AXIOM in particular publishes macOS artefact coverage, and several of
these cells will be a tick when somebody reads the datasheets. Filling them in
from memory is the one thing that would make this section worse than its
absence.

| Artifact | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Quarantine, TCC, knowledgeC, FSEvents, install history, launchd, BOM | ✅ | ? | ? | ? | ? | ? | ? | ? |
| Apple Mail `Envelope Index` | ⚠️ | ? | ? | ? | ? | ? | ? | ? |
| Apple Mail `.emlx` messages | ✅ | ? | ? | ? | ? | ? | ? | ? |
| A `.partial.emlx`'s `.emlxpart` parts reunited | ⚠️ | ? | ? | ? | ? | ? | ? | ? |
| `utmpx` — the sessions open at acquisition | ✅ | ? | ? | ? | ? | ? | ? | ? |
| **Apple System Log (`/var/log/asl`) — the login history** | ✅ | ? | ? | ? | ? | ? | ? | ? |
| **OpenBSM audit trails (`/var/audit`)** | ✅ | ? | ? | ? | ? | ? | ? | ? |
| Classic keychain — the cleartext index | ✅ | ? | ? | ? | ? | ? | ? | ? |
| Data-protection keychain and the iCloud keychain circle | ✅ | ? | ? | ? | ? | ? | ? | ? |
| Classic keychain **secret** decryption — password or `SystemKey` supplied; the data-protection keychain stays locked | ⚠️ | ? | ? | ? | ? | ? | ? | ? |
| Unified log **catalogue** (`/var/db/uuidtext`, `dsc`) — the inventory of code that logs | ✅ | ? | ? | ? | ? | ? | ? | ? |
| Unified log per-message decode (`.tracev3`) | ⚠️ | ? | ? | ? | ? | ? | ? | ? |
| Spotlight `Store-V2` per-item decode | ✅ | ? | ? | ? | ? | ? | ? | ? |

**Why the Jump List row is split, and what the second half asserts.** `seance_plugin_jumplists` reads an
`automaticDestinations-ms` file as the OLE compound file it is (the `cfb` crate,
already in the tree): the directory's hex-numbered streams are handed on as
`.lnk` `FileEntry` artifacts typed `JumpListStream`, and the **`DestList`** stream
is decoded by its header version and never guessed — version 1 (Windows 7/8,
114-byte fixed part) and versions 2–4 (Windows 10+, 130-byte fixed part) — giving
per entry its number, stream name and whether that stream exists, the path, the
NetBIOS host, the four DROID GUIDs, the last recorded time (an unset FILETIME is
`last_recorded_time_unavailable`, never 1601), the pin status raw and decoded,
and its index in stream order with the basis stated. The application is named for
41 known AppIDs by a CRC-64 the build computes (19 cross-checked against an
independently published ID, 22 computed only — the basis on every record); an unknown
AppID is reported as unknown. Pinned to plaso's own expectations on its Windows 7
(v1, 11 entries) and Windows 10 (v3, 2 entries) fixtures. **Two things the row
does not say.** The Windows 10 entry field at offset 116 — the one other tools
report as an access or interaction count — is published as
`offset_116_unknown_possibly_access_count` with a note beside it, because both
format sources the module cites mark that field *unknown* (libyal: "Unknown
(access count?)"; plaso: `unknown5`); Séance does not call it a count, and a
version 1 entry carries `offset_116_unavailable` because its layout has no such
field. Shortcuts in sectors a *readable* directory no longer
references are carved too, from the file's own free-sector and free-mini-sector
maps, and labelled `unreferenced_sector_carve` with the sector they lay in; the
mechanism is pinned on files the `cfb` writer built, and no real jump list examined
(30 of them) has yet held one, which each record says.

**What "Amcache / Shimcache" says.** Both are marked for what the code asserts:
Amcache records that Windows **catalogued** a file (no run count, no last-run time), and a
shimcache entry means Windows **looked at** it, with the execution flag read only on the
Windows 7 and Vista layouts. Neither is an execution record, and the triage detections
built on them are named accordingly.

**What the two unified-log rows mean.** The catalogue row is ✅ because
`/var/db/uuidtext` reads in both its forms and yields the machine's inventory of code
that logs — 262 binaries, graded as `MACOS-UUIDTEXT-1`. It is **not** a claim that any
log message is recovered: a catalogue holds the sentences the OS would have substituted
arguments into, and every record says so. The per-message row is ⚠️. The macOS image this project is
graded on holds no `.tracev3` file at all. Six public `.logarchive`
trees are held (Mandiant's test corpus), and the reader decompresses
every chunkset in them and parses every firehose tracepoint (9,900,644, all read
whole), and a resolver/formatter library turns them into text against each archive's
own tree. The cell is ⚠️ because that text reaches a case. A
`.tracev3` read from loose files or a ZIP climbs (at most three directories, through
`DataSource::open_from_ancestor`) to its own `uuidtext`/`dsc` tree and `timesync`
database, and each message becomes a record with its rendered text, process,
subsystem and a timesync-dated timestamp — Big Sur's `Persist/…04.tracev3` gives
110,953 records, Mandiant's count for that file (a comparison, not ground truth). It is
**not ✅** because the common forensic case has not been graded: a `.tracev3` inside an
APFS or HFS+ image is handed the log tree listed from the same volume (`attach_sibling_bundles`,
unit-tested on listings), but no image held here carries a macOS log tree, so that reach has
not been read end to end on a real image. A source that is not a mounted-volume listing still
says "tree not reachable, not decoded". Oversize
arguments are joined within a file (not across files), and statedump and simpledump
entries are messages of their own, with a statedump's protocol-buffer or custom-object
data kept as bytes and not decoded.

**What the Spotlight row does and does not claim.** ✅ means the per-item metadata
decodes: the path, content type, sizes, owner, download source and dates of every
file the index saw, **including files since deleted** — 14,934 items off the graded
image, with 8,782 of the 8,797 decoded sizes matching the actual file on the mounted
volume (`MACOS-SPOTLIGHT-1`). It does **not** claim everything in the format is
understood: the record's flag byte, one unnamed number, the `0x41` block and six of
`value_type`'s bits are read and published uninterpreted, and nine of the 33 value
shapes rest on a handful of observations rather than on the exact-tiling test the
rest are pinned by. `MACOS_DESIGN.md` lists each one.

**Why the two login rows are bolded.** macOS keeps no `btmp` and, since 10.5, no
on-disk `wtmpx` or `lastlogx`. `utmpx` therefore answers only "who was logged in
when the image was taken" — the history is in the Apple System Log and the audit
trail, which is where `MACOS-ASL-1` and the OpenBSM run found six boots, four
shutdowns, eighteen accepted SSH logins and **two refused password attempts from
one address**. A macOS suite that reads `utmpx` and stops has not answered "who
logged in last Tuesday"; it has answered a different question.

**Mail ⚠️, and the reason is worth stating.** It is an *index*, not the mail: the
`Envelope Index` reader recovers sender, recipients, subject, mailbox and dates
for every message Mail has seen — including messages whose `.emlx` is gone — and
carries no body and no RFC header, which every record says on itself. It is also
graded against Apple's own schema rather than against a mailbox Apple filled,
because the only real index held here is empty. Both are on the record as
`basis: schema_verified_rows_unverified`. The messages themselves are a
separate row. Where an `.emlx` survives, the email parser reads it: the byte
count bounds the message, the trailing plist goes on the record and not in the
body. A `.partial.emlx` has its `.emlxpart` attachments reunited **only from a
host directory or a ZIP entry**; a file inside a disk image (APFS, HFS+, NTFS,
ext4) cannot open its neighbours, so on a Mac's disk image — the usual case —
every part is reported "could not look" and no attachment is recovered, hence
the ⚠️. Each part is reported as reunited, absent, or "could not look". This was checked against
three files Apple Mail wrote. The plist `flags` integer is reported raw and not
decoded, because its bits are Apple-private.

**Keychain secrets ⚠️ for the classic keychain, locked for the data-protection keychain.**
The classic `kych` keychain opens with the keychain password or `/var/db/SystemKey`,
supplied by the examiner (`macos_keychain_password`, `macos_system_key`). The unwrap is
PBKDF2-HMAC-SHA1, 3DES-EDE-CBC and the RFC 3217 key unwrap, in
`keychain_unlock.rs`, and a wrong password is rejected. It is graded on two openwall
keychains with published passwords (`KEYCHAIN-1`), on a `security`-made keychain whose four
password items decrypt to the published secret (`KEYCHAIN-2`), and on the macOS 11.2.1
`System.keychain` with its `SystemKey` (`KEYCHAIN-3`). Limits: the item-key layout is graded
on one file from one macOS version, nothing derives or guesses a password, and macOS
Monterey or later is unmet. A decrypted secret is withheld from every record, export and
index and is released one item at a time by an audited reveal. The data-protection keychain
opens with nothing an image carries, because its class keys live in hardware, and its
records say so rather than leaving an examiner hunting for a password that does not exist.
What it does give is the index: which application owns each secret and which devices the
Apple ID trusted. An iPhone's keychain inside an encrypted **backup** is a third case and a
different file (`keychain-backup.plist`, §7): there the backup password opens the items
outside the `ThisDeviceOnly` classes, and their attributes are cleartext. The secrets are
withheld from every record and released one at a time by an audited reveal.

---

## 6. Memory forensics — Séance's strongest area

| Capability | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Windows memory analysis | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Linux memory analysis | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| macOS memory analysis | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Process list + cross-view (pool scan, hidden procs) | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Handles, VADs, kernel objects, modules, hooks | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Linux: open files with mount-crossing paths and `socket:`/`pipe:`/`anon_inode:` forms, process command lines, syscall-table / ftrace / kprobe / eBPF hook attribution | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| Windows hibernation file restored **whole** (both restore sets walked to the header's page counts; NT10 and NT6.2/6.3 layouts, plain Xpress and Xpress-Huffman) | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| ARM64 memory analysis — QEMU-captured guests only | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| Credential recovery from memory | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| Per-process Linux capability sets (`cap_*`) | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| File recovery / MFT records from memory | ✅ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ✅ | ❌ |
| Process tampering / injection detection | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Pagefile / swap integration | ✅ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ | ❌ |
| Network connections from memory | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| Symbol handling: ISF, PDB, **kallsyms + BTF from image** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Build-variant member binding (fails loudly on mismatch) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Published Volatility 3 parity tests | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

Most of the ⚠️s in this section mean *"integrates or bundles Volatility, or
performs string/artifact carving over the dump"* rather than *"implements
address-space translation and structure parsing."* X-Ways' native memory
analysis, notably, is documented against **Windows 2000 through Windows 7** —
it is not a current-Windows capability. Autopsy has none.

**Linux, hibernation and ARM64 rows.** The Linux row:
`seance_plugin_memory_linux` reconstructs paths across
mount points with the kernel's own `prepend_path` and states the walk on every
record (`path_scope`), decodes the pseudo-file names under their own scope, reads
each process's argument bracket through its own page tables, and attributes every
`sys_call_table` entry, `ftrace_ops`, direct call, kprobe and eBPF program to
kernel text, a named module or nothing known, with what it could not check named
on the record, never rendered as "no hooks". Against Volatility 3: `linux.lsof`
and `psaux` have counterparts with the full path where upstream's is
mount-relative; `check_syscall` prints `UNKNOWN` for an address in a module,
which this stage names; and `tracing.ftrace` walks only bucket 0 of an
`ftrace_hash`, so its filter lists are not a parity target, and every bucket is
walked here. Stated bounds: no kernel-text diff against a pristine copy, no
perf-event walk, no `dyn_ftrace` walk, no BPF-trampoline decode; the eBPF
registry only in its 4.20+ xarray shape. `LINUX_DESIGN.md` has the per-stage
detail and `VALIDATION.md` the lab-capture known answers. The hibernation reader
walks both restore sets to the page counts the header states (40,004 and 511,499 on
the Windows 11 26200 corpus; 16,664 and 113,548 on Server 2012 R2), a block
yields every byte of its pages or is a **counted gap**, and all 65,536 planted
marker pages come back byte-exact.

The ARM64 row is ⚠️. The VMSAv8-64 page-table walk (4, 16 and 64 KiB granules,
TTBR0/TTBR1) ships. It agrees with an independent walker on every leaf of
real page tables written by real kernels: 11,663 of 11,663 leaves of two MMUShell
AArch64 guests (4 KiB), a Debian 16 KiB kernel
(35,417 pages and 8 blocks, then 90 pages) and an Ubuntu 64 KiB kernel (13,203 and 26
pages) that were booted under QEMU TCG for the purpose (`VALIDATION.md` `MEM-ARM-5`,
`MEM-ARM-6`). Three arm64 Linux kernels are profiled end to end, and two Windows 11 ARM64
builds are graded, all on QEMU-captured guests (`MEM-ARM-4` to `MEM-ARM-8`, `MEM-ARM-11`). Linux
discovery offers the arm64 kernel regimes to its banner proof and profiles each kernel
from its own BTF and `kallsyms` or an exact symbol file, with the process list and the
file offsets of each process's mappings graded structurally. No ARM64 hardware capture is
validated. An arm64 kernel whose tables prove under no regime this build decodes is
refused as `UnsupportedArchitecture` naming arm64 **when the symbol
table (`kimage_voffset`) or the image's own `VMCOREINFO` says arm64** (`MEM-043`). When
neither says so, that kernel ends at `PageTablesUnproved`, and one whose tables also read as
valid x86-64 tables is profiled as x86-64, with a discovery note that the arm64 regimes did
not prove, what the `VMCOREINFO` check found or that it could not settle it, and that the
architecture rests on the page-table proof alone. An x86-64-only proof is not taken while
any `VMCOREINFO` copy found names arm64, even in a sweep cut short or whose copies disagree.
An arm64 capture with no matching ISF and no in-image BTF ends at `SymbolsNotFound`, which
names neither arm64 nor what the image's `VMCOREINFO` says. On the Windows side a crash dump whose
header states an ARM64 machine is refused as `UnsupportedArchitecture` before any DTB
sweep.

Three things here appear to be Séance-only:

1. **Image-derived symbols.** When no ISF describes the kernel, Séance recovers
   `kallsyms` and BTF *from the capture itself* and compiles them into a
   validated symbol table — so a custom build or an appliance nobody publishes
   symbols for is analysable instead of a dead end. Verified against a host's
   own `/proc/kallsyms`: 202,525 symbols, every address as the kernel printed it.
2. **BTF layout corroboration.** An ISF is matched to an image by kernel banner,
   and a banner is not unique to a build. Séance cross-checks the matched symbol
   file against the type information the kernel carries about itself and *fails*
   the symbols when they disagree — the only such check whose reference came out
   of the evidence rather than out of another file's name.
3. **Typed holes.** A page not in the capture is reported as unmapped, not
   present, swapped out, or heuristically suppressed — never as zeros.

Séance's honest gaps here: **macOS ⚠️** is built, tested against Apple's KDK and
**registered** (`seance_api::modules`), but every record it emits carries
`validated_against_real_capture: false` and an examiner-facing
`validation_notice`, because no real macOS capture has ever been run through it.
The coverage row in the report repeats that marker, so the analysis reaches the
examiner with its unproven status on it rather than being withheld. **Network ⚠️** —
both routes are implemented: a pool-tag **sweep** (`TcpE`/`TcpL`/`UdpA`/`TTcb`)
that finds torn-down and unlinked endpoints, and a partition-table **walk**
(`netstat`) as the cross-view. What holds it at ⚠️ rather than ✅ is that the
`_TCP_ENDPOINT` field layout is carried as a baked ISF (unit-tested) rather than
derived from the image the way the Linux symbol path is, and it has not yet been
validated end-to-end against a real Windows capture.

### Volatility 3's Windows plugins, one by one

"Volatility has more breadth" is checkable, so it was checked: all 84 plugins in
Volatility 3's `plugins/windows/` namespace (plus the nine OS-independent ones
that apply to a Windows image) against the Rust tree, by grepping
for each plugin's own name and then reading the module. Understating the product is
the same class of error as overstating it.

**Answered, and where** (paths under `seance_plugin_memory_windows/src/`):

| Volatility plugin | Answered by |
|---|---|
| `pslist`, `pstree`, `cmdline` | `process.rs` |
| `psscan`, `poolscanner` | `poolscan.rs` |
| `psxview`, `thrdscan`, `threads` | `psxview.rs`, `psxview_threads.rs` |
| `suspicious_threads` | `psxview_suspicious.rs`, `psxview_suspicious_survey.rs`, the `suspicious_threads` stage. Measured: 0 findings over 123 processes on the clean build-26200 capture; 1 / 10 / 9 on the XP captures be2 / zeus / stuxnet, every one also a Volatility 3 row. Volatility prints more rows there (4 / 13 / 25): the extras are XP `Win32StartAddress` values that are LPC message ids (`LpcReceivedMsgIdValid` set) or zero, which Séance does not judge as addresses. Kernel-mode starts are counted apart rather than dropped, and **not every one is judged**: on the build-26200 capture 76 of 78 are on threads whose `_KTHREAD.SystemThread` is clear, which neither this stage nor the orphan-thread group examines, so that record says it is incomplete. Observed and oracle-compared, not graded: no published answer names an injected user thread on these captures |
| `handles`, `privileges`, `getsids` | `handles.rs` and its `_token` / `_privileges` / `_sid` / `_name` parts |
| `dlllist`, `modules`, `modscan`, `ldrmodules` | `modules.rs` — all three `_PEB_LDR_DATA` heads walked through their distinct link members and cross-referenced against the VAD tree |
| `vadinfo`, `vadwalk`, `malfind` | `vad.rs` |
| `netscan`, `netstat` | `netscan.rs` and its `_decode` / `_netstat` / `_legacy` parts |
| `svcscan`, `svclist`, `getservicesids` | `services.rs` (`list_service_sids`, the `S-1-5-80` derivation) |
| `ssdt`, `callbacks`, `driverscan`, `drivermodule`, `driverirp` | `kernel_hooks*.rs` — including the IRP major-function table |
| `direct_`, `indirect_`, `unhooked_system_calls` | `syscalls.rs` |
| `hollowprocesses`, `processghosting` | `hollow.rs` |
| `filescan`, `mutantscan`, `symlinkscan` | `objects.rs` |
| `dumpfiles`, `memmap`, `pedump`, `iat` | `dump.rs` (`memory_map`, `memory_dump`, `dump_pe`, `read_imports`), `recovered.rs` |
| `hashdump`, `lsadump`, `cachedump` | `credentials.rs`, `credential_decrypt.rs` |
| `hivelist`, `hivescan`, `printkey` | `registry*.rs`. `userassist` is not answered on memory hives: no memory plugin decodes it, and `registry.rs` leaves value decoding to the on-disk registry plugin |
| `amcache`, `shimcachemem` | `amcache.rs`, `amcache_hive.rs`, `amcache_shim.rs` |
| `desktops`, `deskscan`, `windowstations`, `sessions`, `envars` | `environment*.rs`, `psxview.rs` (`tagDESKTOP`) |
| `mftscan` | `mftscan.rs` |
| `joblinks` | `jobs.rs`, the `jobs` stage — one record per **distinct** job object |
| `devicetree` | `device_tree.rs`, the `device_tree` stage |
| `yarascan`, `vadyarascan`, `regexscan`, `vadregexscan` | `pattern_scan.rs`, the `pattern_scan` stage — the per-process scan planned from the VAD tree, with each match's allocation on it; `seance_memory::patterns::ImagePatternScan` for an image's own space, which is the only route for a reconstructed hibernation file or a swap area; a YARA rule set (`SEANCE_YARA_RULES`) and a regular expression (`SEANCE_MEMORY_REGEX`) drive the same plan |
| `strings` | `strings_map.rs`, the `strings_map` stage — the examiner's own `strings -t d` offsets attributed through a reverse mapping built across every process's page tables plus the kernel's (`seance_memory::reverse`, `seance_memory::translate::enumerate`). **Upstream's per-process attribution does not work**: its process branch keys the reverse map by the *virtual* page number, so a genuine physical offset returns `FREE MEMORY` and physical `0x7ffe0000` returns 123 of 130 processes because `0x7ffe0` is `KUSER_SHARED_DATA`'s virtual page in each — measured on this project's Win11 corpus. Only its kernel column is correct |
| `info`, `crashinfo` | `profile.rs`; `seance_memory::module::crash_dump_facts` |
| `layerwriter` | `seance_memory::export`: the image's decoded **physical** layer as an address-aligned raw file, streamed, with a hole manifest listing every fill range, its reason and the totals — upstream's pads the same ranges and records nothing. `GET …/memory/layer/{image}/manifest` and `…/raw` (`CORE_DESIGN.md` §4.4b), `/memory layer` in the REPL. Checked on the corpus crash dump `win10.dmp`: the manifest's 11,686 holes are exactly the complement of the dump's own run table and sampled exported bytes equal the dump reader's. Physical only: a translated virtual layer has no route |
| `unloadedmodules` | `tamper_unloaded.rs`, one group of the `tamper_checks` stage |
| `timers` | `tamper_timers.rs`, one group of the `tamper_checks` stage |
| `suspended_threads`, `debugregisters`, `orphan_kernel_threads` | `tamper_threads.rs`, three groups of the `tamper_checks` stage, from one pass |
| `etwpatch` | `tamper_etw.rs`, one group of the `tamper_checks` stage |
| `skeleton_key_check` | `tamper_skeleton.rs`, one group of the `tamper_checks` stage — **one of its two routes, with the other named as not run** |
| `pebmasquerade` | `hollow.rs`, inside the `tampering` stage — with the kernel's audit record as a third opinion upstream does not read |
| `kpcrs` | `processor_blocks.rs`, the `processor_blocks` stage — `KiProcessorBlock` walked to the first null slot, every `_KPCR` held to three self-checks (`Self`/`SelfPcr`, `CurrentPrcb`, `_KPRCB.Number`), the count compared with `KeNumberProcessors` and never taken from it |
| `bigpools` | `big_pool.rs`, the `big_pool` stage — every `_POOL_TRACKER_BIG_PAGES` slot, live / freed / never-used told apart by type, totals per tag exact regardless of the 50,000-row publication cap; `ExpPoolBigEntriesInUse` compared with the walk |
| `virtmap` | `virtual_map.rs`, the `virtual_map` stage — regions named from the kernel's own `Vs.SystemVaType` per-slice map, **never by slot index** (on 26200 the array is not indexed by `_MI_SYSTEM_VA_TYPE`: 18 slots, 20 enum values, the kernel in slot 17); cross-checked against `MmPfnDatabase` and the kernel base; `SystemVaTypeCount` published in 2 MiB units, each count checked against the kernel's own `SystemVa.DynamicBitMap<Type>` and withheld if one falls below it (measured on 26200 only) |
| `getcellroutine` | `hive_cell_routines.rs`, the `hive_cell_routines` stage — `CmpHiveListHead` walked, each hive's `GetCellRoutine` / `ReleaseCellRoutine` symbolicated inside the kernel image only |
| `verinfo` | `version_info.rs`, the `version_info` stage — `VS_VERSIONINFO` decoded from the bytes in memory for every kernel module and every DLL of every process, with **seven** outcomes told apart, including a resource section marked `IMAGE_SCN_MEM_DISCARDABLE` and therefore **not read** (`resource_discarded` — the kernel's own case on 26200; the flag alone decides, and the bytes at the directory are not checked) |
| `mbrscan` | `mbr_scan.rs`, the `mbr_scan` stage — every 512-byte-aligned `55 AA` sector decoded and held to six named checks with every outcome published; boot code hashed, not judged |
| `cmdscan` | `console_history.rs`, the `console_history` stage — each console host's heap swept for the command-history vector; **one build** (Windows 11 26200.6584), in-house layout, five of five typed commands recovered on a capture whose commands were recorded; `consoles` (screen output) not answered |
| `scheduled_tasks` | `scheduled_tasks.rs`, the `scheduled_tasks` stage — `TaskCache\Tasks` from the in-memory `SOFTWARE` hive, `Actions`, `DynamicInfo` and `Triggers` decoded — each trigger's kind (time with schedule mode, boot, logon, idle, registration, session change, event with XPath subscription, WNF), start, repetition and enabled flag; a localized start printed as wall-clock time, never UTC; an unknown kind stops the decode and is named. All 246 blobs on the 26200 capture decode whole; one build |
| `truecryptmaster`, `truecryptpassphrase`, `truecryptsummary` | `truecrypt.rs`, the `truecrypt` stage — driver presence decided from the module list (a partial list cannot clear the machine); the non-paged-pool sweep for AES key schedules runs only with the driver loaded, publishes address, size and the key's SHA-256 (never the key), labels an adjacent AES-256 pair as a **possible** XTS pair; graded on one capture with one mounted VeraCrypt AES volume (both master keys reported, alongside BitLocker's schedules); the driver's key container is **not** decoded |

`pe_symbols` is **partly** answered — `dump.rs::read_exports` covers the export
side — and `svcdiff` may be: `services.rs` already reaches the service records
two ways, which is most of what that plugin does; exercising it on the corpus
is not yet done.

All eight of these reach the **Findings** screen through
`plugin.findings.kernel_tamper`, which raises six kinds of lead from the
stage's own record and re-derives nothing: the grade and the qualification are
what it adds, and every qualification carries the clean-capture number the rule
was measured against. Nothing it raises is graded `Strong`, a suspended thread
raises nothing at all, and an orphan row whose exclusions were not all
assessable is not a lead. Upstream has no equivalent layer: its plugins print
tables and the reading is the examiner's.

`unloadedmodules` is answered, and in three ways that are worth naming because
they are where this reader and the upstream plugin give different answers on
the same bytes — `tamper_unloaded.rs`, graded on the Windows 11 26200 capture
(`tests/win11_corpus_analysis.rs`):

1. **The table is circular and fifty entries long.** `MmLastUnloadedDriver` is
   a monotonic **write count**, so the slots populated are `min(count, 50)` and
   the newest is `(count - 1) % 50`. Volatility 3's `unloadedmodules` sets the
   array length to the counter (clamping only at 1024), so on a machine that
   has unloaded 63 drivers it reads 63 records out of a 50-record table.
2. **The time field is classified before it is rendered.** On the capture here
   all nine populated slots hold 1.49 s – 5.78 s in 100-nanosecond units,
   monotonically increasing with the unload order: an interval **since boot**,
   not a FILETIME. Séance publishes it as an interval and states that no
   absolute time is claimed. Upstream converts the field with
   `wintime_to_datetime` unconditionally, which dates all nine unloads to
   1601-01-01 — a date that sorts to the top of a timeline and reads as a
   timestomp.
3. **No row is dropped by a plausibility heuristic.** Upstream yields a row
   only if `CurrentTime > 1024` and both addresses are page-aligned in kernel
   space; a driver whose slot fails one of those is simply absent from the
   output. Here every populated slot is reported, with the reason a field is
   absent beside it.

The layout is Séance's own declaration — 46 of the 1,724 `ntkrnlmp.pdb` ISFs on
the build machine declare `_UNLOADED_DRIVERS` and all 46 agree exactly, so the
x64 form is validated against real symbols; **no x86 ISF declares it at all**,
so the x86 form is documented, unvalidated, and every record read through it is
stamped `unvalidated` and says so.

`timers` is answered by `tamper_timers.rs`, and two of its measurements are
worth stating because they are the places a reader gets a plausible wrong
answer. **The bucket count is the product of the declared array dimensions.**
`_KTIMER_TABLE.TimerEntries` is declared `[2][256]` on Windows 11 build 26200
and `[256]` on all 1,233 older ISFs in the pack measured here; a reader taking
the outer dimension walks 2 of 512 buckets, finds real timers in both, and
produces a result with nothing about it looking wrong. **And `_KTIMER.DueTime`
is not reported at all** — its encoding on modern x64 is established by no
source in this tree, and `KiWaitNever`/`KiWaitAlways`, the globals an
obfuscation of that field uses, are declared on the builds measured. The
forensic value of a timer is its DPC routine, which does not depend on it. The
bucket's own `_KTIMER_TABLE_ENTRY.Time` is published as the raw number it holds
with no epoch claimed, rather than omitted without looking.

The clean-machine baseline is on the record rather than assumed: 209 timers over
4,096 buckets on 8 processor tables of the Windows 11 capture, 52 of them
carrying a DPC once `_KTIMER.Dpc` is decoded (the other 157 decode to
null), and **not one routine outside a loaded module**
(`seance_memory/tests/KNOWN_ANSWERS.md`). A timer with the shape of PatchGuard's
own — a misaligned `_KTIMER`, a routine in no module and a non-canonical
`DeferredContext`, all three — is published as `patchguard_shaped` and not
graded; the one clean Windows 10 capture here that has such a timer
(DFIR Madness Case 001's desktop) therefore raises no lead. No other Windows
capture held shows the shape: eleven further captures were re-measured and read 0 graded and 0 shaped (`documentation/VALIDATION.md`).
That is a shape, not
an identification, and a rootkit could imitate it, so the row stays on the record
and its routine is still cross-referenced against the unloaded-driver table.
Every timer count is of distinct `_KTIMER`s: a timer
reached from several bucket lists is one row naming each place it was reached,
and a list that leads into another bucket's head stops there rather than
publishing that head as a timer; on the modern captures held, most timers seen
twice carry no established reason and say so.

**The legacy global table, graded against upstream on real XP captures.** Upstream hardcodes the XP table as 256 `_LIST_ENTRY` heads;
Séance derives the length from the image, bounded by the next symbol the build
declares, and on four XP SP2/SP3 x86 captures (Malware Cookbook and Stuxnet, not
redistributable) derives 256 and reports exactly upstream's 60, 60, 64 and 58
DPC timers — same addresses, routines and periods. The Vista SP2 x86 form is read on one capture and reaches all 51 of Volatility 2's timers (`MEM-XP-5`). The Server 2003 R2 SP2 x64 form is read on one capture and gives the same 211 timers as a Volatility 2 address-space walk of the table (`MEM-XP-6`). Windows XP x64 itself has no capture.

The three thread groups are answered from **one** pass over the threads, and
each differs from upstream in a way worth naming:

* **`debugregisters`.** Upstream reads `Tcb.TrapFrame.Dr0`–`Dr3`/`Dr7` without
  consulting the thread's own `DebugActive`/`ActiveDR7`, reports any non-zero
  `Dr0`–`Dr3` as a breakpoint whenever `Dr7` is non-zero (no per-slot enable
  test), and then drops any thread none of whose register values maps to a
  **file-backed** VAD. Séance gates on the thread's own flags, because on build
  26200 `Dr0` shares its offset with `ShadowStackFrame` and `Dr1` with
  `Spare[5]` — reading them regardless produced nine rows on this project's
  clean capture, five claiming armed breakpoints, all of them shadow-stack
  pointers. It then applies `Dr7`'s L/G enable bits per slot, so a stale
  address in an unarmed slot is listed as stale and claimed as nothing; and it
  drops no row for failing to be file-backed, which is the case an examiner
  most wants to see. **The cost of that choice, measured on XP:**
  one `winlogon.exe` thread on each of four XP captures has its own
  `DebugActive` set, `Dr7` = 0x555 and `Dr0`–`Dr3` in the null page, so Séance
  reports an armed breakpoint on every XP capture where upstream, dropping it
  for not being file-backed, prints nothing. On XP this group has a
  clean-capture false positive; on the Windows 11 capture it has none.
* **`suspended_threads`.** Upstream treats suspension as a detection and
  carries a hardcoded exception for `WorkFoldersShell.dll` — "the only false
  positive found in mass scanning of samples". Séance reports it as a
  **listing** with `is_a_finding: false` and the basis on every row (the
  platform suspends packaged apps, debuggers suspend, and `CREATE_SUSPENDED` is
  how nearly every injector starts), because a name-based exception is
  bypassable by naming the DLL that.
* **`orphan_kernel_threads`.** Upstream's exclusions are pid/ppid == 4, an exit
  time or state 4, and a start address below kernel space. Séance applies four
  and **grades a finding only when all four were assessable**: kernel-thread
  identity (`SystemThread`, or the owning process being
  `PsInitialSystemProcess` where that bitfield is not declared — 650 of the
  1,724 ISFs here), not terminated, `StartAddressInvalid` clear, and **not
  inside the range of a driver the kernel has unloaded** — the one explanation
  that accounts for the address with nothing being wrong, which upstream does
  not test. Where one exclusion could not be assessed the row is an
  observation, not a finding, and says which control was missing. **On a real
  rootkit** — the Malware Cookbook's `tigger.vmem` — both tools
  print the same three orphan system threads, including the one Ligh's 2011
  write-up names (Tid 1648 at 0xf2edd150). Upstream calls them orphans; Séance
  publishes them as observations, because XP declares no
  `StartAddressInvalid` and one of its four controls cannot be applied there.

`etwpatch` is answered by **two independent routes**, neither of which needs a
stored baseline per build of `ntdll.dll` — which is what would otherwise rot on
the next Patch Tuesday. **Classification** decodes each export's prologue and
reports a function that returns immediately (`ret`, or `xor eax,eax; ret`),
traps, or whose first control transfer leaves the module. **Modal comparison**
takes the modal first-sixteen-bytes of each export across every corroborated
copy in the image and reports a minority: a patch in one process is
1-against-123 with no reference bytes at all, and a patch applied machine-wide —
where the mode is itself patched — is what the classification catches. Every row
says which route fired, and `ordinary` is explicitly **not** a claim that the
function is unpatched.

Two disciplines carry over from `syscalls.rs`. A copy of `ntdll` positively in
private memory is classified but **never votes in the mode** — an attacker able
to hand-map a copy carrying the name would otherwise be choosing the baseline
every other process is compared against. And a process whose `ntdll` pages are
not resident is **unassessed and counted**, never "unpatched": on the clean
capture that is 6 of 129 processes, three of which map no `ntdll` at all
(`System`, `Registry`, `MemCompression`). Baseline: 491 prologues over 123
processes, no signal on either route
(`seance_memory/tests/KNOWN_ANSWERS.md`).

`skeleton_key_check` is answered **on one of its two routes, and the other is
named on every record as not run**. The route that runs classifies
`cryptdll!CDLocateCSystem` inside each `lsass.exe`, resolved from that module's
own export table — no symbols needed — with the same decoder the ETW check
uses. The route that does not is the `CSystems` descriptor table, where an
RC4-HMAC descriptor's function pointer has been redirected while the exported
entry point is left intact; that is the stronger signal, and reaching it needs
the layout of a structure **nobody publishes**. Microsoft ships `cryptdll.pdb`
as a *public* PDB — names, no structure layouts — exactly as it ships
`tcpip.pdb`, which this project records at 10,376 symbols and zero types. So the
record says the route did not run and what it would have established, rather
than listing it as pending a symbol file: an ISF of a public PDB would give the
address of the `CSystems` global and nothing about the entry layout.
Two things follow that are worth stating. The group's record is marked
**incomplete on every build**, including the clean capture where it found
nothing, because half its coverage never runs. And a machine whose `lsass.exe`
the walk never reached reports **not assessed**, never a clean machine — the
question is asked precisely when domain authentication is in doubt.

`pebmasquerade` is answered inside the `tampering` stage, and with one more
source than upstream reads. Upstream prints three names per process —
`_EPROCESS.ImageFileName`, the `SeAuditProcessCreationInfo` path and the PEB
path — plus two length flags, and **does not compare them**: the reader is left
to. Here the audit path is compared against both of the others, and against the
path of the file the range backing the image actually maps, which the stage
already read. That last comparison is what makes the answer a statement about
the machine rather than about two fields.
The length marker ships too, in the form the reader supports: the loader
allocates `ImagePathName`'s buffer to fit the path and its terminator, so
`MaximumLength == Length + 2`, and a breach of that is reported with all three
numbers and `is_proof: false`. Upstream's form — comparing the declared length
against the decoded string length — is vacuous for a reader that takes `Length`
as authoritative and reads exactly that many bytes, and in Python it fires on
any path holding a non-BMP character.
The stage raises nothing at all on the clean Windows 11 capture.

`joblinks` is answered by the `jobs` stage, and the comparison with upstream is
worth setting out because the **row counts differ while the sets do not**.
Upstream iterates processes and prints one row per process that has a job, then
repeats that job's member list under each — so a job holding three processes is
printed three times. This stage emits one record per **distinct** `_EJOB`,
naming every process that pointed at it, because two rows for one kernel object
would be two answers to one question. On the Windows 11 capture the two
reconcile exactly: 21 distinct jobs, named by 24 processes (upstream's 24 job
rows), and `Σ named_by × members` = 32 (upstream's 32 member rows).
Two things this stage reports that upstream does not. The job's own
`ActiveProcesses` counter is published **beside** the member walk, and on that
clean capture one job reports 7 while its list holds 3 — mid-teardown, or a
member unlinked; upstream prints `0` for a member row's counters and never
compares them. And a member the active process list does not hold is named as
such, but only when that list walked end to end, so the claim rests on a
complete population rather than on a walk that stopped.

`devicetree` is answered by the `device_tree` stage, and on the Windows 11
capture it walks **more** of the machine than upstream does: 124 drivers, **245
devices** and **113 attachments**, against upstream's 129 DRV, **100 DEV** and
**26 ATT** rows for the same bytes on the same day. Where upstream reports, the
two agree — four `(driver, device)` pairs from its own output are asserted in
this project's test — and what differs is how much of each driver's `NextDevice`
chain is walked: its output holds at most one device per driver, where this
record holds `\Driver\ACPI`'s 32, `\Driver\PnpManager`'s 15 and
`\FileSystem\FltMgr`'s 14, with the sequential PnP names a real ACPI
enumeration produces. **Why upstream stops is not established**, and neither
this file nor the test claims a reason.
The attachments that follow are the ones an examiner wants: `Serial0` attached
by `\Driver\Serial` above ACPI's `00000028`, and an unnamed `\Driver\Serenum`
device above that — a two-level serial stack upstream's output does not reach.
Two honesty points carry through from the rest of the memory tier. **An
attachment is not a finding** — a volume encryptor, an antivirus and a USB class
filter all attach, and the record says so — and a device with **no name** is
distinguished from one whose name could not be read, because most devices are
legitimately unnamed and rendering the two alike would invent a failure. A
device type the Windows Driver Kit does not define is reported as its **number**:
an examiner can look up a number and cannot look up a word this build invented.

`vadyarascan` and `yarascan` are answered by the `pattern_scan` stage, and the
comparison with upstream is an exact one. Upstream's
`windows.vadyarascan --pid 4708 --yara-string FORENSIC-W11` prints eight matches
in `taskhostw.exe` on the Windows 11 build 26200 capture; this stage, driving the
same string as a compiled rule, reports **exactly those eight addresses** —
`0x2ca2f84c44e`, `0x2ca2f84d9ed`, `0x2ca2f8508cb`, `0x2ca2f8511ba`,
`0x2ca2f991c4b`, `0x2ca2f991d0d`, `0x2ca2f99206c`, `0x2ca2f992093` — compared as
a **set of addresses and not as a count**, which is the only comparison that
would catch the same total reached at different places
(`tests/win11_corpus_analysis.rs`). Each process's own virtual address space is
assembled through the page tables recovered from the capture, and the kernel's
space is scanned as its own; the two are upstream's `vadyarascan` and `yarascan`
respectively.

**The allocation travels with the match rather than being looked up after it.**
The scan is planned from the VAD tree and from nothing else, so every match in a
process carries the allocation its first byte falls in — the range, the
protection as the kernel's own `MmProtectToValue` table names it, whether the
memory is private, and the mapped file if there is one — and a match outside
every allocation is not a row this stage can produce. All eight addresses above
are attributed to two private `PAGE_READWRITE` allocations with no file behind
them (`0x2ca2f840000-0x2ca2f93ffff` and `0x2ca2f990000-0x2ca2f99ffff`) out of
`taskhostw.exe`'s 171; 1,126 mapped regions and 17,248,256 bytes were examined,
with 0 bytes mapped-and-unreadable. A match in the kernel's space carries no
allocation and **says in words why there is none** — VADs describe a process's
user memory — and a process whose VAD tree will not walk is reported as **not
searched**, with the reason, rather than swept as one flat range: a row whose
attribution is unavailable is a row an examiner cannot act on.

The limitation that matters is stated **on the record** rather than left for the
reader to infer. **A rule's condition is evaluated against one chunk of the
address space at a time** (16 MiB by default), not against a file, and the
record says so where it is read: an individual string match is reliable and is
what the rows are, `$a and $b` fires only where both strings fall in the same
chunk, `filesize` is meaningless because there is no file and the chunk's length
is not substituted for one, and `#a > 10` counts within a chunk. A larger chunk
moves those boundaries rather than removing them. A rule that matched with none
of its own strings found produces no row — there is no address to give — and is
named separately with that reason; a chunk the engine **refused** (a 30-second
per-chunk timeout, an engine error) is counted and published beside the hits,
because a refused chunk that reads as a clean one is a false absence; and
coverage is two figures the stage never adds together — bytes that were mapped
and would not read, where evidence may have been missed, against bytes never
mapped, where nothing could have been. **And Séance ships no rules.** With no
rule set named (`SEANCE_YARA_RULES` unset) the stage reports that it **did not
run**, with that reason, because an empty match list from a scan that never had
a pattern must not render like one from a rule set that ran and matched nothing.
The same compiled rule set drives the file scanner (`plugin.detection.yara`) and
this stage — one compilation, two drivers — and there is **no dedicated screen
for it**: the
records reach `GET /api/v1/cases/:id/memory/pattern-scan` and the generic memory
record surface.

A **regular expression** drives the same plan — `SEANCE_MEMORY_REGEX` is
upstream's `regexscan` and `vadregexscan` — and the two routes are graded
against *each other* on the real capture: run in one pass over
`taskhostw.exe`, the rule `FORENSIC-W11` and the pattern `FORENSIC-W1[0-9]`
report the same eight addresses. Two engines over one plan agreeing is the
check neither engine's own tests can make, because a disagreement there would
be in the planning or the attribution rather than in either engine. A regex is
matched against **raw bytes**: it is Unicode-unaware, so a pattern written in
ASCII does not find the UTF-16 most Windows strings are stored as, and the
record says so rather than leaving an empty result to be read as an absence.

**Refused with the reason named, which is not the same as answered:**
`windows` (`tagWND`) — the walk is symbol-table-driven and reports
`Unsupported` on every image this build can profile, because no source of
win32k type information exists that the licence permits; every desktop record
carries `windows_enumerated: false` with that reason, so an absent window list
cannot read as a desktop with nothing drawn on it.

The eight rows from `kpcrs` down each have a
release-only known-answer test on the Windows 11 26200 capture
(`tests/win11_kernel_dumps.rs`; `VALIDATION.md` `MEM-DUMPS-1`). The measured
answers, because a reader should be able to check them: **8 processors**, all
three self-checks agreeing on every block, all eight idle on the Idle process;
**32,768 pool slots**, 6,965 live, 25,803 freed, 300 tags, the kernel's counter
agreeing exactly; **18 VA slots**, the kernel in slot 17 typed `MiVaDriverImages`
by the kernel's own map and the PFN database in slot 0 — a slot's index is not
its type; **38 hives** all on `HvpGetCellPaged` / `HvpReleaseCellPaged`;
**767 images**, 561 with a version, 150 whose resource section is marked
`IMAGE_SCN_MEM_DISCARDABLE` and was not read (the kernel's among them; the reader
decides from the flag alone and does not check the bytes at the directory),
and every Windows binary carrying product version 10.0.**26100** under a
kernel that states build **26200**, because 25H2 is an enablement package over
24H2 binaries — a reader comparing the two must not read it as tampering;
**14 boot-sector candidates** over 10,737,418,240 bytes with exactly one
well-formed, the GPT protective MBR at physical `0x1b5e49000` declaring
`0xFFFFFFFF` sectors (Windows writes the UEFI "or 0xFFFFFFFF" form on a 64 GiB
disk, not size-minus-one); **246 tasks**, every `Actions` blob decoding whole,
the planted `\SeanceTestBeacon` decoding to `powershell.exe -w hidden -c exit`,
author `FORENSIC-W11\analyst`, created 2026-08-06T19:04:27Z, never run — and
itself one of the two tasks reported incomplete, a paged-out value on its key;
**155 modules**, no TrueCrypt driver, list complete, no sweep. Two bounds carried
on the records rather than here: `ExpPoolBigEntriesInUse` is read at pointer
width though the kernel declares a 32-bit counter (it agreed because the
adjacent dword was zero). (The TrueCrypt sweep's positive path is graded on VeraCrypt captures, below.)

**Not answered**, in the order a case would miss them: console *output*
(`consoles`, what a command printed) and `timeliner`. Console command history
(`cmdscan`'s question) is answered on one build — see below.

`timeliner`: no memory module puts an event
on the case timeline — memory times such as a process's create and exit time
live inside the memory records (`MemoryProcessTree` and the like) and reach
neither the timeline, its CSV/JSON/SQLite exports nor the body file. The only
memory-derived route onto the timeline is indirect: a file recovered from the
memory file cache is parsed again by the disk parsers, and its own contents may
carry dated events; the recovered file itself carries no times. Memory
times are not put on the timeline.

TrueCrypt is answered on the presence
question and the sweep, graded on captures (VeraCrypt 1.26.29, one mounted AES volume, both
master keys found; VeraCrypt 1.25.9, two mounted AES volumes, all four keys found); the container
(`CRYPTO_INFO`) is decoded from the two layouts read on those captures (`VALIDATION.md` `MEM-VC-2`, `MEM-VC-3`),
so cipher, mode and which key is which are stated for those two versions and for AES; a Serpent volume, a Twofish volume, a Camellia volume, a Kuznyechik volume
and ten cascades of them were captured on both versions (`MEM-VC-3`, `MEM-VC-4`) and every master key of those twenty-eight volumes
is found, the Twofish and Camellia ones recovered from their schedules, and their containers decoded, the ids being each version's own;
TrueCrypt 7.1a is read the same way on a capture with eight volumes mounted by its own driver (`MEM-VC-5`), and VeraCrypt 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24 and 1.26.28 Beta4, with seven volumes each (`MEM-VC-6`, `MEM-VC-8`, `MEM-VC-9`, `MEM-VC-12`, `MEM-VC-13`; the driver is still named `truecrypt.sys` on the Windows 11 captures of 1.22, 1.23, 1.24-Update7 and 1.26.7 to 1.26.24, and `veracrypt.sys` on the fresh Server 2019 and 2022 installs of 1.23-Hotfix-2, 1.24 to 1.24-Update6, 1.26.14, 1.26.18 and 1.26.28 Beta4). Every TrueCrypt release from 6.0 to 7.2 (thirteen builds, eight volumes each) and VeraCrypt 1.0e, 1.0f, 1.0f-1, 1.0f-2, 1.12, 1.13, 1.14, 1.16, 1.17, 1.18, 1.19, 1.21, 1.25, 1.25.4 and 1.25.7 are read the same way (`MEM-VC-7`); a build not named in this paragraph is not recognised.
Console history: the `console_history` stage recovers the
commands typed at a console from the console host's heap, **decoded on one build only** (Windows 11
26200.6584, a layout derived in-house from a capture whose typed commands were recorded; five of five
commands returned in order, and nothing else found in that image — `VALIDATION.md` `CON-1`). It does
not read the screen buffer, so `consoles` is not answered; it has not met `OpenConsole.exe`; and on any
other build it yields nothing, which is not evidence that nothing was typed. Upstream's plugin covers
more builds through per-build tables this project does not transcribe under its clean-room rule.

---

## 7. Mobile and messaging artifacts (post-acquisition)

Given an extraction from someone else's tool, how much does each read?

| Capability | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| iOS backup (encrypted + unencrypted) | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ⚠️ |
| iOS keychain in an encrypted backup (`keychain-backup.plist`) — attributes of the items the backup keybag opens; `ThisDeviceOnly` items listed as device-bound; secrets withheld from every record and released one at a time by an audited API reveal (no UI yet) | ⚠️ | ? | ? | ? | ? | ? | ? | ? |
| Android backup (.ab) | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ⚠️ |
| SMS/MMS, call logs, contacts | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ✅ |
| WhatsApp, Telegram, Signal, Messenger | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ⚠️ |
| Instagram, Snapchat, X/Twitter, WeChat, Line, Viber, Kik, Skype | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ |
| iMessage | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ⚠️ |
| iOS Safari — bookmarks, open tabs (private flag, tab groups, per-tab back/forward history), recent web searches | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ❌ |
| iOS HealthKit samples with the recording timezone (`healthdb_secure.sqlite`; `data_type` named for step count, walking distance and flights climbed only, unit as the file records it) | ⚠️ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ |
| iOS Notes — bodies (the gzip-wrapped protobuf), folders, Recently Deleted state | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ⚠️ |
| iOS Photos albums and album membership (faces / persons counted, not decoded) | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ⚠️ |
| Installed-app inventory **with install provenance** — which package installed each app | ✅ | ? | ? | ? | ? | ? | ? | ? |
| Breadth of app coverage | ⚠️ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ |
| App-version tracking cadence | ❌ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ |
| **Declares when a parser is behind the app's schema** — the store's version checked against the range each parser was validated on (endpoints read from real files), every column resolved through a candidate map, a `ParserStaleWarning` naming the version or the unresolved field, and the rows still read | ✅ | ? | ? | ? | ? | ? | ? | ? |

**The install-provenance row is marked `?` for everyone else on purpose.** Every suite
listed inventories installed apps; what is not known from their datasheets is whether any
of them reports the package manager's `installer` attribute and distinguishes "no installer
because nothing installed it" from "no installer, and the code is in user data". On the
graded Android image that distinction is the difference between 151 packages of noise and
one finding — a rooting tool (`ANDROID-PKG-1`). Filling those columns in needs the
datasheets read, which is not a claim to make here.

The cadence row matters more than the rest combined. Cellebrite, AXIOM and
Belkasoft employ teams whose full-time job is keeping pace with app schema
changes, shipping updates every few weeks. **Séance's app parsers are correct
for the schemas they were written against and will fall behind** — and they say so rather than falling behind silently.
For a lab doing volume mobile work, that cadence — not the tick count — is the
product, and the declaration row is not a cadence: it is a declaration of being behind.
What it asserts, per parser, with the version each was validated on (every
endpoint read from a real file on this machine; no range is typed from a
document): Android SMS/MMS `mmssms.db` `user_version` 57..=67; call logs
`calllog.db` 5 and the Magnet-agent `contacts2.db` calls 1 (single
observations); contacts `contacts2.db` 1300; calendar 600; Google Keep 95;
accounts `accounts_de.db` 3 / `accounts_ce.db` 10; telephony 1703944; Chrome on
any platform `meta.version` History 20..=70, Cookies 5..=24, Web Data 77..=152,
Login Data 24..=43; Firefox `places.sqlite` 10..=82, `cookies.sqlite` 5..=16,
`formhistory.sqlite` 5 (one live profile — no reference corpus holds one);
Safari `History.db` 13..=16; iMessage `_ClientVersion` 9005..=15009; iOS
`AddressBook.sqlitedb` `_ClientVersion` 83; `applicationState.db`
`schema.version` 1; Snapchat `arroyo.db` 102 (Android and iOS, the one
cross-platform anchor) and `main.db` Friend 427; Skype
`AppSchemaVersion.SQLiteSchemaVersion` 66; Twitter per-account store 7..=59.
**Declared Unranged, with the reason on every record, because no readable real
database is held:** WhatsApp, Telegram, Signal (both real stores are SQLCipher —
the iOS one is reported *encrypted*, and no "version" is read
from its ciphertext header), Viber, Kik (the one real Kik file is the iOS Core
Data schema the Android parser does not read), LINE, WeChat, Instagram, Facebook
Messenger, the Twitter search store, and iOS `CallHistory.storedata` (Core Data
carries no numeric version). Those parsers catch drift by the column map only. A
store recording no version (`PRAGMA user_version` 0 — true of every Chromium and
Apple store measured, and of Skype's real `main.db`) is "not recorded", never
ranked as older than a range. Most ranges are single points or short spans
because one to four real stores exist per app, so a newer store warns; that is
the intended behaviour and a known limitation. The warning is a disclosure, not
a claim of missing records: a store is marked incomplete
only when a required column or table did not resolve, or when a Chromium store's
own `meta.last_compatible_version` is past the validated maximum. The Magnet 2019 agent `contacts2.db` keys `calls` on `id`,
not `_id`. Both real Twitter per-account stores keep `search_queries` in the
main `<uid>-<NN>.db` (the Pixel 3's holds 2 real rows) and the parser reads
searches only from a `<uid>-search.db` that exists in no corpus here.

**The four iOS rows** are read from the Magnet 2022
iPhone 8 GrayKey full file system (iOS 15.0, build 19A404), the only iOS evidence
on this machine, and every count was read with `sqlite3` before the parser was
written. HealthKit is ⚠️ rather than ✅ because `samples.data_type` is Apple's
private enum: three types are named (7, 8, 12 — corroborated by the value shapes
in the file, marked `asserted`), every other type carries
`data_type_name_unknown`, and `unit_strings` is empty on the device so no sample
carries a unit; workouts, sleep and category samples are counted and not decoded
(0 rows held). Not shipped, each because no held extraction contains an
instance: Voice Memos, voicemail audio and transcripts, Photos faces, the
deleted-note positive branch, note attachments. The keychain of an encrypted
backup is read (known answer `IOS-KEYCHAIN-1`): the
row above is ⚠️ because a decrypted secret is released only one item at a time
through an audited API reveal with no screen for it yet, and because the
`ThisDeviceOnly` items — 715 of 1,368 on the Hickman iOS 17 backup — are wrapped
under a hardware key no backup carries. Three of the four parsers use fixed column lists for
their main `SELECT` (Bookmarks, SafariTabs windows, BrowserState tabs, and the
HealthKit samples join), so a generation lacking one of those columns yields no
summary and no unreadable marker — a `ParserStaleWarning` on the version is all
that would say so.

---

## 8. Analysis, review and triage

| Capability | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Unified timeline across all artifacts | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Full-text index with regex | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Case-wide **byte** sweep — every object in order, UTF-8 / UTF-16LE / UTF-16BE and named single-byte code pages, hit grouping across copies, region scoping, a resume cursor, and `complete` only when nothing was capped, short or unread | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| File carving from unallocated | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Carving signature count | 361 | ? | ? | ? | ? | ? | ? | ~30 |
| SQLite deleted-record recovery | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| SQLite WAL and rollback-journal recovery | ✅ | ✅ | ✅ | ⚠️ | ❌ | ⚠️ | ✅ | ❌ |
| Interactive read-only SQL over a recovered database — run against a **staged copy**, never the evidence file; one statement, row cap and timeout stated on every answer | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| Reconstruction of partially overwritten records | ✅ | ? | ? | ❌ | ❌ | ? | ? | ❌ |
| Hash sets (known / notable, NSRL) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Project VIC / CAID / VICS 2.0 interop** | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| ML media classification (uncategorised CSAM) | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ⚠️ |
| Perceptual / PhotoDNA near-duplicate matching | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ❌ |
| Bulk feature extraction over unallocated / RAM — with the `bulk_extractor`-style **histogram** (most-common values per selector, exact counts, capped at 100,000 distinct values and disclosed when capped) | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Examiner-wellbeing safe viewer (blur/greyscale) | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ |
| Face / object recognition | ❌ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ❌ |
| LLM / agentic assisted review | ❌ | ✅ | ⚠️ | ✅ | ⚠️ | ❌ | ⚠️ | ❌ |
| YARA rules — over files, NTFS alternate data streams, registry values and unallocated space, every hit typed by **surface**; per-region entropy; base64 / gzip decode-and-rescan | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ✅ | ✅ |
| YARA over file **slack** — the per-file slack regions the NTFS, FAT, exFAT, ext4, HFS+ and APFS parsers publish, each hit naming the file and placed at its volume offset; a string crossing a region's edge is not matched there (stated) | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ✅ | ⚠️ |
| OCR over raster images (JPEG, PNG, GIF, BMP, WebP, TIFF) | ✅ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| OCR over **documents** (PDF, Office) | ❌ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| EXIF / geolocation mapping | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Email threaded into exchanges | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ |
| Connections / link-analysis graph | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ❌ | ✅ | ⚠️ |
| Entity extraction | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ⚠️ |
| Duplicate detection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Distributed / multi-node processing | ❌ | ⚠️ | ⚠️ | ✅ | ⚠️ | ❌ | ⚠️ | ⚠️ |
| Packet capture: flows, DNS | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Packet capture: TCP reassembly, HTTP transactions and bodies | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Packet capture: TLS handshake (SNI, JA3, certificates), ARP claims | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

**The unified timeline does not hold every artifact's times.** `seance_db` writes a `timeline_events` row only for
`TimelineEvent` artifacts, the MAC times of `FileEntry` artifacts and parsed
records with `subtype: "chat_message"`. Disk, phone and packet-capture parsers
that emit `TimelineEvent`s reach it; a memory capture's own times (a process's
create and exit time) do not — no memory module emits a `TimelineEvent`, see the `timeliner`
entry under "Volatility 3's Windows plugins, one by one" — and several `ParsedRecord`-only modules say
in their method statement that their times stay on the record
(`METHOD_STATEMENTS.md`, e.g. the Chromium disk cache and WebCache parsers).

**What the full-text index reaches is stated, and it is narrower than the byte
sweep.** It reads metadata for the artifacts ingest
hands to the indexer — not timeline events, which the pipeline does not re-dispatch
and which enter the index only through the re-index backfill, as metadata only —
and the first 16 MiB of file bytes for `FileEntry` / `FileContent` only — no slack,
no unallocated space. In UTF-16 it indexes ASCII, the Latin-1 letters and one
single-block alphabet per run (Greek, Cyrillic, Cyrillic Supplement/Armenian/Hebrew,
Arabic, kana) and no other script — no Latin Extended, Indic or Thai;
**CJK ideographs and Hangul stored as UTF-16 are not indexed**, by decision,
because two bytes of binary look like one of those characters too often to vouch
for. Every search response and export carries that statement (`universe`) and
names the byte sweep, which does search them. The ✅ on the full-text row is for
the index and its regex mode as they are, within that scope.

**The byte-sweep row is ✅.** The Search screen's *Byte sweep of the
evidence bytes* panel and the REPL's `/sweep` command both call the route, show
`complete` as the server states it, name every ceiling reached with its number,
continue from the cursor (a *Resume* button; a printed `--resume` token), list
short reads, read failures and bytes past a declared size, name both readings of
an endian-ambiguous hit, and print the slack sentence beside the region counts
(pinned by `ByteSweepPanel.test.tsx` and `seance_repl::sweep` tests against
fixtures in the route's shape). Slack is searched only where the NTFS, FAT,
exFAT, ext4, HFS+ and APFS parsers publish slack regions, and the answer says so. `seance_search::sweep` scans an ordered
stream of (artifact, `DataSource`) objects with an Aho-Corasick automaton,
reports every overlapping occurrence exactly once across chunk edges, bounds by
hit count and by fresh bytes with each ceiling echoed by number, returns a resume
cursor (artifact id + byte) that loses and repeats nothing and refuses a cursor
naming an object the stream lacks, lists short reads and read failures per
object, and sets `complete` only when the stream was exhausted with no ceiling,
short read or read error. Scope is by artifact type, extension, path prefix,
path glob and region (`live` / `slack` / `unallocated` / `recovered` / `raw`),
with the regions **not** searched and the objects offered per region echoed on
the result — so a scope that admits slack but was offered no slack object says
`slack: 0`. Text patterns are searched as UTF-8, UTF-16LE, UTF-16BE and any
`encoding_rs` code page named, and each hit lists every encoding its bytes are
consistent with: an ASCII hit is `utf-8` plus every ASCII-compatible code page,
because "UTF-8" alone would be an inference. **UTF-16 twins are folded, not
counted twice:** the LE and BE forms of Latin-1 text are one byte apart, so a
UTF-16 string on real evidence normally reads as the pattern under both
endiannesses; the sweep reports one hit naming both readings, marks it
`endian_ambiguous`, and counts the folded reading — a report must quote both,
never pin one. Validated on the NIST CFTT string-search image
(`VALIDATION.md`, `CFTT-SWEEP-1`): all 72 published offsets of `cities`,
`mañana` NFC and NFD and `SecretKey` found with the published encoding and
region, the whole 2,098,028,544-byte image swept `complete` with exactly 72 hits
and 29 twins folded; and on the unix image of the same data set (`CFTT-SWEEP-2`) 1,035 of 1,049 published offsets found, 452 of the 456 deleted-file rows among them, the other 14 explained row by row. **Its limits:** slack is offered
only where the NTFS, FAT, exFAT, ext4, HFS+ and APFS parsers published a slack region, so no
other file system's slack is reached, and it does no Unicode
normalisation and no case folding. It searches exactly the bytes of the form
given. The indexed keyword search is exact-form in the same way: no Unicode
normalisation of the index or the query, so an NFC term does not find NFD text
or the reverse. It finds decomposed text in the form given (`VALIDATION.md`).

**The SQL row is ✅:** `POST
/api/v1/cases/:id/sqlite/query` stages the database file and its `-wal` to a
temporary copy the way every SQLite parser in the tree does, opens it
`SQLITE_OPEN_READONLY` under an authorizer that admits reads only, runs one
statement under a row cap and a timeout the answer reports, refuses anything
else with a named code (`sql_not_single_statement`, `sql_not_readonly`,
`sql_timeout`, `not_a_sqlite_database`), and audits every run. The editor in the
SQLite viewer prints the attestation (`read_only`, `source: staged_copy`, the
timeout) only when the server sends it; sixteen query templates are each proven
against a real fixture named in the template; query history is per case and
browser-local, and says so.

**YARA reach.** Three surfaces beyond a plain file:
a `FileEntry` the `$MFT` parser marked `is_ads` (191 `[ZoneTransfer]` hits on the
204 resident streams of a real 35.8 MiB `$MFT`, every record stamped `ads` with
its stream name and base file); the value inventory of a `RegistryHive` record
(5,602 values of a real `NTUSER.DAT`, 3,569 scanned as their exact stored bytes
and 2,033 re-encoded from a rendering, the basis on every record); and
`UnallocatedSpace` regions from allocation bitmaps and partition-table gaps, each
hit placed at its device offset. Every record carries `surface` from a closed
vocabulary and a `surface_means` sentence, so a hit in free space cannot be read
as a hit in a live file. **Slack:** the `SlackSpace` regions the
NTFS, FAT, exFAT, ext4, HFS+ and APFS parsers publish are scanned as the `slack`
surface, each hit naming the file whose last cluster holds it and placed at its
volume offset — not a device offset: on a partitioned image the partition's offset must
still be added, and the scanner does not add it. Graded on DFTT #3 (`n-slack`, found once,
in `file-n-4.dat`'s slack, at the published image offset, which equals the volume offset
only because the image is a bare volume) and DFTT #2 (`3slack3`, likewise). The bound, pinned by the
same test: each region is scanned on its own, so DFTT #2's `1slack1` and `2slack2`,
which cross from a file into its slack or from slack into the next cluster, are **not**
found as slack hits; a whole-volume scan finds them, attributed to no file. Slack the
parser does not publish (an all-zero tail; a resident, compressed, encrypted or deleted
file's; a tail that could not be read in full; a live file whose run list or chain is
incomplete; regions past the 250,000-per-volume ceiling) is not scanned, and the volume's
`slack_space_summary` counts each of those it could count (`files_not_located` for the live
files whose tail it could not locate) and marks `content_incomplete` where the parser could
not look. (A carved, deleted or whole-volume artifact is stamped `carved`,
`deleted_file` or `volume`, not `file`.)

**OCR is two rows.** `seance_plugin_ocr` gates
on raster extensions and magic (`jpg`, `jpeg`, `png`, `gif`, `bmp`, `webp`,
`tif`, `tiff`) and nothing else in the tree hands a PDF page or an Office
document's images to it, so "images and documents" was half a claim.

**The packet-capture rows are not a claim to beat Wireshark, and the ❌s are
narrower than they look.** They say one thing: *none of these suites reads a
capture found inside an image as evidence in the same case as the disk and the
memory*. Each of the seven is a disk-and-mobile product whose documented
feature set contains no packet analysis at all, so a capture on the suspect's
desktop is exported and opened in a second tool, and the correlation between
"this host fetched `invoice.pdf` over HTTP" and "this file is on the disk" is
made by hand. Séance reads it in place and hands each HTTP body back into the
same pipeline, where it is hashed, type-detected, YARA-scanned and indexed
like any other file. That is graded on one real case (`VALIDATION.md` NET-4): on DFIR Madness Case 001 the implant's body read off the wire hashes
to the MD5 and SHA-256 the publisher's `autorunsc` recorded for the file on disk,
and a corpus-gated test asserts it. What the specialist network tools do that Séance does not is the
larger list: every other protocol, live capture, flow statistics, VoIP
reassembly, and a packet-level view. The comparison Séance can make is with
**NetworkMiner and Wireshark's export-objects**, not with this table's columns,
and against those two it is one capability among dozens — see
`documentation/Container_Formats.md` for exactly what is read and what is
refused.

**Project VIC / CAID interop is the most consequential feature for a law
enforcement buyer and is substantially built.** Séance imports
and exports VICS 2.0 JSON with a category-preserving round trip (REST + the
hash-sets page); every decodable image now gets an **open PDQ perceptual hash**
plus **aHash/dHash/pHash** companions (`seance_plugin_perceptual`) for cross-tool
matching against externally-supplied sets; **near-duplicate grouping ships** — images are clustered by PDQ Hamming distance and surfaced across
the API (`/near_duplicate_images`), the REPL (`/duplicates near`) and the GUI
(Duplicates page), transitively so a run of re-encodes collapses into one group;
and the gallery has an **examiner-wellbeing safe viewer** (blur/greyscale, on by
default). What still keeps the perceptual/ML rows at ⚠️, not ✅: PhotoDNA needs a
site-supplied licensed back-end (the pluggable slot exists; no network here to
add one) and the ONNX classifier needs a site-supplied model. So a CSAM unit can
load VIC/CAID sets, match exact and (via computed PDQ) near-duplicates —
grouped in the UI — and work behind a safe viewer; the remaining gap to
AXIOM/Griffeye is the licensed PhotoDNA back-end and an ML model, not algorithms.

The carving row is the one place a count is meaningful: Séance's **361**
signatures cover every format PhotoRec carves by default (351 of its 352 — the
one left out, its `dovecot` layout of 80 KiB of zeros, PhotoRec itself ships
disabled, and it is not carried here) and more. They are **not a
port** — each is written from the format's own specification with unit tests on
the signature, which is why the tree is MIT and not GPL (see
[`LICENSING.md`](../LICENSING.md)). Autopsy's default carver is far smaller. The commercial tools do
not publish counts, so `?` is the honest entry.

**Fragmented carves.** A carve that runs across the pointer blocks ext2/ext3
write in line with a file's content is rebuilt without them, once every pointer entry is
verified; DFTT #12's ten files all carve to their published MD5s (`VALIDATION.md` `DFTT-12`).
That is the only fragmentation the carver repairs: files scattered across a disk, and every
other file system's fragments, still come back as one contiguous run. PhotoRec performs a
comparable ext2/ext3 indirect-block skip; no row here claims more than that.

The number above is counted from the tree.

**What the carving row covers.** The carver is pointed at the gaps a
**partition table** leaves and at the free clusters *inside* a filesystem. Six file
systems emit free regions: **NTFS, FAT, exFAT, ext4, HFS+ and APFS** each emit one
region per run the volume's own bitmap proves free, and the carver reads them on
every ingest. NTFS reads `$Bitmap`, FAT and exFAT their allocation tables, ext4
its block bitmaps — the last graded on a real 67 GB volume. Two things this deliberately
does not claim: **slack** — the unused tail of a cluster a live file owns
— is not free space and gets no free region (it gets a `SlackSpace`
region of its own type on NTFS, FAT, exFAT, ext4, HFS+ and APFS, which the carver also reads, so no
free-space total can count it); and a bitmap that could not be read in
full leaves its tail reported as **unassessed** rather than carved, because a
zero bit means free and the alternative is reporting unallocated space nobody
looked at. The free-region ceiling (4,096 regions per volume by default) declines 37.6% of the
free space on the fragmented 67 GB ext4 volume of the Magnet 2022 Linux CTF image and nothing on
the other twelve of the thirteen held volumes measured, a sample and not every volume held
(`VALIDATION.md`); a lab raises it with
`SEANCE_FREE_REGION_CAP` and the record states the ceiling applied.

**Email threading** is a row where Séance reaches
parity rather than leads: reading a mailbox as exchanges is table stakes in every mail-review
tool. What is Séance's own is narrower — each message states **how** it was placed in the
exchange (its own thread root from `References`, its parent from `In-Reply-To`, or itself), the
pane says when a thread may be a fragment of a longer one, and a message carrying none of the
three headers is grouped into **nothing** and counted as unthreadable rather than swept into a
catch-all conversation. Subject-line grouping is deliberately not implemented: "Re: invoice" is
not evidence that two messages are the same exchange.

**Outlook 2013+ OST (format version 36) is read.** The linked PST library refuses version 36,
so Séance reads it with its own reader, validated on
that one real file — all eleven messages NIST's answer key lists for question 21 are found
with their folder, subject and time; the sender matches the key's address on the six messages
from the other party, and on the informant's own five only by display name, because those hold
no SMTP address (their `from` is an Exchange X.500 DN). This is parity, not a lead, and it is narrower
than the suites' mail modules in four named ways: an encoded store (`bCryptMethod` other
than 0) is refused by number, recipients are the display strings rather than the recipient
table's SMTP addresses, a body held only as compressed RTF is not decoded (the record says
`body_source: rtf_not_decoded` and is marked incomplete — the store's three Sync Issues logs),
and deleted mail is recovered from version 36 stores and from version 14, 15 and 23 stores (below).

**Deleted mail from a version 36 store is recovered.**
The bytes are walked again with the allocation map ignored: node B-tree pages no live tree
references still hold the entries of deleted messages, and their blocks are found by their own
trailers. On the Data Leakage OST this recovers the key's twelfth message, "It's me" (Sent
Items, 2015-03-23 20:38:47 UTC — the key's 16:38:47 local), whole, and marks it recovered from
unallocated space with its offsets. It also recovers three deleted messages the key does not
list (not graded against it) and names one deleted entry whose data was overwritten. Two
limits: a deleted message's pieces are found only within the bytes supplied (an image that never
initialised the file's tail holds none there); and a property context with no node entry is
reported as a fragment whose folder and subnodes are unknown.

**Deleted mail from a version 14, 15 or 23 store is recovered** (`seance_plugin_email::pst512`). The same method over the older 512-byte-page layouts, by a
reader of their own because the linked `outlook-pst` library exposes no scan of what the live trees
do not reference. Graded on a real Outlook 2000 mailbox (the NPS M57-Jean scenario, 258 messages)
against libpff: every live message reads as libpff reads it; with the 62 messages that have a
stale node entry removed from the live tree, 61 come back with subject, folder and attachment
count matching libpff, and the 62nd is named as an entry whose data was overwritten, not invented.
Limits, stated on the records: a deletion that left no stale node entry is not found (the block is
still named by the live block tree); the recipient table is read for versions 14, 15, 23 and 36; the one real fragment in that
mailbox turned out to be an earlier draft of a live message, so a fragment that shares its subject
and delivery time with a live message says it may be one; and **the Unicode (version 23) layout is
graded on a real 543-item mailbox against libpff; the three messages recovered from
its Deleted Items are not corroborated by libpff, whose own recovery fails on that file.**

### Automated triage

Séance
lists **20** rule-based investigative leads over artifacts its own parsers established.
The "PE carved from another file's slack" lead fires
on an executable the automatic carver recovers from a `SlackSpace` region the NTFS, FAT
or exFAT parser published, so only on those file systems, only in a live file's slack,
and only where the executable fits in what is left of one cluster (about 3.5 KiB on
4 KiB clusters), which makes it rare; and only under a profile that runs the automatic
carver (triage publishes slack but does not carve it). Because, under the volume's
current cluster size, no file starts in slack (files start on a cluster boundary), the lead
says an executable there was part of an earlier file's content or was put there
deliberately, not that it was a deleted program, and says that a volume reformatted with
larger clusters, or one that once held another file system, could leave a former file
starting there, which nothing excludes.
Its reachability is shown on a synthetic NTFS
volume, parser to finding, including a real `mkntfs` volume inside an MBR partition (`VALIDATION.md` SLACK-3); no held image carries an executable in slack, so it is not
graded on real evidence. The slack regions themselves are graded on DFTT #2 and #3
(`VALIDATION.md`). The timestomp lead subscribes to `FileEntry`, where the MFT parser writes its verdict. That path is pinned on a synthetic record and has not been
measured on a real image with a stomped file.
The list, with the slack lead's reach marked: timestamps reordered in a way no copy, move or rename produces; an Authenticode
signature whose digest is not the file's; a PE in an alternate data stream, or carved from
another file's slack (NTFS, FAT, exFAT, ext4, HFS+ and APFS slack only; not graded on real evidence); a packed section; persistence running from a directory software is
not installed into; persistence naming an image that was not recovered; a program a
prefetch file records as having been run with no file entry anywhere, or with only
deleted ones; a file Amcache records Windows as having **catalogued** with the same two
answers, kept as separate detections because Amcache records that Windows saw the file
and not that it ran; and a USN delete the MFT still describes as in use at the same
sequence number. The other leads are memory and hive leads: a pointer into an unloaded
driver, an unattributed kernel timer routine, an orphan kernel thread, a hardware
breakpoint, a patched ETW write path, a patched LSA crypto export, a registry hive whose
subkey count disagrees with its keys, a service binary not recognised in a system directory,
and a high-entropy executable. They are ranked Strong / Notable / Weak by
how much room there is for an innocent explanation, reach a triage screen and
the report's own section, and each carries its **observation** (checkable),
its **inference** (labelled as the tool's reading) and its **qualification**
(what it does not establish) as three separate things.

**Measured, not asserted.** The nine file-system and execution rules were run against the
NIST CFReDS Hacking Case (`HACK-1` in [VALIDATION.md](VALIDATION.md)): 236 leads on a
25,018-file volume, 17 of them `Notable`, and seven of those 17 name software the published answer key asks about —
Cain & Abel, Ethereal, NetStumbler, mIRC, Look@LAN among them. No comparable false-positive rate
is published for any of the suites below, so the row is a claim about *this* tool only.

Where this sits against the suites, stated without a matrix row because the
competitors' rule sets are not published in a form that can be counted: every
major suite has some automated triage — AXIOM's and Cellebrite's Insights,
Belkasoft's artifact importance, FTK's alert flags, Autopsy's Interesting Items,
EnCase's conditions and EnScript — and most of them carry **far more rules than
these**. Séance is behind on breadth and deliberately so: the
naive `$SI`/`$FN` timestomp rule at **4,054 of 25,018 files on a stock Windows
XP install**, and a triage list that fires on a sixth of a clean disk buries the
one file that matters. The count above is stated here by hand; the product's own
screens take it from `seance_api::FINDING_DETECTIONS`. What Séance does claim over them is narrower and is on
the record: the three-part shape above, and a report section that states in its
Limitations what a rule-generated claim is worth. Nothing here does ML or
LLM-assisted review, and those rows stay ❌.

---

### SQLite recovery, in detail

SQLite is the store under nearly every application on a phone, and a deleted row
in one is usually still in the file — SQLite marks the space reusable rather than
erasing it. Séance reads these databases as **raw b-trees**, with no driver and no
temporary copy, which is what makes the parts a driver hides reachable at all.

Recovery runs from six sources and each recovered row records which one it came
from: freeblock chains inside a live page, whole pages on the freelist,
record-shaped runs carved from a page's unallocated region, printable text
salvaged from slack, earlier page versions replayed from an uncheckpointed
`-wal`, and pre-images from a rollback `-journal`.

**The row that makes the ✅ on "partially overwritten" defensible.** Freeing a
cell writes a four-byte `[next][size]` freeblock header over the start of it —
landing exactly on the payload-length and rowid varints a parser needs to read
the rest. The usual outcome is that the remains decode as one undifferentiated
string. `carving.rs::recover_clobbered_columns` instead searches for the
`(skip, header-end)` alignment at which the surviving serial-type header and the
column bodies consume the region **exactly**, and accepts it only when the
decoded columns are clean: at least two non-null, at least one convincingly
textual, and no control or replacement bytes inside a text column — the signature
of an alignment that split a field mid-value. The exact-fit constraint is what
disambiguates the true alignment; where nothing fits, the region falls back to
text salvage rather than shipping a confident wrong split. A coalesced freeblock
holding two records is deliberately not attempted.

The ❓ against AXIOM, Cellebrite, X-Ways and Belkasoft on that row is honest: all
four recover deleted SQLite rows, and none of them document whether they
reconstruct a record whose leading varints were overwritten. It is not a claim
that they do not.

Every recovered row also carries a **confidence from 0 to 100**, scored down by
its recovery source (slack −35, unallocated −30, freelist −20, freeblock −15,
journal −15, WAL −10), by each corruption note attached to it, and by its null
ratio — so a slack salvage cannot present itself with the authority of a live
read. Recovered rows from the chat schemas (iMessage `chat.db`, WhatsApp on iOS
and Android, Android SMS/MMS) are threaded back into conversations and rendered
in the message viewer, each flagged as recovered; only rows that decoded into
named columns with a usable body are threaded, and nothing is synthesised to fill
a gap.

87 tests cover this parser.

---

## 9. Reporting, integrity and defensibility

| Capability | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| HTML / PDF / DOCX / XLSX / CSV / RTF / XML report output | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Timeline and communications-network **figures** baked into the generated report (HTML inline SVG, DOCX picture + data table, PDF vector; RTF/XML carry the data tables) | ✅ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| KML / GeoJSON export | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ❌ | ✅ | ⚠️ |
| Cryptographically signed reports | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ❌ |
| Declaration + statement of truth, UTC stated | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Acquisition hash recorded and re-verified | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Parent-child artifact lineage / provenance | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| **Tamper-evident audit log (HMAC hash chain)** | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Evidence grading on findings (Confirmed→Supplied) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Incompleteness declared in output | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Shipped known-answer validation suite** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| NIST CFTT / formal third-party validation | ❌ | ⚠️ | ✅ | ⚠️ | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Established court precedent | ❌ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Expert-witness / vendor testimony support | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ❌ |

**DOCX and the figures.** `render_docx` writes the
OOXML parts by hand into a deterministic ZIP (two renders are byte-identical),
renders every section HTML renders under the same condition and in the same
order from the same statement helpers, and is served at `GET
/cases/:id/export/docx`, audited like the other formats. Two bounds: the figure
is an SVG-only picture (`svgBlip`), so Word 2016+ and LibreOffice 7.4+ render it
and older Word shows an empty frame above the data table that carries the same
numbers; and Microsoft Word itself was not exercised — LibreOffice and pandoc
were. The communications figure labels each link with its exchange count only up
to 24 drawn links; above that the counts are in the Links table, and the caption
printed under the figure says which case it is.

Two rows cut in opposite directions and both matter.

**In Séance's favour:** `seance-validate` ships *in the product* and re-runs
known-answer cases against published corpora (DFTT, Windows, BitLocker, memory),
so a lab can demonstrate correct behaviour on its own hardware on the day it
testifies, rather than citing a vendor's validation of a different build. The
audit log is a hash chain that becomes **HMAC-keyed once a server secret is
configured**, and only then can entries not be silently rewritten by someone with
database access. The shipped compose file requires `SEANCE_AUDIT_HMAC_KEY`, and the
server refuses to start unkeyed on a non-loopback bind unless `SEANCE_AUDIT_UNKEYED_OK=true`
is set. The verification result carries a `tamper_evident` flag that is true only when the
chain is keyed, and `tamper_evident_from` names the entry from which it is. See
[DEPLOYMENT.md](DEPLOYMENT.md). Findings carry an evidence grade, and a
section that could not be read in full says so — a listing marked incomplete is
never presented as the whole of what the evidence held.

**Against it, decisively for some buyers:** Séance has **no court history and no
CFTT validation**, and nobody will appear as a witness to its methodology.
EnCase has two decades of admitted evidence behind it. In a contested criminal
matter that difference can outweigh every technical row above, and no amount of
engineering closes it quickly — it is earned in courtrooms, not commits.

---

## 10. Platform, interfaces and licensing

| | Séa | AXM | CB | FTK | EnC | XW | BKS | Aut |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Runs on Windows | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Runs on Linux | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Runs on macOS | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Runs on ARM64 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ |
| Web UI | ✅ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ |
| Terminal UI for a headless machine | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Desktop GUI | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Headless CLI / batch | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| REST API | ✅ | ⚠️ | ⚠️ | ✅ | ❌ | ❌ | ⚠️ | ❌ |
| Interactive REPL | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Scripting / extension API | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| Multi-user with RBAC | ✅ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| Source available / auditable | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| No dongle / hardware licence | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Licence cost | £0 | ££££ | ££££ | ££££ | ££££ | ££ | £££ | £0 |
| Vendor support, training, certification | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ |

Séance and Autopsy are the only two that run natively outside Windows. For a
lab standardised on Linux, or anyone wanting analysis on the same ARM hardware
they already run, that alone narrows the field to two. Séance is the only entry
here offering a REST API *and* a web UI *and* a CLI *and* a REPL against one
engine — it is built to be driven by a pipeline, not only by a mouse.

Licence cost is indicative only: commercial pricing is quote-based, typically
per-seat and annual, and ranges from roughly four to low five figures per seat
per year. **Séance's MIT licence is not automatically an advantage.** Zero
licence cost does not make a tool cheaper to run: the cost moves to the lab, as
validation, training, deployment and the absence of a vendor to escalate to.
What it does remove is every restriction on what the lab may do with the tool —
including building something closed on it, which a copyleft licence prevents.

---

## Summary

**Where Séance wins outright**

1. **Memory forensics.** Native Windows and Linux analysis with symbol handling
   nothing else here attempts — image-derived `kallsyms`/BTF, cross-checked
   layouts, build-variant member binding, typed holes, and published Volatility 3
   parity tests. Most competitors wrap Volatility or carve strings.
2. **Cross-platform.** Native Linux, macOS, Windows, x86-64 and ARM64 as *host*
   platforms. An ARM64 memory *image* is analysed on QEMU-captured guests only, and no
   hardware capture is validated (§6). Six of the
   seven comparators are Windows-only.
3. **Automation surface.** REST API, CLI, REPL and web UI over one engine.
4. **Defensibility mechanics.** Shipped known-answer validation, HMAC-chained
   audit log, evidence grading, and declared incompleteness.
5. **Linux/modern-Windows encryption.** Native LUKS1/2 and current-default
   BitLocker (XTS-AES-256), verified against a purpose-built corpus.
6. **SUM/UAL parsing** — the surviving authentication record in server
   intrusions, and apparently unique among the tools surveyed.
7. **Carving breadth** — 361 signatures, covering every format PhotoRec carves
   by default and more, each written from the format's specification rather than
   ported. A signature matched on a magic of four bytes or fewer checks the
   structure its header block must carry before it may end a carve already
   running, and a TIFF-style header's directory is checked where it
   lies, however far past that block. Dahua `DAD` is checked frame by frame (header checksum, footer and length, on two real
   exports), and three
   (`TXT`'s `#!`, a Zstandard skippable frame, `HDF4`) have checks that prose
   passes, so a stray magic of those four can still end a running carve; five with
   neither a layout nor a sample (`CAM`, `DIM`, `Papyrus`, `QuarkXpress`, `TIB`) may
   start a carve but never end one that is running, at the cost that a genuine file
   of theirs met inside a running carve is not recovered past where that carve stops.
8. **AES key recovery from a memory image** — key schedules verified in RAM
   (bulk_extractor's `scan_aes`), feeding the decryptors; apparently unique among
   the disk-forensics suites here.
9. **Per-process Linux capabilities** — `cred.cap_*` decoded to named
   capabilities, validated against a real capture; apparently unique here.
10. **RAID 6 double-fault recovery** (Q syndrome) and multi-PV LVM, plus a
    SquashFS reader, an examiner-wellbeing safe viewer, and PDQ perceptual
    hashing on every image.
11. **No licence cost, auditable source.**

**Where Séance loses, and by how much**

1. **No acquisition of any kind** — structural, and it means Séance can never be
   a lab's only tool.
2. **No mobile extraction and no exploit chain.** Not closable by ordinary
   engineering.
3. **CSAM triage not yet at parity.** VICS import/export, PDQ hashing on every
   image, near-duplicate grouping by PDQ distance and a wellbeing safe viewer ship;
   still missing are a licensed PhotoDNA back-end and an ONNX model, so Séance is
   short of AXIOM/Griffeye.
4. **No court precedent, no CFTT validation, no expert testimony.** May outweigh
   everything technical in contested proceedings.
5. **Password recovery still narrow.** `crack-luks` and `crack-bitlocker` ship
   (CLI, off by default), validated end-to-end against a real LUKS volume;
   iOS/Office verifiers, a UI trigger and GPU acceleration are not there yet.
6. **RAID/LVM is CLI-driven.** `assemble-raid` and `scan-raid` (virtual, in-ingest)
   reconstruct RAID 0/1/5/6 and multi-PV LVM, but RAID 5EE and Windows
   dynamic disks (LDM) are not supported.
7. **Mobile app parsers will fall behind** without a team tracking schema churn —
   they declare when they have, per store, rather than parsing
   a newer schema silently; that is a disclosure, not a cadence.
8. **No vendor support, training or certification path.**

**Honest positioning.** Séance is a strong *analysis* platform — outstanding at
memory, competitive on disk and Windows artifacts, uncommonly rigorous about
stating what it does not know — that does not acquire evidence and has no
courtroom track record. Its natural place today is alongside a commercial suite:
the deep-dive and automation tool, particularly for memory, Linux, and scripted
pipelines, running on hardware and operating systems the commercial tools will
not touch. Positioning it as a drop-in replacement for AXIOM or Cellebrite would
not survive contact with a procurement checklist, and claiming otherwise would
damage its credibility on the rows where it genuinely leads.

---

## Sources

Competitor rows were compiled in August 2026 from:

- [X-Ways Forensics feature list](https://x-ways.net/forensics/) and the
  [white paper](https://www.x-ways.net/forensics/X-Ways_Forensics_White_Paper.pdf)
- [X-Ways 21.6 release notes — BitLocker startup-key decryption](https://h11dfs.com/x-ways-forensics-v21-6-smarter-decryption-better-partition-insight-and-improved-filtering/)
- [Magnet AXIOM product page](https://www.magnetforensics.com/products/magnet-axiom/)
  and [cloud acquisition docs](https://docs.magnetforensics.com/docs/axiom/html/Content/en-us/acquire-cloud/acquiring-cloud-evidence.htm)
- [Magnet AXIOM Project VIC / CAID media categorisation](https://www.magnetforensics.com/resources/overhauling-media-categorization-in-magnet-axiom-3-0-with-new-project-vic-caid-features/)
  and [VICS certification](https://www.magnetforensics.com/blog/magnet-axiom-now-vics-certified-by-project-vic-international/)
- [Cellebrite Inseyets](https://cellebrite.com/en/products/cellebrite-inseyets/),
  [UFED](https://cellebrite.com/en/products/ufed/) and
  [Physical Analyzer](https://cellebrite.com/en/products/physical-analyzer/)
- [Exterro FTK Forensic Toolkit](https://www.exterro.com/digital-forensics-software/ftk-forensic-toolkit)
  and [ARMOUR for FTK launch, July 2026](https://www.globenewswire.com/news-release/2026/07/09/3324850/0/en/Exterro-Launches-ARMOUR-for-FTK-Forensic-Investigations-That-Start-with-a-Question-Not-a-Stack-of-Tools.html)
- [OpenText Forensic (EnCase)](https://www.opentext.com/products/forensic) and
  [EnCase 8.07 APFS/BitLocker notes](https://www.forensicfocus.com/news/enhancing-digital-investigations-with-opentext-encase-forensic-8-07/)
- [Belkasoft X](https://belkasoft.com/x),
  [mobile acquisition methods](https://belkasoft.com/mobile_acquisition) and
  [checkm8 iOS extraction](https://belkasoft.com/full_file_system_extraction_for_ios_devices_with_belkasoft_evidence_center)
- [Autopsy features](https://www.sleuthkit.org/autopsy/features.php) and
  [4.22.0 release notes](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.22.0)
- [Practitioner comparison: EnCase vs Magnet vs Cellebrite, 2026](https://teradriveforensics.ca/insights/encase-vs-magnet-vs-cellebrite-2026)
- [X-Ways and encrypted APFS — Forensic Focus forum](https://www.forensicfocus.com/forums/general/x-ways-does-not-process-apfs/)

Séance rows were established from this source tree, its test suite, and
the corpora described in [TESTING.md](TESTING.md) and [VALIDATION.md](VALIDATION.md).
