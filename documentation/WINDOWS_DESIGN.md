# Windows Forensics Extension Design

**Target:** Windows Workstations & Servers (Windows 10/11, Server 2016+)
**Architecture:** Modular Seance Plugins (implementing `ForensicsModule`)
**Status:** Partially Implemented. Shipped and registered in `seance_api::modules`: all core artifact plugins; the 36-stage native memory tier `seance_plugin_memory_windows` (crash dumps, hibernation files and pagefile attachment included); BitLocker as `seance_plugin_bitlocker`, which reports a locked volume even with no credential; autostart enumeration as `seance_plugin_asep`; NTFS security descriptors as `seance_plugin_secure_sds`; Windows Timeline as `seance_plugin_win_timeline`; Thumbcache as `seance_plugin_thumbcache`. See `documentation/MEMORY_BUILD_BINDING.md` for the memory tier's symbol-binding contract and `documentation/Container_Formats.md` for BitLocker coverage in full.

The memory tier is native. No code in the tree recovers an FVEK from RAM, and BitLocker is not unlocked from one.

This document outlines the architecture for extending Seance with comprehensive Windows forensics capabilities, targeting parity with EnCase, X-Ways, and Magnet AXIOM.

---


## 1. Core Filesystem Support

### `seance_plugin_ntfs`
*(Shipped as separate crates: `seance_plugin_mft`, `seance_plugin_logfile`, `seance_plugin_usnjrnl`, `seance_plugin_i30`, `seance_plugin_badclus`.)*
**Responsibility:** Parsing the New Technology File System (NTFS).
- **Subscribes To:** `ArtifactType::FileSystem`, plus `FileEntry` and `RawEvidence` so a
  `$MFT` lifted out of a tree or handed over loose is read on the same terms. (An `ArtifactType::Partition` artifact is never handed to
  any file-system module in this product.)
- **Input Capability:** `InputCapability::RandomAccess`
- **Output:** `ArtifactType::FileEntry`
- **Features:**
    - **MFT Parsing:** Parse `$MFT` records (Standard Information, File Name, Data runs).
    - **Resident Data:** Extract small files directly from MFT records.
    - **Non-Resident Data:** Parse Data Runs to read file content from disk.
    - **ADS:** Identify and extract Alternate Data Streams.
    - **Both halves of the file reference, on every entry**. A file entry carries
      `record_number` **and** `sequence_number`. NTFS frees a record on delete and increments
      the sequence when it is reused, so a reference naming record 4,712 means nothing without
      the sequence: the reader read it and published only the record number, which left
      nothing downstream able to tell "this is still that file" from "that record now holds a
      different one". That is what the USN-vs-MFT cross-view needs — a journal delete against
      a live record at the **same** sequence is one file described two ways, and against a
      different sequence is the ordinary recycling of a slot.
    - **Deleted Recovery:** Parse unallocated MFT records for deleted file recovery.
    - **File slack as its own region**. On a volume (a `FileSystem`
      input) the parser emits one `ArtifactType::SlackSpace` per live file whose slack holds
      any non-zero byte: the window from the file's logical end to the end of the cluster that
      holds its last byte, computed by `seance_core::slack::slack_window` from the unnamed
      `$DATA`'s **allocation** runs and read once to test for zeros. It is parented to the
      `FileSystem` (so the content resolver rebuilds it like a free region, from
      `offset_bytes`/`size_bytes` in the volume's coordinates) and names its owner —
      `parent_file`, `parent_path`, `owner_artifact_id` — with a `slack_means` sentence saying
      the bytes are allocated, not free space, and not the file's content. Only an in-use,
      non-directory, non-resident, uncompressed, unencrypted `$DATA` whose run list is complete
      from VCN 0 is offered; a deleted file's clusters are not proven to be its own. An
      all-zero tail is counted, not emitted; a tail that reads short is counted as unreadable;
      past 250,000 regions a volume the rest are counted and not read. A live file with a tail
      that is not offered because its runs are compressed, encrypted, incomplete or shorter than
      its size is counted as `files_not_located`, so fragmented files are not read as files
      without slack. One
      `slack_space_summary` record per volume carries every count and a statement, even when no
      region was emitted. A separate type rather than a tagged `UnallocatedSpace` means no
      free-space total can count slack by accident (`slack_regions_are_never_unallocated_space`).
      Clusters allocated past the one holding the last byte (a preallocated tail) are not in
      the window. **Graded on DFTT #3:** the region for `file-n-4.dat` covers the published
      `n-slack` at image offset 4,128,229 and no other region does
      (`seance_tests::slack_dftt_tests`). The automatic carver carves these regions
      (`plugin.recovery.unallocated_carver`), the byte sweep offers them as `slack`, and YARA
      scans them as its `slack` surface (§2.3, graded on DFTT #2 and #3).
    - **Paths, checked hop by hop:** a `$FILE_NAME` parent reference is a record number and
      a sequence number, and both are honoured. A hop whose record is missing, holds a
      different sequence (the directory was deleted and its slot reused), or is not a
      directory ends the walk: the file is filed under `/$OrphanFiles/` with `orphan_reason`
      (`parent_record_missing`, `parent_record_reused`, `parent_not_a_directory`,
      `parent_chain_cycle`). Following the record number alone put 1,419 deleted files on
      the NIST Data Leakage image under a `.lnk`.
    - **`$BadClus:$Bad` — the bad-cluster map**. `$Bad` has an
      initialized size of zero on every real volume, so its `data_runs` — the stream's
      *logical* extent, which is what is hashed and served — is one sparse run the length of
      the volume with every bad-cluster run dropped, which alone would leave
      `seance_plugin_badclus` reporting nothing on any volume. The MFT
      parser also publishes, on record 8's `$Bad` only, the attribute's raw allocated runs
      as `bad_cluster_runs` (with `bad_cluster_runs_complete`) and the volume's
      `cluster_size`; `data_runs` keeps its contract, so no resolver serves never-written
      clusters as the stream's content. The module reads `bad_cluster_runs`, reports each
      non-sparse run as a `badclus_range` with its LCNs, and publishes a `badclus_status`
      record with `inventory_incomplete` when the producer said the run list is not whole.
      The target is exactly the `$BadClus:$Bad` stream (the whole name, or a
      path's last component) — a user's `$Badger.txt` is not read as the
      map — and a target that arrives with no run list publishes a `badclus_status` record
      (`run_list_absent: true`, `inventory_incomplete` with reason `unresolved_structure`)
      rather than an empty result that read as "no bad clusters". Graded through the producer on dfir_ntfs's real `ntfs_index.raw.gz`, unmodified (no
      bad cluster) and with two clusters marked bad by rewriting `$Bad`'s mapping pairs the
      way `chkdsk /r` does; no volume on which Windows itself marked a cluster bad is held.
    - **A bare `$MFT` serves no non-resident content**. Handed an
      `$MFT` with no volume beneath it, applying each non-resident stream's
      cluster runs to the `$MFT` file itself would serve other MFT records as content
      (`$Secure:$SDS` in the real `HD001_MFT.dat` would be "served" 272,848 bytes of them),
      so every non-resident stream (and
      every `$I30` index) from a bare `$MFT` carries its run list and **no data source**,
      stamped `content_incomplete` with reason `volume_not_in_evidence`; resident content is
      still served. Still open: the API content resolver applies a published `data_runs` to
      whatever the parent chain resolves to, and for a bare `$MFT` that is the `$MFT` file,
      so a re-serve (download, hex view) serves the `$MFT`'s own bytes until the resolver refuses
      that reason.
    - **Memory is bounded by the work in flight, not by the volume**. Three
      things the parse could hold until it returned are not held. (1) Timeline events, 8 of
      every 9 artifacts the parse makes and ~2.5 KB of heap each, leave through the module's
      streaming sink (`ForensicsModule::process_streaming`, `documentation/CORE_DESIGN.md`
      §3.1) in batches of 16,384 and are persisted as they go; the returned set is the file
      entries and the rest, and a run with no sink (`process`) returns them all as before.
      (2) An LZNT1-compressed `$DATA` (a malformed token fails the stream, never a partial decode) is still reconstructed at parse time, so that a corrupt
      one is stamped `content_incomplete` when the record is made and not found later by a
      reader; but content of 16 KiB or more is held in a temporary file
      (`seance_core::spilled_source`, removed when the last reference drops) rather than on the
      heap. One real volume held 3.9 GB of reconstructed content after 147,712 records.
      (3) A bare `$MFT` parse for a comparison (`volume_mft::parse_bare_mft_each`) hands each
      file entry to the caller as it is made and keeps none.
      The temporary files go where `TMPDIR` points: a host whose `/tmp` is RAM-backed should
      point `TMPDIR` at disk for a large ingest (`documentation/DEPLOYMENT.md`).
    - **A volume's records come from its `$MFT`, read through the table's own runs**. Handed an NTFS volume, the parser does not step the volume window
      looking for `FILE` signatures, which would publish `$MFTMirr`'s copies of records 0-3
      a second time (dfir_ntfs `ntfs_index`: 62 entries for 58 records) and, on dfir_ntfs's
      Server 2003 shadow-copy volume, 405 entries for 87 records, with record 77 — deleted
      at sequence 2 in the real table — coming back as a live file from an older copy in a
      diff-area block. The boot sector's `$MFT` cluster
      gives record 0, record 0's `$DATA` run list gives the table
      (`seance_plugin_mft::volume_mft`), and the table is the only thing read: record numbers
      are table slots, `mft_offset` is the volume offset the runs put the record at, and a
      `FILE` block anywhere else on the volume is not read. When the table's record 0 is torn
      the `$MFTMirr` copy stands in and the `mft_parse_summary` says `mft_record0_source:
      mftmirr_record_0`; a run list known to be short is `mft_runs_complete: false` with the
      unreached slots counted; a volume whose `$MFT` cannot be located is `mft_located: false`
      with the reason, and no record — there is no signature-scan fallback. Recovering `FILE`
      records from outside the table (free space, slack, diff areas) was never a documented
      capability and is not one; the VSS module publishes a shadow copy's own differing
      records. Pinned by `seance_plugin_mft/tests/real_volume_mft_test.rs` (gated on
      `SEANCE_VSS_CORPUS`) and the synthetic stray-record tests in `seance_plugin_mft/src/tests.rs`.
    - **NTFS 3.0 (Windows 2000) record headers carry no record number**. The record number at header offset 0x2C exists only in NTFS 3.1 records;
      a 3.0 header starts its update sequence array at 0x2A, so 0x2C is the first sector-end
      fixup word. Read unconditionally, a real Windows 2000 record (the
      NIST CFReDS basic-memory `boomer-win2k` capture, physical 0x53ED000) would be
      numbered 4,423 from its fixup bytes `47 11`. `parse_header` reads 0x2C
      only when the USA offset is 0x30 or later (the same test the memory `$MFT` sweeper
      uses) and otherwise reports no number. Consequences: from a bare `$MFT` a 3.0 record is
      numbered by its slot and carries `record_number_source: slot` (3.1 records keep their
      header numbers and carry no such key); on a volume nothing changes (records are slots),
      except that no `header_record_number` is set for a header that has none. An
      `$ATTRIBUTE_LIST` extension record is also checked by its **base reference** —
      the low 48 bits must name the file that listed it — on both versions; on 3.0 that is
      the only link, where a header-number comparison would reject every 3.0 extension
      record. On the NIST Hacking Case XP `$MFT` all 132
      extension references pass the check. Pinned by synthetic 3.0 records in
      `seance_plugin_mft/src/tests.rs` and a header known answer from the real Windows 2000
      memory capture in `mft_structs.rs`, and graded on a real Windows 2000 Professional SP3
      volume (`win2000_ntfs30_metadata`, a metadata-only sparse raw) in
      `seance_plugin_mft/tests/real_win2000_ntfs30_test.rs`, with The Sleuth Kit 4.12.1 as the
      second tool. The volume holds no file content and no non-resident `$ATTRIBUTE_LIST`, so
      neither is graded.
    - **`security_id` on every file entry**. The 72-byte NTFS 3.x
      `$STANDARD_INFORMATION` carries at 0x34 the key into `$Secure:$SDS`; the MFT parser now
      publishes it, as found (0 included, which is no key). On dfir_ntfs's `ntfs_index` volume
      every non-zero id resolves to a descriptor decoded from the same volume's `$SDS`.
      The web UI's file page performs the join (below, `$Secure:$SDS`).
    - **System Files:** Parse `$LogFile` (Journal), `$UsnJrnl` (Change Journal), `$Bitmap`, and
      `$Boot`.
    - **`$Boot` — the volume's own account of its geometry.** One `NtfsBootSector` record per
      NTFS volume: the full BPB, the two derived record sizes, and the volume serial in **three
      labelled forms** (`hex` as `fsstat` prints it, `short` as Windows `vol` prints it, and the
      raw `u64`) because an unlabelled "serial" invites a reader to compare the wrong one.
      Verified field by field against `~/forensic_corpora/alihadi_ntfs/NTFS-HiddenFiles.E01`
      and cross-checked against `fsstat`: 512-byte sectors, 8 sectors per cluster, 198,655
      sectors, `$MFT` at cluster 8,277, MFT records 1,024 bytes, index records 4,096.
      **The signed record-size bytes** at `0x40` and `0x44` are resolved properly — negative
      `n` is `1 << -n` bytes, positive `n` is `n` clusters — with the shift bounded, because a
      hostile `0x80` is −128 and `1 << 128` panics under `overflow-checks`, unwinding
      `process()` and losing every file in the table rather than one field. A byte this build
      cannot resolve yields **no** record size rather than a default: the default would be a
      guess about the volume.
      **The backup boot sector** is compared when it is reachable, and when it is not the record
      says `backup_boot_sector_assessed: false` with `unmapped` — **never** `matches: false`,
      which would read as a tampered volume on the strength of a short read.
      **The checksum at `0x50` is not validated** and says so: real NTFS leaves it zero, so
      "valid" would describe a value nobody writes.
    - **Directory indexes:** `seance_plugin_i30` walks every `$I30` INDX buffer, live entries
      and slack, emitting one `NtfsIndexEntry` record per entry (name, file reference,
      parent, sizes, MACB, `from_slack`, `fixup_verified`) and an `I30ScanStatus` record for
      the buffers it could not read, verify or walk. These are the largest record type on a
      Windows image (225,745 on Case 001).
      **Slack recovery**. The slack is the record's free space —
      from `0x18 + IndexLength` to `0x18 + AllocatedSize` — where a deleted entry survives
      after NTFS shifts the remaining entries down over it. It scans the whole free space for `$FILE_NAME` shapes whose four
      FILETIMEs all fall in 1980–2108, and reads the deleted entry's file reference from the
      stale index-entry header in front of it where that header survives (else the reference
      is published empty, never a `0-0` placeholder). Graded on dfir_ntfs's real
      `ntfs_index.raw.gz`, walked through the MFT parser as the pipeline walks it: the
      deleted `BBBBBBBBBBBBB-del.txt` is recovered from `test_dir`'s index — exactly the
      three names dfir_ntfs's own carver finds in that buffer, two of them stale copies of a
      live entry — and its reference is empty because NTFS wrote the new
      end-of-index marker over its header. The scan states its bounds: NTFS's
      update-sequence stride is 512 bytes on every volume, so the record size is
      `(count − 1) × 512` and there is no 4,096-byte candidate; a read error mid-stream stops
      the scan as `indx_read_failed`; a buffer read whole but not walkable is counted
      (`buffers_unparsed`); and `I30ScanStatus` carries the shared `content_incomplete` and
      `inventory_incomplete` pairs with `_detail`.
      **A stale copy is not a deleted name**. Every slack entry
      carries `slack_status`, set against the live entries of the same stream:
      `copy_of_live_entry` (same file reference and name live — `stale_copy_of_live_entry:
      true`), `reference_live_under_other_name` (an old name of a file still here),
      `live_name_reference_unknown` (reference overwritten, name live — claimed as neither,
      `stale_copy_of_live_entry: null`) or `no_live_entry` (a candidate deleted name). On
      `ntfs_index.raw.gz` the two `AAAAAAAAAAA.txt` copies in `test_dir`'s slack are labelled
      copies and `BBBBBBBBBBBBB-del.txt` `no_live_entry`. The comparison cannot see the
      directory's resident `$INDEX_ROOT` or a buffer that was not read, so `no_live_entry`
      means "not live in what was decoded", not "deleted".
      **An index with no volume is unread, not skipped**. A `$I30`
      stream from a bare `$MFT` has no data source; it yields one
      `I30ScanStatus` with `read_incomplete: volume_not_in_evidence` (or `no_data_source`),
      the directory's `parent_file`, and both shared pairs with reason `unresolved_structure`.
      Graded on the same volume's `$MFT` cut out on its own.
    - **Timestamp indicators, graded:** every file record carries the $SI/$FN
      comparison as `timestamp_indicators`, each entry marked **strong** or
      **weak** and, when weak, naming the ordinary operation that also produces
      it. Only a strong indicator sets `timestomp_suspected`. Two are strong:
      the bulk-set signal — all four $SI values identical to the second against
      a differing $FN Created — which no copy, move or rename produces; and a
      **whole-second $SI ChangeTime older than a sub-second $FN Created**. The
      filesystem writes the ChangeTime itself, at full precision, on every
      change to the record, and writing the name entry is such a change; a
      whole-second value older than the record's own name was set by a tool.
      Restore semantics (AppX deployment, WinSxS servicing, the driver store)
      do carry an older ChangeTime across, at full precision: on the two
      Windows images of DFIR Madness Case 001, 4,231 files carry an older
      ChangeTime and exactly one carries it whole-second — `Beth_Secret.txt`,
      the file the answer key names as timestomped; 0 of 84,674 on the NIST
      Data Leakage image. `SI Modified < FN Created` is what a
      **copy** looks like, `SI Created < FN Created` is what a **move or
      rename** looks like (every file in `\RECYCLER` carries it), and a
      whole-second $SI Created against a sub-second $FN is what a copy from a
      **FAT** volume looks like; each is reported and none of them asserts
      tampering on its own. Treating them as verdicts flagged 16% of a stock
      Windows XP install. The rule lives in
      `seance_core::ntfs_timestamps` and the memory MFT sweep
      (`seance_plugin_memory_windows::mftscan`) applies the same one: its
      `timestomp_candidates` count and per-record `timestomp_suspected` are
      not the bare `SI Created < FN Created` test, which flagged
      57% of the records in the Case 001 domain controller's memory.
      **The investigative lead is built on the verdict.** `plugin.findings.timestomp` subscribes to
      `FileEntry` and reads `timestomp_suspected`, which the MFT parser writes
      there. Only a strong indicator raises a finding. The timeline event
      carries the field inside `full_details`, and the memory sweep nests it per
      record inside one stage record, so neither feeds the lead.
    - **Memory-recovered MFT records are placed, not just named.** A pool sweep
      finds records scattered rather than a directory tree, so each recovered
      record is chained to the volume root through the other records the sweep
      found, and carries `path` with `path_complete`. Only reaching
      record 5 sets `path_complete`; a parent the sweep did not recover gives
      the known tail and a note naming where the trail stops, and a parent whose
      **sequence no longer matches** the one the child recorded stops the walk —
      that slot holds a different file now, and continuing would build this
      file's path out of another file's ancestry.

### NTFS security descriptors (`$Secure:$SDS`)

`seance_plugin_secure_sds` (`plugin.windows.secure_sds`) decodes the volume-wide
store of security descriptors. NTFS 3.0 keeps one copy of each distinct
descriptor in the `$SDS` stream of `$Secure`, MFT record 9. Each file's
`$STANDARD_INFORMATION` holds a 4-byte `security_id` at offset 0x34. The MFT
parser publishes it on the `FileEntry`. A 48-byte NTFS 1.x record has no id and
publishes none.

**What is read.** The module takes the `$SDS` stream entry that the MFT parser
emits, or a hand-extracted stream named `$SDS`, `$Secure:$SDS`, `$Secure_$SDS`
or `$Secure.$SDS`. A `$SDS` alternate stream on any other file is left alone.
It reads at most 64 MiB, walks the stream in 16-byte steps and emits one
`NtfsSecurityDescriptor` record per unique `security_id`, plus one
`NtfsSecurityDescriptorStore` record that describes the scan.

**Entry header, 20 bytes, little-endian**

| Offset | Size | Field | Meaning |
|--------|------|-------|---------|
| 0x00 | 4 | `hash` | Descriptor hash as indexed by `$SDH`. Published as read. |
| 0x04 | 4 | `security_id` | The id `$STANDARD_INFORMATION` carries. 0 is never assigned. |
| 0x08 | 8 | `declared_offset` | Offset the header gives for itself. |
| 0x10 | 4 | `entry_size` | Header plus descriptor, before padding. |
| 0x14 | `entry_size - 20` | descriptor | Self-relative `SECURITY_DESCRIPTOR`. |

Entries start on 16-byte boundaries. A header with `security_id` 0 or
`entry_size` of 20 or less is padding. A header above 65,536 bytes is refused
and counted. `$SDS` is written in 256 KiB blocks and each descriptor is
mirrored 0x40000 bytes from its primary. An entry never crosses a block
boundary, so the scan steps over padding and resumes in the next block. The
first copy of an id wins and later copies count as `duplicate_copies`. A
`declared_offset` that matches neither the entry's offset nor the offset one
block away sets `sds_offset_mismatch`. When a primary will not decode, or runs
past the end of the stream, the copy one block either side is tried. It is used
only when hash, id and size all match, and the record is labelled
`recovered_from_mirror` with the primary's offset and error.

**Descriptor.** The 20-byte header holds revision at 0x00, which must be 1,
control at 0x02, which must include `SE_SELF_RELATIVE` 0x8000, then the owner,
group, SACL and DACL offsets at 0x04, 0x08, 0x0C and 0x10. Offset 0 means none. Owner,
group and each ACL decode separately, so a corrupt DACL does not discard a good
owner. A failed part sets `descriptor_partial` and its own error. A SID is
revision 1 with at most 15 sub-authorities, a big-endian 48-bit authority and
little-endian 32-bit sub-authorities. A SID that runs past its buffer is
rejected and never shortened.

An ACL has an 8-byte header of revision, size and ACE count. Each ACE has a
4-byte header of type, flags and size, and the walk advances by the declared ACE
size only. An ACL holds at most 4,096 ACEs. A shortfall against the declared
count sets `dacl_truncated` or `sacl_truncated` with a reason. Each ACL has one
of four states, published as `dacl_state` and `sacl_state`:

| State | Meaning |
|-------|---------|
| `absent` | Present bit clear. For a DACL, every principal has full access. |
| `null` | Present bit set, offset 0. For a DACL, every principal has full access. |
| `present` | Decoded. A present DACL with zero ACEs grants nobody anything. |
| `unreadable` | Attached but undecodable. Access is unknown. |

**ACE types.** Basic ACEs hold a mask and then the trustee SID: 0x00 allowed,
0x01 denied, 0x02 audit, 0x03 alarm, 0x09 and 0x0A allowed and denied callback,
0x0D and 0x0E audit and alarm callback, 0x11 mandatory label, 0x12 resource
attribute, 0x13 scoped policy, 0x14 process trust label, 0x15 access filter.
Object ACEs hold a mask, `object_flags`, a 16-byte GUID for each of flags 0x1
and 0x2, then the SID: 0x05 to 0x08, 0x0B, 0x0C, 0x0F, 0x10. The GUIDs are
stepped over and not published. Type 0x04, the compound ACE, is named and not
modelled. It and any undefined type publish type, flags and mask with no
trustee and an `ace_error`. Each ACE carries an `effect` of `allow`, `deny`,
`audit`, `alarm`, `mandatory_label`, `resource_attribute`, `scoped_policy`,
`process_trust_label`, `access_filter` or `unknown`. Raw type, flags and mask
always sit beside their names.

ACE flags named: 0x01 `OBJECT_INHERIT`, 0x02 `CONTAINER_INHERIT`, 0x04
`NO_PROPAGATE_INHERIT`, 0x08 `INHERIT_ONLY`, 0x10 `INHERITED`, 0x40
`SUCCESSFUL_ACCESS`, 0x80 `FAILED_ACCESS`. An `INHERIT_ONLY` ACE grants nothing
on the object that carries it. An `INHERITED` ACE is in force.

**Access masks.** The low 16 bits are object-specific, so the decoder is told
it is reading a file. A mask that matches a composite exactly takes its name.
Any other mask is spelled out bit by bit, with the hex appended and any bit
without a name reported as unnamed.

| Mask | Name |
|------|------|
| 0x001F01FF | Full Control |
| 0x001301BF | Modify |
| 0x001200A9 | Read & Execute |
| 0x00120089 | Read |
| 0x00120116 | Write |
| 0x10000000 | Full Control (generic) |

Single bits: 0x1 Read Data or List Directory, 0x2 Write Data or Create File, 0x4
Append Data or Create Subdirectory, 0x8 Read Extended Attributes, 0x10 Write
Extended Attributes, 0x20 Execute or Traverse, 0x40 Delete Child, 0x80 Read
Attributes, 0x100 Write Attributes, 0x10000 Delete, 0x20000 Read Permissions,
0x40000 Change Permissions, 0x80000 Take Ownership, 0x100000 Synchronize,
0x1000000 Access System Security, 0x2000000 Maximum Allowed, and the generic
bits 0x10000000 All, 0x20000000 Execute, 0x40000000 Write, 0x80000000 Read.

The mask of a mandatory label ACE is a policy and not an access right. Its bits
0x1, 0x2 and 0x4 read `NO_WRITE_UP`, `NO_READ_UP` and `NO_EXECUTE_UP`.
`integrity_level` comes from the first label ACE in the SACL whose trustee is
`S-1-16-n`: 0x0000 Untrusted, 0x1000 Low, 0x2000 Medium, 0x2100 Medium Plus,
0x3000 High, 0x4000 System, 0x5000 Protected Process, 0x7000 Secure Process. No
label means no `integrity_level`. It does not mean Medium.

**Well-known SIDs.** A SID is named only from fixed tables. Examples:
`S-1-1-0` Everyone, `S-1-3-0` Creator Owner, `S-1-5-11` Authenticated Users,
`S-1-5-18` Local System, `S-1-5-19` Local Service, `S-1-5-20` Network Service,
`S-1-5-32-544` Administrators, `S-1-5-32-545` Users, `S-1-5-32-551` Backup
Operators, `S-1-5-80-0` All Services, `S-1-15-2-1` All Application Packages.
The tables also hold the other universal, NT-authority and BUILTIN SIDs through
`S-1-5-32-582`, and the `S-1-16-n` integrity levels. A domain or machine SID
`S-1-5-21-<domain>-<rid>` is named by its relative id alone when the id is
below 1000: 500 Administrator, 501 Guest, 502 krbtgt, 512 Domain Admins, 513
Domain Users, 515 Domain Computers, 516 Domain Controllers, 518 Schema Admins,
519 Enterprise Admins, and the other reserved ids. The result reads `Domain
Users (RID 513)`. An id of 1000 or above is an account whose name lives in the
SAM. It stays a bare SID with no `owner_name`. An absent `owner_name` means not
in the table. It does not mean an unknown user.

**What a record carries.** `NtfsSecurityDescriptor` holds `security_id`,
`descriptor_hash`, the found and declared stream offsets, `entry_size`,
`recovered_from_mirror`, the control word as number, hex and names, owner and
group SID with name, `dacl` and `sacl` as ACE arrays with state, revision and
counts, `dacl_protected`, `sacl_protected`, `no_dacl_full_access`,
`integrity_level`, `descriptor_partial` and a `permission_summary` line that
names at most 12 ACEs. An undecodable entry still produces a record with
`security_id` and `security_descriptor_error`, so the id reads as unresolvable
and does not vanish. A descriptor has no timestamp, so no timeline event is
produced.

`NtfsSecurityDescriptorStore` holds the stream size, bytes scanned and the
counts of unique ids, duplicates, mirror recoveries, undecodable descriptors and
refused headers. The listing is capped at 1,000,000 entries. A short read, a cap
or a refused header sets `store_listing_incomplete` and the shared
`inventory_incomplete` pair. A stream with no data source, as a bare `$MFT`
gives, produces the store record stamped unread.

Only the web UI file page joins a file's `security_id` to a descriptor, and it
matches only within the volume or bare `$MFT` both came from, because ids on
two volumes are unrelated. No record, report, export or REPL command carries
the join.

**What is not read.** `$SII` and `$SDH` are not read. The `$SDS` header already
holds the id, so a linear scan builds the id-to-descriptor map without decoding
the index B-trees. The volume's own index is therefore never used to find or
check an entry. The hash is published from the header and never recomputed, so a
body that no longer matches its hash is not detected. A mirror whose primary
decodes is discarded unread, so a mirror that disagrees is not seen. Local and
domain account names are not resolved. A callback ACE's condition, an object
ACE's GUIDs, a resource attribute's data and a scoped policy's id are not
decoded.

### `seance_plugin_vss`
**Responsibility:** Volume Shadow Copy Service (VSS) analysis.
- **Subscribes To:** `ArtifactType::FileSystem` and `ArtifactType::RawEvidence`.
- **Output:** one `VssSnapshot` `ParsedRecord` per store entry (with the snapshot's bytes as
  its data source where the store could be reconstructed) and a `VssCatalogStatus` record.
- **Prior versions:** the live volume's `$MFT` and each rebuilt
  snapshot's `$MFT` are parsed by the MFT module's own code (`seance_plugin_mft::volume_mft`, a
  bare-`$MFT` parse), and every snapshot record that differs from the live record at the same
  record number — sequence number, in-use flag, name, parent path, size, any `$SI`/`$FN`
  timestamp, or absent from live — is published as a `VssPriorVersion` `ParsedRecord` parented to
  its `VssSnapshot`. Each carries `vss_snapshot_id`, `vss_creation_time`, `vss_stack_position`,
  `record_number`, `differences` (`{field, live, snapshot}`), a `snapshot_label` that begins
  "SHADOW COPY VERSION, not the live volume", and the snapshot record's `data_runs`; because the
  record's parent is the snapshot, the content resolver rebuilds the snapshot stream first and the
  runs resolve against it, never against the live volume. It is deliberately not a `FileEntry`, so
  it never joins the live file tree or the timeline. Each snapshot record carries a
  `prior_versions` summary (`compared` with counts, or `not_compared` with the reason). Caps:
  1,048,576 records compared per `$MFT`, 10,000 prior versions per snapshot, either stated on the
  snapshot record as `inventory_incomplete` / `cap_reached`. Graded in `VALIDATION.md` (VSS-1).
  Memory: the live side is held as the JSON of only the fields a comparison reads
  (the 13 compared fields, `deleted` and `path`) in one string per record, not as the MFT
  module's full metadata document — 3.9 GB for one real volume's files — and each snapshot's
  `$MFT` is walked and compared as it is parsed, not collected. The 10,000-record cap keeps the
  differing records with the lowest record numbers, as it did when the set was sorted, by holding
  at most 10,000 candidates.
- **Content parsers read prior versions:** a `VssPriorVersion` carries its
  snapshot's content, and twenty parsers now open it — the generic SQLite parser, the registry, event-log,
  shortcut and prefetch parsers, the jump-list parser, the Recycle Bin and `setupapi` parsers, and the thumbnail-cache, SRUM, WebCache, Windows Search index, Amcache, ShellBags, Shimcache, BITS queue,
  User Access Logging, Windows Timeline and WLAN profile parsers, and the browser-history parser — by subscribing to `ParsedRecord` through
  `seance_core::shadow_copy::parse_with_shadow_copy`. A `ParsedRecord` that is not a prior version returns
  before its data is touched. Everything such a parser produces repeats `is_snapshot_version`,
  `snapshot_label`, `vss_snapshot_id`, `vss_creation_time` and `vss_stack_position`, and states that the
  version's sidecars (`-wal`, transaction logs) were not searched; a timeline event's short description
  begins `[shadow copy <time>]`, so a past hive's key-write events cannot read as the live volume's. A
  parser that selects by name reads the version's `file_name`, because its `name` is
  `<file> [shadow copy <time>]`; the WebCache and Search index parsers use `file_name` to decide whether a
  failure is reported. The file-content analysers and the structural file-system parsers do not read prior versions, by decision: a prior version is one file's bytes, not a volume, and a content analyser reads the live copy of the same file.
- **What it does not do:** a snapshot is **not walked as a file system**. Nothing reads a
  snapshot's `$I30`, `$UsnJrnl`, `$LogFile` or unallocated space, and a file unchanged since the
  snapshot has no record of its own (the live `FileEntry` stands for it). The full walk — each
  rebuilt snapshot a child `FileSystem` walked by every NTFS module with its provenance — stays
  open as an opt-in, because N snapshots cost N walks. The store builder's
  diff-area and bitmap reads loop through `read_exact_or_fail`, graded on the `dfir_ntfs` Windows
  10 and Server 2003 images through a 4 KiB-per-call source
  (`seance_plugin_vss/tests/real_vss_test.rs`, run with `SEANCE_VSS_CORPUS` pointing at the
  extracted raws).

---

## 2. System Configuration & Registry

### `seance_plugin_fat`
**Responsibility:** Parsing FAT12/16/32 and exFAT volumes.
- **Subscribes To:** `ArtifactType::FileSystem`, gated on `subtype()` being one of
  `fat32`, `fat16`, `fat12`, `exfat` or `fat`. **`filesystem_type` is never read by this
  module**.
- **Output:** `ArtifactType::FileEntry`, one `ArtifactType::ParsedRecord` for the
  allocation map (and a `fat_volume_walk` / `exfat_volume_walk` record where the walk
  fell back), one `ArtifactType::UnallocatedSpace` per run of free clusters (§5.4), and
  one `ArtifactType::SlackSpace` per live file whose last cluster's tail holds any non-zero
  byte, with one `slack_space_summary` record per volume (the same rules as the
  NTFS producer above, built from the persisted cluster runs). A **deleted** entry offers no
  slack: its contiguous chain is a guess, not a proven allocation. Neither does an exFAT file
  whose `ValidDataLength` is short of its `DataLength`, whose persisted runs end in a sparse
  run. **Graded on DFTT #2:** `3slack3` lies inside `file4.dat`'s region, `file2.dat`'s region
  begins inside `1slack1` and `file3.dat`'s ends inside `2slack2`, each at the published sector
  and offset (the image's table names `file1.dat` for `1slack1`, but the sector it gives is
  `file2.dat`'s by the same table's row 2, and `file1.dat` fills its cluster).
- **Deleted files, FAT:** a directory entry whose first name byte is `0xE5` is recovered as
  deleted, its first character rendered `_` as The Sleuth Kit does; the NIST DFR set's FAT
  scenarios recover every deleted file the layout key names.
- **Deleted files, exFAT:** an entry set whose InUse bits are cleared (`0x05` / `0x40` / `0x41`)
  is recovered whole — name, size, timestamps, first cluster — marked `deleted` with
  `deleted_recovery_source: "exfat_directory_entry"` and `content_incomplete`, because its
  clusters were freed and may hold another file's data. A deleted
  directory that carried NoFatChain and whose first cluster is still free in the allocation bitmap is
  descended over `DataLength` consecutive clusters, keeping only sets whose `SetChecksum` verifies
  (`directory_content_basis: set_checksum_validated`; refusals counted as `directory_entry_sets_refused`);
  a deleted directory whose first cluster is in use again is flagged and not descended. A
  deleted directory that used a FAT chain is followed through the FAT entries the driver left (Linux's
  `exfat` frees the bitmap and keeps the FAT) for the clusters `DataLength` needs, stopping short, flagged,
  at a cluster in use again, with `directory_chain_basis: stale_fat_chain` and the same `SetChecksum`
  gate (`VALIDATION.md` `LINUX-FAT-1`).
- **Deleted directories and directory slack, FAT:** a deleted directory's first cluster must still
  begin with `.` naming itself and `..`, else nothing is read and the record says
  `directory_content_reallocated` or `directory_content_unrecognised`. It is then extended over the next
  clusters only while they are free and every slot before a `0x00` passes `plausible_dir_slot`; entries read
  that way carry `directory_chain_basis: contiguous_assumed`, and a stop on a failing cluster says
  `fat_deleted_chain_unverified`. The later clusters of a directory that grew around file data are found as
  headless directory clusters; a long name cut by a cluster boundary is joined to the trailing name slots of
  the nearest earlier directory cluster only when all slots carry one 8.3 checksum and the first byte that
  checksum implies for the deleted short name is the upper-case first character of the name
  (`long_name_basis: stitched_across_clusters`), and a deleted name whose last slot has no terminator is
  flagged `long_name_possibly_truncated` (deleted slots lose their ordinal). A driver that frees a directory
  without marking its slots (Haiku's, ReactOS's) leaves the ordinals: the flag is then read from the first slot's own
  `0x40` bit, and the join needs the ordinals to count down without a gap to the short entry and the checksum
  to be that of the short entry's unmarked name (`BSD-FAT-3`, `BSD-FAT-4`). Slots behind a `0x00` marker in the marker's own cluster that pass the same
  test are published as `deleted` with `recovered_from_directory_slack`; refused slots are counted in
  `directory_slack_slots_rejected`. Later clusters and the FAT12/16 fixed root are not examined. Graded on
  synthetic volumes only (open in `BUGS.md` as `HUNT-278`).
- **Layout, bounds and refusals, FAT:** the BPB layout, not the cluster count,
  decides the FAT size, the extended BPB and the root directory: `sectors_per_fat_16 == 0` is read
  as FAT32 (32-bit entries) even under 65,525 clusters, with `fat_type_note` on the allocation map
  saying the count disagrees; a FAT12/16 layout is never read as FAT32. A root listing that cannot be
  trusted is flagged on the allocation map (or a `fat_volume_walk` record) as `directory_parse_incomplete`
  with a reason: `fat_root_chain_incomplete`, `fat_root_cluster_invalid` (FAT32 root cluster below 2)
  or `fat_bpb_layout_inconsistent` (a BPB mixing FAT32 and FAT12/16 root fields). A chain naming a
  cluster past the volume's last data cluster stops with `chain_entry_out_of_range`, and a deleted
  entry's contiguous reconstruction must lie inside the data clusters (else
  `deleted_reconstruction_short`, no run). Its clusters are taken from the start cluster upward in order,
  stepping over any the FAT now calls allocated, as The Sleuth Kit does (`deleted_recovery_method:
  unallocated_clusters_in_order`, `deleted_clusters_skipped`, reason `deleted_clusters_assumed_in_order`; with
  none in the way it stays `contiguous_assumed`): on a real Canon camera card that recovers 7 of 26 erased photos
  exactly where a strictly contiguous read recovered 4 (`CAMERA-FAT-1`). Per-cluster work (bitmap, orphan scan) is sized by the
  entries the FAT holds, not the BPB's declared count (`allocation_fat_covered_clusters` says when
  they differ). The orphan-directory scan is flagged `orphan_directory_scan_incomplete` when its shared
  1,048,576-cluster budget ran out **or** a candidate cluster could not be read, with
  `orphan_directory_scan_incomplete_reason`. A second pass reads free clusters nothing
  anchors as **headless** directory clusters when every slot before the end marker reads as an entry
  (`orphan_directory_headless`, path `/[headless directory entries, cluster N]/NAME`, `headless_directory_scan` on the
  allocation map); it recovered all 23 root-level deleted pictures of CFReDS RM#2 that The Sleuth Kit lists, and
  nothing on seven other FAT volumes (`VALIDATION.md` `RM2-HEADLESS-1`).

### `seance_plugin_registry`
**Responsibility:** Parsing Windows Registry Hives.
- **Subscribes To:** `ArtifactType::FileEntry` (Hives: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `UsrClass.dat`)
- **Input Capability:** `InputCapability::RandomAccess`
- **Output:** `ArtifactType::SystemArtifact`, `ArtifactType::TimelineEvent`
- **Hive reader:** `seance_hive`, this project's own, written from Maxim Suhanov's published
  *Windows registry file format specification* and cross-checked against it field by field in
  `seance_hive/docs/SPEC_CROSSCHECK.md`. It is what makes the product MIT throughout. Every read is bounded by its cell, an absent
  structure and an unreadable one are different answers, and a hive that is unflushed or cut
  short opens under stated tolerances rather than being refused whole. A layered (differencing)
  hive, minor version 6, is interpreted by the library: `seance_hive::LayeredHive`
  merges a base hive and its deltas by the layer semantics (tombstone, supersede-local,
  supersede-tree, inherit-class), and reports what the merge hid (tombstoned keys and values,
  shadowed values) instead of dropping it. It is graded on two real Windows Server 2022 container
  chains against the `PATH` their Dockerfiles set (`seance_hive/docs/SPEC_CROSSCHECK.md`). What
  subkeys below a supersede do is the specification's names read plainly, not validated. The
  registry **module** does not build the merge yet: it does not find or order a container's
  layers, so a `*_Delta` hive in evidence is walked on its own — and is reported
  as what it is: a hive whose keys carry layered-key bits gets `differencing_hive`, `layered_keys`
  counts (tombstone, supersede-local, supersede-tree) and a statement that it is one layer's
  changes and not a registry, each such key carries `layer_semantics`, and the minor version is
  always recorded.
- **Features:**
    - **Hive Parsing:** Parse NK and VK cells, all four subkey index forms (`lf`, `lh`,
      `li`, `ri`), and `SK` (security descriptor) cells.
    - **Key security — who could change a key**. Every walked key
      records its security as `recorded`, `none_recorded` or `unreadable`. Three states, not
      two: "the hive holds no ACL for this key" and "this tool could not read the ACL" are
      different facts, and only the second is a gap in the inventory — it carries the scoped
      `security_incomplete` pair. An absent descriptor carries a note saying what the absence
      does **not** mean, because "no ACL shown" must never read as "anyone may write this key".
      Not one of the 334,111 key nodes in the twelve corpus hives takes either non-recorded
      branch, so on real evidence either is itself worth remarking on.
      A key carries the *offset* of its descriptor, not a copy of it. Descriptors are shared —
      117,488 keys over 289 descriptors on a real `SOFTWARE`, one of them named by 42,002 keys
      — so the decoded ACL is written once into the hive record's `security_descriptors` table
      and the offset is the join. That is also what makes the useful statement expressible: a
      descriptor carried by **exactly one key** is what a widened ACL looks like, and a per-key
      copy could not say it. The table is enumerated from the hive's own `sk` ring (289 reads,
      not 117,488), and each entry carries the hive's declared reference count beside the
      number of keys the walk actually saw — in all twelve corpus hives they agree exactly, and
      a disagreement is reported rather than reconciled.
      Rendered with **registry** rights (`KEY_ALL_ACCESS`, `KEY_READ`, `KEY_SET_VALUE`), not
      file rights: the low 16 bits of an access mask are object-specific, and `0x1` is
      `FILE_READ_DATA` on a file and `KEY_QUERY_VALUE` on a key. The decoder is
      `seance_core::secdesc`, shared with NTFS `$Secure:$SDS`, because two decoders for one NT
      structure can disagree about who owned something on a surface quoted under oath.
      **No effective access is computed and no finding is raised.** "Who could actually write
      this" needs group membership the hive does not hold; a scored "widened ACL" lead needs a
      measured false-positive rate.
      Measured cost: no detectable difference on a 117,488-key walk of the real `SOFTWARE`
      (6.1 ms either way, best of three), and 0.01 ms for the 289-descriptor ring.
    - **Key metadata:** each walked key records its last-write time and its subkey and value
      counts. A key whose index
      root (`ri`) named a subkey list that would not read carries `subkeys_incomplete`,
      `subkeys_incomplete_reason` (`unresolved_structure`), a detail sentence and the
      `unresolved_sublists` (offset and error), and each such list counts in the hive
      record's `walk_subkey_errors` — so a key that declares three subkeys and lists two
      says why.
    - **Both halves of the subkey count, reconciled by nobody**. A key records a
      subkey count in its own fixed fields and separately points at an index listing its
      subkeys, and the two can disagree. `SubKeyNodes::listed_len` publishes what the index
      names beside `KeyNode::subkey_count`, which is what the key claims; the key record
      carries both as `subkey_count` and `subkeys_listed`, plus
      `subkey_count_disagrees_with_index` and a sentence when they differ. Neither is
      corrected: a reader that silently trusted one would present a key's contents as settled
      while the hive disagreed about them. `subkeys_listed` is **absent, not zero**, for a key
      that declares no subkeys — there is then no index to have counted.
      **Distinct from `subkeys_incomplete`:** there, part of the index could not be read; here
      the index reads perfectly and is short. The discrepancy is raised once per hive as a
      `hive_subkey_count_discrepancy` investigative lead, qualified with the ordinary cause —
      a hive lifted off a running machine keeps its newest writes in its transaction logs.
      **Those logs are replayed when they are reachable**, before the hive is parsed
      (`txlog::recover_artifact_hive`: a dirty hive with its `.LOG1`/`.LOG2` beside it has the
      pending dirty pages applied to an in-memory copy, fail-closed on any entry that will not
      verify, with the outcome stamped as `logs_replayed` / `hive_dirty` / `replay_reason`
      provenance). The lead's qualification text in `seance_plugin_findings::hive`
      reads that provenance and says whether the logs were applied.
    - **Deleted keys and values, from the hive's unallocated space**. `seance_hive::Hive::unallocated_cells` walks free space for `nk`/`vk` cells a
      deletion marked free and nothing has overwritten, and
      `seance_plugin_registry::recovered` publishes each as a record of its **own type** —
      `RecoveredRegistryKey`, `RecoveredRegistryValue`, and a `Recovered Registry Key Last
      Written` timeline event — never as a live `RegistryKey` with a flag, so a viewer or an
      export cannot fold a deleted key into the live listing by forgetting to check one.
      Every recovered record carries `evidence_state: recovered` and
      `recovered_from: "unallocated hive cell"`.
      **What a freed cell can say.** An `nk` records its name, last-written time, parent
      offset and the subkey and value counts it *declared*; its subkey list, value list and
      security cell were freed with it and may have been reused, so none is followed and the
      counts are published as declared, not as found. A `vk` records its name, type and size;
      four bytes or fewer are in the cell itself and are read; larger data is read only from a
      data cell that is **still allocated** — and then labelled `data_basis` as a cell
      something may have reused since — or reported unread with the reader's reason. A `vk`
      does not name the key it belonged to, and no key is inferred for it.
      **The path is an inference**, and the record says so: it is rebuilt from the
      parent-offset chain through live and recovered `nk` cells, `key_path_is_inference` is
      `true`, a chain that ends on an offset holding neither is `key_path_complete: false`
      with the unresolved offset, and a recovered key whose inferred path matches a live key's
      carries `live_namesake` with a note — the slot may have been reused for a different key
      since the deletion.
      **Two ceilings, each on the hive record by number**: the walk examines at most
      200,000 free cells (`examined_cap`, `seance_hive::MAX_UNALLOCATED_CELLS`) and the plugin
      emits at most 50,000 recovered records (`records_cap`); `examined_capped` /
      `records_capped` say which fired. Known answer: plaso's `SAM` yields three keys at
      `0x3218`, `0x3520` and `0x4078` under parent `0x9b0` and three inline-data values, every
      one hand-decoded with an independent cell-chain walk before the assertions were written
      (`SEANCE_HIVE_CORPUS`). Two limits the verifier recorded: a freed `vk` whose non-inline
      size is zero is labelled as read from an allocated cell when no cell was read (not
      reachable on the corpus; open), and when the live-cell walk's own 200,000-`nk` cap bites,
      a recovered key's path confidence rests on a truncated live set.
    - **System Info:** Hostname, OS Version, Timezone (`SYSTEM`).
    - **Network:** the machine's DNS domain, from `Tcpip\Parameters` `Domain` / `NV Domain`,
      and **per-interface configuration** as one `NetworkInterface` record per
      `Tcpip\Parameters\Interfaces\{GUID}` per control set:
      the addresses, masks and gateways, the DHCP server, the name servers, and the lease.
      **The DHCP-assigned address is in the `Dhcp`-prefixed values** (`DhcpIPAddress`,
      `DhcpSubnetMask`, `DhcpDefaultGateway`, `DhcpNameServer`, `DhcpDomain`), not in
      `IPAddress` / `SubnetMask` / `DefaultGateway` / `NameServer` / `Domain`, which a DHCP
      interface leaves empty. The
      record carries `dhcp_ip_addresses`, `dhcp_subnet_masks`, `dhcp_default_gateways`,
      `dhcp_name_servers` and `dhcp_domain` beside the static fields (`VALIDATION.md`
      `LEAK-2`). The adapter's device name (`NetworkCards`) is not read.
      **The lease times are checked, not converted.** `LeaseObtainedTime`, `T1`, `T2` and
      `LeaseTerminatesTime` are `REG_DWORD`s and what they count is not fixed across Windows
      versions — on the real Windows 7 hive in `reference/` they are Unix seconds; on a Windows
      10 image the same field held `812456`, which is not a Unix time. So a value is presented
      as a time only when the lease's own arithmetic agrees:
      `LeaseObtainedTime + Lease == LeaseTerminatesTime`. On that hive it does, exactly —
      `1289408803 + 540000 == 1289948803`, with `T1` at half the lease and `T2` at
      seven-eighths, the standard DHCP renewal points. Four independent values agreeing is the
      basis, and it is stated on the record. A lease that fails the check is published as the
      **numbers it is**, marked `unvalidated`, because a boot-relative counter rendered as a
      1970 date puts a wrong day on a report. All four fields zero is **no lease** — a static
      interface — which is a different fact from a lease whose times are unknown.
      Values are read from raw bytes, not from the walk's rendering, which joins a
      `REG_MULTI_SZ` with ` | ` — a separator that is also a legal character in a string.
      **`Tcpip6` is out of scope and every record says so**, so its absence is not read as an
      absence of IPv6 configuration: its value set is entirely disjoint and the roadmap bullet
      this implements names the IPv4 DHCP fields only.
    - **Wireless profiles** (`seance_plugin_wlan`, module id
      `plugin.windows.wlan_profiles`). Not a registry subject: the WLAN service writes one XML
      document per configured network under
      `%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\{interface}\{profile}.xml`, and
      that is what is read — recognised by its root `WLANProfile` element and the v1 namespace
      in its first four kilobytes, never by its path, so a profile exported to a desktop or
      carved out of free space reads the same way. One `WifiNetwork` record with subtype
      `windows_profile`, which is the **same record type** the macOS known-networks parser
      emits (`seance_plugin_macos_artifacts::wifi`), so both platforms' answer to "where has
      this machine been" is one list.
      Read: the profile name, the SSID in **both** the `<hex>` and `<name>` forms the document
      gives (the hex is authoritative — an SSID is a byte string, not text — and where the two
      disagree both are reported and the disagreement is a stamped finding), `nonBroadcast`,
      the connection type and mode, the authentication and encryption, `useOneX`, MAC
      randomisation, and the interface GUID from the directory above the file.
      **The key.** `keyMaterial` is the passphrase in plain text when `<protected>` is `false`
      — what `netsh wlan export profile key=clear` and some deployment tooling write — and it
      is reported, because it is why an examiner opens the file. When `<protected>` is `true`
      it is a DPAPI blob: `seance_plugin_wlan::dpapi` reads the fields DPAPI leaves in the
      clear, names the **master-key GUID** the blob was encrypted under, and states what
      recovering it would need (the boot key from SYSTEM, the `DPAPI_SYSTEM` secret from
      SECURITY, and `Windows\System32\Microsoft\Protect\S-1-5-18\User\{GUID}` — where the
      real LoneWolf profile's master key is). **It does not decrypt**,
      and the on-disk master-key chain is not implemented anywhere in this tree — only the
      in-memory one is (`seance_plugin_memory_windows::credential_decrypt`). A third state
      exists and is reported as itself: material the profile calls protected that is not a blob
      this build can read.
      **What no record here says is when the machine joined, or that it ever did.** The XML
      carries no timestamps at all. It states configuration — and, where `connectionMode` is
      `auto`, that the machine would join whenever in range. The join history is in the
      `NetworkList` registry keys (`DateCreated`, `DateLastConnected`) and the
      `Microsoft-Windows-WLAN-AutoConfig/Operational` channel, both are read below, in their own records. The difference from the macOS record, which does
      carry `added_at` and `last_joined`, is in the evidence rather than in the parsing.
      **Graded on one real profile** (`WLAN-1` in `documentation/VALIDATION.md`):
      LoneWolf's WPA2-Personal "Net 2.4", every field and the DPAPI blob's clear fields agreeing
      with an independent reading. The record names the master-key path under `S-1-5-18\User`, where
      Windows keeps it. An open, 802.1X or
      hidden-network profile from a real machine has not been met.
    - **Which networks the machine has been ON, and when** (`seance_plugin_registry::networklist`). The wireless profile above says the machine was
      *configured* for a network. `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`
      says it was on one, and when. Two halves, joined by `ProfileGuid`:
      `Profiles\{GUID}` carries the name, whether a domain managed it, the firewall category
      (public / private / domain), what **kind** of network it was (`NameType` 6 wired, 0x17
      VPN, 0x47 wireless — and a value this build does not name is reported by its number,
      because the wrong word there would put a machine on a wireless network it was never
      near), and `DateCreated` and `DateLastConnected`;
      `Signatures\{Managed,Unmanaged}\<sig>` carries what the machine recognised the network
      **by** — the SSID in `FirstNetwork`, the `DnsSuffix`, and the **default gateway's MAC**,
      which is the closest thing Windows keeps to a fingerprint of a physical place. One
      `NetworkProfile` record per profile; a profile with no signature, and a signature naming
      a profile the hive does not hold, are each reported as themselves rather than folded
      together, because on a real hive either can happen.
      **The times are LOCAL time, and the offset is measured rather than assumed.** Both are
      16-byte `SYSTEMTIME`s with no zone in them, and a tool that reads them as UTC puts hours
      on a report. Connecting to a network is what writes the profile key, so the key's own
      last-written `FILETIME` — which *is* UTC — records the same instant as
      `DateLastConnected`. On `reference/plaso/test_data/SOFTWARE`, a real Windows 7-era hive,
      all three profiles agree **to the millisecond** and differ by whole hours: +4 h
      (2012-04-04), +5 h (2012-03-02) and +6 h (2010-11-10) — and the +5/+4 pair straddles the
      United States daylight-saving transition of 11 March 2012, which is what a real
      machine's offset does. So where the two correspond the record carries the local time as
      written, the UTC instant **from the FILETIME itself**, and the measured offset; where
      they do not it carries the local time and **claims no instant at all**, because a date
      with an unknown zone is not one a timeline may carry. `DateCreated` has no FILETIME to
      pair with, so its UTC is derived with the measured offset and labelled as derived: across
      a daylight-saving boundary it is out by an hour, and the local time is the primary.
      Every `SYSTEMTIME` field is checked against what a calendar allows, so a value read from
      the wrong offset is refused rather than published as a day in the year 65535.
    - **Every wireless connection, at an instant** (`seance_plugin_evtx`). The
      `Microsoft-Windows-WLAN-AutoConfig/Operational` channel's four events are named —
      8000 attempted, 8001 **connected**, 8002 failed, 8003 disconnected — and each event's
      own data carries the SSID, the profile name, the BSS type, the authentication and the
      cipher (8003 carries the disconnection reason instead). The four are kept apart in the
      wording because a report that called an attempt a connection would put a machine on a
      network it never joined. The ids and their meanings are as EvtxECmd's maps document them
      (`reference/evtx/evtx/Maps/Microsoft-Windows-WLAN-AutoConfig-*`, vendored here, each
      carrying a real event of its shape); an id on that channel this build does not name
      falls back to the provider and the number. **No WLAN-AutoConfig log from a real image
      was available to run this against**, so what is graded is the naming, not the decode of
      a seized channel — the channel itself is read by the same EVTX parser every other
      channel is.
    - **User Accounts:** local account **names**, from the key components under
      `SAM\Domains\Account\Users\Names\<account>` — SAM stores each account as a key whose
      name is the account name, with no value of its own. Kept apart from `ProfileList`, because
      SAM accounts and profile directories are different populations.
     
    - **Local accounts in detail — the `F` and `V` values**. One
      `LocalAccount` per `SAM\Domains\Account\Users\<RID in hex>` key: the RID, the last
      logon, the last password set, the logon count, the account-control state, the comment and
      whether a password hash is stored. **Only offsets the evidence proves are decoded**, and
      each proof is in-file rather than a recollection of the layout — measured on
      `reference/plaso/test_data/SAM`, a real Windows 7-era hive with three accounts:
      `F+0x30` equals the hex key name on all three; `F+0x08` is byte-identical to its own
      key's `nk` last-written time on one account and 6.0 ms before the hive header's own
      last-written time, so it is the last write the hive ever took; `F+0x18` is 0.72 s after
      the instant three sibling keys were written together, which is account creation, and six
      days *before* `F+0x08`, so the two are not interchangeable; `F+0x38`'s word differs
      between the two built-ins by exactly the one bit `0x0004`, and `Guest` is precisely the
      account whose password is not required; and `F+0x42` is a `u16` logon count that varies
      per account (6 / 0 / 4) whose only zero falls on the one account that never logged on.
      All five are independently corroborated by plaso's own checked-in test for the same file.
      **Five groups of fields are named on the record as not read**, because this evidence
      cannot establish them: the expiry slot (zero on two accounts and the `0x7FFF…`
      never-sentinel on the third — a sentinel establishes that the slot is optional, not what
      it means), the bad-password time and `F+0x10` (zero on all three), the failed-logon count
      (zero on all three, so its offset cannot be told apart from any other always-zero field —
      the logon count was established precisely *because* it varies), and the country/codepage
      pair (non-zero on one account only). Naming them is the difference between "this build
      does not read that" and "this machine has no such record".
      **A zero time is not 1601.** `Guest` never logged on and never had a password set; a
      converter that runs unconditionally prints "last logon 1601-01-01" — a fabricated logon
      event on an account that has never been used — and on this one hive it would do so
      eleven times across three accounts. The field is reported as no date **with the reason**,
      because an empty cell reads as a recorded blank rather than as nothing recorded.
      **A zero-length `V` descriptor is an absence, whatever its offset points at.** The
      descriptors are (offset, length) pairs relative to `V+0xCC`, and a zero-length one still
      carries a live offset: on this hive `Administrator`'s full-name and comment descriptors
      share one offset, so a reader that resolves the offset and scans to a NUL publishes
      "Built-in account for administering the computer/domain" as the account's **full name**,
      and on `Preston` the same bug publishes the all-`0xFF` logon-hours bitmap. The declared
      length bounds every read, a descriptor running past the value is refused **and named**,
      and an odd length is not decoded as UTF-16 by dropping a byte. All seventeen descriptors
      are listed on the record with their offsets and lengths, so a slot this build does not
      name is visible rather than hidden.
      **Whether a hash is stored is read from the declared length, never the bytes**: a
      four-byte blob is the header with no material after it, which is an account with no
      stored hash rather than a hash this build could not read. No hash material reaches the
      record. The account's name has two independent routes — the `V` name descriptor and the
      `Users\Names` key, whose default value carries the RID in its **type** field with zero
      bytes of data — and the record says whether they agreed, disagreed, or whether only one
      was available. The RID likewise: the key name is the anchor and `F` is the cross-check,
      and a disagreement is stated with both numbers rather than resolved silently.
      The name index and the account keys are **two populations**: a name present in the index
      with no account key beneath `Users` gets a record saying its detail was not read here,
      and the System Info panel reconciles the two counts so the shorter list is never read as
      the whole answer.
    - **UserAssist — what a user launched, how often, and when last**. One `UserAssistEntry` per value under
      `…\Explorer\UserAssist\{GUID}\Count`, one `UserAssistCoverage` per GUID key, and a
      timeline event (`Program last executed (UserAssist)`) for each entry that is both an
      execution **and** carries a decoded time.
      **The layout is dispatched on the data length, never on the key's declared `Version`**,
      and that is the decision the decoder exists around. In a real Windows 10 hive a
      `{CEBFF5CD-…}\Count` key declares `Version = 5`, 55 of its 56 values are 72 bytes, and
      `UEME_CTLSESSION` is 1,612. Reading that one at the 72-byte offsets would publish bytes
      `0x3C..0x44` from the middle of a session blob as an execution time — a fabricated
      timestamp in the entry nobody would check. A version that disagrees with the length is
      reported, not resolved. An unrecognised length decodes **nothing** and says so with the
      `content_incomplete` pair.
      Three layouts: 72 bytes (Win7+: session, run count, focus count, focus time, FILETIME at
      `0x3C`), 16 bytes (XP: session, run count, FILETIME at `0x08`), 8 bytes (XP session
      bookkeeping, no time). The ten floats and two spare dwords of the 72-byte form are kept
      as `unknown_bytes_hex` and **not named**: Microsoft documents none of this structure, the
      field names come from published research, and every record says so once in
      `layout_source`.
      `UEME_CTL*` entries are `explorer_bookkeeping` and are **never** executions. Every
      non-empty `Count` key on a real machine holds two, so reporting them as programs would
      put `UEME_CTLSESSION` at the top of every execution list ever produced. The XP counter convention (documented as starting at 5) is **stated** in
      `run_count_note`, never applied: a report saying 14 runs where the hive says 19 asserts a
      convention as a fact. A UWP application identity is `app_identity` and must not be
      correlated against the filesystem. Only the two published GUIDs get a role; the other
      seven a real hive holds are reported in full as `unclassified`.
      A `Count` key that exists and holds nothing reads as *Windows recorded nothing here* —
      7 of the 9 GUIDs on a real Windows 10 hive — which is a different sentence from *this
      build did not look*, and only the coverage record can say the first.
      Values reach the decoder as **bytes**, through a targeted capture on the walk: the
      `all_values` rendering is a display format (hex under 64 bytes), so decoding from it
      would be a hidden dependency on one. The capture is anchored — an
      unanchored hive captures nothing, which is why a 117,488-key `SOFTWARE` costs nothing —
      and bounded, with the cap stamped as `resident_capture_complete: false`.
    - **BAM/DAM — the last time each program ran, per user**.
      One `BamEntry` per execution value under
      `ControlSet00N\Services\{bam,dam}\…\UserSettings\<SID>`, one `BamCoverage` per SID
      key and per service per control set, and a timeline event
      (`Program last executed (BAM)`) for each entry carrying a time. Windows 10 1709+.
      **Both layouts match.** 1803 writes `…\bam\UserSettings\<SID>`; 1809 and later insert
      a `State` segment. Handling one would report nothing for half the Windows 10 estate — and
      report it as an absence of executions rather than as a shape that was not looked for.
      `Version` and `SequenceNumber` sit on every SID key and are **not** executions. A builder
      that took every value as a program would publish those two as executed binaries on every
      Windows 10 machine ever examined.
      **`\Device\HarddiskVolumeN` is not translated to a drive letter.** `MountedDevices` is
      in the same hive and §2.6 owns that mapping; until it lands the record carries
      `volume_resolved: false` and says so. The SID is likewise not resolved to an account
      name. A wrong drive letter or a wrong user in a report is worse than a raw name.
      Half of what BAM records is not a file path: thirteen of the 26 executions on a real
      Windows 10 hive are package family names, so `target_kind` is on every record and a
      consumer cannot assume otherwise. The sixteen undocumented bytes after the timestamp are
      kept as `trailing_bytes_hex` and **name nothing** — the classification comes from the
      value name, which is documented.
      **Three absences, each with its own sentence, and each actually emitted.** The service
      key absent (an XP or Windows 7 hive — stated as *this build of Windows kept no such
      record*, never as silence); the service key present with no per-user subkeys (verified on
      a real hive, where `dam` exists with none); and a SID key holding only bookkeeping, which
      reports zero executions beside its value count. Two control sets holding `bam` are both
      reported and distinguished by `control_set` / `is_current_control_set`, never
      deduplicated: two copies of a machine's state are one machine, and the
      reader must see which copy they have. `is_current_control_set` is read from
      `Select\Current`; without it, it is false rather than guessed.
      **Validated end to end** (`BAM-1` in `documentation/VALIDATION.md`): three
      real Windows 10 `SYSTEM` hives — DFIR Madness Case 001's desktop, BelkaCTF 6 and LoneWolf,
      both layouts — 16 SIDs and 117 executions, every one identical to an independent reading
      to the 100 ns. A populated `dam` key has not
      been met.
    - **MUICache — the display names the shell cached, and what that does not mean**. One `MuiCacheEntry` per application, pairing the
      `.FriendlyAppName` and `.ApplicationCompany` values of one path into a single record, plus
      a `MuiCacheCoverage` per key. Both forms: `…\ShellNoRoam\MUICache` (`NTUSER.DAT`, XP)
      and `…\Shell\MuiCache` (`UsrClass.dat`, Win7+) — the casing difference is real and both
      are matched case-insensitively.
      **It is not execution evidence**, and over-claiming it as such is the standard error with
      this artifact. Every record carries `execution_evidence: false` and the basis in words:
      the shell displayed that application's name, which most often follows from running it and
      is also written by a properties dialog, a context menu and a shell-extension
      enumeration.
      **A localised-resource reference is not an application path.** The XP form stores
      `@<dll>,-<id>` — `@xpsp1res.dll,-11004` is "Outlook Express" — and these are classified
      `resource_reference` with `application_path: null`. Reporting `@shell32.dll,-22075` as a
      program on the machine would be a fabricated finding, and an examiner correlating it
      against the filesystem would read the absence as a deletion.
      `LangID` is in both forms and is excluded as bookkeeping — **and counted**, so every
      value on the key lands in one bucket or the other.
      **No timeline event at all.** MUICache carries no per-entry timestamp; the key's write
      time is the key's, reported once with
      `key_last_written_scope: "the MUICache key, not this entry"`. A per-entry event at the
      key's time would date all 131 entries of a real XP key to the most recent one.
    - **The shell MRU lists, and outgoing RDP**. One
      `ShellMruEntry` per value across `RecentDocs` (root and per-extension), `RunMRU`,
      `TypedPaths`, `WordWheelQuery` (what was typed into Explorer's search box, decoded from
      its UTF-16 values, `VALIDATION.md` `LEAK-2`) and all four `ComDlg32`
      lists, with an `MruCoverage` per key; one
      `RdpDestinationEntry` per `Terminal Server Client` destination host — one record joining every `Default\MRUn` that names the host to its
      `Servers\<host>` subkey, not one record per key.
      **Both ordering conventions.** `MRUListEx` is little-endian `u32` indices,
      most-recent-first, `0xFFFFFFFF`-terminated; `MRUList` is `REG_SZ` letters and only
      `RunMRU` uses it. Handling one would leave the other's entries unordered, and an MRU list
      without its order is most of its value gone. Two states that break a naive
      implementation, both in real hives, each with its own sentence: a value the order list
      does **not** name is a stale entry with no position (giving it one would assert an
      ordering the hive does not record), and an index naming a value that does not exist is
      counted onto the coverage and stated.
      **The shell item is parsed**. Most bodies are a UTF-16 display name, a NUL, then a shell item
      ID list, and `read_shell_item_fields` walks that list through
      `seance_shell_item::walk_id_list_detail`. The record carries `shell_item_parsed` — the
      **deepest item's** per-item flag, not a blanket — `shell_items_total` and
      `shell_items_unread`, and from the deepest item's version-7+ `BEEF0004` extension block
      the `shell_item_mft_entry` / `shell_item_mft_sequence` pair under the same names
      `seance_plugin_lnk` uses. **An all-zero file reference is withheld**, with
      `shell_item_mft_reference_note` saying the field was zero: entry 0 / sequence 0 names
      `$MFT`, and every one of the 38 `RecentDocs` `.lnk` items on plaso's `NTUSER-WIN7.DAT`
      has a zeroed block (`seance_plugin_lnk` withholds it the same way,
      with the same note). `content_incomplete` is claimed only when it is true — the tail would not
      walk as an ID list at all (the byte count is named) or *k* of *n* items were not decoded
      (the detail says "k of n") — and when every item decoded the record instead carries
      `shell_item_decode_scope` stating exactly which fields were read and that other
      extension blocks were not. Real-hive evidence: `LastVisitedPidlMRU` value 4 decodes to
      `MyComputer\C:\Users\nfury\Documents\Alloy Research`, MFT 44518/33, hand-decoded and
      independently re-verified. File entries are
      now type `0x30`–`0x3F` only, so a `0xB0`–`0xBF` byte is `UnknownType_0xNN` with
      `parsed: false` rather than a file entry, and a class-`0x00` item carrying a
      users-property-view signature at offset 6 is named `UsersPropertyView`, `parsed: false`,
      its `1SPS` property stores not decoded; and `OpenSavePidlMRU\<ext>` values are read as
      the bare ID list they are, not as a display name followed by one — the misreading was
      what produced the `E` "file" and the `0xEE` "items" (the first byte of the
      `0x23FEBBEE` signature) on that hive. The `.lnk` name is still read as a NUL-delimited ASCII
      run and carries `link_name_basis` saying so: requiring the delimiter was added after a
      printable PIDL byte (`0x4F`, `O`) yielded `OVIBRANIUM.lnk`, and it errs toward not
      extracting rather than extracting wrongly.
      **`CIDSizeMRU` and `FirstFolder` hold a name, not a shell item**. Each value is read as a UTF-16 program name or path — plaso reads both keys as
      string MRUs — and the bytes after its terminator are published whole as
      `value_tail_bytes_base64` with `value_tail_bytes_len` and `value_tail_all_zero`, and
      disclosed as undecoded (`content_incomplete`) when they are not all zero. On plaso's
      `NTUSER-WIN7.DAT` all nine `CIDSizeMRU` entries (a 520-byte name field, then 72 bytes
      this build does not interpret) and both `FirstFolder` entries (a path and two NULs) are
      read as names.
      `RunMRU`'s trailing `\x01` separator is stripped, so no control byte reaches a report.
      **`TypedPaths` is not Internet Explorer's `TypedURLs`** — different keys, different
      meanings, and `TypedURLs` is already normalised into browser-history records. Merging
      them would put a filesystem path into a browsing history.
      **One timeline event per key, never per entry.** An MRU entry has no time of its own; the
      key's `nk` write time is the key's. The event names the position-0 entry and states, in
      both of its branches, that its time is not the time of any other entry on the key — an
      event per entry would date them all to the most recent action.
      Outgoing RDP records a destination **entered** in the client on this machine, which is
      the fact most often got backwards: `direction_note` says it is outgoing and
      `connection_succeeded` is false, because the key does not record whether a connection was
      established. **One destination, one record**: the `Default`
      MRU values and the `Servers\<host>` subkeys are joined by host name, compared
      case-insensitively (both spellings kept: `host`, `servers_key_host`), into a record
      carrying `mru_position` (the lowest), `mru_positions`, `username_hint`, `in_mru_list`,
      `in_servers_key`, and each key's path and time **separately** — `mru_key_path`,
      `mru_key_last_written`, `servers_key_path`, `servers_key_last_written` — each time with
      its own `*_last_written_scope` saying which key it dates: the `Default` key, shared by
      every MRU entry, or the destination's own `Servers\<host>` subkey. A host in only one
      key is still one record, the other key's fields null. **The default port is normalised**: an explicit `:3389` — the client's default — is treated as no
      port, so `host` and `host:3389` are one destination (`[v6]:3389` likewise; an
      unbracketed IPv6 address is taken whole), while `host:3390` is another; the join key is
      published as `destination` and every spelling joined as `hosts_as_stored`. Otherwise the
      join is on the name as typed: an IP address and a host name for the same machine stay
      two records, because the hive holds no evidence they are one machine, and every record
      says so as `ip_to_name_join_attempted: false` as well as in `join_basis`. A destination
      with more than one `Servers` subkey (`host` and `host:3389`) is still one record: `servers_keys` lists every subkey with its own `path`,
      `last_written`, `last_written_scope` and `username_hint`, `servers_key_count` counts
      them, `username_hints` holds every distinct hint, and the `servers_key_*` fields are the
      first subkey seen. `username_hint` is the first non-null hint in that order, so it can
      come from a later subkey than `servers_key_path` and `servers_key_last_written` (a first
      subkey with no `UsernameHint` and a second with one); `join_basis` says so, and the
      `servers_keys` element pairs each hint with its own key. That case is pinned on a synthetic capture
      only; none of the graded hives holds two `Servers` spellings of one host. **Graded on
      three real user hives** (`RDP-1` in `documentation/VALIDATION.md`: DFIR
      Madness Case 001's DC01 Administrator and both CFReDS winreg `CFTT` hives); an `MRU1`-or-
      later entry and a `CertHash` value have not been met.
    - **When a USB device was installed, and on Windows 8+ last connected**.
      The times are in the device instance's `Properties` subtree, and **there are two
      layouts**. Windows 8 and later: `Properties\{GUID}\<4 hex digits>` with one unnamed
      value. Windows 7: `Properties\{GUID}\<EIGHT hex digits>\00000000` — one key deeper —
      with **two named values**, `Type` (a four-byte `DEVPROP` code) and `Data`. A parser
      written to the first alone reports no connection time on any Windows 7 machine, which is
      a false absence on the operating system §2.6's exit criterion is graded against.
      **The decode is gated on the type code and never on the length.** On the real Windows 7
      hive in `reference/`, `{a8b865dd-…}\00000007` holds a string; "eight bytes, so a
      FILETIME" would turn a driver's version string into a date in 1601 and put it on the
      record as a connection time. A leaf with no `Type` value decodes nothing.
      Four properties are read and nothing else, because a date named as the wrong event is
      worse than a date not shown: install date, first install date, last arrival and last
      removal (`{83da6326-…}` `0x64`, `0x65`, `0x66`, `0x67`) and the driver-package date
      (`{a8b865dd-…}` `0x02`), which is labelled as a **package** date and not an event on the
      machine — its clean midnight is the tell.
      **Windows 7 writes no last-arrival or last-removal property at all**, so those records
      carry a sentence saying the absence is the operating system's and not this reader's.
      Without it, "no last connection time" reads as "this device was never disconnected".
      Values reach the decoder as raw bytes through the §2.5 capture, because `all_values`
      renders an 8-byte `REG_BINARY` to hex and a FILETIME decoded from a hex string is a
      decoder depending on a display format.
    - **`MountedDevices` — which drive letter a device was mounted at**. Two value shapes, both real on the Windows 7 hive in `reference/`: a
      UTF-16 **device instance path** for a removable or optical device, and **twelve bytes**
      for a local partition — a four-byte MBR disk signature and an eight-byte offset (`C:` is
      `3ea0be5c` at 1,048,576, the standard first-partition alignment). A `USBSTOR` path's
      third `#`-delimited field is the device's instance id, which is the **same value its own
      `Enum\USBSTOR` key carries**, so `\DosDevices\E:` joins to the `UsbDevice` record for
      the HP v100w on that hive — a drive letter tied to a serial, which is what the BAM
      module's `volume_resolved: false` was waiting for. A serial is read **only** from a
      `USBSTOR` path: the third field means something else on other device classes, and a wrong
      serial joined to a device is worse than no join.
      **A mapping is an assignment, not an observation.** `MountedDevices` is persistent: a
      letter stays recorded for a device not attached in years, and letters are reassigned. So
      `mounted_at_acquisition` is false with the basis in words. And an MBR record names **no
      disk** — which disk a signature belongs to needs the disk's own bytes, which are not in
      the hive.
    - **Windows Search — was the machine indexing, and where is the index**. `Services\WSearch` gives the service start type, and
      `SOFTWARE\Microsoft\Windows Search` gives whether setup completed and the
      `DataDirectory` that `Windows.edb` lives under. On the real Windows 7 hive: `Start = 2`
      and `DelayedAutoStart = 1` in **both** control sets, which is reported as
      `automatic (delayed start)` — a different configuration from plain automatic, and one
      Windows itself shows differently. A `Start` value outside the five documented types gets
      **no** start type claimed for it.
      **Configured to run is not indexed**, and the record says so: a service set to automatic
      on a machine imaged shortly after installation has indexed nothing, so
      `index_populated` is false and whether the index holds anything is named as a question
      for `Windows.edb` itself. The record does say why that file is worth finding — it holds
      names and content excerpts for files that have since been deleted.
      **The absence of the key is stated, per control set.** A control set the walk read which
      holds no `WSearch` key gets a record with `service_key_present: false` and the reason in
      words, because the alternative is silence — and silence reads as "indexing was off"
      rather than as "this build of Windows kept no key of that name". The CFReDS Hacking Case
      `SYSTEM` hive is the case that forces it: the byte string `WSearch` does not occur in the
      file at all, while `cisvc` — the name XP's Indexing Service used — occurs twice, once per
      control set. That hive yields two absence records.
      No start type, effective start type or `indexing_configured_to_run` is claimed on such a
      record, and whether some other indexer ran is named as a question this record does not
      answer.
    - **When a device's own property times contradict each other, the record says so.**
      Measured on the Windows 10 hive read for §2.6: a SanDisk Extreme, serial
      `AA010215170355310594&0`, carries `install_date` 2018-03-27T12:11:32.021203500Z and
      `last_removal_date` 2018-03-27T09:22:13.088887100Z — removed two hours and forty-nine
      minutes **before** it was installed. Each value is read correctly from its own property
      key; the combination is not something this build can vouch for. Both are reported as
      stored and a `time_contradictions` entry names the pair, their values and which way round
      the disagreement runs, because a screen printing "first connected 12:11:32, last removed
      09:22:13" with nothing said is worse than either value alone — the reader takes the pair
      as one coherent account. Only orderings that cannot hold are stated: a last arrival after
      a last removal is the ordinary case, the device still being plugged in, and is
      deliberately not among them. This is **not** an `IncompleteReason`: that vocabulary is
      about what this build could not read, and here it read both values. The USB view carries
      the statement as a row marker and the three date columns, beside name,
      vendor, product, revision and serial.
    - **Sticky Notes, both formats; `.snt` graded on one real file, `plum.sqlite` on one
      lab-made 6.1.4.0 database** (`seance_plugin_stickynotes`). `StickyNotes.snt` — an OLE2
      compound file, one storage per note — and the UWP app's `plum.sqlite`, each recognised by
      its own magic and not by its name.
      **No Sticky Notes of either format exists on the machine this was written on**, and that
      was established rather than assumed: a case-insensitive search of every mounted
      filesystem for `*.snt`, `stickynotes*` and `plum.sqlite*` returns nothing, and an `fls`
      listing of all 200,117 entries of the one Windows image here shows the app installed with
      **both** candidate `LocalState` directories empty. The other Windows corpus is XP, which
      predates the feature. So every record carries the never-validated stamp
      (`validation_state`, `validated_against_real_notes: false`, and the basis and the notice
      in words), stamped through one private choke point and asserted structurally by a test.
      **The stamp comes off when a comparison against real notes is recorded in
      `documentation/VALIDATION.md`, and not before** — and until then no Sticky Notes claim
      may be made in `COMPARISON.md`.
      **The stamp is per format.** `SNT-1` graded the `.snt` reader on the NIST
      Data Leakage case's Windows 7 `StickyNotes.snt` (one note; storage, text, both times and
      every stream agreeing with 7-Zip and a hand reading of the RTF). Every `.snt` note carries `source_format:
      snt_compound_file`, as its coverage record did and as a `plum.sqlite` note carries
      `plum_sqlite` . `.snt` records carry `validation_state:
      snt_validated_against_one_real_file`, `validated_against_real_notes: true` and a notice
      bounding it to one file and one plain-text note. `plum.sqlite` records keep the
      never-validated stamp, and no claim about the Windows 10 format may be made anywhere.
      *(For `user_version` 13 see `PLUM-1`, below.)*
      **No stream-naming guess is load-bearing.** The `.snt` reader enumerates the storages
      beneath the root, emits one note per storage, and for each stream records the name, the
      declared length, the bytes actually readable, and — when the bytes open `{\rtf` — the
      extracted text with which stream it came from on the record. A storage with no recognised
      stream is **listed** with every stream in it named and measured, stamped
      `unresolved_structure`, and never skipped: a note that would not read is not the same as
      no note. A stream directly beneath the root, which the documented layout does not put
      there, is listed too. The storage name is an opaque identifier and is **never parsed**:
      the format caps an object name at 31 UTF-16 code units, so a brace-delimited GUID (38
      characters) and a bare one (36) are both too long to be one.
      **A directory-entry timestamp that is the unset sentinel is reported as absent, with the
      reason.** The OLE2 reader exposes the time as a wall-clock instant and offers no access
      to the raw value, so a zero FILETIME arrives as 1601-01-01 and an unrepresentable one as
      1970-01-01; both are reported as no date, because "created 1601-01-01" is a fabricated
      date on a report. The cost is stated on the record: a note genuinely created at exactly
      1970-01-01T00:00:00Z would also read as absent, and this build cannot tell the two apart
      through the reader it uses.
      `plum.sqlite` goes through the same staging and **three-state** discipline the Windows
      Timeline reader uses: the schema being **present** is read, **absent** is a finding —
      with the tables that *are* there named, because "an unrecognised schema" is otherwise a
      dead end — and **undetermined** is damage rather than an absence. An empty `Note` table
      is its own answer and not the same answer as a database that would not read. A schema
      missing some of the columns this build reads is read for what it has, and
      `columns_present` says which answered, so a null field is distinguishable from a column
      the schema does not have. A row carrying a deletion time is reported **as deleted**
      rather than filtered out.
      **`PLUM-1`: what the real 6.1.4.0 store does.** Graded on a **lab-made**
      database the real app wrote on the project's Windows 11 25H2 VM (`VALIDATION.md`
      `PLUM-1`; not a public or seized image). Four behaviours the reader now depends on:
      *the database can live wholly in `plum.sqlite-wal`* — the app never checkpointed, even on
      a clean close, so `plum.sqlite` was page 1 only and a reader that ignores the `-wal` sees
      no tables; the module stages the file and its `-wal` to a temporary copy and opens that
      read-only (`TempDb::spill`), never the evidence in place, since opening a WAL database
      in place can checkpoint it and rewrite `-shm`. *Times are .NET ticks* in `bigint`
      columns (UTC as the writing machine's clock had it): converted, the raw ticks kept as
      `created_ticks`/`modified_ticks`/`deleted_ticks`, and never corrected for a wrong clock —
      the lab guest ran an hour slow, and the file's value is what is reported. *`Text` is one
      paragraph per line, each prefixed `\id=<guid> `*: `text` has the prefixes removed,
      `text_raw` is the column as stored. *A delete sets no tombstone*: `DeletedAt` is never
      set and the row is removed, so the live table cannot show a deleted note at all. The
      module therefore reads the `-wal` a second time, decodes every `Note`-shaped cell in every
      frame with the forensic SQLite parser's WAL and b-tree readers, and emits a
      `StickyNoteRecovered` record for each `Id` absent from the live table, from the newest
      frame holding it: `recovery_source: wal_superseded_frame`, `wal_frame` (0-based),
      `wal_frame_offset`, `wal_frames_holding_row`, `first_wal_frame_without_row`, whether the
      frame is committed and of the current generation, `deleted_inferred: true` and a
      `deletion_basis` saying the deletion is inferred from absence and has no time. Earlier
      images of notes that are still live are edit history and are not reported; a deleted
      note whose frames were checkpointed and reset away survives only in page free space,
      which this does not read.
      **The stamp is keyed on `user_version`.** The file does not record the app version, so a
      record from a store at `PRAGMA user_version` 13 carries `validation_state:
      plum_validated_against_one_lab_made_database` (`validated_against_real_notes: true`,
      `validation_evidence: lab_made`, `validated_app_version: 6.1.4.0`), and a store at any
      other version, or none, keeps the never-validated stamp. Both go through the one choke
      point `unvalidated::stamp_plum`.
      The **RTF extractor** is this repository's only one, written here because none existed.
      It honours `\'hh`, `\uN` with its `\ucN` skip count (emitting the code point and
      swallowing the ANSI fallback, so a non-ASCII character is not printed twice), `\par`,
      `\line`, `\tab` and the literal `\{`, `\}`, `\\`; it skips `\*\` destinations and
      the font, colour and style tables, because keeping them prints a font table into the
      note; and it **reports rather than renders** `\pict` and `\object`, whose hex payload
      would otherwise turn a note into a page of gibberish. A byte in `0x80..=0x9F` means
      different characters in different code pages, and this extractor does not claim to know
      which, so it is replaced rather than guessed. Unbalanced braces keep what was read and
      state the imbalance, which is what a truncated or carved note looks like.
    - **The setupapi device-install logs — the second source for a first connection**
      (`seance_plugin_setupapi`). `%WINDIR%\INF\setupapi.dev.log`
      and its siblings, recognised **by their first line** (`[Device Install Log]`) and never by
      their name — a file merely named `setupapi.dev.log` produces nothing at all, not a
      refusal and not an empty record. The name then rides on every record, because that first
      line does **not** tell `setupapi.dev.log` from `setupapi.setup.log` and the two use
      different section vocabularies. One `DeviceInstallEvent` per section that concerns a
      device, plus one `DeviceInstallLogCoverage` per log carrying the header, the boot
      sessions, the counts and a **complete histogram of every section kind** — on the larger
      real log the two commonest kinds are the driver store's own housekeeping and account for
      154 of 194 sections, so emitting them as device records would bury the three real device
      installs and hiding them would be worse.
      **`log_os_version` rides on every record.** A `setupapi.offline.log` can declare
      `OS Version = 6.3.9600` inside a 10.0.16299 machine: it describes the deployment image's
      servicing, not this machine's device history.
      **Times are local, and no timezone or offset appears anywhere in any of the three logs
      measured** — checked for `UTC`, `GMT`, `timezone`, `Bias`, `daylight`, `DST` and the
      literal `+HH:MM` / `+HHMM` shapes, all absent. So they are reported exactly as written,
      never converted, and **no timeline event is raised** from them: the timeline is in UTC and
      placing a local time on it moves the event by the offset nobody recorded. Comparing a log
      time against a registry time is the examiner's inference, shown to them rather than made
      for them. The view heads its columns *Section start (local)* for the same reason.
      **Six things the format does that a straightforward parser loses**, each real in one of
      the three logs and each pinned by a test: boot sessions are **not** in chronological order
      (one log has a session 9 h 19 m earlier than the one before it, so they are kept in **file
      order** and never sorted); three sections **start before the boot session they sit under**
      by nearly three hours, which is Windows Update replaying an earlier-clock install, and
      clamping or rejecting them loses three device installs; nine sections have **no body line
      at all**; 533 body lines begin `!` or `!!!` in column 0 rather than with indentation,
      including the only two records of a device that failed to start; `cmd:` is indented six
      spaces where every other tag is indented five, and it is the line that says which process
      drove the install; and the header subject is **absent on 176 of 194 sections** and is an
      INF path, a bare GUID, a two-segment hardware id or a full instance id on the rest — so it
      is **shape-classified before anything reads it as a device**, because publishing an INF
      path as a connected device is this parser's headline failure mode. The full instance id is
      sometimes only on an `ndv:` body line: seven sections name `acpi\dellabce` in the header
      and `ACPI\DELLABCE\2&DABA3FF&0` in the body, and the two are kept in separate fields.
      An exit status is captured as **whatever is there**: the real logs hold only `SUCCESS` and
      `SUCCESS (REBOOT_REQUIRED)`, so this build does not treat the vocabulary as closed.
      A section the log never closed is reported as unclosed rather than discarded — that is
      what a machine losing power mid-install leaves behind. Graded against
      `reference/plaso/test_data/setupapi.dev.log` (194 sections, 12 boot sessions) and
      `setupapi.setup.log` (16 sections, 1), whose section counts plaso's own checked-in test
      independently asserts from a second implementation.
    - **USB mass storage:** one `UsbDevice` per device instance under
      `ControlSet00N\Enum\USBSTOR\<class>\<serial>`. Only `Enum` — `Control\usbstor` and its
      `Setup\PnpResources` mirror in SOFTWARE are the driver's per-chipset quirk list, shipped
      with Windows and present whether or not anything was ever plugged in.
    - **Installed programs:** one `InstalledProgram` per subkey of
      `Microsoft\Windows\CurrentVersion\Uninstall` — the native path and the `Wow6432Node`
      mirror in SOFTWARE (`wow64` says which; `scope: machine`), and `Software\...\Uninstall` in
      a user hive (`scope: user`). Carries `display_name`, `display_version`, `publisher`,
      `install_location`, `install_source`, `uninstall_string`, `estimated_size_kb`,
      `system_component`, `key_path`, `source_path` and the hive's replay stamp. A GUID-only
      entry with no `DisplayName` is still a record (`display_name: null`, named by its key),
      so the count of records is the count of entries the hive holds. `InstallDate` is decoded
      only from the documented `YYYYMMDD` shape, with `install_date_source` stating whether the
      value was absent, decoded, or present and not that shape (the raw text is kept either
      way); each decoded date is a `Program installed (InstallDate)` timeline event placed at
      00:00:00 UTC and marked `timestamp_precision: day`, because the value carries no time or
      zone. `key_last_written` is the entry's NK last-write time from the raw cell scan, and
      when the scan did not reach the key the record names the scan's cap rather than saying
      `absent`. `EstimatedSize` and `SystemComponent` are read only from the walk's
      `0x… (n)` DWORD rendering; a string an installer wrote in their place is not guessed at.
      A hive with no `Uninstall` key emits nothing: the hive record's own key count already
      says the hive was walked.
    - **Transaction logs:** a dirty hive's `.LOG1`/`.LOG2` are replayed into an in-memory copy
      before parsing, reached beside the hive on disk, inside a container, or through the
      filesystem parser's sibling bundle for a hive inside a disk image. Replay is fail-closed:
      an unverifiable entry is never applied.
    - **Unflushed hives:** a hive lifted off a running machine normally has mismatched sequence
      numbers, and replay cannot always close the gap — the logs may have wrapped past the
      entry the primary file needs. Such a hive is **parsed anyway** and every record out of it
      carries `hive_dirty`, `logs_replayed` and `replay_reason`, because refusing it costs all
      of the registry to avoid being stale about the last few writes. Every other
      base-block check — signature, version, file type, format, declared size, clustering
      factor, checksum — still refuses a corrupt header.
    - **Origin:** every hive record carries `source_path` and `hive_role` (`live`, `regback`,
      `unknown`), because a volume holds the same hive several times over and a consumer must
      not weigh the `RegBack` copy as a second machine.
    - **Short hives:** a hive whose file holds fewer hive-bin bytes than its base block declares
      is parsed up to the cut and stamped `content_incomplete` / `short_read` with the declared
      and present sizes.
    - **Bound:** a hive that is detected and then cannot be parsed emits a `RegistryHiveUnparsed`
      record naming the reader's own error, so the case never holds the file with no account of
      why nothing came out of it.
    - **Values:** each entry of `all_values` carries the rendering an examiner reads
      (`value_data`) and the stored bytes as `value_data_b64` — every value,
      not only a binary one over 64 bytes. Values of up to 64 bytes always carry
      them; larger ones count against a per-hive cap of 256 MiB, stated on the hive record as
      `value_bytes_budget_bytes` with `value_bytes_complete` and `value_bytes_omitted`, and a
      value past it says so with `value_data_b64_omitted`. On plaso's `NTUSER-WIN7.DAT` and
      `NTUSER.DAT` every one of 5,470 and 5,602 values carries its bytes, and YARA now scans all
      5,602 of the latter as exact bytes (it was 2,033). The records grew by 14–18% on plaso's
      `SOFTWARE`, `SYSTEM` and `NTUSER.DAT`. A `REG_MULTI_SZ` also carries its elements as the
      array `value_data_list`, because the ` | `-joined rendering cannot be split back when an
      element contains ` | `. A `REG_DWORD_BIG_ENDIAN` renders as the big-endian number it is
      (no hive on this machine holds one, so
      that case is pinned on a synthetic hive only). `hive_type` is the ingested file name
      upper-cased (`AMCACHE.HVE`), not a classification of the hive.

#### Transaction-log replay rules

The bullets above say that a dirty hive is replayed and that replay fails
closed. This subsection states the rules. They live in
`seance_plugin_registry::reglog` and `txlog`.

**Dirty.** A primary hive, file type 0 at offset 0x1C of its base block, is
dirty when its primary and secondary sequence numbers at 0x04 and 0x08 differ,
or when the XOR-32 checksum of bytes 0x00 to 0x1FB does not match the value at
0x1FC. Either condition is enough. A log file or any other non-zero file type is
never replayed into, and reads `not_a_primary_hive`.

**Finding the logs.** The logs are found by name beside the hive: `.LOG1` then
`.LOG2`, each also tried in lower case. They are reached on disk, through the
data source's sibling contract inside a container, or through the sibling bundle
the file system parser attaches for a hive inside a disk image. A bare `.LOG` is
consulted only when neither numbered log is reachable. A log is read up to 512
MiB. A log cut short by that cap or a short read is named in
`replay_truncated_logs` and the record carries `content_incomplete` with reason
`transaction_log_read_capped`. A log is accepted only when its own base block
parses with the `regf` signature and a log file type. Types 1 and 2 are legacy
logs and type 6 is a new-format log. Finding a file by name is never trust. The
engine checks every base block, sequence number and hash before it applies a
byte. A log file given to the registry parser as if it were a hive is dropped
with no record, because it shares the `regf` signature and would otherwise read
as an empty hive.

**New-format logs, `HvLE`, type 6.** Entries start at offset 0x200 and each has a
40-byte header: `HvLE` signature, size, flags, sequence number at 0x0C, hive
bins data size at 0x10, dirty page count at 0x14, Hash-1 at 0x18 and Hash-2 at
0x20. Page references follow, each a 4-byte offset into the hive bins data and a
4-byte size, then the page bodies in order. Both hashes are Marvin32 with the
fixed seed `82 EF 4D 88 7A 4E 55 C5`. Hash-2 covers the first 32 bytes. Hash-1
covers everything from the first page reference to the end of the entry.

- An entry size that is not a positive multiple of 512, that runs past the log, or
  whose page table does not fit ends parsing of that log.
- A wrong Hash-2 means the entry is not valid and ends parsing of that log.
- A wrong Hash-1, or page sizes that exceed the entry body, flags the entry. The
  chain stops before it and nothing from it is applied.

**Sequence chain.** Entries from both logs are pooled by sequence number. An
entry at or below the hive's secondary sequence number is already committed and
is dropped. On a tie the first log wins. Replay then applies the longest run
that starts at the secondary sequence number plus one and rises by exactly one.
It stops at the first gap, wrong hash or unusable page. Which physical file holds
which entry does not matter. When no entry sits at the secondary number plus one
but a later one exists, nothing is applied and the reason is `sequence_gap`. A
log that holds nothing newer than the hive leaves a dirty hive `logs_invalid` and
a clean one `clean`.

**Applying pages.** Each entry is checked whole before any of it is written, so
no entry is ever applied in part. Every page must lie inside the entry body and
inside the hive bins data size that entry declares. Its file offset is that
offset plus 0x1000. When an entry declares a larger hive than the buffer holds,
the buffer is grown with zeros to that size, up to a ceiling of 512 MiB, and the
new region is then overwritten by validated pages. After the last applied entry
the base block gets that entry's sequence number in both fields, the entry's hive
bins data size and a recomputed checksum, the way Windows leaves it. The
recomputed checksum maps a sum of 0 to 1 and a sum of all ones to 0xFFFFFFFE.
`hive_last_written_after` is the base-block time of the log that held the last
applied entry. No time is invented for the replay itself.

**Legacy logs, `DIRT`, types 1 and 2.** A `DIRT` signature sits at 0x200, followed
by a bitmap with one bit per 512 bytes of hive bins data, then the dirty pages at
the next 512-byte boundary in bit order. Page `p` is written at `0x1000 + 512 * p`.
A legacy log has no sequence chain, so eligibility is decided first. The log's
base block must pass its checksum. Its last-written time must not be earlier than
the hive's and its primary sequence number must not be below the hive's secondary
number. A hive that is not dirty is refused, because a legacy log is a snapshot
that can only take a complete hive backwards. Candidates are tried newest first by
last-written time, `.LOG1` before `.LOG2` on a tie, and an ineligible log falls
back to the next. A log applies as one entry. Legacy logs are tried only when no
new-format log applied anything.

**Outcomes.** `replay_reason` is one of `clean`, `recovered`, `no_logs_found`,
`logs_invalid`, `sequence_gap`, `hash_mismatch`, `page_out_of_range`,
`log_base_block_invalid`, `log_older_than_hive` or `not_a_primary_hive`. Entries
applied before a stop are kept and the stopping reason is stated. `logs_replayed`
is true only when at least one entry was applied. A dirty hive that applied
nothing is `content_incomplete` with reason `dirty_hive_not_recovered`. A replay
that stopped early is `content_incomplete` with reason `partial_log_replay`. In
both cases a key missing from the output is not evidence that it was missing on
the machine. The record also carries both sequence numbers, the log format, the
log file names, the first and last sequence applied and the counts of entries,
pages and bytes applied. The set of keys the replay changed is not computed, and
the record says so with `replay_changed_keys_computed: false` and does not give
an empty list.

**What is not done.** A hive read from a shadow-copy prior version is not given
its logs. Logs that are not beside the hive under the same name are not found.
The base block's recovery GUIDs and flags after offset 0x70 are not interpreted.

---

## 3. User Activity & Artifacts

> **These four entries state what the parser asserts.** The full
> paragraph for each is in `documentation/METHOD_STATEMENTS.md`, which is generated from
> the code.

### `seance_plugin_lnk`
**Responsibility:** Parsing Windows Shortcut (LNK) files.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Output:** one `LnkFile` `ParsedRecord` per shortcut, plus a `TimelineEvent` per usable
  FILETIME. A shortcut whose three FILETIMEs are all zero produces the record and no
  timeline event at all.
- **Features:**
    - **Target Metadata:** the target path, the three target FILETIMEs (creation, access,
      write) and the target's recorded size.
    - **Volume Info:** the `VolumeID` structure — the **drive type** in words (`removable`,
      `fixed`, `remote`, `cdrom`, `ramdisk`, `no_root_directory`, `unknown`; an unrecognised
      code is reported as the number and not mapped onto a nearby word), the **volume serial**
      rendered as Windows shows it (`A1B2-C3D4`), and the **volume label** where the shortcut
      recorded one, ANSI or Unicode.
    - **Network Share:** UNC paths for network targets.
- **What the volume fields are not**, carried on every record that has them: they are what
  the shortcut recorded **when it was written**, not what is true now. `removable` means
  Windows classified the volume removable at that moment — a lead towards external media,
  not proof the target is on a USB stick, and a drive letter can be reused by a different
  volume. The serial is the **file system's** volume serial, which changes on reformat; it
  is not a hardware serial and does not identify a device. The recorded target size is a
  `u32`, so the format itself records a target over 4 GiB modulo 2³².
- **Does not:** parse the `LinkTargetIDList`'s shell items (§5.16).

### `seance_plugin_jumplists`
**Responsibility:** Reading Jump Lists — the shortcuts they hold and the `DestList` that
orders them.
- **Subscribes To:** `ArtifactType::FileEntry` (`*.automaticDestinations-ms`,
  `*.customDestinations-ms`)
- **Output:** one `FileEntry` per shortcut, each with its own data source so the LNK reader
  downstream can read it — typed `JumpListStream` with `recovery_method: ole_directory` when
  it came out of the container's directory, `JumpListCarvedShortcut` with
  `recovery_method: signature_carve` when it was found by scanning — so a live stream and a
  carved one are told apart by **type**; one `JumpListDestListEntry` `ParsedRecord`
  (`record_type: jumplist_destlist_entry`) per `DestList` entry and a `TimelineEvent` for
  each entry that carries a usable time; one `JumpListDestList` summary per file saying what
  was read and what was not; and a `JumpListCarveStatus` only on the fallback path where the
  directory could not be followed.
- **Features:**
    - **The container is read as the OLE compound file it is** — header, FAT, mini-FAT and
      directory through the `cfb` crate (MIT; already in the tree for Sticky Notes), opened
      permissively. The directory's hex-numbered streams are the shortcuts; each is handed on
      with its stream name, declared and read lengths, and `source_offset` only where the
      stream's bytes lie whole at a shortcut signature in the file (otherwise
      `source_offset_unavailable` says why). All eight OLE signature bytes are checked: an
      earlier reading compared four while its comment claimed eight.
    - **`DestList` is decoded, by header version and never guessed.** Version 1 (Windows 7
      and 8) has a 114-byte fixed entry part; versions 2, 3 and 4 (Windows 10 and later) a
      130-byte fixed part plus four trailing bytes. Any other version is refused with the
      number, and the shortcut streams are still reported. Per entry: the entry number, its
      stream name and whether that stream exists, the path (U+FFFD-flagged if the UTF-16 was
      invalid), the NetBIOS host name (absent when empty), the four DROID GUIDs, the last
      recorded FILETIME as RFC 3339 beside the raw value (an unset sentinel yields
      `last_recorded_time_unavailable`, never a date in 1601), the pin field raw with `pinned`
      true / false / null (−1 unpinned, ≥ 0 a pinned position, per the libyal format document;
      anything else is not asserted either way), and the entry's index in stream order as
      `mru_position` with `mru_position_basis` beside it — the format document does not state
      the order; that the stream is kept most-recently-used first is what real files show and
      how plaso and JLECmd read it, and the record says it rests on that.
    - **One field is named for what is known about it, not for what it is hoped to be.** The
      32-bit value at offset 116 of a version-2+ entry — the one other tools call an access
      or interaction count — is listed by libyal as "Unknown (access count?)" and by plaso as
      `unknown5`, so it is published as `offset_116_unknown_possibly_access_count` with
      `offset_116_note` carrying that uncertainty, and a version-1 entry carries
      `offset_116_unavailable` because the layout has no such field. Every other field those
      sources mark unknown is not surfaced at all.
    - **The AppID in the file name is resolved where this build can name it**, and reported
      as `application: null` with a sentence otherwise. The table (`appid.rs`) holds 41
      identifiers whose CRC-64 the build computes itself; 19 of them are cross-checked
      against an independently published ID and say so (`Basis::CrossChecked`), the other
      22 carry the computed hash alone (`Basis::Computed`). An unknown AppID is "an application this build cannot
      name", never a guess.
    - **The signature carve is the fallback, not the method.** It runs when the directory
      cannot be followed, and on every `customDestinations-ms` file, which has no directory.
      A fragment is scanned, not refused: a file too short for the 512-byte OLE
      header still yields whatever shortcuts its bytes hold, and the status record says both
      that the carve did not cover a whole file and that the container is not corroborated.
- **Known answers:** plaso's `1b4dd67f29cb1962.automaticDestinations-ms` (Windows 7,
  `DestList` v1, 11 entries, 11 streams) and `9d1f905ce5044aee.automaticDestinations-ms`
  (Windows 10, v3, 2 entries), pinned to plaso's own checked-in expectations for the same
  files (`seance_plugin_jumplists/tests/real_jump_lists.rs`); the `DestList` unit fixtures are
  written from the same format description the decoder implements, which is why the real
  files are the grade (`TESTING.md`).
    - **Shortcuts in sectors a readable directory no longer references**. When the directory reads, the file's own allocation tables are walked
      too ([MS-CFB]: header, DIFAT, FAT, the root entry's mini stream, the mini-FAT — the
      `cfb` crate does not expose its free maps) and every run of `FREESECT` sectors and
      mini-sectors is scanned for the shortcut signature. A hit whose bytes are a prefix of a
      live stream (an exact copy, or one cut short at the end of a free run) is left out; any
      other is a `JumpListCarvedShortcut` with `recovery_method: unreferenced_sector_carve`,
      its `sector_kind` and `sector_index`, and `dest_list_correlation: none`. The scan stops at
      10,000 shortcuts; if it stops there, `unreferenced_sector_cap_reached` is true, the scan
      sentence calls the count a floor and the DestList record is marked incomplete
      (`cap_reached`). The mechanism is
      pinned on files the `cfb` writer built and then deleted a stream from (its
      `remove_stream` frees entries without zeroing data); **no real jump list examined has
      held one** — 30 checked, none, including all ten on the Data Leakage PC run through
      this code — and every record says so.
- **Does not:** reassemble a freed shortcut whose first sector was reused; say which
  stream a freed sector belonged to; nor read the four trailing bytes, the floats or the
  other unknown fields.

### `seance_plugin_shellbags`
**Responsibility:** Parsing ShellBags (folder browsing history).
- **Subscribes To:** `ArtifactType::FileEntry`, `ArtifactType::SystemArtifact`
  (`UsrClass.dat`, `NTUSER.DAT`)
- **Output:** one `ShellBagEntry` `ParsedRecord` per BagMRU node, plus a `TimelineEvent`
  per entry.
- **Features:**
    - **Folder Access:** the folder paths Explorer recorded, reconstructed by walking the
      `BagMRU` tree depth-first, with each entry's path, folder name and slot.
    - **The BagMRU key's last-write time** (`VALIDATION.md` `LEAK-2`). Each
      record also carries `key_last_written` (UTC) and a basis sentence: the last write of the
      key that holds the folder's slot. It is when Windows last wrote the folder's entry —
      created, or re-ordered by opening it again — and it is the "ShellBag timestamp" the NIST
      CFReDS Data Leakage key quotes for questions 25 and 27 (`E:\Secret Project Data\` at
      10:00:19 is USRCLASS `BagMRU\1\0` written 14:00:19 UTC). It is **not** the folder's
      FAT times, which are separate fields.
    - **When it was browsed.** All three FAT date/time pairs a file-entry shell item
      carries: the **modification** time from the item itself (offset 8) and the
      **creation** and **last access** times from the `BEEF0004` extension block (block
      offsets 8 and 12), across every block version whose layout is documented (3, 7, 8, 9).
      **All three are local wall-clock with no recorded zone**, at two-second resolution,
      because that is what the FAT encoding is. Every record carrying one also carries
      `timezone: "local"` and a note saying they are **not** UTC, and the screen repeats it
      on the row; shifting one by a zero offset is wrong by whatever the machine's offset
      was. A zero pair means "not recorded" and is reported absent rather than as 1980, and
      an extension block whose version this reader does not know is read for neither name
      nor time.
    - **Bound:** a file carrying a hive's name that is not a hive (no `regf` signature, or
      shorter than the 4 KiB base block) is not parsed and does not panic; the hive reader
      is opened through `seance_hive_util::open_hive`, which guards it, and it
      leaves a `RegistryHiveParseStatus` record naming **what was not looked for** —
      "shellbags were never looked for in it" — and why.
- **Does not:** determine whether a folder still exists. No entry is compared against any
  file system and no deleted or orphaned flag is emitted, so **nothing in the output
  distinguishes a folder still present from one long gone.** It also reads no key
  last-write time, no `MRUListEx` order and no `NodeSlot`/`Bags\<n>\Shell` view state, and
  it does not parse the shell item's other structures. The shared reader is
  `seance_shell_item`, which shellbags and the registry MRUs both use;
  what it does not yet carry is the rest of each item's type-specific structure, the
  `BEEF0004` MFT file reference among it.

### `seance_plugin_prefetch`
**Responsibility:** Parsing Prefetch files (Execution history).
- **Subscribes To:** `ArtifactType::FileEntry`, `ArtifactType::SystemArtifact`. Selection
  is **by content**, through `seance_core::file_detection::detect_file_type`, and never by
  the `.pf` extension — so a prefetch file recovered from a carve or lifted out of a shadow
  copy is read on the same terms as one in `C:\Windows\Prefetch`, and a file named `*.pf`
  that is not prefetch is not read.
- **Output:** one `PrefetchEntry` `ParsedRecord` per file — which is what the Execution
  page and the findings engine consume — plus one `TimelineEvent` per non-zero last-run
  slot, and a `PrefetchParseStatus` `ParsedRecord` where a file was identified as prefetch
  and not decoded.
- **Features:**
    - **Execution Count:** how many times Windows prepared the image for execution.
    - **Timestamps:** the last **eight** execution times on format versions 26, 30 and 31
      — that is Windows 8 onwards, not Windows 10 — and **one** on versions 17 and 23.
    - **Files Loaded:** the referenced filename strings, and one entry per referenced volume
      with its device path, serial number and creation time.
    - **Compression:** the `MAM\x04` Xpress-Huffman wrapper Windows 10 and 11 write is
      inflated by a pure-Rust decoder, with the declared uncompressed length checked against
      a 16 MiB ceiling **before** anything is allocated.
- **Does not:** say who ran the program — a prefetch file carries no account, no SID and no
  session — or that a person ran it at all: Windows prepares an image for a service, a
  scheduled task or another program's child process on the same terms. It gives no full
  path (the name field holds at most 30 UTF-16 code units of the image name, and the volume
  is recorded separately), reads no path hash from the `.pf` file name, and emits no
  directory-strings list. A run count of 400 with eight recorded times leaves 392
  executions with no recorded moment.

### `seance_plugin_srum`
**Responsibility:** System Resource Usage Monitor (SRUM).
- **Subscribes To:** `ArtifactType::FileEntry` (`SRUDB.dat`)
- **Features:**
    - **App Usage:** CPU time, Bytes Sent/Received per application.
    - **Network Usage:** Wi-Fi/Cellular data usage history.

---

### `seance_plugin_webcache`
**Responsibility:** Internet Explorer and EdgeHTML browsing and cache history,
from the `WebCacheV01.dat` ESE database. This module shipped without ever being
named in this document, which is the file that owns per-platform artefact
coverage.
- **Subscribes To:** `ArtifactType::FileEntry`, gated on the ESE database
  signature and the file name — so a `WebCacheV01.dat` carved out of free space
  reads the same as one under
  `AppData\Local\Microsoft\Windows\WebCache`
- **Features:**
    - **Containers:** the catalogue's container tables, each with the name and
      directory the database gives it, so History, Cookies, Cache, DOMStore and
      the IE download list are told apart rather than merged
    - **Entries:** per container, the visited or cached URL with its access,
      modified and expiry times, the entry's own identifier and its file size
      where the container records one. `Visited: user@` decoration is stripped
      to the URL, and the decorated form is kept
    - **Completeness:** a container the catalogue names whose table will not
      open is counted and published, so a listing short of the database's own
      container count says so rather than reading as a short history
- **Bounds and gaps, stated:** the ESE reader is behind the `esedb` Cargo
  feature (`seance_api`'s three `#[cfg(feature = "esedb")]` registrations). With
  it off, an ESE database inside an image is read by nothing and — being a
  parented `FileEntry` rather than a parentless `RawEvidence` — leaves no
  unclaimed-source record either. Its one end-to-end fixture,
  `test_data/WebCacheV01.dat`, is not committed: name it with `SEANCE_WEBCACHE`
  or the two fixture-gated tests skip (loudly).

---

### `seance_plugin_chrome_cache` — blockfile long keys, key hashes, split-cache keys
**Responsibility:** Chromium's blockfile disk cache (`index`, `data_0`..`data_3`, `f_*`).
- **Long keys in a sibling `data_#`**. A blockfile entry whose
  key exceeds the 927 bytes an `EntryStore` holds inline stores it at a `long_key` address
  that may name a *different* `data_N`. The plugin is handed one file at a time, but a
  `DataSource` can open a file beside itself by name (`DataSource::open_relative`), and the
  plugin uses it: it decodes `N`, the start block and the block size from the address,
  asks for `data_N`, reads the sibling's own 16-byte header and refuses it unless the magic
  is `0xC104CAC3`, `this_file == N` and `entry_size` equals the block size the address
  implies, then reads `key_len + 1` bytes at `8192 + block × block_size` and publishes the key
  only if the trailing NUL sits exactly at `key_len` and the key hashes to the entry's value.
  The record carries `key_source: long_key_other_file`, `key_file`, `key_block`,
  `key_offset`, `key_length`. An entry whose key could not be read is still published as a
  URL-less `BrowserCacheEntry` naming its file, block and byte offset, with
  `url_unrecoverable_reason` in `sibling_lookup_unsupported` / `sibling_not_present` /
  `sibling_header_mismatch` / `sibling_short_read` / `sibling_key_not_terminated_at_length`
  / `sibling_key_hash_mismatch` / `external_file_not_opened`.
- **Inside a disk image**. `seance_core`'s `attach_sibling_bundles`
  — run by the NTFS, FAT and ext4 parsers over their listing — now also bundles the live
  `data_<n>` files of one directory onto each other by name (`SiblingBundleSource`'s
  name-keyed map, answering `open_relative`; `supports_siblings` is true when anything is
  bundled). Grouping is by the entry's `path`; deleted entries and a name that occurs twice
  in one directory are not bundled. Test: the plaso `chrome_cache` files served as path-less
  in-image sources reach both `data_2` keys.
- **Header and key verification**. The header's `entry_size` is read
  and honoured: only a 256-byte block file is walked for entries (Chromium allocates every
  `EntryStore` from one); `data_0` (36-byte rankings), `data_2` and `data_3` yield nothing
  of their own, and an `entry_size` no block file has is reported, not walked. Every
  key is checked against the entry's `hash` (SuperFastHash, `disk_cache::Hash`) and its
  trailing NUL; `key_hash` and `key_hash_verified` are on every record. The allocation bitmap
  (offset 80) is read for each entry: `allocation` is `allocated`, `free` (an evicted or
  deleted entry whose bytes survive; the name says `freed entry`) or `partly_free`.
- **Split-cache keys**. `<n>/<n>/_dk_[s_]<top-frame site> [<frame
  site> ]<url>`, `<n>/<n>/<url>` and sparse children `Range_<key>:<sig>:<child>` are taken
  apart: `url`, `top_frame_site`, `frame_site`, `subframe_document_resource`,
  `sparse_signature`, `sparse_child_id`, `cache_key` (as stored) and `cache_key_form`. A key
  that verifies by its hash in a form not recognised (`_cn_`, say) is published URL-less with
  `url_unrecoverable_reason: cache_key_form_not_recognised` and counted in
  `entries_key_form_not_recognised`.
- **Known answers.** plaso `chrome_cache/data_1`: 217 URLs (215 inline, 2 from `data_2`
  blocks 20 and 38, keys of 1,339 and 1,335 bytes), every key hash verified, every entry
  allocated. plaso `chrome_cache_v3/data_1`: **862** URLs — 816 `1/0/_dk_`, 6 `1/0/_dk_s_`,
  4 `Range_` children inline, 2 long keys in `data_1`, 33 in `data_2`, 1 in `data_3` — every
  one hash-verified and allocated; 12 blocks declaring a long key with no valid address are
  not entries. Both measured independently
  with a separate Python reader.
- **Does not:** open `f_` files or read cached content; check `self_hash` or `state`; walk the
  `index` hash table or the rankings list; recognise key forms other than those above; verify
  a Simple Cache entry's `key_hash`.

### Desktop browser and Skype stores — the schema range each parser was validated on
Every SQLite app parser now declares the schema version range it was validated against on
real files and resolves each column it reads through a candidate list before writing a
query (the record contract is in `CORE_DESIGN.md` §2.3). A
store outside its range, or with a required column no candidate matched, **still parses
everything that resolved** and carries a `ParserStaleWarning` naming the version seen and
the range, or the logical field and the columns present. The Windows-side ranges, each
endpoint read out of a named real file:

| Store | Locator | Validated range | Evidence |
|---|---|---|---|
| Chrome `History` | `meta.version` | 20..=70 | plaso 20/32/33/36; Chromebook 41; Android 51; a 2026 desktop Chrome profile 70 |
| Chrome `Cookies` | `meta.version` | 5..=24 | plaso `cookies.db` 5, `Cookies-68…` 10; Chromebook 11; Android 16; desktop Chrome 2026 24 |
| Chrome `Web Data` | `meta.version` | 77..=152 | plaso 77; Chromebook 81; Android 98; desktop Chrome 2026 152 |
| Chrome `Login Data` | `meta.version` | 24..=43 | Chromebook 24; Android 31; desktop Chrome 2026 43 |
| Firefox `places.sqlite` | `user_version` | 10..=82 | plaso 10/23 and `places118.sqlite` 75; Firefox 2026 82 |
| Firefox `cookies.sqlite` | `user_version` | 5..=16 | plaso 5/12; Firefox 2026 16 |
| Firefox `formhistory.sqlite` | `user_version` | 5..=5 | one 2026 Firefox profile; no reference corpus holds one |
| Skype classic `main.db` | `AppSchemaVersion.SQLiteSchemaVersion` | 66..=66 | plaso `skype_main.db` (Skype 6.6 era); `PRAGMA user_version` is 0 on it |

Chromium's `meta.last_compatible_version` — the browser's own floor — is carried on the
marker and spelled out in the message when it is past the validated maximum. Skype is now
identified on `Accounts.skypename` plus a `Messages` table rather than on `Messages.body_xml`,
so a store whose body column was renamed is reported as Skype-with-a-field-unresolved rather
than silently as not-Skype. **A single point or a short span is what one to four real
stores give**, so a newer store warns; that is a disclosure, not a claim that records were
missed (`REPORTING_DESIGN.md`). Three schema-drift fixes the harness forced on real files:
Chrome `History` at `meta.version` 20 has `downloads(full_path, url, …)` and every download
had been a `BrowserDownloadIncomplete`; plaso's `cookies.db` at 5 names its flags
`secure`/`httponly` and the whole jar of 560 had failed on `no such column: is_secure`;
Chromebook `Login Data` at 24 predates `date_last_used` and the whole store had failed.

### `seance_plugin_bits` — BITS job queues

**Responsibility:** the Background Intelligent Transfer Service queue — every job's
source URL, the local path it wrote, the owner SID, the job's state and times. BITS
jobs survive reboots and can run a command when a transfer completes, which is why
they are a persistence and download-cradle artifact as well as a record of what
Windows Update and Office fetched.

| File | Windows | Read by |
|------|---------|---------|
| `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr0.dat`, `qmgr1.dat` | XP to 8.1, Server 2003 to 2012 R2 | `seance_plugin_bits::qmgr_dat` |
| `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr.db` (ESE) | 10 and later | `seance_plugin_bits::qmgr_db` (feature `esedb`) |

**The binary queue.** Undocumented; the reader is a clean-room reading of real bytes
(CFReDS Data Leakage, Windows 7; DFIR Madness DC01, Server 2012 R2). A file GUID —
it differs between those two builds — then the header GUID
`{C82BF713-9940-4A12-9F1A-3AAEBD894EEA}` (Server 2012 R2 puts 8 bytes between them),
then queues, each opened and closed by `{005F4447-BDA9-44BA-9851-C47BB6C07ACE}` with
a u32 job count between, then the header and file GUIDs again. A job runs from its
16-byte delimiter to the next copy of it: type, priority, state, job GUID, name,
description, notify command and arguments, owner SID, notify flags; then undecoded
notification and security data; then the file list after
`{7756DA36-516F-435A-ACAC-44A248FFF34D}` (local path, URL, temp path, bytes
transferred, bytes total); then that GUID again and a trailer whose FILETIMEs are
located by shape, because an error block changes the trailer's length.

**What is reported, and how far it goes.** One `BitsJob` per job; the documented
`BG_JOB_*` numbering names the type, priority and state. Credentials and custom
headers are DPAPI blobs, reported present with their own description and master-key
GUID and **never decrypted** (`secrets_decrypted: false`). Of the four trailer times,
the first two are labelled creation and modification — ANSSI's `bits_parser`, run as a
black box, reads them the same way — and the other two are reported unnamed; no
transfer-completion time is claimed. Windows writes `qmgr0.dat` and `qmgr1.dat` in turn and nothing
here says which is newer: each is reported as it reads.

**The stale region.** Bytes past the live structure hold earlier states of the file.
File records found there are `BitsCarvedFileTransfer` (`recovery_method:
stale_region_carve`) with their offset — never jobs, because the header that owned
them has been overwritten. On the Data Leakage PC this is where the Outlook
offline-address-book downloads survive; `qmgr0.dat`'s live queue is empty and its
.NET setup download survives only there.

**The ESE queue, `qmgr.db`.** Tables `Jobs` and `Files`, columns `Id` and `Blob`; a
database without both is not this module's (SRUM, WebCache, UAL and the Search index
all reach it and yield nothing — pinned on every clone against a committed LoneWolf
SettingSync `meta.edb`, and against plaso's copies where `reference/` is present). A
database is copied to a temporary file in 8 MiB chunks and read back into memory only
once it has shown those tables. A `Jobs` blob is a 16-byte GUID then the `.dat` job
header; a `Files` blob a short prefix then the `.dat` file record; both are located by
shape. **Only the job header is read from a `Jobs` blob**: the rest of it, which holds
the job's file list and times, is not decoded, so a `qmgr.db` job carries
`files_read: false`, `times_read: false`, `creation_time: not_read`, no file count or URLs,
and `content_incomplete` saying so; `Files` rows are published as `BitsFileTransfer`
records not linked to any job (`file_rows_linked_to_jobs: false` on the summary). Those layouts were read off record images —
LoneWolf's `edb00001.log` and its database's unreferenced pages — because **the one
real `qmgr.db` held has no rows**: it was imaged running, its header says dirty
shutdown, and its state is in `edb*.log`, which libesedb does not replay. The summary
(`BitsQueueDatabase`) says so and is stamped incomplete; file records the byte scan
finds that no row holds are `BitsCarvedFileTransfer` (`database_byte_scan`, with the
page). Log replay and log carving are not done.

**Refusals.** A file named `qmgr0.dat`/`qmgr1.dat` that does not open with the
GUIDs gets `BitsQueueIncomplete` (`status: NotDecoded`), not an empty summary. So does a
file named `qmgr.db` that cannot be read or staged, is not ESE, will not open, or lacks
the two tables. The `BitsQueueFile` summary names the file's first 16 bytes `file_guid`
(the header GUID is a different, fixed one, whose offset is `header_guid_offset`); a
walk that stops early keeps what it read, stamps `content_incomplete` on the
`BitsQueueFile` summary and says where it stopped.

### `seance_plugin_rdp_cache` — the RDP client's bitmap cache

**Responsibility:** the screen fragments `mstsc` kept from sessions this machine opened
*to* other hosts, under `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\`.

| File | Read |
|------|------|
| `Cache####.bin` (`RDP8bmp` container) | yes — every tile |
| `bcache*.bmc` (older format) | recognised by name; empty reads as empty, non-empty is **not decoded** (no real sample held) |

**Layout, as measured** on DFIR Madness DC01's `Cache0000.bin` (version 4, 86,964,396
bytes): a 12-byte header (`RDP8bmp\0`, u32 version), then tiles back to back — 8-byte
key, u16 width, u16 height, `w × h` four-byte pixels (blue, green, red, then a byte that
is zero throughout and is dropped). That file is exactly 5,304 tiles of 64 × 64.

**Output.** Each tile is a PNG `FileEntry` child (`RdpCacheTile`, `…_tile_NNNNN.png`)
with its index, key and offset, so it reaches the gallery, hashing and OCR. Every tile
also goes into **one collage per cache file** (`RdpCacheCollage`,
`…_collage_cache_order_not_a_reconstruction.png`, 64 cells of 64 px across, cache order
left to right, top to bottom) whose record carries `reconstruction: false` and a note
opening *not a reconstruction* — nothing here fits tile edges together. A tile that cannot be read back leaves its cell black
(`cells_blank`), so no later tile shifts into its place. The collage PNG is streamed one
band of 64 cells at a time, so only one band's pixels (768 KiB) are held however many
tiles the file has; DC01's collage is 4,096 × 5,312 px. A side of 0 or over 64, a
partial last tile or the 65,536-tile cap stops the walk and marks the summary incomplete.

### `seance_plugin_winsearch_edb` — the Windows Search index

**Responsibility:** `%ProgramData%\Microsoft\Search\Data\Applications\Windows\Windows.edb`,
the indexer's ESE database — one row per file, folder, Outlook item or IE favourite/history
entry it saw, with the properties it recorded. A row can outlive the file it names.

| Layout | Table | Row key | 8-byte times and sizes | Measured on |
|--------|-------|---------|------------------------|-------------|
| Windows 7 | `SystemIndex_0A`, one column per property (`System_ItemPathDisplay`) | `DocID` | big-endian | CFReDS Data Leakage (464 rows) |
| Windows 10 | `SystemIndex_PropertyStore`, columns prefixed `NNNN-` / `NNF-` | `WorkID` | little-endian | LoneWolf 1709 (822 rows, a floor) |
| Windows 11 22H2+ | `Windows.db`, SQLite | — | — | **refused**, named |

A database is this module's only when one of those tables carries a path property. It is
copied to a temporary file for libesedb in 8 MiB chunks (only the 4 KiB header is held in
memory); a file named `Windows.edb` that cannot be read or staged, is not ESE, or carries
neither table is refused by name, never shown as an empty index. 46
named properties are read (path, URL, names, type, size, attributes, five times, owner,
flags, link and IE targets, mail sender/recipients/dates, subject, author, auto-summary);
the rest of the several hundred columns are not. Eight `0x2A` bytes (size) and `0x2A2A2A2A`
(attributes) are "not set". Windows 7 stores some text — the auto-summary above all — as an
obfuscated binary value: XOR with `0x05000113 ^ length` and the byte index (the key in
libyal's format notes, checked on every such value here), then a type byte — `1` eight-bit
text, `0` runs of *count, high byte, low bytes*, both decoded; `2` and `3` (a Huffman-table
form) are **not decoded** and are named per property on the row
(`properties_not_decoded`), never rendered. On Data Leakage that is 10 of 113 summaries.

**Two things the summary always says when they apply.** A dirty-shutdown header (both real
indexes are dirty) means the transaction logs hold changes this read does not replay. And on
LoneWolf, libesedb's first count of the table fails on a page that is not a leaf; the count
it returns on a second call is used and stated as a floor.

**Fuzzing and the viewers.** `bits_qmgr`, `rdp_cache` and `winsearch_edb` are targets in
`fuzz/fuzz_targets/`. The analysis screen has a viewer for `BitsJob`, `BitsFileTransfer`,
`BitsCarvedFileTransfer`, `WindowsSearchItem` and `RdpBitmapCache`; a header-only `qmgr.db`
job is shown with the reason its file list is absent, and a carved BITS record is labelled as
carved. The tiles and the collage reach the gallery as PNG children.

### Clipboard history

Windows 10 1809 and later keep a clipboard history behind **Win+V**: about 25
items, with the option to pin one. Almost all of it is held by the clipboard
service (`cbdhsvc`, in `svchost.exe`) **in memory**, and cleared on sign-out or
restart. Three places carry it, and they are not interchangeable.

| Where | Holds | Read by |
|---|---|---|
| `cbdhsvc` process memory | The live history — most of it | A memory capture; no dedicated stage yet |
| `%LOCALAPPDATA%\Microsoft\Windows\Clipboard\` | Pinned items, and history items when sync is on | `seance_plugin_clipboard` |
| `ActivitiesCache.db` → `ClipboardPayload` | Clipboard content, where Windows Timeline is present | `seance_plugin_win_timeline` |

**On-disk layout.** `Pinned` and `HistoryData`, each holding a GUID folder, each
of those holding one GUID folder per item. Inside an item: `metadata.json`, and
one file per clipboard format **named for the format in base64** — `VGV4dA==` is
`Text`, `Qml0bWFw` is `Bitmap`, `TG9jYWxl` is `Locale`. Unpinning removes the
folder outright rather than marking it deleted.

**The payloads are encrypted and Séance does not decrypt them.** Windows uses
CNG DPAPI (`NCryptProtectSecret`), which writes an ASN.1 CMS enveloped-data
blob; the plaintext needs the user's DPAPI master key or a domain root key over
RPC. What is readable without it: the item's existence, a time from its
inventory entry (the first of eleven candidate field names that holds a
plausible 2018–2100 time; which one is named on every record and timeline event
as `timestamp_field`, because no real store has confirmed which field is the pin
time), the clipboard format (from the filename), and the SID the payload was protected to —
which sits in the blob's *unencrypted* header, by design, and answers whose
clipboard it was.

**Registry.** `HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory`
(DWORD) records whether the feature was on. A user profile with the feature off
explains an empty store, and is a different finding from a store that was
cleared.

**Verified against Windows 11 25H2.** On a live 25H2 build the store
is exactly `…\Clipboard\HistoryData\{GUID}` and `…\Clipboard\Pinned\{GUID}` —
which is what `seance_plugin_clipboard::layout::locate_store` recognises. It also
confirmed the memory-only model: enabling history and copying items creates the
`HistoryData`/`Pinned` GUID folders but leaves them **empty** until an item is
actually pinned (Win+V) or clipboard sync is on — so a populated on-disk item
requires interactive use or a Microsoft-account sync, not merely a copy. An
end-to-end extraction test therefore needs a genuinely-pinned item; the parser
itself is exercised by its unit tests against this layout.

**A correction worth carrying.** Several published clipboard-forensics
write-ups point at `%ProgramData%\Microsoft\Windows\ClipSVC` and its
`tokens.dat`. **ClipSVC is the Client License Service** — Microsoft Store
licensing and Windows activation — and has nothing to do with the clipboard. The
name collision is the whole of the connection.

### Windows Timeline (`ActivitiesCache.db`)

`seance_plugin_win_timeline` (`plugin.windows.timeline_activity`) reads the
per-user activity database that the ConnectedDevicesPlatform service writes on
Windows 10 and 11, normally under
`\Users\<name>\AppData\Local\ConnectedDevicesPlatform\<id>\`. Each row records an
app launched, a document or page opened, a window in focus or a clipboard copy.

**Selection.** The artifact must be a file whose last path segment is
`activitiescache.db`, with a data source, and its first 16 bytes must be
`SQLite format 3\0`. The database is staged under a 2 GiB cap together with its
`-wal` sibling where the source can open one, because a live cache often holds
its newest activities only in the log. A shadow-copy prior version is read too,
named by its `file_name`. Its sidecars are not searched.

**Tables read**

| Table | Columns | Use |
|-------|---------|-----|
| `Activity` | `Id`, `AppId`, `ActivityType`, `ActivityStatus`, `Group`, `Payload`, `ClipboardPayload`, `StartTime`, `EndTime`, `LastModifiedTime`, `ExpirationTime`, `LastModifiedOnClient`, `CreatedInCloud`, `IsLocalOnly`, `PlatformDeviceId` | One record per row. |
| `ActivityOperation` | The same columns plus `OperationType` and `OperationOrder` | One record per row when the table exists. |
| `Activity_PackageId` | `ActivityId`, `Platform`, `PackageName` | Read whole into a map keyed by activity id, for app attribution. |

The schema is checked in three answers. `Activity` and `Activity_PackageId` must
both be listed, and `Activity` must carry `ActivityType`, `Payload` and
`StartTime`. A readable catalogue that lacks them is not a Timeline database and
yields nothing. A catalogue or column list that will not answer is damage and
yields a `WindowsTimelineParseStatus` record with status `DatabaseUnreadable`.
`ClipboardPayload` and `CreatedInCloud` arrived in build 1903 and are not
required. The query selects only the known columns that exist, and the walk has
no row limit. An `Id` is a text GUID as stored, or a 16-byte blob in Microsoft's
mixed-endian layout.

**Activity record.** Each row gives one `WindowsTimelineActivity` record with
`source_table`, `activity_id` and these fields:

- `executable` resolved from the `AppId` JSON array of `{application, platform}`
  entries, then the package map. The order is a `windows_win32` path, an
  `x_exe_path`, a `windows_universal` id, then the first entry. A leading
  Known-Folder GUID on an `x_exe_path` is rewritten to its name from a table of
  20, such as `%ProgramFiles%` or `Downloads`. Any other GUID stays verbatim.
- `app_id_raw`, kept to 64 KiB, with `app_id_raw_truncated` stated on every
  record.
- `activity_type` and an advisory `activity_type_label`: 2 Notification, 3
  Mobile backup or Azure auth, 5 Open app, file or webpage, 6 App in focus, 10
  Clipboard, 11, 12 and 15 System operation, 16 Copy and paste, otherwise
  `Type n`. The labels are the community's reading of undocumented values.
- From the `Payload` JSON object: `display_text`, `app_display_name`,
  `description`, `activation_uri`, `content_uri` percent-decoded,
  `reporting_app`, `active_duration_seconds`, `user_timezone` and
  `device_platform`. A payload that is not a JSON object sets `payload_binary`
  and nothing else is guessed.
- From `ClipboardPayload`, a JSON array whose first entry with `content` is
  base64-decoded: `clipboard_text` only when its `format` is `Text`, capped at
  8 KiB with `clipboard_text_truncated` stated, plus `clipboard_bytes` and
  `clipboard_format`. A bitmap or other format gives the format and byte count
  and no text.
- `activity_status`, `group`, `created_in_cloud` as stored, `is_local_only`,
  `platform_device_id`, `packages`, `operation_type` and `operation_order`.

**Time.** Every timestamp column holds Unix seconds in UTC. A value that is not
positive is omitted and never shown as 1970-01-01. `start_time` is also `date`.
`duration_seconds` is `EndTime - StartTime` and is set only when the end is
after the start. `active_duration_seconds` is the payload's own figure for time
in focus, and the two are different measures. `user_timezone` is carried as
recorded and is not applied to any timestamp. A `TimelineEvent` with
description `Windows Timeline Activity` is raised for each record with a
positive `StartTime`, with the content URI or display text as its file name. A
record with no valid start keeps its record and has no event.

**Completeness.** A cap on `AppId` or clipboard text sets `content_incomplete`
with reason `app_id_raw_capped` or `clipboard_text_capped`. A row of either
activity table or of `Activity_PackageId` that will not decode, or a query that
will not run, stamps every record `content_incomplete` and `inventory_incomplete`
and appends a `RowsNotDecoded` status record with the row counts. The activities
listed are then a floor and not the user's whole history. A database staged
short is stamped the same way.

**What is not read.** The `Manifest`, `Metadata`, `AppSettings`,
`ManualSequence`, `DataEncryptionKeys` and `LocalCache` tables are not read.
The columns `MatchId`, `OriginalPayload`, `OriginalLastModifiedOnClient`, `Tag`,
`Priority`, `ETag`, `PackageIdHash` and `UserActionState` are not read, nor is
`Activity_PackageId.ExpirationTime`. Deleted rows are not recovered. The owning
user is not taken from the path. A synced activity's origin device is only what
`platform_device_id` carries. Clipboard content past 8 KiB and non-text
clipboard content are not shown. Windows keeps its clipboard history elsewhere,
and `seance_plugin_clipboard` reads that.

### Outlook mail stores — `seance_plugin_email` (PST and OST)

Outlook's stores share the `!BDN` node database. The header's `wVer` at offset 10 picks the
reader: **14/15** (ANSI) and **23** (Unicode, 512-byte pages) go to the linked `outlook-pst`
library; **36** — the layout Outlook 2013 and later write for offline stores — goes to this
crate's own reader, `seance_plugin_email::ost4k`; any other
version is refused by its number, never called invalid.

**What the PST/OST reader says about itself.** The store is handed to the linked
reader from memory (an owned cursor over a copy of the bytes), not through a file in the shared
temporary directory, so no copy of the evidence is left readable by another local user or behind
after a kill. A store whose header names version 14, 15 or 23 and that the linked reader still
refuses is reported as "a PST/OST store, format version N … this build's reader refused its
structure (<the reader's own reason>) … not shown to be malformed"; "Not a valid PST file" is kept
for a file with no `!BDN` magic. On both layouts a message whose full read fails is re-read from
eight properties (`MINIMAL_PROPS`, one list for both) and published as `read_fallback: true`,
`content_incomplete` (`unresolved_structure`), with `properties_unreadable` saying the rest were not
read; the summary counts these as `messages_partial`. A hierarchy table that names a folder already
entered (a pointer back at an ancestor) is skipped and counted as `folder_cycles`, so its messages
are not published again. An HTML body is decoded in `PidTagInternetCodepage` (Windows 125x, UTF-8,
ISO 8859, the common East Asian pages); with no code page, or an unknown one, it is UTF-8, and
`body_decoding_lossy` is set, with `content_incomplete`, whenever bytes were replaced.
`body_truncated` is true when either the plain or the HTML body passed 64 KiB. The sender's name and
address come from one party (the sender when it has a usable address, else the party it sent on
behalf of), and the other is `sent_on_behalf_of`. For versions 14, 15 and 23, a recovery listing that
stopped at its cap sets `content_incomplete` with `cap_reached` on the summary (the live inventory is
not marked short by it); for version 36 the folder cap does not apply (every folder is listed and
counted) and the message cap is reported only when messages were left over, so exactly 10,000 folders
or exactly 100,000 messages is not "stopped at a parser cap". The cases listed as undecided
(`deletion_status: undecided`) are not marked incomplete by that alone.

Version 36 as read, with no Microsoft specification to lean on — every offset below was
measured on the one real file held, the NIST Data Leakage suspect's OST
(`seance_plugin_email/tests/fixtures/ost_v36/`), with `libpff`'s format notes as a guide:

| Structure | Layout |
|---|---|
| Header | as version 23: `dwCRCPartial` at 4 over 8..479, `dwCRCFull` at 524 over 8..524, `ibFileEof` at 184, NBT root BREF at 0xD8, BBT root BREF at 0xE8, `bCryptMethod` at 0x201 |
| B-tree page | 4,096 bytes; metadata at 4056 (`cEnt` u16, `cEntMax` u16, `cbEnt`, `cLevel`); trailer at 4072 (`ptype` ×2, `wSig`, `dwCRC` over 0..4072, `bid`, 8 bytes not interpreted); intermediate entries 24 bytes, NBT leaves 32, BBT leaves 24 (`bref`, `cb`, `cbInflated`, `cRef`) |
| Block | 512-byte aligned, slot `align(cb + 24, 512)`; trailer ends the slot (`cb`, `wSig`, `dwCRC` over the stored bytes, `bid`, 2 bytes not interpreted, `cbInflated`); zlib stream where `cb ≠ cbInflated` |
| XBLOCK / SLBLOCK | as version 23's 64-bit forms |

**A partly initialised file.** On the image the OST's `$DATA` is 16,818,176 bytes with an
initialised size of 3,360,768, so everything past that reads as zeros. The reader names a page
or block that lies past the bytes it was given, or that is all zeros, as never written —
`page_faults`/`block_faults` with `pages_unwritten`/`blocks_unwritten` on the summary and the
`short_read` incompleteness reason — and never walks zeros as a page. On this file every
referenced page and block lies below 0x98000, so the mailbox is whole. The non-zero data up
to 0x334000 that neither tree references is walked for deleted mail (below); past the bytes
supplied nothing is examined, and the summary's `store_note` says so. The summary also records `header_file_eof` beside `bytes_supplied`.

**Deleted-mail recovery (`ost4k::recover`).** The same page and block reads with
the allocation map ignored. Every 4 KiB-aligned offset is tried as a B-tree page and every
512-byte boundary as the end of a block slot; each is accepted only when its trailer's
signature matches its own offset and BID and its CRC matches (the signature is checked first,
so non-block bytes cost no CRC). Then:

* a **node B-tree leaf page no live tree references** yields the entries of message nodes the
  live node B-tree no longer holds. Every version of an entry (one per data BID) is kept; the
  newest that reads is the one published, the others are listed
  (`recovery_other_versions`, each with `newer_than_recovered` and, for every version that was
  tried, its `read_error`: versions are tried newest first until one reads, so when none reads
  every version carries its own error and `recovery_gaps` names each). When a newer version did not read and an older one did, the
  older is published as `partial` with a gap saying it is an earlier state, not necessarily the
  message's last. Its data and subnode blocks are looked up among every block
  found, referenced or not. A read that loses the subnode tree is `partial`; an entry whose data
  block is not found anywhere is `entry_only` and named in the summary's
  `recovered_entries_without_data`, never published as a message.
* a **message property context in an unreferenced block** that no recovered entry names is a
  fragment (`recovery_source: unreferenced_block`), always `partial`: its folder and subnode
  tree are unknown.
* **deleted is decided only when the live walk was whole.** When a page of the live node
  B-tree did not read, or a live message node was unreadable, a recovery may be live under a
  node that walk never reached; it carries `deletion_status: undecided` and `could_be_live`
  (the reasons, naming the unread page when the node's id falls under it), and the summary
  counts them. Otherwise `deletion_status` is `deleted`.
* an unreferenced property context whose `PidTagMessageFlags` carries `mfFAI` (a view, rule or
  configuration message) is not mail: it is counted in the summary note, not listed.
* a recovery whose class, subject and at least one of the two times (submit, delivery) match a
  live message is not a deleted message; a message with no subject or neither time has no identity
  and is never merged with another (two different appointments with one subject and no times are
  not merged):
  a deleted node holding a live message (moved or re-synchronised) is listed in
  `recovered_copies_of_live`, and an unreferenced copy is counted in `superseded_copies`.

Each recovered record carries `recovered: true`, `allocation: unallocated`, `recovery_source`,
`recovery_completeness`, `recovery_gaps` and `recovery_offsets` (`nbt_pages`, `data_block`,
`subnode_block`); a `partial` one is also `content_incomplete` (`unresolved_structure`), and its
timeline event carries the same two marks. At most 10,000 recoveries and 10,000 fragments are
listed (`recovery_capped`, and `content_incomplete` with `cap_reached` on the summary). A page or
block whose trailer signature matched and whose CRC or metadata did not is counted
(`unreferenced_pages_unvalidated`, `unreferenced_blocks_unvalidated`, with the first 100 offsets),
and so is an unreferenced block that carries the property-context signature and did not decode
(`property_contexts_not_decoded`, with block id, offset and reason); a signature match is a 16-bit
check, so some are chance and the counts are worded as "matched, not validated", not "damaged". The
claim of every data block of a stale entry's tree (not only its top block) keeps the first leaf of a
multi-block message from being listed as a fragment, and an attachment that will not read is named
with its node, block and reason. On the Data Leakage OST: 37 unreferenced B-tree pages and 101
unreferenced blocks; five deleted message nodes — NIST's "It's me" (read whole, but graded partial:
the entry's newest version, data BID 0x7830, is in no block that could be found, so what is
published is an earlier state), "RE: Last
request" at 13:30:10 UTC and "Watch out!" (complete), "RE: Good job, buddy." (partial, its
subnode tree overwritten) and one whose data block 0x7278 is gone; no fragments. Only "It's me"
is in NIST's key; the other three are not graded. The fragment rule is pinned on a synthetic
store. PST/OST versions 14, 15 and 23 are walked by `seance_plugin_email::pst512`:
every 512-byte offset is tried as a B-tree page (trailer type, signature and CRC, with the 12-byte
ANSI or 16-byte Unicode trailer) and every 64-byte boundary as the end of a block, the same
stale-entry and unreferenced-block rules apply, and the output is the same `Recovery`, published by
the same code. Graded on a real version 14 mailbox against libpff; the version 23 layout is graded
on a real 543-item mailbox against libpff (`SEANCE_PST23_CORPUS`): live reading matches, and
the three messages recovered from its Deleted Items are not corroborated by libpff. Fuzz target
`pst512_parser` (compiled, not yet run).

**Bounds.** B-trees 8 pages deep with a visited-page set; a block inflated to at most one byte
past its stated size; data trees no deeper than an XXBLOCK, in which a block named twice is
refused (so a tree reads each block at most once), every XBLOCK's and XXBLOCK's `lcbTotal` must
equal what its leaves hold and reading stops as soon as they pass it; subnode trees with the
same repeated-block refusal; a B-tree-on-heap 8 levels deep whose walk refuses a node named
twice; and a store-wide read budget — node reads may assemble at most 8 times the inflated
bytes the block B-tree holds, plus 1 MiB (the Data Leakage OST's whole mailbox reads 140,192
bytes against 369,411 held), past which a node is named unreadable with the budget as the
reason. Fuzz target `ost4k_parser`, which re-seals every page CRC it
can reach from the roots and every block CRC the block B-tree names after mutation, so
mutations reach the internal-block, heap and property-context readers rather than stopping at
a CRC.

**Not read.** Encoded stores (`bCryptMethod` ≠ 0, refused by number); folder-associated
messages; contents and hierarchy tables (messages are placed by their node's parent NID and
checked against the folder's `PidTagContentCount`); the recipient table of a message whose row matrix is held in a subnode (read for the heap case in every version); compressed-RTF bodies.
A message whose only body is `PidTagRtfCompressed` publishes `body_source: rtf_not_decoded`
with `content_incomplete` (`compressed`) — its body is present and was not read — never
`none`, which is kept for a message with no body property at all. A folder with fewer messages
than its `PidTagContentCount` marks the summary incomplete; one with more is listed in
`folder_count_mismatches` and stated in `store_note` but does not, since nothing read is
missing. A summary whose message cap fired keeps `cap_reached` as its reason when a later
shortfall is added. A B-tree page referenced from more than one parent is walked once and
named (`referenced by more than one parent page`), not called a cycle — a shared child and a
loop look the same to the walk.

## 4. Log Analysis

### `seance_plugin_evtx`
**Responsibility:** Parsing Windows Event Logs (`.evtx`), and recovering the records the
intact parser cannot reach.
- **Subscribes To:** `ArtifactType::FileEntry` and `ArtifactType::SystemArtifact`. The
  intact walk runs on a detected EVTX file; the recovery pass also runs on an input that is
  **named** `*.evtx` or carries an `ElfChnk\0` signature in its first 64 KiB, which is how a
  fragment with no file header — carved from free space, or a log whose header was
  overwritten — is reached. A chunk lying on its own in free space is carved by the
  `EVTX chunk (Windows event log)` signature (`seance_carving/src/formats/evtx_chunk.rs`: the
  `ElfChnk\0` magic with `header_size` 128 and a free-space offset inside the chunk, one fixed
  65,536-byte extent, extension `.elfchnk`, clamped and marked not validated when the source
  ends inside it), and the carved `FileEntry` reaches this module through the
  chunk-signature gate. A whole log carved from free space (the `EVTX` signature, `ElfFile\0`)
  is sized by walking its consecutive `ElfChnk\0` chunks from offset 4,096 and stopping at the
  first 64 KiB block that is not one — never by the header's chunk count (a u16 at 0x2A), which
  real logs contradict both ways: omerbenamram's `system.evtx` says 3 and holds 15, plaso's
  `System2.evtx` says 96 and holds 3. Zeroed blocks a log preallocated past its
  last chunk are outside the carve. Every other file is left alone.
- **Output:** `EvtxLogEntry` `ParsedRecord`s and `TimelineEvent`s for the intact walk with an
  `EvtxParseStatus`; `EvtxRecoveredLogEntry` records and their timeline events for the
  recovery pass with one `EvtxRecoveryStatus` per input. A recovered record is a **different
  type** from a live one and carries a `recovery_source` a live record never has, so a filter
  by type cannot pick up a recovered event as live.
- **Features:**
    - **Chunk Parsing:** Parse binary XML chunks. Each chunk is decoded in isolation: a
      chunk whose decoder panics loses that chunk and no other, and a chunk whose string or
      template table would send the decoder round a cycle (or off the end of the chunk) is
      refused before decoding. Both are counted as unreadable chunks in the
      `evtx_parse_status` record the parser emits, so a log with lost chunks says so. A file
      that ends inside a chunk (bytes past the last whole chunk that open with `ElfChnk\0`)
      is counted on the same record — `chunks_truncated_at_eof`, `truncated_chunk_offset`,
      `truncated_chunk_bytes_present`, reason `chunk_truncated_at_end_of_file` — because the
      upstream walk stops at `(size − 4096) / 65536` whole chunks and would otherwise report a
      complete read; the chunk's surviving records come from the recovery pass.
    - **Event IDs:** Well-known IDs are given a description on the timeline (4624 logon, 4688
      process creation, 7045 service install, and others in `get_event_description`); every
      record is emitted, none is filtered out.
    - **Recovered records**. `seance_plugin_evtx::recovery` runs after the
      intact walk, in three bounded and counted stages. **(1) Carve.** `ElfChnk` chunks are
      found by signature at any byte offset (a 2 GiB scan bound, 16,384 chunks). Each chunk's
      header CRC32 (bytes 0..120 + 128..512) and data CRC32 (512..free-space offset) are
      computed separately — `valid`, `failed`, `absent` (the `NO_CRC32` flag) or
      `unverifiable_truncated` — and a relaxed walker decodes records without trusting the
      header: it walks by record magic, size and trailing size copy, requires the fragment
      header and template-instance token, resynchronises on the magic after a record whose
      size does not lead to the next, ignores `free_space_offset` and `last_record_id`, and
      zeroes a string/template table that cannot be walked (`chunk_header:
      tables_discarded`) so names and templates are read from the data. The intact walk
      records which chunks it decoded whole and which record ids left live; recovery pools
      templates from whole-live chunks, re-walks partly-live chunks minus the live ids, and
      never re-emits a live record (`record_id_also_read_live` marks a slack record whose id a
      live record in the same chunk also carries — most likely an earlier write of that
      record, kept because that is an inference the examiner decides). **(2) Pool templates across chunks.** A
      definition is rendered once with every substitution replaced by a sentinel and keyed by
      its identifier and a hash of that text; a record whose own chunk lost its definition is
      rendered from an identical definition found elsewhere and says so
      (`rendered_with_borrowed_template`, with the `borrowed_template` block naming the
      source chunk, how many candidates matched and whether the GUID confirmed it). **(3)
      Re-bind loose records.** A record outside every carved chunk, or whose template will
      not read, has its substitution array decoded value by value from the descriptor table,
      so one corrupt value does not lose the rest; what cannot be rendered is named by
      substitution index in `incomplete_substitutions`, and the record is `partial`.
      **Where each record came from** is typed: `recovery_source` is `carved_chunk` (below a
      chunk's free-space offset, not decoded live), `chunk_slack` (past it — an earlier use of
      the chunk, decoded against a poisoned window so a reference into rewritten bytes fails
      rather than reads garbage) or `loose_record` (no chunk header; the window was inferred).
      Every recovered record also carries the chunk's offset, header state and both checksum
      states, `chunk_truncated`, the record's own offset, size and trailer validity, and a
      `recovery_note` in words. A `chunk_slack` record's checksum states are `not_applicable`:
      the data CRC stops at the free-space offset and the header CRC covers the real header,
      not the synthesised one the record was decoded under, so neither covers its bytes. The
      containing chunk's own states travel as `containing_chunk_header_checksum` /
      `containing_chunk_data_checksum` with a `chunk_checksum_note` saying so.
      **The status record states every bound with its number and lists the chunks of note by
      offset.** `EvtxRecoveryStatus` carries `bytes_declared` and `bytes_scanned`,
      `short_read` (an input that declared more bytes than it returned is disclosed as one,
      with the unscanned remainder named; it is not presented as a complete scan), the chunk
      tallies (found, checksum valid / failed / absent / unverifiable, truncated, read live,
      tables discarded, unopenable), the record tallies (recovered, partial, header-only,
      borrowed template, already live), the loose-record and template-pool tallies, every
      ceiling under `limits` (2 GiB, 16,384 chunks, 500,000 records, 4,096 pooled templates,
      1,024 listed chunks) with a `*_bound_hit` flag beside each, and a `chunk_listing` — every
      chunk with a checksum that did not verify, a truncation, discarded tables, a failure to
      open, or records recovered, **named by offset** with its checksum states and per-chunk
      record counts, up to its own bound with the omitted count stated. `counts_are_floor` is
      set whenever any bound or a short read applied.
      **Real-file evidence** (`SEANCE_EVTX_CORPUS`): plaso's `System2.evtx` — a real Security
      log whose third chunk was truncated by whoever copied it, which the intact walk had
      silently lost (89 records with no status at all; the recovery status discloses it
      under `chunks_truncated`, and the intact walk's own `EvtxParseStatus`
      names it at offset 135,168 with 64,832 bytes present) — with, per test, its file header zeroed, one chunk header
      zeroed, a template's fragment header overwritten, or chunks copied into unrelated bytes
      at sector offsets; and the omerbenamram `system.evtx`, whose chunk 14 slack holds 79
      stale records.
- **Does not:** carve anything itself — an orphan chunk in free space reaches it only as the
  `FileEntry` the carver emits for the `EVTX chunk` signature, so a chunk in a region the
  carver was not run over is not seen; nor list a failed-checksum chunk that lies outside the
  listing bound other than by count. The vendored `evtx` crate's
  `EvtxChunkData::validate_data_checksum` / `validate_header_checksum` answer `false`, not
  panic, on a chunk whose checksummed bytes are not all present; neither the
  intact walk nor recovery calls them on a partial chunk.

### `seance_plugin_recyclebin`
**Responsibility:** Parsing `$Recycle.Bin`.
- **Subscribes To:** `ArtifactType::FileEntry` (`$I*`, `$R*`)
- **Features:**
    - **Deletion Metadata:** Original filename, deletion time, file size.
    - **User Attribution:** Map SID to user who deleted the file.
    - **Every `$I` name is read** (`VALIDATION.md` `LEAK-2`). The six random
      characters of a `$I` name are `0-9A-Z`, and the parser once skipped every name beginning
      `$ID`: one deletion in thirty-six, silently. On the Data Leakage PC, 13 of 14 `$I` files
      read and `$IDOI3HE.jpg` (Tulips.jpg, 2015-03-24 20:11:42 UTC) did not. The real file is a
      committed fixture (`seance_plugin_recyclebin/tests/fixtures/`, SHA-256 `610ec17f…b3f4a`).

---

## 5. Enterprise & Commercial Features (Advanced)

### `seance_plugin_amcache`
**Responsibility:** Parsing `Amcache.hve`.
- **Subscribes To:** `ArtifactType::FileEntry`, `ArtifactType::SystemArtifact`
- **Features:**
    - **File presence, not execution.** The keys this reader takes —
      `InventoryApplicationFile` and `File` — are written when Windows **catalogues** a
      file. They carry no run count and no last-run time, and this module emits none. An
      `AmcacheEntry` establishes that the file was on the machine and what it was; it does
      **not** establish that it ran, and the findings layer raises its own detections for
      it (`inventoried_binary_absent_from_filesystem`,
      `inventoried_binary_only_deleted_entries`) rather than folding it in with prefetch.
    - **Presence of deleted binaries:** an entry survives the file, so a catalogued file
      with no live file entry is recoverable from here.
    - **SHA1 Hashes:** the hash the hive recorded for the file (useful for malware
      correlation).
    - Also reads the Windows 7 `RecentFileCache.bcf` format, whose only recognised
      signature is `0xDEADBEEF`.
    - **LinkDate, judged before it is a timeline event.** `LinkDate` is the PE header's
      link timestamp copied into the hive; Windows 10 and later Microsoft binaries carry a
      reproducible-build *hash* there, not a time. Each entry records
      `key_last_written` (the hive key's own write time) and `link_date_plausible`: a
      LinkDate later than the key that records it cannot be a link time and stays on the
      record with `link_date_note`, off the timeline. Before this, Case 001's timeline
      opened with `Amcache LinkDate` events dated 2090, 2077 and 2049. The
      timeline event is labelled `Amcache LinkDate (PE link time)` so it is read as a
      build attribute, not host activity.

### `seance_plugin_pe`
**Responsibility:** PE / Authenticode analysis of Windows executables — a SigCheck-style
reader that self-selects on the DOS `MZ` magic by content, never by filename.
- **Subscribes To:** `ArtifactType::FileEntry`, `ArtifactType::FileContent`
- **Output:** one `PeSignature` `ParsedRecord`
- **Features:**
    - **Authenticode:** signed or not, the signer subject, the issuing CA, the validity
      window, and whether the signature is *internally intact* — the Authenticode PE hash is
      recomputed and compared to the digest inside the PKCS#7. `signature_integrity` reads
      `valid (bytes match the signed digest)`, `MISMATCH — file does not match its signature`,
      or `unverified (why)`. **No OS-level trust-chain validation is claimed**: "valid" means
      the bytes match what was signed, not that the signer is trusted.
    - **Where the hash ends.** Authenticode hashes the image up to
      `FileLength − SizeOfCertTable` and **nothing at or after it**: the optional-header
      checksum and the certificate-table directory entry are the two holes, and the
      certificate table is the end. In a file a signing tool wrote the table is last, so that
      boundary and the end of the file are the same byte. On evidence they are not. The hash
      stops at the table. Continuing past it, on a PE carved from unallocated space — where the
      end offset is derived as `max(PointerToRawData + SizeOfRawData)` and is therefore a
      guess — covers the overshoot and produced **231 `Strong` "modified after it was
      signed" findings against 231 unmodified binaries** on one image. Stopping
      at the table reproduced the signed digest for 231 of 231. No synthetic padding is added
      either: the specification's 8-byte alignment rule is for an image with *no* certificate
      table, and injecting zeros would hash bytes that are not in the evidence.
    - **`signed` is null, never false, when the question is open.** A capped or short read
      leaves the certificate table — which sits at the end of a signed image — unreached, so
      the verdict is withdrawn rather than reported negative (`B2-052`), and
      `analysis_incomplete` / the standard `content_incomplete` pair are stamped (`B6-009`).
      An image whose declared certificate table lies outside the bytes held is
      `table_unreadable` for the same reason (`B2-169`).
    - **Version resource, imphash, headers and section entropy:** CompanyName / ProductName /
      OriginalFilename etc.; the import-table hash for family clustering; machine, subsystem,
      compile timestamp; the highest section entropy with `likely_packed` above 7.2 bits/byte.
    - **An `MZ` file that will not parse still leaves a record** (`B6-010`), carrying
      `status: pe_unparsable` and the incompleteness pair — silence would file a deliberately
      malformed dropper beside every text document in the case.
    - **Provenance carried from the source artifact**:
      `in_alternate_data_stream` with `stream_name` / `parent_file` when the source is an ADS,
      `carving_source` when it was carved, `source_deleted` when the source was deleted. Each
      is **copied from the parser that established it**, never derived, and absence means the
      source did not say. Where an executable *was* is a fact only the source artifact holds,
      and the findings layer subscribes to parsed records — so without this a PE-in-an-ADS
      lead is not expressible.
- **Feeds:** the findings layer's `pe_signature_mismatch` (the one `Strong` lead, withheld
  outright on a short read), `pe_in_alternate_data_stream`, `carved_executable_in_slack` and
  `high_entropy_executable`. **`carved_executable_in_slack` fires only on slack the
  NTFS, FAT and exFAT parsers publish**: the automatic carver
  carves each `SlackSpace` region from its first 512-byte boundary past the owner's logical end
  (under a profile that runs it — the triage profile publishes slack regions but does not
  carve them) and stamps every carve `carving_source: "slack"` with `parent_file`, `parent_path` and
  `slack_owner_artifact_id`, which the line above forwards. A carve from slack is shorter than
  one cluster (at most about 3.5 KiB on 4 KiB clusters), so the lead is rare. Under the
  volume's current cluster size no file starts in slack — a file starts on a cluster boundary
  and the start of that cluster is the owner's content — so the finding's inference is that
  the executable was embedded in a former file's content or placed there deliberately, never
  that it is a deleted program of its own; it also says that a volume reformatted with larger
  clusters, or one that once held another file system, could leave a former file starting
  there, which nothing excludes, and its qualification says the carve stops at the end of the cluster. Its
  reachability is shown only on a synthetic NTFS volume, parser to finding
  (`carved_executable_in_slack_fires_on_enumerator_produced_shape` in
  `seance_plugin_mft/src/tests.rs`, and on a real `mkntfs` volume in an MBR partition in
  `seance_plugin_mft/tests/real_slack_pe_test.rs`); no held image carries an executable in slack. Carved
  artifacts also carry `carved`, `carving_signature`, `carving_offset_absolute` and
  `carving_validated`, and the PE record forwards none of them.

### `seance_plugin_shimcache`
**Responsibility:** Parsing ShimCache (AppCompatCache).
- **Subscribes To:** `ArtifactType::FileEntry`, `ArtifactType::SystemArtifact`
  (`SYSTEM` hive)
- **Features:**
    - **Files Windows examined, with the path and the file's "Last Modified" time** as the
      cache recorded them, across the Vista/Server 2008 (`0xBADC0FFE`), Windows 7,
      Windows 8.0 (`00ts`), Windows 8.1 and Windows 10/11 layouts.
- **Does not: say anything ran.** An entry in the application-compatibility cache means
  Windows **looked at** the file. The `exec_flag` read as execution is a shim-database flag
  whose meaning varies by Windows version, and this reader takes it **only** from the
  Windows 7 and Vista fixed-record layouts; on Windows 8.0, 8.1, 10 and 11 it is reported
  as `null` — unknown, not "never" (`B8-010`). The findings layer refuses shimcache as a
  source of execution claims entirely, and
  `a_shimcache_entry_is_not_an_execution_claim` pins it.

### `seance_plugin_memory_windows`
**Responsibility:** Windows memory analysis — **native, not a Volatility wrapper.**
Volatility 3 is the *oracle* these results are compared against
(`seance_plugin_memory_windows/tests/parity_*.rs`); nothing shells out to it at
runtime, and no Volatility installation is required to analyse a capture.

- **Reached through:** `seance_memory::MemoryImageModule` (the container stage),
  which decodes the acquisition format and attaches a physical address space to
  a `MemoryImage` record. This tier subscribes to that record.
- **Registered in:** `seance_api::modules`.

**The 36 stages** (`module::STAGES`, published with every analysis as a stage
manifest so the case records what this build *could* have run, and
`GET /api/v1/cases/:id/memory/coverage` gives every one a row):

processes · process tree · command lines · pool scan · cross view ·
kernel modules · network · services · execution history · MFT scan ·
kernel hooks · kernel objects · environment · credentials · registry hives ·
VAD · DLLs · handles · system calls · recovered files · tampering ·
suspicious threads · kernel tamper checks · jobs · device tree · pattern scan · strings map ·
processor blocks · big pool · virtual map · hive cell routines · version info ·
MBR scan · scheduled tasks · TrueCrypt · console history

**The eight kernel-structure stages** (upstream's
`kpcrs`, `bigpools`, `virtmap`, `getcellroutine`, `verinfo`, `mbrscan`,
`scheduled_tasks` and the `truecrypt*` family), each with a synthetic unit
suite and a release-only known answer on `test_data/win11_bitlocker/memory-unlocked.raw`
(build 26200; `seance_plugin_memory_windows/tests/win11_kernel_dumps.rs`):

| Stage | Record | What it reads, and the bound it states |
|---|---|---|
| `processor_blocks` | `MemoryProcessorBlocks` | `KiProcessorBlock` walked to the first null or non-canonical slot; each `_KPCR` held to three self-checks (Self/SelfPcr, CurrentPrcb, `_KPRCB.Number` equals the slot), each reported agree / disagree / not made; current, next and idle thread, the current thread's process, GDT/IDT/TSS bases, `KdVersionBlock`. `KeNumberProcessors` is read and **compared** with the array, never preferred. Measured: 8 processors, all coherent, all idle. |
| `big_pool` | `MemoryBigPool` | The big-page pool table: live, freed and never-used slots told apart **by type**, per-tag totals exact even where the published rows are capped, `ExpPoolBigEntriesInUse` compared with the walk. Measured: 32,768 slots, 6,965 live, 25,803 freed, 300 tags, and the kernel's counter reads 6,965. |
| `virtual_map` | `MemoryVirtualMap` | `MiState`'s system VA regions. **A slot's index is not its type**: on 26200 `SystemVaRegions` has 18 slots against 20 enumeration values, the kernel image sits in slot 17 and the PFN database in slot 0, so naming by index would have mislabelled every region. Names come from the kernel's own per-slice `SystemVaType` map, cross-checked by placing `MmPfnDatabase` and the kernel base. Nothing before Windows 10's `MiState`. `SystemVaTypeCount` is published in the kernel's dynamic-VA granule (region bytes over each `SystemVa.DynamicBitMap<Type>`'s `MaximumSize`, 2 MiB on 26200) — it is **not** a count of 512 GiB slices, which the 26200 capture disproved — with each count checked against its bitmap's set bits: withheld, with the reason, when the build declares no bitmaps or the bitmaps disagree on the unit, and marked incomplete when a count falls below its bitmap. Five types match their bitmap exactly on 26200 and two (system PTEs, non-cached mappings) exceed it; the non-paged pool has no bitmap and is unchecked. One build measured. |
| `hive_cell_routines` | `MemoryHiveCellRoutines` | Each loaded hive's `GetCellRoutine` / `ReleaseCellRoutine`, placed at a named kernel function, inside the kernel at an offset, inside another module, or in no module — the last claimed only when the module list was walked whole. Measured: 38 hives, every routine on `HvpGetCellPaged` / its release counterpart. |
| `version_info` | `MemoryVersionInfo` | The version resource of every kernel module and every process's DLLs, from the image bytes in memory. **On 26200 kernel-module versions are unavailable by design**: the kernel's and 149 drivers' `.rsrc` sections are marked `IMAGE_SCN_MEM_DISCARDABLE`, and a section so marked is not read — the reader decides from the flag alone and never checks the bytes at the resource directory — so they are reported as `resource_discarded`, never as "no version". User mode over the DLLs of five processes: 612 images, 558 with a version, 4 with none, 50 whose resource page is not present; the whole survey, the 155 kernel modules included, is 767 images and 561 with a version (`win11_kernel_dumps.rs`). **25H2 (NtBuildNumber 26200) ships 24H2 binaries**: every file's product version is 10.0.26100.x, which a reader comparing kernel build with file versions must not read as tampering. |
| `mbr_scan` | `MemoryMbrScan` | Every 512-byte-aligned sector ending `55 AA`, held to six checks each reported; a sector failing them is reported with the checks it failed and nothing more (a file system's own boot sector ends the same way and fails them). The boot code is hashed, not judged. Windows writes `0xFFFFFFFF` as the protective MBR's sector count on this 64 GiB disk, the UEFI alternative and not disk size minus one. |
| `scheduled_tasks` | `MemoryScheduledTasks` | Every task in the in-memory SOFTWARE hive's `TaskCache`: path, author, the `Actions` blob decoded, creation and last-run times and last result from `DynamicInfo`, and the `Triggers` blob decoded (`scheduled_tasks_triggers.rs`): header, job bucket (flags, XML CRC32, principal, user and SID) and one record per trigger by magic — `0xDDDD` time (once/daily/weekly/monthly/monthly-DOW), `0xFFFF` boot, `0xAAAA` logon, `0xEEEE` idle, `0x8888` registration, `0x7777` session change, `0xCCCC` event (XPath subscription and value queries), `0x6666` WNF. Padding is relative to each field (a WNF trigger's data is unpadded, so the next record can start at an odd offset) and may be absent at the blob's end. A localized boundary is wall-clock time in the machine's zone and printed with no zone; zero and all-ones times are absent. An unknown kind, or a record running past the blob, stops the decode with what came before kept and the stop on the record, and marks the survey incomplete. Layout from the public description (cyber.wtf, 2022), checked on the 246 blobs of the 26200 capture, all decoding to their last byte. |
| `truecrypt` | `MemoryTrueCrypt` | Whether a TrueCrypt / VeraCrypt driver is on the loaded-module list and, when it is, a sweep of the non-paged pool (the region the virtual map names `MiVaNonPagedPool`, or the one that holds the loader entries when that holds none of them, as on Windows Server 2022 20348.587, `MEM-VC-8`) for verified AES key schedules by address, size and key hash, adjacent AES-256 pairs reported as a *possible* XTS pair and labelled an inference. **The positive path is graded on one capture** (VeraCrypt 1.26.29, one AES/XTS volume mounted; both master keys, decrypted from the container header on the host, were among the nine schedules reported — `VALIDATION.md` `MEM-VC-1`). One volume, one version, one cipher; the sweep also reports other AES-256 schedules (BitLocker's) and does not say which are VeraCrypt's; the driver's own key container (`CRYPTO_INFO`) is decoded from the one layout read from that capture (cipher id, mode id at offset 0, primary schedule at +0x10, secondary 5,312 bytes after it; only id 1 is named, AES and XTS) and states nothing for another version or cipher (`VALIDATION.md` `MEM-VC-2`). |

**Console command history** (`console_history`, `MemoryConsoleHistory`;
the question upstream's `cmdscan` answers; `consoles`, what a command *printed*, is not answered). Each
`conhost.exe` / `OpenConsole.exe` on the process list has its private VAD allocations swept on 8-byte
boundaries for a `std::vector<std::wstring>` that passes every check at once (three user pointers,
`begin < end <= cap`, spans a whole number of 32-byte strings, a plausible command limit, a printable
application name); each element is then decoded against the string's own invariants, and one that fails is
reported unreadable and marks the record incomplete, never dropped. **The layout is in-house, from a known
plaintext, on one build** (Windows 11 26200.6584): it was read off the bytes of a capture in which the typed
commands were recorded (`~/win11-lab/console/GROUND-TRUTH.txt`), with no third party's per-build tables and
nothing from any plugin's source. A host built differently yields nothing, which is stated on the record and
is not evidence that nothing was typed. Not claimed: what a command printed, a line still being edited, a
history whose vector is empty (null pointers match no check), which copy is live where stale heap still
satisfies the checks (the address is on the record), a console host under another image name, and
`OpenConsole.exe` (no capture holding one has been examined; it is searched for by name only). Known answer:
`VALIDATION.md` `CON-1`; test `seance_plugin_memory_windows/tests/win11_console_history.rs`.

Beside them, Windows discovery now **refuses a non-Intel architecture the
acquisition header states** as `DiscoveryError::UnsupportedArchitecture`
before any DTB sweep, rather than ending in "no DTB found"; the ARM64
translation primitive in `seance_memory` (4/16/64 KiB granules, TTBR0/TTBR1,
synthetic fixtures only — see `TESTING.md`) has no Windows discovery over it.

**Acquisition formats decoded** by `seance_memory::formats`, all of them behind
one `SegmentedLayer` so hole semantics and bounds cannot differ per format:

| Format | Notes |
|---|---|
| Raw | The absence of a detection, never a positive one |
| Windows crash dump `PAGEDUMP` (32-bit) / `PAGEDU64` (64-bit) | See dump types below |
| Windows hibernation (`hiberfil.sys`) | See below |
| LiME | Linux Memory Extractor segments |
| AVML | Microsoft's snappy-framed blocks |
| ELF64 core | `virsh dump`, VirtualBox, QEMU `dump-guest-memory` |
| QEMU `savevm` | Suspend-to-disk |
| VMware snapshot | `.vmss` / `.vmsn` metadata plus the paired `.vmem` |

**Crash-dump types are accepted or refused explicitly, never partially parsed:**

| `DumpType` | Handling |
|---|---|
| `0x1` full | Decoded — physical runs from `PhysicalMemoryBlockBuffer`, concatenated in list order |
| `0x5` bitmap | Decoded — `_SUMMARY_DUMP` bit per page; unset pages are **holes, not zeros** |
| `0x6` kernel bitmap | Decoded — what Task Manager's "create live kernel dump" writes, so it is now the common acquisition on a running machine. Same structure, narrower scope: the layer carries an incompleteness saying user-mode memory was never acquired |
| `0x0`, `0x2` kernel, `0x3` small, `0x4` automatic | **Refused**, with the type named — exactly as upstream. A partial address space that reads as complete is worse than a refusal |

A **refused** dump still states things. Its `_DUMP_HEADER` is complete
regardless, so `header_facts` reads the bugcheck code and its four parameters,
the moment of the crash, the build, the processor count and the kernel pointers
on either path: an examiner holding a minidump learns why the machine stopped
instead of only that the file would not decode. It changes nothing about the
refusal — there is still no address space in the file.

A crash dump's header also **states the `DirectoryTableBase`**, along with
`KdDebuggerDataBlock`, `PsActiveProcessHead`, `PsLoadedModuleList` and
`PfnDataBase`. Every one of those is otherwise recovered by scanning heuristics
that can be wrong in ways that look right, so they are published into
`LayerMeta` and the self-referential DTB scan is skipped.

**Hibernation (`hiberfil.sys`) is decoded, not merely identified.** This moved
recently and is the single largest coverage change on Windows: the file sits on
the disk image an examiner already has, needs no live acquisition, and records
the machine at a moment nobody chose in advance.

- The signature is itself a finding: `hibr`/`HIBR` (a complete image, not yet
  resumed), `wake`/`WAKE` (resumed — the pages are usually still there, because
  Windows marks the file rather than wiping it), `RSTR` (restored and marked
  reusable), or all-zero (allocated, never hibernated).
- `open` walks the restore sets, decompresses each Xpress page block and places
  every recovered page at its physical address, so the file becomes an ordinary
  memory image the rest of the platform analyses unchanged.
- **Scope:** the x64 image-version-9 layout of both the NT10 (Windows 10/11) and
  NT6.2/6.3 (Windows 8/8.1/Server 2012[R2]) eras. Both page codecs decode —
  plain Xpress and Xpress-Huffman — **and both are used on both layouts**: on
  NT10 bit 30 of a table header marks an Xpress-Huffman block (30,479 of the
  26200 corpus's 31,969 kernel tables), while on NT6.2/6.3 bit 30 alone is plain
  `XpressMax` and bit 31 is Huffman, so the flag is read per layout. The codecs are validated against the two
  real captures (below), Microsoft's own `RtlCompressBuffer` output, and the 131
  real Huffman blocks of the Server 2012 R2 file. **A block yields every byte of
  its pages or is a counted gap**: the plain decoder used for page blocks is
  exact, and does not skip a back-reference that reaches before the output.
- **How much of the file is reconstructed is measured, and on both corpus files
  the answer is the whole of what the header describes** (`MEM-026`). A restore set has no terminator — the walk always
  ends on bytes that are not a table header — so the only ground for calling a
  set complete is that **the pages its tables describe equal the count its
  header states**, and that is what is checked: the boot set against the `u64`
  at header offset `0x58`, the kernel set against `0x238`, both numbers
  recorded on the layer, and `IncompleteReason::UnresolvedStructure` stated
  only when they disagree. On the 26200 corpus (8,499,130,368 bytes) the boot
  set's 2,501 tables describe 40,004 pages and the kernel set's 31,969 tables
  511,499 — 551,503 pages, 2,258,956,288 bytes, every one of the 65,536 marker
  pages the guest wrote present byte-exact; on the 2012 R2 corpus, 16,664 and
  113,548. The
  compressed-size field of the packed table header is **21 bits**, not 22, and
  bit 29 is a flag (set on 15,326 of the kernel tables, meaning not
  established, recorded as uninterpreted); read as size it would step the walk
  into compressed data 4.3 MB into the kernel set. The "stopped on a bad table"
  report is the natural end of a set, not a completeness failure; completeness is
  the count check above. The two-pass walk
  places pages into one physical-page-ordered buffer (peak RSS 2.23 GB
  measured). Discovery succeeding on the reconstruction is the narrower of the two claims,
  not the wider one.
- **Bounded, and it says so:** the Windows 7 (NT6.1) x64 layout is implemented
  as an explicit opt-in only (`SEANCE_HIBER_LEGACY=nt61-x64`), transcribed from
  reference sources with no Windows 7 corpus here to validate it, so every layer
  it returns is stamped `IncompleteReason::Unvalidated`. Vista/XP and 32-bit
  layouts are identified but not reconstructed.
- Volatility 3 has no hibernation layer at all, so there is no upstream to be
  consistent with.

**Pagefile attachment.** A swapped-out page is not in the capture, but if the
examiner acquired `pagefile.sys` too, the pair can read it. Two routes, and
they are deliberately different:

- `SEANCE_CASE_PAGEFILES` — a pagefile held as another evidence item *in the
  same case*. Resolved through `CaseEvidence` against the case the image record
  names, which is what stops one case's reference opening another case's
  evidence. The default resolver (`EvidenceBesideImage`) finds a pagefile
  acquired alongside the capture with nothing wired up.
- `SEANCE_PAGEFILES` — `index=path` entries for a pagefile elsewhere on the
  examiner's host. Split so a Windows drive colon survives
  (`SEANCE_PAGEFILES=0=C:\evidence\pagefile.sys`).

`SEANCE_MEM_DTB` supplies a directory table base in hex or decimal for an image
discovery cannot profile on its own.

**Suspicious threads (`suspicious_threads`, `MEM-024`).** One image-wide record
(`MemorySuspiciousThreads`, served at `GET /api/v1/cases/:id/memory/suspicious-threads`)
over the shared process list. For every live thread of every process, its
`StartAddress` and `Win32StartAddress` are placed in that process's own VAD tree
(`psxview_suspicious.rs`), and a start is **evidence** when its range is backed by
no file, was not created `PAGE_EXECUTE_WRITECOPY` (compared on the access
protection only, from the kernel's own `MmProtectToValue`), or maps an application
`.exe` that is not the process's own. A range whose protection or file could not
be read is a **gap**, never a finding. What is not judged, and why, is on the
record rather than dropped:

* a **kernel** address is one in the kernel half: on x64 at or above the
  canonical `0xFFFF8000_00000000`, always — the non-canonical hole above
  `MmHighestUserAddress` holds no mapping, so a start there (a smeared
  `0x4141414141414141`) is unplaced, never kernel; on x86 at or above the image's
  own `MmSystemRangeStart`, or `0xC0000000` when that does not read (so a `/3GB`
  user start is never waved through). No VAD can cover a kernel start. On a thread
  whose `_KTHREAD.SystemThread` (NT 5.x: `_ETHREAD.SystemThread`) is **set** it is
  counted in `starts_in_kernel_space` and does not make the process incomplete:
  whether it lies in a loaded module is the `tamper_checks` orphan-thread group's
  question. On a thread whose bit is **clear**, unreadable or not declared it is
  counted in `kernel_starts_on_threads_not_known_as_system` and **makes the process
  incomplete**, because the orphan-thread group sets every such thread aside as a
  user thread and so neither stage judges it. Measured on the build-26200 capture:
  78 kernel starts, of which only **2** are on kernel threads; **76** (csrss,
  winlogon, services, lsass, svchost, most in session space) are on threads whose
  bit reads clear. The first version counted all 78 as kernel threads and called
  the capture complete — a claim no stage had checked;
* a **user** start in no range, and a non-canonical one, is counted in
  `starts_outside_the_tree` and makes the process incomplete — it is a smeared
  tree or a smeared thread;
* on Windows XP and Server 2003 `Win32StartAddress` is a union with
  `LpcReceivedMessageId`; when the thread's `LpcReceivedMsgIdValid` bit is set the
  field is a message id and is not judged (`win32_starts_holding_an_lpc_message_id`),
  and when the bit cannot be read it is not judged and the process is incomplete.
  Volatility 3 does not check the bit and reports those small integers as threads
  started in private memory — every extra row it prints on be2, zeus and stuxnet;
* a process with fewer than five ranges is not judged (`analysed: false`); a
  process whose **Peb is null** (System, Registry, Memory Compression) or that had
  exited is **out of scope** with the reason and does not make the survey
  incomplete. The reason states the observation — a null Peb — and nothing more:
  a WSL1 pico process also has a null Peb and does have user threads, and it is
  set aside unjudged too, so "out of scope" means *not looked at*, never *clean*.
  A process whose analysis failed is **skipped** with the error and does make the
  survey incomplete.

The derivation is `inferred`: every range is linked, but "this thread runs
injected code" is an inference, and a JIT's private executable code is a
legitimate start in a private range. Measured on four captures, recorded in
`VALIDATION.md`: none on the clean Windows 11 capture (which the record calls
incomplete, for the 76 kernel starts above); 1 / 10 / 9 on be2 / zeus / stuxnet,
each also a Volatility 3 row, each capture complete.

**Kernel tamper checks (`tamper_checks`), and what the unloaded-driver table
taught.** Seven groups in one stage; `tamper::IMPLEMENTED_GROUPS` is the list of
those whose detection is written, and every sentence the stage emits about how
much of itself is written counts from that list rather than stating a number.
A group that is written and a group that is not give **different reasons** for
not running, and the record carries whichever is true.

The first group is `unloadedmodules` — `MmUnloadedDrivers`, the fifty drivers
the kernel most recently unloaded. A driver that loaded, ran and unloaded is in
no loaded-module list and need not be on disk; this table is how it is still
nameable, and the forensic point is the **cross-reference**: a callback target,
service routine or IRP handler the `kernel_hooks` stage could attribute to no
loaded module, which falls inside the range of a driver the kernel unloaded, is
reported with both sides and never as a verdict — the range was freed when the
driver unloaded and may have been reused by anything since.

Three things here were measured rather than assumed, and each is on the record:

- **The record layout is not in most builds' symbols.** 46 of the 1,724
  `ntkrnlmp.pdb` ISFs on the build machine declare `_UNLOADED_DRIVERS`; all 46
  are x64 and all 46 agree exactly — size 40, `Name` at 0x00, `StartAddress` at
  0x10, `EndAddress` at 0x18, `CurrentTime` at 0x20. So the x64 fallback is
  validated against real symbols. **No x86 ISF in that corpus declares it**, so
  the x86 fallback is documented and unvalidated, and every record read through
  it is stamped `IncompleteReason::Unvalidated` and says so. Which layout
  answered is on each record with its basis.
- **The counter is a write count, not a length.** Capacity is fifty; slots
  populated are `min(count, 50)` and the newest is `(count - 1) % 50`. A count
  above fifty means the table has wrapped and the record says how many unloads
  were overwritten, so a driver's absence is not read as its never having
  unloaded.
- **`CurrentTime` is not a FILETIME on a modern kernel.** On the Windows 11
  26200 capture all nine populated slots hold values between `0x00e393cb` and
  `0x03728e86`, rising with the unload order: 1.491 s to 5.784 s in
  100-nanosecond units — an interval **since boot**. Séance classifies the
  number before rendering it (`UnloadTime`) and publishes an interval as an
  interval, with no absolute time claimed: deriving one would need the boot time
  and a validated relation to the kernel's interrupt time, which is biased by
  the time the machine spends asleep. Converted as a FILETIME the same nine
  values date to 1601-01-01, which sorts to the top of a timeline and reads as a
  timestomp.

**The timer tables, and two things that would read plausibly if they were
wrong.** The second group. For each processor, the `_KPRCB`'s embedded
`_KTIMER_TABLE` is reached and every bucket's list walked; each `_KTIMER` is
recovered by `CONTAINING_RECORD` from its list link (`TimerListEntry` is at
offset 32 on the modern builds, so a walk that reported the link address would
be 32 bytes early, inside the dispatcher header and `DueTime`, which parse),
and each timer's `_KDPC.DeferredRoutine` is attributed against the shared
module map. The signal is a routine in **no** loaded module, and only when the
map is authoritative.

- **The bucket count is the product of the declared dimensions.**
  `_KTIMER_TABLE.TimerEntries` is `[2][256]` on build 26200 and `[256]` on all
  1,233 older ISFs measured, so the count is 512 or 256 depending on the build
  and comes from `seance_memory::object::ArrayShape`, which multiplies every
  dimension. Taking the outer one walks 2 of 512 buckets, finds real timers in
  both, and looks right.
- **Two table shapes, exactly complementary.** `_KPRCB.TimerTable` on 1,233 of
  the 1,724 ISFs; the `KiTimerTableListHead` global on 427; neither on 64,
  where the group does not run and names both. Nothing declares the global
  table's length, so rather than citing a constant this build cannot source,
  the extent is **derived from the evidence** — consecutive buckets whose list
  head is self-referential or whose first link points back at it — **bounded by
  the next symbol the build declares above the table**, and both numbers are on
  the record. *(`MEM-021`.)* The
  bytes alone were not enough: on XP SP2 and SP3 the 256 buckets are followed
  by `KiDispatcherReadyListHead`'s 32 list heads, self-referential when empty,
  so the heads-only probe derived **288** on all four captures measured and
  walked scheduler ready lists as timer buckets. The symbol bound gives 256
  there; across the 926 legacy-shape ISFs of all four x86/x64 kernel names in
  the pack it equals the documented 256 or 512 on 867, and on the other 59 it
  is looser (1,024 or 768) or absent and the probe decides alone.
- **An NT 5.1 bucket is a bare `_LIST_ENTRY`.** 349 of those 926 ISFs — the
  XP-era kernels — declare no `_KTIMER_TABLE_ENTRY` at all. On such a build the bucket stride is
  `_LIST_ENTRY`'s declared size and the head is at offset 0 (`entry:
  bare_list_entry` on the record, with its basis); the extent probe checks the
  stride, since a wrong one fails at bucket 1. `_KTIMER.Period` is declared
  **signed** (`long`) on XP and is read as the integer it is.
- **Graded against Volatility 3 on four real XP x86 captures** (Malware
  Cookbook `tigger`/`be2`/`zeus`, XP SP2 PAE; `stuxnet`, XP SP3 — not
  redistributable): 233, 227, 242 and 176 timers over 256 buckets; the 60, 60,
  64 and 58 carrying a DPC are exactly `windows.timers`' rows — same `_KTIMER`
  addresses, routines and periods — and none lands outside a loaded module.
  ** NIST CFReDS "Basic Memory Images" opened (7-Zip 23.01):
  `boomer-win2003-2006-03-17.img` is Server 2003 **RTM** (3790.srv03_rtm, x86),
  whose ISF declares no `_KTIMER_TABLE_ENTRY` — the bare form again — and its
  43 DPC timers match `windows.timers` in address, routine and period.
  `vista-beta2.img` is kernel `ntkrnlmp.pdb`
  `5B71B326D7C84B88B623F8F1026BE689-2`, which no symbol pack here holds, so
  it is not analysed. The declared-entry form of the global table (Server 2003
  SP1+, Vista, XP x64) was unread from evidence at that date.
  ** Read now from one Server 2008 SP1 x86 PAE capture (samsclass
  `memdump.mem`, `VALIDATION.md` MEM-XP-4): 16-byte `_KTIMER_TABLE_ENTRY`
  buckets, 512 walked, equal to the image's own `KiTimerTableSize`; the 14
  `windows.timers` rows match over buckets 0 to 255. Volatility 3 reads only
  those 256 (it strides an array of `_LIST_ENTRY` over 16-byte entries); the 41
  further DPC timers from buckets 256 to 511 are Séance's alone, pinned and not
  graded. Vista SP2 non-PAE is graded against Volatility 2 (`MEM-XP-5`). Still unread: Server 2003 SP1+ and XP x64.
  *(`MEM-020`)* The Cookbook's other five captures, graded the same
  way: `coreflood`, `laqma`, `sality` and `silentbanker` read 176, 190, 242
  and 175 timers over 256 buckets, and their 62, 63, 61 and 62 DPC timers are
  exactly `windows.timers`' rows.
- **A torn bucket head is not the end of the table** *(`MEM-058`)*. `prolaco.vmem` was taken while the kernel was relinking timers:
  12 of its 256 bucket heads have a first link whose `Blink` names a different
  bucket. The probe read bucket 37's as the end of the table — 37 buckets, 7
  of the 50 real DPC timers, and a list from inside those 37 that
  ran into bucket 68's head published that head as a timer "outside any
  module", a false signal. Now a head is *well-formed* (self-referential, or
  its first link points back), *torn* (a canonical first link whose readable
  `Blink` names somewhere else) or *not a head* (null, non-canonical,
  unreadable). Inside the symbol bound a torn head is counted as a bucket when
  a well-formed head follows it, is walked from its head, and is named on the
  record with the warning that its list may be incomplete; the extent ends at
  the last well-formed head. A torn run that no well-formed head follows
  inside the bound (it reaches the bound, or something that is not a head) is
  **not** counted, because nothing in the bytes shows the table reaches it; it
  is named on the record as not walked, since those heads may be real buckets
  whose timers were not reached, and a list that runs into one of their heads
  stops there as at any other head. Without a symbol bound nothing says where
  the array stops, so a torn head still ends the probe. On `prolaco` that gives
  256 buckets, 140 timers, and 50 DPC timers equal to Volatility's rows less
  four it prints twice (reached from joined lists) and one it gets wrong:
  0x80552408, which is bucket 68's `_LIST_ENTRY` head read as a `_KTIMER`.
- **The processor count is validated, not trusted.** `KeNumberProcessors`
  carries no declared type in any of the 1,724 ISFs, so its width is not
  knowable from the symbols, and on the smeared captures in this corpus it
  reads 0 on machines that plainly had processors. The `KiProcessorBlock` array
  is probed instead, and a disagreement between the two is stated on the
  record.
- **One row per `_KTIMER`, with every place it was reached** *(`MEM-055`)*. A timer reached from more than one bucket list is published
  once, and its `reached_from` names every `(processor, bucket)` whose list
  reached it; `timers_reported`, `timers_with_a_dpc`, `dpc_unreadable`,
  `routines_outside_any_module` and `patchguard_shaped` count distinct timers,
  `rows_walked` counts sightings, `timers_reached_more_than_once` counts the
  timers seen twice or more, and the work cap still counts sightings so
  `capped` means what it did. Two mechanisms are recognised from the walk's own
  evidence and nothing else is invented. A `KiProcessorBlock` slot naming the
  same `_KPRCB` as an earlier slot is walked once and the repeat is named on the
  record (two processors cannot share one). A bucket list whose next link is
  **another bucket's head** stops there (`entered_another_bucket`): that head is
  a `_LIST_ENTRY` inside `_KTIMER_TABLE_ENTRY`, and walked on it was published
  as a "timer" at `head - TimerListEntry` and the walk ended in a cycle. A
  timer reached twice then carries `reached_more_than_once_reason` naming the
  joined lists, or saying the reason is not established. Measured `--release`
  on the held captures (distinct timers / sightings / rows before): Case 001
  DC 179 / 196 / 237, Case 001 desktop 187 / 245 / 367, 13Cubed 197 / 265 /
  475, Lone Wolf 246 / 342 / 639, Windows 11 26200 209 / 209 / 209, the four
  XP captures unchanged. The DPC counts are the distinct counts Volatility 3
  prints (39, 38, 49, 52; Lone Wolf 50, ungraded); the unreadable counts fell
  (DC 35 → 2, desktop 74 → 3, 13Cubed 153 → 8) because bucket heads are no
  longer read as timers. On the four modern captures 12, 16, 21 and 43 timers
  are reached twice with **no** mechanism the walk saw — no list was seen to
  enter another bucket's head and no `_KPRCB` repeated — and they say so
  (`MEM-057`).
- **`_KTIMER.DueTime` is not reported in any form.** Its encoding on modern x64
  is established by no source in this tree, and `KiWaitNever`/`KiWaitAlways` —
  the globals an obfuscation of it uses — are declared on the builds measured.
  A number rendered as a date would be fabrication, and a test fails if a due
  time ever reaches a record. The adjacent `_KTIMER_TABLE_ENTRY.Time` was
  assessed rather than ignored: it is the **bucket's** time, not the timer's,
  and it is published as the raw number it holds with no epoch claimed.
- **`_KTIMER.Dpc` is encoded on x64, and is decoded and checked**
  *(`MEM-052`)*. On an x64 build declaring `KiWaitNever` and
  `KiWaitAlways` the field holds the `_KDPC` pointer XORed with `KiWaitNever`,
  rotated by its low byte, XORed with the timer's address, byte-swapped and
  XORed with `KiWaitAlways` (published by Skape, *Uninformed* vol. 8 art. 5,
  and debugwar.com — not taken from Volatility). Every decoded pointer must
  land on a structure whose `Type` byte is one of the build's own `_KOBJECTS`
  DPC values, or the row carries `dpc_unreadable` with the reason and nothing
  is read through it; the stored field is kept as `dpc_field_raw`. A decode to
  exactly 0 is a timer with no DPC. Read as a pointer, the field would overflow
  the arithmetic on Case 001's Server 2012 R2 capture and publish the encoded values as DPC
  addresses on every other encoding build, so the clean baseline below would be vacuous.
  Every address the tamper groups compute from an evidence value is checked arithmetic.
- **The clean baseline is measured.** 209 timers over 4,096 buckets on 8
  processor tables of the Windows 11 capture; **52** carry a DPC once the field
  is decoded (the other 157 decode to null), all 52 match Volatility 3's
  `windows.timers` in address, routine and period, and **none** of those
  routines lands outside a loaded module. The zero is the false-positive count
  of this signal on a clean machine, and `seance_memory/tests/KNOWN_ANSWERS.md`
  records it. On Case 001's Windows 10 desktop one timer (reached from two
  buckets) does land outside every module — an unaligned `_KTIMER` with a
  pool routine and a non-canonical `DeferredContext`, the shape PatchGuard's
  own timer takes; Volatility prints the same row with no module
  (`VALIDATION.md` MEM-C001-1).
- **A PatchGuard-shaped timer is published and not graded** (`MEM-054`). A row whose `_KTIMER` address is not aligned to the
  build's pointer width, whose routine lands in no loaded module on an
  authoritative map, **and** whose `DeferredContext` is not canonical carries
  `patchguard_shaped: true`, `is_signal: false` and a `patchguard_shape_basis`;
  the table counts it as `patchguard_shaped`, apart from
  `routines_outside_any_module`, and the kernel-tamper findings raise no lead
  from it. The rule is the conjunction — any one condition alone is too broad —
  and breaking any one of them restores the signal
  (`an_aligned_timer_outside_every_module_is_still_the_signal`,
  `a_canonical_context_keeps_the_signal`,
  `an_undetermined_owner_is_neither_the_signal_nor_the_shape`). It is a shape,
  not an identification: a rootkit could imitate all three, which is why the row
  is kept with every value as read rather than dropped, its routine is still
  offered to the unloaded-driver cross-reference exactly as a graded row's is
  (`a_patchguard_shaped_row_is_still_offered_to_the_unloaded_driver_cross_reference`),
  and no capture held shows a timer rootkit to test that against. Re-measured: 0 graded and 0 shaped on Windows 11 26200, the Case 001 DC,
  13Cubed and Lone Wolf; on the Case 001 desktop 0 graded and 1 shaped timer,
  reached from two buckets and published once (`MEM-055`, below). Re-measured on every further Windows capture held (Win 7 SP1 x64 `memdump-001`,
  two more Windows 11 26200 VM captures, Server 2008 and 2003 x86, XP x86
  `0zapftis` and the five further Cookbook images): 0 graded and 0 shaped on all
  of them; the Vista M57 capture is refused at discovery and not measured
  (`VALIDATION.md`, `MEM-054`). No capture held contains a timer
  rootkit.

**The three thread groups, from one pass, and the union that nearly produced a
false finding.** `suspended_threads` is a **listing** — every thread with a
non-zero suspend count, with `is_a_finding: false` and the basis on each row,
because the platform suspends packaged apps, debuggers suspend and
`CREATE_SUSPENDED` is how nearly every injector starts. `debugregisters` is a
**reading**. `orphan_kernel_threads` is the only **graded claim** of the three.

- **The debug registers are read only from a thread whose own flags claim
  them.** On build 26200 `_KTRAP_FRAME.Dr0` shares offset 216 with
  `ShadowStackFrame` and `Dr1` shares 224 with `Spare[5]`: the symbol file
  flattens a union, and the only thing that says which interpretation applies is
  `_DISPATCHER_HEADER.DebugActive` / `ActiveDR7`. Reading them regardless
  produced **nine rows on the clean capture, five claiming armed breakpoints**,
  every one a shadow-stack pointer. With the flag test, that capture produces
  nothing. Where a build declares neither flag (152 of the 1,724 ISFs have no
  `DebugActive`) the values are still published and the row is marked
  `unconfirmed`, claiming no breakpoint. **NT 5.x keeps the flag in `_KTHREAD`
  itself** (`_KTHREAD.DebugActive`, a byte at 0x2c on XP SP2), and it is looked
  for there after the dispatcher header **. **Where the build
  declares `ActiveDR7`, only that bit confirms** *(`MEM-051`)*: it
  is one bit of the `DebugActive` byte, whose other bits are other flags
  (`Instrumented` is bit 1 on Windows 10), and its position is read from the
  build's bitfield declaration. LoneWolf's one graded row — a `RuntimeBroker.exe`
  thread with `DebugActive` 2 and `ActiveDR7` clear — is gone, and the 13Cubed
  capture's confirmed rows fall from 15 to 5. A confirmed row whose thread has
  Tid 0, or whose armed addresses are not canonical, is published with a
  `not_graded_reason` and not graded.
- **Each register is read at the width the build declares**: eight bytes on
  x64, four (`unsigned long`) on x86. A fixed eight-byte read would glue `Dr1:Dr0`
  into one value on the XP captures. Measured there: one
  `winlogon.exe` thread on each of the four XP captures has `DebugActive`
  0x8f/0x8d — its low four bits exactly the slots holding a non-zero address —
  `Dr7` = 0x555 (L0–L3) and `Dr0`–`Dr3` in the null page (1, 2, 1, 0xa on the
  three SP2 images). Reading the null page as armed would report a breakpoint,
  confirmed by the thread's own flag, on every XP capture, malware or not: a
  clean-capture false positive of this group on XP (`MEM-050`).
- **A breakpoint armed only in the null page is published and not graded**
  *(`MEM-050`)*. A row is graded
  (`has_breakpoint: true`, and a lead in the kernel-tamper findings) only when
  at least one address `Dr7` arms is at or above 0x10000 —
  `MM_LOWEST_USER_ADDRESS` in the WDK's `wdm.h`, the lowest address the
  allocator hands to user code (`NULL_PAGE_END` in `tamper_threads.rs`). A row
  whose every armed address is below it keeps its addresses and carries
  `armed_only_in_the_null_page: true` and a `not_graded_reason`. The XP
  winlogon row is graded on none of the four captures; one armed address
  outside the null page is enough to grade a row. **Bound:** before Windows 8
  a 32-bit process could map page 0 (`NtAllocateVirtualMemory` with a base of
  1, or NTVDM's low megabyte), so a breakpoint on memory deliberately mapped
  there is published and not graded. This is Séance's own rule; Volatility 3
  drops the same thread for a different reason (no address in a file-backed
  VAD).
- **`Dr7`'s enable bits decide what a breakpoint is.** Bits 0–7 are L0/G0 …
  L3/G3, so slot *i* is armed when bit `2i` or `2i+1` is set. A non-zero
  `Dr0`–`Dr3` in an unarmed slot is listed as stale and claimed as nothing.
- **The orphan claim is graded only when every exclusion was assessable**:
  kernel-thread identity, not terminated, `StartAddressInvalid` clear, and not
  inside the range of a driver the kernel has unloaded. Where one could not be
  assessed the row is an observation with that exclusion marked
  `not_assessed` — because grading it would publish a claim with one of its own
  controls silently unapplied. A build declaring no unloaded-driver table
  therefore grades no orphan at all, and says which control was missing.
- **A user thread is counted, not published.** Its `StartAddress` is
  `RtlUserThreadStart` in ntdll, a *user*-space module, and the map these
  addresses are attributed against is a map of *kernel* modules — so every user
  thread looks like an orphan to it. On the clean capture that is 1,284 of
  1,514 threads; a row each would have buried the group's question.
- **Members vary, and are resolved per build.** `_KTHREAD.SystemThread` is a
  bitfield whose position is 10, 11, 12 or 13 and whose offset is 60, 76 or 116,
  and it is absent on 650 of the 1,724 ISFs — where it is absent, kernel-thread
  identity falls back to the owning process being `PsInitialSystemProcess` and
  the row says which test answered. `SuspendCount` is declared **signed**, so it
  is read as the integer it is: a negative value is a note, never republished as
  a very large unsigned count.
- **The clean baseline:** 1,514 threads over 129 processes, 1,514 suspend counts
  read and none non-zero, no thread claiming debug state, and no orphan
  candidate at all. Each zero is a different statement and the record carries
  the counts that distinguish them.
- **The first known answer (`MEM-020`).** On the Malware Cookbook's
  `tigger.vmem` the group publishes exactly the three orphan system threads
  Volatility 3's `windows.orphan_kernel_threads` prints, including the one
  Ligh's 2011 write-up names: Pid 4, Tid 1648, `_ETHREAD` 0xff1f92b0,
  StartAddress 0xf2edd150, outside every loaded module and inside no unloaded
  driver's range. **They are observations, not graded findings**: XP declares
  no `_ETHREAD.StartAddressInvalid`, so one exclusion is `not_assessed` and the
  group grades nothing on that build, as designed. `be2`, `zeus` and `stuxnet`
  produce no orphan row, as Volatility 3 prints none; nor do `coreflood`,
  `laqma`, `prolaco`, `sality` and `silentbanker` **, on which
  Volatility 3 also prints none. None of the eight Cookbook captures has a
  published answer for the other six groups, so their silence there is
  agreement with the oracle, not a true negative. **Decided:** no
  test-signed lab driver will be built to manufacture a true positive; the
  remaining evidence item is The Art of Memory Forensics' `zeroaccess` and
  `rustock-c` captures, which carry published timer answers and are not held.

**The ETW write path, and two routes that need no stored baseline.** The
technique is one instruction — overwrite `ntdll!EtwEventWrite`'s first bytes
with a `ret` and the process stops producing events while every API call still
succeeds. It is per-process, the file on disk is untouched, and nothing in an
event log records it, because the absence of events *is* the effect. A check
that compared the prologue against a stored baseline would need one baseline per
build of `ntdll.dll` and would rot on the next Patch Tuesday, so both routes
here are build-independent:

- **Classification.** Decode the prologue and report a function that returns
  immediately, traps, or whose first control transfer leaves the module, with
  the decoded instructions as the evidence.
- **Modal comparison.** Compare each copy's first sixteen bytes against the
  modal value across every copy not shown to be private memory. A patch in one
  process is 1-against-123 with no reference bytes at all; a patch applied
  machine-wide, where the mode is itself patched, is what classification
  catches. Every row says which route fired, and when the copies that set the
  mode themselves classify as a signal the record adds a note naming the
  export **, so "agrees with the mode" is never read as
  reassurance. The note says "machine-wide" only when **every** voting copy,
  and more than one, set the mode; a patched majority is called a patched
  mode whose dissenters may be the clean copies, a mode of one copy is called
  no baseline, and a tie is named as a tie. The mode is a plurality, and on a
  tie the byte-wise greatest prologue wins -- `0xC3` sorts above an ordinary
  `0x48` -- so every tie at the top is stated on the record as arbitrary. The
  counts are of *voting* copies: a copy whose mapping could not be established
  votes, and the note says how many of those there were. All of this is
  pinned by synthetic fixtures, not met on evidence.

Three rules, each of which the clean capture decided:

- **A copy positively in private memory never votes in the mode.** A
  hand-mapped copy carrying the name would otherwise choose the baseline every
  other process is compared against. It is still classified and still compared;
  it just does not set the mode. A copy whose mapping could not be corroborated
  *does* vote, and says it was not corroborated — `None` is not `false`.
- **A process whose `ntdll` pages are not resident is unassessed**, never
  "unpatched", and counted with its reason. On the clean capture that is 6 of
  129; three of them (`System`, `Registry`, `MemCompression`) map no `ntdll` at
  all.
- **A fixed-length window ends mid-instruction, and that is not an invalid
  instruction.** `EtwEventWrite`'s real prologue on 26200 ends `… 48 8d 6c 24
  80 48 81`, where `48 81` begins a `sub rsp,imm32` the sixteenth byte cuts in
  half. The decode stops
  when fewer bytes remain than an instruction can be, so none of the **491
  genuine prologues** on the clean capture is classified unreadable.

Baseline: 491 prologues over 123 processes, every one agreeing with its export's
mode, no signal on either route. The modal prologue of each export is recorded
in `seance_memory/tests/KNOWN_ANSWERS.md` and pinned in the test, because on
this check the bytes are the known answer.

**The skeleton key, and a route named rather than promised.** A skeleton key is
a patch inside `lsass.exe` that makes one attacker-chosen password work for
every domain account while each real password keeps working: nothing on disk
changes, no account is modified, no event is logged. The route this build runs
classifies `cryptdll!CDLocateCSystem` — an exported function, so it is located
from the module's own export table with no symbols at all — using the ETW
check's decoder.

The route it does **not** run is the `CSystems` descriptor table, and the shape
of that statement is the deliverable as much as the code. The stronger signal is
an RC4-HMAC descriptor whose function pointer leaves `cryptdll` while the
exported entry point is intact; reaching it needs the layout of that descriptor,
and nobody publishes it. Microsoft ships `cryptdll.pdb` as a *public* PDB —
names, no structure layouts — exactly as it ships `tcpip.pdb`, which
`seance_memory/tests/KNOWN_ANSWERS.md` records at 10,376 symbols and **zero
types**. So the record names the route, says what it would have established, and
does **not** list it as pending a symbol file: an ISF built from a public PDB
would give the address of the `CSystems` global and nothing about the entry
layout. The group's record is therefore stamped incomplete on every build,
including the clean capture where it found nothing.

A machine whose `lsass.exe` the walk never reached reports **not assessed**,
never clean. Measured on the clean capture: one `lsass.exe` (pid 968),
`cryptdll` at `0x7ffcd9940000` corroborated as an image mapping,
`CDLocateCSystem` at `0x7ffcd9943150` with the prologue
`8b 05 aa b9 00 00 4c 8d 15 83 c0 00 00 44 8b c9`, classified ordinary — the
bytes are pinned in the test, because a wrong export address would not produce
them.

**The PEB masquerade.** A process can rewrite
`_RTL_USER_PROCESS_PARAMETERS.ImagePathName` in its own memory so that anything
reading the PEB reports the wrong program; it is documented and scripted. The
counter-record is `_EPROCESS.SeAuditProcessCreationInfo.ImageFileName`, the path
the **kernel** wrote at process creation, in kernel memory where the process
cannot reach it — declared on all 1,650 ISFs here that declare `_EPROCESS`. The
`tampering` stage now compares it against both the PEB path and the truncated
`ImageFileName`, alongside the comparison it already made against the file the
image's own range maps.

A weaker marker ships beside it: the loader sizes `ImagePathName`'s buffer to
the path plus its terminator, so `MaximumLength == Length + 2`, and a breach is
reported with all three numbers and `is_proof: false` — a reused buffer produces
it too.

**The truncation test.** `names_agree` flags a recorded name as truncated
only when `len + 1 >= width`, because Windows 11 26200 stores fourteen
characters plus a NUL in the fifteen-byte array. On that clean capture the
stage raises nothing.

**Job objects, and why one record is not one row.** A job is how Windows groups
processes for limits and accounting, and it is how a sandbox shows up in memory:
a browser's renderers, a packaged app's processes and a container's are each in
one. The `jobs` stage reads every process's `_EPROCESS.Job`, and for each
**distinct** `_EJOB` walks `ProcessListHead` through `_EPROCESS.JobLinks` by
`CONTAINING_RECORD` — the link offset is published on the record, because every
member address rests on it.

- **One record per job object, naming every process that pointed at it.**
  Upstream's `joblinks` iterates processes and repeats a job's members under
  each, so a job holding three processes is printed three times. Reconciling the
  shapes is arithmetic and it comes out exactly on the Windows 11 capture: 21
  distinct jobs, 24 processes in a job (upstream's 24 job rows), `Σ named_by ×
  members` = 32 (upstream's 32).
- **The counter and the list are both reported.** `ActiveProcesses` is the
  kernel's own count; the member list is a walk. On that clean capture one job
  reports 7 and holds 3 — mid-teardown, or a member unlinked — and preferring
  one number silently would hide it.
- **A process in no job is the ordinary case**, is not a row, and is counted:
  105 of 129 on that capture. An empty list cannot read as a walk that failed.
- **A member the active process list does not hold** is named as such, and only
  when that list walked end to end; otherwise the question is unanswered rather
  than answered "no".

**The process inventory, and a column this build does not describe** . Every per-process stage — `vad`, `dlls`, `handles`,
`command_lines`, `jobs`, `tampering`, `system_calls`, `pattern_scan` — carries
`process_inventory`, and its `content_complete` is the conjunction of its own
work and that inventory. The inventory answers one question: was every process on
the active list reached. A link that would not follow, a cap that fired, or a
field whose bytes would not read makes it a floor. A field the build **declares
no layout for** does not. On Windows 11 24H2 and later `_EPROCESS.Session` points
at a `_PSP_SESSION_SPACE` that no ISF declares; the reader will not read a session
id at the offset upstream hardcodes, so the column is `not_declared`
(`_MM_SESSION_SPACE.SessionId`) on each such row, and the `MemoryProcessList`
record states it once under `undescribed` with a process count — 125 of 129 on the
build 26200 capture, the other four (System, Registry, the master `smss.exe`,
MemCompression) having no session at all. A session whose layout *is* declared but whose bytes were
not captured is still `unavailable` and still makes the list a floor. Pinned by
the `process.rs` unit tests (synthetic fixture: pins the mechanism) and by
`win11_corpus_analysis.rs::the_session_layout_this_build_does_not_publish_is_not_counted_as_a_failed_read`
(real evidence, release only).

**The device tree, and where a filter driver inserted itself.** Windows lets a
driver attach its own device object on top of another driver's, so every request
to the lower device passes through it first. That is how a volume encryptor, an
antivirus and a USB class filter work, and how a rootkit intercepts disk,
keyboard or network I/O without patching any code. The `device_tree` stage walks
each driver's `NextDevice` chain and, above each device, its `AttachedDevice`
stack — using the driver objects the `kernel_hooks` stage already swept for,
because a second pool sweep is a second chance for two records to disagree about
which drivers the machine has.

- **On the Windows 11 capture it reaches more of the machine than upstream
  does**: 124 drivers, 245 devices and 113 attachments, against Volatility's
  129 DRV / 100 DEV / 26 ATT rows for the same bytes. Where upstream reports,
  the two agree (four `(driver, device)` pairs from its own output are asserted
  in the test); what differs is how much of each chain is walked. Upstream's
  output holds at most one device per driver. Why is not established here.
- **An attachment is not a finding**, and the record says so in as many words.
  On that capture all 113 attachments are by a driver other than the one owning
  the device beneath — which is what a filter is, and what nearly every one of
  them legitimately is.
- **An unnamed device is not a device whose name could not be read.** Most
  devices are legitimately unnamed: a name is how user mode opens one. The name
  comes from the `_OBJECT_HEADER_NAME_INFO` in front of the object, through the
  same code the handle table uses, so the same device named twice cannot differ.
- **A device type the WDK does not define is reported as its number**, not as
  `UNKNOWN`: an examiner can look up a number.
- **A device attached above itself stops the walk and is named.** No healthy
  kernel produces it; a smeared acquisition does, and the incompleteness says
  what is at stake — something may be attached above the point it stopped, which
  is exactly what this stage is read for.

**The pattern scan, and the one stage that asks a question this product did not
choose.** Every other stage looks for a structure the kernel defines. The
`pattern_scan` stage (`MemoryPatternScan`, one record per image rather than per
process — `seance_plugin_memory_windows/src/pattern_scan.rs`, the API row in
`seance_api/src/memory.rs`, reached at
`GET /api/v1/cases/:id/memory/pattern-scan`) runs an **examiner-supplied** YARA
rule set over two kinds of address space: **each process's own**, assembled
through the page tables recovered from the capture — upstream's `vadyarascan` —
and **the kernel's own**, upstream's `yarascan`. That makes the honesty
requirements sharper rather than looser, because "your rules matched nothing" is
the answer most likely to be read as "there is nothing here".

- **Séance ships no rules, and a scan that never had a pattern says so.** With
  no rule set named (`SEANCE_YARA_RULES` unset) the stage reports that it **did
  not run**, with that reason. An empty match list from a scan that never had a
  pattern must not render like one from a rule set that ran and matched nothing.
  The same compiled rule set drives the file scanner
  (`plugin.detection.yara`) and this stage — one compilation, two drivers.
- **What the file scanner reaches, and what it does not**. `plugin.detection.yara` scans seven surfaces beyond a plain
  file and stamps every record about scanned bytes with a typed `surface` from
  the closed vocabulary `file` / `ads` / `registry_value` / `unallocated` /
  `carved` / `deleted_file` / `volume` / `slack` (`Surface::ALL`, eight entries), with a
  `surface_means` sentence, so a hit in free space cannot be read as a hit in a
  live file. `file` is the narrow case, not the default: it is stamped only on a
  `FileEntry`, `FileContent` or `SystemArtifact` whose producer marked it neither
  `carved` nor `deleted` nor `is_ads`, and its sentence — "the bytes are the
  file's own content as the file system serves it" — is the one claim the code
  makes for it. The others: an
  NTFS alternate data stream (a `FileEntry` the `$MFT` parser marked `is_ads`,
  named by `stream_name` and `base_file`; on the real `HD001_MFT.dat` a
  `[ZoneTransfer]` rule fires on exactly the 191 `Zone.Identifier` streams that
  carry it, and a non-resident stream a bare `$MFT` cannot serve comes back
  `YaraNotScanned` rather than clean); the value inventory of a `RegistryHive`
  record (with the basis stated per value — bytes as stored, or re-encoded
  from the parser's rendering, which is a weaker claim; `YaraRegistryCoverage`
  counts both); and `UnallocatedSpace` regions from allocation bitmaps and
  partition-table gaps, each hit placed at a device offset, with per-region
  Shannon entropy and a base64 / gzip decode-and-rescan through `seance_bulk`
  (`YaraDecodeCoverage`); anything the carver marked `carved: true` is
  `carved` — no file system served it and its bounds are the carver's
  inference, so the hit carries the `carving_*` fields the carver wrote and is
  placed in its parent only when `carving_offset` is into the parent; a
  `FileEntry` marked `deleted: true` that is not a stream is `deleted_file`,
  with `deleted_recovery_source` and `deleted_content_caveat` carried, because
  its clusters may have been reallocated since; and a `Partition`, `FileSystem`,
  `RawEvidence` or `Container` scanned end to end is `volume`, named by
  `volume_type`, where a hit is a byte offset in that image attributed to no
  file (placed as `offset_in_parent` only on a `Partition`, whose
  `offset_bytes` is its parent's coordinate space). Every surface but `file`
  and `registry_value` also yields a `YaraRegionScanned` record when nothing
  matched, because on those the region is itself the finding. A `ParsedRecord`
  that is not a registry hive, or a `TimelineEvent`, is refused with a
  `YaraNotScanned` naming the type and carrying **no** `surface`. **Slack**: a `SlackSpace` region the NTFS, FAT or exFAT parser published is scanned as `slack`; the hit names the file (`base_file`,
  `path`, `owner_artifact_id`), carries `logical_size`, `cluster_size` and the
  region's `offset_bytes` / `offset_basis`, and each pattern hit is placed as
  `offset_in_parent` in the file system's coordinate space. Each region is
  scanned alone, so a string crossing its edge is not matched there (DFTT #2's
  `1slack1` / `2slack2`, pinned in `surfaces_real_tests.rs`); a `volume` scan
  finds it, attributed to no file. `classify()` has the three surfaces above (`seance_plugin_yara`
  `surfaces_tests`), so a carved `FileEntry` or a whole volume is not stamped `file` with
  a file-system sentence the code had not verified.
- **The scan is planned from the VAD tree and from nothing else.** Each
  allocation's range is probed for the memory that actually exists before
  anything is read, so a reserved region costs a probe rather than a sweep whose
  every byte comes back unexamined; **touching regions are merged**, because the
  chunk overlap is suppressed at a section end and an invented boundary would
  lose a match lying across it. Attribution is therefore by address and never by
  which section produced the hit, and a match outside every allocation is not
  something this planning can produce.
- **The allocation is part of the finding.** Every match in a process carries
  the virtual address descriptor whose **first byte** falls in its range: the
  range, the protection as named by the kernel's own `MmProtectToValue` table,
  whether the memory is private, and the mapped file if any. The same bytes in
  private unbacked memory and in the read-only section of a mapped system DLL
  are different findings, and the difference is in the VAD rather than in the
  bytes. A match in the kernel's space carries **no** allocation and says in
  words why there is none — VADs describe a process's user memory.
- **A process whose VAD tree will not walk is reported as NOT SEARCHED**, with
  the reason, rather than swept as one flat range. A row whose attribution is
  unavailable is a row an examiner cannot act on.
- **A rule's condition is evaluated against one chunk of the address space at a
  time** (16 MiB by default), not against a file, and the record states that on
  itself. An individual string match is reliable and is what the rows are;
  `$a and $b` fires only where both strings fall in the same chunk; `filesize`
  is meaningless, because there is no file and the chunk's length is not
  substituted for one; and `#a > 10` counts within a chunk. A larger chunk moves
  those boundaries rather than removing them. A rule that matched with **none of
  its own strings found** produces no row — there is no address to give — and is
  named separately with that reason.
- **A chunk the engine refuses is counted beside the hits.** A 30-second
  per-chunk timeout or an engine error is published rather than absorbed,
  because a refused chunk that reads as a clean one is a false absence.
- **Coverage is two figures, and the stage never adds them together.** Bytes
  that were **mapped and would not read** are evidence possibly missed; bytes
  **never mapped** — address space between allocations, or reserved inside one —
  could not have held anything. Summed, a small hole in a process's heap
  disappears under the reserved address space around it.
- **Every ceiling is stated with the address it fired at**: 8 GiB per process,
  128 GiB for the image, 100,000 matches per space, and 10,000 individually
  recorded rows — past which the totals stay exact and only the per-match detail
  stops.

**Graded against the oracle, as a set of addresses and not as a count**
(`test_data/win11_bitlocker/memory-unlocked.raw`, Windows 11 build
26200; the release-only tests are
`seance_plugin_memory_windows/tests/win11_corpus_analysis.rs`). Volatility
3.2.28.2's `windows.vadyarascan --pid 4708 --yara-string FORENSIC-W11` prints 8
matches in `taskhostw.exe`, at `0x2ca2f84c44e`, `0x2ca2f84d9ed`,
`0x2ca2f8508cb`, `0x2ca2f8511ba`, `0x2ca2f991c4b`, `0x2ca2f991d0d`,
`0x2ca2f99206c` and `0x2ca2f992093`. With the same string as a compiled rule,
this stage reports exactly those eight addresses — compared as a **set**,
because two scans can agree on eight and disagree about where, and a
disagreement about where means the planning or the attribution is wrong. All
eight are attributed to two private `PAGE_READWRITE` allocations with no file
behind them (`0x2ca2f840000-0x2ca2f93ffff` and
`0x2ca2f990000-0x2ca2f99ffff`). That process has 171 allocations; 1,126 mapped
regions and 17,248,256 bytes were examined, with 0 bytes mapped-and-unreadable.

**And the same patterns over an image's own space, for a capture with no page
tables to plan from.** `plugin.memory.pattern_scan`
(`seance_memory::patterns::ImagePatternScan`) is upstream's `yarascan` over the
physical layer: it takes the pattern sets the registration site built, claims
the image record the container stage emits, and searches the decoded space
itself. That is the only route available for a **reconstructed hibernation
file**, a **swap area**, or any acquisition whose operating system could not be
profiled — and it runs beside the per-process scan rather than instead of it,
because a match in a process's space carries the allocation that held it and a
match in an image's space cannot. Each record says so in words, and says what
an address in it means for that format: a physical address in a reconstructed
image (**not** an offset in `hiberfil.sys`, whose pages are compressed), a
physical address as a dump's run table places it, or -- for a raw blob -- an
offset in the image *as the case declared it*, since nothing in the bytes of a
flat file says it is memory.

Graded on both corpora (`seance_memory/tests/KNOWN_ANSWERS.md`; the
hibernation figures are `MEM-026`): over the
reconstructed hibernation file the shipped scan **hits its match ceiling**
(`MAX_HITS_PER_SPACE`, 100,000) and says so — `truncated`, `complete: false`,
the ceiling named — rather than reporting a count; with the ceiling raised the
pass is complete over all 2,258,956,288 restored bytes and finds 131,110
`HIBRMARK` strings, of which 131,072 begin a byte-exact marker page (every one
of the 65,536 indices at exactly two physical addresses, both named once by
the file's kernel set) and 38 are the string inside other pages, seven of the
eight inspected being the marker script's own source. The corpus test pins the
7-of-65,536 figure as history only. 863 for the same rule over the compressed
file, at offsets that cannot be placed in the machine; and 4,587 `SWAPMARK`
occurrences in the Linux swap area, every one at a 4 KiB boundary.

**A regular expression drives the same plan.** `SEANCE_MEMORY_REGEX` carries
one pattern — never a list, because no character can separate a list of regular
expressions without cutting one of them in half — and it becomes a second
pattern set over the same two address spaces: upstream's `regexscan` and
`vadregexscan`. It is compiled at registration and **fails the run** if it will
not compile, for the same reason a named rule file does. Its own caveat travels
with every result: the match is against **raw bytes**, Unicode-unaware, so `.`
is one byte and an ASCII pattern does not find the UTF-16 most strings in a
Windows process are stored as; there is no bounded match length, so a match
across a chunk boundary is not guaranteed and the pass says so; and a
zero-length match is not reported at all.

The two routes are graded **against each other** on the real capture, in one
pass over one plan: `FORENSIC-W11` as a compiled rule and `FORENSIC-W1[0-9]` as
a pattern report the same eight addresses in `taskhostw.exe`. A disagreement
there would be in the planning or the attribution rather than in either engine,
which is the failure neither engine's own tests can see.

**What is not implemented, and must not be claimed of this stage.** There is
**no dedicated frontend screen** for the pattern scan yet: the records reach the API and the
generic memory record surface. The same is true of `strings_map` below.

#### `strings_map` — `strings` over memory, which runs the other way

Every other stage starts from a structure and reads outward. This one starts
from a **physical** offset and asks which address spaces reach it, which is a
question about every process's page tables at once.

The examiner runs `strings -t d` over the raw image with their own tool, their
own minimum length and their own encodings, and names the file with
`SEANCE_MEMORY_STRINGS`. Séance runs no `strings` of its own: with nothing named
the stage reports that it **did not run**, exactly as the pattern scan does with
no rule set. **The radix is stated, not guessed** —
`SEANCE_MEMORY_STRINGS_RADIX` — because a hexadecimal file read as decimal does
not fail cleanly: lines with a letter in them are rejected and the rest parse
into frames gigabytes from the truth. The record publishes which radix was used
and what proportion of the file was rejected under it; over half is what a wrong
radix looks like, and it is reported as doubt rather than silently re-read,
since the lines that *did* parse cannot be told from correct ones.

The route is a reverse mapping, built rather than guessed:
`seance_memory::translate::enumerate` walks each address space **downward**
through the tables — reading each table whole, descending only into present
entries, and reconstructing each mapping's virtual address from the indices it
took — and `seance_memory::reverse` records every wanted frame against every
space that maps it. The kernel's space is walked first and its top table becomes
the parity every process is compared against, so the kernel's tables are read
once rather than once per process.

**Measured on the corpus capture** (10 GiB, 130 processes, one offset): 43,006
tables read, 176 MiB, 328,132 prototype hops, 5,938 subtrees declined as the
kernel's own, 0.9 s. A byte in `KUSER_SHARED_DATA`'s frame — physical
`0x285000` on this capture — is attributed to **125** address spaces, each at
the virtual address it has there.

**Upstream's per-process attribution does not work, and this is shaped against
it.** Volatility 3's `windows.strings` unpacks `Intel.mapping()`'s tuple in a
different order in its process branch than in its kernel branch
(`strings.py:183-191` against `:150-155`), so its process entries are keyed by
the **virtual** page number. Measured on this same capture:
offsets taken from pages `lsass.exe`, `explorer.exe` and `winlogon.exe` really
map all return `FREE MEMORY`, and physical `0x7ffe0000` returns 123 of the 130
live processes — not because they map that frame but because `0x7ffe0` is
`KUSER_SHARED_DATA`'s *virtual* page in each of them. Only its kernel column is
correct. So here the index is keyed on physical frames only; the physical offset
and the virtual address are fields at different levels of the record, with no
column that could hold either; and a frame reached through the shared kernel
half is **one** owner naming the spaces that reach it rather than 130 findings.

**There is no "free memory" verdict.** An offset no walked space maps is
reported as unmapped only where every declared address space was enumerated
whole, and even then the row states what it does not claim: the PFN database is
not read here, a frame on the free or standby list still holds the last bytes
written to it, and a mapping that existed at another instant is not in this
image. Where any space fell short the verdict is *not assessed* and the record
names each space and why. On a real Windows image coverage is **never** complete
— every space has suppressed uniform tables and trimmed shared pages in it, and
the corpus run reports 129 such shortfalls — so in practice this build does not
assert that a frame is unmapped, and says so rather than rounding to a negative.

**Symbols are a prerequisite, not an extra.** Without an ISF matching that exact
kernel build, discovery identifies the kernel and stops — correctly, because
every offset would otherwise come from a different build. See
`documentation/MEMORY_BUILD_BINDING.md` for the symbol-binding contract and
`documentation/TESTING.md` for provisioning the Volatility symbol pack.

### `seance_plugin_bitlocker`
**Responsibility:** BitLocker (Windows FVE) volume support.
`documentation/Container_Formats.md` owns the full coverage table; the summary:

- **Detection runs before the credential is looked at.** Whether a volume is
  encrypted is a fact about the evidence; whether anyone can open it is a fact
  about this run.
- **A locked volume with no credential is REPORTED**, not skipped, carrying the
  cipher, the FVE volume identifier and the key-protector labels read out of
  the unencrypted FVE metadata — because "an AES-XTS-256 volume with a
  recovery-password protector is present and was not opened" is a finding and
  silence is not.
- **Decryption:** AES-XTS 128/256 and AES-CBC + Elephant diffuser 128/256.
  Plain AES-CBC recovers keys but is reported `CipherNotDecryptable`.
- **Credentials:** for one volume after ingest, the recovery password or the
  password supplied from the Needs attention queue (or `POST
  /cases/{id}/artifacts/{id}/credential`, or the REPL's `/unlock`).
  The decryptor runs again on that volume alone; if it opens, the decrypted
  volume appears beneath it with a `VolumeDecryption` `Unlocked` record that
  supersedes the locked one, and if not, nothing in the case changes and the job
  and audit log say it was refused. For a whole run, `--bitlocker-password` or
  `--bitlocker-recovery-key`. Either way held in process memory for the run and
  never persisted. `seance_cli crack-bitlocker` runs a wordlist or mask.
- **Reading a decrypted volume after its run:** the key is not kept
  after the run, so the decrypted volume and everything beneath it are refused
  (never served as ciphertext) until an examiner unlocks it for reading —
  `POST /cases/{id}/artifacts/{id}/unlock` with `bitlocker_password` or
  `bitlocker_recovery_password`, the Inspector's *Unlock to read*, or the
  REPL's `/unlock --read`. The FVEK is re-derived from the volume's own
  metadata and the decrypting view held in process memory for that case, for
  a TTL (8 h default), audited by kind; lock, expiry, case delete or a restart
  forgets it. Graded end to end on `test_data/bdetogo.raw` (the relocated boot
  record reads back as `mkdosfs`/`0x55AA` after unlock, is refused before and
  after lock).
- **Not implemented:** recovering an FVEK from a memory capture. Nothing in the
  tree does this, and it must not be claimed.

---

### Autostart and persistence (ASEP)

`seance_plugin_asep` answers one question once for a machine: what will Windows
execute at boot or at logon, and why. It reads evidence the other plugins have
already produced and emits one record per autostart location. Its module id is
`plugin.windows.asep`. It subscribes to `FileEntry`, `SystemArtifact` and
`ParsedRecord`, so it sees the volume as it is walked, the task and Startup
files on it, the WMI repository, and the `RegistryHive` records the registry
plugin parses. It does not re-open a hive. It cannot see a value the registry
parser did not surface, and the coverage record states the value counts it
worked from.

**Records**

| Record | Meaning |
|---|---|
| `AsepEntry` | One autostart location read from a live structure: a parsed hive, a file on the volume, a WMI record the repository's own tables resolve. |
| `RecoveredAsepEntry` | The same shape, read from bytes the evidence no longer references. It is a separate type so a consumer that filters on type alone cannot count it as live. |
| `AsepCoverage` | What was looked for, where, and with what result. One per parsed hive and one per `OBJECTS.DATA` file. |

The module is a fact-finder and does not accuse. No record carries a score, a
verdict or a "suspicious" flag. Records carry neutral `observations` such as
`differs_from_windows_default`, `server_outside_system_directories`,
`additional_element_in_list` and `shortcut_target_absent`. Whether an entry is
unwanted is the examiner's call.

**Sources**

| Source | What is read |
|---|---|
| Registry hives | The `SOFTWARE`, `SYSTEM`, `NTUSER.DAT`, `DEFAULT` and `UsrClass.dat` hives, as parsed `RegistryHive` records. Matching is by case-insensitive key-path suffix, so one rule covers `HKLM` and `HKCU` spellings, `Wow6432Node`, every `ControlSet` and the synthetic root an offline hive carries. SAM, SECURITY, COMPONENTS and BCD are not ASEP carriers here and every category is `unexamined` for them, never empty. |
| Task XML | Files under `\Windows\System32\Tasks`, `\Windows\SysWOW64\Tasks` and `\Windows\Tasks`. The store path is the gate, because the Task Scheduler runs only definitions found there. |
| Startup folders | Items under a `Start Menu\Programs\Startup` path: per user, all users (`ProgramData` or `All Users`) and the legacy `Documents and Settings` form. |
| WMI repository | `\wbem\Repository\OBJECTS.DATA`, or `\wbem\Repository\FS\OBJECTS.DATA` as on Windows XP, read by a record-level scan. |

**Categories**

The table `seance_plugin_asep::rules::CATEGORIES` holds 31 categories. Every one
is reported for every hive examined, as entries found, examined and empty,
not applicable to that hive, or unexamined with a reason. Each carries one
ATT&CK technique under TA0003 Persistence, and a technique note where the mapping
is an approximation.

| Category | Locations read | Hives |
|---|---|---|
| `run_key` | `Run`, `RunOnce`, `RunOnceEx`, `RunServices`, `RunServicesOnce`, `Policies\Explorer\Run`, with the `Wow6432Node` views | `SOFTWARE`, `NTUSER` |
| `startup_folder` | Items in the Startup folders above | filesystem |
| `startup_folder_redirect` | `Explorer\User Shell Folders` and `Shell Folders` values `Startup` and `Common Startup` | `SOFTWARE`, `NTUSER` |
| `winlogon_shell`, `winlogon_userinit` | `Winlogon\Shell`, `Winlogon\Userinit` | `SOFTWARE`, `NTUSER` |
| `winlogon_notify` | `Winlogon\Notify\<package>` | `SOFTWARE` |
| `winlogon_other` | `Winlogon\Taskman`, `GinaDLL`, `AppSetup`, `VmApplet`, `UIHost` | `SOFTWARE`, `NTUSER` |
| `ifeo_debugger` | Image File Execution Options `Debugger`, and `SilentProcessExit\<exe>\MonitorProcess` | `SOFTWARE` |
| `appinit_dlls` | `Windows\AppInit_DLLs`, with the `Wow6432Node` view | `SOFTWARE` |
| `appcert_dlls` | `Session Manager\AppCertDlls` | `SYSTEM` |
| `boot_execute` | `Session Manager\BootExecute`, `SetupExecute`, `S0InitialCommand`, `Execute` | `SYSTEM` |
| `known_dlls` | `Session Manager\KnownDLLs`, listed as a mapping table that is a hijack surface, not an autostart | `SYSTEM` |
| `active_setup` | `Active Setup\Installed Components\<guid>\StubPath` | `SOFTWARE`, `NTUSER` |
| `service` | `ControlSet*\Services\<name>` (`Start`, `Type`, `ImagePath`, `ObjectName`, `DisplayName`) and `Parameters\ServiceDll` | `SYSTEM` |
| `lsa_authentication_package`, `lsa_notification_package`, `lsa_security_package` | `Control\Lsa` authentication, notification and security packages, and `OSConfig\Security Packages` | `SYSTEM` |
| `print_monitor`, `print_processor` | `Control\Print\Monitors\<name>\Driver`, `Print\Environments\<env>\Print Processors\<name>\Driver` | `SYSTEM` |
| `netsh_helper` | `Microsoft\NetSh` | `SOFTWARE` |
| `winsock_provider` | `WinSock2\Parameters\Protocol_Catalog9` and `NameSpace_Catalog5` catalog entries | `SYSTEM` |
| `network_provider` | `Services\<name>\NetworkProvider\ProviderPath` | `SYSTEM` |
| `com_server` | `CLSID\<clsid>\InprocServer32`, `LocalServer32`, `InprocHandler32`, kept when the server lies outside the system directories | `SOFTWARE`, `UsrClass`, `NTUSER` |
| `shell_extension` | `shellex` context-menu and property-sheet handlers, icon overlays, `ShellServiceObjects`, `ShellExecuteHooks`, `SharedTaskScheduler` | `SOFTWARE`, `UsrClass`, `NTUSER` |
| `browser_helper_object` | `Explorer\Browser Helper Objects\<clsid>` | `SOFTWARE`, `NTUSER` |
| `scheduled_task` | Task XML above, and Task Scheduler 1.0 `.job` files | filesystem |
| `scheduled_task_registration` | `Schedule\TaskCache\Tree` | `SOFTWARE` |
| `wmi_mof_autorecover` | WMI auto-recover MOF list | `SOFTWARE` |
| `installed_sdb` | `AppCompatFlags\InstalledSDB` and `AppCompatFlags\Custom` | `SOFTWARE` |
| `file_association` | `FileExts\<.ext>\UserChoice`, `OpenWithProgids`, and the `shell\open\command` a ProgId resolves to | `NTUSER`, `UsrClass`, `SOFTWARE` |
| `wmi_event_subscription` | `__EventFilter`, the consumer classes and `__FilterToConsumerBinding` in `OBJECTS.DATA` | WMI repository |

**What a record carries**

- Identity: `category`, `entry_name`, the backing `location` verbatim, `location_kind`
  (`registry_key` or `file`), `value_name`, `hive`, `scope` (`HKLM`, `HKCU` or
  `filesystem`) and the `user` when a per-user profile was established.
- Content: `image`, `command`, `arguments` and `working_dir` as stored, the
  `split_basis` that says how image and arguments were separated, and
  `runs_when`, a plain sentence saying what would run and when.
- State: `enabled` with its `enabled_basis`, `read_status` (`parsed` or `unread`
  with the reason), `incomplete_reason` with its machine-readable code, and
  `evidence_state` (`live`, `allocated_record`, `recovered`, `superseded` or
  `unlinked`).
- Time: `installed_time` only when the evidence records one. A task takes its
  `RegistrationInfo/Date`. A Startup item takes the file's creation time. A
  registry entry has none, because the parsed hive record carries no per-key
  last-write time, and the record says so. A WMI record's header time is a bound
  on when the subscription was made, carried as `record_time` and never as an
  install time. An entry with no time contributes nothing to the timeline, never
  an event at the epoch.
- Target: `target_exists` is `observed_at_path`, `observed_by_name_only`,
  `not_observed`, `no_file_index`, `unresolved_environment_variable` or
  `not_applicable`, with the basis and the paths looked at. `not_observed` means
  the name was not seen in the files enumerated so far. It never means the file
  is absent from the volume. `no_file_index` means no filesystem was enumerated,
  which is not the same answer.
- Category fields: a service carries `service_start_type`, `service_type`,
  `service_dll`, `service_account` and `control_set`, and each control set is
  reported on its own, since `ControlSet001` and `ControlSet002` can disagree. A
  task carries `task_uri`, `task_author`, `task_run_level`, `task_logon_type`,
  `task_hidden`, its triggers and its actions, including `ComHandler` actions
  that name a COM class and no command line. A Startup item carries
  `startup_item_kind` and `startup_all_users`.

**Reading rules**

- A `Start` value that is missing or will not decode is reported unreadable. It is
  never defaulted, because `0` would invent a boot-start driver and `4` would hide one.
- Task XML is sniffed for UTF-16LE with a byte-order mark and for UTF-8 with or
  without a declaration, and neither is assumed. The reader expands no entities
  and bounds depth, event count and text length. A file that trips a bound is
  marked incomplete. A file that will not parse is emitted `unread`.
- A Startup `.lnk` is resolved from its own bytes to its target, since the
  shortcut is a stub and the target is what runs. A shortcut that will not parse
  still yields an entry marked `unread`. A batch file or executable dropped in the
  folder is reported the same way. `desktop.ini` is not an autostart item and is
  skipped.

**Associations, WMI and target resolution in detail**

**File associations** (ATT&CK T1546.001): `FileExts\<.ext>\UserChoice` and `OpenWithProgids`, reported as the association and the ProgId it names with **no hijack claim** — presence is the ordinary state of the system, and one real Windows 7 user hive carries `UserChoice` for 17 extensions and 138 `OpenWithProgids` candidates, counted through this project's reader. `UserChoice`'s `Hash` is a MAC over the SID, the extension and the ProgId that cannot be recomputed offline, so every record states the check exists and was not made. The category's own coverage statement carries both, so a reader of the report and not only of one record is told.

**WMI event subscriptions are read**: a `FileEntry` at `\wbem\Repository\OBJECTS.DATA` (or `\wbem\Repository\FS\OBJECTS.DATA`, the form observed on Windows XP) is read under a 512 MiB ceiling, reported by number if hit, and scanned **page by page** (`seance_plugin_asep::wmi`): each 8,192-byte page's descriptor table is read whole, since freed slots are reused and the entries are not in offset order; every descriptor-listed record that lies within its page is tried as a class definition, and the property tables of the classes found (name, CIM type, state-bit index, value offset, superclass, defaults) are read **from the file itself**, because the two real repositories each carry two different `ActiveScriptEventConsumer` definitions and a table typed into the code would have been wrong for one of them. Instances of `__EventFilter`, `__FilterToConsumerBinding`, the five consumer classes Windows ships, and any consumer class a decoded binding names are found by the class-name hash every instance record begins with — SHA-256 and MD5 of the uppercased UTF-16LE name, **both tried on every file** (observed: SHA-256 on the Windows 10 and Windows 7 repositories, MD5 on the XP one; the reference's version ranges are not relied on) — and decoded against those definitions; `CommandLineEventConsumer` command lines and `ActiveScriptEventConsumer` scripts are decoded when present.

**The page mapping is read when it is beside the file** (`WMI-2` in `documentation/VALIDATION.md`): `MAPPING1/2/3.MAP`, or `OBJECTS.MAP` on XP, reached through `open_relative` — on disk beside a loose file, or inside an image through the neighbour group `attach_sibling_bundles` builds for a `wbem/Repository` directory. `seance_plugin_asep::wmi_mapping` parses each (header `0xABCD`, sequence number, physical and logical page counts, one entry per logical page — 24 bytes whose first u32 is the physical page on the numbered files, 4 bytes on XP — the free list and the `0xDCBA` footer, every count checked against the bytes left; the numbered files carry a second section for `INDEX.BTR`), refuses a malformed one or one that accounts for a different number of physical pages than the file has, and uses the well-formed one with the highest sequence number; the coverage record names it, the older ones, and the refused ones with their reasons. `wmi::scan_with_mapping` then walks the logical pages in order: a record running past its page is read on into the next logical page the mapping names (not the physically next page), a continuation page's first bytes are not read as a descriptor table, and each record carries `record_page_state` — `mapped` with `record_logical_page`, or `unmapped`, a free page whose records are published as `evidence_state: superseded` under `RecoveredAsepEntry`. On the whole Lone Wolf, Data Leakage and XP repositories every spanning record was reassembled (364, 180, 84); the XP ones match their stored CRC-32s, a check the scan makes itself and counts on the coverage record as `reassembled_checksums_verified` / `reassembled_checksums_mismatched` (84 / 0; Windows 7 onward store zero and are counted in neither). A record in an unmapped page that a descriptor table lists is `superseded`; one no descriptor lists stays `recovered`. A binding resolves each end to the copy that stands best in the mapping — a record a mapped page's descriptor table lists before residue, bytes past the mapping or a copy in an unmapped page — so a current binding never borrows a superseded consumer's command line while a current copy exists; an end found only as a copy the mapping does not establish as current marks the binding incomplete and its `enabled_basis` says that it is in force was not established, and a filter's or consumer's bound list counts only current bindings, the rest listed apart as `*_not_current` (mechanism tests on the real Lone Wolf triad with a copy placed in an unmapped page in the test, since no corpus holds one).

**The index is read when it is beside the file** (`WMI-4` in `documentation/VALIDATION.md`): `seance_plugin_asep::wmi_index` reads `INDEX.BTR` for a `MAPPINGn.MAP` repository (the XP form, `INDEX.MAP`, is not read). The index is 8,192-byte pages addressed through the `INDEX.BTR` section of the active mapping; a page opens with signature `0xACCC`, its own logical number and a key count, then the key and child lists, a key-definition table and a string table; a key is its parts joined with `/`, and a key ending `.<logical page>.<record id>.<size>` is a **data reference** naming the descriptor-listed record at that (page, id, size). The root is the logical page in the fourth field of the first entry of the index's mapping section. The tree is **walked from the root**, never by reading every mapped page, because pages the tree no longer reaches stay mapped and keep stale references (4 descriptors on each Flare repository and 23 on Perseverance are listed by a current page and named by none); a page is refused unless it carries the signature and its own logical number, is reached once, and every count fits the bytes left. A subscription record a mapped page lists is `indexed` (named by the index, `evidence_state: allocated_record`) or `listed_not_indexed` (`evidence_state: unlinked`, published under `RecoveredAsepEntry`, not in force, and a binding's end found only so marks the binding incomplete); the coverage record carries `index_read` with the reason when unread, `index_data_references`, `index_pages_visited`, `descriptors_listed_not_indexed`, `records_indexed` and `records_listed_not_indexed`. An index that is missing, withheld, refused or of the XP form leaves the record `in_mapped_page_index_not_read`, current on its page's own descriptor table, with the reason stated. No real subscription record is listed but not indexed in any repository held, so that standing is pinned on a synthetic index only; none of the 4 or 23 unindexed descriptors is a subscription-class record the scan matched. `MAPPING.VER` is not held here and not read. Without a mapping, what follows stands. Every record states what the scan is not: `INDEX.BTR` and, when none was found, `MAPPING*.MAP` are **not read**, so `repository_liveness` is `not_established` — a record found is one the file holds, which may be the mapped one or a superseded copy in a page the mapping no longer points at; a class definition whose descriptor runs past its page is skipped and its instances are reported undecodable for want of a definition; the dynamic-property instance form is not decoded; and the meaning of the two FILETIMEs in the record header is not documented, so the later of the two is carried as `wmi_record_filetime_later_of_two`. Entries recovered this way from a repository are `RecoveredAsepEntry` records, distinct by type. Known answers: the Lone Wolf Windows 10 repository (SCM Event Log filter, `NTEventLogEventConsumer`, their binding; 11,548 descriptors) and the CFReDS XP repository (3,902; a second filter/binding whose consumer instance sits on a page deliberately left out of the fixture, exercising the "consumer not found" path), as page-subset fixtures in `seance_plugin_asep/tests/fixtures/wmi/`.

**A real `CommandLineEventConsumer` is graded** (`WMI-1` in `documentation/VALIDATION.md`): Windows 7's stock `BVTConsumer` (`cscript KernCap.vbs`, working directory `C:\\tools\\kernrate` as stored) and its `BVTFilter` and binding in the NIST Data Leakage repository, every string, the CreatorSID, both header FILETIMEs and the record's extent agreeing with a hex reading; the command splitter takes `cscript KernCap.vbs` as a bare program name and its first token (`command_split_basis: bare_program_name_first_token`).

**A bare program name is resolved on the search path**: a target with no directory, drive or variable is tried at `\Windows\System32`, `\Windows\SysWOW64` and `\Windows`, with the default `PATHEXT` `.com`, `.exe`, `.bat`, `.cmd` appended when it carries no executable extension; the record names every candidate (`target_search_path_candidates`), the directory that answered (`target_search_path_directory`) and whether `target_lookup_path` was observed (`target_search_path_resolution: observed_on_search_path`) or is only the first candidate by convention (`search_path_convention_not_observed`). A miss is `not_observed`, worded as for any other target.

**A WMI consumer's own search**: for a `CommandLineEventConsumer` the recorded `WorkingDirectory` is tried before the system directories (a working directory holding an unexpanded variable is named in the basis as not searched), and the extension rule is `CreateProcess`'s — only `.exe` appended to a name with no extension, since the consumer's properties are `CreateProcess` parameters — so `cscript` is tried as `\tools\kernrate\cscript.exe`, `\Windows\System32\cscript.exe`, `\Windows\SysWOW64\cscript.exe`, `\Windows\cscript.exe`.

**Sources whose documentation requires a full path**: a service's `ImagePath` (when no `ServiceDll` is reported — `CreateService` documents `lpBinaryPathName`, stored as `ImagePath`, as "the fully qualified path to the service binary file") and an Image File Execution Options `Debugger` value (the only Microsoft pages found are service-debugging guidance — "Debugging a Service": "the full path to the debugger"; "Preparing to Debug the Service Application": "the full path and file name" — and the basis says so, since no general specification of the value was found) are resolved under `full_path_required`: the basis says a bare name is outside the documented contract and that how the launcher resolves one is not documented, naming the service control manager for a service (`Type` 0x10 to 0x60, the interactive 0x100 and per-user-instance 0x80 bits masked, so a per-user instance such as 0xD0 or 0xE0 is a service), the kernel for a driver (`Type` 0x1, 0x2 or 0x8, or `Start` 0 or 1, which Microsoft defines for drivers only), and either when `Type` does not say, which includes `SERVICE_ADAPTER` 0x4, documented only as reserved. The `service_type_label` follows winnt.h: 0x40 "User service", 0x50 "User own-process service", 0x60 "User shared-process service", with "(per-user instance)" for the 0x80 bit on 0x50 or 0x60. The shell's `PATHEXT` list is tried as leads, not as the launcher's rule — for an entry that is, or may be, a driver, `\Windows\System32\drivers` is tried first and `.sys` before the `PATHEXT` extensions, since the shell's list alone never names a driver — so a file at a candidate is `target_exists: observed_by_name_only` with `target_search_path_resolution: lead_candidate_observed` — never `observed_at_path`, and never worded as where Windows resolves the name — and a miss, or an entry in a case with no file index, is `lead_candidate_not_observed`. The record's `target_path_expansion` says the same: "bare program name outside the documented full-path contract; how the launcher resolves it is not documented -> lead candidates only (…)", never the search path. Every other source keeps the shell's `PATHEXT` list — Microsoft's pages for Run/RunOnce ("a command line"), the Task Scheduler Exec `Command` ("the executable file or document to be run") and `ShellExecuteEx` (a search of the working directory, `\Windows`, `\Windows\System32`, `PATH` and `App Paths`, with no extension rule stated) do not say which extensions those launchers append, and no page was found tying Run keys, tasks or shortcuts to `ShellExecuteEx` — and every record names the rule applied as `target_search_rule` (`create_process_exe_only` / `full_path_required` / `shell_pathext`) and says it in its basis. A hit in the working directory is `observed_in_working_directory`, worded apart: `CreateProcess` searches the *launching* process's current directory, not the new process's, so a copy there is where a planted program would sit, not proof it was the one loaded. The launching process's own directory (the WMI host's is not recorded in the repository), its current directory and `PATH` are not modelled, and each basis says so; a bare COM server name is never excluded as in-System32 on the convention alone.

**A real, attacker-planted subscription is graded** (`WMI-3` in `documentation/VALIDATION.md`): the HTB Business CTF 2022 "Perseverance" repository, read loose with its three mapping files, gives the `Windows Update` `CommandLineEventConsumer` (`cmd /C powershell.exe … -enc …`), its `Windows Update` filter and binding, as the published write-up and an independent `dissect.cim` reading give them.

**A PowerShell encoded command is decoded on every autostart record**: when a record's `command` runs `powershell` or `pwsh` and passes it an `-EncodedCommand` parameter — any prefix of the name (`-e`, `-enc`, …) or the alias `-ec`, with `-` or `/`, in any case — the argument after it is decoded as PowerShell decodes it (strict base64 of UTF-16LE text) and published as `powershell_encoded_command_decoded`, with `powershell_encoded_command_parameter` (as written) and `powershell_encoded_command_basis`, which says the text is what the stored command carries, not evidence that it ran; an argument that is not base64, decodes to an odd number of bytes or to invalid UTF-16LE is published as `powershell_encoded_command_undecodable` with the reason, and no script. Only the first such parameter after the PowerShell image is read; the command is split on whitespace for this purpose, so an argument quoted with spaces inside it is not reassembled.

**No real `ActiveScriptEventConsumer` instance is held** (Perseverance, whose third-party summary calls its consumer a script consumer, holds none), so that class is decoded by the same definition-driven decoder with no real instance behind it, and its records say so (open in `BUGS.md`, `HUNT-195`). The XP descriptor checksum verifies under the ordinary CRC-32, not the zero-initialised variant the libyal description gives; the bytes won.

**What is not read**

- Task Scheduler 1.0 `.job` files are binary and are not decoded. Each is
  reported as an unread entry, not omitted.
- Winsock catalog entries are binary `WSAPROTOCOL_INFO` structures. The entry and
  its key are reported and the provider DLL path is not decoded.
- The categories not in the table above are not read. Autoruns tabs with no
  category here include sidebar gadgets, codecs and the `htmlfile\shell\open`
  image hijack. A persistence mechanism outside the table is invisible in the
  output, and the coverage record lists only the categories the table holds.
- No signer, publisher or known-good judgment is made. An entry's target is not
  verified against Authenticode.
- A localised or redirected Startup folder does not match the English path
  fragment. The `startup_folder_redirect` category reports the folder Windows
  was told to read, so the move is visible even when the contents are not.
- Caps bound a scan, and a capped scan sets `scan_capped` so counts are lower
  bounds: 2,000,000 values scanned, 50,000 entries emitted per hive, 50,000
  service keys, and 500,000 COM registrations remembered.
- Task files are read to 8 MiB and shortcuts to 4 MiB.

Known answers for the WMI scan are `WMI-1`, `WMI-2`, `WMI-3` and `WMI-4` in
`documentation/VALIDATION.md`. The launcher rules observed on Windows 11 are
`LAUNCH-1` there.

---

## Implementation Roadmap

### Phase 1: Foundation
- [x] **NTFS Support:** `seance_plugin_mft`, `seance_plugin_logfile`, `seance_plugin_usnjrnl`, `seance_plugin_i30`, `seance_plugin_badclus`.
- [x] **Registry Support:** `seance_plugin_registry` (Hive parsing).

### Phase 2: User Activity
- [x] **LNK Files:** `seance_plugin_lnk`.
- [x] **Jump Lists:** `seance_plugin_jumplists`.
- [x] **Prefetch:** `seance_plugin_prefetch`.
- [x] **Event Logs:** `seance_plugin_evtx`.

### Phase 3: Advanced Artifacts
- [x] **ShellBags:** `seance_plugin_shellbags`.
- [x] **SRUM:** `seance_plugin_srum`.
- [x] **Recycle Bin:** `seance_plugin_recyclebin`.

### Phase 4: Commercial Grade
- [x] **Shadow Copies:** `seance_plugin_vss`.
- [x] **AmCache:** `seance_plugin_amcache`.
- [x] **ShimCache:** `seance_plugin_shimcache`.
- [x] **BitLocker:** `seance_plugin_bitlocker`, registered in `seance_api::modules`, unlocked from the case's supplied password or recovery key — and **reported with its cipher, volume identifier and key protectors when no credential was supplied at all.** The encryption detector's own BitLocker record for the volume is tied to the decryptor's records by the shared `volume_artifact_id` and defers the unlock status to them. See `documentation/Container_Formats.md`.
- [x] **Memory:** `seance_plugin_memory_windows`, registered in `seance_api::modules`, 36 stages (`module::STAGES`). See `documentation/MEMORY_BUILD_BINDING.md` for its symbol-binding contract.
- [x] **Hibernation:** `hiberfil.sys` reconstructed into a physical address space (NT10 and NT6.2/6.3 x64, both Xpress codecs). **How much of a file is reconstructed is measured, and on both corpus files it is the whole of what the header describes** — every restore set walked to the page count its header states, checked and recorded on the layer (`MEM-026`). NT6.1 opt-in and stamped unvalidated; older and 32-bit layouts identified only.
- [x] **Crash dumps:** full, bitmap and kernel-bitmap decoded; kernel/small/automatic refused by name, with the header's bugcheck facts still reported.
- [x] **Windows autostart (ASEP):** `seance_plugin_asep` ships and is registered. See "Autostart and persistence (ASEP)" above.
- [x] **NTFS `$Secure:$SDS`:** `seance_plugin_secure_sds` ships and is registered — one record per unique security descriptor in the stream (owner, group, the full DACL and SACL, keyed by the descriptor's `security_id`), with the mirror copy read when the primary will not verify. **It does not answer "who could read this file"**. The key is on both sides — the `$MFT` parser publishes each record's `$STANDARD_INFORMATION` `security_id` on its `FileEntry`, the USN journal parser publishes it on every V2/V3 record, and every descriptor record carries it; on dfir_ntfs's `ntfs_index` volume every non-zero id resolves to a decoded descriptor. **The file page performs the join, and nothing else does.** The Inspector's *Owner and permissions* section (`frontend/src/pages/artifact/OwnershipSection.tsx`, lookup in `ownership.ts`) takes the `FileEntry`'s `security_id`, lists the `NtfsSecurityDescriptorStore` records and keeps the one whose `$Secure:$SDS` stream entry has the file's own parent — the volume, or bare `$MFT`, the MFT parser read both from; ids on two volumes are unrelated — then searches that stream entry's subtree alone through the existing `/records` listing (`type=NtfsSecurityDescriptor`, `source_id`, `q`/`q_keys=security_id`) and matches the id exactly, since the listing's search is a substring. It shows owner, group, integrity level and every DACL/SACL entry, labelled with the stream, the header hash as read and the stream offset (mirror recovery and offset mismatch stated), and renders five other states in words: no `security_id` (FAT, ext4, NTFS 1.x, a file in a container), id 0, no store from that volume in the case, the store not read (its `read_incomplete` and `_detail`), and no descriptor with that id — not shown absent when the store's listing is incomplete. A lookup failure is shown as a failure. No record, report, export or REPL command carries the join. `the_file_views_volume_scoped_join_resolves_on_a_real_volume` pins the parentage the scope rests on against the real volume (`System Volume Information` → id 262 → owner `S-1-5-32-544`, group `S-1-5-18`, one ACE). The module's incompleteness uses the shared vocabulary (`inventory_incomplete`, and `content_incomplete` for a short read, each with `_detail`, beside the module's own `store_listing_incomplete`), and a stream with no readable bytes — what a bare `$MFT` yields — produces the store record stamped unread (`volume_not_in_evidence` or `no_data_source`) rather than an `InvalidInputFormat` the orchestrator filed as an ordinary decline.
- [x] **Thumbcache:** `seance_plugin_thumbcache` ships and is registered. A source that returns fewer bytes than it declares is stamped `short_read` (also in place of `truncated_final_entry` when the short read is what tore the last entry), and `file_read_capped` is kept for a cache over the 1 GiB load ceiling whose bytes up to it all arrived (the cap word is not yet the standard `cap_reached`). The entry size fields are also read at fixed offsets with no version detection — a Vista-layout entry would be counted as `inconsistent_entry_fields` rather than decoded — which is stated here as a code reading, no Vista sample having been examined.

