# Seance Test Data

## Read this first: almost nothing here is in the repository

`/test_data/` is **gitignored** (`.gitignore`). Exactly ten paths are tracked,
having been force-added before the ignore rule:

```
test_data/README.md
test_data/ios_backup_fixtures/mbdb_basic/{Manifest.mbdb,Manifest.mbdx,Manifest.plist,0000…0002}
test_data/ios_backup_fixtures/sqlite_basic/{Manifest.db,Manifest.plist,bb/bb1cc2d3…}
test_data/win11_tamper_plant/{README.md,plant.ps1}
```

Everything else this file describes is a sample you must **obtain or build
yourself**. A fresh clone has none of it, and the tests that want it self-skip.
This file is therefore not an inventory of what is here. It is the instruction
sheet for what to put here.

Where a sample's provenance is recorded, it is recorded **in the test that uses
it**, and this file points at that test rather than restating it — a second copy
of a provenance claim is a second thing to go stale.

## Overview

Tests skip gracefully if their sample is missing, printing something like:

```
Skipping test: test_data/some_file.dat not found
```

**A skip is not a pass, and this is the file that decides whether anyone can
turn one into the other.** For the corpus-gated *memory and image* tests — the
ones reached through `SEANCE_*` environment variables rather than through a
`test_data/` path — the gate in `seance_core::test_support::corpus` makes a
named-but-missing corpus a hard failure, and `SEANCE_REQUIRE_CORPUS=1` makes the
skip itself one. See `documentation/TESTING.md`. The `test_data/` samples below
have **no such gate**: they self-skip on a bare `path.exists()`, so a run over
an empty `test_data/` reports `ok` having compared nothing. Treat the table
below as the list of what a green suite may silently not have covered.

## Directory Structure

Directories the code actually references (`grep -rhoE "test_data/[A-Za-z0-9_./*-]+" --include=*.rs`):

```
test_data/
├── ios_backup_fixtures/     # ✅ IN THE REPO — iOS backup manifests (mbdb + sqlite)
├── win11_bitlocker/         # Windows 11 25H2 BitLocker corpus (built; see below)
├── dftt/                    # DFTT test images (seance_tests); seance_validate reads them from its --corpus root, not here
├── canon2/                  # Digital Corpora nps-2009-canon2 (raw + E01)
├── full_image/              # Large multi-segment E01 (~35 GB, 18 segments)
├── mft/                     # MFT parser fixtures + *.golden.jsonl golden output
├── regf/                    # Registry parser edge-case hives
├── winreg/                  # Amcache hives
├── automatic_destinations/  # Windows Jump Lists
├── custom_destinations/     # Windows Jump Lists
├── chrome_history/          # Chrome History databases, several versions
├── firefox_history/         # Firefox places.sqlite
├── recycler/                # Windows XP-era INFO2
├── vss_extracted/           # Extracted from vss_1_vol.tar.gz
├── zip/                     # ziptest.zip
└── …                        # Individual files, listed below
```

There is no `artifacts/` directory and nothing references one.

## Test Data Sources

### Critical Integration Test Data

These files are required for full-chain integration tests:

#### E01 → Ext4 → File Access Chain (`seance_tests/src/ext4_full_chain_test.rs`)
- **Location**: `test_data/full_image/001.E01` (+ segments 001.E02, 001.E03, etc.)
- **Size**: ~35GB (18 segments @ 2GB each)
- **Description**: Multi-segment E01 image containing Linux Ext4 filesystem
- **Tests**:
  - E01 container parsing
  - Partition detection (MBR/GPT)
  - Ext4 filesystem parsing with extent trees and htree directories
  - File content extraction (/etc/timezone)
  - Full artifact chain validation

**Note**: These large E01 files are not included in the repository. Tests will skip if not present.

### NTFS Artifacts

#### MFT Files
- MFT (Master File Table) test files from various Windows systems
- Used by: `seance_plugin_mft` tests, `seance_tests`, and the Criterion benchmarks
- Whole-system MFT samples live in `test_data/` root:
  - `HD001_MFT.dat` - ~36MB Windows MFT
  - `HD002.0_MFT.dat` - ~256KB small MFT
  - `HD002.1_MFT.dat` - ~14MB medium MFT
- Parser fixtures live in `test_data/mft/`: `nist-hacking-case.mft` (used by four
  `seance_plugin_mft` tests), `ntfs_frag_mft.bin`, and `*.golden.jsonl`
  golden-output fixtures. `seance_tests` walks the whole `test_data/mft`
  directory.

`seance_benchmarks/benches/mft_parsing.rs` resolves `4k-large.mft` and
`compressed_sparse.mft` at the **root** (`test_data/4k-large.mft`,
`test_data/compressed_sparse.mft`), not under `test_data/mft/`. A benchmark that
cannot find its file prints *"Skipping benchmark …: not found"*, measures
nothing and exits zero. The `mft/` subdirectory holds the parser fixtures and
goldens; the split is flagged in `seance_benchmarks/README.md` too.

#### LogFile (`test_data/HD00*_LogFile.dat`)
- NTFS transaction log files
- Used by: `seance_plugin_logfile` tests
- Sizes: 4MB - 64MB

#### USN Journal (`test_data/HD00*_UsnJrnl.dat`)
- NTFS Update Sequence Number journal files
- Used by: `seance_plugin_usnjrnl` tests
- Size: ~128KB each

#### i30 Index (`test_data/HD00*_i30.dat`, `i30_sample_directory.bin`)
- NTFS $I30 directory index files
- Used by: `seance_plugin_i30` tests
- Size: 4KB - 8KB

### Windows Registry

#### Registry Hives (`test_data/`)
- `SAM` - Security Account Manager hive (256KB)
- `SYSTEM` - System hive (~16MB)
- `SOFTWARE` - Software hive (~36MB)
- `NTUSER.DAT` - User hive (~786KB)
- Used by: `seance_plugin_registry` tests

#### Registry Test Files (`test_data/regf/`)
- `100_sub_keys.hiv` - Registry with many sub-keys
- `corrupt_sub_key_list.hiv` - Corrupted registry for error handling tests
- Used by: Registry parser edge case tests

### Windows Artifacts

#### Jump Lists
- **Automatic Destinations**: `test_data/automatic_destinations/*.automaticDestinations-ms`
- **Custom Destinations**: `test_data/custom_destinations/*.customDestinations-ms`
- Neither directory exists in this checkout. They are plaso's fixtures, and `seance_tests` looks
  in `test_data/` first and then in `reference/plaso/test_data/` for the same relative
  path (`seance_tests/src/fixtures.rs`), skipping with a printed line naming both places
  only when neither holds the file.
- Used by: the five fixture-reading tests in `seance_tests/src/lnk_jumplist_tests.rs` —
  **not** by `seance_plugin_jumplists`, whose own unit tests use synthetic buffers (the
  On a checkout with plaso fetched they run
  against the plaso files (5 passed, 0 skipped):
  - `test_automatic_destinations_parsing` — `1b4dd67f29cb1962…` (Windows 7, `DestList` v1):
    the carve contract on every artifact, then the eleven shortcut streams pinned by
    directory name with the offset of the seven that lie whole at their signature and
    `None` for the four scattered across the mini-sector chain;
  - `test_custom_destinations_parsing` — `c98dce577f884ef8…`, a 12-byte file holding no
    shortcut: exactly one record, `carve_complete: true` and `links_carved: 0`, so "nothing
    was in this jump list" cannot render like "this jump list was never read";
  - `test_custom_destinations_carves_the_shortcuts_it_contains` — `368d807282ccde9d…`:
    three MS-SHLLINK structures at offsets 64, 637 and 1226, and no status record because a
    complete carve of a readable file has nothing to disclose;
  - `test_jumplist_integration_with_lnk_parser` — `9d1f905ce5044aee…` (Windows 10, v3):
    the two shortcut streams handed on to `seance_plugin_lnk`;
  - `test_automatic_destinations_with_unreadable_directory_is_carved_and_says_so` — the
    Windows 7 file with its OLE sector-shift field corrupted: the directory-unreadable
    fallback, 11 carved shortcuts at the 11 signature offsets, `ole_directory_read=false`.
  The record set they hold the parser to is: shortcut `FileEntry`s,
  `jumplist_destlist_entry` records, timeline events, one `jumplist_destlist` summary,
  `jumplist_carve_status` on the fallback path only.
- The real-file grade of the `DestList` decode itself lives in
  `seance_plugin_jumplists/tests/real_jump_lists.rs`, which reads the same two automatic
  destinations files from `reference/plaso/test_data/automatic_destinations/`
  (`1b4dd67f29cb1962…`, 11 entries; `9d1f905ce5044aee…`, 2 entries) and pins entry numbers,
  offsets, paths, hosts and times to plaso's own checked-in expectations, skipping with a
  printed line when `reference/` is absent.

#### Shortcut Files (LNK)
- `example.lnk` - Standard Windows shortcut
- `NeroInfoTool.lnk` - Real-world example
- Used by: `seance_plugin_lnk` tests

#### SRUM Database
- `SRUDB.dat` - System Resource Usage Monitor database (~8MB)
- Used by: `seance_plugin_srum` tests

#### Event Logs
- `sample.evtx` - Windows Event Log file (~70KB)
- Used by: `seance_plugin_evtx` tests

### Browser Artifacts

#### Chrome History
- `test_data/chrome_history/History*` - Various Chrome versions
- SQLite databases with browsing history
- Used by: Browser history parser tests

#### Firefox History
- `test_data/firefox_history/places.sqlite`
- Firefox places database
- Used by: Browser history parser tests

### macOS Artifacts

#### Property Lists (plist)
- `com.apple.*.plist` - Various macOS preference files
- `Downloads.plist` - Safari downloads
- Used by: `seance_plugin_plist` tests

### Linux Artifacts

#### Ext4 Filesystem
- `ext4.raw` - Small Ext4 filesystem image (~4MB)
- `ext4_with_binaries.dd` - Ext4 with executables (~10MB)
- Used by: `seance_plugin_ext4` unit tests

### Container Formats

#### E01 Images
- `image.E01` - Small single-segment E01 (~4KB)
- `image-split.E01`, `image-split.E02` - Multi-segment example
- Used by: `seance_container_e01` tests

#### Virtual Disk Images
- `disk.raw` - Raw disk image (~10MB)
- `image.vmdk` - VMware virtual disk
- `image.vhd` - Hyper-V virtual disk
- Used by: Virtual disk parsing tests

#### Archives
- `syslog.zip` (root), `test_data/zip/ziptest.zip` - Test archives
- Used by: Archive extraction tests

### SQLite Databases

Various SQLite databases used for timeline and data extraction tests:
- `activity.sqlite` - Activity database
- `contacts2.db` - Contacts database
- Many application-specific databases

---

## The rest of the inventory

Every path below is referenced by code in this tree. The right column names the test that uses it —
which is also where its provenance and its expected answer are written down.

### Whole images with published or third-party answers

| Path | What it is | Used by |
|---|---|---|
| `dftt/1-extend-part/1-extend-part/ext-part-test-2.dd` | DFTT #1, extended DOS partitions | `seance_validate` case **DFTT-1**, and `seance_tests` |
| `dftt/9-fat-label/9-fat-label/9-fat-label.dd` | DFTT #9, FAT16 volume label `LABEL1` | `seance_validate` case **DFTT-9** |
| `dftt/5-fat-daylight/5-fat-daylight/daylight.dd` | DFTT #5, FAT12 daylight-savings timestamps | `seance_validate` case **DFTT-5** |
| `dftt/3-kwsrch-ntfs/…/ntfs-img-kw-1.dd` | DFTT #3, NTFS keyword search | `seance_tests`; `seance_plugin_yara` slack surface (`VALIDATION.md` SLACK-2) |
| `dftt/2-kwsrch-fat/2-kwsrch-fat/fat-img-kw.dd` | DFTT #2, FAT keyword search (keywords placed in, and across the edge of, file slack) | `seance_tests` slack regions (SLACK-1); `seance_plugin_yara` slack surface (SLACK-2) |
| `dftt/4-kwsrch-ext3/…/ext3-img-kw-1.dd` | DFTT #4, ext3 keyword search | `seance_tests` |
| `dftt/7-undel-ntfs/7-ntfs-undel.dd` | DFTT #7, NTFS undelete | `seance_tests` |
| `dftt/8-jpeg-search/8-jpeg-search/8-jpeg-search.dd` | DFTT #8, JPEG search over NTFS (image MD5 `9bdb9c76…46db5`, asserted): ten pictures allocated, deleted, in ZIP/`.boo`/`.tar.gz`, appended to data, in a Word file and in an ADS, plus three decoys | `seance_tests/src/dftt8_jpeg_search_tests.rs` — the product module set over the image, graded against `index.html`'s MD5s (`VALIDATION.md` **DFTT-8**) |
| `dftt/11-carve-fat/11-carve-fat/11-carve-fat.dd` | DFTT #11, FAT carving | `seance_tests` — byte-exact files pinned against `11-carve-fat.html`  |
| `dftt/12-carve-ext2/…/12-carve-ext2.dd` | DFTT #12, ext2 carving | `seance_tests` — all ten files graded against `12-carve-ext2.html` (`VALIDATION.md` **DFTT-12**) |
| `dftt/14-iso9660/14-iso9660-1/iso-dirtree1.iso` | DFTT #14, ISO9660 directory tree | `seance_tests` |
| `whatsapp_android14/` (a link into `~/forensic_corpora/hickman_android14/whatsapp`) | Seven stored members of Josh Hickman's Android 14 (Pixel 7a) `EXTRACTION_FFS.zip`, streamed out and each checked against its ZIP CRC-32 (`STAGING.log` beside them): `key` `eb2f85a4d4c59021d4b3843382f84a1dcc084892b58cb0d63eafdd949a6ab374`; `msgstore.db.crypt14` `543a65dd426e06e7f5037d1146d4449d134af411337abba3bee4fff5f664b89c`; `msgstore-2024-07-26.1.db.crypt14` `4f63185f70457ad9731f5f3626016a101309b8ef98c875d8ce171347a2b1bedc`; `wa.db.crypt14` `71ac45588e400dd5ab96b8d45bc198a2fe5347fc1c41f619e7c544f727e8b13e`; live `msgstore.db` `e83aed42f6fab3595c6f0b0141c4ab3ce7e0d10507af101dd0c266410663c3ba`, `-wal` `405015abea25c616df2aa5ca28114cc1437016cab210d2aca4c56195b9ea6e5a`, `-shm` `1ac9da2df5325d421c3a253ec8ae2582322528e51aee58ead902fbb78d0491b1` | `seance_plugin_whatsapp/tests/real_crypt14.rs` (`VALIDATION.md` **WHATSAPP-CRYPT14-1**) |
| `whatsapp_crypt15/` (a link into `~/forensic_corpora/wa_crypt15_2_26`; not vendored, GPL-3.0 evidence) | The `tests/res/` crypt15 backups of the public `wa-crypt-tools` project at commit `e2c0282b`, with their published root key (`PROVENANCE.md` there): `encrypted_backup.key` `fe73dc805204eb74537597b24643f43c602bf3d5c8d86300288530ecc2a4219d`; `msgstore.db.crypt15` `af383a886da97080d0545dfa992f5064b69b80a31a6034a5accd5437a62ac155`; `msgstore-2.26.db.crypt15` `a3ee46cab1fa457b9ebc14904fce1cf57a74359ed160ef6eb50784354305a89b`; `wa-2.26.db.crypt15` `919efb76a209d9a753b14a23767328d6454ee3d53d2d69293228bc32934baf12`; `msgstore-increment-2.26.crypt15` `592e7346fc1c3091d9493d3cf43d4d408fadead5c8b72d7b1aaca39cc1519196`; `stickers.backup.crypt15` `bad05ba3cb003ec8cc2caf54958871cb0eec4824530e796be901ede1195c9b5c`. The published plaintexts (`msgstore.db`, `test9.zip`) are in `~/forensic_corpora/wa_crypt_tools_vectors/res/` and their SHA-256 are asserted by the test | `seance_plugin_whatsapp/tests/real_crypt15.rs` (`VALIDATION.md` **WHATSAPP-CRYPT15-1**) |
| `canon2/canon2.raw`, `canon2/nps-2009-canon2-gen6.E01` | Digital Corpora `nps-2009-canon2` scenario image | `seance_tests/src/canon2_pipeline_tests.rs` — the raw image's MD5 is asserted before anything else, and ≥30 carved JPEGs are expected (PhotoRec finds 39) |
| `full_image/001.E01` + `001.E02…` | ~35 GB, 18 segments, Linux ext4 | `seance_tests` ext4 full-chain |
| `syslog_image.dd` | Small disk image with a syslog | `seance_tests/src/golden_image_tests.rs` |

**Obtaining DFTT:** <https://sourceforge.net/projects/dftt/files/Test%20Images/>.
Keep the archives' own nested directory layout — the paths above are doubled
(`dftt/1-extend-part/1-extend-part/…`) because that is how the archives unpack,
and `seance_validate` resolves them literally.

As with `win11_bitlocker/` below, `seance-validate` resolves the three DFTT
cases under its **`--corpus` root**, not under `test_data/`
(`seance_validate/src/cases.rs`, `image_rel: "dftt/…"`). The `seance_tests`
readers do look under `test_data/dftt/`, so a machine holding the corpus
elsewhere symlinks it in (`ln -s ~/forensic_corpora/dftt test_data/dftt`;
`/test_data/` is gitignored, so the link is never committed). Absent, the
validate cases report *Skipped (image absent)* and the tests skip — neither is a
pass.

**Obtaining canon2:** Digital Corpora's `nps-2009-canon2` set.

### Volume Shadow Copy

| Path | What it is | Used by |
|---|---|---|
| `vss_1_vol.tar.gz` → extract to `vss_extracted/vss_1_vol.raw` | dfir_ntfs corpus GPT disk whose NTFS volume carries **exactly two** shadow copies | `seance_tests/src/vss_tests.rs` |
| `vss_1_vol_bm.bin` | The matching bitmap | `seance_tests/src/vss_tests.rs` |
| `vss_2003.raw`, `vss_2003.tgz` | Server 2003-era VSS | `seance_tests` |

The extraction step is manual — the test prints
*"Note: This test requires extracting test_data/vss_1_vol.tar.gz"* and skips.

### APFS

| Path | What it is | Used by |
|---|---|---|
| `apfs.dmg` | GPT raw image; the APFS container begins at byte 20480 | `seance_plugin_apfs` — real-volume regression |
| `apfs_encrypted.dmg` | An encrypted APFS volume | `seance_plugin_apfs` (graceful handling) and `seance_api` (`is_apple_encrypted_dmg`) |
| `apfs_compressed.dmg` | Holds a 4,200,000-byte `decmpfs` file in ~36 KB | `seance_api/src/content_resolver.rs` |

### More Windows artifacts

| Path | Used by |
|---|---|
| `winreg/Amcache.hve`, `winreg/win10-Amcache.hve` | `seance_plugin_amcache` |
| `NTUSER-WIN7.DAT`, `UsrClass.dat` | Registry / ShellBags |
| `WebCacheV01.dat` | `seance_plugin_webcache` (its **only** end-to-end fixture: `parses_real_webcache_fixture_when_present` and `the_real_fixtures_containers_and_tables_agree_exactly`), `seance_plugin_srum` (`a_foreign_ese_database_is_not_reported_as_a_srum_database`) and `seance_ese_util` — an ESE database, the same family as `SRUDB.dat` and `Windows.edb`. **Not committed**: name it with `SEANCE_WEBCACHE` and all three tests run; leave it unset and all three skip, loudly |
| `System.evtx`, `System2.evtx`, `*.evtx` | `seance_plugin_evtx` |
| `sample.pf` | `seance_plugin_prefetch` |
| `sample.lnk`, `example.lnk`, `NeroInfoTool.lnk` | `seance_plugin_lnk` |
| `LogFile_7.bin`, `LogFile_10.bin`, `LogFile_10_large.bin`, `LogFile_empty.bin` | `seance_tests/src/logfile_tests.rs` — Windows 7 and Windows 10 `$LogFile` layouts, plus the empty case. `LogFile_10.bin` has a known answer: **124 significant journal records** |
| `sample_badclus.bin` | `seance_plugin_badclus` |
| `recycler/INFO2` | `seance_plugin_recyclebin` — the XP-era `INFO2`, distinct from the `$I`/`$R` pairs |
| `srudb.DAT` | `seance_plugin_srum` (note the case; `SRUDB.dat` is also referenced) |

### More filesystem and container samples

| Path | Used by |
|---|---|
| `fat12_full_test.txt` | `seance_plugin_fat` — the **expected path list** for the FAT12 image, not an image itself |
| `ext4_with_binaries.dd` | `seance_plugin_ext4` |
| `disk.raw`, `image.vmdk`, `image.vhd` | Virtual disk readers |
| `ARCHIVE.ZIP`, `zip/ziptest.zip`, `syslog.zip` | `seance_container_zip` |

### More application databases

| Path | Used by |
|---|---|
| `EnMicroMsg_encrypted.db` | `seance_plugin_wechat` — needs `SEANCE_WECHAT_IMEI` and `SEANCE_WECHAT_UIN` to derive the key |
| `activity.sqlite`, `contacts2.db` | Timeline / contacts extraction |
| `Downloads.plist`, `com.apple.SoftwareUpdate.plist`, `com.apple.networkextension.uuidcache.plist`, `sample.plist` | `seance_plugin_plist` |
| `ios_backup_fixtures/mbdb_basic/`, `ios_backup_fixtures/sqlite_basic/` | `seance_plugin_ios_backup` — **the only samples actually committed**, covering both the legacy `Manifest.mbdb`/`.mbdx` and the modern `Manifest.db` backup layouts |

### `app_schema_corpus/` — the schema-drift corpus (`ROADMAP` §1.4a)

**Not committed** (this directory is under the `test_data/` ignore rule) and **not gated
through the corpus helper**: `seance_plugin_android_sms`, `seance_plugin_call_history`,
`seance_plugin_imessage` and `seance_plugin_twitter` default to `test_data/app_schema_corpus/`
when `SEANCE_APP_SCHEMA_CORPUS` is unset and test each file with a bare `exists()`, so an
absent file **passes** unless `SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1` is set (`TESTING.md`). The
files the `real_*` tests ask for, each a byte-for-byte copy renamed to say where it came from,
with its `-wal` sibling beside it where the source had one (the parsers stage the main file;
the sibling is kept so a checkpointing tool does not change the evidence).
The Magnet Android 2022, Magnet Android 2019 and Magnet macOS 2021 sets these files were
extracted from are not held. Download them again from their public sources before the
samples can be rebuilt:

| File here | Source | What the test asserts |
|---|---|---|
| `android2022_mmssms.db` | the Magnet 2022 Android CTF `android.tar`, member `data/data/com.android.providers.telephony/databases/mmssms.db` (Magnet 2022 CTF, Pixel 3) | `user_version` 67, 11 SMS rows, every column resolved, no `ParserStaleWarning` |
| `android2022_calllog.db` | the same tar, `data/data/com.android.providers.contacts/databases/calllog.db` | `user_version` 5, 0 rows in the main file |
| `magnet2019_contacts2.db` (+ `-wal`) | the Magnet 2019 Android CTF, `Agent Data/contacts2.db` | `user_version` 1, `calls` keyed `id` (not `_id`), 3 calls |
| `ios2022_CallHistory.storedata` (+ `-wal`) | the Magnet 2022 iOS FFS zip member `/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata` | Core Data, `user_version` 0 (read as "not recorded"), 26 `ZCALLRECORD` columns |
| `ios2022_sms.db` (+ `-wal`) | the same zip, `/private/var/mobile/Library/SMS/sms.db` | `_ClientVersion` 15009, 13 messages |
| `macos2021_chat.db` (+ `-wal`) | the Magnet 2021 macOS CTF tree, `Users/eliflatt/Library/Messages/chat.db` | `_ClientVersion` 14005, 0 messages in the main file |
| `android2022_tw_0-61.db`, `android2022_tw_1489429766507835392-61.db` (+ `-wal`) | the android tar, `data/data/com.twitter.android/databases/` | `user_version` 59; `users` 0 / 401 rows; `search_queries` 0 / 2 (the 2 real searches are **not** extracted — open in `BUGS.md`) |

The plaso halves of the same comparisons (`mmssms.db` at `user_version` 57, `contacts2.db`
at 0, `imessage_chat.db` at `_ClientVersion` 9005, `twitter_android.db` at 7) are read from
`reference/plaso/test_data/` directly. Extraction, once the sets are downloaded: `tar -xf android.tar <member>`
and `unzip <ios zip> '/private/var/mobile/Library/SMS/sms.db'` (the zip's entries carry a
leading slash). Every other fixture in those five suites is synthesised from the column sets
of these files; no real Facebook Messenger store and no real Twitter `<uid>-search.db` is held, so those two parsers' ranges are undeclared and their fixtures
are written from the same description they implement.

### Fixture sets that live beside their crate, not here

Real-file sets sit under a crate's own `tests/fixtures/`, which the root
`.gitignore` un-ignores (`!**/tests/fixtures/**/*.db`, `*.sqlite`, and their `-wal` siblings). They are listed here because someone looking for real samples looks here first;
each directory's own `README.md` is the provenance record and this file does not restate it.

- **`seance_plugin_ios_artifacts/tests/fixtures/magnet2022_ios15/`** — not committed; 17 files,
  10,575,932 bytes, byte-for-byte from the Magnet User Summit 2022 CTF iPhone 8 GrayKey
  full-file-system extraction (iOS 15.0, build 19A404): Safari `Bookmarks.db`,
  `SafariTabs.db`, `BrowserState.db`, `com.apple.mobilesafari.plist`, HealthKit
  `healthdb_secure.sqlite` and `healthdb.sqlite`, `NoteStore.sqlite`, and both
  `Photos.sqlite` libraries, each with its `-wal`. The README carries the device path and
  SHA-256 of every file. It is the iOS known-answer set for the native parsers
  (`tests/magnet2022_ios15_test.rs`: 6 bookmarks / 4 folders; 3 tabs, 1 private; 3 recent
  searches; 688 health samples; 2 notes; 41 albums). Two things the README says that matter
  to anyone touching it: **never open one of these in place with `sqlite3`** (opening a
  WAL-mode database checkpoints it and deletes the `-wal`, and the fixture becomes a
  different file — copy first); and on this device **the WAL adds no rows to Health or
  Notes**, so WAL staging is pinned by `BrowserState.db` alone, whose two windows are
  reachable only through its 24,752-byte `-wal`. A test whose fixture is absent prints one
  `SKIPPED (no fixture):` line and returns.
- **`seance_plugin_asep/tests/fixtures/wmi/`** — two page-subset copies of real
  `OBJECTS.DATA` files (Lone Wolf, Windows 10: pages 0, 1, 112, 130, 140, 143, 148, 1316,
  2645; CFReDS Hacking Case, Windows XP: pages 0, 9, 58, 254, 328, 357), cut by
  `make_fixtures.py` and described page by page in `MANIFEST.json` with the source and
  fixture SHA-256. Every byte inside a kept page is as Windows wrote it; only the choice of
  pages is editing. The XP set deliberately leaves out page 359, where the second binding's
  consumer instance sits, so the "consumer not found" path is exercised on real bytes. The
  whole files are reached by `SEANCE_LONEWOLF_OBJECTS_DATA` / `SEANCE_CFREDS_OBJECTS_DATA`
  (`TESTING.md`).

- **`seance_plugin_bits/tests/fixtures/qmgr/`** — the first 8,192 bytes
  of the NIST CFReDS Data Leakage PC's `qmgr0.dat` and `qmgr1.dat` (MFT entries 15553 and
  15554, Windows 7), unedited; every byte past the cut is zero on the image, which
  `make_fixtures.py` checks before cutting. `MANIFEST.json` carries the source and fixture
  SHA-256. The BITS known-answer files: one live job in `qmgr1.dat`, none in `qmgr0.dat`, and
  the Outlook offline-address-book transfers in both files' stale regions. The whole files
  are reached by `SEANCE_CFREDS_QMGR_DIR`; DFIR Madness DC01's empty Server 2012 R2 queue by
  `SEANCE_DC01_QMGR` (not committed — no redistribution grant).
- **`seance_plugin_bits/tests/fixtures/qmgr_db/`** — Lone Wolf's whole
  Windows 10 `qmgr.db` (MFT entry 92620, 1,310,720 bytes, unedited; dirty shutdown, `Jobs` and
  `Files` empty as libesedb reads them) and a 1,024-byte slice of its `edb00001.log` holding a
  `Jobs` record image. SHA-256s in the directory's README. Pins the dirty-database disclosure,
  the unreferenced-page byte scan and the blob decoders on real bytes.
- **`seance_plugin_winsearch_edb/tests/fixtures/`** — five
  `System_Search_AutoSummary` values exactly as libesedb returns them from the NIST CFReDS
  Data Leakage PC's `Windows.edb` (walk rows 2, 24, 388, 391, 453): two decodable forms (8-bit,
  runs with U+2019) and the two compressed forms that must be named, not rendered. SHA-256s in
  the directory's README. The whole databases are reached by `SEANCE_CFREDS_WINDOWS_EDB` and
  `SEANCE_LONEWOLF_WINDOWS_EDB`.
- **`seance_plugin_winsearch_edb/tests/fixtures/ese_other/`** — Lone
  Wolf's SettingSync `remotemetastore/v1/meta.edb` (MFT entry 130219, 1,441,792 bytes,
  unedited, SHA-256 `a2341594…67af`): a real ESE database that is neither a Search index nor
  a BITS queue. The collision guard of both `seance_plugin_winsearch_edb` and
  `seance_plugin_bits` runs on it (and the Search guard on the BITS `qmgr.db` too), so the
  guard no longer depends on the uncommitted plaso `reference/` copies.
- **RDP bitmap cache** — no fixture is committed: the only real `Cache0000.bin`
  held is DFIR Madness DC01's, whose terms grant no redistribution. `seance_plugin_rdp_cache`'s
  committed tests are synthetic and pin header, bounds and emission handling only; the real
  file is reached through `SEANCE_DC01_RDP_CACHE` (`TESTING.md`).

- **`seance_plugin_email/tests/fixtures/ost_v36/`** — the NIST CFReDS
  Data Leakage suspect's Outlook 2013 OST, `iaman.informant@nist.gov.ost` (MFT entry 46112),
  cut at its NTFS initialised length: the first 3,360,768 of 16,818,176 bytes, every byte past
  the cut being zero on the image. Unedited. It is the format-version-36 known-answer file for
  `tests/ost4k_real_test.rs` (351 nodes, 381 blocks, 14 messages; the eleven of NIST's
  question 21 that are in the store). Its README carries the extraction command, both hashes
  and the answer-key rows. Not under a `*.db`/`*.sqlite` rule, so no un-ignore is needed; its
  absence is a test **failure**, not a skip, because it is tracked.

### Samples reached by environment variable instead of by path

These are *not* `test_data/` paths at all. They are listed here because someone
provisioning test data will look for them here first:
`SEANCE_BROWSER_SAMPLES`, `SEANCE_IOS_SAMPLES`, `SEANCE_THUMBCACHE_SAMPLES`,
`SEANCE_WIN_TIMELINE_SAMPLES`, `SEANCE_DSSTORE_SAMPLE`, `SEANCE_PE_SAMPLE`,
`SEANCE_HEVC_MOV`, `SEANCE_DEFERRED_IMAGES`, `SEANCE_PST14_CORPUS` (the NPS M57-Jean Outlook
mailbox, a version 14 PST, kept at `test_data/pst_old/m57_jean_outlook.pst`; its provenance and the
libpff oracle are under `seance_plugin_email/tests/fixtures/pst_old/`), and the memory corpora. Every one
is documented in `documentation/TESTING.md`, which is the file that owns them.

---

## Required Test Data for P0 Tests

The following test data files are **required** for P0 (critical) tests to pass:

1. **Database & API Tests** - No external files required (use in-memory databases)
2. **Plugin Unit Tests** - Embedded small test fixtures in source code
3. **Integration Tests** - Optional; tests gracefully skip if files missing

## Optional Test Data

Most test files in this directory are optional. Tests are designed to:
- Skip gracefully if files are missing
- Log what was skipped
- Not fail CI/CD if optional data is absent

## Generating Test Data

### For Plugin Development

When developing new plugins, you can:
1. Extract small samples from real forensic images
2. Create synthetic test files using hex editors
3. Use embedded byte arrays in test code for small fixtures

### For Integration Tests

Large forensic images (like `full_image/001.E01`) should be:
- Downloaded from forensic test image repositories
- Generated from test VMs
- Stored separately from the repository (too large for Git)

## Test Data Guidelines

1. **Size Limits**. Note that `/test_data/` is gitignored, so "commit to repo"
   means a deliberate `git add -f` and a decision to carry the bytes forever:
   - Embedded fixtures: < 4KB — **prefer this**; a byte array in the test is
     always present, never skips, and its provenance sits next to it
   - Small files: < 1MB — `git add -f` only if the fixture cannot be built by a
     script and cannot be embedded
   - Medium files: 1-10MB — do not commit; document how to obtain or build it
   - Large files: > 10MB — external storage or a generator script; tests skip if
     missing, and that skip is only honest if this file says how to get it

   **A generated fixture beats an obtained one.** `scripts/build_golden_images.sh`
   builds a real multi-partition E01 rootlessly from a declared layout, so its
   ground truth is the script — readable, auditable, reproducible anywhere, and
   never checked against Séance's own prior output. Prefer that shape.

2. **Privacy**:
   - Never include real user data
   - Sanitize or synthesize all test data
   - Use fake names, paths, timestamps

3. **Licensing**:
   - Ensure test data can be legally redistributed
   - Document source of any third-party test files
   - Prefer synthetic or generated test data

## CI/CD Considerations

GitHub Actions CI does **not** have access to large test files (like `full_image/`). Tests that require these files will:
- Detect missing files
- Print skip message
- Return Ok(()) to pass

This allows development with full test data locally while keeping CI fast and lightweight.

## Adding New Test Data

When adding new test data:
1. Place files in appropriate subdirectory
2. Document the file in this README
3. Update test code to handle missing files gracefully
4. If > 10MB, document how to obtain the file

## Questions?

See `documentation/TESTING.md` for testing strategy and coverage goals.

## Windows 11 BitLocker corpus (`win11_bitlocker/`)

A Windows 11 25H2 Enterprise Evaluation install (build 26200) encrypted with
**XTS-AES-256**, built specifically because the only other BitLocker sample in
this tree, `bdetogo.raw`, is a 2007-era AES-CBC + Elephant diffuser To-Go volume
on FAT. Everything Windows has written since 2015 is AES-XTS on a GPT system
volume, and that path had no real-image evidence behind it at all.

| File | What it is |
|---|---|
| `win11-bitlocker-xts256.raw` | 64 GiB disk, fully encrypted. Sparse — about 20 GiB allocated |
| `win11-bitlocker-xts256.E01` | the same acquisition as EnCase E01, 11 segments |
| `partial-encrypted.raw` | the same machine imaged at **56% converted** |
| `memory-unlocked.raw` | 10 GiB guest RAM, captured while the volume was unlocked |
| `symbols/ntkrnlmp.pdb/` | the ISF for this exact kernel build |

**Recovery password** — the only way into the image, since the TPM protector
seals the VMK inside emulated TPM state that is not part of the disk:

    633281-498102-426096-319726-225203-245927-337876-444884

The BitLocker partition starts at byte **407,896,064** and is 61.52 GiB.

### Ground truth

`C:\seance-manifest.json` inside the image records every planted artifact with
its SHA-256. Planted deliberately before encryption: user documents, a real
JPEG and PNG, a Chromium `History` database from Edge genuinely fetching pages,
`RunMRU`/`TypedPaths` registry values, Prefetch entries, a scheduled task and a
`Run` key.

Two deletions, because they leave different traces: one file sent to the Recycle
Bin (recoverable, as its `$I`/`$R` pair — Windows does not keep the original
name), and one deleted permanently. **The permanently deleted body is genuinely
gone** — the virtual disk was TRIM-capable, and scanning the whole decrypted
volume for text unique to that file returns zero hits. Live files and Recycle
Bin contents are recoverable; permanently deleted bodies are not. If you need
guaranteed carving targets in unallocated space, rebuild with `discard=off` and
TRIM disabled in the guest.

### Symbols

The ISF is generated from Microsoft's own PDB for this kernel:

    curl -o ntkrnlmp.pdb https://msdl.microsoft.com/download/symbols/\
      ntkrnlmp.pdb/E6426A07C26E66F8EB8594621A7B273B1/ntkrnlmp.pdb
    python3 -m volatility3.framework.symbols.windows.pdbconv \
      -f ntkrnlmp.pdb -o E6426A07C26E66F8EB8594621A7B273B-1.json

`tcpip.sys` symbols **are** provisioned
(`900CF8F7561880DF85314A7B161495F8-1`, obtained the same way after reading the
driver's CodeView record out of the capture itself), and the network stage still
cannot run. That is not a provisioning gap:

| source | symbols | types |
|---|---|---|
| Microsoft's public `tcpip.pdb` | 10,376 | **0** |
| Volatility's bundled `tcpip.pdb` ISF | 9,329 | **0** |

Microsoft publishes tcpip.pdb as a *public* PDB, which carries function and
global names and no structure layouts, for every build. Volatility works around
this with hand-authored netscan definitions per Windows version — and its
newest, `netscan-win10-20348-x64.json`, stops thousands of builds short of the
26200 here. The `_TCP_ENDPOINT` layout this stage needs is not published by
anyone; closing it means deriving it from the binary. The ISF ships anyway so
nobody repeats the attempt to find out.

### Running the tests

    cargo test --release -p seance_plugin_bitlocker
    cargo test --release -p seance_plugin_memory_windows
    cargo test --release -p seance_tests --lib bitlocker_win11_chain

`--release` is not optional in practice: decrypting 61 GiB unoptimised takes
long enough that nobody would run the suite. But **the two crates behave
differently in a debug build**:

| Crate | Debug build |
|---|---|
| `seance_plugin_memory_windows` (`tests/win11_corpus_analysis.rs`) | Every corpus test carries `#[cfg_attr(debug_assertions, ignore = "slow in an unoptimised build; run with --release")]`, so it reports as **ignored** — never as a pass over nothing |
| `seance_plugin_bitlocker` (`tests/win11_xts256_corpus_test.rs`) | **Not** `#[ignore]`d. The eight corpus tests run, and they run slowly |

### This corpus also backs two `seance_validate` cases

`BL-1` (BitLocker XTS-AES-256 unlocks and decrypts to NTFS) and `MEM-2` (the
Windows 11 26200 kernel identity, checked against Microsoft's own PDB) both read
from `win11_bitlocker/`. `seance-validate` resolves them under its **`--corpus`
root**, not under `test_data/`, so copy or symlink this directory into the corpus
root before running it — otherwise both cases report *Skipped (image absent)*,
which is correct and is not a pass. See `documentation/VALIDATION.md`.

`memory-unlocked.raw` is also the image behind the `SEANCE_WIN11_MEMORY`
known-answer section of `seance_memory/tests/KNOWN_ANSWERS.md`.

## `bdetogo.raw`

The Vista/Windows 7-era BitLocker To Go volume, 64 MiB, from the
[plaso](https://github.com/log2timeline/plaso) project's `test_data`. Password
`bde-TEST`.

    sha256  ed7982a1f9263e4e54889fea1fa74112d12fea0a0aa7cd8f84fc6f03198ae71b

Its VBR carries the BitLocker GUID at **`0x1a8`** — the older of the two
layouts — which is what makes it the counterpart to the Windows 11 corpus and
the reason both layouts have to be tried. Its known-answer test asserts the
exact recovered FVEK, so it fails loudly if the key hierarchy drifts.

## `sdb_samples/` — Windows shim databases (`ROADMAP` §1.7)

**Not committed.** These are Microsoft-copyrighted binaries and this repository
is MIT throughout. This section is the recipe; the directory is what you put
there. Gate: `SEANCE_SDB_SAMPLES`, pointing at the directory. Unset skips the
tests; set to a missing path panics, because a pass there would report a
comparison that never ran.

Source: Windows 11 Professional ARM64 EN-US build 28000.1,
`28000.1_PROFESSIONAL_ARM64_EN-US.ISO` (4,972,339,200 bytes), extracted so that
`sources/boot.wim` and `sources/install.wim` are reachable.

```sh
mkdir -p test_data/sdb_samples && cd test_data/sdb_samples
cp <iso>/sources/appraiser.sdb .
7z e -y <iso>/sources/boot.wim "1/Windows/apppatch/drvmain.sdb"
7z e -y <iso>/sources/install.wim \
  "Windows/apppatch/sysmain.sdb" "Windows/apppatch/frxmain.sdb" \
  "Windows/apppatch/pcamain.sdb" "Windows/apppatch/msimain.sdb" \
  "Windows/apppatch/shellFeatureInbox.sdb"
```

The `install.wim` listing pass takes several minutes. Verify what you staged —
the golden counts in `seance_plugin_sdb/src/tests.rs` are keyed to these exact
bytes:

```text
3196208a08d5c70f5bb85b55d8c1e3418587385d6376b72711eb80762d0bd4d1  appraiser.sdb (compressed, as shipped)
e61b9af11f48d2d2ca749065542c7abd1d56cb6813087a4a9ee9cc7ae530581c  appraiser, inflated (9,734,396 bytes)
dab84be63aebb005a37941fbb45490edf69ab3dc935f00920a6ddc15ba909913  drvmain.sdb
b4445f2d802f01af254df9fd82e16af293185d75c57f8569ed96ca4c4b2f1082  frxmain.sdb
f7c2cd2cd1cc8bbedd58acb6c9102d7d744eb1e9a0d72fba6dab457c534638e5  msimain.sdb
1b931c05240110ac111031b4db5396806ce10d8c8f9d10e814f82884c89a0d4f  pcamain.sdb
200735f3447e37eb3f208b4ba9992557b8a58c1d9832b1ac90aece5e5a5a56ec  shellFeatureInbox.sdb
2517ff31d34e32a629b8c9c568d1f9834ae7bbcd11c6b9d969423519c3f145c3  sysmain.sdb
```

A different Windows build gives different bytes and different counts. If you
stage from another ISO, the census tests will fail — and they should: they are
golden tests against these files, not against the format in the abstract.
