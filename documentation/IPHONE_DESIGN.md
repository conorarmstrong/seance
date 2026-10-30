# iPhone (iOS) Forensics Extension Design

**Target:** iOS Devices (iPhone, iPad)
**Architecture:** Modular Seance Plugins (implementing `ForensicsModule`)
**Status:** Partially Implemented. Shipped and registered in `seance_api::modules`: iTunes/Finder backups, iMessage/SMS, WhatsApp, contacts, call history, the device databases in `seance_plugin_ios_artifacts` (voicemail, calendar, notes **with bodies, folders and deletion state**, photos **with albums**, Voice Memos, voicemail audio and transcripts, notes attachments, PowerLog, significant locations from `Cache.sqlite` (the cached-locations reader), **Safari bookmarks, open tabs and recent searches, and HealthKit samples with workouts and sleep**), the installed-application inventory (`seance_plugin_installed_apps`, which reads iOS `applicationState.db` as well as the Android inventories), and **knowledgeC/CoreDuet** — `seance_plugin_macos_artifacts::KnowledgeCParser` selects on the database itself rather than on a macOS path, and iOS carries the same file. Design-only: Screen Time, biometrics, Wallet, the cell database (`CellLocation.db`), MVT-style malware checks, Telegram. The Signal iOS store is reported as encrypted and, once its key spec is supplied for it, decrypted and read — graded structurally, on a real store with no messages.

KnowledgeC/CoreDuet is covered by the shared parser.

This document outlines the architecture for extending Seance with comprehensive iOS forensics capabilities, targeting parity with Cellebrite UFED Physical Analyzer and Magnet AXIOM.

---

## 1. Acquisition & Container Support

### `seance_plugin_ios_backup`
**Responsibility:** Parsing standard iTunes/Finder backups (Unencrypted & Encrypted).
- **Subscribes To:** `ArtifactType::RawEvidence` (Folder containing `Manifest.db`)
- **Input Capability:** `InputCapability::RandomAccess`
- **Output:** `ArtifactType::FileEntry` (Virtual mapping)
- **Features:**
    - **Manifest Parsing:** Parse `Manifest.db` to map hashed filenames to real paths. A `fileID` is joined onto the backup directory only when it is a bare alphanumeric name (a hex SHA-1); one that names a path — relative, absolute or non-ASCII — is refused and the entry is listed without content and with the reason.
    - **Decryption:** Support for AES-256 decryption using the Backup Password (Keybag parsing). The password reaches the parser two ways: an examiner supplies it for the locked backup with `POST …/artifacts/{folder}/credential`, kind `ios_backup_password` (the artifact page's unlock field, the attention queue and the REPL's `/unlock` all use it), or the CLI's process-level `--ios-backup-password` for a whole run; the per-run credential wins. The credential is held zeroed for the one run, never merged into metadata, and the parser reports what it did — **accepted** once the password unwraps at least one passcode-wrapped class key, **rejected** when the RFC 3394 integrity check fails (in its own words, never the password, and naming a corrupt wrapped key as the other cause, because the check cannot tell the two apart), no verdict (`not_used`) for a keybag with no passcode-wrapped key, and a module error for a wrapped key that is not a valid RFC 3394 length — so the audit log records the outcome and a rejected run records nothing. A password left in artifact metadata is not read. Pinned on a synthetic encrypted backup built with the parser's own key derivation (`seance_plugin_ios_backup::test_support`): that pins the channel, not decryption against a real device's backup. **Reading the files again after ingest:** the password and every derived key are gone when the run ends, and the only bytes on disk are ciphertext, so stream, hex, export and re-hash of an encrypted backup's files are refused afterwards, the refusal naming `POST …/artifacts/{id}/unlock`. That route (kind `ios_backup_password`; the Inspector's *Unlock to read*) re-derives the class keys through `seance_plugin_ios_backup::unlock_backup` — the same keybag, unwrap and `Manifest.db` code ingest uses — and the API holds the resulting `UnlockedBackup` (class keys zeroed on drop, redacted `Debug`, not `Clone`/`Serialize`) in a process-memory keyring for that one case, 8 hours by default (`SEANCE_UNLOCK_TTL_SECS`); `UnlockedBackup::open_file` then opens each file to its plaintext through the ingest AES path. `DELETE` on the route, the TTL, deleting the case and a restart forget the keys; each unlock, outcome and lock is audited by kind. Pinned on the same synthetic backup: the re-read bytes and their SHA-256 equal what ingest produced — the mechanism, not validation against a real device's backup (none with a known password is held).
    - **Domain Mapping:** Group files by AppDomain (`AppDomain-com.facebook.Facebook`).

#### The backup found inside another exhibit — `resident.rs`
**Responsibility:** The phone backed up to a laptop that was then imaged.
- **Subscribes To:** `ArtifactType::FileEntry` / `FileContent` — a `Manifest.plist`,
  `Info.plist` or `Manifest.db` whose folder is named for a device UDID (40 hex characters, or
  the newer `00008030-001259123E50802E` form)
- **Input Capability:** `InputCapability::RandomAccess` (the bytes the case already holds)
- **Output:** `ParsedRecord` of type `IosBackupInfo` (from the property lists, and a
  `manifest_db_in_evidence` summary from `Manifest.db`); one `FileEntry` of type
  `IosBackupFile` per file the `Manifest.db` names, under its device path
- **Why it exists:** the parser above has `InputCapability::FilePath` and opens the backup as a
  directory on the examiner's own filesystem. A backup inside a disk image has no such
  directory, so the commonest way a phone's contents reach a laptop produced no record at all —
  not the device, not the date, not the fact that a phone had been backed up to that machine.
- **What it reads:** device name, model, iOS version, build, serial, UDID, IMEI (only
  `Info.plist` carries it), backup date and the encryption flag. An encrypted backup still names
  its device: the manifest is readable without the password.
- **The file inventory:** the mapping from hashed blob to device path is the
  backup's own `Manifest.db`. When that file is met, every `Files` row is re-emitted as a
  `FileEntry` named by its device path (`<backup>/<domain>/<relativePath>`), with the stored
  blob beside the manifest (`xx/<fileID>`, or flat for older backups) attached as its bytes
  through `DataSource::open_relative` — so `sms.db` is findable as `sms.db`, and the parsers
  that key on that name run over it. The summary record counts what was re-parented, what the
  manifest lists that the evidence does not hold (marked absent, "not evidence the file was
  empty"), directories, symlinks and ciphertext entries.
- **Bounds, each stated on the record:** a source that cannot open its neighbours — today a file
  inside a disk-image filesystem, as opposed to a host directory or a ZIP entry — yields the
  entries with no bytes and `content_omitted: source_cannot_open_neighbours`, and the summary
  says so rather than reporting every file missing. An **encrypted** backup's blobs are
  ciphertext: each entry is placed at its device path with size and dates and no content,
  because reading them needs the keybag and a password this reader does not have. A
  `Manifest.db` over 1 GiB is refused with `cap_reached`. The property-list record still
  carries `inventory_incomplete`, because it holds no inventory: it points at the
  `manifest_db_in_evidence` record for the same `backup_path`.

**Source-kind label (ROADMAP §1.4).** `GET /cases/{id}/source_kinds`
labels a source that holds an `IosBackupInfo` record `ios_backup` — containment,
not identity: a Mac holding an iPhone backup is an `ios_backup` source, never an
`ios_device` one. `ios_device` rests on `PowerLogSummary` and
`CachedLocationSummary` only where the store sat at its iOS path
(`var/containers/Shared/SystemGroup/…`, `var/mobile/…`), because a Mac keeps
PowerLog and routined too; `PhotoAsset`, `iMessage` and `applicationState.db` are
not markers, since all three fire on a real macOS case. `IosBackupFile` records
(one per backed-up file) are not listed. An `IosArtifactParseStatus` under a
source stops it from being called free of mobile evidence; that rescue is pinned
on fixtures only. So does an `IosBackupInfo` (or any other marker) anywhere in the
case whose parent walk could not reach a root: it may be any source's, so no
source is `none_recognised` while one is outstanding (fixture-pinned).

### `seance_plugin_ios_full_fs`
**Responsibility:** Processing Full File System (FFS) extractions (e.g., Checkm8, GrayKey).
- **Subscribes To:** `ArtifactType::RawEvidence` (Zip/Tar/Folder of root FS)
- **Output:** `ArtifactType::FileEntry`
- **Features:**
    - **Keychain Parsing:** Extract generic and internet passwords from `keychain-2.db` (requires system key). **The reader for this file format already exists** — `seance_plugin_macos_artifacts::DataProtectionKeychainParser` (`macos.keychain_data_protection`), written for the copy macOS keeps, which is the same schema. What it does **not** do is decrypt: each item's payload is wrapped under a class key from the device keybag. So the iOS work is the class-key unwrapping, not a second reader. Read that module before starting, and note what it establishes about this format: every `acct`, `svce` and `srvr` value in it is a **SHA-1** of the attribute, so the file names neither the account nor the service even once the payload is open. **A backup is different:** an encrypted iTunes/Finder backup does not carry `keychain-2.db` at all but `KeychainDomain/keychain-backup.plist`, whose items are wrapped under the *backup* keybag's class keys and whose decrypted attributes are **cleartext** (614 of 616 accounts on the Hickman iOS 17 backup are UTF-8). That file is read by `seance_plugin_ios_backup` — see *Keychain in an encrypted backup* below.
    - **System Partition:** Analyze `/private/var` and `/private/etc`.

---

## Cached locations (`com.apple.routined`) — **shipped**

`seance_plugin_ios_artifacts::RoutinedLocationParser` reads
`private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite`, table
`ZRTCLLOCATIONMO`: every fix CoreLocation recorded, with its timestamp (Core Data epoch,
sub-second precision kept), horizontal and vertical accuracy, altitude, speed and course.

It answers the question asked of a phone more often than any other — *where was this device, and
when* — and it survives app deletions and history clearing, because nothing about it belongs to
an app. The records carry `gps_lat` / `gps_lon`, so they reach the Map screen with no further
work.

Two of CoreLocation's conventions are honoured rather than copied through:

- a **negative horizontal accuracy** is how CoreLocation marks a fix invalid. Such rows usually
  carry `0,0`; drawing them would put the phone in the Gulf of Guinea, so they are counted on
  the summary record and left off the map.
- **-1 speed and -1 course** mean *not measured*. They are absent from the record rather than
  reported as a phone travelling backwards at one metre per second.

A `CachedLocationSummary` states how many fixes were read, how many were invalid, how many rows
would not decode, and whether the cap stopped the walk. `Cache.sqlite` is a name many apps use,
so a readable one without `ZRTCLLOCATIONMO` is not claimed; but one at the `com.apple.routined`
path whose catalogue will not read is the location history unread, and says so
(`DatabaseUnreadable`).

### What the older readers say when they cannot look

The voicemail, calendar, notes, photos, `routined` and PowerLog readers tell three answers
apart that would otherwise render alike as "no records":

- **an expected table absent from a readable catalogue** — a `voicemail.db` with no
  `voicemail`, a `Calendar.sqlitedb` with no `CalendarItem`, a notes store with no
  `ZICCLOUDSYNCINGOBJECT` (the pre-iOS 9 `ZNOTE` layout), a `Photos.sqlite` with neither
  `ZGENERICASSET` nor `ZASSET` — is one `IosArtifactParseStatus` `ExpectedTableAbsent`
  record naming the tables looked for: not a schema this reader knows, so nothing was read —
  which is not a finding that the device held none;
- **a catalogue that will not read**, and **a fixed `SELECT` that will not prepare or run**, is
  `DatabaseUnreadable` with SQLite's error;
- **a NULL flag is `null`**, not `false`: voicemail `deleted` (from `trashed_date`), Photos
  `favorite` / `deleted` (from `ZFAVORITE` / `ZTRASHEDSTATE`) and Calendar `all_day`. The
  viewers show "not recorded" for it.

The PowerLog summary carries `torch_status` — `read`, `table_absent`, or `undetermined` /
`query_did_not_run` / `time_column_unresolved` with `torch_query_error` — so a torch table that
was there and not read does not pass as a flashlight never used. None of these readers has a
column map: a renamed column of a fixed `SELECT` makes the store `DatabaseUnreadable` rather than
read for the columns that remain.

Three more cases are stated in the same readers:

- **Reminders.** The real iOS 15
  `CalendarItem` (Magnet 2022 iPhone 8) calls the column `completion_date`, which the reader uses. A reminders statement that will not prepare or run is one
  `ReminderIncomplete` `DatabaseUnreadable` record with SQLite's error beside the events. The
  held store has no reminder rows (no NULL `start_date`), so the mapping is checked against real
  data for its column names only.
- **Photos album lookups.** For `Z_PRIMARYKEY`, the join table's discovery, the
  membership rows, `ZGENERICALBUM` and the face and person counts, each failure is a sentence in the summary's `lookup_failures`,
  with `content_incomplete` under `unresolved_structure`; the membership rows are read to the end
  or not at all, and when they fail every album's count is `asset_count_unresolved` naming the
  failure, never 0.
- **Empty stores.** Every walked `voicemail.db` yields one `VoicemailSummary`
  (`voicemails`, `trashed`) and every walked `Calendar.sqlitedb` one `CalendarSummary`
  (`events`, `reminders` — `null`, never 0, when the reminders statement did not run), zeros
  included. Both `voicemail.db` files on the Magnet 2022 iPhone 8 are present and empty, and
  say `voicemails: 0`; its calendar says 149 events and 0 reminders.
- **Notes folder and account lookups.** When a folder or account query fails, the rows a failed lookup read before it failed are kept; a note whose
  folder it never reached carries `folder_unresolved` with `in_recently_deleted` and `deleted`
  `null` (unless it is marked for deletion), a note with no account resolved after a failed
  account lookup carries `account_unresolved`, and the summary names every failed lookup —
  entity, account, folder, attachment count, tombstone count — in `lookup_failures` with
  `content_incomplete` and `deleted_notes_unresolved`. The Magnet 2022 NoteStore reads with no
  failure and no marker.
- **The voicemail `deleted` table.** The top-level `voicemail.db` on the Magnet
  2022 iPhone 8 carries a `deleted` table with the `voicemail` table's twelve columns (and a
  `map` table); the per-account store beside it has neither. Its rows are read as
  `Voicemail` records with `source_table: "deleted"` and `row_semantics_validated: false`, and
  the summary states `deleted_table_present`, `deleted_table_rows` and
  `deleted_table_semantics_validated: false`. The held table has 0 rows, so what a row there
  records is not established; both stores are fixtures under
  `seance_plugin_ios_artifacts/tests/fixtures/magnet2022_ios15/Library/Voicemail/`.
- **HealthKit deleted counts.** Both deleted counts are answered from the partial
  index `objects_deleted` on the iOS 15 schema. When the deleted-sample join will not run,
  `deleted_samples` is the count the walk saw and `deleted_samples_basis: walked_samples` says
  so, with the error and `deleted_samples_is_lower_bound`; a deleted-object count that will not
  run is replaced by `deleted_objects_census_error`, not published as absent without a word.


## 2. Core Communication & User Data

### `seance_plugin_ios_chat`
*(Shipped as: `seance_plugin_imessage` (`sms.db`), `seance_plugin_whatsapp` (`ChatStorage.sqlite`) and `seance_plugin_signal` (GRDB store); Telegram remains design-only.)*
**Responsibility:** Parsing native and third-party chat databases.
- **Subscribes To:** `ArtifactType::FileEntry` (`sms.db`, `ChatStorage.sqlite`)
- **Output:** `ArtifactType::TimelineEvent`, `ArtifactType::ParsedRecord`
- **Targets:**
    - **iMessage/SMS:** `sms.db` (Handle `attributedBody` for typed messages). **Validated
      schema range (`ROADMAP` §1.4a):** `_SqliteDatabaseProperties._ClientVersion`
      **9005..=15009** — 9005 from plaso's iOS 9-era `imessage_chat.db`, 14005 from the Magnet
      2021 macOS `chat.db`, 15009 from the Magnet 2022 iPhone 8 `sms.db`. `PRAGMA user_version`
      is 0 on all three real stores, so Apple's own row is the signal; a store outside the
      window still parses and carries a `ParserStaleWarning`; a store with
      `chat_message_join` but no `chat` table falls to the handle-only walk instead of a
      failed prepare. Every column is resolved through a candidate map, and an unresolved one
      is named on the record rather than guessed.
    - **WhatsApp:** `ChatStorage.sqlite` (Messages), `Contacts.sqlite`. **Unranged**: no real
      `ChatStorage.sqlite` is held, so no validated schema range is declared and the record
      says so; the version locator is the Core Data model (`Z_METADATA`), which is not read,
      and `PRAGMA user_version` is not reported for a Core Data store (it is 0 on every one
      measured). The query is built from the column map, so a renamed column is named on the
      record instead of failing the whole store as `ParseFailed`.
    - **Signal:** `grdb/signal.sqlite` — SQLCipher 4 with a 32-byte plaintext header
      (reserve 0x50). Reported **`StoreEncrypted` / `encrypted`**, not as a damaged store. Its
      header bytes 60..63 are ciphertext, reading 360193054 on the Magnet 2022 device, so no
      version is read from it. `seance_sqlcipher` decrypts this form (`decrypt_v4_raw_key`,
      `decrypt_v4_raw_key_wal`: raw key, no KDF, HMAC-SHA512, 80-byte reserve, plaintext
      header) under the 48-byte raw key spec the device's keychain export carries
      (`GRDBDatabaseCipherKeySpec`). Graded on the Magnet 2022 store: all 305 pages and all
      38 committed WAL frames authenticate, SQLite's `integrity_check` passes, and the table
      counts match an independent decryption (`seance_sqlcipher/tests/signal_ios_real_store.rs`,
      gated on `SEANCE_IOS_SIGNAL_DIR`). **The store is read in a
      case once its key spec is supplied for it.** Without one it is still `StoreEncrypted`,
      now carrying `scheme: sqlcipher4_raw_key_plaintext_header`, and its Needs attention row
      takes the spec (`x'…'` or 96 hex digits — the keychain item's 48 bytes); the Signal
      parser then decrypts the store and its committed WAL frames and reads Signal for iOS's
      GRDB schema (`seance_plugin_signal/src/ios_grdb.rs`): `model_TSInteraction` as `Signal`
      message records (`platform: ios`, body, `timestamp`, thread, author), `model_TSThread`
      as `SignalThread`, `model_SignalRecipient` joined to `model_OWSUserProfile` as
      `SignalContact` with the profile name (the profile key is not read), a `SignalSummary`
      with the page and WAL-frame authentication results and the `grdb_migrations` count, and
      a schema record (`app: signal-ios`, unranged) that supersedes the `StoreEncrypted` one.
      **Graded structurally:** on the Magnet 2022 store every page and committed WAL frame
      authenticates, the 84 migrations, 1 thread and 1 recipient are read, and every column
      the reader resolves is present — but the store holds **0 messages**, so no message row
      written by the app has been read. The reader states no direction for a message:
      Signal-iOS keeps it in the row's class code (`recordType`), which no real row has
      confirmed. Rows are exercised on a GRDB-shaped store this project builds and encrypts
      (`seance_plugin_signal/tests/ios_grdb.rs`). The key is not found in the same case's
      keychain automatically; it is supplied.
    - **Telegram:** `db.sqlite` — not parsed on iOS.

### `seance_plugin_ios_contacts_calls`
*(Shipped as: `seance_plugin_contacts` (`AddressBook.sqlitedb`) and `seance_plugin_call_history` (`CallHistory.storedata`).)*
**Responsibility:** Extracting address book and call history.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Targets:**
    - **Contacts:** `AddressBook.sqlitedb`. Validated on
      `_SqliteDatabaseProperties._ClientVersion` **83** (the Magnet 2022 iPhone 8; `PRAGMA
      user_version` is 0 and not consulted). On that device the main file is one empty
      4,096-byte page and **the whole schema lives in its 1.78 MB `-wal`**, which the staging
      takes through the sibling source — a reader that does not stage the sidecar declares the
      store empty.
    - **Call History:** `CallHistory.storedata` (Includes VoIP calls like WhatsApp/FaceTime).
      **No schema window is declared**: Core Data carries no numeric version (model identity is
      hashes in `Z_METADATA.Z_PLIST`), so drift is caught by the `ZCALLRECORD` column map only
      (26 columns on the iOS 15 device), and the record says which fields resolved.
    - **Installed apps:** `applicationState.db` validated on `schema.version` **1** (the iOS 15
      device and the macOS 2021 tree). **Safari `History.db`:** `PRAGMA user_version` 16 on the
      iOS 15 device, inside the shared browser parser's 13..=16 window.
    - **Snapchat `arroyo.db`:** `PRAGMA user_version` **102** on the iOS 15 device — the same
      value as the Android 2022 store, the one cross-platform anchor the schema-drift work has.

---

## 3. System Artifacts & Pattern of Life

### `seance_plugin_knowledgec` (iOS Variant) — **shipped, under another name**
*Shipped as `seance_plugin_macos_artifacts::KnowledgeCParser`. There is no
separate iOS variant and there does not need to be: the parser self-selects on
`knowledgeC.db` and its `ZOBJECT` schema, not on a macOS path, and iOS carries
the same file. It emits every stream, not only `/app/usage`, so the timeline is
complete; timestamps are CFAbsoluteTime and durations are
`ZENDDATE - ZSTARTDATE`. A row cap of 500,000 applies — knowledgeC can hold
millions; the walk is newest-first so the oldest are dropped, and a cap marker
record is emitted when it bites, so a truncated set never reads as a complete
one.*

**Responsibility:** Parsing `knowledgeC.db` (CoreDuet) for detailed user behavior.
- **Subscribes To:** `ArtifactType::FileEntry` (`/private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db`)
- **Output:** `ArtifactType::TimelineEvent`
- **Features:**
    - **App Focus:** Exact timestamps of app usage.
    - **Device Lock/Unlock:** User interaction states.
    - **App Installs:** History of installed/uninstalled apps.
    - **Safari History:** Synced browsing data.

### `seance_plugin_ios_powerlog`
**Responsibility:** Parsing `CurrentPowerlog.PLSQL` for granular system states.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Features:**
    - **Battery Usage:** App energy impact (infer usage when other logs are missing).
    - **Torch/Flashlight:** Physical interaction events.
    - **Audio Routing:** Headphone/Speaker usage.

### `seance_plugin_screentime`
**Responsibility:** Parsing Screen Time usage data.
- **Subscribes To:** `ArtifactType::FileEntry` (`RMAdminStore-Local.sqlite`)
- **Features:**
    - **Usage Categories:** Time spent in Social Networking, Games, etc.
    - **Pickups:** Number of device wakeups per hour.

---

## 4. Location & Media

### `seance_plugin_ios_location` — **partly shipped as `seance_plugin_ios_artifacts::RoutinedLocationParser`**
**Responsibility:** Extracting geospatial data.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Output:** `ArtifactType::TimelineEvent` (with GPS coordinates)
- **Targets:**
    - **Cached locations:** `Cache.sqlite` under `com.apple.routined`. **Shipped**, see the section above. The parser reads the file as plain SQLite and does not decrypt it.
    - **Cellular Location:** `CellLocation.db`. **Design-only**, not parsed.
    - **Photo Metadata:** EXIF GPS data from Camera Roll.

### `seance_plugin_ios_media`
**Responsibility:** Analyzing Photos and Voice Memos.
- **Subscribes To:** `ArtifactType::FileEntry` (`Photos.sqlite`, `Recordings.db`)
- **Features:**
    - **Photos Database:** `ZASSET` / `ZGENERICASSET` rows with capture time, GPS, dimensions, kind, favourite and **trashed** state (`ZTRASHEDSTATE`), so deleted-but-not-purged photos are listed; a NULL `ZFAVORITE` / `ZTRASHEDSTATE` is `null`, not `false`. The hidden flag (`ZHIDDEN`) is not read.
    - **Albums:** one `PhotoAlbum` per `ZGENERICALBUM` row (41 on the
      device's main library, 48 on its Syndication library; two libraries on one device stay
      apart by parent artifact, each with its own summary), with the entity name resolved from
      `Z_PRIMARYKEY` rather than assumed — on iOS 15 `Album` = 6, `FetchingAlbum` = 30,
      `Folder` = 5 — kind, title, cached count, trashed, created, uuid and parent folder. The
      album↔asset join table is **discovered**, not hard-coded: Core Data names it
      `Z_<albumEnt>ASSETS` with columns `Z_<albumEnt>ALBUMS` / `Z_<assetEnt>ASSETS`, and the
      entity numbers move between releases (`Z_27ASSETS` on this device; 0 memberships held).
      `asset_count` is published for the entity that owns the join and for every entity that
      descends from it through `Z_PRIMARYKEY.Z_SUPER` (`CloudSharedAlbum`, `PhotoStreamAlbum`,
      …), whose memberships Core Data keeps in the same table; an album that does not descend
      from it (a `Folder`) is `asset_count_unresolved` with a reason. Pinned on a synthetic
      store by `an_album_subclass_inherits_the_root_album_join_table_and_a_folder_says_which_entity_it_is`;
      no shared-album rows exist on the held device, so the subclass path is ungraded on real
      data. A membership, album or `Z_PRIMARYKEY` query that fails leaves every album
      `asset_count_unresolved` with the reason and lists it under `lookup_failures` on the
      summary, never 0.
    - **Faces / persons:** `ZDETECTEDFACE` and `ZPERSON` are **counted and not decoded** (0 rows
      on the held device — nothing to validate a decoder against). `faces_decoded: false` is
      on the summary.
    - **Cloud Sync:** Identify assets stored in iCloud vs Local.
    - **Voice Memos:** shipped as `seance_plugin_ios_artifacts::VoiceMemosParser`. It reads
      the recordings listed in `CloudRecordings.db`, wherever the iOS release keeps it, and looks
      for the audio file each names beside the database. It does not read transcripts. The
      `ZEVICTIONDATE` meaning and the `ZFLAGS` bits are published as the file holds them and not
      interpreted.

---

## 5. Enterprise & Commercial Features (Advanced)

### `seance_plugin_ios_health` — **shipped as `seance_plugin_ios_artifacts::HealthKitParser`** (`plugin.ios.healthkit`)
**Responsibility:** The samples in `healthdb_secure.sqlite`, with the source name resolved
from `healthdb.sqlite` beside it.
- **Subscribes To:** `ArtifactType::FileEntry` (`healthdb_secure.sqlite`)
- **What is decoded, and the bound on each** (688 samples on the Magnet 2022 iPhone 8, iOS
  15.0.2, build 19A404, histogram exactly `{7:131, 8:133, 12:20, 182:110, 187:118, 188:118,
  194:58}` — every count read with `sqlite3` before the code was written):
    - **`data_type` is Apple's private enum and its name table is asserted, not read.** The
      number is on every record; a name is given for **7 / 8 / 12 only** (`step_count`,
      `distance_walking_running`, `flights_climbed`), each marked `data_type_name_basis:
      asserted` and corroborated by the value shapes in the file (type 7 integer 2..958 summing
      to 21,285 over a month; 12 integer 1..8; 8 running 0.96..682.83 over the same intervals);
      every other type — the mobility types 182 / 187 / 188 / 194 on this device — carries
      `data_type_name_unknown: true`. The observed build is stated on the summary.
    - **The unit is what the file says, or nothing.** `quantity_samples.original_unit` points
      into `unit_strings`, which is **empty on this device**, so every sample says
      `unit_not_recorded: true` and no sample is given HealthKit's canonical unit for a
      guessed type.
    - Start / end / created with `_ns` and a `_source` string naming the column and its epoch
      ("Apple Cocoa seconds since 2001-01-01, converted to Unix"); `deleted` from
      `objects.type = 2`; uuid; the recording timezone (`America/New_York` here), origin
      product type, build and OS version from `data_provenances`; `metadata_values` joined
      (58 `HKMetadataKeyDevicePlacementSide` rows, all on type 194); `source_device` labelled
      as an inferred join. The summary's `metadata_status` is `read`, `tables_absent` or
      `query_did_not_run` (with `metadata_query_error`), and when the join did not run every
      sample carries `metadata_unread` with a `metadata_unread_reason` — never "no metadata".
      A sample whose device is not attributed says why in `source_device_unresolved_reason`:
      `device_id_not_in_source_devices` when the table was read and does not hold the id, or
      the resolution that failed (`sibling_sources_query_did_not_run`,
      `sibling_source_devices_query_did_not_run`, …); the summary carries
      `source_name_resolution` / `source_device_resolution` and `sources_query_error` /
      `source_devices_query_error`.
    - **The source's human-readable name lives in the other file.** `sources.name` is in
      `healthdb.sqlite`, opened as a **neighbour** through `DataSource::open_relative`
      (`"iPhone 8"` here). A source that cannot look says
      `source_name_unresolved_reason: source_cannot_open_neighbours` — today a file inside a
      disk-image file system, as opposed to a host directory or a ZIP entry — and a directory
      without the sibling says `sibling_not_found`; the two are distinguished and both tested.
    - Cap 500,000 samples, newest-first, with a cap marker; 2,000,000 metadata rows. Validated
      `PRAGMA user_version` **15043**; outside it a `ParserStaleWarning` and parsing continues.
      The shared check behind it states a `user_version` of 0 as
      *not recorded* (never "older") and a pragma that will not read as *undetermined*
      (never silence), each a record naming the evidence file; the Safari readers share it.
      This is the **shared** path (`seance_sqlite_util::stale::check_schema_version`), not
      the per-app schema support the chat, contacts and call-log parsers carry: its record
      names the app, the version, the range and the evidence file, and — because these
      readers resolve no columns — no table, unresolved-field list or record count. The
      iMessage and Contacts readers above use the per-app path.
- **Workouts and sleep.** `seance_plugin_ios_artifacts::workouts` reads `HealthWorkout` records
  from both generations of the workout tables and sleep stages from `data_type` 63. Activity,
  location and statistic names are marked `asserted`, because the file names none of them. A
  workout table in a generation the reader was not validated on is counted with
  `workouts_decoded: false`.
- **NOT graded, and why** — each stated on the summary as `*_decoded: false` with the row
  count: ECG and location tables. No held device has a row, so a decoder could not be checked
  against anything and none was written from a specification. Heart rate is not among the
  types on this device.
- **The summary's counts.** `data_type_histogram_status` is `counted` over the whole
  `samples` table, `partial` when the census failed part-way — the data types read before the
  failure are kept in `data_type_histogram`, which is then a lower bound, with
  `data_type_histogram_query_error` — or `query_did_not_run` with
  `data_type_histogram_query_error` — never an empty or short histogram passed off as the
  table's. `deleted_samples` counts sample objects with
  `objects.type = 2` (a join of `samples` to `objects`) and `deleted_objects` every object of
  that type, published apart; the display name says "workouts table absent" when there is no
  `workouts` table, "N workout row(s) unread" only when there is one, and "workouts not
  counted" when the table is there and its count would not read. A table count that fails is
  never published as `_table_absent`: it, a failed `sample_rows` count and a
  histogram that did not complete are each named in `lookup_failures`, which stamps the
  summary `content_incomplete` (`unresolved_structure`) with a `content_incomplete_detail`. On
  the real store `samples_type_anchor` is the index both the histogram and `count(*)` scan (and
  the sample walk), so one damaged leaf of it fails all three; on the Magnet 2022 store every
  census completes and none of these markers appears. The main samples
  `SELECT` is a fixed 19-column list: a generation lacking one of them yields one
  `DatabaseUnreadable` record naming the samples query and SQLite's error, and no summary.
  If the `samples`-to-`objects` join will not run, `deleted_samples` falls back to the count
  of deleted samples the walk saw. The summary says so with `deleted_samples_basis:
  walked_samples`, the error, and `deleted_samples_is_lower_bound`.

### `seance_plugin_ios_biometrics`
**Responsibility:** Analyzing Biometric log events.
- **Subscribes To:** `ArtifactType::FileEntry` (Unified Logs)
- **Features:**
    - **FaceID/TouchID Success/Fail:** Timestamped authentication attempts.
    - **Passcode Unlocks:** Successful manual unlocks.

### `seance_plugin_ios_wallet`
**Responsibility:** Analyzing Apple Wallet and Apple Pay transactions.
- **Subscribes To:** `ArtifactType::FileEntry` (`Passes23.sqlite`)
- **Features:**
    - **Transaction History:** Credit/Debit card usage via Apple Pay.
    - **Passes:** Boarding passes, Event tickets (Geo-location context).

### `seance_plugin_ios_malware`
**Responsibility:** Detecting iOS spyware (Pegasus, Predator).
- **Features:**
    - **Process List Analysis:** Check for anomalous process names (if FFS).
    - **Data Usage:** Check `DataUsage.sqlite` for suspicious background data transfer.
    - **MVT Integration:** Integrate Mobile Verification Toolkit (MVT) indicators (STIX).

---

## Implementation Roadmap

### Phase 1: Backups
- [x] **iTunes Backups:** `seance_plugin_ios_backup` (Manifest parsing).
- [x] **Chat Analysis:** `seance_plugin_imessage` (SMS/iMessage), `seance_plugin_whatsapp`.

### Phase 2: Core Artifacts
- [x] **Contacts/Calls:** `seance_plugin_contacts`, `seance_plugin_call_history`.
- [x] **Media:** shipped as `seance_plugin_ios_artifacts::PhotosParser` (`Photos.sqlite`), not as a separate `seance_plugin_ios_media` crate.

### Phase 3: Pattern of Life
- [x] **CoreDuet:** shipped as `seance_plugin_macos_artifacts::KnowledgeCParser`, which serves iOS as well as macOS. No separate `seance_plugin_knowledgec` crate exists or is needed.
- [x] **PowerLog:** shipped as `seance_plugin_ios_artifacts::PowerLogParser` (`CurrentPowerlog.PLSQL`), not as a separate `seance_plugin_ios_powerlog` crate.
- [x] **Installed apps:** `seance_plugin_installed_apps` reads iOS `applicationState.db` (`application_identifier_tab`).
- [ ] **Screen Time:** `RMAdminStore-Local.sqlite` is not parsed.
- [x] **Location:** `Cache.sqlite` (cached locations, `plugin.ios.routined_locations`) is parsed. `CellLocation.db` is not parsed. Photo EXIF GPS is covered by `seance_plugin_exif`, which is a different and much narrower claim.
- [x] **Safari (`ROADMAP` §1.5):** three readers in `seance_plugin_ios_artifacts::safari`, because on a real device the stores are not where a reference says they are. **`Bookmarks.db`** (`plugin.ios.safari_bookmarks`): one `SafariBookmark` per leaf (title, url, folder path, order, hidden, deleted, reading-list flag, `read` only when non-NULL), one `SafariBookmarkFolder` per folder with its special role, a summary — 6 bookmarks / 4 folders on the iOS 15 device; the `bookmarks` table is **byte-identical** to the one in `SafariTabs.db`, so a file carrying a `windows` table is refused as the bookmarks store whatever its name; the 17,517 bytes of attribute blobs are **counted and not decoded** (the reading list is empty on the device, so `DateAdded` / `PreviewText` had nothing to validate against); validated `PRAGMA user_version` 43. **Open tabs** (`plugin.ios.safari_tabs`): iOS 15+ keeps them in **`SafariTabs.db`** (3 tabs, 1 private, 1 window, 2 tab groups here — tab group, `private_browsing`, the active tab, window uuid, `LastVisitTime` to the microsecond from the `local_attributes` bplist, and each tab's back/forward list from `SessionState` — a 4-byte version then a bplist, uncompressed on iOS 15 — capped at 500 entries with a cap marker; a `SessionState` that does not parse is reported present-and-unread, never as no history); iOS 13/14 keeps them in **`BrowserState.db`** (`tabs`), and on an iOS 15 device that table is **empty** — reported as `tabs_table_empty: true` with a note pointing at `SafariTabs.db`, which is the device's state and not "no tabs were open". The BrowserState `tabs` branch is validated on the real file's DDL and **one synthetic row** only (no real generation with rows is held; the test says so), and `tab_sessions.session_data` is reported present and undecoded. A tab whose session row could not be queried carries `session_state_unknown` with `session_state_unknown_reason`, never "no session", and the summary says `tab_sessions_table_absent`, `session_rows`, or `session_rows_query_did_not_run` with `session_rows_query_error`. A `browser_windows` count that would not read is `windows_count_error` with `content_incomplete` and "windows not counted" in the name, not `windows: 0`. **Recent searches** (`plugin.ios.safari_searches`): not in `RecentSearches.plist`, which does not exist — they are the `RecentWebSearches` array of the app's own `com.apple.mobilesafari.plist`, selected by that key rather than by path (3 queries with nanosecond timestamps here; the search engine is not recorded and the record says so; 16 MiB cap). The summary's `device_udid` is read from the plist key `DidPromptSearchEngineAlertUDID` and the record does not yet name that key; the short-read and cap branches of this reader have no test.
- [x] **Notes bodies, folders, deletion state:** the note entity is resolved from `Z_PRIMARYKEY` (`ICNote` = 11 on the iOS 15 file) with the old title heuristic kept as a stated fallback; the body is decoded from `ZICNOTEDATA.ZDATA` — gzip, then protobuf field **2 → 3 → 2** to the UTF-8 text, verified field by field on both real blobs rather than transcribed from a reference (the Note's field 3 is the styling runs, 4 a UUID-ish message, 5 the repeated per-edit record with Unix-second timestamps: walked past, not mined); a local varint reader, a 16 MiB inflate ceiling, a length past the buffer refused. The Magnet 2022 CTF's grocery list — "Energy drinks, Bread, Hand soap, Birthday card", the "4 items" answer `VALIDATION.md` `IOS-2` recorded as unanswerable — is now in the case. The account link is found by whichever `ZACCOUNT*` column names an `ICAccount` row (`ZACCOUNT4` for notes, `ZACCOUNT5` for folders on this file — Core Data's flattening, discovered rather than hard-coded); one `NotesFolder` per folder (4, two of them Recently Deleted by `ZFOLDERTYPE = 1`, the basis on the folder record); `marked_for_deletion` and `in_recently_deleted` read, `deleted` either. When the `ZICNOTEDATA` query does not run, each note carries `body_unread` with `body_unread_reason` and the summary `bodies_unread`, `body_query_did_not_run` and `body_query_error` — a body that was not read is never a note with no body. **The positive branch is untested**: `ZMARKEDFORDELETION` is 0 on both notes, there are no `ICLegacyTombstone` rows and 0 `ICAttachment` rows, so the deleted-note and attachment branches are ungraded on that device. Attachments are read by `notes_attachments`, validated on the MSAB 2026 iPhone 12 and the Magnet 2021 iPhone 8; a locked attachment's ciphertext is not decrypted and a drawing is listed without a media file. Cap 200,000 notes. Without the `-wal` note 9's body is NULL (its 191 bytes live only in the WAL), so the body assertion pins WAL staging.
- [ ] **Full file system (`seance_plugin_ios_full_fs`):** not built. No generic or internet passwords are recovered from an FFS extraction. Note the precise shape of what is missing, since the format reader is not: `macos.keychain_data_protection` reads `keychain-2.db`'s structure, items, access groups, protection classes and `ckdevicestate`, and reports every secret as locked. An FFS extraction needs the **hardware-derived key** to open those payloads, which an image alone does not carry — a limit to be stated rather than worked around. `ROADMAP` §1.5 carries it.

### Phase 4: Advanced
- [x] **HealthKit:** shipped as `seance_plugin_ios_artifacts::HealthKitParser` — samples, workouts and sleep, with the bounds stated in §5 above.
- [x] **Voicemail audio and transcripts:** the voicemail reader attaches the `<ROWID>.amr` audio and `<ROWID>.transcript` file beside `voicemail.db` and reports an audio file with no row as an orphan. Validated on the Magnet 2020 iPhone (iOS 12.4). The iOS 15 device held for the other voicemail checks has 0 rows.
- [ ] **Messaging attachment media:** `sms.db`'s `attachment` table has 0 rows on the held device and no WhatsApp / Viber is installed on it; skipped.
- [x] **Keychain in an encrypted backup:** `plugin.mobile.ios_backup` reads `KeychainDomain/keychain-backup.plist` while the unlocked keybag is in scope. The file is a binary plist of `genp`, `inet`, `cert` and `keys` arrays of `{v_Data, v_PersistentRef}`; each `v_Data` (version 3) is `<u32 version><u32 class><u32 length>` little-endian, an RFC 3394 wrapped item key, then AES-256-GCM ciphertext with an **empty IV** and a 16-byte tag, whose plaintext is a DER set of the item's attributes. One `IosKeychainItem` per item (access group, account, service, server, label, protection class, sync view, dates, UUID, every other attribute typed) and an `IosKeychainSummary`. **Items in the `ThisDeviceOnly` classes 9/10/11 are in the backup** but their keys are wrapped under the device's hardware-bound key, so they are listed `device_bound` with their table and class only. **The secret (`v_Data`) and the `sha1` digest over it are withheld** from every record and never stored; one item's secret is released by the audited per-record reveal (`POST /cases/{id}/keychain/{record}/reveal`: re-derived from the backup while it is unlocked for reading, `v_PersistentRef` checked, audit row first, refused if the audit write fails). There is no button for it in the UI yet. A tag that does not verify is `authentication_failed` with no attributes. Known answer `IOS-KEYCHAIN-1` in `VALIDATION.md`: on the Hickman iOS 17 backup 1,368 items, 653 read (every tag verifies), 715 device-bound, 616 secrets withheld.
- [x] **Backup keybag class states (`ROADMAP` §1.5):** a keybag class whose `WRAP` has bit 1 set (`WRAP` = 3) is wrapped under the device's hardware key as well as the password. Its passcode layer is still checked (so it still tests the password), but the value it yields is zeroed and never used as a class key; the class is `device_bound`, and `get_class_key` refuses it by name. The `ios_backup_decrypted` record now carries `keybag_classes` (`usable` / `device_bound` / `not_unwrapped`, class numbers only), and `UnlockedBackup::class_key_states()` gives the same without key bytes. On the Hickman iOS 17 backup: 14 classes, 9 usable (1, 2, 3, 4, 6, 7, 8, 17, 18), 5 device-bound (5, 9, 10, 11, 19).
- [ ] **Keychain items from an FFS:** an FFS `keychain-2.db` is wrapped under the device keybag, whose class keys need the hardware-derived key an image does not carry. The backup keybag's class keys (held by `seance_plugin_ios_backup::UnlockedBackup`) do not open it.
- [ ] **Malware:** `seance_plugin_ios_malware` (MVT).

**The known-answer set for all of the above** is `seance_plugin_ios_artifacts/tests/fixtures/magnet2022_ios15/` — 17 real device files (11 MB, with their `-wal` siblings, copied byte-for-byte; not committed, so the tests skip until the files are placed there and never opened in place, since `sqlite3` checkpoints a WAL) and a provenance README; the 17 integration tests in `tests/magnet2022_ios15_test.rs` assert exact ids, URLs, nanosecond timestamps, source strings, histograms and protobuf text. The root `.gitignore` un-ignores `**/tests/fixtures/**/*.{db,sqlite,db-wal,sqlite-wal}`.

