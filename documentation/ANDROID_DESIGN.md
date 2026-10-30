# Android Forensics Extension Design

**Target:** Android Devices (Samsung, Pixel, Xiaomi, etc.)
**Architecture:** Modular Seance Plugins (implementing `ForensicsModule`)
**Status:** Partially Implemented. Shipped and registered in `seance_api::modules`: Android Backup (`.ab`), SMS/MMS, call logs, contacts, the calendar provider, the installed-application inventory, and the third-party chat tier — WhatsApp, Telegram, Messenger, Signal, Instagram, Snapchat, Twitter, Viber, Kik, LINE, WeChat, Skype. Physical dumps are covered by the ext4 and F2FS parsers. Design-only: UsageStats, BatteryStats, runtime permissions, Google Takeout, location, media/MediaStore, APK analysis, Keystore, Digital Wellbeing and Samsung-specific artifacts.

**Schema-drift defence (`ROADMAP` §1.4a).** Every SQLite parser named on this
page now declares the schema version it was validated against — **each endpoint read with
`sqlite3` from a real file on this machine, none typed from a document** — resolves every
column it reads through a candidate map before any query is written, and files a
`ParserStaleWarning` when the store's version is outside that range or a required column
does not resolve, while still parsing everything that did resolve. A store recording no
version (`PRAGMA user_version` 0, SQLite's unset default) is "not recorded", never ranked as
older than a range. The validated ranges, per store, are in the table below; a parser with no
real reference database declares **Unranged** with the reason on every record, and catches
drift by the column map only. Most ranges are a single point because one real store exists
per app; a newer store therefore warns, which is the intended behaviour and a stated
limitation.

| Store | Parser | Validated `PRAGMA user_version` (evidence) | Required logical fields |
|---|---|---|---|
| `mmssms.db` | `seance_plugin_android_sms` | **57..=67** — 57 plaso `mmssms.db` (9 SMS), 67 Magnet 2022 Pixel 3 (11 SMS) | the `sms` / `pdu` / `part` / `addr` walks, each column mapped |
| `calllog.db` | `seance_plugin_call_history` | **5..=5** — Magnet 2022 Pixel 3 (0 rows; single observation) | `calls` columns |
| `contacts2.db` (calls) | `seance_plugin_call_history` | **1..=1** — Magnet 2019 agent copy (3 calls, keyed `id` not `_id`; single observation). Plaso's `contacts2.db` records no version | `calls` columns |
| `contacts2.db` (contacts) | `seance_plugin_contacts` | **1300..=1300** — Magnet 2022 Pixel 3 (0 `raw_contacts` rows, genuine). Plaso's and the Magnet-agent copies lack `raw_contacts` and validate nothing here | `raw_contacts`, `data`, `mimetypes` |
| `calendar.db` | `seance_plugin_android_apps` | **600..=600** — Magnet 2022 Pixel 3 (77 events, 3 calendars) | `Events` columns |
| `keep.db` (Google Keep) | `seance_plugin_android_apps` | **95..=95** — Magnet 2022 Pixel 3 (1 note). `tree_entity` has **no `text` column** on the real file — the body lives in `list_item` — so `text` is declared optional with that reason (it was read silently as `None` before) | `tree_entity` |
| `accounts_de.db` / `accounts_ce.db` | `seance_plugin_mobile_device` | **3..=3** / **10..=10** — Magnet 2022 Pixel 3 (7 accounts each; the framework versions the two files independently) | `accounts.name`, `type` |
| `telephony.db` | `seance_plugin_mobile_device` | **1703944..=1703944** — Magnet 2022 Pixel 3 (1 SIM). The real `siminfo` has **no `imsi` column**; declared optional with the evidence | `siminfo` |
| Chrome on Android `History` / `Cookies` / `Web Data` / `Login Data` | `seance_plugin_browser_history` (`meta.version`, with `meta.last_compatible_version` carried on the marker) | inside the shared **20..=70 / 5..=24 / 77..=152 / 24..=43** windows; the Pixel 3's own values are **51 / 16 / 98 / 31** | per-table maps; the old `downloads(full_path, url)`, `cookies(secure, httponly)` and no-`date_last_used` shapes now parse instead of failing whole |
| Snapchat `arroyo.db` | `seance_plugin_snapchat` | **102..=102** — two real stores, the Pixel 3 (7 messages) and the iOS 15 iPhone 8 (2), both 102: the one cross-platform anchor | `conversation_message` columns |
| Snapchat `main.db` (Friend) | `seance_plugin_snapchat` | **427..=427** — Pixel 3 (3 friends) | `Friend` columns |
| Twitter per-account `<uid>-<NN>.db` | `seance_plugin_twitter` | **7..=59** — 7 plaso `twitter_android.db` (1 DM), 59 both Pixel 3 stores (0 DMs) | `conversation_entries`, `users` |
| Skype `main.db` | `seance_plugin_skype` | `AppSchemaVersion.SQLiteSchemaVersion` **66..=66** — plaso's `skype_main.db` (Skype 6.6, 15 messages); `PRAGMA user_version` is 0 there, so the app's own table is read. Identification widened to `Accounts.skypename` + a `Messages` table so a renamed body column is reported rather than read as "not Skype" | `Messages` columns |
| WhatsApp `msgstore.db` | `seance_plugin_whatsapp` | **Unranged** — a real store is held (Pixel 7a, `test_data/whatsapp_android14/`) and the parser reads it (230 messages, every field resolved), but **Unranged** because `PRAGMA user_version` is a constant 1 in every real msgstore held and cannot detect drift | `text`, `sent_at`, `from_me` |
| Telegram `cache4.db` | `seance_plugin_telegram` | **Unranged** — no real store held | `dialog`, `sent_at` |
| Signal `signal.db` / `.backup` | `seance_plugin_signal` | **Unranged** — the one real `signal.db` (Pixel 3) is raw SQLCipher. A replayed backup now honours the `DatabaseVersion` frame (BackupProtos field 5) as `PRAGMA user_version` — it read as 0 before | `text`, `type` (one marker per message table walked; a legacy `sms` + `mms` store carries two) |
| Viber | `seance_plugin_viber` | **Unranged** — no real store held | `text`, `sent_at` |
| Kik `kikDatabase.db` | `seance_plugin_kik` | **Unranged** — the one real Kik file (`kik_ios.sqlite`, plaso) is the iOS Core Data schema this Android parser does not read | `text`, `sent_at` |
| LINE `naver_line` | `seance_plugin_line` | **Unranged** — no store anywhere searched | `chat_history` columns |
| WeChat `EnMicroMsg.db` | `seance_plugin_wechat` | **Unranged** — `com.tencent.mm` is installed on the Pixel 3 but has no `MicroMsg` data | `message` columns |
| Instagram `direct.db` | `seance_plugin_instagram` | **Unranged** — only sdcard cache on the 2019 image | `messages` columns |
| Facebook Messenger (`threads_db2`, `msys_database_*`, `lightspeed-*`) | `seance_plugin_fbmessenger` | **Unranged** — no real store held | column map only |
| Twitter `<uid>-search.db` | `seance_plugin_twitter` | **Unranged** — no such file in any corpus. Both real per-account stores keep `search_queries` in the main `<uid>-<NN>.db`, and it is read there too, under the main store's `7..=59` window (plaso's store yields 1 search, the Pixel 3's `1489429766507835392-61.db` 2) | `search_queries.time`, `query` |

Three behaviours the adoption changed on real files, each now pinned by a test: Viber, Kik
and Telegram returned an **empty result** when a required column was renamed — identical to a
device with no messages — and now name the field; WhatsApp iOS failed the whole store as
`ParseFailed` on one renamed column and WhatsApp Android substituted `NULL` silently; and the
Magnet 2019 agent `contacts2.db` (calls keyed `id`) was filed `ParseFailed` whole. A
uniquely-named store whose catalogue reads but lacks its message table (`arroyo.db`,
`naver_line`, `EnMicroMsg.db`, `direct.db`) now yields a `SchemaTableAbsent` note instead of
silence. Two shapes of marker exist across the groups for now — the shared
`StaleWarning::marker` (type `ParserStaleWarning`) and the per-crate `<App>Incomplete` note
with `warning_class: ParserStaleWarning` — pending the lift into
`seance_sqlite_util::stale`; `CORE_DESIGN.md` carries the contract. The corpus-gated tests
that pin the ranges read the CTF-derived copies through `SEANCE_APP_SCHEMA_CORPUS`,
`SEANCE_ANDROID2022_TREE`, `SEANCE_SNAPCHAT_SAMPLES` and the plaso tree, skip loudly when
unset, and fail under `SEANCE_REQUIRE_CORPUS=1` / `SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1`;
they are **not yet wired into CI** (`documentation/CI.md`).

**Shared stale check.** The shared `seance_sqlite_util::stale`
check now reads `PRAGMA user_version` three ways like the per-crate copies — 0 is "not
recorded", an unreadable pragma "undetermined", neither ranked — and its marker carries
`subtype: parser_stale`, a `status`, `content_incomplete_reason: unvalidated`, the detail and
a name; `TempDb::stamp_incompleteness` keeps a reason a record already carried (both listed in
`content_incomplete_reasons`, the spill's clause added to its detail) instead of overwriting
it. Every schema record from the Android SMS, call-log, iMessage and Twitter/X parsers now
names the evidence file(s) of its range as `validated_against`, as the other adopters' did.
And in Viber, Kik, LINE, Instagram, Facebook Messenger, Snapchat (`arroyo.db` and `main.db`
`Friend`) and Twitter/X (`conversation_entries`, `search_queries` and the `users` handle
lookup), a statement that will not prepare or run after the table and columns were
established — a store declaring a collation stock SQLite lacks, such as the Android
framework's `LOCALIZED`, or a view that will not compile — yields one `<App>Incomplete`
record with `status: DatabaseUnreadable`, the table as `source_table` and SQLite's message as
`sqlite_error`, never an empty list. Those failure paths are pinned by synthetic fixtures (the
real table with its sort column re-declared under `LOCALIZED`); no real store that fails this
way is held.
The lookup tables that name senders follow the same rule: a Twitter/X `users`
table that could not be looked for or whose column list would not read, and a
Facebook Messenger msys `contacts` or Kik `KIKcontactsTable` that could not be looked for,
whose column list would not read or whose query would not prepare or run, each leave the messages attributed by id and add one `TwitterUserIncomplete` /
`FacebookMessengerContactIncomplete` / `KikContactIncomplete` record (`StoreUnreadable`, or
`DatabaseUnreadable` with `sqlite_error`). Only an absent lookup table carries no record, because
that is a store shape. Graded on the Pixel 3 `1489429766507835392-61.db` and plaso's
`twitter_android.db` (no false marker); no real Messenger or Kik Android store is held.

**ARM64 memory (`ROADMAP` §3.8a):** the translation core in `seance_memory` can
walk arm64 page tables (4 / 16 / 64 KiB granules, 39 / 42 / 47 / 48-bit VA among the widths it
accepts), but Linux arm64 **discovery** — proving a capture's granule, width and TTBR1 by
translating the kernel banner back to where the sweep found it — is not built, so **no
Android or Linux arm64 memory image is analysed end to end yet**; such a capture is refused
by name. Every arm64 fixture is synthetic: no arm64 capture exists on the build host.

This document outlines the architecture for extending Seance with comprehensive Android forensics capabilities, targeting parity with commercial mobile forensic suites.

---

## 1. Acquisition & Container Support

### `seance_plugin_android_backup`
**Responsibility:** Parsing Android Backup (`.ab`) files.
- **Subscribes To:** `ArtifactType::RawEvidence` (File with `.ab` extension)
- **Input Capability:** `InputCapability::Stream`
- **Output:** `ArtifactType::FileEntry`
- **Features:**
    - **Header Parsing:** Validate Magic Header (`ANDROID BACKUP`).
    - **Encryption:** an AES-256 encrypted backup is not decrypted. It yields one
      warning record saying extraction was skipped and a password is needed.
    - **Decompression:** Handle Deflate/Tar streams.
    - **Payload ceiling (shipped):** the inflated tar payload is read to at most
      2,147,483,648 bytes (2 GiB, a constant — not adjustable per run). When the
      payload reaches it, a `CapReached` status record names the ceiling, the entries
      extracted, and the entry it fell inside (path, declared size, bytes extracted)
      when it fell inside one; that entry is stamped `cap_reached`.
    - **A backup that was read says so (ROADMAP §1.4):** a walk that
      reaches the archive's own end closes with one `AndroidBackupSummary`
      (the header's `format_version`, `compressed`, `entries_extracted`,
      `entries_content_incomplete`, `app_packages`). Its `status` is
      `Extracted` ("unpacked whole") only when no entry carries a
      `content_incomplete` flag; a walk that reached the end with an entry over
      the per-entry cap, unreadable, or short is `WalkedToEnd` ("walked to its
      end", with the count), because every entry is listed but not every
      entry's content was read. Before it only failures left a
      record, so a backup read cleanly was indistinguishable from the files that
      came out of it, and the source-kind label could not call it a backup.
      Graded on the Magnet 2019 `adb-data.tar` payload behind a restored header
      (258 entries, 62 packages; `VALIDATION.md` SRCKIND-1).

**Source-kind label.** `GET /cases/{id}/source_kinds` labels a source
`android_device` from the Android parsers' marker records (`MobileDeviceInfo`
and `BluetoothPairing` with `platform: android`, the SMS, calendar and Keep
summaries, `InstalledAppSummary` from `packages.xml`/`packages.list`) and
`android_backup` from `AndroidBackupSummary`/`AndroidBackupWarning` — never from
the source's name. See `CORE_DESIGN.md` §4.

### `seance_plugin_android_physical`
**Responsibility:** Processing physical dumps (Ext4/F2FS images).
- **Subscribes To:** `ArtifactType::FileSystem` (matched on `subtype` or `filesystem_type`, case-insensitively).
- **Output:** `ArtifactType::FileEntry`
- **Features:**
    - **F2FS Support:** Parse Flash-Friendly File System (common on modern Android).
    - **User Data:** Locate `/data/data` (App private data) and `/data/media` (Shared storage).

### `seance_plugin_google_takeout`
**Responsibility:** Parsing Google Takeout cloud exports.
- **Subscribes To:** `ArtifactType::RawEvidence` (Zip/Tgz archive)
- **Features:**
    - **Location History:** Parse `Location History.json` (Semantic Location).
    - **My Activity:** Parse Search, YouTube, and Assistant history.
    - **Google Photos:** Metadata and media extraction.

---

## 2. Core Communication & User Data

### `seance_plugin_android_telephony`
*(Shipped as: `seance_plugin_android_sms` (`mmssms.db`), `seance_plugin_call_history` (`calllog.db`), `seance_plugin_contacts` (`contacts2.db`).)*
**Responsibility:** Extracting SMS/MMS and Call Logs.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Output:** `ArtifactType::TimelineEvent`
- **Targets:**
    - **SMS/MMS:** `mmssms.db` (Standard Android messaging).
    - **Call Logs:** `calllog.db` (System calls).
    - **Contacts:** `contacts2.db`.

### `seance_plugin_android_chat`
*(All four shipped and registered in `seance_api::modules`: WhatsApp as `seance_plugin_whatsapp` (`msgstore.db`), Telegram as `seance_plugin_telegram` (`cache4.db`), Messenger as `seance_plugin_fbmessenger` (`threads_db2`), Signal as `seance_plugin_signal`.)*
**Responsibility:** Parsing third-party chat applications.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Targets:**
    - **WhatsApp:** `msgstore.db` (Requires key for decryption), `wa.db` (Contacts).
      - **`crypt14` backups.** `seance_plugin_whatsapp::crypt14`
        decrypts a `msgstore.db.crypt14` / `wa.db.crypt14` with the device's key file
        (`/data/data/com.whatsapp/files/key`, a Java-serialised 131-byte array whose last 32
        bytes are the AES key) or a bare 32-byte key: the header is `[length][0x01 when a
        feature list follows][protobuf]`, the protobuf's field 2 carrying the server salt, the
        Google ID and the 16-byte IV; then AES-256-GCM ciphertext of a zlib stream, the 16-byte
        tag and an MD5 of everything before it. A key whose server salt is not the backup's is
        refused before decryption; the tag is verified before any byte is released; the result
        must open as SQLite. Graded on the real Pixel 7a backups (`VALIDATION.md`
        `WHATSAPP-CRYPT14-1`). **In ingest** (`seance_plugin_whatsapp::backup`): the gate names
        every `*.cryptNN`. A `crypt14` is paired with the key file (`com.whatsapp/files/key`)
        across the case, in whichever order ingest delivers them — the two sit about seven
        directories apart, beyond a data source's ancestor lookup, and a file in a disk image
        has none. A backup read first is recorded `WhatsAppBackup`/`AwaitingKey` (content
        incomplete, reason `encrypted`); when its key is read the decrypted store is parsed
        by the message-store path as the backup's own child, every record stamped
        `provenance: decrypted_backup` with the backup's and the key's path and SHA-256, and a
        `Decrypted` record supersedes the `AwaitingKey` one (the orchestrator now honours
        `supersedes_status` in the automatic pipeline, not only in an ad-hoc re-run). A key
        from another install is refused by its salt (`KeyRefused`) and the backup keeps
        waiting. The key file gets a `KeyFound` record naming its path and SHA-256; the key
        itself is written nowhere. Limits: pairing is in process memory (a key in another
        case, or read after a restart or after the unlock lifetime, does not reach the backup); at most 64
        pending backups and 16 keys per case; backups over 1 GiB are not read; a backup's
        messages repeat the live store's and are not merged with them. **A backup seized
        without its phone:** `POST
        …/artifacts/{backup}/credential` with kind `whatsapp_key` — the key file's bytes as hex,
        or the bare 32-byte AES key as 64 hex digits (spaces and case ignored) — re-runs the
        parser on that backup with that key and no other: the key file's salt must match the
        backup's, the GCM tag must verify, and only then is the store parsed and filed exactly
        as above, with `key_source: credential`, no `key_path`, and the SHA-256 of what was
        supplied (for a key file, the file's own hash). A key that does not open it is
        **rejected**: nothing is filed and the `AwaitingKey` statement stands. The awaiting
        statement carries `scheme: crypt14` and `credential_kind: whatsapp_key`, so the
        attention queue and the record's unlock field offer the key. **crypt15:**
        an end-to-end encrypted backup is decrypted with its 32-byte root key: the 64 hex
        digits the phone showed, which it also keeps as
        `/data/data/com.whatsapp/files/encrypted_backup.key` (a Java `byte[32]`). The file is
        paired across the case exactly as `files/key` is, and the 64 digits (or that file's
        bytes) can be supplied as `whatsapp_key`. The header's field 3 holds the IV; the AES
        key is HKDF-SHA256 of the root (salt 32 zero bytes, info `backup encryption`); the
        trailer is the GCM tag, then an MD5 of everything before it except on a multi-file
        backup. A crypt14 key is never tried on a crypt15 backup nor the reverse, and neither
        leaves a `KeyRefused` against the other's backups; a wrong root is refused by the GCM
        tag. The plaintext is inflated where it is zlib and holds a message store (parsed as
        above) or a ZIP archive (`stickers.backup.crypt15`, an incremental backup): the archive
        is filed beneath the backup as a `FileEntry` for the archive expander, with fresh
        metadata so the content resolver can never serve the ciphertext as it; it is held in
        memory only and is refused, not served, after the run. `Decrypted` records carry
        `backup_generation`, `payload` (`sqlite` or `zip`) and `checksum_ok` (`null` when there
        is no MD5). A root protected by a backup password is derived by WhatsApp's HSM and
        cannot be recovered offline. Graded on the published backups (`VALIDATION.md`
        `WHATSAPP-CRYPT15-1`). **Key retention** follows the in-memory unlock decision: a key
        read from the evidence is held for its case only, for the unlock lifetime (8 hours,
        `SEANCE_UNLOCK_TTL_SECS`) or until a restart, zeroed when dropped, and written to no
        record, export or log (the `KeyFound` record names its path, SHA-256 and `key_scheme`);
        a supplied key's decoded bytes are zeroed when the run returns. `crypt12` and older are
        refused by name with a `NotDecrypted` record, as is a crypt14/15 whose header will not
        read or whose supplied key does not open it.
    - **Telegram:** `cache4.db` (Images/Media), `maps` (Message cache).
    - **Facebook Messenger:** `threads_db2` (Messages).
    - **Signal:** `signal.db` (SQLCipher-encrypted under a keystore key this build cannot obtain: a `signal.db` that is not SQLite is recorded as `SignalIncomplete`/`StoreNotSqlite`, never silently skipped), `plaintext.db`, and the Android backup export (`signal-YYYY-MM-DD-HH-MM-SS.backup`, decrypted with the 30-digit passphrase). The passphrase is supplied for the locked backup with `POST …/artifacts/{file}/credential`, kind `signal_backup_passphrase` (the artifact page's unlock field and the REPL's `/unlock`), held zeroed for that one run. That is the only way a passphrase reaches the parser: the artifact's metadata is not read for one, because an ingest field such as `signal_backup_password` is replaced by the redaction marker at ingest (every `*_password` key is scrubbed before any module runs), so reading it could only have tried that marker. The parser reports **rejected** when the first frame's MAC does not verify — the passphrase is wrong, or the first frame is corrupt; the MAC cannot tell the two apart and the rejection says both — **accepted** when the replay runs and at least one frame's MAC verified, no verdict (`not_used`) for a backup that ends after its header, and a module error — not a verdict on the passphrase — when the backup itself is corrupt after a MAC has verified or its header does not parse. A backup is classified by its header frame, not its suffix — other apps' `.backup` files are not Signal.

---

### `seance_plugin_installed_apps` — **shipped**
**Responsibility:** The installed-application inventory, Android **and** iOS.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Output:** one `InstalledApp` `ParsedRecord` per application, plus one
  `InstalledAppSummary` per file parsed
- **Inputs, self-selected:**
    - `/data/system/packages.xml` — the package-manager settings XML. Each
      `<package>` carries the package id, `codePath`, install times (`ft`/`it`/`ut`,
      each a **hex** string of Unix epoch milliseconds), `version` and
      `userId`/`sharedUserId`. `<shared-user>`, `<permissions>` and
      `<keyset-settings>` elements are ignored.
      **Android 12 and later write this file as Android Binary XML** (`ABX\0`
      magic, the `BinaryXmlSerializer` token stream), not text. It is detected
      by magic and decoded by `seance_xml_util::abx` to the text form Android's
      own text writer would have produced — `LONG_HEX` install times as bare
      hex, ints decimal, booleans `true`/`false` — and then walked by the same
      parser. The `InstalledAppSummary` says which was read
      (`encoding: "abx" | "text"`). An ABX document that ends mid-token keeps
      every package decoded before the break and stamps the summary
      `content_incomplete` with `short_read` and `parse_stopped_at_offset`;
      bytes that do not form a document stamp `unresolved_structure`. Strings
      that were not valid UTF-8 are decoded with replacement characters and
      counted on the summary (`abx_lossy_strings`). Validated on Josh Hickman's
      Android 14 (Pixel 7a) reference image: the 701,599-byte file decodes
      whole to 369 packages, the same set `packages.list` names, with `ft`/`ut`
      install times. (Android 14 writes no `it` attribute on `<package>`, so
      `install_time` is absent on that release by the device's choice, not the
      parser's.)
    - `/data/system/packages.list` — plain text, space separated.
    - iOS `applicationState.db` — `application_identifier_tab`.
- **Install provenance — how the app got onto the device.** The package manager
  records the **installing package** in `installer`, and on Android 14 splits
  the question again into `installInitiator` and `updateOwner`. All three are
  read where the device wrote them, together with the `isOrphaned` flag. The
  Android 14 pair is graded on the Pixel 7a (`VALIDATION.md` AND-1):
  of 369 packages, `installInitiator` on 123 and `updateOwner` on 56, every value
  the Play Store, each matching an independent ABX count; on the 2022 Pixel 3
  (Android 9) neither is written. What
  makes the missing case mean something is `codePath`: the parser derives a
  `code_partition` from it and reports one of four `install_source` values.

  | `install_source` | When | What it says |
  |---|---|---|
  | `installer_recorded` | `installer` present | That package asked the package manager to install this one. `com.android.vending` is the Play Store |
  | `shipped_with_the_os` | no `installer`, code on `system` / `product` / `vendor` / `apex` | Nothing installed it — it came with the OS. **Not** a sideload signal |
  | `no_installer_recorded` | no `installer`, code under `/data` | **The signal a sideload leaves.** A note on the record says it is a signal and not a proof |
  | `not_recorded` | no `installer` and no `codePath` | The file did not say enough for either reading |

  **Why the partition split is load-bearing.** On the graded Android image
  (`ANDROID-PKG-1`) 151 of 213 packages carry no `installer` — and 150 of those
  are on read-only OS partitions, where the absence means nothing. Without the
  split the signal would be 151 packages of noise. With it, it is **one**:
  `com.topjohnwu.magisk`, a rooting tool, the single package with its code in
  user data and no installer recorded, on a device where the other 62 all name
  the Play Store.

  `/data/app` is **not** "user installed": it holds the code of an app the user
  installed *and* of a system app the Play Store has since updated. 62 of the
  63 packages there on that image name the Play Store and most are Google's
  own. The partition says where the code is, not who put it there.

  `isOrphaned` is reported and **not interpreted**: on that image 40 of the 62
  Play-installed packages carry it while the Play Store itself is installed (and
  59 of 123 on the Android 14 Pixel 7a), so
  the common reading — that the installing package has since been uninstalled —
  does not hold there, and the record says the flag's meaning is unestablished.
- **Honesty:** absent fields are omitted, never emitted as null; a timestamp that
  is non-hex, non-positive or beyond the year 2100 is dropped rather than
  fabricated.

This is *not* `seance_plugin_permissions`: `runtime-permissions.xml` is not
parsed, so which apps hold Camera / Mic / Location grants is still open.

### `seance_plugin_android_apps` — **shipped**
**Responsibility:** The Android calendar provider
(`/data/data/com.android.providers.calendar/databases/calendar.db`, or a bare
`calendar.db`).
- **Output:** one `CalendarEvent` `ParsedRecord` per `Events` row, plus an
  `AndroidCalendarSummary` per file. Deliberately the **same record shape** as
  the iCalendar plugin so both share the frontend calendar viewer; a
  `source: "android_calendar"` field distinguishes the origin.
- `dtstart`/`dtend` are Unix epoch **milliseconds** in Android and are converted
  to RFC 3339 UTC. Out-of-range values, and the provider's unset value 0, are
  omitted rather than fabricated. A `calendar.db` lacking an `Events`
  table is rejected, so an unrelated file sharing the name is not parsed. The
  event's identity is read as SQLite's `rowid`, so an `Events` table without an
  `_id` column still reads.
- A `calendar.db` / `keep.db` that carries the SQLite header and will not open,
  whose catalogue will not read, or whose `Events` / `tree_entity` column list,
  prepare or query fails yields one `StoreUnreadable` marker
  (`AndroidCalendarIncomplete` / `AndroidNoteIncomplete`) naming SQLite's error —
  never an empty result, and never a module error with no artifact.
  A file of that name that is not SQLite at all stays unclaimed.

---

## 3. System Artifacts & Pattern of Life

### `seance_plugin_mobile_device` — **shipped**
**Responsibility:** The device's own identity, from the Android property files.
- **Subscribes To:** `ArtifactType::FileEntry` / `FileContent`, self-selecting on
  the file name: `build.prop`, `default.prop`, `prop.default`, `vendor.prop`,
  `odm.prop`.
- **Output:** one `MobileDeviceInfo` `ParsedRecord` per property file.
- **Read:** manufacturer, model, device codename, product, Android version, SDK
  level, security patch, build id / display id / fingerprint / date / type /
  tags, serial number, hardware, bootloader, CPU ABI, locale, time zone,
  encryption state and type, verified-boot state. `ro.product.*` moved under
  per-partition prefixes in Android 10 (`ro.product.system.*`,
  `ro.product.vendor.*`) and the framework falls back through them, so each fact
  names several candidate keys, most authoritative first.
- **Every fact names the key it came from.** An examiner asked to stand over
  "the model is Pixel 7a" has to be able to say what they read, and the keys
  moved between Android versions.
- **One record per file, nothing reconciled here.** A device has several property
  files and they can disagree — a vendor image reflashed over a system image is
  exactly that — so the disagreement is preserved and shown by
  `GET /cases/{id}/device_info`, which never picks a winner.
- **A name-only match is corroborated**: `build.prop` is not a rare name, and a
  file of unrelated `key=value` text is not claimed unless it carries at least
  one `ro.` property. A file named like a property file that was read short is
  recorded as `properties_unidentified` with the incompleteness pair rather than
  passed over in silence.
- **Short reads are re-asked, and each shortfall has its own reason:**
  The property file and `bt_config.conf` are read with a looped
  read, so a windowed source that answers a few bytes per call still yields the
  whole file; a source that delivered less than it declared is `short_read`, a
  file over the parser's ceiling (1 MiB / 4 MiB) is `cap_reached`, and every
  Bluetooth record carries the reason when the pairing list is a prefix.
The same crate reads the three sources that answer the question for the device's
**owner** rather than the handset:

- **`settings_{global,secure,system}.xml`** (`plugin.mobile.android_settings`) —
  `device_name`, `bluetooth_name`, `android_id`, `bluetooth_address`, and the
  facts that say how far the device's own record of time can be trusted:
  `auto_time` and `auto_time_zone`. A phone whose clock was set by hand is a
  phone whose every timestamp is an assertion by whoever set it, and that belongs
  on the device summary rather than in a file nobody opens. Also `adb_enabled`,
  `development_settings_enabled` and `install_non_market_apps`. Android 12+
  writes these as Android Binary XML; both encodings are read and the record says
  which it found.
- **`accounts_de.db` / `accounts_ce.db`** (`plugin.mobile.android_accounts`) —
  the AccountManager stores. Google accounts are lifted out as `google_account`
  and every account is listed with the authenticator that owns it, because an app
  account can be the identity a case turns on. A file named like the store that
  does not begin with the SQLite header is reported as unreadable; a header probe
  that came back short of 16 bytes is reported as a `short_read`, never as "not
  SQLite"; a real SQLite file that simply is not this store is not
  claimed. A staging shortfall carries the spill's own
  reason, and a refused WAL adds `wal_incomplete_reason`.
- **`telephony.db`** (`plugin.mobile.android_telephony_device`) — `siminfo`:
  the phone's own number, ICCID, IMSI, carrier and the name the user gave each
  line. The column set has changed across Android versions, so the table's own
  columns are read first and only those that exist are selected: a `SELECT`
  naming a column this device lacks fails whole, and the number would then read
  as absent because an unrelated column was renamed. An empty `siminfo` is
  recorded as "no SIM recorded" rather than as nothing, which would read as
  "not examined". Every failure past the name match — staging, opening, the
  `siminfo` column list, the query — is a `telephony_unreadable` record with
  SQLite's error, a row that will not decode is counted (`rows_undecodable`,
  reason `unresolved_structure`), and a short spill or a refused WAL is stamped
  (`staging_incomplete_reason`, `wal_incomplete_reason`). Each value is
  read as whatever SQLite type it holds: an INTEGER `number` is rendered in its
  decimal form rather than published as absent, and a BLOB or non-UTF-8 value is
  counted under `values_not_rendered` with `content_incomplete`. The
  real Pixel 3 store declares `number TEXT` (NULL on its one SIM), so an INTEGER
  arises only where the column carries no text affinity.

- **`bt_config.conf` / `bt_config.bak`** (`plugin.mobile.android_bluetooth`) — the Bluetooth
  stack's own record of every device the phone remembers: address, advertised name, device class
  and type, the services it offered, and the last time it was seen. It answers a question
  nothing else on the device answers — *what physical things has this phone been near, and
  when*. The file's **order** is carried as a field because Android appends a device when it is
  first remembered, so the first section is the earliest pairing, which is the only answer for
  an entry that carries no `Timestamp` at all. The `[Adapter]` section is the phone's own radio,
  so its address is emitted as a device fact rather than as a pairing, where it corroborates the
  one in `settings_secure.xml`. **The link key is never copied into the case**: it secures the
  bond and decrypts that device's traffic, so its presence and type are recorded and its value
  is left in the file, which the record names.

Accounts and SIM facts are **multi-valued**: a dual-SIM phone has two numbers and
a phone can hold several accounts. `GET /cases/{id}/device_info` marks those
facts `multi_valued` and lists every value, instead of reporting them the way it
reports a disagreement.

- **Not yet read:** `euicc.xml` (eSIM), and the IMEI, which is not in these
  files on a modern device.

### `seance_plugin_usagestats`
**Responsibility:** Parsing Android UsageStats (XML/Protobuf).
- **Subscribes To:** `ArtifactType::FileEntry` (`/data/system/usagestats/*`)
- **Output:** `ArtifactType::TimelineEvent`
- **Features:**
    - **App Activity:** Daily/Weekly/Monthly/Yearly aggregation of app usage.
    - **Last Time Used:** Timestamp of last interaction.
    - **Total Time in Foreground:** Duration of app usage.

### `seance_plugin_batterystats`
**Responsibility:** Parsing BatteryStats (`batterystats.bin` / dumpsys).
- **Subscribes To:** `ArtifactType::FileEntry`
- **Features:**
    - **Wake Locks:** Apps keeping the device awake.
    - **Sensor Usage:** GPS/Camera/Microphone usage history.

### `seance_plugin_permissions`
**Responsibility:** Analyzing app permissions (`runtime-permissions.xml`).
- **Subscribes To:** `ArtifactType::FileEntry`
- **Features:**
    - **Granted Permissions:** Which apps have access to Camera, Mic, Location.
    - **Grant Time:** When the permission was granted (Timeline event).

---

## 4. Location & Media

### `seance_plugin_android_location`
**Responsibility:** Extracting location data from various sources.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Output:** `ArtifactType::TimelineEvent` (GPS)
- **Targets:**
    - **Google Maps:** `gmm_storage.db` (Cache).
    - **Waze:** `user.db` (Favorites, Recents).
    - **Wifi Scans:** `wpa_supplicant.conf` (Known networks).

### `seance_plugin_android_media`
**Responsibility:** Analyzing Gallery and Media Store.
- **Subscribes To:** `ArtifactType::FileEntry` (`external.db` / `internal.db`)
- **Features:**
    - **Media Store:** Metadata of all indexed media files.
    - **Thumbnails:** `.thumbnails` folder (evidence of deleted images).
    - **EXIF Analysis:** GPS and Device Model from photos.

---

## 5. Enterprise & Commercial Features (Advanced)

### `seance_plugin_apk_analysis`
**Responsibility:** Static analysis of installed applications (Malware detection).
- **Subscribes To:** `ArtifactType::FileEntry` (`.apk`)
- **Output:** `ArtifactType::RiskIndicator`
- **Features:**
    - **Manifest Parsing:** Extract Package Name, Version, Permissions.
    - **Signature Verification:** Verify APK signature against known certificates.
    - **Malware Scanning:** Hash lookup (SHA256) against threat intelligence.
    - **Decompilation:** Basic string extraction (URLs, IP addresses).

### `seance_plugin_android_keystore`
**Responsibility:** Analyzing the Android Keystore system.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Features:**
    - **Key Enumeration:** List keys stored by apps (without extracting private keys).
    - **Security Level:** Determine if keys are TEE/StrongBox backed.

### `seance_plugin_digital_wellbeing`
**Responsibility:** Parsing Digital Wellbeing events.
- **Subscribes To:** `ArtifactType::FileEntry` (`dw_usage_log.pb`)
- **Features:**
    - **Unlocks:** Count of device unlocks.
    - **Notifications:** Count of notifications received per app.

### `seance_plugin_samsung_custom`
**Responsibility:** Parsing Samsung-specific artifacts.
- **Features:**
    - **Rubin:** Samsung's context service (Location, Activity).
    - **Device Care:** Logs of app crashes and system issues.
    - **Samsung Health:** Step counts and activity logs.

---

## Implementation Roadmap

### Phase 1: Acquisition
- [x] **ADB Backup:** `seance_plugin_android_backup`.
- [x] **Telephony:** `seance_plugin_android_sms` (SMS/MMS), `seance_plugin_call_history` (Call logs), `seance_plugin_contacts`.
- [x] **Physical dumps:** covered by `seance_plugin_ext4` and `seance_plugin_f2fs`, both registered — there is no separate `seance_plugin_android_physical` crate.

### Phase 2: Core Artifacts
- [x] **Installed applications:** `seance_plugin_installed_apps` (`packages.xml`, `packages.list`, and iOS `applicationState.db`), **with the install provenance** — which package installed each app, and which apps' code is in user data with no installer recorded. See above.
- [x] **Calendar:** `seance_plugin_android_apps` (`calendar.db`).
- [ ] **UsageStats:** `seance_plugin_usagestats` (Critical for timeline).
- [ ] **Runtime permissions:** `runtime-permissions.xml` is not parsed — which apps hold Camera/Mic/Location grants, and when they were granted, is not recoverable here.
- [x] **Chat Analysis:** `seance_plugin_whatsapp`, `seance_plugin_telegram`, `seance_plugin_fbmessenger`, `seance_plugin_signal`. Instagram, Snapchat, Twitter, Viber, Kik, LINE, WeChat and Skype ship as their own crates too.

### Phase 3: Cloud & Media
- [ ] **Google Takeout:** `seance_plugin_google_takeout`.
- [ ] **Media:** `seance_plugin_android_media`.

### Phase 4: Advanced
- [ ] **APK Analysis:** `seance_plugin_apk_analysis`.
- [ ] **Digital Wellbeing:** `seance_plugin_digital_wellbeing`.

