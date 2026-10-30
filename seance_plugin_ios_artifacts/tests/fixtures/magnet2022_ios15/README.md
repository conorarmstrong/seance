# Magnet User Summit 2022 CTF — iPhone 8, iOS 15.0 (19A404)

The files are not committed, because their redistribution terms are not stated. Copy them
from the published extraction into the paths below to run `tests/magnet2022_ios15_test.rs`.
Without them every test prints one `SKIPPED (no fixture)` line and returns.

The real files are from the published GrayKey full-file-system extraction of the
Magnet User Summit 2022 CTF iPhone 8 (`Jess_CTF_iPhone8`, extraction id
`fb028ddefa8af7df5b12d3e729f075d150637a31`), byte for byte, with their `-wal`
siblings. Kevin Pagano's published write-up is the answer key; the counts the
tests assert were read from each file with `sqlite3` on a copy before the
parser was written.

| Here | On the device |
|------|---------------|
| `Library/Safari/Bookmarks.db` (+`-wal`, empty) | `/private/var/mobile/Library/Safari/Bookmarks.db` |
| `Library/Safari/SafariTabs.db` (+`-wal`, empty) | `/private/var/mobile/Library/Safari/SafariTabs.db` |
| `Library/Safari/BrowserState.db` (+`-wal`, 24,752 bytes) | `/private/var/mobile/Library/Safari/BrowserState.db` |
| `Library/Preferences/com.apple.mobilesafari.plist` | `/private/var/mobile/Containers/Data/Application/3AD031B2-D637-4B1A-AF0D-306A3BDCEE79/Library/Preferences/com.apple.mobilesafari.plist` |
| `Library/Health/healthdb_secure.sqlite` (+`-wal`, 3,197,152 bytes) | `/private/var/mobile/Library/Health/healthdb_secure.sqlite` |
| `Library/Health/healthdb.sqlite` (+`-wal`, empty) | `/private/var/mobile/Library/Health/healthdb.sqlite` |
| `Notes/NoteStore.sqlite` (+`-wal`, 984,712 bytes) | `/private/var/mobile/Containers/Shared/AppGroup/B7A0EA29-86E3-464A-B2A4-D4199FAD7FA5/NoteStore.sqlite` |
| `Media/PhotoData/Photos.sqlite` (+`-wal`, 94,792 bytes) | `/private/var/mobile/Media/PhotoData/Photos.sqlite` |
| `Library/Photos/Syndication/Photos.sqlite` (+`-wal`, empty) | `/private/var/mobile/Library/Photos/Libraries/Syndication.photoslibrary/database/Photos.sqlite` |
| `Library/Voicemail/voicemail.db` (no `-wal` on the device) | `/private/var/mobile/Library/Voicemail/voicemail.db` |
| `Library/Voicemail/A-90650135-26E7-5671-906A-A5D30473128E/voicemail.db` (no `-wal`) | `/private/var/mobile/Library/Voicemail/A-90650135-26E7-5671-906A-A5D30473128E/voicemail.db` |

The `-shm` files are not kept: they are a shared-memory index SQLite rebuilds.

The WAL files are staged by the parsers exactly as they would be on evidence.
Measured on this device (copies, with and without the `-wal`):

* HealthKit: the same 688 samples either way, so the Health tests do **not**
  pin WAL staging.
* Notes: the same 2 notes either way, but the body of note 9 ("East Woods
  Hike", 191 bytes of `ZICNOTEDATA.ZDATA`) is `NULL` in the main file and
  present only in the WAL — so the assertion on that body **does** pin WAL
  staging.
* `BrowserState.db`: `browser_windows` has 0 rows without the WAL and 2 with
  it, so the `windows == 2` assertion pins WAL staging and the summary must
  say the WAL was reached.

**Never open one of these with the `sqlite3` CLI in place**: opening a WAL-mode
database checkpoints it and deletes the `-wal`, and the fixture would then be
a different file. Copy first.

## What is here, exactly

19 files, 10,637,372 bytes. Each hash below was computed on the file and
matched against `unzip -p` of the archive entry named above; a
file that no longer matches is a different file and the tests' counts no
longer describe the device.

| File | Bytes | SHA-256 |
|------|------:|---------|
| `Library/Health/healthdb.sqlite` | 475,136 | `91b1ddd779dba9655feda1051726c64041ba1cfc8aa8e491ceea84c81e64ada6` |
| `Library/Health/healthdb.sqlite-wal` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `Library/Health/healthdb_secure.sqlite` | 1,482,752 | `1b4748da7d1bfa1301969416b19ecb4406ae856370552c43a563a9aedf60a680` |
| `Library/Health/healthdb_secure.sqlite-wal` | 3,197,152 | `02e53b87cdcda124b838296033ed980f8b13e324be562dcbb854dde860d10679` |
| `Library/Photos/Syndication/Photos.sqlite` | 1,773,568 | `6a30dec4a4ecf9f092f4373ebfec0a3cdd8486672a05f28d414501245330d0bb` |
| `Library/Photos/Syndication/Photos.sqlite-wal` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `Library/Preferences/com.apple.mobilesafari.plist` | 3,548 | `6870bfd69a42d06f1b71581cda617aa35690131c215e3f500e003d0f2c5c1772` |
| `Library/Safari/Bookmarks.db` | 106,496 | `5a61e909afb8ecdd6f949ba023e6f9b5555ea8db1433393ea28036a8562dc30e` |
| `Library/Safari/Bookmarks.db-wal` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `Library/Safari/BrowserState.db` | 40,960 | `f5333e974986323d64bb7c4329a15c8ef38be110afad193d57ac168765305893` |
| `Library/Safari/BrowserState.db-wal` | 24,752 | `9f9c9f6c458f2fbd34e947de9c2e6ac7081edbb0b89d4fc2f491f31bc5ce7e87` |
| `Library/Safari/SafariTabs.db` | 151,552 | `78c1da56c84679b0902f06a9a506aa379d9b0181c9f350ebae076b833bde6e31` |
| `Library/Safari/SafariTabs.db-wal` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `Media/PhotoData/Photos.sqlite` | 1,970,176 | `d15ccdc3563e6e14415336e80b839f6371e72b78b5916c8050b71cb1de2bc072` |
| `Media/PhotoData/Photos.sqlite-wal` | 94,792 | `f876d7295f05dc40165f75afdde0c309fd94f09470dd3431a1f27da8d55b1d2c` |
| `Notes/NoteStore.sqlite` | 270,336 | `e6cfa93c58d0d2f8afbae1d96d20d96b4da3fc5aaafbcfad2f71a9bddf12862d` |
| `Notes/NoteStore.sqlite-wal` | 984,712 | `54f4e00e7bf9aaaeb2271196ef4fdfeb5cb22f438b085d96e39325b2f12bc8c4` |
| `Library/Voicemail/voicemail.db` | 36,864 | `43b1b95b8b49a093b9deb3589ec4f3cf0b55c1264742314c2e29725cc4acc1c0` |
| `Library/Voicemail/A-90650135-26E7-5671-906A-A5D30473128E/voicemail.db` | 24,576 | `d0c958986c92519997482ae4714528747dc8ec56e8179ed5c7174eac5ccd98c3` |

The two voicemail stores are hashed against
`unzip -p` of the same archive entries. The top-level store carries
`voicemail`, `deleted` (the same twelve columns) and `map`, all with 0 rows;
the per-account store carries `voicemail` only, with 0 rows.

The root `.gitignore` keeps every file here out of git except this README. A test whose
fixture is absent prints one `SKIPPED (no fixture):` line naming the path and returns,
rather than failing as if the parser were wrong.
