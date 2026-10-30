# Linux Forensics Extension Design

**Target:** Linux Workstations & Servers (Debian/RHEL families)
**Architecture:** Modular Seance Plugins (implementing `ForensicsModule`)
**Status:** Partially Implemented. Shipped and registered in `seance_api::modules`: ext2/3/4, XFS, Btrfs, F2FS and SquashFS filesystem parsing; login accounting as `seance_plugin_utmp` (`utmp`/`wtmp`/`btmp`/`lastlog`, and Darwin's 628-byte `utmpx`, so the crate is not Linux-only; see `MACOS_DESIGN.md`); shell history, Freedesktop Trash, GTK recent files and thumbnails as `seance_plugin_desktop_artifacts`; LUKS1/LUKS2 unlocking as `seance_plugin_luks`; the twelve-stage native memory tier `seance_plugin_memory_linux`, including network sockets, hidden-process/hidden-module cross-views, mount-crossing paths, process command lines and the kernel-hook stage, with swap attachment. Design-only: the log/journal, persistence, container and eBPF plugins below.

This document outlines the architecture for extending Seance with comprehensive Linux forensics capabilities. It maps functional requirements to specific Seance plugins, defining their inputs (`ArtifactType`), data access patterns (`InputCapability`), and outputs.

---

## 1. Core Filesystem Support

### `seance_plugin_ext4` (In Progress)
**Responsibility:** Low-level parsing of Ext2/3/4 filesystems.
- **Subscribes To:** `ArtifactType::FileSystem` (accepts `filesystem_type`/subtype `ext2`, `ext3`, or `ext4`, case-insensitively).
- **Input Capability:** `InputCapability::RandomAccess` (uses `DataSource::read_at`)
- **Output:** `ArtifactType::FileEntry` (with `FileMetadata` JSON), two `ParsedRecord`s
  (`allocation_map` and `ext4_journal`), and one `ArtifactType::UnallocatedSpace` per free
  run of block-bitmap blocks (§5.4). **No `TimelineEvent`.** The free regions are graded on a real 67 GB volume.
  Also one `ArtifactType::SlackSpace` per live regular file whose last block's tail holds
  a non-zero byte (offered once per inode) and one `slack_space_summary` `ParsedRecord`; graded on
  a synthetic 2 MiB `mke2fs` volume with planted tails (`seance_plugin_ext4/tests/real_slack_test.rs`), not
  on a case volume.
- **Features:**
    - [x] Superblock parsing (magic `0xEF53`, 64-bit feature)
    - [x] Block Group Descriptor parsing
    - [x] Inode & Directory traversal (recursive, with cycle/depth guards)
    - [x] Extent Tree traversal for ext4 large files
    - [x] Indirect block mapping for ext2/ext3 (direct + single/double/triple indirect, sparse-aware)
    - [x] Indirect-block-aware **carving** of ext2/ext3 free space (`seance_carving::ext2_indirect`): where the superblock or inode is gone and a file is found only by carving, a
      carve across the IND/DIND pointer blocks written in line with the content is rebuilt
      without them once every pointer entry is verified against the in-line layout, and served
      as `data_runs`. Single and double indirect only (no TIND); content the pointers place
      elsewhere is not followed. Graded on DFTT #12, 10/10 byte-exact (`VALIDATION.md` `DFTT-12`).
    - [x] Timestamp decoding (a/m/c/dtime + ext4 extended nanosecond timestamps)
    - [x] Deleted-inode detection/recovery (via `dtime`/`links_count`), reached two ways: the
      directory slack the kernel hides a deleted entry in — each live entry's bytes between its
      real end and its `rec_len` are walked for the names deleted from that directory
      — **and** an entry the kernel leaves standing in the live chain with its
      inode number zeroed but its name intact, which is not inside any neighbour's slack and
      is found by a separate check. A hidden name whose inode has been
      reallocated is reported as deleted with `inode_reused` and `content_incomplete`, never as
      that inode's current content; an inode-zeroed name is reported name-only with
      `metadata_unavailable`, since nothing about its size, times or content is reachable.
    - [x] Journal (JBD2) analysis — enumerates committed transactions + the fs blocks they touched (and revoked blocks) as an `ext4_journal` record
    - [x] Extended Attributes (xattrs) — in-inode and `i_file_acl` block, exposed on FileEntry metadata (base64 for binary values)
    - [x] Deleted-directory *content* recovery — an
      unallocated-space pass recognises an orphaned directory's own first block by content (a
      `.`/`..`-opening `ext4_dir_entry_2` chain whose `rec_len` fields tile the block exactly)
      and resolves each name it recovers only when the named inode still agrees with it in type
      and carries its own deletion marker; a reused or unreadable inode is reported as an
      orphaned name with no content attached, never merged into the live listing. Scoped to a
      directory's first block — an htree leaf or a later block has no `.`/`..` anchor for a safe
      content-only test.

- **Walk honesty and refusals:** a root inode that will not read, is
  unallocated (mode 0) or is not a directory publishes an `ext4_root_status` `ParsedRecord`
  (`root_inode_readable: false`, `root_inode_error`, `inventory_incomplete`) instead of an empty-looking
  volume. A live directory entry whose inode cannot be resolved (read error, out of range, mode 0), or whose
  name holds a `/` or NUL (recorded percent-escaped with `name_invalid`), is published name-only
  (`metadata_unavailable`, `content_incomplete`, inode number kept); a dirent chain that stops on a corrupt
  `rec_len` or a name running past the block, and a subtree beyond the recursion cap, mark the directory
  `directory_parse_incomplete` with `directory_parse_incomplete_reason` (`unresolved_structure` or
  `cap_reached`) and `directory_entries_unresolved`. A file whose extent or indirect-block structure cannot be
  read carries `data_runs_error` and `content_incomplete`. A slack name is never descended (its inode may now be a
  live directory linked elsewhere); a slack name whose inode yields no record, and a deleted-directory slack
  name, are recorded name-only with the inode number. **Inline-data inodes are read:** a regular file is served from `i_block` followed by the
  `system.data` xattr, cut to `i_size` (`inline_data_bytes_in_inode`, `inline_data_bytes_in_xattr`, no
  `data_runs`; `content_incomplete` where the bytes fall short); an inline directory's entries come from both
  regions and a real gap stamps `directory_parse_incomplete`. A deleted inline inode's data lies in the freed inode
  body and is not recovered. **Bigalloc volumes are mapped** per cluster: a free region starts and ends on a
  cluster boundary and a partly used cluster is in use; only a volume whose cluster fields disagree with its block
  fields gets an `ext4_free_space_status` record. **BLOCK_UNINIT groups** have their bitmap derived the way
  libext2fs and the kernel derive it (backup superblock and descriptors, plus the block bitmap, inode bitmap and
  inode table of every such group), stated on the map as derived; group 0, a META_BG group with descriptor duties
  and a location outside the volume leave every such group unassessed, never free. **Refused, and said:** a JBD2
  block size that differs from the filesystem's, and an `s_inode_size` that is not a power of two between 128 and
  the block size (revision-0 volumes are 128-byte inodes). A live dirent whose `rec_len` is not a multiple of
  four, is too small for its name or leaves its block ends that block's read and stamps the directory; a
  `file_type` that disagrees with the inode is kept and marked; a directory reached twice carries
  `duplicate_directory_visit`; a cancelled walk leaves an `ext4_walk_status` record. META_BG
  honours `s_first_meta_bg`; JBD2 CSUM_V2 tags are 10/14 bytes. An extent tree that names a block twice, or
  exceeds 65,536 blocks or 1,048,576 extents, is refused; the allocation map is bounded by the image size as
  well as the descriptors. Pinned in `seance_plugin_ext4/src/tests.rs`.

### `seance_plugin_xfs` / `seance_plugin_btrfs`
**Responsibility:** Parsing the XFS and Btrfs filesystems (shipped alongside ext4).
- **Subscribes To:** `ArtifactType::FileSystem`.
- **Output:** `ArtifactType::FileEntry`, and (XFS) a `FileSystem` record for the volume.
- **XFS deleted entries:** a name removed from a block or leaf
  directory survives in the free region that replaced it and is published as a deleted
  `FileEntry` (`deleted_recovery_source: xfs_directory_free_space`), joined to its freed
  inode's owner and times; every inode the inode B+tree marks free whose core still carries
  a timestamp, and that no recovered name reports, is published nameless
  (`xfs_freed_inode`). No content is attached — Linux 6.8 zeroes a freed inode's size,
  extent count and data fork — and a name removed from a shortform directory is not
  recoverable (the kernel compacts the inline list). Graded on a real volume in
  `seance_plugin_xfs/tests/real_deleted_volume_test.rs`. A root inode that will not read
  sets `inventory_incomplete` on the `FileSystem` record.
- **XFS single-block directories:** the entries of an `XDB3`/`XD2B`
  block are scanned only up to the leaf array whose start the block tail's leaf count gives;
  a free region whose length runs past it no longer walks into the leaf array and reads
  hash/address pairs as an entry. A block whose tail gives no usable bound is scanned without
  one and the directory marked `directory_parse_incomplete`.

### `seance_plugin_linux_fs_analysis`
**Responsibility:** Heuristic analysis of the filesystem structure.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Input Capability:** `InputCapability::Stream` (metadata check only)
- **Output:** `ArtifactType::TimelineEvent`, `ArtifactType::RiskIndicator`
- **Features:**
    - **SUID/SGID Scanner:** Flag files with mode 4000/2000.
    - **Hidden File Detector:** Flag `.` files outside user config dirs or with space prefixes.
    - **World Writable Scan:** Flag executables in `/tmp`, `/var/tmp`, `/dev/shm`.
    - **Binary Planting:** Compare `/usr/bin` modification times vs OS install time.

---

## 2. System Configuration & Identity

### `seance_plugin_host_identity`
**Responsibility:** The host's own identity — "whose machine is this?"
- **Subscribes To:** `ArtifactType::FileEntry` / `FileContent`, matched on **path**, not name
- **Input Capability:** `InputCapability::RandomAccess`
- **Output:** `ParsedRecord` of type `HostDeviceInfo`, one per identity file, in the same
  `facts` / `fact_sources` shape the Android property records use, so
  `GET /cases/{id}/device_info` folds all three platforms and the System Info screen renders a
  "Linux machine" card beside any phone cards
- **Files read:**
    - `/etc/os-release`, `/usr/lib/os-release` — `os_name`, `os_version`, `version_id`,
      `codename`, `os_id`, `os_like`, `pretty_name`, `build_id`, `variant`
    - `/etc/lsb-release` — the same facts under `DISTRIB_*` keys (`DISTRIB_ID` is the
      vendor name, so it is read as `os_name`, not as `os-release`'s lower-case `ID`)
    - `/etc/hostname` — `host_name`
    - `/etc/machine-id`, `/var/lib/dbus/machine-id` — `machine_id`, only when the content is
      32 hex characters
    - `/etc/timezone` — `timezone`, only when the content names a zone
    - `/etc/passwd` — `user_account`, uid 0 and uid ≥ 1000 excluding `nobody`, each with its
      uid, home directory and shell; every line is counted and a malformed line is counted as
      unparsed, never dropped
- **Rules:**
    - Matched by path so that a script or manual page merely *named* `hostname` never states
      what the machine is called.
    - Nothing is reconciled: `/etc/os-release` is usually a symlink to `/usr/lib/os-release`,
      and where they differ both readings are shown with their files.
    - A file matched by path but acquired only in part is recorded as read-in-part, so a
      truncated `/etc/hostname` does not read as a machine with no name.

### `seance_plugin_linux_config` (planned — the rest of §2)
**Responsibility:** Parsing the remaining system configuration files.
- **Subscribes To:** `ArtifactType::FileEntry` (matching specific paths)
- **Input Capability:** `InputCapability::Stream` (read file content)
- **Output:** `ArtifactType::SystemArtifact` (SystemInfo, UserAccount, NetworkConfig)
- **Target Files:** (the identity files above are covered by
  `seance_plugin_host_identity`; what is left here is the configuration around them)
    - `/etc/issue` (login banner)
    - `/etc/group` (group membership)
    - `/etc/hosts`, `/etc/resolv.conf` (Network config)
- **Analysis Logic:**
    - Flag UID 0 users that are not 'root'.
    - List `sudo` / `wheel` group members.
    - Detect rogue DNS entries.

---

## 3. Log Analysis

### `seance_plugin_linux_logs`
**Responsibility:** Parsing text-based and binary system logs.
- **Subscribes To:** `ArtifactType::FileEntry` (log files)
- **Input Capability:** `InputCapability::Stream` (supports `SourceCursor` for GZIP)
- **Output:** `ArtifactType::TimelineEvent` (standardized schema)
- **Target Files:**
    - **Auth Logs:** `/var/log/auth.log`, `/var/log/secure`
        - *Regex:* `Accepted publickey`, `Failed password`, `sudo: session opened`
    - **System Logs:** `/var/log/syslog`, `/var/log/messages`, `/var/log/dmesg`
        - *Regex:* `segfault`, `promiscuous mode`, `USB disconnect`
    - **Binary Logs:** `/var/log/wtmp` (Login History), `/var/log/btmp` (Failed Logins)
    - **Package Logs:** `/var/log/dpkg.log`, `/var/log/yum.log`
- **Technical Requirement:** Transparent GZIP decompression for rotated logs (`.log.gz`).
  *What the shipped expanders do today, which this plugin would inherit:*
  `container.gzip_expander` and `container.bzip2_expander` expand **every member** of a
  concatenated stream (`gzip -c >> file.gz`, `cat a.gz b.gz`, a multi-stream `.bz2`) and
  record bytes after the last member that do not begin another as undecoded.
  A `.tar` member's size honours its PAX `size` record. `Container_Formats.md` has the detail.

### `seance_plugin_systemd_journal`
**Responsibility:** Parsing binary Systemd Journal files.
- **Subscribes To:** `ArtifactType::FileEntry` (`/var/log/journal/*`)
- **Input Capability:** `InputCapability::RandomAccess` (complex binary format)
- **Output:** `ArtifactType::TimelineEvent`
- **Note:** Requires specialized binary parser (different from text logs).

### Login accounting (utmp, wtmp, btmp, lastlog)

`seance_plugin_utmp` (`plugin.linux.utmp`) reads the fixed-record login logs. It
subscribes to `FileEntry`, `FileContent` and `SystemArtifact` and selects on
content. The filename supplies only the role, because the three `struct utmp`
files share one format and nothing in a record says that an attempt failed.

| File | Holds |
|------|-------|
| `/var/run/utmp` | Sessions open at acquisition |
| `/var/log/wtmp` | Login and logout history, boots, shutdowns, clock changes |
| `/var/log/btmp` | Failed login attempts |
| `/var/log/lastlog` | One record per UID, indexed by UID, the last successful login |

The same decoder reads macOS `utmpx`, which has its own layout and `ut_type`
enumeration. `documentation/MACOS_DESIGN.md` covers that file.

**Entry layout.** The files have no magic number. The layout is found from the
bytes, and a layout that cannot be confirmed is refused.

| Field | glibc, 384 bytes | musl, 400 bytes |
|-------|------------------|-----------------|
| `ut_type`, u16 | 0 | 0 |
| `ut_pid`, i32 | 4 | 4 |
| `ut_line`, 32 bytes | 8 | 8 |
| `ut_id`, 4 bytes | 40 | 40 |
| `ut_user`, 32 bytes | 44 | 44 |
| `ut_host`, 256 bytes | 76 | 76 |
| `ut_session`, i32 | 336 | 336 little-endian, 340 big-endian |
| `ut_tv.tv_sec` | 340, 4 bytes | 344, 8 bytes |
| `ut_tv.tv_usec` | 344, 4 bytes | 352, 8 byte slot |
| `ut_addr_v6`, 16 bytes | 348 | 360 |
| reserved, 20 bytes, zero | 364 | 376 |

glibc fixes `ut_session` and both time members at 32 bits, so 32-bit and 64-bit
glibc builds write identical records. musl keeps a 64-bit `tv_sec`, which moves
the tail by 16 bytes. The 4 bytes at 332 hold `ut_exit` and are not decoded.
`ut_addr_v6` is in network byte order whatever the host byte order. All zero
means no remote address and no `ip` field. Only the first word set means IPv4.
Anything else is IPv6. Text fields are printable ASCII followed only by NULs, and
the value kept is the printable prefix.

`lastlog` has two layouts. The 292-byte form holds `ll_time` as a 32-bit value
at 0, `ll_line` at 4 for 32 bytes and `ll_host` at 36 for 256 bytes. The 28-byte
legacy form holds the time at 0, `ll_line` at 4 for 8 bytes and `ll_host` at 12
for 16 bytes. The UID is the record's index, and the record holds no username.

**Detection.** The first 64 KiB is sampled. Each known layout is tried in both
byte orders over up to 64 records. All-zero records are padding and do not count.
A candidate is accepted with at least 2 sane records and 70 percent sane. A file
whose size is not a whole number of records is tried only on a second pass, which
needs 4 sane records and 90 percent, and the leftover bytes are reported as
`trailing_partial_bytes`. The best score wins and a tie keeps the fixed order.
`lastlog` is considered only when the name contains `lastlog`. It needs one valid
record and 70 percent of the non-empty sample. When the whole sample is zero the
stride follows from name and size alone and the status record says
`layout_unconfirmed`. A record is anomalous, and still emitted with
`record_anomaly`, when any of these hold:

- `ut_type` is outside 1 to 8.
- `ut_pid` is negative.
- A text field is not clean, or the reserved trailer is not zero.
- `tv_sec` is outside 1980-01-01 to 2106-02-07, the unsigned 32-bit range.
- `tv_usec` is above 999,999.

**Role.** The lower-cased basename is tested in the order `lastlog`, `btmp`,
`wtmp`, `utmp`, and a rotation suffix such as `wtmp.1` still matches. A
structurally valid file with no recognised name is read as `wtmp` and carries a
`role_note`. It is never promoted to failed logins, because that would make an
intrusion signal out of a filename the evidence does not have.

**Record types.** `ut_type` is read against the Linux enumeration: 1 `RUN_LVL`, 2
`BOOT_TIME`, 3 `NEW_TIME`, 4 `OLD_TIME`, 5 `INIT_PROCESS`, 6 `LOGIN_PROCESS`, 7
`USER_PROCESS`, 8 `DEAD_PROCESS`. A record is then classified the way `last`
does:

- Line `~` with user `reboot` is a boot. User `shutdown` is a shutdown. User
  `runlevel` is a run-level change, and level 0 or 6 counts as a shutdown. The
  levels are the low two bytes of `ut_pid`.
- User `date` on line `{` is a clock change to the new time. On line `|` it is the
  old time. Types 3 and 4 give the same result.
- An empty user on a terminal is a logout whatever the type says.
- A non-empty user other than `LOGIN` is a login, even when the writer left the
  type at `INIT_PROCESS`. Reading the type literally would drop real history.
- Anything else, such as an idle getty, is counted as bookkeeping and produces
  no record.

**Sessions.** Pairing is by terminal line, in file order. A logout closes the open
session on its line as `logged_out`, with a duration only when both times are
usable and the logout is not earlier. A login on a line that already has an open
session closes the older one as `gone_no_logout`, `closed_by` `superseded_by_new_login`.
A boot or shutdown closes every open session the same way, with `closed_by`
`boot` or `shutdown`. For those two the later time is `bounded_before_time`, an
upper bound, and `max_duration_seconds` is derived from it. No `logout_time` is
invented, because `last` prints a duration for these and the file does not hold
one. A session open at the end of the file is `still_logged_in`. A logout with no
open session is counted as `unpaired_logouts`, which is normal at the head of a
rotated `wtmp`.

**Failed logins.** A `btmp` is never paired into sessions, because pairing would
assert that a login succeeded. Each login-kind record becomes a `FailedLogin`
with user, terminal, host, `ip`, pid and time, and its timeline row reads `Failed
login`. Boot and clock records found in it are kept. A logout record is counted
as an unpaired logout. A failed attempt is not tied to any later success.

**Clock changes.** A clock change becomes a `BootEvent` with kind
`clock_change_new` or `clock_change_old` and a `Clock change` timeline row. It
closes no session. No timestamp is corrected. Pairing and durations use the times
as written, so a session that spans a clock change has a duration that mixes two
clocks. The parser does not flag it.

**Time.** Times are UTC Unix seconds as the kernel wrote them, with no zone
conversion. A time outside the plausible window gives the record no timeline row.
The record carries `login_time_unusable` and the raw value, never 1970. The
32-bit field is read unsigned, so a system running past 2038 reads as 2038 to 2106
and not as 1901.

**Output.** `LoginSession`, `FailedLogin`, `BootEvent`, `LastLogin` and one
`UtmpParseStatus` per file, plus a `TimelineEvent` for each dated record. Every
record carries the layout name, byte order, role and whether the role came from
the filename. The status record holds counts of decoded, empty and anomalous
records, sessions, unpaired logouts and bookkeeping records. A `lastlog` record
with an all-zero body means the UID never logged in and produces nothing.

**Refusals and caps.** A file is refused when it is empty, smaller than one record,
not a whole number of records of a known layout, entirely zero, or unable to pass
the sanity filter. Only a file whose name claims login accounting gets a
`UtmpParseStatus` with `detected` false, a `failure_reason` and a message that
absence of records is not evidence that no logins occurred. A zeroed `wtmp` keeps
that record. A named file that holds only printable text is not claimed. A named
file with no data source is reported as unreadable. The caps are 256 MiB read, 1,000,000
records and 200,000 sessions per file, and 5,000,000 UID slots walked and
200,000 records emitted for `lastlog`, which is streamed 512 records at a time.
A cap or a short read stamps `content_incomplete` on every record from the file.

**What is not derived.** Account names for `lastlog` UIDs are not resolved,
because that needs `/etc/passwd`, and `user` is null. A `lastlog` host is a source
IP only when the text is an IP literal. Hostnames are never resolved. `ut_exit`
is not read. A logout is never inferred for a session a reboot ended. Log files
that were rotated away, truncated or wiped are not reconstructed, and an absent
login is not shown to be absent from the machine.

---

## 4. User Activity & Persistence

### `seance_plugin_linux_user_activity`
**Responsibility:** Extracting user actions and history.
- **Subscribes To:** `ArtifactType::FileEntry` (user home directories)
- **Input Capability:** `InputCapability::Stream`
- **Output:** `ArtifactType::TimelineEvent`, `ArtifactType::ParsedRecord`
- **Target Artifacts:**
    - **Shell History:** `.bash_history`, `.zsh_history`
        - *Keywords:* `rm -rf`, `wget`, `curl`, `nc`, `chmod +x`
    - **SSH Artifacts:** `~/.ssh/authorized_keys`, `~/.ssh/known_hosts`
    - **Editor History:** `~/.viminfo`
    - **Desktop:** `~/.local/share/recently-used.xbel`, `~/.local/share/Trash/`

### `seance_plugin_linux_persistence`
**Responsibility:** Detecting mechanisms used to maintain access.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Input Capability:** `InputCapability::Stream`
- **Output:** `ArtifactType::ParsedRecord` (PersistenceMechanism), `ArtifactType::TimelineEvent`
- **Target Mechanisms:**
    - **Cron:** `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/crontabs/`
    - **Systemd Services:** `/etc/systemd/system/*.service` (Parse `ExecStart`)
    - **Shell Profiles:** `~/.bashrc`, `/etc/profile`
    - **RC Scripts:** `/etc/rc.local`, `/etc/init.d/`

---

## 5. Web Server Forensics (Optional)

### `seance_plugin_web_server`
**Responsibility:** Analyzing web server logs and content.
- **Subscribes To:** `ArtifactType::FileEntry`
- **Input Capability:** `InputCapability::Stream`
- **Output:** `ArtifactType::TimelineEvent`, `ArtifactType::RiskIndicator`
- **Targets:**
    - **Content:** `/var/www/html/` (Scan for `eval()`, `base64_decode`)
    - **Logs:** `/var/log/apache2/access.log`, `/var/log/nginx/access.log`

---

## 6. Enterprise & Commercial Features (Advanced)

To rival commercial tools (EnCase, Axiom, X-Ways), the following advanced capabilities are proposed:

### `seance_plugin_container_forensics`
**Responsibility:** Analysis of Docker/Kubernetes environments.
- **Subscribes To:** `ArtifactType::FileEntry` (`/var/lib/docker/*`, `/var/log/pods/*`)
- **Features:**
    - **OverlayFS Reconstruction:** Reassemble container filesystems from layers.
    - **Container Config Parsing:** `config.v2.json`, `hostconfig.json` (Network, Mounts, Env Vars).
    - **Container Logs:** Parse JSON-file and journald logging drivers.
    - **Kubernetes Artifacts:** Parse kubelet logs and pod manifests.

### ~~`seance_plugin_memory_integration`~~ — superseded by `seance_plugin_memory_linux`

**This design was not built, and should not be.** It proposed shelling out to Volatility 3.
What shipped instead is a native tier, `seance_plugin_memory_linux`, registered in
`seance_api::modules`. It matches Volatility 3's own row counts on a real Debian 7 capture
(`tests/parity_linux.rs`): pslist 133, lsmod 79, bash 27, envars 1402.

**Twelve stages** (`module::STAGES`, published with every analysis as a stage manifest so
the case records what this build could have run):

| Stage | Module | What an examiner gets |
|---|---|---|
| `linux_processes` | `tasks` | Every process on the kernel's task list, walked from `init_task`, corroborated against an independent physical sweep |
| `linux_capabilities` | `capabilities` | Each process's capability sets (effective, permitted, inheritable, bounding, ambient), decoded to named capabilities |
| `linux_kernel_modules` | `lsmod` | Every loaded kernel module, walked from the `modules` list head, corroborated against an independent physical sweep |
| `linux_kernel_log` | `kernel_log` | The kernel log ring (`dmesg`) still resident in memory — priority, facility, timestamp, message |
| `linux_kernel_hooks` | `hooks` | The system-call tables, every `ftrace` registration and direct call, every kprobe and every loaded eBPF program, each attributed to the kernel's text, a named module, or nothing known — with what could not be checked named under `not_checked` |
| `linux_process_maps` | `proc_maps` | Each process's VMAs — range, permissions, backing file with its **mount-crossing path** and per-record `path_scope` — from `mm_struct.mmap` or the 6.1+ maple tree |
| `linux_open_files` | `lsof` | Each process's open descriptors — number, mount-crossing path or the pseudo-file forms `socket:[inode]` / `pipe:[inode]` / `anon_inode:<name>`, mode, flags |
| `linux_network_sockets` | `sockstat` | Each process's sockets — family, type, protocol, state, and for IPv4 source/destination address and port |
| `linux_mounts` | `mounts` | Filesystems mounted per namespace — device, **absolute** mount point (e.g. `/dev/pts`, walked through the parent mounts rather than the mount's own root), filesystem root, decoded flags |
| `linux_command_lines` | `cmdline` | Each process's argument vector, read from the bracket `mm_struct.arg_start`/`arg_end` names through that process's own page tables |
| `linux_bash_history` | `bash` | Commands typed into a shell, recovered from the shell's own heap |
| `linux_environment` | `envars` | Each process's environment, read from that process's own user memory |

Every structure member it reads is declared as a `seance_memory::binding::MemberSet` rather
than by a hardcoded name, so a kernel that spells a member differently is answered rather
than failed. See `documentation/MEMORY_BUILD_BINDING.md`.

**Hidden-process and hidden-module detection ship.** `taskscan` and `modscan` are second,
independent ways of finding processes and modules — scanning physical memory for the
structures themselves rather than following anybody's pointers to them — precisely because
unlinking a `task_struct` or a `struct module` from its list is the standard way of hiding
on Linux, and a correct list walk cannot reveal an entry removed from the list. Both use
structural criteria the kernel enforces (`enum module_state` has four legal values and is
the first member of `struct module`; `comm` is at most 15 printable bytes), not statistical
ones, because a fabricated process in front of an examiner is as costly as a missed one.
The two views are compared and the comparison is published: "checked and agreed" and "not
checked" must never render the same.

#### Paths, pseudo-files, command lines and hooks

Each of the four is stated here with the bound the code publishes, because the record an
examiner reads is only as good as the sentence beside it.

**Mount-crossing paths, with the scope on every record.** `paths.rs` implements the
kernel's own `prepend_path`: from `file.f_path.{dentry,mnt}` it climbs `d_parent` to the
mount's root, steps across `mnt_mountpoint` into `mnt_parent` (`struct mount` through the
container offset of `mount.mnt` on 3.3+, or the `vfsmount` itself before 3.3 — both shapes
bound by ordered candidates), and stops at the process's own root (`task->fs->root`) or at
the global root. The open-files, memory-map and mount stages all use it. Every record
carries `path_scope` — `mount_crossing` (with the number of mounts crossed and where the
walk ended: the process root, the global root, a disconnected dentry, or the depth bound),
`dentry_tree_relative` (the reduced in-mount walk, with the reason the crossing walk could
not be made for *this* record: `f_path.mnt`, the mount chain or `fs_struct` would not
read), or `pseudo` — and each process row carries its root. A chain that fails midway
yields the partial path with the reason, never a path presented as whole. On the real
5.15 lab capture PID 1's descriptors 0–2 read `/dev/null` (one mount crossed, ended at the
process root), `journald`'s map reads
`/run/systemd/journal/kernel-seqnum`, every crossing path begins with a mount point the
mount list — a different structure — independently knows, and the mount list shows
`/dev/pts`; all asserted by `tests/paths_real_capture_test.rs`.

**Pseudo-files have their own scope, because no walk is made for them.** A dentry whose
`d_op->d_dname` is `sockfs_dname`, `pipefs_dname` or `anon_inodefs_dname` renders as
`socket:[ino]`, `pipe:[ino]` or `anon_inode:<name>` (the kernel's own forms), typed by
`path_kind`, and carries `path_scope: pseudo` naming the `d_dname` function that decided
the form. Any other `d_dname` (a namespace file, for one) is
reported by symbol name with the raw dentry walk beside it (`path_kind:
pseudo_unresolved`), never as a file.

**Command lines: the bracket, and a short read is a short read.** `linux_command_lines`
reads `mm_struct.arg_start..arg_end` through the process's page tables, splits at NUL
keeping empty middle arguments, refuses a bracket over 4,096 bytes with the number
(`MAX_COMMAND_LINE_BYTES`, the same ceiling Volatility's `psaux` applies), keeps kernel
threads as non-gaps (they have no user address space, which is a fact about the machine and
is excluded from the stage's incompleteness), and reports a partial read as a floor. A
bracket whose last byte is not NUL is the mark of a process that rewrote its argument area
(`setproctitle`, as `sshd` and `postgres` do); that flag, `argv_rewritten`, is set **only
when the whole bracket was read**. A bracket the acquisition cut short is `argv_short_read`
with the missing byte count, and a run cut mid-argument is `last_argument_cut` — a missing
page is never reported as a rewrite. The stage reads the bracket only and does not read on into the environment
area as `/proc/<pid>/cmdline` would. On the 5.15 capture the workload reads
`["/usr/bin/python3", "/tmp/swaptest.py"]`, whose NUL-joined bytes a raw scan of `mem.raw`
finds independently, and all 19 tasks with user memory yield a command line with the survey
complete.

**Kernel hooks: four cross-views, and what each does NOT check.** `linux_kernel_hooks`
(`LinuxMemoryKernelHooks`) reads what the kernel *registered* and attributes each address
through a `CodeMap` — `_stext.._etext` and every module's text extent (from `core_layout`,
or on 6.4+ from `module.mem[MOD_TEXT]`: the region the module stage decoded through the
symbol table's own `mod_mem_type`, or, when the table carries no such enumeration, `mem[0]`
read by this stage with the `MOD_TEXT` index it assumed stated) — whose limitations are
published on the record:

* `sys_call_table` (+ `ia32_sys_call_table` / `x32_sys_call_table` when declared), sized by
  the next symbol; every entry attributed to kernel text (nearest symbol + offset), a named
  module's extent, or nothing (a candidate); trailing nulls reported as padding; the
  `x64_sys_call` switch-dispatch caveat stated where that symbol exists (it does on the
  5.15 capture, a BHI backport).
* `ftrace_ops_list` walked to `ftrace_list_end` with callback attribution and decoded flags
  (`IPMODIFY` and `DIRECT` called out), the filter and notrace hashes walked **bucket by
  bucket** — Volatility 3's `tracing.ftrace` reads only bucket 0 of an `ftrace_hash`, so its
  filter lists are not a parity target — an empty filter on an enabled ops stated as "every
  function", trampolines attributed, and `direct_functions` read as (function, target) pairs.
* `kprobe_table` (64 buckets, the size assumed and stated) with the probed address and
  pre/post handler attribution. A probe whose handlers both read as zero is labelled
  `kernel_handlers` vacuously; not exercised on either stock capture.
* `prog_idr` walked as the 4.20+ xarray (the radix tree and the layered IDR before it are
  refused by name): id, name, type (from the symbol table's enum where it has one, else the
  UAPI table — the source stated on every row), tag, `len`, `jited_len`, `bpf_func`,
  `attach_func_name`, load time, with `aux->id` cross-checked against the registry index;
  direct calls are read against the programs' attach targets and reported as
  `explained_by_bpf_program`, `module_direct_call` or `unexplained`.

What it does **not** do, each stated on the record rather than left to be inferred: it does
not diff kernel text against a pristine copy, does not walk perf events to tie a `KPROBE`
program to its probe (the counts are published side by side with that caveat), does not
walk the `dyn_ftrace` patch records, and does not decode BPF trampolines to name the program
behind a direct call — a direct call is explained only when a listed program names that
function as its attach target. A check whose symbol or member is absent, or whose bytes
would not read, is listed under `not_checked` by name — never as "no hooks". On both stock
lab guests every check runs complete with 0 candidates: 5.15 = 449 kernel-symbol entries
(the kernel's `__NR_syscalls`) + 3 padding nulls, 6.8 = 462 + 2; 12 (5.15) and 13 (6.8)
eBPF programs with `aux->id` equal to the registry index, named on 6.8 as systemd's own
`sd_devices` / `sd_fw_egress` / `sd_fw_ingress` and the kernel's `hid_tail_call` TRACING
program, which explains the one direct call there. The real-capture tests
(`tests/hooks_real_capture_test.rs`) assert those exact counts (the syscall counts are the
kernels' own `__NR_syscalls`; the padding, the program counts and the four names are
regression pins read from the captures on the stage's first run), a `CGROUP_` type among
the programs, 0 unexplained direct calls and the module-extent geometry; on 6.8 they also
assert that every program's type is named from the image's own `bpf_prog_type` and that no
`MOD_TEXT` index was assumed.

**Enumerations and `module.mem[]`.** An image-derived symbol
table carries the kernel's enumerations: `seance_memory::btf_isf` emits every named BTF
`ENUM`/`ENUM64` that has constants into the ISF `enums` section, with the base type its
width and sign call for, and types each member by it — so `module_state`, `mod_mem_type` and
`bpf_prog_type` names resolve on a BTF-derived profile, and a 1-byte or 8-byte enumeration
member is read at its own width rather than as a 4-byte `int`. Not emitted, with the member
read at its width and sign but without names: an anonymous enumeration, a forward
declaration with no constants, and a name two different enumerations share (Ubuntu's 6.8
BTF declares `energy_perf_value_index` twice), which is emitted for neither.
`tests/btf_symboltable_test.rs` grades the section against a kernel-written BTF blob, with
the sign, width and 64-bit values checked against `bpftool btf dump`.

`lsmod` decodes `module.mem[]` on 6.4+ through the table's `mod_mem_type`: every region is
published under `memory` by its constant's name with its base and size; `core_base` is
`mem[MOD_TEXT].base`, `core_size` the sum of the regions not named `MOD_INIT_*` and
`init_size` the sum of those that are (the kernel zeroes the init regions once a module's
init returns, so a loaded module reads 0 there) — the meaning Volatility's `linux.lsmod`
gives the columns on 6.4+. The regions are separate allocations, so `core_base` +
`core_size` is not an extent; the hook stage's code map takes the `MOD_TEXT` region itself.
A sum is published only when every region in it read. With no `mod_mem_type` in the table
the array is not decoded and the row says so. `tests/lsmod_real_capture_test.rs` asserts on
both lab guests that `autofs4` — the one module load each guest's serial console records by
name — is listed, that every module's state is named `MODULE_STATE_LIVE`, and on 6.8 that
every module's sizes are decoded, with the `struct module` lying outside its `MOD_TEXT`
region. No `lsmod` listing was taken inside either guest, so the list is not graded for
completeness against one.

**ARM64.** The translation core in `seance_memory` walks VMSAv8-64 tables: 4, 16 and 64 KiB granules, TTBR0/TTBR1 regimes, 25-48-bit VA. Three real arm64 Linux kernels are graded on QEMU-captured guests: a Debian 4.19 4 KiB kernel, a Debian 6.12 16 KiB kernel and an Ubuntu 6.8 64 KiB kernel (`VALIDATION.md` `MEM-ARM-1` to `MEM-ARM-7`). No hardware capture is validated. See `MEMORY_BUILD_BINDING.md`.

**ARM64 discovery.** `discovery::PAGING_MODES` offers the two Intel depths and seven arm64 kernel
(TTBR1) regimes — 4 KiB at 48 and 39 bits, 64 KiB at 48 and 42, 16 KiB at 47, 48 and 36, the
`ARM64_VA_BITS` choices Linux builds without 52-bit — to the same banner proof, which holds
for arm64 unchanged because `linux_banner` and `swapper_pg_dir` both sit in the kernel image
mapping, so one shift (`kimage_voffset`) derives the root from the symbol. Which family is
offered is settled by the symbol table: `kimage_voffset` means arm64 only, `phys_base` /
`init_top_pgt` / `init_level4_pgt` mean Intel only. That is required, not a shortcut: a
simple arm64 4 KiB / 48-bit hierarchy is also a valid x86-64 four-level one, and from Linux
5.4 the arm64 kernel image sits at an x86-64-canonical address, so an Intel walk can "prove"
an arm64 image (pinned in
`an_arm64_4k_48_bit_kernel_is_proved_by_the_banner_walk_and_not_assumed`). With neither,
both families are tried and the image's `VMCOREINFO` is swept, and what that sweep found —
or that it could not look — is kept apart and stated. If both families prove, an agreed
`VMCOREINFO` (every copy the same, on a complete sweep) naming one architecture settles it,
and the profile note says so (`a_proof_in_both_families_is_settled_by_an_agreed_vmcoreinfo`);
otherwise discovery ends at `ArchitectureUndetermined`, whose text says what the
`VMCOREINFO` check found (none on a complete sweep, a note naming neither, or a check that
could not settle it). If only an Intel depth proves and **any** `VMCOREINFO` copy the sweep
found names an arm64 kernel — agreed, or in a sweep that was cut short or whose copies
disagree — the Intel proof is not taken: discovery ends at `UnsupportedArchitecture` naming
the Intel depth that proved, the arm64 regimes that did not, and what the check found
(`an_x86_proof_alone_is_not_taken_when_the_images_vmcoreinfo_names_arm64`,
`an_x86_proof_alone_is_not_taken_when_a_cut_short_vmcoreinfo_sweep_saw_arm64`,
`an_x86_proof_alone_is_not_taken_when_vmcoreinfo_copies_disagree_and_one_says_arm64`).
**The limit:** with no architecture-exclusive symbol (a `kallsyms` table without
`KALLSYMS_ALL` has no `kimage_voffset`) and no `VMCOREINFO` copy naming arm64 — none on a
complete sweep, an agreed note naming neither or x86-64, or a sweep that failed, was cut
short or found disagreeing copies none of which names arm64 — an arm64 image whose tables
prove under Intel alone (a 5.4+ layout under a regime this build does not decode) is
profiled as x86-64. The discovery note then says the arm64 regimes did not prove, states
what the `VMCOREINFO` check found or that it could not settle it, and, unless an agreed note
names x86-64, that the architecture rests on the page-table proof alone and is not
corroborated (`an_x86_proof_alone_with_nothing_naming_arm64_is_not_refused_by_architecture`,
`an_x86_proof_alone_taken_says_what_the_vmcoreinfo_check_could_and_could_not_see`).
On a 4.19 layout this cannot happen: the kernel image's address is not x86-64 canonical, and
on the real MMUShell Debian dump Intel four-level paging reads the recorded root and
translates only the linear-map alias of the banner (`tests/arm64_mmushell_discovery_test.rs`).
A process of a proved arm64 kernel is read under the TTBR0 regime of the same granule and
width with top-byte-ignore on, because Linux sets `TCR_EL1.TBI0` unconditionally
(`arch/arm64/mm/proc.S`), so a tagged user pointer translates as it did on the hardware
(`space::process_paging`). A 16 or 64 KiB kernel is profiled like a 4 KiB one: `proc_maps`
scales `vm_pgoff` by the page shift of the proved regime and checks VMA alignment against it,
and the `init_task` link gate accepts the 48-bit arm64 linear map (`0xffff0000…`). A Debian 6.12 16 KiB kernel and an Ubuntu 6.8 64 KiB kernel under QEMU TCG are the
evidence (`VALIDATION.md` `MEM-ARM-5`, `MEM-ARM-6`). When no regime proves and the image is arm64 — by those symbols, or by its
`VMCOREINFO` swept for on the way to the refusal — discovery ends at
`UnsupportedArchitecture` naming arm64 and every regime tried. `vmcoreinfo` parses the kernel's `VMCOREINFO` text (refusing a
truncated note, a value not in its key's form, and a note or two copies that disagree) and
proves the root it names (`swapper_pg_dir - kimage_voffset`) by reading `init_uts_ns` back
through each regime: on the MMUShell Debian dump that root is the `TTBR1_EL1` QEMU recorded,
under 4K/48 alone (`VALIDATION.md` MEM-ARM-2). The `kallsyms` decoder reads the older
layouts both MMUShell kernels use — every array 256-byte aligned (`.align 8` on the arm64
assembler), eight-byte markers, and offsets that are plain base-relative because
`KALLSYMS_ABSOLUTE_PERCPU` is x86-64 only — and on both dumps its `_text` walks, under the
recorded root, to the arm64 `Image` header (`VALIDATION.md` MEM-ARM-3). Neither kernel was
built with `KALLSYMS_ALL`, so neither table lists `linux_banner` or `swapper_pg_dir`, and the
banner proof cannot be run from them. **Bounds:** every real arm64 capture is
QEMU-emulated and none is from hardware; swap is not resolved on arm64, and the profile's swap block says so
(`swap_entries_decoded: false`, `entries_identified`, `resolvable` and
`a_slot_holding_bytes_is_still_read` all false, and a statement that the tool could not look
rather than that no page was swapped); a 52-bit or LPA2 kernel is not decoded. All of the
above is reached only **after a symbol table has compiled**: an arm64 capture with no matching
ISF and no in-image BTF ends at `SymbolsNotFound`,
which names neither arm64 nor the `VMCOREINFO` hint. When the hint came from the
`VMCOREINFO` sweep, the refusal lists the arm64 regimes apart from the Intel depths that were
also tried. `VmcoreSweep::agreed` answers `SweepIncomplete` for a sweep that was cut short,
never "no copy".

Still not built here: no live-response agent.

### `seance_plugin_live_response` (eBPF)
**Responsibility:** Live system introspection and telemetry.
- **Architecture:** Lightweight agent (separate binary) streaming to Seance Server.
- **Features:**
    - **Process Execution:** Real-time `execve` monitoring.
    - **File Integrity:** Monitor sensitive paths for changes.
    - **Network Telemetry:** Socket open/close events.
    - **Memory Acquisition:** Trigger RAM dump on alert.

### `seance_plugin_malware_analysis`
**Responsibility:** Advanced threat detection.

**Not built, and one line of it must not be built as written:** no crate of this name exists in the tree, and **Séance ships no
YARA rules of its own** — `seance_plugin_yara` takes an examiner's rule set by
path and is not registered at all when none is named, because a forensic tool
has no business asserting maliciousness on an examiner's behalf. "A curated
YARA ruleset" below is therefore a design sketch this project has decided
against, not planned work.
- **Features:**
    - **YARA Scanning:** Scan all files against a curated YARA ruleset.
    - **ELF Analysis:** Detect packed binaries (UPX), anomalous sections, or missing symbols.
    - **Rootkit Hunter:** Check for `LD_PRELOAD` injection and hidden process IDs.

---

## Swap holds far more than `swapon` admits

Measured across the full 16 GiB swap area acquired for this work, page by page:

| Figure | Value |
|---|---|
| `swapon --show` / `/proc/swaps` reported in use | **4.5 GiB** |
| Pages actually holding non-zero data | **15.09 GiB** (3,956,012 of 4,194,303) |
| Freed but not overwritten | **10.59 GiB** |
| Text-like pages | 260,884 (~1.00 GiB) |
| Binary / mixed pages | 2,229,596 / 1,465,532 |

The "in use" figure counts **currently allocated** slots. When a page is swapped
back in, its slot is freed and `SwapFree` rises — but the bytes stay on disk
until something reuses the slot. Swap is therefore the memory equivalent of
unallocated disk space, and on this host **more than twice as much history was
recoverable as the live figure suggested**.

An examiner who sizes the value of a swap area from `swapon --show` will
under-estimate it by a wide margin, and one who images only the allocated slots
will discard the majority of what is there.

### What each artefact gives you alone

| Held | Recoverable | Not recoverable |
|---|---|---|
| **Memory capture only** | Everything resident: processes, network state, modules, open files, credentials in RAM. Swapped pages appear as typed holes naming `SwappedOut` | The contents of swapped-out pages — on a host under memory pressure, a substantial part of the working set |
| **Swap area only** | Page *contents* — strings, credentials, fragments of files and documents, key material — including the freed history above | Any attribution. Without page tables there is no mapping from a swap slot to a process or virtual address, so findings are unattributed carved data |
| **Both, same boot** | Attributed recovery: a swapped page located through a process's PTE and read from the swap area, tied to the process that owned it | — |

Swap alone is genuinely useful — it is carving, and carving finds evidence — but
nothing in it can be attributed to a process without the capture. The pair, from
the same boot, is what turns carved bytes into "this process held this".

## Symbols: how to cover every distribution and version

The combinatorial problem — an ISF per distribution × version × patch level ×
configuration — is largely solved by not having the problem. **Modern kernels
carry their own type information and it is resident in memory.**

### What an ISF actually is

Two things bolted together, and both are recoverable from the capture:

| ISF section | Recover from the image via | Available since |
|---|---|---|
| `user_types` — struct layouts, member offsets, sizes | **BTF** (`CONFIG_DEBUG_INFO_BTF`) | ~2020 distro kernels |
| `symbols` — name → address (`init_task`, `swapper_pg_dir`) | **kallsyms** (`CONFIG_KALLSYMS`) | effectively universal |

BTF exists so eBPF programs can be compiled once and run anywhere; it happens to
be exactly what memory forensics needs. `seance_memory::btf` reads it, and
`tests/btf_real_capture_test.rs` demonstrates recovering it from an AVML capture
and matching it member-for-member against that host's
`/sys/kernel/btf/vmlinux` — 6 MB describing 334,040 types on Ubuntu's 6.8.

The layout so obtained cannot be another build's, because it came out of this
one. No banner matching, no version guessing, no network.

### Why not a generic or "close enough" profile

Struct layout is not a function of kernel version:

- **Configuration moves fields.** `CONFIG_SMP`, cgroups, scheduler and hardening
  options all change `task_struct`. Same version, different layout.
- **Distributions patch heavily.** `6.8.0-1061-aws` is not mainline 6.8.
- **`randstruct` randomises member order at build time** on hardened kernels.

And the failure is silent: a wrong offset reads the neighbouring field and
returns a plausible number. A generic profile is only safe if verified against
the image — and anything able to verify it could have derived it instead.

### Tier 0, shipped: corroboration

Before any of the tiers below is reached, BTF does something an ISF-matching
scheme structurally cannot: **check that the symbol file is for this build.**

An ISF is matched by `linux_banner`. Banners are not unique — two kernels from
one distribution and version, differing in configuration, can carry byte-
identical banners and different struct layouts. A wrong-but-plausible match is
then admitted, and every offset read afterwards is silently wrong: a
`task_struct.comm` read at the wrong offset returns bytes, and those bytes reach
a report as a process name.

Banner matching cannot detect this, because the banner is what matched.
`btf_corroboration_gate` in `seance_plugin_memory_linux::discovery` compares the
matched file against the kernel's own account of itself and fails the symbols on
disagreement, naming the members and both offsets. Absence of BTF is
`NotApplicable`, not a failure — pre-2020 kernels carry none and that says
nothing about the symbols.

### The tiers

| Tier | Source | Network | Certainty |
|---|---|---|---|
| 1 | BTF extracted from the capture | none | exact, self-proving |
| 2 | kallsyms from the capture (addresses) | none | exact |
| 3 | Local ISF cache, keyed by banner hash | none | exact if matched |
| 4 | Generated from distro debuginfo (`dwarf2json`) | yes | exact |
| 5 | Volatility symbol server | yes | exact if matched |
| 6 | Layout inferred by invariant scanning | none | **stamped as inferred** |

Tier 6 is legitimate for pre-BTF kernels — find `task_struct` by scanning for
`comm` strings, check `pid` plausibility, walk `list_head` for self-consistency
across hundreds of processes, and accept a candidate only when it holds
everywhere. It must be labelled as inferred wherever its results appear.

**Whichever tier was used must travel with every record.** `BuildBinding`
already exists for exactly this. "These offsets came from BTF in the image",
"from a banner-matched symbol file", and "inferred and corroborated across 180
processes" are three different evidential claims, and a report that renders them
identically has lost the distinction that matters.

### Tiers 1–2 in practice, and the ordering that looks backwards

Tiers 1 and 2 ship. `image_symbols::recover` assembles both halves out of one
sweep of the capture and discovery uses them **when tier 3 finds nothing** —
that is, a self-proving source is tried *after* a file matched by a version
string. That ordering is deliberate and worth stating, because the table above
implies the opposite.

A banner-matched file is checked against the image's own BTF before admission.
When it passes, two independently produced descriptions of the kernel agree and
a defect in either is detectable. Image-derived symbols cannot describe a
different build — better provenance — but they are a **single source**: if this
codebase's BTF or kallsyms decoding is wrong, nothing in the pipeline disagrees,
because the source that would have disagreed produced the answer. Corroboration
beats provenance here, so the corroborated route stays primary.

The same reasoning forbids something the implementation would otherwise do for
free. The corroboration gate must **not** run against a table built from the
image's BTF: it would compare that BTF against itself, pass every time, and
record a corroboration that never happened. It is recorded `NotApplicable` with
the reason. The image sanity gates still run — reading known structures through
the table tests it against the memory's actual contents, which is independent of
where the layouts came from.

**The generated document declares no identity, deliberately.** It would be easy
to stamp the banner into it — the sweep read one out of the same image moments
earlier. But a document that declares a build is then checked against the build
the image declares, and both would be the same string from the same bytes. The
check would pass because it could not fail. So no banner is stamped, the
identity gate records "the ISF declares no identity of its own", which is
exactly true, and what establishes that these symbols belong to this image is
the page-table proof.

**Every banner candidate is offered to that proof.** An image holds the banner
several times over — the kernel's copy in `.rodata`, whatever `/proc/version`
and the printk ring buffer left behind, and on the test corpus a *second
kernel's* banner sitting in freed memory. Those copies do not all normalise to
one string, so they arrive as separate candidates, and the kernel's own is not
reliably the first. A symbol file names the build to expect and settles it;
nothing does on this route, so each candidate is tried and the proof decides.
This is the rule the banner sweep documents: which copy the symbol
refers to is settled by whether the resulting page tables work.

Provenance travels as `SymbolOrigin`, which a path string could not express:
where each structure was found, how many types and symbols, and a SHA-256 of the
generated document standing in for the file path a defence expert would
otherwise be given. Generation is deterministic, so regenerating from the same
image reproduces that hash. `DiscoveryOptions::image_derived_symbols` refuses
the whole route for a lab whose procedure requires a validated symbol file.

---

## Acquiring swap: the ext4 `unwritten` extent trap

**Copying a Linux swap *file* through the filesystem yields zeros.** This is a
property of how swap files work, not a bug in any tool, and it is silent.

### Why

A swap file is normally created with `fallocate`, which on ext4 reserves blocks
and flags the extents `unwritten` — the filesystem records that nothing has been
written to them and returns zeros for any read, without consulting the disk.
`swapon` then builds an extent map, and from that point the swap subsystem
writes pages with `bio` **directly to the physical blocks**, bypassing the
filesystem entirely. ext4's `unwritten` flags are never cleared, because nothing
went through ext4.

So the blocks hold swapped memory and the filesystem denies it.

### What it looks like

Measured on an Ubuntu 22.04 host, kernel `6.8.0-1061-aws`, with 4.5 GiB of swap
in use (`/proc/swaps` reporting `4774608` KiB used of `16777212`):

| Read path | Non-zero bytes per MiB |
|---|---|
| `dd if=/swapfile` (filesystem) | **0** |
| `dd if=/dev/nvme0n1p1 skip=<physical>` (block device) | **724,505** |

`filefrag -v /swapfile` showed 1,919 of 1,920 extents flagged `unwritten`.

### Why it is worse than an empty file

The one extent *not* flagged is extent 0 — the header page, which `mkswap`
writes through the filesystem normally. So the copy:

- carries a valid `SWAPSPACE2` signature,
- reports the correct page size, page count, UUID and label,
- passes any header-level validation,
- and contains **no swapped pages at all**.

It looks acquired. An examiner who checks that the copy "is a swap file" gets a
pass, and concludes the swap held nothing.

### Acquiring correctly

Read the physical extents from the backing block device and reassemble them at
their logical offsets:

```bash
filefrag -v /swapfile          # logical_offset, physical_offset, length per extent
findmnt -no SOURCE /           # the backing device
```

Then, for each extent, copy `length` blocks from `physical_offset` on the device
to `logical_offset` in the output. Block size is the filesystem block size
(4096 on ext4 by default). The result is the true swap area, byte for byte at
the offsets swap entries name.

A swap **partition** has none of this: it *is* the block device, so a plain
image of it is correct.

### Ordering

Capture memory first, then swap — most volatile first. Both must come from the
same boot: `swapon` reinitialises the area, so entries in a capture taken before
a reboot name pages that no longer exist in a swap area copied after one.

### Attaching the acquired area, and what the resolver refuses to assume

An acquired swap area is attached with **`SEANCE_SWAPFILES`**, the Linux
counterpart of the Windows tier's `SEANCE_PAGEFILES` and deliberately the same
`index=path` grammar so a lab drives both the same way. The index is the area's
`swp_type` — `0` for the first `swapon`:

```text
SEANCE_SWAPFILES=0=/evidence/swap-area.raw
SEANCE_SWAPFILES=0=/evidence/swap0.raw:1=/evidence/swap1.raw
```

An entry that is not `index=path`, has a non-numeric index, names an index
already attached, or cannot be opened is **warned about and not attached** —
never silently dropped, because a swapped page that then stays a hole would
otherwise look like a page that was never swapped.

`swap.rs` settles two things against the evidence rather than guessing them
from the kernel version:

1. **The `swp_entry_t` bit layout.** On x86-64 it changed once — the L1TF
   mitigation (4.19, backported below it) began storing the offset inverted and
   moved the type to the top bits. Nothing in a single PTE says which layout
   wrote it. Each candidate is decoded and kept only if its `swp_type` names an
   *attached* area and its `swp_offset` lands inside that area's bounds; the
   inversion makes the wrong layout produce a wildly out-of-range slot, so the
   bounds are a real discriminator. If more than one candidate survives, nothing
   is read and the ambiguity is reported. If none does, the entry is left as an
   unresolved swap-family entry rather than forced to name a page.
2. **Whether this is even a swap-file entry at all.** The same encoding carries
   migration entries, hardware-poison markers and device-private entries, none
   of which name a location on disk.

x86-64 is the only architecture whose layouts this build decodes. On any other
paging mode a swapped page is left unresolved rather than decoded with bits that
are not its.

**A swap area whose body was never acquired cannot produce a "recovered from
swap" claim.** A swap file copied through the filesystem carries a
valid header and no pages — the trap above. Such an area still attaches, and
still corroborates the entries that name it; what it cannot do is answer for
their contents. A slot that reads as zeros in an area whose sampled body reads
as zeros throughout is reported as `SwapResolution::BodyReadsAsZeros`, and never
as a page recovered from swap.

---

## Implementation Roadmap

### Phase 1: Foundation
- [x] **Ext2/3/4 Support:** `seance_plugin_ext4` (superblock, inodes, directories, extent + indirect block mapping, timestamps, deleted-inode recovery, JBD2 journal transaction enumeration, and extended attributes).
- [ ] **System Config:** `seance_plugin_linux_config`.

### Phase 2: User & Logs
- [ ] **Logs:** `seance_plugin_linux_logs` (Text-based).
- [x] **User Activity:** shipped as `seance_plugin_desktop_artifacts` — shell history (`.bash_history`/`.zsh_history`), Freedesktop Trash (`*.trashinfo`), GTK recent files (`recently-used.xbel`) and thumbnails. SSH artifacts and `~/.viminfo` remain open.

### Phase 3: Advanced Analysis
- [ ] **Persistence:** `seance_plugin_linux_persistence`.
- [ ] **Heuristics:** `seance_plugin_linux_fs_analysis`.
- [~] **Binary Logs:** WTMP shipped as `seance_plugin_utmp` (`utmp`/`wtmp`/`btmp`/`lastlog`, plus macOS `utmpx`). Its session pairing (login, logout, superseding login, boot/shutdown bound, session cap) lives in the shared `seance_login_sessions` crate, the same engine the Apple System Log reader pairs with; record classification stays in the plugin. The systemd journal remains open.

### Phase 4: Enterprise Expansion
- [~] **Encrypted volumes:** LUKS1/LUKS2 unlocking shipped as `seance_plugin_luks` (AES-XTS only). A LUKS volume in a run with no `--luks-passphrase` is reported, as BitLocker's is: a `VolumeDecryption` record (`detected_locked`) with the incompleteness pair, on the Needs attention queue, whose row takes the passphrase for that one volume and re-runs the decryptor on it (graded on LUKS1 and LUKS2 volumes formatted by `cryptsetup`). The encryption detector's own LUKS record is tied to it by the shared `volume_artifact_id` and defers the unlock status to it. The decrypted volume, and everything beneath it, is refused after its run (the key is not kept) until an examiner unlocks it for reading — `POST …/unlock` with `luks_passphrase`, the Inspector's *Unlock to read* or the REPL's `/unlock --read`: the keyslot KDF runs again and the decrypting view is held in process memory for that case with a TTL (8 h default), audited by kind, never on disk; the master key is zeroizing. The LUKS unlock path is pinned on a `cryptsetup luksFormat` volume at unit level; the end-to-end read-back is graded on BitLocker (`bdetogo.raw`). See `documentation/Container_Formats.md`.
- [ ] **Containers:** `seance_plugin_container_forensics`.
- [x] **Memory:** shipped as `seance_plugin_memory_linux` (native, not a Volatility wrapper), twelve stages, with hidden-process (`taskscan`) and hidden-module (`modscan`) cross-views, network sockets (`sockstat`), mount-crossing paths with per-record scope, process command lines, and the syscall-table / ftrace / kprobe / eBPF hook stage (`linux_kernel_hooks`) with its stated bounds. Swap areas attach with `SEANCE_SWAPFILES`. Open: arm64 Linux memory from hardware. Three QEMU-captured arm64 kernels are graded end to end.
- [ ] **Malware:** `seance_plugin_malware_analysis`.

