# Security policy

## Reporting a vulnerability

Report privately through GitHub's private vulnerability advisory on
<https://github.com/conorarmstrong/seance> ("Security" → "Report a
vulnerability"). If that route is unavailable to you, open an issue that says
only that you have a security report and how to reach you; do not put the
details in a public issue. Include the input that triggers it where you can
(a minimal image or file is far more useful than a description), the commit
you tested, and what you observed.

You will get an acknowledgement, a fix or a documented decision, and credit
in the release notes if you want it. There is no bounty programme.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## What is in scope

Séance reads evidence, and evidence is hostile input by definition. Anything
that lets a crafted image, file system, artifact or memory capture do more than
be parsed is in scope:

- **Evidence parsers.** Every crate that decodes bytes from an image — the
  container readers (`seance_container_*`), file systems, registry, EVTX, MFT,
  `$LogFile`, USN journal, email, app databases, memory. A panic, unbounded
  allocation, runaway loop, or out-of-bounds read reached from evidence is a
  security defect, not a robustness nit. Each parser carries a decompression or
  size ceiling; a way past one is reportable.
- **The fuzz targets** in `fuzz/fuzz_targets/` (`cargo fuzz`): partition table,
  FAT, NTFS MFT, `$LogFile`, USN journal, ext4, XFS, btrfs, APFS, HFS+, ISO9660, UDF,
  EVTX, registry, prefetch, LNK, Jump Lists, ShellBags, Thumbcache, the Recycle
  Bin, Amcache, Shimcache, SRUM, WebCache, the BITS queue (`qmgr*.dat`), the RDP bitmap cache, email, the Outlook 2013+ OST (format 36) page, block and property reader, ZIP, AFF4, VHD, VHDX, VMDK, QCOW2, the Windows hibernation reader, the Apple unified log (`.tracev3` Header
  chunk, catalogs, chunksets, firehose tracepoints, oversize, statedump and simpledump entries, the
  printf renderer, and the timesync database), the carving engine, and the E01
  helper's IPC protocol. A crash found by one of
  them is a valid report; a parser with no target is also worth telling us.
- **E01 isolation.** libewf runs in the `seance-ewf-helper` subprocess by
  default so a crash on a hostile image cannot take the server down; a way to
  reach the parent from the child, or to run in-process without the opt-out
  being set, is in scope.
- **The server.** Authentication, per-case ACLs, the audit chain and its HMAC
  keying, evidence-root confinement (`SEANCE_EVIDENCE_ROOTS`), the REPL, and
  the report signing path. The intended posture and every relevant setting are
  in [documentation/DEPLOYMENT.md](documentation/DEPLOYMENT.md#security-posture);
  a default that fails open against that document is a defect.
- **Examiner-supplied credentials.** `POST
  /cases/{id}/artifacts/{id}/credential` takes a BitLocker password or recovery
  password, a LUKS passphrase, a 7z password, the Signal for iOS key spec, an
  iOS backup password or a Signal for Android backup passphrase for one locked
  artifact (it is the only per-run route: `run_module` refuses a `secrets` map),
  and the startup flags and `SEANCE_*` variables take the
  volume credentials for a whole run. The route is meant to hold the secret in
  memory for that one module run, zero it afterwards, and never let it reach
  the database, the audit log (which records the user, the artifact, the *kind*
  of secret and the outcome), the job row, the processing log, a record, an
  error message or a log line. Any of these is in scope: the secret appearing in
  any of those places; a way to apply it to an artifact of another case or
  without a write grant; a way to run the attempt without its audit row. The
  documented limits are not defects: the HTTP body buffer is freed, not zeroed;
  a library may keep its own copy for the call; keys *derived* from the secret
  stay in memory while the decrypted volume is being read (the BitLocker FVEK
  and LUKS master key in zeroizing buffers, wiped when the volume's source is
  dropped).
- **Keys held for reading.** `POST /cases/{id}/artifacts/{id}/unlock` (kind
  `ios_backup_password`) checks an encrypted iOS backup's password
  and holds the backup's unwrapped class keys in process memory — for that one
  case, until `DELETE` on the same route, deletion of the case, a restart, or
  expiry (8 hours by default, `SEANCE_UNLOCK_TTL_SECS`; an expired key is never
  returned and is dropped from memory within one sweep, at most a minute) — so
  its files can be read after ingest. The password is not kept. In scope: a held key or the
  password reaching the database, an export, a backup of the case, the audit
  log (which records user, artifact, kind and outcome), a job row, a response
  or a log line; a held key opening that backup's files in another case, after
  its expiry or lock, or for a caller without a write grant to unlock; an unlock
  or lock without its audit row. Documented limits, not defects: process memory
  is not locked against swap or a core dump; the per-file key of a whole-file
  read and the AES schedule of a streaming read are not zeroed; an expired key
  can stay in memory for up to one sweep interval; the unlock, like ingest,
  writes the decrypted `Manifest.db` (names, domains, wrapped per-file keys) to
  a temporary file for the length of the check; a read under way when the
  backup is locked finishes.
- **Keychain secrets of an iOS backup.** The keychain an encrypted backup
  carries (`keychain-backup.plist`) is read at ingest with its
  secrets withheld: no saved password, token or key is copied into a record, so
  none reaches the database, a listing, an export or search. One item's secret
  is released only by `POST /cases/{id}/keychain/{record}/reveal`, which
  re-derives it from the backup while that backup is unlocked for reading in
  the case (above), and writes the `ios_keychain_secret_revealed` audit row
  (user, record, table, access group, service — never the value) before
  returning it; if the audit write fails, nothing is returned. In scope: a
  keychain secret reaching any stored or logged place; a reveal without its
  audit row, in another case, without a write grant, or of an item other than
  the one the record names (the item's `v_PersistentRef` is checked). Documented
  limits, not defects: the re-derived secret is in process memory for the
  length of the request (zeroed when dropped, but the response body buffer is
  freed, not zeroed), and the examiner's client holds what it was sent.
- **Volumes held for reading.** The same route with kind `bitlocker_password`,
  `bitlocker_recovery_password` or `luks_passphrase` tries the
  secret on a BitLocker or LUKS volume decrypted in an earlier run and, if it
  opens it, holds the decrypting view — and so the FVEK or LUKS master key, in
  a zeroizing buffer — in process memory under the same rules: that one case,
  until `DELETE`, deletion of the case, a restart or the same TTL. The secret
  is not kept. In scope, as above: the secret or the key reaching any of those
  places; a held volume read in another case, after expiry or lock, or
  unlocked without a write grant; an unlock or lock without its audit row
  (`volume=<id>` names the volume, never the key). Documented limits, not
  defects: the BitLocker stretched password key and VMK, and the LUKS slot key
  and merge candidates, are ordinary buffers for the length of the check; the
  resolver's small source caches are cleared on lock, expiry and case delete,
  but a read under way keeps its own handle until it finishes; process memory
  is not locked against swap or a core dump.
- **WhatsApp backup keys read from the evidence.** During ingest the WhatsApp
  parser reads `files/key` (crypt14) and `files/encrypted_backup.key` (the
  crypt15 end-to-end root key) and holds each, zeroed when dropped, in process
  memory to pair with backups read later (ROADMAP §5.7): for that one case, for
  the same TTL (8 hours, `SEANCE_UNLOCK_TTL_SECS`) or until a restart. The key
  is on no record — its `KeyFound` record names the file's path and SHA-256 —
  and the decrypted stores are parsed into records, not kept. In scope: a held
  key reaching the database, an export, a record or a log; a key read in one
  case opening a backup in another; a key used after its TTL. Documented limits,
  not defects: holding is not audited per key (it happens inside a module run,
  which has no audit channel; the `KeyFound` record is the statement); the
  derived crypt15 AES key and the GCM key schedule are in memory for the length
  of a decryption; a supplied `whatsapp_key` follows the credential rules above. A supplied `macos_keychain_password` or `macos_system_key` (the hex of `/var/db/SystemKey`) follows them too: it opens the keychain's `DbBlob` only, the master key is zeroed and on no record, and no item secret is revealed.
- **Honesty of output.** A result that is wrong and *presented as certain* — a
  section that reads as complete when it was truncated, a hash claimed verified
  when it was not — is treated with the same seriousness as a crash, because the
  output is relied on in court.

Out of scope: findings that require an already-authenticated administrator to
act against their own deployment, and denial of service by legitimately large
evidence that the documented ceilings already bound.

## Handling

Each security fix is pinned by a test that uses the input that triggered it.
Open items are recorded in `BUGS.md`.
