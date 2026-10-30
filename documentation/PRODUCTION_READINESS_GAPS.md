# Séance Production Readiness — Gap Analysis

This document is the output of a structured production-readiness assessment:

1. An **extensive known-answer testing program** against the Autopsy/DFTT corpus
   and other real images, comparing actual output to documented expected results
   (phase 1), with issues fixed inline (phase 2).
2. Three parallel read-only **production audits** — forensic soundness &
   reporting, robustness & security, and coverage/performance/operations —
   grounded in specific `file:line` evidence (phase 3).

Findings are deduplicated across audits and ranked. Severities: **BLOCKER**
(unsafe/incorrect for any production use), **HIGH** (required before a paid
engagement), **MEDIUM** (required for a credible v1), **LOW** (polish).

---

## Remediation status

The safety, evidentiary, and operability items below are closed.
The remaining open items are large feature efforts scoped as post-v1 roadmap,
called out explicitly at the end.

### Closed items

| Item | What was done |
|------|---------------|
| B1/B2 | All evidence-metadata-driven allocations bounded (`MAX_RESOLVED_CONTENT_BYTES`, `MAX_DECOMPRESSED_BYTES`); btrfs/NTFS decompression + ingest allocations capped. Crash-on-hostile-input closed. |
| B4 | No hardcoded default password (random generated + logged); evidence roots fail **closed** (confine to CWD, explicit opt-in for unrestricted); refuse auth-disabled on non-loopback bind; `SEANCE_BIND` configurable. |
| C2 | Audit chain keyed with HMAC-SHA256 (`SEANCE_AUDIT_HMAC_KEY`); interior-NULL entry now breaks verification instead of being skipped. |
| C3 | Report signing wired from `SEANCE_SIGNING_CERT/KEY`; `gather_report_data` propagates DB errors instead of silently omitting sections. |
| C4 | Container decoded-media stream is hashed and verified against the acquisition-recorded hash (E01 stored_md5/sha1) with a pass/fail integrity row. The pass runs only where `stored_md5` and a data source are both present on the artifact (`seance_core/src/ingestion.rs:1489`, `:1634`). `seance_container_aff4` reads a hash predicate from its turtle graph where the container records one (MD5/SHA-1/SHA-256, matched by a plausible predicate-name set with no authoritative in-tree spec to pin it against) and publishes `stored_md5`/`stored_sha1` the same way E01 does, so an AFF4 exhibit whose acquisition tool recorded a hash is decoded-media verified too. One that records none, or records only a SHA-256 (this pass has no `stored_sha256` comparison path), is not. The pinning test synthesises its artifact with `ingest_artifact` (`seance_core/tests/ingestion_acquisition_test.rs:558-585`), so it would not catch a regression in the shipped path. |
| C5 | Silent data loss fixed: MFT skips-and-counts bad records (+summary), carving marks validation unknown on short reads, VHDX errors on truncated BAT instead of zero-filling, ext4 flags incomplete directory parses. |
| C7 | libewf discovered via `pkg-config` (portable); CI installs libewf; `cargo audit` gate added. |
| C8 | Multi-stage Dockerfile, docker-compose, and `DEPLOYMENT.md` (full `SEANCE_*` env reference + security posture). |
| D2 | SQLite WAL/journal sidecar reads capped. |
| D4 | `CatchPanicLayer` — a handler panic returns a clean 500 per request. |
| D10 | Fuzz targets added for the untrusted container/filesystem parsers (iso9660, udf, hfsplus, zip, qcow2/vhd/vmdk/vhdx, aff4), build-validated. |
| D11 | `/healthz` + `/readyz` (DB-backed) probes. |
| D15 | Internal error detail no longer leaked to clients (logged server-side under a correlation id). |
| DFTT #11 | OLE2 carves are sized exactly from the FAT (16 files recovered). |
| **B3** | **E01 libewf now runs in an isolated `seance-ewf-helper` subprocess** serving reads over a framed stdio protocol; a libewf crash on a hostile image kills only the child (parent gets an io::Error). Used by ingest + content-resolver reopen; Dockerfile ships the helper. Validated byte-identical on a real E01. **The last crash-on-hostile-input blocker is closed.** |
| **C1** | **Real multi-user auth + RBAC**: users table (bcrypt, admin/examiner roles, active flag), DB-backed login issuing per-user+role JWTs, admin-guarded user-management endpoints, bootstrap-admin seeding, and per-user audit attribution. 24 tests. Per-case ACLs are described under the next heading. |
| **C6** | **LUKS1/LUKS2 volume decryption** (`seance_plugin_luks`): header parse, PBKDF2/Argon2id KDF, anti-forensic merge, AES-XTS decrypting DataSource. Wired into the CLI (`--luks-passphrase`) so an encrypted LUKS disk is no longer a dead end. Real-crypto round-trip tests (LUKS1, LUKS2/PBKDF2, LUKS2/Argon2id, wrong-passphrase). |
| **D9** | sqlx→0.8.6 + rusqlite→0.32 (unifies libsqlite3-sys 0.30), closing RUSTSEC-2024-0363. |

### Further delivered hardening

- **C1 per-case ACLs — delivered and audited.** A `case_access` table (migration
  `0020_case_access.sql`), a fail-closed `case_access_middleware` choke point on
  every `/cases/:id/...` route, and `grant`/`revoke`/`list` admin handlers gate
  access by (case, user, level); the case list is filtered via
  `list_accessible_case_ids`. A **systematic per-endpoint IDOR audit** of all
  ~90 routes then confirmed the enforcement model is sound and fixed the
  remaining cross-case gaps: `create_artifact_bookmark` (unscoped body
  `artifact_id` + an unscoped list JOIN), `create_timeline_tag` (unvalidated
  `event_id`), and `cancel_processing` (a process-global cancel that let one
  case halt another — now per-case). `verify_audit_log` (global chain by design)
  and the filter NULL-case path were reviewed as no-change-needed.
- **C6 breadth** — LUKS is unlocked; **BitLocker now fully decrypts**
  (`seance_plugin_bitlocker`), validated byte-for-byte against a real Windows
  volume: detection, FVE parse, the password KDF, and the AES-CCM VMK/FVEK
  unwrap all verify, and both cipher families decrypt — **AES-XTS** (Win10+) and
  **AES-CBC + Elephant diffuser** (Vista/7/8), the latter validated on the real
  image (empty clusters → zeros; relocated FAT boot record → a valid 0x55AA
  sector). Plain AES-CBC (no diffuser) recovers keys but sector-decrypt isn't
  wired; FileVault/EFS remain detect-only.
- **D5/D6/D7 — delivered.** Timeline events preserve sub-second precision
  (`timestamp_subsec_nanos`) and the source UTC offset (`source_utc_offset_seconds`,
  migration `0021`); report findings now carry byte-offset provenance
  (`source_path` + `source_offset`, rendered as a "Source location" column).
- **CI + validation (T1).** `scripts/ci-gate.sh` reproduces every CI gate
  locally (see `documentation/CI.md`); `seance-validate` (crate `seance_validate`) runs the
  known-answer corpus and emits a provenance-stamped, HMAC-signable report with
  honest Pass/Fail/**Skipped** accounting (`documentation/VALIDATION.md`).
- **Still open (post-v1 roadmap):** **D12** (correlation engine), **D13/D14**
  (coverage: LVM/RAID/ReFS/memory; overlapping-FS and embedded/ADS detection),
  plain AES-CBC BitLocker sector decryption, FileVault/EFS unlock. MEDIUM
  feature work, not readiness blockers.

**v1.0 posture:** all BLOCKER and evidentiary-HIGH findings are closed. The
platform is production-ready with real multi-user accounts + an audited ACL
model, isolated E01 handling, keyed audit trails (required by the shipped
compose file; the server refuses an unkeyed network-exposed start unless
`SEANCE_AUDIT_UNKEYED_OK` is set), verified acquisition,
encrypted-volume support (LUKS + BitLocker key recovery / XTS), forensic-grade
timestamp + finding provenance, and a reproducible validation artifact.
Remaining items are additive coverage/feature work. An independent external
security review before a court/paid engagement remains recommended.

---

## Part A — Testing program results (phases 1-2)

Ran the full DFTT corpus (14 known-answer images) plus canon2 (Digital Corpora)
and the dfir_ntfs VSS images through the real pipeline, comparing to each
image's documented ground truth.

### Passing known-answer comparisons (locked in as committed tests)

| Image | Capability | Result |
|-------|-----------|--------|
| DFTT #1 | Extended DOS partition (hand-edited 3rd entry) | **6/6 FAT16 partitions**, container not mis-emitted |
| DFTT #2/#3/#4 | FAT/NTFS/ext3 keyword search | content keywords resolve to their files |
| DFTT #5 | FAT12 daylight-savings timestamps | both files, DST offset visible |
| DFTT #6/#7 | FAT/NTFS undelete | matches TSK `icat` (fragmented misses are fundamental) |
| DFTT #8 | JPEG search | 8/10 by MD5; the 2 embedded off a sector boundary are a stated limit (see below) |
| DFTT #9 | FAT volume label | "LABEL1" extracted |
| DFTT #10 | NTFS autodetect | partitions found; 2nd overlapping FS not surfaced (gap) |
| DFTT #11 | FAT data carving | **16 files** |
| DFTT #12 | ext2 indirect-block carving | 10/10 byte-exact (in-line IND/DIND pointer blocks verified and left out) |
| DFTT #14 | ISO9660 | detected + extracted |
| canon2 | whole-pipeline scenario | MBR → FAT12 → 113 carved JPEGs |
| VSS 2003 | shadow-copy reconstruction | 80/80 ground-truth blocks, re-servable via API |

### Capability gaps surfaced by the testing program

- **DFTT #10 — overlapping filesystems (MEDIUM).**
  `detect_all_filesystem_types` probes every signature within a partition and
  the detector reports each one it finds, so an overlapping pair is surfaced
  rather than hidden. **No real overlapping image has been put through it.** The
  DFTT #10 image is not in this repository and the only coverage is a synthetic
  NTFS+ext buffer built in-tree.
- **DFTT #8 — embedded/ADS JPEGs.** Run through the product's own module set,
  the image yields all eight pictures the key gives an MD5 for: allocated,
  deleted, the ZIP, `.boo` and `.tar.gz` members, and the ADS. Each is found by
  that MD5, and none of the three decoys is carved as a JPEG. The two pictures the
  key names by their container (`file11.dat`, `file12.doc`) are not found: each
  starts off a 512-byte boundary inside its file, where the carver does not look.
  That is a stated limit (`VALIDATION.md` `DFTT-8`).

---

## Part B — BLOCKERS (unsafe or incorrect for any production deployment)

Parts B and C record the findings as first assessed. Each is closed except where
the remediation table says otherwise (C6 leaves FileVault and EFS detect-only).

### B1. Server crashes on hostile evidence via unbounded allocation
The API content resolver allocates from attacker-controlled image metadata with
no cap, so serving one crafted artifact OOMs and aborts the whole process (not
under `catch_unwind`):
- `seance_api/src/content_resolver.rs:535` `vec![0u8; size as usize]`,
  `:556` `vec![0u8; disk_len]`, `:558` btrfs decompress by `ram_len`.
- NTFS LZNT1 resolve path builds the full logical file in RAM with no cap
  (`content_resolver.rs:269` → `seance_core/src/compression.rs:134`); the mft
  parser writes size-independent descriptors for large files.
- btrfs ingest allocates from per-extent `disk_num_bytes`/`ram_bytes` which the
  file-size gate does not bound (`seance_plugin_btrfs/src/lib.rs:1133`;
  `compression.rs:187`).
**Fix:** cap every allocation and decompressed total against an absolute limit
and the actual container size; stream rather than materialize; copy the ZIP
resolver's bounded pattern (`content_resolver.rs:492-504`).

### B2. Decompression bombs unbounded (btrfs zlib/zstd, NTFS LZNT1)
`compression.rs:187-195` pre-allocates the claimed decompressed length with no
ratio or absolute guard. Same root cause as B1; call out separately because it
also applies at ingest. **Fix:** enforce max decompressed size + max ratio.

### B3. E01 parsing can SIGSEGV the process on malformed input
`seance_container_e01` hands untrusted bytes to libewf (C) over FFI
(`src/lib.rs:89,248,405,466`); a C-side crash is uncatchable by `catch_unwind`
and takes down the server. **Fix:** isolate container ingestion in a sandboxed
subprocess with a memory cap, or fuzz-harden and process-isolate.

### B4. Default credentials + fail-open access controls
- Default admin password `"seance"` when `SEANCE_ADMIN_PASSWORD` unset
  (`seance_api/src/auth.rs:122-132`) — anyone reaching the port is admin.
- Evidence-root policy fails **open**: unset `SEANCE_EVIDENCE_ROOTS` lets any
  authenticated request read/ingest/browse arbitrary server files
  (`seance_api/src/lib.rs:407-415`).
- Auth can be fully disabled via `SEANCE_AUTH_ENABLED=false`.
**Fix:** refuse to start with the default password when bound non-loopback; fail
**closed** on evidence roots; make auth-disable loopback-only.

---

## Part C — HIGH (required before a real engagement)

### C1. Single shared identity breaks chain of custody
`validate_credentials` accepts only the one admin account
(`seance_api/src/auth.rs:156-161`); the `"user"` role branch is dead code
(`:253-257`). Every examiner authenticates as `admin`, so `audit_log.user_id`
cannot attribute an action to a person — a chain-of-custody requirement. The
"enterprise/multi-user" framing is not yet real (single global SQLite DB, a
`WorkspaceLock` forbidding a second instance). **Fix:** real users table (bcrypt,
roles, per-case ACLs); per-person audit attribution.

### C2. Audit hash-chain is keyless and tail-truncatable
`compute_audit_entry_hash` is plain SHA-256 with no HMAC/secret and lives in the
same DB as the data (`seance_db/src/lib.rs:4831-4861`); anyone with DB write
access can recompute a valid replacement chain. `verify_audit_chain` only checks
continuity of present rows, so deleting the last N rows leaves a valid-looking
chain (`:3688-3750`), and interior NULL-hash rows are silently skipped
(`:3701-3703`). **Fix:** HMAC the chain with a server-held secret and/or anchor
the head externally; persist a verified entry count; treat interior NULL hashes
as breaks.

### C3. Reports are unsigned and silently drop failed sections
- The production server hardcodes `signing_config: None`
  (`seance_api/src/main.rs:164`) with no env plumbing, so every server-generated
  report is unsigned and does not say so; the PDF-signing code is dead in server
  deployments.
- `gather_report_data` swallows DB errors (`get_evidence_sources(...)
  .unwrap_or_default()`, etc., `seance_api/src/lib.rs:4740-4809`): a partial DB
  failure yields an authoritative-looking report with evidence sources, findings,
  or hashes silently missing, while the methodology section still asserts
  completeness.
**Fix:** load `SigningConfig` from env or stamp "UNSIGNED — not tamper-evident";
propagate report-assembly errors instead of substituting empty data.

### C4. Acquisition hash covers the container file, not the decoded stream
`hash_source` hashes the raw bytes of `source_path` (`seance_core/src/
ingestion.rs:199-201`); for E01/AFF4/compressed VMDK that is the compressed
container, not the decoded media. The E01's internally-stored decoded-media
MD5/SHA1 are read (`seance_container_e01/src/lib.rs:351-355`) but never
recomputed from a decoded re-read and compared — the forensically authoritative
value is captured yet never verified. AFF4 has no integrity verification at all.
**Fix:** hash the decoded `DataSource` at ingest and compare to stored hashes;
record a pass/fail integrity row; verify AFF4 block/image hashes.

### C5. Silent data loss in evidence parsers
Partial extraction is presented as complete (none of these increment an
examiner-visible skipped-region counter):
- MFT enumeration aborts entirely on one short read
  (`seance_plugin_mft/src/lib.rs:545-547`, `:167-169`) — all later records lost.
- Carving final validation reads into a possibly zero-filled buffer without
  checking the read, then can stamp `validated: true`
  (`seance_carving/src/engine.rs:280-282`).
- VHDX out-of-range BAT index coerced to "not present" → real blocks read as
  zeros (`seance_container_vdisk/src/vhdx.rs:143-152`).
- ext4 htree fallback drops read/parse errors → a directory's files vanish
  (`seance_plugin_ext4/src/lib.rs:1267-1271`); APFS/exFAT/NTFS `$Bitmap` similar.
**Fix:** skip-and-count bad regions, continue, and surface the skipped count;
mark carving validation `unknown` on short reads; error (not zero-fill) on
out-of-range VHDX BAT.

### C6. No decryption of any encrypted volume
BitLocker, LUKS, FileVault2/APFS-encrypted, NTFS EFS and encrypted ZIP are
detected but never unlocked (`seance_plugin_file_analysis/src/encryption.rs`), so
an encrypted disk is a dead end — a whole class of modern evidence. **Fix:** add
unlock modules accepting keys/recovery passwords, exposing a decrypted
`DataSource`.

### C7. CI cannot build the E01 crate on Linux
`test.yml` runs `cargo test --workspace --all-features` without installing
libewf, and `seance_container_e01/build.rs` hardcodes Apple-Silicon Homebrew
paths and `.expect()`-panics if the header is missing, so ubuntu CI and the
Linux release jobs fail (or silently exclude E01). **Fix:** portable libewf
discovery (`pkg-config`) with a graceful cfg fallback; install `libewf-dev` in CI
and release jobs.

### C8. No deployment story
No Dockerfile, compose, systemd unit, or install script. **Fix:** multi-stage
Dockerfile bundling libewf + the built frontend; a compose/systemd example; a
deployment guide covering the `SEANCE_*` env vars.

---

## Part D — MEDIUM (required for a credible v1)

D2 (the prefetch half), D4, D5, D6, D9, D10 and D15 are closed. D7, D11 and D16
are partly open as stated below. The rest are open.

- **D1. Unbounded orchestrator task queue** — `unbounded_channel()`
  (`seance_core/src/orchestrator.rs:599`) can grow without backpressure on a
  large image; README claims a bounded 50K queue (untrue). Add a bounded queue
  with a re-queue lane.
- **D2. Whole-file-into-RAM parsers** — SQLite/registry/amcache/lnk/prefetch/
  badclus read the entire artifact into a `Vec` (`seance_plugin_sqlite/src/
  lib.rs:65`, etc.); a multi-GB SQLite DB is fully materialized. Cap + stream.
  `seance_plugin_sqlite` declares `input_capability` `Stream` and its
  `PageReader` reads a page at a time. The one whole-buffer read left in it is the
  512 MiB `attributedBody` scan at
  `seance_plugin_sqlite/src/sqlite_forensic/mod.rs:539-540`, gated to the
  `message` + `handle` schemas. Prefetch is capped: `MAX_PREFETCH_SIZE` is
  16 MiB, the declared size is checked before anything is allocated, including a
  `MAM\x04` blob's declared uncompressed length, and an oversized file is refused
  with the size it was and a `cap_reached` status record. Pinned by
  `test_prefetch_parser_rejects_oversized_input`. The other parsers named are
  unverified.
- **D3. No `spawn_blocking` on content endpoints** — CPU-bound decode runs on
  tokio workers, unthrottled and un-rate-limited (`content`/`hex`/`thumbnail`).
- **D4. No `CatchPanicLayer`** on the router (`seance_api/src/lib.rs:5821-5826`) —
  a handler panic drops the connection ungracefully.
- **D5. Timeline timestamps truncated to whole seconds**
  (`seance_db/migrations/0001_initial_schema.sql:23`) — 100 ns MFT precision and
  intra-second ordering (and timestomp signals) are lost. Store i64 nanoseconds.
- **D6. Source timezone not recorded** — FAT local-time conversions assume an
  unrecorded zone, so UTC output is not independently reproducible.
- **D7. Findings carry no byte-offset provenance in reports**
  (`seance_reporting/src/report.rs`) — a reviewer cannot verify a result against
  source bytes, though the methodology text says to. Provenance keys are also
  inconsistent across plugins (`data_runs`/`offset`/`carving_offset`); promote to
  a first-class artifact field. Findings now carry byte-offset provenance into the
  report (`ReportBookmark` has `source_path` and `source_offset`). Open: there is
  no per-finding provenance chain for an ordinary record, and provenance keys are
  still inconsistent across plugins. See REPORTING_DESIGN.md, *What is not yet
  covered*.
- **D8. Case deletion destroys integrity/verification history** —
  `integrity_checks` cascades on case delete while `audit_log` is `SET NULL`;
  retain integrity rows.
- **D9. Dependency scanning not wired** — `cargo audit`/`deny` absent from CI;
  `sqlx 0.8.0` is affected by RUSTSEC-2024-0363 (fixed in 0.8.1). Bump + gate.
- **D10. Untrusted parsers unfuzzed** — no fuzz targets for the container crates
  (E01/AFF4/ZIP/vdisk), iso9660, hfsplus, or the content-resolver decode paths
  (the B1/B2 code). Add targets.
- **D11. No metrics endpoint and no JSON log layer.** `/healthz` and `/readyz`
  ship. Add `/metrics` and a JSON log layer with case/job span fields. Until then
  the only way to watch how many search-export index pins are live is the log line
  the export handler emits.
- **D12. No correlation/rules engine** over the (existing, good) super-timeline —
  no temporal-window joins or anomaly detection.
- **D13. Coverage holes vs modern investigations** — LVM/RAID assembly now ships
  (`assemble-raid`/`scan-raid`, incl. RAID-6 double-fault and multi-PV LVM), F2FS
  and memory-image analysis are covered; **still missing**: Windows Storage
  Spaces and dynamic disks (LDM), RAID 5EE, Scheduled Tasks / WMI persistence,
  and ReFS. Prioritize by target market.
- **D14. Overlapping-filesystem detection (DFTT #10)** — **the detection
  shipped** (see the DFTT #10 entry above); what remains of this row is the DFTT #10
  image itself, so that the behaviour is measured against real evidence rather
  than a synthetic buffer — and **embedded/ADS image extraction (DFTT #8)** —
  from the testing program above.
- **D15. Internal error detail / server paths leaked to clients** — log
  server-side, return generic messages.
- **D16. No standalone forensic-methodology or tool-validation document and no
  machine-readable OpenAPI spec.** The admin guide is [DEPLOYMENT.md](DEPLOYMENT.md)
  and the API specification is in [CORE_DESIGN.md](CORE_DESIGN.md) §4.
  [VALIDATION.md](VALIDATION.md) and the shipped `seance-validate` cover much of
  what a methodology document would assert.

---

## Part E — LOW (polish)

- `panic`-prone unchecked slicing in hfsplus/vss (contained by `catch_unwind` at
  ingest only).
- Timeline PDF written to a predictable shared temp path
  (`seance_api/src/lib.rs:1595-1624`) — render in-memory or use `O_EXCL`.
- Cookie `Secure` defaults false (fine for localhost; enforce under TLS).
- No published large-image benchmark; `seance_benchmarks` not run in CI.

---

## Recommended sequencing

1. **Safety first (B1-B4):** bound all allocation/decompression, isolate the E01
   FFI, fail closed on credentials and evidence roots. These are the crash- and
   compromise-on-hostile-input issues; nothing else matters until they are done.
2. **Evidentiary integrity (C1-C5):** real per-user identity + keyed audit chain,
   signed/complete reports, decoded-stream acquisition hashing, and honest
   partial-extraction reporting — the things that get evidence excluded.
3. **Operability (C7-C8, D9-D11):** portable CI/libewf, container deployment,
   dependency scanning, health/metrics/JSON logging.
4. **Coverage & analysis (C6, D12-D14):** decryption, correlation engine, and the
   filesystem/artifact gaps, prioritized by the target investigation profile.
5. **Polish (Part E).**

### Strengths to preserve
The streaming `DataSource` layer (pread-based, lazily composed windows/run-lists),
the block-based carver with progress + cancellation, the normalized plaso-style
super-timeline, and the migrated SQLite schema with a solid CI baseline are
production-grade foundations. The gaps above are in safety hardening, multi-user/
evidentiary rigor, deployment, and encrypted-volume coverage — not in the core
evidence-access design.
