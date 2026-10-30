# Séance Deployment Guide

Operator/administrator guide for building, running, securing, and backing up a
Séance server deployment.

## Architecture at a glance

Séance ships two server binaries:

| Binary | Crate | Serves | Bind |
| --- | --- | --- | --- |
| `seance_api` | `seance_api` | JSON API only (`/api/v1/*`) | `SEANCE_BIND`, default `0.0.0.0:8080` |
| `seance` | `seance_cli` | JSON API **and** the React SPA | hard-coded `127.0.0.1:<port>` (loopback) |

The container image built here runs **`seance_api`**, because it is the binary
that honours `SEANCE_BIND` and can serve on all interfaces. `seance_api` does
**not** serve the web UI. For a browser-facing deployment you put a reverse
proxy in front that:

- serves the static SPA bundle (shipped in the image at `/app/frontend/dist`),
- proxies `/api/*` to the container, and
- terminates TLS.

See [Serving the web UI](#serving-the-web-ui) and [TLS](#tls-reverse-proxy).

If you only need a single-user tool on your own machine, the `seance` CLI binary
(`cargo run -p seance_cli --release`) serves the whole app on
`http://127.0.0.1:8080` with no proxy required.

---

## Prebuilt binaries (releases)

The **Release** GitHub Actions workflow (`.github/workflows/release.yml`) builds
the standalone `seance` CLI for every supported target. A `v*` tag push publishes
them to a GitHub release; a manual `workflow_dispatch` run uploads the same
binaries as downloadable Actions artifacts.

| Asset | Target | E01 (`e01`) | ESE/SRUM (`esedb`) | HEIC thumbnails (`heic`) | Video thumbnails (`video-thumbs`) | Notes |
| --- | --- | :-: | :-: | :-: | :-: | --- |
| `seance-linux-x86_64.tar.gz` | x86_64 Linux (glibc ≥ Ubuntu 24.04) | yes | yes | yes | yes | needs system `libewf`; bundles `libheif.so.1`, `libde265.so.0` and `seance-ewf-helper` |
| `seance-linux-aarch64.tar.gz` | aarch64 Linux (glibc ≥ Ubuntu 24.04) | yes | yes | yes | yes | as above |
| `seance-macos-x86_64.tar.gz` | Intel macOS | yes | yes | yes | yes | needs Homebrew `libewf` and `libheif`; bundles `seance-ewf-helper` |
| `seance-macos-aarch64.tar.gz` | Apple-silicon macOS | yes | yes | yes | yes | as above |
| `seance-windows-aarch64-no-native.zip` | ARM64 Windows | no | no | no | no | no native-C feature builds on this target |
| `seance-windows-x86_64-e01-only.zip` | x86_64 Windows | yes | no | no | no | built under MSYS2; bundles the libewf and mingw runtime DLLs and `seance-ewf-helper` |
| `seance-web-ui-<version>.tar.gz` | any | – | – | – | – | `frontend/dist`; unpack it and pass `--web-root <dir>` |
| `validation-report.{json,md}` | – | – | – | – | – | attached only when present in the tagged tree |

Every asset has a `.sha256` beside it. The feature set of each build is stated
explicitly in the workflow's matrix (`--no-default-features --features ...`),
and the two Windows asset names say what they lack. The x86_64 Windows job
builds libewf from libyal source under MSYS2, builds `seance` with the `e01`
feature alone and zips the binary with the DLLs it loads. `esedb` is off there
because `libesedb-sys` does not compile under MSYS2 gcc. `scripts/check-feature-edges.sh`
fails CI if a native crate leaks past its feature.

The Linux asset's bundled libraries are **verified by the workflow itself**: the
packaging step asserts that the staged `libheif.so.1` carries an `$ORIGIN`
runpath, and a step after it runs the packaged binary in a stock `ubuntu:24.04`
container with only `libewf2` installed, failing the release if anything is
unresolved or if `seance --version` does not run. That check exists because the
build host cannot answer the question — it has libheif and libde265 installed as
build inputs, so `ldd` there resolves them from the system even when the asset
would fail in the loader on a clean machine.

The version is 1.0.1. The workflow checks that every version source agrees
with the tag, builds the five matrix targets and the x86_64 Windows job, packages
the web UI and attaches the validation report when the tagged tree carries one.

The binary is **not** self-contained for the web UI: it serves the React SPA
from disk via `--web-root` (default `frontend/dist`, relative to the working
directory). If those assets are absent it logs a warning and serves the JSON
API only. To run a downloaded binary as the single-user local tool with the UI,
build the SPA once and point `--web-root` at it:

```bash
tar xzf seance-linux-x86_64.tar.gz
npm --prefix frontend ci && npm --prefix frontend run build   # produces frontend/dist
./seance --web-root frontend/dist          # http://127.0.0.1:8080 (loopback only)
# or headless (API only):
./seance --headless
```

For a browser-facing multi-user deployment, use the Docker image below instead —
it runs `seance_api` (which honours `SEANCE_BIND` and enforces auth) behind a
reverse proxy.

---

## Build and run with Docker

The multi-stage `Dockerfile` at the repo root builds everything:

1. **frontend** stage builds the React SPA (`node:20`, `npm ci && npm run build`
   → `frontend/dist`).
2. **backend** stage builds `seance_api` in release on `rust:1-trixie`,
   installing `pkg-config libewf-dev clang libclang-dev libssl-dev libheif-dev`
   (the E01 container crate links libewf and generates FFI bindings with
   bindgen/libclang; the `heic` default feature links libheif, and the stages
   are on trixie rather than bookworm because bookworm ships libheif 1.15.1 and
   `libheif-rs` needs ≥ 1.19).
3. **runtime** stage is `debian:trixie-slim` with the runtime shared
   libraries the binary links (`libewf2` for E01 support, `libheif1` for HEIC
   thumbnails, `libssl3` for report signing; SQLite is statically bundled), the binary, and the SPA bundle,
   running as a non-root `seance` user.

```bash
# Build the image
docker build -t seance:latest .

# Run it (API on http://localhost:8080)
docker run --rm -p 8080:8080 \
  -e SEANCE_ADMIN_PASSWORD='choose-a-strong-password' \
  -e SEANCE_JWT_SECRET="$(openssl rand -hex 32)" \
  -e SEANCE_EVIDENCE_ROOTS=/evidence \
  -v /path/to/evidence:/evidence:ro \
  -v seance-data:/data \
  seance:latest
```

The server writes its SQLite database and search index under its working
directory (`/data` in the image), so mount a volume there to persist state.

## Build and run with Docker Compose

`docker-compose.yml` at the repo root runs the same image as a single service
with an evidence bind-mount (read-only), a named `seance-data` volume, and the
key environment variables.

```bash
# 1. Provide the three secrets (compose refuses to start without them). The
#    audit key makes the chain of custody tamper-evident; keep it stable.
echo "SEANCE_ADMIN_PASSWORD=$(openssl rand -base64 24)" >> .env
echo "SEANCE_JWT_SECRET=$(openssl rand -hex 32)"        >> .env
echo "SEANCE_AUDIT_HMAC_KEY=$(openssl rand -hex 32)"    >> .env

# 2. Put evidence images under ./evidence (mounted read-only at /evidence)

# 3. Build and start
docker compose up --build -d

# 4. Watch startup logs (admin password is logged here if you did not set one)
docker compose logs -f seance
```

---

## Environment variable reference

The variables the server and its container readers consume at runtime, verified against the source
(`seance_api/src/auth.rs`, `seance_api/src/main.rs`, `seance_api/src/lib.rs`,
`seance_api/src/modules.rs`, `seance_db/src/lib.rs`, `seance_container_e01/src/isolated.rs`,
`seance_core/src/orchestrator.rs`).
Variables read by individual parsers for platform-specific inputs (symbol
directories and the like) are documented with the platform they belong to in
the `*_DESIGN.md` documents, not here. Variables that only gate
tests — `SEANCE_REQUIRE_CORPUS`, `SEANCE_MEM_IMAGES`, `SEANCE_DEFERRED_IMAGES`,
`SEANCE_HEVC_MOV` — are not listed here; they are documented with the test
harness ([TESTING.md](TESTING.md)) and the server never reads them.

| Variable | Purpose | Default | Security note |
| --- | --- | --- | --- |
| `SEANCE_BIND` | Address:port the server binds to. | `0.0.0.0:8080` | With auth disabled, only loopback binds (`127.0.0.1`, `localhost`, `::1`) are permitted; a non-loopback bind with auth off **aborts startup**. |
| `SEANCE_AUTH_ENABLED` | Enable JWT authentication (and CSRF). | `true` | Only the literal value `false` (any case) disables it; anything else keeps auth on. Never disable on a shared or network-exposed host. |
| `SEANCE_ADMIN_USERNAME` | Admin login name. | `admin` | — |
| `SEANCE_ADMIN_PASSWORD` | Password for the initial admin, bcrypt-hashed and **seeded once** — the first time the server starts with no users in the database. | none | Three-way rule (`bootstrap_admin` in `seance_api/src/lib.rs`): a value that meets the minimum length is used as given; with none set, a **loopback** bind seeds the well-known password `seance` and forces a change at first login; a **non-loopback** bind seeds a generated password, logs it exactly once, and forces a change at first login. The seed is one-time — a later restart neither regenerates nor rotates it — so a stock `docker compose` deployment (which requires the variable) never runs on a guessable credential, and a bare non-loopback start never does either. |
| `SEANCE_EXAMINER_HOST_FS` | Let every examiner browse the host filesystem (the `browse_filesystem` endpoint, within the evidence roots), which is otherwise admin-only. | unset (admin only) | `true` or `1` widens it to every examiner; anything else is refused with 403 and a reason. Leave unset unless the deployment intends that. |
| `SEANCE_E01_ISOLATED` | Parse E01 images in the isolated `seance-ewf-helper` subprocess. | `true` | Only an explicit falsey value turns isolation off; a libewf crash on a hostile image then takes the server with it. |
| `SEANCE_EWF_HELPER` | Path to the `seance-ewf-helper` binary. | beside the `seance` binary, else one directory up | If it cannot be found the server logs a warning and parses E01 **in-process**, without crash isolation. Release assets ship the helper beside the binary. |
| `SEANCE_JWT_SECRET` | HMAC secret used to sign session JWTs. | none — a random per-process secret is generated | Set a stable, high-entropy value or **all sessions drop on every restart**. Anyone who learns it can forge admin tokens. |
| `SEANCE_COOKIE_SECURE` | Add the `Secure` attribute to the auth cookie. | `false` | Accepts `1`/`true`/`yes` (case-insensitive). Set `true` whenever the API is served over HTTPS; over plain HTTP from a non-localhost host a Secure cookie is dropped by browsers. |
| `SEANCE_WORKERS` | Number of parallel processing workers. | number of CPU cores | Lower it to cap peak memory on a small host: a walk of a folder of many large property lists resolves each one in a large transient tree, and the peak scales with how many resolve at once. Fewer workers trades wall-clock for headroom. `0` or unparseable falls back to the core count. |
| `TMPDIR` | Where temporary spill files go: the task queue's overflow, and the reconstructed content of compressed NTFS files of 16 KiB or more (`seance_core::spilled_source`). | the system temp directory | On a host whose `/tmp` is a RAM-backed `tmpfs` that is memory, only not this process's: point it at real disk for a large ingest (`scripts/findings-sweep.sh` does). |
| `SEANCE_ALLOC_TRACE_MB` | Opt-in allocation profiler for a memory investigation: logs a backtrace for any single allocation of this many MiB or more, and every `SEANCE_ALLOC_DUMP_SECS` seconds (default 30) the call sites holding the most live heap (sampled every `SEANCE_ALLOC_SAMPLE_KB` KiB, default 512). | unset (off; one relaxed load per allocation) | A diagnostic, not a setting for production: sampled allocations cost a backtrace each, and the figures are estimates that order the sites, not exact byte counts. |
| `SEANCE_MEMORY_LIMIT` | The memory **budget** the governor defends (see [Memory limits](#memory-limits-and-not-being-oom-killed)). Accepts `12G`, `12GiB`, `8192M`, `80%` (of `MemAvailable` when the process starts) or `off`/`0`. | the smaller of the cgroup memory limit and 75% of `MemTotal` | An explicit size is also capped at the cgroup limit. At 85% of the budget the orchestrator runs one task at a time and spills queued work to disk at once; at 95% it dispatches nothing new, and if that does not recover within `SEANCE_MEMORY_GRACE_SECS` it **stops the run cleanly** and marks each source incomplete (`stopped: memory limit reached at N GiB ... N tasks done`). Unparseable values are ignored with a warning (the default applies). On a platform without `/proc` the governor is inactive. |
| `SEANCE_MEMORY_GRACE_SECS` | How long pressure may stay critical, with work outstanding, before the run is stopped. | `30` | Whole seconds. A value that is not (`5m`, empty, `-1`) is ignored with a warning and the default applies. A reading that recovers resets the clock. |
| `SEANCE_OOM_SCORE_ADJ` | Opt-in: raise this process's `oom_score_adj` (0 to 1000) so the kernel's OOM killer picks it before `sshd` or the desktop session. | unset | Only ever raises the value (lowering needs a privilege the process does not and should not have); a value at or below the current one is left alone. Logged when applied. |
| `SEANCE_FREE_REGION_CAP` | How many free-space regions (`UnallocatedSpace` artifacts, one per free run the allocation bitmap proves) one NTFS, ext4, FAT or exFAT volume may emit for the carver. | `4096` | The **largest** runs are kept and the rest are reported on the volume's `allocation_map` as `free_runs_dropped` and `free_bytes_dropped` — free space that will not be carved. On the Magnet 2022 Linux CTF ext4 volume the default declines 37.6% of the free space. Raising it carves more of a fragmented volume and costs ingest time: every region is an artifact, a database row and a carve pass of its own, and that volume has 1.36 million runs. The record publishes the ceiling applied as `free_region_cap`, with `free_region_cap_source` `default` or `configured`. The source is decided by the value applied, not by whether the variable was set: `configured` means the ceiling differs from the compiled default, so setting the variable to `4096` is published as `default`. `0` or unparseable falls back to the default. |
| `SEANCE_FREE_BYTE_CAP` | How many bytes of free space one volume may be carved for. | `137438953472` (128 GiB) | Same shape: largest runs first, what it declines is a published byte total, and the record carries `free_byte_cap` and `free_byte_cap_source` (decided by the value applied, in the same way). `0` or unparseable falls back to the default. |
| `SEANCE_EVIDENCE_ROOTS` | Colon-separated **absolute** paths the server may read (ingest, filesystem browse, artifact content/hex/verify). | unset | When unset, access is confined (fail-closed) to the process working directory. Set explicitly for any multi-user or exposed deployment. Paths are canonicalized; `..`/symlink escapes are denied. |
| `SEANCE_ALLOW_UNRESTRICTED_FS` | Opt out of evidence confinement entirely. | `false` | Accepts `true`/`1`. Lets the API read **any** file the process can access. Only for a trusted local workstation. Ignored when `SEANCE_EVIDENCE_ROOTS` is set. |
| `SEANCE_AUDIT_HMAC_KEY` | Server-held secret that turns the audit hash chain into a **keyed** HMAC-SHA256 chain. | none — the chain is a plain SHA-256 chain | **Required on a non-loopback bind: the server refuses to start without it** unless `SEANCE_AUDIT_UNKEYED_OK=true`. Unkeyed, the chain can be recomputed by anyone with database write access, so a rewritten history still verifies; keyed, it cannot be reforged without the key. Must be **stable across restarts** — the server never invents one, and never persists one, because a key stored beside the database would sit exactly where an attacker with database access already is. Each audit row records a 16-hex-character **fingerprint** of the key it was written under (never the key), so verification knows which key each row needs. Startup logs the fingerprint of the key in force. |
| `SEANCE_AUDIT_HMAC_KEY_PREVIOUS` | Colon-separated retired audit keys. | unset | The rotation story: move the old value here and put the new one in `SEANCE_AUDIT_HMAC_KEY`. Rows written under a retired key keep verifying under it, and the verify result counts them as keyed. A row whose fingerprint matches no key the server holds is reported as a **break** naming the fingerprint and this variable. The whole value is also tried as a single key, so a retired key that itself contains a colon still verifies the rows written under it. |
| `SEANCE_LUKS_PASSPHRASE`, `SEANCE_BITLOCKER_PASSWORD`, `SEANCE_BITLOCKER_RECOVERY_KEY`, `SEANCE_IOS_BACKUP_PASSWORD` | Evidence-unlock credentials for ingest, the environment form of `--luks-passphrase`, `--bitlocker-password`, `--bitlocker-recovery-key` and `--ios-backup-password`. | unset | Prefer these to the flags: a credential on the command line is visible to every user of the host in `ps` and is written to the shell's history. Held in process memory only, never persisted, and never echoed in `--help` output. They apply to a whole run; a LUKS or BitLocker credential for **one** volume already in a case is supplied instead through `POST /cases/{id}/artifacts/{id}/credential` (the Needs attention field, or `/unlock` in the REPL), with no restart. |
| `SEANCE_UNLOCK_TTL_SECS` | How long an encrypted iOS backup unlocked for reading (`POST /cases/{id}/artifacts/{id}/unlock`) stays unlocked. | `28800` (8 hours) | A positive whole number of seconds; anything else falls back to the default. The backup's unwrapped class keys are held in process memory only, for one case. They are forgotten on `DELETE` of the same route, when the case is deleted, or on restart; after expiry they are never returned, and are dropped by the next keyring operation or by the expiry sweep, at most a minute past expiry (the sweep runs every `min(TTL, 60 s)`). Each forget except a restart writes an `unlock_forgotten` audit row (`reason=lock`, `case_delete` or `expired`). Neither the password nor the class keys are written to disk, but the unlock, like ingest, writes the backup's decrypted `Manifest.db` (file names, domains, wrapped per-file keys) to a temporary file in the system temp directory for as long as the check takes. Shorten the TTL on a shared host, and put the temp directory on storage you trust. |
| `SEANCE_AUDIT_UNKEYED_OK` | Explicit opt-out of the unkeyed-chain refusal on a non-loopback bind. | `false` | Accepts `true`/`1`. Startup then warns loudly, every report and the verify endpoint say the chain is unkeyed, and the audit log is **not** a tamper-evident record. For a throwaway lab instance only. |
| `SEANCE_SIGNING_CERT` | Path to an X.509 certificate (PEM) for tamper-evident report signing. | unset | Reports are served **UNSIGNED** and marked as such if unset. Mount read-only. |
| `SEANCE_SIGNING_KEY` | Path to the matching private key. | unset | Required together with `SEANCE_SIGNING_CERT`; startup fails if the pair cannot be loaded. Protect the key. |
| `SEANCE_SIGNING_NAME` | Signer name embedded in signed reports. | unset | Optional label only. |
| `SEANCE_ORGANISATION` | Deployment-wide default organisation for the examiner details on a report. | unset | The **case's own** organisation wins where one is recorded; this only fills the gap for an instance where every case belongs to the same body. Blank is treated as unset. |
| `SEANCE_REPORT_CLASSIFICATION` | Deployment-wide default classification marking on generated reports. | unset | Same precedence: a per-case value wins. Renders nothing when unset — a report is not given a marking nobody asked for. |
| `SEANCE_YARA_RULES` | Path to the YARA rule set to load. | unset | The scanner module is **not registered at all** when unset, and the startup log says so. A blank value is treated as unset rather than as the path `""`, which would fail to load and abort the run. A rule set that cannot be loaded is logged against this variable by name. |
| `SEANCE_MEMORY_REGEX` | One regular expression to search **memory** for, over each process's own address space and the kernel's. | unset | Memory only: the file-content search is the case's own index, which understands encodings. **One pattern, never a list** — no character can separate a list of regular expressions without cutting one of them in half — so several go in as `(a\|b)`. The pattern is **not** trimmed: `\s+$` means something. A pattern this build cannot compile **aborts the run**, logged against this variable by name, because a run that searched for nothing must not resemble one that searched and found nothing. With neither this nor `SEANCE_YARA_RULES` set, the memory pattern-scan stage reports that it *did not run*. |
| `SEANCE_MEMORY_STRINGS` | Path to a file of **physical** offsets produced by the examiner's own `strings -t d` over a raw memory image: lines of an offset and the text found there. | unset | The `strings_map` stage attributes each offset to every address space whose page tables reach that frame. Séance runs no `strings` of its own — the minimum length, the encodings and the scope are the examiner's decisions — so with this unset the stage reports that it *did not run*, which is not a statement about what the image holds. A file that is **named** and will not read **aborts the run**, logged against this variable by name. Walking every process's page tables is the cost of the answer: on a 10 GiB capture with 130 processes it is of the order of a gigabyte of table reads, done once for the whole file however many offsets are in it. |
| `SEANCE_MEMORY_STRINGS_RADIX` | Which base the offsets in that file are written in: `decimal`, `hex` or `octal`. | `decimal` | **Stated, never guessed.** `strings -t x` writes hexadecimal, and a hexadecimal file read as decimal does not fail cleanly: every line containing a letter is rejected, and the rest parse into frames gigabytes from the truth with nothing on the row to show it. A value that is not one of the three **aborts the run**. The record publishes which radix was used, which `strings -t` flag produces it, and what proportion of the file was rejected under it — over half is what a wrong radix looks like. |
| `DATABASE_URL` | SQLite connection string. | `sqlite:seance.sqlite` (relative to the working directory) | Not `SEANCE_`-prefixed. Point at the persistent volume, e.g. `sqlite:/data/seance.sqlite`. |
| `HOME` | Fallback starting directory for the filesystem browser when no evidence root is configured. | OS-provided | Minor; browsing is still gated by the evidence-root policy above. |

---

## Memory limits, and not being OOM-killed

An ingest whose footprint outgrows the host is stopped by the kernel's OOM killer with
`SIGKILL` at a moment of the kernel's choosing. It leaves no record of why it stopped, and
on a busy host it can take `sshd`, the desktop session or a virtual machine down first. Two
measures keep that from happening, and they work together.

**1. The governor inside Séance (`SEANCE_MEMORY_LIMIT`).** Séance watches its own
anonymous memory (`RssAnon` + `RssShmem` from `/proc/self/status`; file-backed pages of a
mapped image are reclaimable and are not counted), the host's `MemAvailable`, and the
tightest cgroup limit on its own cgroup or any ancestor (v2 `memory.max`, v1
`memory.limit_in_bytes`) against a budget, every 250 ms:

| State | Enters at | What happens |
|---|---|---|
| `ok` | - | Nothing. |
| `high` | 85% of the budget (or 90% of the cgroup limit, or host `MemAvailable` under 6%) | One task at a time; the task queue's in-memory window drops from 10,000 to 64 artifacts so new work spills to disk at once. |
| `critical` | 95% (97%, 3%) | No new task is dispatched. If it lasts `SEANCE_MEMORY_GRACE_SECS` (30 s) the run is **stopped**. |

Each state is left 10 points lower than it is entered, so a reading at a boundary does not
flap. Every transition is logged (`memory pressure ok -> high: process ...`), and the
run-end log line carries the peak anonymous and resident memory, the time spent at each
state and the number of stops.

A stop is the same clean path an examiner's cancel takes: in-flight module runs finish and
their batches are written, queued work drains *unprocessed*, and every source still being
walked is stamped `inventory_incomplete` with `processing_state: cancelled` and this
sentence in `incomplete_detail`:

> stopped: memory limit reached at 11.2 GiB (budget 12.0 GiB, host available 1.1 GiB), 41230
> tasks done. Processing of this source ended early ... Re-ingest the source with a higher
> SEANCE_MEMORY_LIMIT or fewer SEANCE_WORKERS

Nothing is dropped silently: the case says it is partial, and the ingest-run row is closed
(not left `running` for the next start to call "interrupted"). **A stopped ingest is an
incomplete ingest.** Re-ingest the source to complete it.

The host-wide `MemAvailable` signal only counts when Séance itself holds at least 1 GiB: a
small process does not fail a job because a neighbour is hogging memory.

Note what the governor cannot do. It samples four times a second, so a single module that
allocates many gigabytes in under a quarter of a second still outruns it; and it is
cooperative, so it cannot shrink what a running module already holds. It narrows the window
in which the kernel has to act; it does not remove the need for the second measure.

**2. A hard ceiling from the operating system.** Put Séance in a cgroup with a limit below
the host's RAM, so that if it ever is killed, the victim is Séance and nothing else. The
governor reads that limit and sets its budget under it.

```bash
# One-off, unprivileged, systemd user session. MemoryHigh makes the kernel reclaim and
# throttle before MemoryMax kills; MemorySwapMax=0 stops a runaway from swapping the host
# into the ground first.
systemd-run --user --scope \
  -p MemoryHigh=11G -p MemoryMax=12G -p MemorySwapMax=0 \
  env SEANCE_MEMORY_LIMIT=10G SEANCE_WORKERS=4 SEANCE_OOM_SCORE_ADJ=500 \
  ./seance --headless
# Or one evidence file, no server. A stopped scan prints "[!] STOPPED ... INCOMPLETE" and
# exits non-zero, so a script does not mistake a partial ingest for a finished one:
#   ... ./seance scan --path /evidence/disk.E01
```

For a service, put `MemoryHigh=`, `MemoryMax=`, `MemorySwapMax=0` and `OOMScoreAdjust=500`
in the unit's `[Service]` section; for a container, `--memory=12g --memory-swap=12g`
(`docker-compose.yml`: `mem_limit`). Leave the governor's budget a clear gap under the
kernel's ceiling (10G under 12G above): the governor is the graceful exit, the ceiling is
the backstop, and a budget equal to the ceiling gives the kernel the last word.

Sizing: memory is dominated by how many workers parse large structures at once, so when
the governor reports `high` often, lower `SEANCE_WORKERS` before raising the limit. Several
ingests sharing one host each have their own governor and their own budget; the budgets
should sum to less than the host, because no governor sees another process's budget.


## Security posture

Séance defaults are chosen to fail safely when the server is exposed:

- **Authentication is on by default.** `SEANCE_AUTH_ENABLED` must be explicitly
  set to `false` to turn it off, and doing so also disables CSRF protection.
- **No guessable credential on a network-exposed bind.** The initial admin is
  seeded once, the first time the server starts with an empty users table:
  from `SEANCE_ADMIN_PASSWORD` when set; otherwise a generated password logged
  exactly once on a non-loopback bind, or the well-known `seance` on a loopback
  bind — and in both of those cases the password must be changed at first
  login. The seed never rotates on restart. The shipped compose file requires
  the variable, so a stock deployment never relies on the fallback.
- **Per-process JWT secret.** When `SEANCE_JWT_SECRET` is unset a random secret
  is generated per run. This is safe (no forgeable default) but invalidates all
  sessions on restart — set a stable secret in production.
- **Evidence access is confined.** File access is restricted to
  `SEANCE_EVIDENCE_ROOTS`. When unset it fails closed to the working directory;
  full-filesystem access requires the explicit `SEANCE_ALLOW_UNRESTRICTED_FS`
  opt-in. Mount evidence read-only so ingestion can never alter originals.
- **Refuses unsafe binds.** The server aborts at startup if authentication is
  disabled while bound to a non-loopback address — it will not silently expose
  every endpoint to the network with no login.
- **Login rate limiting.** `/api/v1/auth/login` is throttled per-username
  (5/60s) with a global backstop (50/60s) to slow credential brute-force.
- **Logout revokes the session.** Every token carries a `jti`; `POST
  /api/v1/auth/logout` records it in `revoked_tokens` and every later request
  bearing that token is refused (`SESSION_REVOKED`, 401) until it would have
  expired anyway. The table is the durable record, so a restart does not
  resurrect a logged-out session, and rows past their token's expiry are purged
  on each logout.
- **The audit chain is tamper-evident only once it is keyed, and an exposed
  server refuses to run unkeyed.** With `SEANCE_AUDIT_HMAC_KEY` unset the audit
  log is a plain SHA-256 hash chain: anyone who can write to the database can
  edit an entry and recompute every digest after it, and the result verifies.
  Keyed, the chain is HMAC-SHA256 under a secret the database does not hold, and
  cannot be reforged without it. Because the audit log *is* the chain of
  custody, the server treats an unkeyed chain on a non-loopback bind the way it
  treats a disabled login: it **aborts at startup** and names the variable. The
  shipped `docker-compose.yml` requires the key alongside the other two secrets:

  ```sh
  echo "SEANCE_AUDIT_HMAC_KEY=$(openssl rand -hex 32)" >> .env
  ```

  The key is deliberately **not** generated and persisted for you: a key kept
  beside the database would sit exactly where an attacker with database access
  already is, and the server would then report `tamper_evident: true` for a
  property the chain does not have. A loopback bind keeps the startup warning
  instead of the refusal; `SEANCE_AUDIT_UNKEYED_OK=true` is the explicit,
  loudly-logged opt-out for a throwaway instance.

  **Rotation.** Every audit row records the fingerprint (first 16 hex characters
  of a domain-separated SHA-256; never the key itself) of the key it was written
  under. To rotate, move the old value into `SEANCE_AUDIT_HMAC_KEY_PREVIOUS`
  (colon-separated if there are several; a key that contains a colon is also
  tried whole, so it need not be re-expressed) and set the new one in
  `SEANCE_AUDIT_HMAC_KEY`. Rows written under the retired key keep verifying
  under it; rows written from now on carry the new fingerprint. Drop a retired
  key and the rows written under it become a **break** whose reason names the
  fingerprint and this variable — they are not silently re-read as unkeyed.

  **Keying an existing log.** Setting the key on an installation with history
  does not turn that history into a broken chain, and does not re-label it as
  keyed. The verify result (`GET /api/v1/cases/{id}/audit_log/verify`, the audit
  page, and every report) states `keyed_rows`, `unkeyed_rows` and
  `tamper_evident_from` — the id of the first row from which a passing
  verification is evidence of no alteration. `tamper_evident` is true only when
  a key is configured **and** every checked row was written keyed; rows before
  `tamper_evident_from` verified as internally consistent only. An unkeyed row
  that *follows* a keyed one is reported as a break, because that is what
  replacing the tail of a keyed chain from database access looks like.

  **Anchor the head, or deletion of the most recent entries stays invisible.**
  Keying proves the entries the log *holds* were not altered or reordered. It
  cannot prove the log is *complete*: deleting the last N rows leaves no gap,
  and the shortened chain still verifies — and a database writer, the actor
  keying defends against, is exactly who can do that. The only defence against a
  deleted tail is an anchor held where that writer cannot reach it. Every
  verification publishes the chain **head** (`head_id`, `head_hash`) and the
  verified length (`checked`); record the head — a SIEM, write-once media, a
  signed operator log, anywhere off this host — and pass it back as
  `?expected_head_id=<id>&expected_head=<hash>` on a later verify. The anchor
  names an **entry**, not the current head: an audit log grows on every examiner
  action, so its head legitimately moves, and a check against the current head
  would report tampering during ordinary use. The response's `completeness`
  object carries a machine-readable `verdict` — `intact` (the anchored entry is
  still present with the same hash, and growth since is ordinary), `truncated`
  (the anchored entry is gone: entries were deleted) or `diverged` (it is
  present but rewritten). Supplying only one half of the anchor is refused with
  a 400 rather than silently reported as unchecked. **Recording the anchor is an operator
  obligation, not an optional extra:** with no anchor supplied the verdict says
  completeness was *not checked* — which is not the same as complete — and an
  anchor recorded onto the same host an attacker already owns is no anchor at
  all.

## TLS (reverse proxy)

`seance_api` speaks plain HTTP. Terminate TLS at a reverse proxy in front of the
container and set `SEANCE_COOKIE_SECURE=true` so the auth cookie is only sent
over HTTPS.

## Serving the web UI

The SPA bundle is baked into the image at `/app/frontend/dist`. Serve it from
the same reverse proxy that terminates TLS and proxies the API. Extract the
bundle for the proxy with:

```bash
docker cp $(docker compose ps -q seance):/app/frontend/dist ./dist
```

Example nginx front (TLS termination + static SPA + API proxy):

```nginx
server {
    listen 443 ssl;
    server_name seance.example.org;

    ssl_certificate     /etc/ssl/seance/fullchain.pem;
    ssl_certificate_key /etc/ssl/seance/privkey.pem;

    # Static SPA bundle copied out of the image.
    root /srv/seance/dist;
    index index.html;

    # API → the seance_api container.
    location /api/ {
        proxy_pass http://seance:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Server-Sent Events (/api/v1/events) need buffering off.
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }

    # SPA client-side routing fallback.
    location / {
        try_files $uri /index.html;
    }
}
```

With TLS in front, remember to set `SEANCE_COOKIE_SECURE=true` on the container.

## Report signing

To produce tamper-evident case reports, provide an X.509 certificate and private
key:

```bash
docker run ... \
  -e SEANCE_SIGNING_CERT=/secrets/signing.crt \
  -e SEANCE_SIGNING_KEY=/secrets/signing.key \
  -e SEANCE_SIGNING_NAME="Acme Forensics Lab" \
  -v /path/to/secrets:/secrets:ro \
  seance:latest
```

Both `SEANCE_SIGNING_CERT` and `SEANCE_SIGNING_KEY` must be present or startup
fails. When they are absent, reports are still generated but are stamped as
UNSIGNED / not tamper-evident.

---

## Stopping the server

Stop `seance` with **SIGTERM** (`docker compose stop`, `systemctl stop`,
`kill <pid>`) or **Ctrl-C**. Either one is handled: the server stops accepting
work, commits the search index, and folds the write-ahead log back into
`seance.sqlite` before the process exits.

Both steps matter for what the next start sees:

- The search index auto-commits every 1000 documents. Without the final commit,
  up to 999 already-indexed artefacts are absent from search results — and an
  artefact that returns no hits reads exactly like one that does not contain
  the term.
- Everything a write touches sits in `seance.sqlite-wal` until a checkpoint
  moves it back. A large log is recovered on the next start *before any
  connection opens*, so a server stopped with an unchecked multi-gigabyte WAL
  can appear to hang, then fail with a pool timeout.

**`kill -9` skips both.** If a server was killed hard and the next start is slow
or times out, checkpoint the log by hand and start again:

```bash
sqlite3 <workspace>/seance.sqlite "PRAGMA wal_checkpoint(TRUNCATE);"
```

A case deletion interrupted by any stop is safe: the case stays marked
`deleting`, is hidden from case listings, and the purge resumes at the next
start from where it stopped.


## Backups

Persistent state for a `seance_api` deployment lives under the working
directory (`/data` in the image, the `seance-data` volume in compose):

- `seance.sqlite` — the case database. SQLite runs in **WAL** journal mode, so
  a live copy must account for the `-wal` and `-shm` sidecar files.
- `search_index/` — the Tantivy full-text index.

(The `seance` CLI keeps the equivalent state, plus `seance.log`, inside its
`workspace/` directory; back that directory up instead when using the CLI.)

### An in-flight search export holds index segments on disk

A search export walks the whole match set under **one pinned index snapshot**, so
that its rows are one index state rather than several. Holding a snapshot means
holding the Tantivy segment files it refers to: while an export runs, the space
those segments occupy cannot be reclaimed by a merge, even after the documents in
them have been superseded. On a case being actively ingested, a long export can
therefore keep index disk from shrinking for as long as it runs.

Three things bound this, and none of them needs operator action:

- the pin's lifetime **is** the response body's. A client that disconnects drops
  the body, which drops the pin, which releases the segments. There is no cleanup
  path to forget because there is no cleanup path.
- a pin left unread for longer than the server holds one open (5 minutes) is
  reclaimed, and the export ends with a verdict row saying so. This is what
  stops a stalled download holding disk on an evidence volume indefinitely; it
  does not fire on a download that is still moving.
- the export handler logs when a pin is taken and released, carrying the number
  of live pins. That log line is how an operator watches this — the server
  exposes no metrics endpoint.

The trade is deliberate: the alternative bound is an export that ends early, and
an incomplete exhibit on a case under time pressure costs more than bounded,
observable, self-releasing disk.

### The workspace holds evidence-derived content, in the clear

> **Treat the workspace as you treat the evidence.** It is not a cache of
> pointers; it is a second copy of a substantial part of what was examined.

Specifically:

| In the workspace | What it holds |
|---|---|
| `search_index/` | Each artifact's extracted text, **stored**, up to 16 MiB per artifact. A search hit renders from this index, not from the evidence, which is why the text is kept rather than only indexed. **This includes recovered credential values** — a decrypted NT hash or LSA secret is in the index in the clear, by design, so that an examiner can search for a hash they already hold. No surface prints it: the search snippet says a value was withheld, and the value itself is released only by the audited reveal. Anything reading the index directly reads the secret. |
| `seance.sqlite` | Artifact metadata, including extracted record content — message bodies, registry values, parsed fields. |
| Thumbnail cache | Decoded images from the evidence, at display size. |
| `seance.log` | Paths, artifact names and module diagnostics. |

None of it is encrypted at rest, and that is deliberate. Séance is a workstation
tool; encrypting its own working set would mean managing a key on the same
machine as the ciphertext, which protects against very little. **Full-disk
encryption is what answers "the evidence laptop was stolen"** — BitLocker,
LUKS or FileVault on the volume holding the workspace — and it is the
deployment's responsibility rather than the application's.

What the application owes you is this list, so that:

- the workspace goes on the same media, and under the same handling regime, as
  the evidence it derives from;
- it is included in secure disposal at the end of a matter. Deleting a case from
  within Séance purges its rows, its search-index documents and its cached
  media; disposing of the *workspace* is a separate act and is yours;
- a backup of the workspace is treated as a backup of evidence-derived content,
  not as application state.

The evidence images themselves are **not** copied into the workspace. Séance
reads them where they are, which is why the container mounts them read-only.

**Consistent backup (recommended):** stop the service so no writes are in
flight, copy the volume, then restart.

```bash
docker compose stop seance
docker run --rm -v seance-data:/data -v "$PWD":/backup debian:trixie-slim \
  tar czf /backup/seance-backup-$(date +%F).tar.gz -C /data .
docker compose start seance
```

**Hot backup:** checkpoint the WAL into the main database first so the copied
`.sqlite` file is self-contained, then copy it together with the search index:

```bash
# Fold the WAL back into seance.sqlite
sqlite3 /data/seance.sqlite "PRAGMA wal_checkpoint(TRUNCATE);"
# Copy the DB (plus any remaining -wal/-shm) and the Tantivy index
cp -a /data/seance.sqlite /data/seance.sqlite-wal /data/seance.sqlite-shm \
      /data/search_index  /backup/  2>/dev/null || true
```

Restore by stopping the service, replacing the volume contents with the backup,
and starting again. Keep the database and the search index from the **same**
backup so they stay consistent; if they ever diverge, the index can be rebuilt
from the database via the search-service rebuild path.
