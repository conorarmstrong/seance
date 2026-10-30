# Continuous Integration

## Workflows

| Workflow | Trigger | What it gates |
|----------|---------|---------------|
| `test.yml` | push/PR to `main` | test suite (Ubuntu + macOS), doc tests, the golden-image regression, the frontend (typecheck, lint, tests), `rustfmt --check` and the feature-edge check, `clippy -D warnings`, `cargo deny check` (licences, bans, sources, advisories), coverage (informational), security audit |
| `audit.yml` | push/PR to `main` | `cargo audit` (RustSec advisories) and the no-`unsafe` guard (`scripts/check-unsafe.sh`) |
| `coverage.yml` | push/PR to `main` | coverage reporting — informational, never a correctness gate |
| `fuzz.yml` | schedule / dispatch | fuzz targets for the untrusted container/filesystem parsers |
| `release.yml` | tag / dispatch | `scripts/check-version.sh <tag>` first (a tag that disagrees with the manifests fails before anything is built), then cross-platform release binaries — Linux/macOS/Windows × x86_64/aarch64, each with an explicit per-target feature set (Linux and macOS carry the full default set; Windows x86_64 is `e01` only, Windows ARM64 has no native-C feature) — plus the Web UI bundle, a `.sha256` beside every asset, and the validation report when one is present at the repo root |
| `selfhosted-linux-ci.yml` | dispatch only | the build, fmt, clippy, **test (`--all-features`), doc-test and Web UI** gates on a self-hosted Linux runner, plus `cargo audit` and the third-party corpus gates. A self-hosted runner consumes no hosted minutes, which is why the full set is duplicated here. Hosted GitHub Actions has not run on this history, so `scripts/ci-gate.sh` is the local mirror. |

**The test job needs three native libraries, and only one of them comes from a
package manager on both platforms.** `cargo test --workspace --all-features`
turns on `e01`, `esedb` and `heic`, so the job links libewf, libesedb and
libheif. macOS takes all three from Homebrew. Ubuntu 24.04 ships libheif 1.17
and `libheif-rs` is pinned to the v1_19 API, so the Linux job builds libheif
1.19.8 from source exactly as `release.yml` does, cached on the version. A job that
installs libewf alone fails on `The system library libheif was not found`. Adding a feature to the default set adds a library
here.

Two of those rows are worth reading twice, because both are jobs whose absence
from the local gate once let them stay red on `main` for weeks:

* **`cargo deny check`** is not `cargo audit` repeated. They read the same lock
  file and not the same ignore list — `audit.toml` and `deny.toml` are
  maintained by hand — and they do not agree about scope either: cargo-deny
  reports informational advisories for workspace-direct dependencies only,
  where cargo-audit reports them transitively. `deny.toml` also carries the
  **licence** policy. Séance is MIT, so the constraint is not on what it may
  depend on but on what a dependency demands of anything shipped with it — which
  is why `GPL-2.0-or-later` is on the allow-list with an argument beside it
  rather than by default.
* **The unsafe-code guard** checks that every crate carries
  `#![forbid(unsafe_code)]` or sits on the documented FFI allow-list. It is the
  gate a newly added crate silently fails.

The **golden-image** job builds a synthetic multi-partition E01 from the
checked-in generator and asserts Séance recovers exactly what was written, with
`SEANCE_REQUIRE_CORPUS=1` so a missing or failed image is a hard failure rather
than a silent skip.

### The corpus-gated known-answer tests, and which of them CI runs

Most of the evidence the known-answer tests are graded against is not in the
repository, so each such test asks for its corpus through an environment
variable and **skips, saying so, when the variable is unset**
(`documentation/TESTING.md` owns the table of variables). Which of them any
workflow sets is a fact worth stating plainly, because a green run over a
skipped test is not a comparison that happened:

* `test.yml` sets **`SEANCE_GOLDEN_IMAGES`** (with `SEANCE_REQUIRE_CORPUS=1`,
  so the golden image is a hard requirement there), and, in its
  `app-schema-corpus` job, **`SEANCE_PLASO_TEST_DATA`** and
  **`SEANCE_SKYPE_SAMPLES`** at a fresh `git clone --depth 1` of plaso's
  `test_data/` — the plaso halves of the §1.4a app-schema corpus gates (see
  below).
* `selfhosted-linux-ci.yml` sets **`SEANCE_CFREDS_HACKING`**, **`SEANCE_ALIHADI_NTFS`**,
  **`SEANCE_LONEWOLF`** + **`SEANCE_SYMBOL_DIRS`** and **`SEANCE_LINUX_MEM`**, each
  under `SEANCE_REQUIRE_CORPUS=1`, from `$CORPUS_ROOT` on the runner; and, for
  the CTF halves of the §1.4a app-schema gates, **`SEANCE_APP_SCHEMA_CORPUS`**,
  **`SEANCE_ANDROID2022_TREE`**, **`SEANCE_CHROMEBOOK_TREE`**,
  **`SEANCE_MACOS2021_TREE`**, **`SEANCE_IOS2022_TREE`**,
  **`SEANCE_SNAPCHAT_SAMPLES`**, **`SEANCE_SIGNAL_IOS_SQLITE`** and **`SEANCE_ANDROID14_WHATSAPP`** (plus
  `SEANCE_PLASO_TEST_DATA` again, because the browser corpus test reads plaso
  beside the CTF trees), under both `SEANCE_REQUIRE_CORPUS=1` and
  `SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1`.
* **No workflow sets any of the following** (pinned by
  `seance_tests/tests/ci_corpus_wiring_test.rs`, which fails if a workflow sets
  a variable on this list):
  `SEANCE_HIVE_CORPUS`, `SEANCE_REGISTRY_CORPUS`, `SEANCE_SETUPAPI_CORPUS`,
  `SEANCE_EVTX_CORPUS`, `SEANCE_HACKSHAW_CORPUS`, `SEANCE_BULK_CORPUS`,
  `SEANCE_LONEWOLF_OBJECTS_DATA`, `SEANCE_PERSEVERANCE_OBJECTS_DATA`,
  `SEANCE_CFREDS_OBJECTS_DATA`, `SEANCE_LINUX_SWAP_MEM`, `SEANCE_LINUX_NOBLE_MEM`,
  `SEANCE_WIN_HIBERFIL`, `SEANCE_WIN_HUFFMAN_HIBERFIL`, `SEANCE_CFTT_STRING_SEARCH`.
  The tests behind them — hive unallocated-cell recovery, EVTX fragment
  recovery, the YARA surfaces, the feature histogram, the WMI repository scan, the Linux mount-crossing
  paths and hook checks, the hibernation restore sets, the CFTT string-search
  grader — **run only on a developer machine that has the evidence**. In CI
  every one of them prints its skip line and passes. Nothing in the tree
  claims otherwise; this paragraph exists so that nobody reads the CI badge
  as covering them.

Two gates need a word each. **`SEANCE_HIVE_CORPUS` has a default**:
when it is unset, `seance_hive`'s tests look for `reference/plaso/test_data`
beside the crate, and only skip when that directory is absent — so on a
checkout that has fetched the plaso fixtures they run without anyone setting
anything, and under `SEANCE_REQUIRE_CORPUS=1` an absent default directory is a
failure. **`SEANCE_APP_SCHEMA_CORPUS` is gated by its own switch,
`SEANCE_APP_SCHEMA_CORPUS_REQUIRED`**, and not by `SEANCE_REQUIRE_CORPUS`: the
four crates that read it (`seance_plugin_android_sms`, `seance_plugin_call_history`,
`seance_plugin_imessage`, `seance_plugin_twitter`) test each file with a bare
`exists()` and default the directory to `test_data/app_schema_corpus/`, which
is gitignored and holds nothing on a fresh clone. A job that wants those
comparisons to count must set `SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1`, or an
absent corpus passes.

### The §1.4a app-schema corpus gates: which job runs which half

The app-parser schema-drift tests (ROADMAP §1.4a) read two kinds of store in
the same test: plaso's public `test_data/`, and stores extracted from CTF
images the project cannot redistribute. They are therefore split across two
jobs, and each job has its own guard against a pass over nothing:

* **`app-schema-corpus` in `test.yml` (hosted).** Fetches plaso commit
  `e3401d1558f3` (pinned in `test.yml`, `selfhosted-linux-ci.yml` and
  `scripts/ci-gate.sh`; upstream's current HEAD no longer ships these stores in
  `test_data/`) into `reference/plaso`, then a step checks with `test -f` that `mmssms.db`,
  `imessage_chat.db`, `twitter_android.db`, `contacts2.db`, `skype_main.db`
  and `chrome_history/History` are there — the four group C crates read plaso
  at that default path with a bare `exists()`, so without the check a failed
  clone would pass. It then runs the corpus gates in
  `seance_plugin_browser_history`, `_skype`, `_android_sms`, `_imessage`,
  `_twitter` and `_call_history` with `SEANCE_PLASO_TEST_DATA` and
  `SEANCE_SKYPE_SAMPLES` set. It deliberately sets **neither**
  `SEANCE_REQUIRE_CORPUS` nor `SEANCE_APP_SCHEMA_CORPUS_REQUIRED`: the CTF
  halves of the same tests cannot be satisfied on a hosted runner, so either
  switch would fail the job by design. The enforcement there is the corpus
  gate's named-but-missing panic plus the `test -f` step. It costs hosted
  minutes, and does not run while that quota is exhausted (below).
* **The "App-parser schema drift — CTF-derived stores" step of `corpus-gates`
  in `selfhosted-linux-ci.yml`.** Exports the seven CTF variables from
  `$CORPUS_ROOT` (`app_schema_corpus`, `android2022/data`,
  `chromebook/decrypted`, `macos2021/tree`, `ios2022ffs/tree`,
  `snapchat_samples`, `signal_ios/signal.sqlite`) under both switches, and the
  job's "Confirm the corpora" step lists each of them. Every test is filtered
  by name so the job-level `SEANCE_REQUIRE_CORPUS` demands only the variables
  this step exports.

`seance_tests/tests/ci_corpus_wiring_test.rs` pins both jobs statically. It
cannot prove the self-hosted runner exists or holds those trees; it
proves only that a run of the workflow asks for them.

The other plaso-derived gates could join the hosted job the same way, and what
that needs is recorded here rather than left to be rediscovered: export
`SEANCE_HIVE_CORPUS`, `SEANCE_REGISTRY_CORPUS`, `SEANCE_SETUPAPI_CORPUS` and
`SEANCE_BULK_CORPUS` at plaso's `test_data/` (the EVTX gate also needs
`system.evtx` from the omerbenamram `evtx` samples beside plaso's
`System2.evtx`, so it wants a directory assembled from both).

## Standing-CI status and the hosted-minutes caveat

Push/PR CI runs on GitHub-**hosted** runners, which consume the account's
monthly Actions minutes. When that quota is exhausted (a billing state, not a
code problem), hosted jobs stay `queued` indefinitely and their logs return
`BlobNotFound` — a "red" run with no failed step. This is not something the
codebase can fix.

Two ways to keep CI trustworthy while that is the case:

1. **Local gate (always available).** `scripts/ci-gate.sh` runs the *exact*
   checks CI runs, on your machine, so a build can be certified green before it
   is submitted regardless of the hosted-CI state:

   ```sh
   scripts/ci-gate.sh            # full gate: all twelve
   scripts/ci-gate.sh --quick    # everything except the test gates
   scripts/ci-gate.sh --release  # also link-build seance_cli in release mode
   scripts/ci-gate.sh --tag v1.0.0-rc  # also check the tag names the manifests' version
   scripts/ci-gate.sh --extra    # also the plaso schema-drift and golden-image jobs
   ```

   **Eleven gates, in the order they run, then two opt-in jobs.** The count is
   stated so that a gate missing from the script cannot go unnoticed behind an
   ALL CHECKS PASSED banner. Gate numbers in this document are the numbers in
   this table.

   | # | Gate | Command | In `--quick` |
   |---|------|---------|:---:|
   | 1 | rustfmt | `cargo fmt --all -- --check` | yes |
   | 2 | clippy, warnings as errors | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | yes |
   | 3 | test suite | `cargo test --workspace --all-features` | no |
   | 4 | doc tests | `cargo test --workspace --doc` | no |
   | 5 | dependency audit | `cargo audit` | yes |
   | 6 | licences, bans, sources, advisories | `cargo deny check` | yes |
   | 7 | no-`unsafe` guarantee | `scripts/check-unsafe.sh` | yes |
   | 8 | forensic defect-class lint | `scripts/forensic-lint.sh` | yes |
   | 9 | version agreement | `scripts/check-version.sh` | yes |
   | 10 | feature edges | `scripts/check-feature-edges.sh` | yes |
      | 11 | frontend: install, typecheck, lint, then tests and build | `npm --prefix frontend ci`, `run typecheck`, `run lint`, `test`, `run build` | typecheck and lint only |
   | `--extra` | plaso schema drift (six `cargo test` runs), then the golden-image regression | needs network and the image-building tools | no |

   Gate 2 is a **superset** of CI's clippy job: `--all-targets` also lints test,
   bench and example code, which CI's `--all-features` invocation does not.
   Gate 8 has no CI counterpart yet — it catches the patterns that silently
   fabricate evidence as a class, so they cannot be reintroduced one file at a
   time: zero-pad parses, swallowed lookups, unescaped `LIKE`, reorderable tree
   walks, a stray validation report, and **a run of whitespace inside a
   user-facing string literal**. That last one is what a
   continuation whose trailing backslash was lost leaves behind, and it is in
   the gate because the generated method-statement register — the document this
   project describes as the paragraph an examiner reads aloud — shipped twenty
   lines reading "carrying the              service". SQL literals are excluded,
   because a query's internal whitespace is insignificant and is not prose; a
   deliberate run (an 8.3 short name's padding, `strings -t d` output, a column
   pad in test output) is annotated `forensic-lint: allow RAGGED-STRING` with a
   justification, on the matched line or the line above it.
   Gate 9 asserts that `seance_cli`, `seance_api` and `frontend/package.json`
   all report the single `[workspace.package].version` from the root
   `Cargo.toml` — the number that reaches `tool_version` in signed reports and
   `seance --version`. `release.yml` runs the same script with the tag as its
   argument, so `v1.0.0` cannot be cut from a tree whose manifests say
   otherwise.
   Gate 10 asserts that each native-C feature (`e01`, `esedb`, `heic`,
   `video-thumbs`) really opts out: with the feature off, the C crate must be
   absent from `seance_cli`'s dependency graph. A plain edge from `seance_api`
   to `seance_plugin_webcache` pulled `libesedb-sys` into every `e01`-only
   build and fails the x86_64 Windows job; the call sites were gated and the edge was not, and nothing
   checked the edge. `cargo tree` only, so it runs in the `fmt` job.
   Every gate runs even when an earlier one fails, so one run shows the whole
   picture rather than the first thing to break.

   **A skipped gate is a failure, not a pass.** `cargo-deny` is the one gate the
   script will not install on demand — it is a large build, and forcing it on
   someone running `--quick` would be rude — so when it is absent the gate is
   *not run*. That outcome is kept in its own bucket, separate from gates that
   ran and found something, because they call for different next actions:

   | Banner | Exit | Meaning |
   |---|:--:|---|
   | `CI GATE: ALL CHECKS PASSED` | 0 | Every gate ran and passed. This is the only certified state. |
   | `CI GATE INCOMPLETE (n not run)` | 1 | Everything that ran passed, and that is not the same as passing. CI will still run the missing gates. |
   | `CI GATE FAILED (n)` | 1 | A gate ran and found something. Any not-run gates are listed underneath. |

   Exit code is 0 only when every gate ran *and* passed. Run the full gate
   before any push.

   Corpus-gated tests self-skip **inside** the test suite rather than in the
   script: `test_data`-gated tests skip when the corpus is absent, exactly as on
   CI. Set `SEANCE_REQUIRE_CORPUS=1` to turn that skip into a failure — see
   [TESTING.md](TESTING.md).

   **That flag only reaches a test that asks for its corpus through
   `seance_core::test_support::corpus`.** A test that skips on a bare
   `if !path.exists()` is invisible to it and prints `ok` whether or not the
   comparison ran; `seance_plugin_webcache` and `seance_plugin_srum` were both
   in that state and now name `SEANCE_WEBCACHE`. When adding a
   fixture-gated test, use the helper.

   **What the local gate does not cover**, stated so a green run here is not
   read as a green CI run:

   * the **frontend** job — `npm run typecheck`, `npm run lint`, `npm test` in
     `frontend/`. Run those directly; the help-sync coverage matrix
     (`help-coverage.test.ts`) lives in `npm test` and fails when a
     plugin/container/carving-signature count drifts out of step with the online
     help (see `frontend/src/pages/help/HELP_SYNC.md`).
   * the **golden-image regression**, which needs the image-building toolchain
     the CI job installs.
   * the **corpus gates** in `selfhosted-linux-ci.yml`, which need third-party
     evidence this repository does not carry.

   So the honest claim for a green `ci-gate.sh` is "every Rust gate CI runs
   passed here", not "CI would be green".

2. **Self-hosted runner (does not consume hosted minutes).** Bring a
   self-hosted Linux runner online (register via
   `gh api repos/<owner>/<repo>/actions/runners/registration-token`) and trigger
   `selfhosted-linux-ci.yml` with `workflow_dispatch`. On Apple-silicon hosts use
   the **arm64** runner tarball (the x64 build fails under Rosetta).

## Restoring standing hosted CI

To return to automatic push/PR CI: restore the Actions-minutes billing (or
raise the spending limit) for the account/org that owns the repo. No workflow
changes are required — the configs above will resume running on every push and
pull request. Until then, gate #1 (local) is the source of truth for "is this
build green".
