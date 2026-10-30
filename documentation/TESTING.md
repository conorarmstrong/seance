# Seance Testing Strategy & Plan

> Comprehensive testing approach ensuring robustness and reliability

## How big the suite is

Counted by declaration, not by running it — the workspace suite is
not run end to end on a shared machine, and a figure quoted from a run someone
else did is not checkable:

| Measure | Count | How counted |
|---|---|---|
| Rust test functions | **12,922** | `grep -rE '^\s*#\[(tokio::\|sqlx::)?test\]' --include=*.rs`, excluding `target/` and `reference/` |
| `#[ignore]`d Rust tests | 3 | `grep -rE '^\s*#\[ignore'` over the same set. Two in `seance_search/tests/search_paging_cost_test.rs`, marked *measurement; builds a 60k-document index*; one in `seance_search/tests/byte_sweep_cftt_test.rs` — `a_sweep_of_the_whole_real_image_finds_every_published_offset_of_the_swept_terms`, marked *reads the whole 2 GB image; run with --ignored when the corpus is present* |
| Frontend test cases | **2,315** | `it(` / `test(` at the start of a line in `frontend/src/**/*.test.ts{,x}` |
| Frontend test files | 180 | `find frontend/src \( -name '*.test.ts' -o -name '*.test.tsx' \) \| wc -l` |
| Crates with a `tests/` directory | 26 | `ls -d */tests \| wc -l`; 24 of them hold integration tests and two hold only fixtures |

**A declaration count is an upper bound on what a plain `cargo test` proves.**
It counts corpus-gated tests that skip when their image is absent, and
`#[cfg_attr(debug_assertions, ignore)]` tests that do not run unoptimised. Which
of them actually compared anything is the subject of the corpus gate below, and
that is the number worth quoting in a report.


---

## Testing Philosophy

**"Test Before Trust" - Every feature must have:**
1. ✅ Unit tests for individual components
2. ✅ Integration tests for API endpoints
3. ✅ End-to-end tests for critical workflows
4. ✅ Performance tests for scalability

**No feature is "complete" without passing tests.**

### At least one input the project did not write

Two defects shared a shape: the implementation and its test fixtures
were written from one reading of one specification, so both carried the same
misunderstanding and every test passed.

- **SQLCipher HMAC.** A round-trip through this crate's own encryptor proves
  only that its two halves agree. Fixed by building SQLCipher 4.6.1 from source
  and verifying tags its own OpenSSL provider computed.
- **AVML `end` field.** Read as exclusive when it is inclusive, so no real
  capture could be opened — while all 37 AVML tests passed, because the fixture
  helper wrote `end = start + len`, the same convention backwards. Fixed by
  opening a capture AVML itself produced.

The defence is not more tests in the same style; adding a hundred would have
caught neither. For any format this project both **reads and writes**, or any
format whose fixtures it generates, there must be at least one test input that
came from somewhere else — the reference implementation, another tool, or a real
device. Where that is impossible, say so in `ROADMAP.md` rather than treating a
self-consistent test suite as verification.

**Where it is currently impossible, and said so here.** Two test
sets in the tree are synthetic fixtures written from the same format
description the code implements, and their authors recorded that rather than
letting the green run stand for verification:

- **Jump list `DestList` entries.** The unit tests in
  `seance_plugin_jumplists/src/destlist.rs` build version-1 and version-2+
  entries from the libyal "Jump lists format" layout the decoder follows. What
  keeps them honest is `seance_plugin_jumplists/tests/real_jump_lists.rs`, which
  reads two real plaso jump lists (`1b4dd67f29cb1962…`, Windows 7, DestList v1,
  11 entries; `9d1f905ce5044aee…`, Windows 10, v3, 2 entries) and pins the entry
  numbers, offsets, paths, hosts and times to plaso's *own* checked-in
  expectations for the same files — an independent reading.
- **ARM64 page tables.** `seance_memory/src/translate/arm64_tests.rs` and
  `seance_memory/tests/arm64_address_space_test.rs` walk tables the tests
  themselves wrote, with expected addresses hand-worked from ARM DDI 0487
  §D8.3. Real (QEMU-emulated) AArch64 evidence is the MMUShell pair behind
  `SEANCE_MMUSHELL_AARCH64`: `seance_memory/tests/arm64_mmushell_real_test.rs`
  checks every leaf against an independent walker (`VALIDATION.md` MEM-ARM-1),
  `seance_memory/tests/arm64_64k_blocks_real_test.rs` (`SEANCE_ARM64_64K_4G`, a 4 GiB
  capture of the 64 KiB kernel with six 512 MiB blocks; MEM-ARM-10),
  `seance_memory/tests/arm64_mmushell_other_os_test.rs` does the same for
  FreeBSD, NetBSD and HelenOS (`freebsd/`, `netbsd/` and `helenos/` under the same
  variable; MEM-ARM-9),
  `seance_plugin_memory_linux/tests/arm64_vmcoreinfo_real_test.rs` the root
  from `VMCOREINFO` (MEM-ARM-2), and
  `seance_plugin_memory_linux/tests/arm64_mmushell_discovery_test.rs` the
  banner mappings, the Intel-reads-arm64 hazard and the `kallsyms` decode
  (MEM-ARM-3). No ARM64 hardware capture and no arm64 symbol table is held;
  `BUGS.md` MEM-043 carries what that leaves unexercised.

### Where such an input lives: in the tree, or behind the corpus gate

An input the project did not write arrives one of two ways, and they are
provisioned differently:

**Behind the corpus gate** — real evidence: large, mostly not redistributable,
and never committed. Each is named by an environment variable and the gate
below decides what an absent one means. This is where the disk and memory
images are.

**In the tree** — a small input another implementation produced, committed so
that every clone and every CI run grades against it with nothing to provision
and no variable to set. It lives in `<crate>/tests/fixtures/`, carries a
`README.md` saying what each file holds and what produced it, and is
regenerated by a script in `scripts/` rather than by hand.

Two sets exist:

| Set | What it is | Regenerated by |
|---|---|---|
| `seance_plugin_pcap/tests/fixtures/` | Four files of **real TLS handshake bytes** — one per direction of a TLS 1.2 and a TLS 1.3 connection between an OpenSSL client and an OpenSSL server, dumped by a byte-forwarding proxy in between — plus the certificate the server presented, in DER (what the tests parse) and PEM (what the oracle is run against). The oracles are OpenSSL's own decodes, `openssl s_client -trace` and `openssl x509 -text`, which is what makes the set an input this project did not write: the JA3 cipher, extension, group and point-format lists asserted in `tls_tests.rs` are OpenSSL's lists, not ones a fixture helper and the parser agreed on between themselves. No private key is committed. | `scripts/make-tls-fixtures.sh` |
| `seance_plugin_ocr/tests/fixtures/` | One PNG for the OCR path. | — |

The pcap set is the case that shows why a generator is part of the fixture.
Regenerating it produces a fresh key and certificate, so the bytes change and so
do the certificate's serial, dates and fingerprint: the per-certificate
expectations in `seance_plugin_pcap/src/x509_tests.rs` must then be re-taken from
`openssl x509 -text`. The script writes the certificate in **both** forms for
the same reason — one written and the other not would leave the set describing
two different certificates while every test still passed.

An in-tree fixture is read by the unit tests beside the code, through
`include_bytes!` — which is why a crate can carry a `tests/` directory that
holds fixtures and no tests at all (`seance_plugin_ocr`; `seance_plugin_pcap`
also carries a corpus-gated Case 001 test).

### Extract the region, do not re-sweep the image

When a decoder must find a structure inside a multi-gigabyte capture, do not
debug it by re-running the search. The kallsyms work failed three times at five
minutes an iteration doing exactly that, and succeeded once the arrays were
located *once* and a 3.5 MB region extracted to iterate against — three bugs in
one sitting instead of one fact per attempt.

Locate by anchoring on something already known rather than by shape. The capture
held four copies of `linux_banner`; only the real one was followed by a
plausible symbol count, which identified it unambiguously.

A corpus-gated test must also distinguish **absent** from **produced nothing**.
Returning early when the analysis yields `None` looks identical to skipping for
want of a corpus, and reports a pass either way. In one kallsyms attempt, three of four tests passed while recovering no symbols at all; only
the one with an explicit panic caught it. Gate on the corpus file's presence,
then assert the result is `Some` — the skip and the failure are different
outcomes and must read differently.

The same discipline applies to debugging a *pipeline* against a large capture,
not just a decoder. Image-derived discovery failed on the Oberon capture at
roughly five minutes per attempt, and the first two diagnostic runs each cost
that much to learn one fact. The third hardcoded the two addresses the earlier
runs had established — the banner's virtual address and the page-table root —
skipped the sweep entirely, and ran in 0.27 seconds; it identified the defect on
the first try. **Once a value has been established by an expensive run, put it
in the diagnostic as a constant.** The run that found it does not need repeating.

Delete such a diagnostic once it has done its work. It is scaffolding, not a
test: it asserts nothing, and left behind it would run in every suite and prove
nothing to anybody.

### Test the pipeline against real evidence, not only its parts

Every layer of the Linux memory stack had passing tests, and discovery still
could not profile a single real compressed capture. The defect sat in
`VirtualLayer::require_acquired`, between two well-tested components: the AVML
layer returned exactly what it documents, and the caller asked its question the
wrong way. Unit tests on either side could not see it, because neither side was
wrong on its own.

Nothing had run discovery end to end against a real compressed capture, because
the corpus holds no symbol file for that kernel — so the only route to that code
with real evidence did not exist until symbols could be recovered from the image
itself. **A test that exercises the whole path against real evidence finds
defects that no amount of testing the pieces will**, and the absence of such a
test is worth noticing on its own: if a pipeline cannot be run end to end
against something real, ask what is missing that would let it be.

Cheap corroboration counts too. The Linux swap header parser is checked
field-by-field against what `file(1)` reports for the same bytes, and the AVML
test asserts every segment is page-aligned — a property that is impossible to
satisfy accidentally if the header arithmetic is wrong.

### Hostile-input tests state a time bound, not just a shape

Some defects are not wrong answers but *slow* ones, and a test that only checks
the output cannot see them. `seance_xml_util`, and the EVTX / Office /
`installed_apps` parsers that use it, each carry a regression that asserts a
**wall-clock bound** on parsing a document built to be expensive:

```rust
assert!(elapsed < Duration::from_secs(2),
        "unguarded this input costs ~29 s, so the guard is not in this path");
```

The threshold is set far above the measured cost (~0.1 s) and far below the
unguarded one (~29 s), so it distinguishes the two without being sensitive to
how fast the machine is. Verify such a test is not vacuous by removing the guard
and confirming the test *hangs* rather than merely failing — that is what
proves the bound is load-bearing.

The same bound applies to a parser pointed at raw memory, which is hostile input
by construction rather than by an attacker's choice: nearly every window of a
capture is *not* the structure being looked for.
`kallsyms_hostile_input_test.rs` throws deterministic garbage at
`Kallsyms::find_in` — random bytes, buffers shorter than the structure it looks
for, and runs shaped to satisfy the cheap filter so the expensive structural
walk runs on bytes that were never a table. A panic there aborts a sweep, so
`None` is the only acceptable answer, and one test builds 4 MiB of near-miss
candidates to assert the walk still completes. Use a fixed generator, not a
random one: a failure has to reproduce from the seed the assertion prints.

### I/O doubles come from `seance_core::test_support`, never a private copy

A test that needs a `DataSource` which reads short, dribbles, stalls or fails
takes it from `seance_core::test_support` — `TruncatedSource` (declares more
than it holds: `new`, `halved`, `cut_to`), `DribbleSource` (holds everything,
returns at most `chunk` per call), `StallingSource` and `UnreadableSource` —
and an honest in-memory source is `seance_core::data_source::ByteSliceDataSource`.
Opt in with `seance_core = { path = "../seance_core", features = ["test-support"] }`
under `[dev-dependencies]`.

A private copy asserts a private contract. Before ROADMAP §5.11 retired them
there were 53 such copies under a dozen names; one (the VSS `MemSource`)
zero-filled reads past its end and reported them as full, the fabricated-zeros
behaviour these doubles exist to catch. `seance_tests/tests/no_private_io_doubles_test.rs`
walks the workspace and fails on any `struct` named `ShortSource`,
`ShortReadSource`, `UnderDeliveringSource`, `Oversize[d]Source`,
`OverReportSource`, `HugeDeclaredSource`, `LyingSizeSource`, `HalfReadSource`,
`ChunkedSource`, `MemSource`, `TruncatedSource` or `DribbleSource` outside
`test_support.rs`. A name list only catches a copy that kept its old name: an
adversarial review found renamed copies (`Dribble`,
`MemorySource`, `Mem`) that passed it. So the guard also checks the shape —
any struct whose only field is a `Vec<u8>` and which implements `DataSource`
in the same file, whatever it is called, outside `data_source.rs` and
`test_support.rs`. Thirty-five older copies of that shape (in the archive and
carving crates, many plugin `MockDataSource`s, and one production struct,
`seance_carving`'s `InMemorySlice`) are named in the guard's
`NOT_YET_RETIRED` list; a new copy fails, and so does a listed one that has
gone, so the list can only shrink. A double with a second field (a chunk cap
under another name, a failure counter) is not caught by either check.
A test that needs a shape the module lacks adds it there,
with its own test. A double whose job is something other than the read contract
— routing named siblings, say — keeps that routing local and answers its reads
through a shared double (`seance_plugin_registry`'s `HiveWithLogs` does this).
The guard does not yet cover the 13 `MockDataSource` copies, which are honest
in-memory sources by another name.

---

## Test Structure

Tests are organised **by the crate that owns the behaviour**, not in one central
suite. There is no workspace-root `tests/` directory and there is not meant to
be: 26 crates carry a `tests/` directory of their own — 24 of them with
integration tests in it, and two (`seance_plugin_ocr`, `seance_plugin_pcap`)
holding only `fixtures/` that the unit tests read — and unit tests live beside
the code in `src/` (often in a `tests.rs` module or a `#[cfg(test)] mod tests`).
Both counts come from the tree: `ls -d */tests | wc -l`, and the same list
filtered to the directories holding at least one `.rs` file.

```
seance/
├── seance_core/tests/            # Core logic, ingestion, profiles, DataSource properties
├── seance_db/tests/              # Database layer
├── seance_api/tests/             # API integration
├── seance_tests/src/             # Cross-crate integration suites (CFReDS, Ali Hadi,
│                                 #   golden multipart, canon2, VSS, E01, AFF4, …)
├── seance_memory/tests/          # Acquisition formats against real captures
│   └── KNOWN_ANSWERS.md          #   the memory tier's ground truth
├── seance_plugin_memory_*/tests/ # Volatility parity, per platform
├── seance_plugin_pcap/tests/     # No tests: fixtures only
│   └── fixtures/                 #   real TLS handshake bytes — see below
├── seance_validate/              # The durable known-answer report — see VALIDATION.md
├── seance_benchmarks/benches/    # Criterion benchmarks
├── fuzz/                         # cargo-fuzz targets
└── frontend/src/**/*.test.ts(x)  # React UI (Vitest + RTL + MSW), 163 files
```

The frontend figure is `find frontend/src \( -name '*.test.ts' -o -name
'*.test.tsx' \) | wc -l`; 114 of the 163 are `.tsx`.

Two things sit outside `cargo test` deliberately. `seance_validate` exists
because a `cargo test` run produces no durable artifact and counts a corpus-gated
skip as a pass; see `documentation/VALIDATION.md`. The benchmarks are Criterion
and are run with `cargo bench`; see `seance_benchmarks/README.md`.

No full end-to-end browser automation (Playwright) is wired up.

---

## Timeline Tagging - Test Coverage

### ✅ Unit Tests (`seance_db/tests/timeline_tags_test.rs`) - ALL PASSING

**Test Results:** ✅ 12/12 tests passing

**Test Cases Implemented:**

1. **test_create_timeline_tag** - Create tag with examiner and note
2. **test_create_tag_without_note** - Create tag without optional fields
3. **test_create_tag_idempotent** - INSERT OR REPLACE behavior
4. **test_delete_timeline_tag** - Delete existing tag
5. **test_delete_nonexistent_tag** - Delete returns false for missing tag
6. **test_update_timeline_tag_note** - Update note on existing tag
7. **test_update_nonexistent_tag** - Update returns false for missing tag
8. **test_list_timeline_tags** - List all tags for a case
9. **test_list_tags_empty_case** - Empty list for case with no tags
10. **test_tags_isolated_by_case** - Tags don't leak between cases
11. **test_timeline_query_includes_tags** - LEFT JOIN works correctly
12. **test_cascade_delete_tags_with_case** - ON DELETE CASCADE verified

**Coverage:**
- ✅ CRUD operations
- ✅ Edge cases (empty, nonexistent)
- ✅ Data isolation
- ✅ Database constraints
- ✅ Query integration

### ✅ API Integration Tests (`seance_api/tests/timeline_tags_api_test.rs`) - ALL PASSING

**Test Results:** ✅ 6/6 tests passing

**Test Cases Implemented:**

1. **test_create_tag_api** - POST endpoint creates tag
2. **test_delete_tag_api** - DELETE endpoint removes tag
3. **test_update_tag_note_api** - PUT endpoint updates note
4. **test_list_tags_api** - GET endpoint lists tags
5. **test_delete_nonexistent_tag** - Returns 404 for missing tag
6. **test_invalid_uuid_returns_bad_request** - Returns 400 for invalid UUID

**Coverage:**
- ✅ HTTP methods (POST, GET, PUT, DELETE)
- ✅ Status codes (200, 400, 404)
- ✅ JSON serialization/deserialization
- ✅ Error handling
- ✅ Request validation

### ✅ Web UI Tests (React)

The timeline tagging UI now lives in the React SPA (`frontend/`) and is
covered by component tests, not the removed `seance_gui` browser suite.

**Covered by `frontend/src/pages/timeline/TimelinePage.test.tsx`:**

- Star toggle in the timeline table (`EventsTable` tag column)
- Tag note editing via `TagNoteModal`
- Tagged-only filtering
- Tag state persisted through the API (mutations invalidate react-query keys)

**Tools:**
- Vitest + React Testing Library + MSW (mocked API), run with `npm test`. The pool is pinned
  to half the host's cores (`maxWorkers: '50%'` in `vite.config.ts`): at one worker
  per core a sibling process saturating the machine starved jsdom workers into 5 s timeouts on
  a different test each run, and the per-test timeout is deliberately not raised to hide that.
- 180 test files carrying 2,315 cases — the SPA suite has
  stopped being "the timeline tagging tests plus a few others", and this section
  is a surviving snapshot of one feature rather than a description of frontend
  coverage
- No full end-to-end browser automation (Playwright) is wired yet

---

## Running Tests

### Run one crate's tests — the normal case

```bash
cargo test -p seance_search
cargo test -p seance_api --test search_export_walk_test
```

**Prefer a single crate.** A workspace-wide `cargo test --all` on this tree
links every crate including the E01/libewf FFI, takes long enough to look hung,
and — where several people share a machine — produces timeouts that look like
regressions and are not. A test that fails under load and passes in isolation is
load, not a defect; re-run it alone before treating it as one.

```bash
# Only when you actually need the whole thing, and know what it costs:
cargo test --workspace
```

### Frontend

```bash
cd frontend
npm test
npm run typecheck
npm run lint
LC_ALL=de_DE.UTF-8 npm test   # catches locale-dependent formatting
```

### Run Specific Test Suite
```bash
cargo test -p seance_db timeline_tags
cargo test -p seance_api timeline_tags
```

### Run Single Test
```bash
cargo test -p seance_db test_create_timeline_tag
```

### Run with Output
```bash
cargo test -p seance_db -- --nocapture
```

### Check Test Coverage (requires cargo-tarpaulin)
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html --output-dir coverage
```

---

## Evidence-backed tests and the corpus gate

**Not held.** `~/ctf-evidence` and `~/legacy-lab` are not held. Every variable in the table below whose example path is under either (the Magnet CTF trees and tars, the NIST DFR set, `SEANCE_W2K3_X64_MEM` and the lab VM captures made with `~/legacy-lab/run-w2k3.sh`) now reaches no evidence, so those tests skip. Restore by downloading the public image again (the Magnet and NIST sets are public) or rebuilding the guest.

Some tests compare Séance against real evidence rather than against fixtures
its own authors wrote. The images are large and mostly not redistributable, so
they are never committed; each is reached through an environment variable, and
`seance_core::test_support::corpus` decides what an absent one means.

**The gate has three behaviours, and the third is the point:**

| State | Result |
|---|---|
| Variable unset | Skips, and says so on stderr |
| Variable set, path or file missing | **Fails.** "A pass here would report a comparison that never ran." |
| `SEANCE_REQUIRE_CORPUS=1` and variable unset | **Fails.** The skip itself becomes an error |

Without the third, a corpus that was never provisioned reports `ok`, and a
suite that compared nothing looks identical to one that compared everything.

**Set the variables to absolute paths.** `cargo test` runs each crate's test
binary from that crate's own directory, and the gate resolves the value as
given (`corpus::resolve` does `PathBuf::from(&raw)` and asserts it exists), so
`SEANCE_REGISTRY_CORPUS=reference/plaso/test_data` is looked for under
`seance_plugin_registry/` and the gate **fails** with "is set to ..., which does
not exist" — it does not skip. The rows below that say "locally
`reference/plaso/test_data`" mean the workspace-relative location, to be passed
as `$PWD/reference/plaso/test_data` from the workspace root.

### The variables

| Variable | Holds | Used by |
|---|---|---|
| `SEANCE_CFREDS_HACKING` | NIST CFReDS "Hacking Case" (`4Dell_Latitude_CPi.E01`/`.E02`) | `seance_tests` — asserts NIST's own published answers from `TestAnswers.pdf` |
| `SEANCE_ALIHADI_NTFS` | Ali Hadi's `NTFS-HiddenFiles.E01` (474 KB) | `seance_tests` — asserts the MD5/SHA-1 in the image's own FTK acquisition log, and grades §5.4's free-space regions on a real volume: 24,831 clusters of 4 KiB, two free runs, cluster 0 never in one (it holds the boot sector, so a free region over it would mean the bit convention was inverted), and the largest region scanned end to end by the carver |
| `SEANCE_GOLDEN_IMAGES` | `golden_multipart.E01` — a **reproducible** synthetic multi-partition image built by `scripts/build_golden_images.sh` (≈320 KB) | `seance_tests` — asserts the full `E01 → partition → filesystem → file` chain for NTFS, ext4, FAT16 and APFS against the layout the script declares |
| `SEANCE_LONEWOLF` | Digital Corpora 2018 Lone Wolf `memdump.mem` | Windows memory parity, Win10 |
| `SEANCE_MEM_IMAGES` | `win-xp-laptop.img`, `Win11Dump.mem`, `linux-sample-1.bin` | Memory parity, XP / Win11 / Linux |
| `SEANCE_LINUX_MEM` | An AVML capture of a live Linux host, plus `vmlinux.btf` and `kallsyms.txt.gz` from the **same boot** | `seance_memory` — the AVML reader, BTF extraction, and kallsyms recovery, each against something the kernel produced; `btf_symboltable_test` also grades the BTF enumerations carried into the ISF against the kernel's headers and `bpftool btf dump` |
| `SEANCE_WIN11_BITLOCKER_IMAGE` | `win11-bitlocker-xts256.raw` — a Windows 11 25H2 disk encrypted with XTS-AES-256 | `seance_plugin_bitlocker`, `seance_tests` — modern BitLocker detection, recovery-password unlock, and the full chain through to named files |
| `SEANCE_WIN11_BITLOCKER_PARTIAL` | `partial-encrypted.raw` — the same machine imaged at 56% converted | `seance_plugin_bitlocker` — a volume seized mid-encryption |
| `SEANCE_WIN11_MEMORY` | `memory-unlocked.raw` — RAM from that machine while its volume was unlocked | `seance_plugin_memory_windows` — discovery, processes, handles, recovered files, credentials, and the `strings` reverse mapping (`a_physical_offset_two_processes_map_names_both_of_them`, whose ground truth is `KUSER_SHARED_DATA`'s frame established by the *upward* walk before the reverse map is asked anything); the `suspicious_threads` stage (`suspicious_threads_on_the_clean_win11_capture` — 0 findings over 123 processes; 2 kernel starts on kernel threads, 76 on threads whose `SystemThread` is clear and so judged by no stage, which leaves the record incomplete) |
| `SEANCE_W2K3_X64_MEM` | A directory holding `mem.raw`, the lab Windows Server 2003 R2 SP2 x64 capture (4 GiB map, SHA-256 `592a60af…d1c8`, made by `~/legacy-lab/run-w2k3.sh` and QMP; see `VALIDATION.md` MEM-XP-6) | `legacy_xp_corpus.rs` — `the_server_2003_x64_capture_timer_table_equals_the_volatility2_walk`: the same 211 timers in the same buckets as a Volatility 2 walk. Needs `SEANCE_SYMBOL_DIRS` with the ISF of `ntkrnlmp.pdb` `03185083…0C98`-2 (`seance fetch-symbols`) and `--release` |
| `SEANCE_M57_VISTA_MEM` | A directory holding `terry-2009-11-16.mddramimage`, the M57-Patents "Terry" Vista SP2 x86 non-PAE capture (535,130,112 bytes, SHA-256 `1d8d446d…6806`, Digital Corpora, held in place) | `legacy_xp_corpus.rs` — `the_vista_capture_declared_entry_table_contains_every_volatility2_timer`: all 51 Volatility 2 timers reached, `VALIDATION.md` MEM-XP-5. Needs `SEANCE_SYMBOL_DIRS` and `--release` |
| `SEANCE_WIN11_VC_MEMORY` | `mem.raw` of the Windows 11 lab VM with VeraCrypt 1.26.29 and one AES volume mounted (10 GiB; `~/win11-lab/vc/`; not redistributable) | `seance_plugin_memory_windows` `tests/win11_veracrypt.rs` — both master keys and the container, `VALIDATION.md` MEM-VC-2. `--release` |
| `SEANCE_WIN11_VC1259_MEMORY` | `mem.raw` of the same VM with VeraCrypt 1.25.9 and two AES volumes mounted (10 GiB; `~/forensic_corpora/lab_win11_veracrypt_1259/`) | `tests/win11_veracrypt_1259.rs` — all four keys and both containers, `MEM-VC-3`. `--release` |
| `SEANCE_XP_WMI_DIR` | `forensic_corpora/lab_xp_wmi/`: `OBJECTS.MAP`, `INDEX.MAP`, `OBJECTS.DATA` and `INDEX.BTR` of the 2004 Windows XP disk of the CFReDS Hacking Case (inodes 11943, 11944, 5507, 5508) | `seance_plugin_asep` `wmi_index_tests` — `a_windows_xp_repository_is_read_through_its_index_map_and_agrees_with_python_cim`, `VALIDATION.md` `WMI-9` |
| `SEANCE_WIN11_ETWALL_MEMORY`, `SEANCE_WIN11_ETWALL_TRUTH` | `forensic_corpora/win11_tamper_plant_etwall/tamper-etwall.raw` and `plant-truth.json`: a Windows 11 capture with `EtwEventWrite` patched in 107 processes | `seance_plugin_memory_windows` `win11_tamper_etwall` (release only), `VALIDATION.md` `MEM-W11-TAMPER-2` |
| `SEANCE_W2K3_WMI_DIR` | `forensic_corpora/lab_w2k3_wmi/`: the `FS` directory of a fresh Windows Server 2003 R2 SP2 x64 install with one planted ActiveScriptEventConsumer (`INDEX.BTR`, `MAPPING.VER`, `MAPPING1.MAP`, `MAPPING2.MAP`, `OBJECTS.DATA`) | `seance_plugin_asep` `wmi_index_tests` — `a_windows_server_2003_repository_is_read_through_its_xp_era_mapping_and_index_and_agrees_with_python_cim`, `VALIDATION.md` `WMI-8` |
| `SEANCE_WIN11_VC{122,123,1247,1267,12615,12620,12624}_MEMORY` | `forensic_corpora/lab_win11_veracrypt_{122,123,1247,1267,12615,12620,12624}/mem.raw`: Windows 11 captures with VeraCrypt 1.22, 1.23, 1.24-Update7, 1.26.7, 1.26.15, 1.26.20 and 1.26.24 and seven volumes mounted (10 GiB each) | `seance_plugin_memory_windows` `win11_veracrypt_{122,123,1247,1267,12615,12620,12624}` (release only), `VALIDATION.md` `MEM-VC-6` |
| `SEANCE_LINUX_FAT_DIR` | `forensic_corpora/lab_linux_fat/`: four 64 MiB FAT32 and exFAT volumes written by Linux 5.15's own drivers, with the creation listings (`make-fat.sh`) | `seance_plugin_fat` `tests/real_linux_fat_test.rs` — deleted exFAT directories through the stale FAT chain, deleted FAT names joined across clusters, `VALIDATION.md` `LINUX-FAT-1` |
| `SEANCE_WIN11_VC{10e,10f,10f1,10f2,112,113,114,116,117,118,119,121,125,1254,1257}_MEMORY` | `forensic_corpora/lab_win11_veracrypt_{10e,10f,10f1,10f2,112,113,114,116,117,118,119,121,125,1254,1257}/mem.raw`: Windows 11 captures with VeraCrypt 1.0e, 1.0f, 1.0f-1, 1.0f-2, 1.12, 1.13, 1.14, 1.16, 1.17, 1.18, 1.19, 1.21, 1.25, 1.25.4 and 1.25.7 and seven to ten volumes mounted (10 GiB each, kept as `mem.raw.zst`: `zstd -d --sparse mem.raw.zst -o mem.raw`); 1.19 and later by `VeraCrypt Format.exe /create`, 1.0e to 1.18 by `scripts/oracle/tc7_make_volume.py ... 5 vera` | `seance_plugin_memory_windows` `win11_veracrypt_{10e,10f,10f1,10f2,112,113,114,116,117,118,119,121,125,1254,1257}` (release only), `VALIDATION.md` `MEM-VC-7` |
| `SEANCE_WIN11_TC{60,60a,61,61a,62,62a,63,63a,70,70a,71,72}_MEMORY` | `forensic_corpora/lab_win11_truecrypt{60,60a,61,61a,62,62a,63,63a,70,70a,71,72}/mem.raw`: Windows 11 captures with TrueCrypt 6.0, 6.0a, 6.1, 6.1a, 6.2, 6.2a, 6.3, 6.3a, 7.0, 7.0a, 7.1 and 7.2 and eight volumes mounted (10 GiB each, kept as `mem.raw.zst`); volumes written by `scripts/oracle/tc7_make_volume.py` (header version 4 for 6.x, 5 for 7.x) | `win11_truecrypt{60,60a,61,61a,62,62a,63,63a,70,70a,71,72}` (release only), `MEM-VC-7` |
| `SEANCE_WIN11_TC71A_MEMORY` | `mem.raw` of the same VM with TrueCrypt 7.1a and eight volumes mounted (10 GiB; `~/forensic_corpora/lab_win11_truecrypt71a/`; volumes written by `scripts/oracle/tc7_make_volume.py`) | `tests/win11_truecrypt71a.rs` — every key of the eight and the eight containers, `MEM-VC-5`. `--release` |
| `SEANCE_WIN11_VCCK_MEMORY` | `mem.raw` of the same VM on VeraCrypt 1.26.29 with seven Camellia and Kuznyechik volumes mounted (10 GiB; `~/forensic_corpora/lab_win11_veracrypt_ck/`) | `tests/win11_veracrypt_ck.rs` — every key of the seven and the seven containers, `MEM-VC-4`. `--release` |
| `SEANCE_WIN11_VCCK1259_MEMORY` | `mem.raw` of the VM on VeraCrypt 1.25.9 with the same seven (10 GiB; `~/forensic_corpora/lab_win11_veracrypt_ck1259/`) | `tests/win11_veracrypt_ck1259.rs` — the same on the other version, whose ids differ. `--release` |
| `SEANCE_WIN11_VC1260_MEMORY` | `mem.raw` of the same VM on VeraCrypt 1.26.29 with seven more volumes mounted: Serpent, Twofish and five cascades (10 GiB; `~/forensic_corpora/lab_win11_veracrypt_1260/`) | `tests/win11_veracrypt_1260.rs` — every key of the seven and the seven containers, `MEM-VC-3`. `--release` |
| `SEANCE_WIN11_VCCASCADES_MEMORY` | `mem.raw` of the same VM with five more volumes mounted: Twofish, AES-Twofish, Serpent-AES, Twofish-Serpent, Serpent-Twofish-AES (10 GiB; `~/forensic_corpora/lab_win11_veracrypt_cascades/`) | `tests/win11_veracrypt_cascades.rs` — every key of the five and the five containers, `MEM-VC-3`. `--release` |
| `SEANCE_S22_VC{12614,12618}_MEMORY` | `forensic_corpora/lab_s2022_vc/run_{12614,12618}/mem.raw`: Windows Server 2022 captures with VeraCrypt 1.26.14 and 1.26.18 and the same seven volumes mounted (5 GiB apparent each) | `tests/win2022_veracrypt_{12614,12618}.rs` — every master key of every volume and each container decoded on the pool region chosen from the loader entries. Release only. |
| `SEANCE_CANON2_DIR` | `forensic_corpora/lab_camera_canon2/`: the volumes of six generations of the Digital Corpora `nps-2009-canon2` Canon PowerShot SD800IS card (`canon2-gen<N>.img`, FAT12 from sector 51 of each E01) with `canon2.tsk.tsv`, The Sleuth Kit's listing and `icat` hashes | `seance_plugin_fat` `tests/real_canon_camera_test.rs` — the listing equals TSK's, every live file reads as TSK reads it, 7 of 26 camera-erased photos recovered exactly and every one flagged incomplete |
| `SEANCE_W19_VC{123h2,124,124h1,124u2,124u4,124u5,124u6}_MEMORY` | `forensic_corpora/lab_w19_vc/run_<tag>/mem.raw`: the Server 2019 guest with VeraCrypt 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, -4, -5 and -6 and the same seven volumes mounted | `tests/win2019_veracrypt_<tag>.rs` — every master key and each container on the 1.19 to 1.26.24 geometry with the 1.25.9 ids. Release only. |
| `SEANCE_W19_VC12628_MEMORY` | `forensic_corpora/lab_w19_vc/run_12628/mem.raw`: the Server 2019 guest with VeraCrypt 1.26.28 Beta4 and the same seven volumes mounted | `tests/win2019_veracrypt_12628.rs` — every master key and each container, on the 1.19 to 1.26.24 geometry with 1.26.29's ids. Release only. |
| `SEANCE_W19_VC12629_MEMORY` | `forensic_corpora/lab_w19_vc/run_12629/mem.raw`: a Windows Server 2019 (build 17763.379) guest with VeraCrypt 1.26.29 and seven volumes mounted (5 GiB apparent) | `tests/win2019_veracrypt_12629.rs` — every master key of every volume and each container decoded on the labelled pool region (the loader entries lie in it on this build); needs `ntkrnlmp.pdb/8B11040A5928757B11390AC78F6B6925-1.json.xz` among the symbols. Release only. |
| `SEANCE_W10_VC1259_MEMORY` | `forensic_corpora/lab_w10_vc/run_1259/mem.raw`: a Windows 10 Enterprise 1607 (build 14393) guest with VeraCrypt 1.25.9 and seven volumes mounted (5 GiB apparent) | `tests/win10_veracrypt_1259.rs` — every master key of every volume and each container decoded on the pool region chosen from the loader entries; needs `ntkrnlmp.pdb/DD08DD42692B43F199A079D60E79D217-1.json.xz` among the symbols. Release only. |
| `SEANCE_S22_VC12629_MEMORY` | `mem.raw` of a Windows Server 2022 (build 20348.587) guest with VeraCrypt 1.26.29 and seven volumes mounted: Serpent, Twofish, Camellia, Kuznyechik, AES-Twofish, Serpent-AES, Kuznyechik-Twofish (5 GiB apparent; `~/forensic_corpora/lab_s2022_vc/`) | `tests/win2022_veracrypt_12629.rs` — every master key of every volume and each container decoded, on the pool region chosen from the loader entries because the type map names it `MiVaPagedPool`; needs `ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1.json.xz` among the symbols. Release only. |
| `SEANCE_WIN11_VCCIPHERS_MEMORY` | `mem.raw` of the same VM with a Serpent volume and an AES-Twofish-Serpent cascade mounted (10 GiB; `~/forensic_corpora/lab_win11_veracrypt_ciphers/`) | `tests/win11_veracrypt_ciphers.rs` — all eight master keys (the Twofish ones recovered from their schedules) and both containers, `MEM-VC-3`. `--release` |
| `SEANCE_SAMSCLASS_2008_MEM` | A directory holding `memdump.mem`, the samsclass.info CNIT 121 Windows Server 2008 SP1 x86 PAE capture (SHA-256 `d3b13f22…77f4`, not redistributable) | `seance_plugin_memory_windows` `tests/legacy_xp_corpus.rs` — `the_server_2008_declared_entry_legacy_table_matches_volatility`: the declared `_KTIMER_TABLE_ENTRY` form, `VALIDATION.md` MEM-XP-4. Needs `SEANCE_SYMBOL_DIRS` and `--release` |
| `SEANCE_LINUX_CTF` | A directory holding `LenovoFinal.E01` — the Magnet 2022 Linux CTF image, whose second GPT partition is a 67 GB ext4 volume | `seance_tests` — grades §5.4's free-space regions on real ext4: blocks numbered from the volume's start, one bitmap per block group stitched across groups, block 0 never in a region, and the measurement of the free-region ceiling (1,360,455 free runs, of which the ceiling declines 1,356,359 covering 14,379,802,624 bytes, 37.6% of the free space) |
| `SEANCE_CFREDS_LEAKAGE` | A directory holding NIST CFReDS 2015 "Data Leakage" `cfreds_2015_data_leakage_pc.E01`–`.E04` and `cfreds_2015_data_leakage_rm#1.E01`/`rm#2.E01` | `seance_tests` `free_space_distribution` — the free-region ceiling's cost on the Windows 7 PC's two NTFS volumes and the two removable media (exFAT, FAT32). The same test also measures the volumes behind `SEANCE_ALIHADI_NTFS`, `SEANCE_CFREDS_HACKING`, `SEANCE_LINUX_CTF` and the two VM-disk variables below when they are set; results in `VALIDATION.md` under NTFS-FREE-1. Also `seance_tests` `slack_ingest_cost` (with `SEANCE_CFREDS_HACKING`) — what the file-slack pass publishes and the MFT parse time with it on; results in `VALIDATION.md` under SLACK-1 |
| `SEANCE_JAMMY_DISK`, `SEANCE_NOBLE_DISK` | The `linux-lab` (**not held, the jammy rows no longer run**) and `noble-lab` (**also not held**) VM disks (`~/linux-lab/jammy.img`, `~/noble-lab/noble.img`), **as raw conversions** (`qemu-img convert -O raw`) — their qcow2 clusters are zlib-compressed, which the qcow2 reader refuses | `seance_tests` `free_space_distribution` — the same measurement on lightly used ext4 roots and their EFI partitions |
| `SEANCE_LINUX_SWAP_MEM` | A directory holding `mem.raw` and `swap-area.raw` from one boot of a 5.15 host (Ubuntu 22.04, a KVM guest built for this project, with ground truth; **not held, these tests skip**) | `seance_plugin_memory_linux` — `swap_real_capture_test`: a swapped page located through a PTE and read back out of the attached area; `paths_real_capture_test`: PID 1's fds 0–2 read `/dev/null` across the devtmpfs mount, every crossing path begins with a mount point the mount list knows, sockets and pipes render as the kernel renders them, and the workload's argv matches the bytes in the raw image; `hooks_real_capture_test`: a stock guest has no candidate hook and every check runs; `lsmod_real_capture_test`: `autofs4` (which the guest's serial console records systemd inserting) is listed and every module's state is named `MODULE_STATE_LIVE` from the image's own enumeration. `seance_memory` — `image_pattern_scan_swap_test` over `swap-area.raw` |
| `SEANCE_LINUX_NOBLE_MEM` | A directory holding `mem.raw` from an Ubuntu Noble 6.8 host (**the only one held, `~/noble-lab`, is not held; these tests skip**) | `seance_plugin_memory_linux` — `kallsyms_modern_kernel_test`: the 6.4+ kallsyms layout, which reordered the arrays; `hooks_real_capture_test`: no candidate hook, module text extents from `module.mem[MOD_TEXT]` at the image's own `mod_mem_type` index, and eBPF types named from the image's own `bpf_prog_type`; `lsmod_real_capture_test`: `autofs4` listed, states named, and every module's `mem[]` regions decoded into the size columns |
| `SEANCE_WIN_CRASHDUMP` | A Windows crash dump with `PAGEDU64` and a physical memory block | `seance_memory` `real_image_test`, `seance_plugin_memory_windows` `crash_kernel_bitmap_test` |
| `SEANCE_WIN_MINIDUMP` | A Windows minidump | `seance_memory` `real_image_test` — the **refusal** path: the header's bugcheck facts are read and no address space is produced |
| `SEANCE_WIN_HIBERFIL` | A real NT10 `hiberfil.sys` — locally the Windows 11 build 26200 capture, 8,499,130,368 bytes, whose guest wrote 65,536 `HIBRMARK` marker pages before hibernating | `seance_memory` `hibernation_corpus_test` — both restore sets walk to the page counts the header states (boot 40,004, kernel 511,499), every one of the 65,536 marker pages is byte-exact, and the string count over the reconstruction is accounted for; `seance_plugin_memory_windows` `win11_corpus_analysis` — the reconstruction through the container stage and the examiner's rules search over it. **Both codecs**, plain Xpress and Xpress-Huffman: on this layout bit 30 of a table header marks Huffman, and 30,479 of the 31,969 kernel tables carry it |
| `SEANCE_WIN_HUFFMAN_HIBERFIL` | An NT6.3 (Win8.1 / Server 2012 R2) `hiberfil.sys` (**the only one held, in `win81-lab`, is not held; these tests skip until one is rebuilt**) | `huffman_hiberfil_test` — the Xpress-Huffman codec against 131 real blocks; `seance_memory` `hibernation_corpus_test` — both restore sets to the header's counts (16,664 and 113,548 pages), where bit 31 is Huffman and bit 30 alone is plain `XpressMax` — the opposite of the NT10 reading of the same bit |
| `SEANCE_WIN_NT63_HIBERFIL` | The same era's hiberfil | `nt63_hibernation_test` — the NT6.2/6.3 restore-set layout |
| `SEANCE_DEFERRED_IMAGES` | A directory of real multi-segment EWF sets | `seance_core::ingestion` — segment discovery against a real EWF set |
| `SEANCE_BROWSER_SAMPLES` | Real Chrome/Firefox/Edge history databases | `seance_plugin_browser_history` `real_samples` |
| `SEANCE_IOS_SAMPLES` | Real gold-backup iOS databases (a flat directory; `real_gold_samples` asserts `>100` calendar events, `>50` notes, `>1000` photo assets against a backup this project no longer holds) | `seance_plugin_ios_artifacts` `real_gold_samples`. **Not** the iOS known-answer set: that is the committed Magnet 2022 iPhone 8 fixtures under `seance_plugin_ios_artifacts/tests/fixtures/magnet2022_ios15/` (`tests/magnet2022_ios15_test.rs`, no variable; `test_data/README.md`) |
| `SEANCE_THUMBCACHE_SAMPLES` | A directory of real `thumbcache_*.db` | `seance_plugin_thumbcache` |
| `SEANCE_WIN_TIMELINE_SAMPLES` | A directory holding a real `ActivitiesCache.db` | `seance_plugin_win_timeline` |
| `SEANCE_DSSTORE_SAMPLE` | A real `.DS_Store` | `seance_plugin_dsstore` |
| `SEANCE_PE_SAMPLE` | A signed Windows PE | `seance_plugin_pe` — Authenticode through the full pipeline |
| `SEANCE_HEVC_MOV` | A QuickTime/HEVC clip | `seance_api` — HEVC handling |
| `SEANCE_REGISTRY_CORPUS` | A directory of real hives, one per file name the tests ask for: `SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT`, `UsrClass.dat`. Locally this is `reference/plaso/test_data`, which is in `.gitignore` | `seance_plugin_registry` — UserAssist, BAM, MUICache, the shell MRUs, device properties, network interfaces, `MountedDevices`, Windows Search, the `sk` security ring, and the SAM `F`/`V` accounts, each against answers measured off the hive; `seance_plugin_yara` `surfaces_real_tests` — the `registry_value` surface over `NTUSER.DAT` (5,602 values: 3,569 scanned as stored bytes, 2,033 re-encoded from a rendering) |
| `SEANCE_SETUPAPI_CORPUS` | A directory holding `setupapi.dev.log` and `setupapi.setup.log`. Locally the same `reference/plaso/test_data` | `seance_plugin_setupapi` — the section, boot-session and exit-status counts, of which the section counts are independently asserted by plaso's own checked-in test for the same two files |
| `SEANCE_PST14_CORPUS` | A directory holding `m57_jean_outlook.pst`, the 2,326,528-byte Outlook mailbox extracted from `nps-2008-jean.E01` (NPS M57-Jean, `https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2008-m57-jean/`, SHA-256 `e17b8c39…1119`; `/Documents and Settings/Jean/Local Settings/Application Data/Microsoft/Outlook/outlook.pst`). Locally `test_data/pst_old` | `seance_plugin_email` `pst512_corpus_tests` — every one of its 258 live messages against libpff's reading (`tests/fixtures/pst_old/m57_jean_outlook_libpff_oracle.tsv`), and recovery with its 62 stale-entry messages cut from the live tree |
| `SEANCE_PUBLIC_PST_CORPUS` | A directory holding six public PST stores: `pstsdk-sample1.pst`, `pstsdk-sample2.pst`, `pstsdk-test_ansi.pst`, `pstsdk-test_unicode.pst`, `pstsdk-submessage.pst` (enrondata/pstsdk test stores) and `tika-variousBodyTypes.pst` (Apache Tika), all Apache-2.0, pinned by SHA-256 in `seance_plugin_email/tests/fixtures/pst_public/PROVENANCE.md`. Locally `~/forensic_corpora/public_pst/stores` | `seance_plugin_email/tests/public_pst_real_test.rs` and `public_pst_recipients_test.rs` (recipient tables against libpff, `VALIDATION.md` `PST-PUBLIC-2`) and `public_pst_cjk_test.rs` (a Japanese ANSI store against its Unicode twin, `PST-PUBLIC-3`; the store directory also holds `pst-extractor-contacts.pst` and `pst-extractor-contacts97-2002.pst`) — every message libpff lists is published in its folder with its subject and attachment count, two ANSI and four Unicode stores, two of them read by this crate's own reader after the linked reader refuses them |
| `SEANCE_PST23_CORPUS` | A directory holding `nromanoff_stark_research_labs.pst`, plaso's `test_data/nromanoff@stark-research-labs.com.pst` (version 23, 59,442,176 bytes, SHA-256 `bab64f35…d6013`, Apache-2.0). Locally `~/forensic_corpora/plaso_pst` | `seance_plugin_email` `pst512_v23_corpus_tests` - its 543 live items against libpff's reading (`tests/fixtures/pst_old/nromanoff_v23_libpff_oracle.tsv`), the three messages recovered from Deleted Items, and recovery with a stale-entry message cut from the live tree |
| `SEANCE_HIVE_CORPUS` | A directory of real hives; today only `SAM` is asked for. **Defaults** to `reference/plaso/test_data` beside `seance_hive` when unset, so on a checkout that has fetched plaso's fixtures these run without the variable; an absent default directory skips (and fails under `SEANCE_REQUIRE_CORPUS`), a named-but-missing file panics. Gated by hand in `seance_hive/src/tests/mod.rs` because that crate has no dependencies | `seance_hive` — `corpus_tests`, `security_tests`, `unallocated_tests`: the `sk` ring, the SAM key tree, and the freed `nk`/`vk` cells in the SAM's unallocated space (3 keys at `0x3218`/`0x3520`/`0x4078` under `0x9b0`), hand-decoded with an independent cell-chain walk before the assertions were written |
| `SEANCE_EVTX_CORPUS` | A directory holding `System2.evtx` (plaso's `test_data`: a real Security log, 200,000 bytes, third chunk truncated by whoever copied it) **and** `system.evtx` (the omerbenamram `evtx` project's samples: chunk 14's slack holds 79 stale records). Locally these are in two directories, so a symlink directory is assembled | `seance_plugin_evtx` — `recovery_tests`: fragment recovery with the file header zeroed, a chunk header zeroed, a template's fragment header overwritten, chunks copied into unrelated bytes at sector offsets, and the slack of a reused chunk |
| `SEANCE_CARVE_REAL_ROOTS` | Colon-separated directories of real files of any kind (locally `reference/`, `test_data/`, `/usr/share`, `/usr/lib`, `/usr/bin`: about 210,000 files) | `seance_carving` — `real_files_survive_their_own_header_block_check` (ignored): every signature that claims a file unsized must not refuse that file's first block in `data_check`, nor refute the whole file (up to 256 MiB) in `header_confirmed_by_source`, whose confirmed / refuted / could-not-look outcomes are printed apart per signature (the macOS `User Pictures` TIFFs, directories 229–689 KB in, were run through it); a refusal by a signature listing the file's own extension fails, others are printed |
| `CARVE_SWEEP_OUT` (and `CARVE_SWEEP_ROOT`, default `~/forensic_corpora`) | Where to write the carve list of the raw engine over DFTT #11, DFTT #12 and the 90 NIST DFR images | `seance_carving` — `tests/corpus_sweep.rs` (ignored, run `--release`): one line per carve (image, offset, size, signature, validated), so two runs diff a signature change carve by carve |
| `SEANCE_HACKSHAW_CORPUS` | A directory holding `HD001_MFT.dat`, a real 35.8 MiB `$MFT` whose records carry 216 named `$DATA` streams, 204 resident, 191 of them `Zone.Identifier`. Locally `reference/hackshaw/test_data`, gitignored | `seance_plugin_yara` — `surfaces_real_tests`: the `ads` surface, 191 `[ZoneTransfer]` hits measured independently off the streams' own bytes |
| `SEANCE_BULK_CORPUS` | A directory holding `gcp_logging.jsonl` (plaso `test_data`, 21,883 bytes, sha256 `028852c61f98fc63e39b3f17f19ab3bbaec4837b386dfcd3c811fab43042ca9b`). Locally `reference/plaso/test_data` | `seance_plugin_bulk` — the `FeatureHistogramSummary` counts against `grep -aoiE … \| sort \| uniq -c` measured off the file before the record existed |
| `SEANCE_EMLX_CORPUS` | A directory holding `pronom_research/2.emlx` and `pronom_research/9.emlx`, two messages Apple Mail 13.4 wrote (PRONOM_Research, **no licence**, so not committed). Locally `~/forensic_corpora/emlx_samples` | `seance_plugin_email` — `tests/emlx_real_test.rs`: the byte-count line (701 and 18,173), the plist values (`date-received` 1698374610, raw `flags` 8623685697, `conversation-id` 7) and no plist in the body. The same file's hoover-testdata tests (`1498.partial.emlx` with its `.emlxpart`, MIT) use committed fixtures under `tests/fixtures/emlx/` and need no variable |
| `SEANCE_SIGNAL_IOS_SQLITE` | The **file** `grdb/signal.sqlite` extracted from the Magnet 2022 iOS FFS zip (`~/ctf-evidence/ios2022ffs/…/*_files_full.zip`, member `/private/var/mobile/Containers/Shared/AppGroup/92EFD8F4-…/grdb/signal.sqlite`) — SQLCipher 4 with a plaintext SQLite header and an 80-byte reserve | `seance_plugin_signal` — the store is reported `StoreEncrypted`, and the header's bytes 60..63 (`360193054`, ciphertext) are **not** read as a schema version |
| `SEANCE_ANDROID14_WHATSAPP` | The directory holding the live `msgstore.db` from the Hickman Android 14 Pixel 7a (`~/forensic_corpora/hickman_android14/whatsapp`; default `test_data/whatsapp_android14`) | `seance_plugin_whatsapp` (`the_real_android14_msgstore_resolves_every_field`): 230 messages read, no field unresolved. Set by the self-hosted `corpus-gates` job under `SEANCE_APP_SCHEMA_CORPUS_REQUIRED` |
| `SEANCE_APP_SCHEMA_CORPUS` | A directory of CTF-derived app databases, named as the tests ask: `android2022_mmssms.db`, `android2022_calllog.db`, `android2022_tw_1489429766507835392-61.db`, `android2022_tw_0-61.db`, `magnet2019_contacts2.db`, `macos2021_chat.db`, `ios2022_sms.db`, `ios2022_CallHistory.storedata` (with `-wal` siblings where the source had one). **Defaults** to `test_data/app_schema_corpus/`, gitignored and empty on a fresh clone. The plaso halves of the same tests (`mmssms.db`, `contacts2.db`, `imessage_chat.db`, `twitter_android.db`) are read from `reference/plaso/test_data` directly | `seance_plugin_android_sms`, `seance_plugin_call_history`, `seance_plugin_imessage`, `seance_plugin_twitter` — the §1.4a corpus-diff harness: each real store parses in its validated range with every column resolved, no `ParserStaleWarning`, and at least the record count measured when the range was declared. **Not** gated through `seance_core::test_support::corpus`: each file is tested with a bare `exists()`, so `SEANCE_REQUIRE_CORPUS` does not reach it — set **`SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1`** to make an absent file fail instead of pass |
| `SEANCE_PLASO_TEST_DATA` | plaso's `test_data/` directory (`git clone --depth 1 https://github.com/log2timeline/plaso`): Chrome `History` at `meta.version` 20/32/33/36, `cookies.db` at 5, `Cookies-68.0.3440.106` at 10, `Web Data` at 77, Firefox `places.sqlite` at `user_version` 10/23/75, Firefox cookies at 5/12, Safari `History.db` at 13 | `seance_plugin_browser_history` — `tests/corpus.rs`: every real store a validated range endpoint was read from, parsed with the version, the required columns and a record floor asserted (e.g. plaso `cookies.db` 560 cookies) |
| `SEANCE_ANDROID2022_TREE` | The `data/` directory extracted from the Magnet 2022 Android CTF image (`~/ctf-evidence/android2022/android.tar`, Pixel, Android 12): `contacts2.db` (`user_version` 1300), `calendar.db` (600; 77 events), `keep.db` (95), `accounts_de.db` (3) / `accounts_ce.db` (10), `telephony.db` (1703944), Chrome History 51 / Cookies 16 / Web Data 98 / Login Data 31 | `seance_plugin_contacts`, `seance_plugin_android_apps`, `seance_plugin_mobile_device` (`tests/android2022_corpus.rs`), `seance_plugin_browser_history` — the §1.4a corpus-diff harness for those crates |
| `SEANCE_CHROMEBOOK_TREE` | The Magnet 2021 Chromebook `decrypted/` tree: Chrome History 41 (447 visits), Cookies 11, Web Data 81, Login Data 24 | `seance_plugin_browser_history` `tests/corpus.rs` |
| `SEANCE_MACOS2021_TREE` | The Magnet 2021 macOS tree: Safari `History.db` `user_version` 15, and a FrontBoard `applicationState.db` whose main file is one empty page — the two bundle ids and the schema live in its `-wal` | `seance_plugin_browser_history`, `seance_plugin_installed_apps` (`tests/corpus.rs`) |
| `SEANCE_IOS2022_TREE` | The root of the Magnet 2022 iOS full-file-system extraction, with `-wal` sidecars beside each database: Safari `History.db` `user_version` 16; `AddressBook.sqlitedb` whose main file is one empty page and whose whole schema and `_ClientVersion` 83 live in the 1.78 MB `-wal`; `applicationState.db` (145 bundle ids, `schema.version` 1) | `seance_plugin_browser_history`, `seance_plugin_contacts`, `seance_plugin_installed_apps` (`tests/corpus.rs`) |
| `SEANCE_IOS17_BACKUP` | The unzipped Hickman iOS 17 encrypted Finder backup directory (the one holding `Manifest.plist`; extraction in `VALIDATION.md` `IOS-KEYCHAIN-1`), password `MyPassword123` as published: 1,368 keychain items, 653 read, 715 device-bound, 616 secrets withheld, and no keychain record under a wrong password | `seance_plugin_ios_backup` (`tests/hickman_ios17_keychain.rs`). Not wired into any CI job: about four minutes in a debug build, most of it two 10,000,000-round PBKDF2 derivations |
| `SEANCE_ANDROID14_PACKAGES_XML` | **The file** (the variable is the path): `data/system/packages.xml` from Josh Hickman's Android 14 (Pixel 7a) public image, 701,599 bytes of ABX, SHA-256 `261e59fc…9b2ef4`, streamed out of `EXTRACTION_FFS.zip` as `~/forensic_corpora/hickman_android14/PROVENANCE.md` records. Through `seance_core::test_support::corpus::path`, so `SEANCE_REQUIRE_CORPUS` reaches it. Not set by any CI job yet | `seance_plugin_installed_apps` (`tests/corpus.rs`) — `VALIDATION.md` AND-1: 369 packages decoded from ABX; `installInitiator` on 123 and `updateOwner` on 56, every value `com.android.vending`; `isOrphaned` on 305; each figure counted first by an independent ABX reader written from AOSP's serializer |
| `SEANCE_MAGNET2019_ADB_TAR` | **The file** (the variable is the path): `adb-data.tar` from the Magnet 2019 Android CTF (`~/ctf-evidence/magnet2019android/adb-data.tar`, 75,673,600 bytes, SHA-256 `c3ecaef3…8883d1`), the tar payload of a real `adb backup` published without its header. Through `seance_core::test_support::corpus::path`. Not set by any CI job yet | `seance_plugin_android_backup` (`tests/real_backup.rs`) — `VALIDATION.md` SRCKIND-1: behind a restored header, 258 file entries and one `AndroidBackupSummary` naming 62 packages, against Python's `tarfile` |
| `SEANCE_SOURCE_KINDS_DB` | A **copy** of a case database (it is migrated on open). Read only by an `#[ignore]` test that prints, never asserts | `seance_api` `tests/source_kinds_test.rs` `print_the_label_for_every_case_in_a_real_database` — `VALIDATION.md` SRCKIND-1 |
| `SEANCE_SNAPCHAT_SAMPLES` | A directory holding `android/arroyo.db`, `android/main.db` (+ `-wal`) and `ios/arroyo.db`, extracted as `VALIDATION.md` records; both real `arroyo.db` read `user_version` 102 | `seance_plugin_snapchat` — the corpus-diff anchor: exact row counts, every column resolved, no schema note |
| `SEANCE_SKYPE_SAMPLES` | A directory holding plaso's `skype_main.db` (`AppSchemaVersion.SQLiteSchemaVersion` 66; `PRAGMA user_version` is 0 on it; 15 `Messages` rows) | `seance_plugin_skype` |
| `SEANCE_CASE001_PCAP` | **The file** (the variable is the path, not a directory) `case001.pcap` from DFIR Madness Case 001's `case001-pcap.zip` (pcapng 1.0, 197,583,252 bytes; the publisher's MD5 is checked in `~/forensic_corpora/dfir_madness_case001/VERIFICATION.txt`). Through `seance_core::test_support::corpus::path`, so `SEANCE_REQUIRE_CORPUS` reaches it; release-only (`cargo test --release`), the tests are `ignore`d in a debug build | `seance_plugin_pcap` `tests/case001_capture.rs` — `VALIDATION.md` NET-4: packet, DNS, C2-flow and RDP-conversation counts against `tcpdump`; the whole capture reassembled with no ceiling reached; the `GET /coreupdater.exe` body hashed off the wire against the MD5 and SHA-256 the publisher's `autorunsc` recorded on disk; no TLS session claimed for the Meterpreter channel on 443; and the TLS session records counted before and after the C2's first contact against `tcpdump`'s ClientHello-bearing conversations, every difference named (the test that pins the session-record ceiling on real evidence) |
| `SEANCE_WIN11_ISO` | **The file** (the variable is the path): Microsoft's Windows 11 25H2 Enterprise evaluation ISO, `win11-25h2-enterprise-eval-x64-en-us.iso` (7,092,807,680 bytes, SHA-256 `a61adeab…e7b9`), a UDF 1.02 bridge disc. Through `seance_core::test_support::corpus::path`, so `SEANCE_REQUIRE_CORPUS` reaches it | `seance_plugin_udf` `tests/win11_bridge_corpus.rs` — `VALIDATION.md` UDF-BRIDGE-1: the partition layer publishes both halves as a bridge and not as hidden; the ISO half is `README.TXT` alone; the UDF half has 976 files and 94 folders as 7-Zip lists them, `install.wim` at 6,225,286,811 bytes and hashed whole, and six SHA-256s (`install.wim` among them) matching 7-Zip and xorriso extraction |
| `SEANCE_UDF_IMAGES` | **A directory**: the self-made UDF corpus (`~/forensic_corpora/udf_images` on the lab host; `SOURCE.md` there), holding `images/*.img` written by NetBSD `makefs` and `mkudffs` 2.3 and `payload.sha256`, the answer key. Through `seance_core::test_support::corpus::dir` | `seance_plugin_udf` `tests/udf_variants_corpus.rs` — `VALIDATION.md` UDF-VARIANTS-1: 14 populated images (plain, VAT, sparable, metadata; UDF 1.50/2.01/2.50; 512/2,048/4,096-byte sectors) read every payload file with its SHA-256; three edited-copy tests pin a relocated sparing packet, the metadata mirror and an earlier VAT. Self-made images, not real discs; lean copies run in every build from `tests/fixtures` |
| `SEANCE_LONEWOLF_OBJECTS_DATA`, `SEANCE_CFREDS_OBJECTS_DATA` | Whole `OBJECTS.DATA` files extracted with The Sleuth Kit — Lone Wolf (`icat -o 1259520 LoneWolf.E01 89187`, Windows 10, 23,986,176 bytes, 11,548 descriptor records) and CFReDS Hacking Case (`icat -o 63 4Dell_Latitude_CPi.E01 5507`, Windows XP, 5,464,064 bytes, 3,902). The committed page-subset fixtures in `seance_plugin_asep/tests/fixtures/wmi/` carry the same bytes for the pages the tests read | `seance_plugin_asep` `wmi_tests` — the whole-file scan counts, which are measured independently in Python; with `SEANCE_DATALEAKAGE_OBJECTS_DATA` as well (`icat -o 206848 cfreds_2015_data_leakage_pc.E01 58925`, Windows 7, 14,794,752 bytes), the `*_with_its_mapping_*` tests read all three through their committed real mapping files (`VALIDATION.md` `WMI-2`) |
| `SEANCE_PERSEVERANCE_OBJECTS_DATA` | `OBJECTS.DATA` of the HTB Business CTF 2022 "Perseverance" challenge, with `INDEX.BTR` and `MAPPING1-3.MAP` beside it as the challenge ships them (23,896,064 bytes; source and SHA-256s in the corpus `SOURCE.md`/`SHA256SUMS`; not redistributable, so not committed) | `seance_plugin_asep` `wmi_tests::the_perseverance_repository_holds_the_published_windows_update_persistence` — read through the module as a loose file, so the mapping is found beside it; graded against the published write-up and an independent `dissect.cim` reading (`VALIDATION.md` `WMI-3`) |
| `SEANCE_CFREDS_QMGR_DIR` | A directory holding the Data Leakage PC's whole `qmgr0.dat` and `qmgr1.dat` (`icat -o 206848 cfreds_2015_data_leakage_pc.E01 15553` / `15554`, Windows 7, 4,194,304 bytes each). The committed fixtures in `seance_plugin_bits/tests/fixtures/qmgr/` are their first 8 KiB; every later byte is zero | `seance_plugin_bits` `tests/real_queues.rs` — the whole files decode exactly as the fixtures do: one live job ("Setup Installer", the .NET 4 setup download) in `qmgr1.dat`, none in `qmgr0.dat`, and the Outlook OAB transfers carved from both as stale |
| `SEANCE_DC01_QMGR` | **The file**: DFIR Madness case 001 DC01's `qmgr0.dat` (`icat -o 718848 20200918_0347_CDrive.E01 19702`, Server 2012 R2). Not committed: the case's terms grant no redistribution | `seance_plugin_bits` — the empty Server 2012 R2 queue reads as "queue read, 0 job(s)", with the build's own file GUID, never as not parsed |
| `SEANCE_DC01_RDP_CACHE` | **The file**: DFIR Madness case 001 DC01's `Users/Administrator/AppData/Local/Microsoft/Terminal Server Client/Cache/Cache0000.bin` (`icat -o 718848 20200918_0347_CDrive.E01 87133`, 86,964,396 bytes). Not committed: no redistribution grant | `seance_plugin_rdp_cache` `tests/real_cache.rs` — 5,304 tiles of 64 × 64, each a PNG `FileEntry`, one 4,096 × 5,312 collage named and recorded as not a reconstruction, version 4, nothing incomplete (run with `--release`; debug is slow) |
| `SEANCE_CFREDS_WINDOWS_EDB` | **The file**: the Data Leakage PC's `Windows.edb` (`icat -o 206848 cfreds_2015_data_leakage_pc.E01 490`, Windows 7, 42,008,576 bytes, SHA-256 `f29fa5c3…0ca1`) | `seance_plugin_winsearch_edb` `tests/real_index.rs` — 464 items; the IE 11 installer's size and times against the file's own `$DATA` size and `$STANDARD_INFORMATION` times (istat); the spy's "RE: Good job, buddy." mail with its decoded summary; 10 summaries named not decoded; dirty shutdown stated |
| `SEANCE_LONEWOLF_WINDOWS_EDB` | **The file**: Lone Wolf's `Windows.edb` (`icat -o 1259520 LoneWolf.E01 91047`, Windows 10 1709, 25,100,288 bytes, sparse on the image, SHA-256 `dc000bbb…697c`) | `seance_plugin_winsearch_edb` — the `SystemIndex_PropertyStore` layout, 822 items stated as a floor (libesedb's first count fails on a non-leaf page), `NTUSER.DAT` at 262,144 bytes |
| `SEANCE_CFTT_STRING_SEARCH` | NIST CFTT's Forensic String Search set (`ss-win-07-25-18.dd`, 2,098,028,544 bytes, SHA-256 `1574185b…2eb9`) with its published hit lists. Not routed through `seance_core::test_support::corpus`, but it honours the same switch: absent, the test prints `NOT RUN` and passes, unless `SEANCE_REQUIRE_CORPUS` is set, when it panics (no CI job sets it for this file yet — `corpus-gates` does not run `seance_search`); the default location is `~/forensic_corpora/cftt_string_search`; the whole-image test is `#[ignore]` (`--include-ignored`) | `seance_search` `tests/byte_sweep_cftt_test.rs` — 72 of 72 published offsets for `cities` / `mañana` NFC / `mañana` NFD / `SecretKey`, and every UTF-16 row's opposite-endian twin one byte away is folded into the hit before it and reported as an `endian_aliases` entry, never as a hit of its own |
| `SEANCE_CFTT_SS` | `$CORPUS_ROOT/cftt_string_search` — NIST CFTT's Forensic String Search data set, fetched by `scripts/cftt/fetch.sh string-search`. Two 2,098,028,544-byte images, their target lists and their expected-hit dumps | `ROADMAP` §5.2's string-search grader. The only one of the three CFTT sets whose publisher ships hash lists; see `VALIDATION.md` for what verifies and the one file that does not. It also gates `seance_validate`'s `the_real_key_rows_that_do_not_verify_are_counted`, which checks every key row's term against the image's own bytes at its published offset (903 verified, 13 at the publisher's `<id> <====` marker, 4 `zipped` with no offset, and one — row 7010 — contradicted), and `the_frag_unknown_rows_return_with_key_files`, which grades with the 14 row-to-file resolutions The Sleuth Kit (`ifind`/`ffind`, the reference tool, via `scripts/cftt/resolve-key-files.py`) makes. That resolver is itself gated: `seance_validate`'s `the_resolver_scripts_tests_pass` runs `scripts/cftt/test_resolve_key_files.py` — synthetic data-unit geometry always, and with this corpus and Sleuth Kit installed both real images (Windows: 707 of 708 resolved, the same 14 substitutions; unix: 356 of 926, rows 0152/0154 in `/ext4` and `/osxj`, 228 "could not look"). It also gates `every_id_in_the_case_map_exists_in_win_string_doc`, which reads the data set's `Expected Results by ID v1.1 9-27-19.docx` case table (25 Windows `FT-SS-*` cases, 874 entries) and resolves every entry to exactly one row of the key |
| `SEANCE_CFTT_DFR` | `$CORPUS_ROOT/cftt_dfr` — CFTT's Deleted File Recovery set, fetched by `scripts/cftt/fetch.sh dfr --one-at-a-time`. **90 images of 1,073,742,336 bytes each** (the 20 exFAT ones 65,536,000), so the sweep fetches, decompresses, grades and **deletes** one at a time; 90 GiB held at once will not fit. The directory must hold `setup-july-10-2012.pdf`, NIST's layout document, and a `dd/` of decompressed images; `pdftotext` (poppler-utils) must be installed, or `SEANCE_CFTT_DFR_LAYOUT_TXT` must name its `pdftotext -layout` output | §5.2's DFR sweep (`scripts/cftt/run-dfr.sh`, graded by `cftt-grade --dfr`). The publisher publishes **no** hash list, and the manifest says so as a value rather than omitting the field. It gates `seance_validate`'s `every_one_of_the_90_images_on_disk_has_exactly_one_truth_section`, which parses the whole layout (91 sections; `xfat-14` has no image) and checks every section's arithmetic, listed plus elided equal to declared. With `SEANCE_CFTT_DFR_RESULTS` also naming a `results.json` the runner wrote, `cftt-grade`'s `dfr_01_ext_three_deleted_files_are_listed` grades that **recorded** run's `dfr-01-ext.dd` (it does not ingest the image itself) |
| `SEANCE_CFTT_MOBILE` | `$CORPUS_ROOT/cftt_mobile` — the HTC Desire S JTAG dump (2,256,535,552 bytes) and its answer key | §5.2's mobile grader. Blocked on a decision, not on engineering: the answer key describes itself as a template — see `VALIDATION.md` |

**Which CI job sets the §1.4a app-schema variables.** The plaso halves run in
the hosted `app-schema-corpus` job of `test.yml`, which clones plaso into
`reference/plaso` and sets `SEANCE_PLASO_TEST_DATA` and `SEANCE_SKYPE_SAMPLES`
at its `test_data/`. The CTF halves run in the `corpus-gates` job of
`selfhosted-linux-ci.yml`, which sets `SEANCE_APP_SCHEMA_CORPUS`,
`SEANCE_ANDROID2022_TREE`, `SEANCE_CHROMEBOOK_TREE`, `SEANCE_MACOS2021_TREE`,
`SEANCE_IOS2022_TREE`, `SEANCE_SNAPCHAT_SAMPLES` and `SEANCE_SIGNAL_IOS_SQLITE`
from the runner's `$CORPUS_ROOT` (`app_schema_corpus/`, `android2022/data/` —
the image's `data/` directory — `chromebook/decrypted/`, `macos2021/tree/`,
`ios2022ffs/tree/`, `snapchat_samples/`, `signal_ios/signal.sqlite`), with
`SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1`. `documentation/CI.md` states why the
hosted job sets neither switch, and `seance_tests/tests/ci_corpus_wiring_test.rs`
pins both jobs. Whether the self-hosted runner exists and holds those trees is
not something the tree can show. Hosted GitHub Actions has not run on this
history; `scripts/ci-gate.sh` is the local mirror.

**Runtime inputs, not corpus variables.** These are read by the CLI and the API
in production as well as by tests, so they are not subject to the gate and an
unset one is never a failure:

| Variable | Holds |
|---|---|
| `SEANCE_SYMBOL_DIRS` | Directories of ISF symbol files, split so a Windows drive colon survives. Any Windows or Linux memory analysis |
| `SEANCE_PAGEFILES` | `index=path` entries — a pagefile elsewhere on the examiner's host |
| `SEANCE_CASE_PAGEFILES` | A pagefile held as another evidence item **in the same case**, resolved through `CaseEvidence` so one case's reference cannot open another case's evidence |
| `SEANCE_SWAPFILES` | `index=path` entries, the index being the swap area's `swp_type`. The Linux counterpart of `SEANCE_PAGEFILES` |
| `SEANCE_MEM_DTB` | A directory table base in hex or decimal, for an image discovery cannot profile on its own |
| `SEANCE_HIBER_LEGACY` | `nt61-x64` opts into the unvalidated Windows 7 hibernation layout; every layer it returns is stamped `Unvalidated` |
| `SEANCE_MEM_NETSCAN_ISF`, `SEANCE_MEM_TCPIP_ISF` | Override where the netscan definitions and `tcpip.pdb` ISF are found (default: under `reference/volatility3`) |
| `SEANCE_YARA_RULES` | A YARA rule set. **Unset means the scanner is not registered at all** — registering it with no rules would read as "YARA found nothing" rather than "no rules were loaded", which are opposite claims. A rule set that was named and would not load ends the run |
| `SEANCE_MAX_DECOMPRESSED_BYTES` | The decompression-bomb ceiling (default 10 GiB) — see `documentation/Container_Formats.md` |
| `SEANCE_E01_ISOLATED` | Whether the E01 reader runs isolated; falsey disables it |
| `SEANCE_REQUIRE_CORPUS` | Turns a skip into a failure. The third gate behaviour above |

One variable per **separately obtainable** set, and that is deliberate: a named
corpus short a file fails rather than skipping, so every image sharing a
variable must be provisioned together or none of them can be used. Lone Wolf is
public where the XP and Win11 images are not, which is why it has its own.

### Symbols are a second prerequisite, not an optional extra

A Windows memory capture is not analysable without an ISF matching that exact
kernel build. Without one, discovery identifies the kernel and stops — correctly,
because every offset would otherwise come from a different build. The Volatility
3 Windows symbol pack carries most builds:

```bash
curl -O https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip -d ~/forensic_corpora/symbols/extracted
export SEANCE_SYMBOL_DIRS=~/forensic_corpora/symbols/extracted/windows/ntkrnlmp.pdb
```

### Running them

```bash
# CFReDS, asserting NIST's published answers
SEANCE_CFREDS_HACKING=~/forensic_corpora/cfreds_hacking \
  cargo test -p seance_tests --all-features cfreds_hacking_case_tests

# A capture AVML itself wrote. This is the corpus that found a defect no
# self-built fixture could: `end` in an AVML block header is inclusive, the
# reader treated it as exclusive, and all 37 AVML tests passed because the
# fixture helper had the same convention backwards. Not committed, and never
# will be -- it is live process memory.
SEANCE_LINUX_MEM=~/forensic_corpora/oberon_linux_swap \
  cargo test -p seance_memory --test avml_real_capture_test

# BTF, against the kernel's own type information. The last test in this file
# recovers BTF from the capture and matches it against that host's
# /sys/kernel/btf/vmlinux member for member. It sweeps the whole image, so it
# takes about a minute and is worth running in --release.
SEANCE_LINUX_MEM=~/forensic_corpora/oberon_linux_swap \
  cargo test -p seance_memory --test btf_real_capture_test --release

# BTF -> ISF -> SymbolTable, end to end against the real kernel's types. Compiles
# a table through the ordinary admission gates and compares 5,000+ member
# offsets against the BTF they came from.
SEANCE_LINUX_MEM=~/forensic_corpora/oberon_linux_swap \
  cargo test -p seance_memory --test btf_symboltable_test

# kallsyms, against /proc/kallsyms from the captured host -- same boot, because
# KASLR moves every address on restart. Sweeps the image once and shares the
# result across the tests; about a minute, so run it in --release.
SEANCE_LINUX_MEM=~/forensic_corpora/oberon_linux_swap \
  cargo test -p seance_memory --test kallsyms_real_capture_test --release

# Ali Hadi's NTFS case — 474 KB, so cheap enough to keep provisioned. The one
# test that checks Séance *read* an image rather than understood it: the
# decoded stream is hashed against the MD5 and SHA-1 FTK Imager recorded when
# it made the image, by a different tool on a different machine in 2023.
SEANCE_ALIHADI_NTFS=~/forensic_corpora/alihadi_ntfs \
  cargo test -p seance_tests --all-features alihadi_ntfs_tests

# Volatility 3 parity on the Win10 capture, including swapped-page recovery
# from the scenario's own pagefile.sys (which must sit beside memdump.mem in
# the SEANCE_LONEWOLF directory).
SEANCE_LONEWOLF=~/forensic_corpora/lonewolf \
SEANCE_SYMBOL_DIRS=~/forensic_corpora/symbols/extracted/windows/ntkrnlmp.pdb \
  cargo test -p seance_plugin_memory_windows --all-features --test parity_test win10
```

### What CI actually runs

The `corpus-gates` job of `.github/workflows/selfhosted-linux-ci.yml` runs
**six** corpus steps with `SEANCE_REQUIRE_CORPUS=1`, against
`CORPUS_ROOT` (default `/srv/seance-corpora`, overridable with the
`SEANCE_CORPUS_ROOT` repository variable):

| Step | Corpus | What it runs |
|---|---|---|
| CFReDS Hacking Case | `cfreds_hacking` | `cargo test -p seance_tests --all-features cfreds_hacking_case_tests` |
| Ali Hadi NTFS case | `alihadi_ntfs` | `cargo test -p seance_tests --all-features alihadi_ntfs_tests` |
| Volatility 3 parity, Windows 10 | `lonewolf` + `symbols/extracted/windows/ntkrnlmp.pdb` | `cargo test -p seance_plugin_memory_windows --all-features --test parity_test win10` |
| Linux memory | `oberon_linux_swap` | `--release`: `seance_memory`'s `avml_real_capture_test`, `btf_real_capture_test`, `btf_symboltable_test`, `kallsyms_real_capture_test`, `linux_swap_real_test`, then `seance_plugin_memory_linux`'s `image_derived_discovery_test` |
| App-parser schema drift | `app_schema_corpus`, `android2022/data`, `chromebook/decrypted`, `macos2021/tree`, `ios2022ffs/tree`, `snapchat_samples`, `signal_ios/signal.sqlite`, `hickman_android14/whatsapp`, plus a shallow clone of plaso | with `SEANCE_APP_SCHEMA_CORPUS_REQUIRED=1`: the `corpus` tests of `seance_plugin_browser_history`, `seance_plugin_contacts`, `seance_plugin_installed_apps` and `seance_plugin_android_apps`, `seance_plugin_mobile_device`'s `android2022_corpus`, and the real-store tests of the Snapchat, Signal, WhatsApp, Android SMS, iMessage, Twitter and call-history plugins |
| BitLocker XTS-AES-256 + Windows 11 memory discovery | `win11_bitlocker` | builds `seance-validate`, runs it with `--corpus "$CORPUS_ROOT"`, and fails unless the report's `BL-1` and `MEM-2` cases are both `pass`; the report is uploaded as an artifact |

The job first checks that all twelve corpus directories and the file
`signal_ios/signal.sqlite` are where the gate will look and fails outright if
any is missing, rather than letting a step skip.

Filter each invocation to the tests whose corpus you have provisioned: with the
gate on, an unset variable is a failure, so widening a filter and provisioning
its corpus go together. The Win10 filter is load-bearing for exactly this reason
— Lone Wolf has its own variable, so the XP and Win11 parity tests would
ordinarily skip, but with the gate on "SEANCE_MEM_IMAGES was never set" is a
failure.

**Everything else in the table above runs only on a developer's machine.** The
hibernation, crash-dump, swap, Noble-kernel and per-plugin sample
corpora have no CI step, so a regression in any of them is caught when someone
runs it locally and not before. That is a stated gap, not an oversight to be
discovered later.

### The reproducible golden image

The corpora above are third-party evidence with published answers; they cannot
be redistributed and so run only on the self-hosted runner. The golden image is
different: it is **built from a declared layout**, so the ground truth is the
generator script itself — readable, auditable, and reproducible anywhere without
root. Séance is checked against `mkntfs` / `mke2fs` / `mtools` plus a fixed
layout, never against its own prior output.

```bash
# Build it (rootless: writes filesystems into image files, no loop mounts), then
# run the regression. One GPT E01 carries NTFS + ext4 + FAT16 + APFS partitions,
# so a single image exercises the whole E01 -> partition -> filesystem -> file
# chain. mkapfs is not packaged, so the script builds it from apfsprogs (pinned)
# when it is not already on PATH — hence the git + C toolchain requirement.
./scripts/build_golden_images.sh ~/forensic_corpora/golden
SEANCE_GOLDEN_IMAGES=~/forensic_corpora/golden \
  cargo test -p seance_tests --features e01 golden_multipart_tests
```

Because it is generated rather than downloaded, CI builds it on an ordinary
hosted runner (the `golden-images` job in `.github/workflows/test.yml`) and
caches it keyed on the generator script — rebuilt only when the script changes.

**APFS is a partial case, honestly bounded.** `mkapfs` (from apfsprogs) builds a
real APFS container and volume on Linux, so the chain is exercised through to the
volume superblock and its root directory — the test asserts the fixed
container/volume UUIDs and block size. But there is no rootless way to write
*files* into APFS (no writable FUSE; the kernel module needs root), so file
*content* is asserted only on NTFS/ext4/FAT. A file-bearing APFS image still
needs a real Mac capture, and the harness leaves room for that rather than
faking it.

### Regenerating a Volatility oracle

Expected values in the parity tests come from running Volatility 3 against the
same file — none are hand-derived, and none come from Séance.

```bash
cd reference/volatility3
python3 vol.py -q -s <symbols> -r csv -f <image> windows.psscan > oracle.csv
```

Volatility prints kernel addresses with the sign-extension truncated
(`0xffffae80…` as `0xae80…`), so compare masked to 48 bits rather than
"correcting" either side into agreement.

---

## Test Database Strategy

### In-Memory SQLite for Unit Tests
- Fast execution
- No cleanup required
- Isolated test cases
- Uses `sqlite::memory:`

### Test Fixtures
- Helper functions create test data
- `setup_test_db()` - Initialize in-memory DB
- `create_test_case()` - Create test case
- `create_test_event()` - Create test timeline event

### Migration Testing
- Migrations run automatically in tests
- Verifies schema changes don't break existing code

---

## Performance Testing Plan

### Database Performance
**Target:** <100ms for tag operations

Test queries under load:
```rust
#[tokio::test]
async fn bench_create_1000_tags() {
    let start = Instant::now();
    for _ in 0..1000 {
        db.create_timeline_tag(...).await?;
    }
    assert!(start.elapsed() < Duration::from_secs(5));
}
```

### API Performance
**Target:** <200ms response time

Load testing with tools:
- `wrk` - HTTP benchmarking
- `k6` - Load testing
- `Apache Bench` - Simple load tests

### Timeline Query Performance
**Test with:**
- 1K events (baseline)
- 10K events (typical)
- 100K events (large case)
- 1M events (stress test)

**Metrics:**
- Query execution time
- Memory usage
- JOIN performance with tags

---

## Continuous Integration (CI)

### GitHub Actions Workflows

The workflows are `test.yml`, `audit.yml`, `coverage.yml`, `fuzz.yml`,
`release.yml` and `selfhosted-linux-ci.yml` under `.github/workflows/`.
`documentation/CI.md` lists the gates and how to run them locally with
`scripts/ci-gate.sh`.

### Pre-commit Hooks
```bash
#!/bin/bash
# .git/hooks/pre-commit
cargo test --all || exit 1
cargo clippy -- -D warnings || exit 1
cargo fmt --all -- --check || exit 1
```

---

## Test Data Management

### Synthetic Test Data
- Generate realistic forensic artifacts
- Multiple artifact types (NTFS, Registry, Browser, etc.)
- Various timestamps and metadata

### Test Cases Library
```
tests/fixtures/
├── sample_mft.bin
├── sample_registry.dat
├── sample_evtx.evtx
└── sample_browser_history.db
```

### Privacy Considerations
- **NEVER** commit real case data
- Sanitize any real artifacts before using in tests
- Use synthetic data generators

---

## Regression Testing

### Test Checklist Before Release
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] No performance regressions
- [ ] Database migrations work forward and backward
- [ ] API contracts maintained (no breaking changes)
- [ ] GUI manual smoke test
- [ ] Export functionality tested

### Automated Regression Suite
Run full test suite:
```bash
./scripts/ci-gate.sh
```

---

## Error Scenarios Testing

### Database Errors
- [ ] Connection failures
- [ ] Constraint violations
- [ ] Transaction rollbacks
- [ ] Disk full scenarios

### API Errors
- [ ] Malformed JSON
- [ ] Missing required fields
- [ ] Invalid UUIDs
- [ ] Unauthorized access (future)
- [ ] Rate limiting (future)

### Data Integrity
- [ ] Corrupted evidence files
- [ ] Incomplete timeline events
- [ ] Orphaned tags after event deletion
- [ ] Concurrent modifications

---

## Test Metrics & Goals

### Current Status

| Component | Unit Tests | Integration Tests | Coverage Goal |
|-----------|------------|-------------------|---------------|
| seance_core | ⏸️ TODO | ⏸️ TODO | 80% |
| seance_db | ✅ 12 tests | N/A | 90% |
| seance_api | N/A | ✅ 6 tests | 80% |
| frontend (React) | ✅ Vitest + RTL | ✅ MSW-mocked | 70% |

### Goals
- [x] Database tag tests (12 tests)
- [x] API tag tests (6 tests)
- [ ] GUI manual test checklist
- [ ] Performance baseline established
- [x] CI pipeline configured

---

## Known Testing Gaps

### High Priority
1. **End-to-End Tests** - No full workflow tests yet
2. **Performance Tests** - No benchmarks established
3. **Web UI E2E** - React app has Vitest component tests (RTL + MSW); no full end-to-end browser automation (Playwright) yet
4. **Concurrency Tests** - No multi-user scenario testing

### Medium Priority
5. **Security Tests** - No injection/XSS tests
6. **Accessibility Tests** - No a11y validation
7. **Mobile/Responsive Tests** - No mobile browser testing
8. **Error Recovery Tests** - Limited failure scenario coverage

### Low Priority
9. **Internationalization Tests** - English only
10. **Browser Compatibility** - Chrome/Firefox only

---

## Testing Best Practices

### 1. AAA Pattern (Arrange, Act, Assert)
```rust
#[tokio::test]
async fn test_example() -> Result<()> {
    // Arrange
    let db = setup_test_db().await?;
    let case_id = create_test_case(&db).await?;

    // Act
    let result = db.some_operation(case_id).await?;

    // Assert
    assert_eq!(result.status, "expected");
    Ok(())
}
```

### 2. Test Naming Convention
- `test_<feature>_<scenario>_<expected_result>`
- Examples:
  - `test_create_tag_with_note_returns_id`
  - `test_delete_nonexistent_tag_returns_false`

### 3. Test Independence
- Each test creates its own data
- No shared state between tests
- Tests can run in any order

### 4. Fast Execution
- Use in-memory databases
- Mock external dependencies
- Parallel test execution

### 5. Readable Assertions
```rust
// Good
assert_eq!(tags.len(), 2, "Expected 2 tags for case");

// Better
assert!(tags.len() == 2,
    "Expected 2 tags for case {} but found {}", case_id, tags.len());
```

---

## Test Documentation

### Inline Test Documentation
```rust
/// Tests that creating a tag with a note succeeds and the note
/// is properly stored and retrievable.
///
/// This verifies:
/// - Tag creation returns a valid UUID
/// - Note is persisted to database
/// - Fetching the tag includes the note
#[tokio::test]
async fn test_create_tag_with_note() -> Result<()> {
    // ...
}
```

### Test Reports
Generate HTML test report:
```bash
cargo test -- --format json | cargo2junit > test-results.xml
```

---

## Future Testing Enhancements

### Planned Improvements
1. **Property-based Testing** - Use `proptest` for random inputs
2. **Mutation Testing** - Verify test quality with `cargo-mutants`
3. **Snapshot Testing** - Test JSON responses with `insta`
4. **Database Migrations Testing** - Test upgrade/downgrade paths
5. **Chaos Engineering** - Test resilience under failures

### Testing Tools to Evaluate
- `proptest` - Property-based testing
- `quickcheck` - Randomized testing
- `wiremock` - HTTP mocking
- `testcontainers` - Docker-based integration tests
- `criterion` - Benchmarking framework

---

## Manual Testing Checklist

### Timeline Tagging Feature (GUI)

**Setup:**
- [ ] Fresh database with sample data
- [ ] At least 20 timeline events visible

**Tag Creation:**
- [ ] Click untagged star icon (☆)
- [ ] Icon changes to tagged (★)
- [ ] Badge count increments
- [ ] Refresh page - tag persists

**Tag Deletion:**
- [ ] Click tagged star icon (★)
- [ ] Icon changes to untagged (☆)
- [ ] Badge count decrements
- [ ] Refresh page - tag removed

**Tag Notes:**
- [ ] Right-click tagged event
- [ ] Select "Edit Note"
- [ ] Enter note text
- [ ] Save note
- [ ] Icon shows note indicator
- [ ] Hover shows note preview

**Filtering:**
- [ ] Click "Show Only Tagged" button
- [ ] Timeline shows only tagged events
- [ ] Count matches tagged count
- [ ] Click "Show All" to clear filter

**Export:**
- [ ] Export CSV with tagged events
- [ ] CSV includes tag column
- [ ] Export JSON with tagged events
- [ ] JSON includes tag field

**Edge Cases:**
- [ ] Tag with very long note (1000+ chars)
- [ ] Tag then sort timeline
- [ ] Tag then filter timeline
- [ ] Tag across multiple pages
- [ ] Tag then delete event (future)

---

*This document evolves as testing strategy matures. All tests must pass before merging to main.*

## Continuous adversarial + real-data testing

### Fuzzing (wired in CI)
`.github/workflows/fuzz.yml` runs nightly. It seeds each target with a minimal
magic-valid input (`fuzz/gen_seeds.py`) so the fuzzer reaches real parser code,
builds all `fuzz/fuzz_targets/*`, runs each for a bounded time, fails on any
crash, and uploads the reproducer. A reproducer worth keeping is committed under
`fuzz/artifacts/<target>/` — the directory is tracked —
and `seance_tests::fuzz_regression_tests` replays every one as an ordinary test, in CI
too. Run locally:

```
export PATH="$HOME/.cargo/bin:$PATH"    # if Homebrew cargo shadows rustup
python3 fuzz/gen_seeds.py
cargo +nightly fuzz run <target> fuzz/corpus/<target> -- -max_total_time=120 -rss_limit_mb=4096
```

Seed richer coverage locally from real images (much deeper than the synthetic
seeds): copy a small sample of a real image into `fuzz/corpus/<target>/`, e.g.
`dd if=<image> of=fuzz/corpus/fat_parser/seed_real bs=1 count=32768`. This is how
the campaign found the parser-hardening bugs; unseeded runs stall at the magic
gate (~19 edges). Note: `libfuzzer-sys` aborts on any panic *before*
`catch_unwind` runs, so a parser that guards a third-party panic with
`catch_unwind` (e.g. the mbrman guard in the partition parser) still trips the
fuzzer — validate those with a normal unit test instead.

### Real-image regression in CI
The integration tests (`seance_tests`) are skip-if-absent: with the DFTT/Autopsy
and reference corpora present (49 GB, gitignored) they run as known-answer checks
(177/177), but CI only has small fixtures. Its file-level fixtures are resolved
by `seance_tests/src/fixtures.rs`: a path named as `test_data/<rest>` is looked
for there first and then under `reference/plaso/test_data/<rest>`, both
gitignored, and a test whose fixture is in neither place returns early after
printing both places it looked (no gate variable, so `SEANCE_REQUIRE_CORPUS`
does not reach it). On a checkout with plaso fetched the jump list (5),
registry, browser-history, plist, sqlite and zip tests therefore run against
the plaso files without copies into `test_data/`; the `$LogFile` samples and
the image corpora still skip because they exist in neither place. To gate real-image regressions in CI:
host a small licensed corpus in a private artifact store, fetch it into
`test_data/` in a nightly job, and the existing tests will execute against it
(no code change needed). The images are large and some are licensed, so this is
an operator/legal decision rather than a committed default.
