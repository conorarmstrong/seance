# Reproducible known-answer validation

**Some evidence is not held.** The Magnet 2019, 2020, 2021 and 2022 CTF images, the NIST DFR set, Nitroba and the keys, and the Windows 10, Server 2019, Server 2003 and XP lab VMs with their ISOs and scripts, are not held with this tree. A test gated on a variable that points at them skips. Every figure and path in this file that names them is a record of what was measured. It cannot be re-run without fetching the public image again or rebuilding the guest.

Séance's evidentiary claims rest on known-answer testing: run a documented
image, compare the output to its published ground truth. Those checks live as
corpus-gated integration tests in `seance_tests`, but a `cargo test` run has two
shortcomings as *evidence*:

1. It produces no durable, shareable artifact — only pass/fail on the console.
2. A corpus-gated test early-returns when its image is absent and reports as
   "passed", so a plain run silently overcounts coverage.

`seance-validate` (crate `seance_validate`) closes both. It runs the documented
cases against a local corpus and writes a provenance-stamped, tamper-evident
report in which every case is classified **Pass / Fail / Skipped (image
absent)** — a skip is never counted as a pass.

## Running it

```sh
cargo run -p seance_validate --release -- \
  --corpus ~/forensic_corpora --out engagement-validation
```

The corpus root holds one directory per image set — `dftt/`, `alihadi_ntfs/`,
`oberon_linux_swap/` and `win11_bitlocker/` — matching the layout under
*Evidence held* in `ROADMAP.md` and the `CORPUS_ROOT` the CI job uses. The DFTT
images come from
[the DFTT project on SourceForge](https://sourceforge.net/projects/dftt/files/Test%20Images/);
none of the corpus is in the repository.

**`win11_bitlocker/` is the one set that is also a `test_data/` directory.** The
Windows 11 25H2 BitLocker corpus described in `test_data/README.md` is where the
`BL-1` and `MEM-2` images live in a working tree; `seance-validate` looks for
them under the corpus root, so copy or symlink that directory into the root
before running, or those two cases report **Skipped (image absent)** — which is
correct behaviour and not a pass.

Outputs:

- `<base>.json` — machine-readable report.
- `<base>.md` — human-readable summary table.
- `<base>.hmac` — HMAC-SHA256 of the report, written when
  `SEANCE_VALIDATION_HMAC_KEY` is set (tamper-evidence, same primitive as the
  audit-log chain).

Exit status:

| Code | Meaning |
|---|---|
| `0` | At least one case was evaluated and none failed. Skips do not fail a run that evaluated something; they are counted so the reader knows coverage was incomplete. |
| `1` | At least one case FAILED. |
| `2` | **Nothing was evaluated** — every case was Skipped because its image was absent. The report's headline reads `NO COVERAGE`. This tool exists to stop silent non-coverage being quoted as a pass, and a run against an empty or mis-pointed corpus root is exactly that, so it does not exit `0`. |

## Four statuses, not two, and the assertion a row grades

The report's status vocabulary is `Pass` / `Fail` / `Skipped (image absent)`
plus two more, because recording a CFTT result in three statuses
forces every choice to be a false statement:

- **`NotApplicable`** — the tool does not offer the feature the assertion is
  conditional on. CFTT's own concept, stated in its specifications as "if a
  feature is not present, then requirements for those features will not be
  tested". Five of the eleven CFTT families do not apply to Séance at all. In
  three statuses this had to be a `Pass` (claiming a test that never ran), a
  `Fail` (claiming a defect) or a `Skipped` (claiming the evidence was missing,
  when it was the feature that was).
- **`NotAssessed`** — the run could not reach the question. This project's own
  invariant, which the vocabulary had no way to record: *could not look* is not
  *not there*. An assertion whose published answer key turns out to be a
  template, or whose evidence this build cannot ingest, is unassessed — and
  recording it as a `Fail` asserts a defect the run never established.

**Neither counts towards a pass and neither fails the run**, each is counted
separately in the headline — "2 skipped", "2 not applicable" and "2 not
assessed" are three different facts — and a run that produced **only** those two
reports **NO COVERAGE** and exits non-zero, because it established nothing.

A row can also name the published **assertion** it grades — `SS-CA-02`,
`FT-SS-07-Cyrillic`, `DFR-CR-01` — so a result is traceable to somebody else's
document rather than to this project's own wording. A case that grades none says
nothing about one: the field is absent rather than empty, because an empty cell
reads as an assertion whose identifier was lost. Every case in the current set
grades none, since this project wrote all seven.

The `assertion` field is omitted when unset, so a case that grades no published
assertion serialises without it and the results digest does not depend on it.

## What the report records

- Tool version, git commit, generation timestamp, host, and corpus root. The
  commit is embedded at build time from the tree the binary was compiled from
  (`seance_validate/build.rs`), so it is right wherever the tool is run from.
  That build script re-runs on **every** build, deliberately: the stamp carries
  `--dirty`, which is a fact about the working tree, and cargo cannot watch a
  working tree, so declaring only the git refs would let it replay a cached stamp.
  If a build carried none, the tool asks `git rev-parse` in the run directory
  and the report says so (`git_commit_source: runtime-git`) — that names the
  repository it was *run* in, not necessarily the one it was *built* from. If
  neither is available the commit is `unknown` and the report says that too.
  The embedded stamp alone would say nothing if a binary built
  somewhere else were run inside this repository. The
  report therefore also records `run_directory_commit`: what `git describe` answers in
  the directory the tool was run in, asked with the **identical** command
  `build.rs` uses, so a dirty stamp is never compared against a clean one. When
  the two agree the report says so; when they disagree it says the binary was
  built elsewhere, that this is ordinary for a released binary and does not make
  the validation suspect, and that the surrounding tree is therefore not
  evidence about the code that produced these results. Outside a git repository
  there is nothing to compare and no line is printed, and when the commit itself
  came from run-time `git` no line is printed either — the two values would be
  the same by construction and the comparison would be a tautology.
- Per case: the documented expected answer, what was observed, the status, and
  the **SHA-256 of the exact image examined** (so a third party can confirm the
  same evidence was used).
- `results_digest` — a SHA-256 over the results that is **stable across runs**
  on the same corpus and code (independent of timestamp/host). Two examiners
  running the same corpus and build get the same digest; a change in any result
  changes it.

## The case set

**Seven cases**, as declared in `seance_validate::cases::cases()`.

| Case | Capability | Image (relative to the corpus root) | Whose answer it checks against |
|---|---|---|---|
| DFTT-1 | Extended DOS partitions | `dftt/1-extend-part/…/ext-part-test-2.dd` | DFTT's documented result — 6 partitions, all FAT16, extended container not emitted |
| DFTT-9 | FAT16 volume label | `dftt/9-fat-label/…/9-fat-label.dd` | DFTT's documented result — label `LABEL1` |
| DFTT-5 | FAT12 timestamps | `dftt/5-fat-daylight/…/daylight.dd` | DFTT's documented result — `summer.txt` and `winter.txt`, each with a parseable timestamp |
| WIN-1 | E01 container | `alihadi_ntfs/NTFS-HiddenFiles.E01` | The image's own FTK Imager acquisition log (2023): MD5 `e7d5b36a407d5a02d0872d4dd3f3f9d0`, SHA-1 `5edc4c6efda9d266ecabcab5629694d0063e9d7f` |
| **BL-1** | BitLocker XTS-AES-256 | `win11_bitlocker/win11-bitlocker-xts256.raw` | Windows itself — the recovery password unlocks, and offset 0 of the decrypted volume is an NTFS boot sector (OEM `NTFS    `, signature `0x55AA`) that Windows wrote |
| **MEM-2** | Windows memory discovery | `win11_bitlocker/memory-unlocked.raw` | **Microsoft's PDB** — the kernel identity recovered from the image alone is `ntkrnlmp.pdb` GUID `E6426A07C26E66F8EB8594621A7B273B`, build 26200 |
| MEM-1 | Linux memory symbols | `oberon_linux_swap/oberon_mem.lime.compressed` | The captured host's `/proc/kallsyms`, same boot (host-attested, not third-party) |

*Run the set before quoting a figure; the report's `results_digest` is what
makes such a quotation checkable.*

**WIN-1 is the only case that checks Séance *read* an image** rather than
understood one: the decoded stream is hashed against MD5 and SHA-1 computed by
another tool, on another machine, before this decoder existed. A failure there
says something worse than any parser being wrong — that what every other finding
derives from is not what was acquired.

**Three of the seven check against something outside this project entirely.**
WIN-1 against FTK Imager's 2023 log; BL-1 against genuine Windows crypto (the
volume was encrypted by Windows and the boot sector at offset 0 of the plaintext
is one Windows wrote); MEM-2 against Microsoft's own published PDB for that
kernel build. Those are the strongest form a case here takes, because nothing in
this tree could have produced the expected answer.

**MEM-1's ground truth is host-attested, not third-party**, and the report says
so. The machine stating what its own symbol table held is strong corroboration
and it is not a laboratory's published result; rendering the two alike would
overstate it. It is included because the memory tier carries this tool's
strongest claims and had no known-answer coverage at all.

**MEM-1 runs the product's own discovery path.** The symbols are recovered by
`seance_plugin_memory_linux::image_symbols::recover` — the image-derived route
Linux discovery takes when no symbol file matches — over the capture opened by
the product's LiME/AVML reader, and the comparison is made against the
`symbols` section of the ISF that route generates. A case that does not
exercise what ships is not validation of what ships.

**MEM-1 reports FAIL, not Skipped, when the capture is present but
`kallsyms.txt.gz` is missing beside it.** Skipped has one meaning here: the
image was absent, so nothing was examined. In this situation the image *is*
present and the product *would* have been exercised, but the case has no answer
key to check the result against, so it cannot say whether the product read the
capture correctly. Reporting that as Skipped would let a run with the evidence
in hand be counted as coverage-not-attempted rather than coverage-not-achieved;
a case whose answer key is missing cannot be reported as coverage, and a FAIL
with the reason in the *Observed* column is what makes the operator go and fix
the corpus rather than quote the run.

## What a passing run reports

Run against the full corpus, the seven cases return the results below. Reproduce them
with the command under *Running it*. No report is committed to the repository.

**7 passed, 0 failed, 0 skipped, 7 total.**

| Case | Result |
|---|---|
| DFTT-1 | PASS — 6 partitions, all FAT16, extended container not emitted |
| DFTT-9 | PASS — `volume_label = "LABEL1"` |
| DFTT-5 | PASS — both files, each with a parseable timestamp |
| WIN-1 | PASS — MD5 and SHA-1 of the decoded stream match the acquisition log over 101,711,872 bytes |
| BL-1 | PASS — XTS-AES-256; decrypted offset 0 is an NTFS boot sector (`NTFS    `, `0x55AA`) |
| MEM-2 | PASS — `ntkrnlmp.pdb` `E6426A07C26E66F8EB8594621A7B273B` build 26200 recovered from the image; DTB `0x1ae000` |
| MEM-1 | PASS — 191,565 of 191,565 comparable symbols agree with `/proc/kallsyms` from the same boot (table of 202,525 symbols at physical offset `0x3ad23f088`, via image-derived discovery) |

The report carries the results digest, the build commit the tool was built from, the host,
the corpus root and the per-case observed values. Two independent runs of the same corpus
and code produce the same digest. A reader checks a build by running the command under
*Running it* against the same corpus and comparing the digest.

## CFTT methodologies — which apply to Séance, and why

`ROADMAP` §5.2 runs NIST CFTT's **published test methodologies** in-house. This
section is the determination every part of that work rests on. The claim it makes
is the one place this project could do itself reputational harm.

> **Running a published methodology is not third-party validation.** A ✅ against
> "NIST CFTT" means NIST tested the tool. Nobody has tested Séance. The
> comparison's CFTT row stays ❌ and no document claims more.

**What a run of one of these methodologies does support**, and the only thing it
supports: that Séance was measured against somebody else's published assertions,
by a procedure anybody can re-run, with the result recorded whether it passed or
not. That is a real improvement on measuring the product against tests its own
author designed. It is not, and must never be written as, a NIST result.

### Not applicable — and the reason is structural

Séance performs **no acquisition of any kind** and is not a write blocker. That
is `documentation/COMPARISON.md`'s structural gap #1, stated there as "Séance can
never be a lab's only tool", and it is what makes five of the eleven families
inapplicable rather than merely untested:

| CFTT family | Why it does not apply |
|---|---|
| Disk Imaging | Séance reads images; it does not create them. |
| Forensic Media Preparation | No media is written, wiped or verified. |
| Hardware Write Block | Not a device. |
| Software Write Block | Séance mounts nothing and interposes on no I/O path. |
| Cloud Data Extraction | No cloud acquisition, no tokens, no warrant returns. |

A family being inapplicable is **not** a pass. It is recorded as
`NotApplicable`, which `seance_validate` counts separately and never counts
towards a pass — CFTT's own concept, from its specifications: "if a feature is
not present, then requirements for those features will not be tested".

### Applicable, and in scope for §5.2

| CFTT family | Assertions | State |
|---|---|---|
| Deleted File Recovery | Core `DFR-CR-01`…`04`; optional `DFR-RO-01`…`08` | **Run** 2026-09-30 over all 90 images, `CFTT-DFR-1`: 1,785 passed, 601 failed (134 real defects after a Sleuth Kit pass), 824 not applicable, 1,223 not assessed. `DFR-CR-01`…`03` are paraphrased (the specification is not held) and `DFR-RO-*` are not graded. |
| Forensic String Search | Core `SS-CA-01`…`05`; test cases `FT-SS-01`…`10` with their variants | **Run** on the Windows image, `CFTT-SS-2`: 648 of 709 assessable expectations found, the predicted ceiling. The key is checked against the image (14 rows graded against the file Sleuth Kit places at the key's offset, 1 key row the image contradicts left unassessed). Each row is also graded under the `FT-SS-*` case(s) the data set's own `Expected Results by ID` table names it in (`CFTT-SS-1`, below): 25 cases, every entry resolved. The `SS-CA-*` core assertions are not mapped: the case table names test cases, not assertions. Its data set is the only one of the three whose publisher ships a SHA-256 list. |
| Mobile Devices | `MDT-CA-01`…`13` (the image-file half; `MDT-AO-*` are acquisition and SIM, and do not apply) | **Partly graded; no run result is recorded yet.** The grader is `seance_validate/src/cftt/mdt.rs`. It grades `MDT-CA-02` (one row per address-book entry), `MDT-CA-11` (exact Unicode text for the non-ASCII and special-character entries) and `MDT-CA-12` (the image is unchanged by the run). `MDT-CA-13` is `NotApplicable` when `CA-12` holds and `NotAssessed` otherwise. `MDT-CA-01`, `CA-03`…`CA-10` are `NotAssessed` with the reason: the published answer key for the cheapest mobile image describes itself as "an example/template of a dataset used for populating the internal memory of a mobile device". Its address-book section is itemised and real; its later sections are populator instructions with placeholders ("Account: account1, account2"). Grading against them would grade the product against what NIST intended to seed, and on a raw NAND dump there is no independent tool to arbitrate a divergence. |

### Applicable, and deliberately deferred

These three apply and are a separate item's worth of work. Naming them here is
the point: an unlisted family reads as one nobody considered.

| CFTT family | Assertions | Why deferred |
|---|---|---|
| SQLite Data Recovery | `SFT-CR-01`…`05`, `SFT-RO-01`…`04`, `SFT-CA-01`…`13`, `SFT-AO-01`…`08` | Its test data is generated by the specification's own `sqlite3` actions rather than fetched, so it is self-contained — and it is a whole item, not a corner of this one. |
| MS Windows Registry | `WRT-CA-01`…`06`, `WRT-AO-01`…`08` | Four archives of hives, including ones **deliberately manipulated to hide objects from tools**, which is the most interesting thing in this list and the least like the other two. |
| Forensic File Carving | `FC-CA-01`…`10` | **L0 run** 2026-09-30, `CFTT-FC-1`: 29 of 30 files found at their start, 19 byte-exact, three defects and one signature-carving limitation recorded. L1–L5 not run, and not mapped to `FC-CA-*` (the specification text is not held). Fragment reordering (`FC-CA-09`) stays out of scope. |

### The corpus fetcher, and a discrepancy in NIST's own data set

`scripts/cftt/fetch.sh` is committed, so a run's method is not lost. The script fetches a data set, verifies
it where the publisher published a hash to verify against, and states — every
run, out loud — where there was nothing to verify against. `seance_validate::manifest`
turns that into the paragraph a reader needs, with `NotPublished` as a **value**:
a manifest that simply omitted the publisher's hash where none exists would read
as a file that had been verified.

Of the three data sets §5.2 needs, only the string-search set publishes hashes.
It was fetched on 2026-09-15 (9,091,069 bytes, HTTP 200). Three things about it
are recorded.

**1. Both evidence images verify, against all three of the publisher's lists.**

| File | MD5 | SHA-1 | SHA-256 |
|---|---|---|---|
| `copy-to-test-computer/ss-win-07-25-18.dd` | `dcb0196ce0ee873f6a39dc86b7678ced` | `81f89708221554dcac73253afae1d833d74bcaaa` | `1574185b8dedc343ceb7dd306099a7bd41ceb77730b52c8d97181aeb792b6eb9` |
| `copy-to-test-computer/ss-unix-07-25-18.dd` | — | — | `42bc298d973710c9906568d2d460f980c4523d0308a73f85984fa29d58a320ee` |

Ten of the set's files verify; the two target lists (`win_string_doc.txt`,
`unix_string_doc.txt`), the two expected-hit dumps and
`ft-ss-07-Norm-strings.txt` are among them. The evidence half of the
string-search run is on sound bytes.

**2. `copy-to-test-computer/string-search-test-cases.html` does not verify**, and
it is not a readme — it is the file that says which strings each `FT-SS-*` case
searches for. Measured:

| | SHA-256 | SHA-1 | MD5 |
|---|---|---|---|
| the publisher publishes | `a7aa0177…386e0d` | `283806b617cc98f0fa65b6cc08f243afa030e0b8` | `c7a5afbbafd234947cb5f4b91abd2a2f` |
| the archive contains | `1766226f…db1a6f` | `1bf3c7037b49d4836e99649a4eb95152c589db3c` | `1a28389faa2fa321aaa7a669a8cb3614` |

It disagrees in **all three** algorithms, so this is a content difference and
not an inconsistency between two of the publisher's lists. The file is 11,266 bytes, its modification time is 2019-09-05, and the
hash lists are dated 2019-06-18.
The likeliest reading is that the v1.1 revision of 2019-09-27 changed the
test-case HTML without regenerating the hash lists — and that is a reading, not
a finding: nothing available here establishes which of the two is the intended
file. A second party fetching this set will meet the same mismatch, so it is
recorded with both digests rather than smoothed over. **The script exits
non-zero on it**, which is the right default: a run must not grade past an
unexplained mismatch in a file it reads. The string-search grader takes its case
definitions from the `Expected Results by ID` document, the answer key proper,
and states that it did.

**And the answer key proper is in no hash list at all.**
`Expected Results by ID v1.1 9-27-19.{rtf,pdf,docx}` — the file that assigns
test-case identifiers to the expectations, and therefore the document a grader
must take its case definitions from — appears in none of the three lists. They
name `Expected Results by ID - 07-25 Data Set.{rtf,pdf,docx}` instead, which
this archive does not contain. So the answer key is **unverifiable against the
publisher**, and its digest in the manifest is a first-acquisition record. The
one answer-key document that *does* verify is
`String Search Data Sets Meta-Data Results.rtf`, which is the only file that
assigns test-case ids to the `META` rows.

**3. Six files the publisher hashes are not in the archive under those names.**
The list names `Expected Results by ID - 07-25 Data Set.{docx,pdf,rtf}` and
`String Search Data Sets Meta-Data Results.{docx,pdf,rtf}`; the archive holds
`Expected Results by ID v1.1 9-27-19.{docx,pdf,rtf}` and the Meta-Data files
under matching names at a different path. They are reported as **hashed by the
publisher and not present**, which is what they are: the publisher's hash is for
a file this archive does not contain under that name, so nothing here is
verified by it.

**And a fourth thing, about the reader rather than the data.** The publisher
ships its three hash lists in one directory in **two different formats** —
`<hex>  <path>` for SHA-1 and SHA-256, and BSD's `MD5 (<path>) = <hex>` for MD5.
A reader that knew only the first returned **nothing** from `hash-md5.txt`, and
nothing would have been recorded as "the publisher published no hash" about a
list sitting next to the files. Both forms are read, and a line neither form
explains is **counted** rather than guessed at, because a hash bound to the
wrong file reports a verification that did not happen.

### The string-search answer key, and what its own rows taught

The key is 921 rows of `ID:term:BYTE:SECTOR:filename:fs:encoding`, and
`seance_validate::cftt::string_search` parses every one of them. Six things
about it are load-bearing, and each comes from the real file rather than the
format description.

**The offsets are absolute byte offsets into the raw image.** Established, not
assumed: fifteen occurrences of three target strings were located with
`grep -abo` and all fifteen equalled the published offset exactly. One of them,
`SecretKey` at byte 15427, is *before the first partition begins*, inside the
GPT partition-table region — an offset that cannot exist in any file-relative or
partition-relative scheme. So a grader can compare the key against offsets
measured on the image, which is the fact the whole run rests on.

**134 of the 921 expected hits are in unallocated space.** A search over parsed
records and allocated content cannot reach them, and grading them as misses
would report a defect where the answer is that the expectation is outside the
declared universe. They are separated and recorded as `NotAssessed` **with the
reason**.

**Thirty-five terms carry a leading or trailing space.** Row 0144 asks for
`plan ` — with the space. A parser that trimmed it would search for `plan`,
find different offsets, and grade real hits as false positives.

**Four rows publish no offset at all.** They state the literal word `zipped`,
because the term is inside a compressed `.docx`. They are real assertions — a
tool that reads inside compressed formats should find the term — with no
position to compare against, so they are graded on whether the term is found and
not on where. Rejecting them as malformed would lose four assertions and raise
the pass rate over the remainder.

**One row publishes two offsets.** `6006:Washington:4305916,7758848:…` is a
fragmented occurrence, and both sectors cross-check against both offsets
pairwise. A list with one unreadable member is *not* graded on its readable
half, because that grades a fragment as the whole.

**The 77 rows keyed `META` are not metadata.** Holding them apart as "the set's
own metadata assertions" would exclude 77 gradeable expectations from the run. Each is a hit at a real offset in a real
filesystem whose **containing file** the publisher does not name —
`META:cañón:1000741041:1954572:UNKNOWN:exfat:utf-16-be`, and the next row is the
same term in the other UTF-16 byte order, one byte along. They are content
expectations with an unknown file, and nothing else.

The sector field is `floor(byte / 512)` and therefore redundant, which makes it
a free cross-check: **every row of the real key agrees with itself**, and a row
that did not would have both numbers reported and neither trusted.

**An expectation is identified by `(id, term)`, never by the id alone.** Seven
Windows ids and eight Unix ids appear on three rows each with three *different
and overlapping* targets — verbatim, id 2944 carries `fox`, `panda tiger fox`
and `tiger` at three adjacent offsets — and the answer key lists that id under
both `FT-SS-04` ("Panda and fox") and `FT-SS-10-Hex` ("panda"), neither of which
wants a hit on `tiger`. A grader resolving by id produces three expectations
where the case wants one, and then grades the tool against a hit nobody asked
for.

**And the questions are not verified, only the answers.** The answer key gives
the expected hit identifiers and **never the query**. Every search string and
every search option — match case, whole words, Unicode, stemming, the hex
expression, the regular expression — comes only from
`copy-to-test-computer/string-search-test-cases.html`, which is the one file
that fails all three hash algorithms. So a run here can say "the tool found what
that file asked for"; it cannot say "the tool found what the published
methodology asks for", and the difference rides on the result rather than being
smoothed over.

### The run

Performed with `scripts/cftt/run-string-search.sh`, graded by `cftt-grade`, over
`ss-win-07-25-18.dd` (2,098,028,544 bytes, verifying against all three of the
publisher's hash lists). The current result is `CFTT-SS-2`, below: 648 of 709
assessed expectations found.

> **This is not third-party validation.** NIST has not tested this tool. And the
> expectations are verified against the publisher while **the questions are
> not** — the answer key gives the expected hit identifiers and never the query.

| | count |
|---|---|
| found | **648** |
| not found | 61 |
| not applicable — in unallocated space, which this tool's indexed search does not reach | 134 |
| not assessed — stating a position and naming no file, and row 7010 | 78 |
| **published total** | **921** |

The "not applicable" row describes the **indexed** search this run graded. A byte
sweep that does read unallocated regions offered to it exists in the engine
(`seance_search::sweep`, `ROADMAP` §1.2) and is graded against this same image as
`CFTT-SWEEP-1` below. It is reachable as `POST /api/v1/cases/:id/search/sweep`
(API only: no screen or terminal command calls it), so the row above stands for
what an examiner reaches from a screen.

Failures are attributed by the file inventory the grader takes for the case,
because a term missing from a file that was never recovered is a
**file-recovery** finding, and reporting it as a search finding sends an examiner
to the wrong half of the product.

The index matches exact-form: an NFC query does not find NFD text and the
reverse. CFTT does not grade this because its key always pairs a term with a file
in the same form. The extractor keeps a combining mark with the letter it follows,
so decomposed (NFD) rows such as `mañana` 3153–3173, `libertà` 3217–3237 and
`Mäuse` 3281–3301 are found.

The key names two aliases, `LOUDBIRD` and `WADI`, that occur only in the key
(`win_string_doc.txt`) and the hit dump (`win_hit-dump.txt`, seven
`File: …-LOUDBIRD-…` and seven `File: …-WADI-…` lines). On the image they occur
only inside file content, in the test files' own `TESTFILE: (…-LOUDBIRD-…)`
header and `… (…-LOUDBIRD-…) END-OF-FILE` trailer lines, and never as a file name
(`fls -r` on all four partitions lists none). The prose documents
(`read-me-first`, `Expected Results by ID v1.1 9-27-19` and `String Search Data
Sets Meta-Data Results`, each as `.pdf`, `.docx` and `.rtf`) do not mention
either.

### The key checked against the image

The same script makes two checks of the answer key **before** grading:

* **Its bytes.** Every row's term, in its stated encoding, is compared with the image at its
  published offset (`cftt-grade --image`). Of 921 rows, **903** hold the term there; **13**
  point at the publisher's own `<id> <====` marker beside the hit (7015, the FMT rows
  9000–9003/9006–9007 and their unallocated copies 9508–9511/9514–9515), which does not
  contradict the row; **4** (`zipped`) publish no offset, so could not be looked at; and **1**,
  row 7010 (`bear`, byte 1,677,997,552, whose file field reads
  `(70Ѐ1 or 7а^@1) LIVE-MFT-Ursa-mft-utf-16-be.txt`), is contradicted — the bytes are zero. That
  row is graded *not assessed* as a fault in the key.
* **Its file names.** `scripts/cftt/resolve-key-files.py` asks The Sleuth Kit — an independent
  reference tool, not Séance — which file holds each named row's offset. Of 708 named rows
  (bare `UNKNOWN` and `unalloc` rows are not resolved), 707 resolve and **693 agree with the
  key's name**; row 7010 resolves to no file; and **14 name a file that is not at their
  offset** — the twelve aliases and the two `FRAG-UNKNOWN` rows (6000 in
  `FRAG-fat-Sacramento-split-512.txt`, 6006 across two fragments of
  `FRAG-fat-Olympia-split-32k.txt`). Those fourteen are
  graded against the file at their offset, each row says so, and the count is printed beside
  the headline.

  Each offset is put in its file system's own data unit before `ifind -d`: FAT and exFAT by
  sector, NTFS by cluster, Ext2/3/4 and HFS+/HFSX by block (sizes from `fsstat`); any other
  file system is recorded "could not look", never "no file there". On
  `ss-unix-07-25-18.dd`, 356 of 926 named rows resolve (six `LIVE-` LOUDBIRD/WADI
  aliases, one per Ext4/HFS+/HFSX partition); the 342 `DELETED-` rows on Ext4 and
  HFS+ cannot be placed by `ifind`, because their metadata no longer points at
  their blocks; and 228 are on the fourth partition, which `fsstat` does not
  recognise, so could not be looked at.

**648 of 709 assessed expectations were found** (see `CFTT-SS-2`): 134 not applicable and 78 not
assessed, the 77 `UNKNOWN` rows and row 7010. **14 of the 648 were graded against the file
Sleuth Kit places at the key's offset rather than the file the key names**, and all 14 pass.

**No file-recovery failure remains.** The case's inventory holds all twelve thunderbird/cañón
files, both FRAG files and all eight `*-MFT-Ursa-*` files, including
`LIVE-MFT-Ursa-mft-utf-16-be.txt` (MFT entry 301, resident `$DATA`), whose row 7011 passes.
The run's outputs (`report.json`, `inventory.json`, `key-files.json`) are kept.
A synthetic fixture pins each mechanism (`seance_validate` `image_verification`, `attribution`);
the figures above are from the real image, and
`the_real_key_rows_that_do_not_verify_are_counted` and
`the_frag_unknown_rows_return_with_key_files` (`SEANCE_CFTT_SS` set) re-measure them.

### CFTT-SS-1 — the same run, by published case

The answer key names hit ids and never the case, so a row cannot say on its own which
`FT-SS-*` test case it is evidence for. The mapping is in the data set's own
`Expected Results by ID v1.1 9-27-19.docx` — a table of Case/String, Encoding and the Active,
Deleted and Unalloc ids, for both data sets — and `cftt-grade --cases` reads it
(`seance_validate::cftt::cases_map`). On the Windows set it holds **25 cases and 874
entries, and every entry resolves to exactly one key row** (`SEANCE_CFTT_SS`:
`every_id_in_the_case_map_exists_in_win_string_doc`). Two properties of the table are kept
rather than smoothed: an id two cases name (2944 is under both `FT-SS-04` "Panda and fox" and
`FT-SS-10-Hex` "panda") is graded once **per case**, so the per-case totals below sum to more
than the row count; and where the key holds several terms at one id (2944–2950 each carry
`panda tiger fox`, `tiger` and `fox`), a case is attached only to the row whose term holds
every positive word of its query, so neither case is graded on `tiger`.

The table below is a **re-grade of a recorded run made on a binary without the UTF-16
widening** (`results.json`, `inventory.json`, `key-files.json` kept from it, binary SHA-256
`4e03b2e9…821e6918d`, image checked with `--image`), not a new ingest. That run found 480 of 709
assessed expectations (229 not found, 134 not applicable, 78 not assessed); `CFTT-SS-2` is the
run on the widened indexer. The headline counts each key row once. 812 of the 921 key rows are named by at least one case (771 by one, 27 by
two, 7 by three, 7 by four); 109 are named by none (the 77 `META` rows and 32 numbered ones).

| Case | Passed | Failed | Not applicable | Not assessed | Total |
|---|---|---|---|---|---|
| (no published case names this row) | 24 | 0 | 8 | 77 | 109 |
| FT-SS-01 | 6 | 0 | 1 | 0 | 7 |
| FT-SS-02 | 30 | 0 | 5 | 0 | 35 |
| FT-SS-03 | 18 | 0 | 3 | 0 | 21 |
| FT-SS-04 | 6 | 0 | 0 | 0 | 6 |
| FT-SS-05 | 12 | 0 | 2 | 0 | 14 |
| FT-SS-06 | 24 | 0 | 0 | 0 | 24 |
| FT-SS-07-CJK-char | 12 | 24 | 6 | 0 | 42 |
| FT-SS-07-CJK-hangul | 6 | 12 | 3 | 0 | 21 |
| FT-SS-07-CJK-kana | 12 | 24 | 6 | 0 | 42 |
| FT-SS-07-Cyrillic | 6 | 12 | 3 | 0 | 21 |
| FT-SS-07-Latin | 12 | 24 | 6 | 0 | 42 |
| FT-SS-07-NoBOM | 42 | 36 | 13 | 0 | 91 |
| FT-SS-07-Norm | 66 | 84 | 25 | 0 | 175 |
| FT-SS-07-RTL | 6 | 12 | 3 | 0 | 21 |
| FT-SS-08-Email | 42 | 0 | 7 | 0 | 49 |
| FT-SS-08-Phone | 42 | 0 | 7 | 0 | 49 |
| FT-SS-08-SS | 18 | 0 | 3 | 0 | 21 |
| FT-SS-09-Doc | 15 | 1 | 16 | 0 | 32 |
| FT-SS-09-Frag | 2 | 0 | 0 | 0 | 2 |
| FT-SS-09-Lost | 0 | 0 | 4 | 0 | 4 |
| FT-SS-09-MFT | 7 | 0 | 0 | 1 | 8 |
| FT-SS-09-Meta | 12 | 0 | 2 | 0 | 14 |
| FT-SS-09-Stem | 96 | 0 | 16 | 0 | 112 |
| FT-SS-10-Hex | 6 | 0 | 1 | 0 | 7 |
| FT-SS-10-Regex | 12 | 0 | 2 | 0 | 14 |

Every failure in the `FT-SS-07-*` rows is a non-ASCII term in a UTF-16 file (168 the UTF-16
widening brings into reach and 60 CJK, Hangul and ligature rows it does not), and the one
`FT-SS-09-Doc` failure is `crossbow` (9007), the markup case. The table predates the
widening, so the 168 pass in `CFTT-SS-2`.

#### Behaviours of the evidence and the harness the run depends on

**The GPT entry-array CRC does not verify on this image.** The header CRC verifies
(`0x6e47e4e5`) and the entry-array CRC does not (declared `0xf87a9ff9`, computed
`0x11726dec`). `mmls` reads its four partitions regardless. A failed integrity check is
a fact to report, not a reason to report nothing: a CRC mismatch is what carved,
truncated and deliberately damaged evidence looks like, and **"could not verify" is
not "not there"**. The product decodes the entries and stamps every partition
unverified: **4 partitions, 3 filesystems and 1,242 files**.

**A phone number is a plain string.** One of the published targets is `(901)555-1111`.
Tantivy's query syntax claims parentheses, so the query is retried literally and the
response says that it was. A forensic search does not answer a plain string with an
error, and does not silently reinterpret one.

**An idle task queue is not a committed index.** The runner polls the index's own
visible size until it stops growing, and says so if it never does. A number produced
earlier is a floor.

#### The run's ceiling

Grading the whole published key against an **empty** result set fixes the shape
of what a run can and cannot speak to. A run whose ceiling nobody measured can
report a good percentage over a denominator that quietly excludes the hard
cases:

| | of 921 published expectations |
|---|---|
| **not applicable** — in unallocated space, which Séance offers no search of | 134 |
| **not assessed** — stating a position and naming no file, which a tool reporting artifacts cannot be compared against | 77 |
| **assessable** — the most this tool could ever be graded on | **710** |

Of those 710, **228** have terms that are non-ASCII and stored as UTF-16. Without
the UTF-16 widening the content indexer cannot reach them, which is very nearly a
third of everything the run can be graded on. A further 78 expectations are ASCII
terms stored as UTF-16, roughly half of them big-endian.

**With the UTF-16 widening,** the UTF-16
passes also take the Latin-1 letters and one single-block alphabet per run
(Greek, Cyrillic, Armenian/Hebrew, Arabic, kana); CJK ideographs and Hangul stay
out by decision. Measured against the real key by
`the_expectations_a_known_limitation_will_fail_are_counted_in_advance`
(`SEANCE_CFTT_SS` set): of the 228, **168 are now in reach** and **60 are not** —
`東京`, `中国`, `中國`, `서울`, and `inﬁnity`, whose U+FB01 ligature is in no
accepted block, 12 rows each. **The ceiling is 650 of 710** — 649 of 709 once the
key is checked against the image and row 7010 leaves the assessable set. It is at most
**648 of 709** in practice, because `crossbow` (row 9007) fails for a reason the widening
does not touch. `CFTT-SS-2` found 648.

None of that is a reason to soften the grade. A miss caused by a limitation of a
feature the tool **does** offer is recorded as a **failure** with the defect
named, not as "not assessed": that status exists for *could not look*, not for
*looked with a tool that cannot see this*. The percentage's denominator is the
assessable set, because dividing by 921 would count a not-applicable row as a
success for the tool.

#### What the key's `unalloc` label does and does not mean

134 rows carry it, and cross-checking every one against the image's own GPT
found that it spans **five** distinct places, not one:

| rows | where |
|---|---|
| 128 | the partition holding no filesystem |
| 2 | no offset published at all |
| 1 | before the first partition — the GPT area (`SecretKey`, byte 15427) |
| 1 | after the last partition |
| 1 | **inside the NTFS partition** (row 7016, `disconnected`) |
| 1 | **inside the exFAT partition** |

So `unalloc` means *unallocated*, and two of those rows are unallocated clusters
**inside a live filesystem**. A partition table cannot see that, which means a
grader cannot decide the allocation state of a reported offset arithmetically —
that needs the filesystem's own allocation bitmap. The layout classifier says
which partition an offset is in and claims nothing about allocation, which is
the honest scope for it.

### What this section is not

It is not a result. No CFTT methodology has been run in full and published. String
search (Windows image only), deleted file recovery (`DFR-CR-01`…`04`, three of them
paraphrased) and file carving (L0 only) have each been run in part and recorded:
`CFTT-SS-2`, `CFTT-DFR-1`, `CFTT-FC-1`. None is "in full". When one has, its run goes in this file with its manifest digest
beside it, and the comparison gains a separate, precisely-named row — "CFTT
published test methodology run in full and published" — on which Séance would be
⚠️ (self-administered, reproducible, digest-checkable). The existing
"NIST CFTT or formal third-party validation" row stays ❌, because it asks a
different question.

## What the case set still does not cover

- **Windows memory.** MEM-2 exercises discovery on a
  real Windows 11 26200 capture: the physical layout, the directory table base,
  the kernel load address and the kernel's PDB identity all recovered from the
  bytes, and checked against Microsoft's PDB. What MEM-2 does **not** cover is
  everything after discovery — symbol admission, the page-table proof under
  load, process listing, or any of the other 20 stages. The Volatility parity
  harnesses do compare those against a third-party tool's output on the same
  images (XP, Win10 Lone Wolf, Win11 22000), which is still the right shape for
  further cases here.
- **No Linux or Windows *filesystem* case beyond FAT.** NTFS, ext4, APFS, XFS,
  Btrfs and the rest are covered by unit, golden-image and corpus tests, not by
  a durable known-answer artifact.
- **No macOS case in the declared set**, and no macOS image in the corpus. The
  hand-worked macOS runs below (for example `MAC-1`) are not corpus cases. This is
  the same gap that leaves `seance_plugin_memory_macos` stamped unvalidated — see
  `documentation/MEMORY_BUILD_BINDING.md`, item 4.
- **No mobile case.** Nothing in the *declared case set* exercises an Android or
  iOS extraction against a published answer. Runs below do, by hand, for example
  `AND-1` (Android 14, Pixel 7a) and `IOS-1` (iOS 17, encrypted iTunes backup).
  None is a corpus case, for the same reason as the rest of that section —
  the images are multi-gigabyte public downloads.

### PST-8BIT-1 - a SYNTHETIC ANSI folder name, 2026-10-20

Not a known-answer run and not evidence about any mailbox. `seance_plugin_email/tests/fixtures/pst_old/m57_jean_synthetic_8bit_folder.pst`
(SHA-256 `3b47acfc18eb0f8d65770206d604401f60b733f5d3a7235fef6c4b030d0ff3e3`) is the Jean version 14 store with one folder-name byte patched to 0xE9
(block CRCs recomputed; `PROVENANCE.txt`). It grades the mechanics only: the live walker decodes the 8-bit name in the
assumed Windows-1252 and lists it on the summary. Re-run: `cargo test -p seance_plugin_email a_live_version_14`.
No real ANSI mailbox with non-Latin text has graded the decoding.

## Known-answer runs outside the declared case set

These were worked by hand against a published answer key and are recorded here so
the figure is checkable, but they are **not** in `seance_validate::cases::cases()` —
the images are multi-gigabyte public downloads, not corpus files. The next step for
each is a declarative case that fetches on demand with a pinned hash.

### NET-1 — DFIR Madness Case 001 capture, 2026-09-11

**Image.** `case001.pcap` from `https://dfirmadness.com/case001/case001-pcap.zip`
(197,583,252 bytes; the publisher's MD5 was matched on download). Despite its
name the file is **pcapng 1.0**, one Ethernet interface, written by
`Mergecap (Wireshark) 3.2.6` on `Linux 5.8.0-kali1-amd64` — both read out of the
Section Header Block and carried on the `NetworkCapture` record.

**Ground truth.** Two independent sources: the publisher's answer key names
`203.78.103.109` as the command-and-control address and `194.61.24.102` as the
delivery host; and a hand-written pcapng walk in Python (block census, IPv4 5-tuple
aggregation, UDP/53 count), run before the module existed, gave the packet and flow
figures below.

**Run.** `cargo build --release --example capture_probe -p seance_plugin_pcap`, then
`target/release/examples/capture_probe /path/to/case001.pcap 203.78.103.109`. The
probe drives `PcapParser::process` over the file exactly as ingest does.

| Measure | Independent count | `seance_plugin_pcap` |
|---|---|---|
| Packets (EPB) | 411,797 | 411,797 |
| Frames with no network layer | — | 2,131 |
| Bidirectional flows | 34,047 one-way tuples (≈17 k pairs) | 17,133 |
| UDP/53 messages | 2,650 | 2,650 (2,640 query/response, 10 UPDATE) |
| Flows with `203.78.103.109` | 10 one-way tuples, **6,735 packets** | 5 flows, **6,735 packets** |
| First contact with the C2 | 2020-09-19 02:25:18.566 Z | 2020-09-19 02:25:18.565676 Z |
| Wall time | — | 0.3 s |

Every flow to the C2 is on port 443 and marked `remote_is_external`; three ended in
`handshake_seen`, two in `reset`. The capture record carries **no** incompleteness
stamp, which is the correct statement: nothing was refused, no packet was cut by the
snaplen, the capture engine reported no drops, and the file was read whole.

**DNS UPDATE.** Ten of the 2,650 DNS messages are DNS UPDATE (opcode 5), the
compromised hosts registering with the domain controller. Their sections are
zone/prerequisite/update rather than question/answer. The decoder reads the opcode
and records those messages as what they are, so the count is 2,650 of 2,650 with no
incompleteness stamp. A refusal that says "a layout the decoder refused to guess at"
about a well-formed message of a different kind is a true statement about the
parser and a false one about the evidence.

### NET-4 — DFIR Madness Case 001 capture, stage 2 (reassembly, HTTP, TLS, ARP), 2026-09-26

NET-1 graded stage 1 on this capture; NET-3 graded stage 2 on Nitroba only. This
run grades both stages on Case 001.

**Image.** The same `case001.pcap` as NET-1, unzipped from
`~/forensic_corpora/dfir_madness_case001/case001-pcap.zip` (publisher's MD5
checked in `VERIFICATION.txt`).

**Ground truth, none of it from Séance.** `tcpdump` 4.x reading the pcapng
directly, one BPF filter per figure. The payload's hashes from the publisher's
own `autorunsc` output (`DC01-autorunsc.zip` and
`DESKTOP-SDN1RPT-autorunsc.zip`): the `coreupdater` service at
`C:\Windows\System32\coreupdater.exe`, MD5 `EED41B4500E473F97C50C7385EF5E374`,
SHA-256 `10F3B92002BB98467334161CF85D0B1730851F9256F83C27DB125E9A0C1CFDA6`. **Mind
autorunsc's columns**: it prints `PESHA-256` (the Authenticode hash,
`88763E60…E302FA28E`) immediately before `SHA-256`, and the file's hash is the
second. The C2 and delivery
addresses from the publisher's answer key, as in NET-1.

**Run.** `SEANCE_CASE001_PCAP=/path/to/case001.pcap cargo test --release -p
seance_plugin_pcap --test case001_capture` — six tests, each figure below an
assertion except the stream counts, which the probe (`cargo run --release
--example capture_probe -p seance_plugin_pcap -- /path/to/case001.pcap`) gives.

**The independent counts, verbatim.** Each figure in the middle column is one of
these, run in the directory holding `case001.pcap` (`TZ=UTC` so the times read
as the capture's UTC):

```sh
tcpdump -nn -r case001.pcap | wc -l                                        # 411,797 packets
tcpdump -nn -r case001.pcap 'udp port 53' | wc -l                          # 2,650
tcpdump -nn -r case001.pcap 'udp port 53' | grep -cE ' [0-9]+[+*]? ?update' # 10
TZ=UTC tcpdump -nn -tttt -r case001.pcap 'host 203.78.103.109' | wc -l     # 6,735; head -1 is the first contact
# RDP conversations: fold each packet's two endpoints into an unordered pair
tcpdump -nn -r case001.pcap 'host 194.61.24.102 and tcp port 3389' \
  | awk '{a=$3; b=$5; sub(/:$/,"",b); if (a<b) print a, b; else print b, a}' \
  | sort -u | wc -l                                                        # 14,116
# One-way TCP directions: ordered (source, destination) pairs
tcpdump -nn -r case001.pcap 'tcp' \
  | awk '{b=$5; sub(/:$/,"",b); print $3, b}' | sort -u | wc -l            # 31,548
# ... of them, those that carried a payload byte (IPv4 only; the capture has no IPv6 TCP)
tcpdump -nn -r case001.pcap \
  'tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' \
  | awk '{b=$5; sub(/:$/,"",b); print $3, b}' | sort -u | wc -l            # 17,500
# Conversations that open a ClientHello: a segment whose payload starts with a
# handshake record (type 22) holding handshake type 1
TZ=UTC tcpdump -nn -tttt -r case001.pcap \
  'tcp and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16
       and tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01' > ch.txt            # 30,554 segments
awk '{print $4, $6}' ch.txt | sed 's/:$//' | sort -u | wc -l               # 15,360 pairs
awk '($1" "$2) <  "2020-09-19 02:25:18.565676" {print $4, $6}' ch.txt \
  | sed 's/:$//' | sort -u | wc -l                                         # 15,045 before the C2
awk '($1" "$2) >= "2020-09-19 02:25:18.565676" {print $4, $6}' ch.txt \
  | sed 's/:$//' | sort -u | wc -l                                         # 316 after it
```

| Measure | Independent count | `seance_plugin_pcap` |
|---|---|---|
| Packets | 411,797 (`tcpdump -r … \| wc -l`) | 411,797 |
| UDP/53 messages; of them DNS UPDATE | 2,650; 10 (`'udp port 53'`, opcode printed as `update`) | 2,650; 10 records with `opcode` 5 |
| Flows with `203.78.103.109` | 5 five-tuples, 6,735 packets, all to its 443 | 5 flows, 6,735 packets, all to its 443 |
| First contact with the C2 | 2020-09-19 02:25:18.565676 | `2020-09-19T02:25:18.565676Z` |
| RDP conversations from `194.61.24.102` | 14,116 five-tuples (29,309 SYNs — most retried) | 14,116 `NetworkFlow` records to 3389 |
| One-way TCP directions / those carrying payload | 31,548 / 17,500 | 31,543 streams reassembled, stream table not full (the 5 fewer are consistent with directions that sent neither a SYN nor a byte, which open no stream by design; not confirmed one by one) |
| The implant download | `GET /coreupdater.exe` 10.42.85.10:62410 → 194.61.24.102:80 at 02:24:06.939, answered `HTTP/1.0 200 OK` | one `HttpTransaction` with exactly that; its response body a `FileEntry` with no incompleteness stamp |
| The body's hashes | autorunsc MD5 `eed41b45…5e374`, SHA-256 `10f3b920…c1cfda6` | **both match** |
| The C2 on 443 | the C2's first bytes on each of the five connections are a 4-byte length (the Meterpreter stage size, `tcpdump -x`), not a TLS record | 0 `TlsSession` records for the C2, with all five flows' streams reassembled — so "no session" is a reading of the bytes, not an absence of them |
| Conversations opening a ClientHello | 15,360 pairs; 15,045 before the C2's first contact, 316 after (one reused pair, `194.61.24.102.40240`, is on both sides) | 15,356 `TlsSession` records, every one with its ClientHello read; placed by the first packet of their flow, 15,042 before and 314 after. **Every difference is accounted for**: four conversations have a ClientHello and no session (below), three before and one after, and the reused pair is placed once, before; none goes the other way |
| TLS on 3389 from `194.61.24.102` | 14,116 pairs | 14,113 sessions — the three short are the reused five-tuples noted below |
| ARP | 2,131 frames, 1,058 replies, 3 addresses each answered by one MAC | 2,131 frames, 1,058 replies, 3 bindings, 0 contested, same MACs |
| Capture record | — | **no** incompleteness stamp |
| Wall time / peak RSS | — | 1.3 s / 1.37 GB (the probe, release build) |

**Stream table sizing.** The RDP brute force from the delivery host began at 02:19:26
and opened 28,249 of the capture's 31,543 streams over the next 38 minutes
(`tcpdump`, one per 5-tuple and direction that carried a SYN or data). A table of
4,096 streams would fill about four and a half minutes before the implant was
fetched at 02:24:06 and leave the download, both hosts' five command-and-control
sessions and the whole post-compromise period unread. So:

- the stream ceiling is **262,144** (`reassemble_tests.rs`,
  `the_default_table_holds_a_brute_force_of_twenty_thousand_conversations`) —
  a count bounding the table's bookkeeping, about 64 MiB of it when full of
  empty streams, while the bytes stay bounded by the 256 MiB reassembly budget;
- a conversation the table refuses is named, and its `NetworkFlow` record
  carries `tcp_streams_not_read`, the refused directions in
  `tcp_directions_not_read`, and a `cap_reached` stamp saying no content was
  read from them. Where the table filled between a conversation's two
  directions, the stamp names the one direction refused and says the other was
  read, because that other stream's request or ClientHello has its own record
  (`reassemble_tests.rs` `a_conversation_the_table_refused_is_named`,
  `emit_tests.rs` `a_flow_the_stream_table_refused_says_its_bytes_were_not_read`
  and `a_flow_refused_in_one_direction_names_that_direction_and_not_the_other`);
- the TLS session-record ceiling is one per conversation the table holds,
  131,072 (`tls_tests.rs`
  `the_session_record_ceiling_is_not_tighter_than_the_stream_table`, and on
  the capture itself `case001_capture.rs`
  `tls_sessions_after_the_compromise_have_records`). The brute force's TLS
  handshakes on 3389 are 14,113 of the 15,356 sessions; a ceiling of 10,000 would
  leave the post-compromise sessions without records.

On this capture: 31,543 TCP streams, 229 HTTP transactions and 223 bodies, 15,356
TLS sessions and 2,140 certificates, in 1.3 s.

**What this does not show.** One capture, graded on the figures above. It does
not grade the HTTP or TLS fields of the 228 other transactions or 15,356
sessions against a second decoder (`tshark` is not installed here); NET-3 does
that on Nitroba. The ceiling counts streams, one per direction: a capture
that opens more than 262,144 of them (131,072 two-way conversations, or up to
twice that many one-way ones) still fills the table, and says so on the capture
record and on each refused flow.

**Limits this grade found:**

- **TLS behind a preamble.** TLS is recognised only at a stream's first byte, so
  TLS behind a protocol preamble gets no session record. On this capture that
  is `10.42.85.10:62514 → 10.42.85.115:3389` at 02:35:55 — the RDP session from
  the domain controller to the desktop, after the compromise — whose client
  sends a 19-byte X.224 connection request before its ClientHello. The flow and
  its streams are recorded; the TLS in them is not read. STARTTLS protocols
  have the same shape.
- **A reused five-tuple.** A five-tuple reused for a second connection within the
  capture is one flow, and the later connection's bytes are folded into the
  first connection's streams, where its ClientHello is not at the start. Where
  the first connection carried no TLS at its first byte (a reset before any
  payload, or an X.224 request), no session is read. Three brute-force
  five-tuples (`194.61.24.102:{38088, 38092, 38100}`) lose their TLS session
  this way.

### C001-1 — DFIR Madness Case 001 disk images, questions 11–13 and bonus 7–8, 2026-09-11

**Images.** `20200918_0417_DESKTOP-SDN1RPT.E01`–`.E04` and `E01-DC01` (the domain
controller), from `https://dfirmadness.com/the-stolen-szechuan-sauce/`, ingested as the
case "DFIR Madness 001 — The Stolen Szechuan Sauce" alongside the two memory images.

**Ground truth.** The publisher's answer key. Its times run one hour behind the evidence
(the key's clock is Mountain against a Pacific host; the capture's RDP session at
02:19:28 Z is the EVTX logon at 03:21:48 Z), so each answer below is matched to the
key at the hour it names.

| Question | Key | What Séance holds |
|---|---|---|
| 11 — when the sauce was stolen | ≈ 02:30 | Explorer history (`WebCacheV01.dat`): `file:///C:/FileShare/Secret/Szechuan Sauce.txt` visited 03:32:21 Z, between `SECRET_beth.txt` (03:32:13) and `PortalGunPlans.txt` (03:32:02) |
| 12 — other files accessed or manipulated | Beth's secrets manipulated and Morty's thoughts stolen ≈ 02:34 | `RecycleBinEntry`: `C:\FileShare\Secret\SECRET_beth.txt` deleted 03:34:27 Z; `Beth_Secret.txt` created 03:34:56 Z ($FN) and visited 03:35:07 Z; `NoJerry.txt` visited 03:31:50 Z |
| 13 — last contact with the adversary | interactive logoff ≈ 03:00, attacker still active at capture | Security EVTX logoff at 04:00 Z |
| Bonus 7a — original name of Beth's secret | `Secret_Beth.txt` | `$IU2L112.txt` → `C:\FileShare\Secret\SECRET_beth.txt` |
| Bonus 7b — original contents | "Earth Beth is the real Beth." | `$RU2L112.txt`, 28 bytes: `Earth beth is the real beth.`; the replacement reads `Space Beth is the real Beth` |
| Bonus 8 — timestomped file | `Beth_Secret.txt` | `timestomp_suspected: true` on the strong timestomp signal: $SI ChangeTime 2020-09-18T23:35:35, whole-second, older than $FN Created 2020-09-19T03:34:56.97 |

**Timestomp signal.** Without the strong signal the stomped file carries three weak indicators
and `timestomp_suspected: false`, and the domain controller's memory MFT sweep calls
14,649 of 25,537 cached records timestomped on the bare `SI Created < FN Created` test.
The strong signal was measured on this case's two Windows images (4,231 records with
an older ChangeTime, one whole-second) and the Data Leakage image (none).

### DFR-1 — NIST Deleted-File-Recovery set, 2026-09-11

**Images.** The NIST DFR corpus (`~/ctf-evidence/dfr/`): dozens of small single-
filesystem `.dd` images, each a scripted scenario of created and deleted files with a layout
document that names every file, its size, and whether it was deleted. Graded by `dfr.py`
(create case → ingest → wait idle → compare the case's recovered deleted files against the
scenario's `ground_truth.json` → delete the `.dd`).

*(Superseded by `CFTT-DFR-1`: the claim below that every NTFS, ext and FAT scenario
recovers its deleted files does not survive a graded run of all 90 images.)*

**Result.** Every NTFS, ext and exFAT/FAT scenario graded so far recovers
its deleted files with the right names and sizes — `dfr-01`, `dfr-02`, `dfr-03` across ext,
fat, xfat and ntfs. The one platform that does not is **HFS+ (`-osx`)**: Séance does not yet
claim deleted-file recovery on HFS+, so those images miss their deleted set by design (a
roadmap item, not a defect — the tool is silent about a capability it does not have rather
than wrong).

**Non-ASCII filenames — a strong positive (dfr-04-ext).** The scenario "recover several
non-fragmented files with non-ASCII file names" holds 36 deleted `.txt3` files named in
Devanagari, Hangul, Arabic, Hebrew, CJK, Cyrillic and Urdu (`नान.txt3`, `서울.txt3`,
`北京.txt3`, `پکوڑا.txt3`, `חומוס.txt3`, `чай.txt3`, `ミツビシ.txt3`, …). Séance recovered
**all 36**, each flagged deleted, with its Unicode name decoded correctly. This grades as a
harness FAIL only because the corpus's `ground_truth.json` lists the *English transliterations*
of these names (`BeiJing.txt3`, `Naan.txt3`) while the disk — and Séance — use the real
Unicode, so a name-by-name match cannot join them; the recovery itself is complete and
correct. **Harness limitation, not a product defect:** the DFR grader cannot name-match the
transliterated non-ASCII scenarios (`ext-04` and any like it), so those must be read by
recovered-count and spot-check rather than by the grader's verdict.

**Overwrite scenarios — forensic honesty confirmed (dfr-07-ext).** "Recover one overwritten
file" fills the disk with three ~300 MB `FILL.TXT` files that overwrite the blocks and
directory entries of most of the deleted set. Séance recovered every deleted file that
survived (`FumAlSamakah`, `Furud`, `Giauzar`, `Gomeisa`, `Grumium`, `fornax` — 6/6, each
flagged deleted) and, correctly, did **not** invent the overwritten ones: the nine the
corpus's `ext-07` ground truth still lists (`Bellatrix`, `Canopus`, `Denebola`, …) return
**zero** hits anywhere in the case — their directory entries are gone, so there is nothing to
recover. Fabricating them would be the dangerous failure; their absence is the right answer.
The grader reads this as a FAIL only because the corpus's `ext-07` entry is a different
generation of the scenario than the shipped `.dd`. (NTFS keeps a file's `$MFT` record after
its data is overwritten, so the `-07-ntfs` variant may legitimately recover more — checked
per variant, not assumed.)

**Deleted-directory recovery, characterised (dfr-11-ext).** "Recover one non-fragmented
directory" deletes a directory (`Orion` on ext2, `Andromeda` on ext3, `Lyra` on ext4) holding
nine files. On every partition the deleted directory's inode has `Blockcount 0` — the kernel
freed its data block — so its contents are unreachable through the inode (`debugfs ls
<inode>` returns empty too). Séance recovers the deleted directory's **name** (its parent's
entry survives) but not its contents, which is correct: following the blockless inode recovers
nothing, and reading whatever now occupies the freed block would fabricate. The nine files are
recoverable only by carving the freed directory block out of unallocated space — a capability
gap recorded in `ROADMAP.md` (§5.6, *Deleted-directory contents on ext and HFS+*), like HFS+ deleted recovery, not
a defect. **Nested ext directory entries.** On `dfr-09-ext`, deleted names nested inside another hidden
entry's widened `rec_len`, off the chain the walk follows, are recovered by a 4-byte-aligned carve
pass, checked against the on-disk bytes with `debugfs`: **40 of 40 deleted files recovered.** The corpus's `ground_truth.json` drifts from the shipped
images for the higher-numbered scenarios (confirmed on `dfr-07`, English names vs on-disk
Unicode, and `dfr-13`, `C`-prefixed names in the key vs `E`-prefixed on disk — 0 `C0` bytes,
3,850 `E0` bytes on the ext4 partition), so name-match grading is unreliable there and the
real recovery was verified with `debugfs`/`strings` instead. The link-semantics scenario (`dfr-14`,
"recover other file system object") likewise grades misleadingly: its `false_deleted` is
Séance correctly flagging the `rmTarget`/`rmBoth` targets, which are deleted on disk (inode 0
in `debugfs`), while the harness treats every `created` name as still-live. Its one genuinely
missing file (`far-X4/Castor-far-rmLink-X4.txt`) is another inode-0 entry of the same nested kind; both are recovered.

**Whole-corpus audit.** Every scenario that graded as a failure was categorised, and exactly
one, `dfr-09-ext`, is a Séance miss (nested ext directory entries), and it is recovered. The rest resolve to: the
HFS+ capability gap (`-osx`), overwrite scenarios where the missing files are genuinely gone
(`dfr-07/08/10`), the deleted-directory freed-block gap (`dfr-11/12`), ground-truth generation
drift (`dfr-04` non-ASCII, `dfr-13` prefix), link semantics (`dfr-14`), and harness comparison
artifacts (path-vs-name `dfr-17`, "N files"). Notably, every `false_deleted` alarm is Séance
being **correct** — the files it flags deleted are deleted on disk, confirmed against the
reference tools (`debugfs` on `dfr-14`'s ext, `fls`/Sleuth Kit on `dfr-08`'s FAT, which shows
`r/r * Antares.txt`) — while the corpus's `created` lists do not track files deleted after
creation. Séance detects deletions the ground truth itself omits.

### AND-1 — Josh Hickman Android 14 (Pixel 7a) reference image, 2026-09-11

**Image.** `EXTRACTION_FFS.zip` (34 GB Cellebrite full-file-system, 124,949 files) from Josh
Hickman's Android 14 (Pixel 7a) public reference image, ingested as the case "Josh Hickman
Android 14 (Pixel 7a) reference image" to 3,257,779 artifacts.

**Ground truth.** The image's creation document (`Android14-ImageCreation.txt`), which records
each app's name, install date and local install time, and the scripted per-app activity.

**Installed-application install times.** `/data/system/packages.xml` on Android 12
and later is Android Binary XML, decoded whole: `InstalledAppSummary` reports `encoding: abx, app_count: 369, source: packages.xml`,
complete, beside the 369 from `packages.list`. The install times reconcile with the document
to the second once the device's local zone (America/New_York, EDT = UTC−4 in July) is applied:

| App | Document (local) | Séance (`packages.xml`, UTC) |
|---|---|---|
| BeReal | install 2024-07-26 09:46 | first_install 2024-07-26T13:46:32Z |
| AllTrails | install 2024-07-26 08:51 | update_time 2024-07-26T12:51:38Z |

Each app appears twice — once from `packages.list` (no times) and once from `packages.xml`
(with times) — because both sources are parsed and each is attributed to the file it came from.

**Install provenance — Android 14's finer split, graded 2026-09-27.** `packages.xml` was
streamed out of `EXTRACTION_FFS.zip` on its own (701,599 bytes, SHA-256
`261e59fce3fcd7e6f98b057848a88af49c2e595f6ce2cec3fc772fa51e9b2ef4`; the extraction and its
CRC-32 check are in `hickman_android14/PROVENANCE.md`). Ground truth is an independent ABX
reader written from AOSP's `BinaryXmlSerializer` (`hickman_android14/packages/abx_count.py`),
which shares no code with `seance_xml_util::abx`:

| | Independent count | `seance_plugin_installed_apps` |
|---|---|---|
| `<package>` elements | 369 | `app_count` 369, `encoding: abx`, complete |
| `installer` | 123, all `com.android.vending` | `installer_package` on 123 |
| `installInitiator` | 123, all `com.android.vending` | `install_initiator_package` on 123 |
| `updateOwner` | 56, all `com.android.vending` | `update_owner_package` on 56 |
| `isOrphaned` | `true` on 305; 59 of them with an installer | `is_orphaned: true` on 305 |
| `com.bereal.ft` | initiator, owner, installer all the Play Store; no `isOrphaned` | the same |
| `com.google.android.youtube` | installer and initiator the Play Store; no `updateOwner`; `isOrphaned` true | the same |

On this device `installInitiator` never differs from `installer`, and `updateOwner` is
written on 56 of the 123 Play-installed packages, so it is not a copy of either. Which
packages the device chose to give an update owner is not established here. `isOrphaned`'s meaning stays
unestablished: 59 of 123 Play-installed packages carry it while the Play Store is installed,
as 40 of 62 did on the Pixel 3, and the record's note quotes both devices. One package
has code under `/data` and no installer (`com.google.android.trichromelibrary_584519532`, a
shared library the system stages there); the parser files it under `no_installer_recorded`,
which is the signal and not a proof, as the note on the record says. Test:
`the_pixel_7a_android_14_packages_xml_reports_the_install_initiator_and_update_owner_the_device_wrote`
in `seance_plugin_installed_apps/tests/corpus.rs`, gated on `SEANCE_ANDROID14_PACKAGES_XML`.

**Signal, reported not silently absent.** Signal for Android keeps its stores
SQLCipher-encrypted under a keystore key this build cannot obtain. All seven — `signal.db`,
`signal_v4.db`, `signal-key-value.db`, `signal-megaphone.db`, `signal-jobmanager.db`,
`signal-logs.db`, `signal-local-metrics.db` — are recorded as `SignalIncomplete` /
`StoreNotSqlite` with `sqlcipher_consistent: true`.

**Other parsed messaging.** WhatsApp 230 messages, Telegram 34, Android SMS/MMS 1,099, call
log 2,662, email 259, Snapchat contacts 349, contacts 30 — parsed from their unencrypted
stores.

**A gap.** Séance has no device-facts surface for a mobile
image: `GET /cases/{id}/system_info` compiles Windows registry hives and returns empty for
Android, so the Pixel 7a's model, serial (`1B031JEG500741`), phone number (`919-928-2177`),
build (`UQ1A.240105.004`) and Google account (`ldehner505@gmail.com`) are only reachable by
searching raw files. The build, phone number and account are present in the evidence and
indexed; there is no panel that presents them.

### SRCKIND-1 — the mobile source-type label on real case databases, 2026-09-27

**What was checked.** That `GET /cases/{id}/source_kinds` (ROADMAP §1.4) says
`none_recognised` only where it may, on real ingested cases, and what it costs.

**Evidence.** Copies of the two kept sweep databases (the originals are not
opened; the copy is migrated on open): `seance-sweep/findings-sweep-linux2022-keep/seance.sqlite`
(Magnet 2022 Linux, one root, one `completed` ingest run, 1.75M artifacts) and
`seance-sweep/findings-sweep-lonewolf/seance.sqlite` (Lone Wolf, one root whose only run is
still `running` — the sweep was stopped before it closed).

**Run.** `SEANCE_SOURCE_KINDS_DB=<copy> cargo test -p seance_api --test source_kinds_test
print_the_label -- --ignored --nocapture`.

| Case | Label | Why | Time |
|---|---|---|---|
| linux2022 (`LenovoFinal.E01`) | `none_recognised` | walk `completed`, records present, no marker of any type, nothing capped | 24 ms |
| lonewolf (`LoneWolf.E01`) | `not_assessed` | walk `running`: "markers not yet reached are not ruled out" | 5 ms |

A marker record whose parent walk cannot reach a root stops every source being
`none_recognised`. With that bar in place both labels are unchanged, `unattributed: 0` and
`unattributed_candidates: 0` on both, in 9 ms and 13 ms. The bar has fired on no real
database; it is pinned on fixtures only.

**Cost.** The label reads the `processing_state` the orchestrator stamps on the root and
consults the run table only for a root without the stamp (still running, or ingested before
runs were recorded). Taking each root's walk state from the ingest-run listing instead counts
every closed run's subtree at read time and costs about 10–13 s on the 1.75M-artifact case.

**What this run does not grade.** No kept database holds an Android or iOS case, so every
**positive** label is pinned on records shaped from the plugins' emission sites
(`seance_api::source_kind` unit tests, `seance_api/tests/source_kinds_test.rs`), not
graded on an ingested phone; re-ingesting `android2022` or `ios2022ffs` would grade it.
`IosArtifactParseStatus` — the unread-store rescue — fired in no case the plan measured, so
it is fixture-only. The `ios_device` markers' path rule (`var/containers/Shared/SystemGroup/`
for PowerLog, `var/mobile/` for routined) was read off the iPhone 8 FFS zip listing; that a
Mac keeps PowerLog under `/private/var/db/powerlog` was read off the macOS 2021 tree's
template, and where a Mac keeps routined's cache was not measured here. `IosBackupFile` /
`IosBackupFileLegacy` are **not** markers (one record per file in a backup, thousands per
backup); an iOS backup is recognised by its `IosBackupInfo` records only.

**`android_backup`, graded on a real payload.** `seance_plugin_android_backup` closes a
whole walk with one `AndroidBackupSummary`. Graded on the Magnet 2019 Android CTF's
`adb-data.tar` (75,673,600 bytes, SHA-256 `c3ecaef3…8883d1`) — a real `adb backup` payload
published without its header — behind the documented five-line header restored by the test
(version 5, uncompressed, no encryption; the wrapper is synthetic, the payload real):
258 file entries and 62 `apps/<package>` directories, as Python's `tarfile` counts them;
no entry is over the per-entry cap or short, so the summary is `status: Extracted` with
`entries_content_incomplete: 0` (a walk with such an entry is `WalkedToEnd` instead — pinned
only on a synthetic fixture, `a_whole_walk_with_an_entry_over_the_size_cap_is_walked_to_its_end_not_unpacked_whole`).
Test: `the_magnet_2019_backup_payload_unpacks_whole_and_says_so`
(`seance_plugin_android_backup/tests/real_backup.rs`, gated on `SEANCE_MAGNET2019_ADB_TAR`).

### LEAK-1 — NIST CFReDS Data Leakage Case, 2026-09-11

**Image.** `cfreds_2015_data_leakage_pc.E01`–`.E04` (7.8 GB, Windows 7 Ultimate SP1, 20 GB NTFS)
plus the three removable-media images, from `https://cfreds-archive.nist.gov/data_leakage_case/`;
every file's SHA-1 matched `hash_values.html`. Ingested whole, including the two volume-shadow
snapshots the VSS enumerator exposes: 2,851,222 artifacts in 59 minutes.

**Ground truth.** NIST's `leakage-answers.pdf` (v1.32), 60 numbered questions with worked
answers.

**Graded so far**, against that key, from the product's own screens and records:

| Q | Subject | Result |
|---|---|---|
| 3 | OS, version, build, owner, install date | exact, to the second |
| 4 | Timezone | Eastern |
| 5 | Computer name | `INFORMANT-PC` |
| 6 | Accounts | all four (SAM), kept apart from profiles |
| 7 | Last logon | `informant` |
| 8 | Last shutdown | in the case |
| 13–14 | Browsers and their paths | Chrome (History, cache, downloads) and IE 11 (WebCacheV01, TypedURLs) |
| 16 | Search keywords | Chrome and Bing, to the second |
| 22 | USB devices | both serials, from `Enum\USBSTOR`. Connection timestamps are graded in `LEAK-2` |
| 23 | Renames on the Desktop | USN 56306184 / 56307712, to the second, with `parent_reference` 71147-6 |
| 29, 31 | Google Drive traces and account | all paths, deleted copies flagged; the account found by search in `sync_log.log` |
| 38 | Thumbcache | 840 entries |
| 10 | Installed applications | not answerable in this run: no Windows Uninstall record. See `LEAK-2` |
| 21 | Mail messages | not answerable in this run: Outlook 2013 OST, format 36. Graded at the parser, not through a pipeline run: see "Question 21 at the parser" below |
| 40–41 | Sticky Notes | not answerable in this run: Sticky Notes were not parsed. See `LEAK-2` |

**This table is the run of 2026-09-11.** The rows that run could not answer are graded in
`LEAK-2` below. The rows above are deliberately left saying what was true when the run
happened.

**Question 21 at the parser (2026-09-26).** The version-36 reader (`seance_plugin_email::ost4k`) was graded against the key's question 21 on the real store, not through a case
run over the E01: the OST was extracted with the Sleuth Kit (`icat -o 206848 … 46112`, MFT entry
46112, `$DATA` 16,818,176 bytes with an initialised size of 3,360,768) and handed to `parse_pst`,
both as the initialised prefix and as the whole file with its zero tail. The prefix is the
tracked fixture `seance_plugin_email/tests/fixtures/ost_v36/` (provenance and SHA-1/SHA-256 in
its README), and `tests/ost4k_real_test.rs` pins the result. Of the twelve messages the key lists,
**eleven are found**, each in the folder the key names (Inbox 5, Sent Items 2, Deleted Items 4),
with its subject and submit time to the second — the key's local times are UTC−4, the
store's UTC — and its sender: the key's SMTP address on the six from the other party, and on
the informant's own five by display name ("iaman") and X.500 DN only, which the test asserts
as such (the store holds no SMTP address for them). The bodies the test checks are recovered as the store holds them: "Hello, Iaman" from its
HTML body (it holds no plain body), "RE: Watch out!" from its plain body (it holds no HTML body);
`body_source` says which on every record. The three Sync Issues logs hold only a compressed-RTF
body, which is not decoded: they publish `body_source: rtf_not_decoded` and `content_incomplete`
(`compressed`), not an empty body. The
twelfth, "It's me" (16:38:47), the key itself marks "Recovered Item from unused area of OST
file": it is in neither B-tree. It is answered at the parser (`tests/ost4k_recover_real_test.rs`): the deleted-mail walk finds its node
entry (NID 0x2015E4, parent Sent Items) in five node B-tree pages no live tree references and its
data block at 0x61000 and subnode block at 0x55400, reads it whole, and publishes it marked
`recovered` from `unallocated` space (graded `partial`: the entry's newest
version, data BID 0x7830, is in no block that could be found, so the message read is an earlier
state and the record says so), sent 2015-03-23 20:38:47 UTC — the key's 16:38:47 local. None
of the eleven live keyed messages is reported again. The same walk recovers three deleted messages
the key does not list ("RE: Good job, buddy.", partial; "RE: Last request" at 13:30:10 UTC; "Watch
out!"), which are not graded, and names one deleted entry whose data is gone.
Three further messages are Outlook's own synchronisation logs in Sync Issues, which the key does
not list. Two gaps against the key's columns: the informant's own sent mail carries only his
display name and an Exchange X.500 address (no SMTP property), so `from` for those is the X.500
DN, and `to` is the display string ("spy", "iaman") because the recipient table is not read.
Every page (9) and block (381, 123 compressed) the store references verified; no fault.

### MEM-CTF-1 — 13Cubed Mini Memory CTF, 2026-09-11

**Image.** `memdump.mem`, 5,368,709,120 bytes, from `mini_memory_ctf.zip` (1,366,877,880 bytes,
`https://cdn.13cubed.com/downloads/mini_memory_ctf.zip`). A raw Windows 10 capture: headerless,
so it carries no magic and had to be declared a memory image at ingest.

**Ground truth.** The published solutions guide (`mini_memory_ctf_solutions_guide.pdf`).

**Symbols.** The kernel is `ntkrnlmp.pdb` GUID `1E158A6041094205BE17F93E54DD5E51` age 1, which
no local pack matched; the discovery record said so and named what it had searched ("143 of 143
candidate file(s) under 2 director(y|ies) were identified"). `seance fetch-symbols --guid
1E158A6041094205BE17F93E54DD5E51 --age 1` fetched the PDB and converted it to a pack of 1,436
types, 230 enums and 33,743 symbols.

| Q | Key | Séance |
|---|---|---|
| 1 | The rogue process is PID **8560** | **Answered.** 159 processes, five `svchost.exe` parented by PID 4824 (`explorer.exe`, not `services.exe`); four of the five have exit times and **8560** alone is `not_recorded`, i.e. still running. The list declares itself incomplete and says exactly where it stopped: a 1,695,744-byte hole at `0x4be62000`. |
| 3 | Default gateway MAC `00-50-56-FE-D8-07` | **Not answerable — capability boundary, reported.** 23 registry hives found, 22 named (the 23rd legitimately has no backing file); there is no arbitrary key-walk from an in-memory hive, so the value itself was never reached. Searches for it returned nothing rather than a guess. |
| 4 | `…\Cache\AHF2COV9\13CUBED[1].HTM` | **Answered** (long names, not the key's 8.3 form): `\Users\CTF\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\#!001\MicrosoftEdge\Cache\AHF2COV9\13cubed[1].htm`, `path_complete: true`, on both copies of MFT record 61988. Coverage across the image: 27,396 complete paths and 14,483 partial, of 43,328 records. |

Q2 (carve the flag out of the dumped process) was not attempted.

Symbol packs converted from a PDB emit primitive pointers as pointer types that can be dereferenced, which is what lets the 23 hives be named.

### DFRWS21-1 — DFRWS 2021 challenge, parts 1 and 2, 2026-09-11

The DFRWS 2021 challenge is open-ended — it asks for multi-source timelining prototypes, not
answers to questions — so these two images are recorded as **coverage** runs, not graded ones.

**Part 1 — ATM skimmer microSD.** `skimmer_microSD_Physical.e01`, 36,663,358 bytes (X-Ways
20.0 SR-3, 2021-04-09, "microSD found in skimmer device at EPFL Postomat"). Read whole: E01 →
FAT32 → the two MP3s an ATM skimmer writes, magstripe audio rather than files:

| File | Size | MD5 |
|---|---|---|
| `2021_04_09T1621.mp3` | 1,301,392 | `066c187f3010f62a56c82298116ec3f8` |
| `recording.mp3` | 4,335,015 | `b52421a7547369a770b892026d1b25d0` |

Both typed `MP3` by signature. Nine artifacts, no defects.

**Part 2 — Raspberry Pi microSD (a 3D printer's card).** `E001_Carta_MicroSD_Stampante_3D.e01`
from `2_Raspberry_Pi_mSD.zip` (1,814,397,882 bytes), ingested to 190,369 artifacts: 137,827 file
entries, 49,492 signature analyses, 1,716 encryption detections, 443 perceptual hashes, 420 EXIF
records, 80 utmp parse statuses, 53 shell-history entries, 12 PE signatures. The two
`FSEventsRecord`s are real — the card had been mounted on a Mac.

**Unified Log.** The Apple Unified Log parser does not claim a Linux card's Raspberry Pi firmware files (`sw_bundle_init.bin`, whose first four bytes spell the integer 4096). A tag-only match must be corroborated by a Catalog or Chunkset chunk. Nothing 3D-printer-specific was examined.

### IOS-1 — Josh Hickman iOS 17 reference image, encrypted iTunes backup, 2026-09-12

**Image.** The encrypted iTunes backup inside Josh Hickman's iOS 17 public reference image
(`iOS_17_Public_Image.tar.gz`, 21 GB): backup directory
`00008030-001259123E50802E`, 2.2 GB, 6,696 files, backup password `MyPassword123` as published
with the image.

**Ground truth.** The backup's own `Info.plist` and `Manifest.plist`, and the image's
documentation.

**Locked, and saying what it is.** Ingested with no password, the backup produces one
`IosBackupInfo` with the standard incompleteness pair (`content_incomplete` /
`inventory_incomplete`, reason `encrypted`) and names the device from the part of the manifest
that needs no password — `This Is's iPhone`, `iPhone12,1`, iOS `17.3`, build `21D50`, serial
`F4GZ987AN72N`, UDID `00008030-001259123E50802E`, all agreeing with `Info.plist`.

**Unlocked from the artifact, with no restart.** `POST
/cases/{id}/artifacts/{id}/run_module` with `secrets: {ios_backup_password: …}` decrypted the
backup in place: job `complete`, **15,972 artifacts**, `manifest_entries: 15971`,
`files_not_recovered: 0`. What came out:

| | |
|---|---|
| SQLite rows | 401,898 |
| Backup files | 9,212 |
| Photo assets / EXIF / perceptual hashes | 567 / 1,752 / 1,639 |
| Installed apps | 230 |
| Calendar events | 144 |
| iMessages (+ attachments) | 105 (+28) |
| WhatsApp messages (+ attachments) | 60 (+4) |
| Call log | 38 |
| Wi-Fi networks | 17 |
| Notes | 13 |

**Unlock behaviour.** The password is supplied in the run's `secrets`, so unlocking needs no server restart, and an ad-hoc run against a *folder*, which is what an iTunes backup is, starts. The device facts above are read from the `Lockdown` dictionary of `Manifest.plist` as well as from `Info.plist`'s spaced top-level keys. The run that decrypts emits its own record naming what it supersedes, because the locked record's sentence "no files from it are in this case" is false once the password works. A superseded record is still counted by the completeness census and the report as evidence not recovered.

**Not covered.** The Hexordia Magnet Virtual Summit 2026 images (macOS 15.4/APFS, iOS 18,
Android 14) are not covered by any run here, so APFS and iOS 18 remain uncovered.



### IOS-KEYCHAIN-1 — the iPhone keychain inside the Hickman iOS 17 encrypted backup, 2026-09-27

**Evidence.** The same backup as `IOS-1`: `iOS_17/Backup/00008030-001259123E50802E.zip` from
`iOS_17_Public_Image.tar.gz` (Digital Corpora; SHA-256 of the member
`ACEA6302F7B447DCDF1E845549917030BB0763A9897A2A3AA930C53754499E0B`, matching the published
hash), password `MyPassword123` as published in the image's creation PDF. Extract it with
`tar --occurrence=1 -xzf iOS_17_Public_Image.tar.gz iOS_17/Backup/00008030-001259123E50802E.zip`
and unzip it; the directory holding `Manifest.plist` is what the test takes.

**Ground truth.** An independent Python reader written before the Rust one (`cryptography`'s
RFC 3394 unwrap and AES-ECB, its own GHASH, `plistlib`), which measured every figure below.
Nothing in the Rust reader was tuned to it.

**What was validated.** That the backup's keychain is `KeychainDomain/keychain-backup.plist`
(file ID `51a4616e576dd33cd2abadfea874eb8ff246bf0e`, file protection class 1) — not a
`keychain-2.db`; that its items open with the backup keybag's class keys; and what can and cannot
be read.

| | |
|---|---|
| Keybag classes | 14, every passcode layer passing RFC 3394 |
| … usable class keys (`WRAP` = 2) | **9**: classes 1, 2, 3, 4, 6, 7, 8, 17, 18 |
| … device-bound (`WRAP` = 3, also wrapped under the device's hardware key) | **5**: classes 5, 9, 10, 11, 19 — the passcode-layer value is not a class key and is not kept |
| Items (`genp` / `inet` / `cert` / `keys`) | 1,111 / 201 / 9 / 47 = **1,368**, all `v_Data` version 3 |
| By keychain class | 7: 432, 11: 363, 10: 320, 6: 151, 8: 70, 9: 32 |
| Read (classes 6/7/8) — every one's GCM tag verifies | **653** |
| `device_bound` (classes 9/10/11) — the item key does not unwrap under the backup's class key | **715** |
| `genp` + `inet` items read / with an account / account valid UTF-8 | 616 / 616 / 614 |
| … of those, carrying a secret (`v_Data`) | 579 |
| Secrets withheld, all tables | 616 |
| `genp` items with service `AirPort` (Wi-Fi passwords) | 10 |

**What this does not grade.** The secrets themselves: they are withheld, so no password value is
compared with anything. The attribute *values* beyond the counts above are not graded against
an answer key (Hickman publishes none for the keychain). The GCM construction (empty IV, so
`J0 = 0`) is established by the 653 tags verifying, not by a published specification.

**Test.** `hickman_ios17_keychain_known_answer` in
`seance_plugin_ios_backup/tests/hickman_ios17_keychain.rs`, gated on `SEANCE_IOS17_BACKUP` (the
extracted directory); without it the test says it could not look. It asserts the keybag class
states (9 usable, 5 device-bound) both on the `ios_backup_decrypted` record's `keybag_classes`
and through `unlock_backup(…).class_key_states()` . It
also re-runs with a wrong password and asserts no keychain record exists. Debug build: about
five minutes, most of it the 10,000,000-round PBKDF2 three times; `--release` about 8 s.

**Re-run.** `SEANCE_IOS17_BACKUP=<dir>/00008030-001259123E50802E cargo test -p
seance_plugin_ios_backup --test hickman_ios17_keychain`.

### NET-2 — Nitroba University harassment capture, 2026-09-12

**Image.** `nitroba.pcap`, 56,180,821 bytes, from Digital Corpora's 2008 Nitroba scenario: four
hours of a university dorm's traffic, in which a teacher is being harassed through an anonymous
mailer.

**Ground truth.** The scenario's published solution, and the widely reproduced answer that the
harassing mail was sent from the internal host **192.168.15.4**.

| Q | Key | Séance |
|---|---|---|
| Which host used the anonymous mailer? | 192.168.15.4 | **Answered.** The DNS record for `www.sendanonymousemail.net` carries `client_ip: 192.168.15.4`, and the pivot on that address returns 4,369 records touching it, grouped by kind. |
| What else was that host doing? | Facebook, webmail | **Answered.** The same pivot lists the Facebook photo hosts it resolved, minute by minute. |
| Who is the person? | Identified from session content | **Answered at stage 2.** See NET-3 below: the harassing message itself, its recipient and the account using the machine are now records. |

94,410 packets became 2,864 flows, 2,905 DNS resolutions and one capture record.

### NET-3 — the same capture, read for its contents, 2026-09-15

**Image.** `nitroba.pcap` again, unchanged: 56,180,821 bytes, 94,410 packets.

**Relation to NET-2.** NET-2 recorded "who is the person?" as outside the tool's
boundary. §4.3 stage 2 (TCP reassembly, HTTP, TLS, ARP) removes that boundary, and it
is recorded as a second dated run against the same evidence.

**How it was run.** `target/debug/examples/capture_probe ~/ctf-evidence/nitroba/nitroba.pcap`
under `/usr/bin/time -v`. A debug build: 1.5 s of wall clock and a peak resident set of 405 MB
for a 56 MB capture, which is what holding 46 MB of reassembled stream bytes plus 4,428 body
artifacts costs. The 256 MiB reassembly budget and the 256 MiB body budget are what bound it.

| Q | Key | Séance |
|---|---|---|
| Which host used the anonymous mailer? | 192.168.15.4 | **Answered**, as at stage 1, and now also by the ARP binding `192.168.15.4 ↔ 00:17:f2:e2:c0:ce` — which names the *machine*, not just the address. |
| What did the harassing message say? | Sent through willselfdestruct.com | **Answered.** An `HttpTransaction` record for `POST http://www.willselfdestruct.com/secure/submit` → 302, whose decoded form fields are `to: lilytuckrige@yahoo.com`, `subject: "you can't find us"`, `message: "and you can't hide from us.\r\n\r\nStop teaching.\r\n\r\nStart running. "`, `ttl: 30`. A second message to the same recipient, sent through a different mailer, carries `security_code: xkpmkb` and `sender: the_whole_world_is_watching@nitroba.org`. |
| Who was using the machine? | jcoachj@gmail.com | **Answered.** `POST http://www.google.com/calendar/load` carries `lef: amNvYWNoakBnbWFpbC5jb20`, which is base64 for `jcoachj@gmail.com`; a Gmail chat POST carries `mylady.ixchel@gmail.com`. Both are form fields on transaction records, so both are in the search index and on the Entities surface. |

**Measured, and independently cross-checked.** Every figure below was produced by the probe and
then re-derived from the capture by a separate decoder written for the purpose (a Python walk of
the pcap records), so no number here is the tool agreeing with itself:

| Figure | Séance | Independent decode |
|---|---|---|
| ARP frames | 4,026 | 4,026 |
| ARP requests / replies | 3,972 / 54 | 3,972 / 54 |
| Probes from `0.0.0.0` (claiming nothing) | 51 | 51 |
| Addresses claimed | 13 | 13 distinct sender addresses (14 distinct address-and-hardware pairs, which is why one binding record carries two claims) |
| Contested addresses | 1 — `192.168.1.64`, claimed by `00:1d:d9:2e:4f:61` and `00:1f:f3:5a:77:9b`, overlapping 03:09:07 to 03:22:31 | 1, same two |
| Hardware addresses seen claiming | 10 | 10 |

And the figures the probe alone reports: 3,963 TCP streams (42 with a gap, 19 with no handshake
in the capture, none with a conflicting retransmission), 46,440,025 bytes reassembled; 1,805 HTTP
conversations holding 4,496 transactions across 304 distinct hosts, 20 of them incomplete, 245
paired over a gap, 14 paired over a conversation whose start the capture does not hold, and 4,428
bodies handed on as artifacts; 133 TLS sessions over 18 distinct server names (`image.pegs.com`
on 58 of them), 92 certificates read from cleartext chains — including
`CN=*.google-analytics.com` and `CN=mail.google.com`, both issued by Thawte — and 14 of those
self-signed, which are the roots each chain shipped.

**The honesty fields.** They are not decoration: 14 transactions in a real capture are paired
over a conversation whose start is missing, and they are marked so rather than claiming `in_order`
as a fact.

### MEM-STRINGS-1 — `strings` over memory on the Windows 11 corpus capture, 2026-09-16

**Image.** `test_data/win11_bitlocker/memory-unlocked.raw` — 10,737,418,240 bytes of guest RAM
from `FORENSIC-W11` while its BitLocker volume was unlocked. 130 live processes.

**What was validated.** The `strings_map` stage: an examiner's own physical offsets attributed
to the address spaces whose page tables reach them. `ROADMAP` §5.3 set the criterion — *a
physical offset inside a page mapped by two processes must name both* — and this is that
criterion on real evidence.

**How ground truth was fixed, and why it is not the tool agreeing with itself.** The answer is
fixed by the Windows ABI, not by this code: `KUSER_SHARED_DATA` is one physical frame mapped
into every live user process at the fixed virtual address `0x7FFE0000`. The *upward* walker —
`PageWalk::translate`, tested on its own against hand-built hierarchies and used by every other
memory stage — is asked for that address in each process's own space and answers with the same
physical frame every time. Only then is the reverse mapping asked about an offset inside it.

**How it was run.** `cargo test --release -p seance_plugin_memory_windows --test
win11_corpus_analysis a_physical_offset_two_processes_map_names_both_of_them`.

| Figure | Result |
|---|---|
| The frame | physical `0x285000`, confirmed identical from 8 processes by the upward walk |
| Offset asked about | `0x285040`, written as `strings -t d` writes it |
| Address spaces naming it | **125**, each at virtual `0x7ffe0040` — the ABI's address |
| Verdict | *mapped, and coverage was short* |
| Tables read | 43,006 (176 MiB) |
| Prototype-PTE hops | 328,132, of which 168,438 did not resolve |
| Subtrees declined as the kernel's own | 5,938 |
| Address spaces reporting short coverage | 129 of 131 |
| Wall clock | 0.9 s |

**The qualified verdict is the finding, not a shortfall in the run.** Every address space on a
live Windows machine has suppressed uniform page tables and trimmed shared pages in it, so
coverage is never complete and this build does not report a frame as unmapped. That is the
opposite of what the alternative implementation does.

**Compared against Volatility 3 2.28.2, measured on the same image on 2026-09-15.** Its
`windows.strings` returns `FREE MEMORY` for every offset taken from a page `lsass.exe`,
`explorer.exe` or `winlogon.exe` really maps, and returns 123 of the 130 live processes for
physical `0x7ffe0000` — because its per-process branch keys its reverse map by the **virtual**
page number, and `0x7ffe0` is `KUSER_SHARED_DATA`'s virtual page in each of them. 6,126 of one
process's 330,040 keys are low enough to collide with a real physical page. Only its kernel
column is correct. That run took 10 m 40 s. Full transcript in
`seance_memory/tests/KNOWN_ANSWERS.md`.

### NTFS-FREE-1 — the free-space regions of a real NTFS volume, 2026-09-16

**Image.** `alihadi_ntfs/NTFS-HiddenFiles.E01` — Ali Hadi's NTFS challenge image, 473,520 bytes
compressed, 101,711,872 decoded. A third party's FTK acquisition, and a **logical** one: source
type "Logical" in the log beside it, so the NTFS volume starts at byte 0 and there is no
partition table.

**Why this image.** It is the case §5.4 exists for. With no partition table there are no
inter-partition gaps, and inter-partition gaps would be the only `UnallocatedSpace` regions, so
the free clusters inside the volume are published as regions.

**How ground truth is fixed.** By structure rather than by a published answer, and independently
of the code that produced the regions: every region must lie inside the volume, regions must not
overlap, they must be in address order, each one's offset must equal its own first cluster's
address, and **cluster 0 must never be in one**. That last is the check that matters: cluster 0
holds the boot sector, NTFS marks it allocated, and a free region covering it would mean the bit
convention had been read inverted — an error that would otherwise produce entirely ordinary
looking output.

| Figure | Result |
|---|---|
| Volume | 24,831 clusters of 4,096 bytes = 101,707,776 bytes |
| Free runs the bitmap proved | 2 |
| Bytes those regions cover | 93,405,184 (91.8% of the volume) |
| Runs dropped at a ceiling | 0 |
| Clusters the bitmap could not speak for | 0 |
| The largest region, handed to the carver | 67,543,040 bytes scanned, 0 files carved |

**The last row is the point.** 67.5 MB were read and held no file. The carver emits a summary
carrying `scanned_bytes`, so the case distinguishes free space that was carved and was empty from
free space nobody carved.

**Test.** `the_free_clusters_of_a_real_ntfs_volume_become_carvable_regions` in
`seance_tests/src/alihadi_ntfs_tests.rs`, gated on `SEANCE_ALIHADI_NTFS` and the `e01` feature.

**And the FAT half, on NIST's own image.** DFTT #9 (`9-fat-label.dd`, a FAT16 volume from the
Digital Forensics Tool Testing set): 19,968 clusters of 512 bytes and one free region of
10,111,488 bytes, nothing dropped. The structural assertion that matters here is a different one
from NTFS's: **no region below cluster 2**, because 0 and 1 are the FAT's own reserved entries
and are not data clusters at all — a region over them would mean FAT had been read with NTFS's
base cluster, which is the specific way this route could be wrong and look ordinary. Test
`dftt9_free_clusters_become_carvable_regions` in `seance_tests/src/dftt_corpus_tests.rs`.

**And the ext4 half, on a real 67 GB volume.** The ext4 partition of the Magnet 2022 Linux CTF
image (`LenovoFinal.E01`, gated on `SEANCE_LINUX_CTF`): 16,384,000 blocks of 4,096 bytes.
ext4's conventions differ from both FAT-family filesystems and are what this grades — blocks
numbered from the volume's start, and one bitmap per block group, so the free runs are stitched
across groups — and the assertion that would catch a base error is that **block 0 is never in a
region**, since it is below `first_data_block` and the reader counts the boot area as in use.

This is also the run that measured what the region ceiling costs on real evidence:

| Figure | Result |
|---|---|
| Free runs the bitmaps proved | 1,360,455 |
| Regions emitted (the ceiling) | 4,096, covering 23,899,443,200 bytes |
| Runs declined | 1,356,359, covering 14,379,802,624 bytes |
| Blocks behind a short group bitmap | 0 |

Largest-first selection keeps 62% of the free bytes in 0.3% of the runs, and the record names
the ceiling, the runs it declined and the bytes they covered. **37.6% of that volume's free
space is not carved.** It is a limitation of the design, not a false absence, because the
record says so. The ceiling is configurable, the default stays at 4,096, and sparse regions
are declined. The measurement below is the evidence for that. Test
`a_real_ext4_volume_publishes_its_free_blocks_as_regions` in
`seance_tests/src/ext4_full_chain_test.rs`.

**Is 37.6% typical? Measured on thirteen held volumes, 2026-09-26.** Both ceilings are
configurable (`SEANCE_FREE_REGION_CAP`, `SEANCE_FREE_BYTE_CAP`; defaults 4,096
regions and 128 GiB), and the record publishes the ceiling actually applied
(`free_region_cap`, `free_byte_cap`) with `free_region_cap_source` / `free_byte_cap_source`
saying `default` or `configured`. The default stays at 4,096 and sparse regions (one artifact
spanning many non-adjacent free runs) are not built, because a carve
across a run boundary would assemble bytes that were never next to each other. These are the
thirteen volumes measured, each at the default ceiling:

| Volume | Cluster | Free runs | Emitted | Bytes emitted | Declined | Bytes declined | Share declined |
|---|---|---|---|---|---|---|---|
| Ali Hadi `NTFS-HiddenFiles` (NTFS, logical image) | 4,096 | 2 | 2 | 93,405,184 | 0 | 0 | 0% |
| CFReDS Hacking Case, XP system volume (NTFS) | 512 | 1,706 | 1,706 | 3,080,631,808 | 0 | 0 | 0% |
| CFReDS Data Leakage PC, System Reserved (NTFS) | 4,096 | 6 | 6 | 79,552,512 | 0 | 0 | 0% |
| CFReDS Data Leakage PC, Windows 7 system volume (NTFS) | 4,096 | 868 | 868 | 3,548,745,728 | 0 | 0 | 0% |
| CFReDS Data Leakage RM#1 (exFAT) | 32,768 | 1 | 1 | 3,929,145,344 | 0 | 0 | 0% |
| CFReDS Data Leakage RM#2 (FAT32) | 4,096 | 1 | 1 | 1,069,543,424 | 0 | 0 | 0% |
| Magnet 2022 Linux CTF, EFI (FAT32) | 4,096 | 1 | 1 | 530,329,600 | 0 | 0 | 0% |
| Magnet 2022 Linux CTF, root (ext4) | 4,096 | 1,360,455 | 4,096 | 23,899,443,200 | 1,356,359 | 14,379,802,624 | **37.6%** |
| `linux-lab` jammy VM, root (ext4) | 4,096 | 72 | 72 | 397,967,360 | 0 | 0 | 0% |
| `linux-lab` jammy VM, EFI (FAT32) | 512 | 1 | 1 | 103,053,312 | 0 | 0 | 0% |
| `noble-lab` VM, ext4 at 1,074,790,400 | 4,096 | 101 | 101 | 833,114,112 | 0 | 0 | 0% |
| `noble-lab` VM, ext4 at 116,391,936 | 4,096 | 19 | 19 | 857,759,744 | 0 | 0 | 0% |
| `noble-lab` VM, EFI (FAT32) | 512 | 1 | 1 | 102,995,968 | 0 | 0 | 0% |

**What this does and does not show.** Twelve of thirteen volumes are far under the ceiling; the
largest real Windows volume held (the Data Leakage PC's Windows 7 install) has 868 free runs. The
Lenovo ext4 volume is the only one the ceiling bites on, and it is an outlier by three orders of
magnitude in run count. That is a sample of the volumes this machine holds, not of the
population of volumes an examiner meets: the Windows images are 2004 and 2015 installs of a few
GB to tens of GB, and both VM disks are lightly used cloud images. A long-lived, heavily
churned volume like the Lenovo one is exactly the case where a lab would raise the ceiling, and
the declined bytes are stated on its record either way. The VM disks were read from raw
conversions (`qemu-img convert -O raw`, confirmed identical with `qemu-img compare`), because
their qcow2 clusters are zlib-compressed and the qcow2 reader refuses compressed clusters; given
the qcow2 files, the test says it could not look.

**Held here and not in the table.** The thirteen are not every volume this machine holds. Not
measured for this question: the five FAT and exFAT reference images in
`reference/dfir_ntfs/test_data/` (the exFAT one is graded separately below, for correctness and
not for the ceiling's cost), the Belkasoft CTF 6 image (`~/forensic_corpora/belkasoft_ctf6`,
held zipped), and the `test_data/win11_bitlocker` disk. Nothing is claimed about their run
counts. So "twelve of thirteen decline nothing" is a statement about the thirteen measured.

**The configured ceiling, end to end on real data.** On every volume with at least two runs and
none declined, the same test re-parses with `SEANCE_FREE_REGION_CAP` set one below the run count
and asserts exactly one run is declined, `free_region_cap_source` is `configured`, and the
sentence names the variable. On a volume with runs declined and no more than 250,000 runs it
re-parses at a ceiling equal to the run count and asserts nothing is declined; the Lenovo volume
is past that bound (1.36 million artifacts held at once is the cost a lab accepts by raising the
ceiling, not one this test imposes on a shared machine), so the "whole volume" case is pinned on
real data only by the lower-cap direction and on synthetic data by
`a_ceiling_above_the_run_count_drops_nothing_and_says_complete` in
`seance_core/src/free_space.rs`. Test `the_region_ceiling_cost_on_every_held_volume` in
`seance_tests/tests/free_space_distribution.rs`, one `#[test]` in its own binary because the
ceiling is read from the environment; run it with the variables in `documentation/TESTING.md`
(5 min 17 s and 3.1 GB peak with all of them set).

**And the exFAT half, on a third party's image.** `exfat_lin_part.raw.gz` from the `dfir_ntfs`
reference corpus (`reference/dfir_ntfs/test_data/`), whose exFAT volume sits at offset
`0x100000`: 16,096 clusters of 4,096 bytes and one free region of 65,855,488 bytes, nothing
dropped and no cluster unassessed. exFAT's convention is the third distinct one this route has
to get right — the allocation bitmap's **first bit is cluster 2**, at `cluster_to_offset(2)`,
not cluster 0 — so the assertion that would catch a base error is that no region begins below
the first data cluster. A cluster the FAT marks bad is separately asserted never to be reported
as free. Test `the_free_clusters_of_a_real_exfat_volume_become_carvable_regions` in
`seance_plugin_fat/src/tests.rs`.

Five exFAT volumes are held in `reference/dfir_ntfs/test_data/`. `load_test_image` searches
that directory as well as `../test_data`. A test that skips and a test that passes look
identical in the output.

### MACOS-LOGIN-1 — the macOS login history, from `utmpx` and nine audit trails, 2026-09-16

**Evidence.** The Magnet 2021 macOS image, mounted as a logical tree
(`ctf-evidence/macos2021/tree/`, 81 GB): `/private/var/run/utmpx` (2,512 bytes) and the nine
OpenBSM audit trails in `/private/var/audit/` (838 KB, 4,327 records).

**What was validated.** That "who was on this machine, from where, and when" is answered on a
macOS image.

**How ground truth is fixed, and why it is not the tool agreeing with itself.** Three
independent fixings, none of which is this code:

1. **The file's own arithmetic.** `utmpx` is 2,512 bytes, exactly four 628-byte records, and
   `308 + 256 + 64 = 628` accounts for every byte of one. There is no slack for a different
   tail. The first record is a `SIGNATURE` carrying the literal `utmpx-1.00` — the format naming
   its own version, which is the only content-borne corroboration of a chosen layout anywhere in
   this artefact family.
2. **The format stating each record's length twice.** Every BSM record's header declares its
   byte count and its trailer repeats it behind the magic `0xB105`. The token walk must land
   exactly on that trailer. Across all 4,327 records **it does, every time**, with no unknown
   token and no length that overruns — 4,327 independent confirmations of the token-length
   table, and a check that a mistake in any single length could not have survived, because it
   would have shifted everything after it.
3. **The two artefacts corroborating each other.** `utmpx` puts the boot at 1617653088. The
   first record of the `.not_terminated` trail is timed 1617653090. Neither reader was
   consulted for the other.

**The answers.**

| Question | Answer | From |
|---|---|---|
| Who was logged in when the image was taken? | `eliflatt` on `console` at 20:07:07 and on `ttys000` at 20:08:26, both still open | `utmpx` |
| When did the machine boot? | 20:04:48, `ut_pid` 1 | `utmpx` |
| Who logged in over SSH, and from where? | `uid 501`, eighteen accepted logins from `184.171.155.71`, `184.171.149.230` and `184.171.149.138` | audit trail |
| Was anyone refused? | **Two SSH password attempts from `184.171.155.71` on 2021-03-25**, and 107 of 182 password verifications | audit trail |
| Which binary asked? | `com.apple.sshd`, cdhash `b8ebfa4de56fcade816623770d451cac9d2ce0e5` | audit trail |
| Console logins and logouts | ten `AUE_lw_login`, ten `AUE_logout`, six power-offs | audit trail |
| Records that did not account for their own bytes | 0 of 4,327 | audit trail |
| Event identifiers the reader could not name | 0 of 21 distinct | audit trail |

**The measurement behind the design.** 496 records in these trails report a failure. Only
**109** of them are somebody offering a password or a key; the other 387 are Security Server
*authorization* decisions (`AUE_ssauthorize`, `AUE_ssauthmech`) and one refused account
modification. Both sets are in the `aa` audit class, so a `FailedLogin` line drawn on the class
would have put 387 rows on the screen an examiner reads to answer "was there a brute force" —
on a machine nobody attacked — and buried the two that were real. The line is drawn on a
per-event *credential-attempt* flag instead, and the 388 other refusals are counted under their
own name with a note saying what they are.

**Tests.** `the_real_macos_utmpx_reads_as_the_session_it_recorded` in
`seance_plugin_utmp/src/tests.rs` and `the_real_macos_audit_trails_read_as_the_logins_they_recorded`
in `seance_plugin_macos_artifacts/src/openbsm.rs`. Both skip with a printed notice when the
corpus is absent, which is why the counts above are pinned in the assertions rather than left to
a reader's inspection.

**What this does not grade.** No macOS clock-change or shutdown audit record is in these trails,
so the `OLD_TIME`/`NEW_TIME` swap between the two `ut_type` enumerations is pinned from Apple's
header rather than observed; and the Apple System Log, which carries the same history a second
time, is not read at all (`ROADMAP` §1.6).

### MACOS-KEYCHAIN-2 — the data-protection keychain, and the last answer on the macOS key, 2026-09-16

**Evidence.**
`ctf-evidence/macos2021/tree/Users/eliflatt/Library/Keychains/622523FF-A9E8-5BFC-9142-B14980A33465/keychain-2.db`
— 4,677,632 bytes, schema version 11.9, with a 2.3 MB write-ahead log beside it.

**What was validated.** Two things: that the one question on the Magnet Virtual Summit 2021
macOS key this product could not answer now answers, and — at least as important — that this
database's *limits* are stated rather than papered over.

**The answer.** Question 14 asks for the encryption key for Eli's iCloud. It is the Mac's own
Octagon peer identifier, in the `ckdevicestate` table:

| Field | Value |
|---|---|
| `os_version` | `macOS 20.3.0 (20D74)` |
| `octagon_peer_id` | **`SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=`** |
| Key's answer | `fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=` |

That takes `MAC-1` to **14 of 14**.

**Which keychain.** The question is about the Mac's own `keychain-2.db`, not the backed-up phone's: the published write-up names the path.
The distinction matters because the backup in this image **is
encrypted** (`Manifest.plist`: `IsEncrypted: true`), so a reader that had gone looking there
would have found nothing and reported the question unanswerable for the wrong reason.

**What else the file gives, measured.** 306 items across four tables — 128 generic passwords,
158 internet passwords, 2 certificates and 18 keys — and 36 `ckdevicestate` rows naming **three
devices**: `macOS 20.3.0 (20D74)`, `iphone 20.3.0 (18D52)` and `watch 19.6.0 (17U63)`. Two of
those are not in the image at all, so this is an inventory of what the Apple ID trusted, read
off one machine. Of the 36 zone rows, **29 read `kSOSCCInCircle` and 7 read `kSOSCCError`** —
the circle status is per zone, not per device, and seven of this account's keychain zones were
not syncing.

**What it cannot say, and why that is the point.** **Not one of the 306 items names an account
or a service.** Every `acct`, `svce`, `srvr`, `path`, `atyp` and `sdmn` value in this database is
exactly twenty bytes of non-text — a SHA-1 of the attribute — 128 of 128 and 158 of 158, with no
exceptions, and even the `cert` table's subject, issuer and serial are hashed. So the reader
emits those under names ending `_sha1` and reports no account and no service, because a hash
rendered in an `account` column is a username an examiner would quote. What it *does* name is
the **access group** — fourteen distinct ones, including `com.apple.cloudd`,
`com.apple.security.sos`, `com.apple.continuity.unlock` and `InternetAccounts` — the protection
class, and the sync view.

Every secret is locked and, unlike the classic `kych` keychain, **no password would open it**:
the payloads are wrapped under class keys from the device keybag, which is protected by hardware
an image does not carry. That is stated on every record rather than left to be discovered, and
the items in a `…ThisDeviceOnly` class carry a note saying what the class means. `aku`/`cku`/`dku`
items (classes 9, 10 and 11) are written to an encrypted backup wrapped under the device's UID and can be
restored only to the same device; the Hickman iOS 17 backup holds 715 of them. `akpu`
(`WhenPasscodeSetThisDeviceOnly`) exists only in the system keybag, is not backed up, and is rendered
useless if the passcode is removed. The classes follow Apple Platform Security, "Keychain data class
protections". An iOS backup does not carry a `keychain-2.db`; it carries
`KeychainDomain/keychain-backup.plist`. The note field is `this_device_only_note`, and
`a_this_device_only_class_is_decoded_and_says_why_it_matters` pins both wordings on a synthetic
fixture. No real `akpu` item has been examined.

**Test.** `the_real_data_protection_keychain_answers_the_question_utmpx_and_the_classic_one_cannot`
in `seance_plugin_macos_artifacts/src/keychain2.rs`, which pins every figure above, including
the 29/7 circle split and the assertion that not one item names an account.

**What this does not grade.** Decryption, which is impossible from an image here rather than
merely unimplemented. The classic keychain's decryption is graded in `KEYCHAIN-1` to
`KEYCHAIN-3`, and the iOS keychain in `IOS-KEYCHAIN-1`.

### MACOS-ASL-1 — the login history macOS keeps no `wtmpx` for, 2026-09-16

**Evidence.** The eleven Apple System Log stores in
`ctf-evidence/macos2021/tree/private/var/log/asl/` (2.4 MB; eight daily stores from
2021-03-30 to 2021-04-06 and three `BB.*` expiring stores).

**What was validated.** That the login and logout **history** of a macOS machine is recoverable.
`/var/run/utmpx` holds only the sessions open at acquisition, there is no `btmp`, and since 10.5
there is no on-disk `wtmpx` — `utmpx(5)` itself says those files "can be replaced with log
entries" in this store. So this is the run that decides whether "who logged in last Tuesday" is
answerable on macOS at all.

**How ground truth is fixed, and why it is not the tool agreeing with itself.** Four structural
checks, all of which hold across every record in every store, plus three content corroborations:

1. **The records tile exactly.** From offset 80 to the last byte of all eleven files, with no
   unknown record type and no remainder.
2. **The header's own pointer.** Each store's `first` field equals the offset of the first
   message record found — in every file.
3. **Each record's own two statements of its length.** A message's byte count is exactly
   `116 + 8 × the key/value slot count it declares`, in **every one of 7,022**. That single
   equation is what fixes the fixed part at 60 bytes, the six reference slots at 48 and the
   trailing `prev` pointer at 8; a mistake in any of the three would break it.
4. **The chain, in both directions.** Messages are a doubly linked list through their first and
   last eight bytes, and `next`/`prev` agree with file order for all 7,022 with no break — a
   second, independent statement of the record order.
5. The first record's `time` equals the header's; its `pid` 1191 matches the `objc[1191]` inside
   its own message text; and its `uid` 501 and `gid` 20 are the account's.

**The answers.**

| Question | Answer |
|---|---|
| Records read | 7,022 messages and 5,774 strings |
| Login-history records | **32** — 19 under `com.apple.system.utmpx`, 13 under `com.apple.system.lastlog` |
| Boots / clean shutdowns | 6 / 4 |
| Whose sessions? | Every one `eliflatt`, on `console`, `ttys000` and `ttys001` |
| Sessions from a remote address | **3**, from `184.171.155.71` and `184.171.149.230` |
| Duration of the longest remote session | Over 30,000 seconds, stated rather than bounded, because both ends are in the store |
| Stores that failed to tile | 0 |
| Chain breaks | 0 |

**What this run corroborates in the `utmpx` reader.** Two things the `utmpx` reader had taken
from Apple's `<utmpx.h>` with no evidence behind them:

* **`ut_type` 11 is `SHUTDOWN_TIME`.** The store writes
  `SHUTDOWN_TIME: <seconds> <microseconds>` beside `ut_type = 11`, four times on this image, and
  `USER_PROCESS`/`DEAD_PROCESS` beside 7 and 8.
* **The `console` record's `ut_id` is the opaque bytes `2f 00 01 01`**, which Apple's own logger
  renders as `0x2f 0x00 0x01 0x01` — the same text/hex distinction
  `seance_plugin_utmp` arrived at independently.

The stores also agree with the binary `utmpx` file where the two overlap: the boot at
1617653088.421051, the `console` login at 1617653227.621636 and the `ttys000` login at
1617653306.394470 appear in both, to the microsecond, and neither reader was consulted for the
other.

**Test.** `the_real_macos_asl_stores_hold_the_login_history_utmpx_cannot_give` in
`seance_plugin_macos_artifacts/src/asl.rs`, which pins every figure above and skips with a
printed notice when the corpus is absent.

**What this does not grade.** The `OLD_TIME`/`NEW_TIME` swap between the two `ut_type`
enumerations is still the header's word: no macOS clock-change record is in these stores either.
The `AUX.<date>/` directories, which hold the payloads some messages point at, are not read. And
sessions are not paired across stores, so a login on one day and its logout on the next are
reported as an open session and an unpaired logout rather than joined — which is recorded on the
status row rather than implied.

### ANDROID-PKG-1 — the one app that did not come from the store, 2026-09-17

**Evidence.** `data/system/packages.xml` (1,145,741 bytes, text XML) from Josh Hickman's
2022 Android reference image, at
`ctf-evidence/android2022/tree/data/system/packages.xml`. Recreate it from the 9.5 GB
tar with `mkdir -p ~/ctf-evidence/android2022/tree && cd
~/ctf-evidence/android2022/tree && tar xf ../android.tar data/system`.

**What was validated.** That the Android package manager's **install provenance** is
recoverable and, more to the point, that it can be read in a way that produces a finding
rather than a wall of absences. The attribute is `installer` — the package that asked the
package manager to install this one — and reading it naively is worse than not reading it,
because on this device **151 of 213 packages have no installer at all**.

**How ground truth is fixed.** The device's own file answers three ways at once, and the
readings have to agree:

1. **The census adds up.** 213 `<package>` elements; 62 with an `installer`, and **every
   one of those 62 names `com.android.vending`** — the Play Store. 151 with none.
2. **The partition splits the 151 correctly.** Of them, **150** have their code on a
   read-only OS partition (`/system` 123, `/product` 19, `/vendor` 8), where the absence
   of an installer means nothing installed it — it shipped with the OS. That leaves
   **one**.
3. **The one is `com.topjohnwu.magisk`** — Magisk, an Android rooting tool — with its code
   at `/data/app/com.topjohnwu.magisk-1` and no installer recorded, on a device where every
   other package in that partition names the Play Store. Nothing in the parser knows what
   Magisk is; the finding falls out of the two counts above.

**The answers.**

| | |
|---|---|
| `<package>` elements | 213 |
| `installer_recorded` | 62, all `com.android.vending` |
| `shipped_with_the_os` | 150 |
| `no_installer_recorded` | **1 — `com.topjohnwu.magisk`** |
| `not_recorded` | 0 |
| Packages with `installInitiator` or `updateOwner` | 0 — this release writes neither |
| Packages with an `it` install time | 213 |

**What this run does not grade.**

* **Android 14's finer split.** `installInitiator` and `updateOwner` appear on no package
  here, so nothing on this image exercises them. They are read where a device writes them
  and absent otherwise; the parser does not fill them in from `installer`.
  Graded on the Android 14 Pixel 7a: see AND-1, "Install provenance".
* **`isOrphaned`'s meaning is not established.** 40 of the 62 Play-installed packages carry
  it while `com.android.vending` is itself installed, so the common reading — the
  installing package has since been uninstalled — does not hold on this device. The flag is
  reported as written, with that stated on the record.
* **The sideload reading is a signal, not a proof, and the record says so.** An absent
  `installer` can also mean the record predates the device's Android version writing it,
  that the app was restored from a backup, or that the installing package has since been
  uninstalled. The note tells the reader to compare against the other data-partition
  packages on the same device — which is exactly what makes it worth anything here.
* **An adopted SD card** (`/mnt/expand/<guid>/app/...`) is reported as partition `other`,
  not `data`, so a package installed normally onto external storage is **not** filed under
  the signal. That path does not occur on this image, so the classification is pinned by a
  unit test rather than graded.

**Test.** `the_real_android_packages_xml_finds_the_one_sideloaded_app` in
`seance_plugin_installed_apps/src/lib.rs`, which pins every figure above and skips with a
printed notice — naming the `tar` command that recreates the file — when the corpus is
absent.

### MACOS-UUIDTEXT-1 — the unified log's catalogue, and the logs that are not there, 2026-09-17

**Evidence.** The whole `uuidtext` tree on the Magnet 2021 macOS image:
`ctf-evidence/macos2021/tree/System/Volumes/Preboot/943CAEE3-8306-426A-A65E-4E0F4B52EBDB/PreLoginData/uuidtext`
— 274 per-image entry files across 169 hex directories, and two `dsc` shared caches of
31,004,568 and 31,004,566 bytes. 69 MB in 276 files.

**What was validated.** Two things. That the unified log's **format-string catalogue** is
readable in both of its forms, and that reading it yields something on its own: an
inventory of the code on the machine that logs. And — separately, and it is why this run
exists — **that the image holds no `.tracev3` file at all**, which is both the finding the
catalogue carries alone and the reason `ROADMAP` §1.6's per-message decode cannot be graded
here.

**How ground truth is fixed.** Each format states its own arithmetic, and the two checks
are of a kind that cannot pass by accident:

1. **A per-image entry's tail holds exactly one NUL.** After the 16-byte header, the
   `range_count` × 8-byte range table and the sum of the ranges' declared sizes, what
   remains must be the binary's path and nothing else. **274 of 274** corpus files land on
   a tail holding exactly one NUL. Any error in the header width, the table width, a
   declared size or the count would leave a tail with none or several.
2. **A shared cache's image table ends at exactly the byte its first range's data begins
   at.** `16 + 783 × 16 + 527 × 28 = 27,300`, and the first range's declared data offset is
   **27,300** — in both caches. Both table widths and both counts have to be right for that
   to hold, so it catches the whole class of layout errors at once. All **783** range data
   offsets land in the string area and all **527** path offsets resolve to a
   NUL-terminated path.
3. **The paths are real, and they are macOS's.** 262 distinct binaries including
   `/usr/libexec/opendirectoryd`, `/usr/sbin/bluetoothd`,
   `/System/Library/Frameworks/InputMethodKit.framework/Versions/A/Resources/imklaunchagent`
   and 527 shared-cache libraries from `/usr/lib/system/libxpc.dylib` down. Nothing in this
   reader supplies a path.

**The answers.**

| | Per-image entries | Shared caches |
|---|---|---|
| Files | 274 | 2 |
| Files whose own arithmetic comes out | 274 | 2 |
| Format version | 2.1 (all 274) | 1 |
| Ranges | 504 | 783 each |
| Images | 274 | 527 each |
| Format strings | 197,742 | 651,026 each |
| Images the catalogue holds no strings for | 0 | 33 each |

**274 files name 262 binaries.** Twelve paths appear twice under two different UUIDs — two
**builds** of the same binary, each with its own catalogue. Nine of the twelve are
Bluetooth and power components (`bluetoothd`, `IOBluetoothFamily` and its four plug-ins,
`BluetoothReporter`, `powerd`, `pmset`) and two are `/System/Installation/CDIS/templateMigrator`
and `/usr/libexec/recoveryos_agent`: the shape of an OS update, or a recovery variant
sitting beside the installed one. A reader counting files would overstate the inventory by
twelve.

**The absence, measured.** The image's `diagnostics` tree is walked recursively for
anything a unified-log reader could decode and holds **zero** `.tracev3` files — its
`Persist`, `Special`, `HighVolume`, `Signpost` and `timesync` directories are all empty,
leaving only `logd.0.log`, `shutdown.log` and a `version.plist`. So on this image the
catalogue is the only thing left saying what code was running and logging, and the
per-message decode in `ROADMAP` §1.6 has nothing to be graded against.

**What this run does not grade, and does not claim.**

* **Not a single log message.** A format string is a sentence the operating system *would*
  have substituted arguments into. Nothing in this tree says any of them was written, and
  a catalogue entry is **not** a record that the binary ran. Every record carries that
  sentence, and the record type is filed with the device rather than with execution
  evidence for the same reason.
* **The per-image entries' range `offset` field is not interpreted.** It is read and
  reported; what it is an offset into — the binary's `__TEXT`, presumably — is not
  established from these bytes.
* **The shared cache's range `range start` field** likewise.
* **A copied file loses its identity.** An entry file's UUID is its own path; a file carved
  or copied under another name is still read, and reported as one that cannot be matched to
  a log reference.

**Test.** `the_real_uuidtext_tree_yields_the_machines_logging_inventory` and
`the_corpus_holds_a_catalogue_and_no_logs_at_all` in
`seance_plugin_macos_artifacts/src/uuidtext.rs`, which pin every figure above and skip with
a printed notice when the corpus is absent.

### MACOS-UNIFIEDLOG-1 — unified-log messages put in the case, six public archives, 2026-09-26

**Evidence.** Mandiant's `macos-UnifiedLogs` test corpus, held at
`~/forensic_corpora/mandiant_unifiedlogs/test_data`: six `.logarchive` trees (High Sierra,
three Big Sur, Monterey, Tahoe) with 125 `.tracev3` files between them, each beside its own
`uuidtext` entries, `dsc` shared caches and `timesync` database. None of it is from the
graded macOS image, which holds no `.tracev3` at all (`MACOS-UUIDTEXT-1`).

**What was validated.** What `macos.unifiedlog` **emits into a case** when each `.tracev3` is
read where it lies, as a collected `.logarchive` added as loose files would be: that every
file reaches its own tree (including `logdata.LiveData.tracev3`, which sits at the archive's
root rather than one directory down), that the file records' `messages` blocks add up, that
one record is emitted per message up to the per-file cap, and that every message is dated.

**How the answers are fixed — and what they are not.** There is no ground truth for these
archives beyond Apple's own `log` tool, which is not run here. The comparison column is
**Mandiant's reading of the same files**, as pinned in its tests: per archive, tracepoints
plus statedump and simpledump entries equal Mandiant's totals for High Sierra (569,796), Big
Sur (747,616) and Monterey (2,397,109), and Big Sur's 747,294 tracepoints are the figure
those tests quote from Apple's `log raw-dump`. The unresolved references by reason equal
Mandiant's categories in all six. Agreement with another reader is a **comparison**, not
validation against ground truth; it says two independent readings of the bytes agree.

**The answers.** Resolved / dynamic-format / unresolved / loss records — the firehose
tracepoints — as the module reports them, and how the emitted records (tracepoints,
statedumps and simpledumps) were dated:

| Archive | Resolved | Dynamic | Unresolved | Loss | Files (all reach tree and timesync) | Records emitted, all dated through timesync |
|---|---|---|---|---|---|---|
| High Sierra | 569,400 | 180 | 3 | 0 | 7 | 448,877 |
| Big Sur | 746,682 | 553 | 54 | 5 | 16 | 690,250 |
| Big Sur, private enabled | 886,662 | 678 | 60 | 6 | 19 | 760,746 |
| Big Sur, public/private mix | 1,286,876 | 484 | 22 | 3 | 16 | 908,733 |
| Monterey | 2,231,582 | 1,400 | 900 | 23 | 34 | 1,514,824 |
| Tahoe | 4,173,949 | 196 | 917 | 9 | 33 | 2,494,919 |

Statedump and simpledump entries are messages of their own. With them, the module's
entries per archive — tracepoints plus statedumps plus simpledumps, summed from the file
records — equal Mandiant's pinned totals exactly: High Sierra 569,796, Big Sur 747,616 (322
of them statedumps) and Monterey 2,397,109. Across the Big Sur archive 1,259 messages have
their arguments joined back from an oversize entry in the same file and 23 do not find
theirs there, and say so. The emitted column is smaller than the entries because a file with
more than 150,000 emits its first 150,000 and counts the rest (`not_emitted_over_cap`); the
file record's counts stay whole. On one file, Big Sur's `Persist/0000000000000004.tracev3`, the first
message reads `opendirectoryd (build 796.100) launched...` from
`opendirectoryd (build %{public}s) launched...`, pid 105, subsystem
`com.apple.opendirectoryd`, dated `2022-01-16T03:32:13.964503310Z` through timesync and
within 2 s of the file's own header clock — a second, independent anchor. Its eight
unresolved messages each carry the reason (an offset, `0x422304`, outside its entry's
ranges) and no text.

**What this does not show.**

* **A `.tracev3` inside a disk image is not decoded.** The core cannot yet climb from a file
  inside an image to its tree; such a record says "tree not reachable, not decoded". This
  run grades loose files only; the ZIP route is pinned by unit tests, not by a corpus run.
* **Oversize arguments are joined within a file, not across files**, so an argument whose
  oversize entry the log wrote to another file shows as missing, and says so. A
  statedump's protocol-buffer or custom-object data is kept as bytes and not decoded (66 of
  Big Sur's 322 statedumps).
* **Tahoe is one entry short** of Mandiant's total (4,288,583 against 4,288,584), not yet
  attributed.
* **No message text is compared with Apple's own `log show`.** The text of the one message
  above is checked; the rest are counted, not read against a reference rendering.

**Test.** `every_corpus_archive_is_decoded_into_the_case` and
`a_logarchive_file_is_decoded_into_message_records` in
`seance_plugin_macos_artifacts/src/tracev3.rs`, and
`a_file_at_the_archive_root_reaches_the_tree_beside_it`,
`oversize_arguments_are_joined_to_their_messages` and
`statedumps_and_simpledumps_are_messages_of_their_own` in `unifiedlog_decode.rs`, which pin
every figure above and skip with a printed notice when the corpus is absent. The full run
takes about four minutes in a debug build.

### MACOS-SPOTLIGHT-1 — the Spotlight index, whose item blocks are compressed, 2026-09-17

**Evidence.** The two Spotlight version-2 stores on the Magnet 2021 macOS image:
`ctf-evidence/macos2021/tree/System/Volumes/Data/.Spotlight-V100/Store-V2/08E38AC0-8C6B-43EA-B854-C191A2633BD0/store.db`
(1,429,504 bytes, 86 blocks) and
`.../Volumes/Macintosh HD - Data/.Spotlight-V100/Store-V2/9FCCAA69-44EF-4FCB-B3AB-2040BCB5C72A/store.db`
(118,784 bytes, 6 blocks). **The file system those stores describe is mounted on the same
machine**, which is what makes this a known-answer run rather than a consistency check.

**What was validated.** That Spotlight's per-item metadata is recoverable — the name,
path, content type, sizes, owner, download source and dates of every file the index
saw, **including files since deleted** — and that the item blocks are compressed, which
entropy alone cannot show.

**The item blocks are compressed.** Every item payload long enough to measure runs at 7.72 to
7.98 bits per byte with 252 to 256 of the 256 byte values present, against 3.31 to 6.28 for the
three readable kinds, and a search for Apple's compression markers (`bv41`, `bv4$`, `bvx1`,
`bvx2`, `bvxn`, `bvx-`, an LZ4 frame magic and a zlib header) at offsets 0 and 32 finds none.
Neither fact shows the blocks are unreadable. **The zlib header is at block offset 20.** An item
block's `2pbd` header is twenty bytes, and the `u32` at offset 16 is the uncompressed length
counting those twenty. `zlib` inflates **74 of 74** item blocks in the larger store and 1 of 1 in
the smaller, and `len(inflated) + 20 == logical_size` for every one of the 75.

#### How ground truth is fixed

Six checks. The first is the only one that owes nothing whatever to the store's own
internal consistency, and it is the one that matters most.

1. **The file system answers.** For every item whose parent chain reaches a root the
   store holds, the reconstructed path is looked up on the mounted image and the decoded
   `kMDItemLogicalSize` compared with the file's actual length. **8,782 of 8,797 agree.**
   Nothing in this reader knows the file system; if either the path reconstruction or the
   integer decode were wrong, that number would collapse. The **fifteen** that differ are
   every one of them a file macOS rewrites in place — ten SQLite `-wal` logs,
   `InstallHistory.plist`, `ProductMetadata.plist`, a CrashReporter interval file (twice,
   at two different decoded sizes, because the store kept both versions) and one
   `promotedcontentd` cache entry. The index is older than the acquisition, which is a
   fact about the evidence and not a decode error.
2. **The store's own length field.** For all 75 item blocks the declared logical size
   equals the inflated length plus twenty. A wrong offset or a wrong field would not
   satisfy that for one block, let alone all 75.
3. **The records tile exactly, twice over.** An inflated block is a flat sequence of a
   little-endian `u32` byte count and that many bytes: **14,936 records across 75 blocks
   with zero bytes left over.** Inside each record the attribute stream — which has no
   terminator and no padding — is consumed to the record's last byte in **14,936 of
   14,936**, decoding **428,124 values**. One value read at the wrong width desynchronises
   every attribute after it, so this is a sharp test and not a formality: absolute
   property ids instead of a running delta tile 1 record in 14,936; dropping any fixed
   prefix field tiles none.
4. **The store's own map agrees with the page scan.** The `2mbd` block on page 1 lists the
   item blocks; the blocks themselves are found by scanning every page for `2pbd`. The two
   name the same **74** pages in the larger store and the same **1** in the smaller. They
   are independent, and a page named but unreachable would be reported as a gap.
5. **The dates land where the evidence was acquired.** All 14,936 index times, read as
   microseconds since the Unix epoch, fall between 2021-02-11T01:55:56Z and
   2021-04-06T04:46:19Z. The same image's other artefacts agree and this reader consults
   none of them: the data-protection keychain's device state is 2021-02-12T00:35:07Z
   (`MACOS-KEYCHAIN-2`) and the ASL stores run 2021-03-30 to 2021-04-06 (`MACOS-ASL-1`).
   Of the 149,339 `CFAbsoluteTime` values in the attribute streams, **none** falls outside
   2007–2021.
6. **Internal cross-checks the decode did not aim at.** `kMDItemContentType` is a member
   of its own `kMDItemContentTypeTree` list in **14,932 of 14,932** cases;
   `PixelWidth × PixelHeight == PixelCount` in **503 of 503** records carrying all three
   — a proof of the integer rule that owes nothing to tiling; `public.folder` maps to the
   localised kind `Folder` in **5,747 of 5,747**; and 13,967 of 14,934 parent references
   resolve to another item in the same store.

A seventh, structural: the numbers are **big-endian behind a leading-ones length byte**,
and that reading is what makes sibling item ids come out consecutive — `c1 33 ac` and
`c1 33 ad` are 78,764 and 78,765. A little-endian reading of the same bytes gives
plausible values that are neither consecutive nor ids.

**Independently reproduced.** The grammar was derived three times from the bytes by
separate routes — a tiling constraint search, a known-answer approach against the mounted
file system, and a bit-field analysis of the property table — and then each derivation was
handed to a separate adversarial pass told to refute it by reimplementing it from the prose
alone. All three reimplementations reached **100.000000% tiling** on both stores and
confirmed the grammar.

#### The answers

| | Larger store | Smaller store |
|---|---|---|
| Blocks | 86 | 6 |
| Item blocks / inflated / named by the store's map | 74 / 74 / 74 | 1 / 1 / 1 |
| Item records | 14,934 | 2 |
| Bytes unaccounted for after the record walk | 0 | 0 |
| Attribute streams reaching the record's last byte | 14,934 | 2 |
| Attribute values decoded | 428,087 | 37 |
| Paths that reach a root this store holds | 12,808 | 2 |
| Decoded sizes checked against the mounted image | 8,782 / 8,797 | — |
| Items whose parent is not in this store | 967 | 1 |
| Items stating no parent at all | 0 | 1 |
| Distinct item ids | 14,930 (4 ids appear twice) | 2 |
| Attributes named | 130 + 6 placeholders | 53 + 6 |
| Content types / localised display names | 397 / 3,703 | 133 / 41 |
| Category-id lists / localised label sets | 264 / 171 | 1 / 2 |

Named items, decoded end to end and pinned in the test:

* **`/Applications/checkra1n.app`** — `com.apple.application-bundle`, kind `Application`,
  bundle id `kim.cracksby.checkra1n`, version `beta 0.12.2`, **used 6 times**, last on
  2021-02-22T04:06:32Z, owned by uid 501 (the console user) and gid 80 (admin). A jailbreak
  tool, which is the kind of thing this store is read to find.
* **`/private/etc/cups/cupsd.conf.pre-update`** — logical size 6,538 and physical 8,192
  (two 4 KiB pages), gid 26 (the CUPS group). The file on the mounted image is 6,538 bytes.

#### What this run does **not** grade

* **The widest variable-size number form** — `0xff` and eight bytes. Its byte count is
  pinned (no other count tiles) but its value is not, and it occurs **once** in either
  store: on `_kMDItemFinderFlags` of a Finder alias, where the big-endian reading every
  narrower form proves gives 36,310,271,995,674,623 and a little-endian signed reading
  gives −32768, whose low sixteen bits are exactly the `kIsAlias` flag the item should
  carry. Both consume the same nine bytes, so the record's structure cannot choose. The
  reader emits the big-endian value **flagged as unestablished** rather than quoting it.
* **Nine of the 33 value shapes rest on one to five observations plus plausibility, not on
  tiling** — the integer and date arrays, the two float types, the blobs. Mutating each in
  turn leaves tiling at 99.98% or better, so tiling is a razor for the frequent pairs and
  nearly blind for the rare ones. Saying so is the difference between a measurement and a
  claim.
* **Four things read and not interpreted**: the record's flag byte (0, 1, 32, 66, 98 occur),
  the unnamed number between the flags and the parent reference (0 to 190,374), the leading
  byte of each localised-label entry (0x1f–0x22), and `value_type`'s bits other than `0x02`
  and `0x80`. Each is published as what was seen rather than dropped.
* **One category reference in either store does not resolve**: `0xfeffffff` on the older of
  two records for item 46647, whose newer record is `com~apple~CloudDocs`. It looks like a
  tombstone; it is reported as an unresolved id rather than dropped or shown as empty.
* **The `0x41` block** is empty in both stores, so its entry format is unestablished.
* **`value_type` 195** never occurs in an item record in either store, along with eight
  other declared `(property_type, value_type)` pairs. Nothing is assumed about them.

**Test.** `the_real_spotlight_stores_yield_their_vocabularies_and_measure_what_they_cannot_read`
in `seance_plugin_macos_artifacts/src/spotlight.rs`, which pins every figure above —
including the 8,782 / 8,797 file-system comparison and the requirement that all fifteen
disagreements be files macOS rewrites — and skips with a printed notice when the corpus is
absent.

**Entropy.** "No marker found" is not "no marker present", and entropy cannot say a block is
unreadable. The entropy machinery measures only blocks this reader does **not** decode, where it
says whether the bytes look compressed or look like structure that was missed.

### KEYCHAIN-3 — System.keychain opened with /var/db/SystemKey on a real macOS 11.2.1 volume, 2026-10-23

**Evidence:** Josh Hickman's public macOS Big Sur image (`macOS - BigSur.zip`, 34,408,655,935 bytes, SHA-256 `ccdfab334502b9fc28f6369c074d0906ea34d7b5709bffb11512db9bad989687`, MediaFire; macOS 11.2.1 VMware guest, APFS, no FileVault): `/Library/Keychains/System.keychain` (39,912 bytes, SHA-256 `fc33fe78c2b2fcdef1f7a89fb110d8bf0676dc004babae3a0152e525903a2a93`) and `/private/var/db/SystemKey` (48 bytes, `6ccb2773cc0959a74d24d22c6642038bf7d9297a050ee8367c18b962a21cde50`), held at `~/forensic_corpora/found_macos_bigsur/extract/`. **Ground truth:** an independent Python window search (only bytes 8..32 of the SystemKey leave valid PKCS#7 padding) and chainbreaker 3.0.3 `--unlock-file`. **Result:** the 44-byte master key matches; the Guest account's generic password (`AlSPT2l:1VMGGtTI`) decrypts; 3 of 3 private keys are valid PKCS#8 RSA-2048; a one-bit change or a different keychain is `WrongPassword`, a wrong length or magic is `NotASystemKey`; through the credential route `macos_system_key` reports `accepted` and the key and secret are on no record; the reveal route takes `{"system_key": hex}` and audits `kind=macos_system_key`. **Not established:** one SystemKey, one macOS version (11.2.1); the 16-byte signature is not verified; the `LocalBeaconStoreKey` item (28-byte payload, no ciphertext) is reported undecrypted where chainbreaker prints an empty password; the user's `login.keychain-db` is held but its password is not published, so it is not graded; the frontend reveal panel does not offer a SystemKey. **Re-run:** `cargo test -p seance_plugin_macos_artifacts --test keychain_system_key` and `cargo test -p seance_api --test macos_system_key_reveal_test`.

### KEYCHAIN-2 — macOS keychain item decryption on a real keychain with a published answer, 2026-10-22

**Evidence:** `testdata/test.keychain-db` of moond4rk/keychainbreaker (commit `b5ef3a65008e`, Apache-2.0), 31,992 bytes, SHA-256 `026c5ac3...ccdf5`: "a self-contained keychain created with the macOS `security`
command" (its `rfcs/002-api-design.md`), held at `~/forensic_corpora/public_keychain/keychainbreaker/testdata/`. **Answer:** that project's own test table, by the person who made the file: password `keychainbreaker-test`; two
generic passwords (`moond4rk.com` with description `application password`, `HackBrowserData`; account `admin`) and two internet passwords (`moond4rk.com` `htps`/443 with path `/login`, and `smb `/445), all four `password#123`; an RSA-2048 key and a self-signed certificate.
**Not third-party validation of Séance:** a published answer for the file.

**Result.** The password opens the `DbBlob` (the master key is 44 bytes: the 24-byte database key and 20 bytes beyond it); each of the four `ssgp` items is matched to its symmetric key record by the 20-byte label; the item key unwraps; **all four
secrets decrypt to `password#123`**; a wrong password is `WrongPassword` (`tests/keychain_items_real.rs`). With a password supplied through the credential route the four item records read `secret_state: withheld`, `secret_bytes: 12`; the secret, its hex and its
base64 are on no record, and the five wrapped items that did not decrypt (the private key and the four item-key records) stay locked.
**What the real file establishes that round-trip tests cannot:** the unwrapped key block is 36 bytes and the item key is the 24 bytes **after its 12-byte header**, not its first 24 (offset 0 fails the padding check on all four); the `ssgp` label includes the
tag (the first four of its twenty bytes are `ssgp`); the `ssgp` payload is label, 8-byte IV, ciphertext.

**Not established.** One keychain, one macOS version, one `security` run; only `ssgp` password items and the one RSA private key (graded as a valid PKCS#8 RSA-2048 key by the `rsa` crate, not byte for byte against a second reader); no `System.keychain` (`/var/db/SystemKey` is not held).
**Re-run:** `cargo test -p seance_plugin_macos_artifacts --test keychain_items_real` (it prints `KEYCHAIN-2 could not look` and passes without the corpus; `SEANCE_REQUIRE_CORPUS` makes that a failure).

### KEYCHAIN-1 — the macOS keychain master-key unwrap, 2026-10-20

**Evidence (real, third party).** openwall `john-samples`, `Apple_Keychain/Keychain Samples`, held at
`~/forensic_corpora/john_samples_apple_keychain/` (see its `SOURCE.md`): `TestUser1-password/login.keychain`
(password `password`, SHA-256 `af7f112629d18a088a41234a74c885e5993e52cd20da06fe38a73cafbd3ffeb0`) and
`TestUser2-letmein/login.keychain` (password `letmein`, SHA-256
`10a21b0e77af9be8381c1e4d39e60dfcef21b57d73b55706b428a053442e819c`). Each is 20,460 bytes with one `DbBlob`
(version 0x100, wrapped region 48 bytes) at offset 20,280.

**Ground truth.** A second implementation, not a second source of truth: Python `hashlib.pbkdf2_hmac('sha1', pw,
salt, 1000, 24)` then `cryptography` 3DES-CBC over the blob's 48 bytes. Right password: the plaintext ends
`04 04 04 04` and the first 44 bytes are the pinned master key; wrong password: a random tail.

**Graded.** `DbBlob` location, the PBKDF2 + 3DES unwrap and wrong-password detection: both master keys match byte for
byte, and the other file's password, the empty string, a case change and a truncation are all refused. Through the
credential route, the right password reports `password_state: accepted`, a wrong one is rejected, and the key, its
hex and the password appear on no record.

**Not graded.** Both files hold **zero** `ssgp` items, so `unwrap_item_key` and `decrypt_ssgp` are still pinned by
synthetic round-trips only, and no secret is claimed recovered. Needs a keychain with at least one generic-password
item and a known password.

**Re-run.** `cargo test -p seance_plugin_macos_artifacts --test john_keychain_unlock --test keychain_password_credential`
(without the corpus the tests say so and pass vacuously).

### MACOS-KEYCHAIN-1 — the two macOS keychains, read without a password, 2026-09-16

**Evidence.** `ctf-evidence/macos2021/tree/Users/eliflatt/Library/Keychains/login.keychain-db`
(83,168 bytes) and `.../Library/Keychains/System.keychain` (37,904 bytes) from the Magnet 2021
macOS image.

**What was validated.** That a keychain nobody can open still answers *"which services and
accounts did this person hold credentials for, and since when"* — and that it answers nothing
more than that, with every secret reported as unrecovered.

**How ground truth is fixed, and why it is not the tool agreeing with itself.** Four checks, none
of which this code supplies the answer to:

1. **The file's own arithmetic.** The header's `schemaOffset` plus the schema's `schemaSize`
   lands at the end of the file; each attribute offset resolves inside its own record; and the
   attribute data begins exactly where the item's payload ends
   (`24 + 4 × attributes + dataSize`), leaving no slack for a different header.
2. **Each table's own record count.** A table's record-number array mixes zeros, free-list links
   and live record offsets, and separating the last two is the one rule here that a wrong reading
   would get wrong while still producing plausible records. Across all 23 relations of the two
   files, the number of live records found equals the number each table header declares, in every
   one.
3. **The file's own schema.** Every attribute is decoded against the format
   `CSSM_DL_DB_SCHEMA_ATTRIBUTES` declares for it, and the relation names come from
   `CSSM_DL_DB_SCHEMA_INFO`. Nothing about either file's layout is supplied by this reader beyond
   the offset of that first relation.
4. **What comes out reads as itself.** 52 items in the login keychain and 12 in the system
   keychain decode to legible service names, account strings and ISO dates — and the dates fall
   inside the image's own acquisition window (2021-02-11 to 2021-04-05), which is corroboration
   from outside the file.

**The answers.**

| Question | Answer | From |
|---|---|---|
| What Apple ID did this account use? | **`e.flatt610@gmail.com`**, Apple account number `20118734345`, stored 2021-02-12 | `login.keychain-db`, service `iCloud` |
| Was an iOS device backed up to this Mac? | Yes — service `iOS Backup`, key `518e8d766f9b3e76db216f35fdb6b0604e50f61b`, creator `aapl` | same |
| Which wireless networks did the machine hold a password for? | SSID **`Guest`**, "AirPort network password" | `System.keychain`, service `AirPort` |
| Which identities does the machine carry certificates for? | `com.apple.systemdefault` and `com.apple.kerberos.kdc`, both carried out as `.cer` artifacts (835 and 840 bytes, first byte `0x30` — a DER SEQUENCE) | `System.keychain` |
| How many credentials in all? | 23 generic passwords, 23 symmetric keys, 3 public and 3 private keys in the login keychain; 4 passwords, 4 symmetric keys, 2 public, 2 private and 2 certificates in the system keychain | both |
| How many secrets were recovered? | **None.** Every wrapped item is reported `locked` with the reason | both |

**What the run would have got wrong, and why it does not.** The password relations number their
attributes by four-character code, so declaration order and numeric order differ. A reader that
sorted by attribute id would read every value at the wrong offset and produce *entirely legible*
output — an account string where a creation date belongs. That is why the schema's own order is
used and why a test pins it. The same file also settled that the `CSSM_DL_DB_SCHEMA_*` relation
ids are 1 = ATTRIBUTES and 2 = INDEXES, the reverse of the order the tables appear in.

**Tests.** `the_real_macos_keychains_read_as_the_accounts_they_hold` in
`seance_plugin_macos_artifacts/src/keychain.rs`, which pins every figure above and skips with a
printed notice when the corpus is absent.

**What this does not grade.** **Decryption.** The master key is wrapped in each file's `DbBlob`;
unwrapping needs the keychain password, or `/var/db/SystemKey` for `System.keychain`, and
`SystemKey` is **not present** on this image. No keychain whose password is known is held for this
run, so it grades no unwrap. The unwrap and item decryption are graded in `KEYCHAIN-1` to
`KEYCHAIN-3`.

### AND-2 — Magnet Virtual Summit 2022 CTF, Android (Pixel 3), 2026-09-12

**Image.** `2022 CTF - Android-001.tar`, 9,511,577,600 bytes — a full file system extraction of
a Google Pixel 3, from Digital Corpora's mirror of the Magnet CTF material.

**Ground truth.** Kevin Pagano's published write-up (stark4n6.com), cross-checked against
Variable Bytes. Saved with the evidence as `keys/android2022-answers.txt`.

| Q | Key | Séance |
|---|---|---|
| ICCID of the SIM used | 89148000007077222152 | **Answered** on the device-facts panel, from `telephony.db` `siminfo.icc_id`, with the file and column named. |
| MAC of the first IoT device connected | D0:5F:B8:33:DF:00 | **Answered.** `bt_config.conf` is read into pairings; the Moto 360 is `order: 0` and the only one with no last-seen time, which is exactly why the write-up calls it first. |
| How long was the longest podcast? | 03:35:23 | **Answered.** The `.m4a`'s `moov/mvhd` gives 12,923.167 s → `03:35:23`. |
| What day was the device factory reset? | 2022/01/14 | **Answered** from the mtime of `/data/misc/bootstat/factory_reset` — 2022-01-14T17:47:29Z. |
| What LARP armour was being built? | shield | **Answered** from Chrome history ("DIY Small LARP Shield in Under an Hour!"). |
| Snapchat: top sender, last friend added | teamsnapchat, angie_frank07 | **Answered**; the friend comes from recovered SQLite rows rather than a Snapchat-friend record. |
| Zip code where the water photo was taken | 05401 | **Answered** from EXIF GPS (44.47728, −73.22133 → Burlington VT). |
| Whose phone is this? | — | The device panel answers it: Pixel 3, `rafaelshell24@gmail.com`, Reddit `ArcaneArmor1`, Twitter `RafaelShell2`, Tracfone, Android ID, Bluetooth MAC, ADB and sideloading enabled, clock set automatically. |

**Behaviours this run pins.** File entries from a tar or zip carry timestamps (287,014 entries);
Android crash dumps are not parsed as emails; a folder of files is ingested; `bt_config.conf` is
read into pairings; media duration and recording time are read.

### IOS-2 — Magnet User Summit 2022 CTF, iOS 15 (iPhone 8), 2026-09-12

**Image.** `2022 CTF - iOS Full File System.zip`, 4,711,962,945 bytes — a GrayKey full file
system extraction, ingested to 545,783 artifacts.

**Ground truth.** Kevin Pagano's published write-up, saved as `keys/ios2022-answers.txt`.

| Q | Key | Séance |
|---|---|---|
| Last position of the phone | 38.84412765, −77.28686523 | **Answered**, at 2022-02-14T18:26:03.105Z, from `com.apple.routined`'s `Cache.sqlite` — the newest positions are in the write-ahead log, which is read. |
| App with the most screen time | Bumble | **Answered** by summing `/app/inFocus` in the parsed knowledgeC records (`com.moxco.bumble`, 2,649 s). |
| Items on the shopping list | 4 | **Answered** (follow-up below): the note body is decoded. |

**Behaviours this run pins.** A nested file in the extraction is opened through the archive's own
entry key, not a key rebuilt from the display path, and a database's newest rows are read from its
write-ahead log.

**Follow-up, 2026-09-19 (Safari, HealthKit, Notes bodies, Photos albums).**
The shopping-list question is answerable in the case: `NotesParser` decodes the body
from `ZICNOTEDATA.ZDATA` (gzip, then protobuf field 2 → 3 → 2, verified byte-for-byte on
both real blobs), and the Grocery list note reads *Energy drinks, Bread, Hand soap,
Birthday card* — **4 items**, the key's answer. The device files that ground this and the
rest of the §1.5 work were copied byte-for-byte (with their `-wal` siblings, never opened in
place) into `seance_plugin_ios_artifacts/tests/fixtures/magnet2022_ios15/` (not committed), and every
count below was read with `sqlite3` on a copy before the parser was written; the 17
integration tests in `tests/magnet2022_ios15_test.rs` pin them. The known answers, each an
assertion in that file:

| Store | Known answer | Test |
|---|---|---|
| `Library/Safari/Bookmarks.db` | 6 bookmarks in 4 folders; `PRAGMA user_version` 43; 17,517 bytes of attribute blobs counted, not decoded | `safari_bookmarks_are_the_six_the_device_holds_and_the_four_folders_it_keeps_them_in` |
| `SafariTabs.db` (the iOS 15 tab store) | 3 open tabs, 1 private ("Start Page" in the Private tab group), 1 window, 2 tab groups; tab 14's back/forward list holds 5 entries — the Google search "plant shops near me", a Maps direction request to Gardener's Supply Company, Williston VT, then bedbathandbeyond.com | `the_three_open_tabs_are_read_and_the_one_private_tab_is_reported_as_private` |
| `BrowserState.db` | `tabs` **empty** on iOS 15 (2 windows, reachable only through the 24,752-byte WAL) — reported as a superseded generation pointing at `SafariTabs.db`, not as "no tabs open" | `an_empty_browserstate_tabs_table_is_reported_as_a_superseded_generation_not_as_no_open_tabs` |
| `com.apple.mobilesafari.plist` (`RecentWebSearches`; `RecentSearches.plist` does not exist on the device) | 3 queries — "what to do if you get hacked" at 2022-02-11T03:59:39.993625998Z, "when does bed bath and beyond close", "plant shops near me"; the search engine is not recorded | `a_recent_search_keeps_the_microseconds_the_plist_recorded` |
| `healthdb_secure.sqlite` (+ `healthdb.sqlite` as a neighbour) | **688** samples, histogram exactly `{7:131, 8:133, 12:20, 182:110, 187:118, 188:118, 194:58}`; recording timezone `America/New_York`; source name "iPhone 8" from the sibling database; `unit_strings` empty, so no sample carries a unit; `PRAGMA user_version` 15043; 0 workouts, 0 sleep rows | `six_hundred_and_eighty_eight_health_samples_with_the_histogram_the_device_holds`, `the_health_source_name_is_read_from_the_sibling_database_and_a_source_that_cannot_look_says_so` |
| `NoteStore.sqlite` | 2 notes, 4 folders (two Recently Deleted), 0 deleted, 0 attachments; the Grocery list body above; note 9's 191-byte body lives only in the WAL, so the assertion pins WAL staging | `the_grocery_list_note_body_is_the_four_items_the_device_stored` |
| `Photos.sqlite` ×2 | 41 albums on the main library, 48 on the Syndication library; the album↔asset join table discovered as `Z_27ASSETS`, 0 memberships; 0 faces, 0 persons | `the_album_join_table_is_found_by_entity_number_and_an_empty_one_is_reported_as_empty`, `the_second_photo_library_on_the_device_is_its_own_summary` |

**Not graded, because the device holds no instance:** Voice Memos (`CloudRecordings.db`
absent, `Media/Recordings/` empty), voicemail audio and transcripts (both `voicemail.db`
files have 0 rows, no `.amr`/`.m4a`), Photos faces (0 rows), a note in Recently Deleted or
with an attachment (0 of each), HealthKit workouts and sleep (0 rows), and keychain items
(the class keys the backup decryptor unwraps are not exposed, and no encrypted backup with a
known password is held). A decoder for any of these would be written from a specification
and graded against nothing, so none was. No Reincubate 12.3.1 backup is held; this extraction is the only iOS
evidence held. Re-run: `CARGO_BUILD_JOBS=3 cargo test -p seance_plugin_ios_artifacts
--all-features --test magnet2022_ios15_test`.


### LIN-1 — Magnet User Summit 2022 CTF, Linux (Lenovo), 2026-09-13

**Image.** `LenovoFinal.E01`, 2,146,419,280 bytes — an EnCase image of an Ubuntu 21.10 laptop,
from Digital Corpora's mirror of the Magnet CTF material. Ingested to 1,755,082 artifacts in
2,177 s.

**Ground truth.** Kevin Pagano's published write-up (stark4n6.com, June 2022), saved with the
evidence as `keys/linux2022-answers.txt`.

| Q | Key | Séance |
|---|---|---|
| Distribution version ("Mischievous Lemur") | 21.10 | **Answered** on the device-facts panel — Ubuntu 21.10 (impish) — read from `/usr/lib/os-release` and corroborated by `/etc/lsb-release`, each naming its own key. |
| Host name (`$whoami`) | rshell-lenovo | **Answered** from `/etc/hostname`, on the same panel. |
| Mail: "A little blue birdie told me" | Attack On Titan | **Answered** — a Twitter notification in the Thunderbird mailbox. |
| Mail: "Be our guest" | 93483 | **Answered** — a Champlain visitor-account receipt in the same mailbox. |
| Minecraft account UUID | 8b0dec19-b463-477e-9548-eef20c861492 | **Answered** from `.minecraft/usercache.json`, read through the artifact's content view. |
| "Today's YouTube video is sponsored by…" | Zerotier | **Answered** twice over: `curl -s https://install.zerotier.com | sudo bash` and `zerotier-cli join` in the shell history, and the video in Chrome history. |
| Discord voice module version | discord_voice (v5) | **Answered** from `.config/discord/0.0.16/modules/installed.json`. |
| The Log4j RCE payload | `-c 192.168.191.253 -p 4444 -e cmd` | **Answered** — `marshalsec/poc/Log4jRCE.java` carries the base64 PowerShell, decoded to that command. |
| Login and boot history | — | 11 `LoginSession` and 47 `BootEvent` records from `/var/log/wtmp`. |

The image-content questions the CTF also asks — the temperature in a screenshot, the channel in
a thumbnail, the pixel count of a picture — are answerable only by looking at the pictures,
which the Gallery presents; they are not machine-graded here.

### MAC-1 — Magnet Virtual Summit 2021 CTF, macOS (Mac mini, Big Sur), 2026-09-13

**Image.** `macos.zip`, 81,139,010,088 bytes, extracted to a directory tree and ingested a
subtree at a time (`Users`, `System/Volumes/Preboot`, `Library/Preferences`, `private/var/db`) to
209,849 artifacts.

**Ground truth.** Kevin Pagano's published write-up, saved as `keys/macos2021-answers.txt`.

**What this image gave the Apple Mail reader, 2026-09-16.** Its
`Users/eliflatt/Library/Mail/V8/MailData/Envelope Index` is a real macOS 11 Mail index — database
version 4.30006, framework 3654.60.0.2.21 — and **every table in it is empty**: `messages`,
`subjects`, `addresses`, `mailboxes`, `recipients` and `attachments` all return zero rows, with
and without the 449 KB write-ahead log attached, and the only populated table is `properties`.
Mail was opened on this machine and no account ever synced. So the image supplies the **schema**
the `Envelope Index` reader was written against — kept as
`seance_plugin_macos_artifacts/tests/fixtures/envelope_index_v8_schema.sql` — and supplies **no
row** to grade the field mapping on. Every record that reader emits says so
(`basis: "schema_verified_rows_unverified"`), and this is the measurement behind that label.

| Q | Key | Séance |
|---|---|---|
| Local host name | Elis-Mac-mini | **Answered** on the device-facts panel from `SystemConfiguration/preferences.plist` (`System.Network.HostNames.LocalHostName`), beside the computer name "Eli's Mac mini". |
| Product build version | 20D74 | **Answered** from `SystemVersion.plist`. |
| IMEI of the backed-up iOS device | 356759080486567 | **Answered** — the iPhone backup in `MobileSync/Backup/` is read from inside the image; the panel shows Eli's iPhone, iPhone10,4, iOS 14.4, backed up 2021-03-07. |
| Preferred energy drink | Bang | **Answered** from Safari history. |
| College lacrosse team | University at Albany | **Answered** from Safari history. (There is no Safari bookmark reader in the tree: `BrowserBookmark` records come only from Firefox `moz_bookmarks`, so the answer rests on history alone.) |
| Sites allowed to autoplay | 165 | **Answered** — `SitesAllowedToAutoplay.plist` parses as an array of 165. |
| Size of the app in the trash | 9,389,392 | **Answered** — `.Trash/checkra1n beta 0.12.2.dmg`. |
| Spreadsheet often navigated to | To-Purchase | **Answered** from Safari history. |
| Safari notification permission | 02/21/2021 23:14:06 EST | **Answered** — `UserNotificationPermissions.plist`, `2021-02-22T04:14:06Z` (UTC−5). |
| System password hint | Fix something! | **Answered** from `CryptoUserInfo.plist`. |
| SHA-1 of the profile picture | 3CC4E757872A7A9C534AD42BFFAA9F8170A99553 | **Answered** — the picture is carried out of the plist as a file of its own and hashed; the SHA-1 matches exactly. |
| Second stock quote searched | $SPCE | **Answered** from the Stocks cache database. |
| Finder source version | 1350.2.10 | **Answered** — the macOS application inventory reads each bundle's `Info.plist`; Finder is version 11.1, build `1350.2.10`. |
| iCloud encryption key | fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os= | **Answered** — `keychain-2.db`'s `ckdevicestate` is read (`macos.keychain_data_protection`), and the Mac's own row carries `octagon_peer_id: SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=`. See `MACOS-KEYCHAIN-2` below. |

**All fourteen answer.** The last, the iCloud encryption key, is recorded separately as
`MACOS-KEYCHAIN-2`. The question is about the **Mac's own**
`Users/eliflatt/Library/Keychains/<UUID>/keychain-2.db`, not the iOS backup's keychain: Kevin
Pagano's write-up names the path. The backup in this image is encrypted and its keychain is not
reachable at all; the answer never needed it.

**Bounded gaps.** An image-resident backup's stored files are not reassembled to their device
paths. An ingest walk of this image peaks at 8.5 GB resident.

### SWEEP-1 — The findings layer across every image on the build host, 2026-09-14

**Purpose.** `HACK-1` measured the nine detections of `ROADMAP` §2.2 against one disk, and the
persistence classifier it refined was derived from that same disk. A false-positive rate measured on
the image the fix came from is not a false-positive rate. This is the sweep across everything
else available.

**How to re-run it.** `scripts/findings-sweep.sh --image PATH --label NAME`. One image in, one
JSON summary out: leads by detection and by confidence, the population they are out of, the
ingest time, what the cross-view pass could not ask, and the `Notable`/`Strong` rows in full.
It sets `SEANCE_AUTH_ENABLED=false` and the evidence root, puts the workspace and **the spill
directory** on real disk (the task queue and the index writer spill through the system temp
directory, and on a host where that is a tmpfs a large image fills it and the index writer is
killed mid-ingest — an invalid run that looks like a finished one), proves the server
answering the port is the one it just started, kills that server by recorded pid rather than
by pattern, and removes the workspace unless `--keep`. `--workers N` caps ingest concurrency.

Two things it does that matter for reading its numbers. The API lists at most 1,000 findings,
so the per-detection counts come from the case database, uncapped. And the two **cross-view**
detections are computed at request time and never persisted, so the database cannot see them:
they are counted from the API and reported as `(recomputed, not persisted)`. Counting only
what the SQL saw reported `execution_of_absent_binary` as silent on the Hacking Case, where it
raised the seventeen leads that answered the case — a false absence produced by the measuring
instrument, which is the one place this project cannot tolerate one.

**Validated against a known answer before being trusted.** Re-run on the Hacking Case it
reproduces `HACK-1` exactly: 236 leads over 25,018 file entries, 188 + 31 + 17, the same eight
detections silent.

**What was measured.**

| Image | Platform | File entries | Artifacts | Leads | Strong |
|---|---|---:|---:|---:|---:|
| CFReDS Hacking Case | Windows XP | 25,018 | 330,062 | 236 | 0 |
| Magnet 2022 Linux (`LenovoFinal`) | Ubuntu | 795,419 | 1,755,021 | **34** | **1** |
| Magnet 2022 iOS full filesystem | iPhone 8 | 91,233 | 1,139,226 | 0 | 0 |
| CTF Chromebook extraction | ChromeOS | 18,425 | 57,989 | 0 | 0 |
| Magnet 2019 Android | Android | 2,674 | 13,753 | 0 | 0 |
| Ali Hadi NTFS hidden-files | Windows | 537 | 5,327 | 0 | 0 |
| DFTT 5-fat-daylight | FAT | 4 | 17 | 0 | 0 |

Six of seven silent, which is the right answer for a layer whose detections read the MFT, the
registry, prefetch, Amcache, the USN journal and PE signatures. A Windows persistence rule
firing on an iPhone would be a defect, and none did.

*Note.* The two NTFS rows' file-entry counts above include `$MFTMirr`'s copies of records 0-3 a
second time. At the MFT parser alone (the `FileEntry`s it publishes for the volume, alternate data
streams included) the Hacking Case volume holds **12,183** and the Ali Hadi volume **172**. On the
Hacking Case, 69 files whose `$DATA` lives wholly in `$ATTRIBUTE_LIST` extension records carry a size
and content, 58 of them LZNT1-compressed and reconstructed, and 12 are flagged
`data_runs_complete: false` because their run lists exceed the 512 runs persisted in metadata. The
full-ingest rows above were not re-run.

**Authenticode on carved executables.** The Linux image raises **34 leads, 1 of them `Strong`**
(`Strong` is the only grade in the product that asserts tampering). `authenticode_hash` hashes the
bytes the specification includes and excludes the certificate table. 231 of the subjects are PE
files carved from unallocated space, and every carve overshoots the end of the signed image by
between 8 and 97,824 bytes. Re-reading all 231 windows from the image (md5-matched against what the
carver recorded) and recomputing: **231 of 231** match the signature with the boundary corrected,
and **0 of 231** match a digest taken over the carve as a whole.

The surviving `Strong` lead is `/usr/libexec/fwupd/efi/fwupdx64.efi.signed`, and it is not of
that class: four digest models, including two that walk the section table as the specification
describes, all fail to reproduce the digest embedded in its Canonical signature, while the
build host's own later copy of that path reproduces it exactly under the corrected model.
`sbverify` reports two gaps in that file's section table and 10,856 bytes it cannot account
for. **Whether that copy was modified is not established here.** What is established is that
the verdict on it is not demonstrably wrong.

**`carved_executable_in_slack`.** The NTFS, FAT and exFAT parsers publish `SlackSpace` regions, the
automatic carver carves them and stamps `carving_source: "slack"`, and the detection is reachable.
See `SLACK-1` for what is and is not graded; this sweep's zero for the detection predates the
producer. It is shown firing from a real NTFS volume in a partitioned disk, with its device offset
checked against `ntfscluster` (`SLACK-3`). The payload is synthetic and no held image has a PE in
slack.

**What this sweep did not cover.** `LoneWolf` (33 GB, Windows 10) is not in the table; its ingest and
findings output are recorded in `INGEST-MEM-1`. Nor does this
sweep cover memory images, DFIR Madness Case 001 (measured separately as `C001-FIND-1`), or any image with planted evidence — a false-positive rate is not a true-positive rate,
and six silent images say nothing about what those detections would find if something were
there.

### HACK-1 — NIST CFReDS Hacking Case, the findings layer, 2026-09-14

**Purpose.** The nine detections of `ROADMAP` §2.2 run against a real image. The exit criterion
is that *the timestomp detection is silent unless a stomped file is planted*. The detections have
unit tests; this is the measurement.

**Image.** `4Dell_Latitude_CPi.E01`–`.E02` (1.1 GB, Windows XP, NTFS), from
`https://cfreds-archive.nist.gov/Hacking%20Case.html`. Ingested whole under the `deep`
profile: 144,121 artifacts processed in 80 s, 25,018 file entries, no capped or failed
subsystem.

**Ground truth.** NIST's `TestAnswers.pdf` — the scenario is a laptop abandoned with a
wireless card and a homemade antenna, its user "Mr. Evil", and the task is "find any hacking
software, evidence of their use, and any data that might have been generated."

**The criterion is met.** `timestomp` raised **0** leads. So did
`pe_signature_mismatch`, `pe_in_alternate_data_stream`, `carved_executable_in_slack`,
`execution_of_deleted_binary`, `usn_delete_contradicts_mft` and
`hive_subkey_count_discrepancy`. On this image that is the right answer for each: nothing was
timestomped, nothing carried a broken signature, and the hive agrees with itself.

**And the detections found the case.** Of the 17 `Notable` leads, seven name software the
answer key itself asks about — every one of them raised by
`execution_of_absent_binary`, which reads prefetch and Amcache against the filesystem:

| Lead | The key's answer |
|---|---|
| `CAIN25B45.EXE` | Cain & Abel |
| `ETHEREAL-SETUP-0.10.6.EXE` | Ethereal |
| `NETSTUMBLERINSTALLER_0_4_0.EX` | NetStumbler |
| `MIRC612.EXE` | mIRC |
| `123WASP_SETUP.EXE` | 123 Write All Stored Passwords |
| `LALSETUP250.EXE` | Look@LAN (the file that ties the suspect to "Mr. Evil", Q12) |
| `WINPCAP_3_01_A.EXE`, `WINPCA~1.EXE` | WinPcap, Ethereal's capture driver |

The other eight are installers and installer temporaries of the same class —
`IRSETUP.EXE`, `INS6.TMP`, `GLJ15.TMP`, `FTINIT.EXE`, `A32-19.EXE`, `CUTE3032.EXE`,
`FABERTOYS_FULLSETUP.EXE`, `30.EXE` — each of which ran and was then deleted, which is what
the lead says and all it says.

**The persistence classifier.** A classifier behind `persistence_in_unexpected_location` that
treats bare names as paths fires **788 times** on this image, against 17 for every other
detection combined, in three parts:

* **742 leads from bare program names.** `normalize_target` guarantees its output a leading
  `/`, so `regsvr32.exe` arrives as `/regsvr32.exe` — shaped exactly like a file at the root of
  the volume. COM in-process servers (470), `KnownDLLs` (80), shell extensions (65), netsh
  helpers, Winlogon notify packages, print monitors and LSA packages all name a DLL Windows
  resolves **by name from the system directory**, and `seance_plugin_asep` says so itself in
  its `package_name_not_a_path` observation. The classifier consults the **raw** value: a
  path carries a separator or a drive letter, and reads the first whitespace-delimited token
  only, because `BootExecute`'s `autoconv \??\Volume{…} /fs:ntfs` carries separators in its
  *argument*.
* **42 leads from 8.3 short names.** `/progra~1/common~1/micros~1/msinfo/ieinfo5.ocx` is a
  genuine `Program Files` path, graded "outside the system and program directories".
* **5 leads from the default Startup folder**, which is where startup items belong.

**With it: 236 leads, 0 of them from that classifier, and 17 `Notable`.** A triage list
of 17 on a 25,018-file volume is readable top-down, which is the whole claim §2.2 makes. The
219 `Weak` leads are `persistence_target_not_recovered` (188) and `high_entropy_executable`
(31) — both graded and qualified as expected on a 2004 machine with software uninstalled.

**What this run did not cover.** The other half of the criterion, DFIR Madness Case 001, where the
persistence and absent-binary leads should rank in the top five, is measured as `C001-FIND-1`:
not met.

### MEM-CTF-2 — Magnet Virtual Summit 2020 CTF, Windows memory, 2026-09-13

**Image.** `memdump-001.mem`, 5,368,709,120 bytes — a Windows 7 SP1 x64 capture.

**What it shows.** No public symbol pack matches this kernel — `ntkrnlmp.pdb` GUID
`ECE191A20CFF4465AE46DF96C2263845` age 1, build lab `7601.win7sp1_ldr_escrow.190220-1800`, and
144 of 144 candidate symbol files were rejected — and Séance says so in a record rather than
guessing. It then recovers the capture from the image itself: DTB, kernel base and KDBG all
**confirmed**, 65 processes walked forward and backward from the process list (`complete: true`,
the forward walk stopping because it wrapped), with per-process VADs, modules and handles, plus
services, registry hives, recovered files, the pool scan, the process tree and a tampering pass.
The profile record that reported the failure is marked superseded by the run that succeeded, so
the case does not carry both statements as current.

This is the case for image-derived discovery: an examiner with a build Microsoft's symbol server
no longer serves still gets a process list, and is told exactly which part rests on symbols and
which on the image.

### CB-1 — Magnet Virtual Summit 2021 CTF, Chromebook, 2026-09-12

**Image.** `chromebook.tgz`, 408,901,035 bytes, extracted; the decrypted user folder ingested to
58,007 artifacts.

**What it shows.** 450 `BrowserHistory`, 997 cookies, 404 local-storage items and 13,280 browser
cache entries, with 106 `BrowserCacheParseStatus` records naming the cache files that would not
parse rather than passing over them. A ChromeOS exhibit is, in practice, a browser profile, and
the browser stack reads it whole.

### AND-3 — Magnet Virtual Summit 2019 CTF, Android ADB backup, 2026-09-12

**Image.** `adb-data.tar` from the 2019 CTF, 13,638 artifacts. Exercised rather than graded: the
backup carries the SD card (1,141 camera pictures, all with EXIF and perceptual hashes), the
calendar provider and a handful of application databases, but not the Kik message store the
CTF's questions turn on — an `adb backup` takes only what each application allows. It is a
useful negative case: the product reports what is there without implying the phone held nothing
else.

### CFTT-SWEEP-2 — the byte sweep over the NIST CFTT unix string-search image, 2026-10-22

**Image:** `ss-unix-07-25-18.dd`, 2,098,028,544 bytes (HFS+, ext4, HFSX and APFS partitions), key `unix_string_doc.txt`, the same data set as `CFTT-SWEEP-1` and `CFTT-SS-3`. **What is
graded:** the engine (`seance_search::sweep`), the whole image as one raw object, 65 distinct terms of the key (every encoding the key lists), no file system parsed. `CFTT-SS-3` found all 492 `DELETED-*` rows
unrecoverable by name, because their text lies in unallocated blocks; this asks whether a byte sweep reaches it. For each of the key's 1,049 rows that state a byte offset: is there a hit for that term at that
offset in the key's encoding (its own hit, or the folded opposite-endian reading)?

**Measured, 2026-10-22** (release build; 9.0 s; `complete: true`; 1,126 hits): **1,035 of 1,049 rows found at the published offset.** All four file systems, live and deleted:

| | live found / missing | deleted found / missing |
|---|---|---|
| ext4 | 129 / 7 | 113 / 1 |
| HFS+ (`osxj`) | 157 / 1 | 113 / 1 |
| HFSX (`osxc`) | 157 / 1 | 113 / 1 |
| APFS | 140 / 1 | 113 / 1 |

**452 of the 456 `DELETED-*` rows with an offset are found at their published offset, and the four that are not are `Wolf` rows whose key is one byte early.** So the deleted text `CFTT-SS-3` could not
name is reachable by the sweep, with its offset; naming the file it belonged to is not what a byte sweep does.

**The 14 not found at the key's offset**, each checked with `dd`/`xxd` and the nearest hit of the same term: eight are `Wolf` (a live and a deleted file on each of the four file systems), the term is there and
begins **one byte after** the key's offset on every one, so the key points at the byte before it. Six are in document formats: `rifle`, `flintlock`, `longbow`, `revolver` and `shotgun` are found 6, 10, 8, 17 and 15 bytes
before the key's offset, which sits inside the line the term opens; `crossbow` is split by markup in the html (`</u>bow`), so no contiguous `crossbow` sits there (the nearest is 5,893 bytes away). None is a
contiguous spelling of a term in the bytes that the sweep missed.

**Not established.** The extra hits (1,126 reported against 1,049 rows, plus folded twins) were not each placed against the key, so no precision figure is claimed; Unicode normalisation and case folding are not graded
(NFC and NFD forms are separate terms, as in `CFTT-SWEEP-1`); the 123 `zipped` and other offset-less rows are not graded; nothing here is about a real macOS or Linux machine. Not third-party validation.
**Re-run:** `SEANCE_CFTT_STRING_SEARCH=<dir> cargo test -p seance_search --release --test byte_sweep_cftt_unix_test -- --ignored --nocapture` (the test is `#[ignore]` and prints `NOT RUN` without the corpus).

### CFTT-SWEEP-1 — the byte sweep over the NIST CFTT string-search image, 2026-09-19

**Image.** `ss-win-07-25-18.dd`, 2,098,028,544 bytes, SHA-256
`1574185b8dedc343ceb7dd306099a7bd41ceb77730b52c8d97181aeb792b6eb9` (the publisher's
hash; the test passes it as the object's `content_hash` so the run does not spend itself
re-hashing). The same image and answer key as the string-search run above.

**What is graded.** `seance_search::sweep` (`ROADMAP` §1.2, the engine module, reachable through the API route
`POST /api/v1/cases/:id/search/sweep` with no screen, so this is a grade of the engine and not of
a screen) over the four terms whose key rows are exact byte strings:
`cities`, `mañana` in NFC, `mañana` in NFD, and `SecretKey`. Two runs, both in
`seance_search/tests/byte_sweep_cftt_test.rs`: every key row read through a window of the
real image as its own object with the key's region, and the whole image as one raw object.

**Measured, 2026-09-19** (release build; the whole-image sweep took 0.52 s):

| | |
|---|---|
| published offsets for the four terms | **72** |
| found, with the published encoding and (windowed run) the published region | **72 of 72** |
| hits reported | **72** — one per key row |
| UTF-16 key rows | 43, of which **29** have an opposite-endianness reading one byte away |
| opposite-endian readings folded into the hit before them | **29** — counted on the response as `endian_aliases_folded`, not as hits |
| hits marked `endian_ambiguous` | 29 — a report must quote both readings; the bytes do not pin which was written |
| bytes scanned, whole-image run | 2,098,028,544 = the image; `complete: true` |

**Endian aliases.** A sweep that reports every byte match returns **101** hits on the whole
image: the 72 published offsets plus 29 extras, every one of which is the opposite-endianness
reading of a UTF-16 key row at ±1 byte (UTF-16BE `xyz` followed by any ASCII code unit contains
the UTF-16LE byte form at +1, and vice versa). That is a real count of real byte matches and a
misleading one, because it doubles every UTF-16 string and states an encoding the bytes cannot
support. The sweep folds the later reading into the hit one byte before it, names both encodings
on that hit, and counts the fold; the test asserts that every hit accounts for exactly one key
row and that no hit the key does not list is reported.

**What it does not grade.** Unicode normalisation (NFC and NFD `mañana` are searched as
two byte strings, which is why both are terms), case folding, and the key rows whose
expectation is a position rather than bytes.

**Re-run.** `SEANCE_CFTT_STRING_SEARCH=<dir> CARGO_BUILD_JOBS=3 cargo test -p
seance_search --release --test byte_sweep_cftt_test -- --include-ignored --nocapture`
(the directory defaults to `~/forensic_corpora/cftt_string_search`; the whole-image test
is `#[ignore]` and runs only when asked). Absent the corpus the file prints `NOT RUN` and
passes, so a green run without the `--nocapture` output is not this grade.

### MEM-DUMPS-1 — eight kernel-structure stages on the Windows 11 26200 capture, 2026-09-19

**Image.** `test_data/win11_bitlocker/memory-unlocked.raw` (10,737,418,240 bytes, the
corpus VM's raw capture, Windows 11 build 26200) with its ISF under
`test_data/win11_bitlocker/symbols/`. Ground truth where there is any: the guest's own
`plant-artifacts.ps1` (`~/win11-lab/answers/guest/`), which registered the scheduled task
`\SeanceTestBeacon` with `schtasks /tr 'powershell.exe -w hidden -c exit'`.

**What is graded.** The eight stages, modelled on the Volatility plugins
`kpcrs`, `bigpools`, `virtmap`, `getcellroutine`, `verinfo`, `mbrscan`,
`scheduled_tasks` and the TrueCrypt trio — each a release-only known-answer test in
`seance_plugin_memory_windows/tests/win11_kernel_dumps.rs`. All eight pass. The measured
answers, each an assertion:

| Stage | Known answer on this capture |
|---|---|
| `processor_blocks` | **8** processors, `KeNumberProcessors` 8 (read and compared, never preferred); all 24 self-checks agree (`Self`/`SelfPcr`, `CurrentPrcb`, `_KPRCB.Number`); all eight idle, on the Idle process |
| `big_pool` | **32,768** slots: 6,965 live, 25,803 freed, 0 never used, 300 tags; `ExpPoolBigEntriesInUse` agrees with the walk exactly. One bound on the record: the counter is read at pointer width though the kernel declares 32 bits — it agreed because the adjacent dword was zero |
| `virtual_map` | **18** slots, 17 assigned; the kernel image in slot **17** typed `MiVaDriverImages` and the PFN database in slot 0 by the kernel's own `Vs.SystemVaType` map — the array is **not** indexed by `_MI_SYSTEM_VA_TYPE` (18 slots, 20 enum values); the big-pool table falls in the region typed `MiVaNonPagedPool`. `SystemVaTypeCount`: **not** a count of 512 GiB slices (slice histogram `[85, 1, 0, 26, 32, 32, 2, 32, 32, 1, 0, 1, 0, 2, 1, 1, 2, 1, 5, 0]` against counts `[0, 0, 0, 0, 2146, 80, 5, 269, 2399, 0, 0, 71, 0, 33, 0, 0, 0, 2044, 0, 0]`); every `DynamicBitMap<Type>` gives 2 MiB per bit (region bytes / `MaximumSize`), five types equal their bitmap's set bits exactly, system PTEs (2,399 vs 2,066) and non-cached mappings (5 vs 1) exceed it and equal their present page-directory entries (one-off page-table walk), none falls below; the non-paged pool (2,146) has no bitmap and is unchecked |
| `hive_cell_routines` | **38** hives, every `GetCellRoutine` / `ReleaseCellRoutine` at `HvpGetCellPaged` / `HvpReleaseCellPaged` +0, none outside the kernel |
| `version_info` | **767** images over the kernel and five processes: 561 read, 6 without a resource directory, **150 discarded** (`IMAGE_SCN_MEM_DISCARDABLE` — the kernel's own case; the bytes at its resource directory are code), 50 unreadable, 0 malformed. Every Windows binary's product version is 10.0.**26100**.x under a kernel stating build **26200**: 25H2 is an enablement package over 24H2 binaries, and a reader comparing the two must not read tampering into it |
| `mbr_scan` | 10,737,418,240 bytes scanned, **14** candidates, exactly **1** well-formed: the GPT protective MBR at physical `0x1b5e49000`, one `0xEE` entry from LBA 1 declaring `0xFFFFFFFF` sectors — Windows writes the UEFI "or 0xFFFFFFFF" form on a 64 GiB disk, not size-minus-one |
| `scheduled_tasks` | **246** tasks from the in-memory `SOFTWARE` hive, every `Actions` blob decoding whole, every `DynamicInfo` 36 bytes; 2 tasks with a paged-out value reported incomplete (`\SeanceTestBeacon` is one of them); the planted task decodes to `powershell.exe` / `-w hidden -c exit`, author `FORENSIC-W11\analyst`, created 2026-08-06T19:04:27Z, never run. `Triggers`: all **246** blobs resident and decoding to their last byte, 279 triggers — 148 WNF, 47 time, 32 logon, 21 boot, 12 event, 11 session change, 4 idle, 4 registration; the planted task's one trigger is a time trigger, localized start `2026-08-06T20:08:00`, repeating every 3,600 s (`/sc hourly`), enabled. This grades the decode's self-consistency (every byte accounted for) and the one planted answer; the per-task comparison against the disk's `System32\Tasks` XML is not yet made |
| `truecrypt` | no `truecrypt.sys` / `veracrypt.sys` among **155** modules, list complete, no sweep. The positive path is graded on a second capture (`MEM-VC-1` below); the driver's key container is decoded from that capture's layout (`MEM-VC-2`) |

**Also pinned:** Windows discovery refuses an image whose acquisition
header states a non-Intel machine as `DiscoveryError::UnsupportedArchitecture` before any
DTB sweep (`automagic.rs`; the test stamps an ARM64 crash-dump layer over otherwise
discoverable x64 bytes). A raw image states no architecture and is swept as before.

**Re-run.** `CARGO_BUILD_JOBS=3 cargo test -p seance_plugin_memory_windows --release
--test win11_kernel_dumps -- --test-threads=1` (`SEANCE_WIN11_MEMORY` and
`SEANCE_SYMBOL_DIRS` override the paths). Absent the capture, each test prints that it is
skipping.

### CON-1 — console command history against a recorded known answer, 2026-09-30

**Image.** `~/win11-lab/console/mem.raw` (`SEANCE_WIN11_CONSOLE_MEMORY`), 10,737,418,240 bytes,
SHA-256 `213397612ac3668bfed09474a21d28772e98cbfae6557f0fca2bc4a37af4d567`: the corpus VM (Windows 11
build 26200.6584, 8 GiB) captured through QMP `dump-guest-memory` from a copy-on-write overlay, while an
interactive `cmd.exe` (`ssh -tt analyst@guest cmd.exe`, served by the legacy `conhost.exe`) held five typed
commands. **Ground truth** is `GROUND-TRUTH.txt` beside it, written before the capture: `tasklist` at capture
(`cmd.exe` 5080; `conhost.exe` 2028, 5360, 5160 and 6136) and the five commands in order
(`echo SEANCE-CMD-ONE-4417`, `hostname`, `echo SEANCE-CMD-TWO-9082`, `dir C:\Users`,
`echo SEANCE-CMD-THREE-5560`).

**What is graded, and it passes** (`seance_plugin_memory_windows/tests/win11_console_history.rs`, release only):
the console hosts found on the process list are exactly pids 2028, 5160 and 5360 (6136 was the probe running
`tasklist` and had exited); `cmd.exe` 5080 and its parent `powershell.exe` 5136 are listed as clients; **exactly one
history is found in the whole image**, in host 5160's heap, application `cmd.exe`, command limit 50, five commands,
**equal to the typed list in order**, none unreadable, record complete. Every host is swept. Host 5160: 46,882,816
bytes swept in 36 ranges, 46,055,424 not resident, 0 paged out, 155,648 unreadable, each stated on the record.
**Negative control:** `test_data/win11_bitlocker/memory-unlocked.raw` holds no console host and no console client; the
stage reports no hosts and says it is not evidence that nothing was typed.

**Bounds.** One build of the host; the layout was derived here from this capture and the same capture is the
grade, so a second build is the thing that would move the claim — nothing here says the layout holds on another.
`OpenConsole.exe` (Windows Terminal) was not captured, so a modern-terminal host is unverified. Order is the
order stored, oldest first here; it is not asserted for a wrapped history. `consoles` (screen output) is not read.

**Re-run.** `cargo test -p seance_plugin_memory_windows --release --test win11_console_history -- --nocapture`;
without the capture the test prints that it is skipping. Unit suite: `console_history_tests.rs` (synthetic,
ten tests).

### MEM-VC-1 — VeraCrypt's master keys in a capture with a volume mounted, 2026-09-30

**Evidence.** `~/win11-lab/vc/mem.raw` (not in
the repository): the corpus VM (Windows 11 build 26200.6584, 8 GiB) captured through QMP `dump-guest-memory` while
a VeraCrypt 1.26.29 volume (MSI from the release, SHA-256 checked against its `sha256sum.txt`; AES, SHA-512,
NTFS, 20 MiB) was mounted as `X:`. **Ground truth is independent of this crate:** the container's header was
decrypted on the host (PBKDF2-HMAC-SHA512, 500,000 iterations, AES-256-XTS, from the recorded password); it reads
`VERA`, and yields the two 32-byte master keys. A plain byte search of the raw capture finds each key exactly once.

**What is graded, and it passes** (`seance_plugin_memory_windows/tests/win11_veracrypt.rs`, release only):
`veracrypt.sys` is on the module list; the sweep of the 167,153,664-byte `MiVaNonPagedPool` region reports nine
verified AES schedules, and the SHA-256 digests of **both** master keys are among them, at 5,312 bytes apart and
listed as a possible XTS pair. **Two findings:** (1) the XTS pair distance bound is 8,192 bytes, set from this one
observation and therefore tuned on it; (2) the sweep also reports
the VM's BitLocker key schedules (two pairs), and does not tell them from VeraCrypt's. The stage's own record
stays `content_complete: false` because most of the virtual-map region was never mapped.

**Bounds.** One volume, one version (1.26.29), AES only, one mount; no Serpent/Twofish/Camellia/Kuznyechik or
cascades, no TrueCrypt 7.x, no system-encrypted volume. The `CRYPTO_INFO` container is decoded in `MEM-VC-2`.
**Re-run.** `cargo test -p seance_plugin_memory_windows --release --test win11_veracrypt -- --nocapture`; without
the capture the test prints that it is skipping.

### MEM-VC-2 — the VeraCrypt driver's container read from the same capture, 2026-10-20

**Evidence.** The `MEM-VC-1` capture, `~/win11-lab/vc/mem.raw` (not in the repository; SHA-256
`8590ad53b066a72ffd55f650e960ddf3dffff85dfc14dc5753099498787b2403`), and its ground truth
`~/win11-lab/vc/GROUND-TRUTH.txt` and `masterkeys.hex`: VeraCrypt 1.26.29, AES, SHA-512, XTS, header decrypted on
the host to `VERA`. **Clean-room.** No VeraCrypt or TrueCrypt source was read or copied (its licence is not MIT, BSD or
public domain); the layout was read from the bytes around the two key schedules, whose physical positions
(`0x232ee7010`, `0x232ee84d0`) the host search had already fixed.

**What the bytes show.** The primary schedule sits 0x10 bytes into its allocation, which starts on a page: the
three dwords before it read `1, 1, 1`, and the secondary schedule sits 5,312 bytes after the primary. The allocation
holds the schedules inline, not by pointer. The primary schedule is the first 32 bytes of `masterkeys.hex` and the
secondary the last 32, which is the order the header decrypts to. Two dwords are published: the cipher id and the
mode id, and only the value observed is named (`1` is AES, `1` is XTS), because the ground truth is AES in XTS and
no other cipher or mode was captured. Any other id is published raw and unnamed. The third dword and the rest of the
allocation (including a value equal to the 500,000 PBKDF2 iterations) are not decoded and not published.

**What is graded, and it passes** (`win11_veracrypt.rs`, release only): exactly one container is decoded on the
capture, at `schedule - 0x10`, with cipher AES, mode XTS, primary equal to the schedule hashing to `PRIMARY_SHA256`
and secondary to `SECONDARY_SHA256`. The two BitLocker pairs the sweep also infers get no container, which is the
check that the header test does reject. Unit suite: `truecrypt_tests.rs`, five container tests on **synthetic**
FIPS-197 images in the observed shape; they grade the decoder's mechanics only, the two positive
tests failed against a stub that decoded nothing; the negatives (secondary not a schedule, id zero or out of range,
no room for a header) pass against the stub too and guard the decoder only against later loosening.

**Bounds.** One build (26200.6584), one version (1.26.29), AES only, one volume. The layout differs between
VeraCrypt versions and was not checked against any other; a cascade or a non-AES volume was not captured, and the
decoder looks only for AES-256 schedules 5,312 bytes apart, so it would yield no container for a different spacing. The id range is a sanity bound (1 to 255), not a list of valid ciphers.
**Re-run.** `cargo test -p seance_plugin_memory_windows --release --test win11_veracrypt -- --nocapture`;
`cargo test -p seance_plugin_memory_windows --lib truecrypt`. A second capture with Serpent or a cascade is the
way to widen this.

### MEM-VC-3 — a second VeraCrypt version, two volumes at once, and a Serpent and a cascade volume, 2026-10-22

**Evidence:** a Windows 11 25H2 capture from the Séance corpus VM with **VeraCrypt 1.25.9** installed from `VeraCrypt_Setup_x64_1.25.9.msi` (SHA-256 `206d31c2...b24fd8`, equal to the
release's `veracrypt-1.25.9-sha256sum.txt`) and two AES / SHA-512 / NTFS volumes, `a.hc` and `b.hc` (20 MiB), mounted as `X:` and `Y:` together; the memory was dumped through QMP
`dump-guest-memory` (ELF) and converted with `elf2raw.py`: `forensic_corpora/lab_win11_veracrypt_1259/` (`mem.raw`, the volumes and their keys). **Ground truth:** each header decrypted on the host
with `scripts/oracle/vc_header_keys.py` (PBKDF2-HMAC-SHA512, AES-256-XTS, the `VERA` magic and the master-key area's CRC-32), which reproduced the pinned digests of the 1.26.29 volume first; the keys' SHA-256
digests are pinned in `win11_veracrypt_1259.rs`.

**Result.** The sweep reports all four master keys (two per volume) and infers both pairs. The container layout differs from 1.26.29. Read from the bytes (no VeraCrypt source was
read): in 1.25.9 the primary schedule sits **0x0c** into its allocation, not 0x10, with the three dwords `1, 1, 1` directly before it, and the secondary **5,304** bytes after it, not 5,312. `decode_crypto_infos`
holds both layouts, one per capture, and publishes which one a container matched (`layout`: `VeraCrypt 1.26.29 (observed)` or `VeraCrypt 1.25.9 (observed)`).
Both volumes decode on the new capture and the 1.26.29 capture still decodes, with its label (`win11_veracrypt_1259.rs`, `win11_veracrypt.rs`; a synthetic layout test, `a_container_in_the_1_25_9_layout_is_decoded_and_names_its_layout`).

**A Serpent volume and an AES-Twofish-Serpent cascade** (`c.hc` password `SeanceVC-C-1129`, `d.hc` password `SeanceVC-D-6650`; `forensic_corpora/lab_win11_veracrypt_ciphers/`, mounted together on the same VM, 10 GiB capture). A scan
for AES only finds 5 AES schedules, one XTS pair and no container, and no key of the other ciphers. **Ground truth:** `scripts/oracle/vc_header_keys_all.py` decrypts a header of any cipher or cascade on the host (PBKDF2-HMAC-SHA512,
XTS under Serpent from `pyserpent`, Twofish from Niels Ferguson's C library and AES from `cryptography`, every ordering tried until the header reads `VERA` with a matching CRC-32 of its key area): `c.hc` is Serpent; `d.hc` decrypts as AES, then Twofish, then Serpent,
with the key area holding every cipher's primary key and then every cipher's tweak key, in the reverse order. That gave eight master-key digests (pinned in `win11_veracrypt_ciphers.rs`), which also showed that the one XTS pair of an AES-only scan, `0b83...`/`0680...`,
was the cascade's **AES layer**, not its Serpent. **What the memory holds:** a Serpent schedule is Gladman's 140 words starting with the raw key (equal, word for word, to `pyserpent`'s on the real memory); a Twofish schedule is **not** the key but the four 1,024-word S-box
tables (VeraCrypt's `mk_tab`, found equal to the tables computed from the Twofish paper for the S vector taken in reverse) followed by the 40 subkeys, so the key is recovered by inverting the key schedule from the subkeys
(`seance_bulk::twofish::recover_key`: MDS inverted, each byte lane of `h` solved for its four key bytes; checked on twelve keys against the reference library) and the whole structure recomputed and compared; in a cascade the schedules lie one after another from the
buffer's start, Serpent (560 bytes), Twofish (4,256), AES, with the tweak keys' copy 5,304 bytes on, under the header `[id, mode, 1]` with id 2 for the Serpent volume and 8 for this cascade.
**Result.** The sweep finds **all eight** master keys by hash (`c.hc` Serpent primary and tweak; `d.hc` Serpent, Twofish and AES primary and tweak, the Twofish ones recovered from their schedules) and decodes both containers with every layer's keys
(`win11_veracrypt_ciphers.rs`, 2.8 s for the 234 MiB pool). **Counter tables.** Tables of counters (distinct low bytes, like an S-box table) pass a shape-only Twofish check and send the key recovery down a 51 s path; the table's own
algebra (each word is MDS column 0 times one byte) is checked first (2.8 s; `a_table_of_counters_is_rejected_before_any_key_recovery`).

**The remaining AES/Serpent/Twofish containers, same VM** (`forensic_corpora/lab_win11_veracrypt_cascades/`, 10 GiB capture, five volumes mounted together: `e.hc` Twofish, `f.hc` AES-Twofish, `g.hc` Serpent-AES, `h.hc` Twofish-Serpent, `i.hc` Serpent-Twofish-AES;
passwords `SeanceVC-E-4471` to `SeanceVC-I-8815`; `AES(Serpent)` and `Serpent(Twofish)` are not cascades VeraCrypt offers). The host oracle decrypted all five headers (the cascade key area is every cipher's primary key then every cipher's tweak key, in the reverse order of the
decryption), and the sweep finds **every key of all five volumes** and decodes **all five containers** (`win11_veracrypt_cascades.rs`, 3.4 s). The header ids are **3** Twofish, **7** AES-Twofish, **9** Serpent-AES, **10** Serpent-Twofish-AES and **11** Twofish-Serpent (with 1 AES, 2 Serpent
and 8 AES-Twofish-Serpent before). The rule the five shapes show: a cascade's schedules lie one after another from the start of the buffer in the **reverse** of the order its name gives (the last-named cipher first), each of the size it has alone (AES 488 bytes, Serpent 560, Twofish 4,256), and the
tweak keys' copy follows 5,304 bytes on. Ids 4 to 6 (the Camellia and Kuznyechik shapes, mounted in `MEM-VC-4`) and above 11 were not mounted here.

**The same seven shapes on VeraCrypt 1.26.29** (`forensic_corpora/lab_win11_veracrypt_1260/`, same VM, 2026-10-22): `s.hc` Serpent, `t.hc` Twofish, `u.hc` AES-Twofish, `v.hc` AES-Twofish-Serpent, `w.hc` Serpent-AES, `x.hc` Serpent-Twofish-AES and `y.hc` Twofish-Serpent,
passwords `SeanceVC-S-1101` to `SeanceVC-Y-7707`, mounted together; the host oracle decrypted all seven headers and the sweep finds every key and decodes all seven containers (`win11_veracrypt_1260.rs`, 4.0 s). The layout is the version's own (header of four dwords, buffer at `+0x10`, tweak keys
5,312 bytes on) and the schedules lie in the same order and sizes as on 1.25.9, but **the ids differ**: Serpent 2 and Twofish 3 as before, then AES-Twofish **6**, AES-Twofish-Serpent **7**, Serpent-AES **8**, Serpent-Twofish-AES **9**, Twofish-Serpent **10**. One id therefore names a different
cipher on each version (7 is AES-Twofish on 1.25.9 and AES-Twofish-Serpent on 1.26.29), which is why each table belongs to its layout.

**Not established:** one OS build; two versions of the product; the cascades with Camellia or Kuznyechik, and those two ciphers alone, were not mounted or recognised;
the host oracle for Twofish is Ferguson's library and its Serpent is Gladman's, the same family VeraCrypt's is derived from. **Re-run:** `cargo test -p seance_plugin_memory_windows --release --test win11_veracrypt_1259 --test win11_veracrypt_ciphers --test win11_veracrypt_cascades --test win11_veracrypt_1260`
(`SEANCE_WIN11_VC1259_MEMORY`, `SEANCE_WIN11_VCCIPHERS_MEMORY`, `SEANCE_WIN11_VCCASCADES_MEMORY`, `SEANCE_WIN11_VC1260_MEMORY`); `cargo test -p seance_plugin_memory_windows --lib truecrypt`; `cargo test -p seance_bulk --lib`.


### MEM-VC-4 - Camellia and Kuznyechik volumes and their cascades on both VeraCrypt versions, 2026-10-22

**Evidence:** two captures on the Windows 11 lab VM, one per version (`forensic_corpora/lab_win11_veracrypt_ck/`, VeraCrypt 1.26.29, and `lab_win11_veracrypt_ck1259/`, 1.25.9; 10 GiB each), with seven volumes mounted together: `p1.hc` Camellia, `p2.hc` Kuznyechik, `p3.hc` Camellia(Kuznyechik),
`p4.hc` Camellia(Serpent), `p5.hc` Kuznyechik(AES), `p6.hc` Kuznyechik(Serpent(Camellia)), `p7.hc` Kuznyechik(Twofish) (passwords `SeanceVC-P1-1111` to `SeanceVC-P7-7777`). **Oracle:** `scripts/oracle/vc_header_keys_all.py` now decrypts a header of any of five ciphers (Camellia by `cryptography`,
Kuznyechik by `gostcrypto`, each checked against its RFC vector before use: RFC 3713 appendix A and RFC 7801 appendix A) and gave every master key of both captures, in every cascade order.

**What memory holds.** A search of each capture for the 32-byte keys: the **Kuznyechik** key is in memory as stored, the first 32 bytes of the cipher's structure, followed by all ten round keys of RFC 7801 (the first 160 bytes are exactly K1 to K10 of the key, checked) and the decryption round keys (320 bytes in all). The **Camellia** key is stored nowhere: its 272-byte table (68 little-endian
32-bit words, 34 64-bit subkeys in RFC 3713 order) holds the six `ke` subkeys as the RFC defines them (`ke1 ke2 = KR <<< 30`, `ke3 ke4 = KL <<< 60`, `ke5 ke6 = KA <<< 77`) and every other subkey with the whitening keys absorbed (the Linux/NTT optimisation: a linear fit over the RFC subkeys of eight tables
fails for ten of the 34 words, which is the FL/FLINV adjustment). The key comes back from the `ke` pairs, and the third pair must equal the `KA` computed from the first two: a 128-bit check. **That is all that is checked of a Camellia table.**

**Result:** every master key of all fourteen volumes is found by hash (`win11_veracrypt_ck.rs`, `win11_veracrypt_ck1259.rs`, 8 s and 4 s), and the seven containers of each version are decoded in buffer order. Ids on **1.26.29**: Camellia 4, Kuznyechik 5, Camellia-Kuznyechik 11, Kuznyechik-Twofish 12, Camellia-Serpent 13, Kuznyechik-AES 14, Kuznyechik-Serpent-Camellia 15. On **1.25.9**: Camellia 4,
Kuznyechik **6**, and the cascades 12, 13, 14, 15 and 16 in the same order: one higher. Sizes: Camellia 272 bytes, Kuznyechik 320; the layout and tweak-key deltas (5,304 and 5,312) are each version's own. The recognisers are graded in `seance_bulk` on the RFC vectors, on twelve keys each against the pure-Python references
(`scripts/oracle/camellia_schedule.py`, which passes the RFC's published ciphertext for the 256-bit key, and `kuznyechik_schedule.py`) and on real tables read out of the captures.

**Not established:** the non-`ke` words of a Camellia table are not verified, so a region that reproduces the three `ke` pairs without being a table cannot be told from one (the check is 128 bits, so by chance it will not); the Kuznyechik decryption round keys are not compared. Camellia and Kuznyechik 128-bit or other key sizes do not exist in VeraCrypt. One OS build; the `ARM`/hardware-accelerated
cipher builds of VeraCrypt (which may lay these structures out differently) were not captured. **Re-run:** `SEANCE_WIN11_VCCK_MEMORY=~/forensic_corpora/lab_win11_veracrypt_ck SEANCE_WIN11_VCCK1259_MEMORY=~/forensic_corpora/lab_win11_veracrypt_ck1259 cargo test --release -p seance_plugin_memory_windows --test win11_veracrypt_ck --test win11_veracrypt_ck1259`;
`cargo test -p seance_bulk --lib`.


### MEM-VC-5 - TrueCrypt 7.1a: eight volumes mounted by the real driver, 2026-10-22

**Evidence:** TrueCrypt Setup 7.1a (`TrueCrypt Setup 7.1a.exe`, 3,466,248 bytes, SHA-256 `e95eca399dfe95500c4de569efc4cc77b75e2b66a864d467df37733ec06a0ff2`, the value published for the release; its detached PGP signature verifies against the TrueCrypt Foundation key, fingerprint `C5F4 BAC4 A7B2 2DB8 B8F8 5538 E3BA 73CA F0D6 B1E0`; fetched from
the `DrWhax/truecrypt-archive` mirror) installed on the Windows 11 lab VM (the UAC prompt shows the verified publisher *TrueCrypt Foundation*; the driver `truecrypt.sys` starts), with eight 20 MiB volumes mounted as `P:` to `W:` by the real driver: AES, Serpent, Twofish, AES-Twofish, AES-Twofish-Serpent, Serpent-AES, Serpent-Twofish-AES and Twofish-Serpent
(`forensic_corpora/lab_win11_truecrypt71a/`, 10 GiB capture, `t1.tc` to `t8.tc`, passwords `SeanceTC-T1-1111` to `SeanceTC-T8-8888`). **How the volumes were made:** `TrueCrypt Format.exe` 7.1a has no command line for creating a volume and its wizard asks for mouse movement, so `scripts/oracle/tc7_make_volume.py` writes the container from the volume format specification with fresh random keys
(PBKDF2-HMAC-SHA-512, 1,000 iterations; magic `TRUE`, header version 5; a cascade applies its ciphers in the reverse of the name's order, each with its own 32 + 32 key bytes); the keys are known by construction and `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back. **The real driver accepted all eight** (and the TrueCrypt window listed their algorithms), which is the
check that the headers are TrueCrypt's.

**What memory holds.** A search for the 32-byte keys shows each master key twice: raw, as an adjacent pair (primary then tweak key, 32 bytes apart) in the container's key area, and inside its expanded schedule. The container begins with two dwords, the **algorithm id** (TrueCrypt's own numbering: 1 AES, 2 Serpent, 3 Twofish, 4 AES-Twofish, 5 AES-Twofish-Serpent, 6 Serpent-AES, 7 Serpent-Twofish-AES, 8 Twofish-Serpent) and the mode (1, XTS);
the schedules follow at `+8` in the reverse of the name's order, and the tweak keys' copy begins 5,324 bytes after the primary. AES and Serpent schedules are the ones already recognised (sizes 488 and 560). **Twofish is laid out differently from VeraCrypt**: `l_key[40]` first, then `s_key[4]` (S reversed), then `mk_tab` with the four tables interleaved (entry `x` of table `j` at word `4x + j`; 40 + 4 + 1,024 words
plus `k_len`, 4,276 bytes); the tables are VeraCrypt's, word for word, interleaved (956 of 956 words read from the capture agree with `twofish_schedule.py`). `seance_bulk::twofish::verify_tc_schedule_at` recognises it (a VeraCrypt-order structure is not taken for it, nor the reverse; a page of zeros passes the table-shape test, so the permutation check the VeraCrypt reader has is applied first).

**Result:** every master key of the eight volumes is found by hash and all eight containers are decoded with their layers in buffer order (`win11_truecrypt71a.rs`, 11 s), `layout: "TrueCrypt 7.1a (observed)"`; synthetic container tests pin the id table and the Twofish layout; the VeraCrypt captures still pass.

**Not established:** other TrueCrypt versions (7.0, 7.0a, 7.1, 7.2 and the 6.x line): only 7.1a was installed, so another version's structure is read only if it matches, and nothing says it does; the data areas of these volumes are random, so no file system was ever read through the driver (the memory evidence is the key material). **Re-run:**
`SEANCE_WIN11_TC71A_MEMORY=~/forensic_corpora/lab_win11_truecrypt71a cargo test --release -p seance_plugin_memory_windows --test win11_truecrypt71a`; `cargo test -p seance_bulk --lib twofish`.

### HIB-1 — the hibernation reconstruction measured against its ground truth, 2026-09-19

**Image.** `~/win11-lab/hiber/hiberfil.sys` (`SEANCE_WIN_HIBERFIL`),
8,499,130,368 bytes, Windows 11 build 26200, full hibernation, decrypted from a BitLocker
volume; and the Server 2012 R2 file (`SEANCE_WIN_HUFFMAN_HIBERFIL`). Ground truth for the
first: before hibernating, the guest ran `marker.ps1`, which committed a 256 MiB buffer and
wrote `"HIBRMARK"` + `le64(i)` at offset 0 and `le64(i)` at offset 2048 into each of its
**65,536** pages (`GROUND-TRUTH.txt` beside the file states those three fields and nothing
about the other bytes; that they are zero is measured, not quoted).

**Format facts the reconstruction rests on.** The packed table header's compressed-size field is
**21 bits**, not 22. Bit 29 is a flag, set on 15,326 of the 31,969 kernel tables (first at byte
33,609,845, header `0x60179002`; read as size it gives 2,103,184 and steps the walk into compressed
data; read as a flag the size is 6,032 and the next table sits exactly at 33,615,897). On the NT10
layout bit 30 marks **Xpress-Huffman** (30,479 kernel tables); bit 30 is plain `XpressMax` only on
NT6.2/6.3, where Huffman is bit 31. `xpress::decompress` does not skip back-references reaching
before the output: a block yields every byte of its pages or is a counted gap. The boot set's stop
is not a defect. 2,501 tables describing 40,004 pages is exactly `NumPagesForLoader` at header
offset `0x58`, and a restore set has no terminator, so the only ground for calling a set complete
is that its described pages equal the header's count. That is what is checked and recorded on the
layer.

| | 26200 corpus | 2012 R2 corpus |
|---|---|---|
| boot set: tables / pages / header count | 2,501 / 40,004 / 40,004 (`0x58`) | — / 16,664 / 16,664 |
| kernel set: tables / pages / header count | 31,969 / 511,499 / 511,499 (`0x238`) | 7,097 / 113,548 / 113,548 |
| restored | 551,503 pages, **2,258,956,288** bytes | both sets complete |
| marker pages present and byte-exact | **65,536 of 65,536** | — |
| `HIBRMARK` strings over the reconstruction | **131,110** = 2 × 65,536 (each marker page at exactly two physical addresses, both placed by the kernel set) + 38 inside other pages (seven of the eight inspected are the marker script's own source) | — |
| the same rule over the compressed file | 863, at offsets that cannot be placed in the machine | — |
| peak RSS of the two-pass walk | 2.23 GB | — |

The shipped pattern scan over the reconstruction **hits its 100,000-match ceiling** and
says so (`truncated`, `complete: false`, the ceiling named) rather than reporting a count;
the 131,110 figure is from the pass with the ceiling raised. The bytes after the kernel
set's end are **not** a zero run (16,025 of the 16,147 bytes to 543,244,288 are non-zero,
at 7.98 bits per byte); what that tail is was
not established and is not asserted. Pinned by `seance_memory/tests/hibernation_corpus_test.rs`
(`the_win11_corpus_restores_both_sets_to_the_page_counts_its_header_states`,
`the_win11_corpus_marker_pages_are_byte_exact_and_their_number_is_stated`,
`the_win11_corpus_holds_each_marker_page_twice_and_the_string_count_is_accounted_for`,
`the_2012r2_corpus_restores_both_sets_to_the_page_counts_its_header_states`) and by
`seance_plugin_memory_windows/tests/win11_corpus_analysis.rs`
(`an_examiners_rules_search_a_reconstructed_hibernation_file`, re-pinned to the ceiling
and the 2,258,956,288 restored bytes). `seance_memory/tests/KNOWN_ANSWERS.md` carries the
same figures.

### LIN-MEM-1 — paths, command lines and hooks on the two Linux lab captures, 2026-09-19

**Evidence not held.** The `~/linux-lab` and `~/noble-lab` captures are not held. Every `SEANCE_LINUX_SWAP_MEM` and `SEANCE_LINUX_NOBLE_MEM` test, and the jammy and noble rows of `free_space_distribution`, skip. The figures below are the record of what they measured. They cannot be re-run without rebuilding the guests.

**Images.** `~/linux-lab/mem.raw` (Ubuntu 22.04, kernel 5.15, the project-built KVM guest
with ground truth; `SEANCE_LINUX_SWAP_MEM`) and `~/noble-lab/mem.raw` (Ubuntu 24.04,
kernel 6.8; `SEANCE_LINUX_NOBLE_MEM`), each profiled from its own BTF and `kallsyms`
recovered from the image. The Oberon 6.8 capture was not used: its `PROVENANCE.md` forbids
fixtures derived from it, and the two guests cover both kernel generations.

**What is graded** (`ROADMAP` §4.2; `seance_plugin_memory_linux/tests/paths_real_capture_test.rs`
and `hooks_real_capture_test.rs`). Every assertion is against a fact established without the
code under test:

| Known answer | Graded against | Capture |
|---|---|---|
| PID 1's descriptors 0–2 read **`/dev/null`**, one mount crossed (devtmpfs under `/`), the walk ended at the process root; the old in-mount walk gave `/null` | a property of `systemd`, and a separate mount | 5.15 |
| every mount-crossing path begins with a mount point the mount list independently knows; the mount list shows `/dev/pts` as an absolute mount point | `mnt_namespace.list`, a different structure from the `f_path.mnt` chain | 5.15 |
| 158 sockets, 3 pipes, 70 anonymous inodes rendered as `socket:[ino]` / `pipe:[ino]` / `anon_inode:<name>` under `path_scope: pseudo`, 0 unresolved (counts observed and printed; the test asserts each form and that sockets > 10, pipes > 0, anonymous inodes > 0) | the kernel's own `d_dname` forms | 5.15 |
| `journald`'s memory map reads `/run/systemd/journal/kernel-seqnum` across a mount | the mount list | 5.15 |
| the workload's command line is `["/usr/bin/python3", "/tmp/swaptest.py"]`, well formed, `argv_rewritten: Some(false)`, nothing short | its NUL-joined bytes found by a **raw byte scan** of `mem.raw` with no page tables and no structures | 5.15 |
| 19 of 19 tasks with user memory (of 117 tasks) yield a command line, survey complete; kernel threads are not gaps | the task list's own `mm` field | 5.15 |
| `sys_call_table`: **449** entries at kernel symbols + 3 trailing nulls (padding); **462** + 2 on 6.8; 0 hook candidates on either; the `x64_sys_call` caveat stated on 5.15 (a BHI backport carries the symbol) | the kernel's `__NR_syscalls` | both |
| **12** eBPF programs (5.15) and **13** (6.8), each `aux->id` equal to its `prog_idr` index; on 6.8 named as systemd's `sd_devices` / `sd_fw_egress` / `sd_fw_ingress` and the kernel's `hid_tail_call` TRACING program, which explains the one `ftrace` direct call there; 0 unexplained direct calls | `bpf_prog_aux.id` vs the xarray slot; systemd's own program names | both |
| module text extents read from `module.mem[MOD_TEXT]` on 6.8 — at the index the image's own `mod_mem_type` gives, so no assumed index is stated | struct-module geometry: a `struct module` lies in its data extent, never in the extent read as text | 6.8 |

The socket and pipe tallies are observed and printed, and the test asserts the forms and
floors above. The hook counts are asserted exactly: the test pins
449 / 462 kernel-symbol entries — the kernels' own `__NR_syscalls` — 3 / 2 padding nulls,
12 / 13 programs and the four 6.8 program names, the last three as regression pins read
from the captures, with a `CGROUP_` type, 0 unexplained direct
calls and the geometry; a re-profiled guest that loads a different number of programs will
fail on the count, and that is intended. What the hook stage does **not** check is on every record and in
`LINUX_DESIGN.md`: no kernel-text diff against a pristine copy, no perf-event walk, no
`dyn_ftrace` walk, no BPF-trampoline decode.

**Re-run.** `SEANCE_LINUX_SWAP_MEM=~/linux-lab SEANCE_LINUX_NOBLE_MEM=~/noble-lab
CARGO_BUILD_JOBS=3 cargo test -p seance_plugin_memory_linux --release --test
paths_real_capture_test --test hooks_real_capture_test -- --nocapture`. Absent a capture
each test prints that it is skipping.

### LIN-MEM-2 — enumerations and `module.mem[]` on the two Linux lab captures, 2026-09-23

**Images.** The two guests of LIN-MEM-1, each profiled from its own BTF and `kallsyms`; and,
for the BTF conversion alone, `vmlinux.btf` from the `SEANCE_LINUX_MEM` corpus (a copy of
`/sys/kernel/btf/vmlinux` from an Ubuntu `6.8.0-1061-aws` host — a blob the kernel wrote,
not a capture-derived fixture).

**What is graded** (`seance_memory/tests/btf_symboltable_test.rs`,
`seance_plugin_memory_linux/tests/lsmod_real_capture_test.rs` and
`hooks_real_capture_test.rs`):

| Known answer | Graded against | Capture |
|---|---|---|
| `module_state` LIVE/COMING/GOING/UNFORMED = 0–3 (unsigned); `mod_mem_type` `MOD_TEXT` = 0, `MOD_INIT_RODATA` = 6, `MOD_INVALID` = −1 (signed); `bpf_prog_type` 8 = `BPF_PROG_TYPE_CGROUP_SKB`; `scsi_cmnd_submitter` 1 byte wide; `netdev_priv_flags` 8 bytes with `IFF_SEE_ALL_HWTSTAMP_REQUESTS` = 2^33; `energy_perf_value_index`, declared twice with different constants, emitted for neither | `include/linux/module.h`, `include/uapi/linux/bpf.h`, and `bpftool btf dump file vmlinux.btf` — a second reader of the format | `vmlinux.btf` |
| `autofs4` is in the module list | each guest's serial console, written during the captured boot: `systemd[1]: Inserted module 'autofs4'` | both |
| every listed module's state is 0 and named `MODULE_STATE_LIVE` from the image's own enumeration (54 modules on 5.15, 51 on 6.8, printed) | `include/linux/module.h`; guests idle at the login prompt | both |
| every module's `mem[]` decoded: `core_base` = `mem[MOD_TEXT].base`, `core_size` = the sum of the non-init regions, init sizes read (0 — the kernel zeroes them after init), the `struct module` outside its `MOD_TEXT` region | struct-module geometry | 6.8 |
| every eBPF program's type named from the image's own `bpf_prog_type`, and no `MOD_TEXT` index assumed | the table's own enumeration | 6.8 |

No `lsmod` listing was taken inside either guest before acquisition, so the module list is
not graded for completeness; the region sizes are not graded against the guest's `.ko`
files.

**Re-run.** `SEANCE_LINUX_MEM=~/forensic_corpora/oberon_linux_swap cargo test -p
seance_memory --release --test btf_symboltable_test`, and `SEANCE_LINUX_SWAP_MEM=~/linux-lab
SEANCE_LINUX_NOBLE_MEM=~/noble-lab cargo test -p seance_plugin_memory_linux --release --test
lsmod_real_capture_test --test hooks_real_capture_test -- --nocapture`.

### SIGNAL-IOS-1 — SQLCipher 4 raw-key decryption of the iOS Signal store, 2026-09-23

The Magnet 2022 iPhone 8 image holds Signal's `signal.sqlite` (SQLCipher 4, raw
48-byte key spec, HMAC-SHA512, plaintext 32-byte header) and, in its keychain export, the key.
`seance_sqlcipher::decrypt_v4_raw_key` and `decrypt_v4_raw_key_wal` were graded against it:

| Measured | Against |
|---|---|
| all 305 pages and all 38 WAL frames authenticate; SQLite's `integrity_check` on the decrypted file returns `ok` | the store's own HMACs, and SQLite |
| `keyvalue` 1,980 rows in the main file, 1,981 with the WAL; `MessageSendLog_Payload` 6 and 8 | an independent Python decryption opened with the system `sqlite3` |
| 16 of the 21 pages in the WAL are newer than the main file's copy | — the WAL changes the answer |
| a wrong key is refused | — |
| `model_TSInteraction` holds 0 rows | this store holds no messages |

The key is read from the keychain plist at run time and written nowhere. What this does **not**
establish: WAL frames after the last commit are counted, not decrypted.

**The parser end.** The key spec reaches the Signal parser for one
file through the credential route, and the parser reads Signal-iOS's GRDB schema.
`seance_plugin_signal/tests/ios_grdb.rs::the_real_ios_store_opens_with_its_key_spec_and_its_grdb_schema_is_read`
hands the same store and spec to `SignalParser` as a case would: 305 pages and 38 committed WAL
frames authenticate, 84 `grdb_migrations`, 1 conversation, 1 contact, 0 messages, and every
column the reader resolves is present; a spec with one digit changed is rejected. Because the
store holds no messages, the schema is graded **structurally** and the records say so. Same
provisioning; `SEANCE_REQUIRE_CORPUS=1` turns the skip into a failure.

**Re-run.** `SEANCE_IOS_SIGNAL_DIR=<directory holding signal.sqlite, its -wal and the keychain
plist> cargo test -p seance_sqlcipher --test signal_ios_real_store -- --nocapture`. Absent the
directory the test prints that it is skipping.

### RDP-1 — outgoing RDP (`Terminal Server Client`) on three real user hives, 2026-09-24

Each hive was handed to `RegistryParser::process` as the NTFS pipeline
hands it over (a `FileEntry` named `NTUSER.DAT`, the file as its data source) and every
`RdpDestinationEntry` compared against a stand-alone Python `regf` walker that shares no code with
`seance_hive`.

| Hive | Independent reading | Séance |
|---|---|---|
| DFIR Madness Case 001 DC01 `Users/Administrator/NTUSER.DAT` (inode 84874; dirty, logs not taken) | `Default\MRU0 = DESKTOP-SDN1RPT`, key FILETIME 132449611339934009; `Servers\DESKTOP-SDN1RPT\UsernameHint = C137\Administrator`, key FILETIME 132449601855804446 | one record: host, `mru_position` 0, `username_hint`, `mru_key_last_written` 2020-09-19T03:52:13.9934009Z, `servers_key_last_written` 2020-09-19T03:36:25.5804446Z, each with its key's scope; `replay.hive_dirty: true` — **all agree** |
| CFReDS winreg `Win_7_IE09_(CFReDS)/…/Users/CFTT/NTUSER.DAT` (clean) | `Default` holds no `MRUn`; `Servers\10.11.11.127\UsernameHint = MSEDGEWIN10\cfreds-server1`, 131226613999287109 | one record, no invented MRU entry — **agrees** |
| CFReDS winreg `Win10_10586_IE11+Edge_(CFReDS)/…/Users/CFTT/NTUSER.DAT` (clean) | `Servers\10.11.11.127\UsernameHint = cfreds-server1`, 131234752294946052; no `MRUn` | one record — **agrees** |

Fields compared: host, MRU position, `UsernameHint`, key path, key last-written time to the
100 ns, hive-dirty state, record count. **Key scope.** Each record names the key its time
belongs to: a `Servers\<host>` key is that destination's own (DC01's is 16 minutes older than its
`Default`), and `Default` is the Terminal Server Client key
(`each_rdp_record_names_the_key_its_time_belongs_to`). What this does **not** establish: the
`CertHash` value and any `MRU1+` ordering (no held hive has them).

**Join by host.** `Default\MRUn` values and `Servers\<host>` keys are joined by host
(case-insensitive) into one record carrying both keys' paths and times, each labelled with its key.
The three hives: DC01 one record with every field above, each CFReDS hive one Servers-only record
(`in_mru_list: false`, the MRU key fields null) — **all agree**
(`an_rdp_destination_in_both_keys_is_one_record_carrying_both` and the two
`real_hive_tests::rdp_*`). Not established: the join is on the name as typed, so an IP address and
a host name for one machine stay two records.

**Port normalisation.** An explicit `:3389` (the client's default port) is treated as no port,
case-insensitively, so `host` and `host:3389` join; a non-default port stays its own destination.
None of the three hives stores a port, so their figures do not move: each record's `destination` is
its host lower-cased (`desktop-sdn1rpt`, `10.11.11.127`) and every record carries
`ip_to_name_join_attempted: false` — the CFReDS destination is an IP address, and nothing in the
hive ties it to a name. The port normalisation itself is graded only on a synthetic capture
(`an_rdp_join_treats_the_default_port_as_the_same_destination`: without it the join gives six
records for `fileserver:3389`, `FILESERVER`, `fileserver:3390`, `[FE80::1]:3389`, `10.0.0.5` and a
`Servers\[fe80::1]` key where four are right); no held hive stores `host:3389`.

**Re-run.** `SEANCE_RDP_DC01_NTUSER=<DC01 hive> SEANCE_RDP_CFREDS_WIN7_NTUSER=<…>
SEANCE_RDP_CFREDS_WIN10_NTUSER=<…> cargo test -p seance_plugin_registry real_hive_tests`. Each
variable is the file's path; unset skips loudly, set-but-missing fails.

### BAM-1 — BAM per-SID decode on three real Windows 10 `SYSTEM` hives, 2026-09-24

The same path as `RDP-1`, the same independent walker, over every `bam`/`dam` `UserSettings` key in
every control set:

| Hive | Layout | SIDs | Executions | Agreement |
|---|---|---:|---:|---|
| DFIR Madness Case 001 desktop | `bam\State\UserSettings` | 9 | 62 | 62 of 62 identical |
| BelkaCTF 6 | `bam\State\UserSettings` | 3 | 27 | 27 of 27 identical |
| LoneWolf (Windows 10 1803) | `bam\UserSettings` | 4 (two with none) | 28 | 28 of 28 identical |

Fields compared per execution: control set, service, SID, value name (target), value length,
last-executed FILETIME to the 100 ns, the 16 trailing bytes, and the SID key's last-written time;
per SID key: value count and execution count (`Version` and `SequenceNumber` excluded). All 24-byte
values decode (`decoded`), and each hive's `dam` key is reported present with no `UserSettings`.
LoneWolf's `cmd.exe` at 2018-04-05T02:05:02.333385Z — the time the synthetic fixture in
`bam_tests.rs` was derived from — is read off the hive. On the Windows XP `SYSTEM` hive, which
holds no `Services\bam` key, the stage states that the hive holds no BAM rather than falling
silent.

**Current control set.** `Select\Current` is a `REG_DWORD` the walk renders as `0x00000001 (1)`,
and the reader parses that form, so `is_current_control_set` is true for the set the machine
booted (`select_current_is_read_from_the_dword_as_the_walk_renders_it`). Not established: a
populated `dam` key (none held), and a hive with two control sets holding BAM.

**Re-run.** `SEANCE_BAM_CASE001_DESKTOP_SYSTEM`, `SEANCE_BAM_BELKA6_SYSTEM`,
`SEANCE_BAM_LONEWOLF_SYSTEM` (each a `SYSTEM` path) `cargo test -p seance_plugin_registry
real_hive_tests`.

### SNT-1 — a real Windows 7 `StickyNotes.snt`, 2026-09-24

For the `.snt` format only. The file is the NIST CFReDS Data Leakage case's
`Users/informant/AppData/Roaming/Microsoft/Sticky Notes/StickyNotes.snt` (inode 22108, 4,096
bytes, SHA-256
`6ccbffc4e978aafeb950ca5d87a413f96435514ca16d6be5508ed68df071b7b2`), run through `StickyNotesParser::process`, against 7-Zip's
compound-file listing (`7z l -slt`, `7z x`), the RTF stream read by hand, and the note's own
UTF-16LE plain-text stream `3`.

| Field | Independent reading | Séance |
|---|---|---|
| root streams | `Version` (4 B), `Metafile` (294 B) | the same, listed on the coverage record |
| note storages | one, `ccbb72fb-d253-11e4-b` | one, same name |
| storage created / modified | 2015-03-24 18:31:17.026 / 18:31:17.058 | `2015-03-24T18:31:17.026+00:00` / `…17.058+00:00` |
| streams | `0` 490 B (RTF), `1` 10 B, `3` 88 B | the same; text taken from `0` |
| text | RTF: `Tomorrow...\par \par Everything will be OK...\par \par \lang9\f1\par }` then `\r\n\0`; stream `3`: `Tomorrow...␍␊␍␊Everything will be OK...␍␊␍␊` | `Tomorrow...\n\nEverything will be OK...\n\n\n` |

**RTF terminator.** Only line ends, blanks and NULs after the outermost closing brace are
dropped, so the stored NUL terminator is not a trailing U+0000 in the note's text
(`nothing_after_the_outermost_group_is_text`); a stray brace or more text still reads and reports
as before.

The note record carries `source_format: snt_compound_file`.

The `.snt` records carry `validation_state: snt_validated_against_one_real_file`, whose notice
states the bound: one file, one plain-text note. Not established: several notes in one file, an
embedded picture, a Windows 8 or pre-Anniversary Windows 10 file, streams `1` and `Metafile`
(listed, not interpreted). A `plum.sqlite` at any `user_version` other than 13 is
never-validated and its records keep the never-validated stamp; see `PLUM-1` below.

**Re-run.** `SEANCE_STICKYNOTES_SNT=<path> cargo test -p seance_plugin_stickynotes snt_real`.

### PLUM-1 — a lab-made Sticky Notes 6.1.4.0 `plum.sqlite`, 2026-09-27

For the `plum.sqlite` format. **The evidence is lab-made, not a public or seized
image**: no public image with a populated `plum.sqlite` could be found, so the real Microsoft
Sticky Notes app, **version 6.1.4.0**, was driven through its own UI on the project's Windows 11
25H2 lab VM (build 26200.6584, local account, no sync) on 2026-09-27. Nothing wrote to the
database but the app. Four fictional notes were made — N1 and N2 typed, N3 pasted (multi-script
Unicode, including U+1F4CC), N4 typed — and N4 was then deleted with the app's own Ctrl+D. The
corpus is `~/forensic_corpora/lab_win11_sticky_notes/`: `SOURCE.md` (provenance, SHA-256 of every
file) and `GROUND-TRUTH.txt` (each note's `Id`, stored and visible text, ticks, and the WAL frame
map), recorded as the notes were made. Three copies of `LocalState`: `running-before-delete/`,
`running-app-copy/` (after the delete, app running) and `after-clean-close/` (app exited).

What the store is, and what the reader does about it:

* **The whole database is in the WAL.** `plum.sqlite` is 4,096 bytes (page 1) in every copy; the
  app never checkpointed, even on a clean close. The module's existing SQLite staging
  (`TempDb::spill`, which copies the file and its `-wal` to a temporary directory and opens the
  copy read-only) already read it; the test also proves the three evidence files are
  byte-identical after the run.
* **Times are .NET ticks in `bigint` columns.** The reader converts them (ticks − 504,911,232,000,000,000 is a
  FILETIME, through `seance_core::time`), with `created_ticks`/`modified_ticks` kept. The guest
  clock ran one hour behind real UTC; the reader reports the file's own value and does not
  correct it (`time_basis` says so).
* **`Text` is one paragraph per line, each prefixed `\id=<guid> `.** `text` has the prefixes
  removed; `text_raw` is the column as stored.
* **A delete leaves no tombstone.** `DeletedAt` is never set; the row is removed. N4 survives as a
  cell in the older WAL images of page 2 (the `Note` leaf), and now comes out as a
  `StickyNoteRecovered` record: `recovery_source: wal_superseded_frame`, the frame (0-based) and
  its byte offset, every frame that held the row, the first later image of the page without it,
  and `deletion_basis` saying the deletion is **inferred** from the row's absence in the latest
  committed state. Frames are decoded by `seance_plugin_sqlite::sqlite_forensic`'s WAL and
  b-tree cell readers.

| Copy | Live notes (expected / read) | Recovered | N4 from |
|---|---|---|---|
| `running-before-delete` | 4 / 4 (N1–N4) | 0 | — (live) |
| `running-app-copy` | 3 / 3 (N1–N3) | 1 (N4) | frame 58, offset 238,992; held in 52, 54–58; absent from 59 |
| `after-clean-close` | 3 / 3 (N1–N3) | 1 (N4) | the same |

Per note, compared exactly: `Id`, rowid (1–4), the visible text and the stored text byte for byte
(N2 four lines; N3 French, Polish, Japanese, Greek, U+2014, U+1F4CC, U+2713), `CreatedAt` and
`UpdatedAt` as ticks and as converted instants to the 100 ns, `DeletedAt` null, theme, and
`user_version` 13. **All agree.**

**The stamp.** A `plum.sqlite` record from a store at `PRAGMA user_version` 13 carries
`validation_state: plum_validated_against_one_lab_made_database`, `validated_against_real_notes:
true`, `validation_evidence: lab_made`, `validated_app_version: 6.1.4.0` and a notice saying the
comparison was one lab-made database and that other versions have not been compared. The app
version is not in the file, so the stamp is keyed on `user_version`; a store at any other
version, or none, keeps the never-validated stamp.

Not established: any other app version or `user_version`; a seized or public database; ink,
images, sync fields and the tables other than `Note`; a deleted note whose WAL frames were
checkpointed and reset away (the bytes then survive only in page free space, which the
recovery does not read); earlier text versions of notes that are still live (edit history, not
reported).

**Re-run.** `cargo test -p seance_plugin_stickynotes plum_real` — the corpus is
`SEANCE_STICKYNOTES_PLUM`, or `~/forensic_corpora/lab_win11_sticky_notes` when that is unset;
absent, the tests skip and say so, and `SEANCE_REQUIRE_CORPUS=1` makes that a failure. The
behaviour is also pinned without the corpus in `plum_tests.rs`.

### WLAN-1 — a real Windows 10 wireless profile, 2026-09-24

LoneWolf's
`ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{4B0AE068-B350-4BD4-85AB-77E00E581863}/{4D7FCC2E-EF1B-4B7B-8143-9514F97A9AE3}.xml`
(inode 92655; 1,271 bytes, CRLF, tab-indented, a `v3`-namespaced `MacRandomization` element) was
run through `WlanProfiles::process` with its path, against the XML read by eye and the
`keyMaterial` blob decoded field by field in Python.

Fields compared, all agreeing: profile name and SSID `Net 2.4` (both the `<name>` and the
`<hex>` `4E657420322E34` forms), `connectionType` ESS, `connectionMode` auto, WPA2PSK / AES,
`useOneX` false, MAC randomisation false, `keyType` passPhrase, `protected` true, interface GUID
from the path, the whole document read with no unread element; and the DPAPI blob — version 1,
provider `df9d8cd0-1501-11d1-8c7a-00c04fc297eb`, master-key version 1, master key
`1fbfafc4-8882-463c-89ee-65cbdc18313a`, empty description, 230 bytes, 16 of ciphertext
(`CALG_AES_256`, `CALG_SHA_512`, which Séance does not publish). The profile's real element order,
namespacing and whitespace, and `keyMaterial`'s uppercase hex, are what the parser expected.

**Master-key file.** The record names the master-key file where Windows keeps it: in this image
`Windows/System32/Microsoft/Protect/S-1-5-18/User/1fbfafc4-…` (inode 90938), not
`System32\Microsoft\Protect\S-1-5-18\{GUID}`
(`the_statement_names_the_master_key_file_where_windows_keeps_it`). Not
established: the passphrase (the blob is not decrypted and no held image pairs a profile with a
known key), an open or 802.1X profile, a hidden network, a non-UTF-8 SSID.

**Re-run.** `SEANCE_WLAN_PROFILE=<path> cargo test -p seance_plugin_wlan real_profile`.

### WMI-1 — a real `CommandLineEventConsumer` in a Windows 7 repository, 2026-09-24

The Data Leakage PC's
`Windows/System32/wbem/Repository/OBJECTS.DATA` (inode 58925; 14,794,752 bytes, SHA-256
`60f36aa92bc04511ade1c4a052622b532285c046cd7b72857bf3f201fd584c29`) holds Windows 7's stock BVT subscription. The file went through
`wmi::scan` and `AsepEnumerator::process`; the independent reading is a Python search for each
class's SHA-256 name hash and a hex dump of the records.

| Field | Independent reading | Séance |
|---|---|---|
| class-hash hits | 10: `NTEventLogEventConsumer` 282506, `__EventFilter` 282821 and 14447162, `CommandLineEventConsumer` 14447560, six bindings | `signature_hits` 10; six records at exactly those offsets plus the bindings at 283120 and 14447934; four hits inside other records |
| consumer extent | hash at 14447560, next record's hash at 14447934 | size 374 |
| header FILETIMEs | `0x01CB8926E37533A5` (2010-11-21T02:50:42.8062629Z), `0x01CA042B90828ED4` (2009-07-14T02:34:08.8060628Z) | the same, raw and rendered |
| strings | `cscript KernCap.vbs`, `BVTConsumer`, `C:\\tools\\kernrate` (the doubled backslashes are stored) | `CommandLineTemplate`, `Name`, `WorkingDirectory` as stored; `ExecutablePath` null |
| CreatorSID | bytes decode to `S-1-5-21-3111613574-2524581245-2586426736-500` | the same |
| filter | `BVTFilter`, `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_Processor" AND TargetInstance.LoadPercentage > 99`, `root\cimv2` | the same, and the binding resolves both ends |

`RunInteractively` decodes as stored `false`, which is the value in Windows 7's published BVT MOF;
the remaining booleans and `Priority` 32 are class defaults, read from this file's own class
definition and not independently checked. `CommandLineEventConsumer` joins the classes whose
records carry no "no real instance" note.

**Command splitting.** A bare first token — no directory, drive or extension — followed by a later
executable extension is the image, resolved on the search path, with basis
`bare_program_name_first_token`
(`a_bare_program_name_before_a_script_is_the_image_and_the_script_its_argument`): `cscript KernCap.vbs`
is image `cscript` with argument `KernCap.vbs`. The logic is in the shared `normalize::split_command`,
so Run-key and service commands of the same shape (`wscript //B x.vbs`) split the same way. Not
established: an `ActiveScriptEventConsumer` instance (none held); liveness and page-spanning
records, which need `MAPPING*.MAP`, are graded in `WMI-2`.

**Search-path resolution, against the image's own file listing:** the Data Leakage
PC's executables named `cscript` were read independently with The Sleuth Kit (`fls -r -p`):
`Windows/System32/cscript.exe` (inode 24052) and `Windows/SysWOW64/cscript.exe` (36826), and no
`tools` directory on the volume. Fed those two files and then the repository, the `BVTConsumer`
row tries, in order, `/tools/kernrate/cscript.exe` (its `WorkingDirectory`),
`/windows/system32/cscript.exe`, `/windows/syswow64/cscript.exe`, `/windows/cscript.exe` — four
candidates under `CreateProcess`'s `.exe`-only rule (`target_search_rule:
create_process_exe_only`) — and answers
`observed_at_path` at `System32`, its basis naming `C:\tools\kernrate` and the `CreateProcess`
rule
(`the_bvt_consumer_is_resolved_in_its_working_directory_first_under_the_create_process_rule`).
Not established: a planted copy in a working directory on real evidence (none held), and the WMI
host's own directory, which the repository does not record.

**Re-run.** `SEANCE_DATALEAKAGE_OBJECTS_DATA=<path> cargo test -p seance_plugin_asep
data_leakage` (and `the_bvt_consumer` for the search-path re-grade).

None of these files is in the repository. The CFReDS files are US-government works, but the
DFIR Madness, BelkaCTF and LoneWolf files' redistribution terms have not been settled here, so
all five runs are gated on the files' paths in the `seance_core::test_support::corpus` style
(`SEANCE_REQUIRE_CORPUS=1` turns a skip into a failure).

### WMI-2 — the CIM repository page mapping on three real repositories, 2026-09-26

The mapping files (`MAPPING1/2/3.MAP`; `OBJECTS.MAP` on XP) and `OBJECTS.DATA` were
extracted with The Sleuth Kit's `icat` from Lone Wolf (`LoneWolf.E01`, Windows 10, sector
1259520: MFT 89187, 89212-89214), NIST CFReDS Data Leakage (`cfreds_2015_data_leakage_pc.E01`,
Windows 7, sector 206848: MFT 58922-58925) and NIST CFReDS Hacking Case
(`4Dell_Latitude_CPi.E01`, Windows XP, sector 63: MFT 5507, 11943). The independent reading is a
Python decoder written from the format references (header, one entry per logical page, free list,
`0xDCBA` footer), which walks the logical pages in order, treats the pages a spanning record runs
into as its continuation, reassembles each spanning record and parses every record as a class
definition. Its source and output are in `seance_plugin_asep/tests/fixtures/wmi/README.md`.

| Field | Lone Wolf | Data Leakage | CFReDS XP |
|---|---|---|---|
| mapping used (sequence) | `MAPPING1.MAP` (25064; the others 25050, 25052) | `MAPPING1.MAP` (26717; 26546, 26631) | `OBJECTS.MAP` (4557) |
| physical / logical / free pages | 2928 / 2774 / 154 | 1806 / 1715 / 91 | 667 / 621 / 46 |
| continuation pages | 1450 | 884 | 156 |
| descriptor records (in unmapped pages) | 11460 (1951) | 7449 (677) | 3894 (237) |
| spanning records / reassembled | 364 / 364 | 180 / 180 | 84 / 84 |
| class definitions parsed (of them reassembled) | 7049 (282) | 5110 (98) | 2865 (83) |
| subscription records in unmapped pages | 0 | 0 | 0 |

Séance's `scan_with_mapping` gives every number in the table exactly. Two checks do not rest on
the decoder agreeing with itself. On XP each descriptor stores the record's CRC-32: all 84
records reassembled through `OBJECTS.MAP` match it, against 25 when the physically next page is
read instead. The scan makes this check itself and publishes it on the coverage record —
`reassembled_checksums_verified` 84, `reassembled_checksums_mismatched` 0 — pinned by
`the_whole_xp_repository_with_its_mapping_reassembles_the_spanning_descriptors`. On all three, the mapped and free pages partition the physical pages exactly, and
reading the physically next page instead of the next logical one parses fewer spanning records as
class definitions (233 against 282, 87 against 98, 51 against 83). Without the mapping the scan
reported 427, 201 and 91 spanning descriptors: the surplus were read from the first bytes of
pages that are another record's continuation.

Not established at the mapping level (`INDEX.BTR` is walked in `WMI-4`): a record its mapped page's descriptor table lists is
current on that table, not on the index. A record no descriptor lists is residue even in a mapped
page (`repository_liveness: "unreferenced_in_mapped_page"`), and one in the trailing part-page past
the last whole page is covered by no mapping entry (`record_page_state: "beyond_mapping"`); neither
is called current or in force. Both are pinned by the real filter record placed in the test
(`a_record_no_descriptor_lists_in_a_mapped_page_is_not_called_current`,
`a_record_in_the_trailing_part_page_is_not_placed_in_the_mapping`), mechanism checks only, as is
the report of a mapping file the neighbour bundle withheld because its directory holds the name
twice (`a_withheld_mapping_file_is_reported_withheld_not_absent`). No repository held has a subscription record in an
unmapped page, so the `superseded` label is pinned by a mapping edited in the test
(`a_record_in_a_page_the_mapping_drops_is_published_as_superseded`), a mechanism check only.
Which copy a binding resolves to when more than one exists is pinned the same way — the real
triad with a copy placed in an unmapped page in the test
(`a_current_binding_resolves_to_the_current_consumer_not_an_earlier_superseded_copy`,
`a_current_binding_whose_consumer_survives_only_as_a_superseded_copy_says_so`,
`a_superseded_binding_is_not_counted_among_what_a_current_filter_and_consumer_are_bound_to`) —
mechanism checks only.
`MAPPING.VER` is not held in any repository here and is not read. The 24-byte entry's second
field is not CRC-32 or CRC-32C of the page and is not checked. No end-to-end run over a whole disk
image is made here; the in-image route is the neighbour bundle, pinned by
`wbem_repository_files_reach_each_other_by_name`.

**Re-run.** The mapping files are committed (`tests/fixtures/wmi/`); name the three
`OBJECTS.DATA` copies: `SEANCE_LONEWOLF_OBJECTS_DATA=<path> SEANCE_DATALEAKAGE_OBJECTS_DATA=<path>
SEANCE_CFREDS_OBJECTS_DATA=<path> cargo test -p seance_plugin_asep with_its_mapping`.

### WMI-3 — an attacker-planted subscription in a real repository (HTB "Perseverance"), 2026-09-27

The evidence is the HTB Business CTF 2022 "Perseverance" challenge, which ships a
bare CIM repository: `INDEX.BTR`, `MAPPING1/2/3.MAP` and `OBJECTS.DATA` (23,896,064 bytes, SHA-256
`6fe0b99195923d89c70935dcee5c507c8317fc4fc211b58d13e68adc54a48043`; the zip, SHA-256
`4babb50ec3eb6ee59eb80fbfbab0d1fe7d0d85638d25883a0bae3d806437c34c`, was fetched from a write-up
author's public mirror; its terms are not stated, so it is held for internal validation and not
committed). Two answers:

* **The published write-ups** (hackthebox.com/blog/perseverance-biz-ctf-2022-forensics-writeup;
  arne-ctf.gitbook.io): the persistence is a WMI filter-to-consumer binding; the consumer runs
  PowerShell with an encoded command; that command decodes to the script they print, beginning
  `$file = ([WmiClass]'ROOT\cimv2:Win32_MemoryArrayDevice').Properties['Property'].Value;` and
  ending `.EntryPoint.Invoke(0,@(,[string[]]@()))|Out-Null`.
* **An independent parse** with `dissect.cim` over `INDEX.BTR`, the mapping and `OBJECTS.DATA`:
  in `root\subscription`, two `__EventFilter` (`Windows Update`, `SCM Event Log Filter`), one
  `CommandLineEventConsumer` (`Windows Update`, a 1,540-character `CommandLineTemplate`, SHA-256
  of its UTF-8 `696c03da…25c7`), one `NTEventLogEventConsumer`, two bindings and **no
  `ActiveScriptEventConsumer`**; the `Windows Update` filter's query is `SELECT * FROM
  __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA
  'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND
  TargetInstance.SystemUpTime < 325`.

Séance read the loose `OBJECTS.DATA` through the ASEP module, which found the mapping beside it
(`MAPPING2.MAP`, sequence 21626, over `MAPPING1.MAP` 21621 and `MAPPING3.MAP` 21589) and decoded
six subscription records, none in an unmapped page. Every value above agrees: the consumer's
command line to the byte, the filter's query verbatim, the binding resolved to the consumer, no
script consumer. The encoded command, decoded by a base64 reader written in the test and again by
the module (`powershell_encoded_command_decoded`), is the published script
character for character.

Not established: which mapping `dissect.cim` chose was not compared; `INDEX.BTR` is graded separately in `WMI-4`, where all six records are named by it; the payload the script loads (`Win32_MemoryArrayDevice.Property` in `root\cimv2`) is outside
the subscription classes and is not decoded, so the flag the write-ups recover from it is not
graded. **This is not a grade of the script-consumer decode**: a third-party summary calls this
consumer an `ActiveScriptEventConsumer`, but the repository holds none. `WMI-5` grades a real one on a Windows 11 repository.

**Re-run.** `SEANCE_PERSEVERANCE_OBJECTS_DATA=<dir>/OBJECTS.DATA cargo test -p seance_plugin_asep
perseverance`, with the other three files in the same directory.

### WMI-4 — the CIM repository index (`INDEX.BTR`) walked from its root on four real repositories, 2026-10-20

The evidence is four real repositories, each `INDEX.BTR` + `MAPPING1-3.MAP` + `OBJECTS.DATA`:
the three Windows 7 repositories in FireEye/Mandiant's `flare-wmi` test set (Apache-2.0; upstream commit
`b0a5a094ff9ca7d7a1c4fc711dc00c74dec4b6b1`; fetched 2026-09-27 to `~/forensic_corpora/flare_wmi_python_cim_repos/`,
`SOURCE.md` and `SHA256SUMS` there) — `deleted-instance`, `overwritten-instance`, `wmikatz` — and the HTB
"Perseverance" repository (`WMI-3`; held for internal validation, not committed). SHA-256 of each `INDEX.BTR`:

| Repository | `INDEX.BTR` SHA-256 | `OBJECTS.DATA` SHA-256 |
|---|---|---|
| flare `deleted-instance` | `cdc00c22efc60c112f10ddf71fc6bb732962b45bfc45a25e48bee41c8db09d40` | `f55a6e33a3ea38d70c444ba9bad5aead408e723f70dd0c77ea07c27c84f00110` |
| flare `overwritten-instance` | `d959e9494032ec9f78ad76b37c9d6c70b607da0067ccc4364feef173daabf74f` | `da52bc7b6897b6d5be3c8e6d118444d7cc15097ce8c4ecd5cba32da7ff6b66f5` |
| flare `wmikatz` | `52755256e5575fa838264268bc209a663c3b87a44d4e71714a499f13be1f6592` | `7dec56b6e4deb00865fd8777349b835f6c6fa6dc98371c30c8938b2346fe8b8f` |
| Perseverance | `90ff94e2974bffc4d4c2cbde3183e6900f4510cb4f17b1fe1c4e7b2dd194698e` | `6fe0b99195923d89c70935dcee5c507c8317fc4fc211b58d13e68adc54a48043` |

**The question.** A page's descriptor table lists every record the page holds; the index decides which of them the
repository still resolves. Does the index, walked as a tree from its root, name the records Séance reads, and which
descriptor-listed records does it not name?

**The independent reading.** `seance_plugin_asep/tests/fixtures/wmi/independent_index_decoder.py`, written from the
libyal `dtformats` *WMI repository file format* document and the bytes, not from the Rust decoder. **Clean room:**
`dissect.cim` 3.13 is AGPL-3.0 and was used only as a run-time grader of the result — its output was compared with the
script's and with Séance's — and none of its source was read into or ported to this code. The script chooses the
well-formed mapping with the highest sequence number, finds the root (the fourth `u32` of the first entry of the
`INDEX.BTR` section: logical page 60 on the three Flare repositories, 61 on Perseverance), walks the tree, and
separately walks `OBJECTS.DATA` in logical order for its descriptors. Its output is committed as
`tests/fixtures/wmi/index_answer_key.json`; the set of references it reached equals `dissect.cim`'s on all four.

| | flare deleted | flare overwritten | flare wmikatz | Perseverance |
|---|---|---|---|---|
| mapping used (sequence) | `MAPPING1.MAP` (89090) | (89105) | (101696) | `MAPPING2.MAP` (21626) |
| index pages reached from the root | 305 | 305 | 321 | 430 |
| data references the index names | 6743 | 6744 | 6979 | 9523 |
| descriptors in mapped, non-continuation pages | 6747 | 6748 | 6983 | 9546 |
| index references with no descriptor | 0 | 0 | 0 | 0 |
| **listed by a descriptor, named by no key** | **4** | **4** | **4** | **23** |

Séance's `indexed_records` reproduces every row exactly, and the list of unindexed (logical page, record id, size)
triples equals the answer key's in all four (the Flare four are identical in all three repositories:
`(1652,106171,636)`, `(1654,117879,628)`, `(1655,103644,576)`, `(1655,115315,576)`). Two findings:
**walking every mapped index page is wrong** — the unindexed descriptors' references sit in mapped index pages the tree
from the root no longer reaches, so a whole-file walk would call them indexed; and the 4 and 23 are none of them a
subscription-class record the scan matched, so on these files no subscription record is "listed but not indexed". End
to end through the ASEP module, every subscription record found in a mapped page is `indexed`: `BVTConsumer` and
`BVTFilter` on each Flare repository, and all six records of the Perseverance repository (two filters, the `Windows Update`
`CommandLineEventConsumer`, the `NTEventLogEventConsumer` and two bindings). The `deleted-instance`
repository also holds subscription copies in pages the mapping drops, published as `superseded` and carrying no index
claim. The in-image route (the neighbour bundle) is pinned by
`the_index_is_reached_through_the_neighbour_bundle_too`.

**Not established.**
- The `listed_not_indexed` standing for a subscription record is pinned only on a synthetic index
  (`a_record_a_mapped_page_lists_and_the_index_does_not_name_is_published_as_unlinked`, on the real Lone Wolf pages and
  mapping with an index supplied in the test): no real repository held has such a record, so what the 4 and 23 unindexed
  descriptors are (deleted records, superseded class definitions, other instances) was not decoded. That a record is
  unindexed is read as "deleted or unlinked"; why was not established.
- The Windows XP index (`INDEX.MAP` with `OBJECTS.MAP`) is graded in `WMI-9`. The Vista-onward
  `MAPPINGn.MAP` form with a root in the first mapping entry is read, off four repositories, not
  from a specification. Windows Server 2003's form (`MAPPINGn.MAP` with XP's four-byte entries and
  the root in the header of index page 0) is graded in `WMI-8`.
- The meaning of the key's other numeric parts, the 4-byte unknown values per key, and the second and third
  fields of each mapping entry are not read.
- The descriptor side of the comparison is the committed script's own walk (and `WMI-2`'s mapping decoder), not
  `dissect.cim`'s; `dissect.cim` graded the index side.
- None of these four repositories holds an `ActiveScriptEventConsumer`; `WMI-5` grades one.

**Re-run.** `SEANCE_FLARE_WMI_DIR=~/forensic_corpora/flare_wmi_python_cim_repos
SEANCE_PERSEVERANCE_OBJECTS_DATA=~/forensic_corpora/htb_business2022_perseverance/forensics_perseverance/OBJECTS.DATA
cargo test -p seance_plugin_asep wmi_index`. The key: `python3
seance_plugin_asep/tests/fixtures/wmi/independent_index_decoder.py <repository directory>`.

### L01-1 — five real EnCase logical evidence files of one iPhone, 2026-09-24

The evidence is Digital Corpora's 2012 National Gallery DC scenario, "extra"
images of Tracy's iPhone taken with EnCase: five `.L01` acquisitions made with EnCase 7.4.1.10
between 2012-07-05 and 2012-07-15, each passing `ewfverify` (libewf 20140816; no MD5 is stored in
any of them, and none is published), and a plain zip export of the same phone made a minute
after the last of them (`Tracy-phone-logical-2012-07-15-1317.zip`, SHA-256
`1e4287dff75dd2fb84ff46be3ef5f3152bb894b64030831b442776e522d30329`). The scenario page permits
teaching and research use. Each file went through `E01ContainerModule::process` as a `Container`
with subtype `e01`, with the walk in the isolated helper; the 07-15 file was also run in process.

Two answers, of different kinds. **libewf's own reading:** `ewfinfo`'s "Single files" tree for
each file, saved beside it — every entry it lists must be published at the same `/`-joined path,
and nothing it does not list may be. That proves the walk complete and faithful to libewf, not
independent of it; `ewfinfo` prints no sizes, so sizes are graded by the second answer and by
reading every file to its end. **An independent export:** the zip's 30 camera-roll JPEGs
(`DCIM/800AAAAA/IMG_0042.JPG` … `IMG_0071.JPG`), each matched to a published entry by name, size
and the MD5 of the bytes served.

| File | Entries `ewfinfo` lists | Published | Matched by path |
|---|---:|---:|---:|
| `tracy-phone-2012-07-05-1640.L01` | 9,952 | 9,952 | 9,952 |
| `Tracy-phone-2012-07-07-1446.L01` | 10,152 | 10,152 | 10,152 |
| `Tracy-phone-2012-07-08-1515.L01` | 10,581 | 10,581 | 10,581 |
| `Tracy-phone-2012-07-09-1644.L01` | 14,198 | 14,198 | 14,198 |
| `Tracy-phone-2012-07-15-1316.L01` | 14,804 | 14,804 | 14,804 |
| **all five** | **59,687** | **59,687** | **59,687** |

Across the five, the 55,599 non-directory entries were each read in full through the data
source published for them — 103,292,662 bytes — and every one returned exactly its recorded
size; the 646 whose L01 stores an MD5 match it. **Against the zip, 30 of 30 JPEGs match** an entry
of the 07-15 L01 (`/LogicalEntries/Raw Data/MediaDomain/Media/DCIM/100APPLE/IMG_nnnn.JPG/IMG_nnnn.JPG`)
by name, size and MD5. In process, the 07-15 file publishes the same 14,804 entries, and 143
sampled files are byte-identical to the isolated reading.

What the run showed that the records now say: the L01's four time fields are **0 for every
entry** in all five files (published raw, projected nowhere); 732 to 936 directory entries per
file store data of their own; and exactly one entry per file is flagged sparse. Not established:
a real non-zero L01 time (the projection is unit-tested only), an `.Lx01` (none public), a
multi-segment `.L01` set, a walk near either ceiling on real evidence.

**Directory data and the sparse entry.** The
entry table and the media stream were read a second way, outside libewf's API: the `ltree`
section's UTF-16LE text decoded by a stand-alone Python reader, and the media stream written
out by `ewfexport -f raw` (33,088,746 bytes for the 07-15 file, the size the `ltree` records).

*Directory data.* Each file's directories split two ways, and the splits add to the old counts:

| File | Stored data = recorded size (served as a stream) | No size, one byte stored (not served) |
|---|---:|---:|
| 07-05 | 123 | 609 |
| 07-07 | 131 | 639 |
| 07-08 | 159 | 639 |
| 07-09 | 164 | 683 |
| 07-15 | 191 | 745 |

The 768 streams (158,022 bytes) are each served in full at `<directory>:l01_directory_data`,
and the listing comparison above is unchanged (streams are not entries). In process the 07-15
file publishes 14,995 `FileEntry` records (14,804 entries and 191 streams), and the every-97th
sample — 145 sources, streams included — is byte-identical to the isolated reading. The record beside
`DCIM/100APPLE/IMG_0061.JPG` is the 192 bytes at media offset `0x138`; read independently it is
a count (8) and eight 16-byte slots — `u16` type (`0x40`, `0x1F`, `0x1F9`), `u16` id, two `u32`
values — then UTF-16LE strings: `IMG_0061.JPG`, `0`, `595432` (the photo's size) and four slots
of type `0x40` holding the POSIX time `0x4FF9F85A` (2012-07-08T21:15:06Z). **The times are not
decoded**, because they do not agree with the independent export: for 29 of the 30 photos they
fall within 2012-07-08T21:15:06–21:15:11Z, while the zip's NTFS modification times for the same
photos run from 16:33:37Z to 17:02:23Z (`IMG_0061.JPG` 16:50:53Z), and `IMG_0071.JPG`'s record
says 2012-07-15T17:16:21Z where the zip says 2012-07-11T16:18:48Z — no constant offset maps one
onto the other. With no published description of the record
found, the streams are published as bytes with `l01_directory_data_decoded: false`. Directories
with no size store one byte at a distinct offset (values vary); libewf requires exactly that of a
size-0 entry and serves nothing for it, so those are marked `l01_directory_placeholder_byte` and
counted.

*The placeholder bytes.* The walk reads each placeholder's one byte
and records it as `l01_directory_placeholder_value`. The same test asserts, per file, that every
placeholder has a value, that `directory_placeholder_values_recorded` equals the placeholder count,
that no file (non-directory) entry has the placeholder form, that no walked entry's span is unknown
(`stored_spans_unknown` is 0), that the product's own span check (stored spans and every sparse
entry's read at its duplicate data offset) marks every placeholder `alone`
(`directory_placeholder_bytes_alone` equals the count,
`directory_placeholder_bytes_in_shared_span` is 0), and that the stored spans (`l01_media_data_offset`, `l01_media_data_size`) of
every published entry with stored data, placeholders included, sorted by offset, start at 0, abut
exactly, and end at the inventory's `media_size`. Measured:

| File | Placeholders (values recorded) | Stored spans | Media size |
|------|-------------------------------:|-------------:|-----------:|
| `tracy-phone-2012-07-05-1640` | 609 | 9,951 | 7,710,182 |
| `Tracy-phone-2012-07-07-1446` | 639 | 10,151 | 8,273,057 |
| `Tracy-phone-2012-07-08-1515` | 639 | 10,580 | 26,370,526 |
| `Tracy-phone-2012-07-09-1644` | 683 | 14,197 | 27,950,053 |
| `Tracy-phone-2012-07-15-1316` | 745 | 14,803 | 33,088,746 |

*The placeholder byte has no defined meaning.* Read from public source, not
measured: the EWF specification (`documentation/Expert Witness Compression Format (EWF).asciidoc` in
https://github.com/libyal/libewf) says of the ltree file-entry size field that "if the file size is 0 the data size
should be 1", and says nothing else about the byte. libewf's `libewf_internal_file_entry_read_buffer`
(https://raw.githubusercontent.com/libyal/libewf/main/libewf/libewf_file_entry.c) rejects a size-0 entry whose data
size is not 1 and otherwise returns 0 before reading, because the offset is not below the size. The byte is a mandated
one-byte extent; what fills it is not established and is not claimed. The recorded values stay pinned by
`PLACEHOLDER_KNOWN`; this paragraph adds no new grade.

So each placeholder byte is stored for its entry alone on these files. The values are pinned
against a second read. `ewfexport -u -f raw` of each L01 gives the whole media stream (its size is
the inventory's `media_size`), and a Python read of that stream at every placeholder's recorded
offset matched all 3,315 values. That is the same library by a different read path (sequential
export rather than a random read through the helper), not an independent implementation. From
that read the test pins, per file, the count of 0x00 bytes, the sum of the bytes, and the
lowest-offset non-zero (offset, byte):

| File | 0x00 bytes | Sum | First non-zero (offset, byte) |
|------|-----------:|----:|------------------------------:|
| `tracy-phone-2012-07-05-1640` | 397 of 609 | 23,728 | (263,466, 111) |
| `Tracy-phone-2012-07-07-1446` | 418 of 639 | 24,755 | (273,786, 43) |
| `Tracy-phone-2012-07-08-1515` | 136 of 639 | 66,897 | (595,936, 99) |
| `Tracy-phone-2012-07-09-1644` | 131 of 683 | 73,721 | (595,936, 99) |
| `Tracy-phone-2012-07-15-1316` | 120 of 745 | 81,737 | (595,936, 99) |

A read one byte off fails the pin (red on a deliberate `offset + 1`:
`tracy-phone-2012-07-05-1640: placeholders whose byte is 0x00`, `left: 103, right: 397`); a
one-byte shift changes 525 to 714 of the values per file. With `SEANCE_L01_RAW_DIR` pointing at
the `ewfexport` outputs (`<stem>.raw`), the test also compares every value byte for byte. That is
all this establishes: the values vary (the rest spread across 0-255), a one-off libewf probe run during triage found no relation to the neighbouring bytes or to the entry's name,
and what EnCase means by the byte is not established. That needs EnCase documentation or a
controlled EnCase acquisition, and neither is held. Run with
`SEANCE_L01_CORPUS=~/forensic_corpora/ngdc_tracy_phone_l01 SEANCE_REQUIRE_CORPUS=1 cargo test -p
seance_container_e01 --test l01_real_evidence_test -- --nocapture`, adding
`SEANCE_L01_RAW_DIR=<dir>` after `for f in <corpus>/*.L01; do ewfexport -q -u -f raw -t
<dir>/$(basename "$f" .L01) "$f"; done` for the byte-for-byte comparison.

*The sparse entry.* In all five files it is
`…/LocalStorage/https_s-static.ak.facebook.com_0.localstorage/https_s-static.ak.facebook.com_0.localstorage`.
Its `ltree` row (07-15) records size 12,288, one byte stored at `0xE14F86` (`0xB6`), flags
`0x04400000` (sparse), `du` 3474730 (`0x35052A`) and MD5 `044ffec2c42972422a51842b8070e805`.
libewf 20140816's `libewf_file_entry_read_buffer` (read from the Debian `libewf_20140816.orig`
source, outside the tree) reads a sparse entry with a duplicate offset from the media stream at
that offset. `0x35052A` is the media offset of `…/http_m.facebook.com_0.localstorage`, whose own
MD5 is the same value; the 12,288 media bytes there begin `SQLite format 3` and hash to
`044ffec2…e805` (Python over the `ewfexport` stream). So the bytes served are the entry's by its
own stored MD5, and the record says where they come from (`l01_content_source:
duplicate_data_offset`, `l01_duplicate_of_path`) with `l01_duplicate_content_check:
stored_md5_matches`, unstamped. The `unvalidated` count per file goes from 1 to 0.

**Re-run.** `SEANCE_L01_CORPUS=<dir holding the five .L01s, their .ewfinfo.txt listings and the
zip> cargo test -p seance_container_e01 --test l01_real_evidence_test -- --nocapture`. The
listings are `ewfinfo <file>.L01 > <file>.ewfinfo.txt`. None of the files is in the repository;
unset, the test says it compared nothing and skips, and `SEANCE_REQUIRE_CORPUS=1` makes that a
failure.

### MEM-XP-1 — the legacy global timer table on four real XP x86 captures, 2026-09-24

**Images.** Three of the Malware Analyst's Cookbook's eight Windows XP SP2 x86 PAE
captures (`tigger.vmem`, `be2.vmem`, `zeus.vmem`, 128 MiB each; O'Reilly examples repository,
git blob SHA-1s verified) and Ligh's Stuxnet capture (`stuxnet.vmem`, XP SP3 x86 PAE, 512 MiB).
**None is redistributable, and all four hold live malware in memory**: they were unzipped to a
scratch directory outside the repository, read as data, and deleted after the run. Provenance
and hashes: `~/forensic_corpora/malware_cookbook_mem/PROVENANCE.md`,
`~/forensic_corpora/stuxnet_mem/PROVENANCE.md`. Symbols: the extracted Volatility Windows pack
(`ntkrnlpa.pdb/BD8F451F3E754ED8A34B50560CEB08E3-1` for the SP2 three).

**Oracle.** Volatility 3 2.28.2 (`reference/volatility3`, run as an oracle, never wrapped)
`windows.timers` on the same four files. It hardcodes 256 `_LIST_ENTRY` buckets for XP x86;
Séance derives the count. Each image went through the whole Windows pipeline
(`MemoryAnalysisModule` + `WindowsMemoryAnalysis`) and its `MemoryTamperChecks` record was graded.

| Image | Buckets | Timers | With a DPC (= Volatility rows) | Same address/routine/period | Outside every module |
|---|---:|---:|---:|---:|---:|
| tigger | 256 | 233 | 60 | 60 of 60 | 0 |
| be2 | 256 | 227 | 60 | 60 of 60 | 0 |
| zeus | 256 | 242 | 64 | 64 of 64 | 0 |
| stuxnet | 256 | 176 | 58 | 58 of 58 | 0 |

**Three behaviours of the XP timer table, each pinned by a test**
(`seance_plugin_memory_windows/src/tamper_timers_tests.rs`):

1. NT 5.1 declares no `_KTIMER_TABLE_ENTRY` type: each bucket is a bare `_LIST_ENTRY`, and 349 of
   the 926 legacy-shape ISFs in the pack are in that state. A table of bare list heads is walked,
   not refused.
2. **The derived extent is 256, not 288.** `KiDispatcherReadyListHead`'s 32 list heads follow the
   table, self-referential when empty, and a heads-only probe would walk them as timer buckets
   (2–4 bogus rows per image). The probe is bounded by the next symbol the build declares above the
   table, `KiDispatcherReadyListHead`, +2,048 bytes, and the record names it. Across the pack the
   bound equals the documented 256/512 on 867 of the 926 legacy ISFs; on the other 59 it is looser
   or absent and the probe decides alone.
3. `_KTIMER.Period` is declared `long` on XP and is read signed: an unsigned-only read drops all
   12 periods on tigger.

**Not covered.** The legacy table with a declared `_KTIMER_TABLE_ENTRY` (Server 2003 SP1+,
Vista, XP x64) is unread from evidence. NIST CFReDS "Basic Memory Images"
was opened with 7-Zip 23.01 (`~/.local/bin/7zz`): `boomer-win2003-2006-03-17.img` is Server 2003
**RTM** (3790.srv03_rtm.030324-2048, x86, 2 processors), whose ISF declares no
`_KTIMER_TABLE_ENTRY` — the bare-`_LIST_ENTRY` form, 256 buckets bounded by `KiBiosFrame` at
+2,048 — and its 156 timers, 43 carrying a DPC, match `windows.timers`' 43 in address, routine
and period, none outside a module. `vista-beta2.img` (build 5384) has kernel `ntkrnlmp.pdb`
`5B71B326D7C84B88B623F8F1026BE689-2`, which neither the extracted Volatility pack nor Microsoft's
server (Volatility's own download failed) supplies; Séance publishes the discovery failure naming
that GUID. **An evidence bound, not a defect:** no capture with symbols of the declared-entry
form exists on this host.

**Re-run.** `SEANCE_COOKBOOK_MEM=<dir with tigger.vmem, be2.vmem, zeus.vmem>
SEANCE_STUXNET_MEM=<dir with stuxnet.vmem>
SEANCE_NIST_BASIC_MEM=<dir with boomer-win2003-2006-03-17.img> SEANCE_SYMBOL_DIRS=<extracted
pack>/windows cargo test -p seance_plugin_memory_windows --release --test legacy_xp_corpus`.
Answers: `seance_memory/tests/KNOWN_ANSWERS.md`. The Server 2003 RTM result
above is pinned by `the_server_2003_rtm_legacy_table_matches_volatility`:
the bare form, 256 buckets bounded by `KiBiosFrame` at +2,048, 156 timers, 43 with a
DPC, none outside a module, and the 43 `(_KTIMER, routine, period)` rows of a fresh Volatility
3.2.28.2 `windows.timers` run on the same file, set-equal. Extract the image with
`~/.local/bin/7zz e memory-images.rar boomer-win2003-2006-03-17.img` (SHA-256
`dc7022c2183dade6c36ebf19c74af5234bff8800e2a6f95e825287da9a214adb`). It does not reach the declared-`_KTIMER_TABLE_ENTRY` form.

### MEM-XP-4 — the declared `_KTIMER_TABLE_ENTRY` form on a real Server 2008 capture, 2026-10-20

**Image.** `memdump.mem`, Windows Server 2008 SP1 x86 PAE (kernel `ntkrpamp.pdb`
`37D328E3BAE5460F8E662756ED80951D-2`, `6001.18000.x86fre.longhorn_rtm`), 536,870,912 bytes,
SHA-256 `d3b13f2224cab20440a4bb3c5c971662be6e61f431340f319cef7312bb6177f4` (vendor MD5
`b50ae13dc659ec9c8af66b539e5768d8` matches). Source: https://samsclass.info/121/proj/memdump.7z
(CCSF CNIT 121, Project 2). A clean lab VM capture with no licence stated: not redistributable,
read in place from `~/forensic_corpora/samsclass_server2008_mem/` (`SOURCE.md` there). Its ISF
declares `_KTIMER_TABLE_ENTRY` {Entry at 0, Time at 8, size 16}, `KiTimerTableListHead`,
`KiTimerTableSize` and no `_KPRCB.TimerTable`: the declared-entry legacy form.

**Oracle.** Volatility 3 2.28.2, `windows.timers` against the extracted symbol pack
(`vol3/windows.timers.txt`, 14 rows). A second implementation, not ground truth. The kernel's own
`KiTimerTableSize` is the second oracle for the bucket count: the dword at RVA 0x137b30 (physical
0x01971b30, read with a one-off script) is 0x200 = **512**.

**Result.** Séance walks **512** buckets (16-byte entries, bounded by the next symbol,
`AlpcpNPLookasides`, 8,192 bytes above the head), equal to `KiTimerTableSize`. 35 of the 512
heads are torn and named. 173 timers, 57 with a DPC, none outside a loaded module. 171 timers and 55 with a DPC, because two list items in torn bucket 346 (dispatcher header types `0x1` and `0x8d`) are no timers and are skipped, as Volatility skips them. The 14
Volatility rows (timer address, routine, period) are set-equal with the timers Séance reaches
from buckets 0 to 255. **Volatility 3 and Séance differ above that, and the kernel sides with
Séance:** `windows/timers.py` reads `KiTimerTableListHead` on Vista and later as an array of 512
`_LIST_ENTRY` (8 bytes), but each element is a 16-byte `_KTIMER_TABLE_ENTRY`, so it covers only
the first 256 buckets. The 41 further DPC timers Séance reaches only from buckets 256 to 511
are pinned and not graded against a second reader (every routine is inside a loaded module).
Séance's counts (171, 190 rows walked, 55 with a DPC, 17 reached more than once) are
measurements pinned against regression.

**Re-run.** `SEANCE_SAMSCLASS_2008_MEM=<dir with memdump.mem> SEANCE_SYMBOL_DIRS=<extracted
pack>/windows cargo test -p seance_plugin_memory_windows --release --test legacy_xp_corpus --
server_2008`. Test: `the_server_2008_declared_entry_legacy_table_matches_volatility`. **Not
covered:** Server 2003 SP1+, XP x64 and Vista non-PAE (`m57_terry_vista_ram` has the same ISF
form but Volatility 3 cannot stack it, so it has no oracle and is not tested).

### MEM-XP-5 — a Vista SP2 x86 non-PAE capture against Volatility 2, 2026-10-22

**Image:** `terry-2009-11-16.mddramimage` (M57-Patents "Terry", Digital Corpora, 535,130,112 bytes; SHA-256 `1d8d446d...6806`; kernel `ntkrnlmp.pdb` `79682A989AB049B491E4E18B258C7A1C-2`, 6.0.6002.18082, 512 MiB machine).
Not redistributable terms stated; held in place. **Oracle:** Volatility 2.6.1 (`sk4la/volatility` image, profile `VistaSP2x86`), because Volatility 3 cannot stack this image: `timers`, 51 distinct `_KTIMER` rows (`tests/legacy_xp_oracle/vista_terry_volatility2.rs`).
A second implementation, not ground truth.

**Three behaviours this capture requires:**
1. **Discovery accepts a short capture.** The capture ends 1.7 MiB short of the top of RAM; the real directory (`0x122000`, one of twelve self-referencing frames in the low 90 MiB) names three page tables above the layer's last byte (`0x1ff41000`, `0x1ff51000`, `0x1ff53000`). The plausibility test refuses a directory whose tables are more than a tenth out of range, as a random page is, and does not refuse one for a few tables above the acquisition's top.
2. **Torn table.** A capture taken while the system ran leaves 56 torn heads. A probe that takes the run of torn heads at the end as the end of the table derives 353 of 512 buckets and misses 17 of Volatility's timers. The kernel's own `KiTimerTableSize` (a dword in the image: 512, read by hand at physical `0x193c938`) is the extent when the build declares the symbol and the value is a power of two inside the room the next symbol leaves.
3. **Junk is not a timer.** A torn list runs into memory that is no `_KTIMER`; three rows with routines `0x24b25548`, `0x1cccfd60` and `0x850a0ca4` would be published. An item is a timer only if its dispatcher header's `Type` is 8 or 9 (Volatility's test), where the build declares the header.

**Result.** 512 buckets walked, 188 distinct timers (214 rows), 54 with a DPC, none outside a loaded module, and 17 list items skipped because their header is no timer's. **All 51 of Volatility 2's timers are reached with the same routine and period (51 of 51)**, and Séance reports one more, `0x82f78e68` (60,000 ms, routine in a loaded
module), which Volatility 2 does not print; it is pinned and ungraded. The same header check applies to the Server 2008 capture of `MEM-XP-4`: two items in torn bucket 346 (types `0x1` and `0x8d`), both with
a DPC, are no timers, so that capture's counts are 171 timers and 55 with a DPC; the 14 Volatility 3 rows are unaffected. The 15 other legacy-table tests (XP, Server 2003, Stuxnet, the Cookbook set) pass.

**Not established.** One Vista build, one capture; Volatility 2 is a second reader; Server 2003 SP1+ and XP x64 have no capture. **Re-run:** `SEANCE_M57_VISTA_MEM=~/forensic_corpora/m57_terry_vista_ram SEANCE_SYMBOL_DIRS=<extracted pack>/windows cargo test -p seance_plugin_memory_windows --release --test legacy_xp_corpus -- the_vista`.

### MEM-XP-6 - a Windows Server 2003 R2 SP2 x64 capture against a Volatility 2 walk, 2026-10-22

**Image:** `forensic_corpora/lab_w2k3_r2_sp2_x64/mem.raw`, made here: Microsoft's own 180-day evaluation of Windows Server 2003 R2 Datacenter x64 SP2 (build 3790, `WS03SP2_RTM_3959_DX6_EN-CRMDXEVL_EN_180_1.iso`, SHA-1 `e4b7e323...8bad`, an archive.org copy of the Evaluation
Center download), installed unattended under KVM (`~/legacy-lab/run-w2k3.sh`, `winnt.sif` on a floppy, no product key entered, the evaluation needs none), logged on as Administrator and dumped with QMP `dump-guest-memory`; SHA-256 `592a60af...d1c8`, 4 GiB physical map, 2 processors, 2026-10-22. Kernel
`ntkrnlmp.pdb` GUID `03185083233249D9BB747EA777B80C98` age 2, fetched from Microsoft's symbol server with `seance fetch-symbols --allow-network` (6,441,984 bytes). **Oracle:** Volatility 2.6.1 (`sk4la/volatility`, `Win2003SP2x64`) identifies the image and lists its 60-odd processes, but its `timers` plugin prints
nothing ("Cannot find KiTimerTableListHead"), so the reference is its address space walking the same table: `scripts/oracle/vol2_legacy_timers.py` takes the kernel base from the KDBG block and the table's address from the symbol's RVA in the ISF of the same PDB (the symbol file is shared, the walk is not), reads each of the
512 buckets as the declared `_KTIMER_TABLE_ENTRY` (24 bytes) and each item as a `_KTIMER`. **Result:** 211 timers, every dispatcher header of type 8 or 9; the product's `timers` stage reports the same 211, in the same buckets (bucket 0 to 498) with the same periods
(`tests/legacy_xp_oracle/w2k3_x64_volatility2.rs`, `the_server_2003_x64_capture_timer_table_equals_the_volatility2_walk`). A walk of 256 buckets, the XP x86 extent, would have found 119 and missed 92: this build's table has 512. 54 timers carry a DPC; the DPC fields are encoded with `KiWaitNever` and `KiWaitAlways` and every
decoded routine lies in a loaded module (`tcpip.sys`, `rdbss.sys`, `NDIS.sys`, `TDI.SYS`, `ntoskrnl.exe`), 0 outside any.

**Not established:** **Windows XP Professional x64** itself. Microsoft's trial ISO (`ARMPXEVL_EN.iso`, SHA-1 `50748c63...c9c`) was downloaded and Setup started, but it requires a product key the trial media does not carry and none is published with it; no key was sought. XP x64 and Server 2003 x64 share the 3790 kernel (XP x64 is the Server 2003 SP1 x64 code with a
client shell), which is why one capture of the family answers the declared form and the encoded DPCs, and XP x64 itself stays ungraded. The DPC decode is graded only by every routine landing in a loaded module, not against a second decoder. **Re-run:** `SEANCE_W2K3_X64_MEM=~/forensic_corpora/lab_w2k3_r2_sp2_x64 SEANCE_SYMBOL_DIRS=<dir with the ISF> cargo test --release -p seance_plugin_memory_windows --test legacy_xp_corpus the_server_2003_x64`.

### MEM-XP-2 — the tamper checks against a published orphan-thread answer, 2026-09-24

**Same four images and oracle as MEM-XP-1**, plus Volatility 3's
`windows.orphan_kernel_threads`, `windows.unloadedmodules` and `windows.debugregisters`.
**Published answer:** M. H. Ligh, *Investigating Windows Threads with Volatility*
(2011-04-18), on the Cookbook's `tigger.vmem`: `threads -F OrphanThread` prints `ETHREAD
0xff1f92b0 Pid 4 Tid 1648 … StartAddress 0xf2edd150` (created 2010-08-15 19:26:13, matching this
file; the 2009 post showing other TIDs is of an earlier capture).

| Group | tigger | be2 / zeus / stuxnet | Against |
|---|---|---|---|
| `orphan_kernel_threads` | 3 rows: Tid 1648 at 0xf2edd150 (thread 0xff1f92b0, Pid 4), 1720 at 0xf2edc54e, 1992 at 0xf2edba46 — **0 graded** | 0 rows | Ligh's thread; Volatility's same three / none |
| `unloadedmodules` | 10 | 9 / 10 / 16 | Volatility: every name, range and slot |
| `timers` | see MEM-XP-1 | | |
| `debugregisters` | 1 row (winlogon), **0 graded** | 1 row each (winlogon), **0 graded** | Volatility prints none — see below |
| `suspended_threads` | 0 of 365 counts | 0 of 360 / 370 / 368 | — |
| `etwpatch` | every process unassessed | same | — |
| `skeleton_key_check` | `lsass` unassessed (`cryptdll` headers paged out) | same | — |

**The first true positive, and why it is not graded.** `orphan_kernel_threads` fires on the
published thread with every value Ligh printed, and publishes the same three rows Volatility 3
does. They are observations, not graded findings: XP declares no `_ETHREAD.StartAddressInvalid`,
so that exclusion is `not_assessed`, and the group grades nothing on a build where one of its four
controls cannot be applied — by design. The signal fired; the grade is withheld for a reason the
record states.

**Two behaviours of `debugregisters`**
(`seance_plugin_memory_windows/src/tamper_threads_tests.rs`): the registers are read at the build's width (four bytes each on x86; an eight-byte read gives `Dr1:Dr0` as one value), and XP's `_KTHREAD.DebugActive` is looked for (`Tcb.DebugActive`). Every capture shows one `winlogon.exe` thread whose own flag
(0x8f / 0x8d, low four bits = the slots with a non-zero address) confirms `Dr7` = 0x555 with
`Dr0`–`Dr3` in the null page. That is reported as an armed breakpoint on four of four XP
captures, three of whose malware has nothing to do with winlogon — **a false positive of this
group on XP**. Volatility 3 drops the same thread because no address lands in a file-backed VAD.

**Null-page rule.** Séance's rule, not Volatility's: a row is
graded as an armed breakpoint only when at least one address `Dr7` arms is at or above 0x10000
(`MM_LOWEST_USER_ADDRESS`, WDK `wdm.h`); a row whose every armed address is below it is published
with its addresses, `armed_only_in_the_null_page: true` and a `not_graded_reason`, and not graded.
Clean-capture counts of `threads_with_a_breakpoint` under this rule: tigger, be2, zeus, stuxnet 0
each; Windows 11 26200 0; LoneWolf (Windows 10) 1 — a Tid-0 `RuntimeBroker.exe` row whose armed
addresses are not in the null page, not a true positive; 13Cubed mini-memory 0; the Case 001
captures are measured in MEM-C001-1. **Bound:** before Windows 8 a 32-bit process could map page 0
(`NtAllocateVirtualMemory` with a base of 1, or NTVDM), so a breakpoint on memory deliberately
mapped there is published and not graded.

**Still without a true positive:** `timers`, `unloadedmodules` as a signal, `debugregisters`,
`suspended_threads`, `etwpatch`, `skeleton_key_check`. `be2`'s published answer (SSDT hooks
in thread 1284 of svchost) and Stuxnet's (callbacks, IRP hooks, injected `lsass`) are not in
these groups and are not graded here.

**Re-run.** As MEM-XP-1; the same test file.

### MEM-XP-3 — the tamper groups on the Cookbook's other five captures, 2026-09-27

**Images.** The five Malware Analyst's Cookbook XP SP2 PAE captures no earlier run had
graded: `coreflood`, `laqma`, `prolaco`, `sality`, `silentbanker` (128 MiB each, git blob SHA-1s
verified in `~/forensic_corpora/malware_cookbook_mem/PROVENANCE.md`). Not redistributable, live
malware in memory: unzipped outside the repository, read as data, deleted after the run. **No
published answer ties any of the five to the seven groups**, so this measures agreement with the
oracle and false positives; it cannot produce a graded true positive.

**Oracle.** Volatility 3 2.28.2 (`reference/volatility3`, with `pefile` on `PYTHONPATH`, the
extracted symbol pack) `windows.timers`, `windows.unloadedmodules`,
`windows.orphan_kernel_threads`, `windows.debugregisters`. Its timer and unloaded-driver rows are
copied, by script, into `seance_plugin_memory_windows/tests/legacy_xp_oracle/cookbook_volatility.rs`.
As a control the same invocation printed tigger's three orphan threads.

| Group | coreflood | laqma | prolaco | sality | silentbanker | Against |
|---|---|---|---|---|---|---|
| `timers` (buckets / timers / with a DPC) | 256 / 176 / 62 | 256 / 190 / 63 | 256 / 140 / 50 | 256 / 242 / 61 | 256 / 175 / 62 | Volatility: every row, same address, routine, period (prolaco: below) |
| `timers` routine outside every module | 0 | 0 | 0 | 0 | 0 | — |
| `unloadedmodules` | 11 | 10 | 12 | 10 | 10 | Volatility: every name, range and slot |
| `orphan_kernel_threads` | 0 | 0 | 0 | 0 | 0 | Volatility: none |
| `debugregisters` rows (graded) | 1 (0) | 1 (0) | 1 (0) | 1 (0) | 1 (0) | winlogon null-page row; Volatility none |
| `suspended_threads` | 1 of 329 | 1 of 340 | 0 of 305 | 0 of 398 | 1 of 329 | a `VMUpgradeHelper` thread; a listing, never a finding |
| `etwpatch` | every process unassessed | same | same | same | same | — |
| `skeleton_key_check` | `lsass` unassessed | same | same | same | same | — |

**Torn bucket heads.** `prolaco.vmem` was captured while timers were being relinked: 12 of 256 bucket
heads have a first link whose `Blink` names another bucket. Inside the symbol bound a torn head is a
bucket, named on the record; without a bound it still ends the probe
(`without_a_symbol_bound_a_torn_head_still_ends_the_legacy_probe`). A probe that read bucket 37's torn
head as the end of the table would see 37 buckets (7 of the 50 real DPC timers reached), and a list
from inside the 37 that ran into bucket 68's head would publish that head as a timer outside every
module (`a_torn_bucket_head_does_not_end_the_legacy_table`). Volatility prints 55 rows on prolaco:
Séance's 50 plus four timers it prints twice and one row at 0x80552408 that is bucket 68's
`_LIST_ENTRY` head read as a `_KTIMER` — Volatility's error. tigger, be2, zeus, stuxnet and boomer
are unaffected.

**Result.** Across all eight Cookbook captures and Stuxnet, the only kernel-side
signal that has met a published answer is tigger's orphan thread (MEM-XP-2). `timers`,
`unloadedmodules` as a signal, `debugregisters`, `suspended_threads`, `etwpatch` and
`skeleton_key_check` still have none, and no held capture carries one.

**Re-run.** `SEANCE_COOKBOOK_MEM=<dir with all eight .vmem>`
`SEANCE_SYMBOL_DIRS=<extracted pack>/windows cargo test --release -p seance_plugin_memory_windows
--test legacy_xp_corpus`.

### MEM-W11-TAMPER - user-mode tamper planted on the Windows 11 corpus VM, 2026-10-20

**SYNTHETIC.** The answer is planted by us, in processes we own, so this grades
whether the checks SEE the technique when it is present and stay silent elsewhere on the same
machine. It says nothing about how often real attackers use the technique, and nothing about
kernel-side tamper (timers, unloaded modules, Skeleton Key), which a user-mode plant cannot reach.

**Image.** `~/forensic_corpora/win11_tamper_plant/tamper-plant.raw`, SHA-256
`6a2c583db52818965c3d9a5972c6ce583e9a6ddba5e185eebd80f904682c9fa7`: guest RAM of the repo's own
Windows 11 25H2 VM (build 26200, `FORENSIC-W11`, BitLocker unlocked via swtpm), taken from a
copy-on-write overlay of `seance-w11.qcow2` with QMP `dump-guest-memory` and `elf2raw.py`.
Provenance: that directory's `SOURCE.md`. Not committed (10 GiB apparent).

**Planter.** `test_data/win11_tamper_plant/plant.ps1`, one PowerShell process per role, each
printing its ground truth (`plant-truth.json`) from inside the guest, then sleeping so the state
is live at capture.

| Role | Planted (pid / tid) | Seen as |
|---|---|---|
| `etw1` | `ntdll!EtwEventWrite` first byte := `c3`, pid 1788, `0x7ffc7dc0e470` | `returns_immediately` (`ret`), minority 1 against 100 of 102, route `both`, prologue bytes equal the planted bytes |
| `etw2` | first bytes := `33 c0 c3`, pid 4696, same address | `returns_immediately` (`xor eax,eax; ret`), minority, route `both` |
| `dr` | Dr0 = `0x7ffc7cdcaf90`, Dr7 = 1 via `SetThreadContext`, pid 1428 tid 2640 | one armed slot 0 at the planted address, claim `confirmed_by_the_thread's_own_flags`, `DebugActive` 1, `ActiveDR7` 1 |
| `susp` | worker thread left suspended, pid 4868 tid 1332 | listed in `suspended_threads` with `suspend_count` 1; every row `is_a_finding` false |

**False positives on the same capture.** ETW: 407 export rows over 102 assessed processes,
exactly 2 signals, both planted. Debug registers: exactly 1 thread with a breakpoint, the
planted one. Suspended threads stay a listing.

**Result.** Three of the six groups have a true positive on a known answer:
`etwpatch` (both routes agree on both patch shapes), `debugregisters` and `suspended_threads`.

**Bounds.** The ETW patch is in one process, so the modal route is exercised; the machine-wide case (mode itself
patched, classification alone fires) is graded in `MEM-W11-TAMPER-2`. Each plant is a technique we
wrote, self-applied, user mode. Timers, unloaded modules as a signal and `skeleton_key_check` remain without a true positive.

**Re-run.** `SEANCE_SYMBOL_DIRS=<win11 ISF dir>:<volatility3 symbols> cargo test --release -p
seance_plugin_memory_windows --test win11_tamper_plant` (about 8 minutes; skips if the capture
is absent).

### MEM-W11-TAMPER-2 - a machine-wide EtwEventWrite patch, 2026-10-23

**SYNTHETIC**, as `MEM-W11-TAMPER`. **Image:** `~/forensic_corpora/win11_tamper_plant_etwall/tamper-etwall.raw` (SHA-256 `d7857286d76fb1dd41ccd7e63f04aad3180bf77fae8c0fe04cb5560b39e839c1`; provenance in that directory's `SOURCE.md`): guest RAM of the Windows 11 lab VM (build 26100) after `plant.ps1 -Role etwall` wrote `c3` (`ret`) over `ntdll!EtwEventWrite` in 107 of its 130 processes (every 64-bit one the account could open; the rest are protected, 32-bit or gone), through `OpenProcess` / `VirtualProtectEx` / `WriteProcessMemory`. The pids and original bytes are `plant-truth.json`. The earlier plant patched one process, so the modal route fired; this one makes **the mode itself the patch**, which only the classification route can see.
**Modal route.** With the mode itself patched, genuine copies differ from it: 18 genuine, unpatched copies would be signals on the modal route, while the record's own note says such copies "may be the clean ones". A row carries `mode_is_patched`, true when every copy that set the mode classifies as a signal, and the modal route ignores a mode that is itself the patch (`a_copy_that_differs_from_a_patched_mode_is_not_a_signal`). **Result:** exactly the patched copies are signals (`route: classification`, `agrees_with_the_mode: true`, prologue `c3`, the one `ntdll` address everywhere), every other row is silent, and the record's note says the mode is patched. `a_machine_wide_etw_patch_is_seen_on_the_classification_route_and_the_clean_copies_are_not_flagged` (`win11_tamper_etwall.rs`, 53 s in release); the earlier `win11_tamper_plant` tests still pass. **Not established:** a plant we wrote, user mode, one machine; how real attackers patch; a machine-wide patch that preserves the prologue. **Re-run:** `cargo test --release -p seance_plugin_memory_windows --test win11_tamper_etwall` (ISF for the kernel under `reference/volatility3`; see `MEM-VC-6`).

### MEM-THR-1 — suspicious threads on a clean Windows 11 capture and three XP captures, 2026-09-27

**What.** The `suspicious_threads` stage: each live thread's
`StartAddress` and `Win32StartAddress` placed in its own process's VAD tree.
**Oracle.** Volatility 3 2.28.2 `windows.malware.suspicious_threads`
(`reference/volatility3`, run as an oracle only; it needs `pefile` on the
Python path). **Known answer:** none. The Cookbook and Stuxnet write-ups name
kernel orphan threads, not injected user threads, so every count below is
**observed and oracle-compared, not graded**.

| Image | Processes judged | Starts tested | Séance findings | Volatility rows (distinct thread/address) | LPC ids not judged | Kernel starts on kernel threads | Kernel starts on threads with `SystemThread` clear (judged by no stage) | Record complete |
|---|---|---|---|---|---|---|---|---|
| Windows 11 build 26200 `memory-unlocked.raw` (clean) | 123 | > 500 | **0** | not run (10 GiB) | — | 2 | 76 | **no** |
| `be2.vmem` (XP SP2) | 23 | 192 | **1** — svchost 856 | 4 | 33 | 0 | 0 | yes |
| `zeus.vmem` (XP SP2) | 23 | 202 | **10** — winlogon 632 ×2, svchost 856 ×8 | 13 | 26 | 0 | 0 | yes |
| `stuxnet.vmem` (XP SP3) | 28 | 215 | **9** — services 668, svchost 940 ×2, lsass 868 ×2, lsass 1928 ×4 | 25 | 33 | 0 | 0 | yes |

Every Séance finding is also a Volatility row, and every one is a
`Win32StartAddress` in a private `PAGE_EXECUTE_READWRITE` range. Every
Volatility row Séance does not print is a `Win32StartAddress` of zero or a
small integer (0x66ae, 0x685f, 0x35178 …) in a read-write range at the bottom
of the address space. On XP that field shares its offset with
`LpcReceivedMessageId`, and each such thread has `LpcReceivedMsgIdValid` set, so
the value is an LPC message id. Séance does not judge them as starts (a judgement that would report smss.exe's 0x66ae on be2 and count 32 other message ids as starts in no range). Kernel-mode starts (kernel threads working inside csrss, lsass, svchost …) are counted separately: 78 of them on the Windows 11 capture would otherwise be unattributed and make every one of those processes incomplete. Both are pinned by unit tests on synthetic fixtures; the counts above are the real-evidence measurement.

**Kernel-mode starts.** On x64 the floor for a kernel start is the canonical `0xFFFF8000_00000000` (x86: the image's `MmSystemRangeStart`), not `MmHighestUserAddress` + 1, which admits the whole non-canonical hole: a smeared `0x4141414141414141` would read as a kernel thread. Of the 78 kernel-mode starts on the Windows 11 capture only 2 are on threads whose `_KTHREAD.SystemThread` is set; the other 76 read **clear**, and the `tamper_checks` orphan-thread group sets every such thread aside as a user thread, so no stage judges them. They are counted in `kernel_starts_on_threads_not_known_as_system` and the Windows 11 record says it is incomplete. What those 76 threads are (most start in session space, `0xffffcc81…`) is not established here. The XP counts do not depend on it.

### MEM-THR-2 — suspicious threads on seven more captures, with the clean-capture false-positive count, 2026-10-22

**Re-run:** `cargo test --release -p seance_plugin_memory_windows --test case001_corpus -- --nocapture --test-threads=1`
with `SEANCE_SYMBOL_DIRS` (the extracted Volatility Windows symbol pack), `SEANCE_CASE001_MEM` (a directory holding
`citadeldc01.mem` and `DESKTOP-SDN1RPT.mem`), `SEANCE_CUBED13_MEM`, `SEANCE_LONEWOLF_MEM`, `SEANCE_SAMSCLASS_MEM`
and `SEANCE_BOOMER2003_MEM`; a capture whose variable is unset skips and says so. **Known answer:** none for an injected
user thread in any of these captures, so the counts are **observed and oracle-compared, not graded** (as in `MEM-THR-1`).
All twelve tests of the file pass: every pinned count holds.

| Capture | Processes judged | Starts tested | Findings (evidence) | Gaps (backing file unreadable) | Kernel starts on threads without `SystemThread` |
|---|---:|---:|---:|---:|---:|
| samsclass Server 2008 SP1 x86, clean lab VM | 44 | 387 | **0** | 3 | 61 |
| CFReDS Server 2003 SP0 (`boomer-win2003`), Notepad only | 21 | 173 | **0** | 0 | 0 |
| LoneWolf Windows 10 1803 | 150 | 1,174 | **0** | 0 | 211 |
| 13Cubed mini-memory CTF (Windows 10, rogue svchost planted) | 125 | 968 | **0** | 0 | 183 |
| Case 001 domain controller (Server 2012 R2, compromised) | 38 | 365 | **1**: spoolsv 3724 / 2508 | 0 | 69 |
| Case 001 desktop (Windows 10, compromised) | 85 | 697 | **1**: powershell 3316 / 3892 | 61 | 85 |

**The false-positive count on non-intrusion captures is 0 of 4, plus 0 on the clean Windows 11 capture of `MEM-THR-1`.** No
write-up or key says any of the four holds an injected thread, and the stage printed none; the 13Cubed capture's planted
process is a masquerading svchost, not an injected thread, and is not a finding of this stage. **Two findings on compromised
machines.** Both Case 001 findings are a `Win32StartAddress` in a private `PAGE_EXECUTE_READWRITE` range. No key was
consulted for whether these threads belong to the intrusion, so they are observations, not graded true positives. Volatility 3 2.28.2 `windows.malware.suspicious_threads` on the desktop prints
the powershell thread (3316 / 3892, `0x10c6bb00000`) twice, once for the non-file-backed region and once for the unexpected
`PAGE_EXECUTE_READWRITE` protection, which is the one Séance finding. The other rows Volatility prints are
`PAGE_EXECUTE_WRITECOPY` starts whose file name it could not read; Séance publishes the same 61 as gaps, not as evidence.
The domain controller was not re-run under Volatility here.

**Not established.** No capture holds an injected thread that Séance missed or that is known to be absent from a
compromised machine, so a missed-detection rate is not measured; the 61 gaps on the desktop are threads the stage could not place,
not threads it cleared.

### MEM-C001-1 — the tamper checks on DFIR Madness Case 001 memory, and the encoded timer DPC, 2026-09-24

**Images.** DFIR Madness Case 001 ("The Stolen Szechuan
Sauce"): `citadeldc01.mem` (Windows Server 2012 R2 x64, 2 processors, from `DC01-memory.zip`)
and `DESKTOP-SDN1RPT.mem` (Windows 10 x64, from `DESKTOP-SDN1RPT-memory.zip`), 2 GiB raw each;
provenance and published MD5s in `~/forensic_corpora/dfir_madness_case001/PROVENANCE.md`.
Re-graded with them: Windows 11 26200 (`memory-unlocked.raw`), the 13Cubed mini-memory CTF
image (Windows 10), LoneWolf (`~/forensic_corpora/lonewolf/memdump.mem`, Windows 10; the
`lonewolf_mem` path is a symlink to it), the four XP captures of MEM-XP-1 and the CFReDS
Server 2003 RTM capture. **Oracle:** Volatility 3 2.28.2 `windows.timers`, run on the same files,
never wrapped; its offsets print without the canonical sign extension and were compared
canonicalised.

**Encoded DPC.** Server 2012 R2 stores `_KTIMER.Dpc` encoded with `KiWaitNever`/`KiWaitAlways` and
the timer's address, and the group decodes it instead of reading it as the pointer it is declared
as. A misreading is silent on every x64 build that encodes: on the Desktop 359 encoded values would
be published as DPC addresses with no routine read, and the Windows 11 baseline of "209 timers, all
with a DPC, 0 outside a module" would have read no routine at all. Evidence arithmetic never
panics: `citadeldc01.mem` would otherwise stop the pipeline with `attempt to add with overflow` at
`dpc + layout.dpc_routine`. Pinned by `a_dpc_value_whose_members_overflow_is_unreadable_and_not_a_panic`
and two further evidence-arithmetic sites (`a_legacy_link_at_the_top_of_the_address_space_…`,
`a_prcb_pointer_whose_table_runs_past_the_address_space_…`); the decode's own tests
(`an_encoded_dpc_is_decoded_with_this_builds_keys`, `…_not_a_kdpc_is_unreadable_…`,
`unreadable_keys_…`) and `an_encoded_null_dpc_is_a_timer_with_no_dpc`. An unloaded-driver slot past
the top of the address space and a module ending at 2^64 in the ETW/Skeleton Key route are likewise
handled without a panic.

**The decode.** Published by Skape (*Uninformed* vol. 8 art. 5) and debugwar.com: XOR
`KiWaitNever`, rotate left by its low byte, XOR the `_KTIMER` address, byte-swap, XOR
`KiWaitAlways`. It runs only on an x64 build declaring both keys, and every result must land on
a structure whose `Type` byte is one of the build's own `_KOBJECTS.DpcObject` /
`ThreadedDpcObject` values; a failure is `dpc_unreadable` with the reason, never a fallback.

| Image | Timers | With a DPC (distinct) | Unreadable (decodes non-canonical) | = Volatility timer, routine, period | Outside every module |
|---|---:|---:|---:|---:|---:|
| Windows 11 26200 | 209 | 52 (52) | 0 | 52 of 52 | 0 |
| Case 001 DC (2012 R2) | 237 | 40 (39) | 35 | 39 of 39 | 0 |
| Case 001 Desktop (Win 10) | 367 | 63 (38) | 74 | 38 of 38 | **1 timer** (2 rows walked; ungraded, see below) |
| 13Cubed (Win 10) | 475 | 83 (49) | 153 | 49 of 49 | 0 |
| CFReDS Server 2003 RTM (x86, not encoded) | 156 | 43 (43) | 0 | 43 of 43 | 0 |

LoneWolf (Windows 10, smeared) reads 639 timers and 107 with a DPC (50 distinct)
and 0 outside a module, but is **not graded**: Volatility 3 printed no timer row for it within a
5,000-second run. No row Séance located is absent from Volatility's output, and none of Volatility's is missing
from Séance's. Volatility prints no row for any of the unreadable ones either. **The Desktop's
one signal** is the timer at 0xffffbe8e7105d5ab — not 8-aligned, its `_KDPC` at +0x40, its
routine 0xffffbe8e70b622b1 in pool, its `DeferredContext` non-canonical (0x5a474314a0a22080) —
which Volatility also prints with no module. That is the shape PatchGuard's own timer takes on
a clean machine; it is published as the signal the rule defines and is not a graded verdict.

**PatchGuard-shaped timers.** A row with all three of those conditions (unaligned `_KTIMER`, routine
in no module on an authoritative map, non-canonical `DeferredContext`) is published as
`patchguard_shaped` and not graded, and raises no kernel-tamper lead. Measured (`--release`, the
extracted Volatility Windows pack): Desktop 0 timers outside every module graded and 1 timer
PatchGuard-shaped. The Desktop reads 187 distinct timers, 38 with a DPC, and the shaped timer at
0xffffbe8e7105d5ab is published once with both buckets it was reached from in `reached_from`. That is
pinned by `the_desktops_patchguard_shaped_timer_is_not_a_signal` (`patchguard_shaped == 1`, one row,
`reached_from` of at least 2), run green on the capture 2026-09-26; DC, Windows 11 26200, 13Cubed and
LoneWolf 0 graded and 0 shaped (DC and Windows 11 pinned; 13Cubed 475 rows and LoneWolf 639 rows
measured with `measure_the_tamper_checks_on_any_capture`). The rule has no true positive to be
tested against: no capture here holds a timer rootkit.

**Further captures.** Eleven more Windows captures are held. Measured `--release` with
`measure_the_tamper_checks_on_any_capture`; the figures are Séance's own counts of distinct timers, not graded
against Volatility (the Volatility comparison above stands for the captures it names).

| Image | Timers (distinct) | Rows walked | With a DPC | Unreadable | Outside any module | PatchGuard-shaped | Status |
|---|---:|---:|---:|---:|---:|---:|---|
| `ctf-evidence/winmem2020/memdump-001.mem`, Win 7 SP1 x64 (Magnet Virtual Summit 2020) | 452 | 611 | 85 | 79 | 0 | 0 | measured |
| `win11-lab/console/mem.raw`, Win 11 26200.6584 | 157 | 157 | 53 | 0 | 0 | 0 | measured |
| `win11-lab/vc/mem.raw`, Win 11 26200.6584 | 168 | 168 | 52 | 0 | 0 | 0 | measured |
| `samsclass_server2008_mem/memdump.mem`, Server 2008 SP1 x86 | 171 | 190 | 55 | 0 | 0 | 0 | measured |
| `r2d2_0zapftis_mem/0zapftis.vmem`, XP x86 | 205 | 205 | 55 | 0 | 0 | 0 | measured |
| Cookbook `coreflood.vmem`, XP SP2 x86 | 176 | 176 | 62 | 0 | 0 | 0 | measured |
| Cookbook `laqma.vmem` | 190 | 190 | 63 | 0 | 0 | 0 | measured |
| Cookbook `prolaco.vmem` | 140 | 148 | 50 | 0 | 0 | 0 | measured |
| Cookbook `sality.vmem` | 242 | 242 | 61 | 0 | 0 | 0 | measured |
| Cookbook `silentbanker.vmem` | 175 | 175 | 62 | 0 | 0 | 0 | measured |
| CFReDS `boomer-win2003-2006-03-17.img`, Server 2003 x86 | 156 | 156 | 43 | 0 | 0 | 0 | measured |
| `m57_terry_vista_ram/terry-2009-11-16.mddramimage`, Vista SP2 x86 | 188 | 214 | 54 | 0 | 0 | 0 | measured 2026-10-22 (`MEM-XP-5`) |
| `lab_w2k3_r2_sp2_x64/mem.raw`, Server 2003 R2 SP2 x64 | 211 | 211 | 54 | 0 | 0 | 0 | measured 2026-10-22, equals the Volatility 2 walk (`MEM-XP-6`) |

The three Windows 11 images are one build (26200.6584), and `win11-lab/images/memory-unlocked.raw`, already
pinned above, is the same VM's capture. The Volatility pack alone holds no ISF for that kernel
(`ntkrnlmp.pdb` `E6426A07C26E66F8EB8594621A7B273B`) and the stage refuses with a stated reason, so the two new
Windows 11 captures were measured with `SEANCE_SYMBOL_DIRS` naming `test_data/win11_bitlocker/symbols` as well.
`memory-unlocked.dmp`, `crashdump/win10.dmp` and `hiber/hiberfil.sys` are other formats and were not run through
this raw-image harness; `win11_bitlocker` is a disk image. The Cookbook `tigger`, `be2`, `zeus`, the Stuxnet
capture, 13Cubed and Lone Wolf are recorded above and in `legacy_xp_corpus.rs`. **No capture held contains a
timer rootkit.** Across every capture that could be read, the only PatchGuard-shaped timer is the Case 001
Desktop's, so the rule has no true positive tested against it, only the absence of a false one.

SHA-256 of the images new to this table:

| Image | SHA-256 |
|---|---|
| `memdump-001.mem` | `18e9007993c45f813dd5bd23b6bf6ad703d3e6ac70effd9c47a310a8443c7b8a` |
| `win11-lab/console/mem.raw` | `213397612ac3668bfed09474a21d28772e98cbfae6557f0fca2bc4a37af4d567` |
| `win11-lab/vc/mem.raw` | `8590ad53b066a72ffd55f650e960ddf3dffff85dfc14dc5753099498787b2403` |
| `samsclass_server2008_mem/memdump.mem` | `d3b13f2224cab20440a4bb3c5c971662be6e61f431340f319cef7312bb6177f4` |
| `0zapftis.vmem` | `eb8cc1f46cf0ed2ada1b467916a684ee8ab3e5ce2cb66ee581f89d921e4e539b` |
| `terry-2009-11-16.mddramimage` | `1d8d446db95ccae3c1daf95348bce78ddf4aaf759001d711b3cef5be136d6806` |

Re-run (one capture at a time; the JSON has `timers.timers_reported`, `rows_walked`, `timers_with_a_dpc`,
`dpc_unreadable`, `routines_outside_any_module`, `patchguard_shaped`):

```
SEANCE_TAMPER_IMAGE=<capture> SEANCE_TAMPER_OUT=<out>.json \
SEANCE_SYMBOL_DIRS=<volatility pack>:test_data/win11_bitlocker/symbols \
cargo test -p seance_plugin_memory_windows --release --test case001_corpus \
  measure_the_tamper_checks_on_any_capture -- --nocapture
```

Pinned by `further_captures_read_no_graded_and_no_patchguard_shaped_timer` (`case001_corpus.rs`), one variable per
capture: `SEANCE_WINMEM2020`, `SEANCE_SERVER2008_MEM`, `SEANCE_ZAPFTIS_MEM`, `SEANCE_WIN11_CONSOLE_MEM`,
`SEANCE_WIN11_VC_MEM`, skipped when unset. The Cookbook five and the 2003 image are pinned in
`legacy_xp_corpus.rs` for 0 outside a module.

**Counts of timers, not rows.** The first table above counts rows. A `_KTIMER` reached from more than one bucket list is one row with every
`(processor, bucket)` that reached it in `reached_from`; a `KiProcessorBlock` slot repeating an
earlier `_KPRCB` is walked once and named; and a bucket list whose next link is another bucket's
head stops there (`entered_another_bucket`) instead of publishing that head as a timer and walking
on into a cycle. Measured `--release` with the extracted Volatility Windows pack, every capture
held:

| Image | Distinct timers | Sightings (`rows_walked`) | Rows before | With a DPC | Unreadable (before) | Reached twice: lists seen to join / reason not established |
|---|---:|---:|---:|---:|---:|---:|
| Windows 11 26200 | 209 | 209 | 209 | 52 | 0 (0) | 0 / 0 |
| Case 001 DC (2012 R2) | 179 | 196 | 237 | 39 | 2 (35) | 4 / 8 |
| Case 001 Desktop (Win 10) | 187 | 245 | 367 | 38 | 3 (74) | 11 / 16 |
| 13Cubed (Win 10) | 197 | 265 | 475 | 49 | 8 (153) | 12 / 21 |
| LoneWolf (Win 10, smeared; ungraded) | 246 | 342 | 639 | 50 | 5 (—) | 15 / 43 |
| tigger, be2, zeus, stuxnet (XP) | unchanged | = distinct | — | 60, 60, 64, 58 | — | 0 / 0 |

The DPC counts are now the distinct counts Volatility 3's `windows.timers` prints, and are
unchanged from the "(distinct)" column above. The unreadable rows fell because most were bucket
heads read as `_KTIMER`s. No capture repeated a `_KPRCB` pointer (LoneWolf's kernel claims 4
processors and the array names 4). 31, 56, 97 and 120 bucket lists entered another bucket's head
on the DC, Desktop, 13Cubed and LoneWolf. The timers reached twice with no mechanism the walk saw
say so on the row. Pinned: `case001_corpus.rs` (DC 179/196/12,
Desktop 187/245/27), `win11_corpus_analysis.rs` (209/209/0) and `legacy_xp_corpus.rs`
(`rows_walked` equals the distinct count on all four); 13Cubed and LoneWolf were measured with
`measure_the_tamper_checks_on_any_capture` and are not pinned. The CFReDS Server 2003 RTM capture
was not re-run. The mechanisms are pinned on synthetic fixtures in `tamper_timers_tests.rs`;
those fixtures pin the mechanism and are not validation.

**Debug registers.** On a build declaring `ActiveDR7`, only that bitfield (position from the
ISF) confirms, and a confirmed row with Tid 0 or a non-canonical armed address is not graded.
Confirming whenever the whole `DebugActive` byte is non-zero overcounts. Tests: `ActiveDR7 is clear, so nothing says these bytes are debug registers`, `bit 0 is not
ActiveDR7 on this build`, `a Tid-0 thread is not graded`, and the non-canonical case. The table
gives confirmed and graded rows on the whole-byte rule → on the `ActiveDR7` rule.

| Capture | Confirmed rows before → after | Graded before → after |
|---|---:|---:|
| tigger, be2, zeus, stuxnet (XP; no `ActiveDR7`) | 1 → 1 each | 0 → 0 |
| CFReDS Server 2003 RTM | 1 → 1 | 0 → 0 |
| Windows 11 26200 | 0 → 0 | 0 → 0 |
| LoneWolf | 3 → 1 | **1 → 0** |
| 13Cubed | 15 → 5 | 0 → 0 |
| Case 001 DC | 1 → 1 (Tid 0) | 0 → 0 |
| Case 001 Desktop | 1 → 0 | 0 → 0 |

**The Desktop tamper-checks record.** With the extracted pack the
Desktop yields a `MemoryTamperChecks` record with all seven groups run, and the regression test
fails if it yields neither that record nor the stage's failure record. With a symbol
directory lacking its kernel (`81BC5C377C525081645F9958F209C527-1`) the pipeline emits the stage
manifest and a `MemoryProfile` discovery-failure record naming the GUID, which is a stated
refusal, not silence.

**Re-run.** `SEANCE_CASE001_MEM=<dir with both .mem files> SEANCE_SYMBOL_DIRS=<extracted pack>
cargo test -p seance_plugin_memory_windows --release --test case001_corpus`; any other image:
`SEANCE_TAMPER_IMAGE=<file> SEANCE_TAMPER_OUT=<json>` with the `measure_…` test of that file.

### MEM-ARM-1 — the ARM64 translation core on real (emulated) AArch64 page tables, 2026-09-24

**Evidence.** The MMUShell dataset (Oliveri & Balzarotti, ACM TOPS 2022; EURECOM
S3, `mmushell_dataset.tar` SHA-256 `70679ac2…c82e0e`): `aarch64/linux.7z` and
`aarch64/linux_debian.7z`, each a 4 GiB RAM dump at physical 0x40000000 and a register trace
QEMU recorded. **QEMU-emulated guests, not ARM64 hardware**; no symbols. The trace is a Python
pickle and was read with `pickletools` and a symbolic opcode reader, never unpickled.

**Ground truth and oracle.** The `TCR_EL1` / `TTBR1_EL1` / `TTBR0_EL1` values in force at the end
of each run (linux: `0x32b5593519`, `0xe6000040755000`, `0x139de0000`; debian:
`0x400032b5503510`, `0x42e0000412ee000`, `0x13d142000` — debian's last twelve `TTBR0` values map
nothing, so the latest that does was used). Both decode to a 4 KiB granule, `IPS` 40-bit,
`TBI0` = 1, `TBI1` = 0, `DS` = 0; linux is 39-bit (three levels), debian 48-bit (four). The
oracle is a Python stage-1 walker written from ARM DDI 0487 D8 without reference to Séance's.

| Tree | 4K pages | 2M blocks | 1G blocks | Agree |
|---|---:|---:|---:|---|
| linux kernel (`TTBR1`) | 2,383 | 544 | 3 | all |
| linux process (`TTBR0`) | 264 | — | — | all |
| debian kernel | 6,125 | 1,183 | 2 | all |
| debian process | 1,159 | — | — | all |

**11,663 of 11,663 leaves agree** (counts by size and an order-independent digest over
`(va, pa, size)`), with 69 interior spot translations and 64 faults (level, entry, entry
address) hard-coded from the oracle. Not exercised on these trees: swap or `PROT_NONE`
descriptors (none exist in them). Granules other than 4 KiB have met real QEMU page tables in
`MEM-ARM-5` and `MEM-ARM-6`, and Linux arm64 discovery is graded in `MEM-ARM-2` to `MEM-ARM-4`.

**Re-run.** `SEANCE_MMUSHELL_AARCH64=<dir holding linux/linux.dump and debian/linux.dump> cargo
test -p seance_memory --release --test arm64_mmushell_real_test`.

**Regime decoding.** The regimes are built from the recorded `TCR_EL1` values by
the crate's own decoder (`Arm64Regime::from_tcr_el1`; the test also reads each field by hand
and asserts they agree), and every leaf count and digest above is unchanged under it. TBI is
honoured when the regime records it: the pinned limit is flipped, and
`a_tagged_user_pointer_translates_under_tbi0_and_a_tagged_kernel_pointer_faults_under_tbi1_clear`
translates every `TTBR0` spot address with the tag `0x2a` to the oracle's physical address
while a tagged kernel pointer (`TBI1 = 0`) is still `NonCanonical`. `IPS` is enforced (an output
address above it is an Address size fault, refused with the entry verbatim) and hierarchical
`PXNTable`/`UXNTable` are folded into `no_execute` unless `HPDn` is set; **neither has a real
descriptor to meet here** (no output address above 40 bits, no table descriptor sets bits
63:59), so both are pinned on synthetic tables only. `APTable` is not read (no access
permission is reported at any level).

### MEM-ARM-2 — the arm64 kernel page-table root from the kernel's own `VMCOREINFO`, 2026-09-26

**Evidence.** The same MMUShell `aarch64/linux_debian` dump (QEMU-emulated, Debian
`4.19.0-11-arm64`). A byte search for `OSRELEASE=` finds four hits: two are the kernel's
`"OSRELEASE=%s"` format string in `.rodata` copies and are refused as not a note; two are the
`VMCOREINFO` text itself (the ELF note, after its `VMCOREINFO` name, and the `vmcoreinfo_data`
buffer), and they agree line for line. The buildroot `aarch64/linux` dump holds no
`VMCOREINFO` at all: the sweep is complete and meets no `OSRELEASE=` hit, accepted or refused
(both asserted empty), so this validation has one image. Why it holds none — presumably a kernel
built without `CONFIG_CRASH_CORE` — is inferred from that absence, not read from the image. A
sweep that is cut short now answers "could not look" (`SweepIncomplete`), never "no copy".

**Ground truth.** The note states `SYMBOL(swapper_pg_dir)=ffff0000092ee000` and
`NUMBER(kimage_voffset)=0xfffeffffc8000000`; their difference, `0x412ee000`, is the claim.
QEMU's recorded `TTBR1_EL1` is `0x42e0000412ee000` — BADDR `0x412ee000` — which the code never
reads. **Result.** The claim equals the register, and of the seven arm64 kernel regimes
offered (4K/48, 4K/39, 64K/48, 64K/42, 16K/47, 16K/48, 16K/36) exactly one — 4 KiB, 48-bit,
matching the note's `PAGESIZE=4096` and `NUMBER(VA_BITS)=48` — translates
`SYMBOL(init_uts_ns)` to bytes holding `4.19.0-11-arm64` NUL-terminated. **Bounds.** A root
proof, not a Linux profile: no arm64 symbol table (ISF) is held for this image and 4.19 carries no
BTF, so no analysis stage runs here (`MEM-ARM-4` builds a profile from the exact kernel package's
symbol file); one emulated image, 4 KiB granule only.

**Re-run.** `SEANCE_MMUSHELL_AARCH64=<dir> cargo test -p seance_plugin_memory_linux --release
--test arm64_vmcoreinfo_real_test`.

### MEM-LAYER-1 — the layer export and its hole manifest on a real crash dump, 2026-09-27

`layerwriter`. **Evidence.** `win10.dmp`, the corpus's genuine Windows 11 26200
kernel crash dump (a `MANUALLY_INITIATED_CRASH` on the corpus VM; 401,435,031 bytes), whose own
`_DUMP_HEADER` run table states which physical ranges it saved. **Ground truth.** That run table,
read by the crash reader (`formats::crash::open`) independently of the export. **Result.** The
export seam (`open_physical_layer`) rebuilds a 10,737,418,240-byte physical space; the manifest
lists **11,686 holes, 10,336,395,264 bytes of fill**, exactly the complement of the run table,
and **401,022,976 backed bytes**, equal to the bytes the dump stores. The whole layer was streamed
into a checking sink (nothing written to disk, 9.5 s in release): every byte the manifest calls
fill is `0x00`, the byte count equals the plan, and the first 64 bytes of the first, middle and
last run equal the crash reader's own reads. **Bounds.** One format on real evidence; LiME is
pinned only on a synthetic file built in the test (`seance_memory` unit test and
`seance_api/tests/memory_layer_export_test.rs`), and hibernation, AVML, ELF core, QEMU and
VMware exports are not checked on real captures here. The physical layer only: no translated
(virtual) layer export was run. No other tool's `layerwriter` output was compared.

**Re-run.** `SEANCE_MEM_IMAGES=<dir holding win10.dmp> cargo test -p seance_memory --release
--test layer_export_real_test -- --nocapture`.

### MEM-ARM-3 — the kernel's own `kallsyms` decoded from both AArch64 dumps, 2026-09-26

**Evidence.** Both MMUShell AArch64 dumps (QEMU-emulated; buildroot
`4.19.91`, Debian `4.19.0-11-arm64`). **Layout.** On arm64 `Kallsyms::find_in` meets three differences from the older layout, each
read from a byte dump of the Debian table and confirmed on buildroot: every
array starts on a **256-byte** boundary (the older `.align 8`, which the arm64 assembler reads
as 2^8), `kallsyms_markers` entries are **eight bytes**, and no offset is negative (arm64 is
built without `KALLSYMS_ABSOLUTE_PERCPU`, so every address is `relative_base + offset`). The
decoder tries both alignments and both marker widths, keeping only a candidate that passes
the whole self-checking decode, and reads a table with no negative offset as base-relative;
each is pinned on a synthetic block as well.

**Ground truth.** Read by hand from the bytes, not by the decoder: `kallsyms_num_syms` 38,164
(Debian) and 20,637 (buildroot); `kallsyms_relative_base` `0xffff000008080000` and
`0xffffff8008080000`. The arm64 `Image` header at physical `0x40080000` (`ARM\x64` at 0x38,
`text_offset` `0x80000`, per `Documentation/arm64/booting.txt`) is where `_text` must land.
**Result.** Both decode to exactly those counts; `_stext` is `relative_base + 0x1000`, and
`_stext - 0x1000` translates under QEMU's recorded `TTBR1_EL1` root to `0x40080000`, which
holds that header. The x86-64 6.8 known answer (`kallsyms_modern_kernel_test`, guest
`/proc/kallsyms`) is unchanged. **Bounds.** Neither kernel was built with `KALLSYMS_ALL`: the
complete decode lists no data symbol (`linux_banner`, `swapper_pg_dir`, `init_task` and
`kimage_voffset` all absent), so the banner proof of the kernel root **could not be run from
kallsyms** on either dump — an arm64 capture whose kernel has `KALLSYMS_ALL` is what that
needs. Only text-symbol addresses are validated; no arm64 profile is built (4.19 has no BTF).

**Re-run.** `SEANCE_MMUSHELL_AARCH64=<dir> cargo test -p seance_plugin_memory_linux --release
--test arm64_mmushell_discovery_test` and `cargo test -p seance_memory --lib kallsyms`.

### MEM-ARM-4 — end-to-end arm64 Linux discovery and the process stages on the Debian dump, 2026-09-30

**Evidence.** The MMUShell `aarch64/linux_debian` dump (QEMU-emulated, not
hardware; 4 KiB granule, 48-bit) and the symbol file built from the **exact** kernel package
(`linux-image-4.19.0-11-arm64-dbg_4.19.146-1`, sha256 `d205f2eb…42b2`; `System.map` from the
`-unsigned` package, sha256 `34cb26b4…967b`), provenance in
`forensic_corpora/debian_4.19.0-11-arm64_dbg/SOURCE.md`. **Result.** `discovery::discover`
finds the banner, offers only the arm64 regimes (the symbol table declares `kimage_voffset`),
proves the tables by walking `linux_banner` back to the bytes the sweep found, and returns a
profile; the process list then walks from `init_task` and is graded against what the kernel's own
structures prove (idle task, pid 1/2, closed doubly-linked list, unique pids, `comm` equal to the
bytes at the linear-map physical address, every module a `.ko` the package ships, the kernel log
opening with the banner in `vmlinux`) — 8 tests, all passing on 2026-09-30. The buildroot dump has
no symbol file, so it is not profiled. **Bounds.** One emulated image, 4 KiB granule here. `proc_maps` takes the page shift from
the proved regime, and a 16 and a 64 KiB kernel are profiled and graded in `MEM-ARM-5` and
`MEM-ARM-6`. No published process list exists for the capture, so the grading is
structural, not a comparison with another tool's output. No arm64 hardware capture.

**Re-run.** `SEANCE_MMUSHELL_AARCH64=<dir> SEANCE_ARM64_DEBIAN_KERNEL=<dir holding isf/ and
extracted/> cargo test -p seance_plugin_memory_linux --release --test arm64_debian_profile_real_test`.


### MEM-ARM-5 — a real 16 KiB-granule arm64 Linux kernel: translation and discovery, 2026-10-20

**Evidence. QEMU-emulated, not hardware.** Debian trixie's own
`linux-image-6.12.107+deb13-arm64-16k-unsigned` (`CONFIG_ARM64_16K_PAGES`, sha256
`a9833c04…bcd867d`; the `-dbg` package sha256 `476e232b…0f17d75`) booted by `qemu-system-aarch64`
10.2.1 (TCG, `-M virt -cpu max,lpa2=off -m 512`, direct kernel boot) with a busybox initramfs
that starts three `sleep` processes. The guest was paused over QMP, RAM saved with `pmemsave
0x40000000` (`mem.raw`, 512 MiB, sha256 `86f87a25…87ba3b`), and `TCR_EL1`, `TTBR0_EL1`,
`TTBR1_EL1` read through the gdbstub: `0x015001f57551b511`, `0x00000000480a8001`,
`0x001a000041f54001`. They decode to 16 KiB in both halves, 47-bit, `IPS` 48-bit, `TBI0 = TBI1 =
1`, `DS = 0` (the kernel is built `VA_BITS_52` and fell back because `lpa2=off` withheld the
feature). Provenance and full hashes: `forensic_corpora/arm64_16k_qemu/SOURCE.md`; the verbatim
QEMU command line was not preserved, the line above is reconstructed from the flags the tests
record.

**Translation oracle.** A Python stage-1 walker written from ARM DDI 0487 D8 (16 KiB granule,
level 1 table only, level 2 a 32 MiB block or a table, level 3 a 16 KiB page) without reference
to the crate. `Arm64Regime::from_tcr_el1` on the recorded `TCR_EL1`, then
`seance_memory::translate` over the same RAM: kernel tree **35,417 pages and 8 blocks of 32 MiB**,
process tree **90 pages**, every leaf agreeing on count and an order-independent digest over
`(va, pa, size)` (`0x742bd1b6db017400`, `0x41b4c02ac781e505`), plus the spot translations and
the faults (level, descriptor, descriptor address) the oracle gave, and a tagged pointer under
`TBI0`/`TBI1`. No disagreement: the 16 KiB rules in `spec.rs` were right.

**Discovery.** `discover` with no symbol file builds the profile from the image's own BTF and
`kallsyms`, selects `arm64_16k_ttbr1`, proves the `TTBR1` base `0x41f54000` from `swapper_pg_dir`, and
the process list closes: pid 1 `init`, `kthreadd` as pid 2 with every kernel thread its child,
four user tasks of which three are `sleep` children of init, no duplicated pid. The map survey
reads busybox's file-backed VMAs with offsets equal to the ELF program headers' (`start -
0x400000`), which fails if `vm_pgoff` is scaled by 4 KiB. `proc_maps` takes the page shift from the
regime.

**Bounds.** One emulated kernel, one boot. The `-cpu max` capture of the same kernel
(`arm64_16k_lpa2_qemu`, `TCR_EL1` `0x095001f6754cb50c`, 52-bit, `DS = 1`) is refused by name and
not walked. No 32 MiB block in a process tree, no non-zero invalid descriptor, no
`APTable` bit set (the table descriptors do set `PXNTable`/`UXNTable`, see `MEM-ARM-9`), `HA = HD = 0`, output addresses below 40 bits. The graded process
list is structural (the boot script and the kernel's own invariants), not another tool's output.
No hardware.

**Re-run.** `SEANCE_ARM64_16K=~/forensic_corpora/arm64_16k_qemu cargo test -p
seance_memory --test arm64_16k_real_test` and `cargo test -p seance_plugin_memory_linux --test
arm64_16k_discovery_real_test`.

### MEM-ARM-6 — a real 64 KiB-granule arm64 Linux kernel: translation and discovery, 2026-10-20

**Evidence. QEMU-emulated, not hardware.** Ubuntu noble's
`linux-image-unsigned-6.8.0-71-generic-64k` (`CONFIG_ARM64_64K_PAGES`, package sha256
`69a4e64e…e0b9fc97`), the same QEMU invocation and initramfs, `mem.raw` sha256 `c9f25895…29fa1b`
(full hashes in `forensic_corpora/arm64_64k_qemu/SOURCE.md`). Registers through the gdbstub:
`TCR_EL1` `0x015001f5f5507510`, `TTBR1_EL1` `0x001a0000428a0001`, `TTBR0_EL1`
`0x001a0000400ec801`: 64 KiB, `T0SZ = T1SZ = 16` (48-bit, level 1 of 64 entries), `IPS` 48-bit,
`TBI0 = TBI1 = 1`, `DS = 0`.

**Translation oracle.** The same independent walker (64 KiB: levels 1 and 2 tables, a 512 MiB
block at level 2, level 3 a 64 KiB page, descriptor bits 15:12 RES0): kernel tree **13,203
pages**, process tree **26 pages**, digests `0xc8373daf6f15716b` and `0xe405543dd4e26e36`, spot
translations and faults, TBI. All agree. **Discovery.** The profile is image-derived from the
kernel's own BTF and `kallsyms` (no `System.map` or config was fetched), selects the 64 KiB
`TTBR1` regime, the process list closes as in `MEM-ARM-5`, and busybox's mappings carry `start -
0x400000` file offsets with the text ending at `0x5d0000` (`memsz` `0x1cb1ac` rounded to 64 KiB);
a reader scaling `vm_pgoff` by 4 KiB is 16 times short. This kernel's `init_task` links read
`0xffff0000…` (the 48-bit arm64 linear map), so the link gate's bound is `0xffff000000000000`
(`discovery::is_kernel_link`, pinned by `a_48_bit_arm64_linear_map_link_is_a_kernel_address`). **Bounds.** As `MEM-ARM-5`;
every leaf is a 64 KiB page, so no 512 MiB block was met.

**Re-run.** `SEANCE_ARM64_64K=~/forensic_corpora/arm64_64k_qemu cargo test -p
seance_memory --test arm64_64k_real_test` and `cargo test -p seance_plugin_memory_linux --test
arm64_64k_discovery_real_test`.

### VSS-1 — prior versions from a shadow copy's `$MFT`, 2026-09-24

Option B (diff only). The images are `dfir_ntfs`'s `vss_2003.tgz` (SHA-256
`0c0d35223bd2c155724973b7d0a411d6716ceee6c1986896b37e6fddf7f7bdcc`; NTFS at sector 63, six
shadow copies) and `vss_10.tgz` (SHA-256
`77deebdcede3d6464e5a183f7b9d5d14023accd27eb206fa9ed24010e581bf4f`; NTFS at sector 2048, six
shadow copies), extracted sparse with GNU tar. Every snapshot's `$MFT` was compared with the live
one: 6 × 87 records on the Server 2003 volume (10 to 73 differing per snapshot) and 6 × 51–53 on
the Windows 10 volume (9 to 34), all published, no cap reached. `vss_1_vol` lists its two
snapshots with `prior_versions.status: not_compared` and the reason — their store chain does not
build from that volume alone.

**The graded record.** Server 2003 volume, stack-1 snapshot (created 2019-06-04 23:43:01 UTC),
record 79, `Копия (50) Текстовый документ.txt`. Independent reading: `istat -o 63 vss_2003.raw 79`
on the live volume, and the stack-1 snapshot rebuilt by `reconstruct_snapshot_content` and written
whole to a sparse scratch file, then `istat`, `icat` and `fls` on that file, and the record's
header read by hand (`FILE`, sequence at 0x10, flags at 0x16, record number at 0x2C).

| Field | Independent reading | Séance (`VssPriorVersion`) |
|---|---|---|
| sequence number | live 2, snapshot 1 (`istat`; hand read) | `{field: sequence_number, live: 2, snapshot: 1}` |
| in use | live "Not Allocated", flags 0; snapshot "Allocated", flags 1 | `{field: in_use, live: false, snapshot: true}` |
| other compared fields | name, parent, size 7,106 and all eight `$SI`/`$FN` times equal | not listed |
| snapshot `$DATA` | 7,106 bytes, clusters 173–174 | `data_runs: [[708608, 7106]]` (173 × 4,096) |
| snapshot content | `icat` of the scratch file: 7,106 × `1`, MD5 `67e7f704b4d8042333c76b61c322e87f` | the same bytes, the same MD5, at ingest and through the content resolver |
| live clusters 173–174 | `3333…` — reused by another file since the deletion | not served: the runs resolve against the snapshot |

A second record pins a reused slot: Windows 10 volume, stack 1 (2019-06-05 00:14:31 UTC), record
39, `New Text Document.txt` — `istat` gives sequence 3, 80,640 bytes live and sequence 1, 34,944
bytes at clusters 6353–6361 in the snapshot; Séance publishes sequence 3→1 and size
80,640→34,944 among the differences, runs `[[26021888, 34944]]`, content MD5
`4169b85def5a85ec3e35d4996ae22acd` (= `icat` of the scratch file).

**Not established.** The full per-snapshot file-system walk (option A) is not built: nothing from a
snapshot's `$I30`, `$UsnJrnl`, `$LogFile` or unallocated space is read, and a file unchanged since
the snapshot has no prior-version record. No image here reaches either cap (1,048,576 records
compared, 10,000 published per snapshot), and none has a `$MFT` whose record 0 carries an
`$ATTRIBUTE_LIST`.

**Re-run.** `SEANCE_VSS_CORPUS=<dir with vss_10.raw and vss_2003.raw> cargo test -p
seance_plugin_vss --release --test real_vss_test` and `SEANCE_VSS_CORPUS=<same> cargo test -p
seance_api --lib a_vss_prior_version_resolves_against_the_rebuilt_snapshot`.

### CARVE-2 — Parquet extent, below-minimum carves and the BPG cap, 2026-10-20

**Question.** Is a Parquet file sized exactly from its trailing magic and footer length, and what does a carve
that ends short of its minimum look like in the case?

**Evidence, and what it is.** SYNTHETIC from a real tool, not real-world evidence, and it grades the extent only.
`seance_carving/tests/fixtures/carve018/pyarrow_26_0_0.parquet`: 11,249 bytes, SHA-256
`c3624c4f627130585493dd299bcf2c9043f6f36b0ac70e27305783f3a0030d27`, written by pyarrow 26.0.0
(`pq.write_table(pa.table({'a': range(1000), 'b': [str(i) ...]}))`), footer length field 0x1c, ending `PAR1`. The
below-minimum and BPG cases are in-test buffers, also synthetic.

**Result.** The file is sized to 11,249 bytes exactly when followed by 4 KiB of noise and when embedded at offset
8,192 in noise; cut 100 bytes short it has no extent and stays
unsized; a planted `PAR1` whose length field points at a non-`0x15` byte is skipped. The Parquet match is rare, and
the carve counts on DFTT 11/12 and the NIST DFR set (5,121, `CARVE-1`) were not re-run.

**Re-run.** `cargo test -p seance_carving --lib parquet`, `cargo test -p seance_carving --lib bpg`, `cargo test -p seance_plugin_carver below_minimum`.

### CARVE-1 — loose carving signatures checked on their header block, 2026-09-24

**Question.** A new header ends a running unsized carve only when it survives
its own `data_check` on its header block. Every signature matched on a magic of four bytes or
fewer (or zero bytes, or text) has a structural check from its format's specification. Does that
lose any real file, and what does it change on real images?

**Corpus.** DFTT #11 (FAT32) and #12 (ext2), and all 90 NIST CFReDS DFR images (72 GB); for the
per-file check, about 210,000 real files under `reference/`, `test_data/`, `/usr/share`,
`/usr/lib` and `/usr/bin`.

**Result.** Carves before (with `Dovecot` registered) 5,126; with it unregistered
5,123 (three `Dovecot` carves of 30 MB each after zero runs on `dfr-01-osx.dd`, lost); after
the per-signature checks 5,121: two `EXT` matches on `dfr-10-ext.dd` (offsets 485,088,256 and
597,481,472, each an indirect-block list whose block numbers put `53 EF` at 0x38) are refused,
and the two `EXT` carves they had cut short grow by 60,416 and 15,014,912 bytes. Every other
carve on all 92 images is identical in offset, size and validation. No real file is refused by
its own format's check. The JPEG check holds only the first segment to the specification, because DFTT #11's
`haxor2.jpg` is the image's deliberately damaged JPEG (its second segment's length byte zeroed).

**2026-09-26 re-run** (the generic `TIFF` registration given the IFD check its `TIFF_LE`/`TIFF_BE`
twins already had; a TIFF-style directory checked from the source where it lies; `CAM`, `DIM`,
`Papyrus`, `QuarkXpress` and `TIB` made weak headers that never end a running carve). Before and
after on the same 92 images: 5,121 carves each, identical in offset, size, signature and
validation. None of the 92 images yields a carve from any TIFF-family or weak-header signature,
so this sweep does not exercise the change at all; it shows only that nothing else moved. The
per-file check was run over 35 whole real TIFFs — the 34 macOS `User Pictures` TIFFs
(big-endian, directories 229–689 KB in) and the little-endian ImageMagick 6 fixture
`tiff_le_whole.tif` (directory at 8,200 of 8,450 bytes): all 70 claims on them (`TIFF` plus
`TIFF_BE` or `TIFF_LE`) passed their header block and were confirmed from the whole file
(`Some(true)`), none refuted. The same run also took the two 512-byte header-block fixtures
`tiff_le.bin` and `tiff_be.bin`; their directories lie at offset 520, past their 512 bytes, so
the 4 claims on them passed the header block but could not be looked at from the source
(`None`) — they are not counted as confirmations. The check prints the three outcomes apart
(`source_confirmed`, `source_refuted`, `source_could_not_look`). No real file of the five
weak-header formats, nor of `DAD` or `MYI`, is held.
`checks::tiff_ifd_plausible_at` reports a directory none of whose
entries lies inside the source as unknown (`None`) rather than confirmed (`Some(true)`); the
engine treats the two alike, so this sweep's result stands for it without a re-run.

**Re-run.** `CARVE_SWEEP_OUT=<file> cargo test --release -p seance_carving --test corpus_sweep
-- --ignored` before and after a change, and diff the two lists;
`SEANCE_CARVE_REAL_ROOTS=<dirs> cargo test -p seance_carving --lib
real_files_survive_their_own_header_block_check -- --ignored --nocapture`.

**2026-09-26 re-run, GIF/JPEG/PDF/OpenPGP.** Four signatures were given the
structure their specification sets: GIF walks its blocks to the trailer instead of stopping at
the first `0x3B` byte; JPEG walks its marker segments by length before the first scan, so an Exif
thumbnail's EOI is not the image's; PDF goes on past an `%%EOF` that another section (`N N obj`
or `xref`) follows in the same block; and the single-byte OpenPGP tags also need the algorithm
their packet layout places (RFC 4880/9580), a v3 key to be RSA and a v6 session-key packet's
field count to be one it can have. The OLE2 size its FAT gives is not marked truncated
when it ends exactly at the source's end. Before and after on the same 92 images: 5,121 carves
→ 5,068. All 53 `GPG` carves on the 92 images were false (none is an OpenPGP file) and are
gone, and the 30 carves they had cut short grow (27 `EXT`, one each of `GZIP`, `APPLE` and
`ZIP`). The format changes move eight carves (3 JPEG, 3 PDF, 2 GIF). On DFTT #11, `paul.jpg`,
`shark.jpg`, `sm1.gif`, `wword60t.zip` and `lin_1.2.pdf` now carve at their key's size and MD5
(12 of 15 byte-exact; `pumpkin.jpg`, `enterprise.wav` and `surf.mov` do not on this sweep). On DFTT #12 the raw engine's `blogo.gif` goes from 953 bytes "validated" to
12,288 not validated (its walk meets the indirect block), which is the honest verdict for a
contiguous carve; the carver rebuilds it (below). Every other carve on the 92 images is
identical in offset, size, signature and validation.

**Current result.** `surf.mov` carves to its key (550,653 bytes, MD5 `5328d2b0...`), so DFTT #11 is 13 of 15 byte-exact;
only `pumpkin.jpg` and `enterprise.wav` do not. Pinned by `dftt11_byte_exact_files_against_the_answer_key`
(the list is pinned both ways).

**MySQL `.MYI`.** The `.MYI` header check and its size are graded on
**synthetic** fixtures, so no claim about real-world evidence rests on them: MyISAM tables built
with docker `mariadb:10.11` (10.11.19) and `mysql:8.0` (a few rows to 200,000 rows; with no key,
one key, five keys, a fulltext key, empty). On all eight index files the header's `key_file_length`
(big-endian u64 at 0x3c) equals the file size. Committed: `myisam_mysql8_a.MYI` (3,072 B, SHA-256
`fa0726619c9c555d4c47082ac75a62ed96e73654ba7f6082fbfd2f98c5c63a24`), `myisam_mariadb_nokey.MYI`
(1,024 B, `4f153d89392aa5fb9165cb8ad0b414c01a95cd487205c536218c1cc7111f81d7`) and the first 1,024
bytes of the 14,090,240 B five-key index (`myisam_mariadb_many_head.bin`,
`67c5998d761c76c7bb3706cc2c3216ed18cb6e51220b2b8f495c5f26ac7bb32a`). The 92-image carve count
was not re-run. Re-run: `cargo test -p seance_carving myi`.

### WHATSAPP-CRYPT14-1 — `crypt14` decryption on the real Pixel 7a backups, 2026-09-26

**Evidence.** Josh Hickman's Android 14 public image (Google Pixel 7a, Cellebrite FFS,
`~/forensic_corpora/hickman_android14/`, archive verified against its published hashes). Seven
stored members were streamed out of its `EXTRACTION_FFS.zip` and each checked against the CRC-32
in its data descriptor, into `test_data/whatsapp_android14/` (SHA-256 in `test_data/README.md`):
the key file `data/data/com.whatsapp/files/key` (158 bytes), the backups
`msgstore.db.crypt14` (186,343), `msgstore-2024-07-26.1.db.crypt14` (179,819) and
`wa.db.crypt14` (9,508) from `media/0/Android/media/com.whatsapp/WhatsApp/`, and the live
`msgstore.db` (2,805,760) with its `-wal` and `-shm`.

**Independent answers.** Three, none of them this code: the AES-GCM tag (a wrong key or a
changed byte fails it with probability 1 − 2⁻¹²⁸); the MD5 the backup carries of itself; and the
live `msgstore.db` + `-wal` the same extraction took from the phone, whose `message` rows the
backup's must be a subset of. The format was first confirmed with OpenSSL's AES-GCM (Python
`cryptography`) before this implementation existed; the GCM code is also pinned by the GCM
specification's Test Case 14 and an OpenSSL vector for a 16-byte IV.

**Result: pass.** `msgstore.db.crypt14` (header: feature byte present, WhatsApp 2.24.14.81,
server salt and Google ID equal to the key file's) decrypts under the key file: tag verifies,
MD5 matches, 1,662,976 bytes of SQLite. Its 197 messages (`key_id`, `timestamp`, `text_data`)
are all among the live store's 230. `wa.db.crypt14` has no feature byte (the protobuf follows
the length byte directly) and decrypts to 409,600 bytes of SQLite. `msgstore-2024-07-26.1.db.crypt14`
names a different server salt and an older build (2.24.1.78): it was made under another key and
is refused by the salt check, and by the tag when the check is skipped. A byte flipped in the
real backup is refused by the tag.

**What this does not show.** One device, one WhatsApp generation, crypt14 only; `crypt12` is
not implemented (`crypt15` is graded separately, `WHATSAPP-CRYPT15-1`). The live `msgstore.db` is held, but the
parser's schema is not graded against it here.

**Ingest pairing, 2026-09-27.** `real_backups_and_key_ingested_in_zip_order_are_paired` hands the
three backups and then the key to `WhatsAppParser` as file entries carrying their zip paths, in
the order `EXTRACTION_FFS.zip` holds them (`/data/media` before `/data/data`). Each backup is
first recorded `AwaitingKey`; the key then decrypts `msgstore.db.crypt14` and `wa.db.crypt14`
and is refused on `msgstore-2024-07-26.1.db.crypt14` by its salt (`KeyRefused`). 197 message
records are filed under the current backup — 197 distinct `key_id`s, every one a row of the live
store — each stamped `provenance: decrypted_backup` with the key file's SHA-256 (`eb2f85a4…`).
`wa.db` decrypts and files no message (it is the contacts store). No record claims a missing
write-ahead log: the decrypted store is read as one file with no `-wal` to miss. This drives the module directly, not the whole pipeline over
the 30 GB image; the orchestrator's half (a `Decrypted` record superseding `AwaitingKey` in an
automatic run) is pinned by `seance_core/tests/automatic_supersession_test.rs`.

**Key supplied as a credential, 2026-09-27.** `a_real_backup_opens_with_its_key_supplied_as_a_credential`
hands `msgstore.db.crypt14` alone (no key file in its case) to `WhatsAppParser` with a
`whatsapp_key` credential in scope, as `POST …/credential` does. The key file as hex, and the bare
AES key (its last 32 bytes) as 64 hex digits, are each **accepted** and file all 197 messages, the
`Decrypted` record naming `key_source: credential` and the key file's SHA-256 (`eb2f85a4…`). The
same two secrets are **rejected** on `msgstore-2024-07-26.1.db.crypt14` (the key file by its salt,
the bare key, which has no salt, by the GCM tag) and file nothing. This drives the module with the
credential in scope, not the HTTP route; the route's generic handling is covered by the
credential-route tests of the other kinds.

**Re-run.** `cargo test -p seance_plugin_whatsapp --test real_crypt14` (skips when the files
are not staged); the synthetic fixtures' generator is
`seance_plugin_whatsapp/tests/fixtures/make_synthetic_crypt14.py`.

### WHATSAPP-CRYPT15-1 — `crypt15` decryption on published backups with published plaintexts, 2026-09-27

**Evidence.** The `tests/res/` backups of the public `wa-crypt-tools` project at commit
`e2c0282be6769898de7abd95c3f6208f11822f83` (GPL-3.0; held outside this tree as evidence only, no
code from it used), at `~/forensic_corpora/wa_crypt15_2_26/` (linked as
`test_data/whatsapp_crypt15`; `PROVENANCE.md` there) and `~/forensic_corpora/wa_crypt_tools_vectors/`
(`SOURCE.md`, `SHA256SUMS`). The key is `encrypted_backup.key` (SHA-256 `fe73dc80…219d`), a Java
`byte[32]` whose 32 bytes are the root key the project's own tests publish
(`6730a595…f017`). Five backups: `msgstore.db.crypt15` (`af383a88…c155`, WhatsApp 2.22.5.13, a
random IV), and four with the sequential IV `00 01 … 0f` that marks the project's own encryptor
rather than a phone — `msgstore-2.26.db.crypt15`, `wa-2.26.db.crypt15` (no feature byte) and
`msgstore-increment-2.26.crypt15` (a ZIP payload), whose headers are real WhatsApp 2.26.34.7
headers, and `stickers.backup.crypt15` (a raw ZIP with no MD5 trailer).

**Independent answers.** The plaintexts the project publishes beside the backups: `res/msgstore.db`
(SHA-256 `1425b944a2e3885fc936a7bb82f6548c5cc09523a2f61f02aa836c4ed8bbd16e`) for
`msgstore.db.crypt15` and `res/test9.zip` (`70b6b1718c499277138a686828165fdf5f07fb532500363366d641e0362d35ea`)
for `stickers.backup.crypt15`; the GCM tag; and the MD5 each backup but the multi-file one
carries of itself. All five were first decrypted by a separate script (`independent_dec15.py`,
Python `cryptography`, not that project's library) before this implementation existed. The HKDF
step is pinned on a synthetic root against Python's `cryptography` HKDF.

**Result: pass.** `msgstore.db.crypt15` decrypts under `encrypted_backup.key` and under the same
root as 64 hex digits; tag verifies, MD5 matches, and it inflates to 1,273,856 bytes whose SHA-256
is the published `msgstore.db`'s. `stickers.backup.crypt15` decrypts (tag only; there is no MD5) to
540 bytes whose SHA-256 is the published `test9.zip`'s. The three 2.26 header variants decrypt:
`msgstore-2.26` to 1,425,408 bytes of SQLite, `wa-2.26` (no feature byte) to 888,832, and the
incremental backup (zlib, MD5 present) to a 5,359-byte ZIP. A root with one bit changed, and a
flipped ciphertext byte, are refused by the tag; a crypt14 key file is refused on a crypt15 by
name. In ingest (`real_crypt15_backups_and_their_key_are_paired_in_ingest`), the store and the
stickers backup handed to `WhatsAppParser` before the key are each `AwaitingKey` (`scheme:
crypt15`); `files/encrypted_backup.key` then decrypts both — the store's `Decrypted` record carries
the published `msgstore.db`'s SHA-256 and supersedes `AwaitingKey`, the stickers backup's carries
`payload: zip`, `checksum_ok: null` and the published `test9.zip`'s SHA-256, and the archive is
filed beneath it as a `FileEntry` with that SHA-256. The root key is on no record.

**What this does not show.** Only `msgstore.db.crypt15` plausibly came off a phone; the other four
were written by the project's encryptor under real headers and pin the format's variants, not
WhatsApp's behaviour. No crypt15 with real message content is held: the published `msgstore.db`
has one sentinel `message` row (`key_id` `-1`) and the 2.26 stores are sanitised to none, so the
message parser is not graded on crypt15 content here. A root behind a backup password (derived
through WhatsApp's HSM) is out of reach. This drives the module, not the HTTP route or the whole
pipeline.

**Re-run.** `cargo test -p seance_plugin_whatsapp --test real_crypt15` (skips when the files are
not staged); the synthetic fixtures' generator is
`seance_plugin_whatsapp/tests/fixtures/make_synthetic_crypt15.py`.

### DFTT-8 — JPEG search over NTFS, against the image's answer key, 2026-09-26

**Image.** DFTT #8, "JPEG Search Test #1" (Brian Carrier, 2004): `8-jpeg-search.dd`, MD5
`9bdb9c76b80e90d155806a1fc7846db5` (asserted by the test), an NTFS volume. Held at
`test_data/dftt/8-jpeg-search/` with `index.html` and `results.txt`.

**Independent answers.** `index.html`: an MD5 for each of eight pictures (allocated
`file1.jpg` and `file2.dat`; deleted `file6.jpg` and `file7.hmm`; the members of
`file8.zip`, `file9.boo` and `file10.tar.gz`; the stream `file13.dll:here`), the container MD5
only for two more (`file11.dat`, a picture after 1,572 random bytes; `file12.doc`, a picture in
a Word file), and three decoys that must not be reported as pictures.

**Method.** The product's module set (`build_module_set`), dispatched the way the orchestrator
dispatches an unprofiled case, from a `RawEvidence` of the image; every artifact with data is
hashed. An embedded picture counts as found when a JPEG carve starts at its disk offset; a decoy
fails if a JPEG carve has its MD5 or starts where it starts.

**Result.** Keyed pictures: **8 of 8**, each by its MD5 — the NTFS walk lists the allocated and
deleted files and the stream, the ZIP and archive modules open the `.zip`, the `.boo` (a ZIP by
its magic) and the `.tar.gz`, and the carver also recovers the pictures that start on a sector
boundary in free space. Decoys: none carved as a JPEG. Embedded pictures: **0 of 2**. The
carver looks for a header only at a 512-byte boundary, and on disk `file11.dat`'s picture starts
36 bytes past one and `file12.doc`'s 329 bytes past one. DFTT itself says tests 8–12 may be out
of scope if the tool documents it; this is documented as a decided limit,
not an open defect.

**What this does not show.** One NTFS image, one run order. A picture inside a container
format this product does not open, or at an unaligned offset inside any file, is not found.

**Re-run.** `cargo test -p seance_tests --lib dftt8 -- --nocapture`.

### DFTT-12 — ext2 indirect-block carving, against the image's answer key, 2026-09-26

**Image.** DFTT #12, "Basic Data Carving Test #2" (Nick Mikus, 2005): `12-carve-ext2.dd`,
MD5 `6cbd2c5248fa7030d699eb6cde051623`, an ext2 volume whose superblock is corrupted so that
it can only be carved. Held at `test_data/dftt/12-carve-ext2/` (a link into
`~/forensic_corpora/dftt`, fetched 2026-09-19 with its `PROVENANCE.md`).

**Independent answers.** The image's own page, `12-carve-ext2.html`: ten files with MD5, size
and the sectors of each content run and of each indirect (IND) and double-indirect (DIND)
pointer block. Nine of the ten have an IND in line after their twelfth 1 KiB block;
`n_lin_ss.pdf` (734,652 bytes) also has a DIND and two INDs under it; `main_dive.jpg` (17
blocks) has none.

**Result: pass, 10 of 10 byte-exact.** `FileCarver` over the whole image as one region.
Each carve that runs across in-line pointer blocks is rebuilt without them
(`seance_carving::ext2_indirect`): every pointer entry the layout predicts is read and must name
exactly the blocks after it, then zeros, or nothing is rebuilt. A carve whose own sizing read
the IND as content (the compound files `stats.xls` and `test.ppt`, and `blogo.gif`'s walk) is
sized again through the layout, and its `carving_validated` is that second walk's flag
(the test fails if any keyed file is published as not validated). The rebuilt carve records `carving_reconstruction:
ext2_indirect`, the pointer blocks skipped and the block size, and `data_runs` that the content
route serves; the MD5 is of those runs. All ten MD5s and sizes match the key. Without this
rebuild the carver matches 1 of 10 (`main_dive.jpg`), with `haxor2.bmp` right-sized and
byte-wrong.

**What this does not show.** One image, one allocator (the 2005 Linux ext2 driver, 1 KiB
blocks), every file laid out contiguously in free space. A file the allocator scattered — its
pointer blocks naming blocks elsewhere — is not followed and stays a contiguous, byte-wrong
carve; triple-indirect files (over 64 MiB at 1 KiB blocks) are not rebuilt; block sizes 2 and 4
KiB are pinned only by synthetic tests. ext4 extent-mapped files have no in-line pointer blocks
and are not this mechanism's concern.

**Re-run.** `cargo test -p seance_tests --lib dftt12 -- --nocapture` (and `dftt11` for the
DFTT #11 byte-exact list); the raw-engine sweep as in `CARVE-1` above.

### UDF-BRIDGE-1 — both halves of a real UDF-bridge disc, 2026-09-26

**Image.** `win11-25h2-enterprise-eval-x64-en-us.iso`: Microsoft's Windows 11 25H2
Enterprise evaluation ISO. 7,092,807,680 bytes, SHA-256
`a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9`. It is a UDF 1.02
bridge. Its Volume Recognition Sequence (sectors 16–21) is `CD001` (primary), `CD001`
(El Torito), `CD001` (terminator), `BEA01`, `NSR02`, `TEA01`. The AVDP is at 256 and the
LVD domain is `*OSTA UDF Compliant` with one Type 1 map. It is not committed, because it
is 7 GB and Microsoft's to distribute.

**Independent answers.** 7-Zip 26.00: `7zz l -tudf <iso>` lists **976 files and 94
folders**, with `sources/install.wim` at 6,225,286,811 bytes and `sources/boot.wim` at
593,147,852. `7zz x -tudf` extracts the files whose SHA-256 is checked: `setup.exe`
`72a0bcac…7c5`, `autorun.inf` `3378723c…852`, `bootmgr` `6374f092…c88` and
`sources/uninstall.xml` `2c15a254…f56`, and `sources/install.wim` `119100d9…3985`. xorriso: `-ls /` shows the ISO 9660 half holds
**`README.TXT` alone**, and `-extract /README.TXT` gives `b1243f19…df0`.

**Result: pass.** The partition layer publishes `iso9660` and `udf`, both stamped
`udf_bridge: true`, with no `hidden` flag and no overlap warning. The ISO 9660 reader
lists `/README.TXT` and nothing else, and its hash matches. The UDF reader's volume
record gives volume set `d84dc000MS UDFBridge` from anchor 256, and it lists 976 files
and 94 directories. No entry is deleted or content-incomplete, and every one carries a
modification time with its offset (`setup.exe`: `2025-09-15T20:22:25.488000+00:00`;
7-Zip shows `2025-09-15 20:22:25`). `install.wim` is served whole: its 6,225,286,811 bytes hash
to 7-Zip's (`7zz x -tudf -so <iso> sources/install.wim | sha256sum` gives `119100d9…3985`;
the size alone proves nothing, since the data source reports the information length even over
a hole). So the extents are followed and
not capped. All six hashes match.

**What this does not show.** This is one disc, from one authoring tool (Microsoft's
`MS UDFBridge`), on a physical partition. It says nothing about VAT, sparable or
metadata-partition UDF (see `UDF-VARIANTS-1`, on self-made volumes only), or about
deleted identifiers, of which this disc has none.

**Re-run.** `SEANCE_WIN11_ISO=<path to the iso> cargo test -p seance_plugin_udf --test
win11_bridge_corpus -- --nocapture`. For the cross-check, `7zz l -tudf <iso> | tail -1`
and `xorriso -indev <iso> -ls /`.

### UDF-VARIANTS-1 — VAT, sparable and metadata partitions, 512- and 4 KiB sectors, on self-made volumes, 2026-09-27

**These images are self-made, not real discs.** No public image with files in a VAT,
sparable or metadata partition and a published answer key was found (searched: libyal
testdata, golift/udf, pali/udftools, SecurityRonin/udf-forensic, whose two images hold
empty file systems). The corpus was therefore written on the lab host from one synthetic
payload (5 files, 3 directories, a 384,000-byte multi-extent file, a 0-byte file and a
16-bit CS0 name) by two third-party writers: NetBSD `makefs -t udf` (built from
github.com/Randrianasulu/makefs_termux @ e2c4fa1c) and udftools `mkudffs` 2.3, two of
whose rewritable images were then populated read-write by the Linux 5.15 kernel. It
lives at `~/forensic_corpora/udf_images` with `SOURCE.md`, `SHA256SUMS`, the payload and
the oracle outputs; it is not committed. Lean copies of seven images (the multi-extent
file replaced by compressible text) are committed as
`seance_plugin_udf/tests/fixtures/*.img.gz` with their own `README.md` and answer key.

**Independent answers.** The payload's own SHA-256s (`payload.sha256`) are the key. The
Linux 5.15 UDF driver mounted every populated image except the two `makefs` sparable ones
(it refuses their sparing-table size field, which `makefs` sets to the whole sparing area)
and the 4 KiB ones (built after the kernel oracle ran), and its hashes matched the payload
5 of 5 on each. `udfinfo` 2.3 counts 5 files and 4 directories on every populated image
but the UDF 1.50 VAT one (it reports that image's VAT logical-volume extension damaged).
7-Zip 26.00 extracts the multi-extent file with the payload hash from the plain and
metadata images at 512 and 2,048 bytes; it reads no VAT, sparable or 4 KiB image.

**Result: pass.** Through the partition layer and the reader, all 14 populated images read
every payload file with the payload's SHA-256, list the three directories, and flag
nothing incomplete: plain UDF 2.01 at 512, 2,048 and 4,096 bytes; VAT at UDF 1.50 (the
trailer form, `*UDF Virtual Alloc Tbl`), 2.01 and 2.50 (the header form); sparable at 1.50
and 2.01 from both writers; and the metadata partition at 2.50 on 512, 2,048 and 4,096
bytes. The two empty `mkudffs` VAT volumes read as empty, not refused. On the
kernel-populated sparable images the identifier of the deleted `deleted_later.txt` is
listed as deleted, and `mkudffs`'s hidden UDF 1.50 `Non-Allocatable Space` file is listed
as hidden (the kernel's listing hides it, so the payload key has no row for it). On the VAT
images the volume record says `partition_unrecorded_after_vat`, not that the evidence is
truncated.

**Mechanisms pinned by editing a copy.** No image here has a relocated sparing packet, an
unreadable main metadata file or an earlier VAT. Three tests load one image into memory,
make that one change (resealing the descriptors touched) and require the payload to read
exactly: a packet of `kernel_sparable_dvdrw_udf201.img` moved to a spare and recorded in
both tables; the main metadata file of `metadata_bdre_udf250_32m.img` failing its CRC (the
mirror is read); and the newest VAT of `vat_dvdr_udf201.img` naming an earlier one (it is
located in `vat_earlier_icb_lbns`, and the chain ends cleanly). With the translation each
exercises disabled, each of the three fails.

**What this does not show.** Nothing here is a real burned, rewritable or Blu-ray disc,
and every image comes from two writers. No 1,024-byte-sector volume, no volume with the
metadata duplicate flag, no UDF 2.60 volume (no available tool writes one) and no real
multisession disc has been read. The earlier-VAT test shows the chain is followed; the
volume as it stood under an earlier VAT is not walked.

**Re-run.** `SEANCE_UDF_IMAGES=~/forensic_corpora/udf_images cargo test -p
seance_plugin_udf --test udf_variants_corpus`; the committed copies run in every build as
`cargo test -p seance_plugin_udf --test variant_fixtures`.

### SLACK-1 — file slack regions against DFTT #2 and #3, 2026-09-26

**Purpose.** The NTFS, FAT and exFAT parsers produce one `SlackSpace` region per live file whose last
cluster's tail holds a non-zero byte. This grades where
those regions lie against keywords a third party placed in slack and published the offsets
of.

**Images.** Brian Carrier's Digital Forensics Tool Testing images, both whole volumes with no
partition table, so a region's volume-relative `offset_bytes` is an image offset.
DFTT #3 `ntfs-img-kw-1.dd` (MD5 `389e42124eb23c5053ff6596976d6710`) and DFTT #2
`fat-img-kw.dd` (MD5 `bac12239bd466fa6c86ceb0b0426da0a`), under `test_data/dftt`.

**Ground truth.** Each image's `index.html`: sector and byte offset per keyword, and whether
it lies in a file, in its slack, or across the boundary. Every offset below was checked
against the image bytes before the test was written.

**Result: pass.**

| Image | Keyword | Published (sector, offset) | Image offset | Result |
|---|---|---|---|---|
| DFTT #3 | `n-slack` — "slack space of a non-resident allocated file", `file-n-4.dat` | 8062, 485 | 4,128,229 | Inside the one region owned by `file-n-4.dat`; no other region covers it; the region's bytes read `n-slack` |
| DFTT #2 | `3slack3` — in slack, `file4.dat` | 277, 385 | 142,209 | Inside `file4.dat`'s region |
| DFTT #2 | `1slack1` — crosses a file into its slack | 272, 396 | 139,660 | `file2.dat`'s region begins inside the keyword, at the file's logical end (139,664), so the file's own bytes are not in it |
| DFTT #2 | `2slack2` — crosses slack into the next file | 274, 508 | 140,796 | `file3.dat`'s region ends inside the keyword, at the end of its cluster (140,800) |

**A discrepancy in the published table, recorded rather than smoothed over.** DFTT #2's table
names `file1.dat` for `1slack1`. The sector it gives, 272, is `file2.dat`'s cluster by the same
table's own row 2 (`SECOND`, sector 272, "file2.dat, in file"), and the image agrees:
`file1.dat` is exactly 512 bytes in a 512-byte cluster and has no slack. The test grades the
published offset against the file those bytes belong to, and asserts `file1.dat` has no
region.

**On a real Windows volume.** On the CFReDS Hacking Case NTFS volume (Windows XP, 12,183 file
entries) the pass offered 5,980 windows: 5 held non-zero bytes and became regions (1,737
bytes), 5,975 were all zeros, none was unreadable, and the ceiling was not reached; the whole
MFT parse, pass included, took 6.6 s (release build, one run of `slack_ingest_cost`). On the CFReDS 2015
Data Leakage PC's Windows 7 system volume (19.9 GiB, 77,873 file entries) the pass offered
52,187 windows: 5,519 held non-zero bytes and became regions (12,353,913 bytes), 46,668 were
all zeros, none was unreadable, and the 250,000-region ceiling was not reached; the whole MFT
parse, pass included, took 24.3 s (release build, one run). There is no switch that turns the
pass off, so both figures are the parse, not the pass alone: the pass's own cost was not
isolated on either volume. A measurement
on `LenovoFinal.E01` would not measure this: that image is an ext4
laptop, and ext4 has no slack producer; only its EFI FAT partition would be offered.
Re-run with `SEANCE_CFREDS_LEAKAGE=<dir> SEANCE_CFREDS_HACKING=<dir> cargo test --release -p
seance_tests --features e01 --test slack_ingest_cost -- --nocapture`. On the dfir_ntfs
`exfat_win.raw.gz` exFAT volume, 400 windows were offered and all 400 were zeros.

**2026-09-27: the files whose tail could not be located.** The summary also counts, as
`files_not_located`, every live file with a tail that was never offered because its runs were
compressed, encrypted, incomplete or shorter than its size; without that count a volume of them
reads like one with no slack-bearing files. Measured (debug
build, one run each, same command without `--release`): the Hacking Case volume offered the
same 5,980 windows with the same outcome, and **397** live files had a tail that could not be
located; the Data Leakage system volume offered the same 52,187 with the same outcome, and
**11** could not be located. On both, `offered` = regions + all-zero + unreadable +
past-ceiling, which the test asserts. Which of the reasons each of those files had is not
broken out; the count is "could not look", not "nothing there".

**What this does not show.** No held image carries an executable in file slack, so
`carved_executable_in_slack` is not graded on real evidence. Its reachability is shown on a
synthetic NTFS volume, parser to carver to PE plugin to finding
(`carved_executable_in_slack_fires_on_enumerator_produced_shape`). The search indexer does
not subscribe to `SlackSpace`, so at ingest a slack region is not in the full-text index at
all — neither its bytes nor its metadata; a backfill would add its metadata, never its bytes —
so `n-slack` stays unreachable by keyword search and the DFTT #3 keyword test still pins that;
the byte sweep offers slack regions as `slack`. Slack is published only under a profile that
runs a slack-producing parser, and carved only under one that also runs
`plugin.recovery.unallocated_carver`: the triage profile publishes the regions but neither
carves them nor runs the findings modules, so there the detection cannot fire. Slack on
ext4, APFS, HFS+ and every other file system is not produced.

**Re-run.** `cargo test -p seance_tests --lib slack_dftt` (skips when `test_data/dftt` is
absent), and `cargo test -p seance_plugin_fat --lib exfat_real_volume` for the exFAT count.

### SLACK-2 — YARA over file slack against DFTT #2 and #3, 2026-09-26

**Purpose.** `plugin.detection.yara` has an eighth surface, `slack`, over the
`SlackSpace` regions `SLACK-1` grades. This grades what a YARA hit there reports — which file,
which surface, which offset — against the same published keyword offsets.

**Images and ground truth.** As `SLACK-1`: DFTT #3 `ntfs-img-kw-1.dd` and DFTT #2
`fat-img-kw.dd`, under `test_data/dftt`, whole volumes, so a hit's `offset_in_parent` (into
the file system) is an image offset. One rule per keyword, each a plain string.

**Result: pass, with one stated limit.** The regions are produced by the real parsers
(`MftParser`, `FatParser`) and every one is handed to the scanner.

| Image | Keyword | Published image offset | Result |
|---|---|---|---|
| DFTT #3 | `n-slack` | 4,128,229 | One hit, surface `slack`, `base_file` `file-n-4.dat`, `offset_in_parent` 4,128,229 (1 region scanned) |
| DFTT #2 | `3slack3` | 142,209 | One hit, surface `slack`, `base_file` `file4.dat`, `offset_in_parent` 142,209 (3 regions scanned) |
| DFTT #2 | `1slack1` | 139,660 | **No slack hit** — the keyword begins in `file2.dat`'s content and ends in its slack (see the note below: DFTT's index says `file1.dat`) |
| DFTT #2 | `2slack2` | 140,796 | **No slack hit** — the keyword begins in `file3.dat`'s slack and ends in the next cluster |

**Where this departs from the published label.** DFTT #2's `index.html` describes `1slack1`
as in "file1.dat and file1.dat slack". The table above says `file2.dat`, and that is measured,
not copied: The Sleuth Kit's `ifind` puts sector 272 in inode 6, `FILE2.DAT`, of 400 bytes, so
the keyword's bytes 396–403 of that cluster run across `file2.dat`'s logical end. The offset
is the published one; only the file name differs from the index.

**What the offset is.** A slack hit's `offset_in_parent` is into the file system the region
hangs off (`offset_basis` says so), not into the evidence. Both images are bare volumes with no
partition table, so here the two coincide. On a partitioned image the partition's own offset
must be added, and the scanner does not do that sum — this grade does **not** show that a slack
hit carries a device offset on partitioned media.

**The limit.** Each slack region is scanned on its own, so a string that crosses the region's
edge is not matched whole there. That is pinned by the test rather than hidden, and stated in
the `slack` surface's own `surface_means` sentence and in the module's method statement. The
same test scans the whole volume as one `volume` region and finds all three DFTT #2 keywords
at their published offsets, attributed to no file — which is the route for a crossing string.

**Re-run.** `cargo test -p seance_plugin_yara --lib dftt -- --nocapture`
(`surfaces_real_tests::dftt3_n_slack_is_found_once_in_slack_at_its_published_offset` and
`surfaces_real_tests::dftt2_3slack3_is_found_in_slack_and_the_crossing_keywords_are_not`;
each skips and says so when its image is absent, and fails instead under
`SEANCE_REQUIRE_CORPUS=1`, so a run that must read evidence cannot pass having read none).

### SLACK-3 — `carved_executable_in_slack` on a real partitioned NTFS volume, 2026-10-20

**SYNTHETIC.** The volume is real `mkntfs` output; the planted payload is not real-world evidence. This
grades the mechanism and the offsets, not how often real evidence holds an executable in slack.

**Purpose.** Show the detection firing from a volume a real tool wrote rather than a hand-built record, and check a
slack region's offsets on partitioned media.

**Fixture.** `seance_plugin_mft/tests/fixtures/ntfs_slack_pe/ntfs_slack_pe.img.gz` (8 MiB disk, gzip SHA-256
`a5ac421db5b450a2e13da670341edeae2362cdde20030059bcaf27105d20ad03`; raw image SHA-256 in `expected.json`), built by
`scripts/synth/build_ntfs_slack_pe_fixture.py`: `mkntfs -s 512 -c 4096`, files added with `ntfscp`, an MBR partition at
LBA 2048 (1,048,576 bytes) from `sfdisk`. A 1,024-byte PE32 is planted at +1,024 in `host.bin`'s cluster (1,000-byte
file, tail 3,096 bytes). `zero.bin` (all-zero tail) and `exact.bin` (no tail) are controls.

**Ground truth.** The script's plan, with each file's cluster read from `ntfscluster` (an independent reader) and the
planted offset derived from it: LCN 297 for `host.bin`, disk offset 2,266,112, bytes read `MZ`. Never Séance's output.

**Result: pass.** One region, for `host.bin`, at volume offset 1,217,512; none for the controls. The carve is at volume
offset 1,217,536, stamped `carving_source: "slack"`; the FileSystem artifact's `offset_bytes` (1,048,576) plus it is
2,266,112, the planted offset. Exactly one `carved_executable_in_slack` finding, naming `host.bin`. Region and carve
offsets are volume-relative and the region says so in `offset_basis`; the partition start is not folded into them.

**What this does not show.** Real-world prevalence; APFS and HFS+ slack (graded in their own records); a case-level ingest
through the API.

**Re-run.** `cargo test -p seance_plugin_mft --test real_slack_pe_test`. Rebuild the fixture with
`python3 scripts/synth/build_ntfs_slack_pe_fixture.py --out <dir>` (needs ntfs-3g tools and sfdisk).

### BITS-1 — the binary BITS queue on two real machines, 2026-09-26

Three real `qmgr*.dat` files, read by `seance_plugin_bits` and, as a black
box, by ANSSI's `bits_parser` 1.x (`pip install bits_parser`; its output was compared, its
code was not read):

- NIST CFReDS Data Leakage PC (Windows 7), `qmgr0.dat` / `qmgr1.dat` (MFT entries 15553 /
  15554, 4,194,304 bytes each, SHA-256 `c078c4e6…9d5a` / `197c0c14…509b`);
- DFIR Madness case 001 DC01 (Server 2012 R2), `qmgr0.dat` (MFT entry 19702; `qmgr1.dat`,
  19701, is byte-identical).

| Field | `bits_parser` | Séance |
|---|---|---|
| `qmgr1.dat` live jobs | 1: `7b403240-…-23774df1f57a`, "Setup Installer", download, foreground, transferred, owner `S-1-5-21-2425377081-3129163575-2985601102-1000` | the same job and values (`BitsJob`) |
| its file | `…\TMP72E4.tmp` ← `http://go.microsoft.com/fwlink/?LinkId=164181&clcid=0x409`, temp `…\BIT7308.tmp`, 872,448 / 872,448 bytes | the same |
| ctime / mtime | 2015-03-25 14:50:55.671406 / 14:50:56.357806 | `creation_time` / `modification_time`, the same (100 ns precision) |
| further times | `other_time0..2` | two reported unnamed; the fifth (+90 days) not read |
| `qmgr0.dat` live jobs | none (all carved) | none: "queue read, 0 job(s)" |
| stale records | .NET file; the OAB job's three files (one a partial record) with its times | the .NET file and `diff1867.tm_` / `diff1868.tm_` as `BitsCarvedFileTransfer`; the partial first record is not carved; **no times are attached to carved records** |
| DC01 | 0 jobs, warning "Job delimiter is undefined" | "queue read, 0 job(s)", file GUID `{09ED3228-C7A6-45E9-8F6D-36D946C27C3E}` |

**Two points:** the carver does not take each file record's volume
field (`\\?\Volume{…}\`) as a transfer source (`assert_no_volume_path_taken_as_a_source`);
and the fourth trailer time is unnamed, because
nothing independent names it.

**Bounds.** Two builds, one of them with jobs. No XP, Vista, 8 or 8.1 queue has been read.
Credentials are reported present (two DPAPI "BITS job credentials" blobs on the .NET job)
and never decrypted.

**`qmgr.db` (Windows 10), LoneWolf, MFT entry 92620** (1,310,720 bytes, SHA-256
`dbdab2b6…d661`). Measured, not graded — there is no independent reading to grade against:
the ESE header reads state 2 (dirty shutdown), page size 16,384; libesedb opens `Jobs` and
`Files` (columns `Id`, `Blob`) and returns **0 rows** from each. The queue's recent state is
in `edb.log` / `edb00001.log` beside it (54 and 171 URL strings respectively), which are not
replayed. 22 URL strings sit in database pages 32 and 42, which no row points at; the byte
scan reports those file records as `BitsCarvedFileTransfer` with their page. A `Jobs` record
image in `edb00001.log` (offset `0x11066`) decodes with the `.dat` job header reader
("UpdateBinary", owner `…-1001`, normal, suspended), which is the basis for the blob decoder;
no decoder has run on a row a walk returned. plaso's `SRUDB.dat`, `WebCacheV01.dat`,
`SystemIdentity.mdb` and `Windows.edb` yield nothing.

**Re-run.** `SEANCE_CFREDS_QMGR_DIR=<dir> SEANCE_DC01_QMGR=<file> cargo test -p
seance_plugin_bits`; the committed fixtures (the files' first 8 KiB) run without either.

### RDP-CACHE-1 — a real `Cache0000.bin`, 2026-09-26

DFIR Madness case 001 DC01 (Server 2012 R2),
`Users/Administrator/AppData/Local/Microsoft/Terminal Server Client/Cache/Cache0000.bin`
(MFT entry 87133, 86,964,396 bytes); `bcache24.bmc` beside it (MFT entry 87126) is 0 bytes.

| Check | Independent reading | Séance |
|---|---|---|
| header | `RDP8bmp\0`, u32 4 (hex dump) | version 4 |
| tiles | (86,964,396 − 12) / (12 + 64 × 64 × 4) = 5,304 exactly; a Python walk of the per-tile width/height finds 5,304 tiles, all 64 × 64, 5,304 distinct keys | 5,304 `RdpCacheTile` PNGs, each 64 × 64, key 16 hex digits |
| pixel order | a Python render of tiles 2,000–2,255 as blue-green-red shows Windows 10 UI (taskbar, Defender and Firewall search results) in its normal colours | the same order |
| fourth byte | zero on every pixel of tile 0 | dropped |
| collage | 5,304 tiles / 64 across = 83 rows | one, `Cache0000_collage_cache_order_not_a_reconstruction.png`, 4,096 × 5,312 px (read from its PNG header), `tiles_placed` 5,304, `reconstruction: false`, the not-a-reconstruction note |
| `bcache24.bmc` | 0 bytes | "empty file (0 bytes)" |

**Bounds.** One real `.bin`, one version, one tile size. No non-empty `.bmc` is held, so
that format is recognised and refused, not decoded. The collage is not graded: it claims
nothing but order.

**Re-run.** `SEANCE_DC01_RDP_CACHE=<file> cargo test --release -p seance_plugin_rdp_cache`.

### WINSEARCH-1 — two real `Windows.edb` indexes, 2026-09-26

NIST CFReDS Data Leakage (Windows 7, MFT entry 490, 42,008,576 bytes, SHA-256
`f29fa5c3…0ca1`) and LoneWolf (Windows 10 1709, MFT entry 91047, 25,100,288 bytes, sparse,
`dc000bbb…697c`). Both headers say dirty shutdown (state 2), page size 32,768.

| Check | Independent reading | Séance |
|---|---|---|
| IE 11 installer, size | `istat` MFT 62436: `$DATA` 55,915,216 | `System_Size` 55,915,216 |
| its created / modified | `$STANDARD_INFORMATION` 15:11:04.0873339 / 15:11:04.8517352 (2015-03-22 UTC) | the same, to the 100 ns |
| the reply "RE: Important request" (Sent Items) | NIST's answer key quotes the exchange: "I confirmed it. But, I need a more data. Do your best." / "Umm... I need time to think." | summary decoded to "Umm….. I need time to think. From: spy … Subject: Important request I confirmed it.  But, I need a more data.  Do your best." (the key's own spacing differs) |
| "RE: Good job, buddy." (Inbox) | not in the key; measured only | sender "spy", summary "Okay, I got it. I’ll be in touch. …" |
| encoded summaries | 113 values; after de-obfuscation 98 of type 1, 5 of type 0, 9 of type 3, 1 of type 2 (a Python census) | 103 decoded, 10 named not decoded |
| rows | libesedb: 464 (Data Leakage); 822 on the second count call, the first failing "not a leaf page" (LoneWolf) | 464; 822 stated as a floor |
| Windows 10 byte order | NTUSER.DAT `13F-System_Size` bytes `00 00 04 00 …` | 262,144 (little-endian) |

**Not established.** No second reader of the table was run, so the row counts rest on
libesedb. The type-2/3 form is not decoded. Only 46 properties are read. No Windows 8 or
8.1 index, and no Windows 11 `Windows.db`, has been read. The encoded-value fixtures are
committed; the databases are not.

**Re-run.** `SEANCE_CFREDS_WINDOWS_EDB=<file> SEANCE_LONEWOLF_WINDOWS_EDB=<file> cargo test -p
seance_plugin_winsearch_edb`.

### UAL-1 — the User Access Logging databases of a real Server 2012 R2 domain controller, 2026-09-30

**Question.** `seance_plugin_sum` is written from the published UAL layout and unit-tested on synthesised
databases. Does it read a real `Sum` directory, and is every field it maps the field the file holds?

**Image.** DFIR Madness Case 001, the domain controller `CITADEL-DC01` (Windows Server 2012 R2, build 9600):
`20200918_0347_CDrive.E01`/`.E02` under `~/forensic_corpora/dfir_madness_case001/E01-DC01` (the publisher's
MD5 for the archive is checked in that directory's `VERIFICATION.txt`). The C: volume starts at sector
718,848. The files are extracted with The Sleuth Kit through `ewfmount`, none of it Séance:

```sh
ewfmount 20200918_0347_CDrive.E01 /mnt/ewf
icat -o 718848 /mnt/ewf/ewf1 84733 > Current.mdb          # sha256 97598e6c…cf2a1, 1,056,768 bytes
icat -o 718848 /mnt/ewf/ewf1 84695 > SystemIdentity.mdb    # sha256 daeb8617…be51
icat -o 718848 /mnt/ewf/ewf1 84645 > Svc.log               # sha256 79bf0d56…4bd1
```

`fls -r` names the three as `Windows/System32/LogFiles/Sum/{Current.mdb,SystemIdentity.mdb,Svc.log}`. The
directory holds no `{GUID}.mdb` archive, although `SystemIdentity.mdb`'s `CHAINED_DATABASES` names
`{9D2CCF2E-F5C3-47F3-9BFA-49937CC468C0}.mdb` for 2020.

**Independent reader.** `dissect.esedb` 3.18 (Python), reading the same bytes, dumped every table with its
columns and rows (`EseDB(open(f,'rb')).tables()`; `table.records()`). It is the ground truth for the
figures below.

**What the independent reader found, and what Séance said.**

| Database | Independent reader | Séance |
|---|---|---|
| `SystemIdentity.mdb` (ESE state 3, clean) | `SYSTEM_IDENTITY` 3 rows, `ROLE_IDS` 13, `CHAINED_DATABASES` 1 | 3 / 13 / 1 |
| hosts and domains of the 3 identity rows | `WIN-E0PO207ERMD`/`WORKGROUP`, `WIN-E0PO207ERMD`/`C137.local`, `CITADEL-DC01`/`C137.local` | the same, in the same order |
| OS fields | build 9600, 6.3, `OSCurrentTimeZone` 65,116 | 9600, `6.3`, `UTC-07:00` |
| first `CreationTime` | FILETIME 132,448,316,944,240,000 | `2020-09-17T15:54:54.424+00:00` |
| `Current.mdb` (ESE state 2, **dirty shutdown**) | `ROLE_ACCESS`, `DNS`, `VIRTUALMACHINES` and `CLIENTS` all **0 rows** | 0 client-access records, 4 tables read |

**Two facts the real file establishes.**

1. **Time zone.** No real database carries a text column `SystemTimeZone`. The column is
   `OSCurrentTimeZone`, an unsigned 16-bit count of minutes from UTC in two's complement (65,116 is
   -420, UTC-7). The parser reads it and renders `UTC-07:00`.
2. **The client table is not named after a role GUID.** On this file the table is `CLIENTS`, and the
   role is in its `RoleGuid` column. Detection is by columns.

**Dirty shutdown.** `Current.mdb` reads empty, and that is **not** "no
client reached a role": its header state is 2 (dirty shutdown) and the transaction log beside it,
`Svc.log`, holds `c137\administrator` (5 occurrences), `c137\citadel-dc01$` (3), `c137\desktop-sdn1rpt$` (2),
`c137\mortysmith` (2), `c137\ricksanchez` (1) and `c137\win-e0po207ermd$` (2) (`strings -a`). The committed
rows sit in the log and this reader does not replay ESE logs. A `0` is therefore indistinguishable from an
empty server. The summary and every record from such a database carry `database_state: dirty_shutdown`,
`content_incomplete: true` and the reason.

**What this does not show.** Not one real `CLIENTS` row has been read: the only real client-access table in
hand is empty, so the per-client mapping (`AuthenticatedUserName`, `Address`, `TotalAccesses`, the `Day` columns,
`InsertDate`, `LastAccess`) is still graded only on synthesised rows. Log replay (what
`esentutl /r` does) is not implemented; with it `Current.mdb` would most likely yield the rows above. The
identity figures come from three rows of one machine.

**Re-run.** Extract the files as above into a directory and `SEANCE_DC01_SUM_DIR=<dir> cargo test --release -p
seance_plugin_sum --test dc01_real_files` — two tests, which return without asserting (and say so) when the
variable is unset. 2026-09-30: 2 passed; the crate's 18 unit tests pass.

### CFTT-FC-1 — the L0 (non-fragmented) images of NIST's Forensic File Carving set, 2026-09-30

**Question.** Of the 30 images of Forensic File Carving only
L0 is a conformance target (L1–L5 need fragment reordering, which is on the deliberately-out-of-scope list).
Does the carver find each file NIST placed in the five L0 images, and is what it cuts the file?

**Data.** `~/forensic_corpora/cftt_file_carving` (`Images/L0_{Graphic,Documents,Archive,Audio,Video}.dd`, the
layout `ImageLayouts.htm` and the original files in `TestFiles/`). NIST publishes **no hash** for any of it, so
none of this data set is verified against the publisher. The layout's file names, sizes and start sectors are
the expectation; the original file's bytes (from `TestFiles/`) are the reference.

**Procedure.** `scripts/cftt/run-file-carving.py --corpus ~/forensic_corpora/cftt_file_carving --out OUT`.
One server and one workspace per image. The image is ingested with the `deep` profile, which carves nothing
from a raw image with no partition table or file system (the source is reported "no module in this build
parses it" and 2 artifacts exist), so the script then runs `plugin.recovery.file_carver` on the source
(`POST /cases/{id}/artifacts/{source}/run_module`), the opt-in route of `CORE_DESIGN.md`. For each non-`Fill`
file it records: `found_at_start` (a carved object starts at exactly `start_sector * 512`); `exact` (the
image's bytes from that offset for the carved object's own size hash to the original's MD5); `contains` (the
carved object is at least the original's size and begins with it); `overshoot`. Carved objects starting at no
file's start are counted as extra and, separately, those that fall in a `Fill` region.

**Result (run twice on L0_Video, L0_Documents and L0_Archive; the numbers agree).**

| Image | Files | Found at the right start | Exact | Contains | Extra carves |
|---|---:|---:|---:|---:|---:|
| L0_Graphic | 6 | 6 | 4 | 6 | 0 |
| L0_Documents | 7 | 7 | 6 | 6 | 1 (ZIP) |
| L0_Archive | 7 | 6 | 4 | 6 | 1 (JPEG) |
| L0_Audio | 4 | 4 | 1 | 4 | 0 |
| L0_Video | 6 | 6 | 4 | 5 | 11,025 (11,024 MPEG, 1 GPG; 49 in a `Fill` region) |
| **All** | **30** | **29** | **19** | **27** | |

**What did not pass, none tuned.**

* **`arc4.tar` is not found.** It has no `ustar` magic at offset 257 (it begins with the name
  `100_0001.JPG`, a pre-POSIX v7 header), and the `TAR` signature is the `ustar` test, so there is nothing to
  match. A limitation of signature carving rather than a bug.
* **`vid5.mpg` (22,579,200 bytes) is carved as 2,048 bytes** — one pack header — and the same signature
  produces the **11,024 extra `MPEG` carves** inside that file, one per pack header. The carved object is
  neither the file nor a useful fragment.
* **`D4.xlsx` (13,824 bytes) is carved as 4,608** (`ZIP`, `carving_validated: false`), 9,216 short. `D3.xlsx`
  (23,513) and the other four OOXML files are exact.
* **Eight files are found at the right start, contain the file, and overshoot** (27 contain, 19 are exact):
  `02010025.pcx` (+5,120,248), `100_0018.tif` (+5,120,016), `arc2.bz2` (+5,120,144), `arc3.gz`
  (+5,120,595), `Audio1.mp3` (+5,120,477) and `vid4.flv` (+5,120,323) each end where the next file's header
  begins, so they swallow the 5,120,000-byte `Fill` that follows; `Audio2.wav` (+8) and `Audio4.wma` (+213)
  end a few bytes late. A carve with no footer cannot know where the file ends; that is stated here, not
  graded a pass.
* **Two extra carves inside files or fill**: a `JPEG` in `L0_Archive`, a `ZIP` in `L0_Documents`.

**What this does not show.** Not every `FC-CA-*` assertion: the NIST specification text was not used, so
the rows above are the L0 layout's expectation, not `FC-CA-01`…`10`. L1–L5 were not run. "Extra" is not "false
positive": NIST's `Fill` is data of no stated content.

**Re-run.** The command above (`--bin` to choose the binary; ~3 minutes for all five). Running a published
methodology is not third-party validation; NIST has not tested this tool.

### CFTT-DFR-1 — NIST Deleted File Recovery, all 90 images, graded against the layout document, 2026-09-30

**Question.** CFTT's Deleted File Recovery methodology (`DFR-CR-01`…`04`) over the whole
public image set. This supersedes `DFR-1` above.

**Data.** `~/forensic_corpora/nist_dfr`: 90 `.dd.bz2` images fetched 2026-09-19 from
`cfreds-archive.nist.gov/dfr-test-images.html`, decompressed to `dd/`, and `setup-july-10-2012.pdf`. **NIST
publishes no hash** for any of them; `SHA256SUMS` is this project's, taken at fetch, and all 91 lines
verified on 2026-09-30 (`sha256sum -c`: 0 failures). That proves the files are the ones fetched, not that
they are NIST's.

**Ground truth.** NIST's own layout document, `pdftotext -layout`, parsed by `seance_validate`'s `dfr_layout`.
It is not Séance's output. NIST elides rows from it (`<N> omitted`, `. . . + N more`), and those are graded
**not assessed**, never passed. The DFR specification itself is not held: `DFR-CR-01`…`03` are this grader's
paraphrase (and `DFR-CR-04` is quoted); `DFR-RO-01`…`08` are not graded.

**Procedure (as run).**

```sh
SEANCE_BIN=<release binary> CFTT_GRADE=<release cftt-grade> \
  scripts/cftt/run-dfr.sh --corpus ~/forensic_corpora/nist_dfr --out OUT \
      --classes scripts/cftt/dfr-classes.json --timeout 900
python3 scripts/cftt/dfr-evidence.py OUT/report.json ~/forensic_corpora/nist_dfr/dd evidenced.json OUT/results.json
# merge dfr-classes.json and evidenced.json into one list, then
cftt-grade --dfr --layout OUT/layout.txt --results OUT/results.json --out OUT2 --classes merged.json
```

One server and one workspace per image, `deep` profile; each image's ingest settled (none timed out, none
died: 90 of 90 `ingest_complete`). 21,606 file entries were read, 6,617 of them deleted. The second step asks
The Sleuth Kit 4.12.1 (`fls -r -d`, `istat`) about each failure: a failure is reclassified only where TSK,
an independent tool, bears the reclassification out, and otherwise stays `real_defect`.

**Result.** 1,785 passed, 601 failed, 824 not applicable, 1,223 not assessed (4,433 rows). By assertion:

| | pass | fail | not applicable | not assessed |
|---|---:|---:|---:|---:|
| `DFR-CR-01` listed as deleted | 735 | 161 | 206 | 13 |
| `DFR-CR-02` content produced | 507 | 389 | 206 | 0 |
| `DFR-CR-03` sectors | 161 | 35 | 206 | 700 |
| `DFR-CR-04` | 382 | 16 | 206 | 498 |

The 601 failures, after the Sleuth Kit pass: **134 real defects**, 240 grader artifacts (the layout's
names are `pdftotext`'s visual-order Arabic, Windows renamed Recycle Bin files, ext directory entries whose
inode is 0 or whose inode records size 0 and no blocks — nothing in residual metadata says where the content
was), 182 corpus divergences (NIST's layout names a deleted file that **neither** this tool **nor** TSK finds;
that is two tools agreeing, not proof the layout is wrong), and 45 declared gaps (FAT fragmented files read
contiguously from the start cluster; FAT overwritten files).

**The 134 real defects, not excused.**

* **HFS+ (`osx-01`, `osx-04`), 100 rows (50 files, `CR-01` and `CR-02`).** Deleted files are not listed at
  all. TSK cannot list deleted HFS+ entries, so there is no independent arbiter, and the failure is not
  reclassified. The `plugin.filesystem.hfsplus` method statement describes an unallocated-space pass that recovers an
  orphaned catalog leaf; on these two images it produced none of the named files.
* **exFAT `xfat-11` (3 files) and `xfat-12` (6 files), 18 rows**, which are the deleted-directory and
  fragmented-directory scenarios: TSK lists the entries, this tool does not.
* **NTFS**: `ntfs-10` (2 files not listed), `ntfs-14` (a deleted hard link not listed; two symbolic links
  listed without content), `ntfs-05-nest` (`Duhr.TXT`, sector 198850 missing).
* **ext**: `ext-08` (`Atlas.txt`) and `ext-12` (three files) are listed with no content, where TSK's inode
  shows blocks.
* **FAT** `fat-06` (three files, `DFR-CR-03` a sector missing).

**What this does not show.** It does not show that the tool recovers 1,785 of anything: 1,223 rows are not
assessable because NIST's own document elides them (8,979 of the 10,085 deleted files it declares are in
elided rows). `DFR-CR-03`/`04` depend on data-run reconstruction (`data_runs`) and a paraphrased assertion.
"Corpus divergence" is an agreement between two tools. The earlier statement that every NTFS, ext and
exFAT/FAT scenario "recovers its deleted files" (`DFR-1`) is superseded by the table above.

**Re-run.** The commands above; about 45 minutes for the 90 images, the Sleuth Kit pass about 40 seconds.
Not third-party validation; NIST has not tested this tool.

### MEM-ARM-7 — FEAT_LPA2 (`TCR_EL1.DS = 1`) under a 16 KiB granule on real tables, 2026-10-22

**Evidence:** a second boot of the same Debian 6.12.107 16 KiB kernel under `qemu-system-aarch64` 10.2.1
TCG, `-cpu max` (so the CPU offers FEAT_LPA2 and the kernel used it), paused when init printed `SEANCE_READY`, RAM saved with
`pmemsave`, and the registers read through the gdbstub with a minimal remote-serial client
(`forensic_corpora/arm64_16k_lpa2_qemu/{SOURCE.md,run.sh,gdbregs.py}`). `TCR_EL1` `0x0950_01f6_754c_b50c` (TG0 16 KiB,
TG1 16 KiB, T0SZ = T1SZ = 12, IPS 52-bit, DS = 1; identical to the first capture), `TTBR1_EL1` `0x0014_0000_41f5_4001`,
`TTBR0_EL1` `0x0000_0000_441f_6401`. QEMU-emulated, not
hardware.

**Oracle:** `scripts/oracle/arm64_walk.py`, a stage-1 walker for the 16 KiB granule with and without `DS`, written from ARM DDI
0487 D8 without reference to the Rust walker. **It was first run on the non-LPA2 sibling capture and reproduced that
capture's pinned numbers exactly** (35,417 pages, 8 blocks, digest `0x742b_d1b6_db01_7400`), then on these tables.

| Tree | Start level | Leaves | Digest |
|---|---|---|---|
| TTBR1 (kernel), 52-bit | 0, 32 entries | 35,418 pages + 8 blocks of 32 MiB | `0x89e4_7ee7_3731_7a67` |
| TTBR0 (init's `pgd`), 52-bit | 0, 32 entries | 91 pages | `0xeb34_87c3_5655_afe1` |

Séance's walker agrees on every leaf of both trees (the order-independent digest over `(va, pa, size)`), on 24 spot
translations in each, and on 8 faults in each, two at every depth the walk can stop at. **Decoding.**
`Arm64Regime::from_tcr_el1` decodes `TCR_EL1.DS = 1` for the 16 KiB granule (52-bit widths, address bits 51:50 from descriptor bits 9:8
and 49:48 from 49:48, a 64 GiB level-1 block, an IPS of 52, and `TTBRn_EL1.BADDR` bits 5:2 as address bits 51:48);
`DS = 1` under a 4 KiB or 64 KiB granule is still refused by name.

**Not established.** Every leaf in these trees has output-address bits 51:48 clear, so the evidence does not exercise the
high address bits, a frame above 2^48, or a 64 GiB block: those are pinned on synthetic tables worked by hand from the manual
(`arm64_tests.rs`, `an_lpa2_page_names_output_address_bits_51_to_48_from_9_8_and_49_48` and four more). Hardware, the 4 KiB LPA2
layout, and Linux discovery of an LPA2 kernel without registers are not covered. **Re-run:**
`SEANCE_ARM64_16K_LPA2=~/forensic_corpora/arm64_16k_lpa2_qemu cargo test --release -p seance_memory --test
arm64_16k_lpa2_real_test`; unset, the tests skip and say so.

### CARVE-2 — Dahua DHAV exports carve whole, on two public files, 2026-10-23

**Evidence:** the two `.dav` files of FFmpeg's public sample server (ticket 6144; user uploads, no licence stated, used as test input only; `forensic_corpora/found_dahua_dav_ffmpeg_samples/SOURCE.md`): `19.25.00-19.25.50[R].dav` (25,788,416 bytes, SHA-256 `c17602dd3958ef850e8b435a1c23a652a28fd8733ca15ad4661fc1fd15b2da07`, a 2017 export starting with frame type `F0`) and
`85aa0-amphi-salle-2_salle-2_main_20161105110831_20161105111959.dav` (314,550,138 bytes, `1bb652bd00ee31ddbea076df9214ce6b4c2b2de271c4bcb5cc9d6e980672451f`, a 2016 export starting with `FD`). **Layout, read from the bytes** with a throwaway script and checked against the frame-header table of Rzayeva et al., *Information* 17(5):493
(CC BY 4.0; `found_dhav_spec_mdpi/`), without reading FFmpeg's demuxer: `DHAV`, type, subtype, channel, frame number, total length at 12, time at 16, extension length at 22, a checksum at 23 equal to the low byte of the sum of bytes 0..23, and a footer of `dhav` and the length again. All 2,042 + 25,778 frames satisfy the checksum, the footer magic
and the repeated length, and each file is one unbroken chain (the first ends at 25,786,748 and is followed by 1,668 bytes of `0xFF`; the second ends exactly at the end of the file). Frame types seen: `F0`, `F1`, `FC`, `FD`; extension lengths 8, 12, 16, 20, 36.
**Result:** the engine carves each file as one DAD, to the byte of the chain's end (`two_real_dahua_exports_are_carved_to_the_end_of_their_frames`, `SEANCE_DAHUA_DAV_CORPUS=<dir> cargo test --release -p seance_carving --lib dad`). Without a size check a DAD carve runs to the next header or the 2 GB cap. A frame that begins a 512-byte block does not end the carve: `header_confirmed_by_source` treats a frame that follows a whole frame as the next of the chain (`a_frame_on_a_block_boundary_does_not_end_the_carve`). The filler survey (`survey_no_loose_unsized_signature_survives_filler`) does not allow `DAD`. **Not established:** two files; no export with an extension length above 36, a type outside the four, or more than one channel; two exports written back to back read as one chain.

### MEM-ARM-8 — Windows 11 ARM64 software PTEs on a real kernel's page tables, 2026-10-23

**Evidence:** the Windows 11 ARM64 build 28000 install already held (`winarm/vm/win.qcow2`) booted under
`qemu-system-aarch64` 10.0.11 TCG (`-cpu max -smp 4 -m 6G`) to the lock screen, RAM written with QMP `dump-guest-memory` and flattened
to `mem.raw` (6 GiB), registers read through the gdbstub: `TCR_EL1` `0x0000_0695_b551_3511` (4 KiB granules, `T0SZ = T1SZ = 17`, `IPS` 5,
`HPD0`, `HA`), `TTBR1_EL1` `0x09c0_0001_4dbd_d800` (a 256-entry level 0 in the upper half of one page shared with `TTBR0`)
(`forensic_corpora/winarm_28000_qemu/SOURCE.md`). QEMU-emulated, not hardware.
**Ground truth for the layout:** Microsoft's own PDB for the captured kernel (`ntkrnlmp.pdb`, GUID `0382994831D35A1367EF9CC7C56B3F26`, age 1,
fetched from the symbol server and converted with Volatility's `pdbconv`): `_MMPTE_TRANSITION` has `Transition` at bit 11, `Prototype` at bit 10,
`Protection` bits 5:1, `PageFrameNumber` bits 51:12; `_MMPTE_PROTOTYPE` `Prototype` bit 10, `ProtoIndex` bits 53:12; `_MMPTE_SOFTWARE`
`PageFileLow` bits 17:14, `PageFileHigh` bits 63:32. **What the kernel half holds:** 2,325,080 valid 4 KiB pages and 75 valid 2 MiB blocks, and in
non-valid entries 941 transition (all frames inside RAM, bits 63:52 zero, `Protection` values 1, 3, 4 and 31), 1,184 pagefile (`PageFileLow` 0 in
every one, `PageFileHigh` up to 130,655) and 262,418 prototype entries. Level 0 entry 83 is a self-map and six 512 GiB regions alias, so the tree
is some 813 million leaves by path and whole-space enumeration refuses at its run cap and says so.
**Result:** under `PteSemantics::Windows` the ARM64 translation core reads a valid-clear descriptor as above (transition entries are not holes, prototype and pagefile entries are not plain absence). 240 addresses drawn by random descent (seed 28000) and translated by an
independent walker (`scripts/oracle/winarm_walk.py`) agree on every one: 60 pages, 20 blocks, 40 transition pages (recovered, frame and offset), 40
pagefile entries (the page number), 40 prototype entries (named, not followed) and 40 absent ones. Unit tests in `arm64_tests.rs` pin the type bit not being read on a transition entry (`Protection`
bit 0 sits there), a transition page table followed, a transition frame above 2^48 refused, and a valid descriptor's bits 10 and 11 staying the access flag and nG.
**Not established:** one build (28000, a very recent one); any other Windows-on-ARM64 build's layout; the prototype PTE's `ProtoIndex` is not decoded to an address, so shared pages
stay unfollowed; no hardware capture; no `APTable`/`XNTable` bit met. **Re-run:** `SEANCE_WINARM_28000=<dir with mem.raw> cargo test --release -p seance_memory --test arm64_windows_real_test`.

### WMI-5 — a real `ActiveScriptEventConsumer`, and what a WMI record's header time is, on a Windows 11 repository, 2026-10-22

**Evidence:** a repository made on purpose: `forensic_corpora/lab_win11_wmi/` (`GROUND-TRUTH.txt`, `SOURCE.md`, `SHA256SUMS`), copied
from the Seance Windows 11 lab VM (a fresh install of the 25H2 Enterprise Evaluation ISO) after `Stop-Service winmgmt`. Through the WMI API
over SSH, in three waves at known times (02:43:44Z, 02:49:58Z, 02:51:12Z; the guest's UTC read the host's to within a second), one filter and an
`ActiveScriptEventConsumer` (VBScript, a 177-character inert script) and their binding; then a filter, `CommandLineEventConsumer` and binding; then a
lone filter. **`dissect.cim` 3.13 could not grade it** (`ReferenceNotFoundError` on every instance query of this repository); python-cim 1.1 later did (`WMI-7`). The
answer key is what was planted, recorded as it was made.

**Decoded exactly.** The first real `ActiveScriptEventConsumer` instance Séance has met decodes to its name, `ScriptingEngine` `VBScript` and the
script byte for byte, bound to its filter, with the filter's WQL query and the binding beside it (`a_planted_active_script_consumer_decodes_to_what_was_planted`);
the decoder, validated until now on four other classes, read this one from the file's own class definition and was right. Windows' own `SCM Event Log`
instances decode beside them. The index (`INDEX.BTR`) is walked in `WMI-6`.

**What a record's header time is.** A record's later header FILETIME is not its installation time. Every planted record carries a time **before** it was made: 76 minutes (the first wave: `01:27:19Z`, the machine's first boot), 6 minutes (`02:43:56Z`)
and 3 seconds (`02:51:09Z`), the three records of a wave differing by single ticks. The values behave as the repository's *previous commit*: each wave's time equals the
commit of the wave before it. The other FILETIME is the class definition's time, `2024-04-01T07:29:05Z`, the same for every instance of a class. So the header time bounds a
subscription's creation from below and is not the creation time. A record carries `record_time` and `record_time_basis`, `installed_time` is null with its reason, and
the timeline event reads "WMI repository record time (the subscription was made no earlier than this)" (`a_wmi_record_time_is_not_published_as_the_time_the_subscription_was_installed`). **Not established:** one machine and one build; the commit explanation is read from three waves and the byte offsets, not from Microsoft's
documentation; the Windows 7 and Windows 10 repositories' times are labelled the same way without being measured. **Re-run:**
`SEANCE_WIN11_WMI_DIR=~/forensic_corpora/lab_win11_wmi cargo test --release -p seance_plugin_asep -- planted_active a_wmi_record_time`.

### WMI-6 — the Windows 11 repository's index is walked, 2026-10-22

The repository of `WMI-5` (`forensic_corpora/lab_win11_wmi/`). **Mapping and file length.** The mapping accounts for 645 physical pages of `INDEX.BTR` but the file holds 643. Read from the mapping's bytes: its INDEX section has 451 logical pages (444 mapped, the highest to physical page 615) and a free list of 201 pages that includes
643 and 644, the two the file does not hold; no logical page lives past the end of the file. The check accepts a file shorter than the mapping when every page past its end is free, and refuses a file longer than
the mapping or one short of a page that is mapped (three synthetic tests).
**Result on the real repository:** the index is walked (443 pages, 9,453 data references) and names **10 records, all live: the 7 planted** (two filters, two consumers and one binding in the first two waves, a lone filter in the third)
**and Windows' own 3 `SCM Event Log` records**; none is listed-but-not-indexed. The three records of the first wave, rewritten by the second commit, appear once more as `superseded_page` copies, which is what `WMI-5` read from the
byte offsets (each wave's records sit in the next commit). Not a second decoder's grade: `dissect.cim` still refuses this repository, so the answer is what was planted and the structure above. The Flare and Perseverance
repositories grade as before. **Re-run:** `SEANCE_WIN11_WMI_DIR=~/forensic_corpora/lab_win11_wmi cargo test -p seance_plugin_asep --lib wmi_index_tests`.

### WMI-7 - a second decoder reads the Windows 11 repository and lists the same ten records, 2026-10-22

The repository of `WMI-5` and `WMI-6` (`forensic_corpora/lab_win11_wmi/`). **Why a second decoder:** `dissect.cim` 3.13 refuses this repository, so the index walk needs another independent reader of the format. **Decoder:** python-cim 1.1 (flare-wmi, Apache-2.0, `pip install
python-cim`), a different parser of the same format; it opens the repository (`CIM_TYPE_WIN7`, the current mapping `MAPPING3.MAP`), builds its own index and enumerates the instances of each class (`scripts/oracle/wmi_cim_instances.py`, run as an external grader only; no code of it is
in this tree). **Result:** in `root\subscription` it lists **4 `__EventFilter`, 3 consumers (`ActiveScriptEventConsumer`, `CommandLineEventConsumer`, `NTEventLogEventConsumer`) and 3 `__FilterToConsumerBinding`**, with the planted script and command line verbatim: the same ten records the product's index walk names
(`SeanceMarkerFilter`, `SeanceSecondFilter`, `SeanceThirdFilter`, `SeanceMarkerConsumer`, `SeanceSecondConsumer` and Windows' three `SCM Event Log` records), with the same filter and consumer in each of the three bindings. `the_windows_11_repository_agrees_with_a_second_decoder_on_every_subscription_record`
pins it against the committed listing (`seance_plugin_asep/tests/fixtures/wmi_win11_python_cim.tsv`). `SeanceThirdFilter` is a lone filter: neither decoder finds a binding for it.

**Not established:** one repository, one Windows build; the Flare and Perseverance repositories were not re-run through python-cim. **Re-run:** `PYTHONPATH=<dir with cim> python3 scripts/oracle/wmi_cim_instances.py ~/forensic_corpora/lab_win11_wmi | sort` and `SEANCE_WIN11_WMI_DIR=~/forensic_corpora/lab_win11_wmi cargo test -p seance_plugin_asep --lib second_decoder`.

### WMI-8 - a Windows Server 2003 R2 SP2 x64 repository: the XP-era mapping and index, graded by python-cim, 2026-10-22

**Evidence:** the `wbem\Repository\FS` directory (`INDEX.BTR`, `MAPPING.VER`, `MAPPING1.MAP`, `MAPPING2.MAP`, `OBJECTS.DATA`; `forensic_corpora/lab_w2k3_wmi/`) of the fresh Windows Server 2003 R2 Datacenter x64 SP2 evaluation install of `MEM-XP-6`, booted again under KVM with one
`ActiveScriptEventConsumer` (`SeanceXpConsumer`, a VBScript that writes `C:\seance-xp-marker.txt`), its `__EventFilter` and the binding planted by `mofcomp D:\plant.mof` (`~/legacy-lab/mofiso/plant.mof`), then `net stop winmgmt` and a clean shutdown; the five files read out of the disk image.

**What the bytes are.** The mapping files are XP's, not Vista's: a 16-byte header (signature `0xABCD`, sequence, physical page count, logical page count), 4-byte entries, the free list and the footer `0xDCBA`; but in **numbered files holding two sections** like Vista's (`OBJECTS.DATA`'s: 694 logical over 743 physical pages, 49 free; `INDEX.BTR`'s: 126 over 147, 21 free; sequence `0x1544` in both files and both
sections; mapped plus free partition the physical pages exactly). `MAPPING.VER` holds the little-endian number 1. The index pages have the Vista layout, but the root is **not** in the mapping: it is the fourth u32 of the header of logical page 0 (zero on every page of a Vista-onward index).

**Result:** `MappingForm::XpNumbered` reads the two sections; a numbered file is read as Vista's form and, if that fails, as this one (both reasons are kept when neither parses); the index is walked from the root page 0 names. `a_windows_server_2003_repository_is_read_through_its_xp_era_mapping_and_index_and_agrees_with_python_cim`: `mapping_read` and `index_read` true, **all 189 records
are `indexed`** (1 `ActiveScriptEventConsumer`, 62 `NTEventLogEventConsumer`, 63 filters, 63 bindings: a stock install holds the sixty-odd `MCA` machine-check subscriptions and `SCM Event Log` ones, so 188 of the 189 are Windows' own) and their names, classes and bindings equal the 189 python-cim 1.1 lists for the same directory (`CIM_TYPE_XP`,
`scripts/oracle/wmi_cim_instances.py --type=xp`; listing in `tests/fixtures/wmi_w2k3_python_cim.tsv`). The real `MAPPING1.MAP` (3,608 bytes) is a fixture; unit tests pin the two sections, the free-list partition, the refusals (wrong form, truncation, a differing index sequence) and the root-in-page-zero walk on a synthetic index.

**Not established:** one repository, one build. (The single-section Windows XP form was read in the same session, from a disk that held its `INDEX.MAP` all along: `WMI-9`.) **Re-run:** `SEANCE_W2K3_WMI_DIR=~/forensic_corpora/lab_w2k3_wmi cargo test -p seance_plugin_asep --lib windows_server_2003`.

### WMI-9 - a Windows XP repository: INDEX.MAP and INDEX.BTR, graded by python-cim on the same bytes, 2026-10-22

**Evidence:** the `wbem\Repository` of the CFReDS Hacking Case disk (`4Dell_Latitude_CPi.E01`, a Windows XP laptop imaged in 2004; `forensic_corpora/lab_xp_wmi/`: `OBJECTS.MAP` inode 11943, `INDEX.MAP` 11944, `OBJECTS.DATA` 5507, `INDEX.BTR` 5508, read out with `icat`; the `OBJECTS.MAP` is byte-identical to the fixture `cfreds-xp-OBJECTS.MAP`, SHA-256 `61e588e5...87`).
**What the bytes are.** `INDEX.MAP` is one XP-form section (signature `0xABCD`, sequence 4557, equal to `OBJECTS.MAP`'s; 137 physical pages, 105 logical, 32 free; mapped plus free partition the 137 exactly; footer `0xDCBA`; 572 bytes). `INDEX.BTR` is 1,122,304 bytes = 137 pages of 8,192; its logical page 0 is an administrative page (`0xADDD`) whose fourth u32 names the root, logical page 96, as on Windows Server 2003 (`WMI-8`); the other pages are the layout `INDEX.BTR` has everywhere else.
**Result:** `parse_xp_index_map` reads the section; the XP candidate (`OBJECTS.MAP`) gets its index section from `INDEX.MAP` when it is present, parses and carries the same sequence number, and otherwise says so (`INDEX.MAP` is listed as not found or refused, with the reason). `a_windows_xp_repository_is_read_through_its_index_map_and_agrees_with_python_cim`: `mapping_read`, `index_read` and `index_walked` true and **all six subscription records `indexed`**: `SCM Event Log Filter`, its consumer and binding, and `Microsoft WMI Updating Consumer Scenario Control` as filter, as consumer (class `MSFT_UCScenarioControl`) and as binding. They are the six python-cim 1.1 lists for the same bytes. python-cim reads only the numbered form, so the oracle was given `OBJECTS.MAP` and `INDEX.MAP` joined into one `MAPPING1.MAP`, which is the numbered form's own layout; the listing is `tests/fixtures/wmi_xp_python_cim.tsv`. The oracle selects consumer classes by name suffix and by the class's own parent, because `MSFT_UCScenarioControl` is a consumer class with no `EventConsumer` suffix. Unit test: `the_xp_index_map_is_a_single_section_of_its_own_with_the_data_maps_sequence` (real `INDEX.MAP` fixture `cfreds-xp-INDEX.MAP`, truncations and a bad signature refused).
**Not established:** one XP repository, a 2004 machine with five stock subscriptions and no planted one; the deleted copies of `OBJECTS.MAP` and `INDEX.MAP` on that disk (inodes 12302 and 12303) were not read. **Re-run:** `SEANCE_XP_WMI_DIR=~/forensic_corpora/lab_xp_wmi cargo test -p seance_plugin_asep --lib windows_xp`.

### WMI-10 — a subscription made and deleted on Windows Server 2003: the deleted records survive as residue and superseded copies, graded by python-cim, 2026-10-23

**Evidence:** `forensic_corpora/lab_w2k3_wmi_deleted/` (`before/`, `after/`, `SOURCE.md`, `SHA256SUMS`): the `FS` directory of the Server 2003 R2 SP2 x64 lab VM (`WMI-8`) after `mofcomp` made an `__EventFilter`, an `ActiveScriptEventConsumer` and their binding (`SeanceDeleted*7F3A`), and after the three were deleted through the WMI API (`SWbemServices.Delete`; enumeration confirmed 64 to 63 filters, 2 to 1 consumers, 64 to 63 bindings), each taken after `net stop winmgmt` and read from the powered-off NTFS volume (the live files equal `after/`). **Question:** does a deleted subscription leave a record a mapped page lists and no index key names (`listed_not_indexed`, `unlinked`)? **Answer: no.** The page is rewritten without the three descriptors (logical page 693: physical 695 with 13 descriptors before, physical 431 with 10 after), so the record is no longer listed; it survives as bytes in the current page and as copies in two pages the mapping left. python-cim 1.1 lists 192 records before and 189 after, equal to the 189 of `WMI-8`; Seance's `records_indexed` is 192 then 189, `records_listed_not_indexed` 0 both times. **What Seance publishes after the deletion:** seven `RecoveredAsepEntry` rows for the deleted subscription, none live: two `unreferenced_in_mapped_page` (consumer, binding; the filter's bytes were overwritten) and five `superseded_page` (filter, consumer, binding on the original page 695; consumer, binding on an intermediate page 679), each with the "not in force as found" basis and the consumer's script recovered. Pinned by `a_deleted_subscription_leaves_residue_the_scan_publishes_as_recovered_and_the_index_no_longer_names`, which also reads the descriptor tables of the raw pages itself. **Not established:** one machine, one build, one deletion order (binding, filter, consumer); other deletion paths (`mofcomp` `#pragma deleteinstance`, `wmic`, a crash mid-commit) were not run; Vista-form repositories were not tried. **Re-run:** `SEANCE_W2K3_WMI_DELETED_DIR=~/forensic_corpora/lab_w2k3_wmi_deleted cargo test -p seance_plugin_asep --lib a_deleted_subscription`.


### WMI-11 — what the 4 and 23 unindexed descriptors are: system class definitions, 2026-10-25

**Evidence:** the answer key of `WMI-7` (`seance_plugin_asep/tests/fixtures/wmi/index_answer_key.json`) names the descriptors each real repository lists and its index does not: four in each of the three Flare Windows 7 repositories and 23 in the HTB "Perseverance" one. Each descriptor's `(id, size)` was matched in the page descriptor tables of `OBJECTS.DATA` and the record it points at was read. **Result:** all 35 (the same four in each of the three Flare repositories, and the 23) read as class definitions of system classes: strings such as `__Provider`, `__Win32Provider`, `ClientLoadableCLSID`, `HostingModel`, `__IndicationRelated`, `__NamespaceOperationEvent`, `__ProviderRegistration` and its `__*ProviderRegistration` children, `__PARAMETERS`, `SUPPORTS...` provider properties, with the qualifiers `abstract`, `SUBTYPE`, `singleton` and the CIM type names (`string`, `boolean`, `sint32`, `uint64`, `datetime`, `object:`) a definition declares; each holds a `__` system-class name or a declared type, and none names a subscription class (`__EventFilter`, `__FilterToConsumerBinding`, any `*EventConsumer`). The Flare four are the same four records in all three repositories. This is a reading of the strings, not a decode of the record header. **What it does not change:** `listed_not_indexed` / `evidence_state: unlinked` for a subscription record is still pinned on a synthetic index only, because no real repository holds a subscription descriptor its index lacks. Pinned by `the_descriptors_the_index_does_not_name_are_system_class_definitions`. **Re-run:** `SEANCE_FLARE_WMI_DIR=<dir> SEANCE_PERSEVERANCE_OBJECTS_DATA=<file> cargo test -p seance_plugin_asep --lib wmi_index_tests`.


### WMI-12 — a power cut while WMI commits: the last commit stays live, the rest is recovered, 2026-10-25

**Evidence:** `forensic_corpora/lab_w2k3_wmi_deleted/loopA` and `loopF` (`SOURCE.md`): the Server 2003 R2 lab VM's repository after a VBScript made 400 subscriptions and deleted the even-numbered ones, the VM killed after it finished (`loopA`) and 10 s into it (`loopF`). **Result:** `loopA` is 789 records, all indexed, 0 listed and not indexed, the 789 python-cim 1.1 lists. `loopF` is 189 live (the commit before the script) and 609 records in unmapped pages published as recovered, 0 listed and not indexed; python-cim 1.1 raises `Not enough data in fd!` on it, so there is no second decoder for that file. **Not established:** no cut produced `listed_not_indexed`; eight further cuts (3 to 14 s) gave the untouched 189 (4 cuts, before the first write) or the 189 plus the same 609 unmapped records (4 cuts, from 9 s), 0 listed and not indexed in each; the repository files of those eight were not kept. **Re-run:** `SEANCE_W2K3_WMI_DELETED_DIR=~/forensic_corpora/lab_w2k3_wmi_deleted cargo test --release -p seance_plugin_asep --lib power_cut`.

### RM2-HEADLESS-1 — deleted FAT entries in free clusters no `.` anchors, against The Sleuth Kit on CFReDS RM#2, 2026-10-22

**Evidence:** the Data Leakage case's USB stick RM#2 (`cfreds_2015_data_leakage_rm#2.E01`, exported to raw with `ewfexport`; one 1 GiB FAT32 partition at
sector 128, quick-formatted after the files were deleted). **Oracle:** The Sleuth Kit through `scripts/cftt/fat_deleted_key.py` (`fls -r -d`, whose `$OrphanFiles` scan
reaches deleted entries in free clusters, and `istat`): **41 deleted files**, key `seance_plugin_fat/tests/data/cfreds_rm2_deleted_key.json`. They are the 17 the published
answer key names (five deleted directories), `desktop.ini`, and **23 pictures at the root level** whose entries sit in free clusters with no `.` that names the cluster
(the first of them has a `.` and `..` whose `.` names cluster 11492 while the entries sit in 45007: a copy of a directory cluster).

**Result:** all 41 recovered, matched by size and first cluster; the orphan scan alone, which needs a `.` that names its own cluster, recovers 18 of the 41. A further pass reads each free cluster
nothing anchors as a headless directory cluster when its first slot passes `plausible_dir_slot`, every slot before the end marker passes it, and at least two are short entries; a cluster
whose `.`/`..` pair names another cluster is stamped `orphan_directory_dot_names_cluster`. It publishes **23 entries, every one in TSK's list**, and **none on seven other FAT volumes**
(DFTT 6, 2, 11, 9 and 5 and the string-search Windows image's FAT32 partition, 182 deleted entries, the same count TSK gives; the exFAT partition has no FAT scan). Also pinned synthetically (`entries_in_a_free_cluster_nothing_anchors_are_recovered_and_labelled_headless`: the multi-cluster fixture with its parent entry
zeroed and its `.` pointed elsewhere also shows that a deleted directory's later clusters are found as headless clusters of their own; `a_free_cluster_of_file_bytes_is_not_read_as_directory_entries`).

**Not established:** the precision measure is this one volume against TSK plus seven volumes with none to find; TSK is not an oracle for what it does not list. The scan reads the first slot of every free
cluster up to 1,048,576 of them (`headless_directory_scan` says how many and how many it left). A headless cluster does not say which directory it belonged to. **Re-run:**
`SEANCE_LEAK_RM2_RAW=<raw> SEANCE_DFTT_DIR=~/forensic_corpora/dftt SEANCE_CFTT_WIN_DD=<ss-win .dd> cargo test --release -p seance_plugin_fat --test real_rm2_headless_test`.

### WIN11-FAT-1 — Windows 11's own FAT32 and exFAT drivers: what a deleted file and a deleted directory leave, 2026-10-22

**Evidence:** four fixed VHDs made on the Séance Windows 11 lab VM (`forensic_corpora/lab_win11_fat/`, `what-was-done.log`, the
`*.listing.csv` files; `win11-lab/sticky/ps/fat-shapes.ps1`): `fat32.vhd` (256 MiB, 2 KiB clusters) and `exfat.vhd` (128 MiB, 4 KiB), each with a directory of 300
long-named files deleted whole (`DirA`), one of 300 files with 260 deleted and the directory kept (`DirB`), one of 20 files deleted whole (`DirC`), and then
40 files written (`Keep`); and `fat32-clean.vhd` / `exfat-clean.vhd`, the same with nothing written after the deletions. Written by Windows' drivers through
PowerShell and `diskpart`. The answer key is the script; The Sleuth Kit confirmed the deleted entries that exist (`fls -d`: 260 under `DirB`, and `DirA`/`DirC`
themselves with no children).

**Deleted files in a live directory:** recovered by name exactly on all four volumes, 260 of 260, with the sizes the files had. **Deleted directories: Windows
leaves nothing.** Read by hand from the images, every cluster of `DirA`'s exFAT chain (12+ clusters, interleaved with file data, not contiguous) and the first cluster of
the FAT32 `DirA` are entirely zero, `.` and `..` included: the 300 names are not on the volume. (Whether this is the drivers' rule or a consequence of how PowerShell
deletes a tree was not separated; both drivers did it.) Where the freed first cluster was taken again, by the next directory (`Keep`, on the volumes that had files written)
or by file data, it is that instead.

**Four cases that must not be silent** (`seance_plugin_fat/tests/real_win11_fat_test.rs`): a deleted directory with no children is flagged (FAT32 and exFAT), so an empty list is not read as "empty directory"; a deleted directory whose first cluster is the first cluster of a live directory is not skipped without a word; an exFAT
deleted directory whose free first cluster held file bytes does not return an empty, complete-looking listing; and the walk's order does not decide which of two directories wins. A
free, all-zero first cluster is `directory_content_zero` with reason `fat_/exfat_deleted_directory_zeroed` (an empty directory looks the same and the volume cannot tell
which it was); a first cluster that is another directory's, or holds anything but entries, is `_unverified`; and live entries are all read before any deleted one.

**Not established:** other drivers (Linux, macOS, cameras and phones) leave what they leave; none could be written here (a mount needs root). One Windows build. The
zero fill is observed on two volumes of one machine. **Re-run:** `SEANCE_WIN11_FAT_DIR=~/forensic_corpora/lab_win11_fat cargo test --release -p seance_plugin_fat
--test real_win11_fat_test`.

### PST-PUBLIC-2 — recipient tables of four public stores, read and compared with libpff, 2026-10-22

**Scope:** recovery and the live reader read a message's recipient table (a table context in the message's subnode `0x692`), so a deleted message's recipients carry an address and not only display strings. **Evidence:** the public stores of `PST-PUBLIC-1`, graded against libpff through `scripts/oracle/pst_recipients.py` (pypff, every cell of every recipient row as `tag:type=value`; the answers are
`seance_plugin_email/tests/fixtures/pst_public/<store>.recipients.tsv`): `pstsdk-sample2` (ANSI, version 14) and `pstsdk-sample1`, `pstsdk-submessage`, `tika-variousBodyTypes` (Unicode, version 23; four messages). **Result:** all 7 recipient rows match libpff cell for cell (`public_pst_recipients_test.rs`), the
ANSI row index being 2 bytes wide against the Unicode 4 (a unit test and the ANSI store pin it). libpff lists a cell with no data (existence bit clear) as an entry with an empty value; this reader does not list it, and the comparison drops empty cells on both sides. A message with a recipient table is
published with `recipients` (type To/Cc/Bcc, name, address type, address, SMTP address) and `recipients_read: true`; one without says `recipients_read: false` and why. The deleted-message path is pinned by cutting `pstsdk-sample2`'s only message from the live tree
(`a_deleted_messages_recipient_table_is_published_with_its_addresses`).

**Version 36:** `javalibpst-example-2013.ost` (Outlook 2013 OST, 16 MiB, from java-libpst, Apache-2.0, SHA-256 `b18ff390d0c22273029ee580ab6025976af69a4f84e276d1b1c01a988650853d`; libpff reads it) holds three messages with one recipient each; the live reader and the recovery both read the table, and
the three rows' type, name, address type and address equal libpff's end to end (`version_36_ost_messages_publish_their_recipient_tables`). A version 36 multi-block row matrix takes its rows per block from the first block's length.
**Not established:** row matrices held in a subnode, rather than the heap, were not exercised by any store here (a synthetic unit test pins the heap case; the subnode path is the same code with the block bound
8,176 / 8,180 bytes of the specification, and for version 36 the first block's length); no recipient holds non-Latin 8-bit text. The `pst512_parser` fuzz target ran 15 minutes on the public stores and the Jean fixtures.
**Re-run:** `SEANCE_PUBLIC_PST_CORPUS=~/forensic_corpora/public_pst/stores cargo test -p seance_plugin_email --test public_pst_recipients_test`.

### PST-PUBLIC-4 — recipient tables held in a subnode, on three Enron mailboxes, and the row order they exposed, 2026-10-23

**Evidence:** `zl_bailey-s_000.pst`, `zl_dean-c2_000.pst` and `zl_harris-s_000.pst` (Unicode, version 23, EDRM Enron v2 in native PST from `intellekthq/enron-ferc-pst`, CC BY 3.0 US, publisher's SHA-256 list matches;
`tests/fixtures/pst_public/PROVENANCE.md`), graded against libpff through `scripts/oracle/pst_recipients.py`. **What they hold:** messages of 82 to 384 recipients. A row is 52 bytes, so a message of 82 to 144 rows keeps its row matrix in one subnode block and one of 338, 356
or 384 rows in **three** (157 rows per 8,176-byte block), confirmed by a temporary trace of the reader's `Matrix::Blocks` path (not left in the code): 8 messages with 82 to 144 rows (800 recipient rows) and 3 with 338, 356 and 384 (1,078).
**Row order.** A recipient table's rows are in numeric order of their little-endian row ids, not byte order: on bailey's `0x200024` (144 recipients, row ids 88 to 517) row 0 is id 88, and no id of 256 or more precedes a smaller one. `ost4k::ltp::bth` sorts keys of up to eight bytes as little-endian integers (`a_bth_with_four_byte_keys_is_in_numeric_order_not_byte_order`, and the Enron store test on the first row).
**Result:** all 1,878 recipient rows of the 11 messages equal libpff's cell for cell (`public_pst_recipients_test.rs`: `unicode_enron_many_recipient_tables`, `unicode_enron_subnode_matrix_dean`, `unicode_enron_subnode_matrix_harris`); the multi-block path is exercised by a real store for the first time.
**Two comparison limits:** libpff answers `0` for an integer or boolean cell whose existence bit is clear (the rows' bitmaps are `df 80`) and cannot say so, so zero integer and boolean cells are dropped on both sides, which hides a present stored zero that this reader omitted; and libpff
fails to read 3 to 6 messages of each store, so the oracle skips a message it cannot read and says so (`# skipped`). A display name can hold a tab (`Melissa<TAB> Ann`); the listing escapes it.
**Not established:** the 82-to-144-row cases are one block, the 338-to-384 cases three; no store here holds a matrix in more than three blocks or a version 14 or 36 store with a subnode matrix; deleted-item recovery from these stores (the publisher overwrote free space). **Re-run:** `SEANCE_PUBLIC_PST_CORPUS=~/forensic_corpora/public_pst/stores cargo test --release -p seance_plugin_email --test public_pst_recipients_test`.

### PST-CYCLIC-1 — cyclic ("high") encryption, on synthetic re-encodings read by libpff, 2026-10-23

**Why synthetic:** the public stores are all permute-encrypted (a header range request on all 171 stores of the Enron dataset: `bCryptMethod` 1 each), and no other public store, test file or sample holds `bCryptMethod` 2. Outlook's "high encryption" option has existed since Outlook 97 and was never the default.
**Construction:** `scripts/synth/pst_to_cyclic.py`, written from the official MS-PST PDF (revision 11.2, 2025-02-18: §5.1's three 256-byte tables, §5.2's `CryptCyclic` with the low DWORD of the block's BID as key, §5.3's CRC, and the header's two CRCs) without reference to this crate: it finds every data block by its trailer (valid signature and CRC), decodes it with the permutation, encodes it with the cyclic
algorithm, recomputes its CRC, and rewrites `bCryptMethod` and the header CRCs. **The independent answer:** libpff 2023 (pypff) reports `encryption_type` 2 for each output and lists the same messages (subject, sender, body digest, attachment count) as for its original, for `pstsdk-sample1` (v23), `pstsdk-sample2` (v14, ANSI) and `tika-variousBodyTypes` (v23), so the construction and libpff's reading of the algorithm agree.
`Store::open` decodes a cyclic store. `pstsdk-sample1`, `pstsdk-sample2` (ANSI) and `tika-variousBodyTypes` re-encoded read the recipient rows of their originals (`cyclic_*_recipient_table`, `public_pst_recipients_test.rs`), and the 59 MB plaso mailbox re-encoded (8,468 data blocks) lists all 543 messages with the subjects, attachment counts and folders libpff gave for the original
(`every_live_message_in_a_cyclic_copy_reads_as_libpff_reads_the_original`). A unit test pins the cipher on a worked example (key `0x12345678`, bytes 0-3 give 228, 198, 87, 153) and as its own inverse. **Not established:** that an Outlook-written store follows the specification as the construction does (the key is the BID as written in the block trailer; the two differ only if bit 0 is ever set, which libpff's reading of these files would have shown for blocks of this
kind but not for every writer); a version 36 store (the 4 KiB layout refuses any encoded store, unchanged). **Re-run:** `SEANCE_PUBLIC_PST_CORPUS=<dir with the *.cyclic.pst> cargo test --release -p seance_plugin_email --test public_pst_recipients_test cyclic` and `SEANCE_PST23_CORPUS=<dir> cargo test --release -p seance_plugin_email --lib v23_corpus_tests`.

### PST-PUBLIC-3 — a Japanese Outlook 97-2002 store against its Unicode twin, 2026-10-22

**Evidence:** `contacts97-2002.pst` (ANSI, version 14) and `contacts.pst` (Unicode, version 23), the test data of pst-extractor (MIT; `seance_plugin_email/tests/fixtures/pst_public/PROVENANCE.md`, SHA-256 pinned), which hold **the same contact with a Japanese name**. The Unicode
store keeps the text as UTF-16, so it is the answer for the ANSI store, whose text is Shift-JIS bytes with no code page declared: the message carries a locale (1041) and an Internet code page (50220), the store carries nothing. libpff reads the ANSI store as Windows-1252 and prints mojibake, as the
product did.

**Read as Windows-1252** the subject is `ƒRƒ€ ƒhƒbƒg ƒCƒOƒUƒ“ƒvƒ‹ “a`, the folder path `Outlook ƒf[ƒ^ ƒtƒ@ƒCƒ‹‚Ìƒgƒbƒv/˜A—æ (Contact dedicated)` and three folder names, all flagged "Windows-1252 is assumed" (honest, and wrong for a Japanese store). **With the locale rule
(`public_pst_cjk_test.rs`):** a message that declares no page is read in the non-Western Windows page its locale (else its Internet code page) implies, taken only if it decodes the bytes without replacing one, and the record says `codepage_basis: message_locale_id` and `codepage_declared: false`; the folder names are read in
the page the store's sampled messages agree on (`folders_8bit_codepage` on the summary). Subject `コム ドット イグザンプル 殿`, folder path `Outlook データ ファイルのトップ/連絡先 (Contact dedicated)` and all three folder names equal the Unicode store's, character for character. The locale and Internet code
page tables are pinned by unit tests, and so is the fallback: an inferred page that cannot decode the bytes is not taken, a declared one is kept as declared.

**Not established:** one language and one double-byte page. The Cyrillic, Greek, Turkish, Hebrew, Arabic, Baltic, Vietnamese and Central European mappings, and the Chinese and Korean ones, are checked against the Windows locale table by unit tests, not by a real store. A message whose locale is Western but whose
text is not stays Windows-1252 (nothing is inferred). **Re-run:** `SEANCE_PUBLIC_PST_CORPUS=~/forensic_corpora/public_pst/stores cargo test -p seance_plugin_email --test public_pst_cjk_test`.

### LINUX-FAT-1 — Linux's own vfat and exfat drivers: what a deleted directory leaves, 2026-10-22

**Evidence:** four 64 MiB volumes written inside the Séance Linux lab VM (Ubuntu 22.04, kernel 5.15.0-187) by the kernel's `vfat` (512-byte clusters) and `exfat` (4 KiB) drivers mounted over loop devices
(`forensic_corpora/lab_linux_fat/`, `make-fat.sh`, `what-was-done.log`, and `<fs>.<Dir>.created.txt`, `ls -1` of each directory before any deletion). Each volume: `DirA` 300 long-named files deleted whole (`rm -rf`), `DirB` 300 files with 260
deleted and the directory kept, `DirC` 20 files deleted whole, `DirD` 240 files written in two bursts around 200 KB of file data (so the directory is not contiguous) deleted whole; `*-clean.img` stops there, `vfat.img` and `exfat.img` add a 40-file `Keep`.
The answer key is the creation listing.

**What the drivers leave. Unlike Windows, Linux does not zero a deleted directory.** `vfat` marks every entry (name slots included) `0xE5` and frees the chain in the FAT; the directory's clusters keep their names. `exfat` clears the in-use bit of each entry set and frees the
clusters in the allocation bitmap but **leaves the FAT chain** of a directory that used one (`DirA`: first cluster 6, FAT(6) = 28, not contiguous).

**Without the rules below:** deleted files of a live directory 300/300 on both; `exfat` single-cluster `DirC` 20/20; but **`exfat` multi-cluster directories 0 of 300 and 0 of 240** (not descended) and `vfat` directories 2 of 300, 2 of 20, 2 of 240 under their own
path, 225, 15 and 180 of the names found at all as headless clusters. A name cut by a cluster boundary would be published as a truncated long name (`Quarterly-rep`) with no sign it was cut, because deleted name slots lose their ordinal and the
checksum is the same on every slot of the chain, so a missing head cannot be seen from the slots that remain.

**With them (`seance_plugin_fat/tests/real_linux_fat_test.rs`, `hunt278_fat16_e.raw.gz`):** a deleted exFAT directory that used a FAT chain is followed through the stale FAT entries for the clusters its `DataLength` needs, stopping short and flagged at a cluster that is in use
again, every set still gated by its `SetChecksum` (`directory_chain_basis: stale_fat_chain`): all 300, 20 and 240 names of `DirA`, `DirC` and `DirD` on `exfat-clean.img`, `DirD` being non-contiguous. A deleted FAT name whose head lies in the nearest earlier directory cluster is joined
to it when all slots share one checksum and the first byte that checksum implies for the deleted short name equals the upper-case first character of the name, including the single-entry last cluster of a directory (`long_name_basis: stitched_across_clusters`): all 300, 20 and 240
names whole on `vfat-clean.img`. A deleted name whose last slot has no terminator is flagged `long_name_possibly_truncated`. After `Keep` was written (`vfat.img`, `exfat.img`) nothing is invented (every name read is one that was created) and a short listing says so.

**Orphaned exFAT directories.** A deleted directory whose parent's entry is gone is found by scanning the free clusters: one that starts a deleted file entry set (`0x05`, `0x40`, `0x41`) and that no free cluster's stale FAT link leads to is read along its stale chain, every set gated by its `SetChecksum`, and what no listing reached is published under `/[orphan cluster N]/`. Graded by blanking, in a copy of `exfat-clean.img`, the root entry set naming `DirA` (type byte `0x01`, so the root listing continues): all 300 names come back from head cluster 6 and nothing else is reported (`a_deleted_exfat_directory_with_no_parent_entry_is_found_by_the_orphan_scan`); the intact `exfat-clean.img` and `exfat.img` and the two Windows 11 exFAT volumes report no orphan (`an_intact_exfat_volume_has_no_orphans`, `the_orphan_scan_finds_nothing_on_windows_exfat_volumes`). The blanked entry is a constructed case: no volume held lost a parent entry by reuse. The directory's name, path and length are unknown and the listing runs to the end of the chain.

**exFAT slack behind the end marker.** The rest of the marker's own cluster is read; a set is kept only if it lies whole in that cluster and its `SetChecksum` verifies, and is published `deleted` with `recovered_from_directory_slack` (a set that fails counts against nothing, since garbage there is ordinary). Graded on a copy of `exfat-clean.img` with the driver-written set for `DirC` moved behind the root's end marker (original slots made type `0x01`): it is published as slack and its 20 names are descended; with one name byte flipped it is not (`an_exfat_entry_set_behind_the_end_marker_is_slack_only_if_its_checksum_verifies`). A constructed case: no volume held left a set behind a marker. Later clusters are not read.

**Not established:** one Linux kernel and one tool set. The macOS driver, cameras and phones. The stitch trusts that the nearest earlier directory-like free cluster precedes this one, which holds when a directory grows in ascending cluster order, as it did here; a directory
grown against that order, or two deleted directories interleaved, would be joined to the wrong tail only if the checksum and first byte also agree, which is 1 in 256 by chance and is flagged as inferred. A chain whose name ends exactly on a slot boundary (13, 26 characters)
has no terminator and is flagged possibly truncated though it is whole. **Re-run:** `SEANCE_LINUX_FAT_DIR=~/forensic_corpora/lab_linux_fat cargo test --release -p seance_plugin_fat --test real_linux_fat_test`; `cargo test -p seance_plugin_fat hunt278` for the committed mtools volume.

### BSD-FAT-1 — FreeBSD and OpenBSD FAT drivers and FreeBSD's FUSE exFAT: what a deleted directory leaves, 2026-10-23

**Evidence:** ten images (five volumes, each before and after a 40-file `Keep`) written inside FreeBSD 14.5-RELEASE (official VM image, SHA-256 `a027c3a9deafa5af07a8f910c38aed3a58e9adefa18ffb040bc512ecfbc1799a`) with `newfs_msdos`/`mount_msdosfs` (FAT32 512 B, FAT16 4 KiB, FAT32 4 KiB) and `fusefs-exfat` 1.4.0 (`mkexfatfs`, exFAT 4 KiB), and inside the OpenBSD 8.0 miniroot (SHA-256 `fe268f373dacf249b36306096404aa578e0ceb950d08c19c5a1117806997399a`) with `newfs_msdos`/`mount_msdos` (FAT32 512 B, FAT16 4 KiB), under QEMU/KVM (`forensic_corpora/lab_bsd_fat/`, `SOURCE.md`, `make-*.sh`). The shapes are those of `LINUX-FAT-1`; the answer keys are the guest's own `ls -1` and `sha256 -r` before any deletion. FreeBSD's `msdosfs` is the ancestor of macOS's `msdos` driver, which could not be run.
**What the drivers leave.** Neither BSD FAT driver zero-fills a deleted directory (Windows 11 does); both mark the entries `0xE5`, free the FAT chain and leave the clusters. FreeBSD allocates a directory's clusters between the data clusters of its own files; OpenBSD allocates them consecutively. FreeBSD's FUSE exFAT frees every FAT link of a deleted directory (Linux's `exfat` leaves them) and leaves `DataLength` at one cluster.
**Result.** Every deleted file read back at its recorded runs hashes to the guest's `sha256`. FreeBSD FAT: all names of the three deleted directories come back whole (stitched across the interleaving), the first cluster under the folder (2 or 21 names) and the rest as headless clusters whose path says it names a cluster; the directory records say the listing is partial. OpenBSD FAT: all 300, 20 and 240 names under their own path, `directory_chain_basis: contiguous_assumed`. FreeBSD FUSE exFAT: the one-cluster `DirC` whole; `DirA` 105 of 300 and `DirD` 84 of 240 (the orphan scan sees only clusters that start at an entry set), both flagged `exfat_chain_incomplete`. Nothing is invented on any image, including after `Keep`.
**No double publication.** The contiguity walk of a deleted directory records the clusters it read, so the headless scan does not publish a later entry a second time (554 of 823 names would otherwise appear twice on `ofat32c1-clean`); pinned by `a_deleted_entry_read_under_its_directory_is_not_published_again_as_headless`.
**Not established:** macOS itself, NetBSD, Haiku, ReactOS, Android and camera firmware; one release of each driver; the exFAT names in clusters that begin mid-set are not recovered. **Re-run:** `SEANCE_BSD_FAT_DIR=~/forensic_corpora/lab_bsd_fat cargo test --release -p seance_plugin_fat --test real_bsd_fat_test`.

### BSD-FAT-2 — NetBSD 11.0's FAT driver: what a deleted directory leaves, 2026-10-24

**Evidence:** four images (two volumes, each before and after a 40-file `Keep`) written inside the official NetBSD 11.0 amd64 live image (SHA-512 `ad0bc2786b2cd8b7c140ae108fd780064465fe06337a3a2c3f3b694ed3a1e042b3d401c9a682be02c081f3eb3efeba1246cfd6a8803149468ebfbd9c0e7c77e8`, checked against the release's `SHA512` list) under QEMU/KVM, with `newfs_msdos` and `mount_msdos -l`: `nfat16c8` (FAT16, 4 KiB clusters) and `nfat32c8` (FAT32, 4 KiB). The shape and answer keys are `BSD-FAT-1`'s. NetBSD's driver refused to mount a 64 MiB FAT32 volume with 512-byte clusters (`Invalid argument`), so no such volume exists. **What the driver leaves:** like OpenBSD's, it marks the entries `0xE5`, frees the FAT chain, leaves the clusters, and grows a directory over consecutive clusters. **Result:** every deleted file read back at its recorded runs hashes to the guest's `sha256`; `DirA`, `DirB`, `DirC` come back whole under their own paths (`contiguous_assumed`); `DirD` is whole on FAT32, and on FAT16 the head of file 043's long name ends one cluster and its tail begins a cluster the filler separates, so that one entry is published cut and flagged `long_name_possibly_truncated` and `DirD`'s listing says it is partial (the other 239 names whole, 42 under the folder). After `Keep`, nothing is invented and no entry is published twice. **Not established:** macOS itself, Haiku, ReactOS, Android and camera firmware; one release of the driver. **Re-run:** `SEANCE_BSD_FAT_DIR=~/forensic_corpora/lab_bsd_fat cargo test --release -p seance_plugin_fat --test real_netbsd_fat_test`.

### MEM-VC-8 — VeraCrypt 1.26.29 on Windows Server 2022 build 20348.587: a second OS build, and a pool region the type map names wrongly, 2026-10-25

**Evidence:** the Windows Server 2022 Standard Evaluation lab disk (`forensic_corpora/lab_s2022_eval`, kernel 10.0.20348.587, `ntkrnlmp.pdb` GUID `D801A9AFC0FB7761380800F708633DEA` age 1, from the evaluation ISO's unattended install) booted under QEMU/KVM with 4 GiB of RAM, VeraCrypt 1.26.29 installed from `VeraCrypt_Setup_x64_1.26.29.msi` (SHA-256 `5ba6426983123cfb92bc1f09bd888fdbc0f53f300d0d9c5da52ce3aee8d474f0`, equal to the release's list), and seven 20 MiB SHA-512 / NTFS volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:` (`a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc` Kuznyechik(Twofish); passwords `SeanceVC-S22-A` to `-G`). The guest has no SSH: the scripts came on a CD (`forensic_corpora/lab_s2022_vc/iso_src`), the keyboard is a UK layout driven through the QEMU monitor, and a second disk carried the containers out. The memory was dumped through QMP (`dump-guest-memory`, ELF) and converted by `elf2raw.py`; the symbol file was made from Microsoft's PDB with Volatility's `pdbconv`. **Ground truth:** each header decrypted on the host by `scripts/oracle/vc_header_keys_all.py` (twenty keys over ten cipher layers), independent of the crate. **Two lab notes:** `msiexec` in a batch file returns before the install ends (use `start /wait`), and `VeraCrypt.exe /v ... /q /s` (silent) hangs and mounts nothing here, where `/v ... /q` mounts a volume in a few seconds only when no other `VeraCrypt.exe` is running; the first capture had no volume mounted and was discarded. **Result:** the region the virtual map names `MiVaNonPagedPool` (23,654,400 bytes) holds no key schedule, while a host search of the image finds the Serpent, Kuznyechik and AES master keys once each. All 145 loader entries (tag `MmLd`, pool-header type non-paged, as on Windows 11) and all the key schedules lie in the region the map names `MiVaPagedPool`; on the Windows 11 build 26200 capture all 155 lie in `MiVaNonPagedPool`. The sweep takes the labelled region unless it holds none of the loader entries and then the region that holds most of them (`pool_sweep_region`, unit tests `the_labelled_pool_region_is_swept_when_the_loader_entries_lie_in_it`, `the_region_holding_the_loader_entries_is_swept_when_the_labelled_one_holds_none`, `without_placed_loader_entries_the_label_decides`). With it, 34 schedules are found, every key of every volume is reported, and all seven containers are decoded under the 1.26.29 layout with ids 2, 3, 4, 5, 6, 8 and 12 (`win2022_veracrypt_12629.rs`). The Windows 11 captures read as before. **Not established:** why the type map names the regions as it does on this build (the survey's `SystemVaRegions` array also reads four junk entries here); other builds of Server 2022, Windows 10 and Server 2019; another VeraCrypt or TrueCrypt version on this build. **Re-run:** `SEANCE_S22_VC12629_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win2022_veracrypt_12629` (`zstd -d --sparse mem.raw.zst -o mem.raw` first); `cargo test -p seance_plugin_memory_windows --lib virtual_map`.

### MEM-VC-12 — VeraCrypt 1.26.28 Beta4 on Windows Server 2019: the container geometry has not changed yet, 2026-10-25

**Evidence:** `VeraCrypt_Setup_x64_1.26.28.msi` from the project's GitHub release `VeraCrypt_1.26.28_Beta4` (SHA-256 `5a632a7e1e15579292142fc10ed9653795bc80ad184f3adf6dd0706155902b5a`; the detached signature verifies Good against the VeraCrypt Team key `5069A233D55A0EEB174A5FC3821ACD02680D16DE`), installed on the Server 2019 lab of `MEM-VC-11` with the same seven volumes mounted (passwords `SeanceVC-W19-12628-A` to `-G`). **Result:** every key of every volume is found and all seven containers are decoded under the 1.19 to 1.26.24 geometry (schedules at `+0x0c`, 5,304 bytes on) with 1.26.29's cipher ids (2, 3, 4, 5, 6, 8, 12); the driver is `veracrypt.sys`. So the geometry change that `MEM-VC-6` placed between 1.26.24 and 1.26.29 happens between 1.26.28 Beta4 and 1.26.29, and the hybrid of 1.26.29's ids on the older geometry runs through 1.26.28 Beta4. The layout label names 1.26.28 Beta4. **Not established:** 1.26.25 to 1.26.27 and 1.26.28's other betas, which no installer was obtained for; 1.26.30 is graded in `MEM-VC-15`. **Re-run:** `SEANCE_W19_VC12628_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win2019_veracrypt_12628`.

### MEM-VC-11 — VeraCrypt 1.26.29 on Windows Server 2019 build 17763.379: a fourth OS build, where the typed pool region is right, 2026-10-25

**Evidence:** the Windows Server 2019 Standard Evaluation ISO (`17763.379.190312-0539.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso`, 5,105,074,176 bytes, SHA-256 `221f9acbc727297a56674a0f1722b8ac7b6e840b4e1ffbdd538a9ed0da823562`), fetched over HTTPS from `software-download.microsoft.com` (the URL is one a public blog lists; no registration; no vendor hash list was found to check against), installed unattended under QEMU/KVM with the Server 2022 answer file (`~/legacy-lab/ans19`), then VeraCrypt 1.26.29 (build 1809 is the oldest it runs on) and the seven volumes of `MEM-VC-8` mounted together (`forensic_corpora/lab_w19_vc/run_vc.sh`, passwords `SeanceVC-W19-12629-A` to `-G`); symbols `ntkrnlmp.pdb` `8B11040A5928757B11390AC78F6B6925` age 1. **Ground truth:** each header decrypted on the host by `scripts/oracle/vc_header_keys_all.py`. **Result:** every key of every volume is found and all seven containers are decoded under the 1.26.29 layout with ids 2, 3, 4, 5, 6, 8 and 12; the driver is `veracrypt.sys`. **Here the region the map names `MiVaNonPagedPool` does hold the loader entries** (`pool_sweep_region` returns the label, basis `Label`, asserted by the test), so the old rule would have found the keys: the mismatch of `MEM-VC-8` and `MEM-VC-10` is specific to builds 20348 and 14393 among the four measured. **Not established:** other builds of Server 2019 and Windows 10 1809 or later; why 14393 and 20348 differ. **Re-run:** `SEANCE_W19_VC12629_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win2019_veracrypt_12629`.

### MEM-VC-10 — VeraCrypt 1.25.9 on Windows 10 Enterprise build 14393 (1607): a third OS build, 2026-10-25

**Evidence:** the evaluation ISO of Windows 10 Enterprise 1607 (`14393.0.160715-1616.RS1_RELEASE_CLIENTENTERPRISEEVAL_OEMRET_X64FRE_EN-US.ISO`, 3,903,653,888 bytes, SHA-256 `f32f451fb702a8660f1cf4ebf714ca38e44b193d54521dd6a9d567fcc3655f97`), fetched over HTTPS from `download.microsoft.com` (the link is the one the public Evaluation Center list gives, `care.dlservice.microsoft.com/...`, which redirects there; no registration was involved, and no vendor hash list was found to check the file against), installed unattended under QEMU/KVM from `~/legacy-lab/ans10/autounattend.xml` (the Server 2022 answer file with image index 1 and the built-in Administrator enabled in the specialize pass). **VeraCrypt 1.26.29 refuses to run here** ("requires at least Windows 10 version 1809"), so VeraCrypt 1.25.9 (`veracrypt-1.25.9-sha256sum.txt` equal) was installed and the same seven volumes were created and mounted as in `MEM-VC-8` (`forensic_corpora/lab_w10_vc/run_vc.sh`, passwords `SeanceVC-W10-1259-A` to `-G`); the kernel's symbols are `ntkrnlmp.pdb` `DD08DD42692B43F199A079D60E79D217` age 1 made with `pdbconv`. **Ground truth:** each header decrypted on the host by `scripts/oracle/vc_header_keys_all.py`. **Result:** the virtual map's region named `MiVaNonPagedPool` holds none of the loader entries on this build either, so the sweep takes the region that does (`pool_sweep_region`, basis `LoaderEntries`, asserted by the test); every key of every volume is found and all seven containers are decoded under the 1.19 to 1.26.24 layout with the 1.25.9 ids (2, 3, 4, 6, 7, 9, 13); the driver is `veracrypt.sys` (`win10_veracrypt_1259.rs`). **Not established:** other builds of Windows 10, Server 2016 and 2019; a VeraCrypt newer than 1.25.x on this kernel (none runs); the cause of the typed region's place. **Re-run:** `SEANCE_W10_VC1259_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win10_veracrypt_1259`.

### MEM-VC-9 — VeraCrypt 1.26.14 and 1.26.18 on Windows Server 2022: two more builds, no code change beyond a label, 2026-10-25

**Evidence:** two fresh copies of the Server 2022 lab disk of `MEM-VC-8`, each with one version installed from its signed MSI (`forensic_corpora/veracrypt_installer/v12614`, `v12618`, from the project's GitHub release; SHA-256 `9a29c7b3b911bbc50bc7f41f93c7659ce70599fd19a78aca002bd6e4a8d3e9a4` and `b7d0495453259fffe0b9c5ffba02a4c36614f18dd2ad00c90ef7b95613cb1314`; each detached signature verifies Good against the VeraCrypt Team key `5069A233D55A0EEB174A5FC3821ACD02680D16DE`, the key of the earlier 1.25.x and 1.26.x installers) and the same seven volumes mounted together as `P:` to `V:` (passwords `SeanceVC-S22-12614-A` to `-G` and `SeanceVC-S22-12618-A` to `-G`). The cycle is scripted (`forensic_corpora/lab_s2022_vc/run_vc.sh`, `finish_vc.sh`); each mount is its own run of `VeraCrypt.exe /v ... /q` with the previous process killed, 16 s apart, and all seven drive letters were confirmed in the guest before the dump. **Ground truth:** each header decrypted on the host by `scripts/oracle/vc_header_keys_all.py`. **Result:** on both builds every key of every volume is found and all seven containers are decoded under the 1.19 to 1.26.24 layout with 1.26.29's cipher ids (2, 3, 4, 5, 6, 8, 12), as on 1.26.7 to 1.26.24; the driver is `veracrypt.sys` on both (not `truecrypt.sys`). The layout's label names the versions it was observed on, and now includes 1.26.14 and 1.26.18. **On the second boot the virtual map named the region that holds the loader entries `MiVaUnused`, where on the first it was `MiVaPagedPool`:** the map's names on this build do not follow the allocations even between boots, which the loader-entry choice of `MEM-VC-8` covers and a name-based choice would not. **Not established:** 1.15, 1.20 and 1.0a to 1.0d (unobtainable), 1.26.28 Beta4 and 1.26.30 (not captured), the other 1.24 updates, the other cascades. **Re-run:** `SEANCE_S22_VC{12614,12618}_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win2022_veracrypt_{12614,12618}`.

### BSD-FAT-3 — Haiku's FAT driver: a deleted directory whose slots keep their ordinals, 2026-10-25

**Evidence:** four images (two volumes, each before and after a 40-file `Keep`) written inside the official Haiku nightly `hrev60295` x86_64 live image (SHA-256 `8463dae69f38525d9b36038cdb39252b9b4f604efad37724b08cc018ebe3a951`, from `haiku-nightly.cdn.haiku-os.org`, matching its `.sha256`) under QEMU/KVM, with Haiku's own `mkfs -t fat` and `mount -t fat`: `hfat64` (FAT16, 2 KiB clusters) and `hfat300` (FAT16, 8 KiB). The guest was driven through the QEMU monitor (`sendkey`, the PS/2 pointer to open Terminal from the Deskbar), the script delivered on a SATA disk (`forensic_corpora/lab_bsd_fat/make-fat-haiku.sh`, `guest_haiku/`, `what-was-done-haiku.log`); Haiku's live image has no virtio-blk driver. The shape and answer keys are `BSD-FAT-1`'s (`sha256sum` in place of `sha256 -r`). **What the driver leaves:** it frees the FAT chain and leaves the clusters, and it **does not mark the slots `0xE5`**: every name slot keeps its ordinal and every short entry its first byte. It interleaves a directory's clusters with the data of its own files, as FreeBSD's does. **Cut names.** A long name cut by a cluster boundary would be published as a shorter name with no flag (35 names on `hfat64-clean` and 8 on `hfat300-clean`: `Quarterly-rep`, `Quarterly-report-DirD-235-with-a-long-d`) by a cut flag that reads only the terminator a `0xE5`-marked slot leaves and a join that requires a marked short entry. For this driver the cut is read from the first slot's ordinal (`0x40` opens the chain), and the head is joined from the cluster before when the ordinals count down without a gap and the checksum is the short entry's own. **Result:** every name of `DirA`, `DirC` and `DirD` comes back whole on both volumes, none is shown cut, every deleted file read back at its recorded runs hashes to the guest's `sha256sum` (560 of 560 on `hfat64`), `DirB`'s 300 names come back, and the directory records say the listing under the folder is partial. After `Keep`, nothing is invented, no entry is published twice, and the one name per volume whose cluster `Keep` reused is shown cut and flagged. Every earlier FAT real-volume suite (Linux, Windows 11, FreeBSD, OpenBSD, NetBSD, the rm2 image) passes. **Not established:** macOS itself, Android and camera firmware (ReactOS is `BSD-FAT-4`); one release of the driver; Haiku's exFAT driver (it mounts exFAT, and `mkfs` cannot create it). **Re-run:** `SEANCE_BSD_FAT_DIR=~/forensic_corpora/lab_bsd_fat cargo test --release -p seance_plugin_fat --test real_haiku_fat_test`; `cargo test -p seance_plugin_fat ordinals`.

### MEM-KERN-1 — real kernel-mode malware on Windows Server 2003 R2 SP2 x86: the kernel-side tamper groups stay silent, 2026-10-26

**Evidence:** `forensic_corpora/lab_w2k3x86_malware/` (`SOURCE.md`, `SHA256SUMS`): a 32-bit Windows Server 2003 R2 Standard SP2 trial install (the Internet Archive item `WindowsServer2003R2StandardEditionwithSP2Trialx86`, SHA-1 `925ad2ea...` equal to the item's, uniprocessor kernel `ntoskrnl.pdb` GUID `6CB8DB5C933549D480D86C017861E13D` age 2) under QEMU/KVM with **no network device**, and the samples of `ytisf/theZoo` (hash-checked against each zip's `.sha256`, password `infected`, extracted into new directories and never run on the host): Rustock `-23`, `.C`, `.E`, `.I`, `.J` and `.NFE`, BlackEnergy 2.1 and ZeroAccess. Each ran on a fresh overlay of the clean install; the three native Rustock drivers were loaded with `sc create ... type= kernel` and `sc start`, the droppers run, `Rustock.J`'s decoy installer clicked through; RAM was dumped 100 to 150 s later. Eleven captures: the clean machine after 20 s (`base`), after 150 s with nothing run (`idle`), and nine runs (Rustock-23, .C, .E, .I, .J twice, .NFE, BlackEnergy 2.1, ZeroAccess). The ISF was built from Microsoft's symbol server. **Result:** all seven groups run on all of them (`groups_ran` 7) and **none claims anything**: no timer routine outside a module, no orphan kernel thread, no suspended or breakpointed thread, no pointer into an unloaded driver's range. What the malware did change, graded in `seance_plugin_memory_windows/tests/w2k3x86_malware.rs` on `base`, `idle`, `r23`, `rc`, `be2`, `za`: BlackEnergy 2.1 adds one listed module named `0000224A`; `Rustock.C` and `.NFE` load as ordinary listed modules (`rc.sys`, `rnfe.sys`); ZeroAccess leaves the loaded list one module short and `ipnat.sys` in the unloaded-driver table (a fifth entry beside four); Rustock-23's run leaves `Beep.SYS` in the unloaded table while it is also loaded. The idle control unloads nothing in 150 s, so the unloads coincide with the runs; one run each does not establish that the malware caused them (`Beep.SYS` can be loaded by the console bell). Rustock.E crashed the guest and its capture is the logon screen. **Not established:** a true positive. No sample put code outside a module, which is what the timer and orphan-thread groups look for, so this measures that the checks do not cry wolf over real malware that stays inside modules, not that they would find a hidden driver. The converse risk the entry names (a check too strict to fire) is not retired. **Re-run:** `zstd -d --sparse mem.raw.zst -o mem.raw` in each of `base idle r23 rc be2 za`, then `SEANCE_W2K3X86_MALWARE_DIR=~/forensic_corpora/lab_w2k3x86_malware cargo test --release -p seance_plugin_memory_windows --test w2k3x86_malware`.

### MEM-ARM-11 — a second real Windows 11 ARM64 kernel (build 26300): the pagefile index, `APTable`, and the tables, 2026-10-26

**Evidence:** `forensic_corpora/lab_winarm64/` (`SOURCE.md`, `SHA256SUMS`, `mem.raw.zst`): Microsoft's `Windows11_Client_arm64_en-us_26300_9457.iso` (from Microsoft's download service), installed unattended under `qemu-system-aarch64` 10.2.1 TCG and paused at the first-logon screen; RAM by `pmemsave`, registers by the gdbstub: `TCR_EL1` `0x0000_0695_b551_3511` (4 KiB, `T0SZ = T1SZ = 17`), `TTBR0_EL1` `0x0040_0000_400a_1000`, `TTBR1_EL1` `0x0040_0000_400a_1800`. **QEMU-emulated, not hardware.** Kernel `ntkrnlmp.pdb` GUID `7A9F162A39E89C67CD02CF2126D51A65` (from its `RSDS` record). **Layout, from that PDB:** `_MMPTE_SOFTWARE.PageFileLow` bits 9:6 and `PageFileHigh` 63:32; `_MMPTE_PROTOTYPE.ProtoAddress` 63:16; `Prototype` bit 10 and `Transition` bit 11. Build 28000's PDB (`MEM-ARM-8`) has `PageFileLow` at 17:14 and `ProtoIndex` at 53:12, so **the layout moved between the two builds**. **Result:** the user tree (13 tables, 83 4 KiB pages, digest `0xe89dd0eb5dad96fb`, no anomaly) equals `scripts/oracle/arm64_walk.py --granule 12`; 240 addresses drawn from the kernel half by `scripts/oracle/winarm_walk_ram.py` (seed 26300: 60 pages, 20 blocks, 40 each of transition, pagefile, prototype and absent) all agree; the kernel half has a self-map and five 512 GiB regions that alias (some 813 million leaves by path) and enumeration refuses at its run cap and says so (`caps_reached: [Runs]`, top indices 176 to 255 unfinished). **Pagefile index.** Bits 17:14 are 0 in every one of 376 distinct pagefile entries drawn (400 draws) while `PageFileLow` is 1 in 7 of them, so reading the index at bits 17:14 would give `swap_index` `Some(0)` for entries whose own field names pagefile 1. No index is stated on ARM64; the offset is. **`APTable`:** 48 of the 52 valid kernel level-0 table descriptors and both user ones have bits 63:59 = `0x14` (`NSTable` and `APTable[0]`, EL0 access denied below); the self-map and three others have none, and no `XNTable`/`PXNTable` bit is set. The older build 28000 capture shows the same (49 and 3 of 52). This is the first real `APTable` bit; the crate reports no access permission, so it stays a decided limit. **Not established:** hardware; `ProtoAddress` is not decoded (the field differs by build); `PageFileLow` per build (a build number is not available to the spec); any build other than 28000 and 26300. **Re-run:** `zstd -d --sparse mem.raw.zst -o mem.raw` in `lab_winarm64/`, then `SEANCE_WINARM_26300=~/forensic_corpora/lab_winarm64 cargo test --release -p seance_memory --test arm64_windows_26300_real_test`.

### MEM-VC-15 — VeraCrypt 1.26.30 on Windows Server 2019, 2026-10-26

**Evidence:** `VeraCrypt_Setup_x64_1.26.30.msi` from the project's SourceForge folder (`Windows/`, released 2026-10-25; SHA-256 `6164d4e4e8d8e600003f6cf14fafe7f50ce23b3452cae02ea19e5ad6f0cc41ad`, the line of `veracrypt-1.26.30-sha256sum.txt`; the MSI's `.sig` and the sums file's `.sig` both verify Good against the VeraCrypt Team key `5069A233D55A0EEB174A5FC3821ACD02680D16DE`), installed with `msiexec /qn` on a fresh copy of the Server 2019 lab of `MEM-VC-11` with the seven volumes of `MEM-VC-8` mounted (`forensic_corpora/lab_w19_vc/run_12630/`, `mem.raw.zst`). **Result:** every master key of every volume is found and every container decoded under the 1.26.29 layout (the geometry change stays between 1.26.28 Beta4 and 1.26.29); 48 product builds are graded. `win2019_veracrypt_12630.rs`; the layout label reads "VeraCrypt 1.26.29 to 1.26.30 (observed on 1.26.29, 1.26.30)". **Re-run:** `SEANCE_W19_VC12630_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win2019_veracrypt_12630`.

### MEM-ARM-10 — a real 64 KiB-granule 512 MiB block, and real non-zero invalid descriptors written by Linux, 2026-10-25

**Evidence:** the Ubuntu 6.8 64 KiB kernel of `MEM-ARM-6` booted again under QEMU TCG with 4 GiB of RAM (`~/arm-qemu/run64.sh`, `qemu-system-aarch64` 10.2.1, `-M virt -cpu max,lpa2=off -m 4096`) and the command line `rodata=on kfence.sample_interval=100`, RAM saved with `pmemsave` and `TCR_EL1` `0x0150_01f5_f550_7510`, `TTBR1_EL1` `0x001a_0000_428a_0001`, `TTBR0_EL1` `0x001a_0001_0058_1801` read through the gdbstub (`forensic_corpora/arm64_64k_4g_qemu/`). **Why those arguments:** with 4 GiB and `rodata=on`, then `rodata=off`, the linear map was still 70,624 64 KiB pages and no block, because Ubuntu's kernel is built with KFENCE and, in this version, a KFENCE that is compiled in and not started forces page mappings; starting it early lets the linear map use level-2 blocks. **Oracle:** `scripts/oracle/arm64_walk.py` extended to `--granule 16` (levels 1 to 3, blocks only at level 2; it reproduces `MEM-ARM-6`'s 13,203 pages and digest exactly) and, for this tree, to report the addresses that stop at a non-zero invalid descriptor. **Result:** the kernel tree has **21,211 pages and 6 blocks of 512 MiB**, the process tree 26 pages, and both agree with the oracle on counts, digest, 16 spot translations and the faults at every depth (`arm64_64k_blocks_real_test.rs`; a wrong block count fails it). The kernel tree also holds **261 invalid descriptors that are not zero**: KFENCE protects its guard pages by clearing the valid bit and leaving the rest (`0x0068_0001_3dfe_0706`), and six faults pinned from them report the entry as written. These are the first real 64 KiB block and the first non-zero invalid descriptors a Linux kernel wrote in these captures; they are not swap or `PROT_NONE` entries. **Not established:** ARM64 hardware; an `APTable` bit (none set in any capture); a non-zero invalid descriptor that is a Linux swap or `PROT_NONE` entry in a running 64 KiB guest. **Re-run:** `SEANCE_ARM64_64K_4G=<dir with mem.raw> cargo test --release -p seance_memory --test arm64_64k_blocks_real_test`.

### MEM-ARM-9 — FreeBSD, NetBSD and HelenOS page tables, a real non-zero invalid descriptor, and execute-never on the 16 KiB capture, 2026-10-25

**Evidence:** three more QEMU-emulated AArch64 guests of the MMUShell dataset (Oliveri & Balzarotti, ACM TOPS 2022; `aarch64/freebsd.7z`, `netbsd.7z` and `helenos.7z` of the tar of `MEM-ARM-1`): FreeBSD's `pmap`, NetBSD's and HelenOS's own tables, the first non-Linux ones this crate has met, each a RAM dump at physical `0x4000_0000` and a `.regs` register history read without unpickling (`forensic_corpora/mmushell_aarch64/regs_read.py`). All three record a 4 KiB granule and 48-bit regimes (`TCR_EL1` `0x14_b510_3510`, `0x12_b510_3510` and `0x15_b510_3510`; FreeBSD programs a 44-bit `IPS`, NetBSD 40, HelenOS 48). **Oracle:** `scripts/oracle/arm64_walk.py`, now with `--granule 12` (and counts of table descriptors with bits 63:59 set, non-zero invalid descriptors, and execute-never leaves), unchanged in its 16 KiB output. **Result:** seven trees agree with it on every leaf (counts by size, the digest over `(va, pa, size)`, 16 spot translations and the faults at every depth): FreeBSD kernel 71,633 pages, 524 2 MiB and 3 1 GiB blocks, and a process tree of 17,953 pages; NetBSD kernel 26,822 pages, 514 and 3, and a process tree of 3,360 pages (ASID `0x1bb`); HelenOS kernel 529,649 pages, a boot tree of 7,167 pages, 1,099 and 512 blocks, and a process tree of 1,010 pages (`arm64_mmushell_other_os_test.rs`; a corrupted expected digest fails it, so it runs). **HelenOS's kernel root holds 510 invalid descriptors that are not zero** (`0x41d0a002`: valid bit clear, next-table address and bit 1 left in place) and two of the pinned faults stop at one: the crate reports the entry as written. No table descriptor in these trees sets bits 63:59. **Table descriptors on the 16 KiB capture.** The 16 KiB Debian 6.12 capture (`MEM-ARM-5`) sets them: 26 of its kernel's 28 table descriptors set `PXNTable` and `UXNTable` (`0x1800_0000_5fff_c003`) and 6 of its process's set `PXNTable`. Every leaf below already carries its own bit, so the hierarchical rule is never what decides there (0 of 34,313 no-execute kernel leaves are made so by a table descriptor), and the crate's counts (34,313 of 35,425 kernel leaves, 6 of 90 process ones) equal the oracle's (`execute_never_agrees_with_the_independent_walker_on_every_leaf_of_both_trees`); the rule itself stays pinned on synthetic tables. **Not used, and why:** rCore (its RAM is 25 dump fragments), Barrelfish (a reserved `TG1` encoding) and Embox, whose `TCR_EL1` `0x4000` has `TG0` = 64 KiB and `T0SZ` = 0 with the MMU on: the crate refuses it by name ("wider than 48 bits needs FEAT_LPA2 or FEAT_LVA"), pinned by `a_recorded_tcr_with_a_64k_granule_and_a_zero_t0sz_is_refused_not_guessed`. **Not established:** ARM64 hardware (every result here is emulated); a 16 or 64 KiB block (none met); an `APTable` bit (none met); a non-zero invalid descriptor that is a swap or `PROT_NONE` entry of another OS. **Re-run:** `SEANCE_MMUSHELL_AARCH64=<dir with freebsd/ netbsd/ helenos/> cargo test --release -p seance_memory --test arm64_mmushell_other_os_test`; `SEANCE_ARM64_16K=<dir> cargo test --release -p seance_memory --test arm64_16k_real_test`.

### MEM-VC-14 — VeraCrypt 1.23-Hotfix-2 on Windows Server 2019, 2026-10-25

**Evidence:** `VeraCrypt Setup 1.23-Hotfix-2.exe` from the project's SourceForge folder (SHA-256 `d55c26807a591643dd4c21ac0ffaaa733aafa52307d36ed9a95ed0a5ef35e4fe`, equal to the line of the release's `veracrypt-1.23-Hotfix-2-sha256sum.txt`; the installer's own detached signature verifies Good against the VeraCrypt Team key `5069A233D55A0EEB174A5FC3821ACD02680D16DE`, and **the signature of that sums file reports BAD**, so the list is corroborated by the installer's own signature and not by its own), installed by the wizard driven as in `MEM-VC-13` on a fresh Server 2019 copy with the seven volumes mounted (`SeanceVC-W19-123h2-A` to `-G`). **Result:** every key of every volume is found and all seven containers are decoded under the 1.19 to 1.26.24 geometry with the 1.25.9 ids; the driver is `veracrypt.sys`. The layout label names the build (47 product builds). **Not established:** 1.24-Update3 (its folder holds no Windows installer), 1.15, 1.20, 1.0a to 1.0d. **Re-run:** `SEANCE_W19_VC123h2_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win2019_veracrypt_123h2`.

### MEM-VC-13 — VeraCrypt 1.24, 1.24-Hotfix1 and 1.24-Update2, -4, -5, -6 on Windows Server 2019: six more builds from the wizard installers, 2026-10-25

**Evidence:** `VeraCrypt Setup 1.24.exe`, `1.24-Hotfix1`, `1.24-Update2`, `-Update4`, `-Update5` and `-Update6` from the project's SourceForge folders (`forensic_corpora/veracrypt_installer/w124*`; SHA-256 prefixes `b85aaef5a6f6a879`, `09f530345fd3fde3`, `8633e3ea7382f2cb`, `7adcd1dd0c814d64`, `fc30f9f33701ff8f`, `af097f8dd7f4f070`; every detached signature verifies Good against the VeraCrypt Team key `5069A233D55A0EEB174A5FC3821ACD02680D16DE`), each on a fresh copy of the Server 2019 lab of `MEM-VC-11` with the seven volumes of `MEM-VC-8` mounted (passwords `SeanceVC-W19-<tag>-A` to `-G`). These installers are GUI-only: `/silent` still shows the language dialog, so the wizard was driven by keyboard through the QEMU monitor (Return, Alt+A to accept, Alt+N twice, Return to install, Return on the success box and on Finish, N to decline the tutorial; `forensic_corpora/lab_w19_vc/cycle_exe.sh`). **Ground truth:** each header decrypted on the host by `scripts/oracle/vc_header_keys_all.py`. **Result:** on all six, every key of every volume is found and all seven containers are decoded under the 1.19 to 1.26.24 geometry with the 1.25.9 ids (2, 3, 4, 6, 7, 9, 13); the layout label names them (46 product builds). **The driver is `veracrypt.sys` on all six**, where the Windows 11 captures of 1.22, 1.23 and 1.24-Update7 loaded `truecrypt.sys`; the fresh MSI installs of 1.26.14, 1.26.18 and 1.26.28 Beta4 on Server 2019 and 2022 also load `veracrypt.sys`. The difference is in the machine (Windows 11 lab VM against fresh Server installs), not in the installer kind, since both used the wizard; why is not established, and the documents now say which captures show which name. **Not established:** 1.24-Update3 (its SourceForge folder holds no Windows installer), 1.23-Hotfix-2, 1.24-Update8 (macOS only), 1.15, 1.20 and 1.0a to 1.0d (unobtainable). **Re-run:** `SEANCE_W19_VC{124,124h1,124u2,124u4,124u5,124u6}_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win2019_veracrypt_{124,124h1,124u2,124u4,124u5,124u6}`.

### CAMERA-FAT-1 — a Canon PowerShot SD800IS card at six points of its life: camera-written FAT12 and erased photos, 2026-10-25

**Evidence:** the Digital Corpora `nps-2009-canon2` set (`https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-canon2/`; six E01 images of a 31 MB SD card, `forensic_corpora/lab_camera_canon2/`): a card shot in a Canon PowerShot SD800IS, taken out, photos erased in the camera, imaged, and the cycle repeated (`narrative.txt`). The raw SHA-1 of each generation equals the one the narrative publishes (for example `4742c325f10583dab1eb4c55d0d45ab3beb99eb3` for generation 6). The partition (type `0x04`, from sector 51) holds a **FAT12** volume labelled `CANON_DC`, OEM name `PwrShot`, not FAT32 as the narrative says; the camera is the only writer. The answer key is The Sleuth Kit's (`fls -r` of each generation and the size and SHA-256 of each file by `icat`: 221 entries, 26 of them erased by the camera as `_MG_00NN.JPG`), independent of this crate; the photos are `IMG_00NN.JPG` and a photo's true bytes are its copy in a generation that still held it live. **What the camera leaves:** an erased photo's directory entry is marked `0xE5` with its first character lost, its chain is freed, and later photos reuse its clusters. **Result:** the files of every generation are listed exactly as The Sleuth Kit lists them (live and erased); every live file reads back byte for byte as `icat` reads it. **Reconstruction.** A strictly contiguous read of an erased photo recovers 4 of the 26 exactly where The Sleuth Kit, which steps over clusters the FAT now calls allocated, recovers 7; three photos had later photos written into the middle of their old run. The reconstruction steps over allocated clusters (`deleted_recovery_method: unallocated_clusters_in_order`, `deleted_clusters_skipped`, reason `deleted_clusters_assumed_in_order`), with no change where nothing lies in the way, and recovers the same 7; none of the 26 is presented as whole (every one carries `content_incomplete`), and the other 19 are not recoverable from a freed chain by either tool (overwritten or fragmented). **Not established:** other cameras and firmware, FAT32 and exFAT cards, a card the camera formatted in place; that a stepped-over reading is right where it matches here (it is a guess, and says so). **Re-run:** `SEANCE_CANON2_DIR=~/forensic_corpora/lab_camera_canon2 cargo test --release -p seance_plugin_fat --test real_canon_camera_test`; `cargo test -p seance_plugin_fat --lib a_deleted_files_clusters`.

### BSD-FAT-5 — Android-x86 9.0-r2's FAT stack: the kernel's `vfat` under Android's formatter and mount options, 2026-10-25

**Evidence:** four images (two volumes, each before and after a 40-file `Keep`) written inside Android-x86 9.0-r2 (`android-x86_64-9.0-r2.iso`, SHA-1 `1cc85b5ed7c830ff71aecf8405c7281a9c995aa0` and MD5 `e9ba997cede7bf3514d2ba3e624ff767`, equal to the values SourceForge lists; kernel 4.19.110-android-x86_64) under QEMU/KVM in the Debug-mode initramfs shell, formatted by the system's own `/system/bin/newfs_msdos` (the formatter Android's volume daemon uses) and mounted by the kernel's `vfat` with the options `vold` passes (`nodev,nosuid,dirsync,uid=1023,gid=1023,fmask=0007,dmask=0007,shortname=mixed,utf8,errors=remount-ro`): `afat16c8` (FAT16, 4 KiB clusters, 64 MiB) and `afat32c8` (FAT32, 4 KiB, 260 MiB). The script (`forensic_corpora/lab_bsd_fat/make-fat-android.sh`) was typed into the shell through the QEMU monitor; the shape and answer keys are `BSD-FAT-1`'s (busybox `sha256sum`). **What the stack leaves:** every slot of a deleted file or directory is marked `0xE5` (820 name slots on each volume; the 40 surviving `DirB` files keep their ordinals), the FAT chain is freed and a directory's size field stays zero, as Linux's `vfat` does (`LINUX-FAT-1`); `dirsync` means no directory was lost to a cache. **Result:** every name of the three deleted directories comes back whole on both volumes, none is shown cut, every deleted file hashes to the guest's answer, and after `Keep` nothing is invented or published twice. **Not established:** a real Android device or a vendor kernel (Samsung's `sdfat`, exFAT variants), the FUSE sdcard layer over internal storage (not FAT), the Android build's exFAT. **Re-run:** `SEANCE_BSD_FAT_DIR=~/forensic_corpora/lab_bsd_fat cargo test --release -p seance_plugin_fat --test real_android_fat_test`.

### BSD-FAT-4 — ReactOS 0.4.16's FAT driver: the same unmarked slots, a second driver, 2026-10-25

**Evidence:** four images (two volumes, each before and after a 40-file `Keep`) written inside the official ReactOS 0.4.16 LiveCD (`ReactOS-0.4.16-i386.zip`, SHA-256 `e5851510cf5b79ef51a76b8155dd5ef7faca1155f44d0a1d41c35b77ece4ce2a`, whose SHA-1 and MD5 equal the ones SourceForge lists for the file) under QEMU/KVM: `hreact64` (FAT16, 2 KiB clusters, 63 MiB) and `hreact300` (FAT32, 4 KiB). The guest has no serial shell and a Colemak keyboard under a US label, so `guest_reactos/boot.sh` boots the CD, passes the language page and the Live CD choice by keyboard, opens `cmd.exe` from Run, and `typr.py` types through the QEMU monitor with each letter sent as the key that produces it; batch files on a FAT script disk (`gen_scripts.py` writes them) do the work, and the host times the steps from the serial log. The partitions were made on the host (`sfdisk`, MBR) and formatted by ReactOS's own `format`. ReactOS has no hashing tool: the answer keys are made on the host from the known content, and 40 of 40 surviving `DirB` files on each volume hash to them. The shape is `BSD-FAT-1`'s with a 3 MB file (`kernel32.dll` from the CD) between the two bursts of `DirD`. **A lab artifact, not a finding:** a first run deleted `DirD` straight after creating it, and 112 of its names (FAT16) and 200 (FAT32) were not on the disk, because the guest's cache dropped the directory's dirty clusters when the directory went; the run was repeated with 90 s before the deletions and 90 s before the copy. **What the driver leaves:** a deleted directory's name slots are not marked `0xE5` (ordinals and short names stay, as Haiku's), its FAT chain is freed, its clusters are interleaved with the data of its own files, and its own directory entry carries a non-zero length (59,392 bytes for `DirA`). **Result:** every name of `DirA`, `DirC` and `DirD` comes back whole on both volumes, none is shown cut, every deleted file hashes to the answer key, and after `Keep` nothing is invented or published twice. **Not established:** macOS itself, Android and camera firmware; one release of the driver; FAT12; what the cache would have kept on a real disk. **Re-run:** `SEANCE_BSD_FAT_DIR=~/forensic_corpora/lab_bsd_fat cargo test --release -p seance_plugin_fat --test real_reactos_fat_test`.

### MEM-VC-6 - VeraCrypt 1.22, 1.23, 1.24-Update7, 1.26.7, 1.26.15, 1.26.20 and 1.26.24: seven volumes each, a driver still named truecrypt.sys, and a hybrid, 2026-10-22

**Evidence:** six captures on the Windows 11 lab VM, one per version, each installed through its own wizard from the public installer whose SHA-256 equals the release's list (`forensic_corpora/veracrypt_installer/v122`, `v123`, `v1247`, `v1267`, `v12615`, `v12620`, `v12624`) and each with seven 20 MiB SHA-512 / NTFS volumes mounted together (`a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc` Kuznyechik(Twofish)), the memory dumped through QMP (`forensic_corpora/lab_win11_veracrypt_{122,123,1247,1267,12615,12620,12624}/`). The wizards were driven through a pointing device added to the VM (a `usb-tablet`); versions before 1.26 have no `/quick` in Format. Between the 1.24 and the later captures Windows Update moved the guest to a new kernel, whose ISF was made from Microsoft's PDB (`ntkrnlmp.pdb` GUID `B661C6FE72991D160FE37C48B8BC5470`, age 1, with Volatility's `pdbconv`, kept in the gitignored `reference/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/`).
**Ground truth:** each header decrypted on the host by `scripts/oracle/vc_header_keys_all.py`.
**Result:** on **1.22, 1.23 and 1.24-Update7** every master key of all seven volumes is found and all seven containers are read under the 1.25.9 geometry and ids (2, 3, 4, 6, 7, 9, 13); the driver is `truecrypt.sys` on all three. **1.26.7 is a hybrid** (also `truecrypt.sys`): its container has the 1.25.9 geometry (a header of three dwords, buffer at `+0x0c`, tweak keys 5,304 bytes on) but numbers the ciphers as 1.26.29 does: Serpent 2, Twofish 3, Camellia 4, Kuznyechik 5, AES-Twofish 6, Serpent-AES 8, Kuznyechik-Twofish 12. A table for that pairing (`OBSERVED_CONTAINERS_1267`, the seven ids mounted) reads all seven (without it the sweep decodes 4 of the 7: the cascades and Kuznyechik are absent, and one volume is published with the id 8 it cannot name), and the layout is labelled with every version it was seen on. **1.26.15, 1.26.20 and 1.26.24 read in full** (the geometry flips to 1.26.29's somewhere between 1.26.24 and 1.26.29; 1.26.20 also holds ten more AES schedules than the others, which the sweep reports and no container claims). Every earlier capture passes. Tests: `win11_veracrypt_{122,123,1247,1267,12615,12620,12624}.rs` (about 6 s each in release).
**Not established:** other builds (1.25.x others, 1.26.x others, 1.21 and earlier, the hardware-accelerated ones), the cascades not mounted on 1.26.7 to 1.26.24, other TrueCrypt versions, one OS build. **Re-run:** `SEANCE_WIN11_VC{122,123,1247,1267,12615,12620,12624}_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test win11_veracrypt_{122,123,1247,1267,12615,12620,12624}`.

### MEM-VC-7 — 37 TrueCrypt and VeraCrypt builds, 27 of them new: TrueCrypt 6.0 to 7.2 and VeraCrypt 1.0e to 1.25.7, 2026-10-23

**Evidence:** the Windows 11 lab VM (build 26200, 8 GiB) with one version installed at a time from the public installer whose SHA-256 equals the release's list and whose detached signature verifies (`forensic_corpora/truecrypt_installer`, `veracrypt_installer`): TrueCrypt 6.0, 6.0a, 6.1, 6.1a, 6.2, 6.2a, 6.3, 6.3a, 7.0, 7.0a, 7.1 and 7.2 (7.1a is `MEM-VC-5`), VeraCrypt 1.0e, 1.0f, 1.0f-1, 1.0f-2, 1.12, 1.13, 1.14, 1.16, 1.17, 1.18, 1.19, 1.21 (wizard), 1.25, 1.25.4 and 1.25.7 (msi, `msiexec /qn`). The silent switches of the wizards do not work (a modal dialog in a non-interactive session), so the `.exe` installers were driven on the desktop through the `usb-tablet`. Before each install the guest was cleaned of every TrueCrypt and VeraCrypt install and restarted, so each capture holds that version's driver alone (`truecrypt.sys` on TrueCrypt, `veracrypt.sys` on every VeraCrypt here). **Volumes:** TrueCrypt, eight 20 MiB volumes (AES, Serpent, Twofish, AES-Twofish, AES-Twofish-Serpent, Serpent-AES, Serpent-Twofish-AES, Twofish-Serpent), written by `scripts/oracle/tc7_make_volume.py` (header version 4 for 6.x, 5 for 7.x; 7.2 cannot create volumes and mounted them), mounted by the real driver; VeraCrypt 1.19 to 1.25.7, seven volumes created by `VeraCrypt Format.exe /create` (SHA-512, NTFS; `1.19` and `1.21` use `AES(Twofish(Serpent))` for the seventh because `Kuznyechik(Twofish)` hangs the silent format); VeraCrypt 1.0e to 1.18, eight volumes (1.18: ten, with Camellia and Kuznyechik) written on the host by `tc7_make_volume.py ... vera` because `VeraCrypt Format.exe /create` hangs on 1.12 (the drivers of 1.0e and 1.13 to 1.17 refuse Camellia and Kuznyechik, 1.18 mounts them), and mounted by the real drivers, which accepted every one. **Ground truth:** each header decrypted on the host by `scripts/oracle/vc_header_keys_all.py`, independent of the crate. **Result:** every master key of every mounted volume is found by hash and every container decoded with its layers in buffer order. **TrueCrypt 6.0 to 7.2 and VeraCrypt 1.21, 1.25, 1.25.4, 1.25.7 and 1.0e read by the same sweep** (1.0e has TrueCrypt's container layout). The layouts it needs: **1.19** keeps Twofish as 40 subkeys then four tables (4,256 bytes) and Camellia as 64-bit little-endian words, neither of which was recognised (`seance_bulk::twofish::verify_subkeys_first_schedule_at`, `camellia::verify_table_le64_at`; a real 1.19 table is a fixture); **1.0f to 1.18** put the schedule buffer at `+0x0c` with the tweak keys 5,324 bytes on (TrueCrypt's Twofish size; 1.19 and later are 5,304), a fourth `ContainerLayout`, with TrueCrypt's ids to 1.17 and 1.25.9's ids from 1.18 (`OBSERVED_CONTAINERS_118`, tried first because id 8 is a three-layer cascade there and a two-layer one in 1.12). A schedule a decoded container already owns is skipped, so a cascade's AES layer is not published again as a plain AES volume under the TrueCrypt layout. All 42 real-capture tests of the family pass (`win11_truecrypt{60,60a,61,61a,62,62a,63,63a,70,70a,71,71a,72}`, `win11_veracrypt_{10e,10f,10f1,10f2,112,113,114,116,117,118,119,121,125,1254,1257}` and the earlier ones); the unit tests in `truecrypt_tests` (27) pin the layouts and ids.
**Not established:** VeraCrypt 1.15, 1.20, 1.0a to 1.0d and the other 1.22 to 1.24 and 1.26 updates; Camellia and Kuznyechik cascades on any build before 1.22 (not offered by the drivers or the silent format); volumes with a file system on 1.0e to 1.18 (the data areas are random, so the memory evidence is the key material); other hashes, PIM, keyfiles, hidden volumes, system encryption; one OS build. **Re-run:** `SEANCE_WIN11_<TAG>_MEMORY=<mem.raw> cargo test --release -p seance_plugin_memory_windows --test <name>` (`zstd -d --sparse mem.raw.zst -o mem.raw` first where the capture is compressed); `cargo test -p seance_bulk --lib twofish camellia`; `cargo test -p seance_plugin_memory_windows --lib truecrypt`.

### INGEST-MEM-1 — the 33 GB LoneWolf disk ingests on a 30 GB host, 2026-10-22

**Question:** whether `LoneWolf.E01`-`.E21` (Windows 10, 33 GB of segments, 120,034,123,776 bytes
logical) ingests on a 30 GB host. The memory governor (`seance_core::memory_guard`), allocation tracing, streaming
sinks and spilled compressed NTFS content bound its memory.

**Method.** `scripts/findings-sweep.sh --image LoneWolf.E01 --label lonewolf-h125 --scratch <real disk> --keep` (profile
`deep`, **default concurrency: 16 workers, one per core**, a 30 GB host with 28-30 GB available at the start), the server
run inside a systemd scope capped at `MemoryMax=24G`, `MemorySwapMax=0` so a runaway could not take the host with it. The
server's resident set (`ps -o rss`) and the host's `MemAvailable` were sampled every 15 s for the whole run. The release
build of this tree (`target/release/seance`).

**Result.** The ingest **completed**: 2,625 s, 169,761 file entries, **3,594,811 artifacts**, 1,462 findings. Resident memory
of the server:

| Time | Server RSS | Host `MemAvailable` |
|---:|---:|---:|
| 314 s | 2.3 GB | 13.6 GB |
| 608 s | 2.4 GB | 27.1 GB |
| **818 s (peak)** | **10.1 GB** | 21 GB |
| 909 s | 5.9 GB | 21.6 GB |
| 1,209 s | 3.3 GB | 26.0 GB |
| 1,802 s | 2.4 GB | 23.9 GB |
| 2,411 s | 1.9 GB | 27.5 GB |

The lowest `MemAvailable` the host saw was 7.6 GB (page cache and the image reads; it is not the server's resident set).
The task queue holds its 10,000-task window and spills the rest, and nothing else grows
with the image: resident memory rose to a peak of 10.1 GB, about **0.3 times the 33 GB image and 0.08 times its logical size**,
and fell again to under 2 GB while ingest continued.

**Not established.** One image, one run: a 500 GB disk was not run, so the curve is not extrapolated; the peak at 818 s
is a phase of the ingest not attributed to an allocator here (the allocation trace was not enabled), and 10 GB is a
measured ceiling for this image, not a bound. The findings layer's output on this machine (`SWEEP-1`'s Windows 10 workstation case) is recorded in the same run: 1,462 leads over 169,761 file entries;
`service_binary_unrecognised_in_system_directory` raised 0.

### HFS-SLACK-1 — HFS+ file slack against The Sleuth Kit, 2026-10-22

**Evidence:** the HFS+ partition of the NIST CFTT string-search unix image (`ss-unix-07-25-18.dd`, partition
0 at sector 2048, 4,096-byte allocation blocks, 219 files with a tail and 29 whose size is a whole number of blocks),
written by a macOS. **Oracle:** The Sleuth Kit 4.x (`fls`, `istat`, `icat -s`), through
`scripts/cftt/hfs_slack_key.py`, whose output is `seance_plugin_hfsplus/tests/data/cftt_unix_hfsplus_slack_key.json`:
for each file the tail's offset in the partition and its length, and a SHA-256 for any tail that is not zero.

**Real result: every one of the 219 real tails is all zero**, so a correct reader publishes no region and counts 219
zero tails. Séance does exactly that (`files_offered` 219, `zero_tails` 219, `files_not_located` 0, no `SlackSpace`).
The same holds for the HFSX partition at sector 1955840 (219 and 29 by the key script; not run through Séance).

**Planted result (synthetic).** With nothing real to find, the test overlays a deterministic non-zero pattern on 44 of the
tails in memory, at the offsets the key gives; `scripts/synth/plant_hfs_slack.py` plants the same bytes in a copy and
checks that `icat -s` prints exactly them (44 of 44). Séance publishes 44 regions, each at TSK's offset and length with
exactly the planted bytes, and counts the other 175 tails as zero. What a real macOS leaves in a tail is not shown by
this: the tails here were zero.

**Whole-block runs.** The `data_runs` an HFS+ entry publishes are trimmed to the file's logical size, but
the slack locator wants whole-block runs, and trimmed runs would count every file as "not located". The producer builds the
runs from the fork's extents. Pinned by `a_live_files_planted_tail_is_published_as_a_slack_region` (synthetic volume) and
`seance_plugin_hfsplus/tests/real_slack_test.rs`. **Re-run:** `SEANCE_CFTT_UNIX_DD=<the .dd> cargo test -p
seance_plugin_hfsplus --test real_slack_test`; unset, the tests skip and say so. **Not graded:** APFS (graded in `APFS-SLACK-1`), a file whose extents continue in the overflow tree, and a compressed file.

### APFS-SLACK-1 — APFS file slack against libfsapfs, 2026-10-22

**Evidence:** the APFS partition of the NIST CFTT string-search unix image (`ss-unix-07-25-18.dd`, partition 3 at
sector 2,932,736, 1,164,936 sectors, 4,096-byte blocks; one unencrypted volume), which neither The Sleuth Kit nor `fsstat`
recognises. **Oracle:** libfsapfs 20260921 (libyal's `pyfsapfs`, from PyPI), through `scripts/cftt/apfs_slack_key.py`: each regular file's
size and extents `(physical offset, length, flags)` in file order, from which the tail's offset in the partition is computed and the tail's
bytes are read straight from the partition. Key: `seance_plugin_apfs/tests/data/cftt_unix_apfs_slack_key.json`.

**Real result: all 218 real tails are zero** (28 more files have no tail), so a correct reader publishes no region and counts 218 zero
tails; Séance does exactly that. **Planted result (synthetic):** 44 of the tails are overlaid in memory with a deterministic non-zero
pattern at libfsapfs's offsets and Séance publishes 44 regions at those offsets and lengths with exactly the planted bytes, counting the
other 174 as zero. **The check is weaker than HFS+'s:** no second tool prints an APFS file's slack, so the planted offsets are checked against
the extents of an independent reader, not against its output. A synthetic unit test (`a_live_files_planted_tail_is_published_as_a_slack_region`)
pins the rest: one inode under two names is offered once, an incomplete run list is counted as not located, an all-zero tail raises nothing.
**Not graded:** a real macOS volume holding a non-zero tail, compressed and encrypted files (counted as not located), snapshots. **Re-run:**
`SEANCE_CFTT_UNIX_DD=<the .dd> cargo test -p seance_plugin_apfs --test real_slack_test` (`pip install --target <dir> libfsapfs-python` and
`PYTHONPATH=<dir>` to regenerate the key); unset, the tests skip and say so.

### CFTT-SS-3 — the string-search run over the unix image, 2026-10-22

**How:** `scripts/cftt/run-string-search.sh --image unix` on this tree (release build), the same method, key
verification and fallbacks as `CFTT-SS-1`/`-2` on the Windows image; `ss-unix-07-25-18.dd` (SHA-256 `42bc298d...58a320ee`)
holds an HFS+ partition, an ext4 partition, an HFSX partition and an APFS partition. **Result:** 1,051 key rows, **429 of 928
assessed rows found, 499 not found, 123 not assessed** (the key states a byte offset and names no file, and this tool reports
artifacts rather than offsets); 6 of the passes were graded against the file The Sleuth Kit places at the key's offset
because the key's name is not on the image there (the key-file rule above). Not third-party validation: NIST has not tested this tool.

**What the 499 are.** The rows split by the file name the key gives. Every one of the **492 `DELETED-*` rows fails, on all four
file systems (123 on each)**: the data set deleted those files, and none of them is recoverable *by name* from this image by
any structural reader. On ext4 the kernel cleared the inode's size and extents (`istat` shows `size: 0`, no blocks, and `icat`
prints 0 bytes), so The Sleuth Kit cannot read them either; on HFS+ and APFS the catalogue records are gone. The text is still in the
unallocated blocks; finding it there is the byte sweep's job, which is run over this image in (`CFTT-SWEEP-2`): 452 of the 456
`DELETED-*` rows with an offset are found at it. The remaining failures among `LIVE-*` rows are the known
UTF-16 limits (CJK ideographs, Hangul and U+FB01 stored as UTF-16, which the index tokenises word by word) and two APFS
rows (`LIVE-LOUDBIRD-apfs-ascii.txt`, `LIVE-WADI-apfs-utf-8.txt`) whose key names are the publisher's labels and which no
reference tool resolves to a file. **The APFS partition is read:** 111 of 123 `LIVE-*-apfs-*` rows pass, the
others being those two and the UTF-16 kinds.

**Not established.** Deleted-file rows were not graded any other way, the 123 offset-only rows are not graded, and the
unix numbers say nothing about a real macOS or Linux machine. **Re-run:** the command above with `--corpus` and `--out`.

### CFTT-SS-2 — the string-search run on the Windows image with UTF-16 indexing, 2026-09-30

`CFTT-SS-1` predates the UTF-16 widening. This is the run on the widened indexer.

**Procedure.** `scripts/cftt/run-string-search.sh --corpus ~/forensic_corpora/cftt_string_search --out OUT
--workers 4` on the Windows image `ss-win-07-25-18.dd` (2,098,028,544 bytes; sha256 `1574185b…6eb9`,
checked against `our-sha256.txt`, this project's list: the data set's own published hashes fail, as the
methodology section records). The release binary of 2026-09-30, the key checked against the image with The
Sleuth Kit as before (707 of 708 named rows resolve to a file on the image; 14 name a different file than
the key; 0 could not be looked at).

**Result: 648 of 709 assessed expectations found (61 not found)**; 134 not applicable, 78 not assessed, 14
graded against the file at the key's offset. The ceiling was recorded **before** the run as at most 648
(the widening predicts 650 of 710 on the key, 649 of 709 with row 7010 out, and `crossbow` fails for
another reason): the result equals it exactly. The 61 failures are 60 rows because
UTF-16 CJK ideographs and Hangul are not indexed (`中國`, `中国`, `서울`, `東京`, each 12 rows,
and `inﬁnity`, the `ﬁ` ligature, 12 rows, all UTF-16 LE/BE) — each recorded a failure, not
excused — and `crossbow` in `FMT-bolt-htmlfmt-win.html` (9007), a search failure inside a file the tool
read (the search returned 1 artifact, not that file). By case, 20 of the 26 case groups have no failure; the
six with one are `FT-SS-07-CJK-char`, `-CJK-hangul`, `-NoBOM`, `-Norm` and `FT-SS-09-Doc`.

**What this does not show.** The same as `CFTT-SS-1`: the expectations are verified against the publisher
only in the answer key, and the questions are from a test-cases page that fails all three publisher
hashes. 134 key rows in unallocated space are outside what a search over parsed records can answer. The
unix image was not re-run. Not third-party validation.

### C001-FIND-1 — the findings layer on DFIR Madness Case 001's two disks, 2026-09-30

**The criterion.** On Case 001 "the persistence and absent-binary leads should rank in the top five".

**Images.** `E01-DC01/20200918_0347_CDrive.E01` (Server 2012 R2, 93,133 file entries) and
`E01-DESKTOP/20200918_0417_DESKTOP-SDN1RPT.E01` (107,183), from the archives whose publisher MD5s
`VERIFICATION.txt` records as OK. **Procedure:** `scripts/findings-sweep.sh --image <E01> --label <name>
--workers 4 --keep` (the script of `SWEEP-1`), scratch on a real disk; DC01 1,714,917 artifacts in 900 s,
the desktop 1,866,023 in 2,268 s. The leads are read in the order the findings API returns them
(`findings.json`: confidence, then the order the detections ran), so "rank" below is that list position.

**Ground truth, none of it from Séance.** The publisher's `autorunsc` output (`DC01-autorunsc.zip`,
`DESKTOP-SDN1RPT-autorunsc.zip`): the implant is the service `coreupdater`,
`C:\Windows\System32\coreupdater.exe`, on both machines (the pcap run `NET-4` has its hashes). Sleuth Kit
`fls` finds `coreupdater.exe` on DC01 (MFT 87137, 7,168 bytes), and the desktop workspace has
`/Windows/System32/coreupdater.exe` (7,168 bytes) and its `COREUPDATER.EXE-157C54BB.pf`. The second known
answer is bonus question 8, `Beth_Secret.txt` timestomped (`C001-1`).

**What was measured.**

| | DC01 | Desktop |
|---|---:|---:|
| leads | 643 (4 notable, 639 weak) | 756 (13 notable, 743 weak) |
| `persistence_target_not_recovered` | 448 weak | 367 weak |
| `high_entropy_executable` | 191 weak | 245 weak |
| `persistence_in_unexpected_location` | 1 notable | 1 notable, 131 weak |
| `execution_of_absent_binary` (cross-view) | 0 | 7 notable |
| `inventoried_binary_absent_from_filesystem` (cross-view) | 0 | 5 notable |
| `timestomp` | 1 notable (`Beth_Secret.txt`) | 0 |
| other notable | `hive_subkey_count_discrepancy` (NTUSER.DAT), `usn_delete_contradicts_mft` (`WinPEpge.sys`) | |

The top four on DC01 are the NTUSER subkey-count discrepancy, the Active Setup `/UserInstall` lead, the
`Beth_Secret.txt` timestomp, and the `WinPEpge.sys` journal/MFT contradiction. On the desktop rows 1–7 are
"ran, and no file entry for it was recovered" (AM_DELTA.EXE, FTK IMAGER.EXE, Op-SEARCHAPP.EXE,
SETUP64.EXE, UPDATEPLATFORM.EXE, VCREDIST_X64.EXE, VCREDIST_X86.EXE), rows 8–12 are Amcache-catalogued
binaries with no file entry (fmui, hxcalendarappimm, skypeapp, skypebackgroundhost, skypebridge), and row
13 is the Active Setup lead again.

**Result: the criterion is NOT met, and is not measurable as written.**

* **The implant's persistence is not a lead on either machine.** Both hold the service registered in the
  SYSTEM hive (an `AsepEntry` of category `service`, image `C:\Windows\System32\coreupdater.exe`), the
  binary present in `System32`, and on the desktop its prefetch; neither of the two persistence detections
  fires, because one asks whether a target is missing and the other whether it sits outside a system
  directory, and this one is neither. A service whose binary was created at 03:24:12 Z and installed by a `7045` event at 03:27:49 Z (DC01's `$FN` and System log) raises nothing. This is a missing
  detection, not a mis-ranked one.
* **Absent-binary leads exist and rank first, but are about other things.** On the desktop seven of the top
  seven are real (the files are not on the disk), and none is the implant, which is present. FTK Imager is
  presumably the acquisition tool (not verified). On DC01 the detection is silent.
* **The one persistence lead that ranks high is a false one, on both images:** Active Setup's
  `/UserInstall` component is Windows' own, and it outranks everything but the absent binaries. The
  desktop's other 131 weak `persistence_in_unexpected_location` leads are per-user OneDrive COM servers and
  shell extensions (25 per user for four users).
* **What worked:** the `Beth_Secret.txt` timestomp is a notable lead on DC01 (bonus question 8), and the
  desktop's absent-binary leads are each true statements about its disk.

**What this does not show.** Only two images of one case; "rank" is list order, not a score; the
hive-discrepancy and `WinPEpge.sys` leads were not judged here. The cross-view detections cap comparison
at 8 file entries per deleted name (5 names on DC01, 83 on the desktop hit the cap), so their result is a
floor.

**Re-run.** The script and images above; about 15 and 38 minutes.

A detection for the implant's persistence is graded in "C001-FIND-1 re-measure" below. The measurement above is unchanged.

### C001-FIND-1 re-measure, 2026-10-20

**Rule (R1).** `service_binary_unrecognised_in_system_directory`: `AsepEntry` category `service`,
`service_start_type` 2, `service_type & 0x10` (own-process, no driver bits), `target_exists` =
`observed_at_path`, raw `image_path` a literal drive-letter path `X:\Windows\System32\*.exe` or
`X:\Windows\SysWOW64\*.exe`, not `svchost.exe`. Raised `Weak`.

**Procedure.** Read-only queries of the `AsepEntry` rows already ingested in each workspace
(`sqlite3 -readonly`, `json_extract` on `metadata_json`), evaluated by a script that mirrors the Rust rule
(scratch `measure.py`, not committed). No new ingest was run.

| Workspace | Machine | Service rows | R1 hits |
|---|---|---:|---|
| `s6work/findings-sweep-c001-dc01` | Case 001 DC01, Server 2012 R2 (compromised) | 915 | 1: `coreupdater` (the implant) |
| `s6work/findings-sweep-c001-desktop` | Case 001 DESKTOP (compromised) | 816 | 1: `coreupdater` (the implant) |
| `hunt125/findings-sweep-lw-fix3` | LoneWolf Windows 10 workstation | 776 | 0 |
| `leak-workspace` | Data Leakage case image | 1,606 | 0 |

Ground truth for the implant is the publisher's `autorunsc` output (`C001-FIND-1`). The two Case 001 rows
are true positives; the LoneWolf row is a clean-machine row with zero false positives. Whether the
`leak-workspace` machine is clean is not established here, so it is counted as a zero-hit workspace, not as
a verified clean machine. The rule for Notable (zero false positives over at least three
clean machines) is therefore not met and the lead ships Weak.

**What this does not show.** A spelling heuristic. The stock-service population is spelled
`%SystemRoot%\system32\...`, and the rule exists only because the implant was written as a literal path;
an implant written with `%SystemRoot%` is not seen. Vendor services in System32 (`igfxcuiservice`,
`dbxsvc`, `btwrsupportservice`, `wlms`) use the `%SystemRoot%` spelling and so do not hit, but a vendor
installer that writes a literal path would. The Windows 11 BitLocker capture was not unlocked for this
measurement. The findings sweep was not re-run on the E01s with the new binary. Install time and file
creation time are not on the record and are not used.

**Re-run.** Script above over the listed workspaces; unit tests
`cargo test -p seance_plugin_findings asep_tests`.

**Re-measured through the findings sweep, 2026-10-22.** `scripts/findings-sweep.sh` (deep profile, current release binary) on whole images, no script mirroring the rule:

| Image | Machine | Artifacts | `service_binary_unrecognised_in_system_directory` |
|---|---|---:|---:|
| `lab_win11_clean/` (the corpus VM, Windows 11 25H2, fresh install plus sshd and VeraCrypt) | clean | 5,594,932 | **0** |
| Case 001 DESKTOP E01 | compromised | 1,866,024 | **1** |
| Case 001 DC01 E01 | compromised | 1,714,918 | **1** |

The Case 001 counts equal the earlier script's (one hit each, the `coreupdater` implant by that measurement); the sweep summary carries counts, not the lead's subject, so the name is not re-confirmed here.
The clean row is a fresh Windows 11 install with `sshd` installed, and the rule did not fire on it. Clean machines at zero are now three: LoneWolf Windows 10, this one, and the 1,606-service Data Leakage workspace
(which is not verified clean). The Notable threshold of three verified-clean machines is still not met, so the lead stays Weak. The sweep summaries are kept in `forensic_corpora/lab_win11_clean/findings-sweep.json`.

**Two more clean installs, measured through the same sweep, 2026-10-22.** Both are fresh installs of Microsoft's own evaluation media made under KVM (no key, no software added), whole-image, deep profile:

| Image | Machine | Artifacts | `service_binary_unrecognised_in_system_directory` |
|---|---|---:|---:|
| `lab_s2022_eval/` (Windows Server 2022 Standard Evaluation, desktop experience, unattended install, `autounattend.xml` in `~/legacy-lab/ans2022`) | clean | 1,674,109 | **0** |
| `lab_w2k3_r2_sp2_x64/` (Windows Server 2003 R2 Datacenter x64 SP2 evaluation, `MEM-XP-6`) | clean | 465,748 | **3** |

**The Server 2003 hits are one stock service.** `MSDTC`, Microsoft's Distributed Transaction Coordinator, is written `C:\WINDOWS\system32\msdtc.exe` (a literal path) by Windows setup itself: read from the SYSTEM hive of the image (`ControlSet001` and `ControlSet002` hold the same value; the three rows are those two and the entry's own
record), start type 2, own-process. So **the rule has a false positive on a clean machine**, which the claim "the stock ones are written with %SystemRoot%" had denied. With the earlier measurements the clean population is now: Windows 10 and Windows 11 and Server 2022 at 0, Server 2003 at 1 service. The lead stays **Weak and the Notable threshold
cannot be met**: it fired on one of four clean machines (the others having no literal stock path). The qualification text on the lead says so. The sweep summaries are `findings-sweep.json` in each corpus directory (the images are kept compressed with `zstd`, `disk.raw.zst`).

**Install-time comparison, 2026-10-22.** The record carries `target_created` (the creation time the file system recorded for an executable in a Windows system directory) and `os_install_time` (the live SOFTWARE hive's `InstallDate`, `os_install_time_basis` naming where it came from or that none had been read), and the lead is not raised for a file created at or before the install time. Read off the Server 2003 image with TSK: `msdtc.exe` created 16:20:16Z, `InstallDate` 1792686465 = 16:27:45Z (setup's own files can carry either the install time, as `msdtc.exe` does, or the media's 2007-11-15, as `ntdll.dll` and `W32Time`'s image do; both are at or before the install). Two facts from real data: `SOFTWARE.SAV`, the setup-time backup, is the same hive kind to the enumerator and records `InstallDate` 0, which reads as 1970; and the evidence order matters, as the repair copy of the SYSTEM hive is read before the SOFTWARE hive. ASEP records carry `hive_path`, and a service read from a hive under `\Windows\repair` (the setup-time copy of SYSTEM) is not raised: it was registered during setup, and the live hive is judged on its own. Re-sweep with `scripts/findings-sweep.sh` (2026-10-23): **Server 2003 clean: 0 leads** (the three `MSDTC` rows are the repair copy, which says no install time was read, and two live-hive rows, which carry the install time and a file created before it); Case 001 DC01 and DESKTOP: 1 each, the `coreupdater` implant (created 2020-09-19T03:24:12Z and 03:40:00Z, after the install), the desktop's from `/Windows/System32/config/SYSTEM`. Pinned by `a_service_in_the_setup_time_repair_copy_of_the_system_hive_raises_no_lead` and `an_entry_carries_the_path_of_the_hive_it_was_read_from`. Not changed: the rule is still a spelling heuristic and stays Weak; a file's creation time can be set by the file's author; and the order dependence is the enumerator's, as for `target_exists`.

### NET-4 re-run — the Case 001 capture on 2026-09-30

`NET-4` was re-run. `SEANCE_CASE001_PCAP=~/forensic_corpora/dfir_madness_case001/pcap/case001.pcap cargo test --release
-p seance_plugin_pcap --test case001_capture`: **6 passed, 0 failed** (59 s including the build). The
independent count was repeated: `tcpdump -nn -r case001.pcap | wc -l` is **411,797**, `NET-4`'s figure. The
capture's MD5 is published only for the zip; `VERIFICATION.txt` records the zip as OK.

### LAUNCH-1 — the bare-name search rule of five Windows launchers, 2026-09-27

An autostart entry that names a
bare program (`evil`, not `C:\Windows\System32\evil.exe`) is searched for by a launcher, and
which extensions that launcher tries was established by **running it**, not read from
documentation: Microsoft documents only `CreateProcess` (`.exe` appended) and says a service
`ImagePath` must be fully qualified.

**Machine.** Windows 11 Enterprise evaluation 25H2, build **26200.6584**, x64 — the `win11-lab`
corpus VM booted from a copy-on-write overlay. One machine, one build; no other Windows version
was tested. `PATHEXT` was the default `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL`.

**Method and evidence.** Process-creation auditing (Security 4688) with command lines; one set of
planted files per launcher and variant in `C:\Windows\System32`; the entries set by
`phase1.ps1`–`phase3.ps1`, the later two followed by a reboot and logon. The scripts and the
event transcripts are committed under `seance_plugin_asep/tests/fixtures/launcher_rules/`
(`README.md` there is the full table). They are evidence of a live test, not unit-test fixtures:
`seance_plugin_asep/src/tests.rs` pins the rules the code applies.

| Launcher | Ran | Did not run |
|---|---|---|
| Service control manager, own-process `ImagePath` | `.exe` | `.com` `.bat` `.cmd` `.vbs` |
| IFEO `Debugger` (target started by `CreateProcess`) | `.exe` | `.com` `.bat` `.cmd` |
| Winlogon `Userinit` element | `.exe` | `.com` `.bat` `.cmd` `.vbs` `.js` `.ps1` (event 4006) |
| Explorer `Run` (HKLM; HKCU), `runonce.exe` `RunOnce` (HKLM) | `.com` `.exe` `.bat` `.cmd`, and `.pif` under HKLM `Run`; App Paths | `.vbs` `.js` `.lnk` |
| Task Scheduler `Exec` | `.com` `.exe` `.bat` `.cmd` `.vbs` `.js` | `.ps1` `.pif` `.lnk`, App Paths |

**Not tested, and so left on the default or the documented contract:** a share-process service,
boot- and system-start entries, `.pif`'s place in the Run order and `.pif` under HKCU and
RunOnce, HKCU `RunOnce`, `Wow6432Node`, `Policies\Explorer\Run`, `RunOnceEx`, `RunServices`,
Winlogon `Shell`, a debugger started through `ShellExecute`, `SilentProcessExit`'s
`MonitorProcess`, a task's `WorkingDirectory`, the machine's own `PATHEXT` (the record assumes
the default and says so), and a Startup-folder shortcut whose target is bare. Every record that
uses an observed rule carries the build and says other Windows versions were not tested.

### LEAK-2 — the Data Leakage key, all 60 questions, run through the product on 2026-09-30

`LEAK-1` is the 2026-09-11 run, left saying what was true then; this is the run through the
product on 2026-09-30. **Headline: the "55 of 60 from a screen" criterion is
not met.** Graded strictly, column by column against the key, **36 questions are answered in full, 21 in
part and 3 not at all** (table below). Every answered row was compared with the key, and where an
independent reading was cheap (The Sleuth Kit on the same E01: `ifind`/`icat`/`istat`/`fls`) it was taken.

**Evidence and run.** The 2026-09-19 re-fetch under `~/forensic_corpora/cfreds_data_leakage` (every
SHA-1 in `VERIFICATION.txt` OK): `cfreds_2015_data_leakage_pc.E01`–`E04`, `rm#1.E01`, `rm#2.E01`,
`rm#3_type3.E01`; `leakage-answers.pdf` v1.32 is the key. RM#3 type 1 and 2 (`.7z` archives of the
same disc) and the seed files were not ingested. Ingested with the `deep` profile through
`POST /cases/{id}/ingest` **with no `artifact_type`** (an `artifact_type` of `RawEvidence` is honoured over
an image's own signature): **2,261,987 artifacts in 920 s, no `EVIDENCE LOSS` line**, built `--release`.

**An earlier ingest of the same image is not graded.** It lost 610,857 artifacts, most of the Windows
volume's file entries and all of RM#2's, because a test case was deleted while its ingest was still
running: that case's rows violate the foreign key, the writer kept the failed batch whole, and when it
passed its 100,000-row cap it dropped the *oldest* rows, which were other cases' valid ones
(`EVIDENCE LOSS: artifact writer buffer exceeded cap of 100000; dropped 610857`). The writer writes the
rows the database accepts and keeps only the refused ones
(`orchestrator_writer_test` `one_unwritable_row_does_not_hold_back_the_valid_rows`).

Times: the key's are local (UTC−4 for events; the account table uses UTC−5 without the daylight hour
— `informant`'s last logon 09:45:59 is 14:45:59 UTC); the product's are UTC.

| Q | Key asks | Result | Basis |
|---|----------|--------|-------|
| 1 | Image hashes, acquisition vs verification | **Partial** | `stored_md5`/`stored_sha1` on the container record equal the key for PC, RM#2 and RM#3 type 3 (RM#1 is not in the key). No media re-hash against the stored value is run or shown; RM#3 type 1/2 not ingested |
| 2 | Partition table | Answered | 2048+204,800 (100 MB) and 206,848+41,734,144 (19.9 GB), both 0x07. The key puts the boot flag on partition 2; the MBR (`0x80` at byte 446) puts it on partition 1, as the product does |
| 3 | OS, build, owner, install date | Answered | Windows 7 Ultimate 6.1.7601, `informant`, 2015-03-22 14:34:26 UTC |
| 4 | Timezone | **Partial** | "Eastern Standard Time" on System Info; the bias (300) and daylight bias (−60) are in the registry viewer only |
| 5 | Computer name | Answered | `INFORMANT-PC` |
| 6 | Accounts | **Partial** | four accounts, RIDs, status, **login counts and last-logon times exact** (10, 2, 0, 1; informant 14:45:59 UTC) from the current SAM, the RegBack copy read as an earlier state. Not produced: account-created time (the key's 10:51:54 etc.), failed-logon time (`F+0x28`, deliberately unread), NT hashes |
| 7 | Last logon | Answered | `informant` |
| 8 | Last shutdown | Answered | 2015-03-25 15:31:05 UTC = 11:31:05 |
| 9 | DHCP interface | **Partial** | the interface record carries the address: 10.11.11.129 / 255.255.255.0 / gateway and name server 10.11.11.2 / `localdomain` / server 10.11.11.254. Not produced: the adapter's device name (`NetworkCards`) |
| 10 | Installed applications | **Partial** | all nine by name, version, publisher, path (Office 15.0.4420.1017, Chrome 41.0.2272.101, Google Update Helper, Apple Application Support, Bonjour, Apple Software Update, Google Drive, .NET 4, Eraser 6.2.2962) with the **date**; not the time of day, because the key-write scan stops at `timeline_event_cap` on a 174,112-key SOFTWARE hive and the record says so |
| 11 | Execution logs | Answered | Prefetch run counts and times exact (Chrome 71 / 17:05:38; Stikynot 2 / 14:31:55; Eraser 2 / 11:13:30; …); UserAssist counts (Excel 1 at 16:26:50, PowerPoint 2, Outlook 5, Word 4, StickyNotes 13); all 18 checked Shimcache times; MuiCache |
| 12 | On/off, logon/logoff | Answered | 35 of the 36 events present by ID and second. The 36th, "4637" at 10:45:59, is event 4634 at that second — the key's ID is wrong (no 4637 exists in the log) |
| 13 | Browsers | Answered | IE `svcVersion` 11.0.9600.17691; Chrome `BLBeacon` 41.0.2272.101 |
| 14 | Browser file paths | Answered | `WebCacheV01.dat`, `History`, cache directories as file entries |
| 15 | Websites visited | **Partial** | 72 of the key's 74 rows by time (±2 s) and URL. The two IE 8 rows (11:09:01, 11:09:47) come from `index.dat`, which is not parsed |
| 16 | Search keywords | Answered | 28 of 28 rows, keyword found in the URL at the key's time (no dedicated keyword column) |
| 17 | Explorer search box | Answered | `secret`, key written 18:40:17 UTC = 14:40:17. `WordWheelQuery` is decoded |
| 18–20 | Mail application, file, account | Answered | Outlook 2013 (`Clients\Mail`, UserAssist); `…\Outlook\iaman.informant@nist.gov.ost` from the registry and the file tree; account from the file name |
| 21 | All e-mails | **Partial** | all 12 present with subject, folder, time to the second and body, including "It's me" recovered from unallocated space (graded `partial`). The five of the informant's own messages carry the Exchange X.500 DN as sender, not the SMTP address the key shows |
| 22 | External devices | **Partial** | both serials, names and first-connected times (setupapi 14:31:10 and 09:58:32, equal to the key). Not produced: the volume names (`IAMAN $_@` is visible only inside a jump-list stream) and the "connected after reboot" times |
| 23 | Renames on the Desktop | Answered | 46 of 46 USNs present with file name, Old/New and time to the second |
| 24 | Shared drive address | Answered | `\\10.11.11.128\secured_drive` from `RunMRU` (16:23:28) and Map Network Drive MRU |
| 25 | RM#2 directories | **Partial** | all directories; the key's ShellBag times match the BagMRU key last-write for 6 of 8 rows  |
| 26 | Files opened in RM#2 | Answered | jump-list `DestList` rows at 10:01:23 and 10:01:29 exact; the shortcut for the zip |
| 27 | Network-drive directories | **Partial** | directories and all jump-list rows exact; ShellBag times 4 of 7 |
| 28 | Network-drive files | Answered | jump-list and `.LNK` rows exact (16:26:53, 16:27:33) |
| 29 | Cloud traces | Answered | `Program Files (x86)\Google\Drive`, `AppData\…\Drive\user_default` (`snapshot.db`, `sync_config.db` deleted, `sync_log.log`), `HKU\informant\Software\Google\Drive`, `Classes\GoogleDrive.*`, `icloudsetup.exe` |
| 30 | Files deleted from Google Drive | **Partial** | `happy_holiday.jpg` and `do_u_wanna_build_a_snow_man.mp3` DELETE at 16:42:17 are in `sync_log.log`, found by search; there is no structured sync-log record, so the modified times are read by hand from the log text |
| 31 | Drive account | Answered | `iaman.informant.personal@gmail.com`, 16:05:32, from the log, by search |
| 32 | Burning method | **Partial** | every trace is present (Burn-folder USN, `cdrom` events, `CD Burning` key, no third-party burner in Prefetch); the conclusion "Windows' own burning" is the examiner's |
| 33 | When burned | Answered | `DAT`/`FIL`/`POST` USN at 15:47:47, 15:56:01, 16:24:19; four `cdrom` events (ID **133**; the key prints 113) at 15:47:47, 15:56:11, 16:24:46, 16:41:21; `CD Burning` key 16:53:16, `DefaultToMastered` 0 |
| 34 | Files copied to CD-R | **Partial** | all 17 names (USN renames); the `Burn\Burn\{de,pd,prog,prop,tr}` folders are not reconstructed (parents overwritten, as the key says) |
| 35 | Files opened from CD-R | Answered | jump-list rows exact; `.LNK` file times for `Penguins`/`Koala`/`Tulips` 17:01:10/12/14 |
| 36 | Resignation file times | Answered | `$SI` and `$FN` created 14:48:40, modified 14:59:30; OOXML 14:32:00 / 14:59:00; Sleuth Kit agrees |
| 37 | Printing | Answered | `.xps` on the Desktop, written 11:28:33–34; `Microsoft XPS Document Writer` printer |
| 38 | Thumbcache files | Answered | `thumbcache_32/96/256/1024/idx/sr.db` in the informant's Explorer folder |
| 39 | Confidential files in thumbcache_256 | **Partial** | 630 thumbnail entries; a record does not name the `.db` it came from |
| 40 | Sticky Note location | Answered | `\Users\informant\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt` |
| 41 | Sticky Note text | Answered | "Tomorrow… / Everything will be OK…"; see below for the timestamp |
| 42–43 | Search enabled, what it indexes | Answered | `WSearch` `Start` 2, `Databases\Windows\FileName` = `Windows.edb`; stores `file`, `iehistory`, `mapi15`, `StickyNotes` (464 items, database marked dirty) |
| 44 | IE in the search database | Answered | 11:09:22, 11:09:23, 11:09:40, 11:09:50 … |
| 45 | Mail in the search database | Answered | 18 subjects at the key's times (13:29:29 …) |
| 46 | Desktop in the search database | Answered | the key's paths (two dates differ from the key by one second) |
| 47 | Shadow copy | Answered | `9b365826-d2ef-11e4-b734-000c29ff2429`, created 14:57:27 UTC = 10:57:27 |
| 48 | Drive in the shadow copy | Answered | `snapshot.db` 20,480 / `sync_config.db` 11,264 / `sync_log.log` 349,702 bytes; created 16:02:51, modified 16:47:55 (`snapshot_times`); live copy differs |
| 49 | Deleted records in the VSC `snapshot.db` | **Partial** | **the SQLite parser did not run on shadow-copy versions in this run**; run by hand it recovered record 1 exactly (answered in the 2026-10-22 re-run below). Record 2's header is overwritten, as the key says: its name survives only as slack fragments |
| 50 | Why no Outlook data in the VSC | Answered | `BackupRestore\FilesNotToSnapshot\OutlookOST` |
| 51 | Recycle Bin | **Partial** | 13 of 14 `$I` files; **`$IDOI3HE.jpg` (Tulips.jpg) was skipped by a `$ID` exclusion; the exclusion is fixed, pinned by a real-file test, and the run was not repeated** |
| 52 | Anti-forensics on 03-25 | Answered | searches 10:46:44–10:47:51, downloads 10:47:34 and 10:48:12, installs and runs (Prefetch), Eraser wipes (USN), Drive sign-out 11:22:47 (log), deleted mail |
| 53 | RM#2 recovery | **Partial** | carving recovers all 17 by size (65 carved from 1,069,543,424 bytes); **no file names**: the FAT root is empty after the quick format and the parser does not scan free space for directory entries, which The Sleuth Kit does (answered for the names in the 2026-10-22 re-run below) |
| 54 | RM#2 anti-forensics | **Not answered** | "quick format" is an inference no screen states |
| 55 | Files copied to RM#2 | **Partial** | sizes from carving, names from USN renames and LNK; not stated as one answer |
| 56 | RM#3 hidden files | **Partial** | the whole-source carve (**API only**, no screen) recovers 17 documents matching the key's sizes; the original names are not recoverable, the key says to infer them from the first page |
| 57 | RM#3 anti-forensics | **Partial** | 10 deleted directory entries in the UDF listing (names shown as `[undecoded CS0 254] …`) and the carved files support it; no screen states format / copy / delete |
| 58 | Timeline | **Partial** | the timeline holds 1,213,782 events; no narrative |
| 59–60 | Methods; diagram | **Not answered** | an examiner's synthesis |

**Sticky Notes.** Through the pipeline on this run: one `StickyNote` record,
`source_format: snt_compound_file`, text `Tomorrow...\n\nEverything will be OK...\n\n\n` with no trailing
NUL, `validation_state: snt_validated_against_one_real_file`, agreeing with `SNT-1`. The key's
"timestamp (file modified) 14:31:59" is the **file's** `$SI` modification (`istat` 22108: 18:31:59.463
UTC); the record's own times are the compound file's storage times (18:31:17, labelled as such), so the
key's figure is on the file entry, not the note. The never-validated stamp is off for `.snt` only,
unchanged: it is per format, and `plum.sqlite` is covered by `PLUM-1`.

**Behaviours this run pins.**
* The artifact writer writes the rows the database accepts, so one unwritable row does not hold back the valid ones (above).
* The SQLite DDL reader treats a column name as a constraint keyword only when it is the whole word: `checksum` starts `check`, and treating it as a constraint shifts every later column of a recovered row by one place (`shared` would hold the checksum; `schema.rs`).
* A `$I` file whose random name begins with `D` is read (one name in thirty-six).
* A ShellBag record carries the BagMRU key's last-write time as `key_last_written`; the key's ShellBag times are that, not the folder's own FAT times.

**Not done, stated.** The adapter name for Q9; Q22's volume names;
UDF deleted names with compression ID 254 (the hex decodes to the folder names `de`, `design`, `pd`, … — left
undecoded because the byte is not defined by the standard); IE 8 `index.dat`; the `key_last_written`
scan cap on large hives; RM#3 type 1/2 and the seed files; the Recycle Bin fix, which is pinned by a real-file test and not re-run through a case.

**Re-run.** `SEANCE_LEAKAGE_SYSTEM_HIVE=<SYSTEM hive> cargo test -p seance_plugin_registry
the_data_leakage_dhcp_interface_reads_the_key_answer` (hive: `icat -o 206848 <E01> 58912`); the rest by
`cargo test -p seance_plugin_shellbags -p seance_plugin_sqlite -p seance_plugin_recyclebin` and
`cargo test -p seance_core --test orchestrator_writer_test`; the run itself is about 15 minutes.

**2026-10-22 re-run (questions 49 and 53 only; the other 58 were not re-graded; it supersedes rows 49 and 53 above).** The Data Leakage images are held (`cfreds_2015_data_leakage_pc.E01`-`E04`, `rm#1`, `rm#2`,
`rm#3_type3`, every SHA-1 OK) and the `deep` ingest was repeated on this tree (release build): **2,470,872 artifacts in 1,445 s, no `EVIDENCE LOSS` line**, of which **204,861 were read
out of shadow-copy prior versions** (1,491 `VssPriorVersion`; `WebCacheEntry` 8,139, `TimelineEvent` 5,933, `RecoveredRegistryKey` 5,831, `EvtxLogEntry` 4,949, `ShimcacheEntry` 262, `UserAssistEntry` 109 and others),
each stamped as a shadow-copy version.

* **Question 49: answered.** The parser runs on the shadow-copy `snapshot.db` through the case with no hand-run: the deleted `cloud_entry` row at the key's place comes back as
  `doc_id 0Bz0ye6gXtiZaVl8yVU5mWHlGbWc`, `filename do_u_wanna_build_a_snow_man.mp3`, modified 1422636560, created 1427142765, size 6,844,294, checksum `2c4553f99533d85adb104b3a5c38521a`,
  `deleted: true`, `recovery_source: unallocated`, `is_snapshot_version: true`, `database: snapshot.db [shadow copy 2015-03-25 14:57:27 UTC]`; and the matching deleted `cloud_relations` row. Record 2's
  header is overwritten, as the key says.
* **Question 53: answered for the names.** The orphaned-directory scan recovers **all 17 of the key's deleted files by name** (design 2, pricing decision 4, progress 3, proposal 2, technical review 6) under five
  `[orphaned directory, cluster N]` directories, plus `desktop.ini`, with every size equal to The Sleuth Kit's `istat` (checked on `winter_storm.amr` 14,547,968, `winter_whether_advisory.zip` 16,381,123,
  `my_favorite_cars.db` 1,260,544, `diary_#1d.txt` 121,441, `landscape.png` 6,484,502). The directories' own names are not recovered (a cluster number stands in for them; The Sleuth Kit reads `design`, `progress`, `proposal`
  from the parent entries it finds and `PRICIN~1`/`TECHNI~1` as short names). 23 deleted pictures at the root of the volume (`amalfi.bmp`, `barn.gif`, ... `wat.gif`) are directory entries in
  free clusters that no `.` names; the headless pass reads them all (`RM2-HEADLESS-1`).

## A real Windows 2000 NTFS 3.0 volume

Real evidence, answer key derived from a second tool, no published key.

- **Source.** https://archive.org/details/Windows2000VHDCollection, "Windows 2000 Professional with Service
  Pack 3 Hard Disk.vhd". Fetched 2026-09-27. The full VHD download is truncated (about 950 MB of 2.27 GB, md5 does
  not match archive.org's) and is not cited. The graded file is a metadata-only sparse raw built by HTTP range
  fetch from the VHD: `$MFT`, metadata and index clusters only, file content is zero.
  `~/forensic_corpora/win2000_ntfs30_metadata/win2k-pro-sp3-ntfs30-metaonly.raw`, sha256
  `61ea3bc9a946321d23070218a6c50ba491155438d85d3473e4cada0249a60624`, with `SOURCE.md` and the extents map beside it.
- **Key.** The Sleuth Kit 4.12.1 cluster and path listing, committed as
  `seance_plugin_mft/tests/data/win2000_ntfs30_tsk_clusters.txt`. Synthetic: no. Published by the source: no.
- **Result.** 6,604 `FILE` records numbered by slot; 6,586 base `FileEntry` rows; paths and cluster lists of the four
  extension-record files agree with TSK 4.12.1 (`istat`, `fls -r -p`). Only the cluster lists are committed as a key;
  the 6,578-name path figure in the method statement was not re-counted here.
- **Cannot grade.** File content, a non-resident `$ATTRIBUTE_LIST`, any other 3.0 volume.
- **Re-run.** `cargo test -p seance_plugin_mft --test real_win2000_ntfs30_test -- --nocapture`
  (`SEANCE_WIN2000_NTFS30=<raw>` overrides the path; the tests skip when it is absent).

### PST-PUBLIC-1 - six public PST stores against libpff, 2026-10-22

**Evidence.** Six published test stores of other projects, pinned by SHA-256 (`seance_plugin_email/tests/fixtures/pst_public/PROVENANCE.md`): pstsdk `sample1` (Unicode, 1 message, 1 attachment), `sample2` (**ANSI**, the same message
with an attachment), `test_ansi` (**ANSI**, 1 message), `test_unicode` (Unicode, 2 messages), `submessage` (Unicode, an embedded message) and Apache Tika's `variousBodyTypes` (Unicode, 4 messages in HTML and RTF).
**Answer:** libpff, through `scripts/oracle/pst_list.py` (pypff): folder, subject and attachment count per message. Not third-party validation.

**Messages without a recipient table.** `test_ansi` and `test_unicode` hold 1 and 2 messages that libpff reads. The linked `outlook-pst` reader refuses a message that has no recipient table, and a refused row is only counted (`messages_unreadable` 1 and 2, the summary marked truncated). The same refusal affected `m57_jean_administrator_outlook.pst`'s one message. The product asks this crate's own reader (`pst512`), which does not need the table, for each refused node (`a_live_message_the_linked_reader_refuses_is_published_by_the_crates_own_reader`); the message is published with
`read_by: own_reader`, its recipient table marked not read (so the record is `content_incomplete`), and the summary counts `messages_read_by_own_reader`; a node neither reader opens stays in `messages_unreadable`.

**Result.** All six stores: every message libpff lists is published in the folder libpff places it in, with its subject and attachment count, and none libpff does not list; `messages_unreadable` 0 and no truncation on any;
3 messages read by the crate's own reader (1 + 2). (`public_pst_real_test.rs`, 6 tests.) The live ANSI (version 14) path with an attachment is graded end to end on a store the reader opens (`sample2`).

**Not established.** No store of these six has non-Latin text (`PST-PUBLIC-3` grades one); bodies and attachment names were not compared byte for byte, only counts and subjects; recipient tables are compared in PST-PUBLIC-2; `java-libpst`'s `dist-list.pst` (held) cannot be read by libpff and has no answer; no Unicode store libpff can recover deletions from was found.
**Re-run:** `SEANCE_PUBLIC_PST_CORPUS=~/forensic_corpora/public_pst/stores cargo test -p seance_plugin_email --test public_pst_real_test`.

### PST-23-1 - a real version 23 Outlook data file against libpff, 2026-10-20

Evidence: plaso's public test data
`nromanoff@stark-research-labs.com.pst` (Apache-2.0), 59,442,176 bytes, SHA-256
`bab64f3589f8ce758df9e595b89a5e4b9be159929e49100397152fdcc7bd6013`, version 23 (Unicode, 64-bit,
compressible encryption). Not committed; held at `~/forensic_corpora/plaso_pst/`.

**Method.** `docker run --rm --user 1000:1000 -v <dir>:/in -v <out>:/out pffexport:local pffexport -q -d -l /out/log.txt -m items -t /out/x /in/nromanoff_stark_research_labs.pst`
(pffexport 20231205). The log's item identifiers are the node ids; the oracle
(`seance_plugin_email/tests/fixtures/pst_old/nromanoff_v23_libpff_oracle.tsv`) lists 543 mail and
contact items with node id, attachment count, folder and subject.

**Result.** All 543 match on node id, folder, subject and attachment count; no fault. The only live message
libpff does not export is the free/busy item `0x200044` (logged as skipped). Three messages in Deleted Items have a stale
node entry and no live one and are read Complete; libpff cannot corroborate them (`-m recovered` fails at offset
356864). 500 live messages have a stale entry, so cutting one from the live tree (real bytes, mutated) recovers it with
libpff's subject, folder and attachment count. Synthetic parts: none; the mutation is stated as such.

**Re-run.** `SEANCE_PST23_CORPUS=~/forensic_corpora/plaso_pst cargo test -p seance_plugin_email --lib v23_corpus`.

### Synthetic FAT/exFAT directory-recovery volumes (2026-10-20)

**These volumes are SYNTHETIC.** They were built by tools on this machine to a layout the generator knows, and
they grade this parser's behaviour on that layout. They say nothing about what Windows, a camera, a phone or any
other FAT driver leaves behind on a real volume, and no claim about real-world evidence rests on them. The
answer key is the generator script, written before the parser change; nothing was read back from a Séance output.

| Fixture (gzip, `seance_plugin_fat/tests/fixtures/`) | Built as | Key | SHA-256 (gz) |
|---|---|---|---|
| `hunt278_fat16_a.raw.gz` | `mkfs.fat -F 16 -s 1`, 4 MiB; `mmd` KEEP and D; 40 empty long-named files in D; `mdeltree D` | 40 names recovered, `deleted`, later-cluster records `contiguous_assumed` | `ca3303d0316b8d17a8d288d04e4eea4f47fca3337525689543d76e8a8949b9c2` |
| `hunt278_fat16_e.raw.gz` | `mkfs.fat -F 16 -s 1`, 8 MiB; `mmd` DirD; 40 files with 57-character names, 50 KB of file data, 60 more files; `mdeltree DirD` (names straddle 512 B directory clusters) | `names_cut_by_a_cluster_boundary...`: all 100 names whole, some joined; `a_deleted_name_whose_head...`: with the cluster before zeroed the cut names are flagged |
| `hunt278_fat16_a2.raw.gz` | as A, but 4 files in D, then a 1,200-byte text file written and deleted into the next clusters, then D grown to 12 files, then `mdeltree D` | only the 4 files in D's first cluster; `fat_deleted_chain_unverified`; the text is not read as entries | `645302ff491504da19c459e19d19344d0cd3fe608a7283b2ada6436bbed07cdb` |
| `hunt278_fat16_b.raw.gz` | decoy dir E and D made, both deleted, then a 900-byte file written onto E's and D's first clusters | D's record: `directory_content_reallocated`; no entry read from the file's bytes | `e41761f265c5a1b32dbb01225c589d84e7de4aa3e343301f9101107a19505fc2` |
| `hunt278_fat16_c.raw.gz` | live dir S with ONE..SEVEN, `plant_hunt278_slack.py` puts `0x00` over FOUR and 32 bytes of `FF FE` over SEVEN; dir Z with one file | THREE live; FIVE and SIX `recovered_from_directory_slack`; the garbage slot counted, not published; Z publishes nothing extra | `d18fd30450f9cef75555f097981459ace780a83eb2e8cb5935d8a4198f09f743` |
| `hunt278_exfat.raw.gz` | `mkfs.exfat -c 512` 8 MiB; `make_hunt278_exfat.py` adds /DIR (NoFatChain, 2 clusters, six sets, f6 straddling the boundary), then deletes it (InUse cleared, bitmap bits cleared), clears InUse on f2's set and corrupts f3's `SetChecksum` | f1, f2, f4, f5, f6 recovered; f3 refused and counted | `6720cf2543c2be455f30342a6bbc0a1c3169dfba9418e60970c4ca06a50b6dc0` |

Tools: `mkfs.fat 4.2 (2021-01-31)`, GNU mtools 4.0.49, exfatprogs 1.3.2 (`mkfs.exfat`, `fsck.exfat`), Python 3.14.
No exFAT populator exists here, so the exFAT directory is written by a stdlib python3 writer; the honest check on it
is `fsck.exfat -n` on the **live** layout before the delete step, which reports `clean. directories 2, files 6`
(the generator runs it and fails if it does not). The deleted image fsck's clean with no files, as it should.
mtools stamps the current time, so rebuilding changes the bytes (and the hashes) but not the layout.

**Re-run.** `bash seance_plugin_fat/tests/fixtures/make_hunt278_fixtures.sh <outdir>` rebuilds the five volumes;
`cargo test -p seance_plugin_fat hunt278` grades the committed ones. **Mutation checks:** removing the `.`/`..`
guard fails the reused-cluster test, removing the plausibility test fails the file-bytes test, and disabling
`SetChecksum` validation fails the exFAT test.

**Not graded, stated.** A deleted directory whose first cluster was reused and whose later clusters survive; an exFAT orphan
scan; slack behind a marker in a later cluster or in the FAT12/16 root.

## Extending the case set

Cases are declarative — add an entry to `seance_validate::cases::cases()` with
its documented expected answer and a `check` closure that runs the real
pipeline. The framework handles image presence, hashing, and Pass/Fail/Skipped
classification, so a new case cannot accidentally count a skip as a pass. The
framework logic itself is unit-tested (no corpus required); the cases run
against the corpus when present.
