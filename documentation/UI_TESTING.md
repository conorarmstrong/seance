# Browser-driven UI testing

How Séance's web interface is tested by **driving a real browser against a real
server holding real evidence**, what that catches which nothing else does, and
the plan for doing it systematically.

This is the strategy document for one layer of testing. The unit and integration
layers are in [TESTING.md](TESTING.md). Known-answer validation against the forensic
corpus is [VALIDATION.md](VALIDATION.md).

---

## 1. Why this layer exists

Séance has ~1,800 frontend unit tests and they are good ones. They did not catch
any of these, all found in a single browser pass:

| What the screen did | Why the unit tests missed it |
|---|---|
| Labelled the largest evidence class in an NTFS case **"1"** (73,640 records) | The grouping code was correct. The *data* made a numeric field the label, and no fixture carried that shape. |
| Listed four bookmarks an examiner made as four identical **"Unknown"** rows | The column rendered exactly what the record held. Only a record type with no `name` shows it, and no fixture had one. |
| Drew the primary button dark-on-dark, and faded a dropped-connection warning to 3.3:1 | Both were correct for the one palette that existed. A hardcoded `color:` is invisible to the contrast guard, which reads only token-valued declarations; a fade is a second declaration a palette tuned against the first does not cover. **A light theme is an instrument**: adding one found four of these in a single run. |
| Put raw metadata JSON in a search result snippet | The excerpt was correct over the text it was given. That text happens to begin with the serialised metadata, which only real indexed records reveal. |
| Showed **"100%"** with 148,215 of 148,216 tasks done | `Math.round` is correct arithmetic. Only a real 4-nines ratio makes it lie. |
| Drew an activity chart spanning **1979→2027** with all real activity in two bars | Fixtures have tidy date ranges. Real evidence has a FAT epoch date in it. |
| Overlapped a badge across nine card titles | jsdom has no layout. `toBeInTheDocument()` passes on an unreadable screen. |
| Flung a two-node graph to opposite panel edges and drew one label off-canvas | Canvas rendering is invisible to jsdom entirely. |

The pattern: **unit tests assert that the code does what it was told. This layer
asks whether what it was told is any good, on data the developer did not choose.**
Three of the five above are forensic-honesty defects — a screen stating something
an examiner would quote and that is not true — which this project treats as HIGH
regardless of whether a byte was wrong.

### 1.1 The three questions

Every check below answers one of:

1. **Is it true?** Does the screen assert anything the evidence does not support —
   a count without its population, a slice presented as a total, a rounded
   completion, an absence that is really a limit?
2. **Is it usable?** Can an examiner find the thing, read it, and act on it —
   without already knowing where it is?
3. **Is it there at all?** Does a record type that an examiner will need reach a
   view built for its fields, or fall through to a generic table?

---

## 2. The instrument

A Playwright harness driving a **locally installed Chromium** against a live
`seance` server. No browser extension, no cloud, no network egress.

```
scripts/ui-tests/
  harness.mjs   open() → browser+page+shot(); login(); writeReport()
  walk.mjs      route-level sweep: every case surface, screenshotted
  interact.mjs  interaction pass + forensic-honesty assertions (dimension B/J)
```

`SEANCE_PASS` must be exported — the harness carries no default credential and
refuses to start without one.

`open()` returns a `shot(name)` helper that screenshots full-page and **buckets
every console error, page error, failed request and HTTP ≥400 against the screen
that caused it**, written to `problems.json` / `problems.txt` beside the images.
A screen that looks right while failing underneath is therefore visible.

### 2.1 Rules the harness itself must obey

These are not style preferences; each is a bug the harness has already had.

- **A failed precondition must abort, never degrade.** The first run's login
  silently failed (the username input carries no `type` attribute, so an
  attribute selector matched nothing) and produced 28 screenshots *of the login
  page*, each with a 401 that looked like an application defect. `login()` now
  asserts the app has left `/login` and throws with the on-screen text if not.
  **Any harness step whose failure could be mistaken for a product defect must
  assert loudly.**
- **Wait for the thing, not for a duration.** Wait on the selector, never a fixed
  `setTimeout`; a busy machine otherwise reports a slow screen as a broken one.
- **Never select on attributes the markup does not carry.** Prefer role and text.
- **Screenshots are evidence.** Keep the run's `problems.json` beside them; a
  screenshot with no record of what the browser complained about is half a
  finding.
- **Run it alone.** Concurrent cargo builds or a fuzz sweep starve the server and
  produce timeouts that read as product failures. (This has cost real time.)

---

## 3. The evidence matrix

Browser testing is only as good as the data behind it. Fixtures produce tidy
screens; **real acquisitions are what expose the defects above**.

| Image | Size | What it exercises on screen |
|---|---|---|
| `lonewolf/LoneWolf.E01` | 33 GB | The realistic case: browser history, LNK, prefetch, registry, `$LogFile` at volume, a 46-year timestamp spread. The scale case for paging, search and charts. |
| `cfreds_hacking/4Dell_Latitude_CPi.E01` | 1.1 GB | Windows artefacts on an older build. |
| `cfreds_utf8/Cfreds-utf-8.E01` | 100 MB | **Unicode filenames** — column truncation, RTL, combining marks, CJK width. |
| `golden/golden_multipart.E01` | 316 KB | NTFS + ext4 + FAT16 + APFS in one image: the multi-filesystem tree. |
| `alihadi_ntfs/NTFS-HiddenFiles.E01` | 472 KB | Fast NTFS case for iteration; ADS and hidden files. |
| `win11_bitlocker/memory-unlocked.raw` | 10 GB | The `/memory/*` screens with real data (otherwise all empty states). |
| `oberon_linux_swap/` | 12 GB | Linux memory + swap; `utmp`, shell history. |
| `dftt/*` | 164 MB | Known-answer images whose expected output is documented. |
| none | | No macOS data is held. The `AuditEvent`, `AslMessage` and `KeychainItem` screens have no real data, and neither do the `ICloudKeychainDevice` and macOS `FailedLogin` screens. A logical tree has no partition table, which is how the free-space carving gap (§5.4) stayed invisible. |

**A screen tested only against an empty case is untested.** The memory screens,
the communications graph and the gallery have all been screenshotted as empty
states; that is a third of their behaviour at most.

### 3.1 Data-shape matrix

Every list/table/chart surface must be seen at each shape it can take:

| Shape | Why | Expected |
|---|---|---|
| **Absent** | Feature never ran | Empty state naming *why*, distinct from zero |
| **Zero** | Ran, found nothing | "None found", not "not looked up" |
| **One** | Degenerate layouts | Charts and graphs must not look broken (the 2-node graph) |
| **Typical** | The normal case | Readable, sorted, paginated |
| **Huge** | 4M artifacts | Virtualisation, paging ceiling honesty, no unbounded query |
| **Outlier-skewed** | FAT epoch / 2038 dates | Axis focus + disclosure, not a squashed chart. **Covered** for all three time charts, in the unit suite rather than the browser: `ActivityHistogram.test.tsx` and `RichCharts.test.tsx` build the skewed shape the server actually returns and assert both the focus and the sentence disclosing what it left out. Five of those cases were shown to fail with the focus removed. The residue is that the bucket *width* is still chosen against the unfocused extent |
| **Unicode** | CJK, RTL, combining, emoji | No mojibake, no clipped glyphs, correct width |
| **Hostile** | `=cmd`, `<script>`, 4 KB single-line value | Escaped, neutralised, bounded |
| **Truncated** | Server capped the result | The cap is *stated on screen* |

---

## 4. Test dimensions

### A. Route coverage
Every route in `frontend/src/app/routes.tsx` is visited and screenshotted,
including `*` (not-found) and a case-scoped not-found. **Status: automated
(`walk.mjs`), 35 screens.**

### B. Interaction pass
Route coverage only proves a screen renders. Each surface additionally needs its
controls exercised, and the honesty invariants (dimension J) asserted against
what the screen says *after* the interaction. Per-screen matrix in §6.
**Status: automated (`interact.mjs`), 39 checks** over timeline chart modes,
search refusal, gallery safe-view, every analysis viewer, audit verification,
the memory stages and the not-found route.

**The lesson from its first run, which is the point of §7.1.** Seven of 39
checks failed and **not one was a product defect** — every one was the check
being wrong, and in each case the product's real behaviour was *better* than
what the check demanded:

| Check said | Product actually said | Who was wrong |
|---|---|---|
| not-found must say "not found" | *"No view at this address … Nothing is missing from the case — the address itself matches no view in this product"* | The check. The product distinguishes a bad address from missing evidence, which is the more useful answer. |
| audit must show the completeness caveat | *"CHAIN BROKEN … row 1 was written under key fingerprint 4de6f752…, which matches neither `SEANCE_AUDIT_HMAC_KEY` nor any key in `SEANCE_AUDIT_HMAC_KEY_PREVIOUS`"* | The check. The chain was legitimately broken (this environment restarts with a fresh key over a persisted workspace — the rotation case), and the product named the variable that fixes it. |
| every viewer must disclose it shows a slice | *"Feature — 8 records"*, with all 8 rows shown | The check. Demanding slice language where nothing is sliced is demanding a falsehood. |

A harness that cries wolf is worse than no harness, for the same reason a tool
that cries tampering during ordinary use is: it trains its reader to ignore it.
Assertions are now written against the behaviour the product actually has, and
each records the text it judged so a human can disagree with the verdict.

### C. Visual regression → layout geometry
Pixel baselines would need an image-diff dependency (`pixelmatch`/`pngjs`, or
`@playwright/test`) in a forensics product's tree, which is an owner's decision,
not a test author's. **The defect that motivated it does not need one.** The
badge drawn across nine card titles is two text elements whose bounding boxes
intersect — computable from geometry the browser already has, and it yields a
*reason* ("these two overlap by 34px²") where a pixel diff yields "0.3% of
pixels differ".

`scripts/ui-tests/layout.mjs` reports three things per screen: text elements
painted on top of one another, text clipped by its own box with no ellipsis and
no scroll, and text painted past the viewport with no scrollable container.

**Status: exploratory tool, not a gate.** Clean at 1280 / 1440 / 1920 px; three
residual false positives at 1024 px, where a timeline row that scrolls at page
level (no scrolling ancestor to clip against) reports an intersection with the
custody strip below it. The screen is correct there — verified by eye.

Its development is the §7.1 lesson again, and worth keeping: it began by
reporting hundreds of overlaps, **every one of them wrong**, and each round of
false positives was a wrong model of how the browser paints:

| Reported | Actually | Correction |
|---|---|---|
| Sidebar items over the evidence tree | Scrolled out of the sidebar's own overflow | Hit test at the element's centre |
| Collapsed panels' buttons over the results table | Panels visibly shut; the hit test accepted a shared *ancestor* | Topmost must be the element or a **descendant** |
| Four `<strong>`s over each other in help prose | A wrapped inline's `getBoundingClientRect()` is the **union** across lines | Compare per-line `getClientRects()` |
| Table rows over the status bar | Content under an overlay, then rows past a scroll container's edge | Skip fixed/sticky layers; clip rects to the scroll container |

Before pixel baselines are added, this should be finished (page-level scroll
clipping) — it is cheaper, dependency-free, and names the defect.

### D. Console and network hygiene
No `pageerror`, no unhandled rejection, no HTTP ≥400 that is not a *deliberate*
refusal, no request that fails other than by navigation abort. Already collected;
should become an assertion. **Known open item:** the app requests
`/api/v1/cases` before it knows it is authenticated, producing a 401 on every
cold load.

### E. Accessibility
`contrast.test.ts` already derives every composited pairing from the stylesheets
and hovers. Add `axe-core` per screen for roles, names, landmarks, focus order,
and keyboard reachability of every control (this product's users are heavy
keyboard users and several surfaces are keyboard-first by design).

### F. Viewport and responsive
1440×900 (primary), 1280×800 (laptop), 1920×1080, and a narrow 1024 case. The
graph label clipping only appears when the panel is narrow.

### G. Locale
The suite already runs `en-US` and `de_DE`. Add a check that **no forensic
timestamp is localised** — everything evidential is UTC ISO-8601 — while UI
chrome is translated. The native `datetime-local` pickers currently render
`mm/dd/yyyy` under en-US, which is ambiguous next to ISO timestamps everywhere
else.

### H. Performance budgets
Time-to-interactive per screen on the 33 GB case; a budget per surface; alert on
regression. The gallery did not finish loading within 1.4 s and has never been
seen populated.

### I. Degraded and error states
Server 500; session expiring mid-session (401 on a background poll); a slow or
aborted SSE stream; an export aborted mid-download; the search index still
building. Each must degrade to a *stated* condition, never a blank panel.

### J. Forensic-honesty assertions
The distinguishing layer. Automatable checks:
- No visible count without a population or an explicit "of N" nearby.
- No progress indicator reading 100% while work is outstanding.
- Any capped/truncated list carries its cap on screen.
- Any chart whose domain excludes data discloses what it excluded.
- "0" and "—"/"not stated" are visually distinguishable everywhere.
- Every empty state says which of *absent* / *zero* / *not looked up* it is.
  The mobile source-type chip on a Dashboard source card is the pattern:
  `none_recognised` (*zero* — the walk completed and names what was looked
  for), `mobile: not assessed` with its reason (*not looked up*), and
  `mobile label unavailable` for a failed request; it never reads "no mobile
  evidence" (ROADMAP §1.4, `SourcesSection.test.tsx`).

---

## 5. Visualiser coverage

A record type an examiner needs, reaching a generic key/value table, is a
usability defect even when nothing false is shown. Coverage is measured, not
assumed:

- **Emitted types**: `grep -rhoE '"type"\s*:\s*"[A-Za-z0-9_]+"' --include=*.rs`
  over the plugin crates.
- **Tailored viewers**: keys of `VIEWERS` in
  `frontend/src/pages/analysis/viewers.tsx`.
- **Gap** = emitted − viewers − status/disclosure records (those are markers, not
  browsable evidence, and belong in their parent record's disclosure).

The Analysis index already labels an untailored type **"generic view"**, so the
gap is visible to the operator; it should also be tracked here. A type earns a
tailored viewer when it has (a) a natural time axis, (b) a natural grouping
dimension, or (c) fields whose raw JSON is unreadable (paths, hashes, flags).

---

## 6. Per-screen interaction matrix

| Screen | Must exercise | Honesty assertion |
|---|---|---|
| Login | Bad password, lockout/rate limit, forced change | No credential echoed; failure reason precise |
| Cases | Create, filter, sort, open, no-access | Counts scoped to accessible cases |
| Dashboard | Export HTML/PDF/XLSX, tile → drill-down, live processing, the mobile label chip on each source card | Tiles state populations; progress never rounds to 100; the mobile chip has four states — kinds with their basis in the accessible name, `none_recognised` naming each marker's whole test (type, field value, path) and never saying no record of those types was found, the label re-read when a source's walk state changes, `not assessed` with its reason, `unavailable` on a failed request — and none of them says a source holds no mobile evidence |
| Timeline | Filter, date range, page size, columns, **Swimlanes**, **Heatmap**, tag, export ×3, **the page type-ahead**, **the case-wide window** | Chart discloses excluded outliers; count is of matches, not page; the type-ahead says it searched one loaded page and not the case; a page under the case-wide window says which of the two windows narrowed it (§1.1) |
| **Time-window bar** (every case page) | Click a bar, clear, a case with no dated events, a failed histogram with and without a window in force | The window is printed in UTC, names the screens it is in force on, and says those screens show a subset; a backwards drag is normalised rather than queried as `from > to` (§1.1) |
| Search | Regex, fuzzy, extensions, deep offset (refusal), cursor walk, export, **a zero-hit search** | Floor/exact wording; refusal names the reaching route; **a zero-hit page states what was searched** — the server's `universe` statement (16 MiB of file bytes, no slack or unallocated, UTF-16 CJK/Hangul not indexed, the byte-sweep route) beside "No results", and under the count on a page of hits (`SEARCH-002`; unit-pinned in `SearchPage.test.tsx`, not yet in the harness) |
| Search — byte sweep panel | Patterns, code pages, extensions, region checkboxes, max hits, **Resume** from the cursor, a 400 refusal | The status line is the server's `complete` — never "Complete" on a cut answer; every ceiling reached named with its number; no cursor on an incomplete answer says it cannot be continued; the slack sentence beside the per-region table on every answer; short reads, read failures and bytes past a declared size listed; an endian-ambiguous hit names both encodings and offsets (`ROADMAP` §1.2; unit-pinned in `ByteSweepPanel.test.tsx` against fixtures in the route's shape, reachability in `SearchPage.test.tsx`; not yet in the harness) |
| **Findings** | Grade filter (each chip), reveal the values a lead rests on, pivot from one, open the subject **and** the finding record, empty list, failed load | The observation, the inference and the qualification are three separately labelled blocks and the qualification is **never** hidden; the detection list is on the screen; the cross-view block renders in all three of its states; an empty list carries the server's own absence note and a failed load never renders as an empty one (§2.2) |
| **Needs attention** (Dashboard) | Supply a secret and re-run, a start-up-credential row, an unsupported row, an unrecognised blockage, empty queue, failed load, failed re-run | A field is offered **only** where a per-artifact secret reaches the module — through the credential route (iOS backup; BitLocker, with a kind selector for its password or recovery password; LUKS; header-encrypted 7z; Signal for iOS), one request per target artifact however many statements name it, the field cleared once sent; a start-up credential row renders no input and names the variable; the scope note saying this is not the completeness record is always present (§2.11) |
| **Traced values** (Bookmarks) | Pin from the pivot drawer, re-pin, unpin from both surfaces, a capped snapshot | The counts are stated as a snapshot; a capped snapshot says its per-kind counts are a sample; the panel says the report re-checks the value (§5.13) |
| **My queue / Mine (personal) / Assign** (Bookmarks, §3.15) | Assign the listed bookmarks as owner; view as a non-owner (no control); read the queue as the assignee after a colleague reviews an item; add a personal mark from the artifact viewer, promote it, promote one whose artifact already has a shared bookmark | A failed read says "could not be read", never "nothing assigned" / "you have none"; progress says it counts the assignee's own reviews only; `read_only` examiners are not offered; the personal panel says it is never reported; "in shared bookmarks" is shown only while the shared bookmark still exists (a deleted one leaves the mark re-promotable and says it is not in the report); an empty queue claims "reviewed every item" only when no item was unreadable and the assignment still holds items; a `5xx` on Assign says the assignment may have been recorded, only a `4xx` says nothing was. Component tests: `frontend/src/pages/assignments/*.test.tsx`; no browser-harness scenario yet |
| **Files: whole-case body file** (§5.12) | Press **Export whole case as mactime body file** with filters set and nothing selected; a failed download; a download that arrives without its verdict line; a whole file whose verdict is `INCOMPLETE`; a cancelled save dialog | The sentence beside the button says every file in the case, from every source, and that the page's filters are ignored; no filter is sent; the download is reported saved (with the file's own verdict quoted) only when its last line is `# ### END OF EXPORT ### VERDICT: COMPLETE`; an `INCOMPLETE` verdict and a fragment are both shown as errors; a cancelled dialog is said to have written nothing; a failure names the retry. Component tests: `frontend/src/pages/files/FileGridPage.test.tsx`, `frontend/src/lib/download.test.ts`; no browser-harness scenario yet |
| **Artifact: Timeline tab** (§5.12) | An artifact with its own, parent and child/sibling events; a capped list; an artifact with none; a failed load | Rows name *this artifact* / *parent* / *child or sibling* (never guessing which of the last two); a capped list says it stops at the cap and is not the whole history; no events is stated in words, never an empty table; a failure says nothing here means no events. Component tests: `frontend/src/pages/artifact/RelatedTimelineTab.test.tsx`, `ArtifactPage.test.tsx`; no browser-harness scenario yet |
| **Artifact: Unlock to read** (Inspector) | A file of an encrypted iOS backup: preview before unlock (refused, route named), a wrong password, the right one then preview/hex/download, **Lock again** then preview, move to another file mid-request, a read-only grant, a server restart while unlocked | Before unlock and after lock the content is refused, never ciphertext shown as the file; the verdict belongs to the file it was typed for; the field is cleared once sent; the panel says the keys are held in server memory for this case and a time limit, and that the password is not kept. Unit-pinned in `ReadUnlockPanel.test.tsx`; not yet in the browser pass |
| **Artifact: Unlock to read — volumes** (Inspector) | A file beneath a BitLocker or LUKS volume decrypted in a run: preview before unlock (refused, route named), BitLocker password vs recovery password selector, a wrong secret, a LUKS kind on a BitLocker volume, the right one then preview/hex/download of the file and the decrypted volume, **Lock again** then preview, an artifact with no decrypted ancestor, a read-only grant | Offered only where the ancestors route marks a `decrypted_volume` (never guessed from a name); before unlock and after lock the content is refused, never ciphertext shown as plaintext; the verdict says the key is held for this case with a time limit and the secret is not kept; unit-pinned in `VolumeReadUnlockPanel.test.tsx`, the browser run is not yet implemented |
| Analysis index | Open each type, **filter the types** | "generic view" badge accurate; the filter states the population it searched |
| Each viewer | Sort, filter, paginate, select, open source artifact, **Export all as CSV** | Column truncation disclosed; the export is labelled as the whole type, not the viewer's narrowed rows |
| **Email** (viewer) | Open an exchange, switch exchange, a thread grouped by `In-Reply-To` alone, the unthreadable residue, a deep link from Communications | A thread that may be a fragment says so above its messages; the unthreadable rows say that being collected together is not a claim that they belong together; each message states how it was placed (§5.14) |
| **HTTP / TLS / certificates / ARP** (pcap viewers) | Open each of the four, a transaction paired across a gap, one whose headers are a prefix, one with no response, a posted form past the field cap, a TLS 1.3 session, a known-weak suite, a session with no SNI, a chain with an unparsable certificate, a self-issued certificate whose names do not cover the one asked for, and an address claimed by more than one hardware address | A pairing made over a gap reads **"may be wrong" in the row**, not only in a tooltip, and a message that is a prefix is called a prefix rather than merely incomplete; the SNI column is headed as the name the **client asked for** and never as the server; a known-weak suite is a statement about the suite and not about the conversation; a TLS 1.3 session's absent certificate reads "encrypted by TLS 1.3" and is visually distinct from a server that presented none, because no capture of TLS 1.3 can establish the latter; certificates this build could not parse are counted **beside** the ones it could; every certificate row carries "signature not verified · no chain built · no revocation check" and `self_signed` reads "subject = issuer", with a name comparison labelled a comparison and never validity; and a contested ARP address counts its claimants, says how many are past the ceiling, and carries the record's own sentence, which reaches no verdict (`UI-038`) |
| Gallery | Tiles/list, **Safe view toggle**, sort, source filter, run analysis | Safe view default OFF and the choice persists; nothing decoded without consent |
| Map | Points, clustering, KML/GeoJSON export | Cap disclosed (`geo_truncation_note`) |
| Connections | Node select, hover dim, search-from-node | Labels on-canvas; no participant unlabelled |
| Communications | Contact filter, channel tile, conversation open, review mark | Population never inferred from the slice |
| **Memory: device tree** (`device_tree`) | A device with a filter attached, a device attached two levels deep, an unnamed device, a device type the WDK does not define, a driver with no device, and an attachment stack that stopped | An attachment renders as a relationship and never as a finding, with the attaching driver named; an unnamed device is visually distinct from one whose name could not be read; an undefined device type shows the **number** and not `UNKNOWN`; a driver with no device is a row with none rather than an absence; and a stack that stopped says so where the stack is drawn, because something may be attached above the point it stopped (§5.3) |
| **Memory: jobs** (`jobs`) | A job named by more than one process, a job whose counter exceeds its member list, a member the process list does not hold, a capture where no process is in a job, and one whose process list stopped early | One row per job object with every process that named it, never one row per process; the counter and the walked member count are both on screen and a disagreement is visible rather than reconciled; "no process is in a job" renders with the count of processes that are in none, so it cannot read as a walk that failed; and where the process list stopped early, "in the process list" reads as unanswered for every member rather than as "no" (§5.3) |
| **Memory: pattern scan** (`pattern_scan`) | A case with **neither a rule set nor a pattern named** (`SEANCE_YARA_RULES` and `SEANCE_MEMORY_REGEX` both unset, so the stage reports it did not run), a run with **both** (two pattern sets, and every row has to say which engine found it), a rule set that ran and matched nothing, a match in private unbacked memory, a match inside a mapped image, a match in the **kernel's** address space (which carries no allocation), a process whose VAD tree would not walk, a rule that matched with no address of its own, a chunk the engine refused (the 30-second per-chunk timeout or an engine error), and a scan that hit a ceiling (8 GiB per process, 128 GiB for the image, 100,000 matches per space, 10,000 recorded rows) | "Did not run for want of a rule" and "ran and matched nothing" must **not** render alike — an empty list from a scan that never had a pattern is not an empty list from a rule set that ran; a match never appears without the allocation its first byte falls in — the range, the protection as the kernel's own table names it, whether the memory is private, and the mapped file if any — and a kernel-space match instead carries the sentence saying **why** there is none; each pattern set's own caveat is on screen wherever its matches are — the chunk-scoped condition for a rule set, because a condition joining two strings, `filesize` and a count are each evaluated against one chunk and not against a file, and for a regular expression that the match is against raw bytes and knows nothing of Unicode, so an ASCII pattern does not find the UTF-16 the same string is stored as; a rule that matched with none of its own strings found is **named with that reason** rather than dropped for having no address; bytes that were **mapped and would not read** are distinguishable from address space **never mapped**, and are never added together; a refused chunk is visible **beside** the match count, because a refused chunk reading as a clean one is a false absence; a process that could not be searched is a row with its reason rather than an absence; and a ceiling names the address it fired at. A match over an **image's own** space (`MemoryImagePatternScan`, the route for a reconstructed hibernation file or a swap area) must show the address it carries *and* the sentence saying it names no process and no allocation — a row that looked like a process match would be read as one — and must show what an address in it means for that format, since for a hibernation file it is not an offset in `hiberfil.sys`. **Specification only — not in the harness yet** (§9): no dedicated screen ships for this stage, so the records reach the generic memory record surface (§5.3, §3.8) |
| **Memory: strings over memory** (`strings_map`) | A case with **no strings file named** (`SEANCE_MEMORY_STRINGS` unset, so the stage reports it did not run), a file in the wrong radix (over half the lines rejected), an offset inside a frame **two or more processes** map, an offset in a frame only the **kernel** maps, an offset in a frame reached through a **prototype PTE** (a shared page), an offset whose frame came from a **suppressed uniform table** (so the virtual address was not enumerated), an offset **no walked space** maps, an offset **outside** the frames the map was asked to index, a process whose address space would not build, and a run that hit a ceiling (5,000,000 offsets read, 10,000 listed, 4,096 processes walked, 64 owners listed per frame) | "No file was named" and "no address space maps this offset" must **not** render alike; an offset with owners never shows one owner where there were two, and the **count** of owners is shown whether or not they are all listed; the **physical** offset and each owner's **virtual** address are never in the same column, which is the shape upstream's own two branches disagree about; each owner shows the **page size** beside the frame, since a 1 GiB mapping and a 4 KiB one look identical in a frame column; an owner reached through a section object is marked **shared**, because "this process wrote these bytes" is not a claim the mapping supports; a frame from a suppressed uniform table says its virtual address was **not enumerated** rather than showing one of its 512 addresses as if it were the one; a frame in the kernel's shared half is **one** row naming the spaces that reach it, never one row per process; an offset with no owner is **never** called free memory -- where any space fell short the row claims nothing and names the space, and where none did the sentence still states that the PFN database was not read and that a frame on the free list holds its last contents; the radix used and the proportion of the file rejected under it are on screen beside the answers. **Specification only -- not in the harness yet** (§9): no dedicated screen ships for this stage, so the records reach the generic memory record surface (§5.3, §3.8) |
| Memory ×7 | Process tree, VADs, handles, modules, cross-view, credentials **reveal**, **the per-lens type-ahead** | Unvalidated tier marked; reveal is audited; a lens filter states the rows it searched |
| **Memory: tampering** (`tampering`) | A process with a masquerading PEB path, one whose audit record could not be read, one with a length-invariant breach, and a process with a long (truncated) name | An `audit_path_differs` row shows **both** paths and says which of the two the process could have written; a process whose audit record was unreadable renders the check as **unmade**, not as clean; a length-invariant row is labelled a marker and carries `is_proof: false`; and a process whose name filled the kernel's fifteen-byte field is **not** rendered as a mismatch |
| **Memory: kernel tamper checks** (`tamper_checks`) | A capture where some groups ran and others did not; a group whose symbols are absent; a group whose detection is unwritten; a group that ran and found nothing; an unloaded table that is null; a timer table on a build with neither shape; a capture with no process list (the three thread groups); a debug-register row on a build declaring neither `DebugActive` nor `ActiveDR7`; an orphan row with an exclusion `not_assessed`; an ETW row that is `ordinary`, one that is a minority of the mode, one whose copy did not vote, and a process that could not be assessed; a skeleton-key result with no `lsass.exe` examined, and one with a clean `lsass.exe` | A group that did not run is **named with its reason** rather than rendered as an empty list, and the reasons — this build's symbols do not carry what the group needs, the detection is not written yet, and there was no process list to walk — are distinguishable on the screen; a group that ran and found nothing is distinguishable from all of them; an empty suspended list shows how many suspend counts were **read**, so "nothing was suspended" and "nothing could be read" are not the same screen; a stale debug-register slot is not rendered as a breakpoint and an `unconfirmed` row says so; an orphan **observation** is visually distinct from a **graded finding** and names the exclusion it could not assess; an ETW row shows which route made it a signal and an `ordinary` one is not rendered as "unpatched"; the count of processes the ETW check could not assess is on the screen beside the rows, never only in a detail pane; a skeleton-key result states on screen that one of its two routes did not run — a clean result there must not render as "no skeleton key" — and a run that examined no `lsass.exe` is visually distinct from one that examined it and found nothing; a range hit is labelled as a lead with both sides shown and never as a verdict; no unload or timer is shown with a date the record does not carry (§5.3) |
| Duplicates / Entities / Execution / System info | Group open, sort, drill-through, **filter by value** (Entities) | Slice vs case-wide stated; the entity filter says so too when the server capped the scan. **System info on a multi-acquisition case renders one compiled section per acquisition, each named**, and never a merged view: a merged answer to "what machine is this" withholds one machine's value when two disagree and presents one machine's value as the case's when they agree. Past ten acquisitions the page states how many it did not compile |
| Bookmarks / Filters / Hash sets | CRUD, import, apply, **filter the library** | A needle matching nothing says the library has filters and none matched, never "no filters" |
| Audit | Verify chain, **anchored verify**, filter, CSV export | Keyed/unkeyed wording; completeness "not checked" ≠ complete |
| Settings / Help | Access grants, shortcut list | Every documented shortcut has a handler |

---

## 7. Triage

### 7.1 A failing check is a claim about the product — verify it first

On the evidence so far, **a failing check is more often the check's fault than
the product's**: the interaction pass's first run failed seven of 39 and every
one was the assertion being wrong. Before recording a defect, open the screen
and read what it actually says. `interaction-report.json` stores the text each
verdict was based on precisely so this is possible.

A browser finding is one of:

- **Defect — false statement.** The screen asserts something untrue. HIGH,
  regardless of severity of the underlying data error.
- **Defect — false absence.** The screen implies nothing exists when something
  does, or a limit is presented as an end. HIGH.
- **Defect — correctness.** Wrong value, wrong sort, wrong link.
- **Usability.** True but hard to read, find or act on. Ranked by how central the
  task is.
- **Limitation.** Real, bounded, and *stated on screen*. Recorded in `BUGS.md`
  under the "weighed and deliberately not closed" convention, not fixed silently.


---

## 8. Running it

```bash
# 1. A server with real evidence (loopback only)
SEANCE_ADMIN_PASSWORD=... SEANCE_JWT_SECRET=$(openssl rand -hex 32) \
SEANCE_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \
SEANCE_EVIDENCE_ROOTS=$HOME/forensic_corpora \
  target/release/seance --port 8899 --web-root frontend/dist --workspace /tmp/ws

# 2. Ingest, then walk every screen. harness.mjs throws unless SEANCE_PASS is exported.
export SEANCE_PASS=...
node scripts/ui-tests/walk.mjs <case-id> <out-dir> 1440

# 3. Read out-dir/problems.txt, then the screenshots
```

Run it **alone**: a concurrent build or fuzz sweep starves the server and the
timeouts read as product failures.

### 8.1 CI

This layer is deliberately **not** in `scripts/ci-gate.sh` today: it needs a
built binary, a running server and a multi-gigabyte corpus that is not
redistributable. The route walk and interaction pass could run in CI against the
**golden multi-partition image** (316 KB, generated by
`scripts/build_golden_images.sh`), which is reproducible and small. That is the
recommended first CI step, with visual-regression baselines committed per
viewport.

---

## 9. Status and next steps

| Dimension | Status |
|---|---|
| A. Route coverage | Automated, 35 screens |
| D. Console/network hygiene | Collected; not yet asserted |
| E. Contrast | Automated and thorough (`contrast.test.ts`), and over **every palette** — the default plus six skins × light and dark — through one shared sweep in `composedContrast.ts` rather than a copy of it per palette (`themes/themes.contrast.test.ts`). The default is a light palette, which is why the canvas drawings were caught: a canvas has no `color:` for the sweep to read, and the Connections graph had been drawing near-white labels for anyone on a light skin |
| G. Locale | Two locales in the unit suite |
| B. Interaction pass | Automated, 39 checks |
| C. Layout geometry (overlap/clip/offscreen) | Exploratory tool; clean at 1280–1920px |
| J. Outlier-skewed time charts | Automated in the unit suite, three charts through one helper (`src/lib/focusWindow.ts`) — see below |
| B. Interaction pass — **Memory: pattern scan** | **Not implemented.** `pattern_scan` has no dedicated screen yet; the records reach the API and the generic memory record surface, so the §6 row for it is a specification the harness does not yet assert |
| B. Interaction pass — **Memory: strings over memory** | **Not implemented.** `strings_map` has no dedicated screen yet, for the same reason as the pattern scan beside it; the records reach the API at `/memory/strings-map` and the generic memory record surface, so the §6 row for it is a specification the harness does not yet assert |
| E. axe / keyboard | Not implemented |
| F. Viewports | Manual, one size |
| H. Performance budgets | Not implemented |
| I. Degraded states | Not implemented |
| J. Honesty assertions | Partly automated inside the interaction pass |

Ordered by value per unit of work: **finish the layout check** (page-level
scroll clipping) and run it on the golden image in CI, then **axe + keyboard**,
then degraded states, then performance budgets. Pixel baselines remain worth
having for the classes geometry cannot see — colour, contrast under overlap,
icon regressions — but they carry a dependency decision that is the owner's.

### 9.1 Running the interaction pass

```bash
SEANCE_PASS=... node scripts/ui-tests/interact.mjs <caseId> <outDir> [memoryCaseId]
```

It prints one line per check and writes `interaction-report.json` with the text
each verdict was based on. A failure is a **claim about the product** and must be
triaged as one: confirm against the screen before recording a defect, because on
the evidence so far a failing check is more often the check's fault.
