# Keeping the online help in sync

The online help (`HelpPage.tsx`) documents Séance's user-facing behaviour. Docs
drift in two distinct ways, and each needs a different mechanism, because only
one of them is mechanically decidable:

| Drift type | Example | Mechanism | Enforced by |
|---|---|---|---|
| **Coverage** — a capability exists in code but isn't documented, or is documented but was removed | VSS parsing shipped with no help mention | Automated coverage matrix | CI (fails the build) |
| **Accuracy** — a capability is documented but the description is *wrong* | BitLocker said "detect only" after decryption was added | Targeted fact-assertions + on-demand audit | CI (partial) + human/AI review |

Coverage is enumerable from the source tree, so it's a test. Accuracy is a
semantic judgement about prose, so it can't be fully automated — but it can be
pinned down for the facts that matter most, and re-audited on demand.

## Layer 1 — Coverage matrix (automated, CI-gated)

`help-coverage.test.ts` treats the **code as the source of truth** and asserts the
help covers every enumerable capability:

- **Parser plugins** — every `seance_plugin_*` crate must be mentioned (matched by
  a keyword), or be listed in `INTENTIONALLY_OMITTED` with a reason.
- **Evidence-container crates** — every `seance_container_*` crate must be mentioned.
- **Carving-signature count** — the number stated in the carving section must equal
  the count of `seance_carving/src/formats/*.rs` (minus `mod.rs`).

It also fails if a map entry references a plugin that no longer exists (so the
maps can't rot). It runs in the frontend CI job (`.github/workflows/test.yml`).

**When it fails:**
- *"plugin X not covered"* → document X in `HelpPage.tsx` and add its keyword(s) to
  `PLUGIN_HELP_KEYWORDS`, **or** add X to `INTENTIONALLY_OMITTED` with a reason.
- *"stale map entry"* → the plugin was removed; delete its map entry (and any help text).
- *"signature count mismatch"* → update the number in the carving section.

This is what catches the big class of drift: a new parser or container shipping
undocumented, or a removed one lingering in the docs.

## Layer 2 — Accuracy (targeted assertions + on-demand audit)

A coverage test can prove BitLocker is *mentioned*; it can't prove the mention is
*correct*. Two things address that:

1. **Fact-assertion tests** in `HelpPage.test.tsx` — for load-bearing, security-
   relevant, or historically-wrong claims, assert the *specific true statement*
   appears (e.g. BitLocker "Decrypt with password or recovery key", the admin
   bootstrap naming `SEANCE_ADMIN_PASSWORD` and the forced change, the absence of
   a `mactime` export control — the body file is served by the API and the REPL,
   and this UI has no button for it). Add one whenever you correct a factual error, so
   it can't silently regress. These run in CI.

2. **On-demand accuracy audit** — periodically (before a release, or after a batch
   of feature work), re-run a systematic section-by-section verification of the
   prose against the code. The proven approach: fan out one reviewer per section
   group, each instructed to *verify every claim against the code, never trust the
   help text*, and report `VERIFIED / STALE (with the correct value + file:line) /
   GAP (undocumented) / MISSING`. The section groups that map cleanly to reviewers:
   formats/encryption; carving/artifacts; timeline/search/browser/visualisers;
   analysis/mobile/entities/media; ingestion/users/settings/dashboard/reporting/
   integrity/shortcuts; review ledger/bookmarks. Apply the STALE findings, and
   turn each into a Layer-1 keyword or a Layer-2 fact-assertion so it stays
   fixed.

   Where each group's claims are actually decided, for the reviewer who has to
   read the handler and not the help: keyboard — `hooks/useRovingRows.ts`,
   `components/tree/useTreeKeyboard.ts`, `components/media/MediaGallery.tsx`,
   `pages/analysis/RecordTable.tsx`; search paging and exports —
   `pages/search/SearchPage.tsx`, `pages/search/HitsPager.tsx`,
   `lib/download.ts`, and `search_export_verdict` in `seance_api/src/lib.rs`;
   the review ledger — `hooks/useReviewed.ts` and
   `components/bookmark/ReviewMark.tsx`.

## Layer 3 — Derive, don't restate

A third class of drift showed up once the UI itself started changing: the help
kept its own hand-written copy of things the app already enumerates. The nav
diagram listed the rail's items, and when five analytical surfaces joined the
rail the diagram — in the one page an examiner opens *because* they cannot find
something — went on showing the old five. No coverage test caught it, because
nothing in `seance_*` had changed.

The rule: **anything the app can enumerate, the help imports rather than
restates.** `NavDiagram` builds its groups, its rows and its `aria-label` from
`NAV_SECTIONS`, so a rail item cannot exist without appearing in the help.
Where prose has to be written by hand — and it does, because a derived list is
not an explanation — pin it with a Layer-2 assertion driven by the same source:
`HelpPage.test.tsx` asserts that the *prose* of the navigation section names
every `NAV_SECTIONS` label, with the diagram excluded from the text it reads so
that the derived half cannot answer the question on the prose's behalf.

The same applies to documented KEYBOARD behaviour, which is not enumerable but
is checkable: read the handler before writing the row, name the surface the key
works on, and split the row when a key means different things on two surfaces
(Enter expands in the timeline and the audit log; it opens the artifact in
search, records and the file grid). A documented key that does nothing costs
more than an undocumented key that works, because the examiner concludes the
product cannot do it.

Two further things the handler decides and the row must therefore say:

- **What the key reaches is often smaller than what exists.** `End` in the media
  gallery moves to `items.length - 1`, and `items` is what the infinite scroll
  has fetched — so on a case of 4,000 images with 200 loaded it lands on the
  200th. "Jump to the last image" would be a false absence built out of a
  shortcut, so the row says *loaded*, says it is not the last item in the case,
  and points at the toolbar figure that gives the two numbers. The same
  distinction is why the data-tables `Home`/`End` row says "of the page you are
  on". Whenever a key's reach is a slice, name the slice.
- **A key that is offered on a family of surfaces must name the members that
  actually have it.** `c` copies the focused row's value on any `RecordTable`
  given a `copy` column, and exactly one view asks for one today (the
  geotagged-photograph EXIF records view, copying the coordinates). Documented
  as a key of "data tables" it would send an examiner pressing it on the
  timeline. Re-check the callers, not just the component, when that row is
  audited.
- **Windowing is a drawing decision and must never be documented as a limit on
  reach.** `VirtualRows` and `VirtualCells` render only the rows near the
  viewport, and both pin the row the keyboard is on (`pinnedIndex`) so it is
  drawn wherever the scroll happens to be. The keys therefore address the whole
  set the surface holds. What that SET is, is the thing that differs and the
  thing to write down: a page for the paged tables, everything fetched so far
  for the records viewer and the gallery.
- **The same key row can be wrong for one member of its own caption.** The
  data-tables `Home`/`End` row said "these tables are paged" over a caption that
  includes **Parsed records**, which is not paged at all — it loads instalments
  into one growing table, so `End` is the last row *loaded*. When a row covers
  five surfaces, check five.

## Layer 4 — A bound that moved is a claim that broke

The most dangerous sentences in this page are the ones that describe a **limit**,
because limits are exactly what gets raised, lifted or replaced — and unlike a
removed capability, a lifted ceiling leaves the old sentence looking perfectly
plausible. It understates the product to an examiner who will act on it: someone
who reads that an export "stops at a ceiling" will narrow their query, or tender
a smaller exhibit, for a reason that has ceased to exist.

Two of these are worth keeping in view when this page is audited:

- **The search export.** It walks the whole match set by cursor, states `row_limit: none` in its own
  preamble, and ends every file — including a complete one — with a verdict row
  (`### END OF EXPORT ###`). Verdicts: `COMPLETE`,
  `COMPLETE, STATED TOTAL WAS A FLOOR`, `INCOMPLETE` with a named cause. Read
  `search_export_verdict` in `seance_api/src/lib.rs` before writing anything
  about what an exhibit covers.
- **The paging ceiling.** `max_offset` bounds a *jump*, not the evidence:
  `next_cursor` resumes where the last page stopped, so `Next` walks past it.
  Anything that says matches beyond the ceiling are unreachable is a false
  absence, which is the worst class of error this page can make.

The reverse also holds: a bound that is still there must not be flattened away.
A floored match count (`count_is_lower_bound`) has three causes, and only one of
them — an index known to be missing documents — means rows are gone; the help
says the screen cannot tell which, because it cannot, and points at the export's
verdict row, which can.

When you document a limit, name the file that enforces it in the commit message,
so the next person auditing the sentence knows where to check whether it still
binds.

## Adding a new capability — the checklist

1. Document it in `HelpPage.tsx`.
2. Add its plugin/container to the relevant map in `help-coverage.test.ts` (or the
   coverage test will fail — that's the point).
3. If the claim is a specific fact that must not regress, add an assertion to
   `HelpPage.test.tsx`.
4. If the app can enumerate it (nav items, record categories, profile names),
   import the enumeration into the help instead of typing it out again.
