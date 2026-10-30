# Seance Frontend Conventions

React 19 + TypeScript + Vite SPA for the Seance digital-forensics platform.
Read this fully before writing any page code.

## Stack

- Routing: react-router-dom v7 (`useParams`, `Link`, `useSearchParams`)
- Server state: @tanstack/react-query v5 (`useQuery` / `useMutation` + `queryClient.invalidateQueries`)
- Tests: Vitest + React Testing Library + MSW v2 (`src/test/server.ts`; add per-test handlers with `server.use(...)`)
- No new dependencies. No CSS frameworks. No emoji in UI text.

## Design system

Examiner-workbench theme, light by default (`SKINS.opus.light`, written out in
`src/index.css` and pinned to the skin by `src/themes/defaultPalette.test.ts`).
Tokens in `src/index.css` (`--bg-0..3`,
`--border-0/1`, `--text-0/1/2`, `--accent`, `--ok`, `--warn`, `--danger`,
`--info`). Shared classes in `src/app/app.css`:

- Layout: `.page-title`, `.page-actions`, `.panel`, `.panel-title`
- Controls: `.btn`, `.btn-primary`, `.btn-danger`, `.input`, `.select`, `.link-button`
- Tables: `.data-table` (rows get hover; `.selected` for selection)
- Badges: `.badge`, `.badge-accent`, `.badge-danger`, `.badge-ok`
- States: `.empty-state` (with h3 + p), `.loading`, `.error-note`
- Modal: use the `Modal` component, not raw markup
- `.mono` for evidential data: hashes, offsets, IDs, timestamps, paths

Page-specific CSS goes in a `.css` file inside the page directory, imported
by the page component. Prefix classes with the page name (e.g. `.tl-` for
timeline) to avoid collisions.

## Rules that matter

1. **Timestamps are always UTC** — render with `formatUtc` (ISO strings) or
   `formatUtc(new Date(unixSeconds * 1000).toISOString())`; there is also
   `formatBytes` and `truncateHash` in `src/lib/format.ts`. Never render
   local time.
2. **No `location.reload()`** — mutations invalidate react-query keys.
3. **Every async view needs loading, error, and empty states.**
4. Exports/downloads: use `downloadFile` from `src/lib/download.ts`. It buffers
   in the tab by default, which is right for every small export. Pass
   `unbounded: true` only where the payload grows with the case — it opens a
   save-file picker and streams to disk where the browser can, and discloses the
   memory cost before buffering where it cannot. Pass `terminator` when the
   endpoint ends a whole file with a known marker: the helper then throws
   `DownloadIncompleteError` rather than reporting a fragment as a finished
   export, and the caller must say so on the page (a toast alone outlives
   nothing — the file is still on disk).
5. Toasts: `useToast()` from `src/components/toast/ToastProvider` —
   `toast.success/error/info`. Confirmation prompts: build a small confirm
   Modal, never `window.confirm`.
6. Query keys: prefix with the case id, e.g. `['timeline', caseId, params]`,
   `['bookmarks', caseId]`, `['tree', caseId]`, `['case', caseId]`.
7. TDD: write the page test first (MSW handlers for the endpoints, assert
   loading -> data render, one interaction, one error state), then the page.
   Tests live next to the page: `PageName.test.tsx`.
8. Accessibility floor: real `<button>`/`<label>`, `aria-label` on icon-only
   buttons, tables are real `<table>`.
9. **Adding or changing a colour means adding it to every skin.** Colours live
   in `src/index.css` (the default palette) and in `src/themes/palettes.ts`
   (six skins × light and dark). A `color:` written as a literal is invisible
   to the contrast guard, which measures only token-valued declarations, and
   it cannot invert with the theme — three rules hardcoded a near-black ink for
   an amber accent and became dark-on-dark the moment a light skin existed. Use
   a token. If a fill needs an ink of its own, that ink is a token too
   (`--on-accent`, `--on-danger`).
10. **Colour is gated, not reviewed by eye.** `src/app/contrast.test.ts` measures
   every declared pairing in every stylesheet under `src/` — a new `.css` file is
   covered the day it is added — plus a list of rendered surfaces, and holds
   small text to WCAG AA (4.5:1). `src/themes/themes.contrast.test.ts` runs the
   **same** sweep, from the same instrument, over all twelve palettes, so a skin is
   held to the floor the default palette is held to. It measures the ground the screen actually
   paints: tints, `opacity` and grounds painted by an ancestor are composited,
   and hover states are measured hovered. So define colours as tokens from
   `index.css`; add a page to that test's `RENDERED` list when its ground is
   painted by an ancestor rather than by the rule itself; and when a pairing
   genuinely cannot be measured, argue the exception in that test's own ledger
   (`UNMEASURABLE` / `NOT_APPLIED`) next to the assertion it weakens rather than
   weakening the instrument.

## Shared components

- `Modal` (`src/components/Modal.tsx`): `title`, `onClose`, `footer`
- `Pager` (`src/components/Pager.tsx`): `page`, `totalPages`, `onPage`, `totalCount?`
- `HexView` (`src/components/hex/HexView.tsx`): renders API hex responses
- `EvidenceTree`, `ProcessingPanel`, `IngestModal` exist — do not duplicate

## Shared primitives — reach for these before writing a fifth one

Each of these exists because the same problem was solved two or three times and
the copies drifted. The drift is never cosmetic here: two implementations of one
keyboard contract means a key quietly behaves differently in the tree an
examiner happens to be in, and two copies of a windowing rule means one of them
lets the rendered slice decide what is reachable. If you need the behaviour,
import it; if it needs a new capability, add it there and every surface gets it.

| Primitive | Where | Reach for it when |
|---|---|---|
| `VirtualRows` | `src/components/VirtualRows.tsx` | A `<tbody>` may hold more rows than a DOM can carry. Renders only the rows near the viewport with a spacer at each end. |
| `VirtualCells` | `src/pages/gallery/VirtualCells.tsx` | The same, for the media grid, where each cell also costs a query, an observer, an object URL and a decode. |
| `useRovingRows` | `src/hooks/useRovingRows.ts` | Any row list that should be **one** tab stop: ↑/↓, Home/End, Enter, real DOM focus, `onMove` for keyboard-only moves. |
| `useTreeKeyboard` | `src/components/tree/useTreeKeyboard.ts` | Any tree. The whole WAI-ARIA contract — ↑/↓, →/←, Home/End, type-ahead, Enter, Space — over the rendered `treeitem`s. |
| `BookmarksProvider` | `src/components/bookmark/BookmarksProvider.tsx` | A **table** of `BookmarkControl`s. Wrap it once so the case's bookmark list is fetched once and a row re-renders only when its own state changes. |
| The review ledger | `src/hooks/useReviewed.ts` | Recording or reading what has been opened and reviewed. `useReviewEntry` per row, `useReviewLedger` for the panel, `useReviewLedgerWriter` to write without subscribing. |
| `composedContrast` | `src/app/composedContrast.ts` | Writing or auditing a contrast test. It is the instrument the contrast guard measures with — never a runtime import. |
| `metadataMarker` | `src/pages/artifact/lib.ts` | Testing whether an artifact carries an **incompleteness or disclosure marker**. Presence, not type. Never `metadataBool` for these. |
| `useTheme` / `applyTheme` | `src/themes/` | Anything to do with the skin. `applyTheme` is the **only** place custom properties are written to the DOM; `useTheme` is the only place a component reads or changes the choice. A palette is data (`palettes.ts`), never a stylesheet, so that one contrast instrument can measure every one of them — see below. |
| `rampColor` / `rampSampler` | `src/lib/themeRamp.ts` | Any chart drawing a ramp from "nothing" to "everything". Both run `--bg-3` → `--accent`, so two charts cannot become two legends. `rampColor` for anything the browser resolves (SVG attributes, stylesheets); `rampSampler` for a **canvas**, which has no element to resolve `var()` against — a `color-mix(… var() …)` string assigned to `fillStyle` is a no-op and the map paints black (`UI-016`). |
| `LANE_COLORS` / `useLaneColors` | `src/themes/laneColors.ts` | Any chart needing **categorical** colours — one per source, per category, per lane. A categorical set cannot be derived from the tokens the way a ramp can (`rampColor`), so it is carried per mode: the same published hues in the same order, fitted to clear 3:1 against every surface of that mode. Measured by `laneColors.contrast.test.ts`. Never hand-roll a second array of hex literals for a chart (`UI-015`). |
| `useQuickFilter` / `QuickFilterBar` | `src/components/QuickFilter.tsx` | Any grid that should narrow as you type. One box, one wording, and one honesty rule: a client-side type-ahead filters **what is loaded**, not the case, so the bar states the population it searched and — when the caller passes `loadedIsSubset` — says the filter did not search the rest and that a missing row is not a row the case does not hold. Pass `loadedIsSubset` truthfully: it is how a grid comes to assert a population it does not have. |
| `useTimeWindow` / `TimeWindowBar` | `src/app/TimeWindowContext.tsx`, `src/components/TimeWindowBar.tsx` | Narrowing a screen by time. One window per case, set from the persistent bar in the case shell and read by any screen that can narrow itself. Two rules bind a consumer: a screen narrowed by it **must say so** — the window was set on another screen and followed the reader here, so unlike a filter they just set it is not self-evident — and a screen that does **not** honour it must not look as though it does, which is what `WINDOWED_SCREENS` is for. A local window set on the screen itself wins over the global one, because the examiner set it on the screen in front of them. |
| `focusWindow` | `src/lib/focusWindow.ts` | Any chart over a time axis. Decides which part of the range to draw when a FAT-epoch 1980 stamp or a corrupt far-future one would otherwise stretch the axis across decades and squash the case into one bar — and returns the counts that fall outside, which the chart **must** disclose. Used by `MiniTimeline`, `ActivityHistogram` and `EventHistogram` (which every rich-viewer chart and the communications volume chart draw through). Three charts deciding this independently is three chances for two of them to describe one case differently (UI-007). **The timeline's own two charts no longer decide it here**: `focus=auto` has the server choose the window *and* the bucket width for it, and the response says what is outside, so the resolution follows the window rather than the whole extent (`UI-010`). This helper stays for the charts with no server-side focus, and `seance_api`'s `focus_window` is its port — the two carry the same fixtures on purpose. |
| Stage viewers (`LinuxMemoryPathViewers`, `WindowsMemoryStageViewers`) | `src/pages/analysis/` | A record that is **one per stage** with its findings in a nested array (a memory stage's processes, mounts, pool entries, boot-sector candidates). The generic key/value table shows the counters and none of the rows, so each such type gets a viewer that flattens the array into one row per finding under the stage's own `statement`, printed verbatim. Three rules bind one: a check the build could not make renders as **not made**, never as passed (`null` is not a pass); every ceiling the stage hit is printed with its number, in the stage's own sentence where it wrote one; and a qualifier the stage put on a value — a path's `path_scope`, an XTS pair being an inference — is shown beside the value, because a relative path read as absolute names the wrong file. Rich and table viewers (`makeRichViewer`, `makeTableViewer`) stay the answer for one-record-per-finding types. |
| `SqliteQueryHistory` | `src/pages/analysis/SqliteQueryHistory.ts` | The model for **browser-local convenience state**: keyed by case id so two cases never mix, capped with the cap exported and printed on screen, every read validated shape-by-shape and an unreadable store read as empty rather than thrown, and the screen that shows it saying it is this browser only and not part of the case record. Anything an examiner would defend under oath — a review mark, a bookmark — goes to the server with the case (`useReviewed`), never here. |

Two rules bind the two windowing components, and both are tested. **Windowing
must not change what the examiner can reach**: pass `pinnedIndex` (the row or
cell the keyboard is on) so it is rendered wherever the scroll happens to be,
and keep the keys addressing the whole set. **Windowing must not present the
slice as the population**: rows carry `aria-rowindex` over the whole set, give
the `<table>` an `aria-rowcount` of `count + 1`, and never let a printed count
become a count of what is drawn.

`useRovingRows` and `useTreeKeyboard` share one consequence worth knowing before
you use either: **the row becomes the single tab stop, so the controls inside it
must leave the tab order** (`tabIndex={-1}`) and get a key on the focused row
instead. A page of 500 rows is otherwise 1,500 tab stops. Whatever key you add,
document it in the online help against the surface it works on — see
`src/pages/help/HELP_SYNC.md`.

**Read a disclosure marker with `metadataMarker`, never with `metadataBool`.**
Artifact metadata is written by ~100 plugins and the markers are not one type
across them: `compression_unsupported` arrives as a reason string from MFT
(`"ntfs_lznt1_oversize"`) and F2FS (`"f2fs"`), and as `true` from BTRFS.
`metadataBool` returns `null` for anything that is not a boolean, so a badge
gated on it renders for one filesystem and silently not for the others — which
is what happened: the "content unavailable" warning never appeared on an NTFS
artifact, and the badge gated on its negation told the examiner the content
*had* been decompressed. The backend has always tested these markers
with a type-agnostic `present()`; `metadataMarker` is that rule on the client
(`false`, `null`, `undefined` and `""` absent, anything else present). Reserve
`metadataBool` for fields that are a boolean at **every** producer, and check
that before you use it rather than assuming it. A marker that never fires is
invisible in review and in manual testing alike — it looks exactly like a clean
artifact — so it needs a test that feeds it every shape a producer emits.

The review ledger is a module-level store rather than a hook per component, and
the split matters: a component that only WRITES (recording an opening) takes
`useReviewLedgerWriter`, which never subscribes and never re-renders, and a row
takes `useReviewEntry`, whose snapshot is that row's own memoised entry — so a
mark on one row does not re-render the other 499. `useReviewLedger` reads the
whole roll-up and is for the panel only. Nothing in it is optimistic, nothing
retries on a timer, and `null` means *not known* everywhere it appears: read the
module comment before adding a caller.

## API

All endpoint wrappers are in `src/api/resources.ts`, typed by
`src/api/types.ts` (mirrors the Rust serde output exactly — check it before
inventing fields). Add missing wrappers there if needed. `apiFetch` handles
auth/CSRF/errors (`ApiRequestError` with `.code`, `.status`).

Route structure (`src/app/routes.tsx`):

- `/` cases list; `/login`
- `/cases/:caseId` shell (sidebar + custody strip) with children:
  index dashboard, `timeline`, `search`, `analysis`, `analysis/:type`,
  `gallery`, `geo`, `connections`, `execution`, `communications`, `duplicates`,
  `entities`, `system-info`, `memory` (with `image`, `processes`, `network`,
  `handles`, `system`, `credentials`, `findings`), `artifacts/:artifactId`,
  `files/:sourceId`, `bookmarks`, `filters`, `hash-sets`, `audit`, `settings`,
  `help`
- Each view has **one** address. The older `workbench?view=…` / `?type=…` form
  redirects onto it and must not be emitted by new code; an address inside a
  case that matches nothing renders `CaseNotFoundPage`, which keeps the case
  shell rather than throwing the examiner out to the bare 404.
- The rail is enumerated in `src/app/nav.ts` (`NAV_SECTIONS`) and the command
  palette's aliases in `src/app/commands.ts`. Add a view to both, and let the
  help's nav diagram derive itself from `NAV_SECTIONS` rather than restating it.

## Verify before finishing

Run `npx tsc -b` (must be clean) and `npx vitest run src/pages/<your-dir>`
(all green). Do not run the full suite repeatedly while iterating; run your
own directory, then one full `npx vitest run src` at the end.
