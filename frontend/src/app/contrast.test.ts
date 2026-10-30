import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { createElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { ContextMenu } from "../components/ContextMenu";
import { ProcessingPanel } from "../components/processing/ProcessingPanel";
import { ToastProvider } from "../components/toast/ToastProvider";
import { initialProcessingFor } from "../hooks/processing";
import type { ParsedRecord, RecordMetadata } from "../pages/analysis/api";
import type { Column } from "../pages/analysis/cells";
import { PlistViewer } from "../pages/analysis/PlistViewer";
import { RecordTable } from "../pages/analysis/RecordTable";
import { StatTiles, TopBars } from "../pages/analysis/RichCharts";
import { FileTree } from "../pages/files/FileTree";
import type { FileRow } from "../pages/files/types";
import { server } from "../test/server";
import {
  AA_SMALL_TEXT,
  TRANSPARENT,
  asHovered,
  chainOf,
  composite,
  conditionalColourRules,
  contrastRatio,
  drawnAt,
  flatten,
  inkOf,
  markHovered,
  nameOf,
  paletteFailures,
  premul,
  resolveColor,
  resolveInk,
  styleReader,
  styleRules,
  surfacesOf,
  textUses,
  tokens,
  unparseable,
} from "./composedContrast";
import type { Ink } from "./composedContrast";

/**
 * Guards the one property of the palette that is not a matter of taste: every
 * text tone must stay legible on every surface it can land on.
 *
 * Every screen in this product can be screenshotted into a witness statement,
 * and examiners work eight-hour days in dim rooms; a tone that drifts under the
 * WCAG AA floor is a fatigue tax on all of them and a barrier for low-vision
 * examiners. So the floor asserted here is the small-text one, 4.5:1, with no
 * large-text exemption path: these tokens carry 9–12px data-bearing text in
 * several places, far under the 18.66px at which the 3:1 exemption would begin,
 * so no font-size change could make a failing value conformant.
 *
 * THE SET OF TOKENS IS DERIVED, NOT LISTED. An earlier version of this file
 * named the tokens it checked — three text tones, then four semantic tones —
 * and a list is only ever as good as whoever last thought about it. It missed
 * --accent-dim, which was a real `color:` on the 12px byte offsets in the hex
 * viewer and measured 3.49:1 on --bg-0: a worse failure than either token that
 * version was written to pin. Worse than missing it, the file read as coverage
 * while doing so. So the tokens are now read out of the stylesheets themselves.
 * Every token appearing in a `color:` declaration anywhere under src/ answers to
 * the floor, and a token nobody thought to enumerate cannot escape it.
 *
 * THE GROUND IS DERIVED TOO, after the same lesson arrived a second time. The
 * version that derived its tokens still assumed a background was either opaque
 * or absent, so a rule painting `background: var(--danger-bg)` — a 12% tint —
 * was measured against the bare surface underneath instead of against the
 * composite. On a dark palette that is the wrong direction: a light tint
 * LIGHTENS the surface, so the composite is a worse ground than the surface,
 * and `.error-note` measured 4.04:1 on --bg-3 while this file called it 4.73
 * and passed. A translucent ground is now resolved over each opaque surface and
 * the floor is applied to what is actually drawn.
 *
 * REPRODUCED APPEARANCE IS DELIBERATELY EXEMPT, and this is a decision that was
 * taken, not a case nobody looked at. The `.an-theme-*` rules in
 * pages/analysis/analysis.css pair `color: #fff` with the real bubble colours
 * of the messaging apps they render — 1.98:1 for .an-theme-whatsapp on
 * #25d366, the worst of them, and .an-theme-sms, -kik, -line, -wechat, -skype,
 * -twitter, -telegram, -messenger, -imessage and -viber all under the floor
 * too. They are not this tool styling a surface; they are the tool reproducing
 * what the device showed the people in the conversation, on a page whose whole
 * claim is "this is what it looked like". Recolouring them to pass a contrast
 * check would show the examiner a rendering no participant ever saw — a
 * better-looking lie — and where the pixels ARE the evidence, fidelity to the
 * evidence outranks this tool's own accessibility obligation.
 *
 * The exemption is conditional on the content being readable somewhere that is
 * not the reproduction, and it is: selecting a message renders its full body in
 * the properties inspector as `.an-props-text`, which is --text-0 on --bg-1 at
 * 13.68:1 and is measured by this file like any other pairing. The bubble is
 * `tabIndex={0} role="button"`, so that reading is reachable by keyboard, and
 * double-click opens the message as a full artifact besides. Only the sent side
 * is themed at all; a received bubble is --bg-2. If that inspector ever stops
 * carrying the body, this exemption stops standing and the failure becomes
 * real. There is deliberately no toggle that recolours the bubbles: a control
 * that makes evidence look different on demand is one somebody screenshots in
 * the wrong state.
 *
 * WHAT THIS DOES NOT COVER, stated so the file is not read as more than it is,
 * and stated with the numbers so it cannot be read as "probably fine":
 *
 *  - Hardcoded colours generally. Only token-valued `color:` declarations are
 *    measured, so any `color: #fff` is invisible here — the themed bubbles
 *    above are the ones that were audited by hand, not the limit of what the
 *    mechanism misses.
 *  - Grounds an ancestor paints, on any page that is not rendered. The half of
 *    this file below traces them, but only through a document, and only for
 *    the surfaces listed in RENDERED. Everywhere else a ground painted by an
 *    ancestor is still untraced, and text with no ground of its own is still
 *    measured against all four bare surfaces — the strict reading, which can
 *    overstate a failure and, worse, miss the reverse.
 *
 *    A live one, with the numbers, so this is not read as theoretical:
 *    `.data-table tbody tr.selected` in app/app.css fills a selected row with
 *    --accent-bg, a 12% amber tint, and sets no text of its own. --text-2 over
 *    that tint measures 5.13 / 4.72 / 4.35 / 3.88 on --bg-0..--bg-3: under the
 *    floor on two of the four surfaces. Thirty-five rules across twelve
 *    stylesheets fill something with --accent-bg this way. Whether any of them
 *    bites depends on which surface each table is drawn on and on whether a
 *    quiet tone lands in one of its rows, and neither question has an answer
 *    in a stylesheet — which is the whole reason the second half of this file
 *    exists, and the reason its RENDERED list is worth extending.
 *
 *    That rule has since been settled where it is drawn, and so have the other
 *    --accent-bg tints outside pages/files and pages/search: see THE
 *    --accent-bg TINT SWEEP below, which renders each candidate rather than
 *    reasoning about it, and which found exactly two failures — both of them
 *    tints composited over a --bg-2 HOVER fill rather than replacing an opaque
 *    one. This paragraph stays as written because it is still true of every
 *    --accent-bg rule on a page nobody has added to RENDERED.
 *
 *    The example that used to stand here — .ft-row.selected's --accent-dim
 *    fill under --text-1 at 2.86:1 — was a real failure and is fixed: the
 *    tones on a selected file-tree row are --text-0 at 4.87:1 now, and
 *    files.css restates the fill on the rules that set them so that this half
 *    measures the pairing directly. It is recorded here as history rather than
 *    deleted, because a reader who finds the old claim in a commit needs to
 *    know it was answered rather than lost.
 *  - Inline styles and canvas. Anything a component sets in JS or paints itself
 *    is outside a stylesheet and outside this test.
 */

/**
 * Token-valued `color:` declarations that resolve to no measurable colour,
 * keyed by the declaration exactly as written, with why it cannot be measured.
 *
 * Both directions are asserted: an entry that no longer appears in the CSS is a
 * stale excuse and fails, and a new unmeasurable declaration that nobody has
 * justified fails too. That is the whole point — silence is what let
 * --accent-dim through.
 */
const UNMEASURABLE: Record<string, string> = {
  // Empty, and meant to stay that way. The one entry that lived here excused
  // `.av-tamper`'s `color: var(--text, inherit)` in pages/artifact/artifact.css
  // — a colour the guard could not read at all, on the notice that says an
  // image's pixels disagree with its EXIF. It has been resolved to --text-0,
  // which is what the rules around it use and what the `inherit` was picking up
  // anyway, so the tamper alert is now measured like every other text in the
  // product instead of being taken on trust.
};

describe("design token contrast", () => {
  const map = tokens();

  // The surfaces are derived, not listed: a palette that grows a --bg-4 must
  // not widen the set of grounds text can land on without widening what is
  // checked. Derived by the shared instrument, so every skin is measured
  // against the same rule as the default palette.
  const SURFACES = surfacesOf(map);

  it("finds the surfaces, the text tones and the tints in the stylesheets", () => {
    // A guard that silently found nothing to check would pass forever, which is
    // the failure mode this whole file was rewritten to escape. A guard whose
    // tint branch never runs is the same failure, one level down.
    expect(SURFACES.length).toBeGreaterThanOrEqual(4);
    const uses = textUses(map);
    expect(uses.length).toBeGreaterThan(50);
    const composited = uses.filter(
      (use) =>
        use.ground.kind === "painted" &&
        use.ground.layers.some((layer) => layer.alpha < 1),
    );
    expect(composited.length).toBeGreaterThan(0);
  });

  it("accounts for every token-valued color it cannot measure", () => {
    const uses = textUses(map);
    const unresolved = new Set(
      uses
        .filter((use) => resolveInk(use.value, map) === null)
        .map((use) => use.value),
    );
    // Nothing unexplained: a new one has to be justified here, in words, before
    // it can sit outside the floor below.
    expect([...unresolved].sort()).toEqual(Object.keys(UNMEASURABLE).sort());
    // Both sides of that comparison are empty today, and two empty lists match
    // whether the guard measured six hundred declarations or none at all. So
    // the population is stated: the empty result above is a statement about
    // this many declarations that the resolver did read, not about silence.
    const resolved = uses.filter((use) => resolveInk(use.value, map) !== null);
    expect(resolved.length).toBeGreaterThan(50);
  });

  it("accounts for every ground it cannot read", () => {
    // Symmetrical to UNMEASURABLE, and empty: a background written in a form
    // the resolver does not understand is a blind spot of exactly the kind the
    // tint one was, so the fix is to teach the resolver rather than to write an
    // excuse. This assertion is what stops the excuse being silence.
    const unreadable = new Set(
      textUses(map)
        .map((use) => use.ground)
        .filter(
          (ground): ground is { kind: "unreadable"; value: string } =>
            ground.kind === "unreadable",
        )
        .map((ground) => ground.value),
    );
    expect([...unreadable].sort()).toEqual([]);
  });

  it("reads the opacity of every rule that fades its own text", () => {
    const uses = textUses(map);
    // Symmetrical to the two ledgers above. An `opacity` written in a form the
    // resolver cannot read would fall out of the floor silently, which is the
    // shape of every hole this file has had.
    expect(
      uses
        .filter((use) => use.opacity === null)
        .map((use) => `${use.where}: opacity ${use.opacityValue}`)
        .sort(),
    ).toEqual([]);
    // `opacity: 0` is skipped by the floor — there is no text on screen to
    // measure — so it is named here rather than being one more thing that
    // passes by not being looked at.
    expect(
      uses
        .filter((use) => use.opacity === 0)
        .map((use) => use.where)
        .sort(),
    ).toEqual([]);
    // And the population, so the empty lists above are a statement about rules
    // that were read.
    //
    // Named, not counted. `.processing-conn` was removed from this list when
    // the skins arrived — it drew --warn at 0.8 on the badge that says the live
    // connection has dropped, which lands at 3.3:1 on a light surface — and
    // `.version-banner-dismiss` joined it, because restating that rule's ground
    // let the guard measure a fade a literal `color:` had hidden from it.
    //
    // This used to assert only that the population was non-empty, which made
    // the fade branch's coverage depend on a stylesheet accident: removing the
    // last faded rule broke the assertion rather than the guard. The branch is
    // exercised deliberately now, by the synthetic case below, and this lists
    // what the product actually fades so that a new one is a visible change
    // rather than a silent addition to a count.
    const faded = uses.filter(
      (use) => use.opacity !== null && use.opacity > 0 && use.opacity < 1,
    );
    expect(faded.map((use) => use.where).sort()).toEqual([
      "components/version-banner.css:58",
    ]);
  });

  it("still measures a faded rule correctly when one exists", () => {
    // The branch above has no rule in the product to exercise it. Rather than
    // let it pass by having nothing to do — the failure mode this whole file
    // was rewritten to escape — the arithmetic is put to it directly: --text-2
    // at 60% opacity on --bg-3, which is the shape that hid `.an-db-col-hide`
    // at 2.66:1 while the token itself measured 4.83 there.
    const surface = resolveColor(map.get("--bg-3") as string, map) as string;
    const ink = resolveInk(map.get("--text-2") as string, map) as Ink;
    const bare = contrastRatio(ink.hex, surface);
    const nothing: Ink = { hex: "#000000", alpha: 0 };
    const { fg } = drawnAt(ink, nothing, 0.6, surface);
    const drawn = contrastRatio(fg, surface);

    expect(bare).toBeGreaterThanOrEqual(AA_SMALL_TEXT);
    expect(drawn).toBeLessThan(bare);
    expect(drawn).toBeLessThan(AA_SMALL_TEXT);
  });

  it("holds every token used as text to WCAG AA on every ground it can meet", () => {
    // The sweep itself lives in `composedContrast.ts` so that the skins in
    // `src/themes/palettes.ts` are measured by this instrument rather than by a
    // second copy of it — a dozen palettes and a dozen copies would be a dozen chances for
    // one of them to drift into passing what the others catch.
    expect(paletteFailures(map)).toEqual([]);
  });

  it("keeps the three text tones visibly distinct from one another", () => {
    const bg = resolveColor(map.get("--bg-0") as string, map) as string;
    const ladder = ["--text-0", "--text-1", "--text-2"].map((t) =>
      contrastRatio(resolveColor(map.get(t) as string, map) as string, bg),
    );
    // Strictly descending: text-0 is the loudest, text-2 the quietest. A
    // contrast fix that flattens the hierarchy would make every screen shout.
    expect(ladder[0]).toBeGreaterThan(ladder[1]);
    expect(ladder[1]).toBeGreaterThan(ladder[2]);
  });
});

// ---------------------------------------------------------------------------
// The other half: grounds painted by an ancestor.
// ---------------------------------------------------------------------------

/**
 * Everything above measures the ground a rule paints for its OWN text. Text
 * whose ground comes from an ancestor is invisible to it, and that is not a
 * gap a stylesheet pass can close from the stylesheets: whether `.tl-star`
 * lands on `--accent-dim`, on a 12% amber tint or on the bare page depends on
 * what is above it in the tree, and a `.css` file does not say what is above
 * what. It takes a rendered document to answer, so this half renders one.
 *
 * This mechanism was prototyped in pages/files/selectedRowContrast.test.tsx,
 * scoped to the file tree, and is lifted here so that it is defined once and so
 * that the next page to need it adds a line to RENDERED rather than a second
 * copy of the resolver. (The prototype carried its own duplicate of every
 * function above — two resolvers with one set of honesty conventions between
 * them is a drift waiting to happen, and the drift would have been silent.)
 *
 * The walk is deliberately conservative, because a guard that cries wolf gets
 * turned off and a guard that is off is worse than one with a known blind spot:
 *
 *  - only elements with a `color` rule of ther own are measured. Text that
 *    merely inherits a colour is left to the element that declared it.
 *  - a ground that does not resolve to one opaque colour — a gradient, a value
 *    the resolver cannot read, a chain that never reaches an opaque layer — is
 *    reported by name rather than guessed at, and each report is asserted
 *    empty. Guessing is how a false positive gets built.
 *  - `:focus-visible`, `:active` and the rest do not match an element that is
 *    not in that state, and jsdom puts nothing in one, so a rule under those
 *    is measured only by the stylesheet pass — which holds a rule's own text
 *    to the same floor against every surface its own fill can sit on.
 *
 *    `:hover` is the exception, because for `:hover` that is not enough. A
 *    hover fill is a ground an ancestor paints, and text INSIDE the hovered
 *    element is exactly what the stylesheet pass cannot reach: it sees
 *    `.ctx-menu-note`'s --text-2 and four bare surfaces, not the 12% amber the
 *    item above it paints while the pointer is on it. So a RENDERED entry may
 *    name the element under the pointer, and `asHovered`/`markHovered` put the
 *    document into that state before it is walked — the element and its
 *    ancestors, as a browser hovers them. Entries that name nothing are
 *    measured at rest, as before.
 *  - a ground painted by a SIBLING is still invisible. The climb walks
 *    `parentElement`, so an absolutely-positioned fill drawn under text it does
 *    not contain — `.rv-top-bar`, the frequency chart's bar, at z-index 0 with
 *    the row's labels over it at 1 — is walked straight past, and every number
 *    this half prints for those labels is optimistic by whatever that fill
 *    contributes. There is no general fix here: which sibling is behind which
 *    glyph is a question about layout, and jsdom performs none. The one place
 *    it bites is asserted by hand instead, in `names the ground a sibling bar
 *    paints…` below, with the composite spelled out.
 */

/**
 * Every rule this half drops for being inside an at-rule it cannot evaluate,
 * and that would have changed what it measures.
 *
 * Dropping a rule is as capable of producing a wrong number as applying one, so
 * the drops are enumerated and each is argued in {@link NOT_APPLIED}. The
 * comparison runs both ways: an entry that no longer matches any rule is a
 * stale excuse and fails too.
 */
const NOT_APPLIED: Record<string, string> = {
  // The only one, and it changes nothing this half measures: it sets no
  // colour and no ground, and the element it fades is a loading placeholder
  // that never contains text — the bar IS the content. Applying it anyway
  // would fade a `.skeleton` for every reader, including the majority who
  // have expressed no motion preference at all, and would then measure the
  // shimmer gradient's stops against a floor written for text.
  "components/skeleton.css: @media (prefers-reduced-motion: reduce) { .skeleton }":
    "sets opacity on a text-free loading placeholder; no colour, no ground",
};

const CASE_ID = "case-1";
const SOURCE_ID = "source-1";

function fileRow(
  partial: Partial<FileRow> & { id: string; name: string; path: string },
): FileRow {
  return {
    parent_id: SOURCE_ID,
    extension: null,
    size: null,
    created: null,
    modified: null,
    accessed: null,
    is_directory: false,
    is_deleted: false,
    known_status: null,
    ...partial,
  };
}

// One row of every kind the tree can draw, so that every tone it can put on a
// row is on screen to be measured: a folder (its caret and its folder glyph), a
// plain file, a deleted one (struck through, in the danger tone, with its
// Deleted badge), a notable hash-set hit, and a folder the parser could not
// finish enumerating (the incompleteness badge).
const TREE_ROWS: FileRow[] = [
  fileRow({
    id: "windows",
    name: "Windows",
    path: "/Windows",
    is_directory: true,
  }),
  fileRow({
    id: "short",
    name: "Users",
    path: "/Users",
    is_directory: true,
    metadata: {
      directory_parse_incomplete: true,
      directory_parse_incomplete_reason: "fat_chain_incomplete",
    },
  }),
  fileRow({ id: "boot", name: "boot.ini", path: "/boot.ini", size: 512 }),
  fileRow({
    id: "secret",
    name: "secret.pdf",
    path: "/secret.pdf",
    size: 4096,
    is_deleted: true,
  }),
  fileRow({
    id: "evil",
    name: "evil.exe",
    path: "/evil.exe",
    size: 2048,
    known_status: "notable",
  }),
  fileRow({
    id: "carved",
    name: "carved_0001.jpg",
    path: "/carved_0001.jpg",
    size: 1024,
  }),
];

interface Mounted {
  /** The subtrees to walk. */
  roots: Element[];
  unmount: () => void;
}

/** One surface to render, walk and measure. */
interface RenderedSurface {
  name: string;
  mount: () => Promise<Mounted>;
  /**
   * A selector for the element the pointer is over, if this surface is to be
   * measured hovered rather than at rest.
   *
   * Present only where the hover state changes a GROUND rather than a colour.
   * A rule's own `color:` under `:hover` is the stylesheet pass's business and
   * it holds it to the same floor; what that pass cannot do is measure text
   * inside a hovered element, because the fill is one element up. Every entry
   * that sets this names, in its comment, the pairing that only exists here.
   */
  hover?: string;
}

/**
 * The surfaces this half renders and walks.
 *
 * It is a list, and a list is only ever as good as whoever last thought about
 * it — which is the criticism the stylesheet pass above was rewritten twice to
 * escape. The difference is that this list is honest about being one: what is
 * on it is measured as drawn, what is not is measured by the stylesheet pass
 * against all four bare surfaces, and the file's own doc comment says which
 * pages those are. Adding a page here is one entry.
 */
const RENDERED: RenderedSurface[] = TREE_ROWS.map((row) => ({
  name: `the file tree, ${row.name} selected`,
  mount: async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/sources/${SOURCE_ID}/files`, () =>
        HttpResponse.json({
          items: TREE_ROWS,
          total_count: TREE_ROWS.length,
          page: 1,
          page_size: 1000,
          total_pages: 1,
          has_next: false,
          has_previous: false,
        }),
      ),
    );
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    // `.ft-wrap` is the surface the tree is drawn on, and it is painted by
    // FileGridPage rather than by FileTree; without it the climb would go
    // past the panel to the body and measure against the page instead.
    const view = render(
      createElement(
        QueryClientProvider,
        { client: queryClient },
        createElement(
          "div",
          { className: "ft-wrap" },
          createElement(FileTree, {
            caseId: CASE_ID,
            sourceId: SOURCE_ID,
            selectedId: row.id,
            onSelect: () => {},
            onOpen: () => {},
          }),
        ),
      ),
    );
    await screen.findByText("Windows");
    return {
      roots: [document.querySelector(".ft-wrap") as Element],
      unmount: () => view.unmount(),
    };
  },
}));

/**
 * The property-list viewer, for the OTHER shape of ancestor ground: a tint.
 *
 * The file tree above fills its selected row with an opaque --accent-dim, so
 * the climb finds a ground and stops. A tint does not stop it — `.an-plist-item
 * .selected` paints --accent-bg, 12% amber, which is not a ground but a change
 * to whatever ground is already there, and the tone lands on the composite.
 * That is worth having a rendered case of, because the arithmetic is
 * surface-dependent in a way an opaque fill is not: --text-2 over that tint
 * measures 5.13 / 4.72 / 4.35 / 3.88 on --bg-0..--bg-3, so the same rule
 * passes on two surfaces and fails on two.
 *
 * Which one it lands on is the thing only a document answers, and the answer
 * here is --bg-1: `.an-plist-item.selected` REPLACES the --bg-1 that
 * `.an-plist-item` paints on the same element rather than sitting on top of
 * it, so the tint composites over the `.panel` that RecordsViewerPage wraps
 * every viewer in. The panel is reproduced here for the same reason `.ft-wrap`
 * is: without it the climb would reach the body and measure this against the
 * page surface, which is not where an examiner ever sees it.
 */
const PLIST_RECORDS: ParsedRecord[] = [
  {
    id: "p1",
    parent_id: "a-p1",
    artifact_type: "ParsedRecord",
    metadata: {
      type: "PlistFile",
      filename: "com.apple.wifi.plist",
      plist_type: "binary",
      content: { SSID: "CAFE-GUEST", LastJoined: 1_700_000_000 },
    },
  },
  {
    id: "p2",
    parent_id: "a-p2",
    artifact_type: "ParsedRecord",
    metadata: { type: "PlistFile", filename: "preferences.plist" },
  },
];

/**
 * Two photographs with coordinates, one of them missing the camera make.
 *
 * The second is what makes the first row NOTABLE as well as selected, which is
 * the pair of rules `.an-wt-row.selected` was deliberately ordered after
 * `.rv-notable` for: a row can be both, and the selection has to win or the
 * examiner's own pick stops reading as picked.
 */
const GPS_RECORDS: ParsedRecord[] = [
  {
    id: "g1",
    parent_id: "a-g1",
    artifact_type: "ParsedRecord",
    metadata: {
      type: "ExifData",
      filename: "IMG_0001.HEIC",
      make: "Unknown",
      gps_latitude: 51.5014,
      gps_longitude: -0.1419,
    },
  },
  {
    id: "g2",
    parent_id: "a-g2",
    artifact_type: "ParsedRecord",
    metadata: {
      type: "ExifData",
      filename: "IMG_0002.HEIC",
      make: "Apple",
      gps_latitude: 48.8584,
      gps_longitude: 2.2945,
    },
  },
];

const GPS_COLUMNS: Column[] = [
  {
    key: "filename",
    header: "File",
    render: (meta: RecordMetadata) => String(meta.filename ?? ""),
  },
  {
    key: "make",
    header: "Camera",
    render: (meta: RecordMetadata) => String(meta.make ?? ""),
  },
  {
    key: "coords",
    header: "Coordinates",
    render: (meta: RecordMetadata) =>
      `${meta.gps_latitude}, ${meta.gps_longitude}`,
  },
];

/**
 * The processing panel, which is where `opacity` is load-bearing in this
 * product rather than decorative.
 *
 * Two of its rules fade text they do not colour: `.processing-close` sets
 * `color: inherit` and `opacity: 0.55`, and `.processing-module-line.stale`
 * sets an opacity and nothing else, over a line whose tones come from
 * `.processing-module-name` and its siblings. Neither is visible to the
 * stylesheet pass — one has no token in its `color`, the other has no `color`
 * at all — and both are exactly the case the climb was taught to fold. This is
 * an S1 triage surface: it is what an examiner reads to decide whether an
 * ingest will finish before an interview starts.
 */
RENDERED.push({
  name: "the processing panel, reconnecting with a stale module line",
  mount: async () => {
    const now = Date.now();
    const view = render(
      createElement(
        ToastProvider,
        null,
        createElement(ProcessingPanel, {
          state: {
            ...initialProcessingFor(CASE_ID),
            active: true,
            phase: "Extract",
            processed: 42,
            connectionState: "reconnecting" as const,
            modules: {
              "mft:art-1": {
                moduleId: "mft",
                artifactId: "art-1",
                unitsDone: 512,
                unitsTotal: 1024,
                unit: "bytes",
                updatedAt: now,
              },
              "registry:art-2": {
                moduleId: "registry",
                artifactId: "art-2",
                unitsDone: 7,
                unitsTotal: null,
                unit: "items",
                updatedAt: now - 90_000,
              },
            },
          },
        }),
      ),
    );
    await screen.findByText("registry");
    return {
      roots: [document.querySelector(".processing-panel") as Element],
      unmount: () => view.unmount(),
    };
  },
});

RENDERED.push({
  name: "the processing panel, a finished run the operator may dismiss",
  mount: async () => {
    const view = render(
      createElement(
        ToastProvider,
        null,
        createElement(ProcessingPanel, {
          state: {
            ...initialProcessingFor(CASE_ID),
            complete: true,
            phase: "Complete",
            processed: 1204,
            durationMs: 61_000,
          },
        }),
      ),
    );
    await screen.findByLabelText("Processing activity");
    return {
      roots: [document.querySelector(".processing-panel") as Element],
      unmount: () => view.unmount(),
    };
  },
});

const PLIST_SURFACE: RenderedSurface = {
  name: "the plist viewer, first entry selected",
  mount: async () => {
    const view = render(
      createElement(
        "div",
        { className: "panel" },
        createElement(PlistViewer, {
          records: PLIST_RECORDS,
          caseId: CASE_ID,
          type: "PlistFile",
        }),
      ),
    );
    await screen.findByText("com.apple.wifi.plist");
    return {
      roots: [document.querySelector(".panel") as Element],
      unmount: () => view.unmount(),
    };
  },
};
RENDERED.push(PLIST_SURFACE);

/**
 * THE --accent-bg TINT SWEEP.
 *
 * Thirty-odd rules across the product fill something with --accent-bg, a 12%
 * amber tint, and the ones that set no text of their own hand their ground to
 * whatever is behind them. --text-2 over that tint measures 5.13 / 4.72 / 4.35
 * / 3.88 on --bg-0..--bg-3, so those rules are conformant or not according to
 * a fact no stylesheet states. The entries below settle the ones that were
 * left open, and the reasoning that narrowed the list to them is worth keeping
 * because it is what stops this becoming a sweep that restyles on suspicion:
 *
 *  - MOST selected-state tints REPLACE an opaque fill on the same element.
 *    `.an-thread`, `.an-mail-item`, `.an-db-table`, `.an-plist-item` and
 *    `.rv-stat` each paint --bg-1 and then swap it for the tint, so the tint
 *    composites over the CONTAINER — the `.panel` every records viewer is
 *    wrapped in, at --bg-1, where --text-2 clears at 4.72. PLIST_SURFACE above
 *    proves that composite with the instrument rather than by reading CSS, and
 *    the other four are the same rule shape in the same container.
 *  - A hover fill does NOT get to be that container, everywhere it was
 *    checked. `.an-thread:hover`, `.an-db-table:hover`, `.an-mail-item:hover`,
 *    `.an-plist-item:hover`, `.rv-stat:hover`, `.side-link:hover`,
 *    `.ingest-entry:hover` and `.data-table tbody tr:hover` all paint --bg-2 at
 *    the same specificity as the tint rule beside them and all lose to it on
 *    source order, so hovering a selected row does not put the tint on --bg-2.
 *  - Which leaves the two places where a tint composites over a hover fill
 *    instead of replacing it, because the tint is on a DIFFERENT element from
 *    the hover: `.ctx-menu-item:hover` inside `.ctx-menu` (--bg-2), and
 *    `.rv-top-bar` inside `.rv-top-row:hover` (--bg-2). Both are below.
 *
 * pages/gallery/gallery.css and pages/entities/entities.css use --accent-bg
 * nowhere at all, so there was nothing to settle there.
 */

/**
 * The context menu, with an item under the pointer.
 *
 * This is the one --accent-bg tint in the product that composites over a
 * --bg-2 container, and it is invisible to both halves of this file without
 * the hover probe: the stylesheet pass measures `.ctx-menu-note`'s --text-2
 * against the four bare surfaces (6.15 / 5.80 / 5.39 / 4.83, all clear) and
 * the resting document never applies the hover fill at all. Drawn, the note
 * sits on 12% #e5a13c over `.ctx-menu`'s --bg-2 — #322e29 — where --text-2 is
 * 4.35:1.
 *
 * It is not a decorative sub-label. The gallery puts the artifact's id in it
 * and the evidence navigator puts a module's execution mode there, both at
 * 10.5px: identifiers an examiner reads off the screen and quotes.
 */
RENDERED.push({
  name: "the context menu, an item under the pointer",
  hover: ".ctx-menu-item",
  mount: async () => {
    const view = render(
      createElement(ContextMenu, {
        x: 40,
        y: 40,
        header: "carved_0001.jpg",
        footer: "Actions apply to the selected item only.",
        items: [
          {
            label: "Open artifact",
            note: "a1b2c3d4-0000-4000-8000-000000000001",
          },
          { label: "Copy path", note: "/Users/suspect/Pictures" },
          { label: "Remove bookmark", note: "this case only", danger: true },
        ],
        onClose: () => {},
      }),
    );
    await screen.findByText("Open artifact");
    return {
      roots: [document.querySelector(".ctx-menu") as Element],
      unmount: () => view.unmount(),
    };
  },
});

/**
 * The stat tiles, with one of them driving a filter.
 *
 * `.rv-stat.active` is the fifth rule of the replace-an-opaque-fill family and
 * the only one whose quiet tone is not a timestamp: `.rv-stat-label` is
 * --text-2 at 11px under a count an examiner is reading as a figure. Drawn in
 * a `.panel`, which is the WORSE of its two real grounds — RichRecordViewer and
 * WindowsTimelineViewer put these tiles inside one at --bg-1, CorrelationPage
 * puts them at page level on --bg-0 — so the number this settles is 4.72
 * rather than 5.13.
 *
 * The tone variants are here too. `.rv-tone-critical` and `.rv-tone-warning`
 * recolour the count, and the active tile is the critical one deliberately:
 * --danger over that tint on --bg-1 is 5.54, against --accent's 6.61, so the
 * tile that is measured on the tint is the worse of the two.
 */
RENDERED.push({
  name: "the stat tiles, one tile active",
  mount: async () => {
    const view = render(
      createElement(
        "div",
        { className: "panel" },
        createElement(StatTiles, {
          tiles: [
            { key: "total", label: "Activities", count: 41_233 },
            {
              key: "notable",
              label: "Notable",
              count: 12,
              tone: "critical" as const,
            },
            {
              key: "cloud",
              label: "Synced",
              count: 908,
              tone: "warning" as const,
            },
            {
              key: "local",
              label: "Local only",
              count: 40_313,
              tone: "ok" as const,
            },
          ],
          active: "notable",
          onToggle: () => {},
        }),
      ),
    );
    await screen.findByText("Notable");
    return {
      roots: [document.querySelector(".panel") as Element],
      unmount: () => view.unmount(),
    };
  },
});

/**
 * The frequency bars, with the top row under the pointer.
 *
 * `.rv-top-bar` is the awkward one, and it is here with its awkwardness
 * declared rather than smoothed over. The bar is a SIBLING of the two labels
 * it sits behind — `position: absolute` at `z-index: 0`, the labels at 1 — so
 * the ancestor climb walks straight past it and reports the row's own ground.
 * This entry therefore settles everything on the row EXCEPT the pairing that
 * matters most, and the test below it (`names the ground a sibling bar
 * paints…`) does that one by hand, out of the same primitives.
 *
 * Hovered, because that is the state in which the row's ground is --bg-2: at
 * rest the row paints nothing and the climb reaches the `.panel`.
 */
RENDERED.push({
  name: "the frequency bars, the top row under the pointer",
  hover: ".rv-top-row",
  mount: async () => {
    const view = render(
      createElement(
        "div",
        { className: "panel" },
        createElement(TopBars, {
          title: "Most frequent applications",
          items: [
            { label: "chrome.exe", count: 18_402 },
            { label: "explorer.exe", count: 9_120 },
            { label: "cmd.exe", count: 311 },
          ],
          active: null,
          onSelect: () => {},
        }),
      ),
    );
    await screen.findByText("chrome.exe");
    return {
      roots: [document.querySelector(".panel") as Element],
      unmount: () => view.unmount(),
    };
  },
});

/**
 * A record table with a row selected, which is `.data-table tbody tr.selected`
 * — the rule this whole sweep started from — drawn where an examiner meets it.
 *
 * `RecordTable` is what the GPS, call-log, contact, SRUM and Windows-timeline
 * viewers all draw, so one mount settles the shared rule and the per-viewer
 * ones (`.an-gps-row.selected`, `.an-wt-row.selected`) that repeat it: all
 * three paint the tint on a `<tr>` that paints nothing else, inside the
 * `.panel` RecordsViewerPage wraps every viewer in.
 *
 * The row is a NOTABLE one as well as the selected one, which is the case the
 * two rules were ordered for: `.rv-notable`'s --danger-bg would otherwise be
 * the ground, and the badge it carries paints a third tint on top of that.
 */
RENDERED.push({
  name: "a record table, a notable row selected",
  mount: async () => {
    const view = render(
      createElement(
        MemoryRouter,
        null,
        createElement(
          "div",
          { className: "panel" },
          createElement(RecordTable, {
            records: GPS_RECORDS,
            caseId: CASE_ID,
            columns: GPS_COLUMNS,
            rowClassName: "an-gps-row",
            selectedId: "g1",
            notable: (metadata: Record<string, unknown>) =>
              metadata.make === "Unknown" ? "No camera make recorded" : null,
            onSelect: () => {},
            copy: {
              header: "",
              label: "Copy coordinates",
              value: (metadata: Record<string, unknown>) =>
                `${metadata.gps_latitude}, ${metadata.gps_longitude}`,
            },
          }),
        ),
      ),
    );
    await screen.findByText("IMG_0001.HEIC");
    return {
      roots: [document.querySelector(".panel") as Element],
      unmount: () => view.unmount(),
    };
  },
});

/**
 * Text on a disabled control inside a rendered surface, which the floor above
 * exempts and this names.
 *
 * Empty today: nothing in RENDERED currently draws a disabled control. It is
 * asserted rather than assumed because the exemption is the one place this
 * half stops measuring something it can see, and an exemption nobody can list
 * is indistinguishable from a bug.
 */
const INACTIVE_CONTROLS: string[] = [];

describe("contrast on grounds an ancestor paints", () => {
  it("reads the stylesheets it claims to read", () => {
    const all = styleRules();
    expect(all.length).toBeGreaterThan(100);
    expect(all.some((rule) => rule.selector.includes(".ft-row.selected"))).toBe(
      true,
    );
    expect(all.some((rule) => rule.opacity !== undefined)).toBe(true);
  });

  it("accounts for every rule it drops for being conditional", () => {
    expect(conditionalColourRules()).toEqual(Object.keys(NOT_APPLIED).sort());
  });

  it("holds every rendered surface to WCAG AA on the ground it actually lands on", async () => {
    const rules = styleRules();
    const resting = styleReader(rules);
    // Built once and shared: `styleReader` caches against the element, and
    // every surface mounts fresh elements, so the two readers never disagree
    // about the same node.
    const hovering = styleReader(asHovered(rules));
    const map = tokens();

    const failures = new Set<string>();
    const measured = new Set<string>();
    const unresolvedInk = new Set<string>();
    const unreadableGround = new Set<string>();
    const groundless = new Set<string>();
    const inactive = new Set<string>();

    for (const surface of RENDERED) {
      const mounted = await surface.mount();
      let unhover: (() => void) | null = null;
      let read = resting;
      if (surface.hover !== undefined) {
        const under = document.querySelector(surface.hover);
        // A hover selector that matches nothing would measure the RESTING
        // document under a name claiming otherwise — the one outcome worse
        // than not measuring the state at all, because it reads as coverage.
        expect(
          under,
          `${surface.name}: nothing matches ${surface.hover}`,
        ).not.toBeNull();
        unhover = markHovered(under as Element);
        read = hovering;
      }
      for (const root of mounted.roots) {
        for (const element of [root, ...root.querySelectorAll("*")]) {
          // Only elements that carry a `color` rule of their own; inherited
          // text answers to the element that declared it.
          if (read(element).color === undefined) continue;
          const where = `${surface.name}: ${nameOf(element)}`;
          // A disabled control is exempt: WCAG 1.4.3 asks nothing of "text
          // that is part of an inactive user interface component", and every
          // `:disabled` rule in this codebase fades one — `.btn:disabled`,
          // `.fg-sort:disabled`, `.bmk-star:disabled` and the two login
          // buttons all sit at 0.45 to 0.6 opacity. Measuring them would fail
          // this on a rule that is conformant, which is how a guard gets
          // switched off. They are named rather than dropped in silence, and
          // the ledger is compared both ways: a control that stops being
          // disabled has to come back under the floor.
          if (element.closest(':disabled, [aria-disabled="true"]') !== null) {
            inactive.add(where);
            continue;
          }
          const colour = inkOf(element, read, map);
          if (!colour || colour.ink === null) {
            unresolvedInk.add(`${where}: ${colour?.declaredAs ?? "(none)"}`);
            continue;
          }
          const { chain, unreadable } = chainOf(element, read, map);
          for (const note of unreadable)
            unreadableGround.add(`${where} — ${note}`);
          const ground = composite(TRANSPARENT, chain);
          const fg = composite(premul(colour.ink), chain);
          if (ground === null || fg === null) {
            groundless.add(where);
            continue;
          }
          measured.add(where);
          const ratio = Number(contrastRatio(fg, ground).toFixed(2));
          if (ratio < AA_SMALL_TEXT) {
            failures.add(
              `${where}: color ${colour.declaredAs} (${fg}) on ${ground} is ${ratio}:1`,
            );
          }
        }
      }
      unhover?.();
      mounted.unmount();
    }

    // Every hole is named rather than skipped, and each list is asserted
    // empty: an element whose colour will not resolve, a ground written in a
    // form the resolver cannot read, and a climb that reached the root without
    // finding anything opaque are three different faults, and each of them
    // would otherwise pass by not being looked at.
    expect([...inactive].sort()).toEqual(INACTIVE_CONTROLS);
    expect([...unresolvedInk].sort()).toEqual([]);
    expect([...unreadableGround].sort()).toEqual([]);
    expect([...groundless].sort()).toEqual([]);
    expect([...failures].sort()).toEqual([]);
    // A guard that found nothing to measure would pass forever, which is the
    // failure mode the stylesheet pass was twice rewritten to escape.
    expect(measured.size).toBeGreaterThan(10);
    expect([...unparseable]).toEqual([]);
  });

  /**
   * The climb itself, pinned on a row that still inherits its ground.
   *
   * Every tone on a SELECTED row now restates the fill on its own rule, so the
   * assertion above no longer exercises the climb even though the climb is what
   * makes it correct: revert `.ft-name` to --text-1 and the climb is the only
   * reason the failure is seen at all. An unselected row is the case that still
   * inherits — nothing between `.ft-name` and `.ft-wrap` paints anything — so
   * it is what this measures the mechanism against.
   */
  /**
   * The tint case, pinned to the composite rather than to "it passed".
   *
   * The assertion above would stay green if the plist viewer were never
   * mounted, if its selected item painted nothing, or if the climb stopped one
   * element too early and read --bg-1 straight — all three of which are ways of
   * measuring the wrong thing and finding nothing wrong with it. So the ground
   * itself is named: 12% of the accent over --bg-1 is #e2e1f5, and the
   * quietest tone the row carries sits on it at 5.46:1.
   *
   * That number is the whole reason this surface is here: the ground is the
   * composite, not the surface, and `.an-plist-item.selected` is conformant
   * because of WHERE it is drawn rather than because of what it declares —
   * nothing in a stylesheet says where that is.
   *
   * The figures move with the shipped palette, and they did when the default
   * became a light one. Under the dark palette this composite was #2d2821 and
   * the pairing 4.72:1, with the same rule over --bg-2 at 4.35 and over --bg-3
   * at 3.88 — under the floor, because a light tint LIGHTENS a dark surface and
   * so makes the ground worse. Under the light default the tint darkens the
   * surface and the same pairing improves. Both directions are the point; the
   * assertion is on the palette this build ships.
   */
  it("composites a tint an ancestor paints onto the surface behind it", async () => {
    const read = styleReader(styleRules());
    const map = tokens();
    const mounted = await PLIST_SURFACE.mount();

    const item = document.querySelector(
      ".an-plist-item.selected",
    ) as HTMLElement;
    expect(item).not.toBeNull();
    const type = item.querySelector(".an-plist-type") as HTMLElement;
    const { chain } = chainOf(type, read, map);
    const ground = composite(TRANSPARENT, chain);

    // Not --bg-1 itself: the tint is on top of it, and which way it moves the
    // ground depends on the palette — a light tint makes a dark surface worse,
    // a dark tint makes a light one better.
    expect(ground).toBe("#e2e1f5");
    expect(ground).not.toBe(resolveInk("var(--bg-1)", map)?.hex);
    const colour = inkOf(type, read, map);
    expect(colour?.declaredAs).toBe("var(--text-2)");
    const fg = composite(premul(colour?.ink as Ink), chain) as string;
    expect(Number(contrastRatio(fg, ground as string).toFixed(2))).toBe(5.46);
    mounted.unmount();
  });

  /**
   * The claim the whole --accent-bg sweep rests on, measured rather than read.
   *
   * Every selected-state tint in the product sits beside a `:hover` rule that
   * paints --bg-2 on the SAME element, at the same specificity. If the hover
   * won, the tint would composite over --bg-2 rather than over the container
   * and --text-2 would drop from 4.72:1 to 4.35:1 the moment the pointer
   * touched the row an examiner had selected — a failure that appears and
   * disappears with the mouse, which is the hardest kind to find in a
   * screenshot and the easiest to be cross-examined on.
   *
   * It does not win: the tint rule is written after it, and equal specificity
   * is broken by source order. That is a fact about the FILE, though, and one
   * an innocent-looking reorder would silently reverse, so it is asserted here
   * on the drawn ground instead of trusted to the reader of a stylesheet.
   */
  it("keeps a selected row on its own tint when the pointer is also on it", async () => {
    const map = tokens();
    const read = styleReader(asHovered(styleRules()));
    const mounted = await PLIST_SURFACE.mount();

    const item = document.querySelector(
      ".an-plist-item.selected",
    ) as HTMLElement;
    const unhover = markHovered(item);
    const type = item.querySelector(".an-plist-type") as HTMLElement;
    const { chain } = chainOf(type, read, map);

    // The tint over the panel, exactly as at rest — not the tint over --bg-2.
    expect(composite(TRANSPARENT, chain)).toBe("#e2e1f5");
    expect(composite(TRANSPARENT, chain)).not.toBe("#d9d9ee");

    unhover();
    mounted.unmount();
  });

  /**
   * The hover probe, pinned to the ground it changes.
   *
   * The sweep above would stay green if `asHovered` rewrote nothing, if
   * `markHovered` marked the wrong element, or if the hover rule simply lost
   * the cascade — three ways of measuring the resting document while reporting
   * a hovered one. So both grounds are named. At rest the context menu's note
   * sits on `.ctx-menu`'s --bg-2, #1a1e26, where --text-2 is a comfortable
   * 5.39:1; under the pointer the item paints 12% #e5a13c over it, #322e29,
   * where --text-2 is 4.35:1 and under the floor.
   *
   * That is why the note's tone is restated for the hovered state rather than
   * left alone, and this is the assertion that says the restatement is needed:
   * the ground it answers to is one no stylesheet states and one the resting
   * document does not draw.
   */
  it("measures a hovered item on the fill the hover paints", async () => {
    const map = tokens();
    const rules = styleRules();
    const surface = RENDERED.find((s) => s.hover === ".ctx-menu-item");
    expect(surface).toBeDefined();
    const mounted = await (surface as RenderedSurface).mount();

    const item = document.querySelector(".ctx-menu-item") as HTMLElement;
    const note = item.querySelector(".ctx-menu-note") as HTMLElement;
    expect(note).not.toBeNull();

    const resting = styleReader(rules);
    expect(composite(TRANSPARENT, chainOf(note, resting, map).chain)).toBe(
      resolveInk("var(--bg-2)", map)?.hex,
    );

    const unhover = markHovered(item);
    const hovering = styleReader(asHovered(rules));
    const { chain } = chainOf(note, hovering, map);
    const ground = composite(TRANSPARENT, chain) as string;
    expect(ground).toBe("#d9d9ee");

    // The tone the rule carries, measured on the ground the hover paints. It
    // is --text-1 because of what --text-2 measured HERE under the palette
    // shipped at the time — 4.35:1, under the floor. That number belonged to a
    // dark palette, where a light tint lightens the surface the text sits on;
    // under the light default the same tint darkens it and --text-2 would clear
    // the floor too. The rule was not loosened when the palette changed: a tone
    // chosen for the worse of two grounds is still right on the better one, and
    // this asserts the drawn pairing rather than the argument for it.
    const colour = inkOf(note, hovering, map);
    expect(colour?.declaredAs).toBe("var(--text-1)");
    const fg = composite(premul(colour?.ink as Ink), chain) as string;
    expect(Number(contrastRatio(fg, ground).toFixed(2))).toBe(6.4);
    expect(contrastRatio(fg, ground)).toBeGreaterThan(AA_SMALL_TEXT);

    unhover();
    mounted.unmount();
  });

  /**
   * The ground a SIBLING paints, which the climb cannot reach — named here
   * because the sweep above cannot name it.
   *
   * `.rv-top-bar` is the frequency chart's bar: `position: absolute`,
   * `z-index: 0`, a width set inline from the row's share of the peak, with the
   * row's label and count drawn over it at `z-index: 1`. It is not an ancestor
   * of either label, so {@link chainOf} — which walks `parentElement` — walks
   * past it and reports the row's own ground. Every number the sweep prints for
   * `.rv-top-label` and `.rv-top-count` is therefore an OPTIMISTIC one, and
   * this is the assertion that says by how much.
   *
   * The arithmetic is done with the same primitives the climb uses rather than
   * a second formula, and the bar's tint is read off the bar rather than
   * written down here, so a change to --accent-bg reaches this test.
   *
   * The pairing: the top row's bar is the full width of the row, so the count
   * at its right-hand end is over the bar and not merely beside it. Hovered,
   * the row paints --bg-2 and the bar puts 12% #e5a13c over that — #322e29,
   * where --text-2 was 4.35:1 under the palette shipped at the time. It cannot
   * be fixed by declaring a ground on the count, because the count's ground is
   * a bar of data-dependent width: it is over the bar on a busy row and over
   * the row on a quiet one, and no single declared fill is true for both. So
   * the tone moved instead, to the one that clears both grounds in either
   * palette — --text-1.
   */
  it("names the ground a sibling bar paints, which the ancestor climb cannot reach", async () => {
    const map = tokens();
    const rules = styleRules();
    const surface = RENDERED.find((s) => s.hover === ".rv-top-row");
    expect(surface).toBeDefined();
    const mounted = await (surface as RenderedSurface).mount();

    const row = document.querySelector(".rv-top-row") as HTMLElement;
    const bar = row.querySelector(".rv-top-bar") as HTMLElement;
    const count = row.querySelector(".rv-top-count") as HTMLElement;
    // A sibling, not an ancestor. This is the whole reason the test exists.
    expect(bar.contains(count)).toBe(false);

    const unhover = markHovered(row);
    const read = styleReader(asHovered(rules));
    const { chain } = chainOf(count, read, map);

    // What the climb sees: the row's hover fill, with no bar in it.
    const climbed = composite(TRANSPARENT, chain) as string;
    expect(climbed).toBe(resolveInk("var(--bg-2)", map)?.hex);

    // What the screen draws on the top row, whose bar spans the whole width.
    const tint = resolveInk(read(bar).background as string, map) as Ink;
    expect(tint.alpha).toBeLessThan(1);
    const drawn = flatten(tint, climbed);
    expect(drawn).toBe("#d9d9ee");

    // --text-1, and why: under the palette shipped when this was found,
    // --text-2 measured 4.35:1 on this composite — under the floor, and
    // unfixable from the ground's side because the bar's width is
    // data-dependent. The light default moves that pairing the other way; the
    // tone stays, and what is asserted is the drawn pairing.
    const colour = inkOf(count, read, map);
    expect(colour?.declaredAs).toBe("var(--text-1)");
    const ink = colour?.ink as Ink;
    const fg = ink.hex;
    expect(Number(contrastRatio(fg, drawn).toFixed(2))).toBe(6.4);
    expect(contrastRatio(fg, drawn)).toBeGreaterThan(AA_SMALL_TEXT);

    unhover();
    mounted.unmount();
  });

  it("reads the ground an ancestor paints, not the one the element declares", async () => {
    const read = styleReader(styleRules());
    const map = tokens();
    const mounted = await RENDERED[2].mount();

    const unselected = screen
      .getByText("Windows")
      .closest(".ft-row") as HTMLElement;
    expect(unselected.className).not.toContain("selected");
    const name = unselected.querySelector(".ft-name") as HTMLElement;
    const { chain } = chainOf(name, read, map);

    // Nothing between the label and the panel paints anything...
    expect(chain.findIndex((layer) => layer.ink !== null)).toBeGreaterThan(0);
    expect(chain.find((layer) => layer.ink !== null)?.from).toBe(
      document.querySelector(".ft-wrap"),
    );
    // ...so the ground is the panel's, not the four bare surfaces the
    // stylesheet pass would have measured this label against.
    expect(composite(TRANSPARENT, chain)).toBe(
      resolveInk("var(--bg-1)", map)?.hex,
    );
    mounted.unmount();
  });

  /**
   * The failure this half was built for, put back and caught.
   *
   * Every tone on a selected file-tree row passes now, so the assertion above
   * proves the walk runs but not that it can still see anything. This puts the
   * historical failure back — one rule, appended so it wins the cascade the way
   * an edit to files.css would — and requires the pass to report it, with the
   * ratio it was reported at when it was real: --text-1 on the --accent-dim
   * fill an ancestor paints, 2.86:1. If the climb ever stops climbing, this is
   * the assertion that says so, and it says so in the number.
   */
  it("reports a tone that fails on a fill only its ancestor paints", async () => {
    const map = tokens();
    const read = styleReader([
      ...styleRules(),
      {
        selector: ".ft-row.selected .ft-name",
        order: Number.MAX_SAFE_INTEGER,
        color: "var(--text-1)",
        background: "none",
      },
    ]);
    const mounted = await RENDERED[2].mount();
    const name = document.querySelector(
      ".ft-row.selected .ft-name",
    ) as HTMLElement;

    const { chain } = chainOf(name, read, map);
    const ink = resolveInk(read(name).color as string, map) as Ink;
    const ground = composite(TRANSPARENT, chain) as string;
    const fg = composite(premul(ink), chain) as string;

    expect(ground).toBe(resolveInk("var(--accent-dim)", map)?.hex);
    expect(Number(contrastRatio(fg, ground).toFixed(2))).toBe(2.33);
    expect(contrastRatio(fg, ground)).toBeLessThan(AA_SMALL_TEXT);
    mounted.unmount();
  });

  /**
   * The `opacity` fold, on a tree built here rather than found in the product.
   *
   * The product currently has no element that fades an ancestor of text, which
   * is exactly why this is asserted on a constructed case: a mechanism whose
   * only proof is that nothing triggers it is a mechanism nobody has checked.
   * `.ft-wrap` paints --bg-1; a wrapper at 50% opacity between it and the label
   * halves everything inside it, and the pairing that the climb must report is
   * the faded text against the faded ground, not the text against --bg-1.
   */
  it("folds an ancestor opacity into both the text and the ground", () => {
    const map = tokens();
    const wrap = document.createElement("div");
    wrap.className = "ft-wrap";
    const faded = document.createElement("div");
    faded.className = "contrast-probe-faded";
    const label = document.createElement("span");
    faded.appendChild(label);
    wrap.appendChild(faded);
    document.body.appendChild(wrap);

    const read = styleReader([
      { selector: ".ft-wrap", order: 0, background: "var(--bg-1)" },
      { selector: ".contrast-probe-faded", order: 1, opacity: "0.5" },
    ]);
    const { chain } = chainOf(label, read, map);
    const bg1 = resolveInk("var(--bg-1)", map) as Ink;
    const white: Ink = { hex: "#ffffff", alpha: 1 };

    // The ground is unchanged: the fill is outside the faded group.
    expect(composite(TRANSPARENT, chain)).toBe(bg1.hex);
    // The text is not. White at 50% over --bg-1 is the midpoint, and the ratio
    // it draws at is the one an examiner would see.
    const fg = composite(premul(white), chain) as string;
    expect(fg).toBe(flatten({ hex: "#ffffff", alpha: 0.5 }, bg1.hex));
    expect(contrastRatio(fg, bg1.hex)).toBeLessThan(
      contrastRatio(white.hex, bg1.hex),
    );
    wrap.remove();
  });
});
