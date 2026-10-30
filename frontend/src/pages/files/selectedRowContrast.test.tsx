import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import {
  AA_SMALL_TEXT,
  TRANSPARENT,
  chainOf,
  composite,
  contrastRatio,
  inkOf,
  nameOf,
  premul,
  resolveInk,
  styleReader,
  styleRules,
  tokens,
  unparseable,
} from "../../app/composedContrast";
import { server } from "../../test/server";
import { FileTree } from "./FileTree";
import type { FileRow } from "./types";

/**
 * The selected row of the file tree, measured as it is actually drawn.
 *
 * This is the pairing the whole composed-contrast mechanism exists because of.
 * `.ft-row.selected` paints --accent-dim and every tone the row carries is set
 * one element further in, so a row drawing --text-1 on that fill at 2.86:1
 * measured, in a stylesheet pass, as --text-1 against the four bare page
 * surfaces — 8.54 / 8.05 / 7.49 / 6.70 — and passed comfortably. The tones are
 * --text-0 now, at 4.64:1 on the fill, and files.css restates the fill on the
 * rules that set them so the stylesheet pass can see the pairing too.
 *
 * Two guards would therefore have to fail before this regresses, which is
 * deliberate: this one pins the NUMBER that files.css's comment claims, on the
 * rendered row, through the ancestor climb. If someone removes the restated
 * `background` as redundant, the stylesheet pass goes quiet and this one does
 * not.
 *
 * The mechanism itself lives in app/composedContrast.ts and is exercised
 * across every rendered surface by app/contrast.test.ts. This file used to
 * carry its own copy of it — a second resolver with one set of honesty
 * conventions between them, which is a drift waiting to happen and a drift
 * that would have been silent.
 */

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

const ROWS: FileRow[] = [
  fileRow({
    id: "windows",
    name: "Windows",
    path: "/Windows",
    is_directory: true,
  }),
  fileRow({ id: "boot", name: "boot.ini", path: "/boot.ini", size: 512 }),
];

async function renderTree(selectedId: string) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/sources/${SOURCE_ID}/files`, () =>
      HttpResponse.json({
        items: ROWS,
        total_count: ROWS.length,
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
  // FileGridPage rather than by FileTree; without it the climb would go past
  // the panel to the body and measure against the page instead.
  const view = render(
    <QueryClientProvider client={queryClient}>
      <div className="ft-wrap">
        <FileTree
          caseId={CASE_ID}
          sourceId={SOURCE_ID}
          selectedId={selectedId}
          onSelect={() => {}}
          onOpen={() => {}}
        />
      </div>
    </QueryClientProvider>,
  );
  await screen.findByText("Windows");
  return view;
}

describe("the file tree selection fill", () => {
  it("draws the selected row on --accent-dim, not on the page surface", async () => {
    const read = styleReader(styleRules());
    const map = tokens();
    const view = await renderTree("boot");

    const row = document.querySelector(".ft-row.selected") as HTMLElement;
    const label = row.querySelector(".ft-name") as HTMLElement;
    const { chain } = chainOf(label, read, map);

    // The ground under the label is the row's fill, and it is the ROW that
    // paints it: the climb has to leave the label to find it. That is the
    // whole shape of the bug — a stylesheet pass stops at the label.
    const ground = composite(TRANSPARENT, chain);
    expect(ground).toBe(resolveInk("var(--accent-dim)", map)?.hex);
    const accentDim = ground as string;
    const surfaces = ["--bg-0", "--bg-1", "--bg-2", "--bg-3"].map(
      (name) => resolveInk(`var(${name})`, map)?.hex,
    );
    expect(surfaces).not.toContain(accentDim);

    view.unmount();
  });

  it("clears AA for every tone that row carries, on that fill", async () => {
    const read = styleReader(styleRules());
    const map = tokens();
    const view = await renderTree("boot");
    const row = document.querySelector(".ft-row.selected") as HTMLElement;

    const measured: string[] = [];
    const failures: string[] = [];
    for (const element of [row, ...row.querySelectorAll("*")]) {
      const colour = inkOf(element, read, map);
      if (!colour?.ink) continue;
      const { chain } = chainOf(element, read, map);
      const ground = composite(TRANSPARENT, chain);
      const fg = composite(premul(colour.ink), chain);
      // A tone this cannot read is not a pass. There are none here; the
      // shared guard keeps the written ledger for the ones there are.
      expect(ground, `no ground under ${nameOf(element)}`).not.toBeNull();
      expect(fg, `no colour on ${nameOf(element)}`).not.toBeNull();
      const ratio = Number(
        contrastRatio(fg as string, ground as string).toFixed(2),
      );
      measured.push(nameOf(element));
      if (ratio < AA_SMALL_TEXT) {
        failures.push(
          `${nameOf(element)}: ${colour.declaredAs} (${fg}) on ${ground} is ${ratio}:1`,
        );
      }
    }

    expect(failures.sort()).toEqual([]);
    // A regression that found nothing to measure would pass forever.
    expect(measured.length).toBeGreaterThan(2);
    // And a cascade that could not parse the selectors it ranked would measure
    // the wrong rules while still finding something, which reads the same from
    // outside.
    expect([...unparseable]).toEqual([]);
    view.unmount();
  });

  /**
   * The number files.css's comment claims, checked against the palette.
   *
   * A comment that states a ratio is a claim like any other on this product's
   * screens, and a stale one costs the reader the same trust as a wrong figure
   * would. --text-0 on --accent-dim is the pairing index.css chose --accent-dim
   * to serve, so if either token moves this is what says the comment beside the
   * rule has stopped being true.
   */
  it("keeps --text-0 on --accent-dim at the 4.64:1 files.css documents", () => {
    const map = tokens();
    const text0 = resolveInk("var(--text-0)", map)?.hex as string;
    const fill = resolveInk("var(--accent-dim)", map)?.hex as string;
    expect(Number(contrastRatio(text0, fill).toFixed(2))).toBe(4.64);
    expect(contrastRatio(text0, fill)).toBeGreaterThan(AA_SMALL_TEXT);
  });
});
