import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { server } from "../../test/server";
import type { ParsedRecord } from "./api";
import { RecordsViewerPage } from "./RecordsViewerPage";

const CASE_ID = "case-1";

interface Captured {
  type: string | null;
  page: string | null;
  page_size: string | null;
}

/** Register a /records handler returning `records`; captures query params. */
function mockRecords(
  records: ParsedRecord[],
  opts: { total?: number; captured?: Captured[] } = {},
) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url);
      opts.captured?.push({
        type: url.searchParams.get("type"),
        page: url.searchParams.get("page"),
        page_size: url.searchParams.get("page_size"),
      });
      return HttpResponse.json({
        records,
        total: opts.total ?? records.length,
        page: Number(url.searchParams.get("page") ?? 1),
        page_size: Number(url.searchParams.get("page_size") ?? 50),
        type: url.searchParams.get("type"),
      });
    }),
  );
}

function renderViewer(type: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/${type}`]}>
        <Routes>
          <Route
            path="/cases/:caseId/analysis/:type"
            element={<RecordsViewerPage />}
          />
          <Route
            path="/cases/:caseId/artifacts/:artifactId"
            element={<div>artifact page</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Switches the `:caseId` route param in place, without remounting the page. */
function CaseSwitcher({ type }: { type: string }) {
  const navigate = useNavigate();
  return (
    <button
      type="button"
      onClick={() => navigate(`/cases/case-2/analysis/${type}`)}
    >
      Go to case-2
    </button>
  );
}

function renderViewerWithSwitcher(type: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/${type}`]}>
        <CaseSwitcher type={type} />
        <Routes>
          <Route
            path="/cases/:caseId/analysis/:type"
            element={<RecordsViewerPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const rec = (id: string, metadata: Record<string, unknown>): ParsedRecord => ({
  id,
  parent_id: `a-${id}`,
  artifact_type: "ParsedRecord",
  metadata,
});

describe("aggregate scope note names its sample size (B4-023)", () => {
  it("says how few records the shell checked instead of implying coverage", async () => {
    // For an aggregate viewer this page fetches ONE page purely to decide what
    // to mount; the viewer below loads far more. "The records this page
    // checked" read as coverage, so a stamp on record 300 of 4,000 went
    // unmentioned while the sentence implied the whole set was examined.
    mockRecords(
      [
        rec("e1", {
          type: "EmailMessage",
          subject: "hello",
          date: "2023-01-01T00:00:00Z",
          content_incomplete: true,
          content_incomplete_reason: "cap_reached",
        }),
      ],
      { total: 4000 },
    );
    renderViewer("EmailMessage");

    // The viewer below carries its own banner over its own records, so match
    // the shell's by the sentence only the shell writes.
    const ledes = await screen.findAllByText(/declares itself\s+incomplete/);
    const said = ledes
      .map((n) => (n.textContent ?? "").replace(/\s+/g, " "))
      .find((t) => t.includes("sample this page fetched"));
    expect(said).toBeDefined();
    expect(said).toContain("over the first 1 of 4,000");
    expect(said).toContain("reports on those separately");
  });
});

describe("RecordsViewerPage", () => {
  it("renders a tailored browser_history table from /records", async () => {
    mockRecords([
      rec("r1", {
        type: "BrowserHistory",
        browser: "Chrome/Edge",
        url: "https://example.com/very/long/path/segment",
        title: "Example Site",
        visit_count: 7,
        visit_time: 1704110400,
      }),
    ]);
    renderViewer("BrowserHistory");

    expect(await screen.findByText("Example Site")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Browser History" }),
    ).toBeInTheDocument();
    // URL is mono + truncatable with full value in a title tooltip.
    expect(
      screen.getByTitle("https://example.com/very/long/path/segment"),
    ).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    // visit_time (unix seconds) rendered via formatUtc.
    expect(screen.getByText("2024-01-01 12:00:00 UTC")).toBeInTheDocument();
    expect(screen.getByText("Chrome/Edge")).toBeInTheDocument();
    // Row links to the artifact detail page.
    expect(screen.getByRole("link", { name: "open" })).toHaveAttribute(
      "href",
      `/cases/${CASE_ID}/artifacts/r1`,
    );
  });

  it("plots a GPS dot and shows coordinates in the exif viewer", async () => {
    mockRecords([
      rec("e1", {
        type: "exif",
        make: "Canon",
        model: "EOS R5",
        datetime_original: "2023-05-01T10:00:00Z",
        width: 4000,
        height: 3000,
        has_gps: true,
        gps_lat: 48.8584,
        gps_lon: 2.2945,
      }),
      rec("e2", {
        type: "exif",
        make: "Nikon",
        model: "Z6",
        width: 100,
        height: 100,
        has_gps: false,
      }),
    ]);
    renderViewer("exif");

    expect(await screen.findByText("Canon EOS R5")).toBeInTheDocument();
    // Offline map present with an accurately projected dot for the GPS row.
    expect(screen.getByTestId("an-gps-map")).toBeInTheDocument();
    const dot = screen.getByTestId("an-gps-dot-e1");
    expect(Number(dot.getAttribute("cx"))).toBeCloseTo(182.2945); // lon + 180
    expect(Number(dot.getAttribute("cy"))).toBeCloseTo(41.1416); // 90 - lat
    expect(dot.getAttribute("data-lat")).toBe("48.8584");
    // The non-GPS record is not plotted.
    expect(screen.queryByTestId("an-gps-dot-e2")).not.toBeInTheDocument();
    // Coordinates + copy affordance + dimensions.
    expect(screen.getByText("48.8584, 2.2945")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy coordinates" }),
    ).toBeInTheDocument();
    expect(screen.getByText("4000×3000")).toBeInTheDocument();

    // Clicking the GPS row focuses (activates) its dot.
    const row = screen.getByText("Canon EOS R5").closest("tr")!;
    await userEvent.click(row);
    expect(screen.getByTestId("an-gps-dot-e1").getAttribute("class")).toContain(
      "an-map-dot-active",
    );
  });

  it("marks deleted SqliteRow records distinctly", async () => {
    mockRecords([
      rec("s1", {
        type: "SqliteRow",
        table: "messages",
        rowid: 42,
        deleted: true,
        recovery_source: "freelist",
        confidence: 200,
        columns: { text: "recovered secret", sender: "bob" },
      }),
      rec("s2", {
        type: "SqliteRow",
        table: "messages",
        rowid: 43,
        deleted: false,
        recovery_source: null,
        confidence: 255,
        columns: { text: "live message" },
      }),
    ]);
    renderViewer("SqliteRow");

    await screen.findByText("freelist");
    const deletedRow = screen.getByTestId("sqlite-deleted-row");
    expect(deletedRow).toHaveClass("an-row-deleted");
    expect(within(deletedRow).getByText("deleted")).toBeInTheDocument();
    expect(
      within(deletedRow).getByText("recovered secret"),
    ).toBeInTheDocument();

    const liveRow = screen.getByTestId("sqlite-live-row");
    expect(liveRow).not.toHaveClass("an-row-deleted");
    expect(within(liveRow).getByText("live")).toBeInTheDocument();
  });

  it("falls back to a generic key/value table for unknown types", async () => {
    mockRecords([
      rec("g1", { type: "MysteryType", foo: "bar-value", count: 9 }),
    ]);
    renderViewer("MysteryType");

    expect(await screen.findByText("bar-value")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Mystery Type" }),
    ).toBeInTheDocument();
    // Metadata keys become humanized column headers.
    expect(screen.getByText("Foo")).toBeInTheDocument();
    expect(screen.getByText("Count")).toBeInTheDocument();
    expect(screen.getByText("bar-value")).toBeInTheDocument();
  });

  it("streams records in pages as the list is scrolled", async () => {
    const captured: Captured[] = [];
    mockRecords(
      [rec("r1", { type: "BrowserHistory", title: "Row", url: "http://a" })],
      { total: 200, captured },
    );
    renderViewer("BrowserHistory");

    await screen.findByText("Row");
    expect(captured[0]).toMatchObject({
      type: "BrowserHistory",
      page: "1",
      page_size: "100",
    });
    // The header is honest about how much of the set is in hand.
    expect(screen.getByText(/of 200 records/)).toBeInTheDocument();

    // Reaching the end pulls the next page (button is the no-IO fallback).
    await userEvent.click(screen.getByRole("button", { name: /load more/i }));
    await waitFor(() =>
      expect(captured.at(-1)).toMatchObject({
        type: "BrowserHistory",
        page: "2",
        page_size: "100",
      }),
    );
  });

  it("shows an empty state when there are no records", async () => {
    mockRecords([], { total: 0 });
    renderViewer("BrowserHistory");
    expect(
      await screen.findByText("No Browser History records"),
    ).toBeInTheDocument();
  });

  it("exports the whole type as CSV through the records export route", async () => {
    // `GET /cases/{id}/records/export/csv` shipped with no control reaching
    // it. The button asks for the type the page shows and nothing narrower,
    // and says so in its label.
    mockRecords([rec("g1", { type: "MysteryType", foo: "bar-value" })]);
    const exportUrls: string[] = [];
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records/export/csv`, ({ request }) => {
        exportUrls.push(request.url);
        return new HttpResponse("a,b\n1,2\n", {
          status: 200,
          headers: { "Content-Type": "text/csv; charset=utf-8" },
        });
      }),
    );
    const createObjectURL = vi.fn(() => "blob:csv");
    const origCreate = URL.createObjectURL;
    const origRevoke = URL.revokeObjectURL;
    URL.createObjectURL =
      createObjectURL as unknown as typeof URL.createObjectURL;
    URL.revokeObjectURL = vi.fn();
    try {
      renderViewer("MysteryType");
      await screen.findByText("bar-value");
      await userEvent.click(
        screen.getByRole("button", { name: "Export all as CSV" }),
      );
      await waitFor(() => expect(exportUrls).toHaveLength(1));
      const url = new URL(exportUrls[0]);
      expect(url.searchParams.get("type")).toBe("MysteryType");
      expect(url.searchParams.has("q")).toBe(false);
      await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1));
      expect(screen.queryByRole("alert")).toBeNull();
    } finally {
      URL.createObjectURL = origCreate;
      URL.revokeObjectURL = origRevoke;
    }
  });

  it("says when the CSV export failed and leaves the button usable", async () => {
    mockRecords([rec("g1", { type: "MysteryType", foo: "bar-value" })]);
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records/export/csv`, () =>
        HttpResponse.json(
          { error: { code: "INTERNAL", message: "export broke" } },
          { status: 500 },
        ),
      ),
    );
    renderViewer("MysteryType");
    await screen.findByText("bar-value");
    const button = screen.getByRole("button", { name: "Export all as CSV" });
    await userEvent.click(button);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /CSV export failed/,
    );
    expect(button).toBeEnabled();
  });

  it("offers no CSV export for a type with no records", async () => {
    mockRecords([], { total: 0 });
    renderViewer("BrowserHistory");
    await screen.findByText("No Browser History records");
    expect(
      screen.queryByRole("button", { name: "Export all as CSV" }),
    ).toBeNull();
  });

  it("shows an error state when the request fails", async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, () =>
        HttpResponse.json(
          { error: { code: "INTERNAL", message: "records unavailable" } },
          { status: 500 },
        ),
      ),
    );
    renderViewer("BrowserHistory");
    expect(await screen.findByText(/records unavailable/)).toBeInTheDocument();
  });

  it("never carries a viewer's selection into another case (B2-029/056/090/091/121)", async () => {
    // Every tailored viewer keeps local state — a selected conversation,
    // database, table, plist or activity row, a client search string, a page
    // cap. None of it means anything under another case, and record ids are
    // per-case so a carried selection can latch onto an unrelated record of the
    // same id and present it as the examiner's pick. The viewer is keyed on the
    // case at its single mount site, which covers the whole family.
    mockRecords([
      rec("p1", {
        type: "plist",
        filename: "caseA-first.plist",
        plist_type: "binary",
        content_preview: "case A first",
      }),
      rec("p2", {
        type: "plist",
        filename: "caseA-second.plist",
        plist_type: "binary",
        content_preview: "case A second",
      }),
    ]);
    server.use(
      http.get("/api/v1/cases/case-2/records", () =>
        HttpResponse.json({
          records: [
            rec("p1", {
              type: "plist",
              filename: "caseB-first.plist",
              plist_type: "binary",
              content_preview: "case B first",
            }),
            // Same id as the record selected in case A: without the key this is
            // what stays selected under case B.
            rec("p2", {
              type: "plist",
              filename: "caseB-second.plist",
              plist_type: "binary",
              content_preview: "case B second",
            }),
          ],
          total: 2,
          page: 1,
          page_size: 100,
          type: "PlistFile",
        }),
      ),
    );
    renderViewerWithSwitcher("PlistFile");

    await screen.findByText("caseA-first.plist");
    await userEvent.click(screen.getByText("caseA-second.plist"));
    expect(screen.getByText("case A second")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Go to case-2" }));

    expect(await screen.findByText("caseB-first.plist")).toBeInTheDocument();
    // Case B opens on its own first record, not on the id picked in case A.
    await waitFor(() =>
      expect(screen.getByText("case B first")).toBeInTheDocument(),
    );
    expect(screen.queryByText("case B second")).not.toBeInTheDocument();
  });
});

describe("viewer state is scoped to the case at the mount site (B2-173/174/175)", () => {
  it("drops a Windows Timeline client-side filter when the case changes", async () => {
    // Every viewer keeps some local state — a client filter, a selection, a
    // page cap — and none of it means anything under another case. Rather than
    // guard it in each of the ~20 viewers, RecordsViewerPage keys the viewer on
    // `${caseId}/${type}`, which remounts it and so cannot leave a value in
    // hand for even one render. This test is what pins that key in place: with
    // it removed, case 2's activity is rendered through case 1's filter string
    // and reads as "no matching records" for a case that has them.
    const activity = (id: string, app: string, text: string) =>
      rec(id, {
        type: "WindowsTimelineActivity",
        source_table: "Activity",
        activity_id: `guid-${id}`,
        executable: `C:\\\\${app}.exe`,
        app_display_name: app,
        activity_type: 6,
        activity_type_label: "App in focus",
        display_text: text,
        start_time: 1546300800,
        device_platform: "Windows",
        name: text,
      });

    server.use(
      http.get("/api/v1/cases/:caseId/records", ({ params, request }) => {
        const url = new URL(request.url);
        const records =
          params.caseId === CASE_ID
            ? [activity("r1", "Microsoft Word", "caseone-notes.docx")]
            : [activity("r2", "Notepad", "casetwo-ransom.txt")];
        return HttpResponse.json({
          records,
          total: records.length,
          page: Number(url.searchParams.get("page") ?? 1),
          page_size: Number(url.searchParams.get("page_size") ?? 200),
          type: url.searchParams.get("type"),
        });
      }),
    );
    renderViewerWithSwitcher("WindowsTimelineActivity");

    await screen.findByText("caseone-notes.docx");
    await userEvent.type(
      screen.getByRole("textbox", { name: "Filter Windows Timeline activity" }),
      "caseone",
    );
    await waitFor(() =>
      expect(
        screen.getByRole("textbox", {
          name: "Filter Windows Timeline activity",
        }),
      ).toHaveValue("caseone"),
    );

    await userEvent.click(screen.getByRole("button", { name: "Go to case-2" }));

    // Case 2's single activity is shown, not filtered away by case 1's needle.
    expect(await screen.findByText("casetwo-ransom.txt")).toBeInTheDocument();
    expect(
      screen.getByRole("textbox", { name: "Filter Windows Timeline activity" }),
    ).toHaveValue("");
    expect(screen.queryByText("caseone-notes.docx")).not.toBeInTheDocument();
  });

  it("drops a contact viewer search filter when the case changes", async () => {
    // Same mount-site key, a viewer that filters client-side over an
    // all-pages fetch (ContactViewer/EmailViewer/CalendarViewer share the
    // shape). A name fragment from case 1 matches nothing in case 2.
    const contact = (id: string, name: string) =>
      rec(id, { type: "Contact", subtype: "contact", display_name: name });

    server.use(
      http.get("/api/v1/cases/:caseId/records", ({ params, request }) => {
        const url = new URL(request.url);
        const records =
          params.caseId === CASE_ID
            ? [contact("c1", "Alice Caseone")]
            : [contact("c2", "Bob Casetwo")];
        return HttpResponse.json({
          records,
          total: records.length,
          page: Number(url.searchParams.get("page") ?? 1),
          page_size: Number(url.searchParams.get("page_size") ?? 200),
          type: url.searchParams.get("type"),
        });
      }),
    );
    renderViewerWithSwitcher("Contact");

    await screen.findByText("Alice Caseone");
    const search = screen.getByLabelText("Search contacts");
    await userEvent.type(search, "Caseone");
    await waitFor(() => expect(search).toHaveValue("Caseone"));

    await userEvent.click(screen.getByRole("button", { name: "Go to case-2" }));

    expect(await screen.findByText("Bob Casetwo")).toBeInTheDocument();
    expect(screen.getByLabelText("Search contacts")).toHaveValue("");
  });

  it("tells the examiner when the records it shows declare themselves incomplete", async () => {
    // ~809 plugin sites stamp `content_incomplete` / `content_incomplete_reason`
    // and nothing in the UI read either key: a browser history whose database
    // the parser stopped reading rendered exactly like a complete one. The
    // reason has to survive too — a cap and an undecodable row are different
    // problems with different follow-up.
    mockRecords([
      rec("r1", {
        type: "BrowserHistory",
        url: "https://example.com/a",
        title: "A",
        content_incomplete: true,
        content_incomplete_reason: "cap_reached",
      }),
      rec("r2", {
        type: "BrowserHistory",
        url: "https://example.com/b",
        title: "B",
      }),
    ]);
    renderViewer("BrowserHistory");

    await screen.findByText("A");
    const notes = await screen.findAllByRole("note");
    const banner = notes.find((n) =>
      /declares itself incomplete|declare themselves incomplete/.test(
        n.textContent ?? "",
      ),
    );
    expect(banner).toBeDefined();
    expect(banner).toHaveTextContent("1 of the 2");
    expect(banner).toHaveTextContent("safety cap");
  });

  it("shows no incompleteness banner when every record is whole", async () => {
    mockRecords([
      rec("r1", {
        type: "BrowserHistory",
        url: "https://example.com/a",
        title: "A",
      }),
    ]);
    renderViewer("BrowserHistory");

    await screen.findByText("A");
    expect(
      screen.queryByText(/declare themselves incomplete/),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/declares itself incomplete/),
    ).not.toBeInTheDocument();
  });
});

/**
 * The EXIF/GPS table used to be hand-rolled: every record a live `<tr>`, a
 * `tabIndex=0` on each of them, and a tabbable copy button inside each. On a
 * case with a hundred thousand photographs that is the same unbounded DOM and
 * the same unbounded run of tab stops the shared table was written to remove.
 */
describe("EXIF viewer is the shared windowed table", () => {
  const photo = (n: number, gps: boolean): ParsedRecord =>
    rec(`p${n}`, {
      type: "exif",
      make: "Canon",
      model: `EOS ${n}`,
      width: 100,
      height: 100,
      ...(gps ? { has_gps: true, gps_lat: 10 + n, gps_lon: 20 + n } : {}),
    });

  /** The record rows of the shared table, without its spacer rows. */
  const tableRows = () =>
    Array.from(document.querySelectorAll<HTMLElement>("tbody tr[data-index]"));

  it("numbers its rows against the whole set and holds one tab stop", async () => {
    mockRecords([photo(1, true), photo(2, true), photo(3, false)]);
    renderViewer("exif");

    await waitFor(() => expect(tableRows()).toHaveLength(3));
    // aria-rowindex is what stops assistive technology reading the rendered
    // window out as the population.
    expect(tableRows()[2]).toHaveAttribute("aria-rowindex", "4");
    expect(
      tableRows().filter((r) => r.getAttribute("tabindex") === "0"),
    ).toHaveLength(1);
    // And nothing inside a row is a tab stop of its own — the copy button
    // included, which is the capability that made this table bespoke.
    const stops = Array.from(
      document.querySelectorAll<HTMLElement>(
        "tbody tr a, tbody tr button, tbody tr input",
      ),
    ).filter((el) => el.getAttribute("tabindex") !== "-1");
    expect(stops).toHaveLength(0);
  });

  it("walks the rows with the arrows and moves the map pin with them", async () => {
    mockRecords([photo(1, true), photo(2, true), photo(3, true)]);
    renderViewer("exif");

    await waitFor(() => expect(tableRows()).toHaveLength(3));
    tableRows()[0].focus();
    await userEvent.keyboard("{ArrowDown}");
    expect(tableRows()[1]).toHaveFocus();
    // Selection follows the keyboard, or the map is a mouse-only instrument.
    expect(screen.getByTestId("an-gps-dot-p2").getAttribute("class")).toContain(
      "an-map-dot-active",
    );
  });

  it("copies the focused row s coordinates from the keyboard", async () => {
    const written: string[] = [];
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: (text: string) => {
          written.push(text);
          return Promise.resolve();
        },
      },
    });
    mockRecords([photo(1, true), photo(2, true)]);
    renderViewer("exif");

    await waitFor(() => expect(tableRows()).toHaveLength(2));
    tableRows()[0].focus();
    // The button is out of the tab order on purpose, so `c` on the row is the
    // only way a keyboard reaches it. If that is missing the move onto the
    // shared table has taken a capability away.
    await userEvent.keyboard("c");
    expect(written).toEqual(["11, 21"]);
  });
});

/**
 * HUNT-107. Every record type is mounted through this page, so the sentence
 * about what an earlier run left is written here once — for the aggregate and
 * conversation viewers as much as the plain tables.
 */
describe("records a later run answered, on the page shell", () => {
  function mockWithSuperseded(supersededTotal: number | null) {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url);
        const include = url.searchParams.get("include_superseded") === "true";
        const rows: ParsedRecord[] = [
          {
            id: "r1",
            parent_id: null,
            artifact_type: "ParsedRecord",
            metadata: { type: "SomeType", name: "current" },
          },
        ];
        if (include) {
          rows.push({
            id: "r0",
            parent_id: null,
            artifact_type: "ParsedRecord",
            metadata: { type: "SomeType", name: "earlier", superseded: true },
          });
        }
        return HttpResponse.json({
          records: rows,
          total: rows.length,
          type_total: rows.length,
          superseded_total: include ? null : supersededTotal,
          page: 1,
          page_size: 50,
          type: url.searchParams.get("type"),
        });
      }),
    );
  }

  it("says how many an earlier run left, and can show them", async () => {
    mockWithSuperseded(53);
    renderViewer("SomeType");

    const note = await screen.findByTestId("rv-superseded-note");
    expect(note.textContent).toMatch(/53/);
    expect(note.textContent).toMatch(/earlier run/i);

    await userEvent.click(
      screen.getByRole("button", { name: /show the earlier run/i }),
    );
    expect(await screen.findByText("superseded")).toBeInTheDocument();
  });

  it("says nothing when no run has been answered", async () => {
    mockWithSuperseded(0);
    renderViewer("SomeType");

    await waitFor(() =>
      expect(screen.getByText("current")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("rv-superseded-note")).not.toBeInTheDocument();
  });
});
