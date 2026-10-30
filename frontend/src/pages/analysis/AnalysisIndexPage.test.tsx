import { render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { server } from "../../test/server";
import { AnalysisIndexPage } from "./AnalysisIndexPage";

const CASE_ID = "case-1";

function mockTypes(record_types: { type: string; count: number }[]) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/record_types`, () =>
      HttpResponse.json({ record_types }),
    ),
  );
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis`]}>
        <Routes>
          <Route
            path="/cases/:caseId/analysis"
            element={<AnalysisIndexPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AnalysisIndexPage", () => {
  // One test below stubs the process-wide default locale; left in place it
  // would silently change what every later test in this file renders.
  afterEach(() => {
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    mockTypes([
      { type: "BrowserHistory", count: 1200 },
      { type: "exif", count: 5 },
      { type: "ZanyCustom", count: 3 },
      { type: "file_hash", count: 9999 },
    ]);
  });

  it("renders humanized types with counts and links to viewers", async () => {
    renderPage();
    const link = await screen.findByRole("link", { name: /Browser History/ });
    expect(link).toHaveAttribute(
      "href",
      `/cases/${CASE_ID}/analysis/BrowserHistory`,
    );
    expect(link).toHaveTextContent("1,200");

    expect(screen.getByText("EXIF (Photos)")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /EXIF \(Photos\)/ }),
    ).toHaveAttribute("href", `/cases/${CASE_ID}/analysis/exif`);
  });

  it("marks unknown types as a generic view and hides internal types", async () => {
    renderPage();
    // Unknown type is humanized and flagged generic.
    const generic = await screen.findByText("Zany Custom");
    expect(generic).toBeInTheDocument();
    expect(screen.getByText("generic view")).toBeInTheDocument();
    // Internal/derived types never appear.
    expect(screen.queryByText("file_hash")).not.toBeInTheDocument();
    expect(screen.queryByText(/File Hash/i)).not.toBeInTheDocument();
  });

  it("groups the record counts the same way, whatever the runtime locale", async () => {
    // This card is the first figure an examiner sees for a record type and it
    // gets quoted onward, so its grouping cannot follow the machine it is read
    // on: a de-DE runtime renders 1200 as "1.200", which an en-GB reader takes
    // for one point two. Stubbing the default locale rather than reading it,
    // because that is exactly what a de-DE runner does to this number.
    vi.spyOn(Number.prototype, "toLocaleString").mockImplementation(function (
      this: number,
    ) {
      return new Intl.NumberFormat("de-DE").format(Number(this));
    });

    renderPage();
    const link = await screen.findByRole("link", { name: /Browser History/ });
    expect(link).toHaveTextContent("1,200");
    expect(document.body.textContent).not.toMatch(/1\.200|9\.999/);
  });

  it("shows an empty state when no record types exist", async () => {
    mockTypes([]);
    renderPage();
    expect(await screen.findByText("No parsed records")).toBeInTheDocument();
  });

  it("shows an error state when the request fails", async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/record_types`, () =>
        HttpResponse.json(
          { error: { code: "INTERNAL", message: "types unavailable" } },
          { status: 500 },
        ),
      ),
    );
    renderPage();
    expect(await screen.findByText(/types unavailable/)).toBeInTheDocument();
  });
});

/**
 * UI-033. Counting is not importance: the index ranked by population, so a
 * macOS case opened with 78,093 recovered SQLite rows and 37,738 signature
 * analyses while the five iMessages and the device the case was about sat
 * below the fold.
 */
describe("the analysis index reads as a case, not a ranking", () => {
  it("leads with what people did and demotes what the tool derived", async () => {
    mockTypes([
      { type: "SqliteRow", count: 78093 },
      { type: "PerceptualHash", count: 16528 },
      { type: "iMessage", count: 5 },
      { type: "UtmpParseStatus", count: 73 },
    ]);
    renderPage();

    const headings = await screen.findAllByRole("heading", { level: 2 });
    expect(headings.map((h) => h.textContent)).toEqual([
      "People and messages",
      "Derived analysis",
      "What could not be read",
    ]);
  });

  it("says how many records a group holds, and what the group is", async () => {
    mockTypes([
      { type: "iMessage", count: 5 },
      { type: "EmailMessage", count: 64 },
    ]);
    renderPage();

    expect(
      await screen.findByRole("heading", { name: "People and messages" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/69 records/)).toBeInTheDocument();
    expect(
      screen.getByText(/Who this exhibit was in contact with/),
    ).toBeInTheDocument();
  });

  it("shows a type it has no category for rather than hiding it", async () => {
    mockTypes([{ type: "ZanyCustom", count: 3 }]);
    renderPage();

    expect(
      await screen.findByRole("heading", { name: "Other records" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /Zany Custom/ }),
    ).toBeInTheDocument();
  });
});
