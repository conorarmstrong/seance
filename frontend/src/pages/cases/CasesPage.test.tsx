import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { Case } from "../../api/types";
import { RequireAuth } from "../../app/RequireAuth";
import { AuthProvider } from "../../auth/AuthProvider";
import { ToastProvider } from "../../components/toast/ToastProvider";
import { ThemeProvider } from "../../themes/ThemeProvider";
import { server } from "../../test/server";
import { CasesPage } from "./CasesPage";

const CASES: Case[] = [
  {
    id: "case-1",
    name: "Laptop Seizure",
    status: "open",
    reference_number: "REF-001",
    examiner_name: "Alice",
    created_at: "2026-01-05T10:00:00Z",
    last_accessed_at: "2026-03-04T08:15:00Z",
  },
  {
    id: "case-2",
    name: "Phone Dump",
    status: "closed",
    reference_number: "REF-002",
    examiner_name: "Bob",
    created_at: "2026-02-01T12:30:00Z",
    last_accessed_at: null,
  },
];

function mockList(cases: Case[] = CASES) {
  server.use(http.get("/api/v1/cases", () => HttpResponse.json(cases)));
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthProvider>
          {/* The header carries the theme control, and `ThemeProvider` reads the
              session — so it nests inside `AuthProvider`, as it does in
              App.tsx. */}
          <ThemeProvider>
            <MemoryRouter initialEntries={["/"]}>
              <Routes>
                <Route path="/" element={<CasesPage />} />
                <Route path="/cases/:caseId" element={<div>case-shell</div>} />
              </Routes>
            </MemoryRouter>
          </ThemeProvider>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe("CasesPage chrome on a server with auth disabled (LIVE-004)", () => {
  /**
   * The real composition: the page is only reachable through `RequireAuth`,
   * which is what asks the server for its mode. Rendering `CasesPage` alone
   * would leave the mode `unknown` forever and the assertion below would pass
   * for the wrong reason.
   */
  function renderGuarded() {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <AuthProvider>
            <ThemeProvider>
              <MemoryRouter initialEntries={["/"]}>
                <Routes>
                  <Route element={<RequireAuth />}>
                    <Route path="/" element={<CasesPage />} />
                  </Route>
                  <Route path="/login" element={<div>login screen</div>} />
                </Routes>
              </MemoryRouter>
            </ThemeProvider>
          </AuthProvider>
        </ToastProvider>
      </QueryClientProvider>,
    );
  }

  it("names the absent sign-in instead of offering a Sign out that ends nothing", async () => {
    // SEANCE_AUTH_ENABLED=false: `/auth/me` reports no accepted credentials and
    // the protected list answers anyway. Every action is attributed to the
    // local operator, and the chrome has to say so — a Sign out button implies
    // a session that could be ended and a name that could be produced later.
    server.use(
      http.get("/api/v1/auth/me", () =>
        HttpResponse.json({ authenticated: false }),
      ),
    );
    mockList();
    renderGuarded();

    expect(await screen.findByText("Laptop Seizure")).toBeInTheDocument();
    expect(screen.getByText("no sign-in required")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Sign out" }),
    ).not.toBeInTheDocument();
  });
});

describe("CasesPage", () => {
  it("renders the case cards with details", async () => {
    mockList();
    renderPage();
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    expect(await screen.findByText("Laptop Seizure")).toBeInTheDocument();
    expect(screen.getByText("Phone Dump")).toBeInTheDocument();
    expect(screen.getByText("REF-001")).toBeInTheDocument();
    expect(screen.getByText("Alice")).toBeInTheDocument();
    expect(screen.getByText("open")).toBeInTheDocument();
    expect(screen.getByText("2026-01-05 10:00:00 UTC")).toBeInTheDocument();
    // Header bar
    expect(screen.getByText("SÉANCE")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "New Case" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign out" }),
    ).toBeInTheDocument();
  });

  it("labels card metadata and shows last opened when present", async () => {
    mockList();
    renderPage();
    await screen.findByText("Laptop Seizure");

    // Small muted labels identify each metadata line.
    expect(screen.getAllByText("ref")).toHaveLength(2);
    expect(screen.getAllByText("examiner")).toHaveLength(2);
    expect(screen.getAllByText("created")).toHaveLength(2);

    // Only case-1 has been opened before.
    expect(screen.getAllByText("last opened")).toHaveLength(1);
    expect(screen.getByText("2026-03-04 08:15:00 UTC")).toBeInTheDocument();
  });

  it("closes the card menu on Escape and on outside click", async () => {
    mockList();
    renderPage();
    await screen.findByText("Laptop Seizure");

    const menuButton = screen.getByRole("button", {
      name: "Actions for Laptop Seizure",
    });
    await userEvent.click(menuButton);
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();

    await userEvent.click(menuButton);
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await userEvent.click(screen.getByText("SÉANCE"));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("shows the empty state when there are no cases", async () => {
    mockList([]);
    renderPage();
    expect(
      await screen.findByText(/create your first case/i),
    ).toBeInTheDocument();
  });

  it("filters cases by search text and status", async () => {
    mockList();
    renderPage();
    await screen.findByText("Laptop Seizure");

    await userEvent.type(screen.getByPlaceholderText(/search/i), "phone");
    expect(screen.queryByText("Laptop Seizure")).not.toBeInTheDocument();
    expect(screen.getByText("Phone Dump")).toBeInTheDocument();

    await userEvent.clear(screen.getByPlaceholderText(/search/i));
    await userEvent.selectOptions(
      screen.getByLabelText("Filter by status"),
      "open",
    );
    expect(screen.getByText("Laptop Seizure")).toBeInTheDocument();
    expect(screen.queryByText("Phone Dump")).not.toBeInTheDocument();
  });

  it("creates a case and navigates to it", async () => {
    mockList();
    let createdBody: Record<string, unknown> | null = null;
    server.use(
      http.post("/api/v1/cases", async ({ request }) => {
        createdBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          id: "case-new",
          name: "Fresh Case",
          status: "open",
          reference_number: "REF-9",
          examiner_name: "Carol",
          created_at: "2026-03-01T00:00:00Z",
          last_accessed_at: null,
        });
      }),
    );
    renderPage();
    await screen.findByText("Laptop Seizure");

    await userEvent.click(screen.getByRole("button", { name: "New Case" }));
    const dialog = screen.getByRole("dialog");
    // Create disabled until a name is entered
    expect(
      within(dialog).getByRole("button", { name: "Create" }),
    ).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Name"), "Fresh Case");
    await userEvent.type(within(dialog).getByLabelText(/reference/i), "REF-9");
    await userEvent.type(within(dialog).getByLabelText(/examiner/i), "Carol");
    await userEvent.click(
      within(dialog).getByRole("button", { name: "Create" }),
    );

    expect(await screen.findByText("case-shell")).toBeInTheDocument();
    expect(createdBody).toEqual({
      name: "Fresh Case",
      reference_number: "REF-9",
      examiner_name: "Carol",
    });
  });

  it("requires typing the case name before delete is enabled", async () => {
    let deleted = false;
    server.use(
      http.get("/api/v1/cases", () =>
        HttpResponse.json(deleted ? [CASES[1]] : CASES),
      ),
      http.delete("/api/v1/cases/case-1", () => {
        deleted = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderPage();
    await screen.findByText("Laptop Seizure");

    await userEvent.click(
      screen.getByRole("button", { name: "Actions for Laptop Seizure" }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Delete case" }));

    const dialog = screen.getByRole("dialog");
    const deleteButton = within(dialog).getByRole("button", { name: "Delete" });
    expect(deleteButton).toBeDisabled();

    const confirmInput = within(dialog).getByLabelText(/type the case name/i);
    await userEvent.type(confirmInput, "Wrong Name");
    expect(deleteButton).toBeDisabled();

    await userEvent.clear(confirmInput);
    await userEvent.type(confirmInput, "Laptop Seizure");
    expect(deleteButton).toBeEnabled();

    await userEvent.click(deleteButton);
    await waitFor(() =>
      expect(screen.queryByText("Laptop Seizure")).not.toBeInTheDocument(),
    );
    expect(deleted).toBe(true);
    expect(screen.getByText("Phone Dump")).toBeInTheDocument();
  });

  it("shows an error state when the list fails", async () => {
    server.use(
      http.get("/api/v1/cases", () =>
        HttpResponse.json(
          { error: { code: "INTERNAL", message: "boom" } },
          { status: 500 },
        ),
      ),
    );
    renderPage();
    expect(await screen.findByText(/boom/)).toBeInTheDocument();
  });
});
