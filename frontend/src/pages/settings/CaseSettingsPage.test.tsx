import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { server } from "../../test/server";
import { AuthProvider } from "../../auth/AuthProvider";
import { ToastProvider } from "../../components/toast/ToastProvider";
import { ThemeProvider } from "../../themes/ThemeProvider";
import type { Case, IngestionProfile } from "../../api/types";
import { CaseSettingsPage } from "./CaseSettingsPage";

const CASE_ID = "case-1";

const testCase: Case = {
  id: CASE_ID,
  name: "Alpha Case",
  status: "open",
  reference_number: "REF-9",
  examiner_name: "Rivera",
  created_at: "2026-01-01T00:00:00Z",
  last_accessed_at: "2026-02-01T12:30:00Z",
};

const profiles: IngestionProfile[] = [
  {
    id: "p-1",
    case_id: CASE_ID,
    name: "triage",
    description: "Fast triage pass",
    enabled_modules: ["a", "b", "c"],
    disabled_modules: [],
    is_active: true,
    created_at: 1700000000,
  },
  {
    id: "p-2",
    case_id: CASE_ID,
    name: "full",
    description: "Everything enabled",
    enabled_modules: ["a", "b", "c", "d", "e"],
    disabled_modules: [],
    is_active: false,
    created_at: 1700000000,
  },
];

beforeEach(() => {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}`, () => HttpResponse.json(testCase)),
    http.get(`/api/v1/cases/${CASE_ID}/profiles`, () =>
      HttpResponse.json(profiles),
    ),
  );
});

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  render(
    <QueryClientProvider client={queryClient}>
      {/* In the order App.tsx nests them: AuthProvider reads the toast context
          (a failed logout revocation is reported through it), ThemeProvider
          reads the session, and the Appearance panel reads the theme. */}
      <ToastProvider>
        <AuthProvider>
          <ThemeProvider>
            <MemoryRouter initialEntries={[`/cases/${CASE_ID}/settings`]}>
              <Routes>
                <Route path="/" element={<div>cases home</div>} />
                <Route
                  path="/cases/:caseId/settings"
                  element={<CaseSettingsPage />}
                />
              </Routes>
            </MemoryRouter>
          </ThemeProvider>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe("CaseSettingsPage", () => {
  it("renders the edit form and read-only case details", async () => {
    renderPage();
    expect(await screen.findByLabelText(/case name/i)).toHaveValue(
      "Alpha Case",
    );
    expect(screen.getByLabelText(/reference number/i)).toHaveValue("REF-9");
    expect(screen.getByLabelText(/examiner/i)).toHaveValue("Rivera");
    expect(screen.getByText(CASE_ID)).toBeInTheDocument();
    expect(screen.getByText("open")).toBeInTheDocument();
    expect(screen.getByText("2026-01-01 00:00:00 UTC")).toBeInTheDocument();
    expect(screen.getByText("2026-02-01 12:30:00 UTC")).toBeInTheDocument();
  });

  it("shows an error state when the case fails to load", async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}`, () =>
        HttpResponse.json(
          { error: { code: "NOT_FOUND", message: "case missing" } },
          { status: 404 },
        ),
      ),
    );
    renderPage();
    expect(await screen.findByText(/case missing/)).toBeInTheDocument();
  });

  it("saves edits and toasts", async () => {
    let body: Record<string, unknown> | null = null;
    server.use(
      http.put(`/api/v1/cases/${CASE_ID}`, async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ ...testCase, ...body });
      }),
    );
    renderPage();
    const nameInput = await screen.findByLabelText(/case name/i);

    const user = userEvent.setup();
    await user.clear(nameInput);
    await user.type(nameInput, "Beta Case");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("Saved")).toBeInTheDocument();
    expect(body).toEqual({
      name: "Beta Case",
      reference_number: "REF-9",
      examiner_name: "Rivera",
    });
  });

  it("lists profiles and activates one", async () => {
    let activated = false;
    server.use(
      http.post(`/api/v1/cases/${CASE_ID}/profiles/p-2/activate`, () => {
        activated = true;
        return HttpResponse.json({ status: "activated" });
      }),
    );
    renderPage();
    await screen.findByText("triage");
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();

    const user = userEvent.setup();
    const row = screen.getByText("full").closest("tr")!;
    await user.click(within(row).getByRole("button", { name: "Activate" }));
    await waitFor(() => expect(activated).toBe(true));
  });

  it("deletes a profile after confirmation", async () => {
    let deleted = false;
    server.use(
      http.delete(`/api/v1/cases/${CASE_ID}/profiles/p-2`, () => {
        deleted = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderPage();
    await screen.findByText("full");

    const user = userEvent.setup();
    const row = screen.getByText("full").closest("tr")!;
    await user.click(within(row).getByRole("button", { name: "Delete" }));
    const dialog = screen.getByRole("dialog", { name: /delete profile/i });
    await user.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(deleted).toBe(true));
  });

  it("gates case deletion behind typing the exact case name", async () => {
    let deleted = false;
    server.use(
      http.delete(`/api/v1/cases/${CASE_ID}`, () => {
        deleted = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderPage();
    await screen.findByLabelText(/case name/i);

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Delete case" }));
    const dialog = screen.getByRole("dialog", { name: /delete case/i });
    const confirmButton = within(dialog).getByRole("button", {
      name: "Delete permanently",
    });
    expect(confirmButton).toBeDisabled();

    const confirmInput = within(dialog).getByLabelText(/type the case name/i);
    await user.type(confirmInput, "Alpha");
    expect(confirmButton).toBeDisabled();

    await user.clear(confirmInput);
    await user.type(confirmInput, "Alpha Case");
    expect(confirmButton).toBeEnabled();

    await user.click(confirmButton);
    await waitFor(() => expect(deleted).toBe(true));
    expect(await screen.findByText("cases home")).toBeInTheDocument();
  });
});
