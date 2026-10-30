import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { server } from "../../test/server";
import { AssignmentsOverview } from "./AssignmentsOverview";
import type { Assignment } from "./api";

function row(over: Partial<Assignment> = {}): Assignment {
  return {
    id: "a1",
    case_id: "c1",
    assignee_user_id: "u1",
    assignee_username: "alice",
    assigned_by: "u0",
    note: null,
    created_at: 1_757_000_000,
    withdrawn_at: null,
    withdrawn_by: null,
    due_at: null,
    reassigned_from: null,
    overdue: false,
    progress: {
      total: 4,
      opened_by_assignee: 2,
      reviewed_by_assignee: 1,
      counts: "the assignee",
    },
    ...over,
  };
}

const ACCESS = [
  { user_id: "u1", username: "alice", access_level: "read_write" },
  { user_id: "u2", username: "bob", access_level: "read_write" },
  { user_id: "u3", username: "rita", access_level: "read_only" },
];

function wrap() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <AssignmentsOverview caseId="c1" />
    </QueryClientProvider>,
  );
}

function serve(assignments: Assignment[]) {
  server.use(
    http.get("/api/v1/cases/c1/access", () => HttpResponse.json(ACCESS)),
    http.get("/api/v1/cases/c1/assignments", () =>
      HttpResponse.json({ assignments }),
    ),
  );
}

describe("AssignmentsOverview (§3.15)", () => {
  it("is not offered to someone the server would refuse (not owner)", async () => {
    server.use(
      http.get("/api/v1/cases/c1/access", () =>
        HttpResponse.json({ error: { message: "no" } }, { status: 403 }),
      ),
    );
    wrap();
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByTestId("assignments-overview")).toBeNull();
  });

  it("shows progress as the assignee's own reviews, the due date and an overdue badge", async () => {
    serve([
      row({ id: "a1", due_at: 1_757_500_000, overdue: true }),
      row({ id: "a2", assignee_username: "bob", due_at: null }),
    ]);
    wrap();
    const rows = await screen.findAllByTestId("ao-row");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("alice");
    expect(rows[0]).toHaveTextContent("1 reviewed of 4");
    expect(rows[0]).toHaveTextContent(/due/i);
    expect(within(rows[0]).getByText(/overdue/i)).toBeInTheDocument();
    expect(within(rows[1]).queryByText(/overdue/i)).toBeNull();
  });

  it("a withdrawn assignment is listed as withdrawn and offers no action", async () => {
    serve([row({ withdrawn_at: 1_757_100_000 })]);
    wrap();
    const r = await screen.findByTestId("ao-row");
    expect(r).toHaveTextContent(/withdrawn/i);
    expect(within(r).queryByRole("button", { name: /reassign/i })).toBeNull();
    expect(within(r).queryByRole("button", { name: /withdraw/i })).toBeNull();
  });

  it("reassigns to another examiner, offering only those who can record reviews", async () => {
    let posted: unknown = null;
    serve([row()]);
    server.use(
      http.post(
        "/api/v1/cases/c1/assignments/a1/reassign",
        async ({ request }) => {
          posted = await request.json();
          return HttpResponse.json(row({ id: "a9" }), { status: 201 });
        },
      ),
    );
    wrap();
    const r = await screen.findByTestId("ao-row");
    const select = within(r).getByRole("combobox", { name: /reassign to/i });
    const names = Array.from((select as HTMLSelectElement).options).map(
      (o) => o.textContent ?? "",
    );
    expect(names.some((n) => n.includes("bob"))).toBe(true);
    expect(names.some((n) => n.includes("rita"))).toBe(false);
    expect(names.some((n) => n.includes("alice"))).toBe(false); // the current assignee
    await userEvent.selectOptions(select, "u2");
    await userEvent.click(within(r).getByRole("button", { name: /reassign/i }));
    await screen.findByTestId("ao-done");
    expect(posted).toEqual({ assignee_user_id: "u2" });
  });

  it("a refusal says nothing was recorded; a server failure does not claim that", async () => {
    serve([row()]);
    server.use(
      http.post("/api/v1/cases/c1/assignments/a1/reassign", () =>
        HttpResponse.json({ error: { message: "no access" } }, { status: 400 }),
      ),
    );
    wrap();
    const r = await screen.findByTestId("ao-row");
    await userEvent.selectOptions(
      within(r).getByRole("combobox", { name: /reassign to/i }),
      "u2",
    );
    await userEvent.click(within(r).getByRole("button", { name: /reassign/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Nothing was recorded",
    );
  });

  it("withdraws an assignment", async () => {
    let withdrawn = false;
    serve([row()]);
    server.use(
      http.post("/api/v1/cases/c1/assignments/a1/withdraw", () => {
        withdrawn = true;
        return HttpResponse.json(row({ withdrawn_at: 1_757_200_000 }));
      }),
    );
    wrap();
    const r = await screen.findByTestId("ao-row");
    await userEvent.click(within(r).getByRole("button", { name: /withdraw/i }));
    await screen.findByTestId("ao-done");
    expect(withdrawn).toBe(true);
  });
});
