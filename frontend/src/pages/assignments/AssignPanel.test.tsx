import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { server } from "../../test/server";
import { AssignPanel } from "./AssignPanel";

function wrap(ids: string[]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <AssignPanel caseId="c1" artifactIds={ids} />
    </QueryClientProvider>,
  );
}

describe("AssignPanel (§3.15)", () => {
  it("is not offered to someone the server would refuse (not owner)", async () => {
    server.use(
      http.get("/api/v1/cases/c1/access", () =>
        HttpResponse.json({ error: { message: "no" } }, { status: 403 }),
      ),
    );
    wrap(["x1"]);
    // Wait for the question to settle, then nothing is rendered.
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByTestId("assign-panel")).toBeNull();
  });

  it("offers only examiners who can record reviews and posts the selection", async () => {
    let posted: unknown = null;
    server.use(
      http.get("/api/v1/cases/c1/access", () =>
        HttpResponse.json([
          { user_id: "u1", username: "alice", access_level: "read_write" },
          { user_id: "u2", username: "rita", access_level: "read_only" },
        ]),
      ),
      http.post("/api/v1/cases/c1/assignments", async ({ request }) => {
        posted = await request.json();
        return HttpResponse.json({ id: "a1" }, { status: 201 });
      }),
    );
    wrap(["x1", "x2"]);
    const panel = await screen.findByTestId("assign-panel");
    expect(panel).toHaveTextContent("read_only");
    const select = screen.getByRole("combobox", { name: /assign to/i });
    const options = Array.from((select as HTMLSelectElement).options).map(
      (o) => o.textContent,
    );
    expect(options.some((o) => o?.includes("alice"))).toBe(true);
    expect(options.some((o) => o?.includes("rita"))).toBe(false);
    await userEvent.selectOptions(select, "u1");
    await userEvent.click(screen.getByRole("button", { name: /assign 2/i }));
    await screen.findByTestId("assign-done");
    expect(posted).toEqual({
      assignee_user_id: "u1",
      artifact_ids: ["x1", "x2"],
    });
  });

  it("posts a due date as Unix seconds when one is chosen, and omits it otherwise", async () => {
    let posted: Record<string, unknown> | null = null;
    server.use(
      http.get("/api/v1/cases/c1/access", () =>
        HttpResponse.json([
          { user_id: "u1", username: "alice", access_level: "read_write" },
        ]),
      ),
      http.post("/api/v1/cases/c1/assignments", async ({ request }) => {
        posted = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ id: "a1" }, { status: 201 });
      }),
    );
    wrap(["x1"]);
    await screen.findByTestId("assign-panel");
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: /assign to/i }),
      "u1",
    );
    await userEvent.type(screen.getByLabelText(/due/i), "2099-01-31");
    await userEvent.click(screen.getByRole("button", { name: /assign 1/i }));
    await screen.findByTestId("assign-done");
    const due = posted!.due_at as number;
    expect(typeof due).toBe("number");
    // The end of 31 January 2099, in the examiner's own day.
    expect(new Date(due * 1000).getFullYear()).toBe(2099);
    expect(new Date(due * 1000).getDate()).toBe(31);
  });

  function failWith(status: number, message: string) {
    server.use(
      http.get("/api/v1/cases/c1/access", () =>
        HttpResponse.json([
          { user_id: "u1", username: "alice", access_level: "read_write" },
        ]),
      ),
      http.post("/api/v1/cases/c1/assignments", () =>
        HttpResponse.json({ error: { message } }, { status }),
      ),
    );
  }

  async function assignOne() {
    wrap(["x1"]);
    await screen.findByTestId("assign-panel");
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: /assign to/i }),
      "u1",
    );
    await userEvent.click(screen.getByRole("button", { name: /assign 1/i }));
    return screen.findByRole("alert");
  }

  it("a refusal (4xx) says nothing was recorded", async () => {
    failWith(400, "cannot record reviews");
    const alert = await assignOne();
    expect(alert).toHaveTextContent("Nothing was recorded");
  });

  it("a server failure (5xx) does not claim nothing was recorded", async () => {
    // The assignment is written before its audit entry; a failure after the
    // write returns 500 with the assignment already stored.
    failWith(500, "audit write failed");
    const alert = await assignOne();
    expect(alert).not.toHaveTextContent("Nothing was recorded");
    expect(alert).toHaveTextContent("may have been recorded");
  });
});
