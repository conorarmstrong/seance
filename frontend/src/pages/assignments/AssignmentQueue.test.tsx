import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { server } from "../../test/server";
import { AssignmentQueue } from "./AssignmentQueue";
import { PersonalBookmarksPanel } from "./PersonalBookmarksPanel";
import type { Assignment, PersonalBookmark } from "./api";

function assignment(over: Partial<Assignment> = {}): Assignment {
  return {
    id: "a1",
    case_id: "c1",
    assignee_user_id: "u1",
    assignee_username: "alice",
    assigned_by: "u0",
    note: "triage the browser history",
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

function wrap(ui: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AssignmentQueue (§3.15)", () => {
  it("a failed fetch says it could not be read and never that nothing is assigned", async () => {
    server.use(
      http.get("/api/v1/cases/c1/assignments", () =>
        HttpResponse.json({ error: { message: "boom" } }, { status: 500 }),
      ),
    );
    wrap(<AssignmentQueue caseId="c1" />);
    const err = await screen.findByTestId("aq-error");
    expect(err).toHaveTextContent("could not be read");
    expect(screen.queryByText(/nothing assigned/i)).toBeNull();
  });

  it("an empty answer says nothing is assigned to you in this case", async () => {
    server.use(
      http.get("/api/v1/cases/c1/assignments", () =>
        HttpResponse.json({ assignments: [] }),
      ),
    );
    wrap(<AssignmentQueue caseId="c1" />);
    expect(await screen.findByTestId("aq-empty")).toHaveTextContent(
      "Nothing assigned to you in this case",
    );
  });

  it("shows the due date and an overdue flag only when the server says so", async () => {
    server.use(
      http.get("/api/v1/cases/c1/assignments", () =>
        HttpResponse.json({
          assignments: [
            assignment({ id: "a1", due_at: 1_757_500_000, overdue: true }),
            assignment({ id: "a2", due_at: 1_999_999_999, overdue: false }),
          ],
        }),
      ),
      http.get("/api/v1/cases/c1/assignments/:id/queue", () =>
        HttpResponse.json({
          assignment: assignment(),
          progress: assignment().progress,
          items: [],
          limit: 100,
          offset: 0,
          has_more: false,
          undecodable: 0,
        }),
      ),
    );
    wrap(<AssignmentQueue caseId="c1" />);
    const blocks = await screen.findAllByTestId("aq-block");
    expect(blocks).toHaveLength(2);
    expect(blocks[0].querySelector('[data-testid="aq-overdue"]')).not.toBeNull();
    expect(blocks[1].querySelector('[data-testid="aq-overdue"]')).toBeNull();
    expect(blocks[1].querySelector('[data-testid="aq-due"]')).not.toBeNull();
  });

  it("states progress as the assignee’s own reviews and lists what is left", async () => {
    server.use(
      http.get("/api/v1/cases/c1/assignments", ({ request }) => {
        expect(new URL(request.url).searchParams.get("mine")).toBe("true");
        return HttpResponse.json({ assignments: [assignment()] });
      }),
      http.get("/api/v1/cases/c1/assignments/a1/queue", () =>
        HttpResponse.json({
          assignment: assignment(),
          progress: assignment().progress,
          items: [
            { artifact_id: "x1", artifact_type: "FileEntry", opened_at: null },
            {
              artifact_id: "x2",
              artifact_type: "FileEntry",
              opened_at: 1_757_000_100,
            },
          ],
          limit: 1000,
          offset: 0,
          has_more: false,
          undecodable: 0,
        }),
      ),
    );
    wrap(<AssignmentQueue caseId="c1" />);
    const progress = await screen.findByTestId("aq-progress");
    expect(progress).toHaveTextContent("1 reviewed of 4");
    expect(progress).toHaveTextContent("your own reviews");
    expect(progress).toHaveTextContent("colleague's review");
    expect(await screen.findAllByTestId("aq-item")).toHaveLength(2);
  });

  function emptyQueue(over: { undecodable?: number; total?: number }) {
    const progress = { ...assignment().progress, total: over.total ?? 4 };
    const a = assignment({ progress });
    server.use(
      http.get("/api/v1/cases/c1/assignments", () =>
        HttpResponse.json({ assignments: [a] }),
      ),
      http.get("/api/v1/cases/c1/assignments/a1/queue", () =>
        HttpResponse.json({
          assignment: a,
          progress,
          items: [],
          limit: 1000,
          offset: 0,
          has_more: false,
          undecodable: over.undecodable ?? 0,
        }),
      ),
    );
  }

  it("an empty queue with unreadable items never claims everything was reviewed", async () => {
    emptyQueue({ undecodable: 2 });
    wrap(<AssignmentQueue caseId="c1" />);
    expect(await screen.findByTestId("aq-unreadable-only")).toHaveTextContent(
      "could not be read",
    );
    expect(screen.queryByTestId("aq-done")).toBeNull();
    expect(screen.queryByText(/reviewed every item/i)).toBeNull();
  });

  it("an assignment whose artifacts are all gone does not say you reviewed them", async () => {
    emptyQueue({ total: 0 });
    wrap(<AssignmentQueue caseId="c1" />);
    expect(await screen.findByTestId("aq-no-items")).toHaveTextContent(
      "no longer holds any item",
    );
    expect(screen.queryByTestId("aq-done")).toBeNull();
  });

  it("an empty, fully readable queue with items assigned says every item was reviewed", async () => {
    emptyQueue({});
    wrap(<AssignmentQueue caseId="c1" />);
    expect(await screen.findByTestId("aq-done")).toHaveTextContent(
      "reviewed every item",
    );
  });

  it("a withdrawn assignment is not shown as live work", async () => {
    server.use(
      http.get("/api/v1/cases/c1/assignments", () =>
        HttpResponse.json({
          assignments: [assignment({ withdrawn_at: 1_757_000_500 })],
        }),
      ),
    );
    wrap(<AssignmentQueue caseId="c1" />);
    expect(await screen.findByTestId("aq-empty")).toBeInTheDocument();
    expect(screen.getByTestId("aq-withdrawn")).toHaveTextContent("1 withdrawn");
  });
});

function personal(over: Partial<PersonalBookmark> = {}): PersonalBookmark {
  return {
    id: "p1",
    case_id: "c1",
    artifact_id: "x1",
    owner_user_id: "u1",
    note: "check later",
    created_at: 1_757_000_000,
    updated_at: 1_757_000_000,
    promoted_at: null,
    promoted_bookmark_id: null,
    in_shared_set: false,
    artifact_type: "FileEntry",
    ...over,
  };
}

describe("PersonalBookmarksPanel (§3.15)", () => {
  it("says the marks are private and never reported, and promotes on request", async () => {
    let promoted = false;
    server.use(
      http.get("/api/v1/cases/c1/personal_bookmarks", () =>
        HttpResponse.json({
          items: [personal()],
          limit: 1000,
          offset: 0,
          has_more: false,
          undecodable: 0,
          visibility: "private",
        }),
      ),
      http.post("/api/v1/cases/c1/personal_bookmarks/p1/promote", () => {
        promoted = true;
        return HttpResponse.json({ promoted: true, shared_bookmark_id: "b1" });
      }),
    );
    wrap(<PersonalBookmarksPanel caseId="c1" />);
    const panel = await screen.findByTestId("personal-bookmarks");
    expect(panel).toHaveTextContent("Only you see these");
    expect(panel).toHaveTextContent("never included in a report");
    await userEvent.click(
      await screen.findByRole("button", { name: /add to shared bookmarks/i }),
    );
    await screen.findByTestId("pb-promoted-note");
    expect(promoted).toBe(true);
  });

  function listOf(items: PersonalBookmark[]) {
    server.use(
      http.get("/api/v1/cases/c1/personal_bookmarks", () =>
        HttpResponse.json({
          items,
          limit: 1000,
          offset: 0,
          has_more: false,
          undecodable: 0,
          visibility: "private",
        }),
      ),
    );
  }

  it("a promoted mark whose shared bookmark still exists is shown as in the shared set", async () => {
    listOf([
      personal({
        promoted_at: 1_757_000_100,
        promoted_bookmark_id: "b1",
        in_shared_set: true,
      }),
    ]);
    wrap(<PersonalBookmarksPanel caseId="c1" />);
    expect(await screen.findByTestId("pb-in-shared")).toHaveTextContent(
      "in shared bookmarks",
    );
    expect(
      screen.queryByRole("button", { name: /add to shared bookmarks/i }),
    ).toBeNull();
  });

  it("a promoted mark whose shared bookmark was deleted is not claimed to be reported and can be added again", async () => {
    listOf([
      personal({
        promoted_at: 1_757_000_100,
        promoted_bookmark_id: "b1",
        in_shared_set: false,
      }),
    ]);
    wrap(<PersonalBookmarksPanel caseId="c1" />);
    const item = await screen.findByTestId("pb-item");
    expect(item).not.toHaveTextContent("in shared bookmarks");
    expect(item).toHaveTextContent("shared bookmark it became was deleted");
    expect(
      screen.getByRole("button", { name: /add to shared bookmarks/i }),
    ).toBeInTheDocument();
  });

  it('a failed fetch is not "you have no personal marks"', async () => {
    server.use(
      http.get("/api/v1/cases/c1/personal_bookmarks", () =>
        HttpResponse.json({ error: { message: "x" } }, { status: 500 }),
      ),
    );
    wrap(<PersonalBookmarksPanel caseId="c1" />);
    expect(await screen.findByTestId("pb-error")).toHaveTextContent(
      "could not be read",
    );
    expect(screen.queryByTestId("pb-empty")).toBeNull();
  });
});
