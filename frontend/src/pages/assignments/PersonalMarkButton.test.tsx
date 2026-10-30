import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { server } from "../../test/server";
import { PersonalMarkButton } from "./PersonalMarkButton";

describe("PersonalMarkButton (§3.15)", () => {
  it("adds a private mark and says it is not reported", async () => {
    let body: unknown = null;
    server.use(
      http.post("/api/v1/cases/c1/personal_bookmarks", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ id: "p1" }, { status: 201 });
      }),
    );
    render(
      <QueryClientProvider client={new QueryClient()}>
        <PersonalMarkButton caseId="c1" artifactId="x1" />
      </QueryClientProvider>,
    );
    const btn = screen.getByRole("button", { name: /mark privately/i });
    expect(btn).toHaveAttribute(
      "title",
      expect.stringMatching(/never.*report/i),
    );
    await userEvent.click(btn);
    expect(
      await screen.findByRole("button", { name: /marked privately/i }),
    ).toBeInTheDocument();
    expect(body).toEqual({ artifact_id: "x1" });
  });
});
