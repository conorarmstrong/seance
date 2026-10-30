import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { server } from "../../test/server";
import type { SweepRequest, SweepResponse } from "./api";
import { ByteSweepPanel } from "./ByteSweepPanel";

/**
 * Synthetic answers in the route's serialized shape
 * (`SweepResponse` flattened into `SweepRouteResponse`). They pin what the
 * panel shows of an answer, not how the sweep behaves on evidence — that is
 * `seance_api/tests/search_sweep_api_test.rs` and `VALIDATION.md` CFTT-SWEEP-1.
 */
const SLACK_SENTENCE =
  "Slack is offered as the file-slack regions the NTFS, FAT and exFAT parsers publish.";

function cutSweep(overrides: Partial<SweepResponse> = {}): SweepResponse {
  return {
    hits: [
      {
        artifact_id: "a1",
        artifact_type: "FileContent",
        region: "live",
        path: "/docs/a.txt",
        offset: 10,
        length: 18,
        pattern_index: 0,
        pattern_kind: "text",
        pattern_value: "SecretKey",
        encodings: ["utf-16le", "utf-16be"],
        endian_aliases: [{ encoding: "utf-16be", offset: 9, folded: true }],
      },
    ],
    scope_statement: "Searched every region.",
    regions_searched: ["live", "slack", "unallocated", "recovered", "raw"],
    regions_not_searched: [],
    objects_offered: 3,
    objects_searched: 2,
    objects_empty: 0,
    objects_offered_by_region: { live: 2, slack: 0, raw: 1 },
    objects_searched_by_region: { live: 2 },
    bytes_scanned: 5000,
    bytes_declared: 9000,
    beyond_declared_size: [
      {
        artifact_id: "a4",
        declared_size: 10,
        source_size: 30,
        bytes_beyond: 20,
      },
    ],
    hits_endian_ambiguous: 1,
    max_hits: 1,
    hit_cap_reached: true,
    max_bytes: 4096,
    byte_cap_reached: false,
    next_cursor: { artifact_id: "a1", offset: 28 },
    complete: false,
    coverage_statement: "Stopped at the hit ceiling.",
    short_reads: [{ artifact_id: "a2", declared_size: 100, bytes_read: 40 }],
    read_failures: [{ artifact_id: "a3", offset: 0, error: "source gone" }],
    encodings_searched: ["utf-8", "utf-16le", "utf-16be"],
    codepages_absent: [],
    encodings_skipped: [],
    elapsed_ms: 7,
    max_hits_ceiling: 10000,
    max_bytes_ceiling: 17179869184,
    objects_ceiling: 50000,
    object_stream_cut: false,
    objects_without_bytes: 4,
    raw_objects_not_offered: 0,
    slack_statement: SLACK_SENTENCE,
    ...overrides,
  };
}

let bodies: SweepRequest[] = [];

function mockSweep(...answers: SweepResponse[]) {
  let call = 0;
  server.use(
    http.post("/api/v1/cases/c1/search/sweep", async ({ request }) => {
      bodies.push((await request.json()) as SweepRequest);
      const answer = answers[Math.min(call, answers.length - 1)];
      call += 1;
      return HttpResponse.json(answer);
    }),
  );
}

function renderPanel() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ByteSweepPanel caseId="c1" />
    </QueryClientProvider>,
  );
}

async function openAndSweep(text = "SecretKey") {
  const user = userEvent.setup();
  renderPanel();
  await user.click(screen.getByText(/byte sweep/i, { selector: "summary" }));
  await user.type(screen.getByLabelText("Sweep text"), text);
  await user.click(screen.getByRole("button", { name: "Sweep" }));
  return user;
}

beforeEach(() => {
  bodies = [];
});

describe("ByteSweepPanel", () => {
  it("posts patterns, codepages and scope to /cases/:id/search/sweep", async () => {
    mockSweep(cutSweep());
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByText(/byte sweep/i, { selector: "summary" }));
    await user.type(screen.getByLabelText("Sweep text"), "SecretKey");
    await user.type(screen.getByLabelText("Sweep bytes (hex)"), "4d5a");
    await user.type(
      screen.getByLabelText("Sweep code pages"),
      "windows-1252, koi8-r",
    );
    await user.type(screen.getByLabelText("Sweep extensions"), ".txt,.doc");
    await user.click(screen.getByRole("checkbox", { name: "raw" }));
    await user.clear(screen.getByLabelText("Sweep max hits"));
    await user.type(screen.getByLabelText("Sweep max hits"), "50");
    await user.click(screen.getByRole("button", { name: "Sweep" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      patterns: [
        { kind: "text", value: "SecretKey" },
        { kind: "bytes", value: "4d5a" },
      ],
      codepages: ["windows-1252", "koi8-r"],
      scope: {
        extensions: [".txt", ".doc"],
        regions: ["live", "slack", "unallocated", "recovered"],
      },
      bounds: { max_hits: 50 },
    });
  });

  it("an incomplete sweep is never shown as finished, and Resume re-posts with the cursor", async () => {
    mockSweep(
      cutSweep(),
      cutSweep({ complete: true, hit_cap_reached: false, next_cursor: null }),
    );
    const user = await openAndSweep();
    const status = await screen.findByTestId("sweep-status");
    expect(status).toHaveTextContent("Incomplete");
    expect(status).not.toHaveTextContent(/^Complete/);
    expect(
      screen.getByText(/hit ceiling of 1 was reached/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Stopped at the hit ceiling\./),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /resume/i }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1].resume).toEqual({ artifact_id: "a1", offset: 28 });
    expect(bodies[1].patterns).toEqual(bodies[0].patterns);
    await waitFor(() =>
      expect(screen.getByTestId("sweep-status")).toHaveTextContent("Complete"),
    );
    expect(screen.queryByRole("button", { name: /resume/i })).toBeNull();
  });

  it("an incomplete sweep with no cursor says it cannot be continued", async () => {
    mockSweep(cutSweep({ next_cursor: null, hit_cap_reached: false }));
    await openAndSweep();
    expect(await screen.findByTestId("sweep-status")).toHaveTextContent(
      "Incomplete",
    );
    expect(screen.getByText(/cannot be continued/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /resume/i })).toBeNull();
  });

  it("the slack statement is always shown beside slack: 0", async () => {
    mockSweep(cutSweep());
    await openAndSweep();
    const table = await screen.findByRole("table", { name: /by region/i });
    const slackRow = within(table).getByRole("row", { name: /slack/ });
    expect(slackRow).toHaveTextContent("0");
    expect(screen.getByText(SLACK_SENTENCE)).toBeInTheDocument();
  });

  it("an endian-ambiguous hit names both encodings and both offsets", async () => {
    mockSweep(cutSweep());
    await openAndSweep();
    const hit = await screen.findByTestId("sweep-hit-0");
    expect(hit).toHaveTextContent("utf-16le, utf-16be");
    expect(hit).toHaveTextContent("offset 10");
    expect(hit).toHaveTextContent(/also reads as utf-16be at offset 9/);
  });

  it("short reads, read failures and bytes beyond the declared size are listed, not hidden", async () => {
    mockSweep(cutSweep());
    await openAndSweep();
    expect(
      await screen.findByText(/a2 ended at 40 of a declared 100 bytes/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/a3 failed at offset 0: source gone/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/a4 holds 20 bytes past its declared 10/),
    ).toBeInTheDocument();
  });

  it("a 400 refusal shows the server's message", async () => {
    server.use(
      http.post("/api/v1/cases/c1/search/sweep", () =>
        HttpResponse.json(
          {
            error: {
              code: "BAD_REQUEST",
              message: "pattern 1 duplicates pattern 0",
            },
          },
          { status: 400 },
        ),
      ),
    );
    await openAndSweep();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "pattern 1 duplicates pattern 0",
    );
  });

  it("a sweep with no pattern is not sent", async () => {
    mockSweep(cutSweep());
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByText(/byte sweep/i, { selector: "summary" }));
    expect(screen.getByRole("button", { name: "Sweep" })).toBeDisabled();
    expect(bodies).toHaveLength(0);
  });
});
