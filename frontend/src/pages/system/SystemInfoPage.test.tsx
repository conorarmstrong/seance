import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { server } from "../../test/server";
import { MAX_SOURCE_SECTIONS, SystemInfoPage } from "./SystemInfoPage";

const CASE_ID = "case-1";

function mock(info: unknown, sources: { id: string; name: string }[] = []) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/system_info`, () =>
      HttpResponse.json(info as Parameters<typeof HttpResponse.json>[0]),
    ),
    http.get(`/api/v1/cases/${CASE_ID}/artifacts/root/children`, () =>
      HttpResponse.json({
        items: sources.map((s) => ({
          id: s.id,
          parent_id: null,
          artifact_type: "RawEvidence",
          name: s.name,
          has_children: true,
        })),
      }),
    ),
  );
}

/** system_info whose payload depends on the ?source_id= param. */
function mockScoped(
  bySource: Record<string, unknown>,
  sources: { id: string; name: string }[],
) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/system_info`, ({ request }) => {
      const sid = new URL(request.url).searchParams.get("source_id");
      const payload = (sid && bySource[sid]) || bySource["__all__"];
      return HttpResponse.json(
        payload as Parameters<typeof HttpResponse.json>[0],
      );
    }),
    http.get(`/api/v1/cases/${CASE_ID}/artifacts/root/children`, () =>
      HttpResponse.json({
        items: sources.map((s) => ({
          id: s.id,
          parent_id: null,
          artifact_type: "RawEvidence",
          name: s.name,
          has_children: true,
        })),
      }),
    ),
  );
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/system-info`]}>
        <Routes>
          <Route
            path="/cases/:caseId/system-info"
            element={<SystemInfoPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SystemInfoPage", () => {
  it("shows each local account's RID, last logon and whether it is enabled", async () => {
    // ROADMAP §2.6 names the RID and the last-login time as what was unread:
    // they live in the SAM `F` and `V` binary values, and this page showed a
    // list of names only.
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: "WKS-WIN732BITA",
      timezone: null,
      last_shutdown: null,
      users: [],
      sam_accounts: ["Administrator", "Guest", "Preston"],
      local_accounts: [
        {
          type: "LocalAccount",
          username: "Administrator",
          rid: 500,
          last_logon: "2010-11-20T21:48:12.569244+00:00",
          login_count: 6,
          account_enabled: false,
        },
        {
          type: "LocalAccount",
          username: "Guest",
          rid: 501,
          last_logon: null,
          last_logon_absent_reason:
            "Not recorded: this field is zero in the account's F value, which is what Windows leaves when the account has never logged on.",
          login_count: 0,
          account_enabled: false,
        },
        {
          type: "LocalAccount",
          username: "Preston",
          rid: 1000,
          last_logon: "2014-09-30T02:59:34.316692+00:00",
          login_count: 4,
          account_enabled: true,
        },
      ],
      local_accounts_note:
        "3 account(s) are in this machine's SAM name index and 3 of them have their own account key read, which is what carries the RID, the last logon and whether the account is enabled.",
      usb_devices: [],
      hive_count: 1,
    });
    renderPage();

    expect(await screen.findByText("Local accounts (3)")).toBeInTheDocument();
    // The RID, which is what the rest of the registry and the profile list
    // join on.
    expect(screen.getByText(/RID 500/)).toBeInTheDocument();
    expect(screen.getByText(/RID 1000/)).toBeInTheDocument();
    // The times.
    expect(
      screen.getByText(/2010-11-20T21:48:12.569244/),
    ).toBeInTheDocument();
    // Guest never logged on. The cell must say so, not sit empty and not
    // carry a 1601 date.
    expect(screen.getByText(/never logged on/)).toBeInTheDocument();
    expect(screen.queryByText(/1601-01-01T/)).not.toBeInTheDocument();
    // Enabled and disabled are different facts about an account, and both
    // built-ins are disabled here while the real user is not.
    expect(
      screen.getByText(/Administrator — RID 500, disabled, 6 logons/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Preston — RID 1000, enabled, 4 logons/),
    ).toBeInTheDocument();
  });

  it("does not report a missing account detail as an account with no detail", async () => {
    // The name index is the wider population. When the walk reached fewer
    // account keys than names, the page says so rather than letting the
    // shorter list read as the whole answer.
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: null,
      timezone: null,
      last_shutdown: null,
      users: [],
      sam_accounts: ["Administrator", "Guest", "Preston"],
      local_accounts: [
        {
          type: "LocalAccount",
          username: "Administrator",
          rid: 500,
          last_logon: null,
          account_enabled: true,
        },
      ],
      local_accounts_note:
        "3 account(s) are in this machine's SAM name index and 1 of them have their own account key read, which is what carries the RID, the last logon and whether the account is enabled. The other 2 are named in the index and their detail was not read here -- that is this build's reach, not an absence in the account.",
      usb_devices: [],
      hive_count: 1,
    });
    renderPage();

    expect(await screen.findByText("Local accounts (3)")).toBeInTheDocument();
    expect(
      screen.getByText(/that is this build's reach, not an absence in the account/),
    ).toBeInTheDocument();
  });

  it("renders OS, machine facts, users and USB history", async () => {
    mock({
      os: {
        product_name: "Windows 10 Pro",
        release_id: "22H2",
        current_version: "6.3",
        build: "19045",
        registered_owner: "Examiner",
        registered_organization: null,
        install_date: "2021-06-01",
      },
      computer_name: "DESKTOP-ABC",
      timezone: "GMT Standard Time",
      last_shutdown: null,
      users: ["alice", "bob"],
      usb_devices: [
        { friendly_name: "SanDisk Cruzer", vendor: "SanDisk", serial: "4C531" },
      ],
      hive_count: 2,
    });
    renderPage();

    expect(await screen.findByText("Windows 10 Pro")).toBeInTheDocument();
    expect(screen.getByText("DESKTOP-ABC")).toBeInTheDocument();
    expect(screen.getByText("GMT Standard Time")).toBeInTheDocument();
    expect(screen.getByText("19045")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("bob")).toBeInTheDocument();
    expect(screen.getByText("SanDisk Cruzer")).toBeInTheDocument();
    expect(screen.getByText("4C531")).toBeInTheDocument();
  });

  it("writes timestamps the way the rest of the product writes them", async () => {
    // The API answers with the precision the registry held; the page was
    // printing the raw RFC 3339 string while every other screen renders
    // "YYYY-MM-DD HH:MM:SS UTC".
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: "2004-08-19T22:48:27+00:00",
      },
      computer_name: null,
      timezone: null,
      last_shutdown: "2004-08-27T15:46:33.109216400+00:00",
      users: [],
      usb_devices: [],
      hive_count: 1,
    });
    renderPage();

    expect(
      await screen.findByText("2004-08-27 15:46:33 UTC"),
    ).toBeInTheDocument();
    expect(screen.getByText("2004-08-19 22:48:27 UTC")).toBeInTheDocument();
    expect(
      screen.queryByText(/2004-08-27T15:46:33\.109216400/),
    ).not.toBeInTheDocument();
  });

  it("keeps local accounts and user profiles apart, and says what each is", async () => {
    // LIVE-029. An account that never logged on has no profile directory, so
    // the two populations differ — and showing only profiles under a heading
    // that said "user accounts" under-reported the inventory on a court-facing
    // screen. The NIST case that found it: five SAM accounts, four profiles.
    mock({
      os: {
        product_name: "Microsoft Windows XP",
        release_id: null,
        current_version: "5.1",
        build: "2600",
        registered_owner: "Greg Schardt",
        registered_organization: null,
        install_date: null,
      },
      computer_name: "N-1A9ODN6ZXK4LQ",
      timezone: "Central Standard Time",
      last_shutdown: null,
      users: ["Mr. Evil", "LocalService", "NetworkService", "systemprofile"],
      sam_accounts: [
        "Administrator",
        "Guest",
        "HelpAssistant",
        "Mr. Evil",
        "SUPPORT_388945a0",
      ],
      usb_devices: [],
      hive_count: 23,
    });
    renderPage();

    expect(await screen.findByText("Local accounts (5)")).toBeInTheDocument();
    expect(screen.getByText("User profiles (4)")).toBeInTheDocument();
    // An account with no profile is present in one list and not the other.
    expect(screen.getByText("SUPPORT_388945a0")).toBeInTheDocument();
    expect(
      screen.getByText(/every local account the machine holds/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Fewer than the local accounts above, by design/),
    ).toBeInTheDocument();
    // And the old heading is gone, because it named the wrong population.
    expect(screen.queryByText(/^User accounts \(/)).not.toBeInTheDocument();
  });

  it("counts a conflict on a new field as shown, because the page now has a row for it", async () => {
    // The banner lists conflicts the page renders nowhere. Adding a field to
    // the API without adding it here would put its disagreement in that list
    // while the row for it sat right there (LIVE-029).
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: null,
      timezone: null,
      last_shutdown: null,
      last_logon_user: null,
      logon_domain: null,
      network_domain: null,
      users: [],
      usb_devices: [],
      hive_count: 2,
      identity_conflicts: [
        {
          field: "last_logon_user",
          value_name: "DefaultUserName",
          values: [
            { hive: "SOFTWARE #1", value: "Mr. Evil" },
            { hive: "SOFTWARE.SAV #2", value: "" },
          ],
        },
      ],
    });
    renderPage();

    await screen.findByText("Last interactive logon");
    expect(
      screen.queryByText(/does not have a row for/),
    ).not.toBeInTheDocument();
  });

  it("reports the last interactive logon and the domain it used", async () => {
    mock({
      os: {
        product_name: "Microsoft Windows XP",
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: "N-1A9ODN6ZXK4LQ",
      timezone: null,
      last_shutdown: null,
      last_logon_user: "Mr. Evil",
      logon_domain: "N-1A9ODN6ZXK4LQ",
      network_domain: null,
      users: [],
      usb_devices: [],
      hive_count: 1,
    });
    renderPage();

    expect(
      await screen.findByText("Last interactive logon"),
    ).toBeInTheDocument();
    expect(screen.getByText("Mr. Evil")).toBeInTheDocument();
    expect(screen.getByText("Logon domain")).toBeInTheDocument();
  });

  it("shows an empty state when no registry hives were parsed", async () => {
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: null,
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 0,
    });
    renderPage();

    expect(
      await screen.findByText("No system information"),
    ).toBeInTheDocument();
  });

  /**
   * HUNT-054. A domain controller imaged while running rendered this page
   * completely blank: the SOFTWARE and SYSTEM hives were in the case and the
   * reader had refused both, so every field was null and nothing said why. A
   * machine with no registry and a machine whose registry would not parse are
   * different findings and must not render alike.
   *
   * Against the unfixed page the hive name and the reason are nowhere on screen.
   */
  it("names the hives that could not be parsed instead of only going blank", async () => {
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: null,
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 0,
      unparsed_hives: [
        {
          hive: "SOFTWARE",
          error:
            "Failed to parse hive: the base block checksum does not verify",
          hive_dirty: true,
          replay_reason: "sequence_gap",
        },
      ],
    });
    renderPage();

    expect(await screen.findByText("SOFTWARE")).toBeInTheDocument();
    expect(screen.getByText(/could not be parsed/i)).toBeInTheDocument();
    expect(screen.getByText(/not evidence of absence/i)).toBeInTheDocument();
    expect(
      screen.getByText(/base block checksum does not verify/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/never cleanly flushed/i)).toBeInTheDocument();
    expect(screen.getByText(/sequence_gap/i)).toBeInTheDocument();
  });

  it("shows a hive disagreement instead of a blank field", async () => {
    // The API refuses to pick between two hives that name two machines, so it
    // reports the field as null — exactly what an absent field looks like.
    // Without this, "two hives in this case disagree about the computer name"
    // and "no computer name was recorded" render as the same dash, and an
    // examiner cannot tell that the case may hold two machines' evidence.
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: null,
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 2,
      identity_conflicts: [
        {
          field: "computer_name",
          value_name: "ComputerName",
          values: [
            { hive: "SYSTEM #1", value: "DESKTOP-ABC" },
            { hive: "SYSTEM #2", value: "LAPTOP-XYZ" },
          ],
          detail:
            "2 hives in this case report different computer_name values; this summary reports none of them as the answer",
        },
      ],
    });
    renderPage();

    expect(await screen.findByText("hives disagree")).toBeInTheDocument();
    // Every competing answer, and which hive gave it.
    expect(screen.getByText("DESKTOP-ABC")).toBeInTheDocument();
    expect(screen.getByText("LAPTOP-XYZ")).toBeInTheDocument();
    expect(screen.getByText("SYSTEM #1")).toBeInTheDocument();
    expect(screen.getByText("SYSTEM #2")).toBeInTheDocument();
    // And a banner, so the disagreement is not only visible to someone who
    // happens to scroll to the field it affects.
    expect(screen.getByText(/machine-identity field is/)).toBeInTheDocument();
  });

  it("shows the control set each hive was read under", async () => {
    // A computer name left behind in ControlSet002 is not the running
    // configuration; the set each hive named is part of the answer.
    mock({
      os: {
        product_name: "Windows 10 Pro",
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: "DESKTOP-ABC",
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 1,
      control_sets: [
        { hive: "SYSTEM #1", current_control_set: "ControlSet001" },
      ],
      identity_notes: [
        "SYSTEM #1 has no Select\\Current; values were read unscoped",
      ],
    });
    renderPage();

    expect(await screen.findByText("ControlSet001")).toBeInTheDocument();
    expect(screen.getByText(/no Select/)).toBeInTheDocument();
  });

  it("does not cry conflict when the hives agree", async () => {
    mock({
      os: {
        product_name: "Windows 10 Pro",
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: "DESKTOP-ABC",
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 2,
      identity_conflicts: [],
    });
    renderPage();

    await screen.findByText("DESKTOP-ABC");
    expect(screen.queryByText("hives disagree")).not.toBeInTheDocument();
  });

  it("keeps the answer the hives did agree on beside the one they did not", async () => {
    // The API reads several fields from more than one registry value name:
    // `DisplayVersion` first, then `ReleaseId`. A disagreement on the first is
    // filed as a conflict while the second still resolves — so the field
    // arrives with BOTH a value and a conflict. Rendering the disagreement in
    // place of the value would hide an answer the evidence actually gave.
    mock({
      os: {
        product_name: null,
        release_id: "22H2",
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: null,
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 2,
      identity_conflicts: [
        {
          field: "os.release_id",
          value_name: "DisplayVersion",
          values: [
            { hive: "SOFTWARE #1", value: "21H2" },
            { hive: "SOFTWARE #2", value: "22H2" },
          ],
          detail: "2 hives report different os.release_id values",
        },
      ],
    });
    renderPage();

    expect(await screen.findByText("hives disagree")).toBeInTheDocument();
    expect(
      screen.getByText("22H2", { selector: ".sysinfo-value" }),
    ).toBeInTheDocument();
  });

  it("shows every disagreement it counts, not only the first per field", async () => {
    // One field can be read from two value names, so it can carry two
    // conflicts. Showing one while the banner counts two promises the examiner
    // a disagreement that is nowhere on the page.
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: null,
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 2,
      identity_conflicts: [
        {
          field: "timezone",
          value_name: "TimeZoneKeyName",
          values: [
            { hive: "SYSTEM #1", value: "GMT Standard Time" },
            { hive: "SYSTEM #2", value: "Pacific Standard Time" },
          ],
          detail: "2 hives report different timezone values",
        },
        {
          field: "timezone",
          value_name: "StandardName",
          values: [
            { hive: "SYSTEM #1", value: "GMT" },
            { hive: "SYSTEM #2", value: "PST" },
          ],
          detail: "2 hives report different timezone values",
        },
      ],
    });
    renderPage();

    expect(await screen.findByText("TimeZoneKeyName")).toBeInTheDocument();
    expect(screen.getByText("StandardName")).toBeInTheDocument();
    expect(screen.getByText("Pacific Standard Time")).toBeInTheDocument();
    expect(screen.getByText("PST")).toBeInTheDocument();
  });

  it("offers no source filter for a single-source case", async () => {
    mock(
      {
        os: {
          product_name: "Windows 11 Pro",
          release_id: null,
          current_version: null,
          build: null,
          registered_owner: null,
          registered_organization: null,
          install_date: null,
        },
        computer_name: "ONLY-PC",
        timezone: null,
        last_shutdown: null,
        users: [],
        usb_devices: [],
        hive_count: 1,
      },
      [{ id: "only", name: "disk.E01" }],
    );
    renderPage();
    await screen.findByText("Windows 11 Pro");
    expect(screen.queryByLabelText("Source")).toBeNull();
  });

  it("compiles each acquisition on its own rather than merging two machines", async () => {
    // ROADMAP §2.6. A merged view answers about A MACHINE, and this case holds
    // two. The extractor's own rules make that view unsafe: a field two
    // machines disagree about is nulled — so A's computer name is withheld
    // because B exists — and where they coincidentally agree, one value is
    // presented as the case's answer with nothing saying two machines said it.
    const machine = (name: string, tz: string) => ({
      os: {
        product_name: "Windows 10 Pro",
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: name,
      timezone: tz,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 1,
    });
    mockScoped(
      {
        "src-a": machine("DESKTOP-ABC", "GMT Standard Time"),
        "src-b": machine("LAPTOP-XYZ", "Pacific Standard Time"),
      },
      [
        { id: "src-a", name: "desktop.E01" },
        { id: "src-b", name: "laptop.E01" },
      ],
    );
    renderPage();

    // One section per acquisition, each NAMED, so a reader can tell which
    // machine they are looking at.
    expect(
      await screen.findByRole("heading", { name: /desktop\.E01/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /laptop\.E01/ }),
    ).toBeInTheDocument();
    // Both machines' own answers, neither withheld because the other exists.
    expect(screen.getByText("DESKTOP-ABC")).toBeInTheDocument();
    expect(screen.getByText("LAPTOP-XYZ")).toBeInTheDocument();
    expect(screen.getByText("GMT Standard Time")).toBeInTheDocument();
    expect(screen.getByText("Pacific Standard Time")).toBeInTheDocument();
    // And the page says why it is shaped this way, rather than leaving the
    // reader to infer it from the layout.
    expect(
      screen.getByText(/This case holds 2 acquisitions/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/where two disagree the answer is withheld/),
    ).toBeInTheDocument();
  });

  it("offers the all-sources option under a name that says what it now does", async () => {
    mockScoped(
      {
        "src-a": {
          os: {
            product_name: null,
            release_id: null,
            current_version: null,
            build: null,
            registered_owner: null,
            registered_organization: null,
            install_date: null,
          },
          computer_name: "A",
          timezone: null,
          last_shutdown: null,
          users: [],
          usb_devices: [],
          hive_count: 1,
        },
        "src-b": {
          os: {
            product_name: null,
            release_id: null,
            current_version: null,
            build: null,
            registered_owner: null,
            registered_organization: null,
            install_date: null,
          },
          computer_name: "B",
          timezone: null,
          last_shutdown: null,
          users: [],
          usb_devices: [],
          hive_count: 1,
        },
      },
      [
        { id: "src-a", name: "a.E01" },
        { id: "src-b", name: "b.E01" },
      ],
    );
    renderPage();
    await screen.findByText("A");
    // "All sources (merged)" promised a merge that is no longer performed, and
    // would not be safe to perform.
    const select = screen.getByLabelText("Source") as HTMLSelectElement;
    expect(select.options[0].textContent).toMatch(/separately/i);
    expect(select.options[0].textContent).not.toMatch(/merged/i);
  });

  it("says how many acquisitions it did not compile when a case holds more than the ceiling", async () => {
    const sources = Array.from({ length: MAX_SOURCE_SECTIONS + 3 }, (_, i) => ({
      id: `src-${i}`,
      name: `image-${i}.E01`,
    }));
    const payload = Object.fromEntries(
      sources.map((s) => [
        s.id,
        {
          os: {
            product_name: null,
            release_id: null,
            current_version: null,
            build: null,
            registered_owner: null,
            registered_organization: null,
            install_date: null,
          },
          computer_name: s.name,
          timezone: null,
          last_shutdown: null,
          users: [],
          usb_devices: [],
          hive_count: 1,
        },
      ]),
    );
    mockScoped(payload, sources);
    renderPage();

    expect(
      await screen.findByRole("heading", { name: /image-0\.E01/ }),
    ).toBeInTheDocument();
    // A silent truncation here would read as "this case holds ten machines".
    expect(
      screen.getByText(/3 further acquisitions were not compiled/),
    ).toBeInTheDocument();
    // The uncompiled ones have no section. They are still OFFERED in the
    // picker, which is the point: an examiner can reach every one of them.
    expect(
      screen.queryByRole("heading", {
        name: new RegExp(`image-${MAX_SOURCE_SECTIONS + 2}\\.E01`),
      }),
    ).toBeNull();
    expect(
      screen.getByRole("option", { name: `image-${MAX_SOURCE_SECTIONS + 2}.E01` }),
    ).toBeInTheDocument();
  });

  it("scopes the compiled view to the chosen acquisition", async () => {
    const machine = (name: string, hives: number) => ({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: name,
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: hives,
    });
    mockScoped(
      {
        // Merged: two machines disagree, so the API returns null + a conflict.
        __all__: {
          ...machine("", 2),
          computer_name: null,
          identity_conflicts: [
            {
              field: "computer_name",
              value_name: "ComputerName",
              detail: "two hives name two machines",
              values: [
                { hive: "SYSTEM #1", value: "MACHINE-A" },
                { hive: "SYSTEM #2", value: "MACHINE-B" },
              ],
            },
          ],
        },
        "src-a": machine("MACHINE-A", 1),
        "src-b": machine("MACHINE-B", 1),
      },
      [
        { id: "src-a", name: "laptop.E01" },
        { id: "src-b", name: "desktop.E01" },
      ],
    );
    renderPage();

    // With two acquisitions and none chosen, each is compiled on its own and
    // BOTH names are on the page. Until 2026-09-15 this rendered the merged
    // view, whose extractor nulls `computer_name` when two machines disagree —
    // so machine A's true name was withheld because machine B existed, and the
    // examiner was shown a disagreement banner instead of two machines.
    // The page now issues one request per acquisition, so wait for the second
    // section to exist before asserting on what is inside either.
    await screen.findByRole("heading", { name: /laptop\.E01/ });
    expect(await screen.findByText("MACHINE-A")).toBeInTheDocument();
    expect(screen.getByText("MACHINE-B")).toBeInTheDocument();
    expect(screen.queryByText(/reported by more than one hive/i)).toBeNull();

    // Scope to laptop → MACHINE-A, no conflict.
    await userEvent.selectOptions(
      screen.getByLabelText("Source"),
      "laptop.E01",
    );
    expect(await screen.findByText("MACHINE-A")).toBeInTheDocument();
    expect(screen.queryByText(/reported by more than one hive/i)).toBeNull();

    // Scope to desktop → MACHINE-B.
    await userEvent.selectOptions(
      screen.getByLabelText("Source"),
      "desktop.E01",
    );
    expect(await screen.findByText("MACHINE-B")).toBeInTheDocument();
  });

  it("names a disputed field it has no row for rather than counting it silently", async () => {
    // The banner's count comes from the API. A field this page does not render
    // would otherwise be counted and shown nowhere, which reads as a page that
    // lost the disagreement.
    mock({
      os: {
        product_name: null,
        release_id: null,
        current_version: null,
        build: null,
        registered_owner: null,
        registered_organization: null,
        install_date: null,
      },
      computer_name: null,
      timezone: null,
      last_shutdown: null,
      users: [],
      usb_devices: [],
      hive_count: 2,
      identity_conflicts: [
        {
          field: "os.edition_id",
          value_name: "EditionID",
          values: [
            { hive: "SOFTWARE #1", value: "Professional" },
            { hive: "SOFTWARE #2", value: "Enterprise" },
          ],
          detail: "2 hives report different os.edition_id values",
        },
      ],
    });
    renderPage();

    expect(await screen.findByText("os.edition_id")).toBeInTheDocument();
  });
});

/**
 * HUNT-079. "Whose phone is this?" is the first question asked of a mobile
 * exhibit, and this page returned "No system information" for it: `system_info`
 * compiles Windows registry hives, and a Pixel's model, serial and build were
 * reachable only by searching raw files.
 */
describe("mobile device facts", () => {
  function mockDevices(info: unknown, systemInfo: unknown = { hive_count: 0 }) {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/system_info`, () =>
        HttpResponse.json(
          systemInfo as Parameters<typeof HttpResponse.json>[0],
        ),
      ),
      http.get(`/api/v1/cases/${CASE_ID}/device_info`, () =>
        HttpResponse.json(info as Parameters<typeof HttpResponse.json>[0]),
      ),
      http.get(`/api/v1/cases/${CASE_ID}/artifacts/root/children`, () =>
        HttpResponse.json({ items: [] }),
      ),
    );
  }

  it("answers whose phone it is on a case with no registry at all", async () => {
    mockDevices({
      devices: [
        {
          platform: "android",
          disagreements: 0,
          facts: [
            {
              fact: "model",
              agreed: true,
              multi_valued: false,
              readings: [
                {
                  value: "Pixel 7a",
                  source_file: "/system/build.prop",
                  source_key: "ro.product.model",
                },
              ],
            },
            {
              fact: "serial_number",
              agreed: true,
              multi_valued: false,
              readings: [
                {
                  value: "1B031JEG500741",
                  source_file: "/system/build.prop",
                  source_key: "ro.serialno",
                },
              ],
            },
          ],
        },
      ],
      incomplete: [],
    });
    renderPage();

    expect(await screen.findByText("Android device")).toBeInTheDocument();
    expect(screen.getByText("Pixel 7a")).toBeInTheDocument();
    expect(screen.getByText("1B031JEG500741")).toBeInTheDocument();
    // Every fact names where it was read. An examiner asked to stand over the
    // model has to be able to say what they read.
    expect(screen.getAllByText("/system/build.prop").length).toBeGreaterThan(0);
    expect(screen.getByText("ro.product.model")).toBeInTheDocument();
  });

  it("shows a disagreement between sources rather than picking a winner", async () => {
    mockDevices({
      devices: [
        {
          platform: "android",
          disagreements: 1,
          facts: [
            {
              fact: "model",
              agreed: false,
              multi_valued: false,
              readings: [
                {
                  value: "Pixel 7a",
                  source_file: "/system/build.prop",
                  source_key: "ro.product.model",
                },
                {
                  value: "lynx",
                  source_file: "/vendor/build.prop",
                  source_key: "ro.product.vendor.model",
                },
              ],
            },
          ],
        },
      ],
      incomplete: [],
    });
    renderPage();

    expect(await screen.findByText("sources disagree")).toBeInTheDocument();
    // Both answers are on screen, each with the file that gave it.
    expect(screen.getByText("Pixel 7a")).toBeInTheDocument();
    expect(screen.getByText("lynx")).toBeInTheDocument();
    expect(screen.getByText("/vendor/build.prop")).toBeInTheDocument();
  });

  it("says when a source was not read whole", async () => {
    mockDevices({
      devices: [
        {
          platform: "ios",
          disagreements: 0,
          facts: [
            {
              fact: "device_name",
              agreed: true,
              multi_valued: false,
              readings: [
                {
                  value: "This Is's iPhone",
                  source_file: "/ev/Backup/00008030",
                  source_key: "Lockdown.DeviceName",
                },
              ],
            },
          ],
        },
      ],
      incomplete: [
        {
          source_file: "/system/build.prop",
          reason: "short_read",
          detail: "only 200 byte(s) were acquired",
        },
      ],
    });
    renderPage();

    expect(await screen.findByText("Apple device")).toBeInTheDocument();
    expect(
      screen.getByText(/not read in full/i, { exact: false }),
    ).toBeInTheDocument();
  });

  it("explains a disagreement in the words of the exhibit it is about", async () => {
    // The banner was written for a phone ("a device whose partitions
    // disagree"). On a laptop the sentence names something the evidence does
    // not have, and an examiner reading it looks for partitions.
    mockDevices({
      devices: [
        {
          platform: "linux",
          disagreements: 1,
          facts: [
            {
              fact: "version_id",
              agreed: false,
              multi_valued: false,
              readings: [
                {
                  value: "21.04",
                  source_file: "/etc/os-release",
                  source_key: "VERSION_ID",
                },
                {
                  value: "21.10",
                  source_file: "/usr/lib/os-release",
                  source_key: "VERSION_ID",
                },
              ],
            },
          ],
        },
      ],
      incomplete: [],
    });
    renderPage();

    expect(await screen.findByText("Linux machine")).toBeInTheDocument();
    const note = screen.getByRole("note");
    expect(note.textContent).toMatch(/one fact about this machine/i);
    expect(note.textContent).not.toMatch(/partitions/i);
    expect(note.textContent).toMatch(/finding, not a tie to break/i);
  });

  it("does not claim a Linux case has no system information", async () => {
    // The page compiles Windows registry hives, and a Linux or mobile exhibit
    // has none. Showing "No system information" under a card that has just
    // named the machine reads as a contradiction of the panel above it.
    mockDevices({
      devices: [
        {
          platform: "linux",
          disagreements: 0,
          facts: [
            {
              fact: "host_name",
              agreed: true,
              multi_valued: false,
              readings: [
                {
                  value: "rshell-lenovo",
                  source_file: "/etc/hostname",
                  source_key: "file contents",
                },
              ],
            },
          ],
        },
      ],
      incomplete: [],
    });
    renderPage();

    expect(await screen.findByText("Linux machine")).toBeInTheDocument();
    expect(screen.queryByText("No system information")).not.toBeInTheDocument();
    expect(
      screen.getByText(/no Windows registry hives were parsed/i),
    ).toBeInTheDocument();
  });

  it("renders nothing for a case holding no mobile evidence", async () => {
    mockDevices({ devices: [], incomplete: [] });
    renderPage();

    expect(await screen.findByText("No system information")).toBeInTheDocument();
    expect(screen.queryByText("Android device")).not.toBeInTheDocument();
    expect(screen.queryByText("Apple device")).not.toBeInTheDocument();
  });

  it("names the machine a Linux exhibit came from", async () => {
    // The same question of a laptop as of a phone: what is it called, what does
    // it run, and who has an account on it. Compiled from /etc/hostname,
    // os-release and passwd.
    mockDevices({
      devices: [
        {
          platform: "linux",
          disagreements: 0,
          facts: [
            {
              fact: "host_name",
              agreed: true,
              multi_valued: false,
              readings: [
                {
                  value: "rshell-lenovo",
                  source_file: "/etc/hostname",
                  source_key: "file contents",
                },
              ],
            },
            {
              fact: "version_id",
              agreed: true,
              multi_valued: false,
              readings: [
                {
                  value: "21.10",
                  source_file: "/usr/lib/os-release",
                  source_key: "VERSION_ID",
                },
              ],
            },
            {
              fact: "user_account",
              agreed: true,
              multi_valued: true,
              readings: [
                {
                  value: "rafael (uid 1000, /home/rafael, /bin/bash)",
                  source_file: "/etc/passwd",
                  source_key: "passwd entry",
                },
              ],
            },
          ],
        },
      ],
      incomplete: [],
    });
    renderPage();

    expect(await screen.findByText("Linux machine")).toBeInTheDocument();
    expect(screen.getByText("rshell-lenovo")).toBeInTheDocument();
    expect(screen.getByText("Host name")).toBeInTheDocument();
    expect(screen.getByText("OS version ID")).toBeInTheDocument();
    expect(screen.getByText("Accounts")).toBeInTheDocument();
    expect(
      screen.getByText("rafael (uid 1000, /home/rafael, /bin/bash)"),
    ).toBeInTheDocument();
  });

  it("lists every value of a fact a device can have several of", async () => {
    // HUNT-079. A dual-SIM phone has two numbers and a phone can hold several
    // accounts. Showing only the first would hide an identity the case may turn
    // on; showing it as a disagreement would turn the ordinary into an alarm.
    mockDevices({
      devices: [
        {
          platform: "android",
          disagreements: 0,
          facts: [
            {
              fact: "google_account",
              agreed: true,
              multi_valued: true,
              readings: [
                {
                  value: "ada@gmail.com",
                  source_file: "/data/system_de/0/accounts_de.db",
                  source_key: "accounts.name",
                },
                {
                  value: "ada.work@gmail.com",
                  source_file: "/data/system_de/0/accounts_de.db",
                  source_key: "accounts.name",
                },
              ],
            },
          ],
        },
      ],
      incomplete: [],
    });
    renderPage();

    expect(await screen.findByText("ada@gmail.com")).toBeInTheDocument();
    expect(screen.getByText("ada.work@gmail.com")).toBeInTheDocument();
    expect(screen.queryByText("sources disagree")).not.toBeInTheDocument();
  });
});
