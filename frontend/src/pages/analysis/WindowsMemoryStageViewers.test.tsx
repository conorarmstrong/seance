import { render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { server } from "../../test/server";
import type { ParsedRecord } from "./api";
import { RecordsViewerPage } from "./RecordsViewerPage";

/**
 * The eight Windows memory stages of ROADMAP §5.3 are each ONE record whose
 * substance is a nested array (processors, pool entries, regions, hives,
 * images, boot-sector candidates, tasks, key schedules) that the generic
 * table skips. What every test here pins: the stage's own `statement` is
 * printed verbatim, a check the build could not make is shown as not made
 * (never as passed), a cap is shown with its number, and an inference is
 * labelled as one.
 */

const CASE_ID = "case-1";

function mock(type: string, records: ParsedRecord[]) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, () =>
      HttpResponse.json({
        records,
        total: records.length,
        type_total: records.length,
        page: 1,
        page_size: 50,
        type,
      }),
    ),
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
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function stage(
  id: string,
  type: string,
  stageKey: string,
  metadata: Record<string, unknown>,
): ParsedRecord {
  return {
    id,
    parent_id: "img-1",
    artifact_type: "ParsedRecord",
    metadata: {
      type,
      record_type: type,
      stage: stageKey,
      stage_ran: true,
      content_complete: true,
      statement: `the ${stageKey} stage's own sentence`,
      incomplete: [],
      ...metadata,
    },
  } as unknown as ParsedRecord;
}

describe("Windows memory stage records (ROADMAP §5.3)", () => {
  it("processor blocks: one row per processor, each check as agree, disagree or not made", async () => {
    mock("MemoryProcessorBlocks", [
      stage("p1", "MemoryProcessorBlocks", "processor_blocks", {
        processors_walked: 2,
        processors_claimed: 2,
        processor_count_note: "KeNumberProcessors agrees with the array",
        incoherent: 0,
        processors: [
          {
            index: 0,
            kpcr: "0xfffff80012340000",
            prcb: "0xfffff80012340180",
            self_agrees: true,
            current_prcb_agrees: true,
            number_agrees: null,
            checks_made: 2,
            coherent: true,
            idle: false,
            current_thread: "0xffff9a0000001000",
            current_process: {
              process: "0xffff9a0000002000",
              pid: 4,
              name: "System",
            },
            major_version: 15,
            minor_version: 26200,
          },
          {
            index: 1,
            kpcr: "0xfffff80012350000",
            prcb: "0xfffff80012350180",
            self_agrees: true,
            current_prcb_agrees: false,
            number_agrees: true,
            checks_made: 3,
            coherent: false,
            idle: true,
            current_thread: "0xffff9a0000003000",
            current_process: null,
          },
        ],
      }),
    ]);
    renderViewer("MemoryProcessorBlocks");
    await waitFor(() =>
      expect(
        screen.getByText("the processor_blocks stage's own sentence"),
      ).toBeInTheDocument(),
    );
    const rows = screen.getAllByRole("row");
    const row0 = rows.find((r) => within(r).queryByText("0xfffff80012340000"));
    expect(row0).toBeDefined();
    expect(within(row0!).getByText("System (4)")).toBeInTheDocument();
    // A check the symbols could not make is "not made", never a pass.
    expect(within(row0!).getByText("not made")).toBeInTheDocument();
    const row1 = rows.find((r) => within(r).queryByText("0xfffff80012350000"));
    expect(within(row1!).getByText("disagree")).toBeInTheDocument();
    expect(within(row1!).getByText("idle")).toBeInTheDocument();
  });

  it("big pool: per-tag totals, the published entries with the cap named, and the in-use counter compared", async () => {
    mock("MemoryBigPool", [
      stage("b1", "MemoryBigPool", "big_pool", {
        entries_declared: 4096,
        entries_read: 4096,
        entries_in_use: 2,
        entries_free: 1,
        entries_empty: 4093,
        in_use_counter_claimed: 2,
        in_use_counter_agrees: true,
        tags: {
          MmSt: { in_use: 1, free: 0, bytes_in_use: 65536, bytes_free: 0 },
          Ntfx: { in_use: 1, free: 1, bytes_in_use: 4096, bytes_free: 8192 },
        },
        tags_total: 2,
        entries: [
          {
            index: 0,
            va: "0xffffa00000010000",
            free: false,
            tag: "MmSt",
            number_of_bytes: 65536,
            pool_type: { raw: 0, name: "NonPagedPool" },
          },
          {
            index: 1,
            va: "0xffffa00000020000",
            free: true,
            tag: "Ntfx",
            number_of_bytes: 8192,
            pool_type: null,
          },
        ],
        entries_published: 2,
        entries_truncated: true,
        entries_publication_cap_note:
          "2 of 3 entries are published; the per-tag totals cover all 3",
      }),
    ]);
    renderViewer("MemoryBigPool");
    await waitFor(() => expect(screen.getAllByText("MmSt").length).toBe(2));
    expect(screen.getAllByText("64.0 KiB").length).toBe(2);
    expect(
      screen.getByText(/2 of 3 entries are published/),
    ).toBeInTheDocument();
    // Freed and live entries are told apart by a word, not a colour.
    expect(screen.getByText("freed")).toBeInTheDocument();
    expect(screen.getByText("in use")).toBeInTheDocument();
    expect(screen.getByText(/counter.*agrees/)).toBeInTheDocument();
  });

  it("virtual map: every region with its name from the type map, and the checks made", async () => {
    mock("MemoryVirtualMap", [
      stage("v1", "MemoryVirtualMap", "virtual_map", {
        regions_declared: 18,
        regions_in_use: 2,
        naming_unavailable: null,
        kernel_base_in_a_region: true,
        kernel_base_region: { index: 17, type_name: "MiVaDriverImages" },
        regions: [
          {
            index: 2,
            type_value: 2,
            type_name: "MiVaBootLoaded",
            base: "0xfffff80000000000",
            end: "0xfffff80100000000",
            bytes: 4294967296,
            empty: false,
          },
          {
            index: 5,
            type_value: 5,
            type_name: null,
            base: "0x0",
            end: null,
            bytes: 0,
            empty: true,
          },
        ],
        checks: [
          {
            name: "kernel base in a region",
            passed: true,
            detail: "slot 17 (MiVaDriverImages)",
          },
          {
            name: "no overlaps",
            passed: false,
            detail: "regions 3 and 4 overlap",
          },
        ],
      }),
    ]);
    renderViewer("MemoryVirtualMap");
    await waitFor(() =>
      expect(screen.getByText("MiVaBootLoaded")).toBeInTheDocument(),
    );
    expect(screen.getByText("4.0 GiB")).toBeInTheDocument();
    expect(screen.getByText("regions 3 and 4 overlap")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
    // A region the type map did not name says so rather than showing a blank.
    expect(screen.getByText("not named by the type map")).toBeInTheDocument();
  });

  it("hive cell routines: each routine placed, and a routine outside the kernel flagged", async () => {
    mock("MemoryHiveCellRoutines", [
      stage("h1", "MemoryHiveCellRoutines", "hive_cell_routines", {
        hives_examined: 2,
        hives_with_a_routine_outside_the_kernel: 1,
        hive_list_complete: true,
        module_map_authoritative: true,
        hives: [
          {
            hive_name: "\\REGISTRY\\MACHINE\\SYSTEM",
            cmhive: "0xffffa00000100000",
            get_cell_routine: {
              address: "0xfffff80012345678",
              symbol: "CmpGetCellRoutine",
              symbol_offset: 0,
              at_a_symbol: true,
              ownership: { kind: "in_module", module: "ntoskrnl.exe" },
              outside_the_kernel: false,
            },
            release_cell_routine: null,
            routine_outside_the_kernel: false,
            routine_off_a_symbol: false,
            unreadable: null,
          },
          {
            hive_name: "\\REGISTRY\\USER\\S-1-5-21",
            cmhive: "0xffffa00000200000",
            get_cell_routine: {
              address: "0xfffff80099990000",
              symbol: null,
              symbol_offset: null,
              at_a_symbol: false,
              ownership: { kind: "in_module", module: "evil.sys" },
              outside_the_kernel: true,
            },
            release_cell_routine: null,
            routine_outside_the_kernel: true,
            routine_off_a_symbol: true,
            unreadable: null,
          },
        ],
      }),
    ]);
    renderViewer("MemoryHiveCellRoutines");
    await waitFor(() =>
      expect(screen.getByText("CmpGetCellRoutine")).toBeInTheDocument(),
    );
    expect(screen.getByText(/in evil\.sys/)).toBeInTheDocument();
    expect(screen.getByText("outside the kernel")).toBeInTheDocument();
  });

  it("version info: images by name with their file version, and an unreadable image reported as such", async () => {
    mock("MemoryVersionInfo", [
      stage("i1", "MemoryVersionInfo", "version_info", {
        images_examined: 3,
        images_with_a_version: 1,
        images_resource_discarded: 1,
        kernel_list_complete: true,
        process_list_complete: true,
        kernel_modules: [
          {
            name: "ntoskrnl.exe",
            path: "\\SystemRoot\\system32\\ntoskrnl.exe",
            base: "0xfffff80012000000",
            outcome: "read",
            outcome_detail: null,
            fixed: {
              file_version: "10.0.26200.1",
              product_version: "10.0.26200.1",
            },
            company: "Microsoft Corporation",
            original_filename: "ntkrnlmp.exe",
          },
          {
            name: "cng.sys",
            path: null,
            base: "0xfffff80013000000",
            outcome: "resource_discarded",
            outcome_detail:
              "the .rsrc section is discardable and was not resident",
            fixed: null,
          },
        ],
        processes: [
          {
            pid: 4,
            name: "System",
            images: [
              {
                name: "kernel32.dll",
                path: "C:\\Windows\\System32\\kernel32.dll",
                base: "0x7ff800000000",
                outcome: "unreadable",
                outcome_detail: "PE headers not resident",
                fixed: null,
              },
            ],
            list_complete: true,
            unavailable: null,
          },
        ],
      }),
    ]);
    renderViewer("MemoryVersionInfo");
    await waitFor(() =>
      expect(screen.getByText("ntoskrnl.exe")).toBeInTheDocument(),
    );
    expect(screen.getAllByText("10.0.26200.1").length).toBe(2);
    expect(screen.getByText("Microsoft Corporation")).toBeInTheDocument();
    expect(
      screen.getByText(/discardable and was not resident/),
    ).toBeInTheDocument();
    expect(screen.getByText(/PE headers not resident/)).toBeInTheDocument();
    expect(screen.getByText("kernel32.dll")).toBeInTheDocument();
  });

  it("MBR scan: each candidate with its checks, and a failing sector claimed as nothing more", async () => {
    mock("MemoryMbrScan", [
      stage("m1", "MemoryMbrScan", "mbr_scan", {
        bytes_scanned: 10737418240,
        unread_bytes: 0,
        unmapped_bytes: 4096,
        sectors_with_signature: 2,
        candidates_published: 2,
        candidates_truncated: false,
        candidates: [
          {
            offset_hex: "0x1000",
            kind: "gpt_protective_mbr",
            well_formed: true,
            disk_signature: "00000000",
            partitions_in_use: 1,
            checks_failed: 0,
            boot_code_sha256: "ab".repeat(32),
            boot_code_empty: false,
            partitions: [
              {
                index: 0,
                type: 238,
                type_name: "GPT protective",
                first_lba: 1,
                sectors: 4294967295,
              },
            ],
            checks: [],
          },
          {
            offset_hex: "0x7c00",
            kind: "mbr",
            well_formed: false,
            disk_signature: "deadbeef",
            partitions_in_use: 0,
            checks_failed: 3,
            boot_code_sha256: null,
            boot_code_empty: true,
            partitions: [],
            checks: [
              {
                name: "partition table",
                passed: false,
                detail: "no entry in use",
              },
            ],
          },
        ],
      }),
    ]);
    renderViewer("MemoryMbrScan");
    await waitFor(() => expect(screen.getByText("0x1000")).toBeInTheDocument());
    expect(screen.getByText("gpt protective mbr")).toBeInTheDocument();
    expect(screen.getByText("well formed")).toBeInTheDocument();
    expect(screen.getByText("3 checks failed")).toBeInTheDocument();
    expect(screen.getByText("deadbeef")).toBeInTheDocument();
  });

  it("scheduled tasks: path, author, the exec action, the last run and the decoded triggers", async () => {
    mock("MemoryScheduledTasks", [
      stage("t1", "MemoryScheduledTasks", "scheduled_tasks", {
        tasks_total: 1,
        tasks_declared: 1,
        tasks_index_complete: true,
        capped: false,
        tasks: [
          {
            id: "{1234}",
            name: "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            path: {
              kind: "text",
              text: "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            },
            author: { kind: "text", text: "Microsoft Corporation" },
            description: { kind: "absent" },
            date: { kind: "unavailable", detail: "value would not read" },
            actions: {
              version: 3,
              actions: [
                {
                  kind: "exec",
                  id: null,
                  command: "%windir%\\system32\\defrag.exe",
                  arguments: "-c -h -o -$",
                  working_directory: null,
                },
              ],
              actions_total: 1,
              complete: true,
            },
            actions_error: null,
            dynamic_info: {
              creation: { utc: "2024-01-01T00:00:00Z" },
              last_run: { utc: "2024-02-02T03:04:05Z" },
              state: 3,
              last_result: "0x00000000",
            },
            dynamic_info_error: null,
            triggers: {
              whole: true,
              stopped: null,
              triggers: [
                {
                  kind: "time",
                  schedule: "once",
                  start: {
                    filetime: 1,
                    localized: true,
                    time: "2026-08-06T20:08:00",
                  },
                  repetition_interval: "PT1H",
                  enabled: true,
                },
                { kind: "boot", start: null, enabled: false },
              ],
            },
            triggers_error: null,
          },
          {
            id: "{5678}",
            name: "\\Other",
            path: { kind: "text", text: "\\Other" },
            author: { kind: "absent" },
            actions: null,
            actions_error: null,
            dynamic_info: null,
            dynamic_info_error: null,
            triggers: {
              whole: false,
              stopped:
                "a trigger kind this decoder does not know (0xbbbb) at byte 96; 48 byte(s) not decoded",
              triggers: [],
            },
            triggers_error: null,
          },
        ],
      }),
    ]);
    renderViewer("MemoryScheduledTasks");
    await waitFor(() =>
      expect(
        screen.getByText("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText("%windir%\\system32\\defrag.exe -c -h -o -$"),
    ).toBeInTheDocument();
    expect(screen.getByText("Microsoft Corporation")).toBeInTheDocument();
    expect(screen.getByText("2024-02-02T03:04:05Z")).toBeInTheDocument();
    expect(
      screen.getByText(
        "time (once) from 2026-08-06T20:08:00 local, every PT1H",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("boot (disabled)")).toBeInTheDocument();
    expect(screen.queryByText(/Triggers .*not decoded/)).toBeNull();
    expect(
      screen.getByText(
        /triggers stopped: a trigger kind this decoder does not know \(0xbbbb\)/,
      ),
    ).toBeInTheDocument();
  });

  it("TrueCrypt: says when no driver was found and the sweep did not run, and labels a pair as an inference", async () => {
    mock("MemoryTrueCrypt", [
      stage("c1", "MemoryTrueCrypt", "truecrypt", {
        driver: {
          present: false,
          modules_walked: 150,
          list_complete: true,
          names_looked_for: ["truecrypt.sys", "veracrypt.sys"],
        },
        driver_present: false,
        sweep_ran: false,
        sweep: null,
        sweep_did_not_run_because:
          "no TrueCrypt or VeraCrypt driver is on the loaded-module list",
        validation_note:
          "the positive path is validated on a synthetic region only",
      }),
      stage("c2", "MemoryTrueCrypt", "truecrypt", {
        driver: {
          present: true,
          name: "veracrypt.sys",
          base: "0xfffff80020000000",
          size: 400000,
        },
        driver_present: true,
        sweep_ran: true,
        sweep: {
          region: "the MiVaNonPagedPool region",
          bytes_scanned: 1048576,
          unread_bytes: 0,
          unmapped_bytes: 0,
          schedules: [
            {
              address: "0xffffa00000300000",
              bits: 256,
              key_sha256: "cd".repeat(32),
            },
            {
              address: "0xffffa00000300200",
              bits: 256,
              key_sha256: "ef".repeat(32),
            },
          ],
          schedules_total: 2,
          schedules_unhashed: [],
          schedules_unhashed_total: 0,
          schedules_truncated: false,
          possible_xts_pairs: [["0xffffa00000300000", "0xffffa00000300200"]],
        },
        sweep_did_not_run_because: null,
        validation_note:
          "the positive path is validated on a synthetic region only",
      }),
    ]);
    renderViewer("MemoryTrueCrypt");
    await waitFor(() =>
      expect(
        screen.getByText(
          /no TrueCrypt or VeraCrypt driver is on the loaded-module list/,
        ),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText("veracrypt.sys")).toBeInTheDocument();
    expect(screen.getAllByText("0xffffa00000300000").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/POSSIBLE XTS pair/).length).toBeGreaterThan(1);
    expect(screen.getByText(/an inference from adjacency/)).toBeInTheDocument();
  });

  it("Console history: prints each stored command with its host and says a missing history is not evidence", async () => {
    mock("MemoryConsoleHistory", [
      stage("ch1", "MemoryConsoleHistory", "console_history", {
        summary: "1 console host(s) swept, 1 command history recognised.",
        histories_total: 1,
        hosts: [
          {
            host: "conhost.exe",
            pid: 5160,
            swept: true,
            histories_found: 1,
            bytes_swept: 1048576,
            bytes_not_resident: 1000000,
            bytes_paged_out: 0,
            bytes_unreadable: 4096,
            histories: [
              {
                address: "0x000001e94d90e280",
                application: "cmd.exe",
                command_limit: 50,
                commands: [
                  {
                    index: 0,
                    text: "echo SEANCE-CMD-ONE-4417",
                    unreadable: null,
                  },
                  {
                    index: 1,
                    text: null,
                    unreadable: "its characters would not read",
                  },
                ],
              },
            ],
          },
        ],
        console_clients_listed: [{ name: "cmd.exe", pid: 5080 }],
        layout_basis: "derived in-house on one build",
      }),
    ]);
    renderViewer("MemoryConsoleHistory");
    await waitFor(() =>
      expect(screen.getByText("echo SEANCE-CMD-ONE-4417")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/unreadable: its characters would not read/),
    ).toBeInTheDocument();
    expect(screen.getByText(/commands in stored order/)).toBeInTheDocument();
    expect(
      screen.getByText(/derived in-house on one build/),
    ).toBeInTheDocument();
  });

  it("prints a stage's incompleteness with its reasons, so a short walk is a floor", async () => {
    mock("MemoryProcessorBlocks", [
      stage("p2", "MemoryProcessorBlocks", "processor_blocks", {
        content_complete: false,
        content_incomplete: true,
        content_incomplete_reason: "the walk stopped at slot 3",
        incomplete: [
          {
            reason: "short_read",
            detail: "slot 3 of KiProcessorBlock would not read",
          },
        ],
        processors: [],
        processors_walked: 0,
      }),
    ]);
    renderViewer("MemoryProcessorBlocks");
    await waitFor(() =>
      expect(
        screen.getByText(/slot 3 of KiProcessorBlock would not read/),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText(/did not complete/)).toBeInTheDocument();
  });
});
