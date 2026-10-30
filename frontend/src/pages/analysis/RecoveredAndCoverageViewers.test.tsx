import { render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { server } from "../../test/server";
import type { ParsedRecord } from "./api";
import { RecordsViewerPage } from "./RecordsViewerPage";

/**
 * The viewers the 2026-09 waves owed: records that are RECOVERED, records
 * that state COVERAGE, and the new parsers' records. What every test here
 * pins is that a fact the parser put on the record reaches the screen with
 * its provenance — a recovered event is never dressed as a live one, a cap is
 * shown with its number, and a field the format does not document is named
 * for what it is.
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

function rec(id: string, metadata: Record<string, unknown>): ParsedRecord {
  return {
    id,
    parent_id: "a1",
    artifact_type: "ParsedRecord",
    metadata,
  } as unknown as ParsedRecord;
}

describe("recovered Windows event log entries (ROADMAP §2.4)", () => {
  it("shows where a recovered event came from, its checksum states, and that its template was borrowed", async () => {
    mock("EvtxRecoveredLogEntry", [
      rec("e1", {
        type: "EvtxRecoveredLogEntry",
        recovered: true,
        recovery_source: "chunk_slack",
        chunk_header: "present",
        chunk_header_checksum: "valid",
        chunk_data_checksum: "unverifiable_truncated",
        chunk_offset: 917504,
        record_offset: 918000,
        event_id: 4624,
        provider_name: "Microsoft-Windows-Security-Auditing",
        channel: "Security",
        level_description: "Information",
        timestamp: 1700000000,
        short_desc: "Successful account logon",
        rendered_with_borrowed_template: true,
        borrowed_template: {
          template_id: "0x00001234",
          from_chunk_offset: 65536,
          candidates: 1,
          ambiguous: false,
          guid_confirmed: true,
        },
        partial: false,
        incomplete_substitutions: [],
      }),
    ]);
    renderViewer("EvtxRecoveredLogEntry");

    await waitFor(() =>
      expect(screen.getAllByText("4624").length).toBeGreaterThan(0),
    );
    // The heading is the recovered label, never the live one.
    expect(
      screen.getByRole("heading", { name: "Windows Event Log (recovered)" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("chunk slack").length).toBeGreaterThan(0);
    expect(screen.getByText("unverifiable (truncated)")).toBeInTheDocument();
    expect(screen.getByText("borrowed")).toBeInTheDocument();
    // The row carries the caution about a borrowed template (the flag's
    // title is the reason).
    expect(
      screen.getByTitle(/template borrowed from another chunk/),
    ).toBeInTheDocument();
  });

  it("marks a partial record and names the substitutions it could not bind", async () => {
    mock("EvtxRecoveredLogEntry", [
      rec("e2", {
        type: "EvtxRecoveredLogEntry",
        recovered: true,
        recovery_source: "carved_chunk",
        chunk_header: "tables_discarded",
        chunk_header_checksum: "failed",
        chunk_data_checksum: "failed",
        event_id: 7045,
        provider_name: "Service Control Manager",
        channel: "System",
        timestamp: 1700000100,
        short_desc: "A new service was installed",
        rendered_with_borrowed_template: false,
        partial: true,
        incomplete_substitutions: [
          { index: 3, position: 120, reason: "value past the chunk" },
          { index: 5, position: 150, reason: "value past the chunk" },
        ],
        content_incomplete: true,
        content_incomplete_reason: "unresolved_structure",
        content_incomplete_detail:
          "2 substitution(s) could not be bound (indices 3, 5); the XML holds what did bind and a SeanceIncomplete marker at each text position that did not",
      }),
    ]);
    renderViewer("EvtxRecoveredLogEntry");

    await waitFor(() =>
      expect(screen.getAllByText("7045").length).toBeGreaterThan(0),
    );
    expect(screen.getByText("partial")).toBeInTheDocument();
    // The partial record's flag carries the parser's own sentence.
    expect(screen.getByTitle(/could not be bound \(indices 3, 5\)/)).toBeInTheDocument();
    expect(screen.getByText("2 (indices 3, 5)")).toBeInTheDocument();
    expect(screen.getAllByText("carved chunk").length).toBeGreaterThan(0);
    expect(screen.getByText("tables discarded")).toBeInTheDocument();
  });

  it("shows the recovery status with every count and the bound that was hit", async () => {
    mock("EvtxRecoveryStatus", [
      rec("s1", {
        type: "EvtxRecoveryStatus",
        name: "EVTX fragment recovery",
        bytes_declared: 200000,
        bytes_scanned: 200000,
        scan_bound_hit: false,
        chunks_found: 4,
        chunks_checksum_valid: 2,
        chunks_checksum_failed: 1,
        chunks_checksum_absent: 0,
        chunks_checksum_unverifiable: 1,
        chunks_truncated: 1,
        chunks_unopenable: 0,
        chunks_bound_hit: false,
        records_recovered: 79,
        records_partial: 3,
        records_header_only: 1,
        records_borrowed_template: 12,
        records_already_live: 5,
        records_bound_hit: true,
        counts_are_floor: true,
        inventory_incomplete: true,
        limits: { max_scan_bytes: 1073741824, max_records: 200000 },
        message: "records bound of 200000 reached",
      }),
    ]);
    renderViewer("EvtxRecoveryStatus");

    await waitFor(() =>
      expect(screen.getByText("EVTX fragment recovery")).toBeInTheDocument(),
    );
    expect(screen.getByText("79")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    // A bound that was hit makes every count a floor, and the row says so.
    expect(screen.getByText(/records bound hit/)).toBeInTheDocument();
    expect(screen.getByText(/counts are a floor/)).toBeInTheDocument();
  });

  it("says when the input returned fewer bytes than it declared, so a short read is never a complete scan", async () => {
    mock("EvtxRecoveryStatus", [
      rec("s2", {
        type: "EvtxRecoveryStatus",
        name: "EVTX fragment recovery",
        bytes_declared: 1200000,
        bytes_scanned: 200000,
        short_read: true,
        scan_bound_hit: false,
        chunks_found: 3,
        records_recovered: 10,
        counts_are_floor: false,
        content_incomplete: true,
        content_incomplete_reason: "short_read",
        message: "the source returned 200000 of 1200000 declared bytes",
      }),
    ]);
    renderViewer("EvtxRecoveryStatus");
    await waitFor(() =>
      expect(screen.getByText("EVTX fragment recovery")).toBeInTheDocument(),
    );
    expect(screen.getByText("195.3 KiB of 1.1 MiB")).toBeInTheDocument();
    expect(screen.getByText(/short read/)).toBeInTheDocument();
    expect(screen.getByText(/not the whole input/)).toBeInTheDocument();
  });
});

describe("registry keys and values recovered from unallocated cells (ROADMAP §5.9)", () => {
  it("shows a recovered key's inferred path as an inference, with its live namesake", async () => {
    mock("RecoveredRegistryKey", [
      rec("k1", {
        type: "RecoveredRegistryKey",
        hive: "SAM",
        key_name: "Names",
        key_path: "SAM\\Domains\\Account\\Users\\Names",
        key_path_is_inference: true,
        key_path_complete: true,
        bin_offset: 12824,
        parent_offset: 2480,
        last_written: "2012-04-05T11:22:33Z",
        subkey_count_declared: 3,
        value_count_declared: 0,
        live_key_with_same_name_under_parent: true,
        live_namesake_note: "the live tree holds a key of this name under the same parent",
        evidence_state: "recovered",
        recovered_from: "unallocated hive cell",
      }),
    ]);
    renderViewer("RecoveredRegistryKey");

    await waitFor(() =>
      expect(
        screen.getByText("SAM\\Domains\\Account\\Users\\Names"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByRole("columnheader", { name: /Key path \(inferred from offsets\)/ }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("recovered").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/live key of this name/).length).toBeGreaterThan(0);
    expect(screen.getByTitle(/not evidence that the key was deleted/)).toBeInTheDocument();
  });

  it("says when a recovered key's path does not reach the root", async () => {
    mock("RecoveredRegistryKey", [
      rec("k2", {
        type: "RecoveredRegistryKey",
        hive: "SAM",
        key_name: "Orphan",
        key_path: "…\\Orphan",
        key_path_is_inference: true,
        key_path_complete: false,
        key_path_parent_offset_unresolved: 4096,
        bin_offset: 16504,
        live_key_with_same_name_under_parent: false,
        evidence_state: "recovered",
      }),
    ]);
    renderViewer("RecoveredRegistryKey");
    await waitFor(() =>
      expect(screen.getByText("…\\Orphan")).toBeInTheDocument(),
    );
    expect(screen.getAllByText(/does not reach the root/).length).toBeGreaterThan(0);
    expect(screen.getByTitle(/stops at an offset \(4096\)/)).toBeInTheDocument();
  });

  it("shows a recovered value with its data basis and no key", async () => {
    mock("RecoveredRegistryValue", [
      rec("v1", {
        type: "RecoveredRegistryValue",
        hive: "SAM",
        value_name: "F",
        value_type: "RegBinary",
        key_path: null,
        key_association_note: "a vk cell does not record the key it belonged to",
        bin_offset: 13600,
        raw_data_size_declared: 80,
        raw_data_size: 80,
        tombstoned: false,
        data_read: true,
        value_data: "02 00 01 00 …",
        data_basis:
          "an allocated data cell the freed vk points at. The cell is in use now, and may have been reused by another value since this one was deleted, so these bytes are what the cell holds today and not necessarily what this value held.",
        evidence_state: "recovered",
      }),
      rec("v2", {
        type: "RecoveredRegistryValue",
        hive: "SAM",
        value_name: "V",
        value_type: "RegBinary",
        key_path: null,
        bin_offset: 13700,
        raw_data_size_declared: 4096,
        tombstoned: true,
        data_read: false,
        value_data: null,
        data_unread_reason: "the data cell lies outside the hive's bins",
        evidence_state: "recovered",
      }),
    ]);
    renderViewer("RecoveredRegistryValue");

    await waitFor(() => expect(screen.getByText("F")).toBeInTheDocument());
    // Every recovered value's key is unknown, and the column says so rather
    // than showing a dash that reads as "root".
    expect(screen.getAllByText("not inferred").length).toBe(2);
    expect(screen.getByTitle(/cell may have been reused since/)).toBeInTheDocument();
    expect(screen.getAllByText(/may have been reused/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("not read").length).toBeGreaterThan(0);
    expect(screen.getByTitle(/outside the hive's bins/)).toBeInTheDocument();
  });
});

describe("YARA over more than files (ROADMAP §2.3)", () => {
  it("shows a match's surface, entropy, pattern hit count and whether the bytes were decoded", async () => {
    mock("YaraMatch", [
      rec("y1", {
        type: "YaraMatch",
        rule: "zone_transfer",
        namespace: "default",
        rules_in_set: 3,
        surface: "ads",
        surface_means: "the bytes are an alternate data stream",
        stream_name: "Zone.Identifier",
        path: "C:\\Users\\a\\setup.exe",
        entropy_bits_per_byte: 4.6123,
        entropy_bytes: 26,
        pattern_match_count: 2,
        bytes_are_decoded: false,
      }),
      rec("y2", {
        type: "YaraMatch",
        rule: "b64_payload",
        namespace: "default",
        rules_in_set: 3,
        surface: "unallocated",
        surface_means: "the bytes are free space",
        entropy_bits_per_byte: 7.91,
        entropy_bytes: 1048576,
        pattern_match_count: 1,
        bytes_are_decoded: true,
        decoded_via: "base64",
      }),
      rec("y3", {
        type: "YaraMatch",
        rule: "slack_marker",
        namespace: "default",
        rules_in_set: 3,
        surface: "slack",
        surface_means: "the bytes are the slack of the live file named here",
        base_file: "file-n-4.dat",
        path: "/file-n-4.dat",
        entropy_bits_per_byte: 3.1,
        entropy_bytes: 539,
        pattern_match_count: 1,
        bytes_are_decoded: false,
      }),
    ]);
    renderViewer("YaraMatch");

    await waitFor(() =>
      expect(screen.getAllByText("zone_transfer").length).toBeGreaterThan(0),
    );
    expect(screen.getAllByText("ads").length).toBeGreaterThan(0);
    expect(screen.getAllByText("unallocated").length).toBeGreaterThan(0);
    expect(screen.getByText("4.6123 over 26 B")).toBeInTheDocument();
    expect(screen.getByText("7.91 over 1.0 MiB")).toBeInTheDocument();
    expect(screen.getByText("decoded (base64)")).toBeInTheDocument();
    expect(screen.getAllByText("stored bytes")).toHaveLength(2);
    // A hit in free space is never presented as a hit in a live file, and
    // a decoded hit says both things: where it was, and that the bytes
    // matched were never stored in that form.
    expect(
      screen.getByTitle(/in free space: not a hit in a live file.*decoded bytes \(base64\)/),
    ).toBeInTheDocument();
    expect(
      screen.getByTitle(/alternate data stream: content beside the named file/),
    ).toBeInTheDocument();
    // A hit in slack names the file and says the bytes are past its end.
    expect(
      screen.getByTitle(/in the slack of file-n-4\.dat: past the file's logical end, not its content/),
    ).toBeInTheDocument();
  });

  it("shows a scanned region with its entropy and whether the scan reached all of it", async () => {
    mock("YaraRegionScanned", [
      rec("r1", {
        type: "YaraRegionScanned",
        surface: "unallocated",
        region_source: "allocation_bitmap",
        offset_bytes: 1048576,
        size_bytes: 4194304,
        bytes_scanned: 4194304,
        declared_size: 4194304,
        scan_complete: true,
        entropy_bits_per_byte: 0.0,
        entropy_bytes: 4194304,
        matches: 0,
        decoded_spans_found: 0,
        decoded_spans_scanned: 0,
      }),
    ]);
    renderViewer("YaraRegionScanned");
    await waitFor(() =>
      expect(screen.getAllByText("unallocated").length).toBeGreaterThan(0),
    );
    expect(screen.getByText("0 over 4.0 MiB")).toBeInTheDocument();
    expect(screen.getByText("whole")).toBeInTheDocument();
  });

  it("shows the registry coverage record's value counts by basis", async () => {
    mock("YaraRegistryCoverage", [
      rec("c1", {
        type: "YaraRegistryCoverage",
        surface: "registry_value",
        hive_type: "NTUSER",
        values_total: 5602,
        values_scanned: 5602,
        values_scanned_exact: 3569,
        values_scanned_reencoded: 2033,
        values_not_scanned: 0,
        bytes_scanned: 812000,
        byte_budget: 268435456,
        byte_budget_reached: false,
        matches: 701,
      }),
    ]);
    renderViewer("YaraRegistryCoverage");
    await waitFor(() =>
      expect(screen.getAllByText("5,602").length).toBe(2),
    );
    expect(screen.getByText("3,569")).toBeInTheDocument();
    expect(screen.getByText("2,033")).toBeInTheDocument();
    expect(screen.getByText("701")).toBeInTheDocument();
  });

  // UI-041: since HUNT-207 a record from an older build counts values whose
  // bytes were rebuilt from a lossless rendering apart from the exact and the
  // re-encoded ones; without its own column, Scanned no longer equals the sum
  // of the basis columns on screen.
  it("shows values rebuilt from a rendering in their own column", async () => {
    mock("YaraRegistryCoverage", [
      rec("c2", {
        type: "YaraRegistryCoverage",
        surface: "registry_value",
        hive_type: "SYSTEM",
        values_total: 950,
        values_scanned: 940,
        values_scanned_exact: 0,
        values_scanned_rebuilt: 613,
        values_scanned_reencoded: 327,
        values_not_scanned: 10,
        bytes_scanned: 81000,
        byte_budget: 268435456,
        byte_budget_reached: false,
        matches: 4,
      }),
    ]);
    renderViewer("YaraRegistryCoverage");
    await waitFor(() => expect(screen.getByText("940")).toBeInTheDocument());
    expect(screen.getByText("Rebuilt from rendering")).toBeInTheDocument();
    expect(screen.getByText("613")).toBeInTheDocument();
    expect(screen.getByText("327")).toBeInTheDocument();
  });

  it("shows the decode coverage record's shortfall verbatim", async () => {
    mock("YaraDecodeCoverage", [
      rec("d1", {
        type: "YaraDecodeCoverage",
        surface: "file",
        path: "/tmp/big.txt",
        decoded_spans_found: 900,
        decoded_spans_scanned: 512,
        decoded_bytes_scanned: 16777216,
        decoded_cap_reached: true,
        content_incomplete: true,
        content_incomplete_detail:
          "388 of 900 decoded spans were not scanned: the span cap of 512 was reached",
      }),
    ]);
    renderViewer("YaraDecodeCoverage");
    await waitFor(() => expect(screen.getByText("/tmp/big.txt")).toBeInTheDocument());
    expect(screen.getByText("512 of 900")).toBeInTheDocument();
    expect(screen.getByText(/span cap of 512 was reached/)).toBeInTheDocument();
  });
});

describe("the feature histogram (ROADMAP §2.1)", () => {
  it("renders the most-common values, the per-kind totals and the record's own cap note", async () => {
    mock("FeatureHistogramSummary", [
      rec("h1", {
        type: "FeatureHistogramSummary",
        subtype: "summary",
        total_hits: 1234,
        distinct_values: 100000,
        hits_dropped: 57,
        capped: true,
        max_distinct_values: 100000,
        top_n: 100,
        top_omitted: 99998,
        top: [
          { kind: "email", value: "a@example.com", count: 40 },
          { kind: "url", value: "https://example.com/x", count: 12 },
        ],
        by_kind: {
          email: { hits: 800, distinct_values: 60000 },
          url: { hits: 434, distinct_values: 40000 },
        },
        bytes_scanned: 21883,
        scan_capped: false,
        note: "Capped: the histogram tracks at most 100000 distinct values, and 57 hits for values beyond that were not tallied. Counts for the tracked values are exact; the distinct-value total is a floor, not the number the scan contained.",
      }),
    ]);
    renderViewer("FeatureHistogramSummary");

    await waitFor(() =>
      expect(screen.getByText("a@example.com")).toBeInTheDocument(),
    );
    expect(screen.getByText("https://example.com/x")).toBeInTheDocument();
    expect(screen.getByText("40")).toBeInTheDocument();
    expect(screen.getByText("800")).toBeInTheDocument();
    expect(screen.getByText("60,000")).toBeInTheDocument();
    // The cap is disclosed in the record's own words, with its number.
    expect(
      screen.getByText(/tracks at most 100000 distinct values, and 57 hits/),
    ).toBeInTheDocument();
    expect(screen.getByText(/2 of 100,000 distinct values/)).toBeInTheDocument();
  });
});

describe("registry MRU entries carry the shell item's file reference (HUNT-147)", () => {
  it("shows the MFT entry and sequence, and how many items were unread", async () => {
    mock("ShellMruEntry", [
      rec("m1", {
        type: "ShellMruEntry",
        mru_kind: "LastVisitedPidlMRU",
        display_name: "Alloy Research",
        shell_item_path: ["MyComputer", "C:", "Users", "nfury", "Documents", "Alloy Research"],
        mru_position: 4,
        shell_item_parsed: true,
        shell_item_mft_entry: 44518,
        shell_item_mft_sequence: 33,
        shell_items_total: 6,
        shell_items_unread: 0,
        key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
      }),
      rec("m2", {
        type: "ShellMruEntry",
        mru_kind: "RecentDocs",
        display_name: "notes.txt",
        shell_item_path: ["notes.txt"],
        mru_position: 0,
        shell_item_parsed: true,
        shell_item_mft_reference_note:
          "the file reference field is all zero and is not reported as an MFT entry",
        shell_items_total: 3,
        shell_items_unread: 1,
        content_incomplete: true,
        content_incomplete_reason: "unresolved_structure",
        content_incomplete_detail: "1 of 3 shell items could not be read past its type byte",
        key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
      }),
    ]);
    renderViewer("ShellMruEntry");

    await waitFor(() =>
      expect(screen.getAllByText("Alloy Research").length).toBeGreaterThan(0),
    );
    expect(screen.getByText("44,518")).toBeInTheDocument();
    expect(screen.getByText("33")).toBeInTheDocument();
    expect(screen.getByText("1 of 3")).toBeInTheDocument();
    // The unread count is the row's flag; the zeroed reference is disclosed
    // on the row rather than shown as entry 0.
    expect(screen.getByTitle(/1 of 3 shell items could not be read/)).toBeInTheDocument();
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent);
    const mftCol = headers.indexOf("MFT entry");
    expect(mftCol).toBeGreaterThan(-1);
    const notesRow = screen
      .getAllByRole("row")
      .find((r) => within(r).queryAllByText("notes.txt").length > 0);
    expect(within(notesRow!).getAllByRole("cell")[mftCol]).toHaveTextContent("—");
  });
});

describe("jump list DestList entries (ROADMAP §2.5)", () => {
  it("shows the MRU position, the last recorded time, the pin state and the undocumented field under its own name", async () => {
    mock("JumpListDestListEntry", [
      rec("j1", {
        type: "JumpListDestListEntry",
        jump_list: "1b4dd67f29cb1962.automaticDestinations-ms",
        app_id: "1b4dd67f29cb1962",
        application: "Windows Explorer (pinned and recent)",
        application_identifier: "1b4dd67f29cb1962",
        dest_list_format_version: 1,
        mru_position: 0,
        entry_number: 11,
        stream_name: "b",
        path: "C:\\Users\\nfury\\Documents",
        hostname: "WKS-WINXP32BIT",
        last_recorded_time: "2012-04-01T13:52:38.9971860Z",
        pin_status: -1,
        pinned: false,
        offset_116_unavailable:
          "a DestList format version 1 entry (Windows 7 and 8) has a 114-byte fixed part and no field at offset 116; none is reported",
      }),
      rec("j2", {
        type: "JumpListDestListEntry",
        jump_list: "9d1f905ce5044aee.automaticDestinations-ms",
        app_id: "9d1f905ce5044aee",
        application: null,
        application_unknown:
          "this AppID is not one this build can name; the application that wrote this jump list is not established",
        dest_list_format_version: 3,
        mru_position: 1,
        entry_number: 2,
        stream_name: "2",
        path: "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
        last_recorded_time: "2016-01-14T13:12:08.3980000Z",
        pin_status: 0,
        pinned: true,
        pinned_position: 0,
        offset_116_unknown_possibly_access_count: 9,
        offset_116_note: "the sources this module follows do not establish what this field is",
      }),
    ]);
    renderViewer("JumpListDestListEntry");

    await waitFor(() =>
      expect(screen.getByText("C:\\Users\\nfury\\Documents")).toBeInTheDocument(),
    );
    expect(
      screen.getAllByText("Windows Explorer (pinned and recent)").length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("pinned")).toBeInTheDocument();
    expect(screen.getByText("not pinned")).toBeInTheDocument();
    // The field at offset 116 is reported as read and never called an
    // access count.
    expect(
      screen.getByRole("columnheader", {
        name: /Offset 116 \(undocumented; possibly an access count\)/,
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/^Access count$/)).toBeNull();
    expect(screen.getByText("9")).toBeInTheDocument();
    // An unmapped AppID is "not established", never a guessed name.
    expect(screen.getAllByText("not established").length).toBeGreaterThan(0);
    expect(screen.getByTitle(/application that wrote this jump list is not established/)).toBeInTheDocument();
    expect(screen.getAllByText("WKS-WINXP32BIT").length).toBeGreaterThan(0);
  });
});

describe("iOS Safari and HealthKit (ROADMAP §1.5)", () => {
  it("shows Safari bookmarks with their folder and reading-list state", async () => {
    mock("SafariBookmark", [
      rec("b1", {
        type: "SafariBookmark",
        platform: "iOS",
        source: "Bookmarks.db",
        bookmark_id: 7,
        title: "Magnet Forensics",
        url: "https://www.magnetforensics.com/",
        folder_path: "Root/BookmarksBar",
        reading_list: false,
        hidden: false,
        deleted: false,
        last_modified: 1650000000,
      }),
    ]);
    renderViewer("SafariBookmark");
    await waitFor(() =>
      expect(screen.getByText("Magnet Forensics")).toBeInTheDocument(),
    );
    expect(screen.getAllByText("Root/BookmarksBar").length).toBeGreaterThan(0);
    // `read` was NULL in the store: the column says not recorded, not unread.
    expect(screen.getByText("not recorded")).toBeInTheDocument();
  });

  it("shows open tabs with the private flag, the window and the back/forward list", async () => {
    mock("SafariOpenTab", [
      rec("t1", {
        type: "SafariOpenTab",
        platform: "iOS",
        source: "SafariTabs.db",
        tab_id: 16,
        title: "DuckDuckGo",
        url: "https://duckduckgo.com/",
        tab_group: "Private",
        private_browsing: true,
        window_id: 3,
        is_active_tab: true,
        deleted: false,
        last_visit: 1650001000,
        session_state_present: true,
        session_history_decoded: true,
        session_history_entries: 5,
        session_history: [],
      }),
      rec("t2", {
        type: "SafariOpenTab",
        platform: "iOS",
        source: "SafariTabs.db",
        tab_id: 18,
        title: "Apple",
        url: "https://www.apple.com/",
        tab_group: "Local",
        private_browsing: false,
        deleted: false,
        session_state_present: true,
        session_history_decoded: false,
        content_incomplete: true,
        content_incomplete_reason: "unresolved_structure",
        content_incomplete_detail:
          "SessionState did not parse as a versioned binary plist; the tab's back/forward history is present and unread",
      }),
    ]);
    renderViewer("SafariOpenTab");
    await waitFor(() => expect(screen.getByText("DuckDuckGo")).toBeInTheDocument());
    expect(screen.getAllByText("private").length).toBeGreaterThan(0);
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByTitle(/present and unread/)).toBeInTheDocument();
    // t1 carries is_active_tab; t2 does not (the store only writes it for a
    // tab whose group maps to a window) — an absent flag is "not recorded",
    // never "background".
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.queryByText("background")).not.toBeInTheDocument();
    expect(screen.getByText("not recorded")).toBeInTheDocument();
  });

  it("shows web searches with the time and says the engine is not recorded", async () => {
    mock("WebSearchQuery", [
      rec("q1", {
        type: "WebSearchQuery",
        platform: "iOS",
        browser: "Safari",
        source: "com.apple.mobilesafari.plist",
        index: 0,
        query: "how to delete photos",
        search_engine_not_recorded: true,
        timestamp: 1650002000,
      }),
    ]);
    renderViewer("WebSearchQuery");
    await waitFor(() =>
      expect(screen.getByText("how to delete photos")).toBeInTheDocument(),
    );
    expect(screen.getByText("not recorded")).toBeInTheDocument();
    expect(screen.getAllByText("Safari").length).toBeGreaterThan(0);
  });

  it("shows HealthKit samples with their type, quantity, source and zone, and says when the unit or type name is not established", async () => {
    mock("HealthSample", [
      rec("hs1", {
        type: "HealthSample",
        platform: "iOS",
        source: "healthdb_secure.sqlite",
        data_id: 100,
        data_type: 7,
        data_type_name: "HKQuantityTypeIdentifierStepCount",
        data_type_name_basis: "asserted",
        start: 1650003000,
        end: 1650003600,
        duration_seconds: 600,
        quantity: 412,
        unit_not_recorded: true,
        deleted: false,
        source_name: "iPhone 8",
        recording_timezone: "America/New_York",
      }),
      rec("hs2", {
        type: "HealthSample",
        platform: "iOS",
        source: "healthdb_secure.sqlite",
        data_id: 101,
        data_type: 182,
        data_type_name_unknown: true,
        start: 1650004000,
        quantity: 1,
        unit_not_recorded: true,
        deleted: false,
      }),
    ]);
    renderViewer("HealthSample");
    await waitFor(() =>
      expect(
        screen.getAllByText("HKQuantityTypeIdentifierStepCount").length,
      ).toBeGreaterThan(0),
    );
    expect(screen.getByText("412")).toBeInTheDocument();
    expect(screen.getAllByText("iPhone 8").length).toBeGreaterThan(0);
    expect(screen.getAllByText("America/New_York").length).toBeGreaterThan(0);
    // Both samples' units were not recorded: two cells, and neither is "0"
    // or a guessed unit.
    expect(screen.getAllByText("not recorded").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("type 182 (not named by this build)").length).toBeGreaterThan(0);
    expect(screen.getByTitle(/sample type 182 is not one this build names/)).toBeInTheDocument();
  });
});

describe("parser schema warnings (ROADMAP §1.4a)", () => {
  it("shows the status, the version seen against the validated range, and the unresolved fields", async () => {
    mock("ParserStaleWarning", [
      rec("w1", {
        type: "ParserStaleWarning",
        subtype: "parse_incomplete",
        status: "SchemaVersionOutOfRange",
        app: "android-sms",
        seen_schema_version: 70,
        supported_range: "57..=67",
        message: "android-sms: schema version 70 is outside the validated range 57..=67",
        content_incomplete: true,
        content_incomplete_detail:
          "android-sms: schema version 70 is outside the validated range 57..=67",
      }),
      rec("w2", {
        type: "ParserStaleWarning",
        subtype: "parser_stale",
        status: "SchemaFieldsUnresolved",
        app: "Chrome history",
        store: "History",
        source_table: "urls",
        supported_range: "20..=59",
        validated_against: "plaso History (Chrome 20) and a Chrome 59 profile",
        unresolved_fields: ["hidden", "typed_count"],
        records_recovered: 55,
        content_incomplete: true,
        content_incomplete_detail:
          "Chrome history: 2 logical fields did not resolve to a column of `urls` (hidden, typed_count)",
      }),
    ]);
    renderViewer("ParserStaleWarning");
    await waitFor(() =>
      expect(screen.getAllByText("android-sms").length).toBeGreaterThan(0),
    );
    expect(screen.getAllByText("SchemaVersionOutOfRange").length).toBeGreaterThan(0);
    expect(screen.getByText("70")).toBeInTheDocument();
    expect(screen.getByText("57..=67")).toBeInTheDocument();
    expect(screen.getByText("hidden")).toBeInTheDocument();
    expect(screen.getByText("typed_count")).toBeInTheDocument();
    expect(screen.getByText("plaso History (Chrome 20) and a Chrome 59 profile")).toBeInTheDocument();
    expect(screen.getByText("55")).toBeInTheDocument();
    expect(screen.getByText("urls")).toBeInTheDocument();
  });

  it("reads the per-app schema notes, which spell the same facts under their own keys", async () => {
    mock("ParserStaleWarning", [
      rec("w3", {
        type: "ParserStaleWarning",
        subtype: "schema_support",
        warning_class: "ParserStaleWarning",
        status: "SchemaNotRanged",
        app: "line",
        store: "naver_line",
        schema_version_seen: 12,
        schema_unranged_reason: "no real LINE database is held; no range is declared",
        schema_unresolved_fields: ["sticker_id"],
        records_recovered: 3,
        detail: "line: no validated schema range is declared",
      }),
    ]);
    renderViewer("ParserStaleWarning");
    await waitFor(() =>
      expect(screen.getAllByText("SchemaNotRanged").length).toBeGreaterThan(0),
    );
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("sticker_id")).toBeInTheDocument();
    expect(screen.getByText(/no real LINE database is held/)).toBeInTheDocument();
  });
});

describe("Linux memory paths carry their own scope (ROADMAP §4.2)", () => {
  it("flattens the open-files stage into one row per descriptor, each with its path scope", async () => {
    mock("LinuxMemoryOpenFiles", [
      rec("l1", {
        type: "LinuxMemoryOpenFiles",
        record_type: "LinuxMemoryOpenFiles",
        stage: "linux_open_files",
        process_count: 1,
        open_file_count: 2,
        complete: true,
        path_scope: "mount_crossing",
        path_scope_note:
          "paths are walked across mount points to the process's root where the build allowed it; each record says which walk it got",
        path_scope_is_per_record: true,
        processes: [
          {
            pid: { kind: "known", value: 1 },
            comm: { kind: "known", value: "systemd" },
            files: [
              {
                fd: 0,
                path: { kind: "known", value: "/dev/null" },
                path_kind: "file",
                path_scope: "mount_crossing",
                path_scope_detail:
                  "crossed 1 mount point(s) and ended at the process's root directory",
              },
              {
                fd: 3,
                path: { kind: "known", value: "socket:[12345]" },
                path_kind: "pseudo",
                path_scope: "pseudo",
                path_scope_detail: "rendered by sockfs_dname; not a path in any mount",
              },
            ],
          },
        ],
      }),
    ]);
    renderViewer("LinuxMemoryOpenFiles");
    await waitFor(() => expect(screen.getByText("/dev/null")).toBeInTheDocument());
    const rows = screen.getAllByRole("row");
    const nullRow = rows.find((r) => within(r).queryByText("/dev/null"));
    expect(nullRow).toBeDefined();
    expect(within(nullRow!).getByText("systemd")).toBeInTheDocument();
    expect(within(nullRow!).getByText("mount crossing")).toBeInTheDocument();
    expect(
      within(nullRow!).getByText(/crossed 1 mount point/),
    ).toBeInTheDocument();
    expect(screen.getByText("socket:[12345]")).toBeInTheDocument();
    const socketRow = rows.find((r) => within(r).queryByText("socket:[12345]"));
    expect(within(socketRow!).getAllByText("pseudo").length).toBeGreaterThan(0);
    // The survey's own statement of which walk the build allowed.
    expect(screen.getByText(/each record says which walk it got/)).toBeInTheDocument();
  });

  it("flattens the mounts stage with the mount point's own scope", async () => {
    mock("LinuxMemoryMounts", [
      rec("l2", {
        type: "LinuxMemoryMounts",
        record_type: "LinuxMemoryMounts",
        stage: "linux_mounts",
        namespace_count: 1,
        mount_count: 1,
        complete: true,
        path_scope: "mount_crossing",
        path_scope_note: "mount points are walked across parent mounts",
        namespaces: [
          {
            mnt_ns_address_hex: "0xffff888100001000",
            mounts: [
              {
                mount_address_hex: "0xffff888100002000",
                devname: { kind: "known", value: "devpts" },
                mount_point: { kind: "known", value: "/dev/pts" },
                mount_point_scope: "mount_crossing",
                mount_point_scope_detail:
                  "crossed 1 mount point(s) and ended at the global root",
                fs_root: { kind: "known", value: "/" },
                flags: {
                  access: "ro",
                  options: ["nosuid", "noexec"],
                  shared: false,
                  unbindable: false,
                },
              },
            ],
          },
        ],
      }),
    ]);
    renderViewer("LinuxMemoryMounts");
    await waitFor(() => expect(screen.getByText("/dev/pts")).toBeInTheDocument());
    expect(screen.getByText("devpts")).toBeInTheDocument();
    // The survey badge and the row badge both say it; the row's is the one
    // a reader takes the path from.
    const row = screen.getAllByRole("row").find((r) => within(r).queryByText("/dev/pts"));
    expect(within(row!).getByText("mount crossing")).toBeInTheDocument();
    expect(within(row!).getByText(/ended at the global root/)).toBeInTheDocument();
    expect(within(row!).getByText("ro nosuid noexec")).toBeInTheDocument();
  });
});
