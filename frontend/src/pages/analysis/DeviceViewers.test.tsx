import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { server } from "../../test/server";
import type { ParsedRecord } from "./api";
import { RecordsViewerPage } from "./RecordsViewerPage";

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

describe("the records that say what an exhibit is", () => {
  it("shows the facts a host identity file stated, and where it read them", async () => {
    // Before this the generic viewer rendered the whole `facts` object into one
    // cell, so the answer to "what is this machine called" was a blob of JSON.
    mock("HostDeviceInfo", [
      {
        id: "h1",
        parent_id: "a1",
        artifact_type: "ParsedRecord",
        metadata: {
          type: "HostDeviceInfo",
          platform: "linux",
          name: "Linux host name",
          source_file: "/etc/hostname",
          facts: { host_name: "rshell-lenovo" },
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("HostDeviceInfo");

    await waitFor(() =>
      expect(screen.getByText("/etc/hostname")).toBeInTheDocument(),
    );
    expect(screen.getByText(/host_name = rshell-lenovo/)).toBeInTheDocument();
    expect(screen.getByText("linux")).toBeInTheDocument();
  });

  it("reads an iOS backup as a phone, not as a plist", async () => {
    mock("IosBackupInfo", [
      {
        id: "b1",
        parent_id: "a2",
        artifact_type: "ParsedRecord",
        metadata: {
          type: "IosBackupInfo",
          device_name: "Eli's iPhone",
          product_type: "iPhone10,4",
          product_version: "14.4",
          imei: "356759080486567",
          serial_number: "FFMV8CNHJC69",
          encrypted: false,
          date: "2021-03-07T05:46:32Z",
          backup_path: "/eliflatt/…/Backup/518e8d76",
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("IosBackupInfo");

    await waitFor(() =>
      expect(screen.getByText("Eli's iPhone")).toBeInTheDocument(),
    );
    expect(screen.getByText("356759080486567")).toBeInTheDocument();
    expect(screen.getByText("iPhone10,4")).toBeInTheDocument();
    // Whether it was encrypted decides what else can be read out of it.
    expect(screen.getByText("not encrypted")).toBeInTheDocument();
  });
});

describe("what is installed on the exhibit", () => {
  it("names the application, its version and where it was installed from", async () => {
    // HUNT-110. "What was on this machine, and at what version" — and an app in
    // a user's Downloads folder is a different statement from one in
    // /Applications.
    mock("InstalledApp", [
      {
        id: "i1",
        parent_id: "a3",
        artifact_type: "ParsedRecord",
        metadata: {
          type: "InstalledApp",
          platform: "macOS",
          name: "Finder",
          package: "com.apple.finder",
          version: "11.1",
          build_version: "1350.2.10",
          installed_in: "system",
          bundle_path: "/System/Library/CoreServices/Finder.app",
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("InstalledApp");

    await waitFor(() => expect(screen.getByText("Finder")).toBeInTheDocument());
    expect(screen.getByText("com.apple.finder")).toBeInTheDocument();
    expect(screen.getByText("1350.2.10")).toBeInTheDocument();
    expect(screen.getByText("com.apple.finder")).toBeInTheDocument();
    expect(screen.getByText("1350.2.10")).toBeInTheDocument();
    expect(screen.getByText("system")).toBeInTheDocument();
  });

  it("flags the app whose code is in user data with no installer recorded", async () => {
    // The screen an examiner comes to this record class for. Android's
    // package manager records the installing package; on the graded device
    // exactly one of the 63 packages with its code in user data has none, and
    // it is a rooting tool. The row has to say that, and has to say it is a
    // signal rather than a proof.
    mock("InstalledApp", [
      {
        id: "a1",
        parent_id: "p1",
        artifact_type: "ParsedRecord",
        metadata: {
          type: "InstalledApp",
          platform: "Android",
          name: "com.topjohnwu.magisk",
          package: "com.topjohnwu.magisk",
          code_path: "/data/app/com.topjohnwu.magisk-1",
          code_partition: "data",
          install_source: "no_installer_recorded",
        },
      },
      {
        id: "a2",
        parent_id: "p1",
        artifact_type: "ParsedRecord",
        metadata: {
          type: "InstalledApp",
          platform: "Android",
          name: "com.discord",
          package: "com.discord",
          code_path: "/data/app/com.discord-1",
          code_partition: "data",
          install_source: "installer_recorded",
          installer_package: "com.android.vending",
        },
      },
      {
        id: "a3",
        parent_id: "p1",
        artifact_type: "ParsedRecord",
        metadata: {
          type: "InstalledApp",
          platform: "Android",
          name: "com.android.settings",
          package: "com.android.settings",
          code_path: "/system/priv-app/Settings",
          code_partition: "system",
          install_source: "shipped_with_the_os",
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("InstalledApp");

    await waitFor(() =>
      expect(screen.getByTitle(/signal a sideload leaves/i)).toBeInTheDocument(),
    );
    // And neither of the other two is flagged: a store install is ordinary,
    // and a system app has no installer because nothing installed it.
    expect(screen.getAllByTitle(/signal a sideload leaves/i)).toHaveLength(1);
    expect(screen.getAllByText("com.android.vending").length).toBeGreaterThan(0);
  });
});

describe("when a USB device was connected", () => {
  // ROADMAP §2.6 Q22 asks for both USB serials WITH a first and last
  // connection time. The parser decodes those times from the device-property
  // keys; the viewer showed friendly name, vendor, product, revision and
  // serial and no date at all, so the answer was on the record and on no
  // screen.
  const REAL_SANDISK = {
    id: "u1",
    parent_id: "a1",
    artifact_type: "ParsedRecord",
    metadata: {
      type: "UsbDevice",
      friendly_name: "SanDisk Extreme USB Device",
      vendor: "SanDisk",
      product: "Extreme",
      revision: "0001",
      serial: "AA010215170355310594&0",
      install_date: "2018-03-27T12:11:32.021203500+00:00",
      last_arrival_date: "2018-03-27T12:13:16.365329600+00:00",
      last_removal_date: "2018-03-27T09:22:13.088887100+00:00",
      time_contradictions: [
        "`last_removal_date` (2018-03-27T09:22:13.088887100+00:00) is earlier than `install_date` (2018-03-27T12:11:32.021203500+00:00): a device cannot have been removed before it was installed. Both values are read from this device's own property keys and both are reported as stored; this build does not choose between them.",
      ],
    },
  } as unknown as ParsedRecord;

  it("puts the connection times on the screen, not only on the record", async () => {
    mock("UsbDevice", [REAL_SANDISK]);
    renderViewer("UsbDevice");

    await waitFor(() =>
      expect(
        screen.getByText("SanDisk Extreme USB Device"),
      ).toBeInTheDocument(),
    );
    for (const header of ["First installed", "Last connected", "Last removed"]) {
      expect(
        screen.getByRole("columnheader", { name: new RegExp(header, "i") }),
      ).toBeInTheDocument();
    }
  });

  it("marks a device whose own property times contradict each other", async () => {
    mock("UsbDevice", [REAL_SANDISK]);
    renderViewer("UsbDevice");

    await waitFor(() =>
      expect(
        screen.getByText("SanDisk Extreme USB Device"),
      ).toBeInTheDocument(),
    );
    // The row carries a marker naming the disagreement. Printing "first
    // connected 12:11:32, last removed 09:22:13" with nothing said is worse
    // than either value alone: the reader takes the pair as one account.
    expect(
      screen.getByTitle(/earlier than .*install_date|removed before it was installed/i),
    ).toBeInTheDocument();
  });

  it("does not mark a device whose times agree", async () => {
    mock("UsbDevice", [
      {
        ...REAL_SANDISK,
        id: "u2",
        metadata: {
          ...(REAL_SANDISK as unknown as { metadata: object }).metadata,
          last_removal_date: null,
          time_contradictions: undefined,
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("UsbDevice");

    await waitFor(() =>
      expect(
        screen.getByText("SanDisk Extreme USB Device"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByTitle(/removed before it was installed/i),
    ).not.toBeInTheDocument();
  });
});

describe("the local accounts on a Windows machine", () => {
  // ROADMAP §2.6. Measured on the real SAM hive: Administrator RID 500, last
  // logon 2010-11-20T21:48:12.569244Z, 6 logons, disabled; Guest RID 501 with
  // no logon recorded at all.
  const ACCOUNTS = [
    {
      id: "a1",
      parent_id: "h1",
      artifact_type: "ParsedRecord",
      metadata: {
        type: "LocalAccount",
        username: "Administrator",
        rid: 500,
        last_logon: "2010-11-20T21:48:12.569244+00:00",
        last_password_set: "2010-11-20T21:56:34.743687+00:00",
        login_count: 6,
        account_enabled: false,
        comment: "Built-in account for administering the computer/domain",
        stored_password_hash_present: true,
      },
    },
    {
      id: "a2",
      parent_id: "h1",
      artifact_type: "ParsedRecord",
      metadata: {
        type: "LocalAccount",
        username: "Guest",
        rid: 501,
        last_logon: null,
        last_logon_absent_reason:
          "Not recorded: this field is zero in the account's F value, which is what Windows leaves when the account has never logged on.",
        login_count: 0,
        account_enabled: false,
        stored_password_hash_present: false,
      },
    },
  ] as unknown as ParsedRecord[];

  it("shows the RID and the times rather than a list of names", async () => {
    mock("LocalAccount", ACCOUNTS);
    renderViewer("LocalAccount");

    await waitFor(() =>
      expect(screen.getByText("Administrator")).toBeInTheDocument(),
    );
    expect(screen.getByText("500")).toBeInTheDocument();
    for (const header of ["Last logon", "Password set", "Logons"]) {
      expect(
        screen.getByRole("columnheader", { name: new RegExp(header, "i") }),
      ).toBeInTheDocument();
    }
    // Guest's last logon is not recorded, and the cell must not be a date.
    expect(screen.queryByText(/1601-01-01/)).not.toBeInTheDocument();
  });

  it("marks an account whose key was never read, and does not mark an ordinary one", async () => {
    mock("LocalAccount", [
      ...ACCOUNTS,
      {
        id: "a3",
        parent_id: "h1",
        artifact_type: "ParsedRecord",
        metadata: {
          type: "LocalAccount",
          username: "Preston",
          rid: 1000,
          account_key_note:
            "This account is in the SAM name index as \"Preston\" with RID 1000, and the walk reached no Users key holding its F and V values.",
          content_incomplete: true,
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("LocalAccount");

    await waitFor(() =>
      expect(screen.getByText("Preston")).toBeInTheDocument(),
    );
    expect(
      screen.getByTitle(/reached no Users key holding its F and V values/),
    ).toBeInTheDocument();
    // Two accounts were read completely and must carry no marker.
    expect(
      screen.queryAllByTitle(/reached no Users key/),
    ).toHaveLength(1);
  });
});

describe("when a device was installed, from the setupapi log", () => {
  const EVENT = {
    id: "d1",
    parent_id: "l1",
    artifact_type: "ParsedRecord",
    metadata: {
      type: "DeviceInstallEvent",
      name: "SWD\\WPDBUSENUM\\_??_USBSTOR#Disk&Ven_SanDisk&Prod_Extreme&Rev_0001#AA010603160707470215&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
      log_file: "setupapi.dev.log",
      section_kind: "Device Install (Hardware initiated)",
      device_instance_id:
        "SWD\\WPDBUSENUM\\_??_USBSTOR#Disk&Ven_SanDisk&Prod_Extreme&Rev_0001#AA010603160707470215&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
      device_action: "install",
      start_local: "2018/03/27 05:22:22.016",
      end_local: "2018/03/27 05:22:22.475",
      exit_status: "SUCCESS",
      section_closed: true,
      timeline_eligible: false,
    },
  } as unknown as ParsedRecord;

  it("shows the local times as written and never a converted one", async () => {
    mock("DeviceInstallEvent", [EVENT]);
    renderViewer("DeviceInstallEvent");

    await waitFor(() =>
      expect(screen.getByText("2018/03/27 05:22:22.016")).toBeInTheDocument(),
    );
    // The column heading says which kind of time this is, because no offset is
    // recorded anywhere in the log.
    expect(
      screen.getByRole("columnheader", { name: /Section start \(local\)/i }),
    ).toBeInTheDocument();
    // And no ISO-8601 rendering, which would imply a zone the log never stated.
    expect(screen.queryByText(/2018-03-27T/)).not.toBeInTheDocument();
  });

  it("marks a device that failed to start and a section the log never closed", async () => {
    mock("DeviceInstallEvent", [
      {
        ...EVENT,
        id: "d2",
        metadata: {
          ...(EVENT as unknown as { metadata: Record<string, unknown> })
            .metadata,
          warnings: [
            "dvi:                     Device not started: Device has problem: 0x0a (CM_PROB_FAILED_START), problem status: 0xc0000001.",
          ],
        },
      },
      {
        ...EVENT,
        id: "d3",
        metadata: {
          ...(EVENT as unknown as { metadata: Record<string, unknown> })
            .metadata,
          device_instance_id: "HID\\DELLABCE\\3&14ed0212&0&0000",
          end_local: null,
          exit_status: null,
          section_closed: false,
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("DeviceInstallEvent");

    await waitFor(() =>
      expect(
        screen.getByText("HID\\DELLABCE\\3&14ed0212&0&0000"),
      ).toBeInTheDocument(),
    );
    expect(screen.getByTitle(/CM_PROB_FAILED_START/)).toBeInTheDocument();
    expect(
      screen.getByTitle(/never closed this section/),
    ).toBeInTheDocument();
  });
});

describe("sticky notes, and the stamp every one of them carries", () => {
  // ROADMAP §2.6. No Sticky Notes evidence of either format exists on the
  // machine this parser was written on, so every record says so — and the
  // screen must show that, because it qualifies every other field on the row.
  const NOTE = {
    id: "n1",
    parent_id: "f1",
    artifact_type: "ParsedRecord",
    metadata: {
      type: "StickyNote",
      name: "Buy milk",
      text: "Buy milk\nCall Bob",
      source_file: "StickyNotes.snt",
      source_format: "snt_compound_file",
      storage_name: "note-0e1d9a4f-00000001",
      created: "2016-04-02T09:15:00+00:00",
      modified: "2016-04-02T09:20:00+00:00",
      validation_state: "never_validated_against_real_notes",
      validated_against_real_notes: false,
      validation_notice:
        "This record was produced by a Sticky Notes parser that has NEVER been run against a real Sticky Notes file of either format.",
    },
  } as unknown as ParsedRecord;

  it("shows the note and marks it as never validated", async () => {
    mock("StickyNote", [NOTE]);
    renderViewer("StickyNote");

    await waitFor(() =>
      expect(screen.getByText(/Buy milk/)).toBeInTheDocument(),
    );
    // The stamp is on the row, not only in the record.
    expect(
      screen.getByTitle(/NEVER been run against a real Sticky Notes file/),
    ).toBeInTheDocument();
  });

  it("marks a storage it could not read rather than leaving the row blank", async () => {
    mock("StickyNote", [
      {
        ...NOTE,
        id: "n2",
        metadata: {
          ...(NOTE as unknown as { metadata: Record<string, unknown> })
            .metadata,
          // A validated record, so the stamp does not mask the other marker.
          validated_against_real_notes: true,
          text: null,
          name: "Sticky note note-0e1d9a4f-00000002",
          unrecognised_structure: true,
          unrecognised_reason:
            "No stream in this storage opens with the RTF magic, so no text was extracted from it.",
          content_incomplete: true,
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("StickyNote");

    await waitFor(() =>
      expect(
        screen.getByText(/Sticky note note-0e1d9a4f-00000002/),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByTitle(/no text was extracted from it/),
    ).toBeInTheDocument();
  });

  it("shows a note recovered from the WAL with why it is called deleted", async () => {
    // HUNT-128 / PLUM-1: the app hard-deletes, so a deleted note is only ever
    // an older WAL image, and the row must say the deletion is inferred.
    mock("StickyNoteRecovered", [
      {
        id: "r1",
        parent_id: "f1",
        artifact_type: "ParsedRecord",
        metadata: {
          type: "StickyNoteRecovered",
          name: "DELETE-ME marker 7C3E91 temporary note to be removed",
          text: "DELETE-ME marker 7C3E91 temporary note to be removed",
          note_id: "1ab471ae-5463-4782-942d-a3ccd77d2f1a",
          source_file: "plum.sqlite",
          wal_frame: 58,
          validated_against_real_notes: true,
          deletion_basis:
            "Deletion is INFERRED, not recorded. A row with this Id is absent from the latest committed state of the database.",
        },
      },
    ] as unknown as ParsedRecord[]);
    renderViewer("StickyNoteRecovered");

    await waitFor(() =>
      expect(screen.getByText(/DELETE-ME marker 7C3E91/)).toBeInTheDocument(),
    );
    expect(screen.getByTitle(/Deletion is INFERRED/)).toBeInTheDocument();
  });
});
