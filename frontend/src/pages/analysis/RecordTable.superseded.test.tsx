import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { ParsedRecord } from "./api";
import { RecordTable } from "./RecordTable";

const CASE_ID = "case-1";

function rows(records: ParsedRecord[]) {
  render(
    <MemoryRouter>
      <RecordTable
        records={records}
        caseId={CASE_ID}
        columns={[
          {
            key: "subject",
            header: "Subject",
            render: (meta) => String(meta.subject ?? ""),
          },
        ]}
      />
    </MemoryRouter>,
  );
}

describe("a record a later run answered", () => {
  it("is marked as superseded rather than shown as a second answer", () => {
    // HUNT-107. Re-running a parser leaves the earlier run's records in the
    // case — they are evidence that the first run said what it said. Shown in
    // the same table with nothing distinguishing them, an examiner counts both.
    rows([
      {
        id: "a",
        metadata: {
          type: "EmailMessage",
          subject: "read by the old parser",
          superseded: true,
          superseded_reason:
            "plugin.email.parser was run again on this artifact",
        },
      },
      {
        id: "b",
        metadata: { type: "EmailMessage", subject: "read by the fixed parser" },
      },
    ] as unknown as ParsedRecord[]);

    const badges = screen.getAllByText("superseded");
    expect(badges).toHaveLength(1);
    expect(badges[0]).toHaveAttribute(
      "title",
      "plugin.email.parser was run again on this artifact",
    );
    expect(screen.getByText("read by the fixed parser")).toBeInTheDocument();
  });

  it("adds no column to a table where nothing was superseded", () => {
    rows([
      {
        id: "b",
        metadata: { type: "EmailMessage", subject: "the only parse" },
      },
    ] as unknown as ParsedRecord[]);

    expect(screen.queryByText("Status")).not.toBeInTheDocument();
    expect(screen.queryByText("superseded")).not.toBeInTheDocument();
  });
});
