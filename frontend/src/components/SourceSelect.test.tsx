import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { ArtifactListItem } from "../api/types";
import { SourceSelect } from "./SourceSelect";
import type { SourceFilter } from "../lib/useSourceFilter";

function source(
  id: string,
  name: string,
  metadata?: Record<string, unknown>,
): ArtifactListItem {
  return {
    id,
    parent_id: null,
    artifact_type: "RawEvidence",
    name,
    has_children: true,
    metadata,
  };
}

function filterOf(sourceItems: ArtifactListItem[]): SourceFilter {
  return {
    activeSource: undefined,
    sourceItems,
    multiSource: sourceItems.length > 1,
    sourceId: undefined,
    setSourceId: () => {},
  };
}

describe("choosing which acquisition to read", () => {
  it("tells two sources of the same name apart by where they came from", () => {
    // A macOS image ingested a subtree at a time gives three sources named
    // "Applications" and two named "CoreServices". Offered by name alone, an
    // examiner scoping to one of them is picking blind.
    render(
      <SourceSelect
        id="src"
        filter={filterOf([
          source("a", "Applications", { path: "/tree/Applications" }),
          source("b", "Applications", {
            path: "/tree/System/Applications",
          }),
        ])}
      />,
    );
    const options = screen.getAllByRole("option");
    const labels = options.map((o) => o.textContent);
    expect(labels).toContain("Applications — /tree/Applications");
    expect(labels).toContain("Applications — /tree/System/Applications");
  });

  it("leaves a name that is already unique alone", () => {
    render(
      <SourceSelect
        id="src"
        filter={filterOf([
          source("a", "LenovoFinal.E01", { path: "/evidence/LenovoFinal.E01" }),
          source("b", "memdump-001.mem", { path: "/evidence/memdump-001.mem" }),
        ])}
      />,
    );
    expect(
      screen.getByRole("option", { name: "LenovoFinal.E01" }),
    ).toBeInTheDocument();
  });

  it("still distinguishes sources whose paths are also identical", () => {
    // Ingesting the same folder twice — after an interrupted run, say — leaves
    // two sources alike in every visible way. They are still two, and the
    // examiner has to be able to pick one.
    render(
      <SourceSelect
        id="src"
        filter={filterOf([
          source("aaaa1111-0000-0000-0000-000000000000", "CoreServices", {
            path: "/tree/System/Library/CoreServices",
          }),
          source("bbbb2222-0000-0000-0000-000000000000", "CoreServices", {
            path: "/tree/System/Library/CoreServices",
          }),
        ])}
      />,
    );
    const labels = screen.getAllByRole("option").map((o) => o.textContent);
    expect(labels.some((l) => l?.includes("aaaa1111"))).toBe(true);
    expect(labels.some((l) => l?.includes("bbbb2222"))).toBe(true);
  });
});
