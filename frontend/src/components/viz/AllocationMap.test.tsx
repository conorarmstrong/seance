import { render, screen } from "@testing-library/react";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { AllocationMap } from "./AllocationMap";

const ctx = {
  scale: vi.fn(),
  clearRect: vi.fn(),
  fillRect: vi.fn(),
  fillStyle: "",
};

beforeAll(() => {
  HTMLCanvasElement.prototype.getContext = vi.fn(
    () => ctx,
  ) as unknown as typeof HTMLCanvasElement.prototype.getContext;
});

describe("AllocationMap", () => {
  it("decodes the bitmap and paints one cell per bucket", () => {
    ctx.fillRect.mockClear();
    render(
      <AllocationMap
        data={{
          allocation_bitmap_b64: "AECA/w==", // 4 buckets: 0, 64, 128, 255
          allocation_clusters_per_bucket: 8,
          allocation_total_clusters: 32,
          allocation_cluster_size: 512,
        }}
      />,
    );

    expect(
      screen.getByRole("img", { name: "Cluster allocation map" }),
    ).toBeInTheDocument();
    expect(ctx.fillRect).toHaveBeenCalledTimes(4);

    // Legend: 8 clusters x 512 bytes = 4.0 KiB per cell
    expect(screen.getByText(/each cell ≈ 4\.0 KiB/)).toBeInTheDocument();
    expect(screen.getByText("free")).toBeInTheDocument();
    expect(screen.getByText("allocated")).toBeInTheDocument();
  });

  it("shows an empty note for an empty or invalid bitmap", () => {
    render(
      <AllocationMap
        data={{
          allocation_bitmap_b64: "",
          allocation_clusters_per_bucket: 8,
          allocation_total_clusters: 0,
          allocation_cluster_size: 512,
        }}
      />,
    );
    expect(screen.getByText("No allocation data.")).toBeInTheDocument();
  });
});
