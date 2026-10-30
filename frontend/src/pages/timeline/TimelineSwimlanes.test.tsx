import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TimelineSwimlanes } from "./TimelineSwimlanes";
import { DEFAULT_MODE } from "../../themes/palettes";
import { LANE_COLORS } from "../../themes/laneColors";
import type { TimelineSwimlanes as SwimlanesData } from "./api";

const noop = () => {};

/** jsdom reports an inline colour back as `rgb(r, g, b)`. */
function hexToRgb(hex: string): string {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
  return `rgb(${r}, ${g}, ${b})`;
}

/** jsdom reports zero-size rects; give the brush surface a real geometry. */
function mockPlotRect(plot: HTMLElement, width: number) {
  plot.getBoundingClientRect = () =>
    ({
      left: 0,
      top: 0,
      width,
      height: 60,
      right: width,
      bottom: 60,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    }) as DOMRect;
}

describe("TimelineSwimlanes", () => {
  it("renders one lane per source with totals and density cells", () => {
    const data: SwimlanesData = {
      min_ts: 1000,
      max_ts: 2000,
      bucket_seconds: 100,
      lanes: [
        {
          source: "mft",
          total: 42,
          buckets: [
            { start: 1000, count: 20 },
            { start: 1500, count: 22 },
          ],
        },
        { source: "evtx", total: 10, buckets: [{ start: 1200, count: 10 }] },
      ],
      truncated_lanes: false,
    };
    render(
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    expect(screen.getByText("mft")).toBeInTheDocument();
    expect(screen.getByText("evtx")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    // one <rect> per (lane, bucket) cell
    expect(document.querySelectorAll("rect").length).toBe(3);
  });

  it("shows an empty state when there are no lanes", () => {
    const data: SwimlanesData = {
      min_ts: null,
      max_ts: null,
      bucket_seconds: null,
      lanes: [],
      truncated_lanes: false,
    };
    render(
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    expect(screen.getByText(/No source activity/)).toBeInTheDocument();
  });

  it("says the request failed instead of rendering nothing", () => {
    // This used to assert `container.firstChild` was null. A blank panel where
    // the lanes go is what a capture with no active source looks like, so the
    // failure was indistinguishable from a finding about the evidence — and
    // the sibling "No source activity for the current filters" copy right
    // below is exactly the sentence it must not be mistaken for.
    render(
      <TimelineSwimlanes
        data={undefined}
        isError={true}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    const note = screen.getByTestId("tl-swimlanes-error");
    expect(note.textContent).toMatch(/could not be loaded/i);
    expect(screen.queryByText(/No source activity/)).toBeNull();
  });

  it("subscribes the drag handlers once per drag, not once per mouse move", () => {
    // Same defect as the histogram's brush: a dependency-free effect, and an
    // `onMove` that sets state per pixel, so all three window listeners were
    // replaced on every mousemove for the whole drag.
    const data: SwimlanesData = {
      min_ts: 1000,
      max_ts: 2000,
      bucket_seconds: 100,
      lanes: [
        { source: "mft", total: 5, buckets: [{ start: 1000, count: 5 }] },
      ],
      truncated_lanes: false,
    };
    const { container } = render(
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    const capture = container.querySelector(".tl-sw-capture") as HTMLElement;
    mockPlotRect(capture, 400);
    const addListener = vi.spyOn(window, "addEventListener");

    fireEvent.mouseDown(capture, { clientX: 40, button: 0 });
    for (const clientX of [80, 120, 160, 200, 240]) {
      fireEvent.mouseMove(window, { clientX });
    }

    const subscriptions = addListener.mock.calls.filter(
      ([type]) => type === "mousemove",
    );
    expect(subscriptions).toHaveLength(1);

    fireEvent.mouseUp(window, { clientX: 240 });
    addListener.mockRestore();
  });

  it("brushes the domain on screen when the mouse is released, not the one it went down on", () => {
    // The handlers are attached once per drag, so they must read the time
    // domain live: a refetch landing mid-drag moves the lanes, and the released
    // range has to name the window actually under the pointer.
    const onBrush = vi.fn();
    const lanes = [
      { source: "mft", total: 5, buckets: [{ start: 1000, count: 5 }] },
    ];
    const first: SwimlanesData = {
      min_ts: 1000,
      max_ts: 2000,
      bucket_seconds: 100,
      lanes,
      truncated_lanes: false,
    };
    const second: SwimlanesData = {
      min_ts: 5000,
      max_ts: 6000,
      bucket_seconds: 100,
      lanes: [
        { source: "mft", total: 2, buckets: [{ start: 5000, count: 2 }] },
      ],
      truncated_lanes: false,
    };
    const chart = (data: SwimlanesData) => (
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={onBrush}
        onClearRange={noop}
      />
    );
    const { container, rerender } = render(chart(first));
    const capture = container.querySelector(".tl-sw-capture") as HTMLElement;
    mockPlotRect(capture, 400);

    fireEvent.mouseDown(capture, { clientX: 100, button: 0 });
    rerender(chart(second));
    fireEvent.mouseUp(window, { clientX: 300 });

    // 25%..75% of the domain now drawn (5000..6000).
    expect(onBrush).toHaveBeenCalledWith(5250, 5750);
  });
});

describe("a server-focused response (UI-010)", () => {
  const focused: SwimlanesData = {
    min_ts: 315_532_800,
    max_ts: 1_700_006_400,
    bucket_seconds: 3600,
    lanes: [
      {
        source: "mft",
        total: 100,
        buckets: [
          { start: 1_700_000_000, count: 40 },
          { start: 1_700_003_600, count: 60 },
        ],
      },
    ],
    truncated_lanes: false,
    focus: {
      from: 1_700_000_000,
      to: 1_700_007_200,
      events_before: 3,
      events_after: 0,
    },
  };

  it("draws the lanes against the focused window, not the whole extent", () => {
    const { container } = render(
      <TimelineSwimlanes
        data={focused}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    // Against the four-decade extent every cell would be a sliver at the right
    // edge; against the two-hour window they fill the lane. The first cell
    // starts at the very left of the drawn domain.
    const cells = container.querySelectorAll(".tl-sw-strip rect");
    expect(cells.length).toBe(2);
    expect(cells[0].getAttribute("x")).toBe("0");
    // One hour of a two-hour window is half a 1000-unit viewBox. Against the
    // four-decade extent the same bar would be about 0.008 units wide.
    expect(Number(cells[0].getAttribute("width"))).toBeCloseTo(500, 0);
  });

  it("states what fell outside the window and where the case really starts", () => {
    render(
      <TimelineSwimlanes
        data={focused}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    const note = screen.getByTestId("tl-swimlanes-focus");
    expect(note.textContent).toMatch(/3 events outside the drawn range/);
    expect(note.textContent).toMatch(/1980/);
  });
});

describe("lane colours follow the mode (UI-015)", () => {
  const data: SwimlanesData = {
    min_ts: 1000,
    max_ts: 2000,
    bucket_seconds: 100,
    lanes: [{ source: "mft", total: 5, buckets: [{ start: 1000, count: 5 }] }],
    truncated_lanes: false,
  };

  afterEach(() => {
    delete document.documentElement.dataset.mode;
  });

  it("draws the light-mode lane colours when the light mode is applied", () => {
    // The colours chosen to glow on near-black sit at about 2:1 on near-white,
    // under the 3:1 floor a graphical object has to clear. `applyTheme` stamps
    // the mode on the root element, and the chart reads it from there so it
    // works with or without a provider around it.
    document.documentElement.dataset.mode = "light";
    const { container } = render(
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    const swatch = container.querySelector(".tl-sw-swatch") as HTMLElement;
    expect(swatch.style.background).toBe(hexToRgb(LANE_COLORS.light[0]));
  });

  it("draws the dark-mode lane colours when the dark mode is applied", () => {
    document.documentElement.dataset.mode = "dark";
    const { container } = render(
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    const swatch = container.querySelector(".tl-sw-swatch") as HTMLElement;
    expect(swatch.style.background).toBe(hexToRgb(LANE_COLORS.dark[0]));
  });

  it("draws the shipped default\u2019s lane colours when nothing is applied", () => {
    // Nothing stamped means nobody has chosen, which is the build's default
    // palette — not "dark" from a literal. That literal was right while the
    // default was dark and would have drawn the dark lane colours on a white
    // ground the day it moved, at about 2:1 where 3:1 is the floor for a
    // graphical object.
    const { container } = render(
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    const swatch = container.querySelector(".tl-sw-swatch") as HTMLElement;
    expect(swatch.style.background).toBe(
      hexToRgb(LANE_COLORS[DEFAULT_MODE][0]),
    );
  });

  it("says that a lane colour belongs to the view rather than to the evidence", () => {
    render(
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    const note = screen.getByTestId("tl-swimlanes-colour-note");
    expect(note.textContent).toMatch(/follow the theme/);
    expect(note.textContent).toMatch(/named beside its swatch/);
  });
});

describe("the bucket that holds the first event", () => {
  // UI-027, the swimlane half. The server aligns bucket starts to absolute
  // multiples of the bucket width, so the bucket containing the first event
  // starts before it. Drawing the lanes against the event's timestamp put that
  // bucket at a negative x — off the left edge of the SVG, invisible, with
  // nothing on screen saying the earliest activity in the case was not drawn.
  it("is drawn inside the lane, not clipped off its left edge", () => {
    const data: SwimlanesData = {
      min_ts: 1216691467,
      max_ts: 1216692000,
      bucket_seconds: 300,
      lanes: [
        {
          source: "pcap",
          total: 300,
          buckets: [
            { start: 1216691400, count: 288 },
            { start: 1216691700, count: 12 },
          ],
        },
      ],
      truncated_lanes: false,
    };
    const { container } = render(
      <TimelineSwimlanes
        data={data}
        isError={false}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    );
    const xs = Array.from(container.querySelectorAll("rect")).map((r) =>
      Number(r.getAttribute("x")),
    );
    expect(xs.length).toBeGreaterThan(0);
    expect(Math.min(...xs)).toBeGreaterThanOrEqual(0);
  });
});
