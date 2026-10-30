// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from "vitest";
import { fitView, graphColors } from "./ForceGraph";

/**
 * UI-027. The force layout's equilibrium is set by its own constants, not by
 * the size of the panel: for a twelve-participant case the resting separation
 * is several times the frame's width. The positions used to be clamped into
 * the frame, which piles every node onto the border and destroys the structure
 * between them — the graph drew as a rectangle of dots with labels colliding in
 * one corner. The layout now runs unclamped and the drawing is fitted.
 */
const PAD = 45;

function corners(pos: { x: number; y: number }[], w: number, h: number) {
  const { s, tx, ty } = fitView(pos, w, h);
  return pos.map((p) => ({ x: p.x * s + tx, y: p.y * s + ty }));
}

describe("fitView", () => {
  it("brings a layout far wider than the panel inside it", () => {
    // What the simulation actually produces: a spread several times the frame.
    const pos = [
      { x: -1200, y: -800 },
      { x: 2400, y: 1900 },
      { x: 600, y: -200 },
      { x: -300, y: 1400 },
    ];
    const drawn = corners(pos, 1138, 620);
    for (const p of drawn) {
      expect(p.x).toBeGreaterThanOrEqual(PAD - 1);
      expect(p.x).toBeLessThanOrEqual(1138 - PAD + 1);
      expect(p.y).toBeGreaterThanOrEqual(PAD - 1);
      expect(p.y).toBeLessThanOrEqual(620 - PAD + 1);
    }
  });

  it("keeps the shape: one scale for both axes, so the graph is not stretched", () => {
    // Wide enough that the fit is a reduction rather than the 2.5x cap.
    const pos = [
      { x: 0, y: 0 },
      { x: 1000, y: 0 },
      { x: 0, y: 1000 },
    ];
    const { s } = fitView(pos, 1000, 400);
    const drawn = corners(pos, 1000, 400);
    // The two unit steps are the same length on screen.
    expect(drawn[1].x - drawn[0].x).toBeCloseTo(1000 * s, 6);
    expect(drawn[2].y - drawn[0].y).toBeCloseTo(1000 * s, 6);
    // And the shorter side is what binds, so nothing leaves the frame.
    expect(s).toBeCloseTo((400 - 2 * PAD) / 1000, 6);
  });

  it("does not magnify a tiny graph without limit", () => {
    // Two nodes a pixel apart would otherwise be blown up to fill the panel.
    const { s } = fitView(
      [
        { x: 0, y: 0 },
        { x: 1, y: 1 },
      ],
      1200,
      700,
    );
    expect(s).toBeLessThanOrEqual(2.5);
  });

  it("centres a single node rather than dividing by a zero span", () => {
    const drawn = corners([{ x: 42, y: -17 }], 800, 600);
    expect(Number.isFinite(drawn[0].x)).toBe(true);
    expect(Number.isFinite(drawn[0].y)).toBe(true);
    expect(drawn[0].x).toBeGreaterThan(0);
    expect(drawn[0].y).toBeGreaterThan(0);
  });

  it("is the identity-shaped answer for an empty graph", () => {
    expect(fitView([], 800, 600)).toEqual({ s: 1, tx: 0, ty: 0 });
  });
});

/**
 * The graph is drawn on a canvas, where the contrast guard cannot reach: it
 * measures token-valued `color:` declarations in stylesheets, and a canvas has
 * none. So the colours were literals picked for the palette the product shipped
 * with — near-white labels, a pale amber highlight — and on a light ground the
 * labels were white on white. The day the default became a light palette that
 * was every examiner's first look at the Connections screen; it had already
 * been true for anyone who chose a light skin.
 *
 * `graphColors` reads the palette's own tokens instead, so the graph follows
 * whatever is applied.
 */
describe("graphColors", () => {
  it("takes its ink from the applied palette, not from a literal", () => {
    const read = (name: string) =>
      ({
        "--text-0": "#16181d",
        "--text-2": "#545964",
        "--border-1": "#bcc3ce",
        "--accent": "#4e3ed4",
        "--info": "#1c599d",
        "--ok": "#1a6539",
        "--text-1": "#454a54",
      })[name] ?? "";
    const colors = graphColors(read);
    expect(colors.label).toBe("#16181d");
    expect(colors.labelQuiet).toBe("#545964");
    expect(colors.kind.self).toBe("#4e3ed4");
    expect(colors.kind.contact).toBe("#1c599d");
    expect(colors.kind.email).toBe("#1a6539");
    expect(colors.selected).toBe("#4e3ed4");
  });

  it("falls back to a readable ink when a token cannot be read", () => {
    // `getComputedStyle` returns an empty string for a property that is not
    // set — in a test renderer, or mid-swap. Drawing with "" paints nothing at
    // all, so the node simply vanishes; a fallback that is wrong-coloured is
    // better than one that is invisible.
    const colors = graphColors(() => "");
    expect(colors.label).not.toBe("");
    expect(colors.kind.self).not.toBe("");
    expect(colors.edge).not.toBe("");
  });
});
