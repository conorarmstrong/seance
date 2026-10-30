// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from "vitest";
import {
  contrastRatio,
  resolveColor,
  surfacesOf,
} from "../app/composedContrast";
import { allPalettes, paletteTokens } from "./palettes";
import { LANE_COLORS } from "./laneColors";

/**
 * The swimlane colours, measured (UI-015).
 *
 * Until this file existed they were the one part of the interface's colour that
 * no gate looked at, because they live in a TypeScript array rather than in a
 * stylesheet — and a guard that passes because it is not looking is the failure
 * this project keeps returning to.
 *
 * Two floors, and they are different from the text floors next door:
 *
 * 1. **Visibility.** A lane bar is a graphical object that carries meaning, so
 *    the floor is WCAG 2.1 SC 1.4.11 Non-text Contrast, 3:1 against the ground
 *    — not the 4.5:1 that applies to small text.
 * 2. **Separability.** The lanes must be tellable apart from one another, which
 *    contrast against a ground says nothing about. Measured as CIE76 ΔE in Lab,
 *    which is a perceptual distance rather than a luminance one.
 */

const NON_TEXT_CONTRAST = 3;
/**
 * Pairwise floor. Deliberately modest: twelve categories is more than any
 * qualitative palette keeps separable for every viewer, so the product does not
 * rely on colour alone — each lane is named beside its swatch. This asserts the
 * palette is a considered set rather than a random one, and catches the failure
 * that actually happened before it: two hues so close (ΔE 5.8) that two lanes
 * read as one.
 */
const MIN_DELTA_E = 15;

function channels(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255) as [
    number,
    number,
    number,
  ];
}

/** CIE L*a*b*, D65, via linear sRGB. */
function lab(hex: string): [number, number, number] {
  const [r, g, b] = channels(hex).map((v) =>
    v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4,
  );
  const x = (r * 0.4124 + g * 0.3576 + b * 0.1805) / 0.95047;
  const y = r * 0.2126 + g * 0.7152 + b * 0.0722;
  const z = (r * 0.0193 + g * 0.1192 + b * 0.9505) / 1.08883;
  const f = (t: number) => (t > 0.008856 ? Math.cbrt(t) : 7.787 * t + 16 / 116);
  const [fx, fy, fz] = [f(x), f(y), f(z)];
  return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
}

function deltaE(a: string, b: string): number {
  const [l1, a1, b1] = lab(a);
  const [l2, a2, b2] = lab(b);
  return Math.hypot(l1 - l2, a1 - a2, b1 - b2);
}

describe("swimlane lane colours", () => {
  it.each(allPalettes())(
    "keeps every lane visible against every surface of $label",
    ({ label, palette }) => {
      const mode = label.endsWith("/light") ? "light" : "dark";
      const map = paletteTokens(palette);
      const surfaces = surfacesOf(map);
      expect(surfaces.length, `${label} must declare its surfaces`).toBe(4);

      const failures: string[] = [];
      for (const [index, lane] of LANE_COLORS[mode].entries()) {
        for (const [name, surface] of surfaces) {
          const ratio = contrastRatio(
            lane,
            resolveColor(surface, map) as string,
          );
          if (ratio < NON_TEXT_CONTRAST) {
            failures.push(
              `${label} lane ${index} ${lane} on ${name} ${surface}: ${ratio.toFixed(2)}:1`,
            );
          }
        }
      }
      expect(failures).toEqual([]);
    },
  );

  it.each(["dark", "light"] as const)(
    "keeps the %s lanes tellable apart from one another",
    (mode) => {
      const palette = LANE_COLORS[mode];
      const tooClose: string[] = [];
      for (let i = 0; i < palette.length; i++) {
        for (let j = i + 1; j < palette.length; j++) {
          const d = deltaE(palette[i], palette[j]);
          if (d < MIN_DELTA_E) {
            tooClose.push(
              `${mode} lanes ${i} (${palette[i]}) and ${j} (${palette[j]}): ΔE ${d.toFixed(1)}`,
            );
          }
        }
      }
      expect(tooClose).toEqual([]);
    },
  );

  it("gives both modes the same lanes in the same order", () => {
    // A lane must keep its identity when the theme changes: an examiner
    // comparing two screenshots of one case must not be looking at two charts.
    // Only lightness moves between the modes, so lane n stays the same hue.
    expect(LANE_COLORS.light.length).toBe(LANE_COLORS.dark.length);
    const hueOf = (hex: string) => {
      const [r, g, b] = channels(hex);
      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      if (max - min < 0.02) return null; // neutral: no hue to compare
      let h: number;
      if (max === r) h = ((g - b) / (max - min)) % 6;
      else if (max === g) h = (b - r) / (max - min) + 2;
      else h = (r - g) / (max - min) + 4;
      return (((h * 60) % 360) + 360) % 360;
    };
    const drift: string[] = [];
    LANE_COLORS.dark.forEach((darkHex, i) => {
      const a = hueOf(darkHex);
      const b = hueOf(LANE_COLORS.light[i]);
      if (a == null || b == null) return;
      const d = Math.min(Math.abs(a - b), 360 - Math.abs(a - b));
      if (d > 20)
        drift.push(
          `lane ${i}: ${darkHex} vs ${LANE_COLORS.light[i]} — ${d.toFixed(0)}°`,
        );
    });
    expect(drift).toEqual([]);
  });
});
