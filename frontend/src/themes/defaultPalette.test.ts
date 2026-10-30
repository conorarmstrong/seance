// Runs in the plain node environment: this file reads a stylesheet, not a DOM.
// @vitest-environment node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { paletteTokens, SKINS } from "./palettes";

/**
 * The palette `index.css` declares and the palette `applyTheme(null)` clears
 * back to must be the same thing.
 *
 * `applyTheme` clears the custom properties rather than writing values, so "I
 * never chose a theme" lands on whatever `index.css` says. The shipped default
 * is `SKINS.opus.light`, and that value is written out in CSS as well —
 * because CSS is what paints before any script runs, and a default that lived
 * only in JavaScript would show one palette for a frame and then swap.
 *
 * Two copies of one palette is a drift waiting to happen, so the drift is what
 * this test forbids: change one and the build tells you about the other.
 */
describe("the shipped default palette", () => {
  const css = readFileSync(resolve(process.cwd(), "src/index.css"), "utf8");
  /** `--token: value;` pairs from the `:root` block, comments stripped. */
  const declared = new Map<string, string>();
  const root = css.slice(css.indexOf(":root {"), css.indexOf("\n}"));
  for (const [, name, value] of root
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .matchAll(/--([\w-]+)\s*:\s*([^;]+);/g)) {
    declared.set(`--${name}`, value.trim());
  }

  /** Quote style is the formatter's business, not the palette's: a font stack
   *  written with single quotes is the same stack as one with double. */
  const same = (value: string) => value.toLowerCase().replace(/["']/g, "'");

  it("is Opus light, token for token", () => {
    const palette = paletteTokens(SKINS.opus.light);
    for (const [name, value] of palette) {
      if (name === "--color-scheme") continue;
      expect(
        same(declared.get(name) ?? ""),
        `--${name} in index.css must match SKINS.opus.light`,
      ).toBe(same(value));
    }
  });

  it("declares every token a skin declares, and no others", () => {
    const expected = [...paletteTokens(SKINS.opus.light).keys()]
      .filter((name) => name !== "--color-scheme")
      .sort();
    expect([...declared.keys()].sort()).toEqual(expected);
  });

  it("says it is a light scheme, so the browser paints its own chrome to match", () => {
    expect(root).toMatch(/color-scheme:\s*light/);
  });
});
