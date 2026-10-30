// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AA_SMALL_TEXT,
  contrastRatio,
  paletteFailures,
  resolveColor,
  srcRoot,
  stripComments,
  stylesheets,
  surfacesOf,
  tokens,
} from "../app/composedContrast";
import { allPalettes, paletteTokens, SKINS, SKIN_IDS } from "./palettes";
import type { Palette } from "./palettes";

/**
 * Every skin is held to the same floor as the default palette.
 *
 * `src/app/contrast.test.ts` measures the tokens in `index.css`. That is one
 * palette out of the set an examiner can actually be looking at, and a skin
 * whose ink drifts under WCAG AA is the same defect on the same screens — a
 * fatigue tax on people who read this product for eight hours, and a barrier
 * for low-vision examiners. A dozen unmeasured palettes would also be the
 * failure mode this project keeps returning to: a guard that passes because it
 * was not looking.
 *
 * So the instrument is shared rather than copied. `paletteFailures` is the same
 * sweep the default guard runs — every token-valued `color:` in every
 * stylesheet under `src/`, against every ground it can meet, with translucent
 * fills composited onto each surface and `opacity` accounted for — and it is
 * simply handed a different token map per skin.
 */
describe("skin contrast", () => {
  it("sweeps every palette in the product, and finds enough to be meaningful", () => {
    // A guard that silently found nothing to check would pass forever. Both
    // halves are asserted: that every palette is reached, and that each one
    // presents the sweep with the four surfaces it needs.
    const palettes = allPalettes();
    expect(palettes.map((p) => p.label).sort()).toEqual([
      "candle/dark",
      "candle/light",
      "cyber/dark",
      "cyber/light",
      "nature/dark",
      "nature/light",
      "opus/dark",
      "opus/light",
      "relax/dark",
      "relax/light",
      "win11/dark",
      "win11/light",
    ]);
    for (const { label, palette } of palettes) {
      expect(
        surfacesOf(paletteTokens(palette)).length,
        `${label} must declare the four surfaces text can land on`,
      ).toBe(4);
    }
  });

  it.each(allPalettes())(
    "holds $label to WCAG AA on every ground its text can meet",
    ({ palette }) => {
      // No allowance and no ledger of accepted exceptions, exactly as for the
      // default palette: a pairing the instrument can measure is either over
      // the floor or is a bug to fix before merge. The message names the file,
      // the line, both colours and the ratio.
      expect(paletteFailures(paletteTokens(palette))).toEqual([]);
    },
  );

  it.each(allPalettes())(
    "keeps $label’s three text tones a visible ladder",
    ({ palette }) => {
      const map = paletteTokens(palette);
      const bg = resolveColor(map.get("--bg-0") as string, map) as string;
      const ladder = ["--text-0", "--text-1", "--text-2"].map((t) =>
        contrastRatio(resolveColor(map.get(t) as string, map) as string, bg),
      );
      // Strictly descending. A contrast fix that flattens the hierarchy makes
      // every screen shout, which is its own readability failure — the same
      // assertion the default palette carries.
      expect(ladder[0]).toBeGreaterThan(ladder[1]);
      expect(ladder[1]).toBeGreaterThan(ladder[2]);
    },
  );

  it.each(allPalettes())(
    "draws $label’s selection ink legibly on its own selection fill",
    ({ palette }) => {
      // `--accent-dim` is a fill and a border, never text, and `--text-0` is
      // drawn on it by `::selection` and by every selected row. The guard
      // measures rules that state both; this states the pairing directly so a
      // palette cannot pass by never having been asked.
      const map = paletteTokens(palette);
      const ink = resolveColor(map.get("--text-0") as string, map) as string;
      const fill = resolveColor(
        map.get("--accent-dim") as string,
        map,
      ) as string;
      expect(contrastRatio(ink, fill)).toBeGreaterThanOrEqual(AA_SMALL_TEXT);
    },
  );

  it.each(allPalettes())(
    "draws $label’s inverted text legibly on its accent fill",
    ({ palette }) => {
      // Two rules paint `color: var(--bg-0)` over `background: var(--accent)`
      // — the evidence tree's RAM tag on hover, and the active text match in
      // the artifact viewer. Both are the accent used as a fill with the page
      // surface as ink, which is the one pairing that inverts when a palette
      // does.
      const map = paletteTokens(palette);
      const ink = resolveColor(map.get("--bg-0") as string, map) as string;
      const fill = resolveColor(map.get("--accent") as string, map) as string;
      expect(contrastRatio(ink, fill)).toBeGreaterThanOrEqual(AA_SMALL_TEXT);
    },
  );

  it("gives every skin both modes, and the right color-scheme in each", () => {
    // `color-scheme` is what makes the browser draw form controls, scrollbars
    // and the canvas behind the app to match. A palette that named the wrong
    // one would look right until the first `<select>` opened.
    for (const id of SKIN_IDS) {
      expect(SKINS[id].light["color-scheme"], `${id} light`).toBe("light");
      expect(SKINS[id].dark["color-scheme"], `${id} dark`).toBe("dark");
    }
  });

  it("declares in every palette exactly the tokens index.css declares", () => {
    // The skins are interchangeable at runtime, so a token one palette sets and
    // another does not would leave the previous skin's value in place when the
    // examiner switched — a colour from a theme they are no longer using, on a
    // screen that gets screenshotted into a witness statement. And a token in a
    // palette that `index.css` does not declare has no fallback at all before
    // the first paint.
    //
    // `index.css` carries more than the palette (`--font-ui` and the radii sit
    // beside layout tokens), so the assertion is one-directional in the strict
    // sense the risk is: every palette declares the same set as every other,
    // and every one of those names exists in `index.css`.
    const base = tokens();
    const names = (palette: Palette) => Object.keys(palette).sort().join(",");
    const reference = names(SKINS.opus.dark);

    for (const { label, palette } of allPalettes()) {
      expect(names(palette), `${label} declares a different token set`).toBe(
        reference,
      );
      for (const key of Object.keys(palette)) {
        // `color-scheme` is a real CSS property, not a custom one: it is set on
        // the element rather than declared as `--color-scheme`, so it has no
        // counterpart in `index.css` to look for.
        if (key === "color-scheme") continue;
        expect(
          base.has(`--${key}`),
          `${label} sets --${key}, which index.css does not declare, so there ` +
            `is no value for it before a skin is applied`,
        ).toBe(true);
      }
    }
  });

  it("declares no colour literal that a theme should have decided", () => {
    // The contrast gate proves LEGIBILITY. It does not prove that a colour
    // belongs to the theme, and it cannot: a literal that happens to clear the
    // floor under every palette still shows the wrong theme's colour, and
    // a literal `color:` is not measured at all — the sweep reads only
    // token-valued declarations.
    //
    // That gap is not hypothetical. Adding a second palette exposed five rules
    // painting a hardcoded near-black on the accent (UI-011) and nine painting
    // a frozen copy of the default palette's own tint (UI-012). Two of the nine
    // cleared the floor and would have shipped: legible, and the wrong colour.
    //
    // So the class is caught rather than the instances. A colour written as a
    // literal in a stylesheet is either an entry below, with a reason, or a bug.
    const ALLOWED: Record<string, string> = {
      // Ink on a dark scrim laid over a PHOTOGRAPH or a video frame. The ground
      // is the image, not a theme surface, so there is no token that could be
      // right and white is right under every skin.
      "#fff": "white on a scrim over media, whose ground is the image",
      "#ffffff": "as #fff",
      "#000": "a media letterbox, which is black under every theme",
      "#000000": "as #000",
      "#111": "ink on a light media chip; see #fff",
      "#333": "ink on a light media chip; see #fff",
      // Reproduced third-party chat colours. These pixels are EVIDENCE of what
      // the device showed, and recolouring them would show the examiner a
      // rendering no participant ever saw. Recorded as a decision in BUGS.md
      // under "Weighed and deliberately not closed", with its worst measured
      // pair, and exempt from the contrast floor for the same reason.
      "#0b93f6":
        "reproduced iMessage blue — evidence of what the device showed",
      "#2c6bed": "reproduced Signal blue — as above",
      "#056162": "reproduced WhatsApp green — as above",
      "#005c4b": "reproduced WhatsApp green — as above",
      "#202c33": "reproduced WhatsApp ground — as above",
      "#1f2c34": "reproduced WhatsApp ground — as above",
      "#e7ffdb": "reproduced WhatsApp ink — as above",
      "#f6c344":
        "the star over a THUMBNAIL: on the image, not on a surface, and it carries its own shadow",
      // A modal backdrop. It dims whatever is behind the dialog, which is the
      // page rather than a surface, and it dims it in both modes — a scrim that
      // lightened under a light theme would stop separating the dialog from
      // what it covers.
      "rgba(6, 8, 11, 0.55)":
        "the command palette backdrop: a scrim over the page, dark under every theme",
    };

    // Rules that REPRODUCE a third-party chat surface are exempt as a class,
    // by selector rather than by listing each brand's hex. Those pixels are
    // evidence of what the device showed, and recolouring them would show the
    // examiner a rendering no participant ever saw — the decision is recorded
    // in BUGS.md under "Weighed and deliberately not closed", where it is also
    // exempt from the contrast floor for the same reason. Listing hexes would
    // mean editing this test for every messenger added; naming the namespace
    // means the exemption cannot spread beyond it, which is asserted below.
    const REPRODUCED = ".an-theme-";

    const offenders: string[] = [];
    const exempted: string[] = [];
    for (const file of stylesheets()) {
      const name = relative(srcRoot, file);
      // `index.css` is where the default palette is DEFINED. Literals are the
      // point there, and every one of them is a token the skins override.
      if (name === "index.css") continue;
      const css = stripComments(readFileSync(file, "utf8"));
      let selector = "";
      for (const [line, text] of css.split("\n").entries()) {
        // Track the selector this declaration belongs to, so the exemption can
        // be a property of the rule rather than of the colour.
        if (text.includes("{")) selector = text.slice(0, text.indexOf("{"));
        else if (text.includes("}")) selector = "";
        else if (!text.includes(":") && text.trim())
          selector += ` ${text.trim()}`;

        // Custom properties are read too, and that is not thoroughness for its
        // own sake: `--viz-alloc-lo: #202630` passed this lint when it matched
        // only `color` and friends, and a heatmap read INVERTED under every
        // light skin because of it. A literal hiding behind a token name is
        // still a literal.
        const match = text.match(
          /^\s*(?:--[\w-]+|color|background|background-color|border-color|border-left-color|fill|stroke)\s*:\s*([^;]+)/,
        );
        if (!match) continue;
        const value = match[1].trim().toLowerCase();
        // Anything built from a token, or from a keyword, is fine.
        if (value.includes("var(--") || value.includes("color-mix(")) continue;
        const literal = value.match(/#[0-9a-f]{3,8}|rgba?\([^)]*\)/);
        if (!literal) continue;
        // Black and white at an alpha are scrims and overlays: a translucent
        // veil over whatever is behind it, not a themed surface.
        if (/^rgba\(\s*(0,\s*0,\s*0|255,\s*255,\s*255)\s*,/.test(literal[0]))
          continue;
        const where = `${name}:${line + 1}: ${text.trim()}`;
        if (selector.includes(REPRODUCED)) {
          exempted.push(where);
          continue;
        }
        if (ALLOWED[literal[0]]) continue;
        offenders.push(where);
      }
    }

    // The exemption exists and is confined. Both halves matter: an empty list
    // would mean the branch never runs and the guard passes by not looking, and
    // an exemption reaching beyond the messaging viewer would be the reproduced
    // -evidence argument being borrowed by something it does not cover.
    expect(exempted.length).toBeGreaterThan(10);
    expect(
      [...new Set(exempted.map((e) => e.slice(0, e.indexOf(":"))))].sort(),
    ).toEqual(["pages/analysis/analysis.css"]);

    expect(offenders.sort()).toEqual([]);
  });
});
