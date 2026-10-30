import { useThemeVersion } from "./useThemeVersion";
import { DEFAULT_MODE, type Mode } from "./palettes";

/**
 * The categorical colours the timeline swimlanes give their lanes, one set per
 * mode (UI-015).
 *
 * # Why two sets rather than one
 *
 * A categorical palette is not a point on a ramp between two tokens, so unlike
 * every other colour in the product (UI-011–UI-014) these cannot be derived
 * from the theme. Twelve hues have to be distinguishable *from each other* and
 * visible *against the ground*, and the second constraint changes completely
 * between a near-black surface and a near-white one. One set tuned to glow on
 * dark sat heavy and foreign on the light skins.
 *
 * # Where the hues come from
 *
 * Not invented here. The twelve are Okabe and Ito's colour-universal set (2008)
 * followed by Paul Tol's muted qualitative scheme — both designed so that the
 * members stay distinguishable under the common colour-vision deficiencies.
 * Each hue is then moved along its own lightness axis, and no further than it
 * has to be, until it clears **3:1 against every surface of that mode** across
 * every skin. That floor is WCAG 2.1's 1.4.11 Non-text Contrast, which is
 * the right one here: a lane bar is a graphical object carrying meaning, not
 * text. `laneColors.contrast.test.ts` measures both sets and fails on a
 * regression rather than trusting this comment.
 *
 * # What a lane's colour does and does not mean
 *
 * The two sets are the same hues in the same order, so lane *n* keeps its hue
 * identity when the theme changes; only its lightness moves. That matters
 * because an examiner comparing two screenshots of one case must not see two
 * different charts. It is still true that a lane's colour is a property of the
 * VIEW and not of the evidence, which is why the swimlanes say so beneath the
 * chart and why every lane is named beside its swatch: colour is a second way
 * to tell the lanes apart here, never the only one (WCAG 1.4.1).
 *
 * Twelve categories is more than any qualitative palette can keep separable for
 * every viewer — under simulated dichromacy some pairs in any twelve-colour set
 * draw close — which is exactly why the label carries the meaning and the
 * colour supports it.
 */
export const LANE_COLORS: Record<Mode, readonly string[]> = {
  // Okabe–Ito orange, sky blue, bluish green, blue, vermillion, reddish purple;
  // then Tol muted indigo, teal, olive, wine, purple, grey.
  dark: [
    "#e69f00",
    "#56b4e9",
    "#009e73",
    "#0089d6",
    "#d85f00",
    "#cc79a7",
    "#8574dc",
    "#44aa99",
    "#999933",
    "#d45595",
    "#c061b0",
    "#9aa3b2",
  ],
  light: [
    "#9c6c00",
    "#0f7fa9",
    "#008762",
    "#0058a8",
    "#c15500",
    "#bc4f8b",
    "#3f2a9e",
    "#2f7a6c",
    "#6f7527",
    "#8a1f52",
    "#a4409a",
    "#6b7280",
  ],
} as const;

/**
 * The applied mode, read from the document rather than from a context.
 *
 * `applyTheme` stamps `data-mode` on the root element, so this works in a tree
 * with no provider — a component that cannot render outside a provider turns a
 * display preference into a hard dependency (see `useThemeVersion`).
 *
 * Nothing stamped means nothing was applied, which is the shipped default:
 * [`DEFAULT_MODE`], not a literal. Answering "dark" there was right while the
 * default was dark, and would have drawn the dark lane palette on a white
 * ground the day it moved.
 */
export function appliedMode(): Mode {
  if (typeof document === "undefined") return DEFAULT_MODE;
  const stamped = document.documentElement.dataset.mode;
  return stamped === "light" || stamped === "dark" ? stamped : DEFAULT_MODE;
}

export function useLaneColors(): readonly string[] {
  // Re-read on every theme change: the value below is plain DOM state, so
  // nothing would re-render this component without it.
  useThemeVersion();
  return LANE_COLORS[appliedMode()];
}
