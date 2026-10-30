/**
 * Séance's skins: five looks, each in a light and a dark mode.
 *
 * # Why this is data and not ten stylesheets
 *
 * The contrast guard (`src/app/contrast.test.ts`) reads `index.css`, resolves
 * every `var(--token)` in every stylesheet under `src/`, and holds the result
 * to WCAG AA. Written as ten `@media`-guarded blocks of CSS, nine of these
 * palettes would be invisible to it — the guard's token reader keeps one value
 * per name — and all but one of the palettes an examiner can actually select would
 * ship unmeasured. Colour in this product is gated, not reviewed by eye, and a
 * skin is not an exception to that.
 *
 * As data, each palette is a token map the same instrument can measure:
 * `themes.contrast.test.ts` runs `paletteFailures` over all ten, so a skin
 * whose ink drifts under the floor on one surface fails the build like any
 * other contrast regression.
 *
 * # What a palette may and may not change
 *
 * A palette supplies **values**, never names. Every one declares the same token
 * set, which is what makes them interchangeable at runtime and measurable by
 * one guard. A skin that wanted a token of its own would be a skin the guard
 * does not fully cover, so [`Palette`] is exhaustive and the compiler enforces
 * it.
 *
 * Radii and font stacks are part of a skin because they are what separates
 * "Win11" from "Cyber" once both are legible — a 2px corner and a 8px corner
 * are different products to look at. They carry no contrast consequence, so
 * they are the free part of the design.
 *
 * # How these values were chosen
 *
 * Not by eye. Each ink was seeded with the colour the skin wants and then slid
 * along its own lightness axis — hue and saturation held — until it cleared
 * **4.62:1** against every ground its text can actually land on: the four bare
 * surfaces, and each of the five 12% tints (`--accent`, `--ok`, `--warn`,
 * `--danger`, `--info`) composited onto each of those four — twenty-four
 * grounds per ink. 4.62 rather than 4.50 because a value sitting exactly on the
 * floor fails the moment a surface is nudged, and these surfaces will be
 * nudged.
 *
 * Every text tone is checked against every tint, not only against its own,
 * because a tint is a ground like any other: `--text-1` on the scrollback
 * notice sits on a 12% `--warn`, which is how one of these palettes was caught
 * at 4.33:1.
 *
 * The tint direction is the trap, and it is the one `index.css` documents at
 * length for the default palette: a light tint **lightens** a dark surface, so
 * a dark-mode ink needs to be lighter than the bare-surface check suggests; a
 * dark tint darkens a light surface, so a light-mode ink needs to be darker.
 * Several of the values below moved for that reason alone and for no other.
 *
 * `--accent-dim` is a fill and a border, never text, and `--text-0` is drawn on
 * it (`::selection`, selected rows). It is derived by sliding the accent toward
 * the surface end until `--text-0` clears 4.62:1 on it, which is the same trade
 * `index.css` records: text on it wants it darker, it as a border wants it
 * lighter, and no single value serves both roles.
 *
 * The three text tones are then held apart deliberately. `--text-2` is the
 * constrained one — it is the quietest and so the closest to the floor — so it
 * is tuned first and the two louder tones are held clear of it by ratio.
 * Letting the tuner push `--text-2` up until it met `--text-1` would clear the
 * floor and flatten the hierarchy, which makes every screen shout; the guard
 * asserts the ladder for exactly that reason.
 */

/** The two modes every skin ships in. */
export type Mode = "light" | "dark";

/**
 * The skin and mode this build ships as its default — the palette `index.css`
 * declares, and what `applyTheme(null)` clears back to.
 *
 * Named once, here, because several things have to agree with it: the
 * stylesheet (pinned by `defaultPalette.test.ts`), and every resolver that asks
 * "which mode is applied?" when nothing has been applied at all. Those used to
 * answer "dark" from a literal, which was right while the default was dark and
 * silently wrong the day it moved.
 */
export const DEFAULT_MODE: Mode = "light";

/** The skins, in the order the picker lists them. */
export const SKIN_IDS = [
  "opus",
  "candle",
  "win11",
  "nature",
  "cyber",
  "relax",
] as const;

export type SkinId = (typeof SKIN_IDS)[number];

/** The skin whose light palette `index.css` declares. See [`DEFAULT_MODE`]. */
export const DEFAULT_SKIN: SkinId = "opus";

/**
 * One palette: every token a skin sets, and nothing else.
 *
 * Exhaustive on purpose. A skin that could add a token would be a skin the
 * contrast guard does not fully know about, and the guard deriving its surfaces
 * from `--bg-\d+` means a stray `--bg-4` would silently widen what text can
 * land on.
 */
export interface Palette {
  /** Surfaces, darkest to lightest in dark mode and lightest to darkest in light. */
  "bg-0": string;
  "bg-1": string;
  "bg-2": string;
  "bg-3": string;
  "border-0": string;
  "border-1": string;
  /** Text, loudest to quietest. The three must stay a visible ladder. */
  "text-0": string;
  "text-1": string;
  "text-2": string;
  accent: string;
  "accent-hover": string;
  /** A fill and a border, never text. `--text-0` is drawn on it. */
  "accent-dim": string;
  "accent-bg": string;
  /**
   * The ink for text drawn ON an accent fill — the primary button, the version
   * banner, the hovered RAM tag.
   *
   * A token because it inverts with the skin and a literal cannot. Three rules
   * hardcoded `#1a1204` here, a near-black chosen for the dark theme's amber;
   * under any light skin the accent is itself dark and the primary button
   * became dark-on-dark. A literal `color:` is invisible to the contrast guard
   * as well, which measures only token-valued declarations, so the pairing was
   * unmeasured as well as wrong.
   */
  "on-accent": string;
  ok: string;
  "ok-bg": string;
  warn: string;
  "warn-bg": string;
  danger: string;
  "danger-bg": string;
  /** The same inversion for a `--danger` fill: the gallery's notable flag. */
  "on-danger": string;
  info: string;
  "info-bg": string;
  "font-ui": string;
  "font-mono": string;
  radius: string;
  "radius-lg": string;
  /** What the browser is told, so form controls and scrollbars follow. */
  "color-scheme": Mode;
}

/** A skin: what to call it, what it is for, and its two palettes. */
export interface Skin {
  id: SkinId;
  name: string;
  /** One line, shown under the name in the picker. */
  description: string;
  light: Palette;
  dark: Palette;
}

const INTER = "'Inter Variable', system-ui, -apple-system, sans-serif";
const PLEX_MONO = "'IBM Plex Mono', ui-monospace, 'SF Mono', Menlo, monospace";
// Segoe is Windows 11's own face. It is named first and falls back to the
// bundled Inter everywhere else, so the skin looks native on Windows and
// deliberate rather than broken on Linux and macOS.
const SEGOE = `'Segoe UI Variable Text', 'Segoe UI', ${INTER}`;
const CASCADIA = `'Cascadia Mono', 'Consolas', ${PLEX_MONO}`;

/** The 12% tint every `*-bg` token is: the ink itself, mostly transparent. */
function tint(hex: string): string {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
  return `rgba(${r}, ${g}, ${b}, 0.12)`;
}

export const SKINS: Record<SkinId, Skin> = {
  opus: {
    id: "opus",
    name: "Opus",
    description:
      "Flat and unornamented. Neutral surfaces, one violet accent, nothing pretending to be a physical object.",
    dark: {
      "bg-0": "#16161a",
      "bg-1": "#1d1d22",
      "bg-2": "#25252c",
      "bg-3": "#2f2f38",
      "border-0": "#363640",
      "border-1": "#42424e",
      "text-0": "#eceef4",
      "text-1": "#bdc1cc",
      "text-2": "#a7acb9",
      // Seeded #9d8cff and lifted for its own tint: 3.99 over the 12% violet
      // on --bg-3, where the bare surface read 5.24.
      accent: "#aea0ff",
      "accent-hover": "#b7a9ff",
      "accent-dim": "#6247ff",
      "accent-bg": tint("#aea0ff"),
      "on-accent": "#111111",
      ok: "#5cc98a",
      "ok-bg": tint("#5cc98a"),
      warn: "#e0ad4d",
      "warn-bg": tint("#e0ad4d"),
      danger: "#f19393",
      "danger-bg": tint("#f19393"),
      info: "#71b3e8",
      "info-bg": tint("#71b3e8"),
      "on-danger": "#111111",
      "font-ui": INTER,
      "font-mono": PLEX_MONO,
      radius: "6px",
      "radius-lg": "10px",
      "color-scheme": "dark",
    },
    light: {
      "bg-0": "#ffffff",
      "bg-1": "#f6f7f9",
      "bg-2": "#eceef2",
      "bg-3": "#e2e5ea",
      "border-0": "#d3d8df",
      "border-1": "#bcc3ce",
      "text-0": "#16181d",
      "text-1": "#454a54",
      "text-2": "#545964",
      // Seeded #c0362f, which read 4.36 on --bg-3 and 3.70 over its own tint
      // there. In light mode a tint DARKENS the surface, so the ink goes darker
      // to clear it — the opposite correction to the dark palette above.
      accent: "#4e3ed4",
      "accent-hover": "#4436bd",
      "accent-dim": "#8074e0",
      "accent-bg": tint("#4e3ed4"),
      "on-accent": "#ffffff",
      ok: "#1a6539",
      "ok-bg": tint("#1a6539"),
      warn: "#7b5008",
      "warn-bg": tint("#7b5008"),
      danger: "#a12d27",
      "danger-bg": tint("#a12d27"),
      info: "#1c599d",
      "info-bg": tint("#1c599d"),
      "on-danger": "#ffffff",
      "font-ui": INTER,
      "font-mono": PLEX_MONO,
      radius: "6px",
      "radius-lg": "10px",
      "color-scheme": "light",
    },
  },

  win11: {
    id: "win11",
    name: "Win11",
    description:
      "Windows 11: mica greys, the system blue, generous corners and Segoe where the platform has it.",
    dark: {
      "bg-0": "#202020",
      "bg-1": "#272727",
      "bg-2": "#2d2d2d",
      "bg-3": "#353535",
      "border-0": "#3d3d3d",
      "border-1": "#494949",
      "text-0": "#f3f3f3",
      "text-1": "#cecece",
      "text-2": "#b8b8b8",
      accent: "#60cdff",
      "accent-hover": "#8ad9ff",
      "accent-dim": "#0073a7",
      "accent-bg": tint("#60cdff"),
      "on-accent": "#111111",
      ok: "#6fcc62",
      "ok-bg": tint("#6fcc62"),
      warn: "#f0d000",
      "warn-bg": tint("#f0d000"),
      danger: "#ff9ba6",
      "danger-bg": tint("#ff9ba6"),
      info: "#60cdff",
      "info-bg": tint("#60cdff"),
      "on-danger": "#111111",
      "font-ui": SEGOE,
      "font-mono": CASCADIA,
      radius: "8px",
      "radius-lg": "12px",
      "color-scheme": "dark",
    },
    light: {
      "bg-0": "#f9f9f9",
      "bg-1": "#f3f3f3",
      "bg-2": "#ececec",
      "bg-3": "#e3e3e3",
      "border-0": "#d6d6d6",
      "border-1": "#c2c2c2",
      "text-0": "#1b1b1b",
      "text-1": "#484848",
      "text-2": "#575757",
      // Windows' own accent is #005fb8. It clears the bare surfaces and misses
      // over its own tint on --bg-3, so it sits one step darker here; the
      // difference is invisible beside the real thing, the failure would not
      // have been.
      accent: "#0056a7",
      "accent-hover": "#004c94",
      "accent-dim": "#0083fe",
      "accent-bg": tint("#0056a7"),
      "on-accent": "#ffffff",
      ok: "#0c650c",
      "ok-bg": tint("#0c650c"),
      warn: "#804b00",
      "warn-bg": tint("#804b00"),
      danger: "#a52418",
      "danger-bg": tint("#a52418"),
      info: "#0056a7",
      "info-bg": tint("#0056a7"),
      "on-danger": "#ffffff",
      "font-ui": SEGOE,
      "font-mono": CASCADIA,
      radius: "8px",
      "radius-lg": "12px",
      "color-scheme": "light",
    },
  },

  nature: {
    id: "nature",
    name: "Nature",
    description:
      "Quiet and green. Forest surfaces after dark, paper and sage by day, for long days at the screen.",
    dark: {
      "bg-0": "#12180f",
      "bg-1": "#181f14",
      "bg-2": "#1f281a",
      "bg-3": "#283322",
      "border-0": "#2f3c28",
      "border-1": "#3b4b32",
      "text-0": "#e8efe0",
      "text-1": "#bbcab2",
      "text-2": "#a4b59b",
      accent: "#9ccf6b",
      "accent-hover": "#b5de8c",
      "accent-dim": "#4c7426",
      "accent-bg": tint("#9ccf6b"),
      "on-accent": "#111111",
      ok: "#79c97e",
      "ok-bg": tint("#79c97e"),
      warn: "#d9b45c",
      "warn-bg": tint("#d9b45c"),
      danger: "#ec9b8a",
      "danger-bg": tint("#ec9b8a"),
      info: "#7fbfae",
      "info-bg": tint("#7fbfae"),
      "on-danger": "#111111",
      "font-ui": INTER,
      "font-mono": PLEX_MONO,
      radius: "5px",
      "radius-lg": "9px",
      "color-scheme": "dark",
    },
    light: {
      "bg-0": "#fbfaf5",
      "bg-1": "#f4f2e9",
      "bg-2": "#eae7db",
      "bg-3": "#ded9c9",
      "border-0": "#d4ceb9",
      "border-1": "#c5bca0",
      "text-0": "#1e2417",
      "text-1": "#3d4635",
      "text-2": "#4b5540",
      // Warm rather than white. An off-white ground is what makes this skin
      // read as paper instead of as the default light theme with green links.
      accent: "#365b1c",
      "accent-hover": "#325518",
      "accent-dim": "#5c9b30",
      "accent-bg": tint("#365b1c"),
      "on-accent": "#ffffff",
      ok: "#275c2c",
      "ok-bg": tint("#275c2c"),
      warn: "#704a0d",
      "warn-bg": tint("#704a0d"),
      danger: "#8d3522",
      "danger-bg": tint("#8d3522"),
      info: "#1d5b50",
      "info-bg": tint("#1d5b50"),
      "on-danger": "#ffffff",
      "font-ui": INTER,
      "font-mono": PLEX_MONO,
      radius: "5px",
      "radius-lg": "9px",
      "color-scheme": "light",
    },
  },

  cyber: {
    id: "cyber",
    name: "Cyber",
    description:
      "Terminal-adjacent. Near-black surfaces, teal signal, hard corners and mono in more places.",
    dark: {
      "bg-0": "#080b10",
      "bg-1": "#0d1219",
      "bg-2": "#121a23",
      "bg-3": "#18232f",
      "border-0": "#1d2b39",
      "border-1": "#26374a",
      "text-0": "#dff5ff",
      "text-1": "#9fc4d6",
      "text-2": "#7fa6ba",
      // Mono for the interface too, not only for evidence: the one skin where
      // that is the point rather than a cost. See `font-ui` below.
      accent: "#38e0d0",
      "accent-hover": "#6bf0e3",
      "accent-dim": "#13796f",
      "accent-bg": tint("#38e0d0"),
      "on-accent": "#111111",
      ok: "#4fe08a",
      "ok-bg": tint("#4fe08a"),
      warn: "#ffc857",
      "warn-bg": tint("#ffc857"),
      danger: "#ff7b8a",
      "danger-bg": tint("#ff7b8a"),
      info: "#63b8ff",
      "info-bg": tint("#63b8ff"),
      "on-danger": "#111111",
      "font-ui": PLEX_MONO,
      "font-mono": PLEX_MONO,
      radius: "2px",
      "radius-lg": "3px",
      "color-scheme": "dark",
    },
    light: {
      "bg-0": "#f7fbfc",
      "bg-1": "#eef5f7",
      "bg-2": "#e2eef1",
      "bg-3": "#d4e4e9",
      "border-0": "#c3d9e0",
      "border-1": "#a8c8d3",
      "text-0": "#08131a",
      "text-1": "#354a54",
      "text-2": "#435964",
      accent: "#00615c",
      "accent-hover": "#005a56",
      "accent-dim": "#008f88",
      "accent-bg": tint("#00615c"),
      "on-accent": "#ffffff",
      ok: "#19613d",
      "ok-bg": tint("#19613d"),
      warn: "#7c4a00",
      "warn-bg": tint("#7c4a00"),
      danger: "#a02737",
      "danger-bg": tint("#a02737"),
      info: "#105798",
      "info-bg": tint("#105798"),
      "on-danger": "#ffffff",
      "font-ui": PLEX_MONO,
      "font-mono": PLEX_MONO,
      radius: "2px",
      "radius-lg": "3px",
      "color-scheme": "light",
    },
  },

  // The palette this product shipped with, kept as a skin when the default
  // moved to Opus light. Its dark mode is that palette token for token — every
  // value in it was measured and argued for in `index.css`, and those arguments
  // travel with it here rather than being deleted along with the default. Its
  // light mode is new: the same candlelit family on paper grounds, tuned to the
  // same 4.62 floor as every other palette here.
  candle: {
    id: "candle",
    name: "Candle",
    description:
      "Séance's original look: ink-blue charcoal and one candlelight amber after dark, warm paper and burnt amber by day.",
    dark: {
      "bg-0": "#0e1014",
      "bg-1": "#14171d",
      "bg-2": "#1a1e26",
      "bg-3": "#222732",
      "border-0": "#262b36",
      "border-1": "#333a48",
      "text-0": "#dde1e8",
      "text-1": "#a7aebb",
      // #6f7887 read 4.27 / 4.03 / 3.75 / 3.36 on the four surfaces — under the
      // floor on every one, and this tone carries 9-11px data-bearing text.
      "text-2": "#8a93a3",
      accent: "#e5a13c",
      "accent-hover": "#f0b45c",
      // A fill and a border, never text, with --text-0 drawn on it. #8a6224 put
      // that pairing at 4.15; this value measures 4.87.
      "accent-dim": "#7d5820",
      "accent-bg": tint("#e5a13c"),
      "on-accent": "#1a1204",
      ok: "#55b374",
      "ok-bg": tint("#55b374"),
      warn: "#d9a13b",
      "warn-bg": tint("#d9a13b"),
      // Lightened twice: a 12% light tint LIGHTENS a dark surface, so --danger
      // on --danger-bg is a worse ground than the bare surface, and #e56b6b
      // measured 4.04 there.
      danger: "#ec8080",
      "danger-bg": tint("#ec8080"),
      info: "#5b9fd4",
      "info-bg": tint("#5b9fd4"),
      "on-danger": "#1a0606",
      "font-ui": INTER,
      "font-mono": PLEX_MONO,
      radius: "4px",
      "radius-lg": "8px",
      "color-scheme": "dark",
    },
    light: {
      "bg-0": "#fdfbf7",
      "bg-1": "#f6f2ea",
      "bg-2": "#eee8dc",
      "bg-3": "#e4dccb",
      "border-0": "#d8cdb8",
      "border-1": "#c4b697",
      "text-0": "#241c10",
      "text-1": "#4a4032",
      "text-2": "#5b5142",
      // Seeded from the dark palette's amber and slid down its own lightness
      // axis until it cleared 4.62 on all twenty-four grounds: in light mode a
      // 12% tint DARKENS the surface, so the ink goes darker rather than
      // lighter. The candlelight is still the accent; it is burnt rather than
      // lit, because a lit amber cannot carry text on paper.
      accent: "#744c0f",
      "accent-hover": "#63410c",
      // Kept light: this is a fill and a border with --text-0 on it (6.55).
      "accent-dim": "#c89a4a",
      "accent-bg": tint("#744c0f"),
      "on-accent": "#ffffff",
      ok: "#285f34",
      "ok-bg": tint("#285f34"),
      warn: "#744c07",
      "warn-bg": tint("#744c07"),
      danger: "#9a2d23",
      "danger-bg": tint("#9a2d23"),
      info: "#1e568f",
      "info-bg": tint("#1e568f"),
      "on-danger": "#ffffff",
      "font-ui": INTER,
      "font-mono": PLEX_MONO,
      radius: "4px",
      "radius-lg": "8px",
      "color-scheme": "light",
    },
  },

  relax: {
    id: "relax",
    name: "Relax",
    description:
      "Low-contrast blues and a soft ground. The quietest of the five, for reading rather than scanning.",
    dark: {
      "bg-0": "#131822",
      "bg-1": "#19202b",
      "bg-2": "#202836",
      "bg-3": "#293242",
      "border-0": "#2f394b",
      "border-1": "#39455b",
      "text-0": "#e6ecf5",
      "text-1": "#bbc6d4",
      "text-2": "#a4b0c1",
      accent: "#83b6e8",
      "accent-hover": "#a3cbf1",
      "accent-dim": "#216bb3",
      "accent-bg": tint("#83b6e8"),
      "on-accent": "#111111",
      ok: "#6fc79b",
      "ok-bg": tint("#6fc79b"),
      warn: "#dcb066",
      "warn-bg": tint("#dcb066"),
      danger: "#ef9797",
      "danger-bg": tint("#ef9797"),
      info: "#8fb8dd",
      "info-bg": tint("#8fb8dd"),
      "on-danger": "#111111",
      "font-ui": INTER,
      "font-mono": PLEX_MONO,
      radius: "8px",
      "radius-lg": "14px",
      "color-scheme": "dark",
    },
    light: {
      "bg-0": "#fbfcfe",
      "bg-1": "#f2f5fa",
      "bg-2": "#e8edf5",
      "bg-3": "#dbe3ef",
      "border-0": "#c9d5e7",
      "border-1": "#adbfdb",
      "text-0": "#161c26",
      "text-1": "#3f4a5a",
      "text-2": "#4d586c",
      accent: "#2a598c",
      "accent-hover": "#234c79",
      "accent-dim": "#4d89ca",
      "accent-bg": tint("#2a598c"),
      "on-accent": "#ffffff",
      ok: "#1c6346",
      "ok-bg": tint("#1c6346"),
      warn: "#784f09",
      "warn-bg": tint("#784f09"),
      danger: "#9b3232",
      "danger-bg": tint("#9b3232"),
      info: "#245b89",
      "info-bg": tint("#245b89"),
      "on-danger": "#ffffff",
      "font-ui": INTER,
      "font-mono": PLEX_MONO,
      radius: "8px",
      "radius-lg": "14px",
      "color-scheme": "light",
    },
  },
};

/** Every palette in the product, labelled, for the guard to sweep. */
export function allPalettes(): { label: string; palette: Palette }[] {
  return SKIN_IDS.flatMap((id) => [
    { label: `${id}/light`, palette: SKINS[id].light },
    { label: `${id}/dark`, palette: SKINS[id].dark },
  ]);
}

/**
 * A palette as the token map the contrast instrument and the DOM both take.
 *
 * `--` prefixed, because that is what a custom property is called in both
 * places; the interface drops the prefix only because `palette['bg-0']` reads
 * better than `palette['--bg-0']` at every author site.
 */
export function paletteTokens(palette: Palette): Map<string, string> {
  return new Map(
    Object.entries(palette).map(([name, value]) => [`--${name}`, value]),
  );
}
