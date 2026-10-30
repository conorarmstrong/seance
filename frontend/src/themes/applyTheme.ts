import {
  SKINS,
  SKIN_IDS,
  type Mode,
  type Palette,
  type SkinId,
} from "./palettes";

/**
 * A chosen skin: which look, and which of its two modes.
 *
 * Stored and transmitted as `"<skin>:<mode>"` — see [`encode`] — because the
 * server holds it as one column and validates its shape without holding the
 * catalogue of skins.
 */
export interface Theme {
  skin: SkinId;
  mode: Mode;
}

/**
 * `null` is the theme of someone who has never chosen, and it means the palette
 * `index.css` already declares rather than a skin chosen by name. The first
 * paint of every cold load is that palette whether or not JavaScript has run
 * yet, which is why the default lives in CSS at all.
 *
 * It is distinct from choosing the palette that happens to be the default:
 * only the first moves when the shipped default does. It moved once, on
 * 2026-09-13, from the dark candlelight palette to `SKINS.opus.light`;
 * everyone on `null` moved with it, and everyone who had chosen `candle:dark`
 * — the same palette, by name — did not.
 */

/** The key the browser-local cache is kept under. */
export const THEME_STORAGE_KEY = "seance.theme";

/** `"nature:light"`. The form the server stores and validates. */
export function encode(theme: Theme): string {
  return `${theme.skin}:${theme.mode}`;
}

/**
 * Read a stored theme, or `null` if it is absent, malformed, or names a skin
 * this build does not have.
 *
 * An unrecognised skin is **not** an error to report: it is what a client one
 * version behind sees after someone picks a newly added skin on another
 * machine, and the honest answer is to fall back to the default rather than to
 * refuse to render. The server validates the shape and deliberately does not
 * hold the catalogue, which is what makes this case ordinary.
 */
export function decode(value: string | null | undefined): Theme | null {
  if (!value) return null;
  const [skin, mode] = value.split(":");
  if (mode !== "light" && mode !== "dark") return null;
  if (!(SKIN_IDS as readonly string[]).includes(skin)) return null;
  return { skin: skin as SkinId, mode };
}

/** The palette a theme resolves to. */
export function paletteFor(theme: Theme): Palette {
  return SKINS[theme.skin][theme.mode];
}

/**
 * Paint a theme onto the document, or clear back to `index.css`'s own palette.
 *
 * Custom properties are set on `documentElement` rather than injected as a
 * `<style>` block so that switching costs one write per token and no reparse,
 * and so that nothing in the cascade has to be ordered against the stylesheets.
 *
 * `color-scheme` is set as a real property, not a custom one: it is what makes
 * the browser draw form controls, scrollbars and the canvas behind the app to
 * match. Without it a light skin keeps a dark `<select>` popup.
 *
 * Clearing removes the properties rather than writing the default palette's
 * values over them. The difference matters: removed, the tokens fall back to
 * `index.css`, which is one source of truth; written, they would be a second
 * copy that could drift from it.
 */
export function applyTheme(theme: Theme | null, root: HTMLElement): void {
  const style = root.style;
  if (theme === null) {
    for (const name of Object.keys(SKINS.opus.light)) {
      if (name === "color-scheme") continue;
      style.removeProperty(`--${name}`);
    }
    style.removeProperty("color-scheme");
    root.removeAttribute("data-skin");
    root.removeAttribute("data-mode");
    return;
  }

  const palette = paletteFor(theme);
  for (const [name, value] of Object.entries(palette)) {
    if (name === "color-scheme") continue;
    style.setProperty(`--${name}`, value);
  }
  style.setProperty("color-scheme", palette["color-scheme"]);
  // Published on the element so a stylesheet or a test can ask what is applied
  // without reading twenty custom properties back out.
  root.setAttribute("data-skin", theme.skin);
  root.setAttribute("data-mode", theme.mode);
}

/**
 * The theme to paint before anything has been fetched.
 *
 * Read synchronously from `localStorage` at module load, because the
 * alternative is painting the default palette and swapping it when `/auth/me`
 * answers — a visible flash on every cold load, on a product whose users have
 * chosen a skin precisely because the default one tires them.
 *
 * The browser copy is a **cache**, not the record. The record is the `theme`
 * column on the user's row, which is what makes the choice follow them to the
 * second workstation in the lab. Where the two disagree the server wins, and
 * the cache is corrected.
 *
 * Every access is wrapped: `localStorage` throws outright in a browser
 * configured to block site data, and a theme is not worth failing to start over.
 */
export function cachedTheme(): Theme | null {
  try {
    return decode(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return null;
  }
}

export function cacheTheme(theme: Theme | null): void {
  try {
    if (theme === null) window.localStorage.removeItem(THEME_STORAGE_KEY);
    else window.localStorage.setItem(THEME_STORAGE_KEY, encode(theme));
  } catch {
    // A viewer who cannot store site data still gets the theme for this
    // session — it is applied to the document either way — and gets it again on
    // the next load from the server. Nothing here is worth an error.
  }
}
