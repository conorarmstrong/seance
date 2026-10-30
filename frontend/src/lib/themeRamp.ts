/**
 * The product's one data ramp, in the two forms its two consumers need.
 *
 * # Why there are two forms, and why that is not a choice
 *
 * Both charts that use a ramp — the activity heatmap and the allocation map —
 * interpolated between two hardcoded RGB triples, `[32, 38, 48]` and
 * `[229, 161, 60]`. Those are the 2026 dark palette's `--bg-3` and `--accent`,
 * frozen in JavaScript where no stylesheet lint can see them. Under a light skin
 * both charts were still drawn entirely in the dark theme's colours.
 *
 * The heatmap paints **SVG attributes**, where a `color-mix(... var(--accent)
 * ...)` string resolves against the element like any other CSS. The allocation
 * map paints a **canvas 2D context**, where it does not: a canvas has no element
 * to resolve custom properties against, so `ctx.fillStyle = 'color-mix(…var(--x)…)'`
 * is not a parsable colour, the assignment is a spec-mandated no-op, and the
 * context keeps whatever `fillStyle` it had — `#000000` on a freshly sized
 * canvas. A ramp that "follows the theme" that way paints a solid black grid.
 *
 * So: [`rampColor`] for anything the browser will resolve, and [`rampSampler`]
 * for canvas, which reads the same two tokens through `getComputedStyle` and
 * interpolates them itself. One ramp, one pair of endpoints, two renderers.
 */

/** The two tokens every ramp in the product runs between. */
const LO_TOKEN = '--bg-3'
const HI_TOKEN = '--accent'

/**
 * A point on the ramp, as a CSS colour the browser resolves against the element
 * it is set on.
 *
 * For SVG attributes and stylesheets. **Not for a canvas** — see [`rampSampler`].
 */
export function rampColor(t: number): string {
  const percent = rampPercent(t)
  return `color-mix(in srgb, var(${HI_TOKEN}) ${percent}%, var(${LO_TOKEN}))`
}

/** Rounded to a tenth: fifteen decimal places in a style attribute is noise in
 * every snapshot and every screenshot diff, and 0.1% of a ramp is not a
 * distinction a reader can make. */
function rampPercent(t: number): number {
  const clamped = Math.max(0, Math.min(1, t))
  return Math.round(clamped * 1000) / 10
}

type Rgb = [number, number, number]

/**
 * Parse whatever `getComputedStyle` returns for a colour token.
 *
 * Browsers normalise to `rgb()` / `rgba()`, but a token can also be read back as
 * the hex it was written as (jsdom does this), so both are handled. `null` for
 * anything else, which is the caller's signal to fall back rather than to paint
 * a colour it made up.
 */
function parseColor(value: string): Rgb | null {
  const text = value.trim()
  const rgb = text.match(/^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i)
  if (rgb) return [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])]
  const hex = text.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i)
  if (hex) {
    const h = hex[1]
    const full = h.length === 3 ? [...h].map((c) => c + c).join('') : h
    return [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16)) as Rgb
  }
  return null
}

/**
 * A ramp resolved against the document as it is painted right now, for a canvas.
 *
 * Read once per draw rather than once per cell: `getComputedStyle` is a layout
 * read, and doing it per pixel of a disk map would be pathological.
 *
 * The fallbacks are the default palette's own `--bg-3` and `--accent`. They are
 * reached only where the tokens cannot be read at all — a detached element, a
 * test environment that does not compute custom properties — and a chart drawn
 * in the shipped palette is a better answer there than one drawn in black.
 */
export function rampSampler(
  el: Element | null,
): (t: number) => string {
  const fallbackLo: Rgb = [47, 47, 56]
  const fallbackHi: Rgb = [229, 161, 60]
  let lo = fallbackLo
  let hi = fallbackHi

  if (el && typeof window !== 'undefined' && window.getComputedStyle) {
    const style = window.getComputedStyle(el)
    lo = parseColor(style.getPropertyValue(LO_TOKEN)) ?? fallbackLo
    hi = parseColor(style.getPropertyValue(HI_TOKEN)) ?? fallbackHi
  }

  return (t: number) => {
    const f = rampPercent(t) / 100
    const c = lo.map((l, i) => Math.round(l + (hi[i] - l) * f))
    return `rgb(${c[0]},${c[1]},${c[2]})`
  }
}
