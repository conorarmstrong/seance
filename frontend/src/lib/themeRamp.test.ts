import { describe, expect, it } from 'vitest'
import { rampColor, rampSampler } from './themeRamp'

describe('the data ramp', () => {
  it('gives a CANVAS a colour a canvas can actually use', () => {
    // The defect this exists for. `rampColor` returns
    // `color-mix(in srgb, var(--accent) N%, var(--bg-3))`, which resolves
    // against an element — an SVG `fill`, a stylesheet — and does NOT resolve
    // in a 2D context, which has no element. Assigning it to `fillStyle` is a
    // spec-mandated no-op, so every cell paints in whatever the context last
    // held: `#000000` on a freshly sized canvas. The allocation map rendered as
    // a solid black grid, in every browser and every theme.
    const sample = rampSampler(document.documentElement)
    for (const t of [0, 0.25, 0.5, 1]) {
      const colour = sample(t)
      expect(colour).not.toMatch(/var\(|color-mix/)
      expect(colour).toMatch(/^rgb\(\d{1,3},\d{1,3},\d{1,3}\)$/)
    }
  })

  it('reads its endpoints from the document, so it follows the theme', () => {
    const root = document.documentElement
    try {
      root.style.setProperty('--bg-3', '#000000')
      root.style.setProperty('--accent', '#ffffff')
      const sample = rampSampler(root)
      expect(sample(0)).toBe('rgb(0,0,0)')
      expect(sample(1)).toBe('rgb(255,255,255)')
      expect(sample(0.5)).toBe('rgb(128,128,128)')

      // Change the tokens and the ramp changes with them: the endpoints are
      // read, not compiled in.
      root.style.setProperty('--accent', '#000000')
      root.style.setProperty('--bg-3', '#ffffff')
      expect(rampSampler(root)(1)).toBe('rgb(0,0,0)')
    } finally {
      root.style.removeProperty('--bg-3')
      root.style.removeProperty('--accent')
    }
  })

  it('paints the shipped palette rather than black when it cannot read tokens', () => {
    // Reached only where the tokens are unreadable — a detached element, an
    // environment that does not compute custom properties. A chart in the
    // default palette is a better answer there than one in black, which is what
    // an unparsed colour would leave behind.
    const sample = rampSampler(null)
    expect(sample(0)).toBe('rgb(47,47,56)')
    expect(sample(1)).toBe('rgb(229,161,60)')
  })

  it('gives SVG and CSS a token-valued colour, so those DO follow the theme', () => {
    // The other half. The heatmap paints an SVG `fill` attribute, where the
    // browser resolves this against the element like any other CSS — which is
    // why it was never affected by the canvas defect above.
    expect(rampColor(0.5)).toBe(
      'color-mix(in srgb, var(--accent) 50%, var(--bg-3))',
    )
    expect(rampColor(0)).toContain('var(--bg-3)')
    expect(rampColor(1)).toContain('var(--accent)')
  })

  it('clamps rather than extrapolating past its own ends', () => {
    expect(rampColor(-1)).toBe(rampColor(0))
    expect(rampColor(2)).toBe(rampColor(1))
    expect(rampSampler(null)(-1)).toBe(rampSampler(null)(0))
    expect(rampSampler(null)(2)).toBe(rampSampler(null)(1))
  })
})

describe('a canvas redrawing when the theme changes', () => {
  it('reports a new version when the applied tokens change', async () => {
    // The other half of the canvas problem. A canvas holds pixels rather than a
    // live style, so it re-resolves nothing on its own; without a trigger the
    // allocation map would keep the previous skin's colours until something
    // else forced a redraw.
    //
    // Watching the DOCUMENT rather than the provider is deliberate: it catches
    // every route a theme can change by, and it means a chart does not need a
    // provider to render — which is what stopped three unrelated test files
    // having to wrap one around components whose subject is not the theme.
    const { renderHook, act, waitFor } = await import('@testing-library/react')
    const { useThemeVersion } = await import('../themes/useThemeVersion')
    const { applyTheme } = await import('../themes/applyTheme')

    const { result } = renderHook(() => useThemeVersion())
    const before = result.current

    act(() => applyTheme({ skin: 'nature', mode: 'light' }, document.documentElement))
    await waitFor(() => expect(result.current).toBeGreaterThan(before))

    applyTheme(null, document.documentElement)
  })
})
