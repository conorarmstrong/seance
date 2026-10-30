import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { WorldMap, projectLonLat, useWorldMapScale } from './WorldMap'

/**
 * UI-029. A case's GPS points are never spread over the globe — they are a
 * town, a commute, a country at most. The map opened at the whole world with
 * the case's 14,804 points as two dots near Washington, and the examiner had to
 * pan and zoom by hand before the screen said anything. Every forensic map
 * opens on its data.
 */
describe('WorldMap', () => {
  const box = () => screen.getByRole('img').getAttribute('viewBox')!.split(' ').map(Number)

  it('opens on the whole world when it is given no points', () => {
    render(<WorldMap ariaLabel="map" />)
    const [x, y, w] = box()
    expect([x, y]).toEqual([0, 0])
    expect(w).toBe(360)
  })

  it('opens on the points it was given', () => {
    // Burlington VT and a few hundred metres away: a single town.
    const points: Array<[number, number]> = [
      projectLonLat(-73.2213, 44.4772),
      projectLonLat(-73.2201, 44.4781),
    ]
    render(<WorldMap ariaLabel="map" fitTo={points} />)
    const [x, y, w, h] = box()

    expect(w).toBeLessThan(360)
    // The points are inside the drawn window.
    for (const [px, py] of points) {
      expect(px).toBeGreaterThanOrEqual(x)
      expect(px).toBeLessThanOrEqual(x + w)
      expect(py).toBeGreaterThanOrEqual(y)
      expect(py).toBeLessThanOrEqual(y + h)
    }
  })

  it('does not zoom past its own limit for a single point', () => {
    render(<WorldMap ariaLabel="map" fitTo={[projectLonLat(-73.2213, 44.4772)]} />)
    const [, , w] = box()
    // One point has no extent; the view must still be a view.
    expect(w).toBeGreaterThanOrEqual(20)
    expect(Number.isFinite(w)).toBe(true)
  })

  it('keeps the window inside the map when the points are at its edge', () => {
    render(
      <WorldMap
        ariaLabel="map"
        fitTo={[projectLonLat(179.9, 89.9), projectLonLat(179.8, 89.8)]}
      />,
    )
    const [x, y, w, h] = box()
    expect(x).toBeGreaterThanOrEqual(0)
    expect(y).toBeGreaterThanOrEqual(0)
    expect(x + w).toBeLessThanOrEqual(360.001)
    expect(y + h).toBeLessThanOrEqual(180.001)
  })
})

describe('what is drawn on the map', () => {
  // UI-029. A marker's radius is in map units, so it is measured in degrees:
  // zoomed to a town, a 4-pixel dot became a blob covering the county. The
  // scale the map publishes is what keeps a marker the same size on screen at
  // every zoom.
  function Dot() {
    const scale = useWorldMapScale()
    return <circle data-testid="dot" cx={0} cy={0} r={2 * scale} />
  }

  it('publishes a scale of 1 at the whole world', () => {
    render(
      <WorldMap ariaLabel="map">
        <Dot />
      </WorldMap>,
    )
    expect(screen.getByTestId('dot').getAttribute('r')).toBe('2')
  })

  it('shrinks what is drawn on it as it zooms in', () => {
    render(
      <WorldMap
        ariaLabel="map"
        fitTo={[projectLonLat(-73.2213, 44.4772), projectLonLat(-73.2201, 44.4781)]}
      >
        <Dot />
      </WorldMap>,
    )
    const r = Number(screen.getByTestId('dot').getAttribute('r'))
    expect(r).toBeGreaterThan(0)
    expect(r).toBeLessThan(0.2)
  })
})
