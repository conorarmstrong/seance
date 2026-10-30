import {
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { WORLD_BORDERS } from './worldBorders'
import './WorldMap.css'

/**
 * Shared offline world map (equirectangular). The base viewBox is 360x180 so the
 * projection is a direct linear map: x = lon + 180, y = 90 - lat. Country borders
 * are pre-projected Natural Earth outlines (public domain) rendered as inline SVG
 * paths — no external tiles, CDN, or network requests, keeping the viewer
 * air-gap safe. The map pans (drag the background) and zooms (wheel); markers
 * passed as children are positioned with `projectLonLat` and pan/zoom with it.
 */

export const MAP_W = 360
export const MAP_H = 180

/** Equirectangular projection of [lon, lat] into the 360x180 SVG space. */
export function projectLonLat(lon: number, lat: number): [number, number] {
  return [lon + 180, 90 - lat]
}

const MIN_W = 20 // deepest zoom (~18x)

interface View {
  x: number
  y: number
  w: number
  h: number
}

const FULL: View = { x: 0, y: 0, w: MAP_W, h: MAP_H }

function clampView(v: View): View {
  const w = Math.min(Math.max(v.w, MIN_W), MAP_W)
  const h = w / 2
  const x = Math.min(Math.max(v.x, 0), MAP_W - w)
  const y = Math.min(Math.max(v.y, 0), MAP_H - h)
  return { x, y, w, h }
}

/**
 * The window that shows `points`, with room around them.
 *
 * A case's coordinates are a town, a commute, a country at most — never the
 * globe — and opening on the whole world left an examiner panning and zooming
 * before the screen said anything (UI-029). The padding keeps the outermost
 * point off the edge; `clampView` handles the rest, including a single point,
 * which has no extent of its own.
 */
/**
 * How zoomed in the map currently is: 1 at the whole world, 0.003 at the
 * deepest zoom.
 *
 * A marker drawn in map units keeps its size in *degrees*, so zooming to a town
 * turned a 4-pixel dot into a blob covering the county (UI-029). Anything drawn
 * into the map multiplies its dimensions by this so it stays the same size on
 * screen at every zoom.
 */
export const WorldMapScale = createContext(1)

export function useWorldMapScale(): number {
  return useContext(WorldMapScale)
}

export function fitView(points: Array<[number, number]>): View {
  if (points.length === 0) return FULL
  let minX = Infinity
  let minY = Infinity
  let maxX = -Infinity
  let maxY = -Infinity
  for (const [x, y] of points) {
    if (!Number.isFinite(x) || !Number.isFinite(y)) continue
    minX = Math.min(minX, x)
    maxX = Math.max(maxX, x)
    minY = Math.min(minY, y)
    maxY = Math.max(maxY, y)
  }
  if (!Number.isFinite(minX) || !Number.isFinite(minY)) return FULL

  const spanX = maxX - minX
  const spanY = maxY - minY
  // A fifth of the span, and never less than a degree: two points a hundred
  // metres apart still need a window a person can read.
  const pad = Math.max(spanX, spanY * 2, 1) * 0.2
  const w = spanX + pad * 2
  const h = spanY + pad * 2
  // The view keeps the map's 2:1 aspect, so take whichever dimension needs more.
  const width = Math.max(w, h * 2)
  return clampView({
    x: (minX + maxX) / 2 - width / 2,
    y: (minY + maxY) / 2 - width / 4,
    w: width,
    h: width / 2,
  })
}

export function WorldMap({
  ariaLabel,
  className,
  children,
  fitTo,
}: {
  ariaLabel: string
  className?: string
  children?: ReactNode
  /**
   * Projected points the map should open on. Changing the set re-fits, so a
   * filter that narrows the case's points moves the window with them.
   */
  fitTo?: Array<[number, number]>
}) {
  const svgRef = useRef<SVGSVGElement>(null)
  const initial = useMemo(() => fitView(fitTo ?? []), [fitTo])
  const [view, setView] = useState<View>(initial)
  // Re-fit when the caller's point set changes identity, but never while the
  // examiner is looking at somewhere they panned to themselves.
  const fittedTo = useRef(initial)
  if (fittedTo.current !== initial) {
    fittedTo.current = initial
    setView(initial)
  }
  const drag = useRef<{ px: number; py: number; vx: number; vy: number } | null>(
    null,
  )

  // Basemap (borders + graticule) is independent of pan/zoom, so build it once
  // instead of recreating 177 country paths on every viewBox change.
  const basemap = useMemo(() => {
    const graticule: ReactNode[] = []
    for (let lon = -180; lon <= 180; lon += 30) {
      const [gx] = projectLonLat(lon, 0)
      graticule.push(
        <line
          key={`v${lon}`}
          x1={gx}
          y1={0}
          x2={gx}
          y2={MAP_H}
          className="wm-graticule"
          vectorEffect="non-scaling-stroke"
        />,
      )
    }
    for (let lat = -90; lat <= 90; lat += 30) {
      const [, gy] = projectLonLat(0, lat)
      graticule.push(
        <line
          key={`h${lat}`}
          x1={0}
          y1={gy}
          x2={MAP_W}
          y2={gy}
          className="wm-graticule"
          vectorEffect="non-scaling-stroke"
        />,
      )
    }
    return (
      <>
        <rect x={0} y={0} width={MAP_W} height={MAP_H} className="wm-frame" />
        {WORLD_BORDERS.map((d, i) => (
          <path
            key={i}
            className="wm-land"
            d={d}
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {graticule}
      </>
    )
  }, [])

  // Wheel zoom toward the cursor. Attached natively so it can preventDefault
  // (React's onWheel is passive and cannot stop the page from scrolling).
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const rect = svg.getBoundingClientRect()
      if (rect.width === 0 || rect.height === 0) return
      const px = (e.clientX - rect.left) / rect.width
      const py = (e.clientY - rect.top) / rect.height
      setView((v) => {
        const factor = e.deltaY < 0 ? 0.85 : 1 / 0.85
        const targetW = v.w * factor
        const sx = v.x + px * v.w
        const sy = v.y + py * v.h
        const w = Math.min(Math.max(targetW, MIN_W), MAP_W)
        const h = w / 2
        return clampView({ x: sx - px * w, y: sy - py * h, w, h })
      })
    }
    svg.addEventListener('wheel', onWheel, { passive: false })
    return () => svg.removeEventListener('wheel', onWheel)
  }, [])

  // Drag the background to pan. Starting on a marker is left to the marker's own
  // click handler, so selecting a point and panning don't fight.
  const onPointerDown = useCallback(
    (e: ReactPointerEvent<SVGSVGElement>) => {
      if ((e.target as Element).classList?.contains('wm-dot')) return
      drag.current = { px: e.clientX, py: e.clientY, vx: view.x, vy: view.y }
      // Capture keeps the drag alive when the pointer leaves the SVG, but it is
      // an enhancement: `endDrag` already guards `hasPointerCapture` the same
      // way. Without the guard here a host that does not implement it throws
      // out of the handler and the map cannot be panned at all.
      ;(e.currentTarget as SVGSVGElement).setPointerCapture?.(e.pointerId)
    },
    [view.x, view.y],
  )
  const onPointerMove = useCallback((e: ReactPointerEvent<SVGSVGElement>) => {
    const d = drag.current
    if (!d) return
    const rect = e.currentTarget.getBoundingClientRect()
    if (rect.width === 0) return
    setView((v) => {
      const dx = ((e.clientX - d.px) / rect.width) * v.w
      const dy = ((e.clientY - d.py) / rect.height) * v.h
      return clampView({ ...v, x: d.vx - dx, y: d.vy - dy })
    })
  }, [])
  const endDrag = useCallback((e: ReactPointerEvent<SVGSVGElement>) => {
    drag.current = null
    if (e.currentTarget.hasPointerCapture?.(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId)
    }
  }, [])

  const zoomed = view.w < MAP_W - 0.5

  return (
    <div className="wm-viewport">
      <svg
        ref={svgRef}
        className={className ? `wm ${className}` : 'wm'}
        viewBox={`${view.x} ${view.y} ${view.w} ${view.h}`}
        role="img"
        aria-label={ariaLabel}
        style={{ cursor: drag.current ? 'grabbing' : 'grab', touchAction: 'none' }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
      >
        {basemap}
        <WorldMapScale.Provider value={view.w / MAP_W}>
          {children}
        </WorldMapScale.Provider>
      </svg>
      {zoomed && (
        <button
          type="button"
          className="wm-reset"
          onClick={() => setView(fitTo && fitTo.length > 0 ? initial : FULL)}
          title="Reset map view"
        >
          Reset view
        </button>
      )}
    </div>
  )
}
