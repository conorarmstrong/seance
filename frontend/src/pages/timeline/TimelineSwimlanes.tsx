import { useEffect, useRef, useState } from 'react'
import { formatCount, formatUtc } from '../../lib/format'
import { useLaneColors } from '../../themes/laneColors'
import type { TimelineSwimlanes as SwimlanesData } from './api'
import { gridStart } from '../../components/viz/MiniTimeline'

const VB_W = 1000
const LANE_H = 20

/** Categorical lane colors, legible on the dark ground. */

const TICK_STEPS = [
  60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400,
  7 * 86400, 14 * 86400, 30 * 86400, 90 * 86400, 365 * 86400,
]

function tickTimes(min: number, span: number): number[] {
  const step = TICK_STEPS.find((s) => span / s <= 5) ?? Math.ceil(span / 4)
  const out: number[] = []
  for (let t = Math.ceil(min / step) * step; t < min + span; t += step) {
    const frac = (t - min) / span
    if (frac > 0.06 && frac < 0.94) out.push(t)
  }
  return out
}

function axisLabel(unix: number, span: number): string {
  const d = new Date(unix * 1000)
  const pad = (n: number) => String(n).padStart(2, '0')
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`
  const time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  if (span >= 3 * 86400) return date
  if (span >= 86400) return `${date} ${time}`
  return time
}

/**
 * Per-source timeline density — one lane per source module, cell opacity by
 * event volume in that time bucket. Shares the aggregate histogram's time
 * domain and drag-to-zoom, so which source was active when reads at a glance.
 */
export function TimelineSwimlanes({
  data,
  isError,
  hasRange,
  onBrush,
  onClearRange,
}: {
  data: SwimlanesData | undefined
  isError: boolean
  hasRange: boolean
  onBrush: (from: number, to: number) => void
  onClearRange: () => void
}) {
  const captureRef = useRef<HTMLDivElement>(null)
  const [drag, setDrag] = useState<{ start: number; end: number } | null>(null)
  const dragging = drag !== null
  const draggingRef = useRef(false)
  draggingRef.current = dragging
  // The fraction the drag began at, held outside the render that started it:
  // the window handlers are attached once per drag (below) rather than being
  // replaced on every mousemove.
  const dragStartRef = useRef(0)

  // Lane colours follow the mode (UI-015): one set for the dark grounds, one
  // for the light, same hues in the same order, each measured against every
  // surface it can meet. The twelve chosen here were not chosen here — see
  // `themes/laneColors.ts`.
  const palette = useLaneColors()
  const laneColor = (i: number) => palette[i % palette.length]

  const lanes = data?.lanes ?? []
  const bs = data?.bucket_seconds ?? 0
  // The drawn domain is the focused window when the server chose one (UI-010),
  // and the whole extent otherwise. Drawing focused lanes against the full
  // extent would squeeze every bar into a sliver at one end — the case that
  // motivated the focus in the first place, with the axis wrong instead of the
  // resolution. `min_ts`/`max_ts` remain the extent, and the note below quotes
  // them, so what is outside the window is stated rather than merely absent.
  const focus = data?.focus ?? null
  // Unfocused, the domain starts at the BUCKET holding the first event, not at
  // the event: the server aligns bucket starts to absolute multiples of the
  // width, so that bucket begins before `min_ts` and was drawn at a negative x
  // — clipped off the left edge of every lane, with nothing said (UI-027).
  const gridMin =
    data && bs > 0 && data.min_ts != null
      ? gridStart(
          data.lanes.flatMap((lane) => lane.buckets),
          data.min_ts,
          bs,
        )
      : (data?.min_ts ?? null)
  const min = focus ? focus.from : (gridMin ?? null)
  const max = focus ? focus.to : (data?.max_ts ?? null)
  const outside = focus ? focus.events_before + focus.events_after : 0
  const span = min != null && max != null ? Math.max(max - min, 1) : null

  // What a brush commits against, refreshed on every render, so a refetch
  // landing mid-drag brushes the domain that is on screen when the mouse is
  // released rather than the one it went down on.
  const commitRef = useRef({ span, min, onBrush })
  commitRef.current = { span, min, onBrush }

  const fracFromClientX = (clientX: number): number => {
    const el = captureRef.current
    if (!el) return 0
    const rect = el.getBoundingClientRect()
    if (rect.width === 0) return 0
    return Math.min(1, Math.max(0, (clientX - rect.left) / rect.width))
  }

  const startDrag = (e: React.MouseEvent) => {
    if (e.button !== 0 || span == null) return
    e.preventDefault()
    const frac = fracFromClientX(e.clientX)
    dragStartRef.current = frac
    setDrag({ start: frac, end: frac })
  }

  // Subscribed once per drag, not once per render: `onMove` sets state for
  // every pixel the pointer travels, so a dependency-free effect removed and
  // re-added all three window listeners on each of those renders.
  useEffect(() => {
    if (!dragging) return
    const onMove = (e: MouseEvent) =>
      setDrag((d) => (d ? { ...d, end: fracFromClientX(e.clientX) } : d))
    const onUp = (e: MouseEvent) => {
      const latest = commitRef.current
      const endFrac = fracFromClientX(e.clientX)
      const lo = Math.min(dragStartRef.current, endFrac)
      const hi = Math.max(dragStartRef.current, endFrac)
      setDrag(null)
      if (latest.span != null && latest.min != null && hi - lo > 0.005) {
        latest.onBrush(
          Math.round(latest.min + lo * latest.span),
          Math.round(latest.min + hi * latest.span),
        )
      }
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setDrag(null)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
      window.removeEventListener('keydown', onKey)
    }
  }, [dragging])

  useEffect(() => {
    if (!hasRange) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      if (draggingRef.current) return
      if (document.querySelector('[role="dialog"]')) return
      onClearRange()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [hasRange, onClearRange])

  // Not `return null`: the lane list is what an examiner reads "these are the
  // sources that were active" off, and a blank panel is indistinguishable from
  // a case where no source was (the BUG-204 / B8-021 class).
  if (isError) {
    return (
      <div className="error-note" role="note" data-testid="tl-swimlanes-error">
        Source activity could not be loaded. This is a failed request, not a
        capture in which no source was active.
      </div>
    )
  }

  if (!data || lanes.length === 0 || span == null || min == null || max == null) {
    return (
      <div className="tl-sw">
        <div className="tl-hist-head">
          <span className="tl-hist-title">Sources</span>
        </div>
        <p className="tl-vh">No source activity for the current filters</p>
      </div>
    )
  }

  const ticks = tickTimes(min, span)
  const selLo = drag ? Math.min(drag.start, drag.end) : null
  const selHi = drag ? Math.max(drag.start, drag.end) : null

  return (
    <div className="tl-sw">
      <div className="tl-hist-head">
        <span className="tl-hist-title">Sources</span>
        {hasRange && (
          <button className="tl-hist-chip" onClick={onClearRange}>
            Clear range
          </button>
        )}
      </div>

      <div className="tl-sw-lanes">
        {lanes.map((lane, i) => {
          const laneMax = Math.max(...lane.buckets.map((b) => b.count), 1)
          return (
            <div className="tl-sw-lane" key={lane.source}>
              <div className="tl-sw-label" title={lane.source}>
                <i
                  className="tl-sw-swatch"
                  style={{ background: laneColor(i) }}
                />
                <span className="tl-sw-name">{lane.source}</span>
                <span className="tl-sw-total mono">
                  {formatCount(lane.total)}
                </span>
              </div>
              <div className="tl-sw-strip">
                <svg
                  viewBox={`0 0 ${VB_W} ${LANE_H}`}
                  preserveAspectRatio="none"
                  shapeRendering="crispEdges"
                  focusable="false"
                >
                  {lane.buckets.map((b) => {
                    const x = ((b.start - min) / span) * VB_W
                    const w = Math.max((bs / span) * VB_W, 1.2)
                    const op = 0.22 + 0.78 * (b.count / laneMax)
                    return (
                      <rect
                        key={b.start}
                        x={x}
                        y={2}
                        width={w}
                        height={LANE_H - 4}
                        fill={laneColor(i)}
                        fillOpacity={op}
                      >
                        <title>{`${lane.source} · ${b.count} event${b.count === 1 ? '' : 's'}\n${formatUtc(new Date(b.start * 1000).toISOString())}`}</title>
                      </rect>
                    )
                  })}
                </svg>
              </div>
            </div>
          )
        })}
        <div
          className="tl-sw-capture"
          ref={captureRef}
          onMouseDown={startDrag}
          aria-hidden="true"
        >
          {span != null &&
            ticks.map((t) => (
              <span
                key={t}
                className="tl-sw-gridline"
                style={{ left: `${((t - min) / span) * 100}%` }}
              />
            ))}
          {drag && selLo != null && selHi != null && (
            <div
              className="tl-hist-brush"
              style={{
                left: `${selLo * 100}%`,
                width: `${(selHi - selLo) * 100}%`,
              }}
            />
          )}
        </div>
      </div>

      <div className="tl-sw-axis" aria-hidden="true">
        <span className="tl-hist-axis-start">{axisLabel(min, span)}</span>
        {ticks.map((t) => (
          <span key={t} style={{ left: `${((t - min) / span) * 100}%` }}>
            {axisLabel(t, span)}
          </span>
        ))}
        <span className="tl-hist-axis-end">{axisLabel(max, span)}</span>
      </div>

      {outside > 0 && data.min_ts != null && data.max_ts != null && (
        <p className="tl-hist-focus" role="note" data-testid="tl-swimlanes-focus">
          Focused on where the events are. {formatCount(outside)} event
          {outside === 1 ? '' : 's'} outside the drawn range, between{' '}
          {formatUtc(new Date(data.min_ts * 1000).toISOString())} and{' '}
          {formatUtc(new Date(data.max_ts * 1000).toISOString())}, are counted
          here, still in the table below, and still in every export.
        </p>
      )}
      {data.truncated_lanes && (
        <p className="tl-sw-trunc mono">
          Lowest-volume sources folded into “Other”.
        </p>
      )}
      {/* Said once, plainly, because it is a fact about the drawing and not
          about the case: a lane's colour comes from the theme in force, and a
          screenshot taken under another theme shows the same lanes in the same
          order in different colours. The source name beside each swatch is
          what identifies the lane. */}
      {lanes.length > 0 && (
        <p className="tl-sw-legend-note" data-testid="tl-swimlanes-colour-note">
          Lane colours belong to this view, not to the evidence: they follow the
          theme, and each lane is named beside its swatch.
        </p>
      )}
    </div>
  )
}
