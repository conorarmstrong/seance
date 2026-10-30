import { useEffect, useMemo, useRef, useState } from 'react'
import { focusWindow } from '../../lib/focusWindow'
import { formatCount, formatUtc } from '../../lib/format'
import type { TimelineHistogram } from './api'

/** Logical SVG coordinate space; stretched to the container width. */
const VB_W = 1000
const PLOT_H = 80
/** Cap on rendered bars so a bad response cannot lock the UI. */
const MAX_BARS = 2000

interface Bucket {
  start: number
  count: number
}

/** Fill interior gaps so every bucket_seconds slot gets a (zero) bar. */
function fillBuckets(data: TimelineHistogram): Bucket[] {
  const bs = data.bucket_seconds
  if (!bs || bs <= 0 || data.buckets.length === 0) return []
  const byStart = new Map(data.buckets.map((b) => [b.start, b.count]))
  const first = data.buckets[0].start
  const last = data.buckets[data.buckets.length - 1].start
  const out: Bucket[] = []
  for (let t = first; t <= last && out.length < MAX_BARS; t += bs) {
    out.push({ start: t, count: byStart.get(t) ?? 0 })
  }
  return out
}

/** Nice tick steps, 1 minute up to a year. */
const TICK_STEPS = [
  60,
  300,
  900,
  1800,
  3600,
  3 * 3600,
  6 * 3600,
  12 * 3600,
  86400,
  2 * 86400,
  7 * 86400,
  14 * 86400,
  30 * 86400,
  90 * 86400,
  365 * 86400,
]

/** Interior tick times at a sensible step; edge-adjacent ticks are dropped. */
function tickTimes(min: number, span: number): number[] {
  const step = TICK_STEPS.find((s) => span / s <= 5) ?? Math.ceil(span / 4)
  const out: number[] = []
  for (let t = Math.ceil(min / step) * step; t < min + span; t += step) {
    const frac = (t - min) / span
    if (frac > 0.06 && frac < 0.94) out.push(t)
  }
  return out
}

/** Compact UTC axis label; detail level follows the visible span. */
function axisLabel(unix: number, span: number): string {
  const d = new Date(unix * 1000)
  const pad = (n: number) => String(n).padStart(2, '0')
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`
  const time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  if (span >= 3 * 86400) return date
  if (span >= 86400) return `${date} ${time}`
  return time
}

function bucketTitle(bucket: Bucket): string {
  const when = formatUtc(new Date(bucket.start * 1000).toISOString())
  return `${bucket.count} event${bucket.count === 1 ? '' : 's'}\n${when}`
}

/**
 * Filter-aware event-count histogram with drag-to-zoom. The frame always
 * renders at full height, so loading and refetching cause no layout jump;
 * a failed request says so in place of the chart rather than blocking the page.
 */
export function ActivityHistogram({
  data,
  isError,
  error,
  hasRange,
  onBrush,
  onClearRange,
}: {
  data: TimelineHistogram | undefined
  isError: boolean
  error: unknown
  hasRange: boolean
  /** Commit a drag-selected range as from/to (unix seconds). */
  onBrush: (from: number, to: number) => void
  onClearRange: () => void
}) {
  const plotRef = useRef<HTMLDivElement>(null)
  // Drag selection as fractions of the plot width, while the mouse is down.
  const [drag, setDrag] = useState<{ start: number; end: number } | null>(null)
  const dragging = drag !== null
  const draggingRef = useRef(false)
  draggingRef.current = dragging
  // The fraction the drag began at. The window handlers are attached once per
  // drag (below), so the one value they need from the render that started it
  // has to be held here rather than read out of that render's closure.
  const dragStartRef = useRef(0)

  useEffect(() => {
    if (isError) console.warn('Timeline histogram failed to load', error)
  }, [isError, error])

  const all = useMemo(() => (data ? fillBuckets(data) : []), [data])

  const bucketSeconds = data?.bucket_seconds ?? 0

  // Focus the axis on where the events are (UI-007). A FAT-epoch 1980 stamp or
  // a corrupt far-future one otherwise stretches this chart across decades and
  // collapses the real activity into one or two bars.
  //
  // Where the response carries a `focus`, the SERVER chose the window and
  // re-queried the buckets at a width picked for it (UI-010), so these bars are
  // already the focused ones and are drawn as they arrived. Narrowing them
  // again here would focus a focused chart, which is how two passes of one rule
  // end up disagreeing about one case.
  //
  // Where it does not — an older server, or a request that did not ask — the
  // same rule is applied to the bars in hand, through the helper the
  // dashboard's MiniTimeline and every rich-viewer chart also use.
  //
  // Either way the events outside the window are counted and disclosed below,
  // never dropped quietly, and the brush maps against the *drawn* domain, so a
  // range an examiner selects is the range they can see.
  const serverFocus = data?.focus ?? null
  const focus = useMemo(() => {
    if (serverFocus) {
      return {
        bars: all,
        before: serverFocus.events_before,
        after: serverFocus.events_after,
      }
    }
    if (!(bucketSeconds > 0) || all.length === 0) {
      return { bars: all, before: 0, after: 0 }
    }
    const { lo, hi, before, after } = focusWindow(all.map((b) => b.count))
    return { bars: all.slice(lo, hi + 1), before, after }
  }, [all, bucketSeconds, serverFocus])

  const filled = focus.bars
  const outside = focus.before + focus.after
  // The whole extent, which is NOT the drawn window when the server focused:
  // the response then holds only the window's buckets, and `min_ts`/`max_ts`
  // are what the case actually spans. The disclosure quotes those.
  const fullStart =
    serverFocus != null
      ? (data?.min_ts ?? null)
      : all.length > 0
        ? all[0].start
        : null
  const fullEnd =
    serverFocus != null
      ? (data?.max_ts ?? null)
      : all.length > 0
        ? all[all.length - 1].start + bucketSeconds
        : null

  const domainMin = filled.length > 0 ? filled[0].start : null
  const domainMax =
    filled.length > 0
      ? filled[filled.length - 1].start + bucketSeconds
      : null
  const span =
    domainMin != null && domainMax != null
      ? Math.max(domainMax - domainMin, 1)
      : null

  // What a brush commits against, refreshed on every render. The drag handlers
  // outlive the render that created them, so they must not read the domain out
  // of that closure: a refetch landing mid-drag redraws the bars on a new
  // domain, and the range the examiner then releases has to mean what is on
  // screen at that moment, not what was there when the mouse went down.
  const commitRef = useRef({ span, domainMin, onBrush })
  commitRef.current = { span, domainMin, onBrush }

  const fracFromClientX = (clientX: number): number => {
    const el = plotRef.current
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

  // While dragging: track the mouse on window, commit on mouseup,
  // cancel on Escape. Subscribed once per drag: `onMove` sets state for every
  // pixel the pointer travels, so a dependency-free effect tore down and
  // re-attached all three window listeners on each of those renders. The
  // handlers read what they need through refs so they stay current without
  // being replaced.
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
      if (latest.span != null && latest.domainMin != null && hi - lo > 0.005) {
        latest.onBrush(
          Math.round(latest.domainMin + lo * latest.span),
          Math.round(latest.domainMin + hi * latest.span),
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

  // Escape resets an applied range (the chip is the pointer path). Skipped
  // while dragging (that Escape only cancels the drag) and while a modal is
  // open so it cannot steal the modal's Escape.
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

  // The failure used to reach a console.warn and nothing else, leaving a blank
  // band where the activity chart goes. An examiner reading a screenshot of
  // that cannot tell a case with no events in this window from a request that
  // failed, and the histogram is the control every other filter on this page is
  // set from (the BUG-204 / B8-021 class).
  if (isError) {
    return (
      <div className="error-note" role="note" data-testid="tl-histogram-error">
        Activity over time could not be loaded
        {error instanceof Error ? `: ${error.message}` : ''}. This is a failed
        request, not a period with no activity in it.
      </div>
    )
  }

  // Counted over every bucket `fillBuckets` produced, focused away or not. The
  // summary states it against `data.min_ts`/`max_ts` — the full extent — so
  // counting only the drawn bars would put a smaller number beside the wider
  // range and quietly under-report the case. (`fillBuckets` still stops at
  // MAX_BARS, so a response needing more slots than that is short here as it
  // always was; the server picks a bucket width that fits the extent into ~120
  // buckets, so reaching that cap takes a response this client did not ask for.)
  // The bar heights, by contrast, are scaled to the tallest bar actually drawn.
  //
  // A server-focused response holds only the window's buckets, so the events it
  // left out have to be added back here or the count beside the full extent
  // would be a count of something narrower than the range it is printed
  // against. When the focus was applied here instead, `all` already holds them.
  const totalCount =
    all.reduce((sum, b) => sum + b.count, 0) +
    (serverFocus ? serverFocus.events_before + serverFocus.events_after : 0)
  const maxCount = Math.max(...filled.map((b) => b.count), 1)
  const barW = filled.length > 0 ? VB_W / filled.length : 0
  const ticks =
    span != null && domainMin != null ? tickTimes(domainMin, span) : []

  const summary =
    data && data.min_ts != null && data.max_ts != null
      ? `${totalCount} events between ${formatUtc(
          new Date(data.min_ts * 1000).toISOString(),
        )} and ${formatUtc(new Date(data.max_ts * 1000).toISOString())}` +
        (outside > 0
          ? `; the chart is focused on where the events are and ${formatCount(
              outside,
            )} fall outside it`
          : '')
      : 'No timeline activity for the current filters'

  const selLo = drag ? Math.min(drag.start, drag.end) : null
  const selHi = drag ? Math.max(drag.start, drag.end) : null

  return (
    <div className="tl-hist">
      <div className="tl-hist-head">
        <span className="tl-hist-title">Activity</span>
        {hasRange && (
          <button className="tl-hist-chip" onClick={onClearRange}>
            Clear range
          </button>
        )}
      </div>
      <p className="tl-vh">{summary}</p>
      <div
        className="tl-hist-plot"
        ref={plotRef}
        onMouseDown={startDrag}
        aria-hidden="true"
      >
        <svg
          className="tl-hist-svg"
          viewBox={`0 0 ${VB_W} ${PLOT_H}`}
          preserveAspectRatio="none"
          shapeRendering="crispEdges"
          focusable="false"
        >
          <line
            className="tl-hist-grid"
            x1={0}
            x2={VB_W}
            y1={PLOT_H / 3}
            y2={PLOT_H / 3}
          />
          <line
            className="tl-hist-grid"
            x1={0}
            x2={VB_W}
            y1={(2 * PLOT_H) / 3}
            y2={(2 * PLOT_H) / 3}
          />
          {span != null &&
            domainMin != null &&
            ticks.map((t) => {
              const x = ((t - domainMin) / span) * VB_W
              return (
                <line
                  key={t}
                  className="tl-hist-grid"
                  x1={x}
                  x2={x}
                  y1={0}
                  y2={PLOT_H}
                />
              )
            })}
          {filled.map((bucket, i) => {
            const height =
              bucket.count > 0
                ? Math.max((bucket.count / maxCount) * (PLOT_H - 4), 2)
                : 0
            const x = i * barW
            return (
              <g className="tl-hist-bucket" key={bucket.start}>
                <rect
                  className="tl-hist-hit"
                  x={x}
                  y={0}
                  width={barW}
                  height={PLOT_H}
                >
                  <title>{bucketTitle(bucket)}</title>
                </rect>
                {bucket.count > 0 && (
                  <rect
                    className="tl-hist-bar"
                    x={x + barW * 0.08}
                    y={PLOT_H - height}
                    width={barW * 0.84}
                    height={height}
                  />
                )}
              </g>
            )
          })}
          <line
            className="tl-hist-baseline"
            x1={0}
            x2={VB_W}
            y1={PLOT_H - 0.5}
            y2={PLOT_H - 0.5}
          />
        </svg>
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
      {/* An axis narrowed to the bulk of the events says so, and says how many
          it left out. Silently trimming a court-facing chart would make an
          outlier timestamp — often the interesting one — disappear. */}
      {outside > 0 && fullStart != null && fullEnd != null && (
        <p className="tl-hist-focus" role="note" data-testid="tl-histogram-focus">
          Focused on where the events are.{' '}
          {focus.before > 0 &&
            `${formatCount(focus.before)} earlier event${
              focus.before === 1 ? '' : 's'
            } from ${formatUtc(new Date(fullStart * 1000).toISOString())}`}
          {focus.before > 0 && focus.after > 0 && ' and '}
          {focus.after > 0 &&
            `${formatCount(focus.after)} later event${
              focus.after === 1 ? '' : 's'
            } to ${formatUtc(new Date(fullEnd * 1000).toISOString())}`}
          {' '}
          {outside === 1 ? 'is' : 'are'} outside the drawn range. They are
          counted here, still in the table below, and still in every export.
        </p>
      )}
      <div className="tl-hist-axis" aria-hidden="true">
        {span != null && domainMin != null && domainMax != null && (
          <>
            <span className="tl-hist-axis-start">
              {axisLabel(domainMin, span)}
            </span>
            {ticks.map((t) => (
              <span
                key={t}
                style={{ left: `${((t - domainMin) / span) * 100}%` }}
              >
                {axisLabel(t, span)}
              </span>
            ))}
            <span className="tl-hist-axis-end">
              {axisLabel(domainMax, span)}
            </span>
          </>
        )}
      </div>
    </div>
  )
}
