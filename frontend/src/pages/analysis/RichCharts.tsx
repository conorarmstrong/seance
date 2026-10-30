import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { useMeasuredWidth } from '../../components/viz/useMeasuredWidth'
import { focusWindow } from '../../lib/focusWindow'
import { formatCount, formatUtc } from '../../lib/format'

// --- Stat tiles: a row of clickable metric tiles that double as quick filters.

export type StatTone =
  | 'critical'
  | 'error'
  | 'warning'
  | 'ok'
  | 'accent'
  | 'neutral'

export interface StatTile {
  /** Filter key; clicking toggles a filter for records in this bucket. */
  key: string
  label: string
  count: number
  tone?: StatTone
}

export function StatTiles({
  tiles,
  active,
  onToggle,
}: {
  tiles: StatTile[]
  active: string | null
  onToggle: (key: string) => void
}) {
  if (tiles.length === 0) return null
  return (
    <div className="rv-stats">
      {tiles.map((t) => (
        <button
          key={t.key}
          type="button"
          className={`rv-stat rv-tone-${t.tone ?? 'neutral'}${active === t.key ? ' active' : ''}`}
          aria-pressed={active === t.key}
          onClick={() => onToggle(t.key)}
        >
          <span className="rv-stat-count">{formatCount(t.count)}</span>
          <span className="rv-stat-label">{t.label}</span>
        </button>
      ))}
    </div>
  )
}

// --- Volume-over-time histogram. ---

/**
 * Bars this chart aims for when it buckets a set of timestamps itself.
 *
 * Exported because a caller that has the SERVER count the buckets has to ask it
 * for this many: asking for a different number would draw a chart of a
 * different resolution from the one the browser draws in the same page's
 * fallback, and the two would not be comparable side by side across a reload.
 */
export const BUCKET_TARGET = 48
const H = 96
const PAD_B = 18
/**
 * Cap on rendered bars, so a response describing a case that spans centuries at
 * minute resolution cannot lock the browser. Reaching it is stated on screen —
 * a silently shortened chart leaves the axis claiming an extent the drawing
 * does not cover.
 */
const MAX_BARS = 2000

/** One drawn bar: a HALF-OPEN period, not an instant. */
export interface HistoBucket {
  /** Inclusive start of the period, in epoch MILLISECONDS. */
  startMs: number
  count: number
  /**
   * Of `count`, how many were placed only by assuming which unit the parser
   * wrote — milliseconds, microseconds, FILETIME ticks — rather than reading
   * the value as the whole seconds its contract states. That is a weaker fact
   * than a value read to contract, so the chart says which it is drawing.
   *
   * Null means the producer did not state it, which is not the same as zero:
   * "none of these bars rests on an assumption" is a claim about the evidence,
   * and a silent default would make it on the producer's behalf.
   */
  rescued: number | null
}

/** Nice tick steps in milliseconds, 1 minute up to a year. */
const TICK_STEPS_MS = [
  60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400,
  7 * 86400, 14 * 86400, 30 * 86400, 90 * 86400, 365 * 86400,
].map((s) => s * 1000)

/** Interior tick instants at a sensible step; edge-adjacent ticks are dropped. */
function tickTimes(minMs: number, spanMs: number): number[] {
  const step = TICK_STEPS_MS.find((s) => spanMs / s <= 5) ?? Math.ceil(spanMs / 4)
  // A degenerate span would otherwise step by zero and never terminate.
  if (!(step > 0)) return []
  const out: number[] = []
  for (let t = Math.ceil(minMs / step) * step; t < minMs + spanMs; t += step) {
    const frac = (t - minMs) / spanMs
    if (frac > 0.06 && frac < 0.94) out.push(t)
  }
  return out
}

/** Compact UTC axis label; detail level follows the visible span. */
function axisLabel(ms: number, spanMs: number): string {
  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`
  const time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  if (spanMs >= 3 * 86400_000) return date
  if (spanMs >= 86400_000) return `${date} ${time}`
  return time
}

const utc = (ms: number) => formatUtc(new Date(ms).toISOString())

/**
 * What one bar stands for, in full.
 *
 * The old tooltip printed the bucket's START INSTANT and nothing else —
 * "2024-03-02 11:14:07 UTC — 412 events" — over buckets that can be weeks wide.
 * Read aloud that says four hundred and twelve things happened at eleven
 * fourteen on 2 March, which is wrong by up to the width of the bar. Server
 * bucketing makes it worse rather than better: a day-aligned start reads as a
 * precise date and invites "412 events on 2 March". So the bar names its period
 * and says which end of it is excluded.
 */
function bucketTitle(b: HistoBucket, bucketMs: number): string {
  const period = `${utc(b.startMs)} to ${utc(b.startMs + bucketMs)} (start included, end excluded)`
  const head = `${formatCount(b.count)} event${b.count === 1 ? '' : 's'} in ${period}`
  return b.rescued != null && b.rescued > 0
    ? `${head}\n${formatCount(b.rescued)} of them placed only by assuming which unit the parser wrote, not by reading the value as written.`
    : head
}

/**
 * Gap-fill so every slot between the first and last bar gets a bar, even where
 * the producer omitted the empty ones.
 *
 * Drawing only the buckets that were sent puts two bars a fortnight apart
 * side by side and labels the axis as though they were consecutive — a quiet
 * period rendered as no period at all. Slots are addressed by INDEX rather than
 * by accumulating the width, because the client-side path derives a fractional
 * bucket width from the span and float accumulation would miss the keys.
 */
function fillBuckets(
  buckets: HistoBucket[],
  bucketMs: number,
): { bars: HistoBucket[]; capped: boolean } {
  if (buckets.length === 0 || !(bucketMs > 0)) return { bars: [], capped: false }
  const sorted = [...buckets].sort((a, b) => a.startMs - b.startMs)
  const first = sorted[0].startMs
  const last = sorted[sorted.length - 1].startMs
  const wanted = Math.round((last - first) / bucketMs) + 1
  const slots = Math.min(wanted, MAX_BARS)
  const bars: HistoBucket[] = Array.from({ length: slots }, (_, i) => ({
    startMs: first + i * bucketMs,
    count: 0,
    // A slot with no events had none to rescue, so this zero is arithmetic
    // rather than an assumption about what the producer meant by its silence.
    rescued: 0,
  }))
  for (const b of sorted) {
    const i = Math.round((b.startMs - first) / bucketMs)
    if (i < 0 || i >= slots) continue
    const slot = bars[i]
    bars[i] = {
      startMs: slot.startMs,
      count: slot.count + b.count,
      rescued: b.rescued == null ? null : (slot.rescued ?? 0) + b.rescued,
    }
  }
  return { bars, capped: wanted > slots }
}

/**
 * The chart itself: bars over a UTC axis, given periods that already exist.
 *
 * Modelled on the timeline's `ActivityHistogram`, which had already worked out
 * gap-filling and the axis; what is deliberately absent is that chart's
 * drag-to-zoom brush, which belongs to a page whose filters are a time range.
 * Both the browser-bucketed chart below and the server-counted communications
 * histogram draw through this one component so they cannot drift into telling
 * the same story two ways.
 *
 * It renders its frame in every state, including the empty one. A chart that
 * disappears when it has nothing to draw is indistinguishable from a period in
 * which nothing happened, and that is the one thing this surface must never
 * imply without being asked to.
 */
export function EventHistogram({
  buckets,
  bucketMs,
  title,
  empty,
  note,
}: {
  buckets: HistoBucket[]
  /** Width of every bucket in milliseconds. Null where there are no bars. */
  bucketMs: number | null
  /** Optional heading; state which population the bars cover. */
  title?: ReactNode
  /**
   * Drawn in place of the bars when there are none. The caller knows WHY there
   * is nothing to draw and this component does not, so the sentence is its to
   * supply; the default below claims only what is true from here.
   */
  empty?: ReactNode
  /** Provenance and caveats, under the chart. */
  note?: ReactNode
}) {
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()

  const model = useMemo(() => {
    const step = bucketMs ?? 0
    const { bars: all, capped } = fillBuckets(buckets, step)
    if (all.length === 0) return null

    // Focus the drawn domain on where the events are (UI-007). One FAT-epoch
    // 1980 stamp or one corrupt far-future stamp otherwise stretches this axis
    // across decades and squashes the whole case into a bar or two. Nothing is
    // hidden: `before` and `after` are the events outside the window, and the
    // note below states them. With no bucket width there is no time axis to
    // focus along, so the range is drawn as it came.
    const { lo, hi, before, after } =
      step > 0
        ? focusWindow(all.map((b) => b.count))
        : { lo: 0, hi: all.length - 1, before: 0, after: 0 }
    const bars = all.slice(lo, hi + 1)

    const min = bars[0].startMs
    const max = bars[bars.length - 1].startMs + step
    return {
      bars,
      capped,
      step,
      min,
      max,
      span: Math.max(max - min, 1),
      peak: Math.max(...bars.map((b) => b.count), 1),
      total: bars.reduce((n, b) => n + b.count, 0),
      // Counted over every bar the producer sent, focused away or not, so the
      // disclosure below accounts for the whole population this chart was
      // given rather than for the part of it that got drawn.
      outsideBefore: before,
      outsideAfter: after,
      firstMs: all[0].startMs,
      lastMs: all[all.length - 1].startMs + step,
    }
  }, [buckets, bucketMs])

  const plotH = H - PAD_B
  const bw = model != null ? width / model.bars.length : 0

  return (
    <div className="rv-histo" ref={ref}>
      {title != null && (
        <div className="rv-top-title rv-histo-title">{title}</div>
      )}
      {model == null ? (
        <p className="rv-note" role="note">
          {empty ?? (
            <>
              No bars: nothing in view carried a time this chart could read, so
              nothing can be placed on a timeline. That is not a statement that
              nothing happened.
            </>
          )}
        </p>
      ) : (
        <>
          {/* The tooltips are the only place a bar states its period, and a
              tooltip is available to neither a screen reader nor a printed
              exhibit. The same sentence is put where both can reach it. */}
          <p className="sr-only" data-testid="rv-histo-summary">
            {`${formatCount(model.total)} event${
              model.total === 1 ? '' : 's'
            } in ${formatCount(model.bars.length)} bar${
              model.bars.length === 1 ? '' : 's'
            } of ${describeMs(model.step)} each, from ${utc(model.min)} to ${utc(model.max)} (start included, end excluded).` +
              (model.outsideBefore + model.outsideAfter > 0
                ? ` The axis is focused on where the events are; ${formatCount(
                    model.outsideBefore + model.outsideAfter,
                  )} further event${
                    model.outsideBefore + model.outsideAfter === 1 ? '' : 's'
                  } fall outside it, between ${utc(model.firstMs)} and ${utc(model.lastMs)}.`
                : '')}
          </p>
          <svg width={width} height={H} role="img" aria-label="Events over time">
            {model.bars.map((b, i) => {
              const h = (b.count / model.peak) * (plotH - 2)
              // The rescued share is drawn faintly at the top of its own bar, so
              // a bar standing mostly on assumed units cannot be read as a bar
              // standing on values read to contract.
              const rescuedH =
                b.rescued != null && b.count > 0
                  ? (b.rescued / model.peak) * (plotH - 2)
                  : 0
              return (
                <g key={b.startMs}>
                  <rect
                    x={i * bw}
                    y={0}
                    width={Math.max(bw, 0.5)}
                    height={plotH}
                    fill="transparent"
                  >
                    <title>{bucketTitle(b, model.step)}</title>
                  </rect>
                  {b.count > 0 && (
                    <rect
                      x={i * bw + 0.5}
                      y={plotH - h}
                      width={Math.max(bw - 1, 0.5)}
                      height={h}
                      className="rv-histo-bar"
                    />
                  )}
                  {rescuedH > 0 && (
                    <rect
                      x={i * bw + 0.5}
                      y={plotH - h}
                      width={Math.max(bw - 1, 0.5)}
                      height={rescuedH}
                      className="rv-histo-bar"
                      style={{ opacity: 0.35 }}
                    />
                  )}
                </g>
              )
            })}
            <line x1={0} y1={plotH} x2={width} y2={plotH} className="rv-axis" />
            {tickTimes(model.min, model.span).map((t) => {
              const x = ((t - model.min) / model.span) * width
              return (
                <g key={t}>
                  <line
                    x1={x}
                    y1={0}
                    x2={x}
                    y2={plotH}
                    className="rv-axis"
                    opacity={0.5}
                  />
                  <text
                    x={x}
                    y={H - 4}
                    className="rv-axis-text"
                    textAnchor="middle"
                  >
                    {axisLabel(t, model.span)}
                  </text>
                </g>
              )
            })}
            <text x={0} y={H - 4} className="rv-axis-text" textAnchor="start">
              {axisLabel(model.min, model.span)}
            </text>
            <text x={width} y={H - 4} className="rv-axis-text" textAnchor="end">
              {axisLabel(model.max, model.span)}
            </text>
          </svg>
        </>
      )}
      {/* An axis narrowed to where the events are must say so, and say how much
          it left out — a focused chart that reads as the whole range is the
          same falsehood as a truncated list that reads as complete. */}
      {model != null && model.outsideBefore + model.outsideAfter > 0 && (
        <p className="rv-note" role="note" data-testid="rv-histo-focus">
          Focused on {utc(model.min)} to {utc(model.max)}, where the events are.{' '}
          {model.outsideBefore > 0 &&
            `${formatCount(model.outsideBefore)} earlier event${
              model.outsideBefore === 1 ? '' : 's'
            } from ${utc(model.firstMs)}`}
          {model.outsideBefore > 0 && model.outsideAfter > 0 && ' and '}
          {model.outsideAfter > 0 &&
            `${formatCount(model.outsideAfter)} later event${
              model.outsideAfter === 1 ? '' : 's'
            } to ${utc(model.lastMs)}`}
          {' '}
          {model.outsideBefore + model.outsideAfter === 1 ? 'is' : 'are'} outside
          it and not drawn. They are counted, not discarded.
        </p>
      )}
      {model?.capped && (
        <p className="rv-note" role="note">
          Only the first {formatCount(MAX_BARS)} bars are drawn; later periods in
          this range are not drawn at all. Narrow the range to see them.
        </p>
      )}
      {note != null && (
        <p className="rv-note" role="note">
          {note}
        </p>
      )}
    </div>
  )
}

/**
 * A bucket width in words, for readers who cannot hover a tooltip.
 *
 * Rounded to the nearest whole unit and never named as a calendar unit: the
 * browser-bucketed path derives its width by dividing the span by the bar
 * count, so a bar is very rarely a whole day, and "1 day" would claim an
 * alignment the drawing does not have. The word "about" carries that.
 */
function describeMs(ms: number): string {
  const unit = (n: number, name: string) =>
    `about ${formatCount(n)} ${name}${n === 1 ? '' : 's'}`
  if (ms >= 86400_000) return unit(Math.round(ms / 86400_000), 'day')
  if (ms >= 3600_000) return unit(Math.round(ms / 3600_000), 'hour')
  if (ms >= 60_000) return unit(Math.round(ms / 60_000), 'minute')
  return unit(Math.max(Math.round(ms / 1000), 1), 'second')
}

/**
 * Volume over time, bucketed in the browser over the timestamps it was handed.
 *
 * `untimed` is how the caller says how many records in the SAME view carried no
 * readable time. It is optional because two of the three callers have no census
 * to give — and inventing a zero there would put "0 records carried no time" on
 * screen as a finding about the evidence — but where it is given, the number is
 * stated beside the bars. Dropping those records silently while the toolbar
 * beside the chart counted them left the figure an examiner reads as the
 * chart's total already short by an unstated amount.
 */
export function TimeHistogram({
  times,
  untimed,
  title,
  note,
}: {
  times: number[]
  /** Records in the same view that could not be placed in time. */
  untimed?: number
  title?: ReactNode
  note?: ReactNode
}) {
  const model = useMemo(() => {
    const ts = times.filter((t) => Number.isFinite(t)).sort((a, b) => a - b)
    if (ts.length === 0) return { buckets: [] as HistoBucket[], bucketMs: null }
    const min = ts[0]
    const max = ts[ts.length - 1]
    // A single instant, or several at the same instant, still has to be drawn
    // over a period rather than at a point: a zero-width bucket would put a
    // tooltip on screen naming one instant as the whole of the bar.
    const bucketMs = Math.max(max - min, 1) / BUCKET_TARGET
    const counts = new Array(BUCKET_TARGET).fill(0)
    for (const t of ts) {
      const i = Math.min(
        BUCKET_TARGET - 1,
        Math.floor((t - min) / bucketMs),
      )
      counts[i]++
    }
    return {
      bucketMs,
      buckets: counts.map((count, i) => ({
        startMs: min + i * bucketMs,
        count,
        // Everything here came through `toEpochMs`, which does not report the
        // footing it read a value on. Claiming zero rescues would be a claim
        // this path cannot support.
        rescued: null,
      })),
    }
  }, [times])

  const placed = times.filter((t) => Number.isFinite(t)).length

  /**
   * Why there are no bars, in the only terms this component can vouch for. With
   * a census in hand the two states are told apart; without one, it says only
   * what is true either way and does not guess which.
   */
  const empty =
    untimed === 0 ? (
      <>There are no records in view to place on a timeline.</>
    ) : untimed != null ? (
      <>
        No bars: all {formatCount(untimed)}{' '}
        {untimed === 1 ? 'record' : 'records'} in view carried no time this
        chart could read, so none of them can be placed. That is not a statement
        that nothing happened.
      </>
    ) : undefined

  const shortfall =
    untimed != null && untimed > 0 ? (
      <>
        {formatCount(placed)} {placed === 1 ? 'record is' : 'records are'} drawn
        above. A further {formatCount(untimed)}{' '}
        {untimed === 1 ? 'record' : 'records'} in this same view carried no time
        this chart could read and {untimed === 1 ? 'is' : 'are'} not on this
        chart at all — which is not a statement that{' '}
        {untimed === 1 ? 'it' : 'they'} did not happen.
      </>
    ) : null

  return (
    <EventHistogram
      buckets={model.buckets}
      bucketMs={model.bucketMs}
      title={title}
      empty={empty}
      note={
        shortfall != null || note != null ? (
          <>
            {shortfall}
            {shortfall != null && note != null ? ' ' : null}
            {note}
          </>
        ) : undefined
      }
    />
  )
}

// --- Top-N frequency bars for one dimension; clicking a row filters by it. ---

export interface TopItem {
  label: string
  count: number
}

/**
 * Bars drawn. Exported because a caller that ranks server-side has to ask the
 * server for exactly this many rows: asking for fewer leaves the list short of
 * what it can draw, and asking for more quietly discards rows the examiner was
 * told were in the answer.
 */
export const TOP_N = 8

export function TopBars({
  title,
  items,
  active,
  onSelect,
}: {
  title: string
  items: TopItem[]
  active: string | null
  onSelect: (label: string) => void
}) {
  const rows = useMemo(() => {
    const sorted = [...items].sort((a, b) => b.count - a.count)
    return sorted.slice(0, TOP_N)
  }, [items])

  if (rows.length === 0) return null
  const peak = Math.max(...rows.map((r) => r.count), 1)

  return (
    <div className="rv-top">
      <div className="rv-top-title">{title}</div>
      <ul className="rv-top-list">
        {rows.map((r) => (
          <li key={r.label}>
            <button
              type="button"
              className={`rv-top-row${active === r.label ? ' active' : ''}`}
              aria-pressed={active === r.label}
              onClick={() => onSelect(r.label)}
              title={r.label}
            >
              <span className="rv-top-bar" style={{ width: `${(r.count / peak) * 100}%` }} />
              <span className="rv-top-label">{r.label}</span>
              <span className="rv-top-count">{formatCount(r.count)}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
