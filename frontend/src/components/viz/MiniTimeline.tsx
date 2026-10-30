import type { HistogramBucket } from '../../pages/timeline/api'
import { formatCount } from '../../lib/format'
// One implementation of the outlier-focus rule, shared by every time chart
// (UI-007). Re-exported so existing importers of this module keep working.
import { focusWindow } from '../../lib/focusWindow'
export { focusWindow }
import './miniTimeline.css'

/**
 * Expand the server's sparse histogram (empty buckets omitted) into a dense
 * array of counts across `[minTs, maxTs]`, one slot per `bucketSeconds`, so the
 * bars sit at their true time position and gaps read as gaps. Capped at 500
 * slots to bound DOM size.
 */
export function gridStart(
  buckets: HistogramBucket[],
  minTs: number,
  bucketSeconds: number,
): number {
  if (bucketSeconds <= 0) return minTs
  let anchor = minTs
  for (const b of buckets) {
    // The server aligns every bucket start to an absolute multiple of the
    // bucket width, so the bucket CONTAINING the first event usually starts
    // before it. Anchoring the grid on the event's own timestamp put that
    // bucket at index -1 and dropped it — the earliest events in the case,
    // reported to the examiner as "beyond the charted range" (UI-027). A start
    // within one width below the first event is that bucket; anything earlier
    // is genuinely outside the range and stays outside.
    if (b.start < anchor && b.start > minTs - bucketSeconds) anchor = b.start
  }
  return anchor
}

export function densify(
  buckets: HistogramBucket[],
  minTs: number,
  maxTs: number,
  bucketSeconds: number,
): number[] {
  if (bucketSeconds <= 0 || maxTs < minTs) {
    return buckets.map((b) => b.count)
  }
  const start = gridStart(buckets, minTs, bucketSeconds)
  const raw = Math.floor((maxTs - start) / bucketSeconds) + 1
  const n = Math.max(1, Math.min(raw, 500))
  const arr = new Array(n).fill(0)
  for (const b of buckets) {
    const idx = Math.floor((b.start - start) / bucketSeconds)
    if (idx >= 0 && idx < n) arr[idx] += b.count
  }
  return arr
}

function fmtDate(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toISOString().slice(0, 10)
}

/**
 * Compact event-density bar for a case's whole timeline.
 *
 * Display-only by default. Pass `onSelect` and each bar becomes a button that
 * names its own range and hands it back — which is what turns this chart into
 * the case-wide time-window control (ROADMAP §1.1). One component rather than
 * two, for the reason `CONVENTIONS.md` gives: two copies of the focus-window
 * and densify rules is two chances for the dashboard and the persistent bar to
 * describe one case differently.
 *
 * `selected` shades the bars inside the window in force, so the control shows
 * its own state on the axis it set it on.
 */
export function MiniTimeline({
  buckets,
  minTs,
  maxTs,
  bucketSeconds,
  onSelect,
  selected,
}: {
  buckets: HistogramBucket[]
  minTs: number | null
  maxTs: number | null
  bucketSeconds: number | null
  /** Called with the bucket's own range, in unix seconds. */
  onSelect?: (from: number, to: number) => void
  /** The window in force, so the bars inside it can be shaded. */
  selected?: { from: number; to: number } | null
}) {
  if (buckets.length === 0 || minTs == null || maxTs == null) {
    return <div className="mtl-empty">No dated events</div>
  }
  const bs = bucketSeconds ?? 0
  const dense = densify(buckets, minTs, maxTs, bs)
  const total = buckets.reduce((s, b) => s + b.count, 0)

  // Focus on where the events actually are; a few outlier timestamps must not
  // squash the whole chart into one bar. With no usable bucket width there is
  // no time axis to focus along, so the whole range is shown as-is.
  const { lo, hi, before, after } =
    bs > 0
      ? focusWindow(dense)
      : { lo: 0, hi: dense.length - 1, before: 0, after: 0 }
  const shown = dense.slice(lo, hi + 1)
  const max = Math.max(1, ...shown)
  // The same anchor the bars were placed on, or the axis would name a time the
  // first bar does not start at.
  const gridTs = gridStart(buckets, minTs, bs)
  const focusedStart = bs > 0 ? gridTs + lo * bs : minTs
  // Never past the last event: the final bucket's nominal end can overshoot
  // `maxTs` by up to one bucket width, and an axis label naming a date after
  // anything in the case is a small falsehood on a screen that gets quoted.
  const focusedEnd = bs > 0 ? Math.min(maxTs, gridTs + (hi + 1) * bs) : maxTs
  // `densify` caps at 500 slots, so on a very wide span the tail buckets are
  // not represented at all. Those events are outside the drawn range too, and
  // the note must account for them or it reads as a complete accounting.
  const capped = Math.max(0, total - dense.reduce((s, c) => s + c, 0))
  const trimmed = before + after + capped
  const parts: string[] = []
  if (before > 0) parts.push(`${formatCount(before)} before ${fmtDate(focusedStart)}`)
  if (after > 0) parts.push(`${formatCount(after)} after ${fmtDate(focusedEnd)}`)
  if (capped > 0) parts.push(`${formatCount(capped)} beyond the charted range`)
  const trimmedNote =
    trimmed > 0
      ? `${formatCount(trimmed)} event${trimmed === 1 ? '' : 's'} outside this range` +
        (parts.length ? ` (${parts.join(', ')})` : '')
      : null

  return (
    <div className="mtl">
      <div
        // The windowed class is set here rather than inferred with `:has()`:
        // the default appearance of every chart in the product must not depend
        // on a selector, and a browser that did not support it would fade
        // every bar on the dashboard.
        className={selected != null ? 'mtl-bars mtl-bars-windowed' : 'mtl-bars'}
        role="img"
        aria-label={
          `${formatCount(total)} events from ${fmtDate(minTs)} to ${fmtDate(maxTs)}` +
          (trimmedNote ? `; view focused on ${fmtDate(focusedStart)}–${fmtDate(focusedEnd)}, ${trimmedNote}` : '')
        }
      >
        {shown.map((count, i) => {
          // The bucket's real range, from the same anchor the bars were placed
          // on. With no usable bucket width there is no range to hand back.
          const barFrom = bs > 0 ? gridTs + (lo + i) * bs : minTs
          const barTo = bs > 0 ? Math.min(maxTs, gridTs + (lo + i + 1) * bs) : maxTs
          const inWindow =
            selected != null && barTo >= selected.from && barFrom <= selected.to
          const className = inWindow ? 'mtl-bar mtl-bar-in' : 'mtl-bar'
          const height = `${(count / max) * 100}%`
          if (!onSelect || bs <= 0) {
            return (
              <span
                key={i}
                className={className}
                style={{ height }}
                title={count > 0 ? `${formatCount(count)} events` : undefined}
              />
            )
          }
          return (
            <button
              key={i}
              type="button"
              className={`${className} mtl-bar-pick`}
              style={{ height }}
              aria-pressed={inWindow}
              title={`${fmtDate(barFrom)} — ${formatCount(count)} event${
                count === 1 ? '' : 's'
              }`}
              aria-label={`Narrow the case to ${fmtDate(barFrom)}: ${formatCount(
                count,
              )} event${count === 1 ? '' : 's'}`}
              onClick={() => onSelect(barFrom, barTo)}
            />
          )
        })}
      </div>
      <div className="mtl-axis mono">
        <span>{fmtDate(focusedStart)}</span>
        <span>{fmtDate(focusedEnd)}</span>
      </div>
      {/* The outliers are disclosed, never silently dropped: the axis shows the
          focused range and this says how many events fall outside it. */}
      {trimmedNote && <div className="mtl-outliers mono">{trimmedNote}</div>}
    </div>
  )
}
