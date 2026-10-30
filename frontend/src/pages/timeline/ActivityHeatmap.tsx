import { useMemo, useState } from 'react'
import { useMeasuredWidth } from '../../components/viz/useMeasuredWidth'
import { VizTooltip, type TipState } from '../../components/viz/Tooltip'
import type { TimelineActivity } from './api'
import { formatCount } from '../../lib/format'
import { rampColor } from '../../lib/themeRamp'

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const LABEL_W = 34
const TOP_H = 16
const GAP = 1
const MIN_CELL = 7

function cellColor(count: number, max: number): string {
  if (count <= 0 || max <= 0) return 'var(--viz-alloc-lo)'
  // sqrt so low-but-nonzero cells stay visible against a busy hour.
  // The ramp itself is `rampColor`'s, shared with the allocation map: the two
  // used to hold identical hardcoded copies of the dark palette's endpoints.
  return rampColor(Math.sqrt(count / max))
}

/**
 * Pattern-of-life heatmap: a 7x24 grid of event counts by weekday and hour of
 * day (UTC). Brighter cells are busier. Reveals working hours, overnight
 * automation, and quiet periods at a glance.
 */
export function ActivityHeatmap({ data }: { data?: TimelineActivity }) {
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()
  const [tip, setTip] = useState<TipState | null>(null)

  const grid = useMemo(() => {
    const m = Array.from({ length: 7 }, () => new Array<number>(24).fill(0))
    for (const c of data?.cells ?? []) {
      if (c.dow >= 0 && c.dow < 7 && c.hour >= 0 && c.hour < 24) {
        m[c.dow][c.hour] = c.count
      }
    }
    return m
  }, [data])

  if (!data || data.total === 0) {
    return <div className="viz-empty">No timestamped events to chart.</div>
  }

  const max = data.max
  const gridW = Math.max(width - LABEL_W, 24 * (MIN_CELL + GAP))
  const cell = gridW / 24
  const height = TOP_H + 7 * (cell + GAP)

  const showTip =
    (dow: number, hour: number, count: number) =>
    (e: React.MouseEvent<SVGRectElement>) => {
      const host = ref.current
      if (!host) return
      const rect = host.getBoundingClientRect()
      setTip({
        x: Math.min(e.clientX - rect.left + 12, Math.max(width - 200, 0)),
        y: e.clientY - rect.top + 14,
        lines: [
          `${DAYS[dow]} ${String(hour).padStart(2, '0')}:00 UTC`,
          `${formatCount(count)} event${count === 1 ? '' : 's'}`,
        ],
      })
    }

  return (
    <div className="tl-heatmap" ref={ref}>
      <svg width={width} height={height} role="img" aria-label="Activity by weekday and hour">
        {/* Hour labels every 3 hours. */}
        {Array.from({ length: 24 }, (_, h) =>
          h % 3 === 0 ? (
            <text
              key={`h${h}`}
              className="viz-axis-text"
              x={LABEL_W + h * cell + cell / 2}
              y={11}
              textAnchor="middle"
            >
              {h}
            </text>
          ) : null,
        )}
        {DAYS.map((day, d) => (
          <text
            key={day}
            className="viz-axis-text"
            x={LABEL_W - 6}
            y={TOP_H + d * (cell + GAP) + cell / 2 + 3}
            textAnchor="end"
          >
            {day}
          </text>
        ))}
        {grid.map((row, d) =>
          row.map((count, h) => (
            <rect
              key={`${d}-${h}`}
              x={LABEL_W + h * cell}
              y={TOP_H + d * (cell + GAP)}
              width={Math.max(cell - GAP, 1)}
              height={Math.max(cell - GAP, 1)}
              rx={1.5}
              fill={cellColor(count, max)}
              className="tl-heatmap-cell"
              onMouseMove={showTip(d, h, count)}
              onMouseLeave={() => setTip(null)}
            />
          )),
        )}
      </svg>
      <div className="tl-heatmap-legend">
        <span>Quiet</span>
        <span className="tl-heatmap-ramp" aria-hidden="true" />
        <span>Busy</span>
        <span className="tl-heatmap-note">Hour of day (UTC) · {formatCount(data.total)} events</span>
      </div>
      <VizTooltip tip={tip} />
    </div>
  )
}
