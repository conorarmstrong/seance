import { useMemo } from 'react'
import { useMeasuredWidth } from '../../components/viz/useMeasuredWidth'
import '../../components/viz/viz.css'
import type { FileSizeBucket } from './api'
import { humanizeArtifactTypePlural } from './labels'
import { formatCount } from '../../lib/format'

// ---- Shared geometry helpers ----

/** Horizontal bar: square at the baseline (left), 4px rounded data end. */
function barPathRight(x: number, y: number, w: number, h: number): string {
  const r = Math.min(4, w / 2, h / 2)
  return (
    `M ${x} ${y} h ${w - r} a ${r} ${r} 0 0 1 ${r} ${r} ` +
    `v ${h - 2 * r} a ${r} ${r} 0 0 1 ${-r} ${r} h ${-(w - r)} z`
  )
}

/** Vertical column: square at the baseline (bottom), rounded cap. */
function colPathUp(x: number, y: number, w: number, h: number): string {
  if (h <= 0) return ''
  const r = Math.min(3, w / 2, h)
  return (
    `M ${x} ${y + h} v ${-(h - r)} a ${r} ${r} 0 0 1 ${r} ${-r} ` +
    `h ${w - 2 * r} a ${r} ${r} 0 0 1 ${r} ${r} v ${h - r} z`
  )
}

function niceCeil(v: number): number {
  if (v <= 0) return 1
  const pow = 10 ** Math.floor(Math.log10(v))
  const m = v / pow
  const nice = m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10
  return nice * pow
}

// ---- Artifact type bars ----

const MAX_TYPE_ROWS = 8

export function TypeBarChart({ counts }: { counts: Record<string, number> }) {
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()

  const rows = useMemo(() => {
    const entries = Object.entries(counts).sort(([, a], [, b]) => b - a)
    const top = entries
      .slice(0, MAX_TYPE_ROWS)
      .map(([type, count]) => ({
        label: humanizeArtifactTypePlural(type),
        count,
      }))
    const rest = entries
      .slice(MAX_TYPE_ROWS)
      .reduce((sum, [, c]) => sum + c, 0)
    if (rest > 0) top.push({ label: 'Other', count: rest })
    return top
  }, [counts])

  if (rows.length === 0) {
    return <div className="viz-empty">No artifacts yet.</div>
  }

  const ROW_H = 22
  const BAR_H = 14
  const LABEL_W = 150
  const COUNT_W = 64
  const plotW = Math.max(40, width - LABEL_W - COUNT_W - 16)
  const max = Math.max(...rows.map((r) => r.count))
  const height = rows.length * ROW_H

  return (
    <div ref={ref}>
      <svg width={width} height={height} role="img" aria-label="Artifacts by type">
        <line
          x1={LABEL_W + 8.5}
          y1={0}
          x2={LABEL_W + 8.5}
          y2={height}
          className="viz-gridline"
        />
        {rows.map((row, i) => {
          const w = Math.max(2, (row.count / max) * plotW)
          const y = i * ROW_H + (ROW_H - BAR_H) / 2
          const midY = i * ROW_H + ROW_H / 2 + 3.5
          return (
            <g key={row.label}>
              <title>{`${row.label}: ${formatCount(row.count)}`}</title>
              <text
                className="viz-bar-label"
                x={LABEL_W}
                y={midY}
                textAnchor="end"
              >
                {row.label}
              </text>
              <path d={barPathRight(LABEL_W + 9, y, w, BAR_H)} fill="var(--viz-series)" />
              <text className="viz-bar-value" x={LABEL_W + 9 + w + 6} y={midY}>
                {formatCount(row.count)}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

// ---- File size distribution ----

const SIZE_SUFFIX = ['B', 'K', 'M', 'G', 'T', 'P', 'E']

/** pow2 exponent -> compact size label: 10 -> "1K", 16 -> "64K". */
export function sizeBucketLabel(pow2: number): string {
  const i = Math.floor(pow2 / 10)
  const rem = pow2 - i * 10
  return `${2 ** rem}${SIZE_SUFFIX[i] ?? '?'}`
}

export function FileSizeColumns({ buckets }: { buckets: FileSizeBucket[] }) {
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()

  const series = useMemo(() => {
    if (buckets.length === 0) return []
    const byPow = new Map(buckets.map((b) => [b.pow2, b.count]))
    const pows = [...byPow.keys()]
    const min = Math.min(...pows)
    const max = Math.max(...pows)
    const out: { pow2: number; count: number }[] = []
    for (let p = min; p <= max; p++) {
      out.push({ pow2: p, count: byPow.get(p) ?? 0 })
    }
    return out
  }, [buckets])

  const total = series.reduce((sum, b) => sum + b.count, 0)
  if (series.length === 0 || total === 0) {
    return <div className="viz-empty">No file size data.</div>
  }

  const TOP = 14
  const PLOT_H = 110
  const AXIS_H = 18
  const Y_LABEL_W = 44
  const height = TOP + PLOT_H + AXIS_H
  const plotW = Math.max(40, width - Y_LABEL_W - 4)
  const pitch = plotW / series.length
  const colW = Math.max(2, Math.min(20, pitch - 2))
  const maxCount = Math.max(...series.map((b) => b.count))
  const yMax = niceCeil(maxCount)
  const yFor = (v: number) => TOP + PLOT_H * (1 - v / yMax)
  const labelStep = Math.max(1, Math.ceil(series.length / Math.floor(plotW / 36)))
  const maxIndex = series.findIndex((b) => b.count === maxCount)

  return (
    <div ref={ref}>
      <svg width={width} height={height} role="img" aria-label="File size distribution">
        {[yMax, yMax / 2].map((v) => (
          <g key={v}>
            <line
              x1={Y_LABEL_W}
              y1={yFor(v)}
              x2={width}
              y2={yFor(v)}
              className="viz-gridline"
            />
            <text
              className="viz-axis-text"
              x={Y_LABEL_W - 6}
              y={yFor(v) + 3}
              textAnchor="end"
            >
              {formatCount(v)}
            </text>
          </g>
        ))}
        <line
          x1={Y_LABEL_W}
          y1={TOP + PLOT_H + 0.5}
          x2={width}
          y2={TOP + PLOT_H + 0.5}
          className="viz-gridline"
        />
        {series.map((bucket, i) => {
          const x = Y_LABEL_W + i * pitch + (pitch - colW) / 2
          const h = (bucket.count / yMax) * PLOT_H
          const label = sizeBucketLabel(bucket.pow2)
          return (
            <g key={bucket.pow2}>
              <title>{`${label}–${sizeBucketLabel(bucket.pow2 + 1)}: ${formatCount(bucket.count)} files`}</title>
              {bucket.count > 0 && (
                <path
                  d={colPathUp(x, TOP + PLOT_H - h, colW, h)}
                  fill="var(--viz-series)"
                />
              )}
              {i === maxIndex && (
                <text
                  className="viz-bar-value"
                  x={x + colW / 2}
                  y={TOP + PLOT_H - h - 4}
                  textAnchor="middle"
                >
                  {formatCount(bucket.count)}
                </text>
              )}
              {i % labelStep === 0 && (
                <text
                  className="viz-axis-text"
                  x={x + colW / 2}
                  y={TOP + PLOT_H + 13}
                  textAnchor="middle"
                >
                  {label}
                </text>
              )}
            </g>
          )
        })}
      </svg>
    </div>
  )
}
