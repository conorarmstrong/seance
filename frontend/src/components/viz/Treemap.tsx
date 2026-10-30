import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatBytes, formatCount } from '../../lib/format'
import { getDirSizes, type DirSizeChild } from './api'
import { VizTooltip, type TipState } from './Tooltip'
import { useMeasuredWidth } from './useMeasuredWidth'
import './viz.css'

const HEIGHT = 420
const PAD = 2
const MAX_TILES = 80


interface Rect {
  child: DirSizeChild
  x: number
  y: number
  w: number
  h: number
}

// --- Squarified treemap layout (Bruls, Huizing, van Wijk 2000). Lays children
// out largest-first, packing rows along the shorter side to keep tiles close to
// square. Values are pre-scaled so their areas fill the container exactly. ---

function worstRatio(row: number[], side: number): number {
  const sum = row.reduce((a, b) => a + b, 0)
  const max = Math.max(...row)
  const min = Math.min(...row)
  const s2 = sum * sum
  const side2 = side * side
  return Math.max((side2 * max) / s2, s2 / (side2 * min))
}

function squarify(children: DirSizeChild[], width: number, height: number): Rect[] {
  // Zero-byte entries have no area to lay out; excluding them also avoids a
  // degenerate all-zero row (thickness 0 -> NaN tile dimensions).
  const items = children.filter((c) => c.size > 0)
  const total = items.reduce((s, c) => s + c.size, 0)
  if (total <= 0 || width <= 0 || height <= 0) return []
  const scale = (width * height) / total
  const areas = items.map((c) => c.size * scale)

  const rects: Rect[] = []
  let x = 0
  let y = 0
  let w = width
  let h = height
  let i = 0
  const n = items.length

  while (i < n) {
    const side = Math.min(w, h)
    // Grow the row [i, i+len) while adding the next tile does not worsen the
    // worst aspect ratio in the row.
    const row: number[] = [areas[i]]
    let len = 1
    while (i + len < n) {
      const next = areas[i + len]
      if (worstRatio([...row, next], side) > worstRatio(row, side)) break
      row.push(next)
      len++
    }

    const rowSum = row.reduce((a, b) => a + b, 0)
    const thickness = rowSum / side // consumed from the longer side
    if (w < h) {
      // Horizontal strip across the top; tiles run left-to-right.
      let cx = x
      for (let r = 0; r < len; r++) {
        const tileW = row[r] / thickness
        rects.push({ child: items[i + r], x: cx, y, w: tileW, h: thickness })
        cx += tileW
      }
      y += thickness
      h -= thickness
    } else {
      // Vertical strip down the left; tiles run top-to-bottom.
      let cy = y
      for (let r = 0; r < len; r++) {
        const tileH = row[r] / thickness
        rects.push({ child: items[i + r], x, y: cy, w: thickness, h: tileH })
        cy += tileH
      }
      x += thickness
      w -= thickness
    }
    i += len
  }

  return rects
}

function crumbs(path: string): { label: string; path: string }[] {
  const out = [{ label: 'root', path: '' }]
  const parts = path.split('/').filter(Boolean)
  let acc = ''
  for (const p of parts) {
    acc += `/${p}`
    out.push({ label: p, path: acc })
  }
  return out
}

function labelFits(text: string, w: number, h: number): boolean {
  return w > text.length * 6.6 + 10 && h > 16
}

export interface TreemapProps {
  caseId: string
  sourceId: string
}

/**
 * Interactive size treemap of a filesystem: each tile is a directory or file,
 * area proportional to bytes. Click a directory to drill in; the breadcrumb
 * walks back up. Data is fetched one level at a time, so a huge filesystem
 * never loads whole.
 */
export function Treemap({ caseId, sourceId }: TreemapProps) {
  const [path, setPath] = useState('')
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()
  const [tip, setTip] = useState<TipState | null>(null)

  const query = useQuery({
    queryKey: ['dir-sizes', caseId, sourceId, path],
    queryFn: () => getDirSizes(caseId, sourceId, path),
  })

  const children = useMemo(() => {
    const items = query.data?.children ?? []
    if (items.length <= MAX_TILES) return items
    // Collapse the long tail into a single "(smaller items)" tile.
    const head = items.slice(0, MAX_TILES - 1)
    const tail = items.slice(MAX_TILES - 1)
    const rest = tail.reduce((s, c) => s + c.size, 0)
    return [
      ...head,
      {
        name: `(${tail.length} smaller items)`,
        path: '',
        size: rest,
        file_count: tail.reduce((s, c) => s + c.file_count, 0),
        is_dir: false,
      },
    ]
  }, [query.data])

  const rects = useMemo(
    () => squarify(children, Math.max(width, 1), HEIGHT),
    [children, width],
  )

  const showTip =
    (child: DirSizeChild) => (e: React.MouseEvent<SVGGElement>) => {
      const host = ref.current
      if (!host) return
      const rect = host.getBoundingClientRect()
      const kind = child.is_dir ? 'directory' : 'file'
      setTip({
        x: Math.min(e.clientX - rect.left + 12, Math.max(width - 220, 0)),
        y: e.clientY - rect.top + 14,
        lines: [
          child.name,
          kind,
          formatBytes(child.size),
          `${formatCount(child.file_count)} file${child.file_count === 1 ? '' : 's'}`,
        ],
      })
    }

  return (
    <div className="viz-treemap" ref={ref}>
      <nav className="viz-tm-crumbs" aria-label="Path">
        {crumbs(path).map((c, i, all) => (
          <span key={c.path}>
            <button
              type="button"
              className="viz-tm-crumb"
              disabled={i === all.length - 1}
              onClick={() => setPath(c.path)}
            >
              {c.label}
            </button>
            {i < all.length - 1 && <span className="viz-tm-sep">/</span>}
          </span>
        ))}
      </nav>

      {query.isPending && <div className="viz-empty">Loading sizes…</div>}
      {query.isError && (
        <div className="viz-empty">Could not load directory sizes.</div>
      )}
      {query.isSuccess && rects.length === 0 && (
        <div className="viz-empty">No sized files under this path.</div>
      )}

      {rects.length > 0 && (
        <svg width={width} height={HEIGHT} role="group" aria-label="Size treemap">
          {rects.map(({ child, x, y, w, h }) => {
            const drillable = child.is_dir && child.path
            return (
              <g
                key={child.path || child.name}
                className={drillable ? 'viz-tm-tile drillable' : 'viz-tm-tile'}
                role={drillable ? 'button' : undefined}
                tabIndex={drillable ? 0 : undefined}
                aria-label={`${child.name}, ${formatBytes(child.size)}`}
                onClick={() => drillable && setPath(child.path)}
                onKeyDown={(e) => {
                  if (drillable && (e.key === 'Enter' || e.key === ' ')) {
                    e.preventDefault()
                    setPath(child.path)
                  }
                }}
                onMouseMove={showTip(child)}
                onMouseLeave={() => setTip(null)}
              >
                <rect
                  x={x + PAD / 2}
                  y={y + PAD / 2}
                  width={Math.max(w - PAD, 0)}
                  height={Math.max(h - PAD, 0)}
                  rx={2}
                  className={child.is_dir ? 'viz-tm-dir' : 'viz-tm-file'}
                />
                {labelFits(child.name, w, h) && (
                  <text className="viz-tm-label" x={x + 6} y={y + 15}>
                    {child.name}
                  </text>
                )}
              </g>
            )
          })}
        </svg>
      )}
      <VizTooltip tip={tip} />
    </div>
  )
}
