import { useEffect, useMemo, useRef, useState } from 'react'
import { rampSampler } from '../../lib/themeRamp'
import { useThemeVersion } from '../../themes/useThemeVersion'
import { formatBytes, formatCount } from '../../lib/format'
import type { AllocationMapResponse } from './api'
import { VizTooltip, type TipState } from './Tooltip'
import { useMeasuredWidth } from './useMeasuredWidth'
import './viz.css'

const CELL = 8
const GAP = 2
const PITCH = CELL + GAP

// The ramp runs from the quietest surface (free space recedes) to the accent
// (fully allocated), shared with the activity heatmap so the two cannot drift
// into two legends that mean different things. It used to be two hardcoded RGB
// triples — the dark palette's, frozen where no lint could see them.
//
// `rampSampler` and not `rampColor`, because this is a CANVAS: a 2D context has
// no element to resolve `var()` against, so a `color-mix(… var(--accent) …)`
// string is not a parsable colour there, the `fillStyle` assignment is a no-op,
// and every cell paints in whatever the context last held — `#000000` on a
// freshly sized canvas. The sampler reads the same two tokens through
// `getComputedStyle` and interpolates them here.
//
// Resolved once per draw, not per cell: `getComputedStyle` is a layout read and
// a disk map has tens of thousands of cells.

function decodeBitmap(b64: string): Uint8Array {
  try {
    const bin = atob(b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return bytes
  } catch {
    return new Uint8Array(0)
  }
}

export interface AllocationMapProps {
  data: AllocationMapResponse
}

/**
 * Cluster-allocation grid: one cell per bitmap bucket, brightness maps
 * the allocated fraction from near-surface to accent. Canvas-rendered
 * and device-pixel-ratio aware.
 */
export function AllocationMap({ data }: AllocationMapProps) {
  const bytes = useMemo(
    () => decodeBitmap(data.allocation_bitmap_b64),
    [data.allocation_bitmap_b64],
  )
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const themeVersion = useThemeVersion()
  const [tip, setTip] = useState<TipState | null>(null)

  const cols = Math.max(1, Math.floor((width + GAP) / PITCH))
  const rows = Math.max(1, Math.ceil(bytes.length / cols))
  const cssHeight = rows * PITCH - GAP

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || bytes.length === 0) return
    const dpr = window.devicePixelRatio || 1
    canvas.width = Math.round(width * dpr)
    canvas.height = Math.round(cssHeight * dpr)
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    ctx.scale(dpr, dpr)
    ctx.clearRect(0, 0, width, cssHeight)
    const cellColor = rampSampler(canvas)
    for (let i = 0; i < bytes.length; i++) {
      const col = i % cols
      const row = Math.floor(i / cols)
      ctx.fillStyle = cellColor(bytes[i] / 255)
      ctx.fillRect(col * PITCH, row * PITCH, CELL, CELL)
    }
    // `themeVersion` is a dependency because the ramp is read from the
    // document: a canvas holds pixels, not a live style, so it re-resolves
    // nothing when the tokens change and would keep the previous skin's colours
    // until something else forced a redraw. Watching the document rather than
    // the provider means this catches every route a theme can change by, and
    // means this chart does not require a provider to render at all.
  }, [bytes, width, cols, cssHeight, themeVersion])

  if (bytes.length === 0) {
    return <div className="viz-empty">No allocation data.</div>
  }

  const bucketBytes =
    data.allocation_clusters_per_bucket * data.allocation_cluster_size

  const onMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current
    const host = ref.current
    if (!canvas || !host) return
    const rect = canvas.getBoundingClientRect()
    const px = e.clientX - rect.left
    const py = e.clientY - rect.top
    const col = Math.floor(px / PITCH)
    const row = Math.floor(py / PITCH)
    const idx = row * cols + col
    if (col < 0 || col >= cols || idx < 0 || idx >= bytes.length) {
      setTip(null)
      return
    }
    const cpb = data.allocation_clusters_per_bucket
    const clusterStart = idx * cpb
    const clusterEnd =
      Math.min(clusterStart + cpb, data.allocation_total_clusters) - 1
    const byteStart = clusterStart * data.allocation_cluster_size
    const byteEnd = (clusterEnd + 1) * data.allocation_cluster_size - 1
    const hostRect = host.getBoundingClientRect()
    setTip({
      x: Math.min(e.clientX - hostRect.left + 12, Math.max(width - 240, 0)),
      y: e.clientY - hostRect.top + 14,
      lines: [
        `bucket ${formatCount(idx)} · ${Math.round((bytes[idx] / 255) * 100)}% allocated`,
        `clusters ${formatCount(clusterStart)}–${formatCount(clusterEnd)}`,
        `bytes ${formatCount(byteStart)}–${formatCount(byteEnd)}`,
      ],
    })
  }

  return (
    <div className="viz-alloc" ref={ref}>
      <canvas
        ref={canvasRef}
        style={{ height: cssHeight }}
        role="img"
        aria-label="Cluster allocation map"
        onMouseMove={onMove}
        onMouseLeave={() => setTip(null)}
      />
      <div className="viz-alloc-legend">
        <span>free</span>
        <span className="viz-alloc-ramp" aria-hidden="true" />
        <span>allocated</span>
        <span className="viz-alloc-note">
          each cell ≈ {formatBytes(bucketBytes)}
        </span>
      </div>
      <VizTooltip tip={tip} />
    </div>
  )
}
