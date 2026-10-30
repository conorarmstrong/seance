import { useId, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { formatBytes, formatCount } from '../../lib/format'
import type { DiskMapRegion, DiskMapResponse } from './api'
import { VizTooltip, type TipState } from './Tooltip'
import { useMeasuredWidth } from './useMeasuredWidth'
import './viz.css'

const STRIP_H = 64
const RULER_Y = STRIP_H + 9
const SVG_H = STRIP_H + 32
const MIN_W = 8
const GAP = 2


interface Block {
  region: DiskMapRegion
  fs: DiskMapRegion | undefined
  x: number
  w: number
  enlarged: boolean
}

/**
 * Proportional layout with a minimum visible width for tiny regions.
 * Clamped regions steal width from the rest; they carry an "enlarged"
 * flag so the strip can mark them as not-to-scale.
 */
function layoutBlocks(
  regions: DiskMapRegion[],
  totalBytes: number,
  width: number,
): Block[] {
  const tops = regions.filter((r) => r.artifact_type !== 'FileSystem')
  const fsByParent = new Map(
    regions
      .filter((r) => r.artifact_type === 'FileSystem')
      .map((r) => [r.parent_id, r] as const),
  )
  if (tops.length === 0) return []
  const usable = Math.max(width - GAP * (tops.length - 1), MIN_W * tops.length)
  const total =
    totalBytes > 0
      ? totalBytes
      : tops.reduce((sum, r) => sum + r.size_bytes, 0) || 1
  const raw = tops.map((r) => (r.size_bytes / total) * usable)
  const clamped = raw.map((w) => w < MIN_W)
  const fixed = clamped.filter(Boolean).length * MIN_W
  const freeRaw = raw.reduce((sum, w, i) => sum + (clamped[i] ? 0 : w), 0)
  const scale = freeRaw > 0 ? Math.max(usable - fixed, 0) / freeRaw : 0
  let x = 0
  return tops.map((region, i) => {
    const w = clamped[i] ? MIN_W : Math.max(raw[i] * scale, 1)
    const block: Block = {
      region,
      fs: fsByParent.get(region.artifact_id),
      x,
      w,
      enlarged: clamped[i],
    }
    x += w + GAP
    return block
  })
}

function regionKind(r: DiskMapRegion): string {
  if (r.artifact_type === 'UnallocatedSpace') return 'Unallocated space'
  if (r.artifact_type === 'FileSystem') return 'File system'
  return 'Partition'
}

/**
 * A region's name, or what it is when the server did not give it one.
 *
 * APFS volume regions come back unnamed. The response type declared `name` as
 * `string`, so consumers interpolated it directly and produced "null — file
 * system" in tooltips and aria-labels (LIVE-018).
 */
function regionName(r: DiskMapRegion): string {
  return r.name?.trim() || regionKind(r)
}

function tipLines(r: DiskMapRegion, enlarged: boolean): string[] {
  const meta = [regionKind(r), r.scheme, r.fs_type].filter(Boolean).join(' · ')
  const lines = [
    regionName(r),
    meta,
    `offset ${formatCount(r.offset_bytes)} B`,
    `size ${formatBytes(r.size_bytes)} (${formatCount(r.size_bytes)} B)`,
  ]
  if (enlarged) lines.push('enlarged to stay visible — not to scale')
  return lines
}

// Approximate mono glyph width at 10px; used to decide if a label fits.
function labelFits(text: string, w: number): boolean {
  return text.length * 6.4 + 14 <= w
}

export interface DiskMapProps {
  caseId: string
  data: DiskMapResponse
}

/**
 * Proportional horizontal strip of a source's partitions and
 * unallocated gaps, with filesystems rendered as the inner fill of
 * their parent partition. Click navigates to the region's artifact.
 */
export function DiskMap({ caseId, data }: DiskMapProps) {
  const navigate = useNavigate()
  const patternId = useId()
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()
  const [tip, setTip] = useState<TipState | null>(null)

  const blocks = useMemo(
    () => layoutBlocks(data.regions, data.total_bytes, width),
    [data, width],
  )

  if (blocks.length === 0) {
    return <div className="viz-empty">No layout information for this source.</div>
  }

  const goTo = (artifactId: string) =>
    navigate(`/cases/${caseId}/artifacts/${artifactId}`)

  // A file system opens in the lazy file tree, not its (flat, huge) artifact page.
  const goToFiles = (artifactId: string) =>
    navigate(`/cases/${caseId}/files/${artifactId}?view=tree`)

  const activateOn =
    (go: (id: string) => void, artifactId: string) =>
    (e: React.KeyboardEvent<SVGGElement>) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        go(artifactId)
      }
    }
  const keyActivate = (artifactId: string) => activateOn(goTo, artifactId)
  const keyActivateFiles = (artifactId: string) =>
    activateOn(goToFiles, artifactId)

  const showTip =
    (region: DiskMapRegion, enlarged: boolean) =>
    (e: React.MouseEvent<SVGGElement>) => {
      const host = ref.current
      if (!host) return
      const rect = host.getBoundingClientRect()
      const x = Math.min(e.clientX - rect.left + 12, Math.max(width - 220, 0))
      setTip({ x, y: e.clientY - rect.top + 14, lines: tipLines(region, enlarged) })
    }

  const hideTip = () => setTip(null)

  const ticks = [0, 0.25, 0.5, 0.75, 1]

  return (
    <div className="viz-diskmap" ref={ref}>
      <svg
        width={width}
        height={SVG_H}
        role="group"
        aria-label="Disk layout map"
      >
        <defs>
          <pattern
            id={patternId}
            width="6"
            height="6"
            patternUnits="userSpaceOnUse"
            patternTransform="rotate(45)"
          >
            <rect width="6" height="6" fill="var(--viz-unalloc-base)" />
            <line x1="0" y1="0" x2="0" y2="6" stroke="var(--viz-hatch)" strokeWidth="1" />
          </pattern>
        </defs>

        {blocks.map(({ region, fs, x, w, enlarged }) => {
          const isUnalloc = region.artifact_type === 'UnallocatedSpace'
          const outerLabel = isUnalloc
            ? `${regionName(region)} — unallocated`
            : `${regionName(region)} — partition`
          const innerLabelText =
            fs?.fs_type ?? (isUnalloc ? null : regionName(region))
          return (
            <g key={region.artifact_id}>
              <g
                role="button"
                tabIndex={0}
                aria-label={outerLabel}
                className="viz-dm-region"
                onClick={() => goTo(region.artifact_id)}
                onKeyDown={keyActivate(region.artifact_id)}
                onMouseMove={showTip(region, enlarged)}
                onMouseLeave={hideTip}
              >
                <rect
                  x={x}
                  y={0}
                  width={w}
                  height={STRIP_H}
                  className={isUnalloc ? undefined : 'viz-dm-part'}
                  fill={isUnalloc ? `url(#${patternId})` : undefined}
                  rx={2}
                />
                {!fs &&
                  innerLabelText &&
                  labelFits(innerLabelText, w) && (
                    <text
                      className="viz-dm-region-label"
                      x={x + w / 2}
                      y={STRIP_H / 2 + 3.5}
                      textAnchor="middle"
                    >
                      {innerLabelText.toUpperCase()}
                    </text>
                  )}
              </g>
              {fs && (
                <g
                  role="button"
                  tabIndex={0}
                  aria-label={`${regionName(fs)} — file system`}
                  className="viz-dm-region"
                  onClick={() => goToFiles(fs.artifact_id)}
                  onKeyDown={keyActivateFiles(fs.artifact_id)}
                  onMouseMove={showTip(fs, enlarged)}
                  onMouseLeave={hideTip}
                >
                  <rect
                    x={x + 4}
                    y={4}
                    width={Math.max(w - 8, 1)}
                    height={STRIP_H - 8}
                    className="viz-dm-fs"
                    rx={2}
                  />
                  {fs.fs_type && labelFits(fs.fs_type, w - 8) && (
                    <text
                      className="viz-dm-region-label"
                      x={x + w / 2}
                      y={STRIP_H / 2 + 3.5}
                      textAnchor="middle"
                    >
                      {fs.fs_type.toUpperCase()}
                    </text>
                  )}
                </g>
              )}
              {enlarged && (
                <path
                  d={`M ${x} 0 h 6 l -6 6 z`}
                  fill="var(--accent-dim)"
                  data-testid="dm-enlarged"
                />
              )}
            </g>
          )
        })}

        {/* Scale ruler */}
        <line x1={0} y1={RULER_Y} x2={width} y2={RULER_Y} className="viz-gridline" />
        {ticks.map((f) => {
          const x = f === 0 ? 0.5 : f === 1 ? width - 0.5 : f * width
          return (
            <g key={f}>
              <line x1={x} y1={RULER_Y} x2={x} y2={RULER_Y + 4} className="viz-gridline" />
              <text
                className="viz-axis-text"
                x={x}
                y={RULER_Y + 16}
                textAnchor={f === 0 ? 'start' : f === 1 ? 'end' : 'middle'}
              >
                {f === 0 ? '0' : formatBytes(Math.round(data.total_bytes * f))}
              </text>
            </g>
          )
        })}
      </svg>
      <VizTooltip tip={tip} />
    </div>
  )
}
