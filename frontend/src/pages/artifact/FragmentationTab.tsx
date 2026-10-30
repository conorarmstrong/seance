import { useMemo, useState } from 'react'
import { formatBytes, formatCount } from '../../lib/format'
import { useMeasuredWidth } from '../../components/viz/useMeasuredWidth'
import { VizTooltip, type TipState } from '../../components/viz/Tooltip'
import { analyzeRuns } from './fragmentation'

const STRIP_H = 46
/**
 * File layout / fragmentation tab: renders a file's `data_runs` as a
 * proportional strip of on-disk extents. Physical extents alternate shade so
 * fragmentation boundaries are visible; sparse (zero-filled) runs are hatched.
 * Answers "how fragmented is this file, and does that make recovery reliable."
 */
export function FragmentationTab({
  metadata,
}: {
  metadata: Record<string, unknown>
}) {
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()
  const [tip, setTip] = useState<TipState | null>(null)
  const analysis = useMemo(() => analyzeRuns(metadata.data_runs), [metadata])

  if (!analysis) {
    return (
      <div className="empty-state">
        <h3>No layout information</h3>
        <p>
          This artifact has no recorded data-run map. It may be resident, stored
          inline, or not from a block-based filesystem.
        </p>
      </div>
    )
  }

  const complete = metadata.data_runs_complete !== false
  const { runs, totalLength, fragments, hasSparse, contiguous } = analysis

  let cursor = 0
  let physicalIndex = 0
  const segs = runs.map((r) => {
    const w = totalLength > 0 ? (r.length / totalLength) * width : 0
    const seg = {
      r,
      x: cursor,
      w,
      alt: !r.sparse && physicalIndex++ % 2 === 1,
    }
    cursor += w
    return seg
  })

  const showTip =
    (offset: number | null, length: number, sparse: boolean, idx: number) =>
    (e: React.MouseEvent<SVGRectElement>) => {
      const host = ref.current
      if (!host) return
      const box = host.getBoundingClientRect()
      setTip({
        x: Math.min(e.clientX - box.left + 12, Math.max(width - 210, 0)),
        y: e.clientY - box.top + 14,
        lines: [
          sparse ? `Sparse run ${idx + 1}` : `Extent ${idx + 1}`,
          sparse ? 'zero-filled, no backing storage' : `disk offset 0x${offset!.toString(16)}`,
          `${formatBytes(length)} (${formatCount(length)} B)`,
        ],
      })
    }

  return (
    <div className="av-diskmap">
      <div className="av-frag-stats">
        <span className={fragments > 1 ? 'badge badge-danger' : 'badge badge-ok'}>
          {fragments > 1 ? `${fragments} fragments` : 'Contiguous'}
        </span>
        {fragments > 1 && !contiguous && (
          <span className="badge badge-danger">Scattered on disk</span>
        )}
        {hasSparse && <span className="badge">Sparse</span>}
        <span className="av-note">{formatBytes(totalLength)} mapped across {formatCount(runs.length)} run{runs.length === 1 ? '' : 's'}</span>
      </div>

      <div className="viz-diskmap" ref={ref}>
        <svg width={width} height={STRIP_H} role="img" aria-label="File data-run layout">
          {segs.map((s, i) => (
            <rect
              key={i}
              x={s.x + 0.5}
              y={0}
              width={Math.max(s.w - 1, 0.5)}
              height={STRIP_H}
              rx={2}
              className={
                s.r.sparse
                  ? 'av-frag-sparse'
                  : s.alt
                    ? 'av-frag-run-alt'
                    : 'av-frag-run'
              }
              onMouseMove={showTip(s.r.offset, s.r.length, s.r.sparse, i)}
              onMouseLeave={() => setTip(null)}
            />
          ))}
        </svg>
      </div>

      {fragments > 1 && (
        <p className="av-note">
          A fragmented file must be reassembled from its run list; contiguous
          recovery would be byte-wrong.
        </p>
      )}
      {!complete && (
        <p className="av-note">
          Run list truncated (over 4096 fragments); this map shows the retained
          runs only.
        </p>
      )}
      <VizTooltip tip={tip} />
    </div>
  )
}
