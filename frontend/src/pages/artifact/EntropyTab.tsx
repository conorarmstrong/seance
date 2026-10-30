import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatBytes, formatCount } from '../../lib/format'
import { useMeasuredWidth } from '../../components/viz/useMeasuredWidth'
import { VizTooltip, type TipState } from '../../components/viz/Tooltip'
import { fetchContentRangeBytes } from './api'
import { entropyProfile } from './entropy'

const CAP = 8 * 1024 * 1024 // analyse at most the first 8 MiB
const WINDOWS = 480
const H = 200
const PAD_B = 20
const THRESHOLD = 7.5 // bits/byte: at/above this is effectively random (packed/encrypted)

/** Calm blue-grey at low entropy ramping to hot accent at ~8 bits. */
function entropyColor(e: number): string {
  const t = Math.min(Math.max(e, 0) / 8, 1)
  const lo = [46, 56, 74]
  const hi = [229, 161, 60]
  const c = lo.map((l, i) => Math.round(l + (hi[i] - l) * t))
  return `rgb(${c[0]},${c[1]},${c[2]})`
}

/**
 * Byte-entropy map: Shannon entropy across a file, plotted against position.
 * Flat regions near 8 bits are compressed or encrypted; low regions are text
 * or zero-fill; the middle band is code/structured binary. Content is read on
 * demand and capped, so a huge file never loads whole.
 */
export function EntropyTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const { ref, width } = useMeasuredWidth<HTMLDivElement>()
  const [tip, setTip] = useState<TipState | null>(null)

  const query = useQuery({
    queryKey: ['entropy', caseId, artifactId],
    queryFn: () => fetchContentRangeBytes(caseId, artifactId, 0, CAP - 1),
    retry: false,
    staleTime: Infinity,
  })

  const model = useMemo(() => {
    const bytes = query.data?.bytes
    if (!bytes || bytes.length === 0) return null
    const profile = entropyProfile(bytes, WINDOWS)
    const analysed = bytes.length
    const total = query.data?.totalSize ?? analysed
    const mean = profile.reduce((s, v) => s + v, 0) / (profile.length || 1)
    const highFraction = profile.filter((v) => v >= THRESHOLD).length / (profile.length || 1)
    return { profile, analysed, total, mean, highFraction, bytesPerWindow: analysed / profile.length }
  }, [query.data])

  if (query.isPending) return <div className="loading">Reading content…</div>
  if (query.isError) {
    return (
      <div className="empty-state">
        <h3>No content</h3>
        <p>This artifact's bytes could not be read for entropy analysis.</p>
      </div>
    )
  }
  if (!model) {
    return (
      <div className="empty-state">
        <h3>Empty</h3>
        <p>There are no bytes to analyse.</p>
      </div>
    )
  }

  const plotH = H - PAD_B
  const bw = width / model.profile.length
  const yFor = (e: number) => plotH - (Math.min(e, 8) / 8) * (plotH - 2)

  const showTip =
    (i: number, e: number) => (ev: React.MouseEvent<SVGRectElement>) => {
      const host = ref.current
      if (!host) return
      const box = host.getBoundingClientRect()
      const at = Math.round(i * model.bytesPerWindow)
      setTip({
        x: Math.min(ev.clientX - box.left + 12, Math.max(width - 220, 0)),
        y: ev.clientY - box.top + 14,
        lines: [
          `offset ~0x${at.toString(16)}`,
          `${e.toFixed(2)} bits/byte`,
          e >= THRESHOLD ? 'random — packed or encrypted' : e < 1.5 ? 'low — text or zero-fill' : 'structured',
        ],
      })
    }

  const verdict =
    model.highFraction > 0.9
      ? 'Almost entirely high-entropy: likely compressed or encrypted.'
      : model.highFraction > 0.4
        ? 'Substantial high-entropy regions: contains compressed or encrypted data.'
        : 'Mostly structured or low-entropy content.'

  return (
    <div className="av-diskmap">
      <div className="av-frag-stats">
        <span
          className={
            model.highFraction > 0.4 ? 'badge badge-danger' : 'badge badge-ok'
          }
        >
          mean {model.mean.toFixed(2)} bits/byte
        </span>
        <span className="av-note">{verdict}</span>
      </div>

      <div className="viz-diskmap" ref={ref}>
        <svg width={width} height={H} role="img" aria-label="Byte entropy across the file">
          {model.profile.map((e, i) => (
            <rect
              key={i}
              x={i * bw}
              y={yFor(e)}
              width={Math.max(bw - 0.5, 0.5)}
              height={plotH - yFor(e)}
              fill={entropyColor(e)}
              onMouseMove={showTip(i, e)}
              onMouseLeave={() => setTip(null)}
            />
          ))}
          {/* Encryption/compression threshold. */}
          <line
            x1={0}
            y1={yFor(THRESHOLD)}
            x2={width}
            y2={yFor(THRESHOLD)}
            className="av-entropy-threshold"
          />
          <text x={4} y={yFor(THRESHOLD) - 3} className="viz-axis-text">
            {THRESHOLD} bits — random
          </text>
          <line x1={0} y1={plotH} x2={width} y2={plotH} className="rv-axis" />
        </svg>
      </div>

      <p className="av-note">
        {model.total > model.analysed
          ? `First ${formatBytes(model.analysed)} of ${formatBytes(model.total)} analysed. `
          : `${formatBytes(model.total)} analysed. `}
        {formatCount(Math.round(model.bytesPerWindow))} bytes per column.
      </p>
      <VizTooltip tip={tip} />
    </div>
  )
}
