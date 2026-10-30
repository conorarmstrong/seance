export interface TipState {
  x: number
  y: number
  lines: string[]
}

/**
 * Hover tooltip positioned inside a relatively-positioned chart wrapper.
 * First line is the title; remaining lines render in mono (offsets,
 * sizes, ranges — evidential data).
 */
export function VizTooltip({ tip }: { tip: TipState | null }) {
  if (!tip) return null
  return (
    <div className="viz-tip" style={{ left: tip.x, top: tip.y }} role="status">
      {tip.lines.map((line, i) => (
        <div key={i} className={i === 0 ? 'viz-tip-title' : 'viz-tip-mono'}>
          {line}
        </div>
      ))}
    </div>
  )
}
