import './skeleton.css'

/** A single shimmering placeholder block. */
export function Skeleton({
  width,
  height,
  radius,
  className,
}: {
  width?: number | string
  height?: number | string
  radius?: number | string
  className?: string
}) {
  return (
    <span
      className={`skeleton ${className ?? ''}`}
      style={{ width, height, borderRadius: radius }}
      aria-hidden="true"
    />
  )
}

// Deterministic pseudo-random so widths look natural but don't reflow each
// render (no Math.random — keeps it stable and test-friendly).
function cellWidth(r: number, c: number): string {
  return `${58 + ((r * 7 + c * 29) % 38)}%`
}

/**
 * Table-shaped loading placeholder: a header plus shimmering rows that mirror
 * the real grid, so the user sees the shape of what's coming rather than a
 * bare "Loading…". First column is wider (names); the rest share the width.
 */
export function SkeletonTable({
  rows = 12,
  cols = 6,
  label = 'Loading',
}: {
  rows?: number
  cols?: number
  label?: string
}) {
  const template = `2fr ${Array.from({ length: Math.max(1, cols - 1) })
    .map(() => '1fr')
    .join(' ')}`
  return (
    <div
      className="skel-table"
      role="status"
      aria-live="polite"
      aria-label={`${label}…`}
    >
      <div className="skel-row skel-head" style={{ gridTemplateColumns: template }}>
        {Array.from({ length: cols }).map((_, c) => (
          <span
            key={c}
            className="skeleton skel-cell"
            style={{ width: c === 0 ? '50%' : '38%' }}
          />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div
          className="skel-row"
          key={r}
          style={{ gridTemplateColumns: template }}
        >
          {Array.from({ length: cols }).map((_, c) => (
            <span
              key={c}
              className="skeleton skel-cell"
              style={{
                width: cellWidth(r, c),
                animationDelay: `${(r % 6) * 90}ms`,
              }}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

/** A vertical list of shimmer lines — for trees, panels, and non-tabular loads. */
export function SkeletonList({
  rows = 8,
  label = 'Loading',
}: {
  rows?: number
  label?: string
}) {
  return (
    <div className="skel-list" role="status" aria-live="polite" aria-label={`${label}…`}>
      {Array.from({ length: rows }).map((_, r) => (
        <span
          key={r}
          className="skeleton skel-line"
          style={{
            width: `${52 + ((r * 13) % 40)}%`,
            animationDelay: `${(r % 6) * 90}ms`,
          }}
        />
      ))}
    </div>
  )
}
