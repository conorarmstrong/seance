import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { measureColumns } from './gridColumns'

/**
 * Rows of cells kept above and below the visible band. Shallower than the
 * record tables' overscan on purpose: every cell here mounts a query, an
 * IntersectionObserver, an object URL and an image the browser has to decode,
 * so an over-generous band undoes most of what windowing bought.
 */
const DEFAULT_OVERSCAN_ROWS = 2

/**
 * How many cells are rendered before anything has been measured. Roughly two
 * screens of a dense grid; the first measurement immediately corrects it.
 */
const INITIAL_RENDER = 60

/** See `adjustments` in VirtualRows — the same budget, for the same reason. */
const MAX_ADJUSTMENTS = 20
const ADJUSTMENT_WINDOW_MS = 200

interface Range {
  start: number
  end: number
}

function clamp(value: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, value))
}

/**
 * Renders only the media cells near the viewport, holding the height of the
 * rest open with a spacer at each end.
 *
 * The gallery is the surface most likely to hold hundreds of thousands of
 * items, and it used to mount every one of them: a button, an
 * IntersectionObserver, a react-query subscription and — for anything that
 * scrolled past once — a decoded image and an object URL, per picture. A case
 * with a large picture set took the tab down, and with it the examiner's place
 * in a triage pass they were forty-five minutes from needing.
 *
 * The same two rules bind here as bind the record tables, and both are tested:
 *
 *  * It must not change what the examiner can reach. `pinnedIndex` — the
 *    highlighted cell — is always rendered however far it is from the scroll
 *    position, so arrow keys, Home and End address the item set rather than the
 *    rendered slice, and this component scrolls a newly rendered pinned cell
 *    into view because the caller's own effect cannot: the cell does not exist
 *    until this component has re-rendered.
 *  * It must not present the slice as the population. The counts a page prints
 *    stay counts of the population — this component never sees them.
 *
 * Windowing also does the work that no amount of lazy-loading could: an image
 * whose cell is not mounted is not fetched, not decoded, and holds no object
 * URL. What remains in flight is bounded by the window, and beneath that by the
 * thumbnail fetch semaphore in `./api`.
 */
export function VirtualCells({
  count,
  className,
  containerRef,
  cellHeight,
  overscanRows = DEFAULT_OVERSCAN_ROWS,
  pinnedIndex,
  head,
  children,
}: {
  /** Items in the whole set the caller holds — never the rendered slice. */
  count: number
  className?: string
  /** Handed back so the caller can measure the grid it does not own. */
  containerRef?: React.RefObject<HTMLDivElement | null>
  /** Starting estimate for a row's height in px; refined by measurement. */
  cellHeight: number
  overscanRows?: number
  /** The highlighted cell. Always rendered, wherever the scroll is. */
  pinnedIndex?: number
  /** Rendered before the cells and outside the window (a list header row). */
  head?: ReactNode
  children: (index: number) => ReactNode
}) {
  const ownRef = useRef<HTMLDivElement>(null)
  const gridRef = containerRef ?? ownRef
  const topRef = useRef<HTMLDivElement>(null)
  const bottomRef = useRef<HTMLDivElement>(null)

  const [range, setRange] = useState<Range>(() => ({
    start: 0,
    end: Math.min(count, INITIAL_RENDER),
  }))
  const [height, setHeight] = useState(cellHeight)
  const [columns, setColumns] = useState(1)
  /**
   * Whether the grid can be measured at all. A grid with no layout — hidden, or
   * an environment that has none — reports a zero-height block of cells, and a
   * window computed from that would hide items nothing on screen accounts for.
   * Rendering the lot is the honest failure mode: slow rather than silently
   * short, and it is what keeps this component correct under jsdom.
   */
  const [measurable, setMeasurable] = useState(true)

  const adjustments = useRef(0)
  const adjustedAt = useRef(0)

  // Read by the measurement, which runs from a DOM event listener and so cannot
  // close over a render's values without going stale.
  const rangeRef = useRef(range)
  rangeRef.current = range
  const heightRef = useRef(height)
  heightRef.current = height
  const columnsRef = useRef(columns)
  columnsRef.current = columns
  const measuredOnce = useRef(false)
  const settledPinned = useRef<number | undefined>(undefined)
  const pinnedRef = useRef(pinnedIndex)
  pinnedRef.current = pinnedIndex
  const countRef = useRef(count)
  countRef.current = count

  const measure = useRef(() => {
    const top = topRef.current
    const bottom = bottomRef.current
    if (!top || !bottom) return
    const total = countRef.current
    const held = rangeRef.current
    const rendered = Math.max(0, held.end - held.start)

    const topRect = top.getBoundingClientRect()
    const bottomRect = bottom.getBoundingClientRect()
    const block = bottomRect.top - topRect.bottom
    if (rendered > 0 && block <= 0) {
      setMeasurable(false)
      return
    }
    setMeasurable(true)

    const cols = Math.max(1, measureColumns(gridRef.current))
    if (cols !== columnsRef.current) {
      columnsRef.current = cols
      setColumns(cols)
    }

    // Measured ONCE (until the viewport resizes), on purpose — a row height
    // re-derived from each window is an input that depends on its own output,
    // and the list then walks the height up and down forever. See VirtualRows.
    const renderedRows = Math.max(1, Math.ceil(rendered / cols))
    if (!measuredOnce.current && rendered > 0 && block > 0) {
      measuredOnce.current = true
      const measured = block / renderedRows
      if (Math.abs(measured - heightRef.current) > 0.5) {
        heightRef.current = measured
        setHeight(measured)
      }
    }
    // Never zero: a measurement that came back as nothing would divide the
    // window calculation into NaN and render an empty grid.
    const rowPx = Math.max(1, heightRef.current)

    const totalRows = Math.ceil(total / cols)
    const listTop = topRect.top
    const viewport = window.innerHeight || 0
    const needStartRow = clamp(Math.floor(-listTop / rowPx), 0, totalRows)
    const needEndRow = clamp(
      Math.ceil((viewport - listTop) / rowPx),
      needStartRow,
      totalRows,
    )

    // Only move the window when the one being held no longer covers what is on
    // screen. This hysteresis is what keeps the component still; see the long
    // note in VirtualRows.
    const heldStartRow = Math.floor(held.start / cols)
    const heldEndRow = Math.ceil(held.end / cols)
    const covers = heldStartRow <= needStartRow && heldEndRow >= needEndRow
    const oversized =
      heldEndRow - heldStartRow > needEndRow - needStartRow + overscanRows * 4
    let startRow = heldStartRow
    let endRow = heldEndRow
    if (!covers || oversized) {
      startRow = clamp(needStartRow - overscanRows, 0, totalRows)
      endRow = clamp(needEndRow + overscanRows, startRow, totalRows)
    }

    let start = clamp(startRow * cols, 0, total)
    let end = clamp(endRow * cols, start, total)

    // The cell the keyboard has just moved onto is never dropped: End on a long
    // gallery asks for an item nowhere near the scroll, and a window that could
    // refuse to render it would be the window deciding what the examiner can
    // reach. Only when it has MOVED there, though — see VirtualRows for why an
    // unconditional pin nails the window to whatever was highlighted first.
    const pinned = pinnedRef.current
    if (pinned != null && pinned >= 0 && pinned < total) {
      if (pinned >= start && pinned < end) {
        settledPinned.current = pinned
      } else if (settledPinned.current !== pinned) {
        const span = Math.max(end - start, cols)
        const pinnedRow = Math.floor(pinned / cols)
        const spanRows = Math.max(1, Math.round(span / cols))
        startRow = clamp(
          pinnedRow - Math.floor(spanRows / 2),
          0,
          Math.max(0, totalRows - 1),
        )
        endRow = clamp(startRow + spanRows, startRow, totalRows)
        start = clamp(startRow * cols, 0, total)
        end = clamp(endRow * cols, start, total)
      }
    }

    if (start !== held.start || end !== held.end) {
      const now = Date.now()
      if (now - adjustedAt.current > ADJUSTMENT_WINDOW_MS) {
        adjustments.current = 0
      }
      if (adjustments.current >= MAX_ADJUSTMENTS) return
      adjustments.current += 1
      adjustedAt.current = now
      rangeRef.current = { start, end }
      setRange({ start, end })
    }
  }).current

  // Re-measure after every commit: the spacer heights this render wrote change
  // where the grid sits, and a cell arriving or leaving changes how tall it is.
  useEffect(measure)

  useEffect(() => {
    // Capture phase, because the scroll that matters is usually a container's
    // rather than the window's, and a scroll event on an element does not
    // bubble.
    const onScroll = () => measure()
    const onResize = () => {
      // A resize changes the band, the row height AND the column count.
      measuredOnce.current = false
      onScroll()
    }
    window.addEventListener('scroll', onScroll, { passive: true, capture: true })
    window.addEventListener('resize', onResize, { passive: true })
    return () => {
      window.removeEventListener('scroll', onScroll, { capture: true })
      window.removeEventListener('resize', onResize)
    }
  }, [measure])

  // Bring a pinned cell into view once it exists. The caller cannot do this: it
  // moves the highlight, and the cell it moved to comes into existence one
  // render later, inside THIS component — so an effect of the caller's runs
  // against a DOM that does not hold the cell yet. `block: 'nearest'` scrolls
  // only as far as it must, so a move between visible cells does not jolt.
  const lastScrolled = useRef<number | undefined>(undefined)
  useEffect(() => {
    if (pinnedIndex == null || pinnedIndex < 0) {
      lastScrolled.current = undefined
      return
    }
    if (lastScrolled.current === pinnedIndex) return
    const el = gridRef.current?.querySelector(`[data-idx="${pinnedIndex}"]`)
    if (el) {
      lastScrolled.current = pinnedIndex
      ;(el as HTMLElement).scrollIntoView?.({ block: 'nearest' })
    }
  })

  const start = measurable ? Math.min(range.start, count) : 0
  const end = measurable ? Math.min(range.end, count) : count
  const aboveRows = Math.ceil(start / columns)
  const belowRows = Math.ceil(Math.max(0, count - end) / columns)
  const above = aboveRows * height
  const below = belowRows * height

  const cells: ReactNode[] = []
  for (let index = start; index < end; index += 1) {
    cells.push(children(index))
  }

  return (
    <div className={className} ref={gridRef}>
      {head}
      {/* Spacers rather than absolute positioning: the browser's own grid and
          flex layout is what keeps the cells aligned, and it only lays out
          children. They carry the height of every row that is not rendered, so
          the scrollbar spans the whole set. `gridColumn` makes a spacer take a
          whole grid row rather than one cell of one. */}
      <div
        ref={topRef}
        data-virtual="top"
        aria-hidden="true"
        style={{ height: above, gridColumn: '1 / -1', pointerEvents: 'none' }}
      />
      {cells}
      <div
        ref={bottomRef}
        data-virtual="bottom"
        aria-hidden="true"
        style={{ height: below, gridColumn: '1 / -1', pointerEvents: 'none' }}
      />
    </div>
  )
}
