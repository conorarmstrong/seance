import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'

/**
 * Rows kept above and below the visible band. Deep enough that a fast scroll
 * or a wheel flick lands on rows that are already in the DOM.
 */
const DEFAULT_OVERSCAN = 12

/**
 * How many rows are rendered before anything has been measured. One screen's
 * worth on a tall monitor; the first measurement immediately corrects it.
 */
const INITIAL_RENDER = 60

/** See `adjustments` below. */
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
 * Attributes every windowed row carries, handed to the render callback so a
 * caller cannot forget them.
 *
 * `aria-rowindex` is the load-bearing one. A virtualized table holds a handful
 * of rows in the DOM out of millions, and without it assistive technology
 * counts what it can see and announces "row 4 of 60" — the rendered slice
 * presented as the whole set, which is the same lie as an unlabelled cap. With
 * it the reading is "row 5,002 of 2,100,001", against the `aria-rowcount` the
 * table declares. Both are 1-based and count the header row, hence the +2.
 */
export interface VirtualRowProps {
  'data-index': number
  'aria-rowindex': number
}

function rowProps(index: number): VirtualRowProps {
  return { 'data-index': index, 'aria-rowindex': index + 2 }
}

/**
 * Renders only the table rows near the viewport, holding the height of the
 * rest open with a spacer row at each end.
 *
 * This exists because a forensic table's population is not a page: an event
 * log yields millions of records and the viewers stream them in a page at a
 * time and never evict, so the DOM grows until the tab stops responding —
 * taking the examiner's filter state and their place in the list with it.
 *
 * Two rules constrain what windowing is allowed to do here, and both are
 * tested:
 *
 *  * It must not change what the examiner can reach. `pinnedIndex` — the row
 *    the keyboard is on — is always rendered, however far it is from the
 *    scroll position, so Home, End and arrow movement address the whole set
 *    rather than the slice. The spacers carry the full height of the set, so
 *    the scrollbar reaches every row too.
 *  * It must not present the slice as the population. Rows carry
 *    `aria-rowindex` over the whole set (see `VirtualRowProps`), and the
 *    counts a page prints stay counts of the population — this component
 *    never sees them.
 *
 * Use it as the only child of a `<tbody>`, and give the `<table>` an
 * `aria-rowcount` of `count + 1`.
 */
export function VirtualRows({
  count,
  rowHeight,
  colSpan,
  overscan = DEFAULT_OVERSCAN,
  pinnedIndex,
  children,
}: {
  /** Rows in the whole set held by the caller — never the rendered slice. */
  count: number
  /** Starting estimate for a row's height in px; refined by measurement. */
  rowHeight: number
  /** Columns the spacer rows must span. */
  colSpan: number
  overscan?: number
  /** Row the keyboard is on. Always rendered, wherever the scroll is. */
  pinnedIndex?: number
  children: (index: number, props: VirtualRowProps) => ReactNode
}) {
  const topRef = useRef<HTMLTableRowElement>(null)
  const bottomRef = useRef<HTMLTableRowElement>(null)

  const [range, setRange] = useState<Range>(() => ({
    start: 0,
    end: Math.min(count, INITIAL_RENDER),
  }))
  const [height, setHeight] = useState(rowHeight)
  /**
   * Whether the page can be measured at all. A table with no layout — hidden,
   * or an environment that has none — reports a zero-height block of rows, and
   * a window computed from that would hide rows nothing on screen accounts
   * for. Rendering the lot is the honest failure mode: slow rather than
   * silently short.
   */
  const [measurable, setMeasurable] = useState(true)

  /**
   * How many window adjustments the measurement has made in the last little
   * while. With a fixed row height the window is a pure function of where the
   * list sits and how tall the viewport is, so a scroll costs one adjustment;
   * this budget exists so that a pathological layout cannot turn
   * measure-and-adjust into a render loop that hangs the tab.
   *
   * The budget is per elapsed time rather than per scroll event on purpose.
   * Changing the window changes the spacer heights, which changes the
   * document's height, which can make the browser adjust the scroll position
   * itself — so a scroll event is not independent evidence that the examiner
   * did anything, and resetting the budget on one let the component feed its
   * own loop. Twenty in 200ms is far more than a real wheel scroll needs and
   * far fewer than a loop would take.
   *
   * Stopping early is safe: the window still contains the pinned row and the
   * spacers still account for every row in the set, so nothing becomes
   * unreachable — the next scroll re-opens the budget.
   */
  const adjustments = useRef(0)
  const adjustedAt = useRef(0)

  // Read by the measurement, which runs from a DOM event listener and so
  // cannot close over a render's values without going stale.
  const rangeRef = useRef(range)
  rangeRef.current = range
  const heightRef = useRef(height)
  heightRef.current = height
  const measuredOnce = useRef(false)
  /**
   * The last pinned row the scrolled band was found to already contain. See
   * the pinning rule in `measure`: without this the window would be nailed to
   * whichever row was focused first and never follow the scrollbar again.
   */
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

    // Rows in these tables are near enough uniform, so one measurement of the
    // rendered block describes all of them — and measuring beats the caller's
    // estimate, which is only ever right for one font size and one density.
    //
    // Measured ONCE (until the viewport resizes), on purpose. A row height
    // re-derived from each window is an input that depends on its own output:
    // a table whose rows differ by a few pixels then walks the height up and
    // down forever, each new average producing a different window and each
    // window a different average. Held fixed, the window is a pure function of
    // where the list sits and how tall the viewport is, and settles at once.
    if (!measuredOnce.current && rendered > 0 && block > 0) {
      measuredOnce.current = true
      const measured = block / rendered
      if (Math.abs(measured - heightRef.current) > 0.5) {
        heightRef.current = measured
        setHeight(measured)
      }
    }
    // Never zero: a measurement that came back as nothing would otherwise
    // divide the whole window calculation into NaN and render an empty table.
    const rowPx = Math.max(1, heightRef.current)

    // The band of the list that is inside the window. The list may be inside a
    // scrolling container rather than scrolling the window itself, so this is
    // measured against the viewport — which is the outer bound of anything
    // visible whatever container is in between — and the overscan absorbs the
    // difference.
    const listTop = topRect.top
    const viewport = window.innerHeight || 0
    const needStart = clamp(Math.floor(-listTop / rowPx), 0, Math.max(0, total))
    const needEnd = clamp(
      Math.ceil((viewport - listTop) / rowPx),
      needStart,
      total,
    )

    // Only move the window when the one we are holding no longer covers what
    // is on screen — not merely because a differently-centred one would be
    // tidier.
    //
    // This hysteresis is what keeps the component still. Real rows are never
    // exactly `rowPx` tall, so every change of window changes the total height
    // of the table by a little, which at the end of a long list makes the
    // browser clamp the scroll position, which measures again and produces yet
    // another window: a table parked at its own bottom would otherwise flip
    // between two windows for as long as it was left open. Recentring only on
    // an actual miss settles it, and the overscan is the margin that absorbs
    // the small scrolls in between.
    const held0 = held.start
    const held1 = held.end
    const covers = held0 <= needStart && held1 >= needEnd
    // A window kept from an earlier, taller viewport is trimmed back rather
    // than carried forever.
    const oversized = held1 - held0 > needEnd - needStart + overscan * 4
    let start = held0
    let end = held1
    if (!covers || oversized) {
      start = clamp(needStart - overscan, 0, Math.max(0, total))
      end = clamp(needEnd + overscan, start, total)
    }

    // The row the keyboard has just moved onto is never dropped. End on a long
    // table asks for a row nowhere near the scroll, and if the window could
    // refuse to render it the keyboard would go dead at the edge of the
    // rendered slice — the window deciding what the examiner can reach.
    //
    // Only when it has *moved* there, though. The pinned row is also whatever
    // row the table last focused, which on a freshly opened table is row 0
    // forever; honouring that unconditionally pinned the window to the top of
    // the set and left the examiner scrolling through blank space. So the
    // window follows the keyboard until the caller's own scroll-into-view has
    // brought the scrolled band to it, and from then on follows the scroll.
    const pinned = pinnedRef.current
    if (pinned != null && pinned >= 0 && pinned < total) {
      if (pinned >= start && pinned < end) {
        settledPinned.current = pinned
      } else if (settledPinned.current !== pinned) {
        const span = Math.max(end - start, 1)
        start = clamp(pinned - Math.floor(span / 2), 0, Math.max(0, total - 1))
        end = clamp(start + span, start, total)
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

  // Re-measure after every commit: the padding this render wrote changes where
  // the list sits, and a row arriving or leaving changes how tall it is.
  useEffect(measure)

  useEffect(() => {
    // Capture phase, because the scroll that matters is usually a container's
    // rather than the window's, and a scroll event on an element does not
    // bubble.
    const onScroll = () => measure()
    const onResize = () => {
      // A resize changes both the band and, potentially, how tall a row is.
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

  const start = measurable ? Math.min(range.start, count) : 0
  const end = measurable ? Math.min(range.end, count) : count
  const above = start * height
  const below = Math.max(0, (count - end) * height)

  const rows: ReactNode[] = []
  for (let index = start; index < end; index += 1) {
    rows.push(children(index, rowProps(index)))
  }

  return (
    <>
      {/* Spacer rows rather than a positioned container: a <tbody> may hold
          only rows, and the browser's own row layout is what keeps the columns
          aligned with the header. They carry the height of every row that is
          not rendered, so the scrollbar spans the whole set. */}
      <tr
        ref={topRef}
        data-virtual="top"
        aria-hidden="true"
        // The shared `.data-table tbody tr:hover` rule would otherwise paint
        // the whole spacer — thousands of pixels of highlight for rows that do
        // not exist — the moment the pointer crossed it.
        style={{ height: above, pointerEvents: 'none' }}
      >
        <td colSpan={colSpan} style={{ height: above, padding: 0, border: 0 }} />
      </tr>
      {rows}
      <tr
        ref={bottomRef}
        data-virtual="bottom"
        aria-hidden="true"
        style={{ height: below, pointerEvents: 'none' }}
      >
        <td colSpan={colSpan} style={{ height: below, padding: 0, border: 0 }} />
      </tr>
    </>
  )
}
