import { useCallback, useEffect, useRef, useState } from 'react'
import type { KeyboardEvent } from 'react'

export interface RovingRowProps {
  ref: (el: HTMLElement | null) => void
  tabIndex: number
  'data-active'?: 'true'
  onKeyDown: (e: KeyboardEvent<HTMLElement>) => void
  onFocus: () => void
}

export interface UseRovingRows {
  activeIndex: number
  setActiveIndex: (index: number) => void
  getRowProps: (index: number) => RovingRowProps
}

/**
 * Roving-tabindex keyboard navigation for a list of table rows (or any
 * row-like elements). Exactly one row is tabbable at a time; ArrowUp /
 * ArrowDown move the active row, Home / End jump to the first / last row,
 * and Enter invokes `onActivate` with the row index. The active row gets
 * `tabIndex=0` and `data-active="true"`; all others get `tabIndex=-1`.
 *
 * The whole table is therefore ONE tab stop rather than one per row, and
 * because the move is a real DOM focus change, a screen reader announces the
 * row the examiner has arrived at — which a scheme that only repaints a
 * selection highlight cannot do.
 *
 * `onMove` fires for keyboard moves only (not for the focus a mouse click
 * causes), so a table that keeps its own selection state can follow the
 * keyboard without having its click-built selections overwritten.
 *
 * Spread the result of `getRowProps(index)` onto each row element.
 */
export function useRovingRows({
  count,
  onActivate,
  onMove,
}: {
  count: number
  onActivate?: (index: number) => void
  onMove?: (index: number) => void
}): UseRovingRows {
  const [activeIndex, setActiveIndex] = useState(0)
  const rowRefs = useRef<(HTMLElement | null)[]>([])

  // Keep the active index valid when rows are removed.
  useEffect(() => {
    if (count > 0 && activeIndex > count - 1) {
      setActiveIndex(count - 1)
    }
  }, [count, activeIndex])

  // Kept in a ref so that `moveTo` — and therefore every row's key handler —
  // does not change identity on each render just because the caller passed a
  // fresh closure.
  const onMoveRef = useRef(onMove)
  onMoveRef.current = onMove

  // A row the move asked for that was not in the DOM to receive focus. A
  // windowed table renders only the rows near the viewport, so the row the
  // arrows move onto routinely comes into existence *because* the active index
  // moved onto it — one render later. Giving up here would let the rendered
  // slice decide how far the keyboard can go, which is the one thing windowing
  // must never do.
  const pendingFocus = useRef<number | null>(null)

  const focusRow = (index: number): boolean => {
    const el = rowRefs.current[index]
    if (!el) return false
    el.focus()
    // A page of rows is taller than the container, so the row we just moved to
    // is routinely below the fold. Without this the examiner keeps pressing
    // ArrowDown against a highlight they cannot see and presses Enter on a row
    // they never read. `block: 'nearest'` scrolls only as far as it must, so a
    // move within the visible rows does not jolt the table.
    el.scrollIntoView?.({ block: 'nearest' })
    return true
  }
  const focusRowRef = useRef(focusRow)
  focusRowRef.current = focusRow

  // Runs after every commit, so the row a move was waiting for is focused as
  // soon as it is rendered.
  useEffect(() => {
    const index = pendingFocus.current
    if (index == null) return
    if (focusRowRef.current(index)) pendingFocus.current = null
  })

  const moveTo = useCallback((index: number) => {
    setActiveIndex(index)
    if (!focusRowRef.current(index)) pendingFocus.current = index
    // Reported only for deliberate keyboard moves, never for the focus a mouse
    // click also causes, so that a caller mapping this to "select this row"
    // does not collapse its own ctrl-click and shift-click selections.
    onMoveRef.current?.(index)
  }, [])

  const getRowProps = useCallback(
    (index: number): RovingRowProps => ({
      ref: (el: HTMLElement | null) => {
        rowRefs.current[index] = el
        // The row a move was waiting for has just been rendered. Doing this
        // here rather than only in an effect matters for a windowed table:
        // the window is state inside the row-rendering component, so a move
        // that scrolls a new row into existence re-renders that component and
        // not this one, and an effect of this hook would never run again to
        // notice. Registering IS the notification.
        if (el && pendingFocus.current === index) {
          pendingFocus.current = null
          focusRowRef.current(index)
        }
      },
      tabIndex: index === activeIndex ? 0 : -1,
      'data-active': index === activeIndex ? 'true' : undefined,
      onFocus: () => setActiveIndex(index),
      onKeyDown: (e: KeyboardEvent<HTMLElement>) => {
        if (count === 0) return
        switch (e.key) {
          case 'ArrowDown':
            e.preventDefault()
            moveTo(Math.min(count - 1, index + 1))
            break
          case 'ArrowUp':
            e.preventDefault()
            moveTo(Math.max(0, index - 1))
            break
          case 'Home':
            e.preventDefault()
            moveTo(0)
            break
          case 'End':
            e.preventDefault()
            moveTo(count - 1)
            break
          case 'Enter':
            onActivate?.(index)
            break
        }
      },
    }),
    [activeIndex, count, moveTo, onActivate],
  )

  return { activeIndex, setActiveIndex, getRowProps }
}
