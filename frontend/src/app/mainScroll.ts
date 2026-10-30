import { useCallback, useLayoutEffect, useRef } from 'react'
import type { RefObject } from 'react'
import { useLocation, useNavigationType } from 'react-router-dom'

/**
 * Scroll memory for the shell's single scroll container.
 *
 * Every case page renders inside one `<main class="main-content">`, so the
 * browser's own scroll restoration never applies: the document does not
 * scroll, a div does. React Router's <ScrollRestoration> has the same blind
 * spot — it manages window scroll. Without this hook, an examiner 400 rows
 * into the flat file list who opens an artifact and presses Back lands at the
 * top of the list every time, dozens of times a day for the length of a case.
 * The mirror-image bug fires too: a forward jump from a long timeline to a
 * short page keeps the old offset, putting the new page's title above the
 * fold.
 *
 * Offsets are keyed by React Router's `location.key`, which is unique per
 * history ENTRY rather than per URL, so two visits to the same list at
 * different depths each keep their own position.
 */

// A cap on the ledger. An eight-hour day is a lot of navigations, and an
// offset for an entry 200 steps back is of no use to anyone; the Map's
// insertion order gives us the eviction order for free.
const MAX_REMEMBERED_ENTRIES = 200

// How long to keep re-applying an offset while the page below is still
// arriving. Long enough for a lazy chunk plus a paged fetch on a slow
// workstation; short enough that it can never feel like the page is fighting
// the examiner, who can abort it at any point by scrolling.
const RESTORE_WINDOW_MS = 1500

const offsets = new Map<string, number>()

/** Test seam: forget every recorded offset. */
export function resetMainScrollMemory(): void {
  offsets.clear()
}

/** Test seam: how many entries the ledger is currently holding. */
export function mainScrollMemorySize(): number {
  return offsets.size
}

export interface MainScrollRestoration<T extends HTMLElement> {
  /** Attach to the scroll container. */
  ref: RefObject<T | null>
  /** Attach to the scroll container's `onScroll`. */
  onScroll: () => void
}

export function useMainScrollRestoration<
  T extends HTMLElement,
>(): MainScrollRestoration<T> {
  const ref = useRef<T | null>(null)
  const { key } = useLocation()
  const navigationType = useNavigationType()

  // The entry that the offsets being recorded belong to. It is updated in the
  // layout effect below, which runs before any scroll event the DOM swap
  // provokes can be dispatched, so a clamped scroll caused by the new page
  // being shorter can never be written over the outgoing page's offset.
  const keyRef = useRef(key)

  // True while we are re-applying a restore. The assignments we make during
  // that window are clamped by the browser, and recording the clamped value
  // would destroy the very offset we are trying to get back to.
  const restoringRef = useRef(false)

  const onScroll = useCallback(() => {
    const el = ref.current
    if (!el || restoringRef.current) return
    const entry = keyRef.current
    // Re-inserting moves the key to the end, which is what makes plain Map
    // order a least-recently-used order.
    offsets.delete(entry)
    offsets.set(entry, el.scrollTop)
    if (offsets.size > MAX_REMEMBERED_ENTRIES) {
      const oldest = offsets.keys().next()
      if (!oldest.done) offsets.delete(oldest.value)
    }
  }, [])

  useLayoutEffect(() => {
    keyRef.current = key
    const el = ref.current
    if (!el) return

    // POP is Back/Forward — the examiner is returning to somewhere they have
    // been, so give them the position they left. Everything else (PUSH,
    // REPLACE) is a new destination, which starts at the top.
    const target = navigationType === 'POP' ? (offsets.get(key) ?? 0) : 0

    restoringRef.current = true
    el.scrollTop = target
    if (target === 0 || el.scrollTop === target) {
      restoringRef.current = false
      return
    }

    // The assignment was clamped: the page below is still a skeleton, or its
    // rows have not come back from the API yet, so the container is not tall
    // enough to hold the offset. Keep re-applying it as the content grows.
    const deadline = Date.now() + RESTORE_WINDOW_MS
    let frame = 0

    const stop = () => {
      restoringRef.current = false
      if (frame) cancelAnimationFrame(frame)
      frame = 0
      el.removeEventListener('wheel', stop)
      el.removeEventListener('touchstart', stop)
      el.removeEventListener('pointerdown', stop)
      el.removeEventListener('keydown', stop)
    }

    const step = () => {
      frame = 0
      const current = ref.current
      if (!current) {
        stop()
        return
      }
      current.scrollTop = target
      if (current.scrollTop === target || Date.now() > deadline) {
        stop()
        return
      }
      frame = requestAnimationFrame(step)
    }

    // Once the examiner takes hold of the page themselves, their position
    // wins; nothing is more annoying than a page that scrolls back under you.
    el.addEventListener('wheel', stop, { passive: true })
    el.addEventListener('touchstart', stop, { passive: true })
    el.addEventListener('pointerdown', stop)
    el.addEventListener('keydown', stop)
    frame = requestAnimationFrame(step)

    return stop
  }, [key, navigationType])

  return { ref, onScroll }
}
