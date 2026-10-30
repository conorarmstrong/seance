import { useLayoutEffect, useRef } from 'react'

/**
 * Records what the UI actually showed in each committed frame.
 *
 * Why this exists: a page that resets entity-scoped local state — a selection,
 * an open dialog, a client-side filter — inside a `useEffect` keyed on the case
 * still renders and COMMITS one frame in which the case has already changed and
 * the previous case's value is still in hand. Passive effects run after that
 * commit, so `render`/`rerender` (which flush them before returning) leave no
 * trace of it: an assertion on the final DOM passes against the broken page and
 * against the fixed one alike.
 *
 * ## Why this observes the DOM rather than rendering alongside the page
 *
 * The obvious implementation — a sibling component snapshotting from a layout
 * effect — does not work, and it fails in the direction that matters: it records
 * nothing, and the test then passes vacuously.
 *
 * A test builds its route element once and hands it to `render`. On navigation
 * React sees a referentially identical element and bails out of re-rendering
 * that subtree. The page itself still re-renders, because it consumes router
 * context, but a sibling that consumes nothing never does — so its layout effect
 * fires exactly once, at mount, and every later frame goes unrecorded. The same
 * applies to any frame produced by a query settling rather than by navigation.
 *
 * A `MutationObserver` on the document has none of that coupling: it fires for
 * every DOM change, whichever component caused it. Its records are delivered as
 * a microtask, before any passive effect has had the chance to repair the frame,
 * so the offending paint is captured as an examiner would have seen it.
 *
 * Usage: clear the sink, perform the case switch, `await waitFor` until frames
 * arrive, then assert EVERY recorded frame is free of the previous case's value.
 * Assert the sink is non-empty first — a harness that records nothing would
 * otherwise report success.
 */
export function FrameSpy<T>({
  capture,
  frames,
}: {
  /** Reads whatever the assertion cares about out of the committed DOM. */
  capture: () => T
  /** Sink the snapshots are appended to, in commit order. */
  frames: T[]
}) {
  // Held in refs so the observer, installed once, always calls the current pair
  // rather than the ones captured at mount.
  const captureRef = useRef(capture)
  const framesRef = useRef(frames)
  captureRef.current = capture
  framesRef.current = frames

  useLayoutEffect(() => {
    // The frame the page was already showing when the spy mounted.
    framesRef.current.push(captureRef.current())

    const observer = new MutationObserver(() => {
      framesRef.current.push(captureRef.current())
    })
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
    })
    return () => observer.disconnect()
  }, [])

  return null
}

/** Value of an input located by its accessible label, or null when absent. */
export function inputValue(label: string): string | null {
  const el = document.querySelector(`[aria-label="${label}"]`)
  return el instanceof HTMLInputElement ? el.value : null
}
