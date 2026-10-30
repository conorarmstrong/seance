import { createContext, useCallback, useContext, useMemo } from 'react'
import type { ReactNode } from 'react'
import { useEntityScopedState } from '../lib/useEntityScopedState'

/** A closed time window, in unix seconds. */
export interface TimeWindow {
  from: number
  to: number
}

export interface TimeWindowApi {
  /** The window in force across the case, or `null` for the whole case. */
  window: TimeWindow | null
  setWindow: (window: TimeWindow | null) => void
}

/**
 * The case-wide time window (ROADMAP §1.1).
 *
 * `MiniTimeline` was a display on the dashboard: it neither followed the
 * examiner across screens nor filtered anything. This is the state that makes
 * it do both — one window, held per case, set from the persistent bar in the
 * case layout and read by any screen that can narrow itself by time.
 *
 * # The rule every consumer is bound by
 *
 * **A screen narrowed by this window must say so, and must not present its
 * population as the case's.** A reader who sees "412 events" under a window and
 * takes it for the case has been misled by the screen, not by the evidence —
 * and unlike a filter the examiner just set on the screen in front of them,
 * this one was set somewhere else and followed them here. That is exactly why
 * it needs a persistent bar rather than a hidden setting: the thing narrowing
 * the view is always on screen, with what it is and how to clear it.
 *
 * **A screen that does not honour it must not look as though it does.** The bar
 * names the screens the window is in force on, so a screen that ignores it is
 * visibly outside the list rather than silently unfiltered.
 *
 * Exported for tests, which provide an observable `setWindow` without mounting
 * the bar and the histogram behind it.
 */
export const TimeWindowCtx = createContext<TimeWindowApi | null>(null)

export function TimeWindowProvider({
  caseId,
  children,
}: {
  caseId: string
  children: ReactNode
}) {
  // Held per case. A window chosen for case A means nothing in case B — its
  // events are somewhere else entirely — and carrying it would show an empty
  // timeline for a case full of evidence (the B2-092 class).
  const [window, setRaw] = useEntityScopedState<TimeWindow | null>(caseId, null)

  const setWindow = useCallback(
    (next: TimeWindow | null) => {
      if (next === null) {
        setRaw(null)
        return
      }
      // Normalise rather than refuse: a drag backwards is a window, and a
      // zero-width one is a single bucket. What must never reach a query is
      // `from > to`, which every consumer would answer with an empty
      // population that reads as "nothing happened".
      const from = Math.min(next.from, next.to)
      const to = Math.max(next.from, next.to)
      setRaw({ from, to })
    },
    [setRaw],
  )

  const api = useMemo(() => ({ window, setWindow }), [window, setWindow])
  return <TimeWindowCtx.Provider value={api}>{children}</TimeWindowCtx.Provider>
}

/**
 * The case-wide time window, and how to change it.
 *
 * Outside a provider it is a no-op with no window, so a screen rendered in
 * isolation (a test, a storybook) still mounts and behaves as though nothing
 * were in force — which is the safe answer: it shows the whole population.
 */
export function useTimeWindow(): TimeWindowApi {
  const ctx = useContext(TimeWindowCtx)
  if (ctx) return ctx
  return { window: null, setWindow: () => {} }
}
