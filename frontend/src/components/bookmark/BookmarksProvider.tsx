import {
  createContext,
  useContext,
  useLayoutEffect,
  useMemo,
  useSyncExternalStore,
} from 'react'
import type { ReactNode } from 'react'
import { useBookmarks, type UseBookmarks } from '../../hooks/useBookmarks'

/**
 * One bookmark lookup for a whole screen, and one answer per row.
 *
 * ## Why this exists
 *
 * `useBookmarks` is the right shape for a page and the wrong shape for a row.
 * It opens two react-query observers and three mutation observers, and the
 * comms table put a `BookmarkControl` — and therefore a copy of all five — in
 * every one of up to five hundred rows. A single capture then invalidated
 * `['bookmarks', caseId]` across a thousand query observers, all of them
 * recomputing the same answer about the same case-wide list. Which artifacts
 * are bookmarked is a fact about the CASE, so the table asks once.
 *
 * ## Why the answer is not simply handed down through context
 *
 * A context whose value changes re-renders every component reading it, so
 * publishing the whole `UseBookmarks` to five hundred rows would have traded
 * a thousand query observers for five hundred re-renders on every capture —
 * cheaper, but still O(rows) for a one-row act. The marked/unmarked answer is
 * therefore published through a tiny store that a row subscribes to with its
 * own id, so a row re-renders only when ITS OWN state changed. The rest of the
 * hook — the categories, the writes, the in-flight and error state — goes
 * through ordinary context, because the only thing that reads it is the one
 * capture form that happens to be open.
 *
 * ## What is deliberately NOT done here
 *
 * No optimistic marking. The star follows the server's list and nothing else,
 * so it can never assert a capture the server rejected. The cost of that is a
 * round trip between the save and the star filling in; the cost of the
 * alternative is a screenshot of a bookmark that does not exist.
 */

/** The marked/unmarked answer for one case, as rows subscribe to it. */
interface MarkedStore {
  /** The case these answers are about; a row checks before trusting them. */
  caseId: string
  subscribe: (listener: () => void) => () => void
  /**
   * True or false once the case's list has loaded, and null while it has not
   * or could not — the distinction `useBookmarks` documents at length, carried
   * through unchanged.
   */
  marked: (artifactId: string) => boolean | null
}

const MarkedContext = createContext<MarkedStore | null>(null)
const BookmarkApiContext = createContext<UseBookmarks | null>(null)

function makeStore(caseId: string) {
  const listeners = new Set<() => void>()
  // Until the provider publishes, nothing is known — which is the same answer
  // `useBookmarks` gives before its query lands, and not the same as "no".
  let lookup: (artifactId: string) => boolean | null = () => null

  const facade: MarkedStore = {
    caseId,
    subscribe: (listener) => {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    marked: (artifactId) => lookup(artifactId),
  }

  return {
    facade,
    publish(next: (artifactId: string) => boolean | null) {
      lookup = next
      for (const listener of listeners) listener()
    },
  }
}

/**
 * Hold one case's bookmarks for everything rendered inside.
 *
 * Wrap a table in this and every `BookmarkControl` under it shares the one
 * lookup. A control with no provider above it makes its own — correct, and
 * fine for the single control on an artifact page, but it is the per-row cost
 * this component exists to avoid, so anything drawing a LIST of controls must
 * provide one.
 */
export function BookmarksProvider({
  caseId,
  children,
}: {
  caseId: string
  children: ReactNode
}) {
  const bookmarks = useBookmarks(caseId)
  const store = useMemo(() => makeStore(caseId), [caseId])

  // `isBookmarked` is rebuilt only when the id set itself changes, so this
  // republishes on a real change to the case's bookmarks and not on every
  // render of the provider.
  //
  // A LAYOUT effect, not a passive one. The rows do not re-render when the
  // provider does — that is the whole point — so they go on showing the
  // previous answer until this runs. A passive effect runs after the browser
  // has painted, which would put one painted frame of the old stars on a
  // screen that gets quoted; a layout effect publishes before that frame
  // exists.
  useLayoutEffect(() => {
    store.publish(bookmarks.isBookmarked)
  }, [store, bookmarks.isBookmarked])

  return (
    <MarkedContext.Provider value={store.facade}>
      {/* `children` is the same element across the provider's own re-renders,
          so React skips the subtree and only the components that actually read
          one of these two contexts are woken. */}
      <BookmarkApiContext.Provider value={bookmarks}>
        {children}
      </BookmarkApiContext.Provider>
    </MarkedContext.Provider>
  )
}

/**
 * The store for `caseId`, or null when there is none for that case above.
 *
 * The case is checked rather than assumed: a control for case A under a
 * provider for case B would otherwise read B's list and paint A's row with a
 * capture made in another case.
 */
export function useMarkedStore(caseId: string): MarkedStore | null {
  const store = useContext(MarkedContext)
  return store && store.caseId === caseId ? store : null
}

/**
 * Whether one artifact is bookmarked, as a subscription to just that answer.
 *
 * Returns null while unknown. The snapshot is a boolean, so React re-renders
 * the row only when the row's own answer changed — the fan-out costs every
 * other row one function call and no render at all.
 */
export function useIsBookmarked(
  store: MarkedStore,
  artifactId: string,
): boolean | null {
  return useSyncExternalStore(
    store.subscribe,
    () => store.marked(artifactId),
    () => null,
  )
}

/**
 * The whole hook, for the one capture form that is open.
 *
 * Throws when there is no provider, which cannot happen: everything that reads
 * it is rendered by `BookmarkControl`, which guarantees one.
 */
export function useBookmarkApi(): UseBookmarks {
  const api = useContext(BookmarkApiContext)
  if (!api) throw new Error('useBookmarkApi requires a BookmarksProvider')
  return api
}
