import { useEffect } from 'react'
import type { RefObject } from 'react'

/**
 * Pull the next page when a sentinel element scrolls into view.
 *
 * `onLoadMore` must be a stable reference (react-query's `fetchNextPage`, or a
 * `useCallback`): the observer is rebuilt whenever it changes, and a fresh
 * closure every render would tear down and re-arm the observer on every render.
 *
 * The `IntersectionObserver` guard is not defensive dressing — jsdom and older
 * browsers have none, and every caller keeps a visible "Load more" button for
 * exactly that case. Silently loading only the first page would leave an
 * examiner scrolling a list that has quietly stopped growing.
 */
export function useInfiniteScroll(
  ref: RefObject<HTMLElement | null>,
  {
    hasNextPage,
    isFetchingNextPage,
    onLoadMore,
    rootMargin = '400px',
  }: {
    hasNextPage: boolean | undefined
    isFetchingNextPage: boolean | undefined
    /** Stable callback; undefined disables the observer entirely. */
    onLoadMore: (() => unknown) | undefined
    rootMargin?: string
  },
): void {
  useEffect(() => {
    const el = ref.current
    if (!el || !onLoadMore || typeof IntersectionObserver === 'undefined') return
    const io = new IntersectionObserver(
      (entries) => {
        if (
          entries.some((e) => e.isIntersecting) &&
          hasNextPage &&
          !isFetchingNextPage
        ) {
          onLoadMore()
        }
      },
      { rootMargin },
    )
    io.observe(el)
    return () => io.disconnect()
    // `ref` is a stable ref object; `rootMargin` is a literal at every call site.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasNextPage, isFetchingNextPage, onLoadMore])
}
