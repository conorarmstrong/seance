import { useRef } from 'react'
import { render } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useInfiniteScroll } from './useInfiniteScroll'

/** Captures the observers a render created so a test can fire them by hand. */
class FakeObserver {
  static instances: FakeObserver[] = []
  observed: Element[] = []
  disconnected = false
  // Declared and assigned rather than written as constructor parameter
  // properties: `erasableSyntaxOnly` is on for this project, and that syntax
  // needs a real TypeScript emit step.
  cb: (entries: { isIntersecting: boolean }[]) => void
  options: { rootMargin?: string }
  constructor(
    cb: (entries: { isIntersecting: boolean }[]) => void,
    options: { rootMargin?: string },
  ) {
    this.cb = cb
    this.options = options
    FakeObserver.instances.push(this)
  }
  observe(el: Element) {
    this.observed.push(el)
  }
  disconnect() {
    this.disconnected = true
  }
  /** Simulate the sentinel scrolling into view. */
  enter() {
    this.cb([{ isIntersecting: true }])
  }
}

function installFakeObserver() {
  FakeObserver.instances = []
  vi.stubGlobal('IntersectionObserver', FakeObserver)
  return FakeObserver
}

function Sentinel(props: {
  hasNextPage: boolean
  isFetchingNextPage: boolean
  onLoadMore: (() => void) | undefined
  rootMargin?: string
}) {
  const ref = useRef<HTMLDivElement>(null)
  useInfiniteScroll(ref, props)
  return <div ref={ref} />
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('useInfiniteScroll', () => {
  it('asks for the next page when the sentinel comes into view', () => {
    const observers = installFakeObserver()
    const onLoadMore = vi.fn()
    render(
      <Sentinel
        hasNextPage
        isFetchingNextPage={false}
        onLoadMore={onLoadMore}
      />,
    )

    observers.instances[0].enter()
    expect(onLoadMore).toHaveBeenCalledTimes(1)
  })

  it('does not stack requests while one is already in flight', () => {
    // Without this guard a sentinel that stays in view fires once per
    // intersection callback and the same page is fetched repeatedly.
    const observers = installFakeObserver()
    const onLoadMore = vi.fn()
    render(
      <Sentinel hasNextPage isFetchingNextPage onLoadMore={onLoadMore} />,
    )

    observers.instances[0].enter()
    expect(onLoadMore).not.toHaveBeenCalled()
  })

  it('does not ask for a page that does not exist', () => {
    const observers = installFakeObserver()
    const onLoadMore = vi.fn()
    render(
      <Sentinel
        hasNextPage={false}
        isFetchingNextPage={false}
        onLoadMore={onLoadMore}
      />,
    )

    observers.instances[0].enter()
    expect(onLoadMore).not.toHaveBeenCalled()
  })

  it('observes nothing when there is no way to load more', () => {
    const observers = installFakeObserver()
    render(
      <Sentinel
        hasNextPage
        isFetchingNextPage={false}
        onLoadMore={undefined}
      />,
    )

    expect(observers.instances).toHaveLength(0)
  })

  it('does not throw where IntersectionObserver is absent', () => {
    // jsdom and older browsers have none; every caller keeps a visible "Load
    // more" button for exactly this case.
    vi.stubGlobal('IntersectionObserver', undefined)
    expect(() =>
      render(
        <Sentinel
          hasNextPage
          isFetchingNextPage={false}
          onLoadMore={vi.fn()}
        />,
      ),
    ).not.toThrow()
  })

  it('honours a caller-chosen root margin', () => {
    const observers = installFakeObserver()
    render(
      <Sentinel
        hasNextPage
        isFetchingNextPage={false}
        onLoadMore={vi.fn()}
        rootMargin="600px"
      />,
    )

    expect(observers.instances[0].options.rootMargin).toBe('600px')
  })
})
