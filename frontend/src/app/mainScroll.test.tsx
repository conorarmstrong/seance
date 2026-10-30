import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'

import {
  mainScrollMemorySize,
  resetMainScrollMemory,
  useMainScrollRestoration,
} from './mainScroll'

/**
 * A stand-in for the shell: one scroll container that every routed page
 * renders inside, exactly as CaseLayout's <main className="main-content">
 * does.
 */
function Shell({ maxScroll }: { maxScroll?: { value: number } }) {
  const { ref, onScroll } = useMainScrollRestoration<HTMLDivElement>()
  return (
    <div
      data-testid="main"
      ref={(el) => {
        ref.current = el
        if (el && maxScroll) clampScrollTop(el, maxScroll)
      }}
      onScroll={onScroll}
    >
      <Routes>
        <Route path="/list" element={<Page name="list" />} />
        <Route path="/artifact" element={<Page name="artifact" />} />
        <Route path="/other" element={<Page name="other" />} />
      </Routes>
    </div>
  )
}

function Page({ name }: { name: string }) {
  const navigate = useNavigate()
  return (
    <div>
      <h1>{name}</h1>
      <button onClick={() => navigate('/artifact')}>to artifact</button>
      <button onClick={() => navigate('/other')}>to other</button>
      <button onClick={() => navigate(-1)}>back</button>
    </div>
  )
}

/**
 * jsdom performs no layout, so assigning `scrollTop` always sticks. Real
 * browsers clamp the assignment to the container's current scroll height,
 * which is the whole reason the restore has to survive a page that is still
 * loading. This reproduces the clamp so that behaviour is testable.
 */
function clampScrollTop(el: HTMLElement, max: { value: number }) {
  let current = 0
  Object.defineProperty(el, 'scrollTop', {
    configurable: true,
    get: () => current,
    set: (next: number) => {
      current = Math.max(0, Math.min(Number(next), max.value))
    },
  })
}

function main(): HTMLElement {
  return screen.getByTestId('main')
}

function scrollTo(offset: number) {
  main().scrollTop = offset
  fireEvent.scroll(main())
}

describe('useMainScrollRestoration', () => {
  beforeEach(() => resetMainScrollMemory())

  it('restores the offset of the entry the examiner goes back to', async () => {
    render(
      <MemoryRouter initialEntries={['/list']}>
        <Shell />
      </MemoryRouter>,
    )
    scrollTo(1840)

    await userEvent.click(screen.getByText('to artifact'))
    expect(await screen.findByText('artifact')).toBeInTheDocument()
    expect(main().scrollTop).toBe(0)

    await userEvent.click(screen.getByText('back'))
    expect(await screen.findByText('list')).toBeInTheDocument()
    expect(main().scrollTop).toBe(1840)
  })

  it('resets to the top on a forward navigation', async () => {
    render(
      <MemoryRouter initialEntries={['/list']}>
        <Shell />
      </MemoryRouter>,
    )
    scrollTo(1200)
    await userEvent.click(screen.getByText('to other'))
    expect(await screen.findByText('other')).toBeInTheDocument()
    expect(main().scrollTop).toBe(0)
  })

  it('keeps one offset per history entry, not per URL', async () => {
    render(
      <MemoryRouter initialEntries={['/list']}>
        <Shell />
      </MemoryRouter>,
    )
    scrollTo(500)
    await userEvent.click(screen.getByText('to artifact'))
    // A second visit to the same URL is a different history entry, so its
    // position is its own.
    await userEvent.click(screen.getByText('to other'))
    await screen.findByText('other')
    scrollTo(90)

    await userEvent.click(screen.getByText('back'))
    await screen.findByText('artifact')
    await userEvent.click(screen.getByText('back'))
    expect(await screen.findByText('list')).toBeInTheDocument()
    expect(main().scrollTop).toBe(500)
  })

  it('re-applies the offset while the page below is still loading', async () => {
    const max = { value: 4000 }
    render(
      <MemoryRouter initialEntries={['/list']}>
        <Shell maxScroll={max} />
      </MemoryRouter>,
    )
    scrollTo(3000)
    await userEvent.click(screen.getByText('to artifact'))
    await screen.findByText('artifact')

    // Back onto a list whose rows have not arrived yet: the container is a
    // single skeleton tall, so the browser clamps the restore to almost
    // nothing.
    max.value = 40
    await userEvent.click(screen.getByText('back'))
    await screen.findByText('list')
    expect(main().scrollTop).toBe(40)

    // The rows land; the offset the examiner left at must come back without
    // them touching anything.
    max.value = 4000
    await waitFor(() => expect(main().scrollTop).toBe(3000))
  })

  it('stops chasing the offset the moment the examiner scrolls', async () => {
    const max = { value: 4000 }
    render(
      <MemoryRouter initialEntries={['/list']}>
        <Shell maxScroll={max} />
      </MemoryRouter>,
    )
    scrollTo(3000)
    await userEvent.click(screen.getByText('to artifact'))
    await screen.findByText('artifact')

    max.value = 40
    await userEvent.click(screen.getByText('back'))
    await screen.findByText('list')

    fireEvent.wheel(main())
    max.value = 4000
    scrollTo(120)
    // Give the chase every chance to fire before asserting it did not.
    await new Promise((resolve) => setTimeout(resolve, 80))
    expect(main().scrollTop).toBe(120)
  })

  it('does not remember offsets without bound over a long session', () => {
    render(
      <MemoryRouter initialEntries={['/list']}>
        <Shell />
      </MemoryRouter>,
    )
    // An eight-hour shift runs to thousands of navigations. `fireEvent`
    // rather than `userEvent` here purely for speed: 260 full pointer
    // sequences take seconds, and nothing in this test is about the pointer.
    for (let i = 0; i < 260; i += 1) {
      scrollTo(i)
      fireEvent.click(screen.getByText(i % 2 === 0 ? 'to artifact' : 'to other'))
    }
    expect(mainScrollMemorySize()).toBeLessThanOrEqual(200)
  })
})
