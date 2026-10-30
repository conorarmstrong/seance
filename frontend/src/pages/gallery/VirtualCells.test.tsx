import { act, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { VirtualCells } from './VirtualCells'

const ROW_HEIGHT = 100
const COLUMNS = 4

function Grid({
  count,
  pinnedIndex,
}: {
  count: number
  pinnedIndex?: number
}) {
  return (
    <VirtualCells
      className="gl-grid"
      count={count}
      cellHeight={ROW_HEIGHT}
      pinnedIndex={pinnedIndex}
    >
      {(index) => (
        <button type="button" key={index} data-idx={index}>
          cell {index}
        </button>
      )}
    </VirtualCells>
  )
}

/** Which absolute item indices are in the DOM right now. */
function renderedIndices(): number[] {
  return Array.from(
    document.querySelectorAll<HTMLElement>('[data-idx]'),
  ).map((el) => Number(el.dataset.idx))
}

/**
 * jsdom has no layout, so the component's measurements have to be supplied.
 * This stands in a scrolled viewport with a fixed four-column grid: the grid
 * starts `-scrollTop` from the top of the window, the spacers are as tall as
 * the component asked for, and every row of cells is ROW_HEIGHT tall.
 */
let scrollTop = 0
const realRect = Element.prototype.getBoundingClientRect
const realOffsetTop = Object.getOwnPropertyDescriptor(
  HTMLElement.prototype,
  'offsetTop',
)

function installLayout() {
  Object.defineProperty(HTMLElement.prototype, 'offsetTop', {
    configurable: true,
    get(this: HTMLElement) {
      const idx = this.dataset?.idx
      if (idx == null) return 0
      return Math.floor(Number(idx) / COLUMNS) * ROW_HEIGHT
    },
  })
  Element.prototype.getBoundingClientRect = function (this: Element): DOMRect {
    const el = this as HTMLElement
    const kind = el.dataset?.virtual
    if (kind !== 'top' && kind !== 'bottom') {
      return { top: 0, bottom: 0, height: 0 } as DOMRect
    }
    const topSpacer = document.querySelector<HTMLElement>(
      '[data-virtual="top"]',
    )
    const pad = parseFloat(topSpacer?.style.height ?? '0') || 0
    const renderedRows = Math.ceil(renderedIndices().length / COLUMNS)
    const listTop = -scrollTop
    const top =
      kind === 'top' ? listTop : listTop + pad + renderedRows * ROW_HEIGHT
    const height = kind === 'top' ? pad : 0
    return { top, bottom: top + height, height } as DOMRect
  }
}

function scrollTo(px: number) {
  scrollTop = px
  act(() => {
    window.dispatchEvent(new Event('scroll'))
  })
}

afterEach(() => {
  Element.prototype.getBoundingClientRect = realRect
  if (realOffsetTop) {
    Object.defineProperty(HTMLElement.prototype, 'offsetTop', realOffsetTop)
  }
  scrollTop = 0
})

describe('VirtualCells', () => {
  it('mounts a window of cells, not the whole picture set', () => {
    installLayout()
    // 200,000 pictures is an ordinary phone extraction. Mounting one button, one
    // observer, one query and one decoded image each is what killed the tab.
    render(<Grid count={200_000} />)
    const rendered = renderedIndices()
    expect(rendered.length).toBeLessThan(200)
    expect(rendered[0]).toBe(0)
  })

  it('holds the height of the whole set open, so the scrollbar reaches it all', () => {
    installLayout()
    render(<Grid count={4000} />)
    const bottom = document.querySelector<HTMLElement>(
      '[data-virtual="bottom"]',
    )!
    const top = document.querySelector<HTMLElement>('[data-virtual="top"]')!
    const renderedRows = Math.ceil(renderedIndices().length / COLUMNS)
    const heldRows =
      (parseFloat(top.style.height) + parseFloat(bottom.style.height)) /
      ROW_HEIGHT
    // Every one of the 1,000 rows is accounted for: rendered, or held open.
    expect(Math.round(heldRows) + renderedRows).toBe(4000 / COLUMNS)
  })

  it('follows the scroll to cells far down the set', () => {
    installLayout()
    render(<Grid count={40_000} />)
    expect(renderedIndices()).not.toContain(20_000)
    scrollTo(20_000 / COLUMNS * ROW_HEIGHT)
    expect(renderedIndices()).toContain(20_000)
    // And the cells at the top are gone again, which is the whole point.
    expect(renderedIndices()).not.toContain(0)
  })

  it('renders the pinned cell however far it is from the scroll', () => {
    installLayout()
    // End on a 40,000-item gallery moves the highlight to an item nowhere near
    // the viewport. A window that refused to render it would be the window
    // deciding how far the keyboard can go.
    const { rerender } = render(<Grid count={40_000} pinnedIndex={0} />)
    expect(renderedIndices()).not.toContain(39_999)
    rerender(<Grid count={40_000} pinnedIndex={39_999} />)
    expect(renderedIndices()).toContain(39_999)
  })

  it('renders every cell when there is no layout to measure', () => {
    // No `installLayout`: jsdom reports a zero-height block. Computing a window
    // from that would hide items nothing on screen accounts for, so the honest
    // failure mode is to render the lot — slow rather than silently short.
    render(<Grid count={30} />)
    expect(renderedIndices()).toHaveLength(30)
    expect(screen.getByText('cell 29')).toBeInTheDocument()
  })
})
