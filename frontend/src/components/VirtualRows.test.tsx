import { render, screen } from '@testing-library/react'
import { act } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { VirtualRows } from './VirtualRows'

const ROW_HEIGHT = 20

function Table({
  count,
  pinnedIndex,
}: {
  count: number
  pinnedIndex?: number
}) {
  return (
    <table aria-rowcount={count + 1}>
      <thead>
        <tr aria-rowindex={1}>
          <th>Row</th>
        </tr>
      </thead>
      <tbody>
        <VirtualRows
          count={count}
          rowHeight={ROW_HEIGHT}
          colSpan={1}
          pinnedIndex={pinnedIndex}
        >
          {(index, rowProps) => (
            <tr key={index} {...rowProps}>
              <td>row {index}</td>
            </tr>
          )}
        </VirtualRows>
      </tbody>
    </table>
  )
}

/** Which absolute row indices are in the DOM right now. */
function renderedIndices(): number[] {
  return Array.from(
    document.querySelectorAll<HTMLElement>('tbody tr[data-index]'),
  ).map((el) => Number(el.dataset.index))
}

/**
 * jsdom has no layout, so the component's measurements have to be supplied.
 * This stands in a scrolled viewport: the virtual list starts `-scrollTop`
 * from the top of the window, the spacer rows are as tall as the component
 * asked for, and every rendered row is ROW_HEIGHT tall.
 */
let scrollTop = 0
const realRect = Element.prototype.getBoundingClientRect
function installLayout() {
  Element.prototype.getBoundingClientRect = function (this: Element): DOMRect {
    const el = this as HTMLElement
    const kind = el.dataset?.virtual
    if (kind !== 'top' && kind !== 'bottom') {
      return { top: 0, bottom: 0, height: 0 } as DOMRect
    }
    const topSpacer = document.querySelector<HTMLElement>(
      'tr[data-virtual="top"]',
    )
    const pad = parseFloat(topSpacer?.style.height ?? '0') || 0
    const rendered = renderedIndices().length
    const listTop = -scrollTop
    const top =
      kind === 'top' ? listTop : listTop + pad + rendered * ROW_HEIGHT
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
  scrollTop = 0
  Element.prototype.getBoundingClientRect = realRect
})

describe('VirtualRows', () => {
  it('renders only the rows near the viewport, not the whole set', () => {
    installLayout()
    render(<Table count={10_000} />)

    const indices = renderedIndices()
    // jsdom's window is 768px tall; at 20px a row that is ~39 rows plus the
    // overscan at each end. The exact number is not the point — that it is
    // two orders of magnitude below 10,000 is.
    expect(indices.length).toBeGreaterThan(30)
    expect(indices.length).toBeLessThan(120)
    expect(indices[0]).toBe(0)
    expect(screen.getByText('row 0')).toBeInTheDocument()
    expect(screen.queryByText('row 5000')).toBeNull()
  })

  it('follows the scroll to rows deep in the set', () => {
    installLayout()
    render(<Table count={10_000} />)

    // 5,000 rows down.
    scrollTo(5_000 * ROW_HEIGHT)

    const indices = renderedIndices()
    expect(indices).toContain(5_000)
    expect(indices).not.toContain(0)
    expect(screen.getByText('row 5000')).toBeInTheDocument()
  })

  it('keeps the pinned row rendered however far it is from the scroll', () => {
    // The pinned row is the one the keyboard is on. If windowing could drop
    // it, End on a 4M-row table would move the active index somewhere the
    // table cannot focus, and the examiner's keyboard would go dead — the
    // window must never decide what the examiner can reach.
    installLayout()
    render(<Table count={10_000} pinnedIndex={9_999} />)

    expect(renderedIndices()).toContain(9_999)
    expect(screen.getByText('row 9999')).toBeInTheDocument()
  })

  it('holds the full height of the set open so the scrollbar tells the truth', () => {
    installLayout()
    render(<Table count={10_000} />)

    const top = document.querySelector<HTMLElement>('tr[data-virtual="top"]')!
    const bottom = document.querySelector<HTMLElement>(
      'tr[data-virtual="bottom"]',
    )!
    const padding =
      parseFloat(top.style.height) + parseFloat(bottom.style.height)
    const rendered = renderedIndices().length
    // Spacers plus rendered rows account for every row in the set: a scrollbar
    // that stops short would be a silent cap the examiner could see but not
    // read.
    expect(padding / ROW_HEIGHT + rendered).toBe(10_000)
  })

  it('numbers rows against the whole set, not the rendered slice', () => {
    installLayout()
    render(<Table count={10_000} />)
    scrollTo(5_000 * ROW_HEIGHT)

    const row = document
      .querySelector<HTMLElement>('tbody tr[data-index="5000"]')!
    // aria-rowindex counts from 1 including the header row, so data row 5,000
    // is 5,002. A screen reader then says "row 5,002 of 10,001" rather than
    // "row 4 of 60", which is the slice pretending to be the population.
    expect(row.getAttribute('aria-rowindex')).toBe('5002')
  })

  it('renders every row when it cannot measure the page', () => {
    // No layout to read (a hidden table, or any environment without one).
    // Hiding rows we cannot prove are off screen would be a cap nothing on
    // screen accounts for, so the fallback is to render the lot.
    render(<Table count={300} />)
    expect(renderedIndices()).toHaveLength(300)
    expect(screen.getByText('row 299')).toBeInTheDocument()
  })
})
