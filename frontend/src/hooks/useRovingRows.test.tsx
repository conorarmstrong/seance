import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { useRovingRows } from './useRovingRows'

function FixtureTable({
  rows = ['alpha', 'beta', 'gamma'],
  onActivate,
  onMove,
}: {
  rows?: string[]
  onActivate?: (index: number) => void
  onMove?: (index: number) => void
}) {
  const { getRowProps } = useRovingRows({
    count: rows.length,
    onActivate,
    onMove,
  })
  return (
    <table>
      <tbody>
        {rows.map((label, i) => (
          <tr key={label} {...getRowProps(i)}>
            <td>{label}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function row(label: string): HTMLElement {
  const cell = screen.getByText(label)
  return cell.closest('tr') as HTMLElement
}

describe('useRovingRows', () => {
  it('gives only the active row tabIndex 0 and data-active', () => {
    render(<FixtureTable />)
    expect(row('alpha')).toHaveAttribute('tabindex', '0')
    expect(row('alpha')).toHaveAttribute('data-active', 'true')
    expect(row('beta')).toHaveAttribute('tabindex', '-1')
    expect(row('beta')).not.toHaveAttribute('data-active')
    expect(row('gamma')).toHaveAttribute('tabindex', '-1')
  })

  it('moves the active row with ArrowDown / ArrowUp and clamps at edges', async () => {
    render(<FixtureTable />)
    row('alpha').focus()

    await userEvent.keyboard('{ArrowDown}')
    expect(row('beta')).toHaveFocus()
    expect(row('beta')).toHaveAttribute('tabindex', '0')
    expect(row('alpha')).toHaveAttribute('tabindex', '-1')

    await userEvent.keyboard('{ArrowDown}')
    expect(row('gamma')).toHaveFocus()
    // Clamped at the last row.
    await userEvent.keyboard('{ArrowDown}')
    expect(row('gamma')).toHaveFocus()

    await userEvent.keyboard('{ArrowUp}{ArrowUp}')
    expect(row('alpha')).toHaveFocus()
    // Clamped at the first row.
    await userEvent.keyboard('{ArrowUp}')
    expect(row('alpha')).toHaveFocus()
  })

  it('jumps with Home and End', async () => {
    render(<FixtureTable />)
    row('alpha').focus()
    await userEvent.keyboard('{End}')
    expect(row('gamma')).toHaveFocus()
    await userEvent.keyboard('{Home}')
    expect(row('alpha')).toHaveFocus()
  })

  it('activates the focused row with Enter', async () => {
    const onActivate = vi.fn()
    render(<FixtureTable onActivate={onActivate} />)
    row('alpha').focus()
    await userEvent.keyboard('{ArrowDown}{Enter}')
    expect(onActivate).toHaveBeenCalledWith(1)
  })

  it('adopts a row focused with the mouse as the active row', async () => {
    render(<FixtureTable />)
    act(() => row('gamma').focus())
    expect(row('gamma')).toHaveAttribute('data-active', 'true')
    await userEvent.keyboard('{ArrowUp}')
    expect(row('beta')).toHaveFocus()
  })

  it('brings the row it moves to into view', async () => {
    // jsdom has no layout and therefore no scrollIntoView; the point of the
    // assertion is that the hook asks for it at all, because a table page of
    // 100 rows is taller than the viewport and an off-screen selection is one
    // the examiner cannot count.
    const scrollIntoView = vi.fn()
    ;(HTMLElement.prototype as unknown as Record<string, unknown>).scrollIntoView =
      scrollIntoView
    try {
      render(<FixtureTable />)
      row('alpha').focus()
      await userEvent.keyboard('{ArrowDown}')
      expect(scrollIntoView).toHaveBeenCalledWith({ block: 'nearest' })
    } finally {
      delete (HTMLElement.prototype as unknown as Record<string, unknown>)
        .scrollIntoView
    }
  })

  it('reports keyboard moves so a caller can keep its own selection in step', async () => {
    const onMove = vi.fn()
    render(<FixtureTable onMove={onMove} />)
    row('alpha').focus()

    await userEvent.keyboard('{ArrowDown}')
    expect(onMove).toHaveBeenCalledWith(1)
    await userEvent.keyboard('{End}')
    expect(onMove).toHaveBeenLastCalledWith(2)
    await userEvent.keyboard('{Home}')
    expect(onMove).toHaveBeenLastCalledWith(0)
  })

  it('does not report a move when a row is merely focused', async () => {
    // Clicking a row focuses it. A caller that maps `onMove` to "select only
    // this row" must not have ctrl-click or shift-click range selection
    // collapsed out from under it by the focus that the click also causes.
    const onMove = vi.fn()
    render(<FixtureTable onMove={onMove} />)
    act(() => row('gamma').focus())
    expect(onMove).not.toHaveBeenCalled()
  })

  it('clamps the active index when rows shrink', async () => {
    function Shrinking() {
      const [rows, setRows] = useState(['alpha', 'beta', 'gamma'])
      return (
        <div>
          <button onClick={() => setRows(['alpha'])}>shrink</button>
          <FixtureTable rows={rows} />
        </div>
      )
    }
    render(<Shrinking />)
    row('gamma').focus()
    await userEvent.click(screen.getByText('shrink'))
    expect(row('alpha')).toHaveAttribute('tabindex', '0')
    expect(row('alpha')).toHaveAttribute('data-active', 'true')
  })
})

describe('useRovingRows over a windowed table', () => {
  // A table that renders only rows near the viewport cannot have the row the
  // arrows move to already in the DOM: it comes into existence because the
  // active index moved onto it. If the hook gave up when the ref was empty,
  // the keyboard would go dead at the edge of the rendered slice — the window
  // deciding what the examiner can reach, which is exactly what windowing is
  // not allowed to do.
  function WindowedTable({ rows }: { rows: string[] }) {
    const { activeIndex, getRowProps } = useRovingRows({ count: rows.length })
    return (
      <table>
        <tbody>
          {rows.map((label, i) =>
            i === activeIndex ? (
              <tr key={label} {...getRowProps(i)}>
                <td>{label}</td>
              </tr>
            ) : null,
          )}
        </tbody>
      </table>
    )
  }

  it('focuses a row that only renders because the move brought it into the window', async () => {
    render(<WindowedTable rows={['alpha', 'beta', 'gamma']} />)
    row('alpha').focus()

    await userEvent.keyboard('{ArrowDown}')
    expect(row('beta')).toHaveFocus()

    await userEvent.keyboard('{End}')
    expect(row('gamma')).toHaveFocus()
  })
})
