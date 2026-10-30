import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { Pager } from './Pager'

/**
 * The pager sits directly under the rows, so its count is the number an
 * examiner reads while looking at them — closer to hand than the count bar
 * above the table. When the listing's population is short (the scan stopped at
 * its ceiling, more matched than the grid will list, rows could not be
 * decoded), that number is a FLOOR, and a bare "1,234 rows" states a population
 * nobody established.
 *
 * The floor-ness is never decided here. The caller passes the same boolean its
 * count bar uses, so the two numbers on one screen cannot disagree about
 * whether they are exact.
 */
describe('Pager', () => {
  const props = { page: 2, totalPages: 5, onPage: () => {} }

  it('states an exact count plainly, with no hedge', () => {
    // Most callers page a set whose size the server counted exactly. An
    // unnecessary "at least" there is its own dishonesty: it would have an
    // examiner qualify a figure in a statement that did not need qualifying.
    render(<Pager {...props} totalCount={1234} />)
    const status = screen.getByTestId('pager-status')
    expect(status.textContent).toContain('1,234 rows')
    expect(status.textContent).not.toMatch(/at least/i)
  })

  it('says nothing about a count it was not given', () => {
    render(<Pager {...props} />)
    const status = screen.getByTestId('pager-status')
    expect(status.textContent).not.toMatch(/rows/)
    expect(status.textContent).toContain('Page 2 of 5')
  })

  it('qualifies the count as a floor when the caller says it is one', () => {
    render(<Pager {...props} totalCount={1234} totalIsFloor />)
    expect(screen.getByTestId('pager-status').textContent).toContain(
      'at least 1,234 rows',
    )
  })

  it('qualifies the page total too, since it is derived from the same count', () => {
    // "Page 2 of 5" is a claim that page 5 is the last one. It is not, when the
    // count the page total was divided out of is a lower bound.
    render(<Pager {...props} totalCount={1234} totalIsFloor />)
    expect(screen.getByTestId('pager-status').textContent).toContain(
      'Page 2 of at least 5',
    )
  })

  it('withholds the jump to the last page when the last page is not known to be last', () => {
    const { rerender } = render(<Pager {...props} totalCount={1234} />)
    expect(screen.getByLabelText('Last page')).toBeInTheDocument()
    rerender(<Pager {...props} totalCount={1234} totalIsFloor />)
    expect(screen.queryByLabelText('Last page')).not.toBeInTheDocument()
    // The jump to page 1 stays: page 1 is page 1 whatever the total turns out
    // to be, and Prev/Next walk pages the caller already knows exist.
    expect(screen.getByLabelText('First page')).toBeInTheDocument()
  })

  it('still pages one step at a time when the total is a floor', async () => {
    const user = userEvent.setup()
    const onPage = vi.fn()
    render(<Pager page={2} totalPages={5} onPage={onPage} totalCount={1234} totalIsFloor />)
    await user.click(screen.getByRole('button', { name: /Next/ }))
    expect(onPage).toHaveBeenCalledWith(3)
  })
})
