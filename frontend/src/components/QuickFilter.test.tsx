import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { QuickFilterBar, useQuickFilter } from './QuickFilter'

interface Row {
  id: string
  name: string | null
  path?: string
}

/**
 * A grid using the primitive the way a real one does: the rows it has loaded,
 * and the truth about whether that is all of them.
 */
function Grid({
  rows,
  scopeId = 'case-1',
  loadedIsSubset = false,
  total,
}: {
  rows: Row[]
  scopeId?: string
  loadedIsSubset?: boolean
  total?: number
}) {
  const filter = useQuickFilter(scopeId, rows, (r) => [r.name, r.path])
  return (
    <div>
      <QuickFilterBar
        filter={filter}
        noun="file entry"
        plural="file entries"
        loadedIsSubset={loadedIsSubset}
        total={total}
      />
      <ul>
        {filter.rows.map((r) => (
          <li key={r.id}>{r.name ?? r.id}</li>
        ))}
      </ul>
    </div>
  )
}

const ROWS: Row[] = [
  { id: '1', name: 'notes.txt', path: '/Users/jsmith/notes.txt' },
  { id: '2', name: 'Invoice.PDF', path: '/Users/jsmith/Documents/Invoice.PDF' },
  { id: '3', name: null, path: '/Windows/System32/svchost.exe' },
]

describe('useQuickFilter / QuickFilterBar (§1.1)', () => {
  it('narrows the rows as you type, case-insensitively, across every field', async () => {
    render(
      <MemoryRouter>
        <Grid rows={ROWS} />
      </MemoryRouter>,
    )
    expect(screen.getAllByRole('listitem')).toHaveLength(3)

    // A name, in the other case.
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'invoice')
    expect(screen.getAllByRole('listitem')).toHaveLength(1)
    expect(screen.getByText('Invoice.PDF')).toBeInTheDocument()

    // And a path, on a row whose name is null — which must not itself match
    // the needle "null".
    await userEvent.clear(screen.getByLabelText('Filter file entries'))
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'system32')
    expect(screen.getAllByRole('listitem')).toHaveLength(1)
    await userEvent.clear(screen.getByLabelText('Filter file entries'))
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'null')
    expect(screen.queryAllByRole('listitem')).toHaveLength(0)
  })

  /** No needle, no sentence: the grid is its own population. */
  it('says nothing until a needle is set', () => {
    render(
      <MemoryRouter>
        <Grid rows={ROWS} />
      </MemoryRouter>,
    )
    expect(screen.queryByTestId('quick-filter-count')).not.toBeInTheDocument()
  })

  it('states the population the count is out of', async () => {
    render(
      <MemoryRouter>
        <Grid rows={ROWS} />
      </MemoryRouter>,
    )
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'invoice')
    const count = screen.getByTestId('quick-filter-count')
    expect(count).toHaveTextContent('1 of 3 file entries match')
    // Nothing was hidden from the search, so nothing is claimed about the rest.
    expect(count).not.toHaveTextContent(/loaded/)
  })

  /**
   * The rule this primitive exists for. A client-side type-ahead filters what
   * is LOADED, not the case, and "3 matches" over a loaded slice of a 40,000-row
   * population is a statement about the slice. A grid that printed it bare
   * would be telling an examiner there are three in the case.
   */
  it('says the filter searched the loaded rows only when they are a subset', async () => {
    render(
      <MemoryRouter>
        <Grid rows={ROWS} loadedIsSubset total={40_000} />
      </MemoryRouter>,
    )
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'invoice')
    const count = screen.getByTestId('quick-filter-count')
    expect(count).toHaveTextContent('1 of 3 file entries match')
    expect(count).toHaveTextContent('are the loaded file entries of 40,000 in this case')
    // And says outright what a missing row does not mean.
    expect(count).toHaveTextContent(
      /is not a file entry the case does not hold/,
    )
  })

  /** Without a known total it still refuses to imply it searched everything. */
  it('discloses the subset even when the case-wide total is unknown', async () => {
    render(
      <MemoryRouter>
        <Grid rows={ROWS} loadedIsSubset />
      </MemoryRouter>,
    )
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'invoice')
    const count = screen.getByTestId('quick-filter-count')
    expect(count).toHaveTextContent('are the loaded file entries, not all of them')
    expect(count).not.toHaveTextContent('in this case')
  })

  /**
   * The grid stays mounted across a `:caseId` change, and a needle from case A
   * matches nothing in case B — the examiner is shown an empty grid for a case
   * that has rows, with no visible reason why (B2-092).
   */
  it('drops the needle when the case changes', async () => {
    function Switcher() {
      const navigate = useNavigate()
      return (
        <button type="button" onClick={() => navigate('/cases/case-2')}>
          Go to case-2
        </button>
      )
    }
    function Page({ scopeId }: { scopeId: string }) {
      return (
        <>
          <Switcher />
          <Grid rows={ROWS} scopeId={scopeId} />
        </>
      )
    }
    render(
      <MemoryRouter initialEntries={['/cases/case-1']}>
        <Routes>
          <Route path="/cases/case-1" element={<Page scopeId="case-1" />} />
          <Route path="/cases/case-2" element={<Page scopeId="case-2" />} />
        </Routes>
      </MemoryRouter>,
    )
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'invoice')
    expect(screen.getAllByRole('listitem')).toHaveLength(1)

    await userEvent.click(screen.getByRole('button', { name: 'Go to case-2' }))
    expect(screen.getByLabelText('Filter file entries')).toHaveValue('')
    expect(screen.getAllByRole('listitem')).toHaveLength(3)
  })

  /** A needle matching nothing is a statement about the search, not the case. */
  it('reports a match count of zero rather than falling silent', async () => {
    render(
      <MemoryRouter>
        <Grid rows={ROWS} />
      </MemoryRouter>,
    )
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'zzz')
    expect(screen.getByTestId('quick-filter-count')).toHaveTextContent(
      '0 of 3 file entries match',
    )
    expect(screen.queryAllByRole('listitem')).toHaveLength(0)
  })

  /** Singular reads as singular: a row quoted into a note must not say "1 file entrys". */
  it('uses the singular for a population of one', async () => {
    render(
      <MemoryRouter>
        <Grid rows={[ROWS[0]]} />
      </MemoryRouter>,
    )
    await userEvent.type(screen.getByLabelText('Filter file entries'), 'notes')
    expect(screen.getByTestId('quick-filter-count')).toHaveTextContent(
      '1 of 1 file entry matches',
    )
  })
})
