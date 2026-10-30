import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { RecordsViewerPage } from './RecordsViewerPage'

const CASE_ID = 'case-1'

/**
 * Serve a type whose `total` claims more rows than the server will hand over:
 * page 1 answers with rows, every later page answers empty. Real causes are
 * mundane — a count taken over a different filter, rows deleted between the
 * count and the read.
 */
function mockShortServer(rowsOnPageOne: number, claimedTotal: number) {
  const pagesRequested: number[] = []
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const page = Number(url.searchParams.get('page') ?? 1)
      const type = url.searchParams.get('type') ?? ''
      pagesRequested.push(page)
      const records =
        page === 1
          ? Array.from({ length: rowsOnPageOne }, (_, i) => ({
              id: `r-${i}`,
              parent_id: null,
              artifact_type: 'ParsedRecord',
              metadata: { type, name: `row ${i}` },
            }))
          : []
      return HttpResponse.json({
        records,
        total: claimedTotal,
        page,
        page_size: 100,
        type,
      })
    }),
  )
  return pagesRequested
}

function renderViewer(type: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/${type}`]}>
        <Routes>
          <Route path="/cases/:caseId/analysis/:type" element={<RecordsViewerPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('scroll-paged records', () => {
  it('stops paging when the server runs out, whatever the total claims', async () => {
    // `loaded < total` alone never becomes false when the server has no more
    // rows to give: the sentinel stays in view, every fetch appends nothing,
    // and the page asks for page 3, 4, 5 … without end. An empty page is the
    // end of the set; the shortfall stays on screen in the record count.
    const pagesRequested = mockShortServer(5, 500)

    renderViewer('GenericThing')

    expect(await screen.findByText('5 of 500 records')).toBeInTheDocument()
    const more = screen.getByRole('button', { name: 'Load more' })
    await userEvent.click(more)

    // Page 2 came back empty, so there is nothing further to ask for.
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /Load more/ })).toBeNull(),
    )
    expect(Math.max(...pagesRequested)).toBe(2)

    // And the count still says the load is short of what the server reported,
    // so "5 rows" is never read as the size of the set.
    expect(screen.getByText('5 of 500 records')).toBeInTheDocument()
  })

  it('does not call a short server an empty case', async () => {
    // The same skew, one row worse: the server counts 500 and serves none. The
    // paging guard stops the request storm, which means this now SETTLES on
    // screen instead of spinning — so the sentence it settles on matters. "This
    // case has no records of this type." is a finding about the evidence; what
    // happened is that the server reported 500 rows and handed over none.
    mockShortServer(0, 500)

    renderViewer('GenericThing')

    expect(await screen.findByText('0 of 500 records')).toBeInTheDocument()
    expect(
      screen.queryByText('This case has no records of this type.'),
    ).not.toBeInTheDocument()
    const note = await screen.findByRole('note')
    expect(note.textContent).toMatch(/reported 500 Generic Thing records/)
    expect(note.textContent).toMatch(/served none/)
  })

  it('still calls a genuinely empty type empty', async () => {
    // The complement: total 0, rows 0. No discrepancy, no warning — a banner on
    // every empty type is one an examiner learns to skip.
    mockShortServer(0, 0)

    renderViewer('GenericThing')

    expect(
      await screen.findByText('This case has no records of this type.'),
    ).toBeInTheDocument()
    expect(screen.queryByRole('note')).not.toBeInTheDocument()
  })
})
