import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { EntitiesPage } from './EntitiesPage'
import type { EntitiesResponse } from './api'

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/cases/c1/entities']}>
        <Routes>
          <Route path="/cases/:caseId/entities" element={<EntitiesPage />} />
          <Route
            path="/cases/:caseId/search"
            element={<div>search-stub</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function mock(body: EntitiesResponse) {
  server.use(
    http.get('/api/v1/cases/c1/entities', () => HttpResponse.json(body)),
  )
}

/** Switches the `:caseId` route param in place, without remounting the page. */
function CaseSwitcher() {
  const navigate = useNavigate()
  return (
    <button type="button" onClick={() => navigate('/cases/c2/entities')}>
      Go to case-2
    </button>
  )
}

function renderPageWithSwitcher() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/cases/c1/entities']}>
        <CaseSwitcher />
        <Routes>
          <Route path="/cases/:caseId/entities" element={<EntitiesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function renderWithClient() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const utils = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/cases/c1/entities']}>
        <Routes>
          <Route path="/cases/:caseId/entities" element={<EntitiesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return { ...utils, client }
}

function emails(n: number, prefix: string) {
  return Array.from({ length: n }, (_, i) => ({
    kind: 'email',
    value: `${prefix}${i}@x.com`,
    count: 1,
    artifact_ids: [`a${i}`],
  }))
}

describe('EntitiesPage paging past the end (B5-014)', () => {
  it('clamps the page when the entity list shrinks under it', async () => {
    // 250 entities is three pages. On page 3, a refetch returning 40 leaves the
    // page number stranded: the table renders empty under "Page 3 of 1", which
    // reads as "this case has no entities" while the kind chips still count
    // them.
    mock({
      entities: emails(250, 'a'),
      counts_by_kind: { email: 250 },
      scanned_records: 1000,
      truncated: false,
    })
    const { client } = renderWithClient()
    await screen.findByText('a0@x.com')

    await userEvent.click(screen.getByLabelText('Last page'))
    expect(await screen.findByText('a249@x.com')).toBeInTheDocument()
    expect(screen.getByText(/Page 3 of 3/)).toBeInTheDocument()

    mock({
      entities: emails(40, 'b'),
      counts_by_kind: { email: 40 },
      scanned_records: 1000,
      truncated: false,
    })
    await client.invalidateQueries({ queryKey: ['entities', 'c1'] })

    // The one page that exists is shown, not an empty table on page 3.
    expect(await screen.findByText('b0@x.com')).toBeInTheDocument()
    expect(screen.getByText(/Page 1 of 1/)).toBeInTheDocument()
  })
})

describe('EntitiesPage', () => {
  it('renders entities and filters by type chip', async () => {
    mock({
      entities: [
        { kind: 'email', value: 'rms@gnu.org', count: 12, artifact_ids: ['a'] },
        { kind: 'url', value: 'https://example.com', count: 5, artifact_ids: ['b'] },
        { kind: 'email', value: 'bob@x.com', count: 2, artifact_ids: ['c'] },
      ],
      counts_by_kind: { email: 2, url: 1 },
      scanned_records: 100,
      truncated: false,
    })
    renderPage()

    expect(await screen.findByText('rms@gnu.org')).toBeInTheDocument()
    expect(screen.getByText('https://example.com')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Email/ }))
    expect(screen.queryByText('https://example.com')).toBeNull()
    expect(screen.getByText('rms@gnu.org')).toBeInTheDocument()
    expect(screen.getByText('bob@x.com')).toBeInTheDocument()
  })

  it('navigates to search for a selected entity value', async () => {
    mock({
      entities: [
        { kind: 'email', value: 'rms@gnu.org', count: 1, artifact_ids: [] },
      ],
      counts_by_kind: { email: 1 },
      scanned_records: 1,
      truncated: false,
    })
    renderPage()
    await screen.findByText('rms@gnu.org')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))
    expect(await screen.findByText('search-stub')).toBeInTheDocument()
  })

  it('shows an empty state when nothing is found', async () => {
    mock({ entities: [], counts_by_kind: {}, scanned_records: 0, truncated: false })
    renderPage()
    expect(await screen.findByText('No entities found')).toBeInTheDocument()
  })

  it('drops the kind filter when the case changes (B2-019)', async () => {
    // The kind chip filters client-side. Case A's "Email" filter carried into
    // case B hides every entity of a kind case B does not have — a case full of
    // URLs and IPs renders as an empty table, which the examiner reads as "no
    // identifiers were found here".
    mock({
      entities: [
        { kind: 'email', value: 'rms@gnu.org', count: 12, artifact_ids: ['a'] },
      ],
      counts_by_kind: { email: 1 },
      scanned_records: 100,
      truncated: false,
    })
    server.use(
      http.get('/api/v1/cases/c2/entities', () =>
        HttpResponse.json({
          entities: [
            {
              kind: 'url',
              value: 'https://evidence.example',
              count: 3,
              artifact_ids: ['z'],
            },
          ],
          counts_by_kind: { url: 1 },
          scanned_records: 10,
          truncated: false,
        } satisfies EntitiesResponse),
      ),
    )
    renderPageWithSwitcher()
    await screen.findByText('rms@gnu.org')
    await userEvent.click(screen.getByRole('button', { name: /Email/ }))

    await userEvent.click(screen.getByRole('button', { name: 'Go to case-2' }))

    expect(await screen.findByText('https://evidence.example')).toBeInTheDocument()
  })
})
