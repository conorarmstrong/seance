import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { DuplicatesPage } from './DuplicatesPage'

const CASE_ID = 'case-1'

function mock(body: unknown) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/duplicates`, () =>
      HttpResponse.json(body as Parameters<typeof HttpResponse.json>[0]),
    ),
  )
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/duplicates`]}>
        <Routes>
          <Route path="/cases/:caseId/duplicates" element={<DuplicatesPage />} />
          <Route
            path="/cases/:caseId/artifacts/:artifactId"
            element={<div>artifact page</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** Switches the `:caseId` route param in place, without remounting the page. */
function CaseSwitcher() {
  const navigate = useNavigate()
  return (
    <button type="button" onClick={() => navigate('/cases/case-2/duplicates')}>
      Go to case-2
    </button>
  )
}

function renderPageWithSwitcher() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/duplicates`]}>
        <CaseSwitcher />
        <Routes>
          <Route path="/cases/:caseId/duplicates" element={<DuplicatesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('DuplicatesPage filter with no matches (B5-033)', () => {
  it('says the filter matched nothing rather than showing an empty list', async () => {
    // Case-wide counts above an empty list read as "no duplicates in this
    // case", which is the opposite of what an empty filter result means.
    mock({
      group_count: 1,
      redundant_copies: 1,
      truncated: false,
      groups: [
        {
          hash: 'aaaa1111bbbb2222cccc',
          count: 2,
          members: [
            {
              id: 'm1',
              name: 'photo.jpg',
              path: '/DCIM/photo.jpg',
              artifact_type: 'FileEntry',
            },
            {
              id: 'm2',
              name: 'photo_copy.jpg',
              path: '/tmp/photo_copy.jpg',
              artifact_type: 'FileEntry',
            },
          ],
        },
      ],
    })
    renderPage()
    await screen.findByText(/photo\.jpg/)

    await userEvent.type(
      screen.getByLabelText('Filter duplicates'),
      'nothing-matches-this',
    )

    const note = await screen.findByTestId('dup-no-matches')
    expect(note.textContent).toContain('No groups match this filter')
    expect((note.textContent ?? '').replace(/\s+/g, ' ')).toContain(
      'Clear the filter to see them all',
    )
  })

  it('does not blame the filter when no filter is set', async () => {
    // The case reports groups and the server returned none. Saying "no groups
    // match this filter" when there is no filter invents an explanation for a
    // disagreement the page cannot resolve.
    mock({
      group_count: 3,
      redundant_copies: 4,
      truncated: false,
      groups: [],
    })
    renderPage()

    const note = await screen.findByTestId('dup-none-returned')
    expect((note.textContent ?? '').replace(/\s+/g, ' ')).toContain(
      'returned none to list',
    )
    expect(screen.queryByTestId('dup-no-matches')).toBeNull()
  })
})

describe('DuplicatesPage', () => {
  it('lists groups largest-first, expands members, and filters', async () => {
    mock({
      group_count: 2,
      redundant_copies: 3,
      truncated: false,
      groups: [
        {
          hash: 'aaaa1111bbbb2222cccc',
          count: 3,
          members: [
            { id: 'm1', name: 'photo.jpg', path: '/DCIM/photo.jpg', artifact_type: 'FileEntry' },
            { id: 'm2', name: 'photo_copy.jpg', path: '/tmp/photo_copy.jpg', artifact_type: 'FileEntry' },
          ],
        },
        {
          hash: 'dddd3333eeee4444ffff',
          count: 2,
          members: [
            { id: 'm3', name: 'report.pdf', path: '/docs/report.pdf', artifact_type: 'FileEntry' },
            { id: 'm4', name: 'report2.pdf', path: '/bak/report2.pdf', artifact_type: 'FileEntry' },
          ],
        },
      ],
    })
    renderPage()

    // Summary reflects the group + redundant-copy counts.
    expect(await screen.findByText(/2 duplicate-content groups/)).toBeInTheDocument()
    expect(screen.getByText(/3 redundant copies/)).toBeInTheDocument()

    // Group headers show the count and the first member's name.
    expect(screen.getByText('photo.jpg')).toBeInTheDocument()
    expect(screen.getByText('report.pdf')).toBeInTheDocument()

    // Members are hidden until the group is expanded.
    expect(screen.queryByText('photo_copy.jpg')).not.toBeInTheDocument()
    await userEvent.click(screen.getByText('photo.jpg').closest('button')!)
    expect(screen.getByText('photo_copy.jpg')).toBeInTheDocument()

    // Filter narrows to the matching group.
    await userEvent.type(screen.getByLabelText('Filter duplicates'), 'report')
    expect(screen.queryByText('photo.jpg')).not.toBeInTheDocument()
    expect(screen.getByText('report.pdf')).toBeInTheDocument()
  })

  it('shows an empty state when nothing is duplicated', async () => {
    mock({ group_count: 0, redundant_copies: 0, truncated: false, groups: [] })
    renderPage()
    expect(await screen.findByText('No duplicates')).toBeInTheDocument()
  })

  it('renders PDQ near-duplicate image groups as a lead, not an ID', async () => {
    mock({ group_count: 0, redundant_copies: 0, truncated: false, groups: [] })
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/near_duplicate_images`, () =>
        HttpResponse.json({
          group_count: 1,
          threshold: 31,
          images_scanned: 3,
          scan_truncated: false,
          grade: 'scanned',
          note: 'PDQ near-duplicates: a lead for human review, not an identification.',
          groups: [
            {
              count: 2,
              members: [
                { record_id: 'r1', image_artifact_id: 'img-1', pdq_hex: 'aa'.repeat(32) },
                { record_id: 'r2', image_artifact_id: 'img-2', pdq_hex: 'ab'.repeat(32) },
              ],
            },
          ],
        }),
      ),
    )
    renderPage()

    expect(await screen.findByText('Near-duplicate images')).toBeInTheDocument()
    // The set and its member images render, with the honesty caveat.
    expect(screen.getByText('near-duplicate image set')).toBeInTheDocument()
    expect(screen.getByText('img-1')).toBeInTheDocument()
    expect(
      screen.getByText(/lead for review, not an identification/),
    ).toBeInTheDocument()
  })

  it('drops the filter text when the case changes (B2-092)', async () => {
    // The filter is client-side. Carried into case B, a filename fragment from
    // case A matches none of case B's groups, so a case that does have
    // duplicates renders as though it has none — with the box, and the reason,
    // out of the examiner's sight.
    mock({
      group_count: 1,
      redundant_copies: 1,
      truncated: false,
      groups: [
        {
          hash: 'aaaa1111bbbb2222cccc',
          count: 2,
          members: [
            { id: 'm1', name: 'photo.jpg', path: '/DCIM/photo.jpg', artifact_type: 'FileEntry' },
            { id: 'm2', name: 'photo_copy.jpg', path: '/tmp/photo_copy.jpg', artifact_type: 'FileEntry' },
          ],
        },
      ],
    })
    server.use(
      http.get('/api/v1/cases/case-2/duplicates', () =>
        HttpResponse.json({
          group_count: 1,
          redundant_copies: 1,
          truncated: false,
          groups: [
            {
              hash: 'ffff9999eeee8888dddd',
              count: 2,
              members: [
                { id: 'n1', name: 'ledger.xlsx', path: '/docs/ledger.xlsx', artifact_type: 'FileEntry' },
                { id: 'n2', name: 'ledger_bak.xlsx', path: '/bak/ledger_bak.xlsx', artifact_type: 'FileEntry' },
              ],
            },
          ],
        }),
      ),
    )
    renderPageWithSwitcher()
    await screen.findByText('photo.jpg')

    await userEvent.type(screen.getByLabelText('Filter duplicates'), 'photo')
    expect(screen.getByText('photo.jpg')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Go to case-2' }))

    expect(await screen.findByText('ledger.xlsx')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter duplicates')).toHaveValue('')
  })
})
