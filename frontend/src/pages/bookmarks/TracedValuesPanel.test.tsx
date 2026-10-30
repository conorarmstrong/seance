import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { TracedValuesPanel } from './TracedValuesPanel'
import type { PinnedPivot } from '../pivot/api'

function pinned(over: Partial<PinnedPivot> = {}): PinnedPivot {
  return {
    id: 'p1',
    case_id: 'c1',
    value: '203.78.103.109',
    note: 'the address the exfil connected to',
    examiner: 'Analyst A',
    pinned_at: 1_757_000_000,
    total_matches: 9,
    grouped: 9,
    truncated: false,
    groups: [
      { kind: 'NetworkFlow', count: 6, samples: [] },
      { kind: 'DnsResolution', count: 3, samples: [] },
    ],
    ...over,
  }
}

function mock(pivots: PinnedPivot[]) {
  server.use(
    http.get('/api/v1/cases/c1/pivots', () =>
      HttpResponse.json({ pivots, count: pivots.length, note: 'n' }),
    ),
  )
}

function renderPanel() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <TracedValuesPanel caseId="c1" />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('TracedValuesPanel (§5.13)', () => {
  it('lists each pinned value with its counts, its author and what the report will do', async () => {
    mock([pinned()])
    renderPanel()

    const item = await screen.findByTestId('tv-item')
    expect(item).toHaveTextContent('203.78.103.109')
    expect(item).toHaveTextContent('9 artifacts')
    expect(item).toHaveTextContent('Analyst A')
    expect(item).toHaveTextContent('the address the exfil connected to')
    expect(item).toHaveTextContent('Network flows 6')
    expect(item).toHaveTextContent('DNS resolutions 3')
    // The panel says the counts are a snapshot and that the report re-checks
    // the value, so a reader about to write the report knows what it will say.
    expect(screen.getByTestId('traced-values')).toHaveTextContent(
      /at the moment it was pinned/,
    )
    expect(screen.getByTestId('traced-values')).toHaveTextContent(
      /re-checks the value/,
    )
  })

  /**
   * A capped pivot's per-kind counts do not add up to its total, and a sample
   * presented as a total is the defect class this project treats as HIGH.
   */
  it('says when the per-kind counts are a sample rather than a total', async () => {
    mock([pinned({ total_matches: 84_000, grouped: 5_000, truncated: true })])
    renderPanel()
    const note = await screen.findByTestId('tv-truncated')
    expect(note).toHaveTextContent(/are a sample/)
    expect(note).toHaveTextContent(/do not add up to the total/)
  })

  it('removes a pin when asked', async () => {
    mock([pinned()])
    const deleted: string[] = []
    server.use(
      http.delete('/api/v1/cases/c1/pivots/:id', ({ params }) => {
        deleted.push(String(params.id))
        return HttpResponse.json({ unpinned: String(params.id) })
      }),
    )
    renderPanel()
    await screen.findByTestId('tv-item')
    await userEvent.click(
      screen.getByRole('button', {
        name: 'Remove 203.78.103.109 from the case',
      }),
    )
    expect(deleted).toEqual(['p1'])
  })

  /** Nothing pinned, nothing on screen: the page has its own empty state. */
  it('renders nothing when no value is pinned', async () => {
    mock([])
    renderPanel()
    await new Promise((r) => setTimeout(r, 0))
    expect(screen.queryByTestId('traced-values')).not.toBeInTheDocument()
    expect(screen.queryByTestId('tv-error')).not.toBeInTheDocument()
  })

  /**
   * A failed load must not render as "nothing is pinned": an examiner would
   * write the report expecting no such section.
   */
  it('a failed load does not read as nothing pinned', async () => {
    server.use(
      http.get('/api/v1/cases/c1/pivots', () =>
        HttpResponse.json({ error: 'nope' }, { status: 500 }),
      ),
    )
    renderPanel()
    expect(await screen.findByTestId('tv-error')).toHaveTextContent(
      /Nothing\s+here says none are pinned/,
    )
  })
})
