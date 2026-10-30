import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { RelatedTimelineTab } from './RelatedTimelineTab'

const URL_PATH = '/api/v1/cases/c1/timeline/related/a1'

function event(over: Record<string, unknown>) {
  return {
    id: 'e',
    case_id: 'c1',
    artifact_id: 'a1',
    timestamp: 1_700_000_000,
    timestamp_subsec_nanos: 0,
    timestamp_desc: 'Modified',
    source_module: 'plugin.ntfs',
    short_desc: 'report.docx',
    full_details: '',
    ...over,
  }
}

function renderTab(parentId: string | null = 'p1') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RelatedTimelineTab caseId="c1" artifactId="a1" parentId={parentId} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('RelatedTimelineTab', () => {
  it('lists the related events newest first with their source module and relation', async () => {
    server.use(
      http.get(URL_PATH, () =>
        HttpResponse.json({
          events: [
            event({ id: 'e1', timestamp: 1_700_000_300, short_desc: 'own event' }),
            event({
              id: 'e2',
              artifact_id: 'p1',
              timestamp: 1_700_000_200,
              source_module: 'plugin.evtx',
              short_desc: 'parent event',
            }),
            event({
              id: 'e3',
              artifact_id: 'k9',
              timestamp: 1_700_000_100,
              short_desc: 'other event',
            }),
          ],
          truncated: false,
          cap: 2000,
        }),
      ),
    )
    renderTab()
    const table = await screen.findByRole('table', { name: /events around this artifact/i })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(3)
    expect(rows[0]).toHaveTextContent('own event')
    expect(rows[0]).toHaveTextContent('2023-11-14 22:18:20 UTC')
    expect(rows[0]).toHaveTextContent(/this artifact/i)
    expect(rows[1]).toHaveTextContent('plugin.evtx')
    expect(rows[1]).toHaveTextContent(/parent/i)
    // Child and sibling cannot be told apart from the response alone, so the
    // row says so rather than guessing; it links to the artifact instead.
    expect(rows[2]).toHaveTextContent(/child or sibling/i)
    expect(within(rows[2]).getByRole('link')).toHaveAttribute('href', '/cases/c1/artifacts/k9')
    expect(screen.getByText(/all 3 related events/i)).toBeInTheDocument()
  })

  it('says the list is capped when truncated is true', async () => {
    server.use(
      http.get(URL_PATH, () =>
        HttpResponse.json({ events: [event({ id: 'e1' })], truncated: true, cap: 2000 }),
      ),
    )
    renderTab()
    const note = await screen.findByTestId('av-related-capped')
    expect(note).toHaveTextContent(/stops at 2,000 events/i)
    expect(note).toHaveTextContent(/not the whole history/i)
    expect(screen.queryByText(/all 1 related event/i)).toBeNull()
  })

  it('says there are no dated events rather than rendering an empty table', async () => {
    server.use(
      http.get(URL_PATH, () => HttpResponse.json({ events: [], truncated: false, cap: 2000 })),
    )
    renderTab()
    expect(
      await screen.findByText(/no timeline events are recorded for this artifact/i),
    ).toBeInTheDocument()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('states a failed load as a failure, not as an empty history', async () => {
    server.use(
      http.get(URL_PATH, () =>
        HttpResponse.json({ error: { code: 'INTERNAL', message: 'db down' } }, { status: 500 }),
      ),
    )
    renderTab()
    const note = await screen.findByRole('alert')
    expect(note).toHaveTextContent(/could not be loaded/i)
    expect(note).toHaveTextContent(/nothing here says this artifact has no events/i)
  })
})
