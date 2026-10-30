import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { ParsedRecord } from './api'
import { AggregateEmpty } from './aggregate'
import { RecordsViewerPage } from './RecordsViewerPage'

const CASE_ID = 'case-1'

function mockByType(byType: Record<string, ParsedRecord[]>) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const type = url.searchParams.get('type') ?? ''
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 50)
      const all = byType[type] ?? []
      const start = (page - 1) * pageSize
      return HttpResponse.json({
        records: all.slice(start, start + pageSize),
        total: all.length,
        page,
        page_size: pageSize,
        type,
      })
    }),
  )
}

function rec(id: string, metadata: Record<string, unknown>): ParsedRecord {
  return { id, parent_id: `a-${id}`, artifact_type: 'ParsedRecord', metadata }
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

/**
 * The aggregate viewers list a SUBSET of what they load: the rows carrying the
 * subtype they render. When rows arrive and none of them qualifies, the empty
 * state used to say "No contact records were parsed for this case" — a claim
 * about the address book, made while holding records the viewer simply did not
 * recognise. A parser that stops stamping `subtype`, or one whose rows are all
 * summaries, turns a populated case into that sentence.
 */
describe('aggregate viewer empty states', () => {
  it('does not report an unlisted contact shape as an empty address book', async () => {
    mockByType({
      Contact: [
        rec('c-sum', {
          type: 'Contact',
          subtype: 'summary',
          contact_count: 250,
        }),
        rec('c-1', { type: 'Contact', display_name: 'Alice Example' }),
      ],
    })

    renderViewer('Contact')

    expect(await screen.findByText('No contacts')).toBeInTheDocument()
    const note = await screen.findByRole('note')
    expect(note.textContent).toMatch(/2 records were loaded for this type/)
    expect(note.textContent).toMatch(/none of them is a contact row/)
    expect(note.textContent).toMatch(/not a finding that there were none/)
  })

  it('does not report unlisted call rows as a phone that made no calls', async () => {
    mockByType({
      CallLog: [rec('call-x', { type: 'CallLog', contact: '+15551110000' })],
    })

    renderViewer('CallLog')

    expect(await screen.findByText('No calls')).toBeInTheDocument()
    const note = await screen.findByRole('note')
    expect(note.textContent).toMatch(/1 record was loaded for this type/)
    expect(note.textContent).toMatch(/none of them is a call row/)
  })

  it('says nothing extra when nothing was loaded at all', () => {
    // A note that is always present is a note an examiner learns to skip. The
    // zero-record case does not reach a viewer through the page shell, so the
    // branch is asserted on the component itself.
    render(
      <AggregateEmpty
        title="No contacts"
        body="No contact records were parsed for this case."
        loaded={0}
        listed={0}
        listedNoun="contact row"
      />,
    )

    expect(screen.getByText('No contacts')).toBeInTheDocument()
    expect(screen.queryByRole('note')).not.toBeInTheDocument()
  })
})
