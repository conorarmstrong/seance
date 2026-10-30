import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { ToastProvider } from '../../components/toast/ToastProvider'
import type { AuditEvent } from '../../api/types'
import { AuditLogPage } from './AuditLogPage'

const CASE_ID = 'case-1'

const events: AuditEvent[] = [
  {
    timestamp: '2026-01-05T10:00:00Z',
    user_id: 'examiner1',
    action: 'case.open',
    resource_type: 'case',
    resource_id: 'resource-aaaa-bbbb-cccc-dddd',
    details: '{"ip":"10.0.0.5","client":"web"}',
  },
  {
    timestamp: '2026-01-05T10:01:00Z',
    user_id: 'examiner2',
    action: 'artifact.view',
    resource_type: 'artifact',
    resource_id: 'resource-eeee',
    details: 'viewed hex at offset 0',
  },
]

interface CapturedRequest {
  limit: string | null
  offset: string | null
  user: string | null
  action: string | null
  resource_type: string | null
  from: string | null
  to: string | null
}

let requests: CapturedRequest[]

beforeEach(() => {
  requests = []
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/audit_log`, ({ request }) => {
      const url = new URL(request.url)
      const p = (key: string) => url.searchParams.get(key)
      requests.push({
        limit: p('limit'),
        offset: p('offset'),
        user: p('user'),
        action: p('action'),
        resource_type: p('resource_type'),
        from: p('from'),
        to: p('to'),
      })
      const user = p('user')
      const filtered = user
        ? events.filter((e) => e.user_id === user)
        : events
      return HttpResponse.json({
        events: filtered,
        total: user ? filtered.length : 300,
        limit: Number(p('limit') ?? 100),
        offset: Number(p('offset') ?? 0),
      })
    }),
  )
})

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={[`/cases/${CASE_ID}/audit`]}>
          <Routes>
            <Route path="/cases/:caseId/audit" element={<AuditLogPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

/** Switches the `:caseId` route param in place, without remounting the page. */
function CaseSwitcher() {
  const navigate = useNavigate()
  return (
    <button type="button" onClick={() => navigate('/cases/case-2/audit')}>
      Go to case-2
    </button>
  )
}

function renderPageWithSwitcher() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={[`/cases/${CASE_ID}/audit`]}>
          <CaseSwitcher />
          <Routes>
            <Route path="/cases/:caseId/audit" element={<AuditLogPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('AuditLogPage', () => {
  it('renders audit events with the framing line', async () => {
    renderPage()
    expect(
      screen.getByText('Every examiner action recorded for this case.'),
    ).toBeInTheDocument()
    expect(await screen.findByText('case.open')).toBeInTheDocument()
    expect(screen.getByText('2026-01-05 10:00:00 UTC')).toBeInTheDocument()
    expect(screen.getByText('examiner1')).toBeInTheDocument()
    expect(screen.getByText('artifact')).toBeInTheDocument()
    // Truncated resource id keeps the full value in a title attribute.
    const truncated = screen.getByTitle('resource-aaaa-bbbb-cccc-dddd')
    expect(truncated).toBeInTheDocument()
  })

  it('shows an error state when the log fails to load', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log`, () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'audit unavailable' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    expect(await screen.findByText(/audit unavailable/)).toBeInTheDocument()
  })

  it('pages forward with offset and resets on limit change', async () => {
    renderPage()
    await screen.findByText('case.open')
    expect(requests[0]).toMatchObject({ limit: '100', offset: '0' })

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() =>
      expect(requests.at(-1)).toMatchObject({ limit: '100', offset: '100' }),
    )

    await user.selectOptions(
      screen.getByLabelText(/rows per page/i),
      '250',
    )
    await waitFor(() =>
      expect(requests.at(-1)).toMatchObject({ limit: '250', offset: '0' }),
    )
  })

  it('sends server-side filter params and resets the offset', async () => {
    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    // Move off the first page so a filter change can reset it.
    await user.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() =>
      expect(requests.at(-1)).toMatchObject({ offset: '100' }),
    )

    await user.type(screen.getByLabelText('Filter by action'), 'case.open')
    await waitFor(() =>
      expect(requests.at(-1)).toMatchObject({
        action: 'case.open',
        offset: '0',
      }),
    )

    await user.type(screen.getByLabelText('Filter by resource type'), 'case')
    await waitFor(() =>
      expect(requests.at(-1)).toMatchObject({ resource_type: 'case' }),
    )

    fireEvent.change(screen.getByLabelText('From (UTC)'), {
      target: { value: '2026-01-01T00:00' },
    })
    fireEvent.change(screen.getByLabelText('To (UTC)'), {
      target: { value: '2026-01-31T23:59' },
    })
    await waitFor(() =>
      expect(requests.at(-1)).toMatchObject({
        from: '2026-01-01T00:00:00.000Z',
        to: '2026-01-31T23:59:00.000Z',
        offset: '0',
      }),
    )
  })

  /** An intact, fully keyed verdict; override to shape the other cases. */
  const verdictJson = (over: Record<string, unknown> = {}) => ({
    valid: true,
    checked: 300,
    broken_at: null,
    tamper_evident: true,
    keyed_rows: 300,
    unkeyed_rows: 0,
    tamper_evident_from: 1,
    break_reason: null,
    tamper_evidence_note: 'The chain is keyed (SEANCE_AUDIT_HMAC_KEY is set).',
    head_id: 300,
    head_hash: 'a'.repeat(64),
    completeness: {
      anchored: false,
      note: 'A hash chain cannot attest that none were deleted from the end.',
    },
    scope: 'instance',
    scope_note: 'instance-wide hash chain',
    ...over,
  })

  it('verifies the hash chain and reports an intact chain', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(verdictJson()),
      ),
    )
    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Verify chain' }))
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent('Chain intact — 300 entries verified')
  })

  it('says completeness was NOT checked, and shows the head to anchor, when no anchor was supplied', async () => {
    // An intact chain with no external anchor must not read as "complete": a
    // deleted tail is invisible to the chain, so the banner has to say the
    // completeness question was unchecked and hand over the head to anchor.
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(verdictJson()),
      ),
    )
    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Verify chain' }))
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent(/Completeness not checked/i)
    expect(banner).toHaveTextContent(/Chain head to anchor: entry #300/)
    expect(banner).toHaveTextContent('a'.repeat(64))
  })

  it('verifies the hash chain and reports a broken chain prominently', async () => {
    let release: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, async () => {
        await gate
        return HttpResponse.json(verdictJson({ valid: false, checked: 120, broken_at: 57, tamper_evident: false, keyed_rows: 56, unkeyed_rows: 0, tamper_evident_from: 1, break_reason: 'row 57 does not recompute under the current key' }))
      }),
    )
    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Verify chain' }))
    // Pending state while the verification runs.
    const pending = screen.getByRole('button', { name: 'Verifying…' })
    expect(pending).toBeDisabled()

    release()
    const banner = await screen.findByRole('alert')
    expect(banner).toHaveTextContent('CHAIN BROKEN at entry #57')
    expect(
      screen.getByRole('button', { name: 'Verify chain' }),
    ).toBeEnabled()
  })

  it('does not present the chain verdict as a finding about this case alone (B6-028)', async () => {
    // `verify_audit_chain` ignores the case id and walks the whole audit_log
    // table: a hash chain has no per-case subsequence. A break introduced in
    // case A therefore fails verification for every case, and a banner reading
    // only "CHAIN BROKEN" under case B's log is a tampering finding recorded
    // against the wrong case.
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(verdictJson({ valid: false, checked: 120, broken_at: 57, tamper_evident: false, keyed_rows: 56, unkeyed_rows: 0, tamper_evident_from: 1, break_reason: 'row 57 does not recompute under the current key' })),
      ),
    )
    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Verify chain' }))
    const banner = await screen.findByRole('alert')
    expect(banner).toHaveTextContent('CHAIN BROKEN at entry #57')
    expect(banner).toHaveTextContent(/spans every case in this installation/)
    expect(banner).toHaveTextContent(
      /not necessarily one of this case’s/,
    )
  })

  it('scopes an intact-chain verdict to the whole audit log, not this case (B6-028)', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(verdictJson()),
      ),
    )
    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Verify chain' }))
    const banner = await screen.findByRole('status')
    // "300 entries verified" over a case holding five of them overstates what
    // was checked here unless the span is named.
    expect(banner).toHaveTextContent(
      /across the whole audit log, which covers every case in this installation, not this case alone/,
    )
  })

  it('says an intact keyed chain is tamper-evident (DEPLOY-001)', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(verdictJson()),
      ),
    )
    renderPage()
    await screen.findByText('case.open')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Verify chain' }))
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent(/Tamper-evident: every entry was written under a server-held key/)
  })

  it('never calls an intact unkeyed chain tamper-evident (DEPLOY-001)', async () => {
    // Test and stock deployments used to be unkeyed, and "Chain intact" on its
    // own reads as "unaltered". A database writer can manufacture that verdict.
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(
          verdictJson({ tamper_evident: false, keyed_rows: 0, unkeyed_rows: 300, tamper_evident_from: null }),
        ),
      ),
    )
    renderPage()
    await screen.findByText('case.open')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Verify chain' }))
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent('Chain intact — 300 entries verified')
    expect(banner).toHaveTextContent(/NOT tamper-evident: the chain is unkeyed/)
    expect(banner).toHaveTextContent(/internally consistent, not that it is unaltered/)
  })

  it('names the entry from which a partially keyed chain is tamper-evident (DEPLOY-001)', async () => {
    // A key set on an existing log: the old rows are internally consistent
    // only, the new rows are evidence. Neither adjective alone is true of the
    // whole chain, so the banner states the boundary the server reports.
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(
          verdictJson({ tamper_evident: false, keyed_rows: 60, unkeyed_rows: 240, tamper_evident_from: 241 }),
        ),
      ),
    )
    renderPage()
    await screen.findByText('case.open')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Verify chain' }))
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent(/Tamper-evident from entry #241 only/)
    expect(banner).toHaveTextContent(/240 earlier entries were written unkeyed/)
    expect(banner).toHaveTextContent(/From entry #241 the chain is keyed \(60 entries\)/)
    expect(banner).not.toHaveTextContent(/every entry was written under a server-held key/)
  })

  it('shows the server\'s reason for a broken chain (DEPLOY-001)', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(
          verdictJson({
            valid: false,
            checked: 4,
            broken_at: 4,
            tamper_evident: false,
            keyed_rows: 3,
            unkeyed_rows: 0,
            break_reason:
              'row 4 recomputes only as an unkeyed digest but follows keyed rows; a keyed chain cannot legitimately continue unkeyed',
          }),
        ),
      ),
    )
    renderPage()
    await screen.findByText('case.open')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Verify chain' }))
    const banner = await screen.findByRole('alert')
    expect(banner).toHaveTextContent('CHAIN BROKEN at entry #4')
    expect(banner).toHaveTextContent(/Reason: row 4 recomputes only as an unkeyed digest but follows keyed rows/)
  })

  it('keeps the expanded row attached to its event when data changes', async () => {
    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    // Expand the examiner2 row (second in the unfiltered page).
    await user.click(screen.getByText('artifact.view'))
    expect(screen.getByTestId('audit-details').textContent).toContain(
      'viewed hex at offset 0',
    )

    // Server-side filter changes the page contents: examiner2's event is
    // now the only (first) row. Expansion must follow the event, not the
    // row index.
    await user.type(screen.getByLabelText('Filter by user'), 'examiner2')
    await waitFor(() =>
      expect(screen.queryByText('case.open')).not.toBeInTheDocument(),
    )
    expect(screen.getByText('artifact.view')).toBeInTheDocument()
    expect(screen.getByTestId('audit-details').textContent).toContain(
      'viewed hex at offset 0',
    )
  })

  it('expands a row to show pretty-printed JSON details', async () => {
    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    await user.click(screen.getByText('case.open'))
    const pre = await screen.findByTestId('audit-details')
    expect(pre.textContent).toContain('"ip": "10.0.0.5"')
  })

  it('exports the audit log as CSV via POST, carrying the active filters', async () => {
    let exportUrl: URL | null = null
    server.use(
      http.post(`/api/v1/cases/${CASE_ID}/export/audit_log/csv`, ({ request }) => {
        exportUrl = new URL(request.url)
        return new HttpResponse('timestamp,user,action\n', {
          headers: { 'Content-Type': 'text/csv' },
        })
      }),
    )
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()

    renderPage()
    await screen.findByText('case.open')

    const user = userEvent.setup()
    // Apply a couple of filters, then export: the request must reflect them so
    // the CSV matches the visible table rather than the whole log (BUG-074).
    await user.type(screen.getByLabelText('Filter by action'), 'case.open')
    await user.type(screen.getByLabelText('Filter by user'), 'examiner1')
    await waitFor(() =>
      expect(requests.at(-1)).toMatchObject({
        action: 'case.open',
        user: 'examiner1',
      }),
    )

    await user.click(screen.getByRole('button', { name: 'Export CSV' }))
    await waitFor(() => expect(exportUrl).not.toBeNull())
    expect(exportUrl!.searchParams.get('action')).toBe('case.open')
    expect(exportUrl!.searchParams.get('user')).toBe('examiner1')
  })

  it('never carries a filter into another case\'s log (B2-027)', async () => {
    // The filters describe who did what in the case on screen. Left in place
    // across a `:caseId` change they trim case B's audit log by criteria the
    // examiner entered for case A — most often to nothing, which reads as
    // "case B has no audit history".
    const case2Requests: (string | null)[] = []
    server.use(
      http.get('/api/v1/cases/case-2/audit_log', ({ request }) => {
        case2Requests.push(new URL(request.url).searchParams.get('user'))
        return HttpResponse.json({
          events: [
            {
              timestamp: '2026-02-01T09:00:00Z',
              user_id: 'examiner9',
              action: 'case.open',
              resource_type: 'case',
              resource_id: 'case-2',
              details: null,
            },
          ],
          total: 1,
          limit: 100,
          offset: 0,
        })
      }),
    )
    renderPageWithSwitcher()
    await screen.findByText('examiner1')

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Filter by user'), 'examiner1')
    await waitFor(() =>
      expect(requests.at(-1)).toMatchObject({ user: 'examiner1' }),
    )

    await user.click(screen.getByRole('button', { name: 'Go to case-2' }))

    expect(await screen.findByText('examiner9')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by user')).toHaveValue('')
    // Every request against case B went out unfiltered.
    expect(case2Requests.every((u) => u === null)).toBe(true)
    expect(case2Requests.length).toBeGreaterThan(0)
  })

  it('does not show one case\'s chain verdict over another case\'s log', async () => {
    // "Chain intact" is an integrity statement about a specific audit log.
    // Shown above a different case's table it attributes one case's verification
    // to another.
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/audit_log/verify`, () =>
        HttpResponse.json(verdictJson()),
      ),
      http.get('/api/v1/cases/case-2/audit_log', () =>
        HttpResponse.json({
          events: [
            {
              timestamp: '2026-02-01T09:00:00Z',
              user_id: 'examiner9',
              action: 'case.open',
              resource_type: 'case',
              resource_id: 'case-2',
              details: null,
            },
          ],
          total: 1,
          limit: 100,
          offset: 0,
        }),
      ),
    )
    renderPageWithSwitcher()
    await screen.findByText('examiner1')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Verify chain' }))
    expect(await screen.findByText(/Chain intact/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Go to case-2' }))

    expect(await screen.findByText('examiner9')).toBeInTheDocument()
    expect(screen.queryByText(/Chain intact/)).toBeNull()
  })
})

describe('audit log keyboard navigation', () => {
  /** The audit rows, without the expanded detail rows. */
  function rows(): HTMLElement[] {
    return Array.from(document.querySelectorAll<HTMLElement>('tr.audit-row'))
  }

  it('is one tab stop and walks the entries with the arrows', async () => {
    renderPage()
    await screen.findByText('examiner1')

    // A page holds up to 500 entries. One tab stop for the table, not 500.
    expect(
      rows().filter((r) => r.getAttribute('tabindex') === '0'),
    ).toHaveLength(1)

    rows()[0].focus()
    await userEvent.keyboard('{ArrowDown}')
    expect(rows()[1]).toHaveFocus()
    await userEvent.keyboard('{Home}')
    expect(rows()[0]).toHaveFocus()
  })

  it('opens and closes an entry’s details from the keyboard', async () => {
    // The details are where an action's parameters live — the part an examiner
    // quotes when reconstructing what was done to the evidence. Reaching them
    // required a mouse: the row's only handler was onClick.
    renderPage()
    await screen.findByText('examiner1')

    rows()[0].focus()
    expect(rows()[0]).toHaveAttribute('aria-expanded', 'false')
    await userEvent.keyboard('{Enter}')

    expect(await screen.findByTestId('audit-details')).toBeInTheDocument()
    expect(rows()[0]).toHaveAttribute('aria-expanded', 'true')

    await userEvent.keyboard('{Enter}')
    await waitFor(() => expect(screen.queryByTestId('audit-details')).toBeNull())
  })
})

describe('audit rows hold no tab stops of their own', () => {
  it('leaves the row as the whole table’s only stop', async () => {
    // The roving stop on the row only buys anything while nothing inside the
    // row is tabbable — one control per row on a 500-entry page would put the
    // presses straight back. The filter and action controls above the table
    // are unaffected; this is about the rows.
    renderPage()
    await screen.findByText('examiner1')

    const stops = Array.from(
      document.querySelectorAll<HTMLElement>(
        'tr.audit-row a, tr.audit-row button, tr.audit-row input',
      ),
    ).filter((el) => el.getAttribute('tabindex') !== '-1')
    expect(stops).toHaveLength(0)
  })
})
