import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { server } from '../test/server'
import { PivotDrawer } from './PivotDrawer'
import type { PinnedPivot, PivotResponse } from '../pages/pivot/api'

function renderDrawer(value = '203.78.103.109') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <PivotDrawer caseId="c1" value={value} onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function mock(body: PivotResponse) {
  server.use(http.get('/api/v1/cases/c1/pivot', () => HttpResponse.json(body)))
  // The drawer asks whether this value is already pinned (§5.13). Answered
  // with an empty list unless a test says otherwise.
  server.use(
    http.get('/api/v1/cases/c1/pivots', () =>
      HttpResponse.json({ pivots: [], count: 0, note: 'n' }),
    ),
  )
}

/** The case already holds a pin for this value. */
function mockPinned(over: Partial<PinnedPivot> = {}) {
  const pinned: PinnedPivot = {
    id: 'p1',
    case_id: 'c1',
    value: '203.78.103.109',
    note: 'the C2',
    examiner: 'Analyst A',
    pinned_at: 1_757_000_000,
    total_matches: 9,
    grouped: 9,
    truncated: false,
    groups: [],
    ...over,
  }
  server.use(
    http.get('/api/v1/cases/c1/pivots', () =>
      HttpResponse.json({ pivots: [pinned], count: 1, note: 'n' }),
    ),
  )
}

const FULL: PivotResponse = {
  value: '203.78.103.109',
  total_matches: 9,
  grouped: 9,
  truncated: false,
  groups: [
    {
      kind: 'NetworkFlow',
      count: 6,
      samples: [
        { artifact_id: 'a1', artifact_type: 'ParsedRecord', name: 'tcp 10.42.85.115 -> 203.78.103.109:443', snippet: null },
      ],
    },
    {
      kind: 'DnsResolution',
      count: 2,
      samples: [
        { artifact_id: 'a2', artifact_type: 'ParsedRecord', name: 'evil.example -> 203.78.103.109', snippet: null },
      ],
    },
    {
      kind: 'FileEntry',
      count: 1,
      samples: [
        { artifact_id: 'a3', artifact_type: 'FileEntry', name: 'notes.txt', snippet: null },
      ],
    },
  ],
}

describe('PivotDrawer', () => {
  it('groups everything touching a value by record kind, largest first', async () => {
    mock(FULL)
    renderDrawer()
    await waitFor(() =>
      expect(screen.getByText('Network flows')).toBeInTheDocument(),
    )
    expect(screen.getByText('DNS resolutions')).toBeInTheDocument()
    // Humanized labels, not raw type strings.
    expect(screen.queryByText('NetworkFlow')).not.toBeInTheDocument()
    // The exact case-wide total, not the sample size.
    expect(screen.getByText(/9 artifacts/)).toBeInTheDocument()
    // A group with more than its samples offers a way to the rest.
    expect(screen.getByText(/\+ 5 more/)).toBeInTheDocument()
    // Each sample links to its artifact.
    expect(
      screen.getByRole('link', { name: /tcp 10.42.85.115/ }),
    ).toHaveAttribute('href', '/cases/c1/artifacts/a1')
  })

  it('says plainly when nothing references the value', async () => {
    mock({ value: '10.0.0.1', total_matches: 0, grouped: 0, truncated: false, groups: [] })
    renderDrawer('10.0.0.1')
    await waitFor(() =>
      expect(
        screen.getByText(/No artifact in this case references/),
      ).toBeInTheDocument(),
    )
  })

  it('marks the counts as a sample when the match set was capped', async () => {
    mock({ ...FULL, total_matches: 40000, grouped: 5000, truncated: true })
    renderDrawer()
    await waitFor(() =>
      expect(screen.getByText(/showing the first 5,000/)).toBeInTheDocument(),
    )
    expect(screen.getByText(/40,000 artifacts/)).toBeInTheDocument()
  })

  it('surfaces a failed pivot instead of a blank drawer', async () => {
    server.use(
      http.get('/api/v1/cases/c1/pivot', () =>
        HttpResponse.json({ error: { message: 'boom' } }, { status: 500 }),
      ),
    )
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    renderDrawer()
    await waitFor(() =>
      expect(screen.getByText(/Pivot failed/)).toBeInTheDocument(),
    )
    spy.mockRestore()
  })
})

/**
 * Pinning the answer to the case (ROADMAP §5.13).
 *
 * The pivot answer was a transient panel: nothing carried "these nine
 * artifacts are what referenced that address" into the report, so it was
 * re-run while writing or transcribed into prose where nothing could check it.
 *
 * The assertions that matter are about what the control CLAIMS. It records the
 * answer as it stands, not a live link, and a pin that failed must not read as
 * a pin — an examiner would write the report expecting the section to be there.
 */
describe('PivotDrawer — pinning to the case', () => {
  it('pins the answer with a note and says what pinning records', async () => {
    mock(FULL)
    const posted: unknown[] = []
    server.use(
      http.post('/api/v1/cases/c1/pivots', async ({ request }) => {
        posted.push(await request.json())
        return HttpResponse.json({
          id: 'p1',
          case_id: 'c1',
          value: '203.78.103.109',
          note: 'the C2',
          examiner: 'Analyst A',
          pinned_at: 1_757_000_000,
          total_matches: 9,
          grouped: 9,
          truncated: false,
          groups: [],
        })
      }),
    )
    renderDrawer()

    const pin = await screen.findByTestId('pivot-pin')
    // It says the answer is recorded as it stands, and that the report
    // re-checks the value — not that the section stays live.
    expect(pin).toHaveTextContent(/as it stands/)
    expect(pin).toHaveTextContent(/re-checks the value/)
    expect(pin).toHaveTextContent(/Values Traced Across the Evidence/)

    await userEvent.type(
      screen.getByLabelText('Why this value matters'),
      'the C2',
    )
    await userEvent.click(
      screen.getByRole('button', { name: /Pin this answer to the case/ }),
    )
    await waitFor(() =>
      expect(posted).toEqual([{ value: '203.78.103.109', note: 'the C2' }]),
    )
  })

  it('shows who pinned an already-pinned value, and offers to re-pin or remove', async () => {
    mock(FULL)
    mockPinned()
    renderDrawer()

    const pinned = await screen.findByTestId('pivot-pinned')
    expect(pinned).toHaveTextContent('Analyst A')
    // What the report will do with it, so a reader of this panel knows.
    expect(pinned).toHaveTextContent(/as it was when pinned/)
    expect(pinned).toHaveTextContent(/re-checks the value/)
    expect(
      screen.getByRole('button', { name: /Re-pin with the current answer/ }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Remove from the case/ }),
    ).toBeInTheDocument()
    // And no second "pin this" control: the value is already pinned.
    expect(screen.queryByTestId('pivot-pin')).not.toBeInTheDocument()
  })

  /** A pin that failed must not read as a pin. */
  it('says a failed pin did not go through', async () => {
    mock(FULL)
    server.use(
      http.post('/api/v1/cases/c1/pivots', () =>
        HttpResponse.json({ error: 'nope' }, { status: 500 }),
      ),
    )
    renderDrawer()
    await screen.findByTestId('pivot-pin')
    await userEvent.click(
      screen.getByRole('button', { name: /Pin this answer to the case/ }),
    )
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/did not go through/)
    expect(alert).toHaveTextContent(/Nothing was\s+pinned/)
  })

  /**
   * "This address appears nowhere in the evidence" is an answer worth carrying
   * into the report — and it is the one an examiner is most likely to be asked
   * to stand behind.
   */
  it('offers to pin a value that matched nothing', async () => {
    mock({
      value: 'nothing@example.com',
      total_matches: 0,
      grouped: 0,
      truncated: false,
      groups: [],
    })
    renderDrawer('nothing@example.com')
    expect(await screen.findByTestId('pivot-pin')).toBeInTheDocument()
  })
})
