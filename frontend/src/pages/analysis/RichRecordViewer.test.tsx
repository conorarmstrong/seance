import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { ParsedRecord } from './api'
import { RecordsViewerPage } from './RecordsViewerPage'

const CASE_ID = 'case-1'
/** The record type is served by a rich viewer with a Filter box. */
const TYPE = 'EvtxLogEntry'

function evt(n: number): ParsedRecord {
  return {
    id: `e${n}`,
    parent_id: `a-e${n}`,
    artifact_type: 'ParsedRecord',
    metadata: {
      type: TYPE,
      event_id: 4624,
      level_description: 'Information',
      provider_name: 'Security-Auditing',
      channel: 'Security',
      timestamp: 1_700_000_000 + n,
      short_desc: `logon ${n}`,
    },
  }
}

/**
 * Serve `held` records out of a case that holds `total` of them, so the loaded
 * slice and the population are different numbers — which is the condition the
 * scope note exists for.
 */
function mockRecords(held: ParsedRecord[], total = held.length) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 50)
      const start = (page - 1) * pageSize
      return HttpResponse.json({
        records: held.slice(start, start + pageSize),
        total,
        page,
        page_size: pageSize,
        type: TYPE,
      })
    }),
  )
}

function renderViewer() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/${TYPE}`]}>
        <Routes>
          <Route
            path="/cases/:caseId/analysis/:type"
            element={<RecordsViewerPage />}
          />
          <Route
            path="/cases/:caseId/artifacts/:artifactId"
            element={<div>artifact page</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** The record rows of the rich table, without its spacer rows. */
function rows(): HTMLElement[] {
  return Array.from(
    document.querySelectorAll<HTMLElement>('.rv-table tbody tr[data-index]'),
  )
}

describe('rich record viewer: what the tiles and bars are computed over', () => {
  it('says the charts rank the loaded rows, not the case, when they differ', async () => {
    // The Filter box moved to the server; the stat tiles, the histogram and the
    // frequency bars did not. On a type with two million records a "top
    // applications" bar chart of the first six hundred rows presented as a
    // ranking of the case is the same false population the old filter caveat
    // guarded against — so this limitation keeps a sentence of its own.
    mockRecords([evt(1), evt(2), evt(3)], 2_100_000)
    renderViewer()

    const note = await screen.findByTestId('rv-charts-scope')
    expect(note.textContent).toMatch(/stat tiles, the histogram and the bars/)
    expect(note.textContent).toMatch(/3 .* loaded so far, not over all 2,100,000/)
  })

  it('says nothing about scope once the whole type is loaded', async () => {
    // With every record of the type in the browser the charts DO describe the
    // case, and a caveat on every screen is one an examiner learns to skip past.
    mockRecords([evt(1), evt(2)])
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(2))
    expect(screen.queryByTestId('rv-charts-scope')).toBeNull()
  })
})

describe('rich record viewer: keyboard', () => {
  it('is one tab stop, and the arrows walk the rows', async () => {
    mockRecords([evt(1), evt(2), evt(3)])
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(3))
    const tabbable = rows().filter(
      (r) => r.getAttribute('tabindex') === '0',
    )
    expect(tabbable).toHaveLength(1)

    rows()[0].focus()
    await userEvent.keyboard('{ArrowDown}')
    expect(rows()[1]).toHaveFocus()
    await userEvent.keyboard('{End}')
    expect(rows()[2]).toHaveFocus()
  })

  it('opens the focused record with Enter', async () => {
    mockRecords([evt(1), evt(2)])
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(2))
    rows()[0].focus()
    await userEvent.keyboard('{ArrowDown}{Enter}')
    expect(await screen.findByText('artifact page')).toBeInTheDocument()
  })

  it('numbers its rows against everything the table holds', async () => {
    mockRecords([evt(1), evt(2), evt(3)])
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(3))
    // Windowing hides rows from the DOM, so the row's own number has to come
    // from the set rather than from its position in the rendered slice.
    expect(document.querySelector('.rv-table')).toHaveAttribute(
      'aria-rowcount',
      '4',
    )
    expect(rows()[2]).toHaveAttribute('aria-rowindex', '4')
  })
})

describe('record table rows hold no tab stops of their own', () => {
  it('leaves the row as the only stop, with Enter reaching the artifact', async () => {
    // The roving tab stop buys nothing if each row still carries a tabbable
    // "open" link: a 60-row window would put 60 presses between the Filter box
    // and whatever follows the table, which is the cost the hook exists to
    // remove. The link stays clickable and stays the row's Enter destination.
    mockRecords([evt(1), evt(2), evt(3)])
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(3))
    const stops = Array.from(
      document.querySelectorAll<HTMLElement>(
        '.rv-table tbody tr a, .rv-table tbody tr button, .rv-table tbody tr input',
      ),
    ).filter((el) => el.getAttribute('tabindex') !== '-1')
    expect(stops).toHaveLength(0)
    // Still a real link: clickable, copyable, and pointed at the artifact.
    expect(
      document.querySelector('.rv-table tbody tr a'),
    ).toHaveAttribute('href', '/cases/case-1/artifacts/e1')
  })
})

/**
 * `GET /cases/:id/records` now takes `q` + `q_keys`, so the Filter box is a
 * query against the whole record type rather than a scan of the rows the
 * browser happens to be holding. These pin the three things that changes: the
 * request carries the term, the counts describe the matching set, and the
 * caveat that described the old limitation is gone rather than reworded.
 */
describe('rich record viewer: the Filter box queries the case', () => {
  /** Every records request the viewer made, newest last. */
  let requests: URL[] = []

  /**
   * A server that actually applies `q` over `q_keys`, so the rows the viewer
   * shows come back from the query rather than from a browser-side scan. It
   * also reports the two populations the response is required to carry: the
   * matching `total` and the type's own `type_total`.
   */
  function mockSearchableRecords(
    all: ParsedRecord[],
    typeTotal = all.length,
    /** Claim more matches than are served, so loaded < matching. */
    claimMatching?: number,
  ) {
    requests = []
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        requests.push(url)
        const q = url.searchParams.get('q')
        const keys = (url.searchParams.get('q_keys') ?? '')
          .split(',')
          .filter(Boolean)
        const matching = q
          ? all.filter((r) =>
              keys.some((k) =>
                String(r.metadata[k] ?? '')
                  .toLowerCase()
                  .includes(q.toLowerCase()),
              ),
            )
          : all
        const page = Number(url.searchParams.get('page') ?? 1)
        const pageSize = Number(url.searchParams.get('page_size') ?? 50)
        const start = (page - 1) * pageSize
        return HttpResponse.json({
          records: matching.slice(start, start + pageSize),
          total: claimMatching ?? matching.length,
          type_total: typeTotal,
          unfilterable_metadata: q ? 0 : null,
          filtered: !!q,
          q,
          q_keys: keys,
          q_match: 'ascii_case_insensitive_substring',
          sort: url.searchParams.get('sort'),
          order: url.searchParams.get('order') ?? 'asc',
          order_by: url.searchParams.get('sort') ? 'metadata_key' : 'ingest',
          page,
          page_size: pageSize,
          type: TYPE,
        })
      }),
    )
  }

  it('sends the term to the server and shows what the case matched', async () => {
    mockSearchableRecords([evt(1), evt(2), evt(3)], 2_100_000)
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(3))
    await userEvent.type(
      screen.getByRole('textbox', { name: /^Filter / }),
      'logon 2',
    )

    await waitFor(() => expect(rows()).toHaveLength(1))
    const sent = requests[requests.length - 1]
    expect(sent.searchParams.get('q')).toBe('logon 2')
    // The keys the term applies to are the viewer's own search fields; the
    // server refuses `q` without them.
    expect(sent.searchParams.get('q_keys')).toContain('short_desc')
    expect(sent.searchParams.get('page')).toBe('1')
  })

  it('no longer warns that a term missing here may not be missing from the case', async () => {
    // The warning described a browser-side scan of the loaded rows. The scan is
    // gone, so the sentence must go with it — a caveat that outlives what it
    // described teaches the examiner to skip caveats. More matching records
    // than have been fetched is the shape that used to print it.
    mockSearchableRecords([evt(1), evt(2), evt(3)], 2_100_000, 900)
    renderViewer()

    await waitFor(() => expect(rows().length).toBeGreaterThan(0))
    expect(screen.queryByTestId('rv-filter-scope')).toBeNull()

    await userEvent.type(
      screen.getByRole('textbox', { name: /^Filter / }),
      'sysmon',
    )
    await waitFor(() => expect(rows()).toHaveLength(0))
    expect(screen.queryByTestId('rv-filter-scope')).toBeNull()
    expect(document.body.textContent).not.toMatch(
      /term missing here is not a term missing from the case/,
    )
  })

  it('states the matching population and the type population side by side', async () => {
    mockSearchableRecords([evt(1), evt(2), evt(3)], 2_100_000)
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(3))
    await userEvent.type(
      screen.getByRole('textbox', { name: /^Filter / }),
      'logon',
    )
    await waitFor(() => expect(rows()).toHaveLength(3))

    // "3 shown" alone is unreadable: three of what? The screen has to name the
    // matching set AND the type it was drawn from.
    const scope = await screen.findByTestId('rv-search-scope')
    expect(scope.textContent).toMatch(/3/)
    expect(scope.textContent).toMatch(/2,100,000/)
  })

  it('says how the server matched, because it folds ASCII case only', async () => {
    mockSearchableRecords([evt(1), evt(2)], 2)
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(2))
    await userEvent.type(
      screen.getByRole('textbox', { name: /^Filter / }),
      'logon',
    )
    const scope = await screen.findByTestId('rv-search-scope')
    // SQLite's LIKE folds ASCII case only, so STRASSE finds strasse but not
    // Straße. An examiner working a German-language device has to be told.
    expect(scope.textContent).toMatch(/ASCII/)
  })

  it('never renders "could not be read" as zero when the question was not asked', async () => {
    mockSearchableRecords([evt(1), evt(2)], 2)
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(2))
    // No term typed: `unfilterable_metadata` comes back null, meaning nothing
    // was ever tested. A "0 unreadable" claim there would be a finding drawn
    // from a question nobody asked.
    expect(document.body.textContent).not.toMatch(/0 record\(s\) could not be/)
  })

  it('reports the records the filter could not be evaluated against', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        const q = url.searchParams.get('q')
        return HttpResponse.json({
          records: q ? [evt(1)] : [evt(1), evt(2)],
          total: q ? 1 : 2,
          type_total: 2,
          unfilterable_metadata: q ? 7 : null,
          filtered: !!q,
          q,
          q_keys: q ? ['short_desc'] : [],
          q_match: 'ascii_case_insensitive_substring',
          sort: null,
          order: 'asc',
          order_by: 'ingest',
          page: 1,
          page_size: 200,
          type: TYPE,
        })
      }),
    )
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(2))
    await userEvent.type(
      screen.getByRole('textbox', { name: /^Filter / }),
      'logon',
    )

    // Seven records were neither matches nor established non-matches. Leaving
    // that out turns "1 match" into a completeness claim it cannot support.
    const scope = await screen.findByTestId('rv-search-scope')
    await waitFor(() => expect(scope.textContent).toMatch(/7/))
    expect(scope.textContent).toMatch(/could not be read/i)
  })
})

/**
 * `sort`/`order` are query parameters now, so a column heading orders the whole
 * record type. A heading that re-sorted the loaded rows instead would put "the
 * newest of the six hundred rows fetched so far" under a "Time ▼" arrow and
 * read as the newest event on the device.
 */
describe('rich record viewer: sorting is a question for the server', () => {
  let requests: URL[] = []

  function mockSortableRecords(all: ParsedRecord[]) {
    requests = []
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        requests.push(url)
        const sort = url.searchParams.get('sort')
        const order = url.searchParams.get('order') ?? 'asc'
        let out = all
        if (sort) {
          const dir = order === 'desc' ? -1 : 1
          out = [...all].sort((a, b) => {
            const va = Number(a.metadata[sort] ?? 0)
            const vb = Number(b.metadata[sort] ?? 0)
            return (va - vb) * dir
          })
        }
        return HttpResponse.json({
          records: out,
          total: all.length,
          type_total: all.length,
          unfilterable_metadata: null,
          filtered: false,
          q: null,
          q_keys: [],
          sort,
          order,
          order_by: sort ? 'metadata_key' : 'ingest',
          page: 1,
          page_size: 200,
          type: TYPE,
        })
      }),
    )
  }

  it('sends no sort key at all until a heading is clicked', async () => {
    mockSortableRecords([evt(1), evt(2), evt(3)])
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(3))
    // Ingest order is the server's default and is NOT event order. Sending a
    // direction for it would put an arrow on a column that does not order on
    // anything, which reads as "most recent" and is not.
    expect(requests[0].searchParams.get('sort')).toBeNull()
    expect(requests[0].searchParams.get('order')).toBeNull()
  })

  it('asks the server to order the whole type when a heading is clicked', async () => {
    mockSortableRecords([evt(1), evt(2), evt(3)])
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(3))
    const header = screen.getByRole('button', { name: /^Event ID/ })
    // The key the server orders on is named on the control, not implied by the
    // heading — a cell that falls back between keys does not sort as it reads.
    expect(header.getAttribute('title')).toContain('event_id')

    await userEvent.click(header)
    await waitFor(() =>
      expect(requests.at(-1)?.searchParams.get('sort')).toBe('event_id'),
    )
    expect(requests.at(-1)?.searchParams.get('order')).toBe('asc')
    expect(requests.at(-1)?.searchParams.get('page')).toBe('1')

    await userEvent.click(screen.getByRole('button', { name: /^Event ID/ }))
    await waitFor(() =>
      expect(requests.at(-1)?.searchParams.get('order')).toBe('desc'),
    )
  })
})

describe('rich record viewer: how the match was made', () => {
  it('quotes an unfamiliar q_match rather than describing one it does not know', async () => {
    // The endpoint publishes `q_match` so a client never has to guess. If it
    // ever stops folding ASCII case only, a screen still describing ASCII
    // folding would be a claim about a search that did not run.
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const q = new URL(request.url).searchParams.get('q')
        return HttpResponse.json({
          records: [evt(1)],
          total: 1,
          type_total: 9,
          unfilterable_metadata: q ? 0 : null,
          filtered: !!q,
          q,
          q_keys: q ? ['short_desc'] : [],
          q_match: 'unicode_normalised_substring',
          sort: null,
          order: 'asc',
          order_by: 'ingest',
          page: 1,
          page_size: 200,
          type: TYPE,
        })
      }),
    )
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(1))
    await userEvent.type(
      screen.getByRole('textbox', { name: /^Filter / }),
      'logon',
    )
    const scope = await screen.findByTestId('rv-search-scope')
    expect(scope.textContent).toMatch(/unicode_normalised_substring/)
    expect(scope.textContent).not.toMatch(/ASCII/)
  })
})

/**
 * HUNT-107. Re-running a module writes a second set of records beside the
 * first. The earlier ones stay in the case as history and are left out of the
 * listing, and a screen that says nothing about them reads as "that is all the
 * case ever held".
 */
describe('records a later run answered', () => {
  function mockWithSuperseded(supersededTotal: number | null) {
    const seen: URL[] = []
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        seen.push(url)
        const include = url.searchParams.get('include_superseded') === 'true'
        return HttpResponse.json({
          records: include ? [evt(1), evt(2), evt(3)] : [evt(1), evt(2)],
          total: include ? 3 : 2,
          type_total: include ? 3 : 2,
          unfilterable_metadata: null,
          superseded_total: include ? null : supersededTotal,
          filtered: false,
          q: null,
          q_keys: [],
          sort: null,
          order: 'asc',
          order_by: 'ingest',
          page: 1,
          page_size: 200,
          type: TYPE,
        })
      }),
    )
    return seen
  }

  it('says how many an earlier run left, and can show them', async () => {
    const seen = mockWithSuperseded(53)
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(2))
    const note = await screen.findByTestId('rv-superseded-note')
    expect(note.textContent).toMatch(/53/)
    expect(note.textContent).toMatch(/earlier run/i)

    await userEvent.click(
      screen.getByRole('button', { name: /show the earlier run/i }),
    )
    await waitFor(() => expect(rows()).toHaveLength(3))
    expect(
      seen.some((u) => u.searchParams.get('include_superseded') === 'true'),
    ).toBe(true)
  })

  it('says nothing when no run has been answered', async () => {
    mockWithSuperseded(0)
    renderViewer()

    await waitFor(() => expect(rows()).toHaveLength(2))
    expect(screen.queryByTestId('rv-superseded-note')).not.toBeInTheDocument()
  })
})
