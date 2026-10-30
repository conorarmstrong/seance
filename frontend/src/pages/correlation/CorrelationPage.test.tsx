import type { ComponentType } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { CommsPage } from '../comms/CommsPage'
import { COMMS_TYPES } from '../comms/normalize'
import { ExecutionPage } from '../execution/ExecutionPage'
import { EXECUTION_TYPES } from '../execution/normalize'

/**
 * The guards the two correlation pages share, asserted against both.
 *
 * These pages were maintained as two copies of one shell, and every fix had to
 * be applied twice by hand. The cases below are the ones where a guard missing
 * from one copy would not look like a bug — it would look like an answer: an
 * empty table where the truth is that the load failed, or that the rows were
 * read and could not be placed.
 */
const PAGES = [
  {
    name: 'Communications',
    Page: CommsPage as ComponentType<{ caseId?: string }>,
    types: COMMS_TYPES as readonly string[],
    /** A type whose records this page correlates. */
    liveType: 'iMessage',
    /** A record of that type carrying no correlation key. */
    uncorrelatable: { body: 'no counterparty here' } as Record<string, unknown>,
    emptyHeading: 'No communications',
    sourceNoun: 'communication types',
  },
  {
    name: 'Execution evidence',
    Page: ExecutionPage as ComponentType<{ caseId?: string }>,
    types: EXECUTION_TYPES as readonly string[],
    liveType: 'PrefetchEntry',
    uncorrelatable: { run_count: 3 } as Record<string, unknown>,
    emptyHeading: 'No execution artifacts',
    sourceNoun: 'execution sources',
  },
] as const

/**
 * Answer `/records` per type: `fail` types return 500, `records` supplies rows
 * for a type, everything else answers an honest empty page.
 */
function mockTypes(opts: {
  fail?: readonly string[]
  records?: Record<string, Record<string, unknown>[]>
  total?: number
}) {
  server.use(
    http.get('/api/v1/cases/:caseId/records', ({ request }) => {
      const url = new URL(request.url)
      const type = url.searchParams.get('type') ?? ''
      if (opts.fail?.includes(type)) {
        return HttpResponse.json({ error: 'boom' }, { status: 500 })
      }
      const rows = opts.records?.[type] ?? []
      const page = Number(url.searchParams.get('page') ?? '1')
      const records =
        page === 1
          ? rows.map((metadata, i) => ({
              id: `art-${type}-${i}`,
              parent_id: null,
              artifact_type: 'ParsedRecord',
              metadata,
            }))
          : []
      return HttpResponse.json({
        records,
        // A total above what the pages fetched is what makes getAllRecords
        // report the load as truncated.
        total: opts.total ?? records.length,
        page,
        page_size: 100,
        type,
      })
    }),
  )
}

function renderPage(Page: ComponentType<{ caseId?: string }>) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <Page caseId="case-1" />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe.each(PAGES)('$name correlation guards', (page) => {
  it('names the failed sources even when the survivors came back empty', async () => {
    // The all-failed guard only catches a fan-out where EVERY type errored.
    // With one type erroring and the rest answering empty, the page used to
    // render a bare "nothing here" empty state: an examiner reads that as a
    // finding about the machine when it is a statement about the server.
    mockTypes({ fail: [page.liveType] })

    renderPage(page.Page)

    expect(await screen.findByText(page.emptyHeading)).toBeInTheDocument()
    const notes = await screen.findAllByRole('note')
    const failure = notes.find((n) => /failed to load/.test(n.textContent ?? ''))
    expect(failure).toBeDefined()
    expect(failure?.textContent).toMatch(
      new RegExp(`1 of \\d+ ${page.sourceNoun} failed to load`),
    )
  })

  it('says the load hit its cap even when nothing correlated', async () => {
    // Truncated plus un-normalisable is the worst pair: the page has neither
    // the rows nor the whole dataset, and must not present that as "none".
    mockTypes({
      records: { [page.liveType]: [page.uncorrelatable] },
      total: 5000,
    })

    renderPage(page.Page)

    expect(await screen.findByText(page.emptyHeading)).toBeInTheDocument()
    const notes = await screen.findAllByRole('note')
    expect(
      notes.find((n) => /hit the per-type load cap/.test(n.textContent ?? '')),
    ).toBeDefined()
  })

  it('distinguishes records it could not place from records that do not exist', async () => {
    // Rows were read; normalisation dropped them for want of a correlation key.
    // "No communications" over two loaded records is an assertion the page is
    // not entitled to make.
    mockTypes({
      records: { [page.liveType]: [page.uncorrelatable, page.uncorrelatable] },
    })

    renderPage(page.Page)

    expect(await screen.findByText(page.emptyHeading)).toBeInTheDocument()
    const notes = await screen.findAllByRole('note')
    const dropped = notes.find((n) =>
      /could be placed on this view/.test(n.textContent ?? ''),
    )
    expect(dropped).toBeDefined()
    expect(dropped?.textContent).toMatch(/2 records were loaded/)
  })

  it('stays silent about dropped records when the case really is empty', async () => {
    // The complement: a banner that is always there is a banner an examiner
    // learns to skip.
    mockTypes({})

    renderPage(page.Page)

    expect(await screen.findByText(page.emptyHeading)).toBeInTheDocument()
    expect(
      screen.queryByText(/could be placed on this view/),
    ).not.toBeInTheDocument()
  })

  it('reports a total failure as a load error, not as an empty case', async () => {
    mockTypes({ fail: page.types })

    renderPage(page.Page)

    expect(
      await screen.findByText(/This is a load error, not an empty result/),
    ).toBeInTheDocument()
    expect(screen.queryByText(page.emptyHeading)).not.toBeInTheDocument()
  })
})


describe('a ranking built from a capped slice (LIVE-024)', () => {
  // The banner used to say only that counts "under-report". The league table is
  // computed over the loaded slice, so with 78,237 WhatsApp records behind a
  // 2,000-record cap the ORDER itself can be wrong — an examiner reading the
  // top row as "the most-contacted party" is reading a statistic derived from
  // 2.5% of the traffic.
  //
  // The communications page now prefers a server-side aggregation. These cases
  // deliberately refuse it, so what they pin down is the state the page is left
  // in when that aggregation is unavailable: the old slice ranking, still
  // carrying the old warning. See CommsPage.test.tsx for the exact ranking.
  const CORRELATABLE = {
    type: 'iMessage',
    sender: 'Alice',
    timestamp: '2024-01-01T00:00:00Z',
    body: 'hi',
  }

  function mockCappedSliceOnly() {
    mockTypes({ records: { iMessage: [CORRELATABLE] }, total: 5000 })
    server.use(
      http.get('/api/v1/cases/:caseId/comms/ranking', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'unavailable' } },
          { status: 500 },
        ),
      ),
    )
  }

  it('warns that the order can be wrong, not merely the totals', async () => {
    mockCappedSliceOnly()
    renderPage(PAGES[0].Page)

    const notes = await screen.findAllByRole('note')
    const cap = notes.find((n) =>
      /hit the per-type load cap/.test(n.textContent ?? ''),
    )
    expect(cap?.textContent).toMatch(/order can be wrong/i)
  })

  it('marks the ranking itself as covering only the loaded slice', async () => {
    mockCappedSliceOnly()
    renderPage(PAGES[0].Page)

    // The chart above the bars is labelled the same way and for the same
    // reason — neither aggregation answered, so both are the browser's own
    // count over the slice, and each says so over its own drawing rather than
    // leaving one label to be read as covering the other.
    await waitFor(() =>
      expect(
        document.querySelector('.rv-dims .rv-top-title')?.textContent ?? '',
      ).toMatch(/within the loaded slice/i),
    )
    expect(
      document.querySelector('.rv-histo-title')?.textContent ?? '',
    ).toMatch(/within the loaded slice/i)
  })
})

/**
 * An exact ranking that matched nobody is still an answer, and has to look like
 * one.
 *
 * `TopBars` draws nothing for an empty list — no heading either — while the
 * provenance note under it is rendered on the note alone. The result was a
 * paragraph of case-wide totals ("counted over all 93,338 records in this
 * case") sitting on the page under no heading and above no bars: the most
 * quotable numbers on the screen, with nothing left to say what they qualify.
 */
describe('an exact ranking with no entries (LIVE-024)', () => {
  const CORRELATABLE = {
    contact: 'Alice',
    is_from_me: false,
    timestamp: '2024-01-01T00:00:00Z',
  }

  function mockEmptyExactRanking(total?: number) {
    mockTypes({ records: { iMessage: [CORRELATABLE] }, total })
    server.use(
      http.get('/api/v1/cases/:caseId/comms/ranking', () =>
        HttpResponse.json({
          contacts: [],
          limit: 8,
          has_more: false,
          distinct_contacts: 0,
          by_type: [['iMessage', 93338]],
          total_records: 93338,
          summary_records: 0,
          unrankable_records: 0,
          records_without_counterparty: 0,
        }),
      ),
    )
  }

  const rankNote = () =>
    document.querySelector('.rv-rank-note')?.textContent ?? ''
  const rankTitle = () =>
    document.querySelector('.rv-dims .rv-top-title')?.textContent ?? ''

  it('keeps the caveat under a heading that says which ranking it qualifies', async () => {
    mockEmptyExactRanking()
    renderPage(PAGES[0].Page)

    await waitFor(() => expect(rankNote()).toMatch(/93,338/))
    // The heading is the whole point: without it those totals qualify nothing.
    expect(rankTitle()).toMatch(/Most-contacted/)
    expect(rankTitle()).toMatch(/exact/i)
    // And the emptiness is stated, so a blank space is not left to be read as
    // a ranking that failed to arrive.
    const notes = screen.getAllByRole('note')
    expect(
      notes.find((n) => /no entries/i.test(n.textContent ?? '')),
    ).toBeDefined()
  })

  it('does not let the cap banner call the empty ranking a slice count', async () => {
    // The complement of the finding: demoting an empty exact ranking to "not
    // exact" would have the banner tell the examiner that the bars below were
    // computed over the loaded slice — which they were not — while the note
    // beneath them quotes a case-wide total.
    mockEmptyExactRanking(5000)
    renderPage(PAGES[0].Page)

    await waitFor(() => expect(rankNote()).toMatch(/93,338/))
    const notes = screen.getAllByRole('note')
    const cap = notes.find((n) =>
      /hit the per-type load cap/.test(n.textContent ?? ''),
    )
    expect(cap).toBeDefined()
    expect(cap?.textContent).not.toMatch(/order can be wrong/i)
  })
})

/**
 * The server ranking is opt-in per config, and this is why.
 *
 * `makeCorrelationPage` is shared. Communications rank by counterparty, which
 * the API can count in SQL; execution ranks by program name, which nothing
 * counts but this page. Baking the aggregation into the factory would have the
 * execution page call an endpoint that does not answer its question — and,
 * worse, label the bars it already draws with a provenance sentence that is not
 * true of them.
 */
describe('a correlation config that opts out of server ranking', () => {
  const PREFETCH = {
    executable_name: 'notepad.exe',
    run_count: 3,
    last_run_time: '2024-01-01T00:00:00Z',
  }

  it('asks no aggregation and labels its bars exactly as it always did', async () => {
    const asked: string[] = []
    mockTypes({ records: { PrefetchEntry: [PREFETCH] } })
    server.use(
      http.get('/api/v1/cases/:caseId/comms/ranking', ({ request }) => {
        asked.push(request.url)
        return HttpResponse.json({ contacts: [] })
      }),
    )

    renderPage(PAGES[1].Page)

    expect(
      await screen.findByText('Most-referenced programs'),
    ).toBeInTheDocument()
    expect(asked).toEqual([])
    // No provenance sentence, because there is no other provenance to state.
    expect(document.querySelector('.rv-rank-note')).toBeNull()
  })

  it('asks for no histogram and leaves its chart labelled exactly as it was', async () => {
    // The histogram is opt-in for the same reason the ranking is: only some
    // correlation dimensions have a server-side aggregation behind them, and a
    // page that has none must not carry a heading claiming its bars came from
    // one.
    const asked: string[] = []
    mockTypes({ records: { PrefetchEntry: [PREFETCH] } })
    server.use(
      http.get('/api/v1/cases/:caseId/comms/histogram', ({ request }) => {
        asked.push(request.url)
        return HttpResponse.json({ buckets: [] })
      }),
    )

    renderPage(PAGES[1].Page)

    expect(
      await screen.findByText('Most-referenced programs'),
    ).toBeInTheDocument()
    expect(asked).toEqual([])
    // No heading over the bars, because there is no second provenance for one
    // to distinguish.
    expect(document.querySelector('.rv-histo-title')).toBeNull()
  })
})

/**
 * The volume chart's two silences.
 *
 * `timeOf` returns null for a record the view cannot place in time, and the
 * chart's input was built with `.filter(t => t != null)` — so those records
 * left the page without being counted anywhere, while the toolbar beside the
 * chart went on counting them. The number an examiner reads as the chart's
 * total was short by an amount nothing on screen stated.
 *
 * And where EVERY record in a filter state was untimed, the chart rendered
 * nothing at all: a blank band that reads exactly like a period in which
 * nothing happened. Both are shared-shell defects, so both are asserted
 * against both pages.
 */
describe.each(PAGES)('$name volume chart', (page) => {
  /** A record this page can correlate but cannot place in time. */
  const UNTIMED: Record<string, Record<string, unknown>> = {
    Communications: { contact: 'Alice', is_from_me: false },
    'Execution evidence': { executable_name: 'notepad.exe', run_count: 3 },
  }
  /** The same, carrying a time key this page reads. */
  const TIMED: Record<string, Record<string, unknown>> = {
    Communications: {
      contact: 'Alice',
      is_from_me: false,
      timestamp: '2024-01-01T00:00:00Z',
    },
    'Execution evidence': {
      executable_name: 'notepad.exe',
      run_count: 3,
      last_execution_time: '2024-01-01T00:00:00Z',
    },
  }

  const chart = () => document.querySelector('.rv-histo')?.textContent ?? ''

  it('counts the records it could not place instead of dropping them silently', async () => {
    mockTypes({
      records: {
        [page.liveType]: [
          TIMED[page.name],
          { ...TIMED[page.name], contact: 'Bob', executable_name: 'calc.exe' },
          UNTIMED[page.name],
        ],
      },
    })

    renderPage(page.Page)

    await waitFor(() => expect(chart()).toMatch(/carried no time/i))
    // Two drawn, one left off — and the one left off is not evidence that it
    // did not happen.
    expect(chart()).toMatch(/\b2\b/)
    expect(chart()).toMatch(/\b1\b/)
    expect(chart()).toMatch(/not on this chart/i)
  })

  it('says so when nothing in view could be placed, rather than drawing nothing', async () => {
    mockTypes({ records: { [page.liveType]: [UNTIMED[page.name]] } })

    renderPage(page.Page)

    // The frame is always drawn, so a screenshot of this state cannot be
    // mistaken for a quiet period.
    await waitFor(() => expect(document.querySelector('.rv-histo')).not.toBeNull())
    expect(chart()).toMatch(/could read/i)
    expect(chart()).toMatch(/not a statement that nothing happened/i)
    expect(document.querySelectorAll('.rv-histo svg title')).toHaveLength(0)
  })

  it('stays quiet about untimed records when every one of them was placed', async () => {
    mockTypes({ records: { [page.liveType]: [TIMED[page.name]] } })

    renderPage(page.Page)

    await waitFor(() =>
      expect(document.querySelectorAll('.rv-histo svg title').length).toBeGreaterThan(0),
    )
    expect(chart()).not.toMatch(/carried no time|not on this chart/i)
  })
})
