import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { FrameSpy, inputValue } from '../../test/frames'
import { CommsPage } from './CommsPage'

/**
 * Budget for assertions that sit behind CommsPage's ranking debounce.
 *
 * `RANKING_DEBOUNCE_MS` is 200 ms of REAL time, and a ranking assertion has to
 * absorb that plus the keystrokes before it, the query it triggers and the
 * re-render after it. Testing Library's default `waitFor` budget is 1000 ms, so
 * the margin was five times the delay — comfortable on an idle machine and thin
 * on a CI runner sharing a core with the rest of the matrix.
 *
 * That thinness is not a slow test, it is a WRONG one: when the budget is
 * missed, `waitFor` reports a failed assertion about the page's contents rather
 * than "this took too long", so an overloaded runner reads as a broken feature.
 * None of these tests is asserting how FAST the ranking arrives — only that it
 * arrives and says the right thing — so the budget is set from the delay it
 * must cover rather than left at a default that knows nothing about it.
 */
const BEHIND_DEBOUNCE = { timeout: 5_000 }

/**
 * The bookmark lookups every row's capture control makes.
 *
 * Registered for the whole file rather than per case, because the control is
 * now part of every comms row: without these the msw server (which is set to
 * error on an unhandled request) would fail tests that have nothing to do with
 * bookmarks. An empty id list is the honest fixture — these cases assert about
 * the table, not about what is marked in it.
 */
beforeEach(() => {
  server.use(
    http.get('/api/v1/cases/:caseId/bookmarks/ids', () => HttpResponse.json([])),
    http.get('/api/v1/cases/:caseId/bookmarks/categories', () =>
      HttpResponse.json([]),
    ),
  )
})

/** One iMessage row per case; every other comms type answers empty. */
function mockRecords(contactByCase: Record<string, string>) {
  server.use(
    http.get('/api/v1/cases/:caseId/records', ({ params, request }) => {
      const type = new URL(request.url).searchParams.get('type')
      const contact = contactByCase[params.caseId as string]
      const records =
        type === 'iMessage' && contact
          ? [
              {
                id: `art-${contact}`,
                parent_id: null,
                artifact_type: 'ParsedRecord',
                metadata: { contact, is_from_me: false },
              },
            ]
          : []
      return HttpResponse.json({
        records,
        total: records.length,
        page: 1,
        page_size: 100,
        type,
      })
    }),
    // These cases predate the server-side ranking and are written against the
    // client-side slice bars. Refusing the aggregation keeps them on exactly
    // that ranking, and exercises the fallback while it is at it.
    http.get('/api/v1/cases/:caseId/comms/ranking', () =>
      HttpResponse.json(
        { error: { code: 'INTERNAL', message: 'no ranking here' } },
        { status: 500 },
      ),
    ),
  )
}

/**
 * The case's review ledger, which the page's coverage panel and every row's
 * review mark read from the server.
 *
 * Registered by the render helpers below rather than by each test, because
 * every test on this page renders the panel. It is stated here rather than left
 * to a base handler: msw runs with `onUnhandledRequest: "error"`, and a request
 * this page makes should be a request this file says it makes.
 */
function mockReviewLedger() {
  server.use(
    http.get('/api/v1/cases/:caseId/artifact_reviews/ids', ({ request }) => {
      const url = new URL(request.url)
      return HttpResponse.json({
        ids: [],
        state: url.searchParams.get('state') ?? 'reviewed',
        examiner: url.searchParams.get('examiner'),
        scope: url.searchParams.get('examiner') ? 'examiner' : 'case',
        total: 0,
        returned: 0,
        capped: false,
        cap: 100_000,
      })
    }),
    http.get('/api/v1/cases/:caseId/artifact_reviews/stats', () =>
      HttpResponse.json({
        examiners: [],
        case: { opened: 0, reviewed: 0 },
        population: {
          total: 4_012_345,
          name: 'artifacts_in_case',
          label: 'every artifact recorded in this case, of every type',
          includes_non_reviewable_rows: true,
          exact: true,
        },
        reviewed_is_subset_of_opened: true,
        counts_are_distinct_artifacts: true,
      }),
    ),
    http.post('/api/v1/cases/:caseId/artifact_reviews', async ({ request }) => {
      const body = (await request.json()) as {
        marks: { artifact_id: string; state: string }[]
      }
      return HttpResponse.json({
        examiner: 'local',
        received: body.marks.length,
        openings_recorded: body.marks.filter((m) => m.state === 'opened').length,
        reviews_recorded: body.marks.filter((m) => m.state === 'reviewed')
          .length,
        reviews_withdrawn: body.marks.filter((m) => m.state === 'unreviewed')
          .length,
        unchanged: 0,
        rejected: [],
        rejected_reason: 'artifact_not_in_case',
        batch_max: 1000,
      })
    }),
  )
}

/** What the page showed in one committed frame. */
type Frame = { search: string | null; channelPressed: string | null }

function snapshot(): Frame {
  const tile = [...document.querySelectorAll('button')].find((b) =>
    /iMessage/.test(b.textContent ?? ''),
  )
  return {
    search: inputValue('Filter communications'),
    channelPressed: tile?.getAttribute('aria-pressed') ?? null,
  }
}

function renderPage(caseId: string) {
  mockReviewLedger()
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const frames: Frame[] = []
  const ui = (id: string) => (
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <CommsPage caseId={id} />
        <FrameSpy capture={snapshot} frames={frames} />
      </MemoryRouter>
    </QueryClientProvider>
  )
  const utils = render(ui(caseId))
  return { switchCase: (id: string) => utils.rerender(ui(id)), frames }
}

describe('CommsPage case switching (BUG-282)', () => {
  it('clears the channel, contact and search filters when the case changes', async () => {
    // The queries are case-keyed but the cross-filters are plain state, and the
    // page stays mounted across a `:caseId` route change. A contact or channel
    // chosen in case 1 does not exist in case 2, so case 2 would render as an
    // empty subset that reads as "no communications".
    mockRecords({ 'case-1': 'alice', 'case-2': 'bob' })
    const { switchCase } = renderPage('case-1')
    expect((await screen.findAllByText('alice')).length).toBeGreaterThan(0)

    // Narrow to case 1's only channel and contact.
    await userEvent.click(screen.getByRole('button', { name: /iMessage/ }))
    const search = screen.getByLabelText('Filter communications')
    await userEvent.type(search, 'alice')
    await waitFor(() => expect(search).toHaveValue('alice'))
    expect(screen.getByRole('button', { name: /iMessage/ })).toHaveAttribute(
      'aria-pressed',
      'true',
    )

    switchCase('case-2')

    // Case 2's traffic must be shown in full, not through case 1's filters.
    expect((await screen.findAllByText('bob')).length).toBeGreaterThan(0)
    expect(screen.getByLabelText('Filter communications')).toHaveValue('')
    expect(screen.getByRole('button', { name: /iMessage/ })).toHaveAttribute(
      'aria-pressed',
      'false',
    )
  })

  it('never paints a single frame of case 2 through case 1 filters (B2-145)', async () => {
    // Clearing the filters from a `useEffect` keyed on the case leaves them in
    // hand for the whole render AND commit in which the case has already
    // changed. With case 2's records already cached that frame is painted: the
    // examiner sees case 2's communications filtered by a contact from case 1
    // — "no communications" for a case that has them — and the effect only
    // corrects it afterwards. `render`/`rerender` flush passive effects before
    // returning, so only a layout-effect snapshot can see that frame at all.
    mockRecords({ 'case-1': 'alice', 'case-2': 'bob' })
    const { switchCase, frames } = renderPage('case-1')
    await screen.findAllByText('alice')

    // Warm case 2's cache, then come back so the switch under test resolves
    // from cache and renders case 2's traffic in the very first frame.
    switchCase('case-2')
    await screen.findAllByText('bob')
    switchCase('case-1')
    await screen.findAllByText('alice')

    await userEvent.click(screen.getByRole('button', { name: /iMessage/ }))
    const search = screen.getByLabelText('Filter communications')
    await userEvent.type(search, 'alice')
    await waitFor(() => expect(search).toHaveValue('alice'))

    frames.length = 0
    switchCase('case-2')

    // A frame that has not drawn the toolbar yet reads as null; what must never
    // appear is case 1's filter over case 2's records.
    //
    // `FrameSpy` observes the DOM, and a `MutationObserver` delivers its records
    // as a microtask, so the sink is still empty on the synchronous line after
    // the switch. Wait for the frames to arrive and then assert on all of them:
    // the sink keeps every frame it saw, so a corrected one landing afterwards
    // cannot hide the offending one. Asserting non-empty first is what stops a
    // harness that recorded nothing from reading as a pass.
    await waitFor(() => expect(frames.length).toBeGreaterThan(0))
    for (const frame of frames) {
      expect(frame.search ?? '').toBe('')
      expect(frame.channelPressed ?? 'false').toBe('false')
    }
  })
})

/**
 * The standard incompleteness pair on the correlated view.
 *
 * `normalizeComms` projects every record down to contact/channel/direction/time,
 * so a WhatsApp database the parser stopped reading arrives here as a smaller
 * set of complete-looking rows. The histogram and the "most-contacted" bars are
 * then read as this machine's traffic. The pair has to be read off the raw
 * records, before that projection, or nothing on the page can say so.
 */
describe('CommsPage incompleteness', () => {
  function mockOneIncompleteMessage(extra: Record<string, unknown>) {
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const type = new URL(request.url).searchParams.get('type')
        const records =
          type === 'iMessage'
            ? [
                {
                  id: 'art-1',
                  parent_id: null,
                  artifact_type: 'ParsedRecord',
                  metadata: { contact: 'Alice', is_from_me: false, ...extra },
                },
              ]
            : []
        return HttpResponse.json({
          records,
          total: records.length,
          page: 1,
          page_size: 100,
          type,
        })
      }),
      http.get('/api/v1/cases/:caseId/comms/ranking', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'no ranking here' } },
          { status: 500 },
        ),
      ),
    )
  }

  it('announces the pair, with its reason, over the correlated table', async () => {
    mockOneIncompleteMessage({
      content_incomplete: true,
      content_incomplete_reason: 'cap_reached',
    })
    renderPage('case-1')

    await screen.findAllByText('Alice')
    const notes = await screen.findAllByRole('note')
    const banner = notes.find((n) => /incomplete:/.test(n.textContent ?? ''))
    expect(banner).toBeDefined()
    expect(banner).toHaveTextContent('safety cap')
  })

  it('says nothing when every correlated record is whole', async () => {
    mockOneIncompleteMessage({})
    renderPage('case-1')

    await screen.findAllByText('Alice')
    expect(
      screen.queryByText(/declares itself incomplete/),
    ).not.toBeInTheDocument()
  })
})

/**
 * The most-contacted league table (LIVE-024).
 *
 * The bars used to be counted in the browser over whatever the correlation
 * page's page cap happened to load — 2,000 records per type against 78,237
 * WhatsApp and 15,101 iMessage records in the reference case. That is not a
 * ranking of the traffic, it is a ranking of a 2.5% sample, and the order it
 * produces can be wrong rather than merely short. The server now aggregates in
 * SQL; what follows pins down which filter states that answer is valid for,
 * that the page falls back when it is not, and that the label on screen always
 * says which of the two an examiner is looking at.
 */
describe('CommsPage most-contacted ranking (LIVE-024)', () => {
  /** A full response, with every population deliberately a different number. */
  const RANKING = {
    contacts: [
      { contact: 'alice', count: 900 },
      { contact: 'bob', count: 100 },
    ],
    limit: 8,
    has_more: true,
    distinct_contacts: 4211,
    by_type: [
      ['WhatsApp', 78221],
      ['iMessage', 15041],
    ],
    total_records: 93338,
    summary_records: 12,
    unrankable_records: 40,
    records_without_counterparty: 25,
  }

  /**
   * The slice ranks bob above alice; the server ranks alice above bob. Which
   * name is on the top bar is therefore proof of which ranking is on screen —
   * an assertion no amount of relabelling can satisfy by accident.
   */
  const ROWS: Record<string, Record<string, unknown>[]> = {
    iMessage: [
      { contact: 'bob', is_from_me: false },
      { contact: 'bob', is_from_me: true },
      { contact: 'alice', is_from_me: false },
    ],
  }

  const rankingRequests: URL[] = []

  beforeEach(() => {
    rankingRequests.length = 0
  })

  // One case below mocks `./normalize` for a dynamically imported page. The
  // registry outlives the test, so it is torn down here rather than there,
  // where an assertion failure would skip the cleanup and leak the fake map
  // into whatever ran next.
  afterEach(() => {
    vi.doUnmock('./normalize')
    vi.resetModules()
    vi.restoreAllMocks()
  })

  function mockCase(
    opts: {
      rows?: Record<string, Record<string, unknown>[]>
      total?: number
      ranking?: unknown
      rankingStatus?: number
    } = {},
  ) {
    const rows = opts.rows ?? ROWS
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type') ?? ''
        const page = Number(url.searchParams.get('page') ?? '1')
        const records =
          page === 1
            ? (rows[type] ?? []).map((metadata, i) => ({
                id: `art-${type}-${i}`,
                parent_id: null,
                artifact_type: 'ParsedRecord',
                metadata,
              }))
            : []
        return HttpResponse.json({
          records,
          // A total above what the page can fetch is what makes getAllRecords
          // report the load as truncated.
          total: opts.total ?? records.length,
          page,
          page_size: 100,
          type,
        })
      }),
      http.get('/api/v1/cases/:caseId/comms/ranking', ({ request }) => {
        rankingRequests.push(new URL(request.url))
        if (opts.rankingStatus && opts.rankingStatus !== 200) {
          return HttpResponse.json(
            { error: { code: 'INTERNAL', message: 'aggregation exploded' } },
            { status: opts.rankingStatus },
          )
        }
        return HttpResponse.json(opts.ranking ?? RANKING)
      }),
    )
  }

  const rankTitle = () =>
    document.querySelector('.rv-dims .rv-top-title')?.textContent ?? ''
  const rankRows = () =>
    [...document.querySelectorAll('.rv-top-row')].map((el) => el.textContent ?? '')
  const rankNote = () =>
    document.querySelector('.rv-rank-note')?.textContent ?? ''
  const bar = (label: string) =>
    [...document.querySelectorAll('.rv-top-row')].find(
      (el) => el.getAttribute('title') === label,
    ) as HTMLElement

  it('ranks from the server, not from the loaded slice, when nothing is narrowed', async () => {
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(rankRows()[0]).toMatch(/alice/))
    // 900 is a number about the case; 1 is alice's count in the loaded slice.
    expect(rankRows()[0]).toMatch(/900/)
    expect(rankRows()[1]).toMatch(/bob.*100/)
    expect(rankTitle()).toMatch(/exact/i)
    expect(rankTitle()).not.toMatch(/loaded slice/i)
  })

  it('asks for the record type behind a channel tile, not the tile label', async () => {
    // The tiles say "SMS"; the endpoint is parameterised by ParsedRecord type
    // names. Sending "SMS" would be answered as "no such channel" — an empty
    // ranking presented as a fact about the case.
    mockCase({ rows: { AndroidSms: [{ contact: 'sms-guy' }] } })
    renderPage('case-1')

    await screen.findAllByText('sms-guy')
    await userEvent.click(screen.getByRole('button', { name: /SMS/ }))

    await waitFor(() =>
      expect(
        rankingRequests.some(
          (u) => u.searchParams.get('channel') === 'AndroidSms',
        ),
      ).toBe(true),
    )
  })

  it('pushes the search needle down to the server as q', async () => {
    mockCase()
    renderPage('case-1')
    await waitFor(() => expect(rankRows()[0]).toMatch(/alice/))

    await userEvent.type(screen.getByLabelText('Filter communications'), 'ali')

    await waitFor(
      () =>
        expect(
          rankingRequests.some((u) => u.searchParams.get('q') === 'ali'),
        ).toBe(true),
      BEHIND_DEBOUNCE,
    )
  })

  it('keeps the case-wide populations apart from the search result', async () => {
    // by_type and the four record counts describe the case narrowed by channel
    // only. Printing them beside a needle-narrowed correspondent count without
    // saying so would read as "93,338 records match your search".
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(rankNote()).toMatch(/93,338/))
    expect(rankNote()).toMatch(/4,211/)
    expect(rankNote()).toMatch(/78,221/)
    expect(rankNote()).toMatch(/not narrowed by the filter box/i)
  })

  it('groups every figure on the screen the same way, whatever the runtime locale', async () => {
    // The bars are formatted with a pinned en-US formatter; the note beside
    // them used to follow the machine's locale. On a de-DE runner that puts
    // "93,338" and "93.338" on one screen, where the second reads as ninety-
    // three point three. A number offered as evidence has to read the same for
    // every examiner, so the whole screen uses the one pinned formatter.
    //
    // Stubbing the default locale rather than reading it: `toLocaleString` with
    // no argument is exactly what a de-DE runner would do to these numbers.
    vi.spyOn(Number.prototype, 'toLocaleString').mockImplementation(function (
      this: number,
    ) {
      return new Intl.NumberFormat('de-DE').format(Number(this))
    })

    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(rankNote()).toMatch(/93,338/))
    expect(rankNote()).toMatch(/78,221/)
    expect(document.body.textContent).not.toMatch(/93\.338|78\.221|4\.211/)
  })

  it('states the two "no counterparty" facts as two different facts', async () => {
    // 40 records carried none of the counterparty keys; 25 are calls the device
    // itself logged with no number. Adding them would invent a 65 that is not a
    // count of anything.
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(rankNote()).toMatch(/93,338/))
    const note = rankNote()
    expect(note).toMatch(/40 record/)
    expect(note).toMatch(/25 call/)
    expect(note).toMatch(/no number/i)
    expect(note).toMatch(/12 summary/)
  })

  it('falls back to the labelled slice ranking under a single-contact filter', async () => {
    // "Rank the correspondents, given that I only want this one correspondent"
    // is not a question, and it is not one the endpoint takes. The bars go back
    // to the slice and say so — and the count the server does know for that
    // contact is stated rather than left to be read off a 2.5% sample.
    mockCase()
    renderPage('case-1')
    await waitFor(() => expect(rankRows()[0]).toMatch(/alice/))

    await userEvent.click(bar('alice'))

    await waitFor(() => expect(rankTitle()).toMatch(/within the loaded slice/i))
    expect(rankTitle()).not.toMatch(/exact/i)
    // The slice holds one alice record; the case holds 900.
    expect(rankRows()[0]).toMatch(/alice/)
    expect(rankNote()).toMatch(/900/)
    expect(rankNote()).toMatch(/clear the contact filter/i)
  })

  it('explains an empty table under a contact the loaded slice never saw', async () => {
    // The trap the exact ranking introduces: its top bars name correspondents
    // that the capped slice may hold no records for at all. Clicking one then
    // empties the table below, and an examiner who has just read "500 records"
    // is looking at a screen that appears to say there are none.
    mockCase({
      ranking: { ...RANKING, contacts: [{ contact: 'carol', count: 500 }] },
    })
    renderPage('case-1')
    await waitFor(() => expect(rankRows()[0]).toMatch(/carol/))

    await userEvent.click(bar('carol'))

    await waitFor(() => expect(rankNote()).toMatch(/carol/))
    expect(rankNote()).toMatch(/500/)
    expect(rankNote()).toMatch(/clear the contact filter/i)
    // The page is still standing and still says how much of it is on screen.
    expect(screen.getByText(/0 of 3\s+events/)).toBeInTheDocument()
  })

  it('does not label one needle\u2019s ranking with another needle', async () => {
    // The aggregation is keyed on the DEBOUNCED needle, so just after a
    // keystroke the answer in hand is still the answer to the previous
    // question. The table of individual records has already re-filtered to the
    // new needle by then; leaving the old ranking above it under the word
    // "exact" would put two different searches on one screen as though they
    // were one.
    let release: (() => void) | null = null
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type') ?? ''
        const records = (ROWS[type] ?? []).map((metadata, i) => ({
          id: `art-${type}-${i}`,
          parent_id: null,
          artifact_type: 'ParsedRecord',
          metadata,
        }))
        return HttpResponse.json({
          records,
          total: records.length,
          page: 1,
          page_size: 100,
          type,
        })
      }),
      http.get('/api/v1/cases/:caseId/comms/ranking', async ({ request }) => {
        const q = new URL(request.url).searchParams.get('q')
        // Hold the follow-up open, so the only ranking this page could draw at
        // all is the stale one.
        if (q === 'alic') await held
        return HttpResponse.json({
          ...RANKING,
          contacts: [{ contact: `only-for-${q ?? 'nothing'}`, count: 900 }],
        })
      }),
    )
    renderPage('case-1')

    const box = await screen.findByLabelText('Filter communications')
    await userEvent.type(box, 'ali')
    await waitFor(
      () => expect(rankRows()[0]).toMatch(/only-for-ali/),
      BEHIND_DEBOUNCE,
    )

    await userEvent.type(box, 'c')

    // "only-for-ali" is still cached under the key the debounced needle names,
    // so it is there for the taking. It must not be shown for "alic".
    expect(rankRows().join()).not.toMatch(/only-for-ali$|only-for-ali[^c]/)
    expect(rankTitle()).toMatch(/within the loaded slice/i)
    release!()
  })

  it('never asks a new case for the needle typed under the old one', async () => {
    // The ranking is keyed on the DEBOUNCED needle, and the endpoint audits
    // every call it answers. A needle held in unscoped state therefore survives
    // the `:caseId` change that resets the search box and is sent to the new
    // case: the request is recorded in case 2's audit trail as a counterparty
    // search, and no examiner ever performed it. A false entry in a custody
    // trail is worse than the wrong bars it would also draw, so what is
    // asserted here is the REQUEST, not the rendering.
    mockCase()
    const { switchCase } = renderPage('case-1')
    await waitFor(() => expect(rankRows()[0]).toMatch(/alice/))

    await userEvent.type(screen.getByLabelText('Filter communications'), 'ali')
    await waitFor(
      () =>
        expect(
          rankingRequests.some((u) => u.searchParams.get('q') === 'ali'),
        ).toBe(true),
      BEHIND_DEBOUNCE,
    )

    switchCase('case-2')

    // Wait for case 2 to ask its own question, so the assertion below is made
    // against a page that has finished asking rather than one that has not
    // started.
    await waitFor(
      () =>
        expect(
          rankingRequests.some((u) => u.pathname.includes('/cases/case-2/')),
        ).toBe(true),
      BEHIND_DEBOUNCE,
    )
    const askedOfCase2 = rankingRequests
      .filter((u) => u.pathname.includes('/cases/case-2/'))
      .map((u) => u.searchParams.get('q'))
    expect(askedOfCase2).not.toContain('ali')
    expect(askedOfCase2.every((q) => q == null)).toBe(true)
  })

  it('does not serve a whole-case ranking under a channel it cannot ask about', async () => {
    // A channel fed by more than one record type is not a question this
    // endpoint takes, so the page must fall back and say so. `enabled: false`
    // stops the fetch but not the READ: with both states keyed alike, the
    // whole-case answer already in the cache is handed straight back and drawn
    // under the tile's name, labelled "exact, counted server-side" — a ranking
    // of the entire case presented as a ranking of one channel.
    //
    // `CHANNEL_OF` is injective today, so the collision is reached by giving
    // the SMS channel a second feeding type. The module is mocked for this test
    // alone: `normalizeComms` keeps the real map internally, so the tiles are
    // still labelled as they always were.
    vi.resetModules()
    vi.doMock('./normalize', async () => {
      const actual =
        await vi.importActual<typeof import('./normalize')>('./normalize')
      return {
        ...actual,
        CHANNEL_OF: { ...actual.CHANNEL_OF, CallLog: 'SMS' },
      }
    })
    const { CommsPage: Page } = await import('./CommsPage')

    mockCase({ rows: { AndroidSms: [{ contact: 'sms-guy' }] } })
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

    // The whole-case ranking lands first and is cached.
    await waitFor(() => expect(rankRows()[0]).toMatch(/alice/))
    expect(rankTitle()).toMatch(/exact/i)

    await userEvent.click(screen.getByRole('button', { name: /SMS/ }))

    await waitFor(() => expect(rankTitle()).toMatch(/within the loaded slice/i))
    expect(rankTitle()).not.toMatch(/exact/i)
    expect(rankNote()).toMatch(/more than one record type feeds it/i)
    // And none of the case-wide figures came with it.
    expect(rankNote()).not.toMatch(/93,338/)
    expect(rankRows().join()).not.toMatch(/alice/)
  })

  it('falls back with an honest label when the aggregation fails, and still renders', async () => {
    mockCase({ rankingStatus: 500 })
    renderPage('case-1')

    // The page is not blanked by a ranking that would not load.
    expect((await screen.findAllByText('bob')).length).toBeGreaterThan(0)
    await waitFor(() => expect(rankNote()).toMatch(/could not be loaded/i))
    expect(rankTitle()).toMatch(/within the loaded slice/i)
    expect(rankTitle()).not.toMatch(/exact/i)
    // Slice order: bob (2) above alice (1).
    expect(rankRows()[0]).toMatch(/bob/)
  })

  it('does not relabel a ranking whose reload failed as an exact answer', async () => {
    // React Query keeps the last successful payload when a background refetch
    // errors, and an ingest completing invalidates every query keyed by the
    // case id — the ranking among them. So the failure this covers is the
    // ranking silently reverting to the PREVIOUS answer while the table below
    // it repaints with the new records, all of it under "exact, counted
    // server-side" and a case-wide total stated in the present tense. That is
    // the precise confusion the exact/slice label exists to prevent.
    mockCase()
    let rankingFails = false
    server.use(
      http.get('/api/v1/cases/:caseId/comms/ranking', () =>
        rankingFails
          ? HttpResponse.json(
              { error: { code: 'INTERNAL', message: 'aggregation exploded' } },
              { status: 500 },
            )
          : HttpResponse.json(RANKING),
      ),
    )
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <CommsPage caseId="case-1" />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(rankRows()[0]).toMatch(/alice/))
    expect(rankTitle()).toMatch(/exact/i)

    // Exactly what a ProcessingComplete for this case does: useProcessingEvents
    // invalidates every query whose key contains the case id, which the
    // ranking's key does.
    rankingFails = true
    await act(async () => {
      await client.invalidateQueries({
        predicate: (q) => q.queryKey.includes('case-1'),
      })
    })

    await waitFor(() => expect(rankNote()).toMatch(/could not be loaded/i))
    expect(rankTitle()).not.toMatch(/exact/i)
    expect(rankTitle()).toMatch(/within the loaded slice/i)
    // The bars are the slice's own ranking now — bob (2) above alice (1) — and
    // not the answer the server gave before the reload failed.
    expect(rankRows()[0]).toMatch(/bob/)
    // And no case-wide figure survives under a label that cannot vouch for it.
    expect(rankNote()).not.toMatch(/93,338/)
  })

  it('stops the cap banner claiming the ranking order is suspect once it is exact', async () => {
    // The banner must stop condemning the one thing that got fixed — and must
    // not let that read as though the tiles, histogram and record table were
    // fixed with it. They are all still the capped slice.
    mockCase({ total: 5000 })
    renderPage('case-1')

    await waitFor(() => expect(rankTitle()).toMatch(/exact/i))
    const notes = screen.getAllByRole('note')
    const cap = notes.find((n) => /per-type load cap/.test(n.textContent ?? ''))
    expect(cap).toBeDefined()
    expect(cap?.textContent).not.toMatch(/order can be wrong/i)
    expect(cap?.textContent).toMatch(/tiles/i)
    expect(cap?.textContent).toMatch(/histogram/i)
    expect(cap?.textContent).toMatch(/under-report/i)
  })

  it('keeps the cap banner intact when the ranking is the slice after all', async () => {
    mockCase({ total: 5000, rankingStatus: 500 })
    renderPage('case-1')

    await waitFor(() => expect(rankNote()).toMatch(/could not be loaded/i))
    const notes = screen.getAllByRole('note')
    const cap = notes.find((n) => /per-type load cap/.test(n.textContent ?? ''))
    expect(cap?.textContent).toMatch(/order can be wrong/i)
  })
})

/**
 * Volume over time, counted server-side.
 *
 * The bars used to be bucketed in the browser over whatever the correlation
 * page's cap happened to load, which makes a histogram a claim about when
 * 2.5% of the traffic happened, drawn at the resolution of that sample. Worse
 * than the ranking beside it, because a chart is read at a glance and its
 * shape — where the peak is, where the quiet weeks are — is the finding.
 *
 * What follows pins down which filter states the server's answer is valid for,
 * that the page falls back and says so when it is not, that the four ways a
 * chart can be empty stay four different sentences, and that nothing on the
 * chart presents an instant the server only assumed as one it read.
 */
describe('CommsPage volume over time', () => {
  /** A day-bucketed answer whose numbers are all deliberately different. */
  const HISTOGRAM = {
    buckets: [
      { bucket_start_secs: 1709424000, count: 400, rescued_count: 3 },
      { bucket_start_secs: 1709596800, count: 9, rescued_count: 0 },
    ],
    bucket_seconds: 86400,
    min_ts_secs: 1709424000,
    max_ts_secs: 1709640000,
    total_records: 93338,
    // The bars sum to 409, which is exactly placed_by_rescue + placed_as_written,
    // and the six census classes sum to matched_records. A fixture that broke
    // either would be refused by the wire reader before it reached the page —
    // which is itself covered, further down.
    matched_records: 759,
    unreadable_metadata: 1,
    not_a_message: 12,
    unplaceable_absent: 40,
    unplaceable_value: 297,
    placed_by_rescue: 3,
    placed_as_written: 406,
    by_type_unplaceable: [
      ['EmailMessage', 289],
      ['CallLog', 8],
    ],
  }

  const RANKING = {
    contacts: [{ contact: 'alice', count: 900 }],
    limit: 8,
    has_more: false,
    distinct_contacts: 1,
    by_type: [['iMessage', 93338]],
    total_records: 93338,
    summary_records: 0,
    unrankable_records: 0,
    records_without_counterparty: 0,
  }

  const ROWS: Record<string, Record<string, unknown>[]> = {
    iMessage: [
      { contact: 'bob', is_from_me: false, timestamp: 1709424100 },
      { contact: 'alice', is_from_me: false },
    ],
  }

  const histogramRequests: URL[] = []

  beforeEach(() => {
    histogramRequests.length = 0
  })

  function mockCase(
    opts: {
      rows?: Record<string, Record<string, unknown>[]>
      total?: number
      histogram?: unknown
      histogramStatus?: number
      ranking?: unknown
      rankingStatus?: number
    } = {},
  ) {
    const rows = opts.rows ?? ROWS
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type') ?? ''
        const page = Number(url.searchParams.get('page') ?? '1')
        const records =
          page === 1
            ? (rows[type] ?? []).map((metadata, i) => ({
                id: `art-${type}-${i}`,
                parent_id: null,
                artifact_type: 'ParsedRecord',
                metadata,
              }))
            : []
        return HttpResponse.json({
          records,
          total: opts.total ?? records.length,
          page,
          page_size: 100,
          type,
        })
      }),
      http.get('/api/v1/cases/:caseId/comms/ranking', () =>
        opts.rankingStatus && opts.rankingStatus !== 200
          ? HttpResponse.json(
              { error: { code: 'INTERNAL', message: 'no ranking' } },
              { status: opts.rankingStatus },
            )
          : HttpResponse.json(opts.ranking ?? RANKING),
      ),
      http.get('/api/v1/cases/:caseId/comms/histogram', ({ request }) => {
        histogramRequests.push(new URL(request.url))
        if (opts.histogramStatus && opts.histogramStatus !== 200) {
          return HttpResponse.json(
            { error: { code: 'INTERNAL', message: 'histogram exploded' } },
            { status: opts.histogramStatus },
          )
        }
        return HttpResponse.json(opts.histogram ?? HISTOGRAM)
      }),
    )
  }

  const chart = () => document.querySelector('.rv-histo')?.textContent ?? ''
  const chartTitle = () =>
    document.querySelector('.rv-histo-title')?.textContent ?? ''
  const bars = () =>
    [...document.querySelectorAll('.rv-histo svg title')].map(
      (t) => t.textContent ?? '',
    )
  const capBanner = () =>
    screen
      .getAllByRole('note')
      .find((n) => /per-type load cap/.test(n.textContent ?? ''))?.textContent ??
    ''

  it('draws the bars the server counted, not the browser’s bucketing of the slice', async () => {
    // The loaded slice holds one placeable record. A bar of 400 can only have
    // come from the server.
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(bars()[0]).toMatch(/400 events/))
    expect(chartTitle()).toMatch(/exact/i)
    expect(chartTitle()).not.toMatch(/loaded slice/i)
  })

  it('draws a bar as the period it covers, never as the instant it starts at', async () => {
    // The bucket starts at midnight on 2024-03-03 and is a day wide. A tooltip
    // naming only the start invites "400 events on 3 March", and with a wider
    // bucket that sentence is wrong by weeks.
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(bars()[0]).toMatch(/400 events/))
    expect(bars()[0]).toMatch(/2024-03-03 00:00:00 UTC/)
    expect(bars()[0]).toMatch(/2024-03-04 00:00:00 UTC/)
    expect(bars()[0]).toMatch(/end excluded/i)
  })

  it('gap-fills the day the server sent no bucket for', async () => {
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(bars()[0]).toMatch(/400 events/))
    // 03-03 and 03-05 came back; 03-04 must be drawn as a quiet day rather
    // than closed up as though the two were consecutive.
    expect(bars()).toHaveLength(3)
    expect(bars()[1]).toMatch(/\b0 events\b/)
    expect(bars()[1]).toMatch(/2024-03-04 00:00:00 UTC/)
  })

  it('sends the record type, the needle and the contact filter', async () => {
    mockCase()
    renderPage('case-1')
    await waitFor(() => expect(bars()[0]).toMatch(/400 events/))

    await userEvent.click(screen.getByRole('button', { name: /iMessage/ }))
    await userEvent.type(screen.getByLabelText('Filter communications'), 'bo')

    await waitFor(
      () =>
        expect(
          histogramRequests.some(
            (u) =>
              u.searchParams.get('channel') === 'iMessage' &&
              u.searchParams.get('q') === 'bo',
          ),
        ).toBe(true),
      BEHIND_DEBOUNCE,
    )
    // The contact bar narrows the chart too — unlike the ranking, which cannot
    // rank the correspondents of a one-correspondent view.
    const aliceBar = [...document.querySelectorAll('.rv-top-row')].find(
      (el) => el.getAttribute('title') === 'alice',
    )
    expect(aliceBar).toBeDefined()
    await userEvent.click(aliceBar as HTMLElement)
    await waitFor(
      () =>
        expect(
          histogramRequests.some(
            (u) => u.searchParams.get('contact') === 'alice',
          ),
        ).toBe(true),
      BEHIND_DEBOUNCE,
    )
  })

  it('keeps the case, the matched population and the placed records apart', async () => {
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(chart()).toMatch(/93,338/))
    expect(chart()).toMatch(/759/)
    expect(chart()).toMatch(/406/)
    expect(chart()).toMatch(/not narrowed by the filter box/i)
  })

  it('names each class of unplaced record without summing them into one figure', async () => {
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(chart()).toMatch(/93,338/))
    const said = chart()
    expect(said).toMatch(/40 record/)
    expect(said).toMatch(/297/)
    expect(said).toMatch(/12/)
    expect(said).toMatch(/EmailMessage 289/)
    expect(said).toMatch(/do not add up to one figure/i)
  })

  it('says which instants it could only place by assuming their unit', async () => {
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(bars()[0]).toMatch(/400 events/))
    expect(bars()[0]).toMatch(/3 of them/i)
    expect(bars()[0]).toMatch(/assuming which unit/i)
    expect(chart()).toMatch(/assuming which unit/i)
  })

  it('states the bar width and refuses to call the buckets calendar days', async () => {
    // FRIENDLY_BUCKET_SECONDS measures a "month" as 30.4375 days from the
    // epoch. An axis that implied calendar alignment would put an event in the
    // wrong month at the boundary.
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(chart()).toMatch(/93,338/))
    expect(chart()).toMatch(/not aligned to calendar/i)
  })

  it('warns that a tall bar can stand above a table with no rows for it', async () => {
    // The exact-answer trap LIVE-024 already fixed for the ranking: a bar of
    // 400 above a table drawn from a capped slice that holds one matching
    // record reads as "there is nothing here".
    mockCase()
    renderPage('case-1')

    await waitFor(() => expect(chart()).toMatch(/93,338/))
    expect(chart()).toMatch(/table of individual records below/i)
  })

  it('does not imply the tiles or the table became exact because the bars did', async () => {
    mockCase({ total: 5000, rankingStatus: 500 })
    renderPage('case-1')

    await waitFor(() => expect(chartTitle()).toMatch(/exact/i))
    // Histogram exact, ranking on the slice: both halves of the 2x2 said.
    expect(capBanner()).toMatch(/order can be wrong/i)
    expect(capBanner()).toMatch(/tiles/i)
    expect(capBanner()).toMatch(/under-report/i)
    expect(capBanner()).toMatch(/histogram is the exception/i)
  })

  it('names both exceptions when the ranking and the histogram are both exact', async () => {
    mockCase({ total: 5000 })
    renderPage('case-1')

    await waitFor(() => expect(chartTitle()).toMatch(/exact/i))
    await waitFor(() =>
      expect(
        document.querySelector('.rv-dims .rv-top-title')?.textContent ?? '',
      ).toMatch(/exact/i),
    )
    expect(capBanner()).not.toMatch(/order can be wrong/i)
    expect(capBanner()).toMatch(/tiles/i)
    expect(capBanner()).toMatch(/under-report/i)
    expect(capBanner()).toMatch(/are the exceptions/i)
  })
})

/**
 * The four ways this chart can be empty, and why they must never look alike.
 *
 * "This case holds no communications", "records exist and not one of them
 * could be placed in time", "your filter matched nothing" and "the request
 * failed" are four different findings, and three of them come back with an
 * identical empty `buckets` array. A blank band under a heading is the one
 * rendering that could be quoted as any of them.
 */
describe('CommsPage volume over time: the empty states', () => {
  const CENSUS = {
    buckets: [],
    bucket_seconds: null,
    min_ts_secs: null,
    max_ts_secs: null,
    by_type_unplaceable: null,
  }

  function mockHistogram(body: Record<string, unknown> | null, status = 200) {
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const type = new URL(request.url).searchParams.get('type') ?? ''
        const records =
          type === 'iMessage'
            ? [
                {
                  id: 'art-1',
                  parent_id: null,
                  artifact_type: 'ParsedRecord',
                  metadata: { contact: 'Alice', is_from_me: false },
                },
              ]
            : []
        return HttpResponse.json({
          records,
          total: records.length,
          page: 1,
          page_size: 100,
          type,
        })
      }),
      http.get('/api/v1/cases/:caseId/comms/ranking', () =>
        HttpResponse.json({ contacts: [] }),
      ),
      http.get('/api/v1/cases/:caseId/comms/histogram', () =>
        status === 200
          ? HttpResponse.json(body)
          : HttpResponse.json(
              { error: { code: 'INTERNAL', message: 'histogram exploded' } },
              { status },
            ),
      ),
    )
  }

  const chart = () => document.querySelector('.rv-histo')?.textContent ?? ''

  it('says a case with no communications in it has none', async () => {
    mockHistogram({
      ...CENSUS,
      total_records: 0,
      matched_records: 0,
      unreadable_metadata: 0,
      not_a_message: 0,
      unplaceable_absent: 0,
      unplaceable_value: 0,
      placed_by_rescue: 0,
      placed_as_written: 0,
    })
    renderPage('case-1')

    await waitFor(() => expect(chart()).toMatch(/no communication records/i))
    expect(chart()).not.toMatch(/matched nothing|could be placed/i)
  })

  it('says a filter that matched nothing matched nothing', async () => {
    mockHistogram({
      ...CENSUS,
      total_records: 93338,
      matched_records: 0,
      unreadable_metadata: 0,
      not_a_message: 0,
      unplaceable_absent: 0,
      unplaceable_value: 0,
      placed_by_rescue: 0,
      placed_as_written: 0,
    })
    renderPage('case-1')

    await waitFor(() => expect(chart()).toMatch(/matched none/i))
    // And it says how big the case is, so "nothing here" cannot read as "this
    // case is empty".
    expect(chart()).toMatch(/93,338/)
  })

  it('says records were read and not one of them could be placed in time', async () => {
    // The single worst empty state to draw as a blank chart: the evidence is
    // there and the times are not, which is a finding about the parsers, not
    // about the machine's owner.
    mockHistogram({
      ...CENSUS,
      total_records: 93338,
      matched_records: 329,
      unreadable_metadata: 0,
      not_a_message: 12,
      unplaceable_absent: 40,
      unplaceable_value: 277,
      placed_by_rescue: 0,
      placed_as_written: 0,
      by_type_unplaceable: [['EmailMessage', 277]],
    })
    renderPage('case-1')

    await waitFor(() => expect(chart()).toMatch(/329/))
    expect(chart()).toMatch(/not one of them could be placed/i)
    expect(chart()).toMatch(/277/)
    expect(chart()).toMatch(/not a statement that nothing happened/i)
  })

  it('falls back to the labelled slice chart when the request failed', async () => {
    mockHistogram(null, 500)
    renderPage('case-1')

    await waitFor(() =>
      expect(
        document.querySelector('.rv-histo-title')?.textContent ?? '',
      ).toMatch(/within the loaded slice/i),
    )
    expect(chart()).toMatch(/could not be loaded/i)
    expect(chart()).not.toMatch(/exact, counted server-side/i)
  })

  it('falls back rather than draw a chart whose own figures contradict', async () => {
    // The bars say 11; the census says 409 records were placed. Neither number
    // can be quoted, so neither is shown under the word "exact".
    mockHistogram({
      buckets: [{ bucket_start_secs: 1709424000, count: 11, rescued_count: 3 }],
      bucket_seconds: 86400,
      min_ts_secs: 1709424000,
      max_ts_secs: 1709510400,
      total_records: 93338,
      matched_records: 762,
      unreadable_metadata: 1,
      not_a_message: 12,
      unplaceable_absent: 40,
      unplaceable_value: 297,
      placed_by_rescue: 3,
      placed_as_written: 409,
      by_type_unplaceable: null,
    })
    renderPage('case-1')

    await waitFor(() =>
      expect(
        document.querySelector('.rv-histo-title')?.textContent ?? '',
      ).toMatch(/within the loaded slice/i),
    )
    expect(chart()).not.toMatch(/93,338/)
  })
})

/** Records shaped so one row of each interesting kind reaches the table. */
function mockRowKinds() {
  server.use(
    http.get('/api/v1/cases/:caseId/records', ({ request }) => {
      const type = new URL(request.url).searchParams.get('type')
      const records =
        type === 'iMessage'
          ? [
              {
                id: 'msg-1',
                parent_id: 'chatdb',
                artifact_type: 'ParsedRecord',
                metadata: {
                  contact: '+44 7700 900123',
                  chat_identifier: 'chat-9',
                  text: 'meet at 9',
                  date: 1_700_000_000,
                  is_from_me: false,
                },
              },
              {
                id: 'msg-2',
                parent_id: 'chatdb',
                artifact_type: 'ParsedRecord',
                metadata: {
                  contact: '+44 7700 900123',
                  chat_identifier: 'chat-9',
                  date: 1_700_000_100,
                  is_from_me: true,
                },
              },
            ]
          : type === 'CallLog'
            ? [
                {
                  id: 'call-1',
                  parent_id: null,
                  artifact_type: 'ParsedRecord',
                  metadata: {
                    contact: '+44 7700 900999',
                    duration_seconds: 154,
                    direction: 'incoming',
                    timestamp: 1_700_000_200,
                  },
                },
              ]
            : []
      return HttpResponse.json({
        records,
        total: records.length,
        page: 1,
        page_size: 100,
        type,
      })
    }),
    http.get('/api/v1/cases/:caseId/comms/ranking', () =>
      HttpResponse.json(
        { error: { code: 'INTERNAL', message: 'no ranking here' } },
        { status: 500 },
      ),
    ),
    http.get('/api/v1/cases/:caseId/comms/histogram', () =>
      HttpResponse.json(
        { error: { code: 'INTERNAL', message: 'no histogram here' } },
        { status: 500 },
      ),
    ),
    http.get('/api/v1/cases/:caseId/bookmarks/ids', () => HttpResponse.json([])),
    http.get('/api/v1/cases/:caseId/bookmarks/categories', () =>
      HttpResponse.json([]),
    ),
  )
}

/** The table row whose text matches `needle`, once the table has drawn it. */
async function findRow(needle: RegExp): Promise<HTMLElement> {
  return await waitFor(() => {
    const row = screen
      .getAllByRole('row')
      .find((r) => needle.test(r.textContent ?? ''))
    if (!row) throw new Error(`no row matching ${needle}`)
    return row
  })
}

describe('a comms row does not dead-end', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('offers the conversation the message belongs to, not only its record', async () => {
    mockRowKinds()
    renderPage('case-1')

    const row = await findRow(/meet at 9/)
    const conversation = within(row).getByRole('link', {
      name: /conversation containing/i,
    })
    // The viewer's own deep-link vocabulary: the record type it renders, the
    // thread it groups on, and the message to bring into view.
    expect(conversation).toHaveAttribute(
      'href',
      '/cases/case-1/analysis/iMessage?conv=chat-9&focus=msg-1',
    )
    // The provenance hop is not lost: the record artifact is still reachable.
    expect(within(row).getByRole('link', { name: 'open' })).toBeInTheDocument()
  })

  it('shows the message the record holds instead of sending the examiner to raw JSON', async () => {
    mockRowKinds()
    renderPage('case-1')
    expect(await screen.findByText('meet at 9')).toBeInTheDocument()
  })

  it('says what a row holds when it holds no text, rather than leaving it blank', async () => {
    mockRowKinds()
    renderPage('case-1')
    // A call has no text and the row says what it has instead.
    expect(await screen.findByText('Call, 2:34')).toBeInTheDocument()
    // A message with no text says so in words.
    expect(
      await screen.findByText(/no message text/i),
    ).toBeInTheDocument()
  })

  it('gives a call no conversation link, because there is no thread to open', async () => {
    mockRowKinds()
    renderPage('case-1')
    await screen.findByText('Call, 2:34')
    const rows = screen.getAllByRole('row')
    const callRow = rows.find((r) => /900999/.test(r.textContent ?? ''))
    expect(callRow).toBeDefined()
    expect(
      within(callRow!).queryByRole('link', { name: /conversation/i }),
    ).toBeNull()
    expect(within(callRow!).getByText(/no conversation view/i)).toBeInTheDocument()
  })
})

describe('the comms table records what has been looked at', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('marks a row reviewed and keeps that apart from having opened it', async () => {
    mockRowKinds()
    renderPage('case-1')

    const row = await findRow(/meet at 9/)
    // The ledger is read from the server, so the row's standing is not known
    // in the first frame and the control says so rather than drawing the row
    // as unreviewed. `false` only becomes an honest answer once the listing
    // has landed.
    const mark = await within(row).findByRole('button', {
      name: /^Mark the message[^(]*$/,
    })
    await waitFor(() =>
      expect(mark).toHaveAttribute('aria-pressed', 'false'),
    )
    await userEvent.click(mark)

    await waitFor(() =>
      expect(
        within(row).getByRole('button', { name: /withdraw the review/i }),
      ).toHaveAttribute('aria-pressed', 'true'),
    )

    // The other row is untouched: clearing one row says nothing about another.
    const other = await findRow(/no message text/i)
    expect(
      within(other).getByRole('button', { name: /^Mark the message[^(]*$/ }),
    ).toHaveAttribute('aria-pressed', 'false')
  })

  it('states no denominator it cannot support, and names who sees a mark', async () => {
    mockRowKinds()
    renderPage('case-1')

    const panel = await screen.findByRole('region', { name: /review ledger/i })
    // This page loaded a capped slice of sixteen record types; the marks it
    // counts are case-wide. There is no denominator here the numerator belongs
    // to, so the panel says the population is not stated rather than borrowing
    // one — and it never draws a proportion.
    expect(panel.textContent).toMatch(/population not stated/i)
    expect(panel.textContent).not.toMatch(/%/)
    // The ledger is the case's now, and the panel says so. The sentence this
    // replaces — "stored in this browser only" — described a real limitation
    // honestly right up until the ledger stopped being browser-local, at which
    // point it became a false reassurance about who can see a mark.
    expect(panel.textContent).toMatch(/stored with the case on the server/i)
    expect(panel.textContent).toMatch(/every examiner with access to this case/i)
    expect(panel.textContent).not.toMatch(/this browser only/i)
    expect(panel.textContent).toMatch(/opening is not examining/i)
  })
})

/**
 * What one row costs, multiplied by the cap.
 *
 * The table draws up to five hundred rows and every one of them carries a
 * capture control and a review mark. An examiner on a three-week case works
 * this list for hours, so anything a row does per-row is done five hundred
 * times for every click — and the two things a row used to do were subscribe
 * to react-query for the case's whole bookmark list and subscribe to the
 * review ledger. Neither is a per-row question, and these cases hold the cost
 * where it belongs.
 */
describe('the comms table at its cap', () => {
  const ROWS = 30

  function mockManyRows() {
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const type = new URL(request.url).searchParams.get('type')
        const records =
          type === 'iMessage'
            ? Array.from({ length: ROWS }, (_, i) => ({
                id: `msg-${i}`,
                parent_id: 'chatdb',
                artifact_type: 'ParsedRecord',
                metadata: {
                  contact: `+44 7700 9001${String(i).padStart(2, '0')}`,
                  chat_identifier: `chat-${i}`,
                  text: `message ${i}`,
                  date: 1_700_000_000 + i,
                  is_from_me: false,
                },
              }))
            : []
        return HttpResponse.json({
          records,
          total: records.length,
          page: 1,
          page_size: 100,
          type,
        })
      }),
      http.get('/api/v1/cases/:caseId/comms/ranking', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'no ranking here' } },
          { status: 500 },
        ),
      ),
      http.get('/api/v1/cases/:caseId/comms/histogram', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'no histogram here' } },
          { status: 500 },
        ),
      ),
    )
  }

  function renderWithClient(caseId: string) {
    mockReviewLedger()
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <CommsPage caseId={caseId} />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    return client
  }

  it('asks for the case bookmarks once for the table, not once per row', async () => {
    mockManyRows()
    const client = renderWithClient('case-1')
    await screen.findByText('message 29')

    // One observer per row means one bookmark write wakes a thousand of them,
    // each recomputing the same answer about the same list. The list is a fact
    // about the case, so the table watches it once and every row reads that
    // one answer.
    for (const leaf of ['ids', 'categories']) {
      const query = client
        .getQueryCache()
        .find({ queryKey: ['bookmarks', 'case-1', leaf] })
      expect(query, `no ${leaf} query`).toBeDefined()
      expect(query!.observers.length, `${leaf} observers`).toBe(1)
    }
  })

  it('still shows every row its own bookmark state', async () => {
    server.use(
      http.get('/api/v1/cases/:caseId/bookmarks/ids', () =>
        HttpResponse.json(['msg-3']),
      ),
    )
    mockManyRows()
    renderWithClient('case-1')
    await screen.findByText('message 29')

    // Sharing the lookup must not share the ANSWER. Exactly the bookmarked row
    // shows as bookmarked; a table that painted the same star on every row
    // would be asserting captures nobody made.
    const marked = await screen.findAllByRole('button', {
      name: /^Edit bookmark for/,
    })
    expect(marked).toHaveLength(1)
    // …and it is the row whose record the server named, identified by the
    // counterparty the control puts in its own accessible label.
    expect(marked[0]).toHaveAccessibleName(/\+44 7700 900103/)
  })
})
