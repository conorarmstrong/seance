import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { delay, http, HttpResponse } from 'msw'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  PaginatedTimeline,
  TimelineEvent,
  TimelinePagination,
  VirtualColumnDef,
} from '../../api/types'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import { FrameSpy } from '../../test/frames'
import { TimelinePage } from './TimelinePage'
import { TimeWindowCtx } from '../../app/TimeWindowContext'

const CASE = 'case-1'

const PAGINATION: TimelinePagination = {
  total_count: 2,
  page: 1,
  page_size: 100,
  total_pages: 1,
  has_next: false,
  has_previous: false,
}

const EVENTS: TimelineEvent[] = [
  {
    id: 'ev-1',
    case_id: CASE,
    artifact_id: 'art-1',
    timestamp: 1700000000,
    timestamp_desc: 'File Modified',
    source_module: 'filesystem.ntfs',
    short_desc: 'evil.dll modified',
    full_details: '{"filename":"evil.dll","file_size":1024}',
    is_tagged: false,
  },
  {
    id: 'ev-2',
    case_id: CASE,
    artifact_id: 'art-2',
    timestamp: 1700003600,
    timestamp_desc: 'Registry Key Updated',
    source_module: 'registry.hives',
    short_desc: 'Run key added',
    full_details: 'plain text details',
    is_tagged: true,
    tag_note: 'suspicious persistence',
  },
]

// $FILE_NAME-derived event: timestamp_desc ends in "(FN)". full_details is the
// plain-text summary the MFT parser emits (stored as a JSON string).
const FN_EVENT: TimelineEvent = {
  id: 'ev-fn',
  case_id: CASE,
  artifact_id: 'art-3',
  timestamp: 1700007200,
  timestamp_desc: 'Created (FN)',
  source_module: 'plugin.ntfs.mft_parser',
  short_desc: 'FILE secret.dll (MFT: 42)',
  full_details: '"MFT Record #42 | Created (FN) | FILE | Path: secret.dll"',
  is_tagged: false,
}

// Timestomp-suspected event whose full_details carries the flag, reasons and
// paired SI/FN timestamps.
const STOMP_EVENT: TimelineEvent = {
  id: 'ev-stomp',
  case_id: CASE,
  artifact_id: 'art-4',
  timestamp: 1700007300,
  timestamp_desc: 'Modified',
  source_module: 'plugin.ntfs.mft_parser',
  short_desc: 'FILE backdoor.exe (MFT: 99)',
  full_details: JSON.stringify({
    timestamp_type: 'SI_Modified',
    timestomp_suspected: true,
    timestomp_reasons: [
      'SI Created precedes FN Created',
      'Sub-second precision mismatch on Created',
    ],
    created: '2021-01-01T00:00:00+00:00',
    fn_created: '2023-06-01T12:00:00+00:00',
  }),
  is_tagged: false,
}

const VIRTUAL_COLUMNS: VirtualColumnDef[] = [
  {
    id: 'vc_file_size',
    name: 'File Size',
    description: 'Size in bytes',
    type: 'integer',
    sources: [{ path: '$.file_size', artifact_types: [] }],
    default_visible: false,
    built_in: true,
  },
  {
    id: 'vc_custom',
    name: 'Custom Col',
    description: 'A custom column',
    type: 'string',
    sources: [{ path: '$.custom', artifact_types: [] }],
    default_visible: false,
    built_in: false,
  },
]

const MODULES = { 'filesystem.ntfs': 120, 'registry.hives': 30 }

// 1h domain, 600s buckets; slots at +600s/+1800s/+2400s/+3000s are omitted
// by the server and must be gap-filled by the chart (7 slots, 3 non-zero).
const HISTOGRAM = {
  min_ts: 1700000000,
  max_ts: 1700003600,
  bucket_seconds: 600,
  // Counts avoid "2" so bucket tooltips never collide with the toolbar's
  // "2 events" total in text queries.
  buckets: [
    { start: 1700000000, count: 5 },
    { start: 1700001200, count: 3 },
    { start: 1700003600, count: 1 },
  ],
}

let timelineRequests: URL[] = []
let histogramRequests: URL[] = []

const lastRequest = () => timelineRequests[timelineRequests.length - 1]
const lastHistogramRequest = () =>
  histogramRequests[histogramRequests.length - 1]

function mockHistogram(response: typeof HISTOGRAM = HISTOGRAM) {
  server.use(
    http.get(`/api/v1/cases/${CASE}/timeline/histogram`, ({ request }) => {
      histogramRequests.push(new URL(request.url))
      return HttpResponse.json(response)
    }),
  )
}

function mockTimeline(overrides: Partial<PaginatedTimeline> = {}) {
  server.use(
    http.get(`/api/v1/cases/${CASE}/timeline`, ({ request }) => {
      const url = new URL(request.url)
      timelineRequests.push(url)
      let events = overrides.events ?? EVENTS
      // Simulate dynamic column extraction when columns param is present.
      if (url.searchParams.get('columns')?.includes('$.file_size')) {
        events = events.map((ev) =>
          ev.id === 'ev-1' ? { ...ev, dynamic_fields: { file_size: 1024 } } : ev,
        )
      }
      return HttpResponse.json({
        events,
        pagination: overrides.pagination ?? PAGINATION,
      })
    }),
  )
}

beforeEach(() => {
  timelineRequests = []
  histogramRequests = []
  mockHistogram()
  server.use(
    http.get(`/api/v1/cases/${CASE}/timeline/modules`, () =>
      HttpResponse.json(MODULES),
    ),
    http.get(`/api/v1/cases/${CASE}/virtual_columns`, () =>
      HttpResponse.json({ virtual_columns: VIRTUAL_COLUMNS }),
    ),
  )
  mockTimeline()
})

afterEach(() => {
  localStorage.clear()
})

function renderPage(initialEntry = `/cases/${CASE}/timeline`, extra?: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={[initialEntry]}>
          <Routes>
            <Route
              path="/cases/:caseId/timeline"
              element={
                <>
                  <TimelinePage />
                  {extra}
                </>
              }
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

/** Test helper simulating browser back navigation. */
function GoBack() {
  const navigate = useNavigate()
  return <button onClick={() => navigate(-1)}>Go back</button>
}

/** Test helper switching to another case without unmounting the page. */
function GoToCase({ to }: { to: string }) {
  const navigate = useNavigate()
  return <button onClick={() => navigate(`/cases/${to}/timeline`)}>Open {to}</button>
}

/** Test helper reaching a URL directly — a back/forward step, a saved view or
 *  a link — rather than through the page's own controls. */
function GoToUrl({ to, label }: { to: string; label: string }) {
  const navigate = useNavigate()
  return <button onClick={() => navigate(to)}>{label}</button>
}

/** jsdom reports zero-size rects; give the brush surface a real geometry. */
function mockPlotRect(plot: HTMLElement, width: number) {
  plot.getBoundingClientRect = () =>
    ({
      left: 0,
      top: 0,
      width,
      height: 80,
      right: width,
      bottom: 80,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    }) as DOMRect
}

describe('TimelinePage', () => {
  it('shows loading then renders events with UTC timestamps and module badges', async () => {
    renderPage()
    expect(screen.getByLabelText(/loading timeline/i)).toBeInTheDocument()
    expect(await screen.findByText('evil.dll modified')).toBeInTheDocument()
    expect(screen.getByText('2023-11-14 22:13:20 UTC')).toBeInTheDocument()
    expect(screen.getByText('filesystem.ntfs')).toBeInTheDocument()
    expect(screen.getByText('File Modified')).toBeInTheDocument()
    expect(screen.getByText(/2 events/)).toBeInTheDocument()
    expect(screen.getByText('suspicious persistence')).toBeInTheDocument()
  })

  it('shows an empty state when there are no events', async () => {
    mockTimeline({
      events: [],
      pagination: { ...PAGINATION, total_count: 0, total_pages: 0 },
    })
    renderPage()
    expect(await screen.findByText(/no timeline events/i)).toBeInTheDocument()
  })

  it('shows an error state when the timeline request fails', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline`, () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    expect(
      await screen.findByText(/failed to load timeline/i),
    ).toBeInTheDocument()
  })

  it('expands a row to show pretty-printed details and an artifact link', async () => {
    renderPage()
    await userEvent.click(await screen.findByText('evil.dll modified'))
    expect(
      await screen.findByText(/"filename": "evil.dll"/),
    ).toBeInTheDocument()
    const link = screen.getByRole('link', { name: /view artifact/i })
    expect(link).toHaveAttribute('href', `/cases/${CASE}/artifacts/art-1`)
    // Non-JSON details render verbatim.
    await userEvent.click(screen.getByText('Run key added'))
    expect(await screen.findByText('plain text details')).toBeInTheDocument()
  })

  it('tags an untagged event and refetches the timeline', async () => {
    const created: string[] = []
    server.use(
      http.post(`/api/v1/cases/${CASE}/timeline/tags/:eventId`, ({ params }) => {
        created.push(params.eventId as string)
        return HttpResponse.json({
          id: 'tag-1',
          case_id: CASE,
          event_id: params.eventId,
          examiner: null,
          note: null,
          created_at: 0,
        })
      }),
    )
    renderPage()
    await screen.findByText('evil.dll modified')
    const before = timelineRequests.length
    await userEvent.click(screen.getByRole('button', { name: 'Tag event' }))
    await waitFor(() => expect(created).toContain('ev-1'))
    await waitFor(() => expect(timelineRequests.length).toBeGreaterThan(before))
  })

  it('removes the tag from a tagged event', async () => {
    const deleted: string[] = []
    server.use(
      http.delete(
        `/api/v1/cases/${CASE}/timeline/tags/:eventId`,
        ({ params }) => {
          deleted.push(params.eventId as string)
          return HttpResponse.json({ success: true })
        },
      ),
    )
    renderPage()
    await screen.findByText('Run key added')
    await userEvent.click(screen.getByRole('button', { name: 'Remove tag' }))
    await waitFor(() => expect(deleted).toContain('ev-2'))
  })

  it('submits search on Enter and shows the syntax help popover', async () => {
    renderPage()
    await screen.findByText('evil.dll modified')
    await userEvent.type(
      screen.getByPlaceholderText(/search timeline/i),
      'malware{Enter}',
    )
    await waitFor(() => {
      expect(lastRequest().searchParams.get('search')).toBe('malware')
      expect(lastRequest().searchParams.get('page')).toBe('1')
    })
    await userEvent.click(
      screen.getByRole('button', { name: /search syntax help/i }),
    )
    expect(screen.getByText(/column:value/)).toBeInTheDocument()
  })

  it('applies range presets and custom from/to bounds', async () => {
    renderPage()
    await screen.findByText('evil.dll modified')
    await userEvent.selectOptions(
      screen.getByLabelText(/date range/i),
      '7d',
    )
    await waitFor(() =>
      expect(lastRequest().searchParams.get('range')).toBe('7d'),
    )
    fireEvent.change(screen.getByLabelText(/from/i), {
      target: { value: '2024-01-01T00:00' },
    })
    await waitFor(() => {
      expect(lastRequest().searchParams.get('from')).toBe('1704067200')
      expect(lastRequest().searchParams.get('range')).toBeNull()
    })
  })

  it('filters by module and tagged-only', async () => {
    renderPage()
    await screen.findByText('evil.dll modified')
    await userEvent.click(screen.getByRole('button', { name: /modules/i }))
    await userEvent.click(screen.getByLabelText(/registry\.hives/))
    await waitFor(() =>
      expect(lastRequest().searchParams.get('modules')).toBe('registry.hives'),
    )
    await userEvent.click(screen.getByLabelText(/tagged only/i))
    await waitFor(() =>
      expect(lastRequest().searchParams.get('tagged_only')).toBe('true'),
    )
  })

  it('paginates and changes page size', async () => {
    mockTimeline({
      pagination: {
        ...PAGINATION,
        total_count: 500,
        total_pages: 3,
        has_next: true,
      },
    })
    renderPage()
    await screen.findByText('evil.dll modified')
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    await waitFor(() =>
      expect(lastRequest().searchParams.get('page')).toBe('2'),
    )
    await userEvent.selectOptions(screen.getByLabelText(/page size/i), '250')
    await waitFor(() => {
      expect(lastRequest().searchParams.get('page_size')).toBe('250')
      expect(lastRequest().searchParams.get('page')).toBe('1')
    })
  })

  it('withdraws the previous filter’s page controls while the new filter loads', async () => {
    // The pager reads page/total_pages off the response, and during a filter
    // change that response is still the previous filter's placeholder -- the
    // one whose rows are already gated behind a skeleton. Left live, its
    // Next/Last buttons compute a target from a total that no longer applies
    // and land the examiner on a page the new filter does not have, which then
    // renders as "No timeline events": a paging artefact that reads as a
    // finding about the evidence.
    let releaseSearch: () => void = () => {}
    const searchGate = new Promise<void>((resolve) => {
      releaseSearch = resolve
    })
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline`, async ({ request }) => {
        const url = new URL(request.url)
        timelineRequests.push(url)
        if (url.searchParams.get('search')) {
          await searchGate
          return HttpResponse.json({
            events: [EVENTS[0]],
            pagination: { ...PAGINATION, total_count: 1, total_pages: 1 },
          })
        }
        return HttpResponse.json({
          events: EVENTS,
          pagination: {
            ...PAGINATION,
            total_count: 500,
            total_pages: 5,
            has_next: true,
          },
        })
      }),
    )
    const { container } = renderPage()
    await screen.findByText('evil.dll modified')
    expect(screen.getByRole('button', { name: /next/i })).toBeEnabled()

    await userEvent.type(
      screen.getByPlaceholderText(/search timeline/i),
      'malware{Enter}',
    )

    // The rows are gated...
    expect(
      await screen.findByLabelText(/loading timeline/i),
    ).toBeInTheDocument()
    // ...so the paging context that belongs to them is gone too.
    expect(container.querySelector('.pager')).toBeNull()
    expect(screen.queryByRole('button', { name: /next/i })).toBeNull()

    // Once the new filter's own pagination arrives, paging is live again --
    // on the single page this result set actually has.
    releaseSearch()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /next/i })).toBeDisabled(),
    )
  })

  it('reuses the cached total while paging instead of recounting (count=false)', async () => {
    // Server-accurate mock: it recomputes the total only when count != false,
    // and returns the -1 sentinel otherwise.
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline`, ({ request }) => {
        const url = new URL(request.url)
        timelineRequests.push(url)
        const skipCount = url.searchParams.get('count') === 'false'
        const pagination: TimelinePagination = skipCount
          ? {
              total_count: -1,
              page: Number(url.searchParams.get('page') ?? '1'),
              page_size: 100,
              total_pages: -1,
              has_next: true,
              has_previous: true,
            }
          : {
              total_count: 500,
              page: 1,
              page_size: 100,
              total_pages: 5,
              has_next: true,
              has_previous: false,
            }
        return HttpResponse.json({ events: EVENTS, pagination })
      }),
    )
    renderPage()
    await screen.findByText('evil.dll modified')
    // Page 1 asks for the count (param omitted) and shows the real total.
    expect(lastRequest().searchParams.get('count')).toBeNull()
    expect(screen.getByText(/500 events/)).toBeInTheDocument()

    // Paging forward skips the recount...
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    await waitFor(() =>
      expect(lastRequest().searchParams.get('page')).toBe('2'),
    )
    expect(lastRequest().searchParams.get('count')).toBe('false')

    // ...and the toolbar keeps the cached total instead of showing -1.
    await waitFor(() =>
      expect(screen.getByText(/500 events/)).toBeInTheDocument(),
    )
    expect(screen.queryByText(/-1 events/)).not.toBeInTheDocument()
  })

  it('does not poison the count cache with the previous filter total on a filter change', async () => {
    // Filter A (no search) totals 500; filter B (search=foo) totals 7. Hold
    // filter B's page-1 count so the previous filter's data lingers as
    // placeholder while we page forward. If the placeholder total were cached
    // under filter B's key, page 2 of filter B would skip the recount and reuse
    // the stale 500. The page-2 request must instead ask for the count.
    let releaseB1: () => void = () => {}
    const b1Gate = new Promise<void>((resolve) => {
      releaseB1 = resolve
    })
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline`, async ({ request }) => {
        const url = new URL(request.url)
        timelineRequests.push(url)
        const isFoo = url.searchParams.get('search') === 'foo'
        const page = Number(url.searchParams.get('page') ?? '1')
        const skipCount = url.searchParams.get('count') === 'false'
        const total = isFoo ? 7 : 500
        if (isFoo && page === 1 && !skipCount) await b1Gate
        const pagination: TimelinePagination = skipCount
          ? {
              total_count: -1,
              page,
              page_size: 100,
              total_pages: -1,
              has_next: true,
              has_previous: true,
            }
          : {
              total_count: total,
              page,
              page_size: 100,
              total_pages: Math.ceil(total / 100),
              has_next: true,
              has_previous: page > 1,
            }
        return HttpResponse.json({ events: EVENTS, pagination })
      }),
    )
    renderPage(
      `/cases/${CASE}/timeline`,
      <GoToUrl
        to={`/cases/${CASE}/timeline?search=foo&page=2`}
        label="Open page 2"
      />,
    )
    await screen.findByText('evil.dll modified')
    expect(screen.getByText(/500 events/)).toBeInTheDocument()

    // Change the filter; its first (count) response is gated, so the previous
    // filter's data stays on screen as placeholder.
    await userEvent.type(
      screen.getByPlaceholderText(/search timeline/i),
      'foo{Enter}',
    )
    await waitFor(() =>
      expect(
        timelineRequests.some((u) => u.searchParams.get('search') === 'foo'),
      ).toBe(true),
    )

    // Page forward while the placeholder is showing. Not via the pager: that is
    // withdrawn while the rows are gated, because the pages it would offer are
    // the previous filter's. The URL still reaches page 2 (back/forward, a
    // saved view), so the count cache has to hold up on that path.
    await userEvent.click(screen.getByRole('button', { name: 'Open page 2' }))
    await waitFor(() => {
      const p2 = timelineRequests.find(
        (u) =>
          u.searchParams.get('search') === 'foo' &&
          u.searchParams.get('page') === '2',
      )
      expect(p2).toBeTruthy()
      // Count omitted (not "false") => the cache was not poisoned.
      expect(p2?.searchParams.get('count')).toBeNull()
    })
    releaseB1()
  })

  it('gates the previous case events, total and chart on a case switch (BUG-195)', async () => {
    // Two cases can carry identical filters. The placeholder kept while the new
    // case loads belongs to the old case, so its identity tag must include the
    // case id — otherwise case A's events, total and histogram render under
    // case B's chrome and read as case B's evidence.
    const OTHER = 'case-2'
    let releaseOther: () => void = () => {}
    const otherGate = new Promise<void>((resolve) => {
      releaseOther = resolve
    })
    server.use(
      http.get(`/api/v1/cases/${OTHER}/timeline/modules`, () =>
        HttpResponse.json(MODULES),
      ),
      http.get(`/api/v1/cases/${OTHER}/virtual_columns`, () =>
        HttpResponse.json({ virtual_columns: VIRTUAL_COLUMNS }),
      ),
      // Hold both of case 2's responses so the placeholder window stays open.
      http.get(`/api/v1/cases/${OTHER}/timeline/histogram`, async () => {
        await otherGate
        return HttpResponse.json(HISTOGRAM)
      }),
      http.get(`/api/v1/cases/${OTHER}/timeline`, async () => {
        await otherGate
        return HttpResponse.json({
          events: [
            {
              ...EVENTS[0],
              id: 'ev-b1',
              case_id: OTHER,
              short_desc: 'case-2 only event',
            },
          ],
          pagination: { ...PAGINATION, total_count: 1 },
        })
      }),
    )

    renderPage(`/cases/${CASE}/timeline`, <GoToCase to={OTHER} />)
    await screen.findByText('evil.dll modified')
    expect(screen.getByText(/2 events/)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: `Open ${OTHER}` }))

    // Case 2's responses are still in flight: nothing from case 1 may show.
    await waitFor(() =>
      expect(screen.queryByText('evil.dll modified')).not.toBeInTheDocument(),
    )
    expect(screen.getByLabelText(/loading timeline/i)).toBeInTheDocument()
    expect(screen.queryByText(/2 events/)).not.toBeInTheDocument()
    expect(
      screen.queryByText(
        '9 events between 2023-11-14 22:13:20 UTC and 2023-11-14 23:13:20 UTC',
      ),
    ).not.toBeInTheDocument()

    releaseOther()
    expect(await screen.findByText('case-2 only event')).toBeInTheDocument()
  })

  it('does not merge another scope’s cached total into the pagination (BUG-265)', async () => {
    // The count cache is written under a filter key but was read without
    // checking it. While case 2's first page is in flight the placeholder is
    // case 1's page-2 response, whose total_count is the -1 "not computed"
    // sentinel; filling it from case 1's cache invents a 5-page result set
    // under case 2 and lets the examiner page into slices that do not exist.
    const OTHER = 'case-2'
    let releaseOther: () => void = () => {}
    const otherGate = new Promise<void>((resolve) => {
      releaseOther = resolve
    })
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline`, ({ request }) => {
        const url = new URL(request.url)
        timelineRequests.push(url)
        const page = Number(url.searchParams.get('page') ?? '1')
        const skipCount = url.searchParams.get('count') === 'false'
        const pagination: TimelinePagination = skipCount
          ? {
              total_count: -1,
              page,
              page_size: 100,
              total_pages: -1,
              has_next: true,
              has_previous: true,
            }
          : {
              total_count: 500,
              page,
              page_size: 100,
              total_pages: 5,
              has_next: true,
              has_previous: page > 1,
            }
        return HttpResponse.json({ events: EVENTS, pagination })
      }),
      http.get(`/api/v1/cases/${OTHER}/timeline/modules`, () =>
        HttpResponse.json(MODULES),
      ),
      http.get(`/api/v1/cases/${OTHER}/virtual_columns`, () =>
        HttpResponse.json({ virtual_columns: VIRTUAL_COLUMNS }),
      ),
      http.get(`/api/v1/cases/${OTHER}/timeline/histogram`, async () => {
        await otherGate
        return HttpResponse.json(HISTOGRAM)
      }),
      http.get(`/api/v1/cases/${OTHER}/timeline`, async () => {
        await otherGate
        return HttpResponse.json({
          events: [{ ...EVENTS[0], id: 'ev-b1', short_desc: 'case-2 event' }],
          pagination: { ...PAGINATION, total_count: 1, total_pages: 1 },
        })
      }),
    )

    renderPage(`/cases/${CASE}/timeline`, <GoToCase to={OTHER} />)
    await screen.findByText('evil.dll modified')
    expect(screen.getByText(/Page 1 of 5/)).toBeInTheDocument()

    // Page 2 skips the recount; the cached total legitimately fills it in.
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    await waitFor(() =>
      expect(screen.getByText(/Page 2 of 5/)).toBeInTheDocument(),
    )

    await userEvent.click(screen.getByRole('button', { name: `Open ${OTHER}` }))

    // Case 2's page is still in flight. Case 1's cached total/page count must
    // not be merged into the placeholder's pagination.
    await waitFor(() =>
      expect(screen.queryByText(/Page 2 of 5/)).not.toBeInTheDocument(),
    )
    expect(screen.queryByText(/500 rows/)).not.toBeInTheDocument()

    releaseOther()
    expect(await screen.findByText('case-2 event')).toBeInTheDocument()
  })

  it('closes an open tag-note modal on a case switch (BUG-266)', async () => {
    // The modal holds a case-1 event; Save posts to the CURRENT case id, so a
    // modal left open across the switch writes case 1's event id into case 2.
    const OTHER = 'case-2'
    server.use(
      http.get(`/api/v1/cases/${OTHER}/timeline/modules`, () =>
        HttpResponse.json(MODULES),
      ),
      http.get(`/api/v1/cases/${OTHER}/virtual_columns`, () =>
        HttpResponse.json({ virtual_columns: VIRTUAL_COLUMNS }),
      ),
      http.get(`/api/v1/cases/${OTHER}/timeline/histogram`, () =>
        HttpResponse.json(HISTOGRAM),
      ),
      http.get(`/api/v1/cases/${OTHER}/timeline`, () =>
        HttpResponse.json({
          events: [{ ...EVENTS[0], id: 'ev-b1', short_desc: 'case-2 event' }],
          pagination: { ...PAGINATION, total_count: 1 },
        }),
      ),
    )

    renderPage(`/cases/${CASE}/timeline`, <GoToCase to={OTHER} />)
    await screen.findByText('Run key added')
    await userEvent.click(screen.getByRole('button', { name: /edit note/i }))
    expect(await screen.findByRole('dialog')).toHaveAccessibleName('Tag note')

    await userEvent.click(screen.getByRole('button', { name: `Open ${OTHER}` }))

    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    )
  })

  it('paints no frame with case 1 selection or note modal under case 2 (B2-148)', async () => {
    // Closing the modal and dropping the selection from a `useEffect` runs
    // AFTER the commit that already reads case 2. That commit is painted: the
    // tag-note dialog for a case-1 event sits over case 2's timeline, and the
    // bulk bar offers "Tag 2" for case-1 event ids that would be POSTed to
    // /cases/case-2/timeline/tags/<idFromCase1>. `userEvent.click` flushes
    // passive effects before returning, so the assertion in the test above
    // passes against the broken version; a layout-effect snapshot does not.
    const OTHER = 'case-2'
    server.use(
      http.get(`/api/v1/cases/${OTHER}/timeline/modules`, () =>
        HttpResponse.json(MODULES),
      ),
      http.get(`/api/v1/cases/${OTHER}/virtual_columns`, () =>
        HttpResponse.json({ virtual_columns: VIRTUAL_COLUMNS }),
      ),
      http.get(`/api/v1/cases/${OTHER}/timeline/histogram`, () =>
        HttpResponse.json(HISTOGRAM),
      ),
      http.get(`/api/v1/cases/${OTHER}/timeline`, () =>
        HttpResponse.json({
          events: [{ ...EVENTS[0], id: 'ev-b1', short_desc: 'case-2 event' }],
          pagination: { ...PAGINATION, total_count: 1 },
        }),
      ),
    )

    const frames: string[] = []
    renderPage(
      `/cases/${CASE}/timeline`,
      <>
        <GoToCase to={OTHER} />
        <FrameSpy
          capture={() => document.body.textContent ?? ''}
          frames={frames}
        />
      </>,
    )
    await screen.findByText('Run key added')
    await userEvent.click(
      screen.getByRole('checkbox', { name: /select all events on page/i }),
    )
    expect(screen.getByText('2 selected')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /edit note/i }))
    expect(await screen.findByRole('dialog')).toHaveAccessibleName('Tag note')

    frames.length = 0
    await userEvent.click(screen.getByRole('button', { name: `Open ${OTHER}` }))

    await waitFor(() => expect(frames.length).toBeGreaterThan(0))
    for (const frame of frames) {
      expect(frame).not.toMatch(/\d+ selected/)
      expect(frame).not.toContain('Tag note')
    }
  })

  it('toggles timestamp sort order via the column header', async () => {
    renderPage()
    await screen.findByText('evil.dll modified')
    expect(lastRequest().searchParams.get('sort_order')).toBe('desc')
    await userEvent.click(
      screen.getByRole('button', { name: /timestamp/i }),
    )
    await waitFor(() =>
      expect(lastRequest().searchParams.get('sort_order')).toBe('asc'),
    )
  })

  it('initializes filters from the URL', async () => {
    renderPage(
      `/cases/${CASE}/timeline?search=preset&range=7d&page=2&tagged_only=true&sort_order=asc`,
    )
    await waitFor(() => expect(timelineRequests.length).toBeGreaterThan(0))
    const req = lastRequest()
    expect(req.searchParams.get('search')).toBe('preset')
    expect(req.searchParams.get('range')).toBe('7d')
    expect(req.searchParams.get('page')).toBe('2')
    expect(req.searchParams.get('tagged_only')).toBe('true')
    expect(req.searchParams.get('sort_order')).toBe('asc')
  })

  it('toggles virtual column visibility, persists it, and renders the dynamic column', async () => {
    renderPage()
    await screen.findByText('evil.dll modified')
    await userEvent.click(screen.getByRole('button', { name: /^columns$/i }))
    await userEvent.click(screen.getByRole('checkbox', { name: /file size/i }))
    await waitFor(() =>
      expect(lastRequest().searchParams.get('columns')).toBe('$.file_size'),
    )
    expect(
      JSON.parse(
        localStorage.getItem(`seance_timeline_columns.${CASE}`) ?? '[]',
      ),
    ).toContain('vc_file_size')
    await userEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(
      await screen.findByRole('columnheader', { name: /file size/i }),
    ).toBeInTheDocument()
    expect(await screen.findByText('1024')).toBeInTheDocument()
  })

  it('creates a custom virtual column and deletes a non-built-in one', async () => {
    const createdBodies: unknown[] = []
    const deletedIds: string[] = []
    server.use(
      http.post(
        `/api/v1/cases/${CASE}/virtual_columns`,
        async ({ request }) => {
          const body = await request.json()
          createdBodies.push(body)
          return HttpResponse.json(body)
        },
      ),
      http.delete(
        `/api/v1/cases/${CASE}/virtual_columns/:columnId`,
        ({ params }) => {
          deletedIds.push(params.columnId as string)
          return HttpResponse.json(null)
        },
      ),
    )
    renderPage()
    await screen.findByText('evil.dll modified')
    await userEvent.click(screen.getByRole('button', { name: /^columns$/i }))
    // Built-in columns cannot be deleted.
    expect(
      screen.queryByRole('button', { name: /delete file size/i }),
    ).not.toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(/column name/i), 'Evil Path')
    await userEvent.type(screen.getByLabelText(/json paths/i), '$.evil_path')
    await userEvent.click(screen.getByRole('button', { name: /add column/i }))
    await waitFor(() =>
      expect(createdBodies[0]).toMatchObject({
        name: 'Evil Path',
        sources: [{ path: '$.evil_path', artifact_types: [] }],
        built_in: false,
      }),
    )
    await userEvent.click(
      screen.getByRole('button', { name: /delete custom col/i }),
    )
    await waitFor(() => expect(deletedIds).toContain('vc_custom'))
  })

  it('edits the note on a tagged event', async () => {
    const updates: { eventId: string; note: string }[] = []
    server.use(
      http.put(
        `/api/v1/cases/${CASE}/timeline/tags/:eventId`,
        async ({ request, params }) => {
          const body = (await request.json()) as { note: string }
          updates.push({ eventId: params.eventId as string, note: body.note })
          return HttpResponse.json({
            id: 'tag-2',
            case_id: CASE,
            event_id: params.eventId,
            examiner: null,
            note: body.note,
            created_at: 0,
          })
        },
      ),
    )
    renderPage()
    await screen.findByText('Run key added')
    await userEvent.click(screen.getByRole('button', { name: /edit note/i }))
    const textarea = screen.getByLabelText('Note')
    expect(textarea).toHaveValue('suspicious persistence')
    await userEvent.clear(textarea)
    await userEvent.type(textarea, 'updated note')
    await userEvent.click(screen.getByRole('button', { name: /save note/i }))
    await waitFor(() =>
      expect(updates[0]).toEqual({ eventId: 'ev-2', note: 'updated note' }),
    )
  })

  it('renders the histogram with gap-filled buckets and a text summary', async () => {
    const { container } = renderPage()
    await screen.findByText('evil.dll modified')
    // 7 slots between the first and last bucket; only 3 have events.
    await waitFor(() =>
      expect(container.querySelectorAll('.tl-hist-bucket')).toHaveLength(7),
    )
    expect(container.querySelectorAll('.tl-hist-bar')).toHaveLength(3)
    expect(
      screen.getByText(
        '9 events between 2023-11-14 22:13:20 UTC and 2023-11-14 23:13:20 UTC',
      ),
    ).toBeInTheDocument()
    // Chart itself is decorative; the summary is the accessible surface.
    expect(container.querySelector('.tl-hist-plot')).toHaveAttribute(
      'aria-hidden',
      'true',
    )
    expect(lastHistogramRequest().searchParams.get('buckets')).toBe('120')
  })

  it('re-requests the histogram with the current filters', async () => {
    renderPage()
    await screen.findByText('evil.dll modified')
    await waitFor(() => expect(histogramRequests.length).toBeGreaterThan(0))
    expect(lastHistogramRequest().searchParams.get('search')).toBeNull()
    await userEvent.type(
      screen.getByPlaceholderText(/search timeline/i),
      'evil{Enter}',
    )
    await waitFor(() =>
      expect(lastHistogramRequest().searchParams.get('search')).toBe('evil'),
    )
    // Pagination never reaches the histogram endpoint.
    expect(lastHistogramRequest().searchParams.get('page')).toBeNull()
    expect(lastHistogramRequest().searchParams.get('page_size')).toBeNull()
  })

  it('brush-selects a range on the histogram, sets from/to, then clears it', async () => {
    const { container } = renderPage()
    await screen.findByText('evil.dll modified')
    await waitFor(() =>
      expect(container.querySelectorAll('.tl-hist-bucket')).toHaveLength(7),
    )
    const plot = container.querySelector('.tl-hist-plot') as HTMLElement
    mockPlotRect(plot, 400)
    // Domain is 1700000000 .. 1700004200 (last bucket start + bucket size).
    // Dragging 25% -> 75% of the width selects 1700001050 .. 1700003150.
    fireEvent.mouseDown(plot, { clientX: 100, button: 0 })
    fireEvent.mouseMove(window, { clientX: 300 })
    fireEvent.mouseUp(window, { clientX: 300 })
    await waitFor(() => {
      expect(lastRequest().searchParams.get('from')).toBe('1700001050')
      expect(lastRequest().searchParams.get('to')).toBe('1700003150')
    })
    // Histogram narrows to the brushed range too.
    await waitFor(() =>
      expect(lastHistogramRequest().searchParams.get('from')).toBe(
        '1700001050',
      ),
    )
    await userEvent.click(screen.getByRole('button', { name: /clear range/i }))
    await waitFor(() => {
      expect(lastRequest().searchParams.get('from')).toBeNull()
      expect(lastRequest().searchParams.get('to')).toBeNull()
    })
  })

  it('bulk tags selected events with a single refetch and toast', async () => {
    const created: string[] = []
    server.use(
      http.post(`/api/v1/cases/${CASE}/timeline/tags/:eventId`, ({ params }) => {
        created.push(params.eventId as string)
        return HttpResponse.json({
          id: `tag-${params.eventId}`,
          case_id: CASE,
          event_id: params.eventId,
          examiner: null,
          note: null,
          created_at: 0,
        })
      }),
    )
    renderPage()
    await screen.findByText('evil.dll modified')
    await userEvent.click(
      screen.getByRole('checkbox', { name: /select all events on page/i }),
    )
    expect(screen.getByText('2 selected')).toBeInTheDocument()
    const before = timelineRequests.length
    await userEvent.click(screen.getByRole('button', { name: 'Tag 2' }))
    // One tag call per selected event...
    await waitFor(() => expect([...created].sort()).toEqual(['ev-1', 'ev-2']))
    // ...a single toast, a single invalidation, and the selection cleared.
    expect(await screen.findByText('Tagged 2 events')).toBeInTheDocument()
    await waitFor(() => expect(timelineRequests.length).toBe(before + 1))
    expect(screen.queryByText('2 selected')).not.toBeInTheDocument()
  })

  it('bulk untags selected events via the delete endpoint', async () => {
    const deleted: string[] = []
    server.use(
      http.delete(
        `/api/v1/cases/${CASE}/timeline/tags/:eventId`,
        ({ params }) => {
          deleted.push(params.eventId as string)
          return HttpResponse.json({ success: true })
        },
      ),
    )
    renderPage()
    await screen.findByText('Run key added')
    await userEvent.click(
      screen.getByRole('checkbox', { name: /select event Run key added/i }),
    )
    await userEvent.click(screen.getByRole('button', { name: 'Untag 1' }))
    await waitFor(() => expect(deleted).toEqual(['ev-2']))
    expect(
      await screen.findByText('Removed tags from 1 event'),
    ).toBeInTheDocument()
  })

  it('shows a per-button pending state while an export is running', async () => {
    const origCreate = URL.createObjectURL
    const origRevoke = URL.revokeObjectURL
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()
    try {
      server.use(
        http.get(`/api/v1/cases/${CASE}/timeline/export/json`, async () => {
          await delay(100)
          return new HttpResponse('{}', { status: 200 })
        }),
      )
      renderPage()
      await screen.findByText('evil.dll modified')
      await userEvent.click(screen.getByRole('button', { name: /export json/i }))
      const pending = await screen.findByRole('button', { name: 'Exporting…' })
      expect(pending).toBeDisabled()
      // The other export buttons stay usable.
      expect(screen.getByRole('button', { name: /export csv/i })).toBeEnabled()
      await waitFor(() =>
        expect(
          screen.getByRole('button', { name: /export json/i }),
        ).toBeEnabled(),
      )
    } finally {
      URL.createObjectURL = origCreate
      URL.revokeObjectURL = origRevoke
    }
  })

  it('judges the CSV export by its verdict row and the PDF by nothing (UI-026)', async () => {
    const origCreate = URL.createObjectURL
    const origRevoke = URL.revokeObjectURL
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()
    // jsdom cannot stream to disk, so the helper asks before buffering an
    // unbounded export; the examiner says yes.
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    try {
      // A whole PDF has no verdict row. It used to be handed the CSV's
      // terminator and judged a fragment every time.
      server.use(
        http.get(`/api/v1/cases/${CASE}/timeline/export/pdf`, () =>
          new HttpResponse('%PDF-1.4\n%%EOF\n', { status: 200 }),
        ),
        // A CSV cut off after its preamble — which quotes the marker — is a
        // fragment and is reported as one.
        http.get(`/api/v1/cases/${CASE}/timeline/export/csv`, () =>
          new HttpResponse(
            `# export,timeline,,,\n# how_to_read,"ends with '### END OF EXPORT ### VERDICT:'",,,\n`,
            { status: 200 },
          ),
        ),
      )
      renderPage()
      await screen.findByText('evil.dll modified')

      await userEvent.click(screen.getByRole('button', { name: /export pdf/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /export pdf/i })).toBeEnabled(),
      )
      expect(screen.queryByText('Export PDF failed')).not.toBeInTheDocument()

      await userEvent.click(screen.getByRole('button', { name: /export csv/i }))
      expect(await screen.findByText('Export CSV failed')).toBeInTheDocument()
    } finally {
      confirm.mockRestore()
      URL.createObjectURL = origCreate
      URL.revokeObjectURL = origRevoke
    }
  })

  // §3.7. The SQLite export is a whole, committed database with no text
  // verdict row of its own — it states its completeness in its own
  // `export_meta` table, which a byte-stream terminator check cannot see.
  // Handing it the CSV/JSON terminator would judge every SQLite export a
  // fragment, exactly the UI-026 failure the PDF case above pins.
  it('does not judge the SQLite export by a text terminator it has none of', async () => {
    const origCreate = URL.createObjectURL
    const origRevoke = URL.revokeObjectURL
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()
    try {
      server.use(
        http.get(`/api/v1/cases/${CASE}/timeline/export/sqlite`, () =>
          new HttpResponse(new Uint8Array([0x53, 0x51, 0x4c, 0x69, 0x74, 0x65]), {
            status: 200,
            headers: { 'Content-Type': 'application/vnd.sqlite3' },
          }),
        ),
      )
      renderPage()
      await screen.findByText('evil.dll modified')

      await userEvent.click(screen.getByRole('button', { name: /export sqlite/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /export sqlite/i })).toBeEnabled(),
      )
      expect(screen.queryByText('Export SQLITE failed')).not.toBeInTheDocument()
    } finally {
      URL.createObjectURL = origCreate
      URL.revokeObjectURL = origRevoke
    }
  })

  // §5.12. The events body file is a text file that ends with a `#` verdict
  // comment, so a body that does not end with it is a fragment: it is refused
  // like a cut-short CSV, and a whole one is saved with the filters applied.
  it('exports the events as a body file and refuses a fragment of it', async () => {
    const origCreate = URL.createObjectURL
    const origRevoke = URL.revokeObjectURL
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()
    // jsdom cannot stream to disk, so the helper asks before buffering.
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const verdict =
      '# ### END OF EXPORT ### VERDICT: COMPLETE. This file holds all 1 of 1 timeline events that matched.\n'
    let whole = true
    let seenQuery = ''
    try {
      server.use(
        http.get(`/api/v1/cases/${CASE}/timeline/export/body_events`, ({ request }) => {
          seenQuery = new URL(request.url).search
          const row = '|[plugin.memory.processes] a.exe Process Created|0||0|0|0|0|0|0|1700000000\n'
          return new HttpResponse(whole ? row + verdict : row, {
            status: 200,
            headers: { 'Content-Type': 'text/plain' },
          })
        }),
      )
      renderPage()
      await screen.findByText('evil.dll modified')

      await userEvent.click(screen.getByRole('button', { name: /export body file/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /export body file/i })).toBeEnabled(),
      )
      expect(seenQuery).not.toBe('')
      expect(URL.createObjectURL).toHaveBeenCalledTimes(1)
      expect(screen.queryByText(/export body_events failed/i)).not.toBeInTheDocument()

      whole = false
      await userEvent.click(screen.getByRole('button', { name: /export body file/i }))
      expect(await screen.findByText(/export body_events failed/i)).toBeInTheDocument()
    } finally {
      confirm.mockRestore()
      URL.createObjectURL = origCreate
      URL.revokeObjectURL = origRevoke
    }
  })

  it('re-syncs the search input when the URL changes (back navigation)', async () => {
    // The URL is the source of truth for the applied search filter; the
    // input mirrors it via an effect in the toolbar. Without that sync the
    // input kept its first value forever and desynced on back/forward.
    renderPage(`/cases/${CASE}/timeline`, <GoBack />)
    await screen.findByText('evil.dll modified')
    const input = screen.getByPlaceholderText(/search timeline/i)
    await userEvent.type(input, 'malware{Enter}')
    await waitFor(() =>
      expect(lastRequest().searchParams.get('search')).toBe('malware'),
    )
    expect(input).toHaveValue('malware')
    await userEvent.click(screen.getByRole('button', { name: /go back/i }))
    await waitFor(() => expect(input).toHaveValue(''))
    await waitFor(() =>
      expect(lastRequest().searchParams.get('search')).toBeNull(),
    )
  })

  it('supports row keyboard navigation: Enter expands, arrows move focus', async () => {
    renderPage()
    const firstRow = (await screen.findByText('evil.dll modified')).closest(
      'tr',
    ) as HTMLTableRowElement
    firstRow.focus()
    fireEvent.keyDown(firstRow, { key: 'Enter' })
    expect(await screen.findByText(/"filename": "evil.dll"/)).toBeInTheDocument()
    // ArrowDown skips the expanded detail row and lands on the next event.
    fireEvent.keyDown(firstRow, { key: 'ArrowDown' })
    const secondRow = screen.getByText('Run key added').closest('tr')
    expect(document.activeElement).toBe(secondRow)
    fireEvent.keyDown(secondRow as HTMLTableRowElement, { key: 'ArrowUp' })
    expect(document.activeElement).toBe(firstRow)
  })

  it('passes current filters to export and toasts on failure', async () => {
    let exportUrl: URL | null = null
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline/export/csv`, ({ request }) => {
        exportUrl = new URL(request.url)
        return new HttpResponse(null, { status: 500 })
      }),
    )
    renderPage(`/cases/${CASE}/timeline?search=malware&range=7d`)
    await screen.findByText('evil.dll modified')
    await userEvent.click(screen.getByRole('button', { name: /export csv/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/export/i)
    expect(exportUrl).not.toBeNull()
    expect(exportUrl!.searchParams.get('search')).toBe('malware')
    expect(exportUrl!.searchParams.get('range')).toBe('7d')
  })

  it('marks FN-derived events with a $FN tag and leaves SI events unmarked', async () => {
    mockTimeline({ events: [...EVENTS, FN_EVENT] })
    renderPage()
    expect(await screen.findByText('Created (FN)')).toBeInTheDocument()
    // The FN event carries the pill; the two SI events do not.
    expect(screen.getAllByText('$FN')).toHaveLength(1)
  })

  it('flags a timestomp-suspected event with a warning badge and its reasons', async () => {
    mockTimeline({ events: [...EVENTS, STOMP_EVENT] })
    renderPage()
    const badge = await screen.findByLabelText(/timestomp suspected/i)
    expect(badge).toHaveTextContent('Timestomp')
    expect(badge).toHaveAttribute(
      'title',
      expect.stringContaining('SI Created precedes FN Created'),
    )
    // Unsuspected SI events carry no badge.
    expect(screen.getAllByLabelText(/timestomp suspected/i)).toHaveLength(1)
    // Expanding the row surfaces the full reason list.
    await userEvent.click(screen.getByText('FILE backdoor.exe (MFT: 99)'))
    expect(
      await screen.findByText('Sub-second precision mismatch on Created'),
    ).toBeInTheDocument()
    // Both SI and FN timestamps are compared in the detail row.
    expect(screen.getByText('$STANDARD_INFORMATION vs $FILE_NAME')).toBeInTheDocument()
  })

  it('filters the loaded page to FN events, then to timestomp-suspected events', async () => {
    mockTimeline({ events: [...EVENTS, FN_EVENT, STOMP_EVENT] })
    renderPage()
    await screen.findByText('evil.dll modified')
    const analysis = screen.getByLabelText(/analysis filter/i)

    await userEvent.selectOptions(analysis, 'fn')
    expect(screen.getByText('FILE secret.dll (MFT: 42)')).toBeInTheDocument()
    expect(screen.queryByText('evil.dll modified')).not.toBeInTheDocument()
    expect(
      screen.queryByText('FILE backdoor.exe (MFT: 99)'),
    ).not.toBeInTheDocument()
    expect(
      screen.getByText(/showing 1 of 4 events loaded on this page/i),
    ).toBeInTheDocument()

    await userEvent.selectOptions(analysis, 'timestomp')
    expect(screen.getByText('FILE backdoor.exe (MFT: 99)')).toBeInTheDocument()
    expect(
      screen.queryByText('FILE secret.dll (MFT: 42)'),
    ).not.toBeInTheDocument()
  })
})

/**
 * The case-wide time window (ROADMAP §1.1).
 *
 * `MiniTimeline` was a display: it neither followed the examiner across
 * screens nor filtered anything. Now it does both, and the layering is what
 * needs pinning — the window the examiner set on THIS page by brushing its own
 * chart must win over the one set elsewhere that followed them here, or the
 * chart on this page cannot change what the page shows.
 */
describe('TimelinePage — the case-wide time window', () => {
  const DAY = 86_400
  const START = 1_704_067_200

  function renderUnderWindow(
    window: { from: number; to: number } | null,
    initialEntry = `/cases/${CASE}/timeline`,
  ) {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    return render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <TimeWindowCtx.Provider value={{ window, setWindow: () => {} }}>
            <MemoryRouter initialEntries={[initialEntry]}>
              <Routes>
                <Route
                  path="/cases/:caseId/timeline"
                  element={<TimelinePage />}
                />
              </Routes>
            </MemoryRouter>
          </TimeWindowCtx.Provider>
        </ToastProvider>
      </QueryClientProvider>,
    )
  }

  it('narrows the query to the case-wide window and says it did', async () => {
    const asked: (string | null)[][] = []
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline`, ({ request }) => {
        const url = new URL(request.url)
        asked.push([url.searchParams.get('from'), url.searchParams.get('to')])
        return HttpResponse.json({
          events: EVENTS,
          pagination: PAGINATION,
        } satisfies PaginatedTimeline)
      }),
    )
    renderUnderWindow({ from: START, to: START + DAY })

    await waitFor(() =>
      expect(asked).toContainEqual([String(START), String(START + DAY)]),
    )
    // The page says which window narrowed it, because the rows look the same
    // either way once they are drawn.
    const note = await screen.findByTestId('tl-case-window')
    expect(note).toHaveTextContent(/Narrowed by the case-wide time window/)
    expect(note).toHaveTextContent(/inside that window, not across the case/)
  })

  /**
   * A brush on this page's own chart is the window the examiner set on the
   * screen in front of them. It wins, and the page stops claiming the
   * case-wide one narrowed it.
   */
  it('lets this page own brush win over the case-wide window', async () => {
    const asked: (string | null)[][] = []
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline`, ({ request }) => {
        const url = new URL(request.url)
        asked.push([url.searchParams.get('from'), url.searchParams.get('to')])
        return HttpResponse.json({
          events: EVENTS,
          pagination: PAGINATION,
        } satisfies PaginatedTimeline)
      }),
    )
    renderUnderWindow(
      { from: START, to: START + DAY },
      `/cases/${CASE}/timeline?from=${START + 5 * DAY}&to=${START + 6 * DAY}`,
    )

    await waitFor(() =>
      expect(asked).toContainEqual([
        String(START + 5 * DAY),
        String(START + 6 * DAY),
      ]),
    )
    expect(asked).not.toContainEqual([String(START), String(START + DAY)])
    expect(screen.queryByTestId('tl-case-window')).not.toBeInTheDocument()
  })

  it('asks for the whole case when no window is in force', async () => {
    const asked: (string | null)[][] = []
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline`, ({ request }) => {
        const url = new URL(request.url)
        asked.push([url.searchParams.get('from'), url.searchParams.get('to')])
        return HttpResponse.json({
          events: EVENTS,
          pagination: PAGINATION,
        } satisfies PaginatedTimeline)
      }),
    )
    renderUnderWindow(null)
    await waitFor(() => expect(asked.length).toBeGreaterThan(0))
    expect(asked[0]).toEqual([null, null])
    expect(screen.queryByTestId('tl-case-window')).not.toBeInTheDocument()
  })
})
