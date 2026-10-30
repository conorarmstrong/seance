import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { FrameSpy } from '../../test/frames'
import type { ParsedRecord } from './api'
import { WindowsTimelineViewer } from './WindowsTimelineViewer'

const CASE_ID = 'case-1'
const TYPE = 'WindowsTimelineActivity'

interface Captured {
  type: string | null
  page: string | null
  page_size: string | null
  q: string | null
  q_keys: string | null
  sort: string | null
  order: string | null
}

/**
 * Register a /records handler that applies `q` and `sort`/`order` the way the
 * endpoint does, over the whole set it was given.
 *
 * A mock that ignored them would let a viewer that had quietly gone back to
 * sorting and searching its loaded rows pass every test here — which is the
 * exact defect this viewer was moved off its hand-rolled table to remove.
 */
function mockRecords(
  records: ParsedRecord[],
  opts: { total?: number; captured?: Captured[] } = {},
) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const q = url.searchParams.get('q')
      const qKeys = (url.searchParams.get('q_keys') ?? '')
        .split(',')
        .filter(Boolean)
      const sort = url.searchParams.get('sort')
      const order = url.searchParams.get('order') ?? 'asc'
      opts.captured?.push({
        type: url.searchParams.get('type'),
        page: url.searchParams.get('page'),
        page_size: url.searchParams.get('page_size'),
        q,
        q_keys: url.searchParams.get('q_keys'),
        sort,
        order,
      })

      let out = records
      if (q) {
        out = out.filter((r) =>
          qKeys.some((k) =>
            String(r.metadata[k] ?? '')
              .toLowerCase()
              .includes(q.toLowerCase()),
          ),
        )
      }
      const matching = out.length
      if (sort) {
        const dir = order === 'desc' ? -1 : 1
        out = [...out].sort((a, b) => {
          const va = a.metadata[sort]
          const vb = b.metadata[sort]
          if (va == null && vb == null) return a.id < b.id ? -1 : 1
          if (va == null) return -1 * dir
          if (vb == null) return 1 * dir
          if (typeof va === 'number' && typeof vb === 'number') {
            return (va - vb) * dir
          }
          return String(va).localeCompare(String(vb)) * dir
        })
      }
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 200)
      const start = (page - 1) * pageSize
      return HttpResponse.json({
        records: out.slice(start, start + pageSize),
        total: opts.total ?? matching,
        type_total: opts.total ?? records.length,
        unfilterable_metadata: q ? 0 : null,
        filtered: !!q,
        q,
        q_keys: qKeys,
        q_match: 'ascii_case_insensitive_substring',
        sort,
        order,
        order_by: sort ? 'metadata_key' : 'ingest',
        page,
        page_size: pageSize,
        type: url.searchParams.get('type'),
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
        <WindowsTimelineViewer records={[]} caseId={CASE_ID} type={TYPE} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const rec = (id: string, metadata: Record<string, unknown>): ParsedRecord => ({
  id,
  parent_id: `a-${id}`,
  artifact_type: 'ParsedRecord',
  metadata: { type: TYPE, ...metadata },
})

const FOCUS = rec('r-focus', {
  source_table: 'Activity',
  activity_id: 'guid-focus',
  executable: 'C:\\Program Files\\Microsoft Office\\WINWORD.EXE',
  app_display_name: 'Microsoft Word',
  activity_type: 6,
  activity_type_label: 'App in focus',
  display_text: 'pshashes.txt',
  description: 'C:\\Users\\bob\\Desktop',
  content_uri: 'file:///C:/Users/bob/Desktop/pshashes.txt',
  activation_uri: 'file:///C:/Users/bob/Desktop/pshashes.txt',
  start_time: 1546300800,
  end_time: 1546300845,
  duration_seconds: 45,
  active_duration_seconds: 40,
  last_modified_time: 1546300900,
  is_local_only: 1,
  device_platform: 'Windows',
  user_timezone: 'America/New_York',
  packages: [
    { platform: 'windows_win32', name: 'C:\\Program Files\\Microsoft Office\\WINWORD.EXE' },
  ],
  name: 'pshashes.txt',
})

const OPEN = rec('r-open', {
  source_table: 'Activity',
  activity_id: 'guid-open',
  executable: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
  app_display_name: 'Google Chrome',
  activity_type: 5,
  activity_type_label: 'Open app / file / webpage',
  display_text: 'GitHub',
  content_uri: 'https://github.com/EricZimmerman/WxTCmd',
  start_time: 1546300000,
  duration_seconds: 180,
  device_platform: 'Windows',
  name: 'GitHub',
})

const CLIP = rec('r-clip', {
  source_table: 'Activity',
  activity_id: 'guid-clip',
  executable: 'C:\\Windows\\explorer.exe',
  app_display_name: 'Windows Explorer',
  activity_type: 10,
  activity_type_label: 'Clipboard',
  display_text: '(copied text)',
  has_clipboard: true,
  clipboard_text: 'hunter2',
  clipboard_format: 'Text',
  start_time: 1546301000,
  created_in_cloud: 1546301500,
  is_local_only: 0,
  device_platform: 'Windows',
  platform_device_id: 'device-abc',
  name: '(copied text)',
})

describe('WindowsTimelineViewer', () => {
  it('renders every activity as a table row with stat tiles and artifact links', async () => {
    mockRecords([FOCUS, OPEN, CLIP])
    renderViewer()

    const rows = await screen.findAllByTestId('an-wt-row')
    expect(rows).toHaveLength(3)

    // Stat tiles reflect the activity-type buckets.
    expect(within(screen.getByRole('button', { name: /Focus/ })).getByText('1')).toBeInTheDocument()
    expect(within(screen.getByRole('button', { name: /Open/ })).getByText('1')).toBeInTheDocument()
    expect(
      within(screen.getByRole('button', { name: /Clipboard/ })).getByText('1'),
    ).toBeInTheDocument()

    // The activity-type badge and resolved app render in the table.
    expect(screen.getByText('App in focus')).toBeInTheDocument()

    // Each row links to its artifact detail page.
    const links = screen.getAllByRole('link', { name: 'open' })
    expect(links.map((l) => l.getAttribute('href'))).toContain(
      `/cases/${CASE_ID}/artifacts/r-focus`,
    )
  })

  it('filters to clipboard activities when the Clipboard tile is clicked', async () => {
    mockRecords([FOCUS, OPEN, CLIP])
    renderViewer()

    expect(await screen.findAllByTestId('an-wt-row')).toHaveLength(3)
    await userEvent.click(screen.getByRole('button', { name: /Clipboard/ }))

    const rows = screen.getAllByTestId('an-wt-row')
    expect(rows).toHaveLength(1)
    expect(within(rows[0]).getByText('Windows Explorer')).toBeInTheDocument()
    expect(screen.queryByText('Microsoft Word')).not.toBeInTheDocument()
  })

  it('opens the detail panel and reveals decoded clipboard text on demand', async () => {
    mockRecords([FOCUS, OPEN, CLIP])
    renderViewer()

    const rows = await screen.findAllByTestId('an-wt-row')
    // Default sort is Start descending: the clipboard row (latest start) is first.
    expect(screen.queryByTestId('an-wt-detail')).not.toBeInTheDocument()
    await userEvent.click(rows[0])

    const detail = await screen.findByTestId('an-wt-detail')
    // Decoded payload fields surface in the panel (app appears in the header and
    // the What section, so there is at least one).
    expect(within(detail).getAllByText('Windows Explorer').length).toBeGreaterThan(0)
    expect(within(detail).getByText('(copied text)')).toBeInTheDocument()

    // Clipboard text is privacy-gated behind an explicit reveal.
    expect(within(detail).queryByText('hunter2')).not.toBeInTheDocument()
    await userEvent.click(
      within(detail).getByRole('button', { name: /Reveal clipboard text/i }),
    )
    expect(within(detail).getByText('hunter2')).toBeInTheDocument()
  })

  it('filters rows by the free-text search box', async () => {
    mockRecords([FOCUS, OPEN, CLIP])
    renderViewer()

    await screen.findAllByTestId('an-wt-row')
    await userEvent.type(
      screen.getByRole('textbox', { name: 'Filter Windows Timeline activity' }),
      'pshashes',
    )

    await waitFor(() =>
      expect(screen.getAllByTestId('an-wt-row')).toHaveLength(1),
    )
    expect(screen.getByText('App in focus')).toBeInTheDocument()
  })

  it('paginates with a Load more button when more records remain', async () => {
    const captured: Captured[] = []
    mockRecords([FOCUS], { total: 400, captured })
    renderViewer()

    await screen.findAllByTestId('an-wt-row')
    expect(captured[0]).toMatchObject({ type: TYPE, page: '1', page_size: '200' })

    await userEvent.click(screen.getByRole('button', { name: /load more/i }))
    await waitFor(() =>
      expect(captured.at(-1)).toMatchObject({ type: TYPE, page: '2' }),
    )
  })

  it('shows an empty state when there are no activities', async () => {
    mockRecords([], { total: 0 })
    renderViewer()
    expect(
      await screen.findByText('No Windows Timeline activity'),
    ).toBeInTheDocument()
  })

  it('shows an error state when the request fails', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'timeline unavailable' } },
          { status: 500 },
        ),
      ),
    )
    renderViewer()
    expect(await screen.findByText(/timeline unavailable/)).toBeInTheDocument()
  })
})

/** A second clipboard capture, newer than CLIP so it sorts above it. */
const CLIP2 = rec('r-clip2', {
  source_table: 'Activity',
  activity_id: 'guid-clip2',
  executable: 'C:\\Windows\\explorer.exe',
  app_display_name: 'Windows Explorer',
  activity_type: 10,
  activity_type_label: 'Clipboard',
  display_text: '(copied text 2)',
  has_clipboard: true,
  clipboard_text: 'second-secret',
  clipboard_format: 'Text',
  start_time: 1546302000,
  device_platform: 'Windows',
  name: '(copied text 2)',
})

describe('WindowsTimelineViewer clipboard reveal scoping', () => {
  it('never paints another activity clipboard text under the first reveal', async () => {
    // "Reveal clipboard text" is consent to see ONE capture. Clearing it in a
    // `useEffect` keyed on the record leaves it set for the whole render AND
    // commit in which the panel is already showing the next activity, so that
    // activity's clipboard is painted unmasked — disclosed by a click the
    // examiner made against a different record. `render`/`rerender` and
    // `userEvent` flush passive effects before returning, so only a DOM
    // observer sees the frame at all.
    mockRecords([FOCUS, OPEN, CLIP, CLIP2])

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const frames: (string | null)[] = []
    const snapshot = () =>
      document.querySelector('.an-wt-clip-text')?.textContent ?? null
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/${TYPE}`]}>
          <WindowsTimelineViewer records={[]} caseId={CASE_ID} type={TYPE} />
          <FrameSpy capture={snapshot} frames={frames} />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    const rows = await screen.findAllByTestId('an-wt-row')
    // Sorted by start descending: CLIP2, CLIP, FOCUS, OPEN.
    await userEvent.click(rows[1])
    const detail = await screen.findByTestId('an-wt-detail')
    await userEvent.click(
      within(detail).getByRole('button', { name: /Reveal clipboard text/i }),
    )
    expect(within(detail).getByText('hunter2')).toBeInTheDocument()

    frames.length = 0
    await userEvent.click(screen.getAllByTestId('an-wt-row')[0])

    // The harness must have seen the switch at all, or the loop below proves
    // nothing.
    expect(frames.length).toBeGreaterThan(0)
    for (const frame of frames) {
      expect(frame).not.toBe('second-secret')
    }
    // And it ends masked, behind its own reveal.
    expect(screen.queryByText('second-secret')).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Reveal clipboard text/i }),
    ).toBeInTheDocument()
  })
})

describe('WindowsTimelineViewer incompleteness (B4-024)', () => {
  it('reports the standard pair stamped on the activities it loaded', async () => {
    // This viewer is `aggregate: true` and loads its own records, so the page
    // shell's banner (over its own page-1 fetch) never sees them. Without a
    // banner here, a capped or short ActivitiesCache.db presented as a complete
    // user-activity history.
    mockRecords([
      rec('r-1', {
        source_table: 'Activity',
        activity_id: 'guid-1',
        app_display_name: 'Notepad',
        activity_type: 5,
        start_time: 1700000000,
        content_incomplete: true,
        content_incomplete_reason: 'cap_reached',
      }),
    ])
    renderViewer()

    expect(
      await screen.findByText(/declares itself\s+incomplete/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/a parser safety cap stopped the read/),
    ).toBeInTheDocument()
  })

  it('shows no banner when nothing is stamped', async () => {
    mockRecords([
      rec('r-2', {
        source_table: 'Activity',
        activity_id: 'guid-2',
        app_display_name: 'Notepad',
        activity_type: 5,
        start_time: 1700000000,
      }),
    ])
    renderViewer()
    // `findAllByText`: the app name appears in the activity row AND in the
    // viewer's "top apps" bar chart, so an exact single-match query throws.
    expect((await screen.findAllByText('Notepad')).length).toBeGreaterThan(0)
    expect(screen.queryByText(/declares itself/)).not.toBeInTheDocument()
  })
})

describe('WindowsTimelineViewer measured scope', () => {
  it('marks a clipboard capture cut at the storage cap, before and after the reveal', async () => {
    // The parser cuts the captured text at a cap and says so on
    // `clipboard_text_truncated`. Nothing read that key, so a fragment of what
    // was copied reached the examiner as the copy — and an absent word in a
    // clipboard capture is read as evidence it was never copied.
    mockRecords([
      rec('r-clip-cut', {
        source_table: 'Activity',
        activity_id: 'guid-clip-cut',
        app_display_name: 'Windows Explorer',
        activity_type: 10,
        activity_type_label: 'Clipboard',
        display_text: '(copied text)',
        has_clipboard: true,
        clipboard_text: 'begin-of-a-long-secret',
        clipboard_text_truncated: true,
        clipboard_bytes: 40960,
        clipboard_format: 'Text',
        start_time: 1546301000,
      }),
    ])
    renderViewer()

    const rows = await screen.findAllByTestId('an-wt-row')
    await userEvent.click(rows[0])
    const detail = await screen.findByTestId('an-wt-detail')

    // Visible without revealing: an examiner who never clicks Reveal must still
    // be told the capture is a fragment.
    const badge = within(detail).getByText('truncated')
    expect(badge.getAttribute('title')).toContain(
      'not evidence it was not copied',
    )
    // The scale of what was cut, from the parser's own byte count.
    expect(badge.getAttribute('title')).toContain('40,960 bytes')

    // And spelled out beside the text once revealed, where a screenshot or a
    // printout carries it and a hover does not.
    await userEvent.click(
      within(detail).getByRole('button', { name: /Reveal clipboard text/i }),
    )
    expect(within(detail).getByText('begin-of-a-long-secret')).toBeInTheDocument()
    expect(
      within(detail).getByText(/This clipboard capture covers only part/),
    ).toBeInTheDocument()
  })

  it('does not mark a clipboard capture the parser recorded whole', async () => {
    mockRecords([
      rec('r-clip-whole', {
        source_table: 'Activity',
        activity_id: 'guid-clip-whole',
        app_display_name: 'Windows Explorer',
        activity_type: 10,
        activity_type_label: 'Clipboard',
        display_text: '(copied text)',
        has_clipboard: true,
        clipboard_text: 'hunter2',
        clipboard_text_truncated: false,
        clipboard_bytes: 7,
        clipboard_format: 'Text',
        start_time: 1546301000,
      }),
    ])
    renderViewer()

    const rows = await screen.findAllByTestId('an-wt-row')
    await userEvent.click(rows[0])
    const detail = await screen.findByTestId('an-wt-detail')
    // A qualifier on every capture is one an examiner learns to skip.
    expect(within(detail).queryByText('truncated')).not.toBeInTheDocument()
    expect(
      within(detail).queryByText(/scope not stated/),
    ).not.toBeInTheDocument()
  })

  it('marks a raw AppId blob cut at the cap', async () => {
    mockRecords([
      rec('r-appid', {
        source_table: 'Activity',
        activity_id: 'guid-appid',
        app_display_name: 'Microsoft Word',
        activity_type: 5,
        start_time: 1546300800,
        packages: [{ platform: 'windows_win32', name: 'WINWORD.EXE' }],
        app_id_raw: '[{"platform":"windows_win32","application":"WINWORD.EX',
        app_id_raw_truncated: true,
      }),
    ])
    renderViewer()

    const rows = await screen.findAllByTestId('an-wt-row')
    await userEvent.click(rows[0])
    const detail = await screen.findByTestId('an-wt-detail')

    expect(
      within(detail).getByText('truncated').getAttribute('title'),
    ).toContain('not the full set of applications')
    await userEvent.click(
      within(detail).getByRole('button', { name: /Show raw AppId/i }),
    )
    expect(
      within(detail).getByText(/This raw AppId covers only part/),
    ).toBeInTheDocument()
  })
})

/**
 * This viewer used to hand-roll its table: a live `<tr>` per activity, a
 * `tabIndex=0` on each, a browser-side filter and a browser-side sort. On an
 * ActivitiesCache.db with a hundred thousand activities that is an unbounded
 * DOM, an unbounded run of tab stops, and — worse than either — a "Start ▼"
 * heading over the newest of the two hundred rows that happened to be loaded,
 * presented as the newest activity on the device.
 */
describe('WindowsTimelineViewer sorts and searches the whole set', () => {
  /** The record rows of the shared table, without its spacer rows. */
  const tableRows = () =>
    Array.from(document.querySelectorAll<HTMLElement>('tbody tr[data-index]'))

  it('asks the server for the ordering, not the loaded rows', async () => {
    const captured: Captured[] = []
    mockRecords([FOCUS, OPEN, CLIP], { captured })
    renderViewer()

    await screen.findAllByTestId('an-wt-row')
    // Newest activity first is the default, and it is the server's ordering
    // over every activity rather than a re-sort of one page.
    expect(captured[0]).toMatchObject({ sort: 'start_time', order: 'desc' })

    await userEvent.click(screen.getByRole('button', { name: /^Application/ }))
    await waitFor(() =>
      expect(captured.at(-1)).toMatchObject({
        sort: 'app_display_name',
        order: 'asc',
      }),
    )
    // Clicking the active column reverses it, and that too is a new question
    // for the server.
    await userEvent.click(screen.getByRole('button', { name: /^Application/ }))
    await waitFor(() =>
      expect(captured.at(-1)).toMatchObject({
        sort: 'app_display_name',
        order: 'desc',
      }),
    )
  })

  it('names the metadata key a sort header orders on', async () => {
    // The Application cell falls back to the executable's basename when there
    // is no display name, so the heading does not describe the ordering. The
    // control has to say which key the server put the type in order on.
    mockRecords([FOCUS, OPEN], {})
    renderViewer()

    await screen.findAllByTestId('an-wt-row')
    expect(
      screen.getByRole('button', { name: /^Application/ }).getAttribute('title'),
    ).toContain('app_display_name')
  })

  it('sends the filter term to the server', async () => {
    const captured: Captured[] = []
    mockRecords([FOCUS, OPEN, CLIP], { captured })
    renderViewer()

    await screen.findAllByTestId('an-wt-row')
    await userEvent.type(
      screen.getByRole('textbox', { name: 'Filter Windows Timeline activity' }),
      'pshashes',
    )
    await waitFor(() => expect(captured.at(-1)?.q).toBe('pshashes'))
    expect(captured.at(-1)?.q_keys).toContain('clipboard_text')
    expect(captured.at(-1)?.page).toBe('1')
  })

  it('does not call a term that matched nothing a device with the feature off', async () => {
    // "The Windows Timeline feature was disabled on this device" is a finding
    // about the evidence. Printing it under a filter that simply matched
    // nothing turns an empty result into a false absence.
    mockRecords([FOCUS, OPEN, CLIP], {})
    renderViewer()

    await screen.findAllByTestId('an-wt-row')
    await userEvent.type(
      screen.getByRole('textbox', { name: 'Filter Windows Timeline activity' }),
      'nothing-matches-this',
    )
    expect(
      await screen.findByText(/No activities in this case match/),
    ).toBeInTheDocument()
    expect(screen.queryAllByTestId('an-wt-row')).toHaveLength(0)
    expect(screen.queryByText(/feature was disabled/)).not.toBeInTheDocument()
  })

  it('is one tab stop and numbers its rows against the whole set', async () => {
    mockRecords([FOCUS, OPEN, CLIP], {})
    renderViewer()

    await screen.findAllByTestId('an-wt-row')
    expect(
      tableRows().filter((r) => r.getAttribute('tabindex') === '0'),
    ).toHaveLength(1)
    expect(tableRows()[2]).toHaveAttribute('aria-rowindex', '4')
    const stops = Array.from(
      document.querySelectorAll<HTMLElement>(
        'tbody tr a, tbody tr button, tbody tr input',
      ),
    ).filter((el) => el.getAttribute('tabindex') !== '-1')
    expect(stops).toHaveLength(0)
  })

  it('opens the detail panel from the keyboard as well as the mouse', async () => {
    mockRecords([FOCUS, OPEN, CLIP], {})
    renderViewer()

    await screen.findAllByTestId('an-wt-row')
    tableRows()[0].focus()
    await userEvent.keyboard('{ArrowDown}')
    // A detail panel a keyboard cannot reach is a detail panel half the
    // examiners on this team cannot use.
    expect(await screen.findByTestId('an-wt-detail')).toBeInTheDocument()
  })

  it('says the tiles and bars rank the loaded rows, not the device', async () => {
    mockRecords([FOCUS, OPEN, CLIP], { total: 480_000 })
    renderViewer()

    const note = await screen.findByTestId('rv-charts-scope')
    expect(note.textContent).toMatch(/480,000/)
  })
})
