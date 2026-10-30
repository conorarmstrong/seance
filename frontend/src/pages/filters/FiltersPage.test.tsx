import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import {
  MemoryRouter,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import { FrameSpy } from '../../test/frames'
import { FiltersPage } from './FiltersPage'

const CASE = 'c1'

let created: unknown = null

function mockApi() {
  created = null
  const filters = [
    {
      id: 'f-pre',
      case_id: CASE,
      name: 'All Executables',
      description: 'PE files',
      filter: { type: 'simple', field: 'extension', operator: 'in', value: ['exe', 'dll'] },
      is_predefined: true,
      created_at: 0,
      updated_at: 0,
    },
    {
      id: 'f-usr',
      case_id: CASE,
      name: 'Deleted files',
      description: '',
      filter: { type: 'simple', field: 'deleted', operator: 'eq', value: true },
      is_predefined: false,
      created_at: 0,
      updated_at: 0,
    },
  ]
  server.use(
    http.get(`/api/v1/cases/${CASE}/filters`, () => HttpResponse.json(filters)),
    http.post(`/api/v1/cases/${CASE}/filters`, async ({ request }) => {
      created = await request.json()
      return HttpResponse.json({ id: 'f-new', ...(created as object) })
    }),
    http.get(`/api/v1/cases/${CASE}/filters/f-usr/apply`, () =>
      HttpResponse.json({
        results: [
          {
            id: 'a1',
            parent_id: null,
            artifact_type: 'FileEntry',
            metadata: { name: 'secret.docx' },
          },
        ],
        total: 1,
        scan_complete: true,
      }),
    ),
  )
}

/** Switches the `:caseId` route param in place, without remounting the page. */
function CaseSwitcher() {
  const navigate = useNavigate()
  return (
    <button type="button" onClick={() => navigate('/cases/c2/filters')}>
      Go to c2
    </button>
  )
}

function renderPage(frames: string[] = []) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={[`/cases/${CASE}/filters`]}>
          <Routes>
            <Route
              path="/cases/:caseId/filters"
              element={
                <>
                  <FiltersPage />
                  <CaseSwitcher />
                  <FrameSpy
                    capture={() => document.body.textContent ?? ''}
                    frames={frames}
                  />
                </>
              }
            />
            <Route
              path="/cases/:caseId/artifacts/:id"
              element={<div>artifact</div>}
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
  mockApi()
})

describe('FiltersPage', () => {
  it('lists saved and predefined filters with their conditions', async () => {
    renderPage()
    expect(await screen.findByText('All Executables')).toBeInTheDocument()
    expect(screen.getByText('extension in (comma list) [exe, dll]')).toBeInTheDocument()
    // Predefined filters cannot be deleted; user filters can.
    expect(screen.queryByLabelText('Delete All Executables')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Delete Deleted files')).toBeInTheDocument()
  })

  it('applies a filter and shows matching artifacts', async () => {
    renderPage()
    await screen.findByText('Deleted files')
    const row = screen.getByText('Deleted files').closest('li')!
    await userEvent.click(within(row).getByRole('button', { name: /Apply/ }))
    expect(await screen.findByText('secret.docx')).toBeInTheDocument()
    expect(screen.getByText(/1 matches/)).toBeInTheDocument()
    // The scan covered the case, so nothing qualifies the count.
    expect(screen.queryByTestId('flt-scan-incomplete')).not.toBeInTheDocument()
    expect(screen.queryByTestId('flt-scan-unknown')).not.toBeInTheDocument()
  })

  it('says the match count is a floor when the scan hit its ceiling (B6-008)', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/filters/f-usr/apply`, () =>
        HttpResponse.json({
          results: [
            {
              id: 'a1',
              parent_id: null,
              artifact_type: 'FileEntry',
              metadata: { name: 'secret.docx' },
            },
          ],
          total: 500_000,
          scan_complete: false,
        }),
      ),
    )
    renderPage()
    await screen.findByText('Deleted files')
    const row = screen.getByText('Deleted files').closest('li')!
    await userEvent.click(within(row).getByRole('button', { name: /Apply/ }))

    const note = await screen.findByTestId('flt-scan-incomplete')
    expect((note.textContent ?? '').replace(/\s+/g, ' ')).toContain(
      'not the number that exist',
    )
  })

  // B8-028. A scan that ran to the end and could not read some rows is short in
  // a way paging cannot repair, and `scan_complete` is TRUE for it. The server
  // discloses the count; the client used to discard it, so such a result
  // rendered as an unqualified match count. "0 matches" from a scan that
  // skipped rows is an absence conclusion nobody established.
  it('says when a completed scan could not read some of what it reached', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/filters/f-usr/apply`, () =>
        HttpResponse.json({
          results: [],
          total: 0,
          scan_complete: true,
          undecodable: 7,
          inventory_incomplete: true,
          inventory_incomplete_reason: 'undecodable_rows',
        }),
      ),
    )
    renderPage()
    await screen.findByText('Deleted files')
    const row = screen.getByText('Deleted files').closest('li')!
    await userEvent.click(within(row).getByRole('button', { name: /Apply/ }))

    const note = await screen.findByTestId('flt-scan-undecodable')
    expect((note.textContent ?? '').replace(/\s+/g, ' ')).toContain(
      '7 artifacts could not be read',
    )
    // The completed-scan path must not also fire: this is a different shortfall.
    expect(screen.queryByTestId('flt-scan-incomplete')).not.toBeInTheDocument()
  })

  it('claims no shortfall when a complete scan read everything it reached', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/filters/f-usr/apply`, () =>
        HttpResponse.json({
          results: [],
          total: 0,
          scan_complete: true,
          undecodable: 0,
        }),
      ),
    )
    renderPage()
    await screen.findByText('Deleted files')
    const row = screen.getByText('Deleted files').closest('li')!
    await userEvent.click(within(row).getByRole('button', { name: /Apply/ }))
    await screen.findByText(/0 match/i)
    expect(screen.queryByTestId('flt-scan-undecodable')).not.toBeInTheDocument()
  })

  it('does not read a missing scan_complete as a complete scan (B6-008)', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/filters/f-usr/apply`, () =>
        HttpResponse.json({ results: [], total: 0 }),
      ),
    )
    renderPage()
    await screen.findByText('Deleted files')
    const row = screen.getByText('Deleted files').closest('li')!
    await userEvent.click(within(row).getByRole('button', { name: /Apply/ }))

    expect(await screen.findByTestId('flt-scan-unknown')).toBeInTheDocument()
  })

  it('defers revoking the export object URL (BUG-203)', async () => {
    // Revoking synchronously after click() can abort the download before the
    // browser has read the blob, producing an empty/truncated filter JSON.
    const createObjectURL = vi.fn(() => 'blob:filter')
    const revokeObjectURL = vi.fn()
    const origCreate = URL.createObjectURL
    const origRevoke = URL.revokeObjectURL
    URL.createObjectURL =
      createObjectURL as unknown as typeof URL.createObjectURL
    URL.revokeObjectURL = revokeObjectURL
    renderPage()
    await screen.findByText('Deleted files')

    vi.useFakeTimers()
    try {
      fireEvent.click(screen.getByLabelText('Export Deleted files'))
      expect(createObjectURL).toHaveBeenCalledTimes(1)
      // Still live immediately after the click…
      expect(revokeObjectURL).not.toHaveBeenCalled()
      // …and released once the browser has had time to read it.
      vi.advanceTimersByTime(60_000)
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:filter')
    } finally {
      vi.useRealTimers()
      URL.createObjectURL = origCreate
      URL.revokeObjectURL = origRevoke
    }
  })

  it('creates a new simple filter from the form', async () => {
    renderPage()
    await screen.findByText('All Executables')
    await userEvent.type(screen.getByLabelText('Filter name'), 'Big files')
    await userEvent.clear(screen.getByLabelText('Field 1'))
    await userEvent.type(screen.getByLabelText('Field 1'), 'size')
    await userEvent.selectOptions(screen.getByLabelText('Operator 1'), 'gt')
    await userEvent.type(screen.getByLabelText('Value 1'), '1000000')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(created).not.toBeNull())
    expect(created).toMatchObject({
      name: 'Big files',
      filter: { type: 'simple', field: 'size', operator: 'gt', value: 1000000 },
    })
  })

  it('drops the applied result set when the case changes (BUG-260)', async () => {
    // This page stays mounted across a `:caseId` route change, so an applied
    // result set from case A would keep rendering under case B — a match count
    // and artifact links that belong to different evidence.
    server.use(
      http.get('/api/v1/cases/c2/filters', () => HttpResponse.json([])),
    )
    renderPage()
    await screen.findByText('Deleted files')
    const row = screen.getByText('Deleted files').closest('li')!
    await userEvent.click(within(row).getByRole('button', { name: /Apply/ }))
    expect(await screen.findByText('secret.docx')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    await waitFor(() =>
      expect(screen.queryByText('secret.docx')).not.toBeInTheDocument(),
    )
    expect(screen.queryByText(/1 matches/)).not.toBeInTheDocument()
    expect(screen.getByText('No filter applied')).toBeInTheDocument()
  })

  it('never paints case A results under case B, not even for one frame (B2-147)', async () => {
    // Dropping the applied result set in a `useEffect` is one commit too late:
    // the frame in which the route already reads case B still paints "1
    // matches" and a row linking to /cases/c2/artifacts/a1 — case A's artifact
    // id under case B. `rerender`/`click` flush passive effects before
    // returning, so the assertion above ("drops the applied result set") passes
    // against that broken version too; only a layout-effect snapshot sees it.
    server.use(
      http.get('/api/v1/cases/c2/filters', () => HttpResponse.json([])),
    )
    const frames: string[] = []
    renderPage(frames)
    await screen.findByText('Deleted files')
    const row = screen.getByText('Deleted files').closest('li')!
    await userEvent.click(within(row).getByRole('button', { name: /Apply/ }))
    expect(await screen.findByText('secret.docx')).toBeInTheDocument()

    frames.length = 0
    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    await waitFor(() => expect(frames.length).toBeGreaterThan(0))
    for (const frame of frames) {
      expect(frame).not.toContain('secret.docx')
      expect(frame).not.toContain('1 matches')
    }
  })

  it('reports a create against the case it was sent to, not the one now on screen (B2-119)', async () => {
    // `onSuccess` runs in the latest render's closure. Reading `caseId` there
    // confirmed "Filter saved" over case B's list while the filter was written
    // to case A, and refreshed case B's list while case A's — the one that
    // actually changed — kept showing stale rows.
    let releaseCreate: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      releaseCreate = resolve
    })
    let c2Lists = 0
    server.use(
      http.post(`/api/v1/cases/${CASE}/filters`, async ({ request }) => {
        created = await request.json()
        await gate
        return HttpResponse.json({ id: 'f-new', ...(created as object) })
      }),
      http.get('/api/v1/cases/c2/filters', () => {
        c2Lists += 1
        return HttpResponse.json([])
      }),
    )
    renderPage()
    await screen.findByText('All Executables')

    await userEvent.type(screen.getByLabelText('Filter name'), 'Big files')
    await userEvent.type(screen.getByLabelText('Value 1'), 'exe')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(created).not.toBeNull())

    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))
    await waitFor(() => expect(c2Lists).toBe(1))
    await waitFor(() =>
      expect(screen.getByText('No filters')).toBeInTheDocument(),
    )

    releaseCreate()
    // Let the create settle and its onSuccess run under case B's chrome.
    await new Promise((resolve) => setTimeout(resolve, 50))

    // Case B's examiner is not told a filter was saved here, and case B's list
    // is not refetched: nothing about case B changed.
    expect(screen.queryByText('Filter saved')).toBeNull()
    expect(c2Lists).toBe(1)
  })
})

/**
 * The compound builder.
 *
 * `seance_core::filter` has always evaluated arbitrary AND/OR/NOT trees and the
 * client model has always described them, but the form built exactly one
 * `field op value` row — so the bread-and-butter triage question, "jpegs over a
 * megabyte that were deleted", could not be asked anywhere in the product
 * except by hand-writing JSON and importing it.
 *
 * Two things are being pinned here, and the second matters more than the first.
 * One: a compound condition can be built. Two: nothing the builder can produce
 * is ambiguous or accidentally wider than what is on screen — every row joins
 * with the SAME connective (so there is no precedence to misread), a NOT sits
 * on the row it inverts, and the states that would silently redefine the
 * population are refused with the reason said out loud rather than repaired.
 */
describe('FiltersPage compound builder', () => {
  beforeEach(mockApi)

  /** Fill row `n` (1-based) of the builder. */
  async function fillRow(
    n: number,
    field: string,
    operator: string,
    value?: string,
  ) {
    await userEvent.clear(screen.getByLabelText(`Field ${n}`))
    await userEvent.type(screen.getByLabelText(`Field ${n}`), field)
    await userEvent.selectOptions(screen.getByLabelText(`Operator ${n}`), operator)
    if (value !== undefined) {
      await userEvent.clear(screen.getByLabelText(`Value ${n}`))
      if (value !== '') {
        await userEvent.type(screen.getByLabelText(`Value ${n}`), value)
      }
    }
  }

  it('builds the three-condition triage query the single-row form could not', async () => {
    renderPage()
    await screen.findByText('All Executables')
    await userEvent.type(screen.getByLabelText('Filter name'), 'Deleted jpegs over 1MB')

    await fillRow(1, 'extension', 'eq', 'jpg')
    await userEvent.click(screen.getByRole('button', { name: /Add condition/i }))
    await fillRow(2, 'size', 'gt', '1000000')
    await userEvent.click(screen.getByRole('button', { name: /Add condition/i }))
    await fillRow(3, 'deleted', 'eq', 'true')

    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(created).not.toBeNull())
    expect(created).toMatchObject({
      name: 'Deleted jpegs over 1MB',
      filter: {
        type: 'compound',
        logic: 'and',
        conditions: [
          { type: 'simple', field: 'extension', operator: 'eq', value: 'jpg' },
          { type: 'simple', field: 'size', operator: 'gt', value: 1000000 },
          { type: 'simple', field: 'deleted', operator: 'eq', value: true },
        ],
      },
    })
  })

  it('joins the rows with OR when the examiner says any', async () => {
    renderPage()
    await screen.findByText('All Executables')
    await userEvent.type(screen.getByLabelText('Filter name'), 'Either')
    await fillRow(1, 'extension', 'eq', 'jpg')
    await userEvent.click(screen.getByRole('button', { name: /Add condition/i }))
    await fillRow(2, 'extension', 'eq', 'png')
    await userEvent.selectOptions(screen.getByLabelText('Join conditions'), 'or')

    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(created).not.toBeNull())
    expect((created as { filter: { logic: string } }).filter.logic).toBe('or')
  })

  it('negates the row it is drawn on, not the group', async () => {
    renderPage()
    await screen.findByText('All Executables')
    await userEvent.type(screen.getByLabelText('Filter name'), 'Not jpegs, but big')
    await fillRow(1, 'extension', 'eq', 'jpg')
    await userEvent.click(screen.getByLabelText('Negate condition 1'))
    await userEvent.click(screen.getByRole('button', { name: /Add condition/i }))
    await fillRow(2, 'size', 'gt', '10')

    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(created).not.toBeNull())
    expect(created).toMatchObject({
      filter: {
        type: 'compound',
        logic: 'and',
        conditions: [
          {
            type: 'not',
            condition: { type: 'simple', field: 'extension', operator: 'eq', value: 'jpg' },
          },
          { type: 'simple', field: 'size', operator: 'gt', value: 10 },
        ],
      },
    })
  })

  it('refuses to save a filter with no conditions, and says what it would have matched', async () => {
    // An AND of nothing is vacuously true on the backend: it matches the whole
    // case under a name that claims otherwise. The refusal has to say that, or
    // it reads as the form being fussy.
    renderPage()
    await screen.findByText('All Executables')
    await userEvent.type(screen.getByLabelText('Filter name'), 'Nothing')
    await userEvent.click(screen.getByRole('button', { name: 'Remove condition 1' }))

    expect(
      await screen.findByText(/match every artifact in the case/i),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(created).toBeNull()
  })

  it('refuses a half-filled row rather than dropping it', async () => {
    renderPage()
    await screen.findByText('All Executables')
    await userEvent.type(screen.getByLabelText('Filter name'), 'Half')
    await fillRow(1, 'extension', 'eq', 'jpg')
    await userEvent.click(screen.getByRole('button', { name: /Add condition/i }))
    await fillRow(2, 'size', 'gt', '')

    expect(await screen.findByText(/Condition 2 has no value/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(created).toBeNull()
  })

  it('shows in words the condition it is about to save', async () => {
    // The saved JSON is the thing that decides the population; the sentence is
    // how an examiner checks it says what they meant before it becomes one.
    renderPage()
    await screen.findByText('All Executables')
    await fillRow(1, 'extension', 'eq', 'jpg')
    await userEvent.click(screen.getByRole('button', { name: /Add condition/i }))
    await fillRow(2, 'deleted', 'eq', 'true')

    expect(await screen.findByTestId('flt-preview')).toHaveTextContent(
      '(extension equals "jpg" AND deleted equals true)',
    )
  })

  it('drops a removed row from the saved condition', async () => {
    renderPage()
    await screen.findByText('All Executables')
    await userEvent.type(screen.getByLabelText('Filter name'), 'One left')
    await fillRow(1, 'extension', 'eq', 'jpg')
    await userEvent.click(screen.getByRole('button', { name: /Add condition/i }))
    await fillRow(2, 'size', 'gt', '10')
    await userEvent.click(screen.getByRole('button', { name: 'Remove condition 2' }))

    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(created).not.toBeNull())
    expect(created).toMatchObject({
      filter: { type: 'simple', field: 'extension', operator: 'eq', value: 'jpg' },
    })
  })

  it('offers no connective until there is something to join', async () => {
    renderPage()
    await screen.findByText('All Executables')
    expect(screen.queryByLabelText('Join conditions')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /Add condition/i }))
    expect(screen.getByLabelText('Join conditions')).toBeInTheDocument()
  })
})

/**
 * Opening a saved filter's population in the file grid.
 *
 * The results table on this page is a preview: no paging, no sort, no
 * selection, no export. The file grid has all of those, and the listing
 * endpoint now takes a `filter_id`, so the filter's population can be handed
 * to it whole.
 *
 * The grid is per evidence source, and a filter is evaluated over the whole
 * case, so this control has to say WHICH source it is about to open — silently
 * picking one would show an examiner a fraction of the population under the
 * filter's name.
 */
function mockSources(
  sources: { source_artifact_id: string; name: string }[],
  extra: Record<string, unknown> = {},
) {
  server.use(
    http.get(`/api/v1/cases/${CASE}/stats/sources`, () =>
      HttpResponse.json({
        sources: sources.map((s) => ({ ...s, artifact_count: 10 })),
        ...extra,
      }),
    ),
  )
}

function renderWithGrid() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={[`/cases/${CASE}/filters`]}>
          <Routes>
            <Route path="/cases/:caseId/filters" element={<FiltersPage />} />
            <Route
              path="/cases/:caseId/files/:sourceId"
              element={<GridStub />}
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

function GridStub() {
  const { pathname, search } = useLocation()
  return <div data-testid="grid-stub">{`${pathname}${search}`}</div>
}

describe('FiltersPage — open a filter in the file grid', () => {
  beforeEach(() => {
    mockApi()
  })

  it('opens the one evidence source directly, listing all files', async () => {
    // "All files" and not the folder view: the population spans the whole
    // file system, and the folder view would intersect it with whatever
    // directory the grid happened to be in.
    mockSources([{ source_artifact_id: 's1', name: 'disk.E01' }])
    renderWithGrid()

    const row = (await screen.findByText('Deleted files')).closest('li')!
    const open = within(row).getByRole('button', { name: /Open in file grid/ })
    // The control depends on a second query — the case's evidence sources —
    // and refuses to guess until it has them.
    await waitFor(() => expect(open).toBeEnabled())
    await userEvent.click(open)

    expect(await screen.findByTestId('grid-stub')).toHaveTextContent(
      '/cases/c1/files/s1?view=flat&filter_id=f-usr',
    )
  })

  it('asks which evidence source when the case holds more than one', async () => {
    mockSources([
      { source_artifact_id: 's1', name: 'disk.E01' },
      { source_artifact_id: 's2', name: 'phone.tar' },
    ])
    renderWithGrid()

    const row = (await screen.findByText('Deleted files')).closest('li')!
    const open = within(row).getByRole('button', { name: /Open in file grid/ })
    await waitFor(() => expect(open).toBeEnabled())
    await userEvent.click(open)

    await userEvent.click(
      await screen.findByRole('menuitem', { name: 'phone.tar' }),
    )
    expect(await screen.findByTestId('grid-stub')).toHaveTextContent(
      '/cases/c1/files/s2?view=flat&filter_id=f-usr',
    )
  })

  it('says the list of sources may be short when the server says so', async () => {
    // The source names come from a paged walk of the case's root artifacts. A
    // menu of two, offered as the choice, is a claim about the case.
    mockSources(
      [
        { source_artifact_id: 's1', name: 'disk.E01' },
        { source_artifact_id: 's2', name: 'phone.tar' },
      ],
      { inventory_incomplete: true, inventory_incomplete_reason: 'capped' },
    )
    renderWithGrid()

    const row = (await screen.findByText('Deleted files')).closest('li')!
    const open = within(row).getByRole('button', { name: /Open in file grid/ })
    await waitFor(() => expect(open).toBeEnabled())
    await userEvent.click(open)

    expect(await screen.findByText(/may be incomplete/i)).toBeInTheDocument()
  })

  it('refuses rather than guesses when the case has no evidence source', async () => {
    mockSources([])
    renderWithGrid()

    const row = (await screen.findByText('Deleted files')).closest('li')!
    const button = within(row).getByRole('button', {
      name: /Open in file grid/,
    })
    await waitFor(() => expect(button).toBeDisabled())
    expect(button).toHaveAccessibleDescription(/no evidence source/i)
  })
})
