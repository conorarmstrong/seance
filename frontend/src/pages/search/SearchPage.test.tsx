import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import {
  MemoryRouter,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProcessingProvider } from '../../app/ProcessingContext'
import { ToastProvider } from '../../components/toast/ToastProvider'
import {
  DownloadIncompleteError,
  downloadFile,
  type DownloadOutcome,
} from '../../lib/download'
import { resetSseBus } from '../../hooks/sse'
import { server } from '../../test/server'
import { FrameSpy } from '../../test/frames'
import {
  SEARCH_EXPORT_ROW_BYTES,
  SEARCH_EXPORT_TERMINATOR,
  type SearchResponse,
} from './api'
import { SearchPage } from './SearchPage'

// Only the function is replaced. `DownloadIncompleteError` is a real class the
// page tests `instanceof` against, and a mocked-away module would make that
// check silently unreachable — the one path where the page has something
// important to say.
vi.mock('../../lib/download', async () => {
  const actual =
    await vi.importActual<typeof import('../../lib/download')>(
      '../../lib/download',
    )
  return { ...actual, downloadFile: vi.fn() }
})

/** A download that reached disk whole. */
const DOWNLOADED: DownloadOutcome = {
  route: 'file-system',
  cancelled: false,
  bytes: 4096,
  terminated: true,
}

const baseResponse: SearchResponse = {
  results: [
    {
      artifact_id: 'a1',
      case_id: 'c1',
      artifact_type: 'FileEntry',
      name: 'invoice.docx',
      snippet: 'found malware string',
      highlights: [[6, 13]],
      score: 4.21,
    },
    {
      artifact_id: 'a2',
      case_id: 'c1',
      artifact_type: 'ParsedRecord',
      name: 'registry-run-key',
      snippet: null,
      highlights: null,
      score: 1.5,
    },
  ],
  total_count: 2,
  query: 'malware',
  elapsed_ms: 37,
}

let searchRequests: URLSearchParams[] = []

function mockSearch(response: SearchResponse = baseResponse) {
  server.use(
    http.get('/api/v1/cases/c1/search', ({ request }) => {
      searchRequests.push(new URL(request.url).searchParams)
      return HttpResponse.json(response)
    }),
  )
}

/**
 * The search page opens its own reader on the orchestrator's event stream to
 * follow an index repair, and jsdom has no `EventSource`. This stands in for
 * one, in the same shape `useProcessingEvents.test.tsx` uses, so a repair's
 * `module_progress` events can be delivered on demand.
 */
class MockEventSource {
  static instances: MockEventSource[] = []
  url: string
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  closed = false
  private listeners = new Map<string, Set<(event: MessageEvent) => void>>()

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  addEventListener(name: string, listener: (event: MessageEvent) => void) {
    if (!this.listeners.has(name)) this.listeners.set(name, new Set())
    this.listeners.get(name)!.add(listener)
  }

  removeEventListener(name: string, listener: (event: MessageEvent) => void) {
    this.listeners.get(name)?.delete(listener)
  }

  close() {
    this.closed = true
  }

  emit(name: string, payload: unknown) {
    const event = { data: JSON.stringify(payload), type: name } as MessageEvent
    for (const listener of this.listeners.get(name) ?? []) listener(event)
  }
}

/** Deliver one `search.index_repair` progress event on the live stream. */
function emitRepairProgress(overrides: Record<string, unknown> = {}) {
  const source = MockEventSource.instances[MockEventSource.instances.length - 1]
  act(() => {
    source.emit('module_progress', {
      event_type: 'ModuleProgress',
      case_id: 'c1',
      module_id: 'search.index_repair',
      artifact_id: 'c1',
      units_done: 1234,
      units_total: 93338,
      unit: 'documents',
      ...overrides,
    })
  })
}

/** Answer the owner-or-admin probe with a refusal, as it does for a collaborator. */
function refuseRepairAccess() {
  server.use(
    http.get('/api/v1/cases/c1/access', () =>
      HttpResponse.json(
        {
          error: {
            code: 'FORBIDDEN',
            message: 'You do not have owner access to this case',
          },
        },
        { status: 403 },
      ),
    ),
  )
}

/** Open the index-repair panel, which ships collapsed. */
function openRepairPanel(container: HTMLElement) {
  container.querySelector<HTMLDetailsElement>('.srch-repair')!.open = true
}

/** Reports where a navigation actually landed, for the keyboard-activation tests. */
function WhereAmI() {
  const location = useLocation()
  return <span data-testid="where">{location.pathname}</span>
}

function GoBack() {
  const navigate = useNavigate()
  return (
    <button type="button" onClick={() => navigate(-1)}>
      go-back
    </button>
  )
}

/** Switches the `:caseId` route param in place, without remounting the page. */
function CaseSwitcher() {
  const navigate = useNavigate()
  return (
    <button type="button" onClick={() => navigate('/cases/c2/search')}>
      Go to c2
    </button>
  )
}

function renderPage(
  urls: string[] = ['/cases/c1/search'],
  frames: string[] = [],
) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={urls} initialIndex={urls.length - 1}>
          <WhereAmI />
          <Routes>
            <Route
              path="/cases/:caseId/search"
              element={
                <>
                  <SearchPage />
                  <GoBack />
                  <CaseSwitcher />
                  <FrameSpy
                    capture={() => document.body.textContent ?? ''}
                    frames={frames}
                  />
                </>
              }
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

let reindexRequests: URL[] = []
let backfillRequests: URL[] = []

beforeEach(() => {
  searchRequests = []
  reindexRequests = []
  backfillRequests = []
  vi.mocked(downloadFile).mockClear()
  vi.mocked(downloadFile).mockResolvedValue(DOWNLOADED)
  MockEventSource.instances = []
  vi.stubGlobal('EventSource', MockEventSource)
  // The shared event bus is module state: without this, one test's stubbed
  // socket survives into the next, where the stub has already been removed.
  resetSseBus()
  // The processing reducer writes its state through to sessionStorage so a
  // reload does not lose a run, which also means a run started in one test is
  // still running in the next unless it is cleared here.
  sessionStorage.clear()
  // Every render asks the server whether this examiner may repair the index,
  // because that is the only place the answer lives. The default here is the
  // owner; the tests that care about a refusal override it.
  server.use(
    http.get('/api/v1/cases/:caseId/access', () =>
      HttpResponse.json([
        { user_id: 'u1', username: 'examiner', access_level: 'owner' },
      ]),
    ),
    // The processing shell reconciles against the server whenever it thinks a
    // run may be live; it is not what these tests are about, so it is answered
    // with an idle server.
    http.get('/api/v1/status', () =>
      HttpResponse.json({ active_tasks: 0, scope: 'global' }),
    ),
    http.post('/api/v1/cases/:caseId/search/reindex', ({ request }) => {
      reindexRequests.push(new URL(request.url))
      return HttpResponse.json({
        repair_id: '2f0d6a1e-0000-4000-8000-000000000abc',
        status: 'running',
      })
    }),
    http.post('/api/v1/cases/:caseId/search/backfill', ({ request }) => {
      backfillRequests.push(new URL(request.url))
      return HttpResponse.json({
        backfill_id: '8c41f2b0-0000-4000-8000-0000000000ff',
        status: 'running',
        artifacts: 580394,
        note: 'documents added by a backfill carry the artifact\'s metadata only; text extracted from file bytes at ingest is not reconstructed, so a keyword search over those files is answered from metadata alone until the evidence is re-ingested',
      })
    }),
  )
})

afterEach(() => {
  resetSseBus()
  vi.unstubAllGlobals()
})

describe('SearchPage', () => {
  it('reaches the case-wide byte sweep from the Search screen (ROADMAP §1.2)', () => {
    renderPage()
    expect(
      screen.getByText(/byte sweep of the evidence bytes/i, { selector: 'summary' }),
    ).toBeInTheDocument()
  })

  it('shows an empty state before the first search', () => {
    renderPage()
    expect(
      screen.getByText('Search across all indexed evidence'),
    ).toBeInTheDocument()
    expect(searchRequests).toHaveLength(0)
  })

  it('searches on submit and renders results', async () => {
    mockSearch()
    renderPage()
    await userEvent.type(screen.getByLabelText('Search query'), 'malware')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))

    expect(await screen.findByText('invoice.docx')).toBeInTheDocument()
    // "matching artifacts", not "results": `total_count` counts what MATCHES,
    // which is not the number of rows in the table below it (B3-001).
    expect(
      screen.getByText('2 matching artifacts in 37 ms'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('FileEntry', { selector: '.badge-accent' }),
    ).toBeInTheDocument()
    expect(screen.getByText('4.21')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'invoice.docx' })).toHaveAttribute(
      'href',
      '/cases/c1/artifacts/a1',
    )

    expect(searchRequests).toHaveLength(1)
    expect(searchRequests[0].get('q')).toBe('malware')
    expect(searchRequests[0].get('limit')).toBe('100')
    expect(searchRequests[0].get('regex')).toBeNull()
  })

  it('submits on Enter in the query input', async () => {
    mockSearch()
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    expect(await screen.findByText('invoice.docx')).toBeInTheDocument()
    expect(searchRequests).toHaveLength(1)
  })

  it('does not search while typing without submit', async () => {
    mockSearch()
    renderPage()
    await userEvent.type(screen.getByLabelText('Search query'), 'malware')
    expect(searchRequests).toHaveLength(0)
  })

  it('renders snippet highlight ranges as mark elements', async () => {
    mockSearch()
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')
    const marked = screen.getByText('malware', { selector: 'mark' })
    expect(marked).toBeInTheDocument()
    const cell = marked.closest('td')!
    expect(cell.textContent).toBe('found malware string')
  })

  it('interprets highlight offsets as UTF-8 bytes (multibyte snippet)', async () => {
    mockSearch({
      ...baseResponse,
      results: [
        {
          ...baseResponse.results[0],
          // 'naïve café ' is 13 bytes; 'malware' spans bytes 13..20.
          snippet: 'naïve café malware end',
          highlights: [[13, 20]],
        },
      ],
      total_count: 1,
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')
    const marked = screen.getByText('malware', { selector: 'mark' })
    expect(marked).toBeInTheDocument()
    expect(marked.closest('td')!.textContent).toBe('naïve café malware end')
  })

  it('sends types (checkbox chips), extensions, regex and limit', async () => {
    mockSearch()
    renderPage()
    await userEvent.type(screen.getByLabelText('Search query'), 'flag')
    await userEvent.click(screen.getByRole('checkbox', { name: 'FileEntry' }))
    await userEvent.click(
      screen.getByRole('checkbox', { name: 'ParsedRecord' }),
    )
    await userEvent.type(screen.getByLabelText('Extensions'), 'exe,dll')
    await userEvent.click(screen.getByLabelText('Regex'))
    await userEvent.selectOptions(screen.getByLabelText('Limit'), '500')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))

    await waitFor(() => expect(searchRequests).toHaveLength(1))
    const params = searchRequests[0]
    expect(params.get('q')).toBe('flag')
    expect(params.get('types')).toBe('FileEntry,ParsedRecord')
    expect(params.get('extensions')).toBe('exe,dll')
    expect(params.get('regex')).toBe('true')
    expect(params.get('limit')).toBe('500')
  })

  it('unchecking a chip removes the type again', async () => {
    mockSearch()
    renderPage()
    const chip = screen.getByRole('checkbox', { name: 'FileEntry' })
    await userEvent.click(chip)
    expect(chip).toBeChecked()
    await userEvent.click(chip)
    expect(chip).not.toBeChecked()
  })

  it('runs a search from URL params so links are shareable', async () => {
    mockSearch()
    renderPage(['/cases/c1/search?q=malware&regex=true&types=FileEntry'])
    expect(await screen.findByText('invoice.docx')).toBeInTheDocument()
    expect(searchRequests[0].get('q')).toBe('malware')
    expect(searchRequests[0].get('regex')).toBe('true')
    expect(screen.getByLabelText('Regex')).toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'FileEntry' })).toBeChecked()
  })

  it('restores form state and results on back navigation', async () => {
    mockSearch()
    renderPage([
      '/cases/c1/search?q=first',
      '/cases/c1/search?q=second&regex=true',
    ])
    expect(await screen.findByText('invoice.docx')).toBeInTheDocument()
    expect(screen.getByLabelText('Search query')).toHaveValue('second')
    expect(screen.getByLabelText('Regex')).toBeChecked()

    await userEvent.click(screen.getByRole('button', { name: 'go-back' }))
    await waitFor(() =>
      expect(screen.getByLabelText('Search query')).toHaveValue('first'),
    )
    expect(screen.getByLabelText('Regex')).not.toBeChecked()
    await waitFor(() =>
      expect(searchRequests.some((p) => p.get('q') === 'first')).toBe(true),
    )
  })

  it('toggles the query syntax help popover', async () => {
    renderPage()
    const helpButton = screen.getByRole('button', {
      name: 'Search syntax help',
    })
    expect(screen.queryByText('Query syntax')).not.toBeInTheDocument()
    await userEvent.click(helpButton)
    expect(screen.getByText('Query syntax')).toBeInTheDocument()
    expect(screen.getByText(/Rust regular expression/)).toBeInTheDocument()
    expect(screen.getByText(/ranks results by relevance/)).toBeInTheDocument()
    await userEvent.click(helpButton)
    expect(screen.queryByText('Query syntax')).not.toBeInTheDocument()
  })

  it('marks the match count as a floor when the server could not count it all (B3-001)', async () => {
    // `total_count` is how many artifacts MATCH. The substring, regex and
    // extension-filtered paths stop at a scan budget and never count past it,
    // so the server labels the figure a lower bound. Rendered identically to an
    // exact count it becomes a prevalence an examiner writes into a note.
    mockSearch({
      ...baseResponse,
      total_count: 37,
      count_is_lower_bound: true,
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    expect(
      await screen.findByText('At least 37 matching artifacts in 37 ms'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/match count above is a lower bound/),
    ).toBeInTheDocument()
  })

  it('states an exact match count without a floor marker', async () => {
    // The other half of the contract: a page that always warned would train the
    // examiner to ignore the warning.
    mockSearch({ ...baseResponse, total_count: 37 })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    expect(
      await screen.findByText('37 matching artifacts in 37 ms'),
    ).toBeInTheDocument()
    expect(screen.queryByText(/lower bound/)).not.toBeInTheDocument()
  })

  it('marks a keyword-list hit count as a floor (B3-001)', async () => {
    // The triage table is the surface most likely to be quoted as prevalence.
    server.use(
      http.get('/api/v1/cases/c1/search', () =>
        HttpResponse.json({
          ...baseResponse,
          total_count: 4242,
          count_is_lower_bound: true,
        }),
      ),
    )
    const { container } = renderPage()
    container.querySelector('details')!.open = true
    fireEvent.change(screen.getByLabelText('Keyword list'), {
      target: { value: 'alpha' },
    })
    await userEvent.click(screen.getByRole('button', { name: 'Run all' }))

    expect(await screen.findByText('lower bound')).toBeInTheDocument()
    expect(screen.getByText(/≥ 4,242/)).toBeInTheDocument()
    // The bare number must not also be on screen: an exact "4,242" beside the
    // floor is the reading this fix exists to prevent.
    expect(screen.queryByText('4,242')).not.toBeInTheDocument()
  })

  it('shows a no-results state', async () => {
    mockSearch({ results: [], total_count: 0, query: 'zzz', elapsed_ms: 2 })
    renderPage()
    await userEvent.type(screen.getByLabelText('Search query'), 'zzz{Enter}')
    expect(await screen.findByText('No results')).toBeInTheDocument()
  })

  it('a search that finds nothing says what was searched (SEARCH-002)', async () => {
    const statement =
      'This search covers the metadata of the artifacts the ingest handed to the search indexer, plus text read from the first 16 MiB of the bytes of FileEntry and FileContent artifacts only.'
    mockSearch({
      results: [],
      total_count: 0,
      query: 'zzz',
      elapsed_ms: 2,
      universe: {
        statement,
        byte_sweep_route: 'POST /api/v1/cases/:id/search/sweep',
      },
    })
    renderPage()
    await userEvent.type(screen.getByLabelText('Search query'), 'zzz{Enter}')
    expect(await screen.findByText('No results')).toBeInTheDocument()
    // "No results" is only "absent" within the scope searched, so the scope is
    // on screen beside it rather than behind a link.
    expect(screen.getByText(statement, { exact: false })).toBeInTheDocument()
  })

  it('a zero-hit page from a server that states no scope says so rather than nothing (SEARCH-002)', async () => {
    mockSearch({ results: [], total_count: 0, query: 'zzz', elapsed_ms: 2 })
    renderPage()
    await userEvent.type(screen.getByLabelText('Search query'), 'zzz{Enter}')
    expect(await screen.findByText('No results')).toBeInTheDocument()
    expect(
      screen.getByText(/did not state what this search covers/),
    ).toBeInTheDocument()
  })

  it('shows an error state when the search fails', async () => {
    server.use(
      http.get('/api/v1/cases/c1/search', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'index unavailable' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    await userEvent.type(screen.getByLabelText('Search query'), 'boom{Enter}')
    expect(await screen.findByText(/index unavailable/)).toBeInTheDocument()
  })

  it('enables exports only after a search and calls downloadFile', async () => {
    mockSearch()
    renderPage()
    const jsonBtn = screen.getByRole('button', { name: 'Export JSON' })
    const csvBtn = screen.getByRole('button', { name: 'Export CSV' })
    expect(jsonBtn).toBeDisabled()
    expect(csvBtn).toBeDisabled()

    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')
    expect(jsonBtn).toBeEnabled()
    expect(csvBtn).toBeEnabled()

    await userEvent.click(jsonBtn)
    expect(downloadFile).toHaveBeenCalledWith(
      '/cases/c1/search/export/json',
      'search-results.json',
      expect.objectContaining({ query: expect.objectContaining({ q: 'malware' }) }),
    )

    await userEvent.click(csvBtn)
    expect(downloadFile).toHaveBeenCalledWith(
      '/cases/c1/search/export/csv',
      'search-results.csv',
      expect.objectContaining({ query: expect.objectContaining({ q: 'malware' }) }),
    )
  })

  it('offers no size estimate from a floor of zero', async () => {
    // The first page of a thinly-spread extension filter: no survivor in the
    // window, `total_count: 0` as a floor, and a cursor so the walk can begin.
    // "At least roughly 0 B" would price a file of unknown size as nothing.
    mockSearch({
      ...baseResponse,
      results: [],
      total_count: 0,
      count_is_lower_bound: true,
      next_cursor: 'c1',
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    const csvBtn = await screen.findByRole('button', { name: 'Export CSV' })
    await userEvent.click(csvBtn)

    const options = vi.mocked(downloadFile).mock.calls.at(-1)![2]!
    expect(options.unbounded).toBe(true)
    expect(options.estimatedBytes).toBeUndefined()
    expect(options.estimatedBytesIsFloor).toBe(true)
  })

  it('asks for the export to be written as it arrives, and prices the fallback', async () => {
    // The server streams the whole match set at a bounded cost to itself. The
    // page has to say so, or the helper buffers it here and the tab dies
    // instead of the server.
    mockSearch({ ...baseResponse, total_count: 4_000_000 })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: 'Export CSV' }))

    const options = vi.mocked(downloadFile).mock.calls.at(-1)![2]!
    expect(options.unbounded).toBe(true)
    expect(options.terminator).toEqual({
      marker: SEARCH_EXPORT_TERMINATOR,
      format: 'csv',
    })
    // The figure an examiner on a browser that cannot stream is shown before
    // they spend it, derived from the match count rather than invented.
    expect(options.estimatedBytes).toBe(
      4_000_000 * SEARCH_EXPORT_ROW_BYTES.csv,
    )
    expect(options.estimatedBytesIsFloor).toBe(false)
  })

  it('carries a lower-bound match count through to the size it quotes', async () => {
    mockSearch({
      ...baseResponse,
      total_count: 4_000_000,
      count_is_lower_bound: true,
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: 'Export JSON' }))

    const options = vi.mocked(downloadFile).mock.calls.at(-1)![2]!
    expect(options.estimatedBytes).toBe(
      4_000_000 * SEARCH_EXPORT_ROW_BYTES.json,
    )
    expect(options.estimatedBytesIsFloor).toBe(true)
  })

  it('leaves the fragment statement on the page, not in a toast that expires', async () => {
    mockSearch()
    vi.mocked(downloadFile).mockRejectedValue(
      new DownloadIncompleteError(
        'search-results.csv is a FRAGMENT. The transfer ended without the ' +
          "server's final \"### END OF EXPORT ###\" row.",
        'search-results.csv',
        1024,
        true,
      ),
    )
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: 'Export CSV' }))

    // The words the helper used, verbatim: the examiner reads what is on their
    // disk, not this page's paraphrase of it.
    expect(await screen.findByText(/is a FRAGMENT/)).toBeInTheDocument()
    expect(screen.getByText(/### END OF EXPORT ###/)).toBeInTheDocument()

    // And it is cleared by the next attempt rather than accumulating.
    vi.mocked(downloadFile).mockResolvedValue(DOWNLOADED)
    await userEvent.click(screen.getByRole('button', { name: 'Export CSV' }))
    await waitFor(() =>
      expect(screen.queryByText(/is a FRAGMENT/)).not.toBeInTheDocument(),
    )
  })

  /**
   * A fragment warning belongs to the case whose evidence it was written from.
   *
   * This page stays mounted across a `:caseId` change, so an unscoped note
   * survives the switch and sits under case B's export buttons unchanged.
   * Nothing in the sentence names a case, and the filename it quotes is the
   * same literal string for every case and every query, so there is nothing on
   * screen to tell the two apart: the examiner reads a statement about case A's
   * truncated export as a statement about case B's. They either condemn a sound
   * exhibit, or — once the note has outlived a successful export — learn to
   * treat it as noise and ignore the next real one.
   */
  it('does not carry one case’s fragment warning onto another case', async () => {
    mockSearch()
    vi.mocked(downloadFile).mockRejectedValue(
      new DownloadIncompleteError(
        'search-results.csv is a FRAGMENT. The transfer ended without the ' +
          "server's final \"### END OF EXPORT ###\" row.",
        'search-results.csv',
        1024,
        true,
      ),
    )
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')
    await userEvent.click(screen.getByRole('button', { name: 'Export CSV' }))
    expect(await screen.findByText(/is a FRAGMENT/)).toBeInTheDocument()

    // Same mounted page, different case.
    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    await waitFor(() =>
      expect(
        screen.queryByText(/is a FRAGMENT/),
        'case A’s fragment warning must not stand under case B’s heading',
      ).not.toBeInTheDocument(),
    )
  })

  it('reports nothing when the examiner cancels the save dialog', async () => {
    mockSearch()
    vi.mocked(downloadFile).mockResolvedValue({
      route: 'file-system',
      cancelled: true,
      bytes: 0,
      terminated: null,
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: 'Export CSV' }))

    // Declining to save is a decision, not a failure. Nothing is announced,
    // and the buttons come back.
    expect(screen.queryByText(/Export failed/)).not.toBeInTheDocument()
    expect(screen.queryByText(/fragment/i)).not.toBeInTheDocument()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Export CSV' })).toBeEnabled(),
    )
  })

  it('defers revoking the keyword-list object URL (BUG-203)', () => {
    // Revoking synchronously after click() can abort the download before the
    // browser has read the blob, producing an empty keywords.txt.
    const createObjectURL = vi.fn(() => 'blob:keywords')
    const revokeObjectURL = vi.fn()
    const origCreate = URL.createObjectURL
    const origRevoke = URL.revokeObjectURL
    URL.createObjectURL =
      createObjectURL as unknown as typeof URL.createObjectURL
    URL.revokeObjectURL = revokeObjectURL
    const { container } = renderPage()
    // The keyword panel is a <details>; open it so its controls are active.
    container.querySelector('details')!.open = true
    fireEvent.change(screen.getByLabelText('Keyword list'), {
      target: { value: 'alpha\nbeta' },
    })

    vi.useFakeTimers()
    try {
      fireEvent.click(screen.getByText('Export', { selector: 'button' }))
      expect(createObjectURL).toHaveBeenCalledTimes(1)
      // Still live immediately after the click…
      expect(revokeObjectURL).not.toHaveBeenCalled()
      // …and released once the browser has had time to read it.
      vi.advanceTimersByTime(60_000)
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:keywords')
    } finally {
      vi.useRealTimers()
      URL.createObjectURL = origCreate
      URL.revokeObjectURL = origRevoke
    }
  })

  it('clears keyword-list hit counts when the case changes (BUG-261)', async () => {
    // The main search is case-keyed through its query key, but the per-term hit
    // counts are plain state on a page that stays mounted across a `:caseId`
    // route change. Case A's triage volumes must not be shown for case B.
    server.use(
      http.get('/api/v1/cases/c1/search', () =>
        HttpResponse.json({ ...baseResponse, total_count: 4242 }),
      ),
    )
    const { container } = renderPage()
    // The keyword panel is a <details>; open it so its controls are active.
    container.querySelector('details')!.open = true
    fireEvent.change(screen.getByLabelText('Keyword list'), {
      target: { value: 'alpha' },
    })
    await userEvent.click(screen.getByRole('button', { name: 'Run all' }))
    expect(await screen.findByText('4,242')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    await waitFor(() =>
      expect(screen.queryByText('4,242')).not.toBeInTheDocument(),
    )
    expect(
      screen.queryByRole('button', { name: 'alpha' }),
    ).not.toBeInTheDocument()
  })

  it('drops the keyword list itself when the case changes (B3-043)', async () => {
    // The counts were scoped; the term list was not. An examiner's keyword list
    // is written for ONE investigation — names, handles, account numbers — and
    // carrying it into the next case runs the wrong terms against the wrong
    // evidence, with nothing on screen saying where the list came from.
    const { container } = renderPage()
    container.querySelector('details')!.open = true
    fireEvent.change(screen.getByLabelText('Keyword list'), {
      target: { value: 'alpha\nbeta' },
    })
    expect(screen.getByLabelText('Keyword list')).toHaveValue('alpha\nbeta')

    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    await waitFor(() =>
      expect(screen.getByLabelText('Keyword list')).toHaveValue(''),
    )
  })

  it('paints no frame of case 1 hit counts under case 2 (BUG-261)', async () => {
    // Clearing the counts in a `useEffect` runs after the commit that already
    // reads case 2, and that commit is painted: "alpha — 4,242" under case 2's
    // chrome, a triage volume an examiner may write down for the wrong case.
    // `click` flushes passive effects before returning, so the assertion above
    // passes against the broken version too; a layout-effect snapshot does not.
    server.use(
      http.get('/api/v1/cases/c1/search', () =>
        HttpResponse.json({ ...baseResponse, total_count: 4242 }),
      ),
    )
    const frames: string[] = []
    const { container } = renderPage(['/cases/c1/search'], frames)
    container.querySelector('details')!.open = true
    fireEvent.change(screen.getByLabelText('Keyword list'), {
      target: { value: 'alpha' },
    })
    await userEvent.click(screen.getByRole('button', { name: 'Run all' }))
    expect(await screen.findByText('4,242')).toBeInTheDocument()

    frames.length = 0
    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    await waitFor(() => expect(frames.length).toBeGreaterThan(0))
    for (const frame of frames) {
      expect(frame).not.toContain('4,242')
    }
  })

  it('shows a pending state on the export buttons while downloading', async () => {
    mockSearch()
    let resolveDownload: () => void = () => {}
    vi.mocked(downloadFile).mockImplementation(
      () =>
        new Promise<DownloadOutcome>((resolve) => {
          resolveDownload = () => resolve(DOWNLOADED)
        }),
    )
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: 'Export JSON' }))
    const pending = screen.getByRole('button', { name: 'Exporting…' })
    expect(pending).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Export CSV' })).toBeDisabled()

    resolveDownload()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Export JSON' })).toBeEnabled(),
    )
    expect(screen.getByRole('button', { name: 'Export CSV' })).toBeEnabled()
  })
})

describe('SearchPage search-index repair', () => {
  it('offers no repair control to an examiner the endpoint would refuse', async () => {
    // The repair is owner-or-admin. A collaborator handed the button would get
    // a 403, and a control that cannot work is worse than no control at all.
    refuseRepairAccess()
    const { container } = renderPage()
    await waitFor(() =>
      expect(container.querySelector('.srch-repair')).toBeNull(),
    )
    expect(
      screen.queryByRole('button', { name: 'Repair display names' }),
    ).not.toBeInTheDocument()
  })

  it('states what a repair does not cover beside the button that runs it', async () => {
    // "Reindexed" must not be readable as "search coverage is now complete".
    // The limit is stated at the point of use, not in a tooltip.
    const { container } = renderPage()
    await waitFor(() =>
      expect(container.querySelector('.srch-repair')).not.toBeNull(),
    )
    openRepairPanel(container)
    expect(
      screen.getByText(/does not add artifacts that were never indexed/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Backfilling, below, is what adds them/),
    ).toBeInTheDocument()
  })

  it('starts a repair and reports the receipt as a receipt, not an outcome', async () => {
    const { container } = renderPage()
    await waitFor(() =>
      expect(container.querySelector('.srch-repair')).not.toBeNull(),
    )
    openRepairPanel(container)
    await userEvent.click(
      screen.getByRole('button', { name: 'Repair display names' }),
    )

    await waitFor(() => expect(reindexRequests).toHaveLength(1))
    expect(reindexRequests[0].pathname).toBe('/api/v1/cases/c1/search/reindex')

    expect(
      await screen.findByText('2f0d6a1e-0000-4000-8000-000000000abc'),
    ).toBeInTheDocument()
    // The outcome lands in the audit log, and the page says so and links there.
    expect(
      screen.getByText('search_index_repair_completed'),
    ).toBeInTheDocument()
    expect(screen.getByText('search_index_repair_failed')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'audit log' })).toHaveAttribute(
      'href',
      '/cases/c1/audit',
    )
  })

  it('offers a backfill beside the repair, and says what it adds and what it does not', async () => {
    // LIVE-028. The repair walks what is indexed; this walks the case. The
    // sentence about metadata is the one that keeps an empty keyword search
    // over a backfilled file from reading as the term being absent.
    const { container } = renderPage()
    await waitFor(() =>
      expect(container.querySelector('.srch-repair')).not.toBeNull(),
    )
    openRepairPanel(container)
    expect(
      screen.getByText(/Backfilling is the operation that/),
    ).toBeInTheDocument()
    expect(screen.getByText(/metadata only/)).toBeInTheDocument()

    await userEvent.click(
      screen.getByRole('button', { name: 'Backfill missing documents' }),
    )
    await waitFor(() => expect(backfillRequests).toHaveLength(1))
    expect(backfillRequests[0].pathname).toBe(
      '/api/v1/cases/c1/search/backfill',
    )
    // Force is no more offered here than it is for the repair.
    expect(backfillRequests[0].searchParams.get('force')).toBeNull()

    // The receipt is a receipt: the outcome is in the audit log, and the
    // server's own note about what was added travels with it.
    expect(
      await screen.findByText('8c41f2b0-0000-4000-8000-0000000000ff'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('search_index_backfill_completed'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/text extracted from file bytes at ingest is not reconstructed/),
    ).toBeInTheDocument()
  })

  it('never sends force, and offers no control that would', async () => {
    // `?force=true` exists to rescue a case whose server died mid-repair. A
    // button labelled "force" invites a click nobody at the screen can weigh.
    const { container } = renderPage()
    await waitFor(() =>
      expect(container.querySelector('.srch-repair')).not.toBeNull(),
    )
    openRepairPanel(container)
    await userEvent.click(
      screen.getByRole('button', { name: 'Repair display names' }),
    )

    await waitFor(() => expect(reindexRequests).toHaveLength(1))
    expect(reindexRequests[0].searchParams.get('force')).toBeNull()
    expect(screen.queryByText(/force/i)).not.toBeInTheDocument()
  })

  it("repeats the server's refusal verbatim when a repair is already running", async () => {
    // That message is what tells the examiner the escape hatch exists and what
    // it is for, so it is shown rather than replaced with a friendlier one.
    const refusal =
      'A search index repair is already running for this case. If the server ' +
      'was restarted while one was in progress, retry with ?force=true.'
    server.use(
      http.post('/api/v1/cases/c1/search/reindex', () =>
        HttpResponse.json(
          { error: { code: 'INVALID_REQUEST', message: refusal } },
          { status: 400 },
        ),
      ),
    )
    const { container } = renderPage()
    await waitFor(() =>
      expect(container.querySelector('.srch-repair')).not.toBeNull(),
    )
    openRepairPanel(container)
    await userEvent.click(
      screen.getByRole('button', { name: 'Repair display names' }),
    )

    expect(
      await screen.findByText(new RegExp(refusal.slice(0, 40))),
    ).toBeInTheDocument()
    expect(screen.getByText(/\?force=true/)).toBeInTheDocument()
  })

  it('warns that results may be stale while a repair runs, with pinned counts', async () => {
    renderPage()
    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1))
    emitRepairProgress()

    expect(
      await screen.findByText(/1,234 of 93,338 documents/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Display names in these results may change/),
    ).toBeInTheDocument()
  })

  it('shows the running repair to an examiner who may not start one', async () => {
    // Two examiners on one case must not be shown different facts. The control
    // is gated; the warning that names are being rewritten is not.
    refuseRepairAccess()
    const { container } = renderPage()
    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1))
    emitRepairProgress()

    expect(
      await screen.findByText(/1,234 of 93,338 documents/),
    ).toBeInTheDocument()
    expect(container.querySelector('.srch-repair')).toBeNull()
  })

  it('ignores repair progress reported for another case', async () => {
    renderPage()
    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1))
    emitRepairProgress({ case_id: 'c2' })

    expect(
      screen.queryByText(/1,234 of 93,338 documents/),
    ).not.toBeInTheDocument()
  })

  it('ignores progress from a module that is not the index repair', async () => {
    renderPage()
    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1))
    emitRepairProgress({ module_id: 'filesystem.walk', unit: 'files' })

    expect(screen.queryByText(/1,234/)).not.toBeInTheDocument()
  })

  it('does not show case 1 repair as case 2 (BUG-261 class)', async () => {
    // This page stays mounted across a `:caseId` change. A receipt naming a
    // repair of case 1, or a banner saying names are being rewritten, is a
    // statement about the case it was started in and about no other.
    const { container } = renderPage()
    await waitFor(() =>
      expect(container.querySelector('.srch-repair')).not.toBeNull(),
    )
    openRepairPanel(container)
    await userEvent.click(
      screen.getByRole('button', { name: 'Repair display names' }),
    )
    expect(
      await screen.findByText('2f0d6a1e-0000-4000-8000-000000000abc'),
    ).toBeInTheDocument()
    emitRepairProgress()
    expect(screen.getByText(/1,234 of 93,338 documents/)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    await waitFor(() =>
      expect(
        screen.queryByText('2f0d6a1e-0000-4000-8000-000000000abc'),
      ).not.toBeInTheDocument(),
    )
    expect(
      screen.queryByText(/1,234 of 93,338 documents/),
    ).not.toBeInTheDocument()
  })

  it('does not claim a finished pass succeeded', async () => {
    // The page is never told the outcome; only the audit log is. Reporting the
    // last progress event as success would invent a fact.
    renderPage()
    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1))
    emitRepairProgress({ units_done: 93338, units_total: 93338 })

    expect(
      await screen.findByText(/processed all 93,338 documents/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/succeeded|successful/i)).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'audit log' })).toBeInTheDocument()
  })
})

/**
 * Reaching match 1,001.
 *
 * The result set used to stop at whatever `limit` said and offer nothing
 * afterwards: no pager, no offset, no route of any kind to the next match. An
 * examiner who testifies "I searched the term and reviewed the results" had
 * seen a bounded prefix, and the screen never said which prefix it was.
 *
 * These tests pin two things together, because either alone is a defect: the
 * examiner can walk the whole match set, AND every page says where in that set
 * it sits and on what authority.
 */
describe('SearchPage paging', () => {
  /** A page of hits as the paging endpoint returns it. */
  function pageResponse(over: Partial<SearchResponse> = {}): SearchResponse {
    return {
      ...baseResponse,
      total_count: 250,
      offset: 0,
      // The page size the mocked server actually serves. It matches the number
      // of rows in `baseResponse` on purpose: a full page is what tells the
      // client there may be another one, so a mock whose page is short would
      // silently be testing the last-page case everywhere.
      limit: 2,
      max_offset: 100_000,
      ...over,
    }
  }

  /**
   * Answer every search from `pages`, keyed by the `offset` asked for, so a
   * test can watch the page the examiner actually lands on rather than a
   * canned body.
   */
  function mockPagedSearch(pages: Record<string, SearchResponse>) {
    server.use(
      http.get('/api/v1/cases/c1/search', ({ request }) => {
        const params = new URL(request.url).searchParams
        searchRequests.push(params)
        const offset = params.get('offset') ?? '0'
        return HttpResponse.json(pages[offset] ?? pages['0'])
      }),
    )
  }

  it('states where the rows sit in the match set', async () => {
    mockPagedSearch({ '0': pageResponse() })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    expect(
      await screen.findByText('Showing matches 1–2 of 250.'),
    ).toBeInTheDocument()
  })

  it('fetches the next page from the server and renumbers the rows', async () => {
    mockPagedSearch({
      '0': pageResponse(),
      '2': pageResponse({
        offset: 2,
        results: [
          {
            artifact_id: 'a101',
            case_id: 'c1',
            artifact_type: 'FileEntry',
            name: 'match-3.txt',
            snippet: null,
            highlights: null,
            score: 1,
          },
        ],
      }),
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: /Next/ }))

    expect(await screen.findByText('match-3.txt')).toBeInTheDocument()
    expect(screen.getByText('Showing matches 3–3 of 250.')).toBeInTheDocument()
    // The rows came from the server, not from a client-side slice of a set it
    // already held: the whole point is that nothing is O(matches) in the tab.
    expect(searchRequests.at(-1)!.get('offset')).toBe('2')
    expect(searchRequests.at(-1)!.get('q')).toBe('malware')
  })

  it('numbers the rows from the offset the SERVER served, not the one asked for', async () => {
    // A server that ignores `offset` returns the first page again. Numbering
    // those rows 101–200 because that is what we asked for would put a false
    // position on screen, which is worse than not paging at all.
    mockPagedSearch({
      '0': pageResponse(),
      '2': pageResponse({ offset: 0 }),
    })
    renderPage(['/cases/c1/search?q=malware&offset=2'])

    expect(
      await screen.findByText('Showing matches 1–2 of 250.'),
    ).toBeInTheDocument()
  })

  it('offers no pager, and says why, when the server does not state its page', async () => {
    // `offset` absent is not "offset 0": it is a server that never told us
    // where the rows came from, so they cannot be positioned and paging cannot
    // be offered on a guess. Same reading the filters page gives an absent
    // `scan_complete`.
    mockPagedSearch({ '0': { ...baseResponse, total_count: 250 } })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    await screen.findByText('invoice.docx')
    expect(screen.queryByRole('button', { name: /Next/ })).toBeNull()
    expect(
      screen.getByText(/did not state which page of the match set/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/Showing matches/)).toBeNull()
  })

  it('returns to the first page when the query changes', async () => {
    mockPagedSearch({ '0': pageResponse(), '2': pageResponse({ offset: 2 }) })
    renderPage(['/cases/c1/search?q=malware&offset=2'])
    await screen.findByText('invoice.docx')
    expect(searchRequests.at(-1)!.get('offset')).toBe('2')

    await userEvent.clear(screen.getByLabelText('Search query'))
    await userEvent.type(screen.getByLabelText('Search query'), 'other{Enter}')

    await waitFor(() => expect(searchRequests.at(-1)!.get('q')).toBe('other'))
    expect(searchRequests.at(-1)!.get('offset')).toBe('0')
  })

  it('withholds the LAST-page jump and calls the page total a floor when the count is one', async () => {
    // `total_count` is a lower bound, so the page count derived from it is one
    // too: a "last page" button would jump to a page the server never called
    // the end. Everything else stays — stepping forward is sound whatever the
    // total is, and page 1 is known whatever the total is.
    mockPagedSearch({
      '0': pageResponse({ count_is_lower_bound: true, total_count: 250 }),
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    expect(
      await screen.findByText(/Page 1 of at least 125/),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Last page' })).toBeNull()
    expect(
      screen.getByRole('button', { name: 'First page' }),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Next/ })).toBeEnabled()
    expect(
      screen.getByText('Showing matches 1–2 of at least 250.'),
    ).toBeInTheDocument()
  })

  it('says how many matches paging cannot reach', async () => {
    mockPagedSearch({
      '0': pageResponse({ total_count: 250_000, max_offset: 100_000 }),
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    expect(
      await screen.findByText(/149,998 further matching artifacts/),
    ).toBeInTheDocument()
    expect(screen.getByText(/stops at match 100,002/)).toBeInTheDocument()
  })

  it('says nothing about a ceiling that does not bite', async () => {
    mockPagedSearch({ '0': pageResponse() })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    await screen.findByText('invoice.docx')
    expect(screen.queryByText(/further matching artifacts/)).toBeNull()
  })

  it('disables Next on the last page', async () => {
    mockPagedSearch({ '0': pageResponse({ total_count: 2 }) })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    await screen.findByText('invoice.docx')
    expect(screen.getByRole('button', { name: /Next/ })).toBeDisabled()
  })

  it('puts the page in the URL so Back walks the pages the examiner saw', async () => {
    mockPagedSearch({
      '0': pageResponse(),
      '2': pageResponse({
        offset: 2,
        results: [
          {
            artifact_id: 'a101',
            case_id: 'c1',
            artifact_type: 'FileEntry',
            name: 'match-3.txt',
            snippet: null,
            highlights: null,
            score: 1,
          },
        ],
      }),
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')
    await userEvent.click(screen.getByRole('button', { name: /Next/ }))
    await screen.findByText('match-3.txt')

    await userEvent.click(screen.getByRole('button', { name: 'go-back' }))

    expect(await screen.findByText('invoice.docx')).toBeInTheDocument()
    expect(screen.getByText('Showing matches 1–2 of 250.')).toBeInTheDocument()
  })

  it('pages with the limit the server applied, not the one requested', async () => {
    // The endpoint clamps `limit`. Paging in steps the server does not serve
    // would skip or repeat matches between pages.
    mockPagedSearch({ '0': pageResponse({ limit: 50, total_count: 250 }) })
    renderPage(['/cases/c1/search?q=malware&limit=1000'])

    expect(await screen.findByText(/Page 1 of 5/)).toBeInTheDocument()
  })

  it('does not call an empty page past the end "nothing matched"', async () => {
    // The single worst sentence this screen can produce. An examiner who pages
    // one step too far, or opens a shared link to a page that has since moved,
    // is looking at a position with no rows in it — not at a case with no
    // matches. "Nothing matched malware" beside a stated count of 250 is a
    // false negative that reads as evidence of absence, and it is the kind of
    // screen that gets quoted.
    mockPagedSearch({
      '0': pageResponse(),
      '2': pageResponse({ offset: 2, results: [], total_count: 250 }),
    })
    renderPage(['/cases/c1/search?q=malware&offset=2'])

    expect(
      await screen.findByText(/No matches at this position/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/Nothing matched/)).toBeNull()
    // The count is still stated, because it is still true, and the way back is
    // a control rather than a suggestion.
    expect(screen.getByText(/250 matching artifacts/)).toBeInTheDocument()
    await userEvent.click(
      screen.getByRole('button', { name: /back to the first page/i }),
    )
    expect(await screen.findByText('invoice.docx')).toBeInTheDocument()
  })

  it('still says nothing matched when the query really matched nothing', async () => {
    mockPagedSearch({ '0': pageResponse({ results: [], total_count: 0 }) })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    expect(await screen.findByText(/Nothing matched/)).toBeInTheDocument()
    expect(screen.queryByText(/No matches at this position/)).toBeNull()
  })

  it('keeps the jump to page 1 when the count is a floor', async () => {
    // Withholding the LAST-page jump on a floor is right — the server never
    // said which page is last. Page 1 is known whatever the total is, so
    // withholding that one costs an examiner a control and buys no honesty.
    mockPagedSearch({
      '0': pageResponse(),
      '2': pageResponse({
        offset: 2,
        count_is_lower_bound: true,
        total_count: 250,
      }),
    })
    renderPage(['/cases/c1/search?q=malware&offset=2'])

    await screen.findByText(/Page 2 of at least 125/)
    expect(screen.queryByRole('button', { name: 'Last page' })).toBeNull()
    expect(screen.getByRole('button', { name: 'First page' })).toBeEnabled()
  })

  it('offers Next past a floor when the page came back full', async () => {
    // A floor is a floor: the count stopping at 200 does not mean the matches
    // do. A full page at the stated end is the server's own evidence that
    // there is more to fetch, and disabling Next there would strand the
    // examiner at a number the server explicitly refused to call a total.
    mockPagedSearch({
      '0': pageResponse({
        count_is_lower_bound: true,
        total_count: 2,
        limit: 2,
      }),
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )

    await screen.findByText('invoice.docx')
    expect(screen.getByRole('button', { name: /Next/ })).toBeEnabled()
  })

  it('does not offer Next past the paging ceiling', async () => {
    mockPagedSearch({
      '0': pageResponse({
        offset: 200,
        limit: 2,
        max_offset: 200,
        total_count: 250_000,
        count_is_lower_bound: true,
      }),
    })
    renderPage(['/cases/c1/search?q=malware&offset=200'])

    await screen.findByText('invoice.docx')
    expect(screen.getByRole('button', { name: /Next/ })).toBeDisabled()
  })

  /**
   * The LAST-page jump must land on a page the server will actually serve.
   *
   * The page grid is laid out in steps of the limit, and the paging ceiling is
   * a fixed number of matches that the limit need not divide. A page count
   * derived from the reachable matches alone therefore names a final page whose
   * offset overshoots the ceiling, and the server refuses that offset outright
   * rather than serving a nearer page. The examiner clicks a control this
   * screen offered and is handed an error — so the last page this pager names
   * is the deepest page-aligned offset the ceiling admits.
   *
   * 300 is a limit the dropdown does not offer but the URL can carry and the
   * server will honour, which is exactly how the bad state is reached.
   */
  it('withholds the LAST-page jump when the last page is past the jump ceiling', async () => {
    // 250,000 matches at 300 a page is 834 pages, but the server will only
    // answer an offset up to 100,000 — the deepest page a JUMP can land on
    // starts at match 99,901, page 334. A control labelled "Last page" that
    // went there would name page 334 as the end of a set that runs to page 834,
    // which is the confident wrong answer this pager exists to avoid. The
    // matches past it are reached by walking instead.
    mockPagedSearch({
      '0': pageResponse({ limit: 300, total_count: 250_000 }),
    })
    renderPage(['/cases/c1/search?q=malware&limit=300'])
    await screen.findByText('invoice.docx')

    expect(screen.queryByRole('button', { name: 'Last page' })).toBeNull()
    // And nothing else on the pager asks for an offset the server refuses.
    await userEvent.click(screen.getByRole('button', { name: /Next/ }))
    await waitFor(() => expect(searchRequests.length).toBeGreaterThan(1))
    expect(Number(searchRequests.at(-1)!.get('offset'))).toBeLessThanOrEqual(
      100_000,
    )
  })

  it('offers the LAST-page jump when the whole match set is inside the ceiling', async () => {
    mockPagedSearch({
      '0': pageResponse({ limit: 300, total_count: 900 }),
    })
    renderPage(['/cases/c1/search?q=malware&limit=300'])
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: 'Last page' }))
    await waitFor(() => expect(searchRequests.length).toBeGreaterThan(1))
    expect(searchRequests.at(-1)!.get('offset')).toBe('600')
  })

  it('counts every match into the page total, and says where jumping stops', async () => {
    // The page total describes the RESULT SET: 250,000 matches at 300 a page is
    // 834 pages, and every one of them is reachable — by walking if not by
    // jumping. Capping the total at the jump ceiling used to tell an examiner
    // standing on page 335 that they were past the end of their own evidence.
    //
    // Where jumping stops is a separate claim, and it is still made: with a page
    // size of 300 the deepest jumpable page starts at match 99,901, so jumping
    // stops at match 100,200.
    mockPagedSearch({
      '0': pageResponse({ limit: 300, total_count: 250_000 }),
    })
    renderPage(['/cases/c1/search?q=malware&limit=300'])

    expect(await screen.findByText(/Page 1 of 834/)).toBeInTheDocument()
    expect(
      screen.getByText(/Jumping to a page stops at match 100,200/),
    ).toBeInTheDocument()
    // And it must not read as a wall: those matches are reachable.
    expect(screen.getByText(/Next keeps walking past this point/)).toBeInTheDocument()
  })

  it('points at the export as the way past the jump ceiling, and at its verdict row for coverage', async () => {
    // The export is the obvious next thought for an examiner told that jumping
    // stops here, so the note has to address it — and until the export learned
    // to walk by cursor it addressed it by warning of a ceiling of the export's
    // own. That warning is now false: the export walks the whole match set with
    // no row cap, and its preamble writes `row_limit,none`. Understating the
    // exhibit is as wrong as overstating it, because an examiner reads this
    // note when deciding whether to narrow the query or what to tender.
    //
    // What the note must still not do is state the export's coverage as a fact
    // of THIS response. The depths were never equal — jumping runs to the end
    // of the page containing the ceiling (100,200 here) — and the authority on
    // what an export covered is the verdict row in the file it produced.
    mockPagedSearch({
      '0': pageResponse({ limit: 300, total_count: 250_000 }),
    })
    renderPage(['/cases/c1/search?q=malware&limit=300'])
    await screen.findByText('invoice.docx')

    const note = screen
      .getByText(/Jumping to a page stops at match 100,200/)
      .textContent!.replace(/\s+/g, ' ')
    expect(note).not.toMatch(/same depth/i)
    // The export no longer stops short, and the note must not say it does.
    expect(note).not.toMatch(/ceiling of its own/i)
    expect(note).toMatch(/whole match set/i)
    expect(note).toMatch(/verdict row/i)
    // And the pager's Prev is not the only way backwards, so the note that
    // withdraws it says what still works — the same disclosure the disabled
    // control itself carries.
    expect(note).toMatch(/Back button/)
  })

  it('reads a limit the URL cannot support as the default page size', async () => {
    // `limit` arrives from a hand-edited or shared URL as readily as from the
    // dropdown. A word is not a page size, and forwarding `NaN` to the server
    // buys an error message about a parameter the examiner never typed.
    mockPagedSearch({ '0': pageResponse() })
    renderPage(['/cases/c1/search?q=malware&limit=nonsense'])

    await screen.findByText('invoice.docx')
    expect(searchRequests.at(-1)!.get('limit')).toBe('100')
  })

  it('states the page size in force even when the dropdown does not offer it', async () => {
    // A control that reads 100 while the pages are 300 long is a false claim
    // about the search that produced the rows on screen.
    mockPagedSearch({ '0': pageResponse({ limit: 300 }) })
    renderPage(['/cases/c1/search?q=malware&limit=300'])

    await screen.findByText('invoice.docx')
    expect((screen.getByLabelText('Limit') as HTMLSelectElement).value).toBe(
      '300',
    )
  })
})

describe('SearchPage walking past the jump ceiling', () => {
  // The server answers an `offset` by walking the case from the start, so it
  // caps how deep an offset may go. It used to be the end of the evidence as
  // well: the export ceiling was the same number, so matches past it were
  // unreachable by every route the product had, and this screen said so.
  //
  // A page now also carries `next_cursor`, which names the position the walk
  // reached instead of a distance from the start. These tests pin the two
  // halves of using it: the walk continues past the ceiling, and a cursor the
  // server refuses is shown as an interrupted walk rather than as rows.

  function pageResponse(over: Partial<SearchResponse> = {}): SearchResponse {
    return {
      ...baseResponse,
      total_count: 250_000,
      offset: 0,
      limit: 300,
      max_offset: 100_000,
      index_snapshot: 'aaaaaaaaaaaaaaaa',
      next_cursor: 'c0',
      ...over,
    }
  }

  /**
   * Answer a search from `byOffset` or `byCursor` depending on which position
   * the request names, so a test can watch the client choose a route.
   */
  function mockWalk(
    byOffset: Record<string, SearchResponse>,
    byCursor: Record<
      string,
      | SearchResponse
      | {
          status: number
          body: { error: { code: string; message: string; details?: unknown } }
        }
    > = {},
  ) {
    server.use(
      http.get('/api/v1/cases/c1/search', ({ request }) => {
        const params = new URL(request.url).searchParams
        searchRequests.push(params)
        const cursor = params.get('cursor')
        if (cursor != null && cursor !== '') {
          const answer = byCursor[cursor]
          if (answer == null) return HttpResponse.json(byOffset['0'])
          if ('status' in answer && 'body' in answer) {
            return HttpResponse.json(answer.body, { status: answer.status })
          }
          return HttpResponse.json(answer)
        }
        return HttpResponse.json(
          byOffset[params.get('offset') ?? '0'] ?? byOffset['0'],
        )
      }),
    )
  }

  it('follows the cursor once an offset would be past the ceiling', async () => {
    // Standing on the deepest page an offset can name. The next page along
    // would start at match 100,200, which the server refuses — so Next must
    // hand back the cursor instead, and must not ask for that offset.
    mockWalk(
      { '99900': pageResponse({ offset: 99_900, next_cursor: 'deep-1' }) },
      { 'deep-1': pageResponse({ offset: 100_200, next_cursor: 'deep-2' }) },
    )
    renderPage(['/cases/c1/search?q=malware&limit=300&offset=99900'])
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: /Next/ }))

    await waitFor(() =>
      expect(searchRequests.at(-1)!.get('cursor')).toBe('deep-1'),
    )
    // Never both: the two name different places and the server refuses a
    // request carrying each.
    expect(searchRequests.at(-1)!.get('offset')).toBeNull()
    expect(
      await screen.findByText('Showing matches 100,201–100,202 of 250,000.'),
    ).toBeInTheDocument()
  })

  it('numbers a walked page from what the server served, not from the cursor', async () => {
    mockWalk(
      { '0': pageResponse({ offset: 0, next_cursor: 'c1' }) },
      { c1: pageResponse({ offset: 150_000, next_cursor: 'c2' }) },
    )
    renderPage(['/cases/c1/search?q=malware&limit=300&cursor=c1'])

    // A cursor is opaque; the position on screen comes from the response.
    expect(
      await screen.findByText('Showing matches 150,001–150,002 of 250,000.'),
    ).toBeInTheDocument()
    expect(screen.getByText(/Page 501 of 834/)).toBeInTheDocument()
  })

  it('withholds Prev past the ceiling and says why rather than looking broken', async () => {
    mockWalk({}, { deep: pageResponse({ offset: 150_000, next_cursor: 'd2' }) })
    renderPage(['/cases/c1/search?q=malware&limit=300&cursor=deep'])
    await screen.findByText('invoice.docx')

    const prev = screen.getByRole('button', { name: /Prev/ })
    // A cursor points one way, and the offset that would name the page before
    // this one is past what the server will answer. Offering the control and
    // then being refused would read as a broken page.
    expect(prev).toBeDisabled()
    expect(prev).toHaveAttribute(
      'title',
      expect.stringContaining('cannot be asked for directly'),
    )
    // The way back is still there.
    expect(screen.getByRole('button', { name: 'First page' })).toBeEnabled()
  })

  it('names the route backwards that does work, and does not overstate it', async () => {
    // A disabled control that only says what it cannot do leaves the examiner
    // believing the pages they walked through are gone. They are not: each one
    // was pushed onto this tab's history, so Back returns to a page the server
    // actually served. The title names that route — conditionally, because an
    // examiner who arrived on a shared deep link has no earlier page of hits
    // behind them and must not be sent looking for one.
    mockWalk({}, { deep: pageResponse({ offset: 150_000, next_cursor: 'd2' }) })
    renderPage(['/cases/c1/search?q=malware&limit=300&cursor=deep'])
    await screen.findByText('invoice.docx')

    const title = screen.getByRole('button', { name: /Prev/ }).title
    expect(title).toContain('If you walked here')
    expect(title).toMatch(/Back/)
    // The claim is about pages already served, not about a fresh position: a
    // title promising Back "returns to the previous page" full stop would be
    // wrong for the examiner who opened this URL from a handover note.
    expect(title).toContain('first page')
  })

  it('walks forward past the ceiling, then browser Back returns to the page walked from', async () => {
    // The evidence for the sentence above, and the reason this pager does NOT
    // carry a stack of visited cursors in its URL: the history stack already
    // holds them, one per page actually read, at no cost to the length or the
    // legibility of the link an examiner shares.
    mockWalk(
      { '99900': pageResponse({ offset: 99_900, next_cursor: 'deep-1' }) },
      { 'deep-1': pageResponse({ offset: 100_200, next_cursor: 'deep-2' }) },
    )
    renderPage(['/cases/c1/search?q=malware&limit=300&offset=99900'])
    expect(
      await screen.findByText('Showing matches 99,901–99,902 of 250,000.'),
    ).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Next/ }))
    expect(
      await screen.findByText('Showing matches 100,201–100,202 of 250,000.'),
    ).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'go-back' }))

    // Back on the page that was walked from, by its own offset — the position
    // the pager itself cannot ask for from where the walk had reached.
    expect(
      await screen.findByText('Showing matches 99,901–99,902 of 250,000.'),
    ).toBeInTheDocument()
  })

  it('stops offering Next when the server says the walk ended', async () => {
    // `next_cursor: null` from a server that states the field is a CLAIM that
    // the set ended here, and is trusted over arithmetic against a count the
    // server may have declined to vouch for.
    mockWalk({}, { last: pageResponse({ offset: 200_000, next_cursor: null }) })
    renderPage(['/cases/c1/search?q=malware&limit=300&cursor=last'])
    await screen.findByText('invoice.docx')

    expect(screen.getByRole('button', { name: /Next/ })).toBeDisabled()
  })

  it('shows a refused cursor as an interrupted walk, not as a failed search', async () => {
    // The ordinary way a walk ends on a live case: ingest committed, the
    // enumeration the cursor named no longer exists, and the server refuses
    // rather than serving rows from a re-ordered set under the same page
    // number. What the examiner must NOT see is "Search failed", which reads as
    // a broken product, or worse, a page of rows.
    mockWalk(
      { '0': pageResponse({ offset: 0, next_cursor: 'fresh' }) },
      {
        stale: {
          status: 409,
          body: {
            error: {
              code: 'SEARCH_CURSOR_REFUSED',
              message:
                'the search index changed after this page of results was fetched, so the position this cursor names no longer exists. Start the walk again from the first page',
              details: { refusal: 'index_moved' },
            },
          },
        },
      },
    )
    renderPage(['/cases/c1/search?q=malware&limit=300&cursor=stale'])

    expect(
      await screen.findByText('This page of results can no longer be shown'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/the search index changed after this page/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/Search failed/)).toBeNull()
    expect(screen.queryByText('invoice.docx')).toBeNull()

    // And the one control that is still sound goes back to a coherent start.
    await userEvent.click(
      screen.getByRole('button', { name: 'Go back to the first page' }),
    )
    await waitFor(() => expect(searchRequests.at(-1)!.get('cursor')).toBeNull())
    expect(searchRequests.at(-1)!.get('offset')).toBe('0')
    expect(await screen.findByText('invoice.docx')).toBeInTheDocument()
  })

  it('shows a refused jump as a position that cannot be jumped to, not as the end of the matches', async () => {
    // A jump the extension-filtered routing cannot reach used to come back as
    // an empty page with a floored count — the shape of "you have paged past
    // the end" — and an examiner read it as nothing further to review. The
    // server now refuses it (SHIP-034) with a sentence that says how far a
    // jump reaches and that the match set goes on; the screen must show that
    // sentence, not "Search failed", and must offer the route that reaches.
    mockWalk({ '0': pageResponse({ offset: 0, next_cursor: 'fresh' }) })
    server.use(
      http.get('/api/v1/cases/c1/search', ({ request }) => {
        const params = new URL(request.url).searchParams
        searchRequests.push(params)
        if (params.get('offset') === '600') {
          return HttpResponse.json(
            {
              error: {
                code: 'SEARCH_OFFSET_UNREACHABLE',
                message:
                  "'offset' 600 cannot be reached by a jump on this search. The extension filter runs after retrieval: the server retrieved a window of 4500 candidates ranked by relevance and only 12 of them carried a matching extension, so a jump on this search reaches only those 12 rows and the deepest 'offset' it can be given is 11. This is not the end of the match set — follow the 'next_cursor' each page carries, or use the search export",
                details: {
                  offset: 600,
                  reachable: 12,
                  deepest_offset: 11,
                  examined: 4500,
                  cause: 'extension_post_filter',
                },
              },
            },
            { status: 400 },
          )
        }
        return HttpResponse.json(pageResponse({ offset: 0, next_cursor: 'fresh' }))
      }),
    )
    renderPage(['/cases/c1/search?q=malware&limit=300&offset=600&extensions=txt'])

    expect(
      await screen.findByText('This page cannot be jumped to on this search'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/the deepest 'offset' it can be given is 11/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/Search failed/)).toBeNull()
    expect(screen.queryByText(/Nothing matched/)).toBeNull()
    expect(screen.queryByText('invoice.docx')).toBeNull()

    // The route the refusal names: the first page, from which Next walks.
    await userEvent.click(
      screen.getByRole('button', {
        name: 'Go to the first page and walk from there',
      }),
    )
    await waitFor(() => expect(searchRequests.at(-1)!.get('offset')).toBe('0'))
    expect(await screen.findByText('invoice.docx')).toBeInTheDocument()
  })

  it('exports the match set, never the position the walk had reached', async () => {
    // An export is of the MATCH SET. Handing it the cursor for the page on
    // screen would produce an exhibit that begins at match 150,001 and says
    // nothing about the 150,000 before it — a file that looks complete and is
    // not, which is the worst shape an exhibit can take.
    mockWalk({}, { deep: pageResponse({ offset: 150_000, next_cursor: 'd2' }) })
    renderPage(['/cases/c1/search?q=malware&limit=300&cursor=deep'])
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: 'Export CSV' }))

    const query = vi.mocked(downloadFile).mock.calls.at(-1)![2]!.query as Record<
      string,
      unknown
    >
    expect(query.cursor).toBeUndefined()
    expect(query.offset).toBeUndefined()
    expect(query.q).toBe('malware')
  })

  it('a jump abandons the walk rather than asking for two positions at once', async () => {
    mockWalk(
      { '0': pageResponse({ offset: 0, next_cursor: 'c1' }) },
      { deep: pageResponse({ offset: 150_000, next_cursor: 'd2' }) },
    )
    renderPage(['/cases/c1/search?q=malware&limit=300&cursor=deep'])
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: 'First page' }))

    await waitFor(() => expect(searchRequests.at(-1)!.get('cursor')).toBeNull())
    // The first page by its plain name, and nothing left over from the walk.
    expect(searchRequests.at(-1)!.get('offset')).toBe('0')
  })

  it('paging inside the ceiling still uses plain offsets, so links stay legible', async () => {
    // The cursor is the instrument for the deep end, not a replacement for the
    // shareable position. A page reached inside the ceiling keeps a URL another
    // examiner can read, hand-edit and quote in a handover.
    mockWalk({
      '0': pageResponse({ offset: 0, next_cursor: 'c1' }),
      '300': pageResponse({ offset: 300, next_cursor: 'c2' }),
    })
    renderPage(['/cases/c1/search?q=malware&limit=300'])
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: /Next/ }))

    await waitFor(() => expect(searchRequests.at(-1)!.get('offset')).toBe('300'))
    expect(searchRequests.at(-1)!.get('cursor')).toBeNull()
  })
})

describe('SearchPage paging across an index that moved', () => {
  function pageResponse(over: Partial<SearchResponse> = {}): SearchResponse {
    return {
      ...baseResponse,
      total_count: 250,
      offset: 0,
      limit: 2,
      max_offset: 100_000,
      index_snapshot: 'aaaaaaaaaaaaaaaa',
      ...over,
    }
  }

  function mockPagedSearch(pages: Record<string, SearchResponse>) {
    server.use(
      http.get('/api/v1/cases/c1/search', ({ request }) => {
        const params = new URL(request.url).searchParams
        searchRequests.push(params)
        return HttpResponse.json(
          pages[params.get('offset') ?? '0'] ?? pages['0'],
        )
      }),
    )
  }

  it('says so when the pages no longer come from one index', async () => {
    // The ordering a page boundary rests on is the index's own physical layout,
    // and ingest committing new documents — or the display-name repair
    // rewriting existing ones — re-lays it. Page 2 of the new index does not
    // continue page 1 of the old one: rows can repeat across the seam and rows
    // can fall through it. Nothing on the client can prevent that; what it can
    // do is refuse to present two enumerations as one walk.
    mockPagedSearch({
      '0': pageResponse(),
      '2': pageResponse({
        offset: 2,
        index_snapshot: 'bbbbbbbbbbbbbbbb',
        results: [
          {
            artifact_id: 'a101',
            case_id: 'c1',
            artifact_type: 'FileEntry',
            name: 'match-3.txt',
            snippet: null,
            highlights: null,
            score: 1,
          },
        ],
      }),
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: /Next/ }))

    expect(
      await screen.findByText(/index changed while you were paging/i),
    ).toBeInTheDocument()
  })

  it('is silent while every page comes from the same index', async () => {
    mockPagedSearch({
      '0': pageResponse(),
      '2': pageResponse({ offset: 2 }),
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    await userEvent.click(screen.getByRole('button', { name: /Next/ }))

    await waitFor(() => expect(searchRequests.at(-1)!.get('offset')).toBe('2'))
    expect(
      screen.queryByText(/index changed while you were paging/i),
    ).toBeNull()
  })

  it('clears the warning once the examiner restarts from page 1', async () => {
    mockPagedSearch({
      '0': pageResponse(),
      '2': pageResponse({ offset: 2, index_snapshot: 'bbbbbbbbbbbbbbbb' }),
    })
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')
    await userEvent.click(screen.getByRole('button', { name: /Next/ }))
    await screen.findByText(/index changed while you were paging/i)

    // Page 1 of whatever the index is now is a coherent start in its own
    // right: the warning is about a walk that crossed a seam, not a permanent
    // mark on the query.
    await userEvent.click(screen.getByRole('button', { name: 'First page' }))

    await screen.findByText('Showing matches 1–2 of 250.')
    expect(
      screen.queryByText(/index changed while you were paging/i),
    ).toBeNull()
  })
})

describe('SearchPage results keyboard navigation', () => {
  it('is one tab stop for the whole table, with the arrows moving focus', async () => {
    mockSearch()
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    const rows = screen
      .getAllByRole('row')
      .filter((row) => row.querySelector('td') != null)
    expect(rows).toHaveLength(2)
    // Exactly one row is tabbable; the rest are reachable only by arrowing.
    expect(rows.map((r) => r.getAttribute('tabindex'))).toEqual(['0', '-1'])
    // The link inside is out of the tab order too, or the table would be back
    // to one tab stop per row — which is what the roving hook removes.
    expect(screen.getByRole('link', { name: 'invoice.docx' })).toHaveAttribute(
      'tabindex',
      '-1',
    )

    rows[0].focus()
    await userEvent.keyboard('{ArrowDown}')
    expect(rows[1]).toHaveFocus()
    await userEvent.keyboard('{ArrowUp}')
    expect(rows[0]).toHaveFocus()
    await userEvent.keyboard('{End}')
    expect(rows[1]).toHaveFocus()
  })

  it('opens the focused hit on Enter', async () => {
    mockSearch()
    renderPage()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    const rows = screen
      .getAllByRole('row')
      .filter((row) => row.querySelector('td') != null)
    rows[1].focus()
    await userEvent.keyboard('{Enter}')

    expect(await screen.findByTestId('where')).toHaveTextContent(
      '/cases/c1/artifacts/a2',
    )
  })
})

describe('SearchPage event stream', () => {
  it('watches the repair on the tab’s shared connection, not a second one', async () => {
    // Browsers cap concurrent connections per origin at about six. A second
    // EventSource per open case tab spends that budget on duplicates of one
    // broadcast, and the tab that loses the race shows a run state nothing is
    // updating.
    renderPage()
    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1))
    emitRepairProgress()
    expect(
      await screen.findByText(/1,234 of 93,338 documents/),
    ).toBeInTheDocument()
    expect(MockEventSource.instances).toHaveLength(1)
    expect(MockEventSource.instances[0].url).toBe('/api/v1/events')
  })
})

describe('SearchPage while the case is still processing', () => {
  /** Render the page inside a live processing context, as the case shell does. */
  function renderWithProcessing() {
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    return render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/cases/c1/search']}>
            <ProcessingProvider caseId="c1">
              <Routes>
                <Route path="/cases/:caseId/search" element={<SearchPage />} />
              </Routes>
            </ProcessingProvider>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )
  }

  /** Put the case into a running state, the way an ingest does. */
  function startProcessing() {
    const source =
      MockEventSource.instances[MockEventSource.instances.length - 1]
    act(() => {
      source.emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'c1',
        phase: 'Analysis',
        artifact_type: 'FileEntry',
      })
    })
  }

  it('calls the results a floor while the index is still being written', async () => {
    // The most common incompleteness of all is time. A detective who searches
    // eight minutes into ingest and writes down "12 results" has recorded a
    // number that was never a finding — the corpus was still growing.
    mockSearch()
    renderWithProcessing()
    await waitFor(() =>
      expect(MockEventSource.instances.length).toBeGreaterThan(0),
    )
    startProcessing()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    expect(
      screen.getByText(/index behind these results is still growing/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/an absence below is not evidence of absence/),
    ).toBeInTheDocument()
  })

  it('says nothing of the sort on an idle case', async () => {
    // A page that always warned would teach the examiner to stop reading it.
    mockSearch()
    renderWithProcessing()
    await userEvent.type(
      screen.getByLabelText('Search query'),
      'malware{Enter}',
    )
    await screen.findByText('invoice.docx')

    expect(screen.queryByText(/still growing/)).toBeNull()
  })
})

describe('a running backfill is announced to everyone on the case', () => {
  // LIVE-028's progress was published on `search.index_backfill` and nothing
  // consumed it, so a colleague reading results while a multi-hour sweep added
  // documents under them was told nothing. The banner reads both passes, and
  // says the right thing about each: the repair rewrites names, the backfill
  // adds documents.
  it('names the backfill, counts artifacts, and says what it adds', async () => {
    const { container } = renderPage()
    await waitFor(() =>
      expect(container.querySelector('.srch-repair')).not.toBeNull(),
    )
    emitRepairProgress({
      module_id: 'search.index_backfill',
      units_done: 12_000,
      units_total: 580_394,
      unit: 'artifacts',
    })
    const note = await screen.findByText(/A search-index backfill is running/)
    expect(note.textContent).toMatch(/12,000 of 580,394 artifacts/)
    expect(note.textContent).toMatch(/metadata only/)
  })
})
