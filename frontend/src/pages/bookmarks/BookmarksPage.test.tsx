import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { BookmarkCategory, BookmarkWithArtifact } from '../../api/types'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import { FrameSpy } from '../../test/frames'
import { BookmarksPage } from './BookmarksPage'

const CATEGORIES: BookmarkCategory[] = [
  {
    id: 'cat-1',
    case_id: 'case-1',
    name: 'Key Evidence',
    color: '#e05c5c',
    created_at: 1700000000,
    bookmark_count: 1,
  },
  {
    id: 'cat-2',
    case_id: 'case-1',
    name: 'Follow Up',
    color: '#5b9fd4',
    created_at: 1700000001,
    bookmark_count: 0,
  },
]

const BOOKMARKS: BookmarkWithArtifact[] = [
  {
    bookmark: {
      id: 'bm-1',
      case_id: 'case-1',
      artifact_id: 'art-1',
      category_id: 'cat-1',
      category_name: 'Key Evidence',
      category_color: '#e05c5c',
      note: 'Suspicious prefetch entry',
      examiner: 'alice',
      created_at: 1767225600, // 2026-01-01 00:00:00 UTC
      updated_at: 1767225600,
    },
    artifact_type: 'SystemArtifact',
    artifact_name: 'CALC.EXE-1234.pf',
  },
  {
    bookmark: {
      id: 'bm-2',
      case_id: 'case-1',
      artifact_id: 'art-2',
      category_id: null,
      category_name: null,
      category_color: null,
      note: null,
      examiner: 'bob',
      created_at: 1767312000,
      updated_at: 1767312000,
    },
    artifact_type: 'FileEntry',
    artifact_name: 'passwords.txt',
  },
]

function mockApi(bookmarks: BookmarkWithArtifact[] = BOOKMARKS) {
  server.use(
    http.get('/api/v1/cases/case-1/bookmarks/categories', () =>
      HttpResponse.json(CATEGORIES),
    ),
    http.get('/api/v1/cases/case-1/bookmarks', ({ request }) => {
      const category = new URL(request.url).searchParams.get('category')
      if (category) {
        return HttpResponse.json({
          items: bookmarks.filter((b) => b.bookmark.category_id === category),
        })
      }
      return HttpResponse.json({ items: bookmarks })
    }),
  )
}

/**
 * The case's review ledger, which the page's coverage panel reads from the
 * server.
 *
 * Stated here rather than left to a base handler: msw runs with
 * `onUnhandledRequest: "error"`, so every request a page makes is a request the
 * test file names. Registered by `renderPage` because every test renders the
 * panel.
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
  )
}

/** Switches the `:caseId` route param in place, without remounting the page. */
function CaseSwitcher() {
  const navigate = useNavigate()
  return (
    <button type="button" onClick={() => navigate('/cases/case-2/bookmarks')}>
      Go to case-2
    </button>
  )
}

function renderPage(frames: string[] = []) {
  mockReviewLedger()
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/case-1/bookmarks']}>
          <Routes>
            <Route
              path="/cases/:caseId/bookmarks"
              element={
                <>
                  <BookmarksPage />
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

describe('BookmarksPage', () => {
  it('renders the category rail and bookmark table with artifact links', async () => {
    mockApi()
    renderPage()
    expect(screen.getByLabelText(/loading/i)).toBeInTheDocument()

    // Rail
    expect(
      await screen.findByRole('button', { name: /^Key Evidence/ }),
    ).toBeInTheDocument()
    expect(screen.getByText('Follow Up')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^All/ })).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Uncategorized/ }),
    ).toBeInTheDocument()

    // Table: artifact name must link to the artifact page
    const link = await screen.findByRole('link', { name: 'CALC.EXE-1234.pf' })
    expect(link).toHaveAttribute('href', '/cases/case-1/artifacts/art-1')
    expect(screen.getByText('SystemArtifact')).toBeInTheDocument()
    expect(screen.getByText('Suspicious prefetch entry')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('2026-01-01 00:00:00 UTC')).toBeInTheDocument()
  })

  it('filters by category and by uncategorized', async () => {
    mockApi()
    renderPage()
    await screen.findByText('passwords.txt')

    // Category filter hits the API with the category param
    await userEvent.click(
      screen.getByRole('button', { name: /^Key Evidence/ }),
    )
    await waitFor(() =>
      expect(screen.queryByText('passwords.txt')).not.toBeInTheDocument(),
    )
    expect(screen.getByText('CALC.EXE-1234.pf')).toBeInTheDocument()

    // Uncategorized filters client-side for category_id null
    await userEvent.click(
      screen.getByRole('button', { name: /Uncategorized/ }),
    )
    expect(await screen.findByText('passwords.txt')).toBeInTheDocument()
    expect(screen.queryByText('CALC.EXE-1234.pf')).not.toBeInTheDocument()
  })

  it('edits a bookmark note and category', async () => {
    mockApi()
    let updateBody: Record<string, unknown> | null = null
    server.use(
      http.put('/api/v1/cases/case-1/bookmarks/art-2', async ({ request }) => {
        updateBody = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({
          ...BOOKMARKS[1].bookmark,
          category_id: 'cat-2',
          note: 'now noted',
        })
      }),
    )
    renderPage()
    await screen.findByText('passwords.txt')

    await userEvent.click(
      screen.getByRole('button', { name: 'Edit bookmark for passwords.txt' }),
    )
    const dialog = screen.getByRole('dialog')
    await userEvent.selectOptions(
      within(dialog).getByLabelText(/category/i),
      'cat-2',
    )
    await userEvent.type(within(dialog).getByLabelText(/note/i), 'now noted')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(updateBody).toEqual({ category_id: 'cat-2', note: 'now noted' }),
    )
  })

  it('removes a bookmark after confirmation', async () => {
    let deleted = false
    server.use(
      http.get('/api/v1/cases/case-1/bookmarks/categories', () =>
        HttpResponse.json(CATEGORIES),
      ),
      http.get('/api/v1/cases/case-1/bookmarks', () =>
        HttpResponse.json({ items: deleted ? [BOOKMARKS[0]] : BOOKMARKS }),
      ),
      http.delete('/api/v1/cases/case-1/bookmarks/art-2', () => {
        deleted = true
        return HttpResponse.json({ success: true })
      }),
    )
    renderPage()
    await screen.findByText('passwords.txt')

    await userEvent.click(
      screen.getByRole('button', { name: 'Remove bookmark for passwords.txt' }),
    )
    const dialog = screen.getByRole('dialog')
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Remove' }),
    )
    await waitFor(() =>
      expect(screen.queryByText('passwords.txt')).not.toBeInTheDocument(),
    )
    expect(deleted).toBe(true)
  })

  it('refreshes the case the delete was sent to, not the one on screen (B6-030)', async () => {
    // The page outlives a `:caseId` change and `onSuccess` runs in the latest
    // render's closure. Reading `caseId` there refreshed case B's bookmarks
    // while case A — the one the row was deleted from — kept showing it.
    let release: (() => void) | null = null
    const inFlight = new Promise<void>((resolve) => {
      release = resolve
    })
    mockApi()
    server.use(
      http.get('/api/v1/cases/case-2/bookmarks/categories', () =>
        HttpResponse.json([]),
      ),
      http.get('/api/v1/cases/case-2/bookmarks', () =>
        HttpResponse.json({ items: [] }),
      ),
      http.delete('/api/v1/cases/case-1/bookmarks/art-2', async () => {
        await inFlight
        return HttpResponse.json({ success: true })
      }),
    )

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const invalidated: unknown[][] = []
    const realInvalidate = queryClient.invalidateQueries.bind(queryClient)
    queryClient.invalidateQueries = ((filters?: { queryKey?: unknown[] }) => {
      if (filters?.queryKey) invalidated.push(filters.queryKey)
      return realInvalidate(filters as never)
    }) as typeof queryClient.invalidateQueries

    render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/cases/case-1/bookmarks']}>
            <Routes>
              <Route
                path="/cases/:caseId/bookmarks"
                element={
                  <>
                    <BookmarksPage />
                    <CaseSwitcher />
                  </>
                }
              />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )
    await screen.findByText('passwords.txt')
    await userEvent.click(
      screen.getByRole('button', { name: 'Remove bookmark for passwords.txt' }),
    )
    await userEvent.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove' }),
    )

    // Switch cases while the delete is in flight, then let it land.
    await userEvent.click(
      screen.getByRole('button', { name: 'Go to case-2' }),
    )
    release!()

    await waitFor(() =>
      expect(invalidated).toContainEqual(['bookmarks', 'case-1']),
    )
    expect(invalidated).not.toContainEqual(['bookmarks', 'case-2'])
  })

  it('shows a nested folder indented under its parent', async () => {
    const nested: BookmarkCategory[] = [
      ...CATEGORIES,
      {
        id: 'cat-3',
        case_id: 'case-1',
        name: 'Prefetch',
        color: '#00ff00',
        created_at: 1700000002,
        bookmark_count: 0,
        parent_id: 'cat-1',
      },
    ]
    server.use(
      http.get('/api/v1/cases/case-1/bookmarks/categories', () =>
        HttpResponse.json(nested),
      ),
      http.get('/api/v1/cases/case-1/bookmarks', () =>
        HttpResponse.json({ items: BOOKMARKS }),
      ),
    )
    renderPage()
    const child = await screen.findByRole('button', { name: /^Prefetch/ })
    const parent = screen.getByRole('button', { name: /^Key Evidence/ })
    // The child's row sits directly after its parent's, one level in.
    const rows = Array.from(document.querySelectorAll('.bm-cat-row'))
    const at = (el: HTMLElement) => rows.findIndex((r) => r.contains(el))
    expect(at(child)).toBe(at(parent) + 1)
    expect(child.closest('.bm-cat-row')).toHaveAttribute('data-depth', '1')
    expect(parent.closest('.bm-cat-row')).toHaveAttribute('data-depth', '0')
  })

  it('creates a category under a chosen parent folder', async () => {
    mockApi()
    let createBody: Record<string, unknown> | null = null
    server.use(
      http.post(
        '/api/v1/cases/case-1/bookmarks/categories',
        async ({ request }) => {
          createBody = (await request.json()) as Record<string, unknown>
          return HttpResponse.json({
            id: 'cat-3',
            case_id: 'case-1',
            name: 'Prefetch',
            color: '#00ff00',
            created_at: 1700000002,
            parent_id: 'cat-1',
          })
        },
      ),
    )
    renderPage()
    await screen.findByRole('button', { name: /^Key Evidence/ })

    await userEvent.click(screen.getByRole('button', { name: 'New category' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Name'), 'Prefetch')
    await userEvent.selectOptions(
      within(dialog).getByLabelText(/parent folder/i),
      'cat-1',
    )
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Create' }),
    )
    await waitFor(() => expect(createBody).not.toBeNull())
    expect(createBody).toMatchObject({ name: 'Prefetch', parent_id: 'cat-1' })
  })

  it('omits the parent when none is chosen (a top-level folder)', async () => {
    mockApi()
    let createBody: Record<string, unknown> | null = null
    server.use(
      http.post(
        '/api/v1/cases/case-1/bookmarks/categories',
        async ({ request }) => {
          createBody = (await request.json()) as Record<string, unknown>
          return HttpResponse.json({
            id: 'cat-3',
            case_id: 'case-1',
            name: 'Malware',
            color: '#00ff00',
            created_at: 1700000002,
          })
        },
      ),
    )
    renderPage()
    await screen.findByRole('button', { name: /^Key Evidence/ })
    await userEvent.click(screen.getByRole('button', { name: 'New category' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Name'), 'Malware')
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Create' }),
    )
    await waitFor(() => expect(createBody).not.toBeNull())
    expect(createBody).not.toHaveProperty('parent_id')
  })

  it('creates a category', async () => {
    mockApi()
    let createBody: Record<string, unknown> | null = null
    server.use(
      http.post(
        '/api/v1/cases/case-1/bookmarks/categories',
        async ({ request }) => {
          createBody = (await request.json()) as Record<string, unknown>
          return HttpResponse.json({
            id: 'cat-3',
            case_id: 'case-1',
            name: 'Malware',
            color: '#00ff00',
            created_at: 1700000002,
          })
        },
      ),
    )
    renderPage()
    await screen.findByRole('button', { name: /^Key Evidence/ })

    await userEvent.click(screen.getByRole('button', { name: 'New category' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Name'), 'Malware')
    // The color input keeps its default; only the name is asserted below.
    expect(within(dialog).getByLabelText(/color/i)).toBeInTheDocument()
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Create' }),
    )
    await waitFor(() => expect(createBody).not.toBeNull())
    expect(createBody).toMatchObject({ name: 'Malware' })
  })

  it('shows the empty state when nothing is bookmarked', async () => {
    server.use(
      http.get('/api/v1/cases/case-1/bookmarks/categories', () =>
        HttpResponse.json([]),
      ),
      http.get('/api/v1/cases/case-1/bookmarks', () =>
        HttpResponse.json({ items: [] }),
      ),
    )
    renderPage()
    expect(await screen.findByText(/artifact viewer/i)).toBeInTheDocument()
  })

  it('resets the category selection when the case changes (BUG-262)', async () => {
    // A category UUID only exists inside its own case. Carrying case A's
    // selection into case B queries listBookmarks(case-B, categoryFromA), which
    // matches nothing — the examiner is shown an empty list for a case that
    // does have bookmarks.
    mockApi()
    const case2Categories: string[] = []
    server.use(
      http.get('/api/v1/cases/case-2/bookmarks/categories', () =>
        HttpResponse.json([]),
      ),
      http.get('/api/v1/cases/case-2/bookmarks', ({ request }) => {
        const category = new URL(request.url).searchParams.get('category')
        case2Categories.push(category ?? '')
        // Case B's bookmarks are only returned for an unfiltered request.
        if (category) return HttpResponse.json({ items: [] })
        return HttpResponse.json({ items: [
          {
            bookmark: {
              id: 'bm-9',
              case_id: 'case-2',
              artifact_id: 'art-9',
              category_id: null,
              category_name: null,
              category_color: null,
              note: null,
              examiner: 'carol',
              created_at: 1767225600,
              updated_at: 1767225600,
            },
            artifact_type: 'FileEntry',
            artifact_name: 'caseB-evidence.txt',
          },
        ] })
      }),
    )
    renderPage()
    await screen.findByText('passwords.txt')
    await userEvent.click(screen.getByRole('button', { name: /^Key Evidence/ }))
    await waitFor(() =>
      expect(screen.queryByText('passwords.txt')).not.toBeInTheDocument(),
    )

    await userEvent.click(screen.getByRole('button', { name: 'Go to case-2' }))

    expect(await screen.findByText('caseB-evidence.txt')).toBeInTheDocument()
    // Every case-2 request must be unfiltered: no category id leaked across.
    expect(case2Categories).not.toContain('cat-1')
  })

  it('paints no frame with case 1 remove dialog under case 2 (BUG-262)', async () => {
    // Closing the modals from a `useEffect` runs after the commit that already
    // reads case 2. That commit paints "Remove the bookmark for
    // 'passwords.txt'?" — a case-1 row — over case 2, and Remove pressed on
    // that frame deletes through case 2's endpoint. Passive effects are flushed
    // before `click` returns, so only a layout-effect snapshot sees the frame.
    mockApi()
    server.use(
      http.get('/api/v1/cases/case-2/bookmarks/categories', () =>
        HttpResponse.json([]),
      ),
      http.get('/api/v1/cases/case-2/bookmarks', () => HttpResponse.json([])),
    )
    const frames: string[] = []
    renderPage(frames)
    await screen.findByText('passwords.txt')
    await userEvent.click(
      screen.getByRole('button', {
        name: 'Remove bookmark for passwords.txt',
      }),
    )
    expect(await screen.findByRole('dialog')).toHaveAccessibleName(
      'Remove bookmark',
    )

    frames.length = 0
    await userEvent.click(screen.getByRole('button', { name: 'Go to case-2' }))
    // Wait for the commits that read case 2 to have actually landed. Asserting
    // straight after the click inspects an empty list and passes vacuously,
    // which is the failure mode the length check below exists to catch.
    await waitFor(() => expect(frames.length).toBeGreaterThan(0))
    for (const frame of frames) {
      expect(frame).not.toContain('Remove bookmark')
    }
  })

  it('shows an error state when bookmarks fail to load', async () => {
    server.use(
      http.get('/api/v1/cases/case-1/bookmarks/categories', () =>
        HttpResponse.json([]),
      ),
      http.get('/api/v1/cases/case-1/bookmarks', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'bookmarks broke' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    expect(await screen.findByText(/bookmarks broke/)).toBeInTheDocument()
  })
})

describe('the review ledger on the bookmarks page', () => {
  it('answers "what has anyone looked at", and says whose answer it is', async () => {
    mockApi()
    renderPage()

    const panel = await screen.findByRole('region', { name: /review ledger/i })
    // The ledger is the case's now, and the panel says who can see a mark and
    // whose name is on it. The two sentences this replaces described a
    // browser-local ledger honestly; once the ledger moved to the server they
    // became a false reassurance, which is worse than the gap they described.
    expect(panel.textContent).toMatch(/stored with the case on the server/i)
    expect(panel.textContent).toMatch(/every examiner with access to this case/i)
    expect(panel.textContent).toMatch(
      /filed under the name of the examiner who was signed in/i,
    )
    // And an empty ledger has inverted its meaning: it used to say only that
    // this browser held no record, and now it is a claim about the whole case.
    expect(panel.textContent).toMatch(
      /an empty ledger is a claim about the whole case/i,
    )
    expect(panel.textContent).not.toMatch(/this browser only/i)
    // Two counts, two claims, and no proportion of a population nobody counted.
    expect(panel.textContent).toMatch(/marked reviewed/i)
    expect(panel.textContent).toMatch(/opened at least once/i)
    expect(panel.textContent).not.toMatch(/%/)
  })
})
