import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { ToastProvider } from '../../components/toast/ToastProvider'
import type { HashSetInfo } from '../../api/types'
import type { HashHit } from './api'
import { HashSetsPage } from './HashSetsPage'

const CASE_ID = 'case-1'

// 1700000000 -> 2023-11-14 22:13:20 UTC
const baseSets: HashSetInfo[] = [
  {
    id: 'hs-1',
    case_id: CASE_ID,
    name: 'NSRL Known',
    description: 'OS baseline files',
    set_type: 'known',
    hash_algorithm: 'sha1',
    entry_count: 1200,
    imported_at: 1700000000,
  },
  {
    id: 'hs-2',
    case_id: CASE_ID,
    name: 'Malware IOCs',
    description: null,
    set_type: 'notable',
    hash_algorithm: 'md5',
    entry_count: 42,
    imported_at: 1700000000,
  },
]

let sets: HashSetInfo[]

beforeEach(() => {
  sets = baseSets.map((s) => ({ ...s }))
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/hash_sets`, () =>
      HttpResponse.json(sets),
    ),
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
        <MemoryRouter initialEntries={[`/cases/${CASE_ID}/hash-sets`]}>
          <Routes>
            <Route
              path="/cases/:caseId/hash-sets"
              element={<HashSetsPage />}
            />
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
    <button type="button" onClick={() => navigate('/cases/case-2/hash-sets')}>
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
        <MemoryRouter initialEntries={[`/cases/${CASE_ID}/hash-sets`]}>
          <CaseSwitcher />
          <Routes>
            <Route path="/cases/:caseId/hash-sets" element={<HashSetsPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

function makeHit(i: number, setId: string): HashHit {
  return {
    artifact_id: `art-${setId}-${i}`,
    name: `file-${setId}-${i}.exe`,
    path: `/evidence/windows/system32/file-${setId}-${i}.exe`,
    hash_set_id: setId,
    hash_set_name: setId === 'hs-1' ? 'NSRL Known' : 'Malware IOCs',
    matched_hash: `${'ab'.repeat(19)}${String(i).padStart(2, '0')}`,
    algorithm: setId === 'hs-1' ? 'sha1' : 'md5',
  }
}

interface HitRequest {
  hash_set_id: string | null
  page: string | null
  page_size: string | null
}

function mockHits(total: number) {
  const hitRequests: HitRequest[] = []
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/hash_hits`, ({ request }) => {
      const url = new URL(request.url)
      const setId = url.searchParams.get('hash_set_id')
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 50)
      hitRequests.push({
        hash_set_id: setId,
        page: url.searchParams.get('page'),
        page_size: url.searchParams.get('page_size'),
      })
      const start = (page - 1) * pageSize
      const count = Math.max(Math.min(pageSize, total - start), 0)
      return HttpResponse.json({
        hits: Array.from({ length: count }, (_, i) =>
          makeHit(start + i, setId ?? 'hs-1'),
        ),
        total,
        page,
        page_size: pageSize,
      })
    }),
  )
  return hitRequests
}

/**
 * Minimal XMLHttpRequest stand-in so upload progress events and the
 * response can be driven from the test.
 */
class FakeXhr {
  static instances: FakeXhr[] = []
  method = ''
  url = ''
  headers: Record<string, string> = {}
  body: FormData | null = null
  status = 0
  responseText = ''
  private listeners: Record<string, ((ev: unknown) => void)[]> = {}
  upload = {
    listeners: {} as Record<string, ((ev: unknown) => void)[]>,
    addEventListener(type: string, cb: (ev: unknown) => void) {
      ;(this.listeners[type] ??= []).push(cb)
    },
  }

  constructor() {
    FakeXhr.instances.push(this)
  }

  open(method: string, url: string) {
    this.method = method
    this.url = url
  }

  setRequestHeader(key: string, value: string) {
    this.headers[key] = value
  }

  addEventListener(type: string, cb: (ev: unknown) => void) {
    ;(this.listeners[type] ??= []).push(cb)
  }

  send(body: FormData) {
    this.body = body
  }

  emitUploadProgress(loaded: number, total: number) {
    for (const cb of this.upload.listeners['progress'] ?? []) {
      cb({ lengthComputable: true, loaded, total })
    }
  }

  respond(status: number, text: string) {
    this.status = status
    this.responseText = text
    for (const cb of this.listeners['load'] ?? []) cb({})
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
  FakeXhr.instances = []
})

describe('HashSetsPage', () => {
  it('renders hash sets with type badges, algorithm and import date', async () => {
    renderPage()
    expect(screen.getByLabelText(/loading/i)).toBeInTheDocument()
    expect(await screen.findByText('NSRL Known')).toBeInTheDocument()
    expect(screen.getByText('Known good')).toBeInTheDocument()
    expect(screen.getByText('Notable')).toBeInTheDocument()
    expect(screen.getByText('SHA1')).toBeInTheDocument()
    expect(screen.getByText('MD5')).toBeInTheDocument()
    expect(screen.getAllByText('2023-11-14 22:13:20 UTC')).toHaveLength(2)
    expect(screen.getByText('OS baseline files')).toBeInTheDocument()
  })

  it('shows an error state when the list fails', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/hash_sets`, () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    expect(await screen.findByText(/boom/)).toBeInTheDocument()
  })

  it('creates a hash set and refreshes the list', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.post(`/api/v1/cases/${CASE_ID}/hash_sets`, async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        sets.push({
          id: 'hs-3',
          case_id: CASE_ID,
          name: String(body.name),
          description: null,
          set_type: String(body.set_type),
          hash_algorithm: String(body.hash_algorithm),
          entry_count: 0,
          imported_at: 1700000000,
        })
        return HttpResponse.json({ id: 'hs-3', status: 'created' })
      }),
    )
    renderPage()
    await screen.findByText('NSRL Known')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'New hash set' }))
    const dialog = screen.getByRole('dialog', { name: 'New hash set' })
    expect(
      within(dialog).getByRole('button', { name: 'Create' }),
    ).toBeDisabled()
    await user.type(within(dialog).getByLabelText(/name/i), 'Project IOCs')
    await user.selectOptions(
      within(dialog).getByLabelText(/type/i),
      'notable',
    )
    await user.selectOptions(
      within(dialog).getByLabelText(/algorithm/i),
      'sha256',
    )
    await user.click(within(dialog).getByRole('button', { name: 'Create' }))

    expect(await screen.findByText('Project IOCs')).toBeInTheDocument()
    expect(body).toMatchObject({
      name: 'Project IOCs',
      set_type: 'notable',
      hash_algorithm: 'sha256',
    })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('imports a file over XHR with upload progress and reports the result', async () => {
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    renderPage()
    await screen.findByText('NSRL Known')

    const user = userEvent.setup()
    const row = screen.getByText('NSRL Known').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Import' }))

    const dialog = screen.getByRole('dialog', { name: /import/i })
    expect(within(dialog).getByText(/NSRL RDS/)).toBeInTheDocument()
    const input = within(dialog).getByLabelText(/hash file/i)
    expect(input).toHaveAttribute('accept', '.csv,.txt')
    expect(
      within(dialog).getByRole('button', { name: 'Import' }),
    ).toBeDisabled()

    const file = new File(['aabbcc\nddeeff\n'], 'hashes.csv', {
      type: 'text/csv',
    })
    await user.upload(input, file)
    await user.click(within(dialog).getByRole('button', { name: 'Import' }))

    await waitFor(() => expect(FakeXhr.instances).toHaveLength(1))
    const xhr = FakeXhr.instances[0]
    expect(xhr.method).toBe('POST')
    expect(xhr.url).toBe(`/api/v1/cases/${CASE_ID}/hash_sets/hs-1/import`)
    expect(xhr.body).toBeInstanceOf(FormData)
    const sent = xhr.body!.get('file')
    expect(sent).toBeInstanceOf(File)
    expect((sent as File).name).toBe('hashes.csv')

    // Upload progress events drive the modal's progress bar.
    const bar = within(dialog).getByRole('progressbar', {
      name: 'Upload progress',
    })
    expect(bar).toHaveAttribute('aria-valuenow', '0')
    act(() => xhr.emitUploadProgress(3, 10))
    expect(bar).toHaveAttribute('aria-valuenow', '30')
    act(() => xhr.emitUploadProgress(10, 10))
    expect(bar).toHaveAttribute('aria-valuenow', '100')

    act(() =>
      xhr.respond(200, JSON.stringify({ imported: 5, total_parsed: 6 })),
    )
    expect(
      await screen.findByText(/Imported 5 of 6 parsed hashes/),
    ).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('surfaces upload failures from the XHR response', async () => {
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    renderPage()
    await screen.findByText('NSRL Known')

    const user = userEvent.setup()
    const row = screen.getByText('NSRL Known').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Import' }))
    const dialog = screen.getByRole('dialog', { name: /import/i })
    await user.upload(
      within(dialog).getByLabelText(/hash file/i),
      new File(['x'], 'hashes.csv', { type: 'text/csv' }),
    )
    await user.click(within(dialog).getByRole('button', { name: 'Import' }))

    await waitFor(() => expect(FakeXhr.instances).toHaveLength(1))
    act(() =>
      FakeXhr.instances[0].respond(
        400,
        JSON.stringify({ error: { code: 'BAD', message: 'not a hash list' } }),
      ),
    )
    expect(await screen.findByText('not a hash list')).toBeInTheDocument()
  })

  it('deletes a hash set after confirmation', async () => {
    let deleted = false
    server.use(
      http.delete(`/api/v1/cases/${CASE_ID}/hash_sets/hs-2`, () => {
        deleted = true
        sets = sets.filter((s) => s.id !== 'hs-2')
        return HttpResponse.json({ status: 'deleted' })
      }),
    )
    renderPage()
    await screen.findByText('Malware IOCs')

    const user = userEvent.setup()
    const row = screen.getByText('Malware IOCs').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Delete' }))

    const dialog = screen.getByRole('dialog', { name: /delete/i })
    expect(within(dialog).getByText(/Malware IOCs/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))

    expect(await screen.findByText(/deleted/i)).toBeInTheDocument()
    expect(deleted).toBe(true)
    expect(screen.queryByText('Malware IOCs')).not.toBeInTheDocument()
  })

  it('opens the hits explorer for one set and paginates', async () => {
    const hitRequests = mockHits(120)
    renderPage()
    await screen.findByText('Malware IOCs')

    const user = userEvent.setup()
    const row = screen.getByText('Malware IOCs').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'View hits' }))

    expect(await screen.findByText('Hits: Malware IOCs')).toBeInTheDocument()
    expect(hitRequests[0]).toEqual({
      hash_set_id: 'hs-2',
      page: '1',
      page_size: '50',
    })

    // First page rows with artifact link, path, algorithm and hash.
    const link = screen.getByRole('link', { name: 'file-hs-2-0.exe' })
    expect(link).toHaveAttribute(
      'href',
      `/cases/${CASE_ID}/artifacts/art-hs-2-0`,
    )
    expect(
      screen.getByTitle('/evidence/windows/system32/file-hs-2-0.exe'),
    ).toBeInTheDocument()
    expect(
      screen.getAllByText('MD5', { selector: '.badge' }).length,
    ).toBeGreaterThan(0)
    expect(screen.getByText(/Page 1 of 3/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(
      await screen.findByRole('link', { name: 'file-hs-2-50.exe' }),
    ).toBeInTheDocument()
    expect(hitRequests.at(-1)).toEqual({
      hash_set_id: 'hs-2',
      page: '2',
      page_size: '50',
    })

    await user.click(screen.getByRole('button', { name: 'Close' }))
    expect(screen.queryByText('Hits: Malware IOCs')).not.toBeInTheDocument()
  })

  it('resets the hits page when another hash set is opened (B4-028)', async () => {
    // The panel is not remounted between sets. A page number carried from set A
    // queries page 2 of set B, and a set with a single page of hits then shows
    // "No hits" while its matches sit on page 1.
    const hitRequests = mockHits(120)
    renderPage()
    await screen.findByText('Malware IOCs')

    const user = userEvent.setup()
    const row = screen.getByText('Malware IOCs').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'View hits' }))
    await screen.findByText('Hits: Malware IOCs')
    await user.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() =>
      expect(hitRequests.at(-1)).toEqual({
        hash_set_id: 'hs-2',
        page: '2',
        page_size: '50',
      }),
    )

    // Open a different set without closing the panel first.
    const other = screen.getByText('NSRL Known').closest('tr')!
    await user.click(within(other).getByRole('button', { name: 'View hits' }))
    await screen.findByText('Hits: NSRL Known')
    await waitFor(() =>
      expect(hitRequests.at(-1)).toEqual({
        hash_set_id: 'hs-1',
        page: '1',
        page_size: '50',
      }),
    )
    expect(screen.getByText(/Page 1 of/)).toBeInTheDocument()
  })

  it('lists hits across all sets via the All hits button', async () => {
    const hitRequests = mockHits(2)
    renderPage()
    await screen.findByText('NSRL Known')

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'All hits' }))

    expect(
      await screen.findByText('All hits', { selector: '.panel-title' }),
    ).toBeInTheDocument()
    expect(hitRequests[0]).toEqual({
      hash_set_id: null,
      page: '1',
      page_size: '50',
    })
    expect(
      await screen.findByRole('link', { name: 'file-hs-1-0.exe' }),
    ).toBeInTheDocument()
  })

  it('closes the delete confirmation when the case changes (B2-016)', async () => {
    // Hash sets are per case. The page stays mounted when `:caseId` changes, so
    // a confirmation left open still names case A's set while the chrome reads
    // case B — and confirming it would DELETE `/cases/case-2/hash_sets/hs-2`,
    // an id that belongs to another case.
    let wrongCaseDelete: string | null = null
    server.use(
      http.get('/api/v1/cases/case-2/hash_sets', () => HttpResponse.json([])),
      http.delete(
        '/api/v1/cases/case-2/hash_sets/:hashSetId',
        ({ params }) => {
          wrongCaseDelete = String(params.hashSetId)
          return HttpResponse.json({ status: 'deleted' })
        },
      ),
    )
    renderPageWithSwitcher()
    await screen.findByText('Malware IOCs')

    const user = userEvent.setup()
    const row = screen.getByText('Malware IOCs').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Delete' }))
    expect(screen.getByRole('dialog', { name: /delete/i })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Go to case-2' }))

    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    )
    expect(wrongCaseDelete).toBeNull()
  })

  it('closes the import dialog when the case changes (B2-016)', async () => {
    server.use(
      http.get('/api/v1/cases/case-2/hash_sets', () => HttpResponse.json([])),
    )
    renderPageWithSwitcher()
    await screen.findByText('NSRL Known')

    const user = userEvent.setup()
    const row = screen.getByText('NSRL Known').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Import' }))
    expect(screen.getByRole('dialog', { name: /import/i })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Go to case-2' }))

    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    )
  })

  it('never queries the new case with the previous case\'s hash set id (B2-016)', async () => {
    // The hits panel is the silent failure: case B has no set `hs-2`, so the
    // query comes back empty and reads as "no matches recorded in this case".
    mockHits(5)
    const case2HitRequests: (string | null)[] = []
    server.use(
      http.get('/api/v1/cases/case-2/hash_sets', () => HttpResponse.json([])),
      http.get('/api/v1/cases/case-2/hash_hits', ({ request }) => {
        case2HitRequests.push(
          new URL(request.url).searchParams.get('hash_set_id'),
        )
        return HttpResponse.json({ hits: [], total: 0, page: 1, page_size: 50 })
      }),
    )
    renderPageWithSwitcher()
    await screen.findByText('Malware IOCs')

    const user = userEvent.setup()
    const row = screen.getByText('Malware IOCs').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'View hits' }))
    await screen.findByText('Hits: Malware IOCs')

    await user.click(screen.getByRole('button', { name: 'Go to case-2' }))

    await waitFor(() =>
      expect(screen.queryByText('Hits: Malware IOCs')).not.toBeInTheDocument(),
    )
    expect(case2HitRequests).toEqual([])
  })

  it('shows the hits empty state', async () => {
    mockHits(0)
    renderPage()
    await screen.findByText('NSRL Known')

    const user = userEvent.setup()
    const row = screen.getByText('NSRL Known').closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'View hits' }))

    expect(
      await screen.findByText('No matches recorded in this case.'),
    ).toBeInTheDocument()
  })
})
