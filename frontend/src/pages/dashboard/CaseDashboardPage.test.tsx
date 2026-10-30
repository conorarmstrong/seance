import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import {
  MemoryRouter,
  Route,
  Routes,
  useNavigate,
  useParams,
} from 'react-router-dom'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import type {
  CaseStats,
  IngestionProfile,
  Job,
  RecentArtifact,
} from '../../api/types'
import type {
  AllocationMapResponse,
  DiskMapResponse,
} from '../../components/viz/api'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import { CaseDashboardPage } from './CaseDashboardPage'
import type { TimelineHistogram } from '../timeline/api'
import type { FileSizeStatsResponse, SourceStatsResponse } from './api'

beforeAll(() => {
  // jsdom has no canvas implementation; smoke-mock the 2d context so
  // the allocation map can render structurally.
  HTMLCanvasElement.prototype.getContext = vi.fn(() => ({
    scale: vi.fn(),
    clearRect: vi.fn(),
    fillRect: vi.fn(),
    fillStyle: '',
  })) as unknown as typeof HTMLCanvasElement.prototype.getContext
})

afterEach(() => {
  vi.restoreAllMocks()
})

const STATS: CaseStats = {
  total_artifacts: 30012,
  artifact_counts_by_type: { FileEntry: 30000, TimelineEvent: 12 },
}

const RECENT: RecentArtifact[] = [
  {
    id: 'art-1',
    artifact_type: 'ParsedRecord',
    display_name: 'MFT Record 1234',
    created_at: '2026-04-02T08:15:00Z',
  },
]

const JOBS: Job[] = [
  {
    id: 'job-1',
    case_id: 'case-1',
    module_id: 'seance_plugin_registry',
    target_artifact_id: 'art-9',
    status: 'running',
    artifacts_produced: 5,
    error_message: null,
    created_at: 1700000000,
    completed_at: null,
  },
  {
    id: 'job-2',
    case_id: 'case-1',
    module_id: 'seance_plugin_email',
    target_artifact_id: 'art-8',
    status: 'complete',
    artifacts_produced: 12,
    error_message: null,
    created_at: 1700000000,
    completed_at: 1700000100,
  },
]

const FILE_SIZES: FileSizeStatsResponse = {
  buckets: [
    { pow2: 10, count: 5 },
    { pow2: 12, count: 9 },
    { pow2: 20, count: 2 },
  ],
}

const MODULES = [
  'plugin.ntfs.mft_parser',
  'plugin.windows.registry_parser',
  'plugin.browsers.history_parser',
  'plugin.messaging.whatsapp',
].map((id) => ({
  id,
  version: '1.0.0',
  subscribes_to: ['FileEntry'],
  execution_mode: 'Automatic',
}))

const TRIAGE: IngestionProfile = {
  id: 'prof-triage',
  case_id: 'case-1',
  name: 'triage',
  description: 'Fast triage mode - essential artifacts only',
  enabled_modules: ['plugin.ntfs.mft_parser', 'plugin.windows.registry_parser'],
  disabled_modules: [],
  is_active: true,
  created_at: 1700000000,
}

const SOURCES: SourceStatsResponse = {
  sources: [
    { source_artifact_id: 'src-1', name: 'laptop.E01', artifact_count: 1234 },
  ],
}

const HISTOGRAM: TimelineHistogram = {
  min_ts: 1700000000,
  max_ts: 1700007200,
  bucket_seconds: 3600,
  buckets: [
    { start: 1700000000, count: 5 },
    { start: 1700003600, count: 9 },
  ],
}

const GIB = 1024 ** 3

const DISK_MAP: DiskMapResponse = {
  total_bytes: 100 * GIB,
  regions: [
    {
      artifact_id: 'art-part-1',
      artifact_type: 'Partition',
      parent_id: null,
      offset_bytes: 1048576,
      size_bytes: 60 * GIB,
      name: 'Partition 1',
      scheme: 'gpt',
      fs_type: null,
    },
    {
      artifact_id: 'art-fs-1',
      artifact_type: 'FileSystem',
      parent_id: 'art-part-1',
      offset_bytes: 1048576,
      size_bytes: 60 * GIB,
      name: 'NTFS volume',
      scheme: null,
      fs_type: 'ntfs',
    },
    {
      artifact_id: 'art-un-1',
      artifact_type: 'UnallocatedSpace',
      parent_id: null,
      offset_bytes: 60 * GIB + 1048576,
      size_bytes: 40 * GIB,
      name: 'Unallocated 1',
      scheme: null,
      fs_type: null,
    },
  ],
}

// 4 buckets: 0, 64, 128, 255
const ALLOC: AllocationMapResponse = {
  allocation_bitmap_b64: 'AECA/w==',
  allocation_clusters_per_bucket: 1024,
  allocation_total_clusters: 4096,
  allocation_cluster_size: 4096,
}

function mockApi({
  stats = STATS,
  recent = RECENT,
  jobs = JOBS,
  fileSizes = FILE_SIZES,
  sources = SOURCES,
  diskMap = DISK_MAP,
  histogram = HISTOGRAM,
  activeProfile = null,
  modules = MODULES,
}: {
  stats?: CaseStats
  recent?: RecentArtifact[]
  jobs?: Job[]
  fileSizes?: FileSizeStatsResponse
  sources?: SourceStatsResponse
  diskMap?: DiskMapResponse
  histogram?: TimelineHistogram
  activeProfile?: IngestionProfile | null
  modules?: { id: string }[]
} = {}) {
  server.use(
    http.get('/api/v1/cases/case-1/stats', () => HttpResponse.json(stats)),
    http.get('/api/v1/cases/case-1/recent', () => HttpResponse.json(recent)),
    // The server answers this with a capped listing, not a bare array. Mocking
    // an array let this suite pass while the real dashboard threw on
    // `jobs.filter` and rendered nothing.
    http.get('/api/v1/cases/case-1/jobs', () =>
      HttpResponse.json({ items: jobs, truncated: false }),
    ),
    http.get('/api/v1/cases/case-1/timeline/histogram', () =>
      HttpResponse.json(histogram),
    ),
    http.get('/api/v1/cases/case-1/stats/file_sizes', () =>
      HttpResponse.json(fileSizes),
    ),
    http.get('/api/v1/cases/case-1/stats/sources', () =>
      HttpResponse.json(sources),
    ),
    http.get('/api/v1/cases/case-1/sources/:sourceId/disk_map', () =>
      HttpResponse.json(diskMap),
    ),
    // Each source card reads its own root artifact for the encryption and
    // incompleteness markers the ingest stamps there (LIVE-003).
    http.get('/api/v1/cases/case-1/artifacts/:id', ({ params }) =>
      HttpResponse.json({
        id: params.id,
        case_id: 'case-1',
        parent_id: null,
        artifact_type: 'RawEvidence',
        metadata: { name: 'laptop.E01' },
      }),
    ),
    // The profile in force on the case, and the population it scopes.
    http.get('/api/v1/cases/case-1/profiles/active', () =>
      HttpResponse.json(activeProfile),
    ),
    http.get('/api/v1/modules', () => HttpResponse.json(modules)),
  )
}

function ArtifactProbe() {
  const { artifactId } = useParams()
  return <div>artifact-page:{artifactId}</div>
}

function FilesProbe() {
  const { sourceId } = useParams()
  return <div>files-page:{sourceId}</div>
}

// The dashboard reads "is an ingest running" from a context the CaseLayout
// provides. Mocking the hook rather than exporting its context keeps the seam
// in the test: standing up a real provider here would mean an SSE stream, and
// exporting the context would widen the module's API for no runtime caller.
let processingActive = false
vi.mock('../../app/ProcessingContext', () => ({
  useProcessingActive: () => processingActive,
}))

function renderPage({ processingActive: active = false } = {}) {
  processingActive = active
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/case-1']}>
          <Routes>
            <Route path="/cases/:caseId" element={<CaseDashboardPage />} />
            <Route
              path="/cases/:caseId/artifacts/:artifactId"
              element={<ArtifactProbe />}
            />
            <Route
              path="/cases/:caseId/files/:sourceId"
              element={<FilesProbe />}
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('CaseDashboardPage job state (B7-033)', () => {
  it('does not file a failed job under active jobs', async () => {
    // A failed job has stopped. Counting it as active claimed work was still
    // running that had in fact ended, and buried the failure.
    mockApi({
      jobs: [
        {
          id: 'job-f',
          case_id: 'case-1',
          module_id: 'seance_plugin_registry',
          target_artifact_id: 'art-9',
          status: 'failed',
          artifacts_produced: 0,
          error_message: 'hive unreadable',
          created_at: 1700000000,
          completed_at: 1700000100,
        },
      ],
    })
    renderPage()

    // The failed job is shown under its own heading…
    expect(await screen.findByTestId('dash-failed-jobs')).toBeInTheDocument()
    expect(screen.getByText(/Failed jobs \(1\)/)).toBeInTheDocument()
    // …and the active section correctly reports nothing running.
    expect(screen.getByText('No active jobs.')).toBeInTheDocument()
  })

  it('does not report an idle case while an ingest is running', async () => {
    mockApi({ jobs: [] })
    renderPage({ processingActive: true })

    // An ingest creates no job row, so this panel has nothing to list. Saying
    // "No active jobs" while artifacts are landing is a false absence on the
    // screen an examiner reads to answer "is anything still running".
    expect(await screen.findByTestId('dash-ingest-running')).toBeInTheDocument()
    expect(screen.queryByText('No active jobs.')).not.toBeInTheDocument()
  })
})

describe('CaseDashboardPage', () => {
  it('renders humanized stat tiles with thousands separators', async () => {
    mockApi()
    renderPage()
    expect(screen.getByText(/loading/i)).toBeInTheDocument()

    expect(await screen.findByText('30,012')).toBeInTheDocument()
    expect(screen.getByText('Total artifacts')).toBeInTheDocument()
    // Humanized, pluralized labels — not raw enum variants
    expect(screen.getAllByText('File entries').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Timeline events').length).toBeGreaterThan(0)
    expect(screen.queryByText('FileEntry')).not.toBeInTheDocument()
    expect(screen.getAllByText('30,000').length).toBeGreaterThan(0)
  })

  it('renders the artifact type bar chart with counts at bar ends', async () => {
    mockApi()
    renderPage()
    const chart = await screen.findByRole('img', { name: 'Artifacts by type' })
    expect(chart.tagName.toLowerCase()).toBe('svg')
    // One bar path per type, count text rendered inside the SVG
    expect(chart.querySelectorAll('path').length).toBe(2)
    const values = [...chart.querySelectorAll('text')].map(
      (t) => t.textContent,
    )
    expect(values).toContain('30,000')
    expect(values).toContain('12')
  })

  it('renders the file size distribution with human size labels', async () => {
    mockApi()
    renderPage()
    const chart = await screen.findByRole('img', {
      name: 'File size distribution',
    })
    const labels = [...chart.querySelectorAll('text')].map(
      (t) => t.textContent,
    )
    expect(labels).toContain('1K')
    expect(labels).toContain('1M')
    // Max column is direct-labeled
    expect(labels).toContain('9')
  })

  it('renders evidence sources with a disk map and navigates on region click', async () => {
    mockApi()
    renderPage()

    expect(await screen.findByText('laptop.E01')).toBeInTheDocument()
    expect(screen.getByText('1,234 artifacts')).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: 'Browse file tree' }),
    ).toHaveAttribute('href', '/cases/case-1/files/src-1?view=tree')

    // Disk map regions render as buttons inside the SVG strip
    const partition = await screen.findByRole('button', {
      name: 'Partition 1 — partition',
    })
    expect(partition.closest('svg')).not.toBeNull()
    expect(
      screen.getByRole('button', { name: 'Unallocated 1 — unallocated' }),
    ).toBeInTheDocument()

    const fs = screen.getByRole('button', { name: 'NTFS volume — file system' })
    await userEvent.click(fs)
    // A file system opens in the lazy file tree, not its flat artifact page.
    expect(
      await screen.findByText('files-page:art-fs-1'),
    ).toBeInTheDocument()
  })

  it('lazy-fetches the allocation map on expand', async () => {
    mockApi()
    let allocCalls = 0
    server.use(
      http.get('/api/v1/cases/case-1/artifacts/art-fs-1/allocation_map', () => {
        allocCalls += 1
        return HttpResponse.json(ALLOC)
      }),
    )
    renderPage()

    const toggle = await screen.findByRole('button', {
      name: 'Disk usage — NTFS volume',
    })
    expect(allocCalls).toBe(0)

    await userEvent.click(toggle)
    expect(
      await screen.findByRole('img', { name: 'Cluster allocation map' }),
    ).toBeInTheDocument()
    expect(allocCalls).toBe(1)
    // Legend: 1024 clusters x 4096 bytes = 4.0 MiB per cell
    expect(screen.getByText(/each cell ≈ 4\.0 MiB/)).toBeInTheDocument()
  })

  it('hides the disk usage section when the allocation map returns 404', async () => {
    mockApi()
    server.use(
      http.get('/api/v1/cases/case-1/artifacts/art-fs-1/allocation_map', () =>
        HttpResponse.json(
          { error: { code: 'NOT_FOUND', message: 'no allocation map' } },
          { status: 404 },
        ),
      ),
    )
    renderPage()

    const toggle = await screen.findByRole('button', {
      name: 'Disk usage — NTFS volume',
    })
    await userEvent.click(toggle)
    await waitFor(() =>
      expect(
        screen.queryByRole('button', { name: 'Disk usage — NTFS volume' }),
      ).not.toBeInTheDocument(),
    )
  })

  it('keeps the disk usage row and says why when the allocation map fails (B8-021)', async () => {
    // A 404 means there is no map for this filesystem, which is why that case
    // hides the row. A 500 means nobody knows: hiding the row then reads as
    // "this filesystem has no usage to show".
    mockApi()
    server.use(
      http.get('/api/v1/cases/case-1/artifacts/art-fs-1/allocation_map', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'allocation map broken' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()

    await userEvent.click(
      await screen.findByRole('button', { name: 'Disk usage — NTFS volume' }),
    )

    expect(
      await screen.findByText(/Disk usage for NTFS volume could not be loaded/),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Disk usage — NTFS volume' }),
    ).toBeInTheDocument()
  })

  it('shows a visible note when a secondary chart query fails (BUG-204)', async () => {
    // Previously these failures were console-only and the panels vanished, so a
    // broken query was indistinguishable from "this case has no such data".
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    mockApi()
    server.use(
      http.get('/api/v1/cases/case-1/stats/sources', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'broken' } },
          { status: 500 },
        ),
      ),
      http.get('/api/v1/cases/case-1/stats/file_sizes', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'file sizes broken' } },
          { status: 500 },
        ),
      ),
      http.get('/api/v1/cases/case-1/timeline/histogram', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'histogram broken' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()

    // Dashboard still renders its core content
    expect(await screen.findByText('30,012')).toBeInTheDocument()
    // Each failed chart keeps its panel and states why it is empty.
    expect(
      await screen.findByText(
        /File size distribution unavailable: file sizes broken/,
      ),
    ).toBeInTheDocument()
    expect(
      await screen.findByText(
        /Case activity chart unavailable: histogram broken/,
      ),
    ).toBeInTheDocument()
    await waitFor(() => expect(warn).toHaveBeenCalled())
    // Evidence sources keeps its panel too. It used to remove itself, so a
    // failed request read as "this case has no evidence sources" — a claim
    // about the case that the failure cannot support (B8-021).
    expect(await screen.findByText('Evidence sources')).toBeInTheDocument()
    expect(
      await screen.findByText(/Evidence sources unavailable: broken/),
    ).toBeInTheDocument()
    expect(screen.queryByText('No evidence sources.')).not.toBeInTheDocument()
  })

  it('renders recent activity and jobs', async () => {
    mockApi()
    renderPage()

    // Recent activity links to the artifact page
    const link = await screen.findByRole('link', { name: 'MFT Record 1234' })
    expect(link).toHaveAttribute('href', '/cases/case-1/artifacts/art-1')
    expect(screen.getByText('2026-04-02 08:15:00 UTC')).toBeInTheDocument()

    // Active job row
    expect(
      await screen.findByText('seance_plugin_registry'),
    ).toBeInTheDocument()
    expect(screen.getByText('running')).toBeInTheDocument()

    // Completed jobs are collapsed until toggled
    expect(screen.queryByText('seance_plugin_email')).not.toBeInTheDocument()
    await userEvent.click(
      screen.getByRole('button', { name: /completed jobs \(1\)/i }),
    )
    expect(screen.getByText('seance_plugin_email')).toBeInTheDocument()
  })

  it('does not carry the completed-jobs disclosure into another case (B2-150)', async () => {
    // `showCompleted` is plain page state and this page is not remounted when
    // `:caseId` changes, so the panel stayed expanded over the next case's job
    // list — a per-case view preference asserted about a case that never set
    // it. Case 2 must open in its own default state.
    mockApi()
    const case2Jobs: Job[] = [
      { ...JOBS[0], id: 'job-b1', case_id: 'case-2', module_id: 'mod_b_running' },
      {
        ...JOBS[1],
        id: 'job-b2',
        case_id: 'case-2',
        module_id: 'mod_b_complete',
      },
    ]
    server.use(
      http.get('/api/v1/cases/case-2/stats', () => HttpResponse.json(STATS)),
      http.get('/api/v1/cases/case-2/recent', () => HttpResponse.json([])),
      http.get('/api/v1/cases/case-2/jobs', () =>
        HttpResponse.json({ items: case2Jobs, truncated: false }),
      ),
      http.get('/api/v1/cases/case-2/timeline/histogram', () =>
        HttpResponse.json(HISTOGRAM),
      ),
      http.get('/api/v1/cases/case-2/stats/file_sizes', () =>
        HttpResponse.json(FILE_SIZES),
      ),
      http.get('/api/v1/cases/case-2/stats/sources', () =>
        HttpResponse.json({ sources: [] }),
      ),
    )

    function CaseSwitcher() {
      const navigate = useNavigate()
      return (
        <button type="button" onClick={() => navigate('/cases/case-2')}>
          Go to case-2
        </button>
      )
    }
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/cases/case-1']}>
            <Routes>
              <Route
                path="/cases/:caseId"
                element={
                  <>
                    <CaseDashboardPage />
                    <CaseSwitcher />
                  </>
                }
              />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )

    await userEvent.click(
      await screen.findByRole('button', { name: /completed jobs \(1\)/i }),
    )
    expect(screen.getByText('seance_plugin_email')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Go to case-2' }))

    expect(await screen.findByText('mod_b_running')).toBeInTheDocument()
    expect(screen.queryByText('mod_b_complete')).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /completed jobs \(1\)/i }),
    ).toHaveAttribute('aria-expanded', 'false')
  })

  it('shows the getting-started state when the case has no artifacts', async () => {
    mockApi({
      stats: { total_artifacts: 0, artifact_counts_by_type: {} },
      recent: [],
      jobs: [],
      sources: { sources: [] },
      fileSizes: { buckets: [] },
    })
    renderPage()
    expect(await screen.findByText(/ingest evidence/i)).toBeInTheDocument()
  })

  it('shows an error toast when an export fails and allows retry', async () => {
    mockApi()
    let exportCalls = 0
    server.use(
      http.get('/api/v1/cases/case-1/export/html', () => {
        exportCalls += 1
        return new HttpResponse(null, { status: 500 })
      }),
    )
    renderPage()
    await screen.findByText('30,012')

    const exportButton = screen.getByRole('button', { name: 'Export HTML' })
    await userEvent.click(exportButton)
    expect(await screen.findByRole('alert')).toHaveTextContent(/export failed/i)

    // Button stays usable so the examiner can retry
    expect(exportButton).toBeEnabled()
    await userEvent.click(exportButton)
    expect(exportCalls).toBe(2)
  })

  it('offers the XLSX report beside HTML and PDF, and fetches it from the xlsx route', async () => {
    // The `/export/xlsx` route shipped with no control reaching it, so the
    // workbook the reporting crate renders could not be produced from the UI.
    mockApi()
    let xlsxCalls = 0
    server.use(
      http.get('/api/v1/cases/case-1/export/xlsx', () => {
        xlsxCalls += 1
        return new HttpResponse(new Uint8Array([0x50, 0x4b, 0x03, 0x04]), {
          status: 200,
          headers: {
            'Content-Type':
              'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          },
        })
      }),
    )
    // The download hands the bytes to an anchor via an object URL; jsdom
    // has neither, so stub the URL and watch which file it was made for.
    const createObjectURL = vi.fn((_blob: Blob) => 'blob:xlsx')
    const origCreate = URL.createObjectURL
    const origRevoke = URL.revokeObjectURL
    URL.createObjectURL =
      createObjectURL as unknown as typeof URL.createObjectURL
    URL.revokeObjectURL = vi.fn()
    try {
      renderPage()
      await screen.findByText('30,012')

      const buttons = screen
        .getAllByRole('button', { name: /^Export (HTML|PDF|XLSX|DOCX|RTF|XML)$/ })
        .map((b) => b.textContent)
      expect(buttons).toEqual([
        'Export HTML',
        'Export PDF',
        'Export DOCX',
        'Export RTF',
        'Export XML',
        'Export XLSX',
      ])

      await userEvent.click(
        screen.getByRole('button', { name: 'Export XLSX' }),
      )
      await waitFor(() => expect(xlsxCalls).toBe(1))
      await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1))
      expect(createObjectURL.mock.calls[0][0].size).toBe(4)
      // Nothing failed: the workbook is its own route.
      expect(screen.queryByRole('alert')).toBeNull()
    } finally {
      URL.createObjectURL = origCreate
      URL.revokeObjectURL = origRevoke
    }
  })

  it.each([
    [
      'DOCX',
      'docx',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ],
    ['RTF', 'rtf', 'application/rtf'],
    ['XML', 'xml', 'application/xml'],
  ])(
    'fetches the %s report from its own export route',
    async (label, format, contentType) => {
      // `/export/rtf` and `/export/xml` shipped with no control reaching
      // them, and `/export/docx` landed the same way (ROADMAP §2.10): the
      // report the reporting crate renders in each format could not be
      // produced from the UI. Each button fetches its own route, so a
      // failure in one format is never reported against another.
      mockApi()
      const calls: string[] = []
      server.use(
        http.get(`/api/v1/cases/case-1/export/${format}`, ({ request }) => {
          calls.push(new URL(request.url).pathname)
          return new HttpResponse(new Uint8Array([1, 2, 3]), {
            status: 200,
            headers: { 'Content-Type': contentType },
          })
        }),
      )
      const createObjectURL = vi.fn((_blob: Blob) => `blob:${format}`)
      const origCreate = URL.createObjectURL
      const origRevoke = URL.revokeObjectURL
      URL.createObjectURL =
        createObjectURL as unknown as typeof URL.createObjectURL
      URL.revokeObjectURL = vi.fn()
      try {
        renderPage()
        await screen.findByText('30,012')
        await userEvent.click(
          screen.getByRole('button', { name: `Export ${label}` }),
        )
        await waitFor(() => expect(calls).toHaveLength(1))
        expect(calls[0]).toBe(`/api/v1/cases/case-1/export/${format}`)
        await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1))
        expect(screen.queryByRole('alert')).toBeNull()
      } finally {
        URL.createObjectURL = origCreate
        URL.revokeObjectURL = origRevoke
      }
    },
  )

  it('shows an error state when stats fail to load', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    mockApi()
    server.use(
      http.get('/api/v1/cases/case-1/stats', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'stats broke' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    expect(await screen.findByText(/stats broke/)).toBeInTheDocument()
    warn.mockRestore()
  })
})



describe('the profile in force on the case', () => {
  it('states what an active profile excluded, and that the absence leaves no trace', async () => {
    // Handover (S3) and the witness box (S4): a case processed under triage is
    // output-identical to one whose evidence had no browser history, and the
    // only place that fact lived was the profile row nobody opens.
    mockApi({ activeProfile: TRIAGE })
    renderPage()

    const note = await screen.findByRole('note', {
      name: /Analysis profile scope/i,
    })
    await waitFor(() => expect(note).toHaveTextContent(/2 of 4/))
    expect(note).toHaveTextContent(/triage/)
    expect(note).toHaveTextContent(/Browser history and cache/)
    expect(note).toHaveTextContent(/no job/i)
    // It governs what runs now; nothing records which profile governed the
    // artifacts already in the case.
    expect(note).toHaveTextContent(/earlier ingest/i)
  })

  it('says nothing about profiles when none is in force', async () => {
    // A case with no profile has no scoping to disclose, and a banner that is
    // always there is a banner nobody reads.
    mockApi({ activeProfile: null })
    renderPage()

    await screen.findByText('Recent activity')
    expect(
      screen.queryByRole('note', { name: /Analysis profile scope/i }),
    ).toBeNull()
  })

  it('does not read a failed profile lookup as "no profile"', async () => {
    mockApi()
    server.use(
      http.get('/api/v1/cases/case-1/profiles/active', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()

    const note = await screen.findByRole('note', {
      name: /Analysis profile scope/i,
    })
    expect(note).toHaveTextContent(/could not be read/i)
  })
})
