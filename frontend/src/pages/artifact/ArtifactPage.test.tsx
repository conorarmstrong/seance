import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import type { Artifact, HashSetMatch } from '../../api/types'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { formatUtc } from '../../lib/format'
import { server } from '../../test/server'
import { ArtifactPage } from './ArtifactPage'

const CASE = 'case-1'

const rootArtifact: Artifact = {
  id: 'art-root',
  case_id: CASE,
  parent_id: null,
  artifact_type: 'RawEvidence',
  metadata: { name: 'disk.e01' },
}

const fileArtifact: Artifact = {
  id: 'art-file',
  case_id: CASE,
  parent_id: 'art-root',
  artifact_type: 'FileContent',
  metadata: {
    name: 'document.bin',
    size: 2048,
    source_path: '/evidence/document.bin',
    md5: 'a'.repeat(32),
    sha256: 'b'.repeat(64),
    created: '2024-01-02T03:04:05Z',
    details: { author: 'unknown' },
  },
}

interface IntegrityRow {
  id: number
  timestamp: string
  computed_md5: string | null
  computed_sha1: string | null
  computed_sha256: string | null
  expected_md5: string | null
  expected_sha1: string | null
  /** Optional here only so the older fixtures below stay as they were. */
  expected_sha256?: string | null
  status: string
  details: string | null
}

interface ChildItem {
  id: string
  parent_id: string | null
  artifact_type: string
  name: string
  has_children: boolean
  metadata?: Record<string, unknown>
}

function mockApi(opts: {
  artifacts?: Record<string, Artifact>
  hashMatches?: HashSetMatch[]
  bookmarkedIds?: string[]
  integrity?: () => IntegrityRow[]
  thumbnailOk?: boolean
  children?: ChildItem[]
}) {
  const artifacts = opts.artifacts ?? {
    'art-root': rootArtifact,
    'art-file': fileArtifact,
  }
  let bookmarks = [...(opts.bookmarkedIds ?? [])]
  server.use(
    http.get('/api/v1/cases/:caseId/artifacts/:artifactId/children', () =>
      HttpResponse.json({ items: opts.children ?? [] }),
    ),
    http.get('/api/v1/cases/:caseId/artifacts/:artifactId', ({ params }) => {
      const artifact = artifacts[params.artifactId as string]
      if (!artifact) {
        return HttpResponse.json(
          {
            error: {
              code: 'RESOURCE_NOT_FOUND',
              message: 'Artifact not found',
            },
          },
          { status: 404 },
        )
      }
      return HttpResponse.json(artifact)
    }),
    http.get(
      '/api/v1/cases/:caseId/artifacts/:artifactId/ancestors',
      ({ params }) => {
        let current: Artifact | undefined =
          artifacts[params.artifactId as string]
        if (!current) {
          return HttpResponse.json(
            {
              error: {
                code: 'RESOURCE_NOT_FOUND',
                message: 'Artifact not found',
              },
            },
            { status: 404 },
          )
        }
        const chain: { id: string; name: string; artifact_type: string }[] = []
        while (current) {
          chain.unshift({
            id: current.id,
            name:
              typeof current.metadata.name === 'string'
                ? current.metadata.name
                : current.artifact_type,
            artifact_type: current.artifact_type,
          })
          current = current.parent_id
            ? artifacts[current.parent_id]
            : undefined
        }
        return HttpResponse.json(chain)
      },
    ),
    http.get('/api/v1/cases/:caseId/artifacts/:artifactId/integrity', () =>
      HttpResponse.json(opts.integrity ? opts.integrity() : []),
    ),
    http.get('/api/v1/cases/:caseId/artifacts/:artifactId/thumbnail', () =>
      opts.thumbnailOk
        ? HttpResponse.arrayBuffer(
            new Uint8Array([0x89, 0x50, 0x4e, 0x47]).buffer,
            { headers: { 'Content-Type': 'image/png' } },
          )
        : HttpResponse.json(
            {
              error: {
                code: 'RESOURCE_NOT_FOUND',
                message: 'Not a raster image',
              },
            },
            { status: 404 },
          ),
    ),
    http.get('/api/v1/cases/:caseId/artifacts/:artifactId/hash_check', () =>
      HttpResponse.json(opts.hashMatches ?? []),
    ),
    http.get('/api/v1/cases/:caseId/bookmarks/ids', () =>
      HttpResponse.json(bookmarks),
    ),
    http.post('/api/v1/cases/:caseId/bookmarks', async ({ request }) => {
      const body = (await request.json()) as { artifact_id: string }
      bookmarks.push(body.artifact_id)
      return HttpResponse.json({ id: 'bm-1', artifact_id: body.artifact_id })
    }),
    http.delete(
      '/api/v1/cases/:caseId/bookmarks/:artifactId',
      ({ params }) => {
        bookmarks = bookmarks.filter((id) => id !== params.artifactId)
        return HttpResponse.json({ success: true })
      },
    ),
  )
}

function renderPage(path = `/cases/${CASE}/artifacts/art-file`) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route
              path="/cases/:caseId/artifacts/:artifactId"
              element={<ArtifactPage />}
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('ArtifactPage header', () => {
  it('renders name, type badge, download link and breadcrumb', async () => {
    mockApi({})
    renderPage()
    expect(
      await screen.findByRole('heading', { name: 'document.bin' }),
    ).toBeInTheDocument()
    expect(screen.getByText('FileContent')).toHaveClass('badge')
    // Download is an authenticated fetch (Bearer header), not a bare cookie-only
    // link, so it is a button that streams the blob rather than an <a href>.
    expect(screen.getByRole('button', { name: 'Download' })).toBeInTheDocument()
    const crumb = await screen.findByRole('link', { name: 'disk.e01' })
    expect(crumb).toHaveAttribute('href', '/cases/case-1/artifacts/art-root')
  })

  it('renders the full ancestry chain from the ancestors endpoint', async () => {
    const partition: Artifact = {
      id: 'art-part',
      case_id: CASE,
      parent_id: 'art-root',
      artifact_type: 'Partition',
      metadata: { name: 'Partition 1 (NTFS)' },
    }
    mockApi({
      artifacts: {
        'art-root': rootArtifact,
        'art-part': partition,
        'art-file': { ...fileArtifact, parent_id: 'art-part' },
      },
    })
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    const nav = await screen.findByRole('navigation', { name: 'Ancestry' })
    const links = within(nav).getAllByRole('link')
    expect(links.map((l) => l.textContent)).toEqual([
      'disk.e01',
      'Partition 1 (NTFS)',
    ])
    expect(links[1]).toHaveAttribute(
      'href',
      '/cases/case-1/artifacts/art-part',
    )
    // The artifact itself is plain text, not a link.
    expect(
      within(nav).queryByRole('link', { name: 'document.bin' }),
    ).not.toBeInTheDocument()
  })

  it('falls back to the source_path basename for the name', async () => {
    mockApi({
      artifacts: {
        'art-file': {
          ...fileArtifact,
          parent_id: null,
          metadata: { source_path: '/mnt/img/photo.zip' },
        },
      },
    })
    renderPage()
    expect(
      await screen.findByRole('heading', { name: 'photo.zip' }),
    ).toBeInTheDocument()
  })

  it('shows hash set match badges', async () => {
    mockApi({
      hashMatches: [
        {
          hash_value: 'a'.repeat(32),
          hash_set_name: 'NSRL',
          hash_set_id: 'hs-1',
          set_type: 'known',
          product_name: null,
        },
        {
          hash_value: 'a'.repeat(32),
          hash_set_name: 'Bad Stuff',
          hash_set_id: 'hs-2',
          set_type: 'notable',
          product_name: null,
        },
      ],
    })
    renderPage()
    expect(await screen.findByText('Known: NSRL')).toHaveClass('badge-ok')
    expect(screen.getByText('Notable: Bad Stuff')).toHaveClass('badge-danger')
  })

  /**
   * The "content unavailable" warning must render whatever shape the producer
   * wrote the marker in.
   *
   * `compression_unsupported` is a reason STRING from MFT and F2FS
   * ("ntfs_lznt1_oversize", "f2fs") and a boolean only from BTRFS. The badge was
   * gated on `metadataBool`, which returns null for a string — so on every NTFS
   * artifact, the most common kind in a Windows case, the warning silently did
   * not render. Worse, the "Compressed" badge below is gated on its negation, so
   * the examiner was shown "Stored compressed on disk; the content shown is
   * decompressed" — a statement that the decompression succeeded, on the exact
   * artifact where it had failed and the bytes on offer are the raw compressed
   * clusters.
   */
  it('warns that content is unavailable however the producer wrote the marker', async () => {
    for (const marker of ['ntfs_lznt1_oversize', 'f2fs', true]) {
      mockApi({
        artifacts: {
          'art-root': rootArtifact,
          'art-file': {
            ...fileArtifact,
            metadata: {
              ...fileArtifact.metadata,
              compressed: true,
              compression_unsupported: marker,
            },
          },
        },
      })
      const view = renderPage()

      const badge = await screen.findByText('Content unavailable')
      expect(badge, `marker ${String(marker)} must raise the warning`).toHaveClass(
        'badge-danger',
      )
      // And the badge that would contradict it must not be shown.
      expect(
        screen.queryByText('Compressed'),
        'nothing may say the content was decompressed when it was not',
      ).toBeNull()
      if (typeof marker === 'string') {
        expect(badge.getAttribute('title')).toContain(marker)
      }
      view.unmount()
    }
  })

  /** A compressed artifact that DID decompress still says so. */
  it('still labels a compressed artifact whose content was resolved', async () => {
    mockApi({
      artifacts: {
        'art-root': rootArtifact,
        'art-file': {
          ...fileArtifact,
          metadata: { ...fileArtifact.metadata, compressed: true },
        },
      },
    })
    renderPage()
    expect(await screen.findByText('Compressed')).toHaveClass('badge')
    expect(screen.queryByText('Content unavailable')).toBeNull()
  })

  it('runs verification as a job and shows the verdict after completion', async () => {
    const md5 = 'aa11'.repeat(8)
    let jobPolls = 0
    let integrityRows: IntegrityRow[] = []
    mockApi({ integrity: () => integrityRows })
    server.use(
      http.post('/api/v1/cases/:caseId/artifacts/:artifactId/verify', () =>
        HttpResponse.json({ job_id: 'vjob-1', status: 'running' }),
      ),
      http.get('/api/v1/cases/:caseId/jobs/:jobId', () => {
        jobPolls += 1
        const done = jobPolls >= 2
        if (done) {
          integrityRows = [
            {
              id: 1,
              timestamp: '2026-07-14T10:00:00Z',
              computed_md5: md5,
              computed_sha1: 'b'.repeat(40),
              computed_sha256: 'c'.repeat(64),
              expected_md5: md5,
              expected_sha1: null,
              status: 'verified',
              details: null,
            },
          ]
        }
        return HttpResponse.json({
          id: 'vjob-1',
          case_id: CASE,
          module_id: 'verify.integrity',
          target_artifact_id: 'art-file',
          status: done ? 'complete' : 'running',
          artifacts_produced: 0,
          error_message: null,
          created_at: 1704164645,
          completed_at: done ? 1704164650 : null,
        })
      }),
    )
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(
      screen.getByRole('button', { name: 'Verify Integrity' }),
    )
    // While the job runs an indeterminate progress bar is shown.
    expect(
      await screen.findByRole('progressbar', { name: 'Verifying integrity' }),
    ).toBeInTheDocument()
    // After the poll flips to complete, the recorded verdict is refetched.
    expect(
      await screen.findByText('Verified', {}, { timeout: 4000 }),
    ).toHaveClass('badge-ok')
    const truncated = screen.getAllByText('aa11aa11…aa11aa11')
    expect(truncated.length).toBeGreaterThanOrEqual(2)
    expect(truncated[0]).toHaveAttribute('title', md5)
    expect(screen.getByText('2026-07-14 10:00:00 UTC')).toBeInTheDocument()
    expect(
      screen.queryByRole('progressbar', { name: 'Verifying integrity' }),
    ).not.toBeInTheDocument()
    expect(jobPolls).toBeGreaterThanOrEqual(2)
  })

  it('shows an error note when the verification job fails', async () => {
    mockApi({})
    server.use(
      http.post('/api/v1/cases/:caseId/artifacts/:artifactId/verify', () =>
        HttpResponse.json({ job_id: 'vjob-2', status: 'running' }),
      ),
      http.get('/api/v1/cases/:caseId/jobs/:jobId', () =>
        HttpResponse.json({
          id: 'vjob-2',
          case_id: CASE,
          module_id: 'verify.integrity',
          target_artifact_id: 'art-file',
          status: 'failed',
          artifacts_produced: 0,
          error_message: 'Failed to hash artifact content: io error',
          created_at: 1704164645,
          completed_at: 1704164646,
        }),
      ),
    )
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(
      screen.getByRole('button', { name: 'Verify Integrity' }),
    )
    const notes = await screen.findAllByText(
      /Failed to hash artifact content: io error/,
    )
    expect(notes.length).toBeGreaterThanOrEqual(1)
    expect(
      screen.getByRole('button', { name: 'Verify Integrity' }),
    ).toBeEnabled()
  })

  it('stops waiting, and says why, when the job status cannot be read (B8-022)', async () => {
    // There was no branch for a failing poll: the page stayed on "Verifying
    // integrity…" forever with Verify disabled and nothing on screen — which
    // reads as a verification still running, long after the client lost it.
    mockApi({})
    server.use(
      http.post('/api/v1/cases/:caseId/artifacts/:artifactId/verify', () =>
        HttpResponse.json({ job_id: 'vjob-3', status: 'running' }),
      ),
      http.get('/api/v1/cases/:caseId/jobs/:jobId', () =>
        HttpResponse.json(
          { error: { code: 'NOT_FOUND', message: 'no such job' } },
          { status: 404 },
        ),
      ),
    )
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(
      screen.getByRole('button', { name: 'Verify Integrity' }),
    )

    const note = await screen.findByTestId('av-verify-lost', {}, { timeout: 4000 })
    expect(note.textContent).toMatch(/could not be read/i)
    // Not presented as a verdict on the exhibit.
    expect(note.textContent).not.toMatch(/Verification failed/i)
    expect(
      screen.queryByRole('progressbar', { name: 'Verifying integrity' }),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Verify Integrity' }),
    ).toBeEnabled()
  })

  it('scopes the verify job to the artifact it started on (BUG-110)', async () => {
    const artA: Artifact = {
      id: 'art-a',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'FileContent',
      metadata: { name: 'a.bin', size: 8 },
    }
    const artB: Artifact = {
      id: 'art-b',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'FileContent',
      metadata: { name: 'b.bin', size: 8 },
    }
    mockApi({ artifacts: { 'art-a': artA, 'art-b': artB } })
    server.use(
      http.post('/api/v1/cases/:caseId/artifacts/:artifactId/verify', () =>
        HttpResponse.json({ job_id: 'vjob', status: 'running' }),
      ),
      // The job never completes: it stays running so the "Verifying…" state is
      // still active at the moment we navigate away.
      http.get('/api/v1/cases/:caseId/jobs/:jobId', () =>
        HttpResponse.json({
          id: 'vjob',
          case_id: CASE,
          module_id: 'verify.integrity',
          target_artifact_id: 'art-a',
          status: 'running',
          artifacts_produced: 0,
          error_message: null,
          created_at: 0,
          completed_at: null,
        }),
      ),
    )
    const client = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    const ui = (id: string) => (
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={[`/cases/${CASE}/workbench`]}>
            <ArtifactPage caseId={CASE} artifactId={id} embedded />
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>
    )
    const { rerender } = render(ui('art-a'))
    await screen.findByRole('heading', { name: 'a.bin' })
    await userEvent.click(
      screen.getByRole('button', { name: 'Verify Integrity' }),
    )
    expect(
      await screen.findByRole('progressbar', { name: 'Verifying integrity' }),
    ).toBeInTheDocument()

    // Navigate to a different artifact (same page instance): B must not inherit
    // A's in-flight verification, and B's own Verify button stays usable.
    rerender(ui('art-b'))
    await screen.findByRole('heading', { name: 'b.bin' })
    expect(
      screen.queryByRole('progressbar', { name: 'Verifying integrity' }),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Verify Integrity' }),
    ).toBeEnabled()
  })

  it('does not deposit a verify job id under the artifact the examiner moved to (B3-053)', async () => {
    const artA: Artifact = {
      id: 'art-a',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'FileContent',
      metadata: { name: 'a.bin', size: 8 },
    }
    const artB: Artifact = {
      id: 'art-b',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'FileContent',
      metadata: { name: 'b.bin', size: 8 },
    }
    mockApi({ artifacts: { 'art-a': artA, 'art-b': artB } })

    // Hold the start response until after the examiner has moved on, which is
    // the whole point: react-query hands the response to the CURRENT render's
    // callback, so an unscoped `setVerifyJobId` writes A's job id into B's
    // scope and B then polls it and refreshes B's integrity on A's verdict.
    let releaseVerify: () => void = () => {}
    const started = new Promise<void>((resolve) => {
      releaseVerify = resolve
    })
    let jobPolls = 0
    server.use(
      http.post(
        '/api/v1/cases/:caseId/artifacts/:artifactId/verify',
        async () => {
          await started
          return HttpResponse.json({ job_id: 'vjob-from-a', status: 'running' })
        },
      ),
      http.get('/api/v1/cases/:caseId/jobs/:jobId', () => {
        jobPolls += 1
        return HttpResponse.json({
          id: 'vjob-from-a',
          case_id: CASE,
          module_id: 'verify.integrity',
          target_artifact_id: 'art-a',
          status: 'complete',
          artifacts_produced: 1,
          error_message: null,
          created_at: 0,
          completed_at: 1,
        })
      }),
    )

    const client = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    const ui = (id: string) => (
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={[`/cases/${CASE}/workbench`]}>
            <ArtifactPage caseId={CASE} artifactId={id} embedded />
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>
    )

    const { rerender } = render(ui('art-a'))
    await screen.findByRole('heading', { name: 'a.bin' })
    await userEvent.click(
      screen.getByRole('button', { name: 'Verify Integrity' }),
    )

    rerender(ui('art-b'))
    await screen.findByRole('heading', { name: 'b.bin' })

    releaseVerify()

    // Give the settled mutation every chance to write somewhere it should not.
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Verify Integrity' }),
      ).toBeEnabled(),
    )
    expect(
      screen.queryByRole('progressbar', { name: 'Verifying integrity' }),
    ).not.toBeInTheDocument()
    // The poll only runs when a job id is readable in the current scope. Any
    // poll here is artifact B asking about artifact A's job.
    expect(jobPolls).toBe(0)
    expect(
      screen.queryByText('Integrity verification complete'),
    ).not.toBeInTheDocument()
  })

  it('renders a previously recorded no_baseline verdict', async () => {
    mockApi({
      integrity: () => [
        {
          id: 3,
          timestamp: '2026-07-10T09:00:00Z',
          computed_md5: 'd'.repeat(32),
          computed_sha1: 'e'.repeat(40),
          computed_sha256: 'f'.repeat(64),
          expected_md5: null,
          expected_sha1: null,
          status: 'no_baseline',
          details: null,
        },
      ],
    })
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    expect(await screen.findByText('No baseline')).toHaveClass('badge')
  })

  it('shows the SHA-256 baseline a check was measured against (B2-045)', async () => {
    // For an ordinary FileEntry the ingest-time SHA-256 is usually the ONLY
    // baseline that exists. With it missing from the record the panel showed a
    // "Verified" badge with nothing beside it saying what was verified against.
    const expected = 'c'.repeat(64)
    mockApi({
      integrity: () => [
        {
          id: 4,
          timestamp: '2026-07-10T09:00:00Z',
          computed_md5: null,
          computed_sha1: null,
          computed_sha256: expected,
          expected_md5: null,
          expected_sha1: null,
          expected_sha256: expected,
          status: 'verified',
          details: null,
        },
      ],
    })
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    const row = (await screen.findByText('SHA256 computed / expected'))
      .parentElement!
    // Both sides present: the computed digest AND the baseline it was compared
    // to, not a computed value on its own.
    expect(within(row).getAllByTitle(expected)).toHaveLength(2)
  })

  it('never dresses an unreadable verification as verified (B2-040)', async () => {
    // The content ran out before its declared size, so the digests cover a
    // fragment. "Verified" there would be a green tick an examiner testifies
    // to; it must read as neither a pass nor a mismatch, and say why.
    mockApi({
      integrity: () => [
        {
          id: 5,
          timestamp: '2026-07-10T09:00:00Z',
          computed_md5: 'd'.repeat(32),
          computed_sha1: 'e'.repeat(40),
          computed_sha256: 'f'.repeat(64),
          expected_md5: null,
          expected_sha1: null,
          expected_sha256: null,
          status: 'incomplete',
          details:
            'content short of declared size: hashed 1024 of 4096 bytes; digests cover only the readable prefix',
        },
      ],
    })
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    expect(screen.queryByText('Verified')).not.toBeInTheDocument()
    expect(
      await screen.findByText(/Incomplete — could not read it all/),
    ).toHaveClass('badge-warn')
    expect(screen.getByText(/hashed 1024 of 4096 bytes/)).toBeInTheDocument()
  })

  it('toggles the bookmark', async () => {
    mockApi({})
    renderPage()
    const add = await screen.findByRole('button', { name: 'Add bookmark' })
    await userEvent.click(add)
    expect(
      await screen.findByRole('button', { name: 'Remove bookmark' }),
    ).toBeInTheDocument()
    await userEvent.click(
      screen.getByRole('button', { name: 'Remove bookmark' }),
    )
    expect(
      await screen.findByRole('button', { name: 'Add bookmark' }),
    ).toBeInTheDocument()
  })

  it('shows an error state when the artifact 404s', async () => {
    mockApi({ artifacts: {} })
    renderPage()
    expect(await screen.findByText(/Artifact not found/)).toBeInTheDocument()
  })
})

describe('ArtifactPage overview', () => {
  it('shows the overview summary by default', async () => {
    mockApi({})
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    expect(screen.getByText('2.0 KiB')).toBeInTheDocument()
    expect(screen.getByText('/evidence/document.bin')).toBeInTheDocument()
    expect(screen.getByText('2024-01-02 03:04:05 UTC')).toBeInTheDocument()
  })

  it('copies a hash to the clipboard with transient feedback', async () => {
    mockApi({})
    const user = userEvent.setup()
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    const copyMd5 = screen.getByRole('button', { name: 'Copy MD5' })
    expect(
      screen.getByRole('button', { name: 'Copy SHA256' }),
    ).toBeInTheDocument()
    await user.click(copyMd5)
    expect(copyMd5).toHaveTextContent('Copied')
    await expect(navigator.clipboard.readText()).resolves.toBe('a'.repeat(32))
  })

  it('shows carving metadata for carved artifacts', async () => {
    mockApi({
      artifacts: {
        'art-carved': {
          id: 'art-carved',
          case_id: CASE,
          parent_id: null,
          artifact_type: 'FileContent',
          metadata: {
            name: 'carved_000001.bin',
            size: 4096,
            carving_offset_absolute: 512,
            carving_signature: 'jpeg_sof',
            carving_validated: true,
          },
        },
      },
    })
    renderPage(`/cases/${CASE}/artifacts/art-carved`)
    await screen.findByRole('heading', { name: 'carved_000001.bin' })
    expect(screen.getByText('0x200 (512)')).toBeInTheDocument()
    expect(screen.getByText('jpeg_sof')).toBeInTheDocument()
    expect(screen.getByText('Validated')).toHaveClass('badge-ok')
  })

  it('labels a carve that ended below its declared size', async () => {
    mockApi({
      artifacts: {
        'art-short': {
          id: 'art-short',
          case_id: CASE,
          parent_id: null,
          artifact_type: 'FileContent',
          metadata: {
            name: 'carved_00000000.clip',
            size: 3000,
            carving_signature: 'Clip Studio Paint',
            carving_validated: false,
            carving_below_minimum: true,
          },
        },
      },
    })
    renderPage(`/cases/${CASE}/artifacts/art-short`)
    await screen.findByRole('heading', { name: 'carved_00000000.clip' })
    expect(screen.getByText('Below declared size')).toBeInTheDocument()
    expect(screen.getByText('Not validated')).toBeInTheDocument()
  })
})

describe('ArtifactPage preview tab', () => {
  it('previews raster images via an authenticated blob fetch', async () => {
    const createObjectURL = vi.fn(() => 'blob:mock')
    URL.createObjectURL = createObjectURL
    URL.revokeObjectURL = vi.fn()
    mockApi({
      artifacts: {
        'art-img': {
          id: 'art-img',
          case_id: CASE,
          parent_id: null,
          artifact_type: 'FileContent',
          metadata: { name: 'photo.png', size: 4 },
        },
      },
    })
    server.use(
      http.get('/api/v1/cases/:caseId/artifacts/:artifactId/content', () =>
        HttpResponse.arrayBuffer(
          new Uint8Array([0x89, 0x50, 0x4e, 0x47]).buffer,
          { headers: { 'Content-Type': 'image/png' } },
        ),
      ),
    )
    renderPage(`/cases/${CASE}/artifacts/art-img`)
    await screen.findByRole('heading', { name: 'photo.png' })
    const tabs = screen.getAllByRole('tab')
    expect(tabs[0]).toHaveTextContent('Preview')
    await userEvent.click(tabs[0])
    const img = await screen.findByRole('img', { name: 'photo.png' })
    expect(img).toHaveAttribute('src', 'blob:mock')
    expect(createObjectURL).toHaveBeenCalled()
  })

  it('falls back to download when the image exceeds the preview cap', async () => {
    mockApi({
      artifacts: {
        'art-big': {
          id: 'art-big',
          case_id: CASE,
          parent_id: null,
          artifact_type: 'FileContent',
          metadata: { name: 'huge.png', size: 64 * 1024 * 1024 },
        },
      },
    })
    renderPage(`/cases/${CASE}/artifacts/art-big#preview`)
    await screen.findByRole('heading', { name: 'huge.png' })
    expect(
      await screen.findByText('Too large to preview'),
    ).toBeInTheDocument()
    const downloads = screen.getAllByRole('button', { name: 'Download' })
    expect(downloads.length).toBeGreaterThanOrEqual(2)
  })

  it('offers a preview when the thumbnail probe succeeds without an extension', async () => {
    mockApi({
      artifacts: {
        'art-noext': {
          id: 'art-noext',
          case_id: CASE,
          parent_id: null,
          artifact_type: 'FileContent',
          metadata: { name: 'DCIM0001', size: 4 },
        },
      },
      thumbnailOk: true,
    })
    renderPage(`/cases/${CASE}/artifacts/art-noext`)
    await screen.findByRole('heading', { name: 'DCIM0001' })
    expect(
      await screen.findByRole('tab', { name: 'Preview' }),
    ).toBeInTheDocument()
  })

  it('previews text files and appends further ranges via Load more', async () => {
    const CHUNK = 262144
    const content = 'STARTMARK ' + 'a'.repeat(CHUNK - 10) + 'ENDMARK'
    mockApi({
      artifacts: {
        'art-txt': {
          id: 'art-txt',
          case_id: CASE,
          parent_id: null,
          artifact_type: 'FileContent',
          metadata: { name: 'notes.txt', size: content.length },
        },
      },
    })
    const rangesSeen: string[] = []
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/:artifactId/content',
        ({ request }) => {
          const range = request.headers.get('range')
          const match = range?.match(/bytes=(\d+)-(\d+)/)
          if (!match) return new HttpResponse(content)
          rangesSeen.push(range as string)
          const start = Number(match[1])
          const end = Math.min(Number(match[2]), content.length - 1)
          return new HttpResponse(content.slice(start, end + 1), {
            status: 206,
            headers: {
              'Content-Range': `bytes ${start}-${end}/${content.length}`,
            },
          })
        },
      ),
    )
    renderPage(`/cases/${CASE}/artifacts/art-txt`)
    await screen.findByRole('heading', { name: 'notes.txt' })
    await userEvent.click(screen.getByRole('tab', { name: 'Preview' }))
    const pre = await screen.findByText(/STARTMARK/)
    expect(pre.textContent).not.toContain('ENDMARK')
    expect(rangesSeen[0]).toBe(`bytes=0-${CHUNK - 1}`)
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await waitFor(() =>
      expect(screen.getByText(/STARTMARK/).textContent).toContain('ENDMARK'),
    )
    expect(rangesSeen[1]).toBe(`bytes=${CHUNK}-${2 * CHUNK - 1}`)
    expect(
      screen.queryByRole('button', { name: 'Load more' }),
    ).not.toBeInTheDocument()
  })
})

describe('ArtifactPage inspector', () => {
  it('shows metadata in the always-visible inspector and expands full properties', async () => {
    mockApi({})
    // A stale #properties hash (no longer a tab) must not break the page.
    renderPage(`/cases/${CASE}/artifacts/art-file#properties`)
    await screen.findByRole('heading', { name: 'document.bin' })
    // Common metadata is visible without opening any tab.
    const inspector = screen.getByRole('complementary', { name: 'Properties' })
    expect(within(inspector).getByText('/evidence/document.bin')).toBeInTheDocument()
    // The full key/value dump is behind a toggle.
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    await userEvent.click(
      screen.getByRole('button', { name: /Show all properties/ }),
    )
    const table = screen.getByRole('table')
    expect(within(table).getByText('source_path')).toBeInTheDocument()
    expect(within(table).getByText(/"author": "unknown"/)).toBeInTheDocument()
  })

  it('opens the viewer named in the URL hash', async () => {
    mockApi({})
    renderPage(`/cases/${CASE}/artifacts/art-file#text`)
    await screen.findByRole('heading', { name: 'document.bin' })
    expect(screen.getByRole('tab', { name: 'Text' })).toHaveAttribute(
      'aria-selected',
      'true',
    )
  })

  it('preserves search params (the workbench ?artifact=) when switching tabs', async () => {
    mockApi({})
    server.use(
      http.get('/api/v1/cases/:caseId/artifacts/:artifactId/hex', () =>
        HttpResponse.json({
          offset: 0,
          limit: 0,
          hex: '',
          ascii: '',
          total_size: 0,
        }),
      ),
    )
    function LocationProbe() {
      const loc = useLocation()
      return <div data-testid="loc-search">{loc.search}</div>
    }
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <MemoryRouter
            initialEntries={[`/cases/${CASE}/workbench?artifact=art-file`]}
          >
            <ArtifactPage caseId={CASE} artifactId="art-file" embedded />
            <LocationProbe />
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(screen.getByRole('tab', { name: 'Hex' }))
    // The tab switch must not drop the workbench's selection param.
    await waitFor(() =>
      expect(screen.getByTestId('loc-search').textContent).toContain(
        'artifact=art-file',
      ),
    )
  })

  it('collapses and restores the inspector', async () => {
    mockApi({})
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    expect(
      screen.getByRole('complementary', { name: 'Properties' }),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Hide inspector' }))
    expect(
      screen.queryByRole('complementary', { name: 'Properties' }),
    ).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Inspector/ }))
    expect(
      screen.getByRole('complementary', { name: 'Properties' }),
    ).toBeInTheDocument()
  })

  // The paging arithmetic is what this test is about, and the viewer steps by
  // its own page size and the reported `total_size`, never by how many bytes a
  // page returned (see `ContentTabs`). So each page answers with sixteen bytes
  // rather than 4,096: the offsets requested, the row labels, and the button
  // states are identical, and the test no longer renders ~16,000 cells four
  // times over. It used to, and carried a 60 s budget for it — which was the
  // one test still timing out under a loaded host once the worker pool was
  // pinned (UI-023). Every assertion below is unchanged.
  it('pages through hex data using the reported total size', async () => {
    mockApi({})
    const TOTAL = 10000
    const PAGE_BYTES = 16
    const offsets: number[] = []
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/:artifactId/hex',
        ({ request }) => {
          const url = new URL(request.url)
          const offset = Number(url.searchParams.get('offset'))
          const limit = Number(url.searchParams.get('limit'))
          offsets.push(offset)
          const count = Math.max(0, Math.min(PAGE_BYTES, limit, TOTAL - offset))
          return HttpResponse.json({
            offset,
            limit,
            hex: new Array(count).fill('41').join(' '),
            ascii: 'A'.repeat(count),
            total_size: TOTAL,
          })
        },
      ),
    )
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(screen.getByRole('tab', { name: 'Hex' }))
    expect(await screen.findByText('00000000')).toBeInTheDocument()
    expect(screen.getByText(/of 10000/)).toBeInTheDocument()
    const prev = screen.getByRole('button', { name: 'Previous page' })
    expect(prev).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(offsets).toContain(4096))
    expect(await screen.findByText('00001000')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeEnabled()
    // Go to end lands on the final 4 KiB page.
    await userEvent.click(screen.getByRole('button', { name: 'Go to end' }))
    await waitFor(() => expect(offsets).toContain(8192))
    expect(await screen.findByText('00002000')).toBeInTheDocument()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled(),
    )
    // Jump back to a hex offset.
    await userEvent.clear(screen.getByLabelText('Go to offset'))
    await userEvent.type(screen.getByLabelText('Go to offset'), '0x0')
    await userEvent.click(screen.getByRole('button', { name: 'Go' }))
    await waitFor(() =>
      expect(offsets.filter((o) => o === 0).length).toBeGreaterThanOrEqual(2),
    )
  })

  it('decodes clicked bytes in the data inspector', async () => {
    mockApi({})
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/:artifactId/hex',
        ({ request }) => {
          const url = new URL(request.url)
          const offset = Number(url.searchParams.get('offset'))
          const limit = Number(url.searchParams.get('limit'))
          return HttpResponse.json({
            offset,
            limit,
            hex: new Array(16).fill('41').join(' '),
            ascii: 'A'.repeat(16),
            total_size: 16,
          })
        },
      ),
    )
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(screen.getByRole('tab', { name: 'Hex' }))
    await screen.findByText('00000000')
    await userEvent.click(screen.getByTitle('offset 0x0'))
    expect(screen.getByText('Inspector at 0x0 (0)')).toBeInTheDocument()
    expect(screen.getByText('u8')).toBeInTheDocument()
    expect(screen.getByText('65')).toBeInTheDocument()
    expect(screen.getByText('u32le')).toBeInTheDocument()
    // u32le and i32le both decode to the same value here.
    expect(screen.getAllByText('1094795585').length).toBeGreaterThanOrEqual(2)
    // 0x41414141 seconds is 2004-09-09, a plausible unix timestamp.
    expect(
      screen.getByText(formatUtc(new Date(1094795585000).toISOString())),
    ).toBeInTheDocument()
  })

  // Serve an artifact's content, honouring Range requests, from a string.
  function mockContentRange(content: string) {
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/:artifactId/content',
        ({ request }) => {
          const range = request.headers.get('range')
          const match = range?.match(/bytes=(\d+)-(\d+)/)
          if (!match) return new HttpResponse(content)
          const start = Number(match[1])
          const end = Math.min(Number(match[2]), content.length - 1)
          const body = start < content.length ? content.slice(start, end + 1) : ''
          return new HttpResponse(body, {
            status: 206,
            headers: {
              'Content-Range': `bytes ${start}-${Math.max(start, end)}/${content.length}`,
            },
          })
        },
      ),
    )
  }

  it('renders the text viewer with line numbers, a wrap toggle and find', async () => {
    mockApi({})
    mockContentRange('alpha line\nbeta needle here\ngamma needle two\ndelta')
    const { container } = renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(screen.getByRole('tab', { name: 'Text' }))
    // Every source line gets a gutter number.
    await waitFor(() =>
      expect(container.querySelectorAll('.av-text-lineno').length).toBe(4),
    )
    expect(container.querySelector('.av-text-lineno')?.textContent).toBe('1')
    expect(screen.getByText('beta needle here')).toBeInTheDocument()
    // Wrap toggle flips the code container class.
    const wrapBtn = screen.getByRole('button', { name: /Wrap:/ })
    expect(container.querySelector('.av-text-code')).not.toHaveClass(
      'av-text-nowrap',
    )
    await userEvent.click(wrapBtn)
    expect(container.querySelector('.av-text-code')).toHaveClass(
      'av-text-nowrap',
    )
    // Find highlights every match and reports a running count.
    await userEvent.type(screen.getByLabelText('Find'), 'needle')
    await waitFor(() =>
      expect(container.querySelectorAll('.av-text-match').length).toBe(2),
    )
    expect(screen.getByText('1 / 2')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Next match' }))
    expect(screen.getByText('2 / 2')).toBeInTheDocument()
  })

  it('appends the next range via Load more', async () => {
    const CHUNK = 262144
    const content = 'STARTMARK ' + 'a'.repeat(CHUNK - 10) + 'ENDMARK'
    mockApi({})
    mockContentRange(content)
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(screen.getByRole('tab', { name: 'Text' }))
    const first = await screen.findByText(/STARTMARK/)
    expect(first.textContent).not.toContain('ENDMARK')
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await waitFor(() =>
      expect(screen.getByText(/STARTMARK/).textContent).toContain('ENDMARK'),
    )
    expect(
      screen.queryByRole('button', { name: 'Load more' }),
    ).not.toBeInTheDocument()
  })

  it('pretty-prints JSON content behind a toggle', async () => {
    mockApi({})
    mockContentRange('{"a":1,"b":[2,3]}')
    const { container } = renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(screen.getByRole('tab', { name: 'Text' }))
    // Raw: a single line.
    await waitFor(() =>
      expect(container.querySelectorAll('.av-text-line').length).toBe(1),
    )
    await userEvent.click(screen.getByRole('button', { name: /Pretty JSON/ }))
    // Pretty: expanded across multiple indented lines.
    await waitFor(() =>
      expect(
        container.querySelectorAll('.av-text-line').length,
      ).toBeGreaterThan(1),
    )
    expect(screen.getByText(/"a": 1/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Raw' })).toBeInTheDocument()
  })

  it('shows the conversation tab for a chat.db file and renders messages', async () => {
    const chat: Artifact = {
      id: 'art-chatdb',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'FileEntry',
      metadata: { name: 'chat.db', size: 4096 },
    }
    mockApi({ artifacts: { 'art-chatdb': chat } })
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const type = new URL(request.url).searchParams.get('type')
        const records =
          type === 'iMessage'
            ? [
                {
                  id: 'msg-1',
                  parent_id: 'art-chatdb',
                  artifact_type: 'ParsedRecord',
                  metadata: {
                    type: 'iMessage',
                    text: 'hey there',
                    date: '1700000000',
                    is_from_me: true,
                    direction: 'sent',
                    contact: 'Dave',
                    chat_identifier: 'chat-dave',
                    service: 'iMessage',
                    has_attachments: true,
                  },
                },
              ]
            : []
        return HttpResponse.json({
          records,
          total: records.length,
          page: 1,
          page_size: 500,
          type,
        })
      }),
    )
    renderPage(`/cases/${CASE}/artifacts/art-chatdb#conversation`)
    await screen.findByRole('heading', { name: 'chat.db' })
    expect(
      screen.getByRole('tab', { name: 'Conversation' }),
    ).toBeInTheDocument()
    const bubble = await screen.findByText('hey there')
    expect(bubble.closest('.av-msg')).toHaveClass('av-msg-out')
    expect(screen.getByText('attachment')).toHaveClass('badge')
  })

  it('lists children with type-appropriate links', async () => {
    const container: Artifact = {
      id: 'art-zip',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'Container',
      metadata: { name: 'evidence.tar' },
    }
    mockApi({ artifacts: { 'art-zip': container } })
    server.use(
      http.get('/api/v1/cases/:caseId/artifacts/:artifactId/children', () =>
        HttpResponse.json({ items: [
          {
            id: 'fs-1',
            parent_id: 'art-zip',
            artifact_type: 'FileSystem',
            name: 'NTFS',
            has_children: true,
          },
          {
            id: 'fe-1',
            parent_id: 'art-zip',
            artifact_type: 'FileEntry',
            name: 'file.txt',
            has_children: false,
          },
        ] }),
      ),
    )
    renderPage(`/cases/${CASE}/artifacts/art-zip`)
    await screen.findByRole('heading', { name: 'evidence.tar' })
    await userEvent.click(screen.getByRole('tab', { name: 'Children' }))
    const fsLink = await screen.findByRole('link', { name: 'NTFS' })
    expect(fsLink).toHaveAttribute('href', '/cases/case-1/files/fs-1?view=tree')
    expect(screen.getByRole('link', { name: 'file.txt' })).toHaveAttribute(
      'href',
      '/cases/case-1/artifacts/fe-1',
    )
    expect(screen.getByText('2 children')).toBeInTheDocument()
  })

  it('shows processing history and jobs', async () => {
    mockApi({})
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/:artifactId/processing-history',
        // A capped listing, like the server sends. Mocked as a bare array this
        // suite passed while the real tab threw on `.map`.
        () =>
          HttpResponse.json({
            items: [
              {
                id: 1,
                case_id: CASE,
                artifact_id: 'art-file',
                module_id: 'pdf_parser',
                status: 'success',
                artifacts_produced: 3,
                error_message: null,
                duration_ms: 1500,
                created_at: 1704164645,
              },
            ],
            truncated: false,
          }),
      ),
      http.get('/api/v1/cases/:caseId/artifacts/:artifactId/jobs', () =>
        HttpResponse.json([
          {
            id: 'job-1',
            case_id: CASE,
            module_id: 'strings_extractor',
            target_artifact_id: 'art-file',
            status: 'complete',
            artifacts_produced: 1,
            error_message: null,
            created_at: 1704164645,
            completed_at: 1704164650,
          },
        ]),
      ),
    )
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(screen.getByRole('tab', { name: 'Processing' }))
    expect(await screen.findByText('pdf_parser')).toBeInTheDocument()
    expect(screen.getByText('1.5 s')).toBeInTheDocument()
    expect(screen.getByText('success')).toHaveClass('badge-ok')
    expect(await screen.findByText('strings_extractor')).toBeInTheDocument()
    expect(screen.getByText('complete')).toHaveClass('badge-ok')
  })

  it('runs a module from the run module tab', async () => {
    mockApi({})
    let requestedModule: string | null = null
    server.use(
      http.get('/api/v1/modules', () =>
        HttpResponse.json([
          {
            id: 'pdf_parser',
            version: '1.0',
            subscribes_to: ['FileContent'],
            execution_mode: 'auto',
          },
        ]),
      ),
      http.get('/api/v1/cases/:caseId/artifacts/:artifactId/jobs', () =>
        HttpResponse.json([]),
      ),
      http.post(
        '/api/v1/cases/:caseId/artifacts/:artifactId/run_module',
        async ({ request }) => {
          const body = (await request.json()) as { module_id: string }
          requestedModule = body.module_id
          return HttpResponse.json({ job_id: 'job-9', status: 'pending' })
        },
      ),
    )
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    await userEvent.click(screen.getByRole('tab', { name: 'Run Module' }))
    const select = await screen.findByLabelText('Module')
    await userEvent.selectOptions(select, 'pdf_parser')
    await userEvent.click(screen.getByRole('button', { name: 'Run' }))
    expect(await screen.findByText(/job-9/)).toBeInTheDocument()
    expect(requestedModule).toBe('pdf_parser')
  })

  it('shows raw JSON for parsed records', async () => {
    const record: Artifact = {
      id: 'art-rec',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'ParsedRecord',
      metadata: { record_type: 'email', subject: 'hello' },
    }
    mockApi({ artifacts: { 'art-rec': record } })
    renderPage(`/cases/${CASE}/artifacts/art-rec`)
    await screen.findByRole('heading', { name: 'art-rec' })
    await userEvent.click(screen.getByRole('tab', { name: 'Raw JSON' }))
    expect(screen.getByText(/"record_type": "email"/)).toBeInTheDocument()
    // A derived record has no bytes on disk: no Download or Verify Integrity.
    expect(
      screen.queryByRole('button', { name: 'Download' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Verify Integrity' }),
    ).not.toBeInTheDocument()
    // Bookmarking a record is still fine.
    expect(
      screen.getByRole('button', { name: 'Add bookmark' }),
    ).toBeInTheDocument()
  })
})

const mftArtifact: Artifact = {
  id: 'art-mft',
  case_id: CASE,
  parent_id: null,
  artifact_type: 'FileEntry',
  metadata: {
    name: 'evil.exe',
    created: '2024-03-01T10:00:00Z',
    modified: '2024-03-02T11:00:00Z',
    mft_modified: '2024-03-02T11:00:00Z',
    accessed: '2024-03-03T12:00:00Z',
    fn_created: '2021-06-15T08:00:00Z',
    fn_modified: '2021-06-15T08:00:00Z',
    fn_mft_modified: '2021-06-15T08:00:00Z',
    fn_accessed: '2021-06-15T08:00:00Z',
    timestomp_suspected: true,
    timestomp_reasons: ['$SI created predates $FN created by over a year'],
  },
}

describe('ArtifactPage forensic panels', () => {
  it('renders md5 and sha256 hash cards with values and copy', async () => {
    mockApi({})
    const user = userEvent.setup()
    renderPage()
    await screen.findByRole('heading', { name: 'document.bin' })
    expect(screen.getByText('a'.repeat(32))).toBeInTheDocument()
    expect(screen.getByText('b'.repeat(64))).toBeInTheDocument()
    const copySha = screen.getByRole('button', { name: 'Copy SHA256' })
    await user.click(copySha)
    expect(copySha).toHaveTextContent('Copied')
    await expect(navigator.clipboard.readText()).resolves.toBe('b'.repeat(64))
  })

  it('renders the SI/FN MACB table and a timestomp warning', async () => {
    mockApi({ artifacts: { 'art-mft': mftArtifact } })
    renderPage(`/cases/${CASE}/artifacts/art-mft`)
    await screen.findByRole('heading', { name: 'evil.exe' })
    expect(screen.getByText('Timestamp analysis')).toBeInTheDocument()
    expect(screen.getByText('Standard ($SI)')).toBeInTheDocument()
    expect(screen.getByText('FileName ($FN)')).toBeInTheDocument()
    // $SI created and $FN created rendered via formatUtc (the $SI value also
    // appears as an overview card, so allow more than one match).
    expect(
      screen.getAllByText('2024-03-01 10:00:00 UTC').length,
    ).toBeGreaterThanOrEqual(1)
    expect(
      screen.getAllByText('2021-06-15 08:00:00 UTC').length,
    ).toBeGreaterThanOrEqual(1)
    expect(
      screen.getByText('Possible timestomping detected'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/\$SI created predates \$FN created/),
    ).toBeInTheDocument()
  })

  it('shows a consistent note when timestomping is not suspected', async () => {
    const clean: Artifact = {
      ...mftArtifact,
      id: 'art-clean',
      metadata: {
        ...mftArtifact.metadata,
        timestomp_suspected: false,
        timestomp_reasons: [],
      },
    }
    mockApi({ artifacts: { 'art-clean': clean } })
    renderPage(`/cases/${CASE}/artifacts/art-clean`)
    await screen.findByRole('heading', { name: 'evil.exe' })
    expect(screen.getByText(/timestamps are consistent/)).toBeInTheDocument()
    expect(
      screen.queryByText('Possible timestomping detected'),
    ).not.toBeInTheDocument()
  })

  it('shows a weak indicator as an observation, not as a tampering verdict', async () => {
    // HUNT-051. A copy keeps the source's Last-Modified in $SI while $FN
    // records when the copy landed, so this pattern is what an installed file
    // looks like. It used to render in the same red box as tampering, on a
    // sixth of a stock Windows install.
    const copied: Artifact = {
      ...mftArtifact,
      id: 'art-copied',
      metadata: {
        ...mftArtifact.metadata,
        timestomp_suspected: false,
        timestomp_reasons: [],
        timestamp_indicators: [
          {
            reason: 'SI Modified precedes FN Created',
            strength: 'weak',
            also_produced_by:
              "a copy, which preserves the source's modification time in $SI while $FN records when the copy landed",
          },
        ],
      },
    }
    mockApi({ artifacts: { 'art-copied': copied } })
    renderPage(`/cases/${CASE}/artifacts/art-copied`)
    await screen.findByRole('heading', { name: 'evil.exe' })

    expect(
      screen.queryByText('Possible timestomping detected'),
    ).not.toBeInTheDocument()
    const note = screen.getByTestId('av-ts-indicators')
    expect(note.textContent).toMatch(
      /1 timestamp indicator, which ordinary file activity also produces/,
    )
    // The ordinary operation is named beside the observation.
    expect(note.textContent).toMatch(/also produced by a copy, which preserves/)
    // And the panel refuses the inference outright.
    expect(note.textContent).toMatch(/Nothing here says this file was tampered with/)
  })

  it('says what a strong indicator rules out when it does assert tampering', async () => {
    const stomped: Artifact = {
      ...mftArtifact,
      id: 'art-stomped',
      metadata: {
        ...mftArtifact.metadata,
        timestomp_suspected: true,
        timestomp_reasons: [
          'SI M/A/C/B timestamps identical to the second (bulk-set)',
        ],
        timestamp_indicators: [
          {
            reason: 'SI M/A/C/B timestamps identical to the second (bulk-set)',
            strength: 'strong',
            also_produced_by: null,
          },
        ],
      },
    }
    mockApi({ artifacts: { 'art-stomped': stomped } })
    renderPage(`/cases/${CASE}/artifacts/art-stomped`)
    await screen.findByRole('heading', { name: 'evil.exe' })
    expect(screen.getByText('Possible timestomping detected')).toBeInTheDocument()
    expect(
      screen.getByText('No ordinary copy, move or rename produces this.'),
    ).toBeInTheDocument()
    // The observation list is for the weak ones; a verdict does not repeat
    // itself in the quiet note below it.
    expect(screen.queryByTestId('av-ts-indicators')).not.toBeInTheDocument()
  })

  it('renders the EXIF section with camera and a GPS map dot', async () => {
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()
    const photo: Artifact = {
      id: 'art-photo',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'FileContent',
      metadata: { name: 'photo.jpg', size: 4 },
    }
    mockApi({
      artifacts: { 'art-photo': photo },
      children: [
        {
          id: 'rec-exif',
          parent_id: 'art-photo',
          artifact_type: 'ParsedRecord',
          name: 'ParsedRecord',
          has_children: false,
          metadata: {
            type: 'exif',
            camera: 'Canon EOS 5D',
            datetime_original: '2024:05:01 09:30:00',
            width: 6000,
            height: 4000,
            fnumber: 2.8,
            iso: 100,
            focal_length: 50,
            software: 'Lightroom',
            has_gps: true,
            gps_lat: 51.5,
            gps_lon: -0.12,
            gps_altitude: 35,
          },
        },
      ],
    })
    server.use(
      http.get('/api/v1/cases/:caseId/artifacts/:artifactId/content', () =>
        HttpResponse.arrayBuffer(
          new Uint8Array([0xff, 0xd8, 0xff, 0xe0]).buffer,
          { headers: { 'Content-Type': 'image/jpeg' } },
        ),
      ),
    )
    renderPage(`/cases/${CASE}/artifacts/art-photo#preview`)
    await screen.findByRole('heading', { name: 'photo.jpg' })
    expect(
      await screen.findByText('Image metadata (EXIF)'),
    ).toBeInTheDocument()
    // The whole point of the inspector: the image (center) and its EXIF/GPS
    // (right-hand inspector) are visible at the same time.
    expect(screen.getByRole('img', { name: 'photo.jpg' })).toBeInTheDocument()
    expect(screen.getByText('Canon EOS 5D')).toBeInTheDocument()
    expect(screen.getByText('51.5, -0.12')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Copy coordinates' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('img', { name: /Location plotted at 51.5, -0.12/ }),
    ).toBeInTheDocument()
  })

  it('omits the EXIF section when the image has no exif child', async () => {
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()
    const photo: Artifact = {
      id: 'art-photo2',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'FileContent',
      metadata: { name: 'plain.jpg', size: 4 },
    }
    mockApi({ artifacts: { 'art-photo2': photo }, children: [] })
    server.use(
      http.get('/api/v1/cases/:caseId/artifacts/:artifactId/content', () =>
        HttpResponse.arrayBuffer(
          new Uint8Array([0xff, 0xd8, 0xff, 0xe0]).buffer,
          { headers: { 'Content-Type': 'image/jpeg' } },
        ),
      ),
    )
    renderPage(`/cases/${CASE}/artifacts/art-photo2#preview`)
    await screen.findByRole('img', { name: 'plain.jpg' })
    expect(
      screen.queryByText('Image metadata (EXIF)'),
    ).not.toBeInTheDocument()
  })

  it('surfaces a SQLite forensic summary with a link to the row viewer', async () => {
    const db: Artifact = {
      id: 'art-db',
      case_id: CASE,
      parent_id: null,
      artifact_type: 'FileEntry',
      metadata: { name: 'places.sqlite', size: 8192 },
    }
    mockApi({
      artifacts: { 'art-db': db },
      children: [
        {
          id: 'rec-sum',
          parent_id: 'art-db',
          artifact_type: 'ParsedRecord',
          name: 'ParsedRecord',
          has_children: false,
          metadata: {
            type: 'SqliteDatabaseForensics',
            live_rows: 128,
            deleted_rows: 47,
            carved_rows: 6,
          },
        },
      ],
    })
    renderPage(`/cases/${CASE}/artifacts/art-db`)
    await screen.findByRole('heading', { name: 'places.sqlite' })
    expect(
      await screen.findByText('SQLite forensic summary'),
    ).toBeInTheDocument()
    expect(screen.getByText('128')).toBeInTheDocument()
    expect(screen.getByText('47')).toHaveClass('av-danger')
    expect(
      screen.getByRole('link', { name: 'View recovered rows' }),
    ).toHaveAttribute(
      'href',
      '/cases/case-1/analysis?type=SqliteRow&source_id=art-db',
    )
  })
})

describe('ArtifactPage related timeline', () => {
  it('mounts the events-around-this-artifact view from the Timeline tab', async () => {
    mockApi({})
    let asked = 0
    server.use(
      http.get(`/api/v1/cases/${CASE}/timeline/related/art-file`, () => {
        asked += 1
        return HttpResponse.json({ events: [], truncated: false, cap: 2000 })
      }),
    )
    renderPage()
    await userEvent.click(await screen.findByRole('tab', { name: 'Timeline' }))
    expect(
      await screen.findByText(/no timeline events are recorded for this artifact/i),
    ).toBeInTheDocument()
    expect(asked).toBe(1)
  })
})
