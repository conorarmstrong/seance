import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { resetThumbnailCache } from '../../lib/thumbnails'
import { ToastProvider } from '../../components/toast/ToastProvider'
import type { ParsedRecord } from './api'
import { makeChatMediaViewer } from './ChatMediaViewer'

const CASE_ID = 'c1'
const Viewer = makeChatMediaViewer('iMessage')

function rec(id: string, metadata: Record<string, unknown>): ParsedRecord {
  return { id, parent_id: 'db1', artifact_type: 'ParsedRecord', metadata }
}

const records = [
  // No message link: the referencing message is gone.
  rec('a1', {
    type: 'iMessageAttachment',
    filename: '~/Library/SMS/Attachments/ab/12/G/ORPHAN.jpeg',
    transfer_name: 'ORPHAN.jpeg',
    mime_type: 'image/jpeg',
    total_bytes: 2048,
  }),
  // Linked to a message, so the conversation already shows it.
  rec('a2', {
    type: 'iMessageAttachment',
    message_guid: 'MSG-1',
    filename: '~/Library/SMS/Attachments/cd/34/G/LINKED.jpeg',
    transfer_name: 'LINKED.jpeg',
    mime_type: 'image/jpeg',
    total_bytes: 4096,
  }),
]

function renderViewer() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>
          {/* The viewer is aggregate: it loads its own records, so the prop is
              just the page shell's page-1 and not what it renders. */}
          <Viewer caseId={CASE_ID} type="iMessageAttachment" records={[]} />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  resetThumbnailCache()
  URL.createObjectURL = vi.fn(() => 'blob:media')
  URL.revokeObjectURL = vi.fn()
  server.use(
    // The viewer loads the whole attachment set itself.
    http.get(`/api/v1/cases/${CASE_ID}/records`, () =>
      HttpResponse.json({
        records,
        total: records.length,
        page: 1,
        page_size: 100,
        type: 'iMessageAttachment',
      }),
    ),
    http.get(`/api/v1/cases/${CASE_ID}/bookmarks/ids`, () =>
      HttpResponse.json([]),
    ),
    http.get(`/api/v1/cases/${CASE_ID}/bookmarks/categories`, () =>
      HttpResponse.json([]),
    ),
    http.post(`/api/v1/cases/${CASE_ID}/files/resolve`, async ({ request }) => {
      const body = (await request.json()) as { paths: string[] }
      // Only the orphan's bytes are present in the evidence.
      const matches: Record<string, string> = {}
      for (const p of body.paths) {
        if (p.includes('ORPHAN')) matches[p] = 'file-orphan'
      }
      return HttpResponse.json({ matches })
    }),
    http.get(
      `/api/v1/cases/${CASE_ID}/artifacts/:artifactId/thumbnail`,
      () =>
        new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
          headers: { 'Content-Type': 'image/png' },
        }),
    ),
  )
})

describe('ChatMediaViewer', () => {
  it('shows only unlinked media by default, on the shared media browser', async () => {
    renderViewer()

    expect(await screen.findByText('ORPHAN.jpeg')).toBeInTheDocument()
    // The linked one lives in the conversation, not here.
    expect(screen.queryByText('LINKED.jpeg')).not.toBeInTheDocument()

    // Its thumbnail resolves from the located bytes.
    await waitFor(() =>
      expect(
        screen.getByAltText('Thumbnail of ORPHAN.jpeg'),
      ).toHaveAttribute('src', 'blob:media'),
    )

    // Selecting it opens the properties sidebar, which links to the artifact.
    await userEvent.click(screen.getByText('ORPHAN.jpeg'))
    const sidebar = screen.getByRole('complementary', {
      name: 'attachment properties',
    })
    expect(
      within(sidebar).getByRole('link', { name: 'Open artifact' }),
    ).toHaveAttribute('href', `/cases/${CASE_ID}/artifacts/file-orphan`)
  })

  it('can show every attachment, marking ones absent from the evidence', async () => {
    renderViewer()
    await screen.findByText('ORPHAN.jpeg')

    await userEvent.click(screen.getByRole('button', { name: 'All media' }))
    const linked = await screen.findByText('LINKED.jpeg')

    // Its bytes are not in the backup, so it is flagged and not openable.
    const cell = linked.closest('.gl-cell')!
    expect(
      within(cell as HTMLElement).getByText('not in evidence'),
    ).toBeInTheDocument()
  })
})

describe('ChatMediaViewer failed path resolution (B4-031)', () => {
  it('says the lookup failed rather than leaving the wall looking unfinished', async () => {
    // On a failed resolve the cells get neither an open action nor "not in
    // evidence", which reads as "still loading" forever. Whether this media is
    // in the evidence is unknown, and that is what has to be said.
    server.use(
      http.post(`/api/v1/cases/${CASE_ID}/files/resolve`, () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'resolve failed' } },
          { status: 500 },
        ),
      ),
    )
    renderViewer()

    const chip = await screen.findByTestId('chat-media-resolve-failed')
    expect(chip.textContent).toContain('lookup failed')
    expect(chip.getAttribute('title')).toContain(
      'is not a finding that it is absent',
    )
  })
})
