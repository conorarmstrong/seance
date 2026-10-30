import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import type { Artifact } from '../../api/types'
import { VolumeReadUnlockPanel } from './VolumeReadUnlockPanel'

const CASE_ID = 'c1'

/** A file record beneath a volume decrypted during a run (HUNT-254). */
const file: Artifact = {
  id: 'f1',
  case_id: CASE_ID,
  parent_id: 'fs',
  artifact_type: 'FileEntry',
  metadata: { name: 'report.docx' },
} as Artifact

function mockAncestors(decrypted: 'bitlocker' | 'luks' | null) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/artifacts/:artifactId/ancestors`, () =>
      HttpResponse.json([
        { id: 'img', name: 'disk.E01', artifact_type: 'RawEvidence' },
        {
          id: 'dv',
          name: 'p2 (decrypted)',
          artifact_type: 'Partition',
          ...(decrypted ? { decrypted_volume: decrypted } : {}),
        },
        { id: 'fs', name: 'NTFS', artifact_type: 'FileSystem' },
        { id: 'f1', name: 'report.docx', artifact_type: 'FileEntry' },
      ]),
    ),
  )
}

function mockUnlockRoute() {
  const posts: { target: string; body: { kind: string; secret: string } }[] =
    []
  const deletes: string[] = []
  server.use(
    http.post(
      `/api/v1/cases/${CASE_ID}/artifacts/:artifactId/unlock`,
      async ({ request, params }) => {
        posts.push({
          target: params.artifactId as string,
          body: (await request.json()) as { kind: string; secret: string },
        })
        return HttpResponse.json({
          status: 'unlocked',
          kind: 'bitlocker_password',
          volume_artifact_id: 'locked',
          expires_in_secs: 28800,
          note: '',
        })
      },
    ),
    http.delete(
      `/api/v1/cases/${CASE_ID}/artifacts/:artifactId/unlock`,
      ({ params }) => {
        deletes.push(params.artifactId as string)
        return HttpResponse.json({
          status: 'locked',
          kind: 'bitlocker_password',
          was_unlocked: true,
        })
      },
    ),
  )
  return { posts, deletes }
}

function renderPanel(a: Artifact) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <VolumeReadUnlockPanel caseId={CASE_ID} artifact={a} />
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('VolumeReadUnlockPanel', () => {
  it('offers Unlock to read beneath a decrypted BitLocker volume and posts the chosen kind', async () => {
    mockAncestors('bitlocker')
    const { posts, deletes } = mockUnlockRoute()
    renderPanel(file)
    const field = await screen.findByLabelText(/bitlocker .* to read/i)
    await userEvent.selectOptions(
      screen.getByLabelText(/credential kind/i),
      'bitlocker_recovery_password',
    )
    await userEvent.type(field, ' 111111-222222 ')
    await userEvent.click(screen.getByRole('button', { name: /unlock to read/i }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]).toEqual({
      target: 'f1',
      body: { kind: 'bitlocker_recovery_password', secret: ' 111111-222222 ' },
    })
    expect(await screen.findByRole('status')).toHaveTextContent(/unlocked/i)
    expect(field).toHaveValue('')
    await userEvent.click(screen.getByRole('button', { name: /lock again/i }))
    await waitFor(() => expect(deletes).toEqual(['f1']))
  })

  it('asks for a LUKS passphrase beneath a decrypted LUKS volume', async () => {
    mockAncestors('luks')
    const { posts } = mockUnlockRoute()
    renderPanel(file)
    const field = await screen.findByLabelText(/luks passphrase to read/i)
    expect(screen.queryByLabelText(/credential kind/i)).toBeNull()
    await userEvent.type(field, 'pp')
    await userEvent.click(screen.getByRole('button', { name: /unlock to read/i }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0].body.kind).toBe('luks_passphrase')
  })

  it('offers nothing when no ancestor is a decrypted volume', async () => {
    mockAncestors(null)
    renderPanel(file)
    // Let the ancestors query settle before asserting absence.
    await new Promise((r) => setTimeout(r, 50))
    expect(screen.queryByRole('button', { name: /unlock to read/i })).toBeNull()
  })
})
