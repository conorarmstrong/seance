import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import type { Artifact } from '../../api/types'
import { ReadUnlockPanel } from './ReadUnlockPanel'

const CASE_ID = 'c1'

/** A file of an encrypted iOS backup, as ingest records it (BUG-026). */
function backupFile(metadata: Record<string, unknown> = {}): Artifact {
  return {
    id: 'f1',
    case_id: CASE_ID,
    parent_id: 'folder',
    artifact_type: 'ParsedRecord',
    metadata: {
      type: 'IosBackupFile',
      name: 'sms.db',
      file_id: 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2',
      backup_path: '/evidence/backup',
      encrypted: true,
      decrypted: true,
      ...metadata,
    },
  } as Artifact
}

function renderPanel(a: Artifact) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <ReadUnlockPanel caseId={CASE_ID} artifact={a} />
      </ToastProvider>
    </QueryClientProvider>,
  )
}

function mockUnlockRoute() {
  const posts: { target: string; body: { kind: string; secret: string } }[] =
    []
  const deletes: string[] = []
  const credentialPosts: unknown[] = []
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
          kind: 'ios_backup_password',
          expires_in_secs: 28800,
          file_count: 1,
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
          kind: 'ios_backup_password',
          was_unlocked: true,
        })
      },
    ),
    http.post(
      `/api/v1/cases/${CASE_ID}/artifacts/:artifactId/credential`,
      async ({ request }) => {
        credentialPosts.push(await request.json())
        return HttpResponse.json({ job_id: 'j', status: 'pending' })
      },
    ),
  )
  return { posts, deletes, credentialPosts }
}

describe('ReadUnlockPanel', () => {
  it('posts the backup password to the unlock route, not the credential route, and can lock again', async () => {
    const { posts, deletes, credentialPosts } = mockUnlockRoute()
    renderPanel(backupFile())
    const field = screen.getByLabelText(/backup password to read/i)
    await userEvent.type(field, ' pass word ')
    await userEvent.click(screen.getByRole('button', { name: /unlock to read/i }))

    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]).toEqual({
      target: 'f1',
      body: { kind: 'ios_backup_password', secret: ' pass word ' },
    })
    expect(credentialPosts).toHaveLength(0)
    expect(await screen.findByRole('status')).toHaveTextContent(/unlocked/i)
    expect(field).toHaveValue('')

    await userEvent.click(screen.getByRole('button', { name: /lock again/i }))
    await waitFor(() => expect(deletes).toEqual(['f1']))
  })

  it('offers nothing for a file that is not an encrypted backup file', () => {
    renderPanel(backupFile({ encrypted: false, decrypted: undefined }))
    expect(screen.queryByLabelText(/backup password to read/i)).toBeNull()
  })

  it('offers nothing for a backup directory record', () => {
    renderPanel(backupFile({ is_directory: true }))
    expect(screen.queryByLabelText(/backup password to read/i)).toBeNull()
  })

  it('shows the server refusal for a wrong password and holds nothing', async () => {
    server.use(
      http.post(
        `/api/v1/cases/${CASE_ID}/artifacts/:artifactId/unlock`,
        () =>
          HttpResponse.json(
            {
              error: {
                code: 'INVALID_REQUEST',
                message: 'the iOS backup password was refused',
              },
            },
            { status: 400 },
          ),
      ),
    )
    renderPanel(backupFile())
    await userEvent.type(
      screen.getByLabelText(/backup password to read/i),
      'wrong',
    )
    await userEvent.click(screen.getByRole('button', { name: /unlock to read/i }))
    expect(await screen.findByRole('status')).toHaveTextContent(/refused/i)
  })
})
