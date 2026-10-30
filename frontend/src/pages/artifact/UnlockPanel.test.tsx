import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import type { Artifact } from '../../api/types'
import { UnlockPanel } from './UnlockPanel'

const CASE_ID = 'c1'

/** A locked-state record, a child of the artifact the backup IS (`f-<id>`). */
function artifact(metadata: Record<string, unknown>, id = 'a1'): Artifact {
  return {
    id,
    case_id: CASE_ID,
    parent_id: `f-${id}`,
    artifact_type: 'ParsedRecord',
    metadata,
  } as Artifact
}

function renderPanel(a: Artifact) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const ui = (target: Artifact, caseId: string) => (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <UnlockPanel caseId={caseId} artifact={target} />
      </ToastProvider>
    </QueryClientProvider>
  )
  const utils = render(ui(a, CASE_ID))
  return {
    ...utils,
    /** Navigate to another locked artifact without unmounting the panel. */
    open: (target: Artifact, caseId = CASE_ID) =>
      utils.rerender(ui(target, caseId)),
  }
}

type CredentialBody = { kind: string; secret: string }

/**
 * Mock the credential route and the job it returns. `jobs` maps a job id to the
 * job the server reports; every POST to run_module is recorded so a test can
 * assert nothing is sent there (SEC-204).
 */
function mockCredentialRoute(opts: {
  jobs?: Record<string, Record<string, unknown>>
  hold?: Promise<void>
} = {}) {
  const bodies: { target: string; body: CredentialBody }[] = []
  const moduleRuns: unknown[] = []
  const jobPolls: string[] = []
  let n = 0
  server.use(
    http.post(
      `/api/v1/cases/${CASE_ID}/artifacts/:artifactId/credential`,
      async ({ request, params }) => {
        bodies.push({
          target: params.artifactId as string,
          body: (await request.json()) as CredentialBody,
        })
        if (opts.hold) await opts.hold
        n += 1
        return HttpResponse.json({
          job_id: `j${n}`,
          status: 'pending',
          kind: 'k',
          module_id: 'm',
          note: '',
        })
      },
    ),
    http.post(
      `/api/v1/cases/${CASE_ID}/artifacts/:artifactId/run_module`,
      async ({ request }) => {
        moduleRuns.push(await request.json())
        return HttpResponse.json({ job_id: 'jx', status: 'pending' })
      },
    ),
    http.get(`/api/v1/cases/${CASE_ID}/jobs/:jobId`, ({ params }) => {
      const id = params.jobId as string
      jobPolls.push(id)
      const job = opts.jobs?.[id] ?? { status: 'running' }
      return HttpResponse.json({
        id,
        case_id: CASE_ID,
        module_id: 'm',
        target_artifact_id: 'f-a1',
        artifacts_produced: 0,
        error_message: null,
        created_at: 0,
        completed_at: null,
        ...job,
      })
    }),
  )
  return { bodies, moduleRuns, jobPolls }
}

describe('UnlockPanel', () => {
  it('submits the passphrase to the credential route with its kind, never run_module secrets', async () => {
    const { bodies, moduleRuns } = mockCredentialRoute()
    renderPanel(
      artifact({
        type: 'SignalBackup',
        decrypted: false,
        file_name: 'mediaanalysis.backup',
      }),
    )

    const field = screen.getByLabelText(/passphrase/i)
    // A password field, so the value is not shoulder-readable.
    expect(field).toHaveAttribute('type', 'password')

    await userEvent.type(field, 'correct horse battery staple')
    await userEvent.click(screen.getByRole('button', { name: 'Decrypt' }))

    await waitFor(() => expect(bodies).toHaveLength(1))
    // Aimed at the artifact the backup IS (the record's parent), not at the
    // status record, which has no bytes of its own.
    expect(bodies[0].target).toBe('f-a1')
    expect(bodies[0].body).toEqual({
      kind: 'signal_backup_passphrase',
      secret: 'correct horse battery staple',
    })
    expect(moduleRuns).toHaveLength(0)

    // Cleared once handed over, so it is not left sitting in the DOM.
    await waitFor(() => expect(field).toHaveValue(''))
  })

  it('a failed credential job shows the rejection', async () => {
    // A rejected secret persists nothing, so the verdict cannot be read from
    // the artifact's children (they never change): it is the job's outcome.
    mockCredentialRoute({
      jobs: {
        j1: {
          status: 'failed',
          error_message:
            'The supplied Signal backup passphrase did not open this artifact (the first frame\'s MAC did not verify). Nothing in the case changed.',
        },
      },
    })
    renderPanel(artifact({ type: 'SignalBackup', decrypted: false }))
    await userEvent.type(screen.getByLabelText(/passphrase/i), 'guess')
    await userEvent.click(screen.getByRole('button', { name: 'Decrypt' }))
    expect(await screen.findByText(/Not decrypted/)).toHaveTextContent(
      /did not open this artifact/,
    )
    expect(screen.queryByText(/Working…/)).not.toBeInTheDocument()
  })

  it('a completed credential job says the passphrase opened it', async () => {
    mockCredentialRoute({
      jobs: { j1: { status: 'complete', artifacts_produced: 12 } },
    })
    renderPanel(artifact({ type: 'SignalBackup', decrypted: false }))
    await userEvent.type(screen.getByLabelText(/passphrase/i), 'right')
    await userEvent.click(screen.getByRole('button', { name: 'Decrypt' }))
    expect(await screen.findByText(/Passphrase accepted/)).toBeInTheDocument()
  })

  it('never carries a typed passphrase to the next locked artifact', async () => {
    // The artifact page stays mounted when `:artifactId` changes. An unscoped
    // field leaves the previous backup's secret sitting in the form, one click
    // from being submitted against a container it was never meant for.
    const { open } = renderPanel(
      artifact({ type: 'SignalBackup', decrypted: false }, 'a1'),
    )
    const field = screen.getByLabelText(/passphrase/i)
    await userEvent.type(field, 'first backup secret')
    expect(field).toHaveValue('first backup secret')

    open(artifact({ type: 'SignalBackup', decrypted: false }, 'a2'))

    expect(screen.getByLabelText(/passphrase/i)).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Decrypt' })).toBeDisabled()
  })

  it('never reports a decryption verdict for an artifact nobody tried', async () => {
    // The attempt is what puts the verdict line on screen. Carried across a
    // navigation it asserts "accepted"/"not decrypted" about THIS artifact on
    // the strength of an attempt made on a different one.
    const { jobPolls } = mockCredentialRoute()
    const { open } = renderPanel(
      artifact({ type: 'SignalBackup', decrypted: false }, 'a1'),
    )
    await userEvent.type(screen.getByLabelText(/passphrase/i), 'guess')
    await userEvent.click(screen.getByRole('button', { name: 'Decrypt' }))
    await screen.findByText(/Working…/)
    await waitFor(() => expect(jobPolls).toContain('j1'))

    open(artifact({ type: 'SignalBackup', decrypted: false }, 'a2'))

    // Rendered straight from the scoped attempt, so the wrong answer is on
    // screen in the very frame the switch produces.
    expect(screen.queryByText(/Working…/)).not.toBeInTheDocument()
  })

  it('does not land a late submit on the artifact the examiner moved to', async () => {
    // react-query hands the response to the CURRENT render's callback, so a
    // submit that settles after a navigation would write the attempt into the
    // NEXT artifact's scope, and that panel would say a decryption is running.
    let release: () => void = () => {}
    const hold = new Promise<void>((resolve) => {
      release = resolve
    })
    const { bodies } = mockCredentialRoute({ hold })
    const { open } = renderPanel(
      artifact({ type: 'SignalBackup', decrypted: false }, 'a1'),
    )
    await userEvent.type(screen.getByLabelText(/passphrase/i), 'guess')
    await userEvent.click(screen.getByRole('button', { name: 'Decrypt' }))

    open(artifact({ type: 'SignalBackup', decrypted: false }, 'a2'))
    // The request is still in flight, and it is not this artifact's request.
    expect(
      screen.queryByRole('button', { name: 'Decrypting…' }),
    ).not.toBeInTheDocument()

    release()
    await waitFor(() => expect(bodies).toHaveLength(1))
    // Typing flushes the settled mutation's callbacks through act(), so the
    // assertion below runs after the response has had every chance to land.
    await userEvent.type(screen.getByLabelText(/passphrase/i), 'x')

    expect(screen.queryByText(/Working…/)).not.toBeInTheDocument()
  })

  it('offers nothing for an artifact that is not locked', () => {
    renderPanel(artifact({ type: 'SignalBackup', decrypted: true }))
    expect(screen.queryByLabelText(/passphrase/i)).not.toBeInTheDocument()
  })

  it('offers nothing for an unrelated record type', () => {
    renderPanel(artifact({ type: 'iMessage' }))
    expect(screen.queryByLabelText(/passphrase/i)).not.toBeInTheDocument()
  })
})

/**
 * HUNT-085, as amended by SEC-204. An encrypted iOS backup's record says
 * "provide the password to decrypt and extract them"; the password now goes
 * through the credential route (kind `ios_backup_password`), held zeroed for
 * the one run and audited by kind and outcome.
 */
describe('UnlockPanel — encrypted iOS backup', () => {
  it('offers the passphrase box for a backup nobody has the password for', async () => {
    renderPanel(
      artifact({
        type: 'IosBackupInfo',
        status: 'encrypted_no_password',
        name: 'iOS backup (encrypted, not extracted)',
      }),
    )
    expect(await screen.findByText(/iOS backup/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/passphrase|password/i)).toBeInTheDocument()
  })

  it('sends it to the credential route as an ios_backup_password, aimed at the backup folder', async () => {
    const { bodies, moduleRuns } = mockCredentialRoute()
    renderPanel(
      artifact({ type: 'IosBackupInfo', status: 'encrypted_no_password' }),
    )
    await userEvent.type(
      await screen.findByLabelText(/passphrase|password/i),
      'MyPassword123',
    )
    await userEvent.click(screen.getByRole('button', { name: /unlock|decrypt/i }))
    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0].target).toBe('f-a1')
    expect(bodies[0].body).toEqual({
      kind: 'ios_backup_password',
      secret: 'MyPassword123',
    })
    expect(moduleRuns).toHaveLength(0)
  })

  it('sends the password exactly as typed, leading and trailing spaces included', async () => {
    // SEC-204 review: an iOS backup password is whatever its owner typed. A
    // trimmed password is a different password, and a wrong one.
    const { bodies } = mockCredentialRoute()
    renderPanel(
      artifact({ type: 'IosBackupInfo', status: 'encrypted_no_password' }),
    )
    await userEvent.type(
      await screen.findByLabelText(/passphrase|password/i),
      ' pass word ',
    )
    await userEvent.click(screen.getByRole('button', { name: /unlock|decrypt/i }))
    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0].body).toEqual({
      kind: 'ios_backup_password',
      secret: ' pass word ',
    })
  })

  it('does not offer to re-supply a password that already worked', () => {
    // PartialDecryption means the backup DID decrypt and some files were still
    // unreadable; a passphrase box there invites the wrong fix.
    renderPanel(artifact({ type: 'IosBackupInfo', status: 'PartialDecryption' }))
    expect(screen.queryByLabelText(/passphrase|password/i)).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /unlock|decrypt/i }),
    ).not.toBeInTheDocument()
  })
})

/**
 * ROADMAP §5.7 (owner decision (c) part b): a crypt14 or crypt15 WhatsApp
 * backup whose key is not in the case takes it as the `whatsapp_key` credential.
 */
describe('UnlockPanel — WhatsApp backup awaiting its key', () => {
  it('sends the key to the credential route as a whatsapp_key, aimed at the backup file', async () => {
    const { bodies, moduleRuns } = mockCredentialRoute()
    renderPanel(artifact({ type: 'WhatsAppBackup', status: 'AwaitingKey' }))
    await userEvent.type(
      await screen.findByLabelText(/passphrase|password|key/i),
      'aabb',
    )
    await userEvent.click(screen.getByRole('button', { name: /unlock|decrypt/i }))
    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0].target).toBe('f-a1')
    expect(bodies[0].body).toEqual({ kind: 'whatsapp_key', secret: 'aabb' })
    expect(moduleRuns).toHaveLength(0)
  })

  it('offers the same key field for a crypt15 awaiting its end-to-end key', async () => {
    const { bodies } = mockCredentialRoute()
    renderPanel(artifact({ type: 'WhatsAppBackup', status: 'AwaitingKey', scheme: 'crypt15' }))
    await userEvent.type(
      await screen.findByLabelText(/passphrase|password|key/i),
      'ccdd',
    )
    await userEvent.click(screen.getByRole('button', { name: /unlock|decrypt/i }))
    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0].body).toEqual({ kind: 'whatsapp_key', secret: 'ccdd' })
  })

  it('offers nothing for a backup that is not awaiting a key', () => {
    // A Decrypted backup is open; a NotDecrypted or KeyRefused statement is
    // not the one a key answers (the AwaitingKey statement is).
    for (const status of ['NotDecrypted', 'Decrypted', 'KeyRefused']) {
      const { unmount } = renderPanel(
        artifact({ type: 'WhatsAppBackup', status, scheme: 'crypt15' }),
      )
      expect(
        screen.queryByRole('button', { name: /unlock|decrypt/i }),
      ).not.toBeInTheDocument()
      unmount()
    }
  })
})
