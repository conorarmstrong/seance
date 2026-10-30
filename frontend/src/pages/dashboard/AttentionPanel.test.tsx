import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { AttentionPanel } from './AttentionPanel'
import type { AttentionItem, AttentionQueue } from './api'

const SCOPE =
  "This queue holds only the problems someone can still do something about. It is NOT the case's completeness record."

function queue(items: AttentionItem[], over: Partial<AttentionQueue> = {}): AttentionQueue {
  return {
    items,
    groups: items.length,
    artifacts: items.reduce((n, i) => n + i.count, 0),
    actionable_artifacts: items
      .filter((i) => i.action !== null && i.action.kind !== 'unsupported')
      .reduce((n, i) => n + i.count, 0),
    reasons_examined: ['encrypted'],
    scope_note: SCOPE,
    ...over,
  }
}

function mock(body: AttentionQueue) {
  server.use(
    http.get('/api/v1/cases/c1/attention', () => HttpResponse.json(body)),
  )
}

function renderPanel() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AttentionPanel caseId="c1" />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const encryptedBackup: AttentionItem = {
  record_type: 'IosBackupInfo',
  scheme: null,
  reason: 'encrypted',
  count: 1,
  examples: [
    {
      artifact_id: 'rec-1',
      target_id: 'src-1',
      name: 'iOS backup (encrypted, not extracted)',
      detail: 'no files from it are in this case',
    },
  ],
  examples_truncated: false,
  problem: 'An encrypted iOS backup was not extracted',
  guidance:
    "Supply the backup password here — the password is held in memory for the length of that run only and is never written to the case.",
  action: {
    kind: 'supply_secret',
    module_id: 'plugin.mobile.ios_backup',
    secret_key: 'ios_backup_password',
    label: "The backup's password",
    route: 'credential',
    alternatives: [],
  },
  unrecognised_note: null,
}

/** A locked BitLocker volume, as the queue reports it since HUNT-120. */
const lockedBitlocker: AttentionItem = {
  record_type: 'VolumeDecryption',
  scheme: 'BitLocker',
  reason: 'encrypted',
  count: 2,
  // Two statements about ONE volume: the unlock must run once, not twice.
  examples: [
    { artifact_id: 'rec-a', target_id: 'vol-1', name: 'locked', detail: null },
    { artifact_id: 'rec-b', target_id: 'vol-1', name: 'failed', detail: null },
  ],
  examples_truncated: false,
  problem: 'A BitLocker volume was not decrypted',
  guidance: 'The contents of this volume are NOT in the case.',
  action: {
    kind: 'supply_secret',
    module_id: 'plugin.crypto.bitlocker_decryptor',
    secret_key: 'bitlocker_recovery_password',
    label: 'The 48-digit recovery password',
    route: 'credential',
    alternatives: [
      { secret_key: 'bitlocker_password', label: 'The BitLocker password' },
    ],
  },
  unrecognised_note: null,
}

describe('AttentionPanel (§2.11)', () => {
  it('offers a field where a per-artifact secret really reaches the module', async () => {
    mock(queue([encryptedBackup]))
    const runs: { url: string; body: unknown }[] = []
    const moduleRuns: unknown[] = []
    server.use(
      http.post(
        '/api/v1/cases/c1/artifacts/:id/credential',
        async ({ request, params }) => {
          runs.push({ url: String(params.id), body: await request.json() })
          return HttpResponse.json({
            job_id: 'j1',
            status: 'pending',
            kind: 'ios_backup_password',
            module_id: 'plugin.mobile.ios_backup',
            note: '',
          })
        },
      ),
      // SEC-204: run_module's `secrets` map is retired; nothing goes there.
      http.post('/api/v1/cases/c1/artifacts/:id/run_module', async ({ request }) => {
        moduleRuns.push(await request.json())
        return HttpResponse.json({ job_id: 'jx', status: 'pending' })
      }),
    )
    renderPanel()

    const item = await screen.findByTestId('at-item')
    expect(item).toHaveTextContent('An encrypted iOS backup was not extracted')
    expect(item).toHaveTextContent(/never written to the case/)

    await userEvent.type(
      screen.getByLabelText("The backup's password"),
      'hunter2',
    )
    await userEvent.click(screen.getByRole('button', { name: /Unlock and re-run/ }))

    // Re-run on the artifact the backup IS, not on the status record: a status
    // record has no bytes, so a decryptor run on it would do nothing.
    await waitFor(() => expect(runs).toHaveLength(1))
    expect(runs[0].url).toBe('src-1')
    expect(runs[0].body).toEqual({
      kind: 'ios_backup_password',
      secret: 'hunter2',
    })
    expect(moduleRuns).toHaveLength(0)

    // And it says what happens next, including what a wrong password does.
    expect(await screen.findByRole('status')).toHaveTextContent(
      /A wrong password fails the job rather than changing the case/,
    )
  })

  it('sends a volume credential to the credential route, once per volume, with the kind chosen', async () => {
    mock(queue([lockedBitlocker]))
    const posts: { id: string; body: unknown }[] = []
    let runModuleCalls = 0
    server.use(
      http.post(
        '/api/v1/cases/c1/artifacts/:id/credential',
        async ({ request, params }) => {
          posts.push({ id: String(params.id), body: await request.json() })
          return HttpResponse.json({
            job_id: 'j2',
            status: 'queued',
            kind: 'bitlocker_password',
            module_id: 'plugin.crypto.bitlocker_decryptor',
            note: 'held in memory for this run only',
          })
        },
      ),
      http.post('/api/v1/cases/c1/artifacts/:id/run_module', () => {
        runModuleCalls += 1
        return HttpResponse.json({ job_id: 'x', status: 'queued' })
      }),
    )
    renderPanel()

    await screen.findByTestId('at-item')
    // The recovery password is the default; the password is the alternative.
    await userEvent.selectOptions(
      screen.getByLabelText('Kind of secret'),
      'bitlocker_password',
    )
    await userEvent.type(screen.getByLabelText('The BitLocker password'), 'bde-TEST')
    await userEvent.click(screen.getByRole('button', { name: /Unlock and re-run \(1\)/ }))

    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0].id).toBe('vol-1')
    expect(posts[0].body).toEqual({ kind: 'bitlocker_password', secret: 'bde-TEST' })
    expect(runModuleCalls).toBe(0)
    // The field is cleared once the secret has been sent.
    expect(screen.getByLabelText('The BitLocker password')).toHaveValue('')
    expect(await screen.findByRole('status')).toHaveTextContent(
      /the record saying it was locked is superseded/,
    )
  })

  /**
   * A dead affordance on a forensic tool is worse than none: an examiner who
   * types a password into a field that cannot reach the decryptor concludes the
   * password is wrong.
   */
  it('offers no field where the credential is read at start-up, and names the variable', async () => {
    mock(
      queue([
        {
          ...encryptedBackup,
          record_type: 'VolumeDecryption',
          scheme: 'BitLocker',
          problem: 'A BitLocker volume was not decrypted',
          guidance: 'The contents of this volume are NOT in the case.',
          action: {
            kind: 'supply_at_startup',
            flag: '--bitlocker-password',
            env: 'SEANCE_BITLOCKER_PASSWORD',
          },
        },
      ]),
    )
    renderPanel()

    const note = await screen.findByTestId('at-startup')
    expect(note).toHaveTextContent('SEANCE_BITLOCKER_PASSWORD')
    expect(note).toHaveTextContent('--bitlocker-password')
    expect(note).toHaveTextContent(/would not reach the decryptor/)
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /Unlock and re-run/ }),
    ).not.toBeInTheDocument()
  })

  it('says outright when this build cannot read it, and offers nothing', async () => {
    mock(
      queue([
        {
          ...encryptedBackup,
          record_type: 'AndroidBackupWarning',
          problem: 'An encrypted Android backup was not extracted',
          guidance: 'This build does not decrypt an encrypted adb backup.',
          action: { kind: 'unsupported' },
        },
      ]),
    )
    renderPanel()
    expect(await screen.findByTestId('at-unsupported')).toHaveTextContent(
      /this build cannot read it/,
    )
    expect(
      screen.queryByRole('button', { name: /Unlock and re-run/ }),
    ).not.toBeInTheDocument()
    // It is still on the queue, and not counted as actionable.
    expect(screen.getByTestId('attention-panel')).toHaveTextContent(
      '0 of 1 can be acted on',
    )
  })

  /** A blockage with no instruction is listed with none, not with a guess. */
  it('lists an unrecognised blockage without inventing an instruction', async () => {
    mock(
      queue([
        {
          ...encryptedBackup,
          record_type: 'SomeFutureFormat',
          problem: null,
          guidance: null,
          action: null,
          unrecognised_note:
            'This build carries no instruction for this kind of blockage, so none is offered.',
        },
      ]),
    )
    renderPanel()
    expect(await screen.findByTestId('at-unrecognised')).toHaveTextContent(
      /no instruction for this kind of blockage/,
    )
    expect(screen.getByTestId('at-item')).toHaveTextContent(
      'SomeFutureFormat — not read',
    )
  })

  /**
   * The queue is about what can still be done, not about what was read. An
   * empty one is the most natural thing in the world to read as a clean case,
   * so the server's own sentence is always on screen.
   */
  it('an empty queue carries the sentence saying it is not the completeness record', async () => {
    mock(queue([]))
    renderPanel()
    expect(await screen.findByTestId('at-empty')).toHaveTextContent(
      'Nothing recoverable is outstanding',
    )
    expect(screen.getByTestId('at-scope')).toHaveTextContent(
      /NOT the case's completeness record/,
    )
  })

  /** A re-run on a subset must not read as a re-run on the group. */
  it('says when the re-run will cover only the listed examples', async () => {
    mock(
      queue([
        {
          ...encryptedBackup,
          count: 14,
          examples_truncated: true,
        },
      ]),
    )
    renderPanel()
    await screen.findByTestId('at-item')
    const item = screen.getByTestId('at-item')
    expect(within(item).getByRole('note')).toHaveTextContent(
      /not on all 14/,
    )
    expect(item).toHaveTextContent('+ 13 more of the same')
  })

  /** A failed load must not render as an empty queue. */
  it('a failed load does not read as nothing outstanding', async () => {
    server.use(
      http.get('/api/v1/cases/c1/attention', () =>
        HttpResponse.json({ error: 'nope' }, { status: 500 }),
      ),
    )
    renderPanel()
    expect(await screen.findByTestId('at-error')).toHaveTextContent(
      /Nothing here says this case has no outstanding problems/,
    )
    expect(screen.queryByTestId('at-empty')).not.toBeInTheDocument()
  })

  /** A failed re-run must not read as a decryption. */
  it('says a failed re-run changed nothing', async () => {
    mock(queue([encryptedBackup]))
    server.use(
      http.post('/api/v1/cases/c1/artifacts/:id/run_module', () =>
        HttpResponse.json({ error: 'nope' }, { status: 500 }),
      ),
    )
    renderPanel()
    await screen.findByTestId('at-item')
    await userEvent.type(screen.getByLabelText("The backup's password"), 'x')
    await userEvent.click(screen.getByRole('button', { name: /Unlock and re-run/ }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/nothing in the case has changed/)
  })
})
