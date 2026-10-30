import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { server } from '../../test/server'
import type { Artifact } from '../../api/types'
import { KeychainRevealPanel, keychainRevealFor } from './KeychainRevealPanel'

const CASE_ID = 'c1'
const SECRET = 'hunter2-the-real-one'

/** An iOS backup keychain item as ingest records it (HUNT-111). */
function keychainItem(
  id: string,
  metadata: Record<string, unknown> = {},
): Artifact {
  return {
    id,
    case_id: CASE_ID,
    parent_id: 'plist',
    artifact_type: 'ParsedRecord',
    metadata: {
      type: 'IosKeychainItem',
      item_kind: 'genp',
      table: 'genp',
      state: 'read',
      secret_state: 'withheld',
      service: 'AirPort',
      account: 'HomeWiFi',
      backup_path: '/evidence/backup',
      ...metadata,
    },
  } as Artifact
}

function renderPanel(a: Artifact) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const ui = (x: Artifact) => (
    <QueryClientProvider client={client}>
      <KeychainRevealPanel caseId={CASE_ID} artifact={x} />
    </QueryClientProvider>
  )
  const r = render(ui(a))
  return { ...r, show: (x: Artifact) => r.rerender(ui(x)) }
}

function mockReveal(
  reply: () => Response = () =>
    HttpResponse.json({
      value: SECRET,
      encoding: 'utf8',
      audit_event_id: null,
    }),
) {
  const posts: string[] = []
  server.use(
    http.post(
      `/api/v1/cases/${CASE_ID}/keychain/:recordId/reveal`,
      ({ params }) => {
        posts.push(params.recordId as string)
        return reply()
      },
    ),
  )
  return posts
}

describe('KeychainRevealPanel (HUNT-111)', () => {
  it('the panel belongs to an iOS keychain item and to nothing else', () => {
    expect(keychainRevealFor(keychainItem('k1'))).toBe(true)
    expect(
      keychainRevealFor(keychainItem('k1', { state: 'device_bound' })),
    ).toBe(true)
    expect(
      keychainRevealFor({
        ...keychainItem('k1'),
        metadata: { type: 'IosBackupFile' },
      } as Artifact),
    ).toBe(false)
  })

  it('reveals nothing until asked, then shows the value the audited route returned', async () => {
    const posts = mockReveal()
    renderPanel(keychainItem('k1'))
    expect(screen.queryByText(SECRET)).toBeNull()
    expect(
      screen.getByText(/recorded in the case audit log/i),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /reveal/i }))
    await waitFor(() => expect(screen.getByText(SECRET)).toBeInTheDocument())
    expect(posts).toEqual(['k1'])
  })

  it('labels a secret that came back as hex, rather than showing it as text', async () => {
    mockReveal(() =>
      HttpResponse.json({
        value: '00ff10',
        encoding: 'hex',
        audit_event_id: null,
      }),
    )
    renderPanel(keychainItem('k1'))
    await userEvent.click(screen.getByRole('button', { name: /reveal/i }))
    await waitFor(() => expect(screen.getByText('00ff10')).toBeInTheDocument())
    expect(screen.getByText(/not UTF-8.*hex/i)).toBeInTheDocument()
  })

  it('keeps the value hidden and says why when the server refuses (a locked backup)', async () => {
    mockReveal(() =>
      HttpResponse.json(
        {
          error: {
            code: 'INVALID_REQUEST',
            message:
              'this backup is not unlocked for reading in this case. Unlock it with the backup password',
          },
        },
        { status: 400 },
      ),
    )
    renderPanel(keychainItem('k1'))
    await userEvent.click(screen.getByRole('button', { name: /reveal/i }))
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        /Not revealed.*not unlocked for reading/i,
      ),
    )
    expect(screen.queryByText(SECRET)).toBeNull()
  })

  it('a device-bound item has no reveal button, and says why nothing can be revealed', () => {
    const posts = mockReveal()
    renderPanel(
      keychainItem('k1', { state: 'device_bound', secret_state: 'locked' }),
    )
    expect(screen.queryByRole('button', { name: /reveal/i })).toBeNull()
    expect(screen.getByText(/hardware key/i)).toBeInTheDocument()
    expect(posts).toEqual([])
  })

  it('an item carrying no secret has no reveal button', () => {
    renderPanel(keychainItem('k1', { secret_state: 'absent' }))
    expect(screen.queryByRole('button', { name: /reveal/i })).toBeNull()
    expect(screen.getByText(/carries no secret/i)).toBeInTheDocument()
  })

  it('a revealed value does not follow the examiner to another item', async () => {
    mockReveal()
    const { show } = renderPanel(keychainItem('k1'))
    await userEvent.click(screen.getByRole('button', { name: /reveal/i }))
    await waitFor(() => expect(screen.getByText(SECRET)).toBeInTheDocument())
    show(keychainItem('k2'))
    expect(screen.queryByText(SECRET)).toBeNull()
    expect(screen.getByRole('button', { name: /reveal/i })).toBeEnabled()
  })
})

describe('ArtifactInspector carries the keychain reveal (HUNT-111)', () => {
  it('an iOS keychain item opened from its viewer row shows the Reveal button in the Inspector', async () => {
    const { ArtifactInspector } = await import('./ArtifactInspector')
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <MemoryRouter>
        <QueryClientProvider client={client}>
          <ArtifactInspector
            caseId={CASE_ID}
            artifact={keychainItem('k1')}
            previewKind={null}
            onCollapse={() => {}}
          />
        </QueryClientProvider>
      </MemoryRouter>,
    )
    expect(
      screen.getByRole('button', { name: /reveal secret/i }),
    ).toBeInTheDocument()
  })
})

/** A macOS `kych` keychain item as the parser records it (HUNT-111). */
function macKeychainItem(
  id: string,
  metadata: Record<string, unknown> = {},
): Artifact {
  return {
    id,
    case_id: CASE_ID,
    parent_id: 'keychain-file',
    artifact_type: 'ParsedRecord',
    metadata: {
      type: 'KeychainItem',
      item_kind: 'generic_password',
      relation: 'generic_password',
      record_number: 0,
      secret_wrapping: 'ssgp_master_key',
      secret_state: 'locked',
      service: 'moond4rk.com',
      account: 'admin',
      ...metadata,
    },
  } as Artifact
}

describe('KeychainRevealPanel for a macOS keychain item (HUNT-111)', () => {
  it('belongs to a password item or a private key, and not to a certificate or a wrapping key', () => {
    expect(keychainRevealFor(macKeychainItem('m1'))).toBe(true)
    expect(
      keychainRevealFor(
        macKeychainItem('m1', { item_kind: 'internet_password' }),
      ),
    ).toBe(true)
    expect(
      keychainRevealFor(macKeychainItem('m1', { item_kind: 'private_key' })),
    ).toBe(true)
    expect(
      keychainRevealFor(macKeychainItem('m1', { item_kind: 'symmetric_key' })),
    ).toBe(false)
    expect(
      keychainRevealFor(
        macKeychainItem('m1', {
          item_kind: 'certificate',
          secret_wrapping: undefined,
        }),
      ),
    ).toBe(false)
  })

  it('asks for the keychain password, sends it once in the body, and shows the audited value', async () => {
    const bodies: unknown[] = []
    server.use(
      http.post(
        `/api/v1/cases/${CASE_ID}/keychain/:recordId/reveal`,
        async ({ request }) => {
          bodies.push(await request.json())
          return HttpResponse.json({
            value: SECRET,
            encoding: 'utf8',
            audit_event_id: null,
          })
        },
      ),
    )
    renderPanel(macKeychainItem('m1'))
    expect(screen.queryByText(SECRET)).toBeNull()
    expect(
      screen.getByText(/used for that one request and kept nowhere/i),
    ).toBeInTheDocument()
    const reveal = screen.getByRole('button', { name: /reveal secret/i })
    expect(reveal).toBeDisabled()
    await userEvent.type(
      screen.getByLabelText(/keychain password/i),
      'keychainbreaker-test',
    )
    await userEvent.click(reveal)
    await waitFor(() => expect(screen.getByText(SECRET)).toBeInTheDocument())
    expect(bodies).toEqual([{ password: 'keychainbreaker-test' }])
    // The password is cleared from the field once sent.
    expect(screen.getByLabelText(/keychain password/i)).toHaveValue('')
  })

  it('keeps the value hidden and says why when the server refuses a wrong password', async () => {
    server.use(
      http.post(`/api/v1/cases/${CASE_ID}/keychain/:recordId/reveal`, () =>
        HttpResponse.json(
          {
            error: {
              code: 'INVALID_REQUEST',
              message: "the password did not open this keychain's DbBlob",
            },
          },
          { status: 400 },
        ),
      ),
    )
    renderPanel(macKeychainItem('m1'))
    await userEvent.type(screen.getByLabelText(/keychain password/i), 'nope')
    await userEvent.click(
      screen.getByRole('button', { name: /reveal secret/i }),
    )
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        /Not revealed.*did not open/i,
      ),
    )
    expect(screen.queryByText(SECRET)).toBeNull()
  })

  it('sends a SystemKey as system_key, not as a password, when that kind is chosen', async () => {
    const bodies: unknown[] = []
    server.use(
      http.post(
        `/api/v1/cases/${CASE_ID}/keychain/:recordId/reveal`,
        async ({ request }) => {
          bodies.push(await request.json())
          return HttpResponse.json({
            value: SECRET,
            encoding: 'utf8',
            audit_event_id: null,
          })
        },
      ),
    )
    renderPanel(macKeychainItem('m1'))
    await userEvent.selectOptions(
      screen.getByLabelText(/credential kind/i),
      'system_key',
    )
    const hex = 'ab'.repeat(48)
    await userEvent.type(screen.getByLabelText(/keychain password/i), hex)
    await userEvent.click(
      screen.getByRole('button', { name: /reveal secret/i }),
    )
    await waitFor(() => expect(screen.getByText(SECRET)).toBeInTheDocument())
    expect(bodies).toEqual([{ system_key: hex }])
  })
})
