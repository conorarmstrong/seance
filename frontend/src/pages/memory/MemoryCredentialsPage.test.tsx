import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { MemoryCredentialsPage } from './MemoryCredentialsPage'
import {
  CASE_ID,
  IMAGE_ID,
  coverageBody,
  image,
  mockImages,
  mockMemory,
  renderMemory,
} from './testing'

const ROUTES = <Route index element={<MemoryCredentialsPage />} />

/** A `MemoryCredential` — one recovered VALUE. Nothing in the tree emits one. */
function credential(overrides: Record<string, unknown> = {}) {
  return {
    id: 'cred-1',
    parent_id: IMAGE_ID,
    artifact_type: 'ParsedRecord',
    metadata: {
      memory_image_id: IMAGE_ID,
      username: 'Administrator',
      rid: '500',
      hash_format: 'NT',
      derivation_chain: [
        { step: 'bootkey', source: 'SYSTEM\\CurrentControlSet\\Control\\Lsa' },
        { step: 'hashed bootkey', source: 'SAM\\Domains\\Account\\F' },
      ],
      ...overrides,
    },
  }
}

/**
 * A `MemoryCredentials` record — the INVENTORY, mirroring
 * `CredentialSurvey::to_json` in `seance_plugin_memory_windows` field for
 * field. This is what the analysis actually emits.
 */
function inventory(overrides: Record<string, unknown> = {}) {
  return {
    id: 'inv-1',
    parent_id: IMAGE_ID,
    artifact_type: 'ParsedRecord',
    metadata: {
      type: 'MemoryCredentials',
      record_type: 'MemoryCredentials',
      stage: 'credentials',
      memory_image_id: IMAGE_ID,
      inventory_only: true,
      plaintext_recovered: false,
      credentials_recovered: 0,
      decryption:
        'the credential material in this image was located and inventoried; it was not decrypted, so no password, hash or secret value has been recovered and nothing here says what any of them is',
      hives: [
        {
          hive: 'SAM',
          cmhive: 18446735277616529408,
          cmhive_hex: '0xffffe000012c4000',
          bin_source: 'mapped hive bins',
          bin_source_authoritative: true,
          available: true,
          detail: null,
        },
      ],
      accounts: [
        {
          name: 'Administrator',
          rid: 500,
          rid_corroborated: true,
          last_write_filetime: 132000000000000000,
          notes: [],
        },
      ],
      account_count: 1,
      secrets: [
        { name: 'DPAPI_SYSTEM', last_write_filetime: 132000000000000000 },
        { name: '$MACHINE.ACC', last_write_filetime: 0 },
      ],
      secret_count: 2,
      cached_logons: 3,
      listings: [
        { key: 'SAM\\Domains\\Account\\Users\\Names', complete: true, detail: null },
      ],
      truncated: false,
      inventory_complete: true,
      inventory_incomplete: false,
      inventory_incomplete_reason: null,
      complete: true,
      incomplete: [],
      ...overrides,
    },
  }
}

/**
 * Serve `/records` per requested type.
 *
 * The page asks for two different record types and they mean two different
 * things, so a handler that answered both with the same rows would let a page
 * that renders the inventory as recovered values pass.
 */
function mockRecords(byType: Record<string, unknown[]>) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const type = new URL(request.url).searchParams.get('type') ?? ''
      const records = byType[type] ?? []
      return HttpResponse.json({
        records,
        total: records.length,
        page: 1,
        page_size: 200,
        type,
      })
    }),
  )
}

function mockCredentials(
  {
    values = [] as unknown[],
    inventories = [] as unknown[],
  }: { values?: unknown[]; inventories?: unknown[] },
  credentialStage: string | null = 'complete',
) {
  mockImages()
  // The page reads coverage as well as the records: an empty page is only a
  // finding when a credential stage ran to produce it.
  mockMemory(
    'coverage',
    coverageBody(
      credentialStage == null
        ? []
        : [{ stage: 'credentials', status: credentialStage }],
    ),
  )
  mockRecords({
    MemoryCredential: values,
    MemoryCredentials: inventories,
  })
}

describe('MemoryCredentialsPage — the inventory (B3-M01)', () => {
  it('states that nothing was decrypted, and offers no reveal over an inventory', async () => {
    // The defect: the page spoke of "recovered credentials" that could be
    // revealed over a stage that only lists what is in the stores. An examiner
    // reading that writes "a password was recovered" into a report.
    mockCredentials({ inventories: [inventory()] })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText(/Nothing here is decrypted/i)).toBeInTheDocument()
    expect(
      screen.getByText(/it was not decrypted, so no password, hash or secret value/i),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reveal' })).not.toBeInTheDocument()
    expect(
      screen.queryByText(/Recovered credential values/i),
    ).not.toBeInTheDocument()
  })

  it('lists account names, RIDs, secret names and the cached-logon count', async () => {
    mockCredentials({ inventories: [inventory()] })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('Administrator')).toBeInTheDocument()
    expect(screen.getByText('500')).toBeInTheDocument()
    expect(screen.getByText('DPAPI_SYSTEM')).toBeInTheDocument()
    expect(screen.getByText('$MACHINE.ACC')).toBeInTheDocument()
    expect(screen.getByText('SAM')).toBeInTheDocument()

    const cached = screen.getByText('cached domain logons present').parentElement
    expect(within(cached as HTMLElement).getByText('3')).toBeInTheDocument()
  })

  it('says a secret name is a name, not a value', async () => {
    mockCredentials({ inventories: [inventory()] })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(
        /a name here says a secret of that name exists — not what it is/i,
      ),
    ).toBeInTheDocument()
  })

  it('renders a count the producer did not state as "not stated", never as zero', async () => {
    // A zero says "this machine had no cached domain logons", which is a
    // finding. An absent field says nothing counted them.
    mockCredentials({
      inventories: [
        inventory({ cached_logons: undefined, secret_count: undefined }),
      ],
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    const cached = (await screen.findByText('cached domain logons present'))
      .parentElement as HTMLElement
    expect(within(cached).getByText('not stated')).toBeInTheDocument()
    expect(within(cached).queryByText('0')).not.toBeInTheDocument()
  })

  it('calls a short inventory a floor and gives the producer’s reason', async () => {
    mockCredentials({
      inventories: [
        inventory({
          inventory_complete: false,
          inventory_incomplete: true,
          inventory_incomplete_reason: "'SAM\\Domains\\Account\\Users\\Names': a bin was not mapped",
        }),
      ],
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/This inventory is a floor, not a total/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/a bin was not mapped/)).toBeInTheDocument()
  })

  it('refuses to read an unstated completeness as complete', async () => {
    mockCredentials({ inventories: [inventory({ inventory_complete: undefined })] })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(
        /does not say whether the inventory is complete/i,
      ),
    ).toBeInTheDocument()
  })

  it('counts entries it could not decode instead of shortening the list in silence', async () => {
    mockCredentials({
      inventories: [
        inventory({
          accounts: [
            { name: 'Administrator', rid: 500, rid_corroborated: true, notes: [] },
            'not an object',
          ],
        }),
      ],
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/1 entry in this record could not be decoded/i),
    ).toBeInTheDocument()
  })

  it('marks a RID the read could not establish rather than leaving the cell blank', async () => {
    mockCredentials({
      inventories: [
        inventory({
          accounts: [
            { name: 'svc_backup', rid: null, rid_corroborated: null, notes: [] },
          ],
        }),
      ],
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('svc_backup')).toBeInTheDocument()
    expect(screen.getByText('not read')).toBeInTheDocument()
  })

  it('flags a record that contradicts itself by claiming plaintext', async () => {
    mockCredentials({
      inventories: [inventory({ plaintext_recovered: true })],
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/claims plaintext was recovered/i),
    ).toBeInTheDocument()
  })

  it('shows an inventory that names no capture rather than hiding it', async () => {
    mockCredentials({
      inventories: [
        {
          id: 'inv-2',
          parent_id: null,
          artifact_type: 'ParsedRecord',
          metadata: { ...inventory().metadata, memory_image_id: undefined },
        },
      ],
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/This inventory names no capture/i),
    ).toBeInTheDocument()
  })
})

describe('MemoryCredentialsPage — recovered values', () => {
  it('masks every value and shows the derivation chain so method can be attested', async () => {
    mockCredentials({ values: [credential()] })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByLabelText('value masked')).toBeInTheDocument()
    expect(screen.getByText('bootkey')).toBeInTheDocument()
    expect(screen.getByText('SAM\\Domains\\Account\\F')).toBeInTheDocument()
  })

  it('labels the hash format, and says so loudly when the producer did not state one', async () => {
    mockCredentials({ values: [credential({ hash_format: undefined })] })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/format not stated — do not feed this to a cracker/i),
    ).toBeInTheDocument()
  })

  it('says method cannot be attested when the producer recorded no derivation chain', async () => {
    mockCredentials({ values: [credential({ derivation_chain: undefined })] })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/Method cannot be attested for this value/i),
    ).toBeInTheDocument()
  })

  it('reveals a value only after the server has recorded the reveal', async () => {
    mockCredentials({ values: [credential()] })
    server.use(
      http.post(
        `/api/v1/cases/${CASE_ID}/memory/credentials/cred-1/reveal`,
        () =>
          HttpResponse.json({
            value: 'aad3b435b51404eeaad3b435b51404ee',
            audit_event_id: 'audit-9',
          }),
      ),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'Reveal' }))
    expect(
      await screen.findByText('aad3b435b51404eeaad3b435b51404ee'),
    ).toBeInTheDocument()
  })

  it('keeps the value masked when the reveal could not be recorded', async () => {
    mockCredentials({ values: [credential()] })
    server.use(
      http.post(
        `/api/v1/cases/${CASE_ID}/memory/credentials/cred-1/reveal`,
        () =>
          HttpResponse.json(
            { error: { code: 'NOT_FOUND', message: 'no such route' } },
            { status: 404 },
          ),
      ),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'Reveal' }))
    expect(
      await screen.findByText(/was not recorded in the audit log/i),
    ).toBeInTheDocument()
    expect(screen.getByLabelText('value masked')).toBeInTheDocument()
  })

  it('does not let one capture s in-flight reveal govern another capture s page (B3-056)', async () => {
    // Two captures in one case, each with its own credential. A reveal belongs
    // to the capture it was requested under: its pending state must not gate
    // the other capture's page, and its response must not be applied there.
    mockImages([image(), image({ image_id: 'image-2', name: 'SERVER.raw' })])
    mockMemory('coverage', coverageBody([{ stage: 'credentials', status: 'complete' }]))
    mockRecords({
      MemoryCredential: [
        credential(),
        {
          id: 'cred-2',
          parent_id: 'image-2',
          artifact_type: 'ParsedRecord',
          metadata: {
            memory_image_id: 'image-2',
            username: 'svc_sql',
            hash_format: 'NT',
          },
        },
      ],
      MemoryCredentials: [],
    })
    let release: () => void = () => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    server.use(
      http.post(
        `/api/v1/cases/${CASE_ID}/memory/credentials/cred-1/reveal`,
        async () => {
          await held
          return HttpResponse.json({
            value: 'aad3b435b51404eeaad3b435b51404ee',
            audit_event_id: 'audit-9',
          })
        },
      ),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'Reveal' }))
    await userEvent.selectOptions(
      screen.getByRole('combobox', { name: /capture/i }),
      'image-2',
    )
    await screen.findByText(/svc_sql/)

    // Capture 2's own credential must still be revealable: the other capture's
    // request says nothing about this one.
    expect(await screen.findByRole('button', { name: 'Reveal' })).toBeEnabled()

    release()
    await waitFor(() =>
      expect(
        screen.queryByText('aad3b435b51404eeaad3b435b51404ee'),
      ).not.toBeInTheDocument(),
    )
    expect(screen.getByLabelText('value masked')).toBeInTheDocument()
  })

  it('shows a credential that names no capture rather than hiding it behind the capture filter', async () => {
    mockCredentials({
      values: [
        {
          id: 'cred-2',
          parent_id: null,
          artifact_type: 'ParsedRecord',
          metadata: { username: 'svc_backup', hash_format: 'MSCACHEv2' },
        },
      ],
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(
        /1 credential value could not be attributed to a capture/i,
      ),
    ).toBeInTheDocument()
    expect(screen.getByText(/svc_backup/)).toBeInTheDocument()
  })
})

describe('MemoryCredentialsPage — empty states', () => {
  it('says no store was inventoried, but only when a credential stage ran', async () => {
    mockCredentials({}, 'complete')
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText('No credential store was inventoried'),
    ).toBeInTheDocument()
    // And it must not read as "no password was recovered": this stage recovers
    // none by design, so that would be a finding about every capture ever run.
    expect(
      screen.queryByText('No credential was recovered'),
    ).not.toBeInTheDocument()
  })

  it('refuses to call an empty page a finding when no credential stage ran', async () => {
    mockCredentials({}, 'did_not_run')
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/No credential stage ran on this capture/i),
    ).toBeInTheDocument()
    expect(
      screen.queryByText('No credential store was inventoried'),
    ).not.toBeInTheDocument()
  })

  it('refuses to call an empty page a finding when this build has no credential stage at all', async () => {
    mockCredentials({}, null)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/no credential stage at all/i),
    ).toBeInTheDocument()
  })

  it('says whether a stage ran is unknown when coverage could not be read', async () => {
    mockImages()
    mockMemory('coverage', { error: 'boom' }, 500)
    mockRecords({ MemoryCredential: [], MemoryCredentials: [] })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/whether any credential stage ran is unknown/i),
    ).toBeInTheDocument()
  })

  it('says when another capture in the case has an inventory this one lacks', async () => {
    mockCredentials({
      inventories: [
        {
          id: 'inv-3',
          parent_id: 'image-2',
          artifact_type: 'ParsedRecord',
          metadata: { ...inventory().metadata, memory_image_id: 'image-2' },
        },
      ],
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/1 other capture in this case has an inventory/i),
    ).toBeInTheDocument()
  })
})
