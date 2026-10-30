import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import type { Artifact } from '../../api/types'
import { server } from '../../test/server'
import { SourcesSection } from './SourcesSection'
import type { SourceKindRow, SourceKindsResponse, SourceStatsResponse } from './api'

beforeAll(() => {
  // jsdom has no canvas; the disk map only needs to render structurally.
  HTMLCanvasElement.prototype.getContext = vi.fn(() => ({
    scale: vi.fn(),
    clearRect: vi.fn(),
    fillRect: vi.fn(),
    fillStyle: '',
  })) as unknown as typeof HTMLCanvasElement.prototype.getContext
})

const ENCRYPTED_SOURCE: SourceStatsResponse = {
  sources: [
    {
      source_artifact_id: 'src-1',
      name: 'apfs_encrypted.dmg',
      name_resolved: true,
      artifact_count: 0,
    },
  ],
}

/** The markers `mark_if_apple_encrypted_dmg` stamps on the root artifact. */
const ENCRYPTED_ARTIFACT: Artifact = {
  id: 'src-1',
  case_id: 'case-1',
  parent_id: null,
  artifact_type: 'RawEvidence',
  metadata: {
    name: 'apfs_encrypted.dmg',
    encrypted: true,
    encryption_format: 'apple_encrypted_dmg',
    content_incomplete: true,
    content_incomplete_reason: 'encrypted',
  },
}

const NO_KINDS: SourceKindsResponse = {
  sources: [],
  looked_for: [],
  capped_types: [],
  unattributed: 0,
  message: '',
}

function mockApi({
  sources = ENCRYPTED_SOURCE,
  artifact = ENCRYPTED_ARTIFACT as Artifact | null,
  kinds = NO_KINDS as SourceKindsResponse | null,
} = {}) {
  server.use(
    http.get('/api/v1/cases/case-1/source_kinds', () =>
      kinds
        ? HttpResponse.json(kinds)
        : HttpResponse.json(
            { error: { code: 'INTERNAL', message: 'label boom' } },
            { status: 500 },
          ),
    ),
    http.get('/api/v1/cases/case-1/stats/sources', () =>
      HttpResponse.json(sources),
    ),
    http.get('/api/v1/cases/case-1/artifacts/:id', () =>
      artifact
        ? HttpResponse.json(artifact)
        : HttpResponse.json(
            { error: { code: 'INTERNAL', message: 'boom' } },
            { status: 500 },
          ),
    ),
    // An encrypted image was never opened, so it has no partition map: the
    // server answers this the way it answers for any source it could not parse.
    http.get('/api/v1/cases/case-1/sources/:id/disk_map', () =>
      HttpResponse.json(
        { error: { code: 'NOT_FOUND', message: 'no partition map' } },
        { status: 404 },
      ),
    ),
  )
}

function renderSources() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  renderWith(queryClient)
  return queryClient
}

function renderWith(queryClient: QueryClient) {
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <SourcesSection caseId="case-1" />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('SourcesSection encrypted disclosure (LIVE-003)', () => {
  it('says a zero beside an encrypted source is about access, not content', async () => {
    // The exact sentence LIVE-003 was filed about: "apfs_encrypted.dmg — 0
    // artifacts", with nothing on the screen to say the image was recognised,
    // recorded and never opened. The markers were already on the artifact; this
    // is the first screen to read them.
    mockApi()
    renderSources()

    const note = await screen.findByRole('note', {
      name: /apfs_encrypted\.dmg — encrypted/i,
    })
    expect(note).toHaveTextContent(/never opened/i)
    expect(note).toHaveTextContent(/apple_encrypted_dmg/)
    expect(note).toHaveTextContent(/not a statement about (its )?content/i)
    // The reason vocabulary is the shared one, not a phrase invented here.
    expect(note).toHaveTextContent(/encrypted at rest and was not decrypted/i)
  })

  it('does not dress the missing partition map up as a failure for an encrypted source', async () => {
    // "Partition map unavailable" beside an image nobody could open reads as a
    // broken product rather than as the expected consequence of encryption.
    mockApi()
    renderSources()

    await screen.findByRole('note', {
      name: /apfs_encrypted\.dmg — encrypted/i,
    })
    await waitFor(() =>
      expect(
        screen.getByText(/no partition map .* was never decrypted/i),
      ).toBeInTheDocument(),
    )
    expect(screen.queryByText(/Partition map unavailable/)).toBeNull()
  })

  it('keeps the partition-map failure note for a source with no encryption stamp', async () => {
    mockApi({
      sources: {
        sources: [
          {
            source_artifact_id: 'src-1',
            name: 'laptop.E01',
            name_resolved: true,
            artifact_count: 1234,
          },
        ],
      },
      artifact: {
        id: 'src-1',
        case_id: 'case-1',
        parent_id: null,
        artifact_type: 'RawEvidence',
        metadata: { name: 'laptop.E01' },
      },
    })
    server.use(
      http.get('/api/v1/cases/case-1/sources/:id/disk_map', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    renderSources()

    expect(
      await screen.findByText(/Partition map unavailable/),
    ).toBeInTheDocument()
  })

  it('does not let an unreadable source record read as "not encrypted"', async () => {
    // A failed request must never be rendered as a fact about the evidence:
    // silence here would be indistinguishable from a source with no stamps.
    mockApi({ artifact: null })
    renderSources()

    const note = await screen.findByRole('note', {
      name: /apfs_encrypted\.dmg — record unavailable/i,
    })
    expect(note).toHaveTextContent(/boom/)
    expect(note).toHaveTextContent(/not a statement that it is complete/i)
  })

  it('says when a source name could not be resolved', async () => {
    // The server sets name_resolved false and falls back to the UUID. Without
    // this the examiner cannot tell an unnamed source from one whose name this
    // response failed to fetch.
    mockApi({
      sources: {
        sources: [
          {
            source_artifact_id: 'src-1',
            name: 'src-1',
            name_resolved: false,
            artifact_count: 12,
          },
        ],
      },
      artifact: {
        id: 'src-1',
        case_id: 'case-1',
        parent_id: null,
        artifact_type: 'RawEvidence',
        metadata: {},
      },
    })
    renderSources()

    expect(
      await screen.findByText(/name could not be resolved/i),
    ).toBeInTheDocument()
  })

  it('discloses a short source-name walk over the panel', async () => {
    mockApi({
      sources: {
        ...ENCRYPTED_SOURCE,
        inventory_incomplete: true,
        inventory_incomplete_reason: 'undecodable_rows',
        undecodable: 3,
      },
    })
    renderSources()

    const note = await screen.findByRole('note', {
      name: /source names incomplete/i,
    })
    expect(note).toHaveTextContent(/3/)
  })
})

/**
 * `/stats/sources` returns `integrity_state` and `acquisition_error` per source
 * precisely so that the count beside a source's name can be read against the
 * state of its acquisition. A source still being hashed has not finished being
 * processed, so its zero means "not yet"; a source whose baseline could not be
 * established is an exhibit the case holds and cannot vouch for. Both used to
 * render as a bare "0 artifacts", which reads as "this exhibit contained
 * nothing" — and that reading gets quoted.
 */
describe('SourcesSection acquisition state', () => {
  function withState(
    integrity_state: string | null,
    acquisition_error: string | null = null,
    artifact_count = 0,
  ) {
    mockApi({
      sources: {
        sources: [
          {
            source_artifact_id: 'src-1',
            name: 'EXH-4.E01',
            name_resolved: true,
            artifact_count,
            integrity_state,
            acquisition_error,
          },
        ],
      },
      artifact: {
        id: 'src-1',
        case_id: 'case-1',
        parent_id: null,
        artifact_type: 'RawEvidence',
        metadata: { name: 'EXH-4.E01' },
      },
    })
    renderSources()
  }

  it('makes a failed acquisition unmistakable and does not call the zero "nothing"', async () => {
    withState('acquisition_failed', 'read error at sector 41,220: Input/output error')

    const note = await screen.findByRole('note', {
      name: /EXH-4\.E01 — acquisition failed/i,
    })
    // The reason the server recorded, verbatim: "acquisition failed" alone
    // tells an examiner something is wrong and nothing about what to do.
    expect(note).toHaveTextContent(/sector 41,220/)
    expect(note).toHaveTextContent(/could not vouch for|cannot vouch for/i)
    // The zero must not be readable as "this exhibit contained nothing".
    expect(note).toHaveTextContent(/rather than that it contained nothing/i)
    // And it has to be visible at a glance beside the count, not only in prose.
    expect(
      screen.getByText('acquisition failed', { selector: '.badge' }),
    ).toBeInTheDocument()
  })

  it('says a zero beside a source still being hashed means "not yet"', async () => {
    withState('verifying')

    const note = await screen.findByRole('note', {
      name: /EXH-4\.E01 — acquisition in progress/i,
    })
    expect(note).toHaveTextContent(/still running/i)
    expect(note).toHaveTextContent(/not yet/i)
    expect(
      screen.getByText('acquiring', { selector: '.badge' }),
    ).toBeInTheDocument()
  })

  it('marks a recorded baseline as acquired, with no alarm attached', async () => {
    withState('baseline_recorded', null, 412806)

    expect(
      await screen.findByText('acquired', { selector: '.badge' }),
    ).toBeInTheDocument()
    expect(screen.queryByText('acquisition failed')).toBeNull()
    expect(screen.queryByText('acquiring')).toBeNull()
  })

  it('says when the walk that produced the count never finished (HUNT-113)', async () => {
    mockApi({
      sources: {
        sources: [
          {
            source_artifact_id: 'src-1',
            name: 'CoreServices',
            name_resolved: true,
            artifact_count: 245_682,
            integrity_state: 'baseline_recorded',
            acquisition_error: null,
            processing_state: 'interrupted',
            processing_note:
              'processing of this source was interrupted by a stopped process; 245682 artifacts were recorded under it before it stopped, and what its walk had not reached is absent from this case, not from the evidence. Re-ingest the source to complete it',
          },
        ],
      },
      artifact: {
        id: 'src-1',
        case_id: 'case-1',
        parent_id: null,
        artifact_type: 'RawEvidence',
        metadata: {
          name: 'CoreServices',
          processing_state: 'interrupted',
          inventory_incomplete: true,
          inventory_incomplete_reason: 'ingest_interrupted',
        },
      },
    })
    renderSources()

    const note = await screen.findByRole('note', {
      name: /CoreServices — processing interrupted/i,
    })
    // The count must be read as "what was recorded", never as a total.
    expect(note).toHaveTextContent(/what had been recorded when it stopped/i)
    expect(note).toHaveTextContent(/absent from this case, not from the evidence/i)
    expect(note).toHaveTextContent(/Re-ingest the source/i)
    expect(
      screen.getByText('processing interrupted', { selector: '.badge' }),
    ).toBeInTheDocument()
    // The acquisition is fine and says so: the two states are independent.
    expect(
      screen.getByText('acquired', { selector: '.badge' }),
    ).toBeInTheDocument()
    // Exactly one chip for the interruption: the specific "processing
    // interrupted" one. The generic "incomplete" chip that the shared
    // inventory_incomplete stamp would otherwise draw is suppressed, so the
    // card does not show two chips for one fact.
    expect(screen.queryByText(/⚠ incomplete/)).toBeNull()
  })

  it('draws no processing chip for a walk that ended', async () => {
    mockApi({
      sources: {
        sources: [
          {
            source_artifact_id: 'src-1',
            name: 'EXH-4.E01',
            name_resolved: true,
            artifact_count: 10,
            integrity_state: 'baseline_recorded',
            acquisition_error: null,
            processing_state: 'completed',
            processing_note: null,
          },
        ],
      },
      artifact: {
        id: 'src-1',
        case_id: 'case-1',
        parent_id: null,
        artifact_type: 'RawEvidence',
        metadata: { name: 'EXH-4.E01', processing_state: 'completed' },
      },
    })
    renderSources()
    expect(
      await screen.findByText('acquired', { selector: '.badge' }),
    ).toBeInTheDocument()
    expect(screen.queryByText(/processing interrupted|processing cancelled/)).toBeNull()
  })

  it('does not let a source with no recorded state pass as acquired', async () => {
    // An exhibit ingested before acquisition states existed carries none. That
    // is not the same fact as a baseline having been recorded, and on a card
    // where its neighbours say "acquired" silence would read as one.
    withState(null, null, 88)

    const chip = await screen.findByText('acquisition state not recorded', {
      selector: '.badge',
    })
    expect(chip).toHaveAccessibleName(/not a statement that no baseline/i)
    expect(screen.queryByText('acquired')).toBeNull()
  })

  it('refuses to interpret a state it does not recognise', async () => {
    withState('quarantined')

    const note = await screen.findByRole('note', {
      name: /EXH-4\.E01 — acquisition state not recognised/i,
    })
    expect(note).toHaveTextContent(/quarantined/)
    expect(note).toHaveTextContent(/cannot say what that means/i)
    expect(screen.queryByText('acquired')).toBeNull()
  })

  it('says the acquisition state is missing because the name walk missed the record', async () => {
    // `integrity_state` is null here for a different reason: the server reads it
    // off the same root-artifact walk that produces the name, so an unresolved
    // name means the state was never fetched — not that none is recorded.
    mockApi({
      sources: {
        sources: [
          {
            source_artifact_id: 'src-1',
            name: 'src-1',
            name_resolved: false,
            artifact_count: 12,
            integrity_state: null,
            acquisition_error: null,
          },
        ],
      },
      artifact: {
        id: 'src-1',
        case_id: 'case-1',
        parent_id: null,
        artifact_type: 'RawEvidence',
        metadata: {},
      },
    })
    renderSources()

    const note = await screen.findByText(/name could not be resolved/i)
    expect(note).toHaveTextContent(/acquisition state/i)
    // The "none recorded" chip would be a different claim, and a wrong one.
    expect(screen.queryByText('acquisition state not recorded')).toBeNull()
  })
})

describe('SourcesSection mobile source-type label (ROADMAP §1.4)', () => {
  const PLAIN_SOURCE: SourceStatsResponse = {
    sources: [
      {
        source_artifact_id: 'src-1',
        name: 'android.tar',
        name_resolved: true,
        artifact_count: 939478,
        processing_state: 'completed',
      },
    ],
  }
  const PLAIN_ARTIFACT: Artifact = {
    id: 'src-1',
    case_id: 'case-1',
    parent_id: null,
    artifact_type: 'Container',
    metadata: { name: 'android.tar' },
  }
  const LOOKED_FOR = [
    { record_type: 'MobileDeviceInfo', kind: 'android_device', written_by: 'x' },
    { record_type: 'IosBackupInfo', kind: 'ios_backup', written_by: 'y' },
  ]
  const kindsWith = (row: Partial<SourceKindRow>): SourceKindsResponse => ({
    ...NO_KINDS,
    looked_for: LOOKED_FOR,
    sources: [
      {
        source_artifact_id: 'src-1',
        name: 'android.tar',
        label: 'not_assessed',
        kinds: [],
        basis: [],
        assessed: false,
        not_assessed_reason: null,
        walk_state: 'completed',
        has_records: true,
        capped: false,
        ...row,
      },
    ],
  })

  it('a labelled source shows its kinds with the basis in the accessible name', async () => {
    mockApi({
      sources: PLAIN_SOURCE,
      artifact: PLAIN_ARTIFACT,
      kinds: kindsWith({
        label: 'android_device',
        kinds: ['android_device'],
        assessed: true,
        basis: [
          {
            kind: 'android_device',
            marker_records: 7,
            records: [
              {
                record_id: 'r1',
                record_type: 'MobileDeviceInfo',
                corroborated_by: { field: 'platform', value: 'android' },
                source_file: '/data/system/users/0/settings_system.xml',
              },
            ],
          },
        ],
      }),
    })
    renderSources()
    const badge = await screen.findByLabelText(/mobile evidence: Android device/i)
    expect(badge).toHaveTextContent(/Android device/)
    expect(badge.getAttribute('aria-label')).toMatch(/MobileDeviceInfo/)
    expect(badge.getAttribute('aria-label')).toMatch(/settings_system\.xml/)
    expect(badge.getAttribute('aria-label')).toMatch(/7 marker record/)
  })

  it('a not_assessed source shows its reason and never "no mobile evidence"', async () => {
    mockApi({
      sources: PLAIN_SOURCE,
      artifact: PLAIN_ARTIFACT,
      kinds: kindsWith({
        walk_state: 'interrupted',
        not_assessed_reason: 'its walk did not end (interrupted): the process stopped',
      }),
    })
    renderSources()
    const badge = await screen.findByLabelText(/mobile evidence not assessed/i)
    expect(badge.getAttribute('aria-label')).toMatch(/the process stopped/)
    expect(screen.queryByText(/no mobile/i)).toBeNull()
  })

  it('a none_recognised source lists what was looked for', async () => {
    mockApi({
      sources: PLAIN_SOURCE,
      artifact: PLAIN_ARTIFACT,
      kinds: kindsWith({ label: 'none_recognised', assessed: true }),
    })
    renderSources()
    const badge = await screen.findByLabelText(/no mobile marker recognised/i)
    expect(badge.getAttribute('aria-label')).toMatch(/MobileDeviceInfo/)
    expect(badge.getAttribute('aria-label')).toMatch(/IosBackupInfo/)
  })

  it("a none_recognised source names each marker's test, not a bare type list", async () => {
    mockApi({
      sources: PLAIN_SOURCE,
      artifact: PLAIN_ARTIFACT,
      kinds: {
        ...kindsWith({ label: 'none_recognised', assessed: true }),
        looked_for: [
          {
            record_type: 'MobileDeviceInfo',
            kind: 'android_device',
            requires_field: { field: 'platform', one_of: ['android'] },
            requires_path_containing: [],
            written_by: 'x',
          },
          {
            record_type: 'PowerLogSummary',
            kind: 'ios_device',
            requires_field: { field: 'platform', one_of: ['iOS'] },
            requires_path_containing: ['var/containers/Shared/SystemGroup/'],
            written_by: 'y',
          },
        ],
      },
    })
    renderSources()
    const badge = await screen.findByLabelText(/no mobile marker recognised/i)
    const label = badge.getAttribute('aria-label') ?? ''
    // A PowerLogSummary at a Mac path WAS found and rejected; the chip must
    // not say no such record was found.
    expect(label).not.toMatch(/none of these record types was found/)
    expect(label).toMatch(/MobileDeviceInfo with platform = android/)
    expect(label).toMatch(
      /PowerLogSummary with platform = iOS, from a path containing var\/containers\/Shared\/SystemGroup\//,
    )
  })

  it('a label read while the walk ran is re-read when the source says the walk ended', async () => {
    let state = 'running'
    const sources = (): SourceStatsResponse => ({
      sources: [{ ...PLAIN_SOURCE.sources[0], processing_state: state }],
    })
    mockApi({ artifact: PLAIN_ARTIFACT })
    server.use(
      http.get('/api/v1/cases/case-1/stats/sources', () => HttpResponse.json(sources())),
      http.get('/api/v1/cases/case-1/source_kinds', () =>
        HttpResponse.json(
          state === 'running'
            ? kindsWith({
                walk_state: 'running',
                not_assessed_reason: 'its walk is still running',
              })
            : kindsWith({ label: 'none_recognised', assessed: true }),
        ),
      ),
    )
    const queryClient = renderSources()
    await screen.findByLabelText(/its walk is still running/i)
    // Only the source counts are refreshed, as a poll or an event would.
    state = 'completed'
    await queryClient.invalidateQueries({ queryKey: ['case', 'case-1', 'stats', 'sources'] })
    await screen.findByLabelText(/no mobile marker recognised/i)
    expect(screen.queryByLabelText(/its walk is still running/i)).toBeNull()
  })

  it('a source with no recorded run renders the not-assessed wording', async () => {
    mockApi({
      sources: PLAIN_SOURCE,
      artifact: PLAIN_ARTIFACT,
      kinds: kindsWith({
        walk_state: 'no_run_recorded',
        not_assessed_reason: 'no ingest run recorded for this source',
      }),
    })
    renderSources()
    const badge = await screen.findByLabelText(/mobile evidence not assessed/i)
    expect(badge.getAttribute('aria-label')).toMatch(/no ingest run recorded/)
    expect(screen.queryByLabelText(/no mobile marker recognised/i)).toBeNull()
  })

  it('a failed label request says the label is unavailable and never that no marker was found', async () => {
    mockApi({ sources: PLAIN_SOURCE, artifact: PLAIN_ARTIFACT, kinds: null })
    renderSources()
    const badge = await screen.findByLabelText(/mobile label unavailable/i)
    expect(badge.getAttribute('aria-label')).toMatch(/label boom/)
    expect(screen.queryByLabelText(/no mobile marker recognised/i)).toBeNull()
  })
})
