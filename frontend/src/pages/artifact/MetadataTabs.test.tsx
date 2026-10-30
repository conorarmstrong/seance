import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { Artifact } from '../../api/types'
import { OverviewTab, PropertiesTab } from './MetadataTabs'

const CASE_ID = 'c1'

function artifact(over: Partial<Artifact>): Artifact {
  return {
    id: 'a1',
    case_id: CASE_ID,
    parent_id: null,
    artifact_type: 'ParsedRecord',
    metadata: {},
    ...over,
  } as Artifact
}

function renderTab(a: Artifact) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <OverviewTab artifact={a} caseId={CASE_ID} />
    </QueryClientProvider>,
  )
}

describe('OverviewTab', () => {
  it("falls back to the source file's properties when a record has none", async () => {
    // A parser summary (e.g. an encrypted Signal backup) carries only what the
    // parser emitted — no size, no dates. Those belong to the file it came from.
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/artifacts/parent-1`, () =>
        HttpResponse.json({
          id: 'parent-1',
          case_id: CASE_ID,
          parent_id: null,
          artifact_type: 'FileEntry',
          metadata: {
            name: 'mediaanalysis.backup',
            size: 4096,
            modified: '2024-03-04T09:10:11Z',
          },
        }),
      ),
    )
    renderTab(
      artifact({
        parent_id: 'parent-1',
        metadata: {
          type: 'SignalBackup',
          file_name: 'mediaanalysis.backup',
          decrypted: false,
        },
      }),
    )

    expect(await screen.findByText('4.0 KiB')).toBeInTheDocument()
    // Attribution is explicit: these are the source file's facts, not the
    // record's own.
    expect(screen.getByText(/From the source file/)).toBeInTheDocument()
    expect(screen.getByText('mediaanalysis.backup')).toBeInTheDocument()
  })

  it("shows a record's own properties without consulting the parent", async () => {
    let parentFetched = false
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/artifacts/parent-1`, () => {
        parentFetched = true
        return HttpResponse.json({})
      }),
    )
    renderTab(
      artifact({
        parent_id: 'parent-1',
        metadata: { size: 2048, name: 'own.bin' },
      }),
    )

    expect(await screen.findByText('2.0 KiB')).toBeInTheDocument()
    expect(screen.queryByText(/From the source file/)).not.toBeInTheDocument()
    expect(parentFetched).toBe(false)
  })
})

describe('PropertiesTab pivot affordance (§1.0)', () => {
  // A pivot trigger renders as a button; a plain property renders as text.
  // `usePivot()` outside a provider is a documented no-op, so this asserts
  // exactly what changed here — which cells are triggers — without needing
  // the drawer. Where the click leads is covered by the Entities and Search
  // tests and by PivotDrawer's own.
  it('makes an identifier a pivot trigger and leaves a property plain', () => {
    render(
      <PropertiesTab
        metadata={{
          client_ip: '10.0.0.5',
          sha256:
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          size: 4096,
          is_directory: false,
          inventory_incomplete_reason: 'ingest_interrupted',
        }}
      />,
    )

    // The identifiers are one click from their footprint across the case. The
    // button's accessible name is the value itself; the pivot intent is in its
    // title, asserted here so the affordance is discoverable on hover too.
    const ip = screen.getByRole('button', { name: '10.0.0.5' })
    expect(ip).toHaveAttribute(
      'title',
      expect.stringContaining('Pivot on 10.0.0.5'),
    )
    expect(
      screen.getByRole('button', { name: /^e3b0c44298fc1c14/ }),
    ).toBeInTheDocument()

    // A count, a flag and one of the product's own incompleteness sentences
    // are not: "every artifact referencing 4096" is noise that teaches an
    // examiner to distrust the affordance.
    expect(screen.queryByRole('button', { name: /4096/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /false/ })).toBeNull()
    expect(
      screen.queryByRole('button', { name: /ingest_interrupted/ }),
    ).toBeNull()
    // ...but every value is still shown.
    expect(screen.getByText('4096')).toBeInTheDocument()
    expect(screen.getByText('ingest_interrupted')).toBeInTheDocument()
  })

  it('leaves a nested value as JSON with no pivot', () => {
    render(
      <PropertiesTab
        metadata={{ unresolved_sublists: [{ offset: 2147483632, error: 'x' }] }}
      />,
    )
    expect(screen.queryByRole('button')).toBeNull()
  })
})
