import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { Artifact } from '../../api/types'
import { server } from '../../test/server'
import { OwnershipSection } from './OwnershipSection'

// The case: file `f1` on volume `vol`; the volume's `$Secure:$SDS` stream entry
// is `sds`, under `vol`. Another volume `vol2` has its own stream `sds2`, whose
// descriptor with the SAME id must never be shown for `f1`.

function file(metadata: Record<string, unknown>, parent: string | null = 'vol'): Artifact {
  return {
    id: 'f1',
    case_id: 'c1',
    parent_id: parent,
    artifact_type: 'FileEntry',
    metadata: { name: 'report.docx', ...metadata },
  }
}

function renderFor(artifact: Artifact) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <OwnershipSection caseId="c1" artifact={artifact} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const WHOLE_STORE = {
  type: 'NtfsSecurityDescriptorStore',
  bytes_scanned: 262_144,
  unique_security_ids: 41,
  store_listing_incomplete: false,
  source_stream: '$Secure:$SDS',
}

const DESCRIPTOR = {
  type: 'NtfsSecurityDescriptor',
  source_stream: '$Secure:$SDS',
  security_id: 256,
  descriptor_hash: 0xab12cd34,
  sds_offset: 0x40,
  recovered_from_mirror: false,
  owner_sid: 'S-1-5-32-544',
  owner_name: 'Administrators',
  group_sid: 'S-1-5-18',
  group_name: 'Local System',
  dacl_state: 'present',
  dacl: [
    {
      effect: 'allow',
      sid: 'S-1-5-21-1-2-3-1001',
      access_mask_desc: 'Full Control (0x001F01FF)',
      inherited: true,
      flag_names: ['INHERITED_ACE'],
    },
    {
      effect: 'deny',
      sid: 'S-1-1-0',
      sid_name: 'Everyone',
      access_mask_desc: 'Write',
      inherited: false,
      flag_names: [],
    },
  ],
  sacl_state: 'absent',
}

/**
 * Serve the records listing and the stream entries. `stores` are listed by
 * type across the case; descriptors are served per `source_id`, filtered by
 * the substring `q` the way the server's LIKE does.
 */
function serve({
  stores,
  descriptors,
}: {
  stores: { id: string; parent: string; metadata: Record<string, unknown> }[]
  descriptors: { id: string; parent: string; metadata: Record<string, unknown> }[]
}) {
  const seen: string[] = []
  server.use(
    http.get('/api/v1/cases/c1/records', ({ request }) => {
      const url = new URL(request.url)
      seen.push(url.search)
      const type = url.searchParams.get('type')
      if (type === 'NtfsSecurityDescriptorStore') {
        const records = stores.map((s) => ({
          id: s.id,
          parent_id: s.parent,
          artifact_type: 'ParsedRecord',
          metadata: s.metadata,
        }))
        return HttpResponse.json({ records, total: records.length })
      }
      const source = url.searchParams.get('source_id')
      const q = url.searchParams.get('q') ?? ''
      const records = descriptors
        .filter((d) => d.parent === source)
        .filter((d) => String(d.metadata.security_id).includes(q))
        .map((d) => ({
          id: d.id,
          parent_id: d.parent,
          artifact_type: 'ParsedRecord',
          metadata: d.metadata,
        }))
      return HttpResponse.json({ records, total: records.length })
    }),
    http.get('/api/v1/cases/c1/artifacts/:id', ({ params }) => {
      const parents: Record<string, string> = { sds: 'vol', sds2: 'vol2' }
      return HttpResponse.json({
        id: params.id,
        case_id: 'c1',
        parent_id: parents[params.id as string] ?? null,
        artifact_type: 'FileEntry',
        metadata: { name: '$Secure:$SDS' },
      })
    }),
  )
  return seen
}

describe('OwnershipSection', () => {
  it('says an entry with no security_id has none, and asks nothing', async () => {
    const seen = serve({ stores: [], descriptors: [] })
    renderFor(file({}))
    expect(screen.getByTestId('av-own-no-id')).toHaveTextContent(
      /carries no NTFS security_id/,
    )
    expect(seen).toHaveLength(0)
  })

  it('says security_id 0 names no descriptor', () => {
    renderFor(file({ security_id: 0 }))
    expect(screen.getByTestId('av-own-zero')).toHaveTextContent(/names no descriptor/)
  })

  it('shows owner, group and the ACL from the same volume, labelled with where they came from', async () => {
    const seen = serve({
      stores: [
        { id: 'st2', parent: 'sds2', metadata: WHOLE_STORE },
        { id: 'st', parent: 'sds', metadata: WHOLE_STORE },
      ],
      descriptors: [
        // Same id on another volume: must not be the answer.
        {
          id: 'other',
          parent: 'sds2',
          metadata: { ...DESCRIPTOR, owner_sid: 'S-1-5-18', owner_name: 'Local System' },
        },
        // A substring match on this volume that is not the id.
        { id: 'near', parent: 'sds', metadata: { ...DESCRIPTOR, security_id: 1256 } },
        { id: 'd256', parent: 'sds', metadata: DESCRIPTOR },
      ],
    })
    renderFor(file({ security_id: 256 }))
    expect(await screen.findByTestId('av-own-owner')).toHaveTextContent(
      'S-1-5-32-544 (Administrators)',
    )
    expect(screen.getByText('S-1-5-18 (Local System)')).toBeInTheDocument()
    const dacl = screen.getByTestId('av-own-dacl')
    expect(dacl).toHaveTextContent('S-1-5-21-1-2-3-1001')
    expect(dacl).toHaveTextContent('Full Control (0x001F01FF)')
    expect(dacl).toHaveTextContent('inherited')
    expect(dacl).toHaveTextContent('deny')
    expect(dacl).toHaveTextContent('S-1-1-0 (Everyone)')
    expect(screen.getByTestId('av-own-sacl')).toHaveTextContent(/nothing is audited/)
    const source = screen.getByTestId('av-own-source')
    expect(source).toHaveTextContent('$Secure:$SDS')
    expect(source).toHaveTextContent('security id 256')
    expect(source).toHaveTextContent('hash 0xAB12CD34')
    expect(source).toHaveTextContent('offset 0x40')
    // The descriptor search is scoped to this volume's stream only.
    const descriptorQueries = seen.filter((s) => s.includes('NtfsSecurityDescriptor&'))
    expect(descriptorQueries.every((s) => s.includes('source_id=sds&'))).toBe(true)
  })

  it('says why when the volume store was not read', async () => {
    serve({
      stores: [
        {
          id: 'st',
          parent: 'sds',
          metadata: {
            type: 'NtfsSecurityDescriptorStore',
            bytes_scanned: 0,
            unique_security_ids: 0,
            read_incomplete: 'volume_not_in_evidence',
            content_incomplete: true,
            content_incomplete_detail:
              'The $SDS security descriptor store ($Secure:$SDS) was identified but has no readable content',
          },
        },
      ],
      descriptors: [],
    })
    renderFor(file({ security_id: 256 }))
    const note = await screen.findByTestId('av-own-store-unread')
    expect(note).toHaveTextContent('was not read (volume_not_in_evidence)')
    expect(note).toHaveTextContent('has no readable content')
  })

  it('says no store from this volume was examined when only another volume has one', async () => {
    serve({
      stores: [{ id: 'st2', parent: 'sds2', metadata: WHOLE_STORE }],
      descriptors: [{ id: 'other', parent: 'sds2', metadata: DESCRIPTOR }],
    })
    renderFor(file({ security_id: 256 }))
    expect(await screen.findByTestId('av-own-no-store')).toHaveTextContent(
      /unknown here, not absent/,
    )
    expect(screen.queryByTestId('av-own-owner')).toBeNull()
  })

  it('says the id is not in a whole store', async () => {
    serve({
      stores: [{ id: 'st', parent: 'sds', metadata: WHOLE_STORE }],
      descriptors: [
        { id: 'near', parent: 'sds', metadata: { ...DESCRIPTOR, security_id: 1256 } },
      ],
    })
    renderFor(file({ security_id: 256 }))
    const note = await screen.findByTestId('av-own-not-found')
    expect(note).toHaveTextContent('Security id 256 is not among the 41 descriptors')
    expect(note).toHaveTextContent('read whole')
  })

  it('does not call an id absent when the store listing is incomplete', async () => {
    serve({
      stores: [
        {
          id: 'st',
          parent: 'sds',
          metadata: {
            ...WHOLE_STORE,
            store_listing_incomplete: true,
            inventory_incomplete: true,
            inventory_incomplete_detail: 'This listing of $SDS security descriptors is not the whole store',
          },
        },
      ],
      descriptors: [],
    })
    renderFor(file({ security_id: 256 }))
    const note = await screen.findByTestId('av-own-not-found')
    expect(note).toHaveTextContent('not shown to be absent from the volume')
    expect(note).toHaveTextContent('not the whole store')
  })

  it('says a lookup failure is a failure, not an absence', async () => {
    server.use(
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ error: 'boom' }, { status: 500 }),
      ),
    )
    renderFor(file({ security_id: 256 }))
    expect(await screen.findByTestId('av-own-error')).toHaveTextContent(
      /could not be looked up/,
    )
  })
})
