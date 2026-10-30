import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { PhysicalLocationSection } from './PhysicalLocationSection'

function renderSection() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <PhysicalLocationSection caseId="c1" artifactId="a1" />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const ENDPOINT = '/api/v1/cases/c1/artifacts/a1/physical-location'

describe('PhysicalLocationSection', () => {
  it('shows fragmentation-aware device extents and the evidence chain', async () => {
    server.use(
      http.get(ENDPOINT, () =>
        HttpResponse.json({
          device: {
            artifact_id: 'root',
            name: 'suspect.E01',
            artifact_type: 'RawEvidence',
            path: '/evidence/suspect.E01',
            decoded_container: true,
          },
          extents: [
            { device_offset: 1048576, length: 4096, sector: 2048, sparse: false },
            { device_offset: 5242880, length: 8192, sector: 10240, sparse: false },
          ],
          precision: 'exact',
          note: null,
          truncated: false,
          logical_size: 12288,
          located_bytes: 12288,
          sector_size: 512,
          chain: [
            {
              artifact_id: 'root',
              name: 'suspect.E01',
              artifact_type: 'RawEvidence',
              offset_in_parent: null,
              transform: 'container:e01',
              fragment_count: null,
            },
            {
              artifact_id: 'a1',
              name: 'secret.jpg',
              artifact_type: 'FileEntry',
              offset_in_parent: null,
              transform: 'runs',
              fragment_count: 2,
            },
          ],
        }),
      ),
    )
    renderSection()

    // Device-absolute offsets, in hex.
    expect(await screen.findByText('0x100000')).toBeInTheDocument()
    expect(screen.getByText('0x500000')).toBeInTheDocument()
    // Decoded-container badge + a two-extent summary.
    expect(screen.getByText('decoded image')).toBeInTheDocument()
    expect(screen.getByText(/2 extents/)).toBeInTheDocument()
    // Chain shows the fragment count on the file level.
    expect(screen.getByText('2 fragments')).toBeInTheDocument()
  })

  it('shows an honest note and no extent table for synthetic content', async () => {
    server.use(
      http.get(ENDPOINT, () =>
        HttpResponse.json({
          device: {
            artifact_id: 'root',
            name: 'disk.dd',
            artifact_type: 'RawEvidence',
            path: '/e/disk.dd',
            decoded_container: false,
          },
          extents: [{ device_offset: null, length: 200, sector: null, sparse: false }],
          precision: 'synthetic',
          note: 'This content has no single device byte range: it is reconstructed or held in memory.',
          truncated: false,
          logical_size: 200,
          located_bytes: 0,
          sector_size: 512,
          chain: [],
        }),
      ),
    )
    renderSection()

    expect(await screen.findByText(/no single device byte range/i)).toBeInTheDocument()
    expect(screen.getByText(/No contiguous device range/)).toBeInTheDocument()
    // No offsets table for synthetic-only content.
    expect(screen.queryByText('Device offset')).not.toBeInTheDocument()
  })

  it('renders nothing when the artifact has no recorded location', async () => {
    server.use(
      http.get(ENDPOINT, () =>
        HttpResponse.json({ error: 'no recorded content location' }, { status: 400 }),
      ),
    )
    const { container } = renderSection()
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  it('says a failed lookup failed instead of collapsing like an artifact with no location', async () => {
    // 400/404 is the endpoint's answer ("this artifact has no content
    // location") and collapsing is right. A 500 is not an answer, and
    // collapsing on it told the examiner this exhibit has no place on the
    // device — the question they are asked in the witness box.
    server.use(
      http.get(ENDPOINT, () =>
        HttpResponse.json({ error: 'the evidence root is offline' }, { status: 500 }),
      ),
    )
    renderSection()

    const note = await screen.findByTestId('av-phys-error')
    expect(note.textContent).toMatch(/could not be established/i)
    expect(note.textContent).toMatch(/no place on the device/i)
  })

  it('names the pagefile an extent lives in rather than implying the image', async () => {
    // The display mistake this guards: a pagefile offset rendered exactly like
    // a device offset. The number is real and it is a coordinate in a
    // different file, so an examiner who seeks to it on the disk gets
    // unrelated bytes with nothing to say they are the wrong ones.
    server.use(
      http.get(ENDPOINT, () =>
        HttpResponse.json({
          device: {
            artifact_id: 'root',
            name: 'memory.raw',
            artifact_type: 'RawEvidence',
            path: '/evidence/memory.raw',
            decoded_container: false,
          },
          extents: [
            {
              device_offset: 1048576,
              length: 4096,
              sector: 2048,
              sparse: false,
              source: 'device',
            },
            {
              device_offset: 4136960,
              length: 4096,
              // No sector: sector numbers are device coordinates.
              sector: null,
              sparse: false,
              source: 'pagefile.sys',
            },
          ],
          precision: 'exact',
          note: null,
          truncated: false,
          logical_size: 8192,
          located_bytes: 8192,
          sector_size: 512,
          chain: [],
        }),
      ),
    )
    renderSection()

    await waitFor(() => expect(screen.getByText('0x100000')).toBeInTheDocument())

    // The swapped page names its file, and the ordinary extent does not
    // borrow that name.
    expect(screen.getByText('pagefile.sys')).toBeInTheDocument()
    expect(screen.getByText('device image')).toBeInTheDocument()

    // And the summary does not claim both extents are on the evidence image.
    expect(
      screen.getByText(/in pagefile\.sys rather than the evidence image/),
    ).toBeInTheDocument()
  })
})
