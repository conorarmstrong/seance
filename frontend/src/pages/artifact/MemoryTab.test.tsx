import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { MemoryTab } from './MemoryTab'
import { tabsForArtifact } from './lib'
import type { MemoryImageSummary } from '../memory/api'
import type { Artifact } from '../../api/types'

const IMAGE: MemoryImageSummary = {
  image_id: 'img-1',
  source_artifact_id: 'file-1',
  name: 'memdump.raw',
  image_format: 'raw',
  architecture: 'X64',
  addressable_bytes: 536_870_912,
  file_bytes: 536_870_912,
  declared_size: 536_870_912,
  size_mismatch: false,
  decode_failed: false,
  content_complete: true,
  content_complete_known: true,
  incomplete: null,
  analysis_state: 'analysed',
  analysis_state_meaning: 'An image profile was established and the stages ran.',
  profile: null,
  stage_failures: 0,
} as MemoryImageSummary

const FILE = {
  id: 'file-1',
  artifact_type: 'FileEntry',
  metadata: { name: 'memdump.raw' },
} as unknown as Artifact

// The artifact page and the Memory section share the query key
// ['memory', caseId, 'images']. MemoryLayout reads it through
// `useEntityScopedQuery`, which stores `{__scope, value}` rather than the bare
// response. When the artifact page used a plain `useQuery` on that same key it
// wrote an untagged response into the cache, MemoryLayout read
// `__scope === undefined`, judged the data to be another case's, and — with
// `staleTime: Infinity` — never refetched. The entire Memory section sat on its
// loading skeleton, and no test saw it because the two pages are never mounted
// together in one test file.
describe('the shared memory-images cache entry', () => {
  it('is written in the shape the Memory section reads back', async () => {
    // Both readers are driven here through the same QueryClient, which is what
    // the running app does and what no single-page test reproduced.
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const body = {
      case_id: 'case-1',
      images: [IMAGE],
      image_count: 1,
      images_truncated: false,
      summaries_complete: true,
    }

    function ArtifactSide() {
      const q = useEntityScopedQuery<typeof body>('case-1', {
        queryKey: ['memory', 'case-1', 'images'],
        queryFn: async () => body,
        staleTime: Infinity,
        retry: false,
      })
      return <span data-testid="artifact-side">{q.scoped ? 'read' : 'pending'}</span>
    }

    // Exactly MemoryLayout's gate: `stale` means "this belongs to another
    // scope", and with staleTime: Infinity nothing ever refetches to clear it.
    function MemorySide() {
      const q = useEntityScopedQuery<typeof body>('case-1', {
        queryKey: ['memory', 'case-1', 'images'],
        queryFn: async () => body,
        staleTime: Infinity,
        retry: false,
      })
      return (
        <span data-testid="memory-side">
          {q.isPending || q.stale ? 'skeleton' : 'resolved'}
        </span>
      )
    }

    render(
      <QueryClientProvider client={client}>
        <ArtifactSide />
        <MemorySide />
      </QueryClientProvider>,
    )

    await waitFor(() =>
      expect(screen.getByTestId('artifact-side')).toHaveTextContent('read'),
    )
    // The regression: an untagged write here left this on 'skeleton' forever,
    // so the whole Memory section never loaded once an artifact page had been
    // opened first.
    expect(screen.getByTestId('memory-side')).toHaveTextContent('resolved')
  })
})

describe('the door from evidence into memory analysis', () => {
  // The navigator hides ParsedRecord children, so an examiner browsing the
  // physical tree sees the capture as a file and never sees the MemoryImage
  // record. Without this tab the only way in is to leave the tree and re-find
  // the same file in a dropdown.
  it('offers a Memory tab on the artifact a capture was decoded from', () => {
    const tabs = tabsForArtifact(FILE, null, IMAGE.image_id)
    expect(tabs.map((t) => t.id)).toContain('memory')
  })

  it('offers nothing on a file that is not a capture', () => {
    const tabs = tabsForArtifact(FILE, null, null)
    expect(tabs.map((t) => t.id)).not.toContain('memory')
  })

  it('carries the image id, which is what scopes every lens', () => {
    render(
      <MemoryRouter>
        <MemoryTab caseId="case-1" image={IMAGE} />
      </MemoryRouter>,
    )
    const link = screen.getByRole('link', { name: /Open in Memory analysis/i })
    expect(link).toHaveAttribute('href', '/cases/case-1/memory?image=img-1')
  })

  // "The container did not say" and "the container said complete" are
  // different claims about the acquisition, and only one of them is a finding.
  it('does not render an unstated completeness as a stated one', () => {
    render(
      <MemoryRouter>
        <MemoryTab
          caseId="case-1"
          image={{ ...IMAGE, content_complete: null, content_complete_known: false }}
        />
      </MemoryRouter>,
    )
    expect(screen.getByText(/did not state whether its content is complete/i)).toBeInTheDocument()
    expect(screen.queryByText(/declared its content complete/i)).not.toBeInTheDocument()
  })

  // A capture that could not be decoded must not let an empty process list read
  // as a machine that was running nothing.
  it('says an undecodable capture makes absence meaningless', () => {
    render(
      <MemoryRouter>
        <MemoryTab caseId="case-1" image={{ ...IMAGE, decode_failed: true }} />
      </MemoryRouter>,
    )
    expect(
      screen.getByText(/gap in the analysis, not a finding about the machine/i),
    ).toBeInTheDocument()
  })

  it('surfaces stages that could not run, rather than leaving them to be discovered', () => {
    render(
      <MemoryRouter>
        <MemoryTab caseId="case-1" image={{ ...IMAGE, stage_failures: 3 }} />
      </MemoryRouter>,
    )
    expect(screen.getByText(/3 analysis stages could not run/i)).toBeInTheDocument()
  })
})
