import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { ArtifactListItem } from '../../api/types'
import { server } from '../../test/server'
import { EvidenceTree } from './EvidenceTree'

const ROOTS: ArtifactListItem[] = [
  {
    id: 'src-1',
    parent_id: null,
    artifact_type: 'RawEvidence',
    name: 'disk.img',
    has_children: true,
  },
]

const CHILDREN: ArtifactListItem[] = [
  {
    id: 'part-1',
    parent_id: 'src-1',
    artifact_type: 'Partition',
    name: 'Partition',
    has_children: true,
    metadata: {
      partition_scheme: 'MBR',
      partition_id: 1,
      partition_type_name: 'NTFS',
      size_bytes: 1073741824,
    },
  },
  {
    id: 'part-2',
    parent_id: 'src-1',
    artifact_type: 'Partition',
    name: 'Partition',
    has_children: false,
    metadata: {
      partition_scheme: 'GPT',
      partition_id: 2,
      size_bytes: 536870912,
    },
  },
  {
    id: 'part-bare',
    parent_id: 'src-1',
    artifact_type: 'Partition',
    name: 'Partition',
    has_children: false,
  },
  {
    id: 'fs-1',
    parent_id: 'src-1',
    artifact_type: 'FileSystem',
    name: 'FileSystem',
    has_children: true,
    metadata: { filesystem_type: 'ext4' },
  },
  {
    id: 'unalloc-1',
    parent_id: 'src-1',
    artifact_type: 'UnallocatedSpace',
    name: 'UnallocatedSpace',
    has_children: false,
    metadata: { size_bytes: 2048 },
  },
]

// The tree fetches the case's RAM captures to mark their source nodes. Every
// test needs this stubbed (unhandled requests error); most want it empty.
function mockMemoryImages(images: unknown[] = []) {
  server.use(
    http.get('/api/v1/cases/case-1/memory/images', () =>
      HttpResponse.json({
        case_id: 'case-1',
        images,
        image_count: images.length,
        images_truncated: false,
        summaries_complete: true,
      }),
    ),
  )
}

function mockTree() {
  mockMemoryImages()
  server.use(
    http.get('/api/v1/cases/case-1/artifacts/root/children', () =>
      HttpResponse.json({ items: ROOTS }),
    ),
    http.get('/api/v1/cases/case-1/artifacts/src-1/children', () =>
      HttpResponse.json({ items: CHILDREN }),
    ),
  )
}

function renderTree() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <EvidenceTree caseId="case-1" />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('EvidenceTree', () => {
  it('labels nodes from artifact metadata after lazy expand', async () => {
    mockTree()
    renderTree()
    await screen.findByText('disk.img')

    await userEvent.click(screen.getByRole('button', { name: 'Expand' }))

    // Partitions become distinguishable: number, type/scheme, size.
    expect(
      await screen.findByText('Partition 1 · NTFS · 1.0 GiB'),
    ).toBeInTheDocument()
    expect(screen.getByText('Partition 2 · GPT · 512.0 MiB')).toBeInTheDocument()
    // Filesystem and unallocated labels.
    expect(screen.getByText('ext4 filesystem')).toBeInTheDocument()
    expect(screen.getByText('Unallocated · 2.0 KiB')).toBeInTheDocument()
    // Missing metadata falls back to the raw name.
    expect(screen.getByText('Partition')).toBeInTheDocument()
  })

  it('says an expanded node failed to load rather than showing it as empty (B8-032)', async () => {
    // The server said this source HAS children. A failed request rendered
    // nothing under it, which is what a container holding nothing looks like —
    // an examiner can read that as "this partition was empty".
    mockMemoryImages()
    server.use(
      http.get('/api/v1/cases/case-1/artifacts/root/children', () =>
        HttpResponse.json({ items: ROOTS }),
      ),
      http.get('/api/v1/cases/case-1/artifacts/src-1/children', () =>
        HttpResponse.json({ error: 'database is locked' }, { status: 500 }),
      ),
    )
    renderTree()
    await screen.findByText('disk.img')

    await userEvent.click(screen.getByRole('button', { name: 'Expand' }))

    const note = await screen.findByTestId('tree-children-error')
    expect(note.textContent).toMatch(/could not load contents/i)
    expect(screen.queryByText('empty')).toBeNull()
    expect(screen.getByRole('button', { name: 'retry' })).toBeInTheDocument()
  })

  it('links every node to its artifact’s canonical address', async () => {
    mockTree()
    renderTree()
    await screen.findByText('disk.img')
    await userEvent.click(screen.getByRole('button', { name: 'Expand' }))

    const fsLink = await screen.findByRole('link', { name: 'ext4 filesystem' })
    expect(fsLink).toHaveAttribute(
      'href',
      '/cases/case-1/artifacts/fs-1',
    )
    const partLink = screen.getByRole('link', {
      name: 'Partition 1 · NTFS · 1.0 GiB',
    })
    expect(partLink).toHaveAttribute(
      'href',
      '/cases/case-1/artifacts/part-1',
    )
  })

  it('marks a capture source with a RAM tag that deep-links to its memory analysis', async () => {
    mockMemoryImages([
      {
        image_id: 'mem-9',
        source_artifact_id: 'src-1',
        name: 'memory.lime',
        image_format: 'lime',
        architecture: 'x64',
        addressable_bytes: null,
        file_bytes: null,
        declared_size: null,
        size_mismatch: false,
        decode_failed: false,
        content_complete: null,
        content_complete_known: false,
        incomplete: null,
        analysis_state: 'complete',
        analysis_state_meaning: '',
        profile: null,
        stage_failures: 0,
      },
    ])
    server.use(
      http.get('/api/v1/cases/case-1/artifacts/root/children', () =>
        HttpResponse.json({ items: ROOTS }),
      ),
      http.get('/api/v1/cases/case-1/artifacts/src-1/children', () =>
        HttpResponse.json({ items: CHILDREN }),
      ),
    )
    renderTree()
    await screen.findByText('disk.img')

    const ramLink = await screen.findByRole('link', { name: /RAM/ })
    expect(ramLink).toHaveAttribute(
      'href',
      '/cases/case-1/memory?image=mem-9',
    )
    // The underlying evidence stays browsable — the source is still a real node
    // with its own workbench link, not replaced by the RAM shortcut.
    expect(
      screen.getByRole('link', { name: 'disk.img' }),
    ).toHaveAttribute('href', '/cases/case-1/artifacts/src-1')
  })

  it('shows no RAM tag when a capture has no known source', async () => {
    mockMemoryImages([
      {
        image_id: 'mem-orphan',
        source_artifact_id: null,
        name: 'floating.lime',
        image_format: 'lime',
        architecture: null,
        addressable_bytes: null,
        file_bytes: null,
        declared_size: null,
        size_mismatch: false,
        decode_failed: false,
        content_complete: null,
        content_complete_known: false,
        incomplete: null,
        analysis_state: 'complete',
        analysis_state_meaning: '',
        profile: null,
        stage_failures: 0,
      },
    ])
    server.use(
      http.get('/api/v1/cases/case-1/artifacts/root/children', () =>
        HttpResponse.json({ items: ROOTS }),
      ),
      http.get('/api/v1/cases/case-1/artifacts/src-1/children', () =>
        HttpResponse.json({ items: CHILDREN }),
      ),
    )
    renderTree()
    await screen.findByText('disk.img')
    expect(screen.queryByRole('link', { name: /RAM/ })).toBeNull()
  })
})

describe('EvidenceTree keyboard navigation', () => {
  /** Every rendered tree row, in the order the examiner sees them. */
  function rows(): HTMLElement[] {
    return Array.from(
      document.querySelectorAll<HTMLElement>('[role="treeitem"]'),
    )
  }

  it('announces itself as a tree and puts one tab stop on the whole thing', async () => {
    mockTree()
    renderTree()
    await screen.findByText('disk.img')

    expect(screen.getByRole('tree')).toBeInTheDocument()
    expect(rows()).toHaveLength(1)
    // Reaching Users/john/AppData six levels down used to cost two Tab
    // presses per node — the caret, then the label. The row is the tab stop
    // now, and there is exactly one of them in the tree.
    expect(rows()[0]).toHaveAttribute('tabindex', '0')
    expect(
      screen.getByRole('button', { name: 'Expand' }),
    ).toHaveAttribute('tabindex', '-1')
    expect(screen.getByRole('link', { name: 'disk.img' })).toHaveAttribute(
      'tabindex',
      '-1',
    )
  })

  it('opens a node with ArrowRight, steps in, and steps back out with ArrowLeft', async () => {
    mockTree()
    renderTree()
    await screen.findByText('disk.img')

    rows()[0].focus()
    // First Right opens without moving: the examiner asked to see inside, not
    // to leave the node they are on.
    await userEvent.keyboard('{ArrowRight}')
    expect(await screen.findByText('ext4 filesystem')).toBeInTheDocument()
    expect(rows()[0]).toHaveFocus()
    expect(rows()[0]).toHaveAttribute('aria-expanded', 'true')

    // A second Right steps into the first child.
    await userEvent.keyboard('{ArrowRight}')
    expect(rows()[1]).toHaveFocus()

    // Down and up walk the visible rows, whatever level they are on.
    await userEvent.keyboard('{ArrowDown}')
    expect(rows()[2]).toHaveFocus()

    // Left from a leaf goes to its parent; Left again collapses the parent.
    await userEvent.keyboard('{ArrowLeft}')
    expect(rows()[0]).toHaveFocus()
    await userEvent.keyboard('{ArrowLeft}')
    expect(rows()[0]).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('ext4 filesystem')).toBeNull()
  })

  it('jumps to the first and last visible row with Home and End', async () => {
    mockTree()
    renderTree()
    await screen.findByText('disk.img')

    rows()[0].focus()
    await userEvent.keyboard('{ArrowRight}')
    await screen.findByText('ext4 filesystem')

    await userEvent.keyboard('{End}')
    expect(rows()[rows().length - 1]).toHaveFocus()
    await userEvent.keyboard('{Home}')
    expect(rows()[0]).toHaveFocus()
  })

  it('follows a leaf node’s own link when Enter is pressed on the row', async () => {
    mockTree()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/cases/case-1/navigator']}>
          <Routes>
            <Route
              path="/cases/case-1/navigator"
              element={<EvidenceTree caseId="case-1" />}
            />
            <Route
              path="/cases/:caseId/artifacts/:artifactId"
              element={<div>artifact page</div>}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )
    await screen.findByText('disk.img')

    rows()[0].focus()
    await userEvent.keyboard('{ArrowRight}')
    const fs = await screen.findByText('ext4 filesystem')
    const row = fs.closest('[role="treeitem"]') as HTMLElement
    row.focus()
    // A filesystem is a leaf here (its children are every file in it), so
    // Enter opens it — and it opens through the row's own link, so the
    // keyboard cannot reach a destination the mouse would not.
    await userEvent.keyboard('{Enter}')
    expect(await screen.findByText('artifact page')).toBeInTheDocument()
  })
})

describe('EvidenceTree rows hold no tab stops of their own', () => {
  function rows(): HTMLElement[] {
    return Array.from(
      document.querySelectorAll<HTMLElement>('[role="treeitem"]'),
    )
  }

  function tabbableInRows(): HTMLElement[] {
    return Array.from(
      document.querySelectorAll<HTMLElement>(
        '[role="treeitem"] a, [role="treeitem"] button',
      ),
    ).filter((el) => el.getAttribute('tabindex') !== '-1')
  }

  it('keeps the caret and the label out of the tab order', async () => {
    mockTree()
    renderTree()
    await screen.findByText('disk.img')
    rows()[0].focus()
    await userEvent.keyboard('{ArrowRight}')
    await screen.findByText('ext4 filesystem')

    // Six levels of nodes with a caret and a label each is what cost two Tab
    // presses per node. Neither is a stop now; both are still clickable, and
    // the row's own keys reach them.
    expect(tabbableInRows()).toHaveLength(0)
  })

  it('leaves exactly one deliberate exception: a capture source’s RAM tag', async () => {
    // Not a per-row cost — it appears only on the artifact a RAM capture was
    // decoded from — and it is the only keyboard path to that capture's memory
    // analysis, which the row's Enter (the artifact) cannot also be.
    mockMemoryImages([
      {
        image_id: 'img-1',
        source_artifact_id: 'src-1',
        name: 'memdump.raw',
        profile: null,
        process_count: 3,
      },
    ])
    server.use(
      http.get('/api/v1/cases/case-1/artifacts/root/children', () =>
        HttpResponse.json({ items: ROOTS }),
      ),
    )
    renderTree()
    await screen.findByText('disk.img')

    const stops = tabbableInRows()
    expect(stops).toHaveLength(1)
    expect(stops[0]).toHaveClass('tree-ram-tag')
  })
})
