import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { canonicalWorkbenchPath } from '../../app/routes'
import { LogicalTree } from './LogicalTree'

function mockTypes(
  types: { type: string; count: number }[],
  media = { pictures: 0, videos: 0, audio: 0, documents: 0, geolocation: 0 },
  sources: { id: string; name: string }[] = [],
) {
  server.use(
    http.get('/api/v1/cases/case-1/record_types', () =>
      HttpResponse.json({ record_types: types }),
    ),
    http.get('/api/v1/cases/case-1/stats/media_counts', () =>
      HttpResponse.json(media),
    ),
    http.get('/api/v1/cases/case-1/artifacts/root/children', () =>
      HttpResponse.json({
        items: sources.map((s) => ({
          id: s.id,
          parent_id: null,
          artifact_type: 'RawEvidence',
          name: s.name,
          has_children: true,
        })),
      }),
    ),
  )
}

/** record_types whose counts depend on the ?source_id= param, plus two sources
 *  and a media count — the fixture for the provenance-filter tests. */
function mockSourceScopedTypes(perSource: Record<string, { type: string; count: number }[]>) {
  const all = perSource['__all__']
  server.use(
    http.get('/api/v1/cases/case-1/record_types', ({ request }) => {
      const sourceId = new URL(request.url).searchParams.get('source_id')
      const types = (sourceId && perSource[sourceId]) || all
      return HttpResponse.json({ record_types: types })
    }),
    http.get('/api/v1/cases/case-1/stats/media_counts', () =>
      HttpResponse.json({
        pictures: 9,
        videos: 0,
        audio: 0,
        documents: 0,
        geolocation: 0,
      }),
    ),
    http.get('/api/v1/cases/case-1/artifacts/root/children', () =>
      HttpResponse.json({
        items: [
          { id: 'src-a', parent_id: null, artifact_type: 'RawEvidence', name: 'laptop.E01', has_children: true },
          { id: 'src-b', parent_id: null, artifact_type: 'RawEvidence', name: 'phone.raw', has_children: true },
        ],
      }),
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
        <LogicalTree caseId="case-1" />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('LogicalTree', () => {
  it('shows categories with aggregated counts and expands to typed children', async () => {
    mockTypes([
      { type: 'WhatsApp', count: 3110 },
      { type: 'iMessage', count: 1486 },
      { type: 'BrowserHistory', count: 6201 },
      { type: 'file_hash', count: 99 }, // internal, must not appear
    ])
    renderTree()

    expect(await screen.findByText('Chats')).toBeInTheDocument()
    // Spelled out rather than computed with toLocaleString(), which would
    // follow whatever locale the test machine happens to run under and so
    // assert nothing about what an examiner is actually shown. 3110 + 1486.
    expect(screen.getByText('4,596')).toBeInTheDocument()
    expect(screen.getByText('Web & Downloads')).toBeInTheDocument()
    expect(screen.queryByText(/file.?hash/i)).not.toBeInTheDocument()

    // Expand the first category (Chats) — children link into the records viewer.
    await userEvent.click(screen.getAllByRole('button', { name: 'Expand' })[0])
    const whatsapp = await screen.findByRole('link', { name: 'WhatsApp' })
    // Sidebar links go to the canonical address of the records viewer, not to
    // the `workbench?type=` form that redirects onto it.
    expect(whatsapp).toHaveAttribute('href', '/cases/case-1/analysis/WhatsApp')
    expect(screen.getByRole('link', { name: 'iMessage' })).toBeInTheDocument()
  })

  it('groups the media kinds under Media, and keeps Geolocation top-level', async () => {
    mockTypes([{ type: 'WhatsApp', count: 5 }], {
      pictures: 42,
      videos: 3,
      audio: 5,
      documents: 0,
      geolocation: 7,
    })
    renderTree()

    // Media carries the combined count and holds the kinds.
    expect(await screen.findByText('Media')).toBeInTheDocument()
    expect(screen.getByText('50')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Pictures' })).toBeNull()

    await userEvent.click(screen.getByRole('button', { name: 'Expand Media' }))
    expect(
      screen.getByRole('link', { name: 'Pictures' }),
    ).toHaveAttribute('href', '/cases/case-1/gallery')
    // Videos and audio are the gallery under a different `?kind=`, which is the
    // one query string the canonical form keeps: without it all three collapse
    // into pictures.
    expect(screen.getByRole('link', { name: 'Videos' })).toHaveAttribute(
      'href',
      '/cases/case-1/gallery?kind=videos',
    )
    expect(screen.getByRole('link', { name: 'Audio' })).toHaveAttribute(
      'href',
      '/cases/case-1/gallery?kind=audio',
    )

    // Geolocation is not media, so it stays where it was.
    expect(
      screen.getByRole('link', { name: 'Geolocation' }),
    ).toHaveAttribute('href', '/cases/case-1/geo')
    expect(screen.getByText('7')).toBeInTheDocument()
  })

  it('shows an empty state when no analyst-facing records exist', async () => {
    mockTypes([{ type: 'allocation_map', count: 3 }])
    renderTree()
    expect(await screen.findByText(/No parsed records yet/)).toBeInTheDocument()
  })

  it('does not carry an expanded category into another case', async () => {
    // The sidebar this tree sits in is not remounted when `:caseId` changes --
    // only the routed page is -- and the expand keys are category slugs that
    // exist in every case. A category left open in case 1 therefore opened
    // itself under case 2, showing that case's records in chrome the examiner
    // never expanded there.
    mockTypes([{ type: 'WhatsApp', count: 3110 }])
    server.use(
      http.get('/api/v1/cases/case-2/record_types', () =>
        HttpResponse.json({ record_types: [{ type: 'Signal', count: 4 }] }),
      ),
      http.get('/api/v1/cases/case-2/stats/media_counts', () =>
        HttpResponse.json({
          pictures: 0,
          videos: 0,
          audio: 0,
          documents: 0,
          geolocation: 0,
        }),
      ),
    )
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const tree = (caseId: string) => (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <LogicalTree caseId={caseId} />
        </MemoryRouter>
      </QueryClientProvider>
    )
    const { rerender } = render(tree('case-1'))

    await userEvent.click(await screen.findByRole('button', { name: 'Expand' }))
    expect(
      await screen.findByRole('link', { name: 'WhatsApp' }),
    ).toBeInTheDocument()

    rerender(tree('case-2'))

    expect(await screen.findByText('Chats')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Signal' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Expand' })).toBeInTheDocument()
  })

  it('offers no source filter for a single-source case (nothing to disambiguate)', async () => {
    mockTypes([{ type: 'iMessage', count: 5 }], undefined, [
      { id: 'only', name: 'disk.img' },
    ])
    renderTree()
    await screen.findByText('Chats')
    expect(screen.queryByLabelText('Source')).toBeNull()
  })

  it('scopes counts and record links to the chosen source, and withholds case-wide media', async () => {
    mockSourceScopedTypes({
      __all__: [
        { type: 'iMessage', count: 10 },
        { type: 'PrefetchEntry', count: 4 },
      ],
      'src-a': [{ type: 'iMessage', count: 7 }],
      'src-b': [{ type: 'PrefetchEntry', count: 4 }],
    })
    renderTree()

    // Case-wide first: both categories, and Media (pictures) is present.
    expect(await screen.findByText('Chats')).toBeInTheDocument()
    expect(await screen.findByText('Media')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()

    // Scope to laptop.E01 (src-a).
    await userEvent.selectOptions(
      screen.getByLabelText('Source'),
      'laptop.E01',
    )

    // Counts rescope: Chats now 7, Program Execution disappears (src-a has none).
    expect(await screen.findByText('7')).toBeInTheDocument()
    expect(screen.queryByText('Program Execution')).toBeNull()
    // Case-wide media is withheld under a source scope.
    expect(screen.queryByText('Media')).toBeNull()

    // The record leaf now carries the source, so the table it opens lists only
    // this acquisition's rows.
    await userEvent.click(screen.getByRole('button', { name: 'Expand' }))
    const link = await screen.findByRole('link', { name: 'iMessage' })
    expect(link).toHaveAttribute(
      'href',
      '/cases/case-1/analysis/iMessage?source=src-a',
    )
  })

  it('lets the examiner return to the whole case', async () => {
    mockSourceScopedTypes({
      __all__: [{ type: 'iMessage', count: 10 }],
      'src-b': [],
    })
    renderTree()
    await screen.findByText('Chats')

    // Scope to a source that has no records → a clear, non-dead-end message.
    await userEvent.selectOptions(screen.getByLabelText('Source'), 'phone.raw')
    expect(await screen.findByText(/no parsed records/i)).toBeInTheDocument()
    // The filter is still there to switch back.
    await userEvent.selectOptions(screen.getByLabelText('Source'), 'All sources')
    expect(await screen.findByText('Chats')).toBeInTheDocument()
  })
})

describe('LogicalTree keyboard navigation', () => {
  function rows(): HTMLElement[] {
    return Array.from(
      document.querySelectorAll<HTMLElement>('[role="treeitem"]'),
    )
  }

  it('is a tree with one tab stop, not two per node', async () => {
    mockTypes([
      { type: 'WhatsApp', count: 3110 },
      { type: 'BrowserHistory', count: 6201 },
    ])
    renderTree()
    await screen.findByText('Chats')

    expect(screen.getByRole('tree')).toBeInTheDocument()
    expect(rows().length).toBeGreaterThan(1)
    expect(
      rows().filter((r) => r.getAttribute('tabindex') === '0'),
    ).toHaveLength(1)
    for (const caret of screen.getAllByRole('button', { name: 'Expand' })) {
      expect(caret).toHaveAttribute('tabindex', '-1')
    }
  })

  it('opens a category with ArrowRight and steps into its record types', async () => {
    mockTypes([
      { type: 'WhatsApp', count: 3110 },
      { type: 'iMessage', count: 1486 },
    ])
    renderTree()
    await screen.findByText('Chats')

    rows()[0].focus()
    expect(rows()[0]).toHaveAttribute('aria-expanded', 'false')
    await userEvent.keyboard('{ArrowRight}')
    expect(rows()[0]).toHaveAttribute('aria-expanded', 'true')
    expect(await screen.findByRole('link', { name: 'WhatsApp' })).toBeInTheDocument()

    await userEvent.keyboard('{ArrowRight}')
    expect(rows()[1]).toHaveFocus()
    await userEvent.keyboard('{ArrowDown}')
    expect(rows()[2]).toHaveFocus()

    // Left from a record type goes back to the category it belongs to.
    await userEvent.keyboard('{ArrowLeft}')
    expect(rows()[0]).toHaveFocus()
  })

  it('leaves nothing inside a row in the tab order', async () => {
    // Caret and label were two stops per node; with the row as the single
    // roving stop, neither is a stop any more and both stay clickable.
    mockTypes([
      { type: 'WhatsApp', count: 3110 },
      { type: 'iMessage', count: 1486 },
    ])
    renderTree()
    await screen.findByText('Chats')
    rows()[0].focus()
    await userEvent.keyboard('{ArrowRight}')
    await screen.findByRole('link', { name: 'WhatsApp' })

    const stops = Array.from(
      document.querySelectorAll<HTMLElement>(
        '[role="treeitem"] a, [role="treeitem"] button',
      ),
    ).filter((el) => el.getAttribute('tabindex') !== '-1')
    expect(stops).toHaveLength(0)
  })

  it('opens a record type from the keyboard through its own link', async () => {
    mockTypes([{ type: 'WhatsApp', count: 3110 }])
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/cases/case-1/navigator']}>
          <Routes>
            <Route
              path="/cases/case-1/navigator"
              element={<LogicalTree caseId="case-1" />}
            />
            <Route
              path="/cases/:caseId/analysis/:type"
              element={<div>records viewer</div>}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )
    await screen.findByText('Chats')

    rows()[0].focus()
    await userEvent.keyboard('{ArrowRight}')
    const link = await screen.findByRole('link', { name: 'WhatsApp' })
    const row = link.closest('[role="treeitem"]') as HTMLElement
    row.focus()
    await userEvent.keyboard('{Enter}')
    expect(await screen.findByText('records viewer')).toBeInTheDocument()
  })
})

describe('LogicalTree addresses', () => {
  /**
   * The tree used to link to `/workbench?view=…` and `/workbench?type=…`. Those
   * are no longer the address of anything: the route table names one canonical
   * address per view and keeps the workbench form only as a redirect onto it.
   * The links therefore still arrived somewhere, which is why nothing caught
   * this — but an examiner following one watched the address bar land on a URL
   * they had not clicked, a bookmark taken mid-flight recorded the superseded
   * form, and every such click cost a second navigation.
   *
   * This asserts the tree emits exactly what the redirect would have produced,
   * rather than restating the destinations by hand. A hand-kept second copy of
   * a route mapping is what put the tree one refactor behind in the first
   * place, so the route table stays the source of truth and this test is the
   * join between them.
   */
  const canonical = (old: string) =>
    canonicalWorkbenchPath('case-1', new URLSearchParams(old))

  it('emits the canonical address for every view leaf, not the redirect', async () => {
    mockTypes([{ type: 'WhatsApp', count: 5 }, { type: 'PrefetchEntry', count: 9 }], {
      pictures: 42,
      videos: 3,
      audio: 5,
      documents: 0,
      geolocation: 7,
    })
    renderTree()

    await userEvent.click(await screen.findByRole('button', { name: 'Expand Media' }))
    const expected: [string, string][] = [
      ['Pictures', 'view=gallery'],
      ['Videos', 'view=videos'],
      ['Audio', 'view=audio'],
      ['Geolocation', 'view=geo'],
      ['Chats', 'view=comms'],
      ['Program Execution', 'view=execution'],
    ]
    for (const [name, old] of expected) {
      expect(screen.getByRole('link', { name }), name).toHaveAttribute(
        'href',
        canonical(old),
      )
    }
  })

  it('emits the canonical address for a record type, carrying the source scope', async () => {
    mockSourceScopedTypes({
      __all__: [{ type: 'iMessage', count: 10 }],
      'src-a': [{ type: 'iMessage', count: 7 }],
    })
    renderTree()
    await screen.findByText('Chats')
    await userEvent.selectOptions(screen.getByLabelText('Source'), 'laptop.E01')
    await screen.findByText('7')

    await userEvent.click(screen.getByRole('button', { name: 'Expand' }))
    expect(await screen.findByRole('link', { name: 'iMessage' })).toHaveAttribute(
      'href',
      canonical('type=iMessage&source=src-a'),
    )
  })
})
