import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import userEvent from '@testing-library/user-event'
import { ConnectionsPage, ParticipantDetail } from './ConnectionsPage'
import type { CommNode, CommunicationGraph } from './types'

beforeAll(() => {
  // jsdom implements neither; the canvas graph needs them to mount.
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null)
})

const SELF = 'self'

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/cases/c1/connections']}>
        <Routes>
          <Route path="/cases/:caseId/connections" element={<ConnectionsPage />} />
          <Route
            path="/cases/:caseId/search"
            element={<div>search-stub</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function mockGraph(body: CommunicationGraph) {
  server.use(
    http.get('/api/v1/cases/c1/graph/communications', () =>
      HttpResponse.json(body),
    ),
  )
}

describe('ConnectionsPage', () => {
  it('renders the network with participant stats and legend', async () => {
    mockGraph({
      nodes: [
        { id: SELF, label: 'This device', kind: 'self', weight: 5 },
        { id: 'alice', label: 'Alice', kind: 'contact', weight: 3 },
        { id: 'bob@x.com', label: 'Bob', kind: 'email', weight: 2 },
      ],
      edges: [
        { source: SELF, target: 'alice', weight: 3 },
        { source: SELF, target: 'bob@x.com', weight: 2 },
      ],
      truncated: false,
      total_participants: 3,
    })
    renderPage()

    expect(await screen.findByText(/participants/)).toBeInTheDocument()
    expect(screen.getByText(/links/)).toBeInTheDocument()
    // legend
    expect(screen.getByText('Contact')).toBeInTheDocument()
    // the canvas graph mounted
    expect(document.querySelector('canvas')).toBeInTheDocument()
  })

  it('shows an empty state when there are no communication records', async () => {
    mockGraph({ nodes: [], edges: [], truncated: false, total_participants: 0 })
    renderPage()
    expect(
      await screen.findByText('No communication records'),
    ).toBeInTheDocument()
    // No canvas when there's nothing to plot.
    expect(document.querySelector('canvas')).toBeNull()
  })
})

/**
 * §5.1. A node in the graph is a participant; the panel for one offers the
 * pivot — "what else in this case touches this person" — beside search, which
 * answers the different question of the full hit list. Tested directly because
 * selecting a node is a canvas click this environment cannot make.
 */
describe('ParticipantDetail', () => {
  const alice: CommNode = {
    id: '+15551234567',
    label: 'Alice',
    kind: 'contact',
    weight: 42,
  }

  function renderPanel(node: CommNode) {
    const pivoted: string[] = []
    const searched: string[] = []
    render(
      <ParticipantDetail
        caseId="c1"
        node={node}
        onClose={() => {}}
        onPivot={(v) => pivoted.push(v)}
        onSearch={(v) => searched.push(v)}
      />,
    )
    return { pivoted, searched }
  }

  it('pivots on the address the graph was built from, not the display label', async () => {
    const { pivoted, searched } = renderPanel(alice)
    // The label is what a reader sees; the id is the identifier the rest of
    // the case carries, and it is what the pivot must ask about.
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('+15551234567')).toBeInTheDocument()

    await userEvent.click(
      screen.getByRole('button', { name: /Pivot on this participant/ }),
    )
    expect(pivoted).toEqual(['+15551234567'])
    expect(searched).toEqual([])
  })

  it('keeps search beside the pivot, on the label', async () => {
    const { pivoted, searched } = renderPanel(alice)
    await userEvent.click(
      screen.getByRole('button', { name: /Search records for this participant/ }),
    )
    expect(searched).toEqual(['Alice'])
    expect(pivoted).toEqual([])
  })

  it('offers neither for the device owner, who is not a counterparty', () => {
    renderPanel({ id: SELF, label: 'This device', kind: 'self', weight: 9 })
    expect(screen.queryByRole('button', { name: /Pivot on/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Search records/ })).toBeNull()
    // The metric still shows: the owner's own volume is a fact about the case.
    expect(screen.getByText('9')).toBeInTheDocument()
  })
})
