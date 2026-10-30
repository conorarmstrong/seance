import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'
import { ToastProvider } from '../toast/ToastProvider'
import { server } from '../../test/server'
import { NavigatorPanel } from './NavigatorPanel'

function mockBoth() {
  server.use(
    http.get('/api/v1/cases/case-1/artifacts/root/children', () =>
      HttpResponse.json({ items: [
        {
          id: 'src-1',
          parent_id: null,
          artifact_type: 'RawEvidence',
          name: 'disk.img',
          has_children: false,
        },
      ] }),
    ),
    http.get('/api/v1/cases/case-1/record_types', () =>
      HttpResponse.json({ record_types: [{ type: 'WhatsApp', count: 5 }] }),
    ),
    http.get('/api/v1/cases/case-1/stats/media_counts', () =>
      HttpResponse.json({
        pictures: 0,
        videos: 0,
        documents: 0,
        geolocation: 0,
      }),
    ),
    http.get('/api/v1/modules', () =>
      HttpResponse.json([
        {
          id: 'plugin.analysis.reindex',
          version: '1',
          subscribes_to: ['ParsedRecord'],
          execution_mode: 'manual',
        },
      ]),
    ),
  )
}

function renderPanel() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter>
          <NavigatorPanel caseId="case-1" />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('NavigatorPanel', () => {
  beforeEach(() => localStorage.clear())

  it('defaults to the physical evidence tree and switches to the logical lens', async () => {
    mockBoth()
    renderPanel()
    expect(await screen.findByText('disk.img')).toBeInTheDocument()
    expect(screen.queryByText('Chats')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: /Logical/ }))
    expect(await screen.findByText('Chats')).toBeInTheDocument()
    expect(screen.queryByText('disk.img')).not.toBeInTheDocument()
    expect(localStorage.getItem('seance.navigator.lens')).toBe('logical')
  })

  it('restores the persisted lens on mount', async () => {
    localStorage.setItem('seance.navigator.lens', 'logical')
    mockBoth()
    renderPanel()
    expect(await screen.findByText('Chats')).toBeInTheDocument()
    expect(screen.queryByText('disk.img')).not.toBeInTheDocument()
  })

  it('right-clicks a logical type and runs an analysis module across it', async () => {
    mockBoth()
    let analyzeBody: unknown = null
    server.use(
      http.post('/api/v1/cases/case-1/analyze', async ({ request }) => {
        analyzeBody = await request.json()
        return HttpResponse.json({
          job_ids: ['j1'],
          targets: 5,
          truncated: false,
        })
      }),
    )
    localStorage.setItem('seance.navigator.lens', 'logical')
    renderPanel()
    await userEvent.click(await screen.findByRole('button', { name: 'Expand' }))
    const whatsapp = await screen.findByRole('link', { name: 'WhatsApp' })
    fireEvent.contextMenu(whatsapp.closest('.tree-row')!)
    expect(await screen.findByRole('menu')).toBeInTheDocument()

    await userEvent.click(
      screen.getByRole('menuitem', { name: /Run plugin\.analysis\.reindex/ }),
    )
    await waitFor(() =>
      expect(analyzeBody).toEqual({
        module_id: 'plugin.analysis.reindex',
        record_type: 'WhatsApp',
      }),
    )
  })

  it('invalidates the case the analysis was queued against, not the one on screen (B5-012)', async () => {
    // The panel outlives a `:caseId` change and `onSuccess` runs in the latest
    // render's closure. Reading `caseId` there refreshed case B's job list
    // while case A — the one that received the run — kept a stale one, and the
    // toast confirmed the run over B's chrome.
    mockBoth()
    let release: (() => void) | null = null
    const inFlight = new Promise<void>((resolve) => {
      release = resolve
    })
    server.use(
      http.get('/api/v1/cases/case-2/record_types', () =>
        HttpResponse.json({ record_types: [{ type: 'WhatsApp', count: 99 }] }),
      ),
      http.get('/api/v1/cases/case-2/stats/media_counts', () =>
        HttpResponse.json({
          pictures: 0,
          videos: 0,
          documents: 0,
          geolocation: 0,
        }),
      ),
      http.post('/api/v1/cases/case-1/analyze', async () => {
        await inFlight
        return HttpResponse.json({
          job_ids: ['j1'],
          targets: 5,
          truncated: false,
        })
      }),
    )
    localStorage.setItem('seance.navigator.lens', 'logical')

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const invalidated: unknown[][] = []
    const realInvalidate = queryClient.invalidateQueries.bind(queryClient)
    queryClient.invalidateQueries = ((filters?: { queryKey?: unknown[] }) => {
      if (filters?.queryKey) invalidated.push(filters.queryKey)
      return realInvalidate(filters as never)
    }) as typeof queryClient.invalidateQueries

    const ui = (caseId: string) => (
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <MemoryRouter>
            <NavigatorPanel caseId={caseId} />
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>
    )
    const { rerender } = render(ui('case-1'))

    await userEvent.click(await screen.findByRole('button', { name: 'Expand' }))
    const whatsapp = await screen.findByRole('link', { name: 'WhatsApp' })
    fireEvent.contextMenu(whatsapp.closest('.tree-row')!)
    await screen.findByRole('menu')
    await userEvent.click(
      screen.getByRole('menuitem', { name: /Run plugin\.analysis\.reindex/ }),
    )

    // Switch cases while the request is still in flight, then let it land.
    rerender(ui('case-2'))
    release!()

    await waitFor(() =>
      expect(invalidated.some((key) => key[0] === 'jobs')).toBe(true),
    )
    const jobKeys = invalidated.filter((key) => key[0] === 'jobs')
    expect(jobKeys).toContainEqual(['jobs', 'case-1'])
    expect(jobKeys).not.toContainEqual(['jobs', 'case-2'])
    // The toast names the case the run was started from rather than confirming
    // it over the case now on screen.
    expect(
      await screen.findByText(/in the case it was started from/),
    ).toBeInTheDocument()
  })

  it('closes the open type menu when the case changes', async () => {
    // The sidebar stays mounted when `:caseId` changes. The menu names one
    // case's record type and prints that case's count in its header, and its
    // "Run …" items queue that analysis against whatever case is now on
    // screen. Left open it reads as a fact about evidence no longer displayed.
    mockBoth()
    server.use(
      http.get('/api/v1/cases/case-2/record_types', () =>
        HttpResponse.json({ record_types: [{ type: 'WhatsApp', count: 99 }] }),
      ),
      http.get('/api/v1/cases/case-2/stats/media_counts', () =>
        HttpResponse.json({
          pictures: 0,
          videos: 0,
          documents: 0,
          geolocation: 0,
        }),
      ),
    )
    localStorage.setItem('seance.navigator.lens', 'logical')

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const ui = (caseId: string) => (
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <MemoryRouter>
            <NavigatorPanel caseId={caseId} />
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>
    )
    const { rerender } = render(ui('case-1'))

    await userEvent.click(await screen.findByRole('button', { name: 'Expand' }))
    const whatsapp = await screen.findByRole('link', { name: 'WhatsApp' })
    fireEvent.contextMenu(whatsapp.closest('.tree-row')!)
    expect(await screen.findByRole('menu')).toBeInTheDocument()
    expect(screen.getByText(/5 records/)).toBeInTheDocument()

    rerender(ui('case-2'))

    // Gone in the first frame the new case is shown, not one frame later.
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(screen.queryByText(/5 records/)).not.toBeInTheDocument()
  })
})
