import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import type { FileBrowserResponse } from '../../api/types'
import { server } from '../../test/server'
import { ToastProvider } from '../toast/ToastProvider'
import { IngestButton } from './IngestButton'

const BROWSE: FileBrowserResponse = {
  current_path: '/evidence',
  parent_path: '/',
  entries: [
    {
      name: 'disk.dd',
      path: '/evidence/disk.dd',
      is_dir: false,
      size: 4096,
      modified: null,
    },
  ],
}

function renderButton(caseId: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const ui = (id: string) => (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <IngestButton caseId={id} />
      </ToastProvider>
    </QueryClientProvider>
  )
  const view = render(ui(caseId))
  return { rerenderAs: (next: string) => view.rerender(ui(next)) }
}

describe('IngestButton', () => {
  it('closes the ingest dialog when the case changes, rather than attaching the selection to the new case', async () => {
    // The button lives in the sidebar, outside the routed content, so it stays
    // mounted through a `:caseId` change — browser back/forward does exactly
    // that. Left open, the dialog still holds the file selection, evidence type
    // and profile chosen for the previous case, while "Ingest" posts to the
    // LIVE case id: an exhibit attached to a case the examiner was not looking
    // at when they picked it.
    const ingested: string[] = []
    server.use(
      http.get('/api/v1/filesystem/browse', () => HttpResponse.json(BROWSE)),
      http.get('/api/v1/cases/:caseId/profiles', () => HttpResponse.json([])),
      // The modal states which profile governs the ingest, so it reads the
      // case's active profile and the build's module registry.
      http.get('/api/v1/cases/:caseId/profiles/active', () =>
        HttpResponse.json(null),
      ),
      http.get('/api/v1/modules', () => HttpResponse.json([])),
      http.get('/api/v1/evidence-roots', () =>
        HttpResponse.json({ restricted: true, roots: ['/evidence'] }),
      ),
      http.post('/api/v1/cases/:caseId/ingest', ({ params }) => {
        ingested.push(params.caseId as string)
        return HttpResponse.json({ artifact_id: 'a1', status: 'hashing' })
      }),
    )

    const { rerenderAs } = renderButton('case-1')
    await userEvent.click(
      screen.getByRole('button', { name: 'Ingest Evidence' }),
    )
    await userEvent.click(await screen.findByText('disk.dd'))
    expect(
      screen.getByRole('dialog', { name: 'Ingest Evidence' }),
    ).toBeInTheDocument()

    rerenderAs('case-2')

    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryByText('disk.dd')).toBeNull()
    expect(ingested).toEqual([])
  })
})
