import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import { WorkbenchPage } from './WorkbenchPage'

const CASE = 'case-1'

// The workbench is a content canvas driven by URL params; the navigator lives
// in the sidebar (tested in NavigatorPanel.test). These cover the param routing.
function mockContent() {
  server.use(
    http.get(`/api/v1/cases/${CASE}/records`, () =>
      HttpResponse.json({
        records: [],
        total: 0,
        page: 1,
        page_size: 50,
        type: 'WhatsApp',
      }),
    ),
    // Endpoints the embedded ArtifactPage needs for a plain (non-previewable) file.
    http.get(`/api/v1/cases/${CASE}/artifacts/file-1`, () =>
      HttpResponse.json({
        id: 'file-1',
        case_id: CASE,
        parent_id: 'src-1',
        artifact_type: 'FileContent',
        metadata: { name: 'report.pdf', size: 2048, source_path: '/report.pdf' },
      }),
    ),
    http.get(`/api/v1/cases/${CASE}/artifacts/file-1/ancestors`, () =>
      HttpResponse.json([
        { id: 'file-1', name: 'report.pdf', artifact_type: 'FileContent' },
      ]),
    ),
    http.get(`/api/v1/cases/${CASE}/artifacts/file-1/hash_check`, () =>
      HttpResponse.json([]),
    ),
    http.get(`/api/v1/cases/${CASE}/artifacts/file-1/integrity`, () =>
      HttpResponse.json([]),
    ),
    http.get(`/api/v1/cases/${CASE}/artifacts/file-1/children`, () =>
      HttpResponse.json([]),
    ),
    http.get(`/api/v1/cases/${CASE}/bookmarks/ids`, () => HttpResponse.json([])),
    http.get(`/api/v1/cases/${CASE}/artifacts/file-1/thumbnail`, () =>
      HttpResponse.json(
        { error: { code: 'RESOURCE_NOT_FOUND', message: 'not raster' } },
        { status: 404 },
      ),
    ),
  )
}

function renderWb(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route
              path="/cases/:caseId/workbench"
              element={<WorkbenchPage />}
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('WorkbenchPage', () => {
  it('shows a placeholder when nothing is selected', () => {
    mockContent()
    renderWb(`/cases/${CASE}/workbench`)
    expect(screen.getByText('Nothing selected')).toBeInTheDocument()
  })

  it('renders the artifact viewer + inspector for ?artifact=', async () => {
    mockContent()
    renderWb(`/cases/${CASE}/workbench?artifact=file-1`)
    expect(
      await screen.findByRole('heading', { name: 'report.pdf' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('complementary', { name: 'Properties' }),
    ).toBeInTheDocument()
  })

  it('renders the records table for ?type=', async () => {
    mockContent()
    renderWb(`/cases/${CASE}/workbench?type=WhatsApp`)
    expect(
      await screen.findByRole('heading', { name: 'WhatsApp' }),
    ).toBeInTheDocument()
  })
})
