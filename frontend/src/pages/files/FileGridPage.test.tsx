import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import { FrameSpy } from '../../test/frames'
import { DownloadIncompleteError, downloadFile } from '../../lib/download'
import { FileGridPage } from './FileGridPage'
import type { FileRow, FilesResponse } from './types'

// Only the function is replaced; `DownloadIncompleteError` stays the real
// class so the page's `instanceof` branch is reachable from a test.
vi.mock('../../lib/download', async () => {
  const actual =
    await vi.importActual<typeof import('../../lib/download')>(
      '../../lib/download',
    )
  return { ...actual, downloadFile: vi.fn() }
})

function row(
  over: Partial<FileRow> & Pick<FileRow, 'id' | 'name' | 'path'>,
): FileRow {
  return {
    parent_id: 's1',
    extension: null,
    size: null,
    created: null,
    modified: null,
    accessed: null,
    is_directory: false,
    is_deleted: false,
    known_status: null,
    ...over,
  }
}

/** The <tr> carrying a given file name in the grid. */
function fileRow(name: string): HTMLElement {
  return screen
    .getByText(name, { selector: '.fg-name' })
    .closest('tr') as HTMLElement
}

const rootRows = [
  row({ id: 'd1', name: 'Windows', path: '/Windows', is_directory: true }),
  row({
    id: 'f1',
    name: 'report.docx',
    path: '/report.docx',
    extension: 'docx',
    size: 2048,
    created: '2024-01-01T10:00:00Z',
    modified: '2024-02-01T11:30:00Z',
    accessed: '2024-03-01T12:00:00Z',
    known_status: 'notable',
    metadata: {
      md5: 'aabbccddeeff00112233445566778899',
      sha256:
        '1111111111111111111111111111111111111111111111111111111111111111',
    },
  }),
  row({
    id: 'f2',
    name: 'secret.pdf',
    path: '/secret.pdf',
    extension: 'pdf',
    size: 4096,
    is_deleted: true,
  }),
  row({
    id: 'f3',
    name: 'carved_0001.jpg',
    path: '/carved_0001.jpg',
    extension: 'jpg',
    size: 1024,
    known_status: 'known',
  }),
]

const windowsRows = [
  row({
    id: 'd3',
    parent_id: 'd1',
    name: 'System32',
    path: '/Windows/System32',
    is_directory: true,
  }),
  row({
    id: 'f4',
    parent_id: 'd1',
    name: 'notepad.exe',
    path: '/Windows/notepad.exe',
    extension: 'exe',
    size: 191488,
  }),
]

const system32Rows = [
  row({
    id: 'f5',
    parent_id: 'd3',
    name: 'kernel32.dll',
    path: '/Windows/System32/kernel32.dll',
    extension: 'dll',
    size: 720896,
  }),
]

function wrap(items: FileRow[], page: number): FilesResponse {
  return {
    items,
    total_count: items.length,
    page,
    page_size: 100,
    total_pages: 3,
    has_next: true,
    has_previous: page > 1,
  }
}

function respond(params: URLSearchParams): FilesResponse {
  const parent = params.get('parent_id')
  const path = params.get('path')
  let items: FileRow[]
  // path-based navigation: '' is the filesystem root, '/Windows' its children,
  // '/Windows/System32' one level deeper.
  if (path === '') items = rootRows
  else if (path === '/Windows') items = windowsRows
  else if (path === '/Windows/System32') items = system32Rows
  else if (path != null) items = []
  else if (parent === 'd1') items = windowsRows
  else if (parent === 'd3') items = system32Rows
  else if (parent == null)
    items = [...rootRows, ...windowsRows, ...system32Rows]
  else items = []
  if (params.get('dirs') === 'only') {
    items = items.filter((r) => r.is_directory)
  }
  return wrap(items, Number(params.get('page') ?? '1'))
}

let fileRequests: URLSearchParams[] = []
let hexCalls = 0
const createObjectURL = vi.fn((_obj: Blob | MediaSource) => 'blob:mock')
const revokeObjectURL = vi.fn()

// Grid requests only (the directory tree fetches with dirs=only).
function gridRequests() {
  return fileRequests.filter((p) => p.get('dirs') !== 'only')
}
function lastGrid() {
  const reqs = gridRequests()
  return reqs[reqs.length - 1]
}

function mockApi(filesResponse?: FilesResponse) {
  server.use(
    http.get('/api/v1/cases/c1/sources/s1/files', ({ request }) => {
      const params = new URL(request.url).searchParams
      fileRequests.push(params)
      return HttpResponse.json(filesResponse ?? respond(params))
    }),
    http.get('/api/v1/cases/c1/artifacts/:artifactId', ({ params }) =>
      HttpResponse.json({
        id: params.artifactId,
        case_id: 'c1',
        parent_id: 'p1',
        artifact_type: 'FileEntry',
        metadata: { md5_hash: 'd41d8cd98f' },
      }),
    ),
    http.get('/api/v1/cases/c1/artifacts/:artifactId/hex', () => {
      hexCalls += 1
      return HttpResponse.json({
        offset: 0,
        limit: 512,
        total_size: 4096,
        hex: '4d 5a 90 00',
        ascii: 'MZ..',
      })
    }),
    http.get('/api/v1/cases/c1/artifacts/:artifactId/thumbnail', () =>
      HttpResponse.json(
        { error: { code: 'NOT_FOUND', message: 'not an image' } },
        { status: 404 },
      ),
    ),
  )
}

function renderPage(url = '/cases/c1/files/s1') {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={[url]}>
          <Routes>
            <Route
              path="/cases/:caseId/files/:sourceId"
              element={<FileGridPage />}
            />
            <Route
              path="/cases/:caseId/artifacts/:artifactId"
              element={<div>artifact-page-stub</div>}
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

/** Render at `from` with a button that navigates to `to`. A case or source
 * switch keeps the same route component mounted, which is the window the
 * stale-data gating has to cover. */
function renderWithSwitch(
  from: string,
  to: string,
  label = 'go',
  frames?: string[],
) {
  function Switcher() {
    const navigate = useNavigate()
    return <button onClick={() => navigate(to)}>{label}</button>
  }
  // Puts the current path into the captured text, so an assertion can tell a
  // frame painted before the case changed from one painted after it. Both
  // cases serve identical rows in these fixtures, so nothing else can.
  function PathMarker() {
    const { pathname } = useLocation()
    return <span data-testid="frame-path">{`[path:${pathname}]`}</span>
  }
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={[from]}>
          <Switcher />
          <PathMarker />
          {frames && (
            <FrameSpy
              capture={() => document.body.textContent ?? ''}
              frames={frames}
            />
          )}
          <Routes>
            <Route
              path="/cases/:caseId/files/:sourceId"
              element={<FileGridPage />}
            />
            <Route
              path="/cases/:caseId/artifacts/:artifactId"
              element={<div>artifact-page-stub</div>}
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

beforeAll(() => {
  URL.createObjectURL = createObjectURL
  URL.revokeObjectURL = revokeObjectURL
})

beforeEach(() => {
  fileRequests = []
  hexCalls = 0
  createObjectURL.mockClear()
  revokeObjectURL.mockClear()
})

describe('FileGridPage folder mode', () => {
  it('loads root folder contents plus a dirs-only tree', async () => {
    mockApi()
    renderPage()
    expect(screen.getByLabelText(/Loading files/)).toBeInTheDocument()

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.getByText('2.0 KiB')).toBeInTheDocument()
    expect(screen.getByText('2024-02-01 11:30:00 UTC')).toBeInTheDocument()

    // Grid request: the filesystem root level, both dirs and files.
    const grid = gridRequests()[0]
    expect(grid.get('path')).toBe('')
    expect(grid.get('parent_id')).toBeNull()
    expect(grid.get('dirs')).toBeNull()
    expect(grid.get('sort')).toBe('name')
    expect(grid.get('order')).toBe('asc')
    expect(grid.get('page')).toBe('1')
    expect(grid.get('page_size')).toBe('100')

    // Tree request: same root level, directories only.
    await waitFor(() =>
      expect(
        fileRequests.some(
          (p) => p.get('dirs') === 'only' && p.get('path') === '',
        ),
      ).toBe(true),
    )
    const tree = screen.getByRole('navigation', { name: 'Directory tree' })
    expect(within(tree).getByText('Windows')).toBeInTheDocument()

    // Status badges: deleted, carved-by-name-prefix, OK.
    expect(screen.getByText('secret.pdf')).toHaveClass('fg-name-deleted')
    expect(screen.getByText('Deleted')).toBeInTheDocument()
    expect(screen.getByText('Carved')).toBeInTheDocument()
    expect(screen.getAllByText('OK').length).toBeGreaterThanOrEqual(1)

    // No Path column in folder mode.
    expect(
      screen.queryByRole('columnheader', { name: 'Path' }),
    ).not.toBeInTheDocument()
  })

  it('descends on double-click and climbs via breadcrumb', async () => {
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.dblClick(
      screen.getByText('Windows', { selector: '.fg-name' }),
    )
    expect(await screen.findByText('notepad.exe')).toBeInTheDocument()
    expect(lastGrid().get('path')).toBe('/Windows')

    const crumbs = screen.getByRole('navigation', { name: 'Current folder' })
    expect(
      within(crumbs).getByRole('button', { name: 'Windows' }),
    ).toBeInTheDocument()

    await userEvent.click(within(crumbs).getByRole('button', { name: 'Root' }))
    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(lastGrid().get('path')).toBe('')
  })

  it('does not show the previous folder rows under the new breadcrumb while loading (BUG-111)', async () => {
    mockApi()
    let releaseWindows: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      releaseWindows = resolve
    })
    // Hold the /Windows grid response so it is still in flight right after the
    // descend — the window where keepPreviousData would surface the root rows.
    server.use(
      http.get('/api/v1/cases/c1/sources/s1/files', async ({ request }) => {
        const params = new URL(request.url).searchParams
        fileRequests.push(params)
        if (
          params.get('path') === '/Windows' &&
          params.get('dirs') !== 'only'
        ) {
          await gate
        }
        return HttpResponse.json(respond(params))
      }),
    )
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.dblClick(
      screen.getByText('Windows', { selector: '.fg-name' }),
    )

    // The breadcrumb reflects the new folder immediately (derived from the URL).
    const crumbs = screen.getByRole('navigation', { name: 'Current folder' })
    await waitFor(() =>
      expect(
        within(crumbs).getByRole('button', { name: 'Windows' }),
      ).toBeInTheDocument(),
    )
    // The previous folder's rows must not render under the new breadcrumb — a
    // skeleton is shown instead, so no wrong file can be opened or exported.
    expect(screen.queryByText('report.docx')).not.toBeInTheDocument()
    expect(screen.getByLabelText(/Loading files/)).toBeInTheDocument()

    // Once the new folder's rows arrive they replace the skeleton.
    releaseWindows()
    expect(await screen.findByText('notepad.exe')).toBeInTheDocument()
  })

  it('navigates folders from the directory tree', async () => {
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    const tree = screen.getByRole('navigation', { name: 'Directory tree' })
    await userEvent.click(
      within(tree).getByRole('button', { name: 'Expand Windows' }),
    )
    await userEvent.click(await within(tree).findByText('System32'))

    expect(await screen.findByText('kernel32.dll')).toBeInTheDocument()
    expect(lastGrid().get('path')).toBe('/Windows/System32')

    // Tree select carries the full path: both crumb segments clickable.
    const crumbs = screen.getByRole('navigation', { name: 'Current folder' })
    expect(
      within(crumbs).getByRole('button', { name: 'Windows' }),
    ).toBeInTheDocument()
    expect(
      within(crumbs).getByRole('button', { name: 'System32' }),
    ).toBeInTheDocument()
  })

  it('builds a fully clickable breadcrumb from a cold ?dir path load', async () => {
    mockApi()
    renderPage('/cases/c1/files/s1?dir=/Windows/System32')

    expect(await screen.findByText('kernel32.dll')).toBeInTheDocument()
    expect(gridRequests()[0].get('path')).toBe('/Windows/System32')

    const crumbs = screen.getByRole('navigation', { name: 'Current folder' })
    // The full path is in the URL, so every ancestor segment is clickable.
    expect(
      within(crumbs).getByRole('button', { name: 'Windows' }),
    ).toBeInTheDocument()
    expect(
      within(crumbs).getByRole('button', { name: 'System32' }),
    ).toBeInTheDocument()
  })

  it('collapses a deep breadcrumb instead of wrapping it over three lines', async () => {
    mockApi()
    const deep =
      '/Users/john/AppData/Local/Packages/Microsoft.WindowsStore/LocalState'
    renderPage(`/cases/c1/files/s1?dir=${deep}`)
    await waitFor(() => expect(lastGrid().get('path')).toBe(deep))

    const crumbs = screen.getByRole('navigation', { name: 'Current folder' })
    // Root, the first segment, an overflow control, and the last three. A
    // Windows path this deep is routine, and rendering every segment pushed
    // the grid and its count bar down the page.
    expect(within(crumbs).getByRole('button', { name: 'Users' })).toBeInTheDocument()
    expect(within(crumbs).getByRole('button', { name: 'LocalState' })).toBeInTheDocument()
    expect(within(crumbs).queryByRole('button', { name: 'john' })).toBeNull()
    expect(within(crumbs).queryByRole('button', { name: 'AppData' })).toBeNull()
    expect(within(crumbs).queryByRole('button', { name: 'Local' })).toBeNull()

    // The whole path is still quotable off this element, which matters when
    // the screen is going into a statement.
    expect(crumbs).toHaveAttribute('title', deep)

    // The hidden segments are not lost: the overflow control lists them, and
    // each one still navigates.
    await userEvent.click(
      within(crumbs).getByRole('button', { name: /3 hidden folders/ }),
    )
    await userEvent.click(screen.getByRole('menuitem', { name: 'AppData' }))
    await waitFor(() =>
      expect(lastGrid().get('path')).toBe('/Users/john/AppData'),
    )
    // Choosing an ancestor shortens the path below the collapse threshold, so
    // the overflow control that opened the menu is gone by the time focus is
    // handed back. A keyboard examiner must land on the folder they chose, not
    // on <body> — which would restart the next Tab at the top of the document.
    await waitFor(() =>
      expect(
        within(crumbs).getByRole('button', { name: 'AppData' }),
      ).toHaveFocus(),
    )
    expect(document.body).not.toHaveFocus()
  })

  it('supports keyboard navigation: arrows move, Enter descends or opens', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))

    await userEvent.keyboard('{ArrowDown}')
    expect(fileRow('secret.pdf')).toHaveClass('selected')

    await userEvent.keyboard('{ArrowUp}{ArrowUp}')
    expect(fileRow('Windows')).toHaveClass('selected')

    // Enter on a directory descends.
    await userEvent.keyboard('{Enter}')
    expect(await screen.findByText('notepad.exe')).toBeInTheDocument()
    expect(lastGrid().get('path')).toBe('/Windows')

    // Enter on a file opens the artifact page.
    await userEvent.click(screen.getByText('notepad.exe'))
    await userEvent.keyboard('{Enter}')
    expect(await screen.findByText('artifact-page-stub')).toBeInTheDocument()
  })

  it('costs one tab stop for the whole table and moves DOM focus with the arrows', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))

    // Roving tabindex: the row the examiner is on is the table's only tab
    // stop, so Tab-ing past a 100-row page is one press, not a hundred. Focus
    // being on the row itself — rather than on a wrapper that merely repaints
    // a highlight — is also what lets a screen reader read out the row the
    // arrows arrived at.
    expect(fileRow('report.docx')).toHaveFocus()
    expect(fileRow('report.docx')).toHaveAttribute('tabindex', '0')
    expect(fileRow('secret.pdf')).toHaveAttribute('tabindex', '-1')
    expect(fileRow('Windows')).toHaveAttribute('tabindex', '-1')

    await userEvent.keyboard('{ArrowDown}')
    expect(fileRow('secret.pdf')).toHaveFocus()
    expect(fileRow('secret.pdf')).toHaveAttribute('tabindex', '0')
    expect(fileRow('report.docx')).toHaveAttribute('tabindex', '-1')

    await userEvent.keyboard('{Home}')
    expect(fileRow('Windows')).toHaveClass('selected')
    await userEvent.keyboard('{End}')
    expect(fileRow('carved_0001.jpg')).toHaveClass('selected')
  })

  it('scrolls the row the arrows move to into view', async () => {
    // With page_size up to 500 the selection routinely leaves the viewport;
    // an examiner who cannot see the highlight loses count and opens a row
    // they never read. jsdom has no layout, so the assertion is that the
    // request is made.
    const scrollIntoView = vi.fn()
    ;(HTMLElement.prototype as unknown as Record<string, unknown>).scrollIntoView =
      scrollIntoView
    try {
      mockApi()
      renderPage()
      await userEvent.click(await screen.findByText('report.docx'))
      scrollIntoView.mockClear()

      await userEvent.keyboard('{ArrowDown}')

      expect(scrollIntoView).toHaveBeenCalledWith({ block: 'nearest' })
    } finally {
      delete (HTMLElement.prototype as unknown as Record<string, unknown>)
        .scrollIntoView
    }
  })

  it('does not let the focus a click causes collapse a multi-row selection', async () => {
    mockApi()
    renderPage()
    // One `setup()` so the held Shift is still down when the click lands.
    const user = userEvent.setup()
    await user.click(await screen.findByText('report.docx'))
    await user.keyboard('{Shift>}')
    await user.click(screen.getByText('secret.pdf'))
    await user.keyboard('{/Shift}')

    expect(fileRow('report.docx')).toHaveClass('selected')
    expect(fileRow('secret.pdf')).toHaveClass('selected')
    expect(screen.getByText('2 selected')).toBeInTheDocument()
  })

  it('right-aligns the size column so magnitudes can be scanned', async () => {
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    // Left-aligned proportional digits make "9.8 MiB" look wider than
    // "1.2 GiB", so the one multi-gigabyte outlier in a hundred rows has to be
    // read rather than seen. The shared .num rule right-aligns and makes the
    // digits tabular; the class is what carries it.
    const sizeCell = within(fileRow('report.docx')).getByText('2.0 KiB')
    expect(sizeCell).toHaveClass('num')
    const header = screen
      .getByRole('button', { name: /^Size/ })
      .closest('th') as HTMLElement
    expect(header).toHaveClass('num')
  })

  it('shows an empty-folder state', async () => {
    mockApi({
      items: [],
      total_count: 0,
      page: 1,
      page_size: 100,
      total_pages: 0,
      has_next: false,
      has_previous: false,
    })
    renderPage()
    expect(await screen.findByText('Empty folder')).toBeInTheDocument()
  })
})

describe('FileGridPage flat mode', () => {
  it('toggles to flat mode: no parent_id, Path column shown', async () => {
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.click(screen.getByRole('button', { name: 'All files' }))
    expect(await screen.findByText('kernel32.dll')).toBeInTheDocument()

    const last = lastGrid()
    expect(last.has('parent_id')).toBe(false)
    expect(
      screen.getByRole('columnheader', { name: 'Path' }),
    ).toBeInTheDocument()
    expect(
      screen.getByText('/Windows/System32/kernel32.dll'),
    ).toBeInTheDocument()
  })

  it('initialises from URL params including view=flat', async () => {
    mockApi()
    renderPage(
      '/cases/c1/files/s1?view=flat&page=2&extension=pdf&sort_by=size&sort_order=desc',
    )
    await screen.findByText('report.docx')
    const first = gridRequests()[0]
    expect(first.has('parent_id')).toBe(false)
    expect(first.get('page')).toBe('2')
    expect(first.get('extension')).toBe('pdf')
    expect(first.get('sort')).toBe('size')
    expect(first.get('order')).toBe('desc')
  })

  it('coerces a malformed page/page_size in the URL to safe defaults', async () => {
    mockApi()
    // A hand-edited/corrupt URL must never send NaN to the API.
    renderPage('/cases/c1/files/s1?page=abc&page_size=xyz')
    await screen.findByText('report.docx')
    const first = gridRequests()[0]
    expect(first.get('page')).toBe('1')
    expect(first.get('page_size')).toBe('100')
  })
})

describe('FileGridPage tree mode', () => {
  it('renders an expandable path-based tree, lazily loading children', async () => {
    mockApi()
    renderPage('/cases/c1/files/s1?view=tree')

    // Root level shows the filesystem's own top-level entries (dirs + files).
    expect(await screen.findByText('Windows')).toBeInTheDocument()
    expect(screen.getByText('report.docx')).toBeInTheDocument()
    // The root level is fetched by empty path, never by parent_id.
    expect(gridRequests()[0].get('path')).toBe('')
    expect(gridRequests()[0].get('parent_id')).toBeNull()

    // notepad.exe lives under /Windows and is not loaded until expansion.
    expect(screen.queryByText('notepad.exe')).not.toBeInTheDocument()
    await userEvent.click(screen.getByText('Windows'))
    expect(await screen.findByText('notepad.exe')).toBeInTheDocument()
    // Children are fetched by the directory's path, not its id.
    expect(gridRequests().some((p) => p.get('path') === '/Windows')).toBe(true)

    // Clicking a file selects it (opening the detail pane).
    await userEvent.click(screen.getByText('report.docx'))
    expect(screen.getByText('report.docx').closest('.ft-row')).toHaveClass(
      'selected',
    )
    expect(screen.getAllByText('/report.docx').length).toBeGreaterThanOrEqual(1)
  })
})

describe('FileGridPage filters and sorting', () => {
  it('sends server-side filter params, keeping the current folder', async () => {
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.type(screen.getByLabelText('Name filter'), 'rep')
    await waitFor(() =>
      expect(gridRequests().some((p) => p.get('name') === 'rep')).toBe(true),
    )
    // Debounce coalesces the three keystrokes into one request.
    expect(gridRequests().filter((p) => p.has('name'))).toHaveLength(1)
    expect(lastGrid().get('path')).toBe('')

    await userEvent.type(screen.getByLabelText('Extension filter'), 'exe')
    await waitFor(() =>
      expect(gridRequests().some((p) => p.get('extension') === 'exe')).toBe(
        true,
      ),
    )

    await userEvent.click(screen.getByLabelText('Deleted only'))
    await waitFor(() =>
      expect(
        gridRequests().some((p) => p.get('deleted_only') === 'true'),
      ).toBe(true),
    )

    await userEvent.selectOptions(screen.getByLabelText('Page size'), '250')
    await waitFor(() =>
      expect(gridRequests().some((p) => p.get('page_size') === '250')).toBe(
        true,
      ),
    )
  })

  it('sorts via server params with asc/desc toggle and aria-sort', async () => {
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    const sizeButton = () => screen.getByRole('button', { name: /^Size/ })
    await waitFor(() => expect(sizeButton()).toBeEnabled())
    await userEvent.click(sizeButton())
    await waitFor(() => {
      expect(lastGrid().get('sort')).toBe('size')
      expect(lastGrid().get('order')).toBe('asc')
    })

    await waitFor(() => expect(sizeButton()).toBeEnabled())
    await userEvent.click(sizeButton())
    await waitFor(() => {
      expect(lastGrid().get('sort')).toBe('size')
      expect(lastGrid().get('order')).toBe('desc')
    })
    expect(sizeButton().closest('th')).toHaveAttribute(
      'aria-sort',
      'descending',
    )
  })

  it('paginates with the shared pager', async () => {
    mockApi()
    renderPage()
    await screen.findByText('report.docx')
    expect(screen.getByText(/Page 1 of 3/)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(lastGrid().get('page')).toBe('2'))
  })
})

describe('FileGridPage detail pane and selection', () => {
  it('shows metadata, lazy hex with total size, hides thumbnail on 404', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))

    expect(screen.getByText('report.docx').closest('tr')).toHaveClass(
      'selected',
    )
    expect(
      screen.getAllByText('/report.docx').length,
    ).toBeGreaterThanOrEqual(1)
    expect(await screen.findByText('d41d8cd98f')).toBeInTheDocument()
    expect(hexCalls).toBe(0)

    await userEvent.click(screen.getByRole('tab', { name: 'Hex preview' }))
    expect(await screen.findByText('4d')).toBeInTheDocument()
    expect(screen.getByText('MZ..')).toBeInTheDocument()
    expect(screen.getByText(/4\.0 KiB total/)).toBeInTheDocument()
    expect(hexCalls).toBe(1)

    // Thumbnail endpoint 404s: no image rendered.
    expect(screen.queryByAltText(/Thumbnail/)).not.toBeInTheDocument()
  })

  it('says when a preview was not decoded from the file it sits beside', async () => {
    // `X-Thumbnail-Source: device-cache`: the server built this PNG from the
    // device's own thumbnail cache or a video keyframe, not from this file's
    // bytes. A cached thumbnail can outlive and disagree with the file it was
    // made from, so rendering it as a plain preview shows an examiner a picture
    // of the evidence that is not one.
    mockApi()
    server.use(
      http.get(
        '/api/v1/cases/c1/artifacts/:artifactId/thumbnail',
        () =>
          new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
            headers: {
              'Content-Type': 'image/png',
              'X-Thumbnail-Source': 'device-cache',
            },
          }),
      ),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))

    const note = await screen.findByTestId('fg-derived-thumb')
    expect(note).toHaveTextContent(/not decoded from this file/)
    expect(
      await screen.findByAltText(/not decoded from this file/),
    ).toBeInTheDocument()
  })

  it('shows no provenance caveat on a preview decoded from the file itself', async () => {
    // A caveat on every preview is a caveat an examiner stops reading.
    mockApi()
    server.use(
      http.get(
        '/api/v1/cases/c1/artifacts/:artifactId/thumbnail',
        () =>
          new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
            headers: { 'Content-Type': 'image/png' },
          }),
      ),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))

    expect(
      await screen.findByAltText('Thumbnail of report.docx'),
    ).toBeInTheDocument()
    expect(screen.queryByTestId('fg-derived-thumb')).not.toBeInTheDocument()
  })

  it('says the hex preview was cut by a failed read, not by the file (B4-022)', async () => {
    // The headline used to be derived from the REQUEST
    // (`min(HEX_PREVIEW_BYTES, total_size)`), so a read that returned 8 of 512
    // bytes still announced "First 512 bytes" over 8 bytes of grid.
    mockApi()
    server.use(
      http.get('/api/v1/cases/c1/artifacts/:artifactId/hex', () =>
        HttpResponse.json({
          offset: 0,
          limit: 8,
          requested_bytes: 512,
          total_size: 4096,
          hex: '4d 5a 90 00 00 00 00 00',
          ascii: 'MZ......',
          content_incomplete: true,
          content_incomplete_reason: 'short_read',
        }),
      ),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    await userEvent.click(screen.getByRole('tab', { name: 'Hex preview' }))

    expect(await screen.findByText(/First 8 bytes of/)).toBeInTheDocument()
    expect(screen.queryByText(/First 512 bytes/)).not.toBeInTheDocument()
    const note = screen.getByTestId('fg-hex-short')
    expect(note).toHaveTextContent('short of the 512 bytes requested')
    expect(note).toHaveTextContent(/not where the file ends/)
  })

  it('warns when a file is too fragmented to fully reconstruct', async () => {
    mockApi()
    server.use(
      http.get('/api/v1/cases/c1/artifacts/:artifactId', ({ params }) =>
        HttpResponse.json({
          id: params.artifactId,
          case_id: 'c1',
          parent_id: 'p1',
          artifact_type: 'FileEntry',
          metadata: { md5_hash: 'd41d8cd98f', data_runs_complete: false },
        }),
      ),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    expect(await screen.findByText(/Content incomplete/)).toBeInTheDocument()
  })

  it('shows no fragmentation warning for a complete file', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    await screen.findByText('d41d8cd98f')
    expect(screen.queryByText(/Content incomplete/)).not.toBeInTheDocument()
  })

  it('warns when a file is striped across missing devices', async () => {
    mockApi()
    server.use(
      http.get('/api/v1/cases/c1/artifacts/:artifactId', ({ params }) =>
        HttpResponse.json({
          id: params.artifactId,
          case_id: 'c1',
          parent_id: 'p1',
          artifact_type: 'FileEntry',
          metadata: { md5_hash: 'd41d8cd98f', data_incomplete_multi_device: true },
        }),
      ),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    expect(
      await screen.findByText(/striped across multiple devices/),
    ).toBeInTheDocument()
  })

  it('renders a thumbnail when the endpoint returns an image', async () => {
    mockApi()
    server.use(
      http.get(
        '/api/v1/cases/c1/artifacts/:artifactId/thumbnail',
        () =>
          new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
            headers: { 'Content-Type': 'image/png' },
          }),
      ),
    )
    renderPage()
    await userEvent.click(await screen.findByText('carved_0001.jpg'))
    expect(
      await screen.findByAltText('Thumbnail of carved_0001.jpg'),
    ).toBeInTheDocument()
  })

  it('opens the artifact page via the Open button', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    await screen.findByText('d41d8cd98f')
    await userEvent.click(screen.getByRole('button', { name: 'Open' }))
    expect(await screen.findByText('artifact-page-stub')).toBeInTheDocument()
  })

  it('multi-selects with ctrl-click and exports a client-side CSV', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    fireEvent.click(screen.getByText('secret.pdf').closest('tr')!, {
      ctrlKey: true,
    })

    expect(screen.getByText('2 selected')).toBeInTheDocument()
    await userEvent.click(
      screen.getByRole('button', { name: 'Export CSV of selection' }),
    )

    expect(createObjectURL).toHaveBeenCalled()
    const blob = createObjectURL.mock.calls.at(-1)![0] as Blob
    const text = await blob.text()
    expect(text).toContain('name,path,extension,size')
    expect(text).toContain('report.docx,/report.docx,docx,2048')
    expect(text).toContain('secret.pdf,/secret.pdf,pdf,4096')
  })

  it('shift-click selects a contiguous range', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    fireEvent.click(screen.getByText('carved_0001.jpg').closest('tr')!, {
      shiftKey: true,
    })
    expect(screen.getByText('3 selected')).toBeInTheDocument()
  })

  it('clears the selection when the source changes (no stale export set)', async () => {
    // A ZIP export posts selectedIds; those must not survive a source switch,
    // which keeps the same route component mounted (BUG-069).
    mockApi()
    server.use(
      http.get('/api/v1/cases/c1/sources/s2/files', ({ request }) => {
        const params = new URL(request.url).searchParams
        fileRequests.push(params)
        return HttpResponse.json(respond(params))
      }),
    )

    function SourceSwitcher() {
      const navigate = useNavigate()
      return (
        <button onClick={() => navigate('/cases/c1/files/s2')}>go-s2</button>
      )
    }

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/cases/c1/files/s1']}>
            <SourceSwitcher />
            <Routes>
              <Route
                path="/cases/:caseId/files/:sourceId"
                element={<FileGridPage />}
              />
              <Route
                path="/cases/:caseId/artifacts/:artifactId"
                element={<div>artifact-page-stub</div>}
              />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )

    await screen.findByText('report.docx')
    await userEvent.click(screen.getByText('report.docx'))
    fireEvent.click(screen.getByText('secret.pdf').closest('tr')!, {
      ctrlKey: true,
    })
    expect(screen.getByText('2 selected')).toBeInTheDocument()

    await userEvent.click(screen.getByText('go-s2'))
    await waitFor(() =>
      expect(screen.queryByText('2 selected')).not.toBeInTheDocument(),
    )
    // The new source's grid loads with no rows selected.
    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument()
  })

  it('does not show the previous source rows under the new source (BUG-196)', async () => {
    // Same path, filters and sort in both sources: keepPreviousData hands the
    // previous source's rows over unless the identity tag names the source.
    mockApi()
    let releaseS2: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      releaseS2 = resolve
    })
    const s2Rows = [
      row({
        id: 'g1',
        parent_id: 's2',
        name: 'source2.txt',
        path: '/source2.txt',
        extension: 'txt',
        size: 12,
      }),
    ]
    server.use(
      http.get('/api/v1/cases/c1/sources/s2/files', async ({ request }) => {
        const params = new URL(request.url).searchParams
        fileRequests.push(params)
        // Hold only the grid request; the directory tree may answer at once.
        if (params.get('dirs') === 'only') return HttpResponse.json(wrap([], 1))
        await gate
        return HttpResponse.json(wrap(s2Rows, 1))
      }),
    )

    renderWithSwitch('/cases/c1/files/s1', '/cases/c1/files/s2', 'go-s2')
    await screen.findByText('report.docx')

    await userEvent.click(screen.getByText('go-s2'))
    // Source 1's filesystem must not render under source 2 — opening or
    // exporting from it would attribute evidence to the wrong source.
    await waitFor(() =>
      expect(screen.queryByText('report.docx')).not.toBeInTheDocument(),
    )
    expect(screen.getByLabelText(/Loading files/)).toBeInTheDocument()

    releaseS2()
    expect(await screen.findByText('source2.txt')).toBeInTheDocument()
  })

  it('clears the selection when the case changes (BUG-263)', async () => {
    // Same source id under a different case keeps this page mounted. A carried
    // selection would let "N selected" — and the ZIP export built from it —
    // target case 1's artifact ids through case 2's export endpoint.
    mockApi()
    server.use(
      http.get('/api/v1/cases/c2/sources/s1/files', ({ request }) => {
        const params = new URL(request.url).searchParams
        fileRequests.push(params)
        return HttpResponse.json(respond(params))
      }),
    )

    renderWithSwitch('/cases/c1/files/s1', '/cases/c2/files/s1', 'go-c2')
    await screen.findByText('report.docx')
    await userEvent.click(screen.getByText('report.docx'))
    fireEvent.click(screen.getByText('secret.pdf').closest('tr')!, {
      ctrlKey: true,
    })
    expect(screen.getByText('2 selected')).toBeInTheDocument()

    await userEvent.click(screen.getByText('go-c2'))
    await waitFor(() =>
      expect(screen.queryByText('2 selected')).not.toBeInTheDocument(),
    )
    // The new case's grid loads with no rows selected.
    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument()
  })

  it('paints no frame showing case 1 selection under case 2 (B2-149)', async () => {
    // Clearing the selection from a `useEffect` runs after the commit that
    // already reads case 2, and that commit is painted: "2 selected" and an
    // enabled "Export selected (ZIP + hashes)" sit over case 2's chrome while
    // `selectedIds` still holds case 1's artifact ids, which the export POSTs
    // to /cases/c2/export/files. `userEvent.click` flushes passive effects
    // before returning, so the assertion above cannot see that frame; a
    // layout-effect snapshot can.
    mockApi()
    server.use(
      http.get('/api/v1/cases/c2/sources/s1/files', ({ request }) => {
        const params = new URL(request.url).searchParams
        fileRequests.push(params)
        return HttpResponse.json(respond(params))
      }),
    )

    const frames: string[] = []
    renderWithSwitch('/cases/c1/files/s1', '/cases/c2/files/s1', 'go-c2', frames)
    await screen.findByText('report.docx')
    await userEvent.click(screen.getByText('report.docx'))
    fireEvent.click(screen.getByText('secret.pdf').closest('tr')!, {
      ctrlKey: true,
    })
    expect(screen.getByText('2 selected')).toBeInTheDocument()

    frames.length = 0
    await userEvent.click(screen.getByText('go-c2'))
    await waitFor(() => expect(frames.length).toBeGreaterThan(0))

    // Judge only the frames in which the case has ALREADY changed. The observer
    // records every DOM mutation, including the ones the click itself produces
    // while case 1 is still on screen — those legitimately still show case 1's
    // selection, and flagging them would be flagging the page for displaying
    // the case the examiner is actually looking at.
    const afterSwitch = frames.filter((f) => f.includes('[path:/cases/c2/'))
    expect(afterSwitch.length).toBeGreaterThan(0)
    for (const frame of afterSwitch) {
      expect(frame).not.toMatch(/\d+ selected/)
    }
  })

  it('does not show the previous case rows under the new case (BUG-196)', async () => {
    // Same source id under a different case: without caseId in the identity tag
    // the placeholder still matches and case 1's rows render under case 2.
    mockApi()
    let releaseC2: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      releaseC2 = resolve
    })
    const c2Rows = [
      row({
        id: 'h1',
        parent_id: 's1',
        name: 'case2.txt',
        path: '/case2.txt',
        extension: 'txt',
        size: 34,
      }),
    ]
    server.use(
      http.get('/api/v1/cases/c2/sources/s1/files', async ({ request }) => {
        const params = new URL(request.url).searchParams
        fileRequests.push(params)
        if (params.get('dirs') === 'only') return HttpResponse.json(wrap([], 1))
        await gate
        return HttpResponse.json(wrap(c2Rows, 1))
      }),
    )

    renderWithSwitch('/cases/c1/files/s1', '/cases/c2/files/s1', 'go-c2')
    await screen.findByText('report.docx')

    await userEvent.click(screen.getByText('go-c2'))
    await waitFor(() =>
      expect(screen.queryByText('report.docx')).not.toBeInTheDocument(),
    )
    expect(screen.getByLabelText(/Loading files/)).toBeInTheDocument()

    releaseC2()
    expect(await screen.findByText('case2.txt')).toBeInTheDocument()
  })
})

describe('FileGridPage known-file triage', () => {
  it('requests metadata and renders a triage badge per known_status', async () => {
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    // Hashes come back with the rows.
    expect(gridRequests()[0].get('include_metadata')).toBe('true')

    const notable = screen.getByText('Notable')
    expect(notable).toBeInTheDocument()
    expect(notable.getAttribute('title')).toMatch(/NOTABLE/)

    const known = screen.getByText('Known')
    expect(known).toBeInTheDocument()
    expect(known.getAttribute('title')).toMatch(/known-good/)
  })

  it('filters by known status via the query param and resets the page', async () => {
    mockApi()
    renderPage('/cases/c1/files/s1?page=3')
    await screen.findByText('report.docx')

    await userEvent.selectOptions(
      screen.getByLabelText('Known status filter'),
      'notable',
    )
    await waitFor(() =>
      expect(gridRequests().some((p) => p.get('known') === 'notable')).toBe(
        true,
      ),
    )
    expect(lastGrid().get('page')).toBe('1')
  })

  it('shows row hashes with a copy-to-clipboard affordance', async () => {
    mockApi()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))

    const md5 = await screen.findByText('aabbccdd…66778899')
    expect(md5).toHaveAttribute(
      'title',
      'aabbccddeeff00112233445566778899',
    )

    await userEvent.click(screen.getByRole('button', { name: 'Copy MD5' }))
    expect(writeText).toHaveBeenCalledWith(
      'aabbccddeeff00112233445566778899',
    )
    expect(await screen.findByText('Copied')).toBeInTheDocument()
  })

  it('bulk-exports the selected files as a ZIP and toasts the counts', async () => {
    mockApi()
    let releaseExport: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      releaseExport = resolve
    })
    let exportBody: {
      artifact_ids: string[]
      include_manifest: boolean
    } | null = null
    server.use(
      http.post('/api/v1/cases/c1/export/files', async ({ request }) => {
        exportBody = (await request.json()) as typeof exportBody
        await gate
        return new HttpResponse(new Uint8Array([80, 75, 3, 4]).buffer, {
          headers: {
            'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="seance-export.zip"',
            'X-Export-File-Count': '2',
            'X-Export-Skipped-Count': '1',
          },
        })
      }),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    fireEvent.click(screen.getByText('secret.pdf').closest('tr')!, {
      ctrlKey: true,
    })

    await userEvent.click(
      screen.getByRole('button', { name: 'Export selected (ZIP + hashes)' }),
    )
    // Pending state reflects the count in flight.
    expect(await screen.findByText('Exporting 2 files…')).toBeInTheDocument()

    releaseExport()
    // Success toast built from the response headers.
    expect(
      await screen.findByText('Exported 2 files, 1 skipped'),
    ).toBeInTheDocument()
    expect(exportBody).toEqual({
      artifact_ids: ['f1', 'f2'],
      include_manifest: true,
    })
  })

  it('does not report an export holding truncated content as a clean one', async () => {
    // The server counts files exported with content SHORT of their declared
    // size and files LONGER than declared, and reports both in headers beside
    // the file/skipped pair. Reading only that pair made "Exported 3 files, 0
    // skipped" a clean bill of health over a ZIP that goes into evidence.
    mockApi()
    server.use(
      http.post('/api/v1/cases/c1/export/files', () => {
        return new HttpResponse(new Uint8Array([80, 75, 3, 4]).buffer, {
          headers: {
            'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="seance-export.zip"',
            'X-Export-File-Count': '3',
            'X-Export-Skipped-Count': '0',
            'X-Export-Incomplete-Count': '2',
            'X-Export-Size-Mismatch-Count': '1',
          },
        })
      }),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    fireEvent.click(screen.getByText('secret.pdf').closest('tr')!, {
      ctrlKey: true,
    })
    await userEvent.click(
      screen.getByRole('button', { name: 'Export selected (ZIP + hashes)' }),
    )

    const note = await screen.findByText(/INCOMPLETE content/)
    expect(note).toHaveTextContent('Exported 3 files, 0 skipped')
    expect(note).toHaveTextContent('2 exported with INCOMPLETE content')
    expect(note).toHaveTextContent('1 whose size does not match')
    expect(note).toHaveTextContent(/manifest\.json/)
  })

  it('still offers the ZIP when the filename is not valid percent-encoding', async () => {
    // The ZIP has already been produced, hashed and audited server-side by the
    // time the header is read. Decoding the filename with decodeURIComponent
    // throws URIError on a stray `%` — before the blob is ever read — so the
    // examiner saw "Export failed" for an export that succeeded, and the
    // evidence package was silently dropped (HUNT-029). A filename is cosmetic;
    // losing the download over one is not. Sources of a stray `%`: an older
    // build's sanitiser, or any producer using the RFC 5987 `filename*=UTF-8''`
    // form whose prefix this regex strips.
    mockApi()
    const downloadNames: string[] = []
    const anchorClick = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(function (this: HTMLAnchorElement) {
        downloadNames.push(this.download)
      })
    server.use(
      http.post('/api/v1/cases/c1/export/files', () => {
        return new HttpResponse(new Uint8Array([80, 75, 3, 4]).buffer, {
          headers: {
            'Content-Type': 'application/zip',
            'Content-Disposition':
              'attachment; filename="export_50%_recovered.zip"',
            'X-Export-File-Count': '2',
            'X-Export-Skipped-Count': '0',
          },
        })
      }),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    fireEvent.click(screen.getByText('secret.pdf').closest('tr')!, {
      ctrlKey: true,
    })
    await userEvent.click(
      screen.getByRole('button', { name: 'Export selected (ZIP + hashes)' }),
    )

    expect(
      await screen.findByText('Exported 2 files, 0 skipped'),
    ).toBeInTheDocument()
    expect(screen.queryByText(/Export failed/)).not.toBeInTheDocument()
    // Undecodable stays as the server sent it, rather than becoming a guess.
    expect(downloadNames).toEqual(['export_50%_recovered.zip'])
    anchorClick.mockRestore()
  })

  it('keeps the plain success toast for an export with nothing flagged', async () => {
    // A warning on every export is a warning an examiner stops reading.
    mockApi()
    server.use(
      http.post('/api/v1/cases/c1/export/files', () => {
        return new HttpResponse(new Uint8Array([80, 75, 3, 4]).buffer, {
          headers: {
            'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="seance-export.zip"',
            'X-Export-File-Count': '3',
            'X-Export-Skipped-Count': '0',
            'X-Export-Incomplete-Count': '0',
            'X-Export-Size-Mismatch-Count': '0',
          },
        })
      }),
    )
    renderPage()
    await userEvent.click(await screen.findByText('report.docx'))
    fireEvent.click(screen.getByText('secret.pdf').closest('tr')!, {
      ctrlKey: true,
    })
    await userEvent.click(
      screen.getByRole('button', { name: 'Export selected (ZIP + hashes)' }),
    )

    expect(
      await screen.findByText('Exported 3 files, 0 skipped'),
    ).toBeInTheDocument()
    expect(screen.queryByText(/INCOMPLETE content/)).not.toBeInTheDocument()
  })
})

describe('FileGridPage error state', () => {
  it('shows an error note when the files request fails', async () => {
    server.use(
      http.get('/api/v1/cases/c1/sources/s1/files', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'source unreadable' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    expect(await screen.findByText(/source unreadable/)).toBeInTheDocument()
  })
})

/**
 * The standard incompleteness pair, at the two places the files surface shows
 * a file: the grid row and the detail pane. Before this the grid marked a
 * half-reconstructed file "OK" and the detail pane said nothing at all, because
 * nothing in `frontend/src` read `content_incomplete`.
 */
describe('FileGridPage incompleteness', () => {
  const partialRow = row({
    id: 'f9',
    name: 'partial.bin',
    path: '/partial.bin',
    extension: 'bin',
    size: 512,
    metadata: {
      content_incomplete: true,
      content_incomplete_reason: 'cap_reached',
    },
  })

  /** Grid serves the partial file plus one whole one; the tree stays empty. */
  function mockGrid(artifactMetadata?: Record<string, unknown>) {
    server.use(
      http.get('/api/v1/cases/c1/sources/s1/files', ({ request }) => {
        const params = new URL(request.url).searchParams
        const items =
          params.get('dirs') === 'only'
            ? []
            : [partialRow, row({ id: 'f8', name: 'whole.bin', path: '/whole.bin' })]
        return HttpResponse.json(wrap(items, 1))
      }),
      http.get('/api/v1/cases/c1/artifacts/:artifactId', ({ params }) =>
        HttpResponse.json({
          id: params.artifactId,
          case_id: 'c1',
          parent_id: 'p1',
          artifact_type: 'FileEntry',
          metadata: artifactMetadata ?? { md5_hash: 'd41d8cd98f' },
        }),
      ),
      http.get('/api/v1/cases/c1/artifacts/:artifactId/thumbnail', () =>
        HttpResponse.json(
          { error: { code: 'NOT_FOUND', message: 'not an image' } },
          { status: 404 },
        ),
      ),
    )
  }

  it('badges a grid row whose parser could not finish it', async () => {
    mockGrid()
    renderPage()

    const tr = (await screen.findByText('partial.bin')).closest('tr')!
    const badge = within(tr).getByRole('note')
    expect(badge).toHaveAccessibleName(/content incomplete/i)
    expect(badge).toHaveAccessibleName(/safety cap/i)
  })

  it('leaves a whole file unbadged', async () => {
    mockGrid()
    renderPage()

    const tr = (await screen.findByText('whole.bin')).closest('tr')!
    expect(within(tr).queryByRole('note')).not.toBeInTheDocument()
  })

  it('explains the incompleteness in the detail pane, with its reason', async () => {
    // The reason drives the follow-up: an encrypted file needs a key, a capped
    // one needs a re-parse. A generic "incomplete" would say neither.
    mockGrid({
      md5_hash: 'd41d8cd98f',
      content_incomplete: true,
      content_incomplete_reason: 'encrypted',
    })
    renderPage()
    await userEvent.click(await screen.findByText('partial.bin'))

    expect(await screen.findByText(/was not decrypted/)).toBeInTheDocument()
  })
})

describe('FileGridPage breadcrumb on deep paths', () => {
  function crumbNav(): HTMLElement {
    return screen.getByRole('navigation', { name: 'Current folder' })
  }

  it('leaves a shallow path alone', async () => {
    mockApi()
    renderPage('/cases/c1/files/s1?dir=/Windows/System32')
    expect(await screen.findByText('kernel32.dll')).toBeInTheDocument()

    const crumbs = crumbNav()
    expect(within(crumbs).getByRole('button', { name: 'Windows' })).toBeInTheDocument()
    expect(within(crumbs).getByRole('button', { name: 'System32' })).toBeInTheDocument()
    expect(within(crumbs).queryByRole('button', { name: /hidden folders/ })).toBeNull()
  })
})

describe('FileGridPage numeric columns', () => {
  it('right-aligns and tabularises the size column', async () => {
    mockApi()
    renderPage()
    expect(await screen.findByText('report.docx')).toBeInTheDocument()

    // Scanning a directory for the one multi-gigabyte outlier is an
    // edge-alignment task; left-aligned proportional digits make "9.8 MiB"
    // look wider than "1.2 GiB" and force every value to be read.
    const sizeHeader = screen.getByRole('columnheader', { name: /Size/ })
    expect(sizeHeader).toHaveClass('num')
    const cell = within(fileRow('report.docx')).getByText('2.0 KiB')
    expect(cell).toHaveClass('num')
  })
})

/**
 * A saved compound filter's population, opened in the grid so that it inherits
 * the grid's paging, sort, selection and export.
 *
 * Two things have to be true of the grid once it is showing one. It has to say
 * WHICH filter it is showing, because a narrowed grid that looks like the whole
 * case is a false absence — the examiner concludes the evidence holds four
 * files when the filter merely matched four. And it has to carry the filter's
 * own disclosure through: a filter whose scan stopped at the case-wide ceiling,
 * or that could not read some of the rows it reached, produces a count that is
 * a floor, and the file grid is the last screen before that number is quoted.
 */
function filterBlock(over: Record<string, unknown> = {}) {
  return {
    filter_id: 'flt-1',
    filter_name: 'over 1 MB',
    matched: 4,
    listed: 4,
    scan_complete: true,
    undecodable: 0,
    population_capped: false,
    population_cap: 50000,
    inventory_incomplete: false,
    inventory_incomplete_reason: null,
    ...over,
  }
}

function withFilter(over: Record<string, unknown> = {}): FilesResponse {
  return {
    ...wrap(rootRows, 1),
    total_pages: 1,
    has_next: false,
    filter: filterBlock(over),
  } as FilesResponse
}

describe('FileGridPage filter population', () => {
  it('asks the server for the filter and names it on the grid', async () => {
    mockApi(withFilter())
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(lastGrid().get('filter_id')).toBe('flt-1')

    const bar = screen.getByTestId('fg-filter-bar')
    expect(bar).toHaveTextContent('over 1 MB')
  })

  it('shows the matched and the listed counts, and says why they differ', async () => {
    // The filter runs over every artifact type in the whole case; the grid
    // lists file-system entries under one evidence source. A grid that showed
    // only its own count would read as the filter having matched 2 things.
    mockApi(withFilter({ matched: 9, listed: 4 }))
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    const bar = screen.getByTestId('fg-filter-bar')
    expect(bar).toHaveTextContent('9')
    expect(bar).toHaveTextContent('4')
    expect(screen.getByTestId('fg-filter-gap')).toHaveTextContent(
      /file-system entries/i,
    )
  })

  it('carries an incomplete scan through to the grid', async () => {
    mockApi(
      withFilter({
        matched: 500_000,
        listed: 4,
        scan_complete: false,
        inventory_incomplete: true,
        inventory_incomplete_reason: 'capped',
      }),
    )
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    const note = screen.getByTestId('fg-filter-scan-incomplete')
    expect((note.textContent ?? '').replace(/\s+/g, ' ')).toContain(
      'not the number that exist',
    )
    // The server's own word for it travels with the notice, so a reader can
    // match the grid's disclosure against the filter page's.
    expect(screen.getByTestId('fg-filter-bar')).toHaveAttribute(
      'data-incomplete-reason',
      'capped',
    )
  })

  it('carries rows the filter could not be evaluated against', async () => {
    mockApi(
      withFilter({
        undecodable: 7,
        inventory_incomplete: true,
        inventory_incomplete_reason: 'undecodable_rows',
      }),
    )
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    const note = screen.getByTestId('fg-filter-undecodable')
    expect((note.textContent ?? '').replace(/\s+/g, ' ')).toContain(
      '7 artifacts could not be read',
    )
    expect(screen.queryByTestId('fg-filter-scan-incomplete')).toBeNull()
  })

  it('says when more matched than this grid will ever list', async () => {
    mockApi(
      withFilter({
        matched: 50_000,
        listed: 4,
        population_capped: true,
        population_cap: 50_000,
        inventory_incomplete: true,
        inventory_incomplete_reason: 'population_cap_reached',
      }),
    )
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.getByTestId('fg-filter-population-capped')).toHaveTextContent(
      /50,000/,
    )
  })

  it('reads the item count as a floor while the filter is short', async () => {
    // "4 items" under a capped scan is a population claim nobody established.
    mockApi(
      withFilter({
        scan_complete: false,
        inventory_incomplete: true,
        inventory_incomplete_reason: 'capped',
      }),
    )
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.getByTestId('fg-count')).toHaveTextContent(/at least 4 items/i)
  })

  it('reads the pager count as the same floor the count bar reads', async () => {
    // The count bar above the table and the pager below it state the same
    // number about the same set. If one of them qualifies it and the other
    // does not, the screen disagrees with itself about its own exactness
    // within one page-height — and whichever half is quoted, the other one
    // impeaches it.
    mockApi(
      withFilter({
        scan_complete: false,
        inventory_incomplete: true,
        inventory_incomplete_reason: 'capped',
      }),
    )
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.getByTestId('pager-status')).toHaveTextContent(
      /at least 4 rows/i,
    )
    // Same reason the count bar's total is a floor: the page total derived
    // from it is one too, and the jump to a "last" page the server never
    // claimed was the end is withheld.
    expect(screen.getByTestId('pager-status')).toHaveTextContent(
      /Page 1 of at least/i,
    )
    expect(screen.queryByLabelText('Last page')).toBeNull()
  })

  it('leaves the pager count unqualified when the filter is complete', async () => {
    // An "at least" on a number the server counted exactly makes an examiner
    // hedge a figure that did not need hedging.
    mockApi(withFilter())
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.getByTestId('pager-status')).not.toHaveTextContent(/at least/i)
    expect(screen.getByLabelText('Last page')).toBeInTheDocument()
  })

  it('does not claim a filter is applied when the server reported none', async () => {
    // A grid narrowed by a filter the response says nothing about must not
    // paint itself as an unfiltered case listing.
    mockApi(wrap(rootRows, 1))
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.queryByTestId('fg-filter-bar')).toBeNull()
    expect(screen.getByTestId('fg-filter-unreported')).toHaveTextContent(
      /did not report/i,
    )
  })

  it('drops the filter from the URL when it is cleared', async () => {
    // The block comes back only while the request carries a filter, the way
    // the server behaves: its absence is what "no filter applied" looks like.
    server.use(
      http.get('/api/v1/cases/c1/sources/s1/files', ({ request }) => {
        const params = new URL(request.url).searchParams
        fileRequests.push(params)
        return HttpResponse.json(
          params.get('filter_id') ? withFilter() : wrap(rootRows, 1),
        )
      }),
    )
    renderPage('/cases/c1/files/s1?view=flat&filter_id=flt-1')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Clear filter/ }))

    await waitFor(() => expect(lastGrid().get('filter_id')).toBeNull())
    expect(screen.queryByTestId('fg-filter-bar')).toBeNull()
  })

  it('says the tree view does not narrow to the filter', async () => {
    // The tree lists the file system level by level and never sends filter_id,
    // so a filter left in the URL while the tree is on screen would have the
    // examiner reading the whole file system as the filter's population.
    mockApi(withFilter())
    renderPage('/cases/c1/files/s1?view=tree&filter_id=flt-1')

    expect(
      await screen.findByTestId('fg-filter-not-in-tree'),
    ).toHaveTextContent(/not applied/i)
  })
})

/**
 * §2.8. "Show unique only" is a population-defining filter: the rows it shows
 * are the files the case can *demonstrate* are one of a kind. A file with no
 * hash is neither unique nor a duplicate, so it is set aside — and the grid has
 * to say how many, or its count reads as "the unique files in this case" when
 * it is a floor on them.
 */
describe('FileGridPage unique-only filter', () => {
  it('asks the server for it and reports what it could not assess', async () => {
    mockApi({
      ...wrap(rootRows, 1),
      total_pages: 1,
      has_next: false,
      unique: {
        unassessable: 7,
        note: '7 file(s) matching these filters carry no SHA-256 and are NOT listed: their uniqueness is unknown, not disproved.',
      },
    } as FilesResponse)
    renderPage('/cases/c1/files/s1?view=flat&unique=true')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(lastGrid().get('unique_only')).toBe('true')

    const note = screen.getByTestId('fg-unique-note')
    expect(note).toHaveTextContent('7 file(s)')
    expect(note).toHaveTextContent(/unknown, not disproved/i)
    // A shortfall is a warning, not a muted aside.
    expect(note).toHaveClass('warn-note')
  })

  it('states plainly when nothing had to be set aside', async () => {
    mockApi({
      ...wrap(rootRows, 1),
      total_pages: 1,
      has_next: false,
      unique: {
        unassessable: 0,
        note: 'Every file in this view carries a hash, so each one shown is one this case can demonstrate is unique.',
      },
    } as FilesResponse)
    renderPage('/cases/c1/files/s1?view=flat&unique=true')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    const note = screen.getByTestId('fg-unique-note')
    expect(note).toHaveTextContent(/every file in this view carries a hash/i)
    // Nothing is wrong, so it must not look like a warning.
    expect(note).not.toHaveClass('warn-note')
  })

  it('refuses to let an unreported filter pass as a narrowing', async () => {
    // Asked for unique-only; the server said nothing about it. The rows cannot
    // be read as "the unique files" without knowing what was set aside.
    mockApi({
      ...wrap(rootRows, 1),
      total_pages: 1,
      has_next: false,
    } as FilesResponse)
    renderPage('/cases/c1/files/s1?view=flat&unique=true')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.queryByTestId('fg-unique-note')).toBeNull()
    expect(screen.getByTestId('fg-unique-unreported')).toHaveTextContent(
      /do not read this count as the number of unique files/i,
    )
  })

  it('is off unless asked for, and says nothing when it is off', async () => {
    mockApi(wrap(rootRows, 1))
    renderPage('/cases/c1/files/s1?view=flat')

    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(lastGrid().get('unique_only')).toBeNull()
    expect(screen.queryByTestId('fg-unique-note')).toBeNull()
    expect(screen.queryByTestId('fg-unique-unreported')).toBeNull()
  })
})

describe('FileGridPage whole-case mactime body file', () => {
  beforeEach(() => {
    vi.mocked(downloadFile).mockReset()
  })

  it('offers a whole-case mactime body-file export that says it ignores the filters', async () => {
    vi.mocked(downloadFile).mockResolvedValue({
      route: 'file-system',
      cancelled: false,
      bytes: 100,
      terminated: true,
    })
    mockApi()
    renderPage('/cases/c1/files/s1?view=flat&deleted=true&name=x')
    await screen.findByText('report.docx')

    // Present with nothing selected: it is not a selection action.
    expect(screen.queryByRole('toolbar', { name: 'Selection actions' })).toBeNull()
    const button = screen.getByRole('button', { name: /body file/i })
    expect(button).toHaveAccessibleName(/whole case/i)
    expect(button).toHaveAccessibleDescription(/every source/i)
    expect(button).toHaveAccessibleDescription(/ignores the filters/i)

    await userEvent.click(button)
    await waitFor(() => expect(downloadFile).toHaveBeenCalledTimes(1))
    const [path, filename, options] = vi.mocked(downloadFile).mock.calls[0]
    // The route takes no filters; none are sent, so nothing implies they apply.
    expect(path).toBe('/cases/c1/timeline/export/body')
    expect(filename).toBe('body_c1.txt')
    expect(options?.query).toBeUndefined()
    expect(options?.unbounded).toBe(true)
    expect(options?.terminator).toEqual({
      marker: '### END OF EXPORT ###',
      format: 'body',
    })
  })

  it('reports the body file saved, with the verdict the file itself states', async () => {
    vi.mocked(downloadFile).mockResolvedValue({
      route: 'file-system',
      cancelled: false,
      bytes: 2048,
      terminated: true,
      verdict:
        'VERDICT: COMPLETE. This file holds all 3 of 3 FileEntry artifacts in the case.',
    })
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.click(screen.getByRole('button', { name: /body file/i }))
    const status = await screen.findByTestId('fg-case-export-status')
    expect(status).toHaveTextContent(/saved/i)
    expect(status).toHaveTextContent(/2\.0 KiB/)
    expect(status).toHaveTextContent(/COMPLETE\. This file holds all 3 of 3/)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('does not call a whole file whose own verdict is INCOMPLETE a complete export', async () => {
    vi.mocked(downloadFile).mockResolvedValue({
      route: 'file-system',
      cancelled: false,
      bytes: 100,
      terminated: true,
      verdict:
        'VERDICT: INCOMPLETE. This file holds 1 rows; the case held 2 FileEntry artifacts when the export began. The set changed while the walk ran. Do not treat this file as the complete file list.',
    })
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.click(screen.getByRole('button', { name: /body file/i }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/INCOMPLETE/)
    expect(alert).toHaveTextContent(/not the complete file list/i)
    expect(screen.queryByTestId('fg-case-export-status')).toBeNull()
  })

  it('says a cancelled body-file save wrote nothing, rather than staying silent', async () => {
    vi.mocked(downloadFile).mockResolvedValue({
      route: 'file-system',
      cancelled: true,
      bytes: 0,
      terminated: null,
    })
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.click(screen.getByRole('button', { name: /body file/i }))
    const status = await screen.findByTestId('fg-case-export-status')
    expect(status).toHaveTextContent(/cancelled.*nothing was written/i)
    expect(status).not.toHaveTextContent(/saved/i)
  })

  it('says the body-file export failed and how to retry', async () => {
    vi.mocked(downloadFile).mockRejectedValue(new Error('HTTP 500'))
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.click(screen.getByRole('button', { name: /body file/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /body file export failed: HTTP 500.*click export whole case as mactime body file to retry/i,
    )
  })

  it('keeps the fragment statement on screen when the body file arrived cut short', async () => {
    vi.mocked(downloadFile).mockRejectedValue(
      new DownloadIncompleteError(
        'body_c1.txt is a fragment: 42 B arrived and it does not end with the verdict line.',
        'body_c1.txt',
        42,
        true,
      ),
    )
    mockApi()
    renderPage()
    await screen.findByText('report.docx')

    await userEvent.click(screen.getByRole('button', { name: /body file/i }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/body_c1\.txt/)
  })
})
