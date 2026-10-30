import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { server } from '../../test/server'
import { FrameSpy } from '../../test/frames'
import { GalleryPage } from './GalleryPage'

// ---- IntersectionObserver mock: cells start out of view ----
class MockIO {
  static instances: MockIO[] = []
  callback: IntersectionObserverCallback
  elements: Element[] = []
  constructor(cb: IntersectionObserverCallback) {
    this.callback = cb
    MockIO.instances.push(this)
  }
  observe(el: Element) {
    this.elements.push(el)
  }
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}

function scrollAllIntoView() {
  act(() => {
    for (const io of MockIO.instances) {
      io.callback(
        io.elements.map(
          (el) =>
            ({ isIntersecting: true, target: el }) as IntersectionObserverEntry,
        ),
        io as unknown as IntersectionObserver,
      )
    }
  })
}

const sources = {
  sources: [{ source_artifact_id: 's1', name: 'Disk 1', artifact_count: 10 }],
}

const jpgImages = [
  {
    id: 'img1',
    name: 'DSC_0001.jpg',
    path: '/DCIM/DSC_0001.jpg',
    extension: 'jpg',
    size: 2048,
    is_directory: false,
    metadata: {
      md5: 'aabbccddeeff00112233445566778899',
      sha256:
        '1111111111111111111111111111111111111111111111111111111111111111',
    },
  },
  {
    id: 'img2',
    name: 'DSC_0002.jpg',
    path: '/DCIM/DSC_0002.jpg',
    extension: 'jpg',
    size: 4096,
    is_directory: false,
    metadata: {},
  },
]

const exifRecords = {
  records: [
    {
      id: 'exif1',
      parent_id: 'img1',
      metadata: {
        type: 'exif',
        camera: 'PENTAX K-1',
        datetime_original: '2024:03:04 09:10:11',
        source_name: 'DSC_0001.jpg',
        has_gps: true,
        gps_lat: 51.5,
        gps_lon: -0.12,
      },
    },
  ],
}

let thumbnailRequests: string[] = []
let filesRequests: {
  page: number
  extensions: string
  known: string | null
  sort?: string | null
  order?: string | null
}[] = []
let batchRequests: { module_id: string; artifact_ids: string[] }[] = []
const createObjectURL = vi.fn(() => 'blob:mock')
const revokeObjectURL = vi.fn()

function mockApi() {
  server.use(
    http.get('/api/v1/cases/c1/stats/sources', () =>
      HttpResponse.json(sources),
    ),
    // Modules: OCR is opt-in (offered on the gallery), EXIF is automatic.
    http.get('/api/v1/modules', () =>
      HttpResponse.json([
        {
          id: 'plugin.media.ocr',
          version: '0.9.0',
          subscribes_to: ['FileEntry', 'FileContent'],
          execution_mode: 'OptIn',
        },
        {
          id: 'plugin.exif.exif',
          version: '1.0.0',
          subscribes_to: ['FileEntry'],
          execution_mode: 'Automatic',
        },
      ]),
    ),
    http.post('/api/v1/cases/c1/run_module_batch', async ({ request }) => {
      const body = (await request.json()) as {
        module_id: string
        artifact_ids: string[]
      }
      batchRequests.push(body)
      return HttpResponse.json({
        job_ids: body.artifact_ids.map((_, i) => `job${i}`),
        targets: body.artifact_ids.length,
        truncated: false,
      })
    }),
    // Case-wide, server-paginated image listing (source filter = 'all').
    http.get('/api/v1/cases/c1/files', ({ request }) => {
      const url = new URL(request.url)
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 100)
      filesRequests.push({
        page,
        extensions: url.searchParams.get('extensions') ?? '',
        known: url.searchParams.get('known'),
        sort: url.searchParams.get('sort'),
        order: url.searchParams.get('order'),
      })
      const start = (page - 1) * pageSize
      const slice = jpgImages.slice(start, start + pageSize)
      return HttpResponse.json({
        items: slice,
        total_count: jpgImages.length,
        page,
        page_size: pageSize,
        total_pages: Math.max(1, Math.ceil(jpgImages.length / pageSize)),
        has_next: start + pageSize < jpgImages.length,
        has_previous: page > 1,
      })
    }),
    http.get('/api/v1/cases/c1/records', () => HttpResponse.json(exifRecords)),
    // Hash overlays default to "no data" so the baseline has no load error;
    // the dedicated hash tests override these.
    http.get('/api/v1/cases/c1/hash_sets', () => HttpResponse.json([])),
    http.get('/api/v1/cases/c1/hash_hits', () =>
      HttpResponse.json({ hits: [], total: 0 }),
    ),
    http.get(
      '/api/v1/cases/c1/artifacts/:artifactId/thumbnail',
      ({ params }) => {
        thumbnailRequests.push(params.artifactId as string)
        return new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
          headers: { 'Content-Type': 'image/png' },
        })
      },
    ),
    http.get(
      '/api/v1/cases/c1/artifacts/:artifactId/content',
      () =>
        new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
          headers: { 'Content-Type': 'image/png' },
        }),
    ),
  )
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/c1/gallery']}>
          <Routes>
            <Route path="/cases/:caseId/gallery" element={<GalleryPage />} />
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
  globalThis.IntersectionObserver = MockIO as unknown as typeof IntersectionObserver
})

beforeEach(() => {
  thumbnailRequests = []
  filesRequests = []
  batchRequests = []
  MockIO.instances = []
  createObjectURL.mockClear()
  revokeObjectURL.mockClear()
})

describe('GalleryPage', () => {
  it('renders a thumbnail grid discovered from the file listing', async () => {
    mockApi()
    renderPage()

    expect(await screen.findByText('DSC_0001.jpg')).toBeInTheDocument()
    expect(screen.getByText('DSC_0002.jpg')).toBeInTheDocument()
    expect(screen.getByText('2 images')).toBeInTheDocument()

    // A per-source filter is present.
    expect(screen.getByLabelText('Source')).toBeInTheDocument()
    expect(
      screen.getByRole('option', { name: 'Disk 1' }),
    ).toBeInTheDocument()
  })

  it('shows previews unobscured by default, and turns Safe view on when asked', async () => {
    localStorage.clear()
    mockApi()
    const { container } = renderPage()
    await screen.findByText('DSC_0001.jpg')

    // Off by default (changed 2026-09-07): most cases are ordinary disk images
    // where blurring every thumbnail is friction and nothing else.
    expect(container.querySelector('.gl-safe-view')).toBeNull()
    const toggle = screen.getByRole('button', { name: /Safe view: off/i })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')

    // Turning it on applies the blur class.
    fireEvent.click(toggle)
    expect(container.querySelector('.gl-safe-view')).not.toBeNull()
    expect(
      screen.getByRole('button', { name: /Safe view: on/i }),
    ).toHaveAttribute('aria-pressed', 'true')
  })

  /**
   * The persistence is the safeguard, not the polish.
   *
   * While Safe view defaulted ON, forgetting the toggle merely re-protected
   * you. Now it defaults OFF, so an examiner who turns it on and then opens
   * another case would be shown an unblurred grid of exactly the material the
   * control exists to hide. That is why this is a test and not a nicety.
   */
  it('remembers Safe view being turned on, across a remount', async () => {
    localStorage.clear()
    mockApi()
    const first = renderPage()
    await screen.findByText('DSC_0001.jpg')
    fireEvent.click(screen.getByRole('button', { name: /Safe view: off/i }))
    expect(first.container.querySelector('.gl-safe-view')).not.toBeNull()
    first.unmount()

    const { container } = renderPage()
    await screen.findByText('DSC_0001.jpg')
    expect(container.querySelector('.gl-safe-view')).not.toBeNull()
    expect(
      screen.getByRole('button', { name: /Safe view: on/i }),
    ).toHaveAttribute('aria-pressed', 'true')
  })

  it('falls back to the shipped default when storage cannot be read', async () => {
    const getItem = vi
      .spyOn(Storage.prototype, 'getItem')
      .mockImplementation(() => {
        throw new Error('site data blocked')
      })
    try {
      mockApi()
      const { container } = renderPage()
      await screen.findByText('DSC_0001.jpg')
      // Off, matching the default — not a third behaviour invented for the
      // error path. The toolbar control still says which state it is in.
      expect(container.querySelector('.gl-safe-view')).toBeNull()
      expect(
        screen.getByRole('button', { name: /Safe view: off/i }),
      ).toBeInTheDocument()
    } finally {
      getItem.mockRestore()
    }
  })

  it('lazy-loads thumbnails only once a cell scrolls into view', async () => {
    mockApi()
    renderPage()
    await screen.findByText('DSC_0001.jpg')

    // Nothing fetched while cells are out of view.
    expect(thumbnailRequests).toEqual([])

    scrollAllIntoView()

    await waitFor(() => expect(thumbnailRequests).toContain('img1'))
    expect(
      await screen.findByAltText('Thumbnail of DSC_0001.jpg'),
    ).toBeInTheDocument()
  })

  it('highlights an image on click and shows its properties in the sidebar', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByText('DSC_0001.jpg'))

    const sidebar = screen.getByRole('complementary', {
      name: 'image properties',
    })
    expect(within(sidebar).getByText('/DCIM/DSC_0001.jpg')).toBeInTheDocument()
    // EXIF joined by parent_id -> image id.
    expect(within(sidebar).getByText('PENTAX K-1')).toBeInTheDocument()
    expect(within(sidebar).getByText('51.5, -0.12')).toBeInTheDocument()
    expect(
      within(sidebar).getByRole('link', { name: 'Open artifact' }),
    ).toHaveAttribute('href', '/cases/c1/artifacts/img1')
    // A single click selects; it does not open the lightbox.
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('opens the image-only lightbox on double-click', async () => {
    mockApi()
    renderPage()
    await userEvent.dblClick(await screen.findByText('DSC_0001.jpg'))

    const dialog = await screen.findByRole('dialog', { name: 'DSC_0001.jpg' })
    expect(within(dialog).getByAltText('DSC_0001.jpg')).toBeInTheDocument()
    expect(
      within(dialog).getByRole('link', { name: 'Open artifact' }),
    ).toHaveAttribute('href', '/cases/c1/artifacts/img1')
    // Properties are not duplicated in the lightbox; they live in the sidebar.
    expect(within(dialog).queryByText('PENTAX K-1')).not.toBeInTheDocument()
  })

  it('moves the highlight with arrow keys and opens the lightbox with Space', async () => {
    mockApi()
    renderPage()
    // Select the first image, then arrow to the second.
    await userEvent.click(await screen.findByText('DSC_0001.jpg'))
    await userEvent.keyboard('{ArrowRight}')

    const sidebar = screen.getByRole('complementary', {
      name: 'image properties',
    })
    expect(within(sidebar).getByText('/DCIM/DSC_0002.jpg')).toBeInTheDocument()

    // Space opens the lightbox on the now-highlighted second image.
    await userEvent.keyboard(' ')
    const dialog = await screen.findByRole('dialog', { name: 'DSC_0002.jpg' })
    expect(
      within(dialog).getByRole('link', { name: 'Open artifact' }),
    ).toHaveAttribute('href', '/cases/c1/artifacts/img2')

    // Escape closes it.
    await userEvent.keyboard('{Escape}')
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    )
  })

  it('runs an opt-in module (OCR) across every gallery image from the toolbar', async () => {
    mockApi()
    renderPage()
    await screen.findByText('2 images')

    // Only OCR is opt-in; the automatic EXIF module is not offered here.
    const trigger = await screen.findByRole('button', { name: /run analysis/i })
    await userEvent.click(trigger)

    await userEvent.click(
      await screen.findByText(/Run OCR on all 2 images/i),
    )

    await waitFor(() => expect(batchRequests).toHaveLength(1))
    expect(batchRequests[0].module_id).toBe('plugin.media.ocr')
    expect([...batchRequests[0].artifact_ids].sort()).toEqual(['img1', 'img2'])
  })

  it('runs an opt-in module on a single image via the thumbnail context menu', async () => {
    mockApi()
    let singleRun: { module_id: string } | null = null
    server.use(
      http.post(
        '/api/v1/cases/c1/artifacts/img2/run_module',
        async ({ request }) => {
          singleRun = (await request.json()) as { module_id: string }
          return HttpResponse.json({ job_id: 'job-single' })
        },
      ),
    )
    renderPage()
    const cell = await screen.findByText('DSC_0002.jpg')

    // Right-click the thumbnail to open the per-image analysis menu.
    fireEvent.contextMenu(cell)
    await userEvent.click(
      await screen.findByText(/Run OCR on this image/i),
    )

    await waitFor(() => expect(singleRun).not.toBeNull())
    expect(singleRun!.module_id).toBe('plugin.media.ocr')
    // The batch endpoint was not touched for a single-image run.
    expect(batchRequests).toHaveLength(0)
  })

  it('pages the server as the grid scrolls instead of loading the case up front', async () => {
    // 250 images over 3 server pages of 100.
    const many = Array.from({ length: 250 }, (_, i) => ({
      id: `m${i}`,
      name: `IMG_${i}.jpg`,
      path: `/DCIM/IMG_${i}.jpg`,
      extension: 'jpg',
      size: 1024,
      is_directory: false,
      metadata: {},
    }))
    server.use(
      http.get('/api/v1/cases/c1/stats/sources', () =>
        HttpResponse.json(sources),
      ),
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ records: [] }),
      ),
      http.get('/api/v1/cases/c1/files', ({ request }) => {
        const url = new URL(request.url)
        const page = Number(url.searchParams.get('page') ?? 1)
        const pageSize = Number(url.searchParams.get('page_size') ?? 100)
        filesRequests.push({
          page,
          extensions: url.searchParams.get('extensions') ?? '',
          known: url.searchParams.get('known'),
        })
        const start = (page - 1) * pageSize
        return HttpResponse.json({
          items: many.slice(start, start + pageSize),
          total_count: many.length,
          page,
          page_size: pageSize,
          total_pages: 3,
          has_next: start + pageSize < many.length,
          has_previous: page > 1,
        })
      }),
    )
    renderPage()

    // Only the first page is fetched, but the count reports the true total —
    // no "100 of 250" and no whole-case download.
    expect(await screen.findByText('IMG_0.jpg')).toBeInTheDocument()
    expect(screen.getByText('250 images')).toBeInTheDocument()
    expect(filesRequests.map((r) => r.page)).toEqual([1])
    expect(screen.queryByText('IMG_100.jpg')).not.toBeInTheDocument()
    // Every image extension is covered by that one request.
    expect(filesRequests[0].extensions).toContain('jpg')
    expect(filesRequests[0].extensions).toContain('heic')

    // Reaching the end of the grid pulls the next page in.
    await userEvent.click(
      screen.getByRole('button', { name: /load more images/i }),
    )
    expect(await screen.findByText('IMG_100.jpg')).toBeInTheDocument()
    await waitFor(() =>
      expect(filesRequests.map((r) => r.page)).toEqual([1, 2]),
    )
  })

  it('warns when the EXIF overlay is short of the records the case holds (B3-040)', async () => {
    mockApi()
    // The case holds far more EXIF records than the overlay pulled in. Images
    // the index has no entry for show no camera, no capture time and no GPS in
    // the lightbox — which reads as a picture stripped of EXIF rather than as a
    // cap. The hash-hit overlay already says so; this one must too.
    server.use(
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ ...exifRecords, total: 90000 }),
      ),
    )
    renderPage()
    await screen.findByText('DSC_0001.jpg')

    expect(
      await screen.findByText(/EXIF annotation partial/i),
    ).toBeInTheDocument()
  })

  it('says nothing about EXIF truncation when the overlay is complete', async () => {
    mockApi()
    server.use(
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ ...exifRecords, total: exifRecords.records.length }),
      ),
    )
    renderPage()
    await screen.findByText('DSC_0001.jpg')

    expect(screen.queryByText(/EXIF annotation partial/i)).toBeNull()
  })

  it('pushes the hash-hit filter to the server so it spans every image', async () => {
    mockApi()
    // The filter control only appears when the case has hash-set data.
    server.use(
      http.get('/api/v1/cases/c1/hash_sets', () =>
        HttpResponse.json([{ id: 'hs1', name: 'Contraband', set_type: 'notable' }]),
      ),
      http.get('/api/v1/cases/c1/hash_hits', () =>
        HttpResponse.json({
          hits: [{ artifact_id: 'img1', hash_set_id: 'hs1', hash_set_name: 'Contraband', set_type: 'notable' }],
          total: 1,
        }),
      ),
    )
    renderPage()
    await screen.findByText('DSC_0001.jpg')

    const filter = await screen.findByLabelText('Hash matches')
    await userEvent.selectOptions(filter, 'notable')
    await waitFor(() =>
      expect(filesRequests.some((r) => r.known === 'notable')).toBe(true),
    )
  })

  it('bookmarks an image from its right-click menu', async () => {
    mockApi()
    const created: { artifact_id: string; category_id?: string }[] = []
    let bookmarked: string[] = []
    server.use(
      http.get('/api/v1/cases/c1/bookmarks/ids', () =>
        HttpResponse.json(bookmarked),
      ),
      http.get('/api/v1/cases/c1/bookmarks/categories', () =>
        HttpResponse.json([{ id: 'cat1', name: 'Evidence', color: '#f00' }]),
      ),
      http.post('/api/v1/cases/c1/bookmarks', async ({ request }) => {
        const body = (await request.json()) as {
          artifact_id: string
          category_id?: string
        }
        created.push(body)
        bookmarked = [...bookmarked, body.artifact_id]
        return HttpResponse.json({ id: 'bm1', artifact_id: body.artifact_id })
      }),
    )
    renderPage()
    const cell = await screen.findByText('DSC_0001.jpg')

    fireEvent.contextMenu(cell)
    // Categories are offered alongside a plain bookmark.
    expect(
      await screen.findByText('Bookmark in Evidence'),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByText('Bookmark image'))

    await waitFor(() => expect(created).toHaveLength(1))
    expect(created[0].artifact_id).toBe('img1')

    // The cell now shows it is bookmarked, and the menu offers removal.
    expect(await screen.findByLabelText('Bookmarked')).toBeInTheDocument()
    // `cell` is the grid label; the sidebar now shows the same filename, so
    // reuse the original node rather than querying the text again.
    fireEvent.contextMenu(cell)
    expect(await screen.findByText('Remove bookmark')).toBeInTheDocument()
  })

  it('toggles the highlighted image bookmark with B', async () => {
    mockApi()
    const created: string[] = []
    const removed: string[] = []
    let bookmarked: string[] = []
    server.use(
      http.get('/api/v1/cases/c1/bookmarks/ids', () =>
        HttpResponse.json(bookmarked),
      ),
      http.get('/api/v1/cases/c1/bookmarks/categories', () =>
        HttpResponse.json([]),
      ),
      http.post('/api/v1/cases/c1/bookmarks', async ({ request }) => {
        const body = (await request.json()) as { artifact_id: string }
        created.push(body.artifact_id)
        bookmarked = [...bookmarked, body.artifact_id]
        return HttpResponse.json({ id: 'bm1' })
      }),
      http.delete('/api/v1/cases/c1/bookmarks/:artifactId', ({ params }) => {
        removed.push(params.artifactId as string)
        bookmarked = bookmarked.filter((id) => id !== params.artifactId)
        return HttpResponse.json({ success: true })
      }),
    )
    renderPage()
    await userEvent.click(await screen.findByText('DSC_0001.jpg'))

    await userEvent.keyboard('b')
    await waitFor(() => expect(created).toEqual(['img1']))
    expect(await screen.findByLabelText('Bookmarked')).toBeInTheDocument()

    // Pressing it again removes the bookmark.
    await userEvent.keyboard('b')
    await waitFor(() => expect(removed).toEqual(['img1']))
  })

  it('labels iOS thumbnail-cache files by their originating photo', async () => {
    // Every size lives under the original photo's name, so the filename alone
    // ("5003.JPG") is the same for thousands of entries.
    server.use(
      http.get('/api/v1/cases/c1/stats/sources', () =>
        HttpResponse.json(sources),
      ),
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ records: [] }),
      ),
      http.get('/api/v1/cases/c1/files', () =>
        HttpResponse.json({
          items: [
            {
              id: 't1',
              name: '5003.JPG',
              path: '/Media/PhotoData/Thumbnails/V2/.../IMG_4902.JPG/5003.JPG',
              extension: 'JPG',
              size: 20108,
              is_directory: false,
              metadata: {},
            },
          ],
          total_count: 1,
          page: 1,
          page_size: 100,
          total_pages: 1,
          has_next: false,
          has_previous: false,
        }),
      ),
    )
    renderPage()
    expect(
      await screen.findByText('IMG_4902.JPG / 5003.JPG'),
    ).toBeInTheDocument()
  })

  it('renders entries whose path is null (iOS-backup files)', async () => {
    // iOS-backup entries record a domain-relative path, so the generated
    // `path` column is empty — most of this case's videos look like this.
    server.use(
      http.get('/api/v1/cases/c1/stats/sources', () =>
        HttpResponse.json(sources),
      ),
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ records: [] }),
      ),
      http.get('/api/v1/cases/c1/files', () =>
        HttpResponse.json({
          items: [
            {
              id: 'n1',
              name: 'CLIP.MOV',
              path: null,
              extension: 'MOV',
              size: 1024,
              is_directory: false,
              metadata: {},
            },
          ],
          total_count: 1,
          page: 1,
          page_size: 100,
          total_pages: 1,
          has_next: false,
          has_previous: false,
        }),
      ),
    )
    renderPage()
    expect(await screen.findByText('CLIP.MOV')).toBeInTheDocument()
  })

  it('switches to a list view with size and date, and sorts server-side', async () => {
    mockApi()
    renderPage()
    await screen.findByText('DSC_0001.jpg')

    // Default: server is asked for name/ascending.
    expect(filesRequests[0]).toMatchObject({ sort: 'name', order: 'asc' })

    await userEvent.click(screen.getByRole('button', { name: 'List' }))
    // The list exposes facts the tiles cannot show without opening each item.
    expect(screen.getByText('Modified')).toBeInTheDocument()
    expect(screen.getByText('2.0 KiB')).toBeInTheDocument()

    // Sorting is pushed to the server, not applied to the loaded page.
    await userEvent.selectOptions(screen.getByLabelText('Sort'), 'size')
    await waitFor(() =>
      expect(filesRequests.at(-1)).toMatchObject({ sort: 'size', order: 'asc' }),
    )
    await userEvent.click(
      screen.getByRole('button', { name: /sort ascending/i }),
    )
    await waitFor(() =>
      expect(filesRequests.at(-1)).toMatchObject({ sort: 'size', order: 'desc' }),
    )
  })

  it('sorts from the list column headers, reversing on a second click', async () => {
    mockApi()
    renderPage()
    await screen.findByText('DSC_0001.jpg')
    await userEvent.click(screen.getByRole('button', { name: 'List' }))

    // The active column is marked, so it is obvious what the order means.
    const nameHeader = screen.getByRole('columnheader', { name: /name/i })
    expect(nameHeader).toHaveAttribute('aria-sort', 'ascending')

    // A new column starts in the direction usually wanted first: largest.
    await userEvent.click(screen.getByRole('columnheader', { name: /size/i }))
    await waitFor(() =>
      expect(filesRequests.at(-1)).toMatchObject({
        sort: 'size',
        order: 'desc',
      }),
    )
    expect(screen.getByRole('columnheader', { name: /size/i })).toHaveAttribute(
      'aria-sort',
      'descending',
    )
    expect(
      screen.getByRole('columnheader', { name: /name/i }),
    ).toHaveAttribute('aria-sort', 'none')

    // Clicking the active column reverses it.
    await userEvent.click(screen.getByRole('columnheader', { name: /size/i }))
    await waitFor(() =>
      expect(filesRequests.at(-1)).toMatchObject({
        sort: 'size',
        order: 'asc',
      }),
    )
  })

  it('shows an empty state when no images are found', async () => {
    server.use(
      http.get('/api/v1/cases/c1/stats/sources', () =>
        HttpResponse.json(sources),
      ),
      http.get('/api/v1/cases/c1/files', () =>
        HttpResponse.json({
          items: [],
          total_count: 0,
          page: 1,
          page_size: 100,
          total_pages: 1,
          has_next: false,
          has_previous: false,
        }),
      ),
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ records: [] }),
      ),
    )
    renderPage()
    expect(await screen.findByText('No images')).toBeInTheDocument()
  })

  it('surfaces a warning when the hash-hit overlay fails to load (BUG-197)', async () => {
    mockApi()
    // A transient hash-hit failure collapses the overlay to empty; without a
    // surfaced error an examiner cannot tell "no hits" from "load failed".
    server.use(
      http.get('/api/v1/cases/c1/hash_hits', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    await screen.findByText('DSC_0001.jpg')

    const warning = await screen.findByText(/hash-hit overlay failed to load/i)
    expect(warning).toBeInTheDocument()
    expect(warning).toHaveAttribute('role', 'alert')
  })

  it('surfaces a warning when the EXIF overlay fails to load (BUG-197)', async () => {
    mockApi()
    server.use(
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    renderPage()
    await screen.findByText('DSC_0001.jpg')

    expect(
      await screen.findByText(/EXIF overlay failed to load/i),
    ).toBeInTheDocument()
  })

  it('resets the source filter to All sources on a case switch (BUG-198)', async () => {
    // The page stays mounted across a case switch (the :caseId param changes in
    // place). A source UUID selected in case 1 must not carry into case 2, where
    // it names a non-existent source and would show an empty gallery while media
    // exists under "All sources".
    function page(items: unknown[]) {
      return {
        items,
        total_count: items.length,
        page: 1,
        page_size: 100,
        total_pages: 1,
        has_next: false,
        has_previous: false,
      }
    }
    const c2SourceFilesHits: string[] = []
    server.use(
      http.get('/api/v1/modules', () => HttpResponse.json([])),
      // ---- Case 1 ----
      http.get('/api/v1/cases/c1/stats/sources', () =>
        HttpResponse.json(sources),
      ),
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ records: [] }),
      ),
      http.get('/api/v1/cases/c1/hash_sets', () => HttpResponse.json([])),
      http.get('/api/v1/cases/c1/hash_hits', () =>
        HttpResponse.json({ hits: [], total: 0 }),
      ),
      http.get('/api/v1/cases/c1/files', () => HttpResponse.json(page(jpgImages))),
      http.get('/api/v1/cases/c1/sources/:sourceId/files', () =>
        HttpResponse.json(page(jpgImages)),
      ),
      // ---- Case 2 (different source id, all-sources listing has content) ----
      http.get('/api/v1/cases/c2/stats/sources', () =>
        HttpResponse.json({
          sources: [
            { source_artifact_id: 's2', name: 'Disk 2', artifact_count: 1 },
          ],
        }),
      ),
      http.get('/api/v1/cases/c2/records', () =>
        HttpResponse.json({ records: [] }),
      ),
      http.get('/api/v1/cases/c2/hash_sets', () => HttpResponse.json([])),
      http.get('/api/v1/cases/c2/hash_hits', () =>
        HttpResponse.json({ hits: [], total: 0 }),
      ),
      http.get('/api/v1/cases/c2/files', () =>
        HttpResponse.json(
          page([
            {
              id: 'c2img',
              name: 'CASE2.jpg',
              path: '/CASE2.jpg',
              extension: 'jpg',
              size: 1,
              is_directory: false,
              metadata: {},
            },
          ]),
        ),
      ),
      // If the stale source id leaked into case 2 this endpoint would be hit and
      // return nothing, leaving the gallery empty (the bug).
      http.get('/api/v1/cases/c2/sources/:sourceId/files', ({ params }) => {
        c2SourceFilesHits.push(params.sourceId as string)
        return HttpResponse.json(page([]))
      }),
    )

    function SwitchCase() {
      const navigate = useNavigate()
      return (
        <button onClick={() => navigate('/cases/c2/gallery')}>go-case2</button>
      )
    }

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/cases/c1/gallery']}>
            <SwitchCase />
            <Routes>
              <Route path="/cases/:caseId/gallery" element={<GalleryPage />} />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )

    await screen.findByText('DSC_0001.jpg')
    // Narrow to a specific source in case 1.
    await userEvent.selectOptions(screen.getByLabelText('Source'), 's1')
    expect(screen.getByLabelText('Source')).toHaveValue('s1')

    // Switch case; the source filter must snap back to "All sources".
    await userEvent.click(screen.getByText('go-case2'))
    expect(await screen.findByText('CASE2.jpg')).toBeInTheDocument()
    expect(screen.getByLabelText('Source')).toHaveValue('all')
    // The gallery landed on case 2's all-sources listing, not the stale id.
    expect(c2SourceFilesHits).not.toContain('s1')
  })
  it('never paints another image properties under the previous highlight (B2-145 class)', async () => {
    // The highlight is an INDEX into the item list. Re-sorting replaces the
    // list, so index N addresses a different picture — and with the new order
    // already cached the swap happens in a single render, with no loading gap
    // in between. Dropping the highlight from a `useEffect` only repairs that
    // after the frame has committed, so the properties sidebar paints one frame
    // of a DIFFERENT image's path, size and hashes as the examiner's pick.
    // `render`/`userEvent` flush passive effects before returning, so only a
    // DOM observer sees that frame at all.
    function page(items: unknown[]) {
      return {
        items,
        total_count: items.length,
        page: 1,
        page_size: 100,
        total_pages: 1,
        has_next: false,
        has_previous: false,
      }
    }
    mockApi()
    // Ordered by the sort the toolbar asks for, so index 1 is a different
    // image under each order.
    server.use(
      http.get('/api/v1/cases/c1/files', ({ request }) => {
        const sort = new URL(request.url).searchParams.get('sort')
        return HttpResponse.json(
          page(sort === 'size' ? [...jpgImages].reverse() : jpgImages),
        )
      }),
    )
    const rowAt = (index: number) =>
      document.querySelector(`[data-idx="${index}"]`)?.textContent ?? ''

    const frames: (string | null)[] = []
    const snapshot = () =>
      document.querySelector('[aria-label="image properties"]')?.textContent ??
      null

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/cases/c1/gallery']}>
            <Routes>
              <Route path="/cases/:caseId/gallery" element={<GalleryPage />} />
            </Routes>
            <FrameSpy capture={snapshot} frames={frames} />
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )

    await screen.findByText('DSC_0001.jpg')
    await userEvent.click(screen.getByRole('button', { name: 'List' }))

    // Largest first: DSC_0002, then DSC_0001. Pick the second row, and wait
    // for the re-sorted rows to be on screen before picking so the index the
    // click sets is the one under test.
    await userEvent.click(screen.getByRole('columnheader', { name: /size/i }))
    await waitFor(() => expect(rowAt(0)).toContain('DSC_0002.jpg'))
    await userEvent.click(screen.getByText('DSC_0001.jpg'))
    const sidebar = screen.getByRole('complementary', {
      name: 'image properties',
    })
    expect(within(sidebar).getByText('/DCIM/DSC_0001.jpg')).toBeInTheDocument()

    // Back to name order, which is already cached: the list is replaced in one
    // render and index 1 is now DSC_0002.
    frames.length = 0
    await userEvent.click(screen.getByRole('columnheader', { name: /name/i }))

    // The harness must have seen the re-sort at all, or the loop proves nothing.
    expect(frames.length).toBeGreaterThan(0)
    for (const frame of frames) {
      expect(frame ?? '').not.toContain('/DCIM/DSC_0002.jpg')
    }
  })
})

/**
 * The standard incompleteness pair in the gallery.
 *
 * A picture whose bytes were only partly recovered still renders — as a
 * thumbnail that looks like a picture. The toolbar chip says how many, and the
 * tile says which: a count on its own is not something an examiner can act on
 * in a grid of several hundred thumbnails.
 */
describe('GalleryPage incompleteness', () => {
  function mockWithPartialImage(metadata: Record<string, unknown>) {
    mockApi()
    server.use(
      http.get('/api/v1/cases/c1/files', () =>
        HttpResponse.json({
          items: [
            { ...jpgImages[0], metadata },
            jpgImages[1],
          ],
          total_count: 2,
          page: 1,
          page_size: 100,
          total_pages: 1,
          has_next: false,
          has_previous: false,
        }),
      ),
    )
  }

  it('chips the count and the reason when an image is only partly recovered', async () => {
    mockWithPartialImage({
      content_incomplete: true,
      content_incomplete_reason: 'cap_reached',
    })
    renderPage()

    await screen.findByText('DSC_0001.jpg')
    const notes = await screen.findAllByRole('note')
    // The toolbar chip specifically: it is the one whose accessible name opens
    // with the proportion. The per-tile badges also carry role="note".
    const chip = notes.find((n) =>
      /^1 of the 2 images/.test(n.getAttribute('aria-label') ?? ''),
    )
    expect(chip).toBeDefined()
    expect(chip).toHaveAccessibleName(/1 of the 2 images/)
    expect(chip).toHaveAccessibleName(/safety cap/)
  })

  it('marks the tile itself, so the count points at a picture', async () => {
    // A toolbar reading "1 incomplete" over 400 thumbnails names a problem and
    // no way to reach it. The badge on the tile is what an examiner acts on.
    mockWithPartialImage({
      content_incomplete: true,
      content_incomplete_reason: 'short_read',
    })
    renderPage()

    await screen.findByText('DSC_0001.jpg')
    const notes = await screen.findAllByRole('note')
    // The per-item badge, not the toolbar chip: the chip's accessible name
    // opens with its proportion, the badge's with the word itself.
    const tileBadge = notes.find((n) =>
      (n.getAttribute('aria-label') ?? '').startsWith('incomplete —'),
    )
    expect(tileBadge).toBeDefined()
    expect(tileBadge).toHaveAccessibleName(
      /fewer bytes than the structure requires/,
    )
  })

  it('shows no chip and marks no tile when every image is whole', async () => {
    mockWithPartialImage({})
    renderPage()

    await screen.findByText('DSC_0001.jpg')
    expect(screen.queryByText(/1 incomplete/)).not.toBeInTheDocument()
    expect(screen.queryByText(/⚠ incomplete/)).not.toBeInTheDocument()
  })
})

/**
 * The gallery is the surface most likely to hold hundreds of thousands of
 * items, and it used to mount every one of them: a button, an
 * IntersectionObserver, a react-query subscription and — for anything that
 * scrolled past once — a decoded image and an object URL, per picture.
 */
describe('GalleryPage windowing', () => {
  const COLUMNS = 4
  const ROW_HEIGHT = 200
  /** Loaded in the browser; the case holds far more. */
  const LOADED = 400
  const POPULATION = 260_000

  const manyImages = Array.from({ length: LOADED }, (_, i) => ({
    id: `w${i}`,
    name: `W_${String(i).padStart(5, '0')}.jpg`,
    path: `/DCIM/W_${String(i).padStart(5, '0')}.jpg`,
    extension: 'jpg',
    size: 1000 + i,
    is_directory: false,
    metadata: {},
  }))

  function mockManyImages() {
    server.use(
      http.get('/api/v1/cases/c1/stats/sources', () =>
        HttpResponse.json(sources),
      ),
      http.get('/api/v1/modules', () => HttpResponse.json([])),
      http.get('/api/v1/cases/c1/files', ({ request }) => {
        const url = new URL(request.url)
        const page = Number(url.searchParams.get('page') ?? 1)
        const pageSize = Number(url.searchParams.get('page_size') ?? 100)
        const start = (page - 1) * pageSize
        return HttpResponse.json({
          items: manyImages.slice(start, start + pageSize),
          total_count: POPULATION,
          page,
          page_size: pageSize,
          total_pages: Math.ceil(POPULATION / pageSize),
          has_next: start + pageSize < LOADED,
          has_previous: page > 1,
        })
      }),
      http.get('/api/v1/cases/c1/records', () =>
        HttpResponse.json({ records: [] }),
      ),
      http.get('/api/v1/cases/c1/hash_sets', () => HttpResponse.json([])),
      http.get('/api/v1/cases/c1/hash_hits', () =>
        HttpResponse.json({ hits: [], total: 0 }),
      ),
      http.get('/api/v1/cases/c1/artifacts/:artifactId/thumbnail', () =>
        HttpResponse.json({}, { status: 404 }),
      ),
    )
  }

  /**
   * jsdom has no layout, and without one the windowing component deliberately
   * renders everything (slow beats silently short). Stand in a four-column grid
   * so the window can actually be computed.
   */
  const realRect = Element.prototype.getBoundingClientRect
  const realOffsetTop = Object.getOwnPropertyDescriptor(
    HTMLElement.prototype,
    'offsetTop',
  )
  function installLayout() {
    Object.defineProperty(HTMLElement.prototype, 'offsetTop', {
      configurable: true,
      get(this: HTMLElement) {
        const idx = this.dataset?.idx
        if (idx == null) return 0
        return Math.floor(Number(idx) / COLUMNS) * ROW_HEIGHT
      },
    })
    Element.prototype.getBoundingClientRect = function (this: Element): DOMRect {
      const el = this as HTMLElement
      const kind = el.dataset?.virtual
      if (kind !== 'top' && kind !== 'bottom') {
        return { top: 0, bottom: 0, height: 0 } as DOMRect
      }
      const topSpacer = document.querySelector<HTMLElement>(
        '[data-virtual="top"]',
      )
      const pad = parseFloat(topSpacer?.style.height ?? '0') || 0
      const renderedRows = Math.ceil(
        document.querySelectorAll('[data-idx]').length / COLUMNS,
      )
      const top = kind === 'top' ? 0 : pad + renderedRows * ROW_HEIGHT
      return {
        top,
        bottom: top + (kind === 'top' ? pad : 0),
        height: kind === 'top' ? pad : 0,
      } as DOMRect
    }
  }
  function restoreLayout() {
    Element.prototype.getBoundingClientRect = realRect
    if (realOffsetTop) {
      Object.defineProperty(HTMLElement.prototype, 'offsetTop', realOffsetTop)
    }
  }

  const cellIndices = () =>
    Array.from(document.querySelectorAll<HTMLElement>('[data-idx]')).map((el) =>
      Number(el.dataset.idx),
    )

  it('mounts a window of tiles while the count stays the population', async () => {
    installLayout()
    try {
      mockManyImages()
      renderPage()

      await screen.findByText('W_00000.jpg')
      // One server page is 100 images; a window over them is fewer still.
      await waitFor(() => expect(cellIndices().length).toBeLessThan(100))
      // The headline count is the case's population, never the rendered slice
      // and never the loaded page — this is the number that gets quoted.
      expect(screen.getByText('260,000 images')).toBeInTheDocument()
    } finally {
      restoreLayout()
    }
  })

  it('says how many of the population are actually in the browser', async () => {
    installLayout()
    try {
      mockManyImages()
      renderPage()

      await screen.findByText('W_00000.jpg')
      // Windowing makes this necessary: with only a slice on screen, an
      // examiner cannot tell how much of the set their keyboard can even reach.
      const note = await screen.findByTestId('gl-loaded')
      expect(note.textContent).toMatch(/100 of 260,000 loaded/)
    } finally {
      restoreLayout()
    }
  })

  it('keeps End reaching the last loaded item, not the last rendered one', async () => {
    installLayout()
    try {
      mockManyImages()
      renderPage()

      await screen.findByText('W_00000.jpg')
      await waitFor(() => expect(cellIndices().length).toBeLessThan(100))
      const last = 99

      await userEvent.keyboard('{End}')

      // The cell the keyboard moved onto has to exist, or the rendered slice is
      // deciding how far the examiner can go.
      await waitFor(() => expect(cellIndices()).toContain(last))
      expect(
        document
          .querySelector(`[data-idx="${last}"]`)
          ?.getAttribute('aria-selected'),
      ).toBe('true')
    } finally {
      restoreLayout()
    }
  })
})
