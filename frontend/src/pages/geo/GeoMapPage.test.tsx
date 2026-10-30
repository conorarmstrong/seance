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
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { projectLonLat } from '../../components/viz/WorldMap'
import { server } from '../../test/server'
import { GeoMapPage } from './GeoMapPage'
import { resetThumbnailCache } from './GeoHoverCard'
import type { GpsPoint } from './api'

// Stubbed so opting into the live map in a test cannot reach OpenStreetMap's
// tile servers (and so Leaflet does not need a laid-out DOM). What matters here
// is which map the page decided to render, not how it draws.
vi.mock('./LeafletMap', () => ({
  LeafletMap: () => <div data-testid="leaflet-map" />,
}))

// The server now applies the record rules and returns finished GpsPoints (the
// has_gps=false exif is excluded server-side, so it simply isn't in this list).
const defaultPoints: GpsPoint[] = [
  {
    id: 'exif1',
    type: 'exif',
    lat: 51.5,
    lon: 0.5,
    camera: 'PENTAX K-1',
    timestamp: '2024:03:04 09:10:11',
    sourceName: 'DSC_0001.jpg',
    // The photo behind the coordinates: the EXIF record's parent FileEntry.
    imageId: 'img1',
  },
  {
    id: 'loc1',
    type: 'browser_location',
    lat: 40,
    lon: -74,
    camera: null,
    timestamp: null,
    sourceName: 'History',
  },
]

let thumbnailRequests: string[] = []

// The server returns points under `items`, like every other capped listing,
// alongside `undecodable`. These mocks used to answer with `{ points }`, which
// no server build has ever sent: the client read `res.points`, got `undefined`,
// and drew every case as having no GPS at all — while this suite passed,
// because producer and consumer agreed here and nowhere else.
function mockApi(
  points: GpsPoint[] = defaultPoints,
  undecodable: number | null = 0,
) {
  server.use(
    http.get('/api/v1/cases/c1/geo/points', () =>
      HttpResponse.json({ items: points, undecodable }),
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
  )
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/c1/geo']}>
          <Routes>
            <Route path="/cases/:caseId/geo" element={<GeoMapPage />} />
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

beforeEach(() => {
  vi.restoreAllMocks()
  thumbnailRequests = []
  resetThumbnailCache()
  URL.createObjectURL = vi.fn(() => 'blob:thumb')
  URL.revokeObjectURL = vi.fn()
})

describe('GeoMapPage', () => {
  // GEO-001. The server has always answered with `items`; the client read
  // `points`. Every case rendered as "no GPS points", however many fixes it
  // held, and no test caught it because the mocks encoded the client's belief
  // rather than the server's contract. Pinned against the real wire key so a
  // revert fails here instead of in front of an examiner.
  it('reads the point array the server actually sends', async () => {
    server.use(
      http.get('/api/v1/cases/c1/geo/points', () =>
        HttpResponse.json({ items: defaultPoints, undecodable: 0 }),
      ),
    )
    renderPage()
    expect(await screen.findByTestId('geo-dot-exif1')).toBeInTheDocument()
    expect(screen.queryByText(/no GPS points/i)).not.toBeInTheDocument()
  })

  // A map drawn from some of the fixes must not read as a map of all of them.
  it('says how many fixes could not be decoded onto the map', async () => {
    mockApi(defaultPoints, 7)
    renderPage()
    expect(await screen.findByTestId('geo-dot-exif1')).toBeInTheDocument()
    expect(
      screen.getByText(/7 further records carry a fix that could not be decoded/i),
    ).toBeInTheDocument()
  })

  it('claims no shortfall when the server reports none', async () => {
    mockApi(defaultPoints, 0)
    renderPage()
    expect(await screen.findByTestId('geo-dot-exif1')).toBeInTheDocument()
    expect(screen.queryByText(/could not be decoded/i)).not.toBeInTheDocument()
  })

  it('plots GPS points with the equirectangular projection', async () => {
    mockApi()
    renderPage()

    const exifDot = await screen.findByTestId('geo-dot-exif1')
    const [ex, ey] = projectLonLat(0.5, 51.5)
    expect(exifDot).toHaveAttribute('data-cx', String(ex)) // 180.5
    expect(exifDot).toHaveAttribute('data-cy', String(ey)) // 38.5

    const locDot = screen.getByTestId('geo-dot-loc1')
    const [lx, ly] = projectLonLat(-74, 40)
    expect(locDot).toHaveAttribute('data-cx', String(lx)) // 106
    expect(locDot).toHaveAttribute('data-cy', String(ly)) // 50

    // has_gps=false exif record is not plotted.
    expect(screen.queryByTestId('geo-dot-exif2')).not.toBeInTheDocument()
    expect(screen.getByText(/2 GPS points/)).toBeInTheDocument()
  })

  it('shows point detail with a jump-to-artifact link on click', async () => {
    mockApi()
    renderPage()
    await userEvent.click(await screen.findByTestId('geo-dot-exif1'))

    const detail = await screen.findByTestId('geo-detail')
    expect(within(detail).getByText('PENTAX K-1')).toBeInTheDocument()
    expect(within(detail).getByText('DSC_0001.jpg')).toBeInTheDocument()
    expect(
      within(detail).getByRole('link', { name: 'Jump to artifact' }),
    ).toHaveAttribute('href', '/cases/c1/artifacts/exif1')
  })

  it('copies coordinates from the detail panel', async () => {
    mockApi()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    renderPage()
    await userEvent.click(await screen.findByTestId('geo-dot-exif1'))
    const detail = await screen.findByTestId('geo-detail')
    await userEvent.click(within(detail).getByRole('button', { name: 'copy' }))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('51.5, 0.5'))
  })

  it('previews the photo thumbnail when hovering a point', async () => {
    mockApi()
    renderPage()
    await userEvent.hover(await screen.findByTestId('geo-dot-exif1'))

    // The thumbnail is fetched for the IMAGE (the record's parent), not the
    // EXIF record itself.
    await waitFor(() => expect(thumbnailRequests).toEqual(['img1']))
    const img = await screen.findByTestId('geo-hover-thumb')
    expect(img).toHaveAttribute('src', 'blob:thumb')
    expect(screen.getByText('51.50000, 0.50000')).toBeInTheDocument()

    // Leaving the point dismisses the card.
    await userEvent.unhover(screen.getByTestId('geo-dot-exif1'))
    await waitFor(() =>
      expect(screen.queryByText('51.50000, 0.50000')).not.toBeInTheDocument(),
    )
  })

  it('says when a hover preview was not decoded from the photo itself (B8-004)', async () => {
    // `X-Thumbnail-Source: device-cache` — the pixels came from the phone's own
    // thumbnail cache or a video keyframe, not from the geotagged file. Such a
    // preview can outlive and disagree with the picture it was made from, so
    // the card must not present it as a rendering of the evidence.
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
    await userEvent.hover(await screen.findByTestId('geo-dot-exif1'))

    expect(await screen.findByTestId('geo-hover-thumb')).toBeInTheDocument()
    const badge = screen.getByTestId('geo-derived-thumb')
    expect(badge.getAttribute('aria-label')).toMatch(
      /not decoded from this file/i,
    )
  })

  it('requires confirmation before switching to the OpenStreetMap layer', async () => {
    mockApi()
    renderPage()
    await userEvent.click(
      await screen.findByRole('button', { name: /live map/i }),
    )

    // A warning names the privacy trade-off before any tile is requested.
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/OpenStreetMap's servers/)).toBeInTheDocument()

    // Cancelling keeps the offline map (its dots are still plotted).
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(screen.getByTestId('geo-dot-exif1')).toBeInTheDocument()
  })

  it('shows an empty state when no records carry coordinates', async () => {
    mockApi([])
    renderPage()
    expect(
      await screen.findByText('No GPS coordinates'),
    ).toBeInTheDocument()
  })

  it('does not carry the movement-track scrubber into another case', async () => {
    // The scrubber position is an index into THIS case's track, and the page
    // stays mounted when `:caseId` changes. Carried over, it cuts case 2's
    // journey short at a point that means nothing there, with nothing on
    // screen saying the track was truncated.
    const timed = (id: string, when: string): GpsPoint => ({
      id,
      type: 'exif',
      lat: 51,
      lon: 0,
      camera: null,
      timestamp: when,
      sourceName: `${id}.jpg`,
    })
    const c1 = [
      timed('a1', '2024:03:04 09:00:00'),
      timed('a2', '2024:03:04 10:00:00'),
      timed('a3', '2024:03:04 11:00:00'),
    ]
    const c2 = [
      timed('b1', '2025:01:02 09:00:00'),
      timed('b2', '2025:01:02 10:00:00'),
      timed('b3', '2025:01:02 11:00:00'),
    ]
    server.use(
      http.get('/api/v1/cases/c1/geo/points', () =>
        HttpResponse.json({ items: c1, undecodable: 0 }),
      ),
      http.get('/api/v1/cases/c2/geo/points', () =>
        HttpResponse.json({ items: c2, undecodable: 0 }),
      ),
    )

    function CaseSwitcher() {
      const navigate = useNavigate()
      return (
        <button type="button" onClick={() => navigate('/cases/c2/geo')}>
          Go to c2
        </button>
      )
    }
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/cases/c1/geo']}>
            <Routes>
              <Route
                path="/cases/:caseId/geo"
                element={
                  <>
                    <GeoMapPage />
                    <CaseSwitcher />
                  </>
                }
              />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )

    await screen.findByTestId('geo-dot-a1')
    await userEvent.click(screen.getByRole('checkbox', { name: /movement track/i }))
    fireEvent.change(screen.getByLabelText('Reveal track up to time'), {
      target: { value: '1' },
    })
    expect(screen.getByText('1 / 3')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    expect(await screen.findByTestId('geo-dot-b1')).toBeInTheDocument()
    expect(
      screen.getByRole('checkbox', { name: /movement track/i }),
    ).not.toBeChecked()
    expect(screen.queryByText('1 / 3')).not.toBeInTheDocument()
  })

  it('asks again before sending another case’s coordinates to OpenStreetMap', async () => {
    // The confirmation is given for the coordinates of the case on screen.
    // Held in plain state it survived a `:caseId` change (the workbench mounts
    // this page by prop, and nothing there forces a remount), so the next
    // case's locations would go to a third party without anyone being asked.
    const point = (id: string, lat: number): GpsPoint => ({
      id,
      type: 'exif',
      lat,
      lon: 0,
      camera: null,
      timestamp: null,
      sourceName: `${id}.jpg`,
    })
    server.use(
      http.get('/api/v1/cases/c1/geo/points', () =>
        HttpResponse.json({ items: [point('a1', 51)], undecodable: 0 }),
      ),
      http.get('/api/v1/cases/c2/geo/points', () =>
        HttpResponse.json({ items: [point('b1', 40)], undecodable: 0 }),
      ),
    )

    function CaseSwitcher() {
      const navigate = useNavigate()
      return (
        <button type="button" onClick={() => navigate('/cases/c2/geo')}>
          Go to c2
        </button>
      )
    }
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/cases/c1/geo']}>
            <Routes>
              <Route
                path="/cases/:caseId/geo"
                element={
                  <>
                    <GeoMapPage />
                    <CaseSwitcher />
                  </>
                }
              />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )

    await screen.findByTestId('geo-dot-a1')
    await userEvent.click(screen.getByRole('button', { name: /live map/i }))
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Use OpenStreetMap',
      }),
    )
    expect(await screen.findByTestId('leaflet-map')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Go to c2' }))

    // Case 2 comes up on the offline map, with the opt-in on offer again.
    expect(await screen.findByTestId('geo-dot-b1')).toBeInTheDocument()
    expect(screen.queryByTestId('leaflet-map')).toBeNull()
    expect(
      screen.getByRole('button', { name: /live map/i }),
    ).toBeInTheDocument()
  })
})

describe('the coordinate list', () => {
  // UI-029. 14,804 rows headed by eight characters of an artifact id, in the
  // order the database returned them. A location list is read to answer "where
  // was this, and when" — the time is the point, and it was not on screen.
  it('leads with the time and puts the newest first', async () => {
    server.use(
      http.get("/api/v1/cases/c1/geo/points", () =>
        HttpResponse.json({
          items: [
            {
              id: 'older',
              type: 'CachedLocation',
              lat: 44.4772,
              lon: -73.2213,
              camera: null,
              timestamp: '2022-02-12T09:58:03Z',
              sourceName: null,
            },
            {
              id: 'newest',
              type: 'CachedLocation',
              lat: 38.8441,
              lon: -77.2868,
              camera: null,
              timestamp: '2022-02-14T18:26:03Z',
              sourceName: null,
            },
          ],
          undecodable: 0,
        }),
      ),
    )
    renderPage()

    const rows = await screen.findAllByRole('button', { name: /2022-02/ })
    expect(rows[0].textContent).toContain('2022-02-14 18:26:03 UTC')
    expect(rows[0].textContent).toContain('38.8441, -77.2868')
    expect(rows[1].textContent).toContain('2022-02-12 09:58:03 UTC')
  })

  it('calls an undated point undated rather than sorting it to the top', async () => {
    server.use(
      http.get("/api/v1/cases/c1/geo/points", () =>
        HttpResponse.json({
          items: [
            {
              id: 'undated',
              type: 'CachedLocation',
              lat: 1,
              lon: 1,
              camera: null,
              timestamp: null,
              sourceName: null,
            },
            {
              id: 'dated',
              type: 'CachedLocation',
              lat: 2,
              lon: 2,
              camera: null,
              timestamp: '2022-02-14T18:26:03Z',
              sourceName: null,
            },
          ],
          undecodable: 0,
        }),
      ),
    )
    renderPage()

    expect(await screen.findByText('undated')).toBeInTheDocument()
    const rows = screen.getAllByRole('button', { name: /2022-02|undated/ })
    expect(rows[0].textContent).toContain('2022-02-14')
  })
})
