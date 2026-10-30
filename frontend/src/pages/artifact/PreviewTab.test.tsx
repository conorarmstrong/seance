import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { useState } from 'react'
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { FrameSpy } from '../../test/frames'
import { PreviewTab } from './PreviewTab'

const createObjectURL = vi.fn(() => 'blob:mock')
const revokeObjectURL = vi.fn()

beforeAll(() => {
  URL.createObjectURL = createObjectURL
  URL.revokeObjectURL = revokeObjectURL
})

beforeEach(() => {
  createObjectURL.mockClear()
  // One test issues a distinct handle per blob; put the shared stub back so it
  // cannot leak into the tests that assert on the constant.
  createObjectURL.mockImplementation(() => 'blob:mock')
  revokeObjectURL.mockClear()
  // Any artifact's content resolves to a few bytes (played from an authed blob).
  server.use(
    http.get('/api/v1/cases/:caseId/artifacts/:artifactId/content', () =>
      HttpResponse.arrayBuffer(new Uint8Array([0, 0, 0, 0]).buffer, {
        headers: { 'Content-Type': 'video/mp4' },
      }),
    ),
  )
})

function renderVideo(artifactId: string, name: string) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const ui = (id: string, n: string) => (
    <QueryClientProvider client={client}>
      <PreviewTab
        caseId="c1"
        artifactId={id}
        kind="video"
        name={n}
        sizeHint={null}
      />
    </QueryClientProvider>
  )
  const utils = render(ui(artifactId, name))
  return { ...utils, ui }
}

describe('PreviewTab video (BUG-109)', () => {
  it('clears a prior decode failure when the artifact changes', async () => {
    const { container, rerender, ui } = renderVideo('art-A', 'clip.mkv')

    // The bytes are fetched with auth and played from a blob URL.
    const video = await waitFor(() => {
      const el = container.querySelector('video')
      if (!el) throw new Error('video not rendered yet')
      return el
    })
    expect(video).toHaveAttribute('src', 'blob:mock')

    // The browser can't decode this codec — fall back to the download card.
    fireEvent.error(video)
    expect(
      await screen.findByText("Can't play this video"),
    ).toBeInTheDocument()

    // Navigating to a different (playable) video reuses the instance; the stale
    // failure must clear so the new video is not stuck on the error card. Once
    // the new blob loads, the <video> renders again (which it only can if the
    // failure was cleared).
    rerender(ui('art-B', 'clip.mp4'))
    await waitFor(() =>
      expect(container.querySelector('video')).toBeInTheDocument(),
    )
    expect(
      screen.queryByText("Can't play this video"),
    ).not.toBeInTheDocument()
  })
})

describe('PreviewTab text (B2-148 class)', () => {
  const CHUNK = 262144

  /** Serves 256 KiB ranges from a two-chunk file, recording what was asked for. */
  function mockRanges(asked: string[]) {
    server.use(
      http.get(
        '/api/v1/cases/c1/artifacts/:artifactId/content',
        ({ params, request }) => {
          const range = request.headers.get('Range') ?? ''
          asked.push(`${params.artifactId} ${range}`)
          const start = Number(/bytes=(\d+)-/.exec(range)?.[1] ?? 0)
          const total = 2 * CHUNK
          const body = new Uint8Array(Math.min(CHUNK, total - start))
          body.fill(params.artifactId === 'art-A' ? 0x41 : 0x42)
          return HttpResponse.arrayBuffer(body.buffer, {
            status: 206,
            headers: {
              'Content-Range': `bytes ${start}-${start + body.length - 1}/${total}`,
            },
          })
        },
      ),
    )
  }

  it('previews the new artifact from the start, not at the old chunk count', async () => {
    // How much has been loaded belongs to the artifact it was loaded from.
    // Reset in a `useEffect`, the previous artifact's chunk count is still in
    // the query key on the render where the ids have already changed, so the
    // new artifact is fetched at the old one's depth — reads past the end of a
    // smaller file, captioned as that file's own preview.
    const asked: string[] = []
    mockRanges(asked)

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const ui = (artifactId: string) => (
      <QueryClientProvider client={client}>
        <PreviewTab
          caseId="c1"
          artifactId={artifactId}
          kind="text"
          name={`${artifactId}.log`}
          sizeHint={null}
        />
      </QueryClientProvider>
    )
    const { rerender } = render(ui('art-A'))

    await screen.findByRole('button', { name: 'Load more' })
    expect(asked).toEqual([`art-A bytes=0-${CHUNK - 1}`])
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await waitFor(() =>
      expect(asked).toContain(`art-A bytes=${CHUNK}-${2 * CHUNK - 1}`),
    )

    rerender(ui('art-B'))
    await waitFor(() => expect(asked).toContain(`art-B bytes=0-${CHUNK - 1}`))

    expect(asked.filter((a) => a.startsWith('art-B'))).toEqual([
      `art-B bytes=0-${CHUNK - 1}`,
    ])
    // And the caption describes what was actually loaded for THIS artifact.
    expect(
      await screen.findByText(/Text preview of the first 256 KiB/),
    ).toBeInTheDocument()
  })
})

describe('PreviewTab image bytes (object-URL scope)', () => {
  it('never paints the previous artifact bytes under the new artifact name', async () => {
    // The object URL is a handle to ONE artifact's bytes. Created and cleared
    // in a `useEffect` keyed on the blob, it still addresses the previous
    // artifact in the render where the ids have already changed — and that
    // frame commits, so an `<img>` of exhibit A is painted with exhibit B's
    // filename on it. Passive effects repair it a frame later, which is why
    // `render`/`userEvent` leave no trace and only a DOM observer sees it.
    let issued = 0
    createObjectURL.mockImplementation(() => `blob:${(issued += 1)}`)
    server.use(
      http.get(
        '/api/v1/cases/c1/artifacts/:artifactId/content',
        ({ params }) =>
          HttpResponse.arrayBuffer(
            new Uint8Array(params.artifactId === 'art-A' ? [1] : [2, 2]).buffer,
            { headers: { 'Content-Type': 'image/png' } },
          ),
      ),
    )

    // The switch has to be a real interaction, not a `rerender`: passive
    // effects are flushed inside the same synchronous act block as a rerender,
    // so the intermediate frame would never reach the observer.
    function Harness() {
      const [id, setId] = useState('art-A')
      return (
        <>
          <button type="button" onClick={() => setId('art-B')}>
            Next exhibit
          </button>
          <PreviewTab
            caseId="c1"
            artifactId={id}
            kind="image"
            name={`${id}.png`}
            sizeHint={null}
          />
        </>
      )
    }

    const frames: (string | null)[] = []
    const snapshot = () => {
      const img = document.querySelector('img')
      return img ? `${img.getAttribute('alt')}|${img.getAttribute('src')}` : null
    }
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <Harness />
        <FrameSpy capture={snapshot} frames={frames} />
      </QueryClientProvider>,
    )

    const first = await screen.findByRole('img')
    expect(first).toHaveAttribute('alt', 'art-A.png')
    expect(first).toHaveAttribute('src', 'blob:1')

    frames.length = 0
    await userEvent.click(screen.getByRole('button', { name: 'Next exhibit' }))

    // The observer must have seen the switch at all, or the loop below proves
    // nothing.
    expect(frames.length).toBeGreaterThan(0)
    for (const frame of frames) {
      expect(frame).not.toBe('art-B.png|blob:1')
    }

    // And it settles on art-B's own bytes, so the scoping did not cost the
    // preview its picture.
    await waitFor(() =>
      expect(screen.getByRole('img')).toHaveAttribute('src', 'blob:2'),
    )
    expect(screen.getByRole('img')).toHaveAttribute('alt', 'art-B.png')
  })
})
