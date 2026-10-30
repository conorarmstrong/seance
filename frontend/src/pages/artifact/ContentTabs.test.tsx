import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { HexTab, TextTab } from './ContentTabs'

/** A hex page whose ascii column is a distinctive marker per artifact. */
function hexPage(ascii: string, hexByte: string) {
  return {
    offset: 0,
    limit: 4096,
    total_size: 4,
    hex: `${hexByte} ${hexByte} ${hexByte} ${hexByte}`,
    ascii,
  }
}

describe('HexTab artifact switching (BUG-068)', () => {
  it('never renders the previous artifact bytes while the new artifact loads', async () => {
    // Artifact B's hex is gated so it is still in flight right after the switch;
    // that is exactly the window where keepPreviousData would otherwise surface
    // artifact A's bytes under artifact B.
    let releaseB: () => void = () => {}
    const gateB = new Promise<void>((resolve) => {
      releaseB = resolve
    })
    server.use(
      http.get(
        '/api/v1/cases/c1/artifacts/:artifactId/hex',
        async ({ params }) => {
          if (params.artifactId === 'art-B') await gateB
          return HttpResponse.json(
            params.artifactId === 'art-A'
              ? hexPage('AAAA', '41')
              : hexPage('BBBB', '42'),
          )
        },
      ),
    )

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )
    expect(await screen.findByText('AAAA')).toBeInTheDocument()

    // Switch to artifact B without unmounting the tab (same component position).
    rerender(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-B" />
      </QueryClientProvider>,
    )

    // The placeholder is artifact A's bytes: they must not be shown under B.
    expect(screen.queryByText('AAAA')).not.toBeInTheDocument()
    expect(screen.getByText('Loading hex data...')).toBeInTheDocument()

    releaseB()
    expect(await screen.findByText('BBBB')).toBeInTheDocument()
    expect(screen.queryByText('AAAA')).not.toBeInTheDocument()
  })
})

describe('HexTab case switching (BUG-259)', () => {
  it('never renders another case bytes for the same artifact id', async () => {
    // Artifact UUIDs are not globally unique across cases, so the stale-data
    // gate has to name the case too — otherwise an in-place case switch keeps
    // case 1's bytes on screen under case 2's chrome.
    let releaseC2: () => void = () => {}
    const gateC2 = new Promise<void>((resolve) => {
      releaseC2 = resolve
    })
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/art-shared/hex',
        async ({ params }) => {
          if (params.caseId === 'c2') await gateC2
          return HttpResponse.json(
            params.caseId === 'c1' ? hexPage('AAAA', '41') : hexPage('BBBB', '42'),
          )
        },
      ),
    )

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-shared" />
      </QueryClientProvider>,
    )
    expect(await screen.findByText('AAAA')).toBeInTheDocument()

    rerender(
      <QueryClientProvider client={client}>
        <HexTab caseId="c2" artifactId="art-shared" />
      </QueryClientProvider>,
    )

    expect(screen.queryByText('AAAA')).not.toBeInTheDocument()
    expect(screen.getByText('Loading hex data...')).toBeInTheDocument()

    releaseC2()
    expect(await screen.findByText('BBBB')).toBeInTheDocument()
    expect(screen.queryByText('AAAA')).not.toBeInTheDocument()
  })
})

describe('HexTab byte-search artifact switching (BUG-146)', () => {
  it('does not attach in-flight byte-search results from a previous artifact', async () => {
    // Artifact A's byte search is gated so it is still in flight when we switch
    // to artifact B; its resolved offsets must not land under B's hex.
    let releaseA: () => void = () => {}
    const gateA = new Promise<void>((resolve) => {
      releaseA = resolve
    })
    server.use(
      http.get('/api/v1/cases/c1/artifacts/:artifactId/hex', ({ params }) =>
        HttpResponse.json(
          params.artifactId === 'art-A'
            ? hexPage('AAAA', '41')
            : hexPage('BBBB', '42'),
        ),
      ),
      http.get('/api/v1/cases/c1/artifacts/art-A/byte-search', async () => {
        await gateA
        return HttpResponse.json({
          pattern_bytes: 1,
          total_size: 4,
          offsets: [4660], // 0x1234 — a distinctive marker for A's matches
          truncated: false,
        })
      }),
      http.get('/api/v1/cases/c1/artifacts/art-B/byte-search', () =>
        HttpResponse.json({
          pattern_bytes: 1,
          total_size: 4,
          offsets: [],
          truncated: false,
        }),
      ),
    )

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )
    await screen.findByText('AAAA')

    // Start a byte search on A (still gated, so in flight).
    await userEvent.type(screen.getByLabelText('Byte pattern (hex)'), 'ff')
    await userEvent.click(screen.getByRole('button', { name: 'Find' }))

    // Switch to B before A's search resolves; its Find button starts fresh.
    rerender(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-B" />
      </QueryClientProvider>,
    )
    await screen.findByText('BBBB')
    expect(screen.getByRole('button', { name: 'Find' })).toBeEnabled()

    // Let A's search resolve: its offset must not appear under B.
    releaseA()
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(screen.queryByText('0x1234')).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('BBBB')).toBeInTheDocument())
  })
})

describe('HexTab offset label (B2-021)', () => {
  it('labels the bytes on screen, never the page that is still loading', async () => {
    // `offset` is deliberately outside the scope key so paging stays smooth,
    // which means keepPreviousData holds the previous page on screen while the
    // next one is fetched. Labelling those bytes "offset 4096" states an
    // address they did not come from: an examiner reading a value out of the
    // grid would record the wrong file offset for it.
    let releaseSecond: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      releaseSecond = resolve
    })
    server.use(
      http.get(
        '/api/v1/cases/c1/artifacts/art-A/hex',
        async ({ request }) => {
          const offset = Number(
            new URL(request.url).searchParams.get('offset') ?? '0',
          )
          if (offset !== 0) await gate
          return HttpResponse.json({
            offset,
            limit: 4096,
            total_size: 8192,
            hex: '41 41 41 41',
            ascii: offset === 0 ? 'PAGE0' : 'PAGE1',
          })
        },
      ),
    )

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )
    expect(await screen.findByText('PAGE0')).toBeInTheDocument()
    expect(screen.getByText(/offset 0 \(0x0\)/)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))

    // Page 1 has not arrived: page 0's bytes are still drawn, so the label must
    // still read offset 0 and say the requested page is on its way.
    expect(screen.getByText('PAGE0')).toBeInTheDocument()
    expect(screen.getByText(/offset 0 \(0x0\)/)).toBeInTheDocument()
    expect(screen.getByText(/loading 0x1000/)).toBeInTheDocument()

    releaseSecond()
    expect(await screen.findByText('PAGE1')).toBeInTheDocument()
    await waitFor(() =>
      expect(screen.getByText(/offset 4096 \(0x1000\)/)).toBeInTheDocument(),
    )
    expect(screen.queryByText(/loading 0x1000/)).not.toBeInTheDocument()
  })
})

describe('HexTab artifact switching, requested offset (B2-148 class)', () => {
  it('never requests the new artifact at the previous artifact’s offset', async () => {
    // `offset` is part of the hex query key. Reset in a `useEffect`, it is
    // still in hand for the whole commit in which `artifactId` has already
    // changed, so react-query asks for artifact B at artifact A's page — past
    // the end of a smaller file. The response is rendered as B's content.
    const asked: { artifactId: string; offset: number }[] = []
    server.use(
      http.get(
        '/api/v1/cases/c1/artifacts/:artifactId/hex',
        ({ params, request }) => {
          const offset = Number(
            new URL(request.url).searchParams.get('offset') ?? '0',
          )
          asked.push({ artifactId: params.artifactId as string, offset })
          return HttpResponse.json({
            offset,
            limit: 4096,
            total_size: 8192,
            hex: '41 41 41 41',
            ascii: `${params.artifactId}@${offset}`,
          })
        },
      ),
    )

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )
    await screen.findByText('art-A@0')
    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await screen.findByText('art-A@4096')

    rerender(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-B" />
      </QueryClientProvider>,
    )
    await screen.findByText('art-B@0')

    expect(asked.some((a) => a.artifactId === 'art-B')).toBe(true)
    for (const ask of asked.filter((a) => a.artifactId === 'art-B')) {
      expect(ask.offset).toBe(0)
    }
  })
})

describe('HexTab byte-search honesty (B2-014)', () => {
  it('says a search that could not read the whole file did not cover it', async () => {
    // The content stopped short of its declared size, so the bytes past that
    // point were never examined. Reporting a bare "0 matches" would let an
    // examiner record that the pattern is absent from the file — a conclusion
    // the search never supported.
    server.use(
      http.get('/api/v1/cases/c1/artifacts/art-A/hex', () =>
        HttpResponse.json(hexPage('AAAA', '41')),
      ),
      http.get('/api/v1/cases/c1/artifacts/art-A/byte-search', () =>
        HttpResponse.json({
          pattern_bytes: 2,
          total_size: 8192,
          offsets: [],
          truncated: false,
          scanned_size: 512,
          incomplete: true,
        }),
      ),
    )

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )
    await screen.findByText('AAAA')

    await userEvent.type(screen.getByLabelText(/byte pattern/i), 'ff d8')
    await userEvent.click(screen.getByRole('button', { name: 'Find' }))

    expect(await screen.findByText(/0 matches/)).toBeInTheDocument()
    expect(screen.getByText(/Searched only 512 of/)).toBeInTheDocument()
  })

  it('says nothing extra when the whole file was searched', async () => {
    server.use(
      http.get('/api/v1/cases/c1/artifacts/art-A/hex', () =>
        HttpResponse.json(hexPage('AAAA', '41')),
      ),
      http.get('/api/v1/cases/c1/artifacts/art-A/byte-search', () =>
        HttpResponse.json({
          pattern_bytes: 2,
          total_size: 8192,
          offsets: [],
          truncated: false,
          scanned_size: 8192,
          incomplete: false,
        }),
      ),
    )

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )
    await screen.findByText('AAAA')

    await userEvent.type(screen.getByLabelText(/byte pattern/i), 'ff d8')
    await userEvent.click(screen.getByRole('button', { name: 'Find' }))

    expect(await screen.findByText(/0 matches/)).toBeInTheDocument()
    expect(screen.queryByText(/Searched only/)).not.toBeInTheDocument()
  })
})

describe('TextTab artifact switching (B2-148 class)', () => {
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
          // Distinct filler per artifact so the decoded text identifies it.
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

  it('loads the new artifact from the start, not at the old chunk count', async () => {
    // `chunkCount` is part of the query key. Reset in a `useEffect`, it is
    // still the previous artifact's value on the render where the ids have
    // already changed, so react-query fetches the NEW artifact at the OLD
    // artifact's depth — ranges past the end of a smaller file, presented as
    // that file's content. Scoped state resolves during render, so the first
    // request for a new artifact is always its first range.
    const asked: string[] = []
    mockRanges(asked)

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const ui = (artifactId: string) => (
      <QueryClientProvider client={client}>
        <TextTab caseId="c1" artifactId={artifactId} />
      </QueryClientProvider>
    )
    const { rerender } = render(ui('art-A'))

    // First range only, then "Load more" pulls the second.
    await screen.findByRole('button', { name: 'Load more' })
    expect(asked).toEqual([`art-A bytes=0-${CHUNK - 1}`])
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await waitFor(() =>
      expect(asked).toContain(`art-A bytes=${CHUNK}-${2 * CHUNK - 1}`),
    )

    rerender(ui('art-B'))
    await waitFor(() =>
      expect(asked).toContain(`art-B bytes=0-${CHUNK - 1}`),
    )

    // Nothing beyond artifact B's first range was ever requested for it.
    expect(asked.filter((a) => a.startsWith('art-B'))).toEqual([
      `art-B bytes=0-${CHUNK - 1}`,
    ])
  })
})

describe('TextTab find over loaded lines (B8-033)', () => {
  it('finds a match past the rendered line limit instead of reporting none', async () => {
    // Only the first 5 000 lines are rendered, but the viewer holds every line
    // it has loaded. Searching the rendered slice made Find answer "0 / 0" for
    // text that is present in the bytes on screen's own buffer — a forensic
    // text search reporting an absence that is not there.
    const lines: string[] = []
    for (let i = 0; i < 5200; i += 1) {
      lines.push(i === 5100 ? 'needle-past-the-window' : `line ${i}`)
    }
    const body = new TextEncoder().encode(lines.join('\n'))
    server.use(
      http.get('/api/v1/cases/c1/artifacts/:artifactId/content', () =>
        HttpResponse.arrayBuffer(body.buffer as ArrayBuffer, {
          status: 206,
          headers: {
            'Content-Range': `bytes 0-${body.length - 1}/${body.length}`,
          },
        }),
      ),
    )
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <TextTab caseId="c1" artifactId="art-long" />
      </QueryClientProvider>,
    )

    const find = await screen.findByPlaceholderText('text to find')
    // Set in one event: 5 000 rendered lines re-render per keystroke.
    fireEvent.change(find, { target: { value: 'needle-past-the-window' } })

    expect(await screen.findByText('1 / 1')).toBeInTheDocument()
    // And it is honest that this match is not one of the highlighted lines.
    expect(
      screen.getByTestId('av-text-match-offscreen').textContent,
    ).toMatch(/past the/i)
    expect(screen.getByTestId('av-text-match-hidden')).toBeInTheDocument()
  })
})

describe('HexTab short reads (B4-022)', () => {
  it('says a page ended in a failed read, not at the end of the object', async () => {
    // The server distinguishes "the page holds fewer bytes because the object
    // ends" from "fewer bytes were readable here": `limit` is what came back,
    // `requested_bytes` is what should have. Discarding the distinction made a
    // sparse or unreadable region mid-file render exactly like the end of the
    // file, while `total_size` still claimed the whole object.
    server.use(
      http.get('/api/v1/cases/c1/artifacts/art-A/hex', () =>
        HttpResponse.json({
          offset: 0,
          limit: 8,
          requested_bytes: 4096,
          total_size: 1_000_000,
          hex: '41 41 41 41 41 41 41 41',
          ascii: 'AAAAAAAA',
          content_incomplete: true,
          content_incomplete_reason: 'short_read',
        }),
      ),
    )
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )

    const note = await screen.findByTestId('av-hex-short')
    expect(note).toHaveTextContent('Only 8 of the 4,096 bytes')
    // The shared vocabulary, so this reads the same as every other surface.
    expect(note).toHaveTextContent(
      /a read returned fewer bytes than the structure requires/,
    )
    expect(note).toHaveTextContent(/not where the content ends/)
  })

  it('still warns when the server declares a short page without naming the figure', async () => {
    // A server that says `content_incomplete` but omits `requested_bytes` has
    // still said the page is short. Requiring both fields to warn dropped the
    // whole alert for want of a number — the fail-open, restored.
    server.use(
      http.get('/api/v1/cases/c1/artifacts/art-A/hex', () =>
        HttpResponse.json({
          offset: 0,
          limit: 8,
          total_size: 1_000_000,
          hex: '41 41 41 41 41 41 41 41',
          ascii: 'AAAAAAAA',
          content_incomplete: true,
          content_incomplete_reason: 'short_read',
        }),
      ),
    )
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )

    const note = await screen.findByTestId('av-hex-short')
    expect(note).toHaveTextContent(/not where the content ends/)
    expect(note).not.toHaveTextContent('NaN')
  })

  it('does not flag the legitimate short last page of a file', async () => {
    // Every file whose size is not a multiple of the page size ends in a short
    // page. A viewer that inferred the warning from `bytes.length < HEX_PAGE`
    // would raise it on all of them, and a warning on every file is a warning
    // an examiner stops reading.
    server.use(
      http.get('/api/v1/cases/c1/artifacts/art-A/hex', () =>
        HttpResponse.json({
          offset: 0,
          limit: 4,
          requested_bytes: 4,
          total_size: 4,
          hex: '41 41 41 41',
          ascii: 'AAAA',
          content_incomplete: false,
          content_incomplete_reason: null,
        }),
      ),
    )
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <HexTab caseId="c1" artifactId="art-A" />
      </QueryClientProvider>,
    )

    expect(await screen.findByText('AAAA')).toBeInTheDocument()
    expect(screen.queryByTestId('av-hex-short')).not.toBeInTheDocument()
  })
})
