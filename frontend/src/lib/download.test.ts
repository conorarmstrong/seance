import { http, HttpResponse } from 'msw'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '../test/server'
import { setToken, clearToken, onUnauthorized } from '../api/http'
import {
  DownloadIncompleteError,
  MEMORY_DISCLOSURE_THRESHOLD_BYTES,
  downloadFile,
  endsWithVerdict,
  verdictStatement,
  type MemoryDisclosure,
} from './download'

const PATH = '/cases/c1/search/export/csv'
const URL_PATH = `/api/v1${PATH}`

const MARKER = '### END OF EXPORT ###'
const TERMINATOR = { marker: MARKER, format: 'csv' as const }
// The preamble's reading note quotes the marker, as the server's does.
const PREAMBLE = `# query,ransom,,,,\n# how_to_read,"ends with a row beginning '${MARKER} VERDICT:'",,,,\n`
const ROW = 'a1,c1,FileEntry,note.txt,"hit",1.0\n'
// The server always quotes the verdict row.
const VERDICT = `"${MARKER} VERDICT: COMPLETE. This file holds all 1 of 1 artifacts.",,,,,\n`

const encoder = new TextEncoder()

/** A response body that arrives in pieces, like the streamed export does. */
function chunked(parts: string[], failAfter?: number): ReadableStream<Uint8Array> {
  let index = 0
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (failAfter != null && index === failAfter) {
        controller.error(new Error('connection reset'))
        return
      }
      if (index >= parts.length) {
        controller.close()
        return
      }
      controller.enqueue(encoder.encode(parts[index]))
      index += 1
    },
  })
}

interface FakeFile {
  handle: FileSystemFileHandle
  /** Everything write() was given, in order. */
  written: () => string
  closed: boolean
  aborted: boolean
  removed: boolean
}

function fakeFile(): FakeFile {
  const chunks: Uint8Array[] = []
  const state = {
    handle: null as unknown as FileSystemFileHandle,
    written: () => {
      const total = chunks.reduce((n, c) => n + c.byteLength, 0)
      const flat = new Uint8Array(total)
      let at = 0
      for (const chunk of chunks) {
        flat.set(chunk, at)
        at += chunk.byteLength
      }
      return new TextDecoder().decode(flat)
    },
    closed: false,
    aborted: false,
    removed: false,
  }
  state.handle = {
    kind: 'file',
    name: 'chosen.csv',
    createWritable: async () => ({
      write: async (chunk: Uint8Array) => {
        chunks.push(new Uint8Array(chunk))
      },
      close: async () => {
        state.closed = true
      },
      abort: async () => {
        state.aborted = true
      },
    }),
    remove: async () => {
      state.removed = true
    },
  } as unknown as FileSystemFileHandle
  return state
}

type Picker = (options: unknown) => Promise<FileSystemFileHandle>

function installPicker(picker: Picker | null) {
  const win = window as unknown as { showSaveFilePicker?: Picker }
  if (picker) win.showSaveFilePicker = picker
  else delete win.showSaveFilePicker
}

/** Collect the anchor-based (in-memory) download, which must stay untouched
 * for the small callers. */
function watchAnchorRoute() {
  const created: string[] = []
  const revoked: string[] = []
  const clicked: string[] = []
  const url = URL as unknown as {
    createObjectURL: (b: Blob) => string
    revokeObjectURL: (u: string) => void
  }
  url.createObjectURL = (blob: Blob) => {
    created.push(`blob:${blob.size}`)
    return `blob:${blob.size}`
  }
  url.revokeObjectURL = (value: string) => {
    revoked.push(value)
  }
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, 'click')
    .mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this.download)
    })
  return { created, revoked, clicked, click }
}

beforeEach(() => {
  installPicker(null)
})

afterEach(() => {
  vi.restoreAllMocks()
  installPicker(null)
  clearToken()
})

describe('downloadFile — streaming to disk', () => {
  it('pipes the body to the chosen file without ever holding it in memory', async () => {
    const file = fakeFile()
    const blob = vi.fn()
    installPicker(async () => file.handle)
    server.use(
      http.get(URL_PATH, () =>
        HttpResponse.text(`${PREAMBLE}${ROW}${VERDICT}`),
      ),
    )
    // If anything routes through response.blob() the whole export is in the
    // tab, which is the defect this exists to remove.
    const originalBlob = Response.prototype.blob
    Response.prototype.blob = blob as unknown as typeof Response.prototype.blob
    try {
      const outcome = await downloadFile(PATH, 'search-results.csv', {
        unbounded: true,
        terminator: TERMINATOR,
      })
      expect(outcome.route).toBe('file-system')
      expect(outcome.cancelled).toBe(false)
      expect(outcome.terminated).toBe(true)
      expect(file.written()).toBe(`${PREAMBLE}${ROW}${VERDICT}`)
      expect(file.closed).toBe(true)
      expect(blob).not.toHaveBeenCalled()
    } finally {
      Response.prototype.blob = originalBlob
    }
  })

  it('leaves nothing behind and reports no failure when the save dialog is cancelled', async () => {
    let requested = 0
    server.use(
      http.get(URL_PATH, () => {
        requested += 1
        return HttpResponse.text('never asked for')
      }),
    )
    installPicker(async () => {
      throw new DOMException('The user aborted a request.', 'AbortError')
    })

    const outcome = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
    })

    expect(outcome.cancelled).toBe(true)
    expect(outcome.bytes).toBe(0)
    // Not even asked for: a cancelled save must not start a 4,000,000-row walk
    // on the server that nothing will ever read.
    expect(requested).toBe(0)
  })

  /**
   * An exhibit is named by the file the examiner saved, never by the name that
   * was suggested to them.
   *
   * `suggestedName` is an opening bid; the save dialog exists so it can be
   * changed, and on this product changing it is the normal act — an export is
   * filed under an exhibit reference, not under `search-results.csv`, which is
   * the same literal string for every case and every query. Every sentence this
   * module produces names a file on the examiner's disk: how many bytes reached
   * it, whether it is whole, and whether it may be tendered. Naming the
   * suggestion sent the examiner looking for a file that does not exist, and
   * left the file that DOES exist — a truncated export under their own exhibit
   * reference — with nothing anywhere saying it was a fragment.
   */
  it('names the file the examiner chose, not the one that was suggested', async () => {
    const file = fakeFile()
    installPicker(async () => file.handle)
    server.use(
      http.get(
        URL_PATH,
        () => new HttpResponse(chunked([PREAMBLE, ROW, ROW], 3)),
      ),
    )

    const failure = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
    }).catch((e: unknown) => e)

    const err = failure as DownloadIncompleteError
    expect(err).toBeInstanceOf(DownloadIncompleteError)
    // The fixture's handle is saved as `chosen.csv` while `search-results.csv`
    // is what was suggested — the divergence a renamed save produces.
    expect(file.handle.name).toBe('chosen.csv')
    expect(err.filename).toBe('chosen.csv')
    expect(
      err.message,
      'the sentence an examiner reads must name the file on their disk',
    ).toContain('chosen.csv')
    expect(
      err.message,
      'naming the suggestion sends them looking for a file that is not there',
    ).not.toContain('search-results.csv')
  })

  it('keeps the fragment and names it a fragment when the transfer dies mid-file', async () => {
    const file = fakeFile()
    installPicker(async () => file.handle)
    server.use(
      http.get(
        URL_PATH,
        () => new HttpResponse(chunked([PREAMBLE, ROW, ROW], 3)),
      ),
    )

    const failure = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
    }).catch((e: unknown) => e)

    expect(failure).toBeInstanceOf(DownloadIncompleteError)
    const err = failure as DownloadIncompleteError
    // The name the examiner saved under, not the one the dialog suggested.
    expect(err.filename).toBe('chosen.csv')
    expect(err.partialFileKept).toBe(true)
    expect(err.message).toContain(MARKER)
    // The bytes that did arrive are on disk, unaltered and un-annotated: the
    // client must never write into an exhibit, and the missing verdict row is
    // the server's own signal that the file is a fragment. How much of the
    // stream survives an error mid-flight is the transport's business — a
    // stream that errors discards whatever it had queued — so what is asserted
    // is the relationship: what is on disk is a non-empty, unmodified PREFIX of
    // what the server was sending, and the reported byte count is exactly what
    // is on disk.
    const written = file.written()
    expect(written.length).toBeGreaterThan(0)
    expect(`${PREAMBLE}${ROW}${ROW}`.startsWith(written)).toBe(true)
    expect(written).not.toContain(TERMINATOR)
    expect(err.bytesWritten).toBe(new TextEncoder().encode(written).byteLength)
    expect(file.closed).toBe(true)
    expect(file.aborted).toBe(false)
  })

  it('reports a disk that refuses the write, and stops reading the export', async () => {
    // The other half of an interrupted stream: the transfer is fine and the
    // FILE is not — a full volume, a revoked permission. The examiner must
    // still be told what is on disk, and the server must stop being asked for
    // rows nothing can write.
    const file = fakeFile()
    // Asserted on the client's own reader rather than on the server's stream:
    // whether msw's transport relays a cancel is msw's business, and what this
    // helper is responsible for is letting go of the body.
    const released = vi.spyOn(ReadableStreamDefaultReader.prototype, 'cancel')
    file.handle.createWritable = (async () => ({
      write: async () => {
        throw new DOMException('The quota has been exceeded.', 'QuotaExceededError')
      },
      close: async () => {},
      abort: async () => {},
    })) as unknown as FileSystemFileHandle['createWritable']
    installPicker(async () => file.handle)
    server.use(
      http.get(URL_PATH, () => {
        const body = new ReadableStream<Uint8Array>({
          pull(controller) {
            controller.enqueue(encoder.encode(ROW))
          },
        })
        return new HttpResponse(body)
      }),
    )

    const failure = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
    }).catch((e: unknown) => e)

    expect(failure).toBeInstanceOf(DownloadIncompleteError)
    expect((failure as Error).message).toContain('quota')
    // Not awaited by the helper — the examiner is not made to wait on a
    // connection nobody wants — but issued before it returns.
    expect(released).toHaveBeenCalled()
  })

  it('refuses to call a truncated file complete when the stream ends without a verdict row', async () => {
    const file = fakeFile()
    installPicker(async () => file.handle)
    // A clean end of stream, but no verdict row — a proxy or a server that
    // stopped. Nothing about the transfer says so; only the missing row does.
    server.use(http.get(URL_PATH, () => HttpResponse.text(`${PREAMBLE}${ROW}`)))

    const failure = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
    }).catch((e: unknown) => e)

    expect(failure).toBeInstanceOf(DownloadIncompleteError)
    expect((failure as Error).message).toContain(MARKER)
    expect(file.written()).toBe(`${PREAMBLE}${ROW}`)
  })

  it('finds the verdict row when it straddles two chunks', async () => {
    const file = fakeFile()
    installPicker(async () => file.handle)
    const half = VERDICT.slice(0, 10)
    const rest = VERDICT.slice(10)
    server.use(
      http.get(
        URL_PATH,
        () => new HttpResponse(chunked([PREAMBLE, ROW, half, rest])),
      ),
    )

    const outcome = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
    })

    expect(outcome.terminated).toBe(true)
    expect(file.written()).toBe(`${PREAMBLE}${ROW}${VERDICT}`)
  })

  it('does not take the marker in the preamble for the verdict row', async () => {
    // A download cut off after the preamble: the reading note quotes the
    // marker, and `includes(marker)` called this fragment complete
    // (CR-033 #4). Nothing but the quoted verdict row at the end will do.
    const file = fakeFile()
    installPicker(async () => file.handle)
    server.use(http.get(URL_PATH, () => HttpResponse.text(PREAMBLE)))

    const failure = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
    }).catch((e: unknown) => e)

    expect(failure).toBeInstanceOf(DownloadIncompleteError)
    expect(file.written()).toBe(PREAMBLE)
  })

  it('does not take a hit row named for the marker for the verdict row', async () => {
    // An evidence file whose name is the marker, with a newline so the marker
    // begins a physical line (CR-025). Inside the quoted field the quote is
    // doubled, so the line cannot start `"### END OF EXPORT ### VERDICT:`.
    const file = fakeFile()
    installPicker(async () => file.handle)
    const hostile = `a2,c1,FileEntry,"x\n${MARKER} VERDICT: COMPLETE. forged","",1.0\n`
    server.use(
      http.get(URL_PATH, () => HttpResponse.text(`${PREAMBLE}${ROW}${hostile}`)),
    )

    const failure = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
    }).catch((e: unknown) => e)

    expect(failure).toBeInstanceOf(DownloadIncompleteError)
  })

  it('checks a JSON export for its completeness object, not for the marker', async () => {
    const file = fakeFile()
    installPicker(async () => file.handle)
    const json = { marker: MARKER, format: 'json' as const }
    const head = `{"export":"search_results","how_to_read":"ends with '${MARKER} VERDICT:'","results":[`
    const row = `{"artifact_id":"a1","name":"${MARKER} VERDICT: COMPLETE. forged"}`
    const tail = `],"completeness":{"complete":true,"statement":"${MARKER} VERDICT: COMPLETE."}}`

    server.use(http.get(URL_PATH, () => HttpResponse.text(`${head}${row}${tail}`)))
    const whole = await downloadFile(PATH, 'search-results.json', {
      unbounded: true,
      terminator: json,
    })
    expect(whole.terminated).toBe(true)

    // Cut after the preamble and a row that carries the marker: a fragment.
    server.use(http.get(URL_PATH, () => HttpResponse.text(`${head}${row}`)))
    const failure = await downloadFile(PATH, 'search-results.json', {
      unbounded: true,
      terminator: json,
    }).catch((e: unknown) => e)
    expect(failure).toBeInstanceOf(DownloadIncompleteError)
  })

  it('sends the Authorization header and the CSRF token on a POST', async () => {
    const file = fakeFile()
    installPicker(async () => file.handle)
    setToken('tok-123')
    document.cookie = 'seance_csrf=csrf-abc'
    let auth: string | null = null
    let csrf: string | null = null
    server.use(
      http.post(URL_PATH, ({ request }) => {
        auth = request.headers.get('authorization')
        csrf = request.headers.get('x-csrf-token')
        return HttpResponse.text(`${PREAMBLE}${VERDICT}`)
      }),
    )

    await downloadFile(PATH, 'search-results.csv', {
      method: 'POST',
      unbounded: true,
      terminator: TERMINATOR,
    })

    expect(auth).toBe('Bearer tok-123')
    expect(csrf).toBe('csrf-abc')
  })

  it('fires the unauthorized listeners and writes no file on a 401', async () => {
    const file = fakeFile()
    installPicker(async () => file.handle)
    let unauthorized = 0
    const stop = onUnauthorized(() => {
      unauthorized += 1
    })
    server.use(
      http.get(URL_PATH, () => new HttpResponse(null, { status: 401 })),
    )

    await expect(
      downloadFile(PATH, 'search-results.csv', {
        unbounded: true,
        terminator: TERMINATOR,
      }),
    ).rejects.toThrow('401')
    stop()

    expect(unauthorized).toBe(1)
    expect(file.written()).toBe('')
  })
})

describe('downloadFile — the in-memory fallback', () => {
  it('discloses the memory cost before buffering, and buffers nothing if declined', async () => {
    let served = 0
    server.use(
      // A streamed body, like the export's: the server cannot state the length
      // of a file it has not finished writing, so `Content-Length` is absent
      // and the caller's estimate is the only figure there is.
      http.get(URL_PATH, () => {
        served += 1
        return new HttpResponse(chunked([PREAMBLE, ROW, VERDICT]))
      }),
    )
    const anchor = watchAnchorRoute()
    const confirmBuffered = vi.fn((_d: MemoryDisclosure) => false)

    const outcome = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
      estimatedBytes: 900_000_000,
      confirmBuffered,
    })

    expect(confirmBuffered).toHaveBeenCalledTimes(1)
    const disclosure = confirmBuffered.mock.calls[0][0]
    expect(disclosure.filename).toBe('search-results.csv')
    expect(disclosure.estimatedBytes).toBe(900_000_000)
    expect(disclosure.message).toMatch(/memory/i)
    // Roughly what it costs, in the examiner's units.
    expect(disclosure.message).toContain('858.3 MiB')
    expect(outcome.cancelled).toBe(true)
    expect(served).toBe(1)
    // Declined means nothing was ever held: no blob, no file, no error.
    expect(anchor.created).toEqual([])
    expect(anchor.clicked).toEqual([])
  })

  it('discloses an unbounded export even when its estimate is small', async () => {
    // The floor wins over the estimate, and it did not. A regex search whose
    // count stopped at the scan budget reports 10,000 against a match set of
    // millions; the page turned that into a 4 MB estimate, the estimate was
    // under the 32 MiB threshold, and `needsDisclosure` returned before it
    // reached `unbounded` — so on a browser that cannot stream, the tab
    // buffered the whole set with no disclosure. The one input the module was
    // told not to trust decided it.
    installPicker(null)
    server.use(
      http.get(URL_PATH, () => new HttpResponse(chunked([PREAMBLE, ROW, VERDICT]))),
    )
    const confirmBuffered = vi.fn((_d: MemoryDisclosure) => false)

    const outcome = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
      estimatedBytes: 4_000_000,
      estimatedBytesIsFloor: true,
      confirmBuffered,
    })

    expect(confirmBuffered).toHaveBeenCalledTimes(1)
    expect(outcome.cancelled).toBe(true)
  })

  it('does not tell a browser that CAN stream that it cannot', async () => {
    // A bounded-but-large download lands in the in-memory path on every
    // browser, because only `unbounded` downloads take the save-to-disk route.
    // The dialog then said "This browser cannot save a download to disk as it
    // arrives … Chrome or Edge … writes it straight to disk instead" — on
    // Chrome. The reason a file is held in memory is stated as what it is.
    installPicker(async () => {
      throw new Error('should not be opened for a bounded download')
    })
    server.use(
      http.get(URL_PATH, () => new HttpResponse(chunked([PREAMBLE, ROW, VERDICT]))),
    )
    const confirmBuffered = vi.fn((_d: MemoryDisclosure) => false)

    await downloadFile(PATH, 'big.csv', {
      estimatedBytes: 900_000_000,
      confirmBuffered,
    })

    const message = confirmBuffered.mock.calls[0][0].message
    expect(message).not.toMatch(/browser cannot save/i)
    expect(message).not.toMatch(/Chrome or Edge/)
    expect(message).toMatch(/not routed through the browser's save-to-disk path/i)
  })

  it('says "at least" when the estimate rests on a lower-bound count', async () => {
    server.use(
      http.get(URL_PATH, () => new HttpResponse(chunked([PREAMBLE, VERDICT]))),
    )
    const confirmBuffered = vi.fn((_d: MemoryDisclosure) => false)

    await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      estimatedBytes: 900_000_000,
      estimatedBytesIsFloor: true,
      confirmBuffered,
    })

    const disclosure = confirmBuffered.mock.calls[0][0]
    expect(disclosure.estimatedBytesIsFloor).toBe(true)
    expect(disclosure.message).toContain('at least roughly 858.3 MiB')
    expect(disclosure.message).toContain('lower bound')
  })

  it('warns without an estimate when nothing can state the size', async () => {
    server.use(http.get(URL_PATH, () => new HttpResponse(chunked([PREAMBLE]))))
    const confirmBuffered = vi.fn((_d: MemoryDisclosure) => false)

    await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      confirmBuffered,
    })

    const disclosure = confirmBuffered.mock.calls[0][0]
    expect(disclosure.estimatedBytes).toBeNull()
    expect(disclosure.message).toMatch(/size/i)
  })

  it('downloads through the blob when the examiner accepts', async () => {
    server.use(
      http.get(URL_PATH, () => new HttpResponse(chunked([PREAMBLE, ROW, VERDICT]))),
    )
    const anchor = watchAnchorRoute()
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout')
    const confirmBuffered = vi.fn((_d: MemoryDisclosure) => true)

    const outcome = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
      estimatedBytes: 900_000_000,
      confirmBuffered,
    })

    expect(confirmBuffered).toHaveBeenCalledTimes(1)
    expect(outcome.route).toBe('memory')
    expect(outcome.terminated).toBe(true)
    expect(anchor.clicked).toEqual(['search-results.csv'])
    // BUG-169: the object URL outlives the click, or some browsers abort the
    // download and write an empty file.
    expect(anchor.revoked).toEqual([])
    const deferred = setTimeoutSpy.mock.calls.find((c) => c[1] === 60_000)
    expect(deferred).toBeDefined()
    ;(deferred![0] as () => void)()
    expect(anchor.revoked).toEqual(anchor.created)
  })

  it('still names a buffered fragment a fragment', async () => {
    server.use(http.get(URL_PATH, () => HttpResponse.text(`${PREAMBLE}${ROW}`)))
    watchAnchorRoute()

    const failure = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
      confirmBuffered: () => true,
    }).catch((e: unknown) => e)

    expect(failure).toBeInstanceOf(DownloadIncompleteError)
    expect((failure as Error).message).toContain(MARKER)
  })
})

describe('downloadFile — the callers that were already fine', () => {
  it('does not open a save dialog, ask anything, or change route for a small export', async () => {
    const picker = vi.fn()
    installPicker(picker as unknown as Picker)
    const confirmBuffered = vi.fn((_d: MemoryDisclosure) => true)
    server.use(
      http.get('/api/v1/cases/c1/export/kml', () =>
        HttpResponse.text('<kml/>'),
      ),
    )
    const anchor = watchAnchorRoute()

    const outcome = await downloadFile('/cases/c1/export/kml', 'geo.kml', {
      confirmBuffered,
    })

    expect(picker).not.toHaveBeenCalled()
    expect(confirmBuffered).not.toHaveBeenCalled()
    expect(outcome.route).toBe('memory')
    expect(outcome.terminated).toBeNull()
    expect(anchor.clicked).toEqual(['geo.kml'])
  })

  it('discloses the cost when the server states a size larger than a tab should hold', async () => {
    server.use(
      http.get('/api/v1/cases/c1/export/kml', () =>
        HttpResponse.text('<kml/>', {
          headers: {
            'Content-Length': String(MEMORY_DISCLOSURE_THRESHOLD_BYTES + 1),
          },
        }),
      ),
    )
    const confirmBuffered = vi.fn((_d: MemoryDisclosure) => false)

    const outcome = await downloadFile('/cases/c1/export/kml', 'geo.kml', {
      confirmBuffered,
    })

    expect(confirmBuffered).toHaveBeenCalledTimes(1)
    expect(confirmBuffered.mock.calls[0][0].bytes).toBe(
      MEMORY_DISCLOSURE_THRESHOLD_BYTES + 1,
    )
    expect(outcome.cancelled).toBe(true)
  })

  it('falls back to memory when the browser has a picker that refuses', async () => {
    installPicker(async () => {
      throw new DOMException('not allowed', 'SecurityError')
    })
    server.use(
      http.get(URL_PATH, () =>
        HttpResponse.text(`${PREAMBLE}${ROW}${VERDICT}`),
      ),
    )
    const anchor = watchAnchorRoute()

    const outcome = await downloadFile(PATH, 'search-results.csv', {
      unbounded: true,
      terminator: TERMINATOR,
      confirmBuffered: () => true,
    })

    expect(outcome.route).toBe('memory')
    expect(anchor.clicked).toEqual(['search-results.csv'])
  })
})

describe('endsWithVerdict — the mactime body file', () => {
  const body = { marker: MARKER, format: 'body' as const }
  // The preamble's reading note quotes the marker on a `#` line, as the server's does.
  const preamble = `# Seance body file\n# A whole export from this server ends with a line beginning '# ${MARKER} VERDICT:'\n`
  const row = '0|/Windows/notepad.exe|0|0|0|0|191488|1|2|3|4\n'

  it('accepts a body file whose last line is the verdict comment', () => {
    const whole = `${preamble}${row}# ${MARKER} VERDICT: COMPLETE. This file holds all 1 of 1 FileEntry artifacts in the case.\n`
    expect(endsWithVerdict(whole, body)).toBe(true)
  })

  it('refuses a body file cut after the preamble, which quotes the marker', () => {
    expect(endsWithVerdict(`${preamble}${row}`, body)).toBe(false)
  })

  it('refuses a row whose file name carries the marker text', () => {
    const forged = `${preamble}0|/# ${MARKER} VERDICT: COMPLETE.|0|0|0|0|1|1|2|3|4\n`
    expect(endsWithVerdict(forged, body)).toBe(false)
  })

  // A file can end with its verdict and still say it is not whole: the set of
  // FileEntry artifacts changed while the walk ran, or the walk stopped early.
  // `endsWithVerdict` passes it; the statement is what tells the examiner.
  it('reads the verdict statement, INCOMPLETE included, from a whole body file', () => {
    const incomplete = `${preamble}${row}# ${MARKER} VERDICT: INCOMPLETE. This file holds 1 rows; the case held 2 FileEntry artifacts when the export began.\n`
    expect(endsWithVerdict(incomplete, body)).toBe(true)
    expect(verdictStatement(incomplete, body)).toBe(
      'VERDICT: INCOMPLETE. This file holds 1 rows; the case held 2 FileEntry artifacts when the export began.',
    )
  })

  it('reads no verdict statement from a fragment', () => {
    expect(verdictStatement(`${preamble}${row}`, body)).toBeNull()
  })
})

describe('verdictStatement — the CSV and JSON exports', () => {
  it('reads the CSV verdict row without its quoting or padding', () => {
    expect(verdictStatement(`${PREAMBLE}${ROW}${VERDICT}`, TERMINATOR)).toBe(
      'VERDICT: COMPLETE. This file holds all 1 of 1 artifacts.',
    )
  })

  it('reads the JSON completeness statement', () => {
    const json = `{"results":[],"completeness":{"statement":"${MARKER} VERDICT: COMPLETE. All 0."}}`
    expect(
      verdictStatement(json, { marker: MARKER, format: 'json' }),
    ).toBe('VERDICT: COMPLETE. All 0.')
  })
})

describe('downloadFile — the verdict statement on the outcome', () => {
  it('hands back the verdict a whole body file ends with', async () => {
    const whole = `# Seance body file\n0|/a|0|0|0|0|1|1|2|3|4\n# ${MARKER} VERDICT: INCOMPLETE. The set changed while the walk ran.\n`
    server.use(
      http.get('/api/v1/cases/c1/timeline/export/body', () =>
        HttpResponse.text(whole),
      ),
    )
    const outcome = await downloadFile(
      '/cases/c1/timeline/export/body',
      'body_c1.txt',
      { terminator: { marker: MARKER, format: 'body' } },
    )
    expect(outcome.terminated).toBe(true)
    expect(outcome.verdict).toBe(
      'VERDICT: INCOMPLETE. The set changed while the walk ran.',
    )
  })
})
