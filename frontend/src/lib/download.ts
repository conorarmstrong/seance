import {
  apiUrl,
  checkUnauthorized,
  csrfToken,
  getToken,
  type QueryParams,
} from '../api/http'
import { formatBytes } from './format'

/**
 * How much of the tail of a download is kept to look for the terminator.
 *
 * The search export's verdict row is a paragraph — around 600 bytes in the CSV
 * and rather more once the JSON tail wraps it — so a few kilobytes is generous
 * enough to hold a whole one and small enough to keep for free while a
 * multi-gigabyte file goes past. Kept as BYTES rather than as decoded text: a
 * rolling decode of every chunk would cost real time on a large export and buys
 * nothing, since the tail is decoded once at the end.
 */
const TAIL_BYTES = 8192

/**
 * The size above which a download that must be held in memory is disclosed
 * before it is held.
 *
 * The number is deliberately far below where a tab actually dies — that limit
 * is not knowable from script, varies by browser, device and what else the tab
 * is holding, and the buffered route needs roughly twice the file's size while
 * the blob is written out. 32 MiB is a size no export in this product reaches
 * by accident, so below it nothing is asked and every small caller behaves
 * exactly as it did; above it the examiner is told what they are about to spend
 * and can choose. The threshold exists to stop a silent death, not to predict
 * one.
 */
export const MEMORY_DISCLOSURE_THRESHOLD_BYTES = 32 * 1024 * 1024

/** What a download did, so the caller can tell success from a cancellation. */
export interface DownloadOutcome {
  /**
   * `file-system` — piped to a file the examiner chose, never fully in memory.
   * `memory` — buffered in the tab first, which is what the fallback costs.
   */
  route: 'file-system' | 'memory'
  /**
   * The examiner declined: the save dialog was dismissed, or the in-memory
   * disclosure was refused. Nothing was written and nothing failed. A caller
   * that announces success must check this first.
   */
  cancelled: boolean
  /** Bytes written. Zero when cancelled. */
  bytes: number
  /**
   * Whether the file ends with the terminator the caller named, or `null` when
   * the caller named none. `false` never returns — it throws
   * [`DownloadIncompleteError`] — but the field is kept so the meaning of
   * "checked and passed" is distinct from "never checked".
   */
  terminated: boolean | null
  /**
   * The verdict statement the file ends with — the text after the marker,
   * e.g. `VERDICT: COMPLETE. This file holds all …` or `VERDICT: INCOMPLETE. …`
   * — or `null` when the caller named no terminator or the download was
   * cancelled. A file can end with its verdict and still be INCOMPLETE (the
   * server's set changed while the walk ran, or the walk stopped early), and
   * `terminated` cannot tell those apart; a caller that reports the export
   * must read this.
   */
  verdict?: string | null
}

/**
 * The verdict row a streamed export ends with, by format.
 *
 * `marker` is the text the row's statement begins with; `format` says how a
 * whole file frames it, because the marker on its own proves nothing
 * (CR-025, CR-033 #4). The server quotes the marker in the preamble's own
 * reading note, so a download cut off after the first two kilobytes still
 * contains it — and `tail.includes(marker)` reported that fragment to the
 * examiner as complete. An evidence file named for the marker writes it into
 * hit rows as well. What no hit row can produce is the SHAPE the server gives
 * the verdict: in the CSV, a physical line beginning with a double quote and
 * then the marker (the first column of a hit row is a UUID, and a quote inside
 * a quoted field is doubled); in the JSON, the member `"statement":"<marker>`
 * outside a string, where every quote is escaped. `endsWithVerdict` tests for
 * that shape and nothing less; the server's reading note states the same test.
 */
export interface ExportTerminator {
  marker: string
  /**
   * `body` is the Sleuth Kit body file (`/timeline/export/body`): the verdict
   * is a `#` comment line, which `mactime` skips, and no data row can begin
   * with `#` because every row's first column is the MD5 (`0` when unknown).
   */
  format: 'csv' | 'json' | 'body'
}

/**
 * Whether the tail of a downloaded export ends with the server's verdict row,
 * framed the way a whole file of that format frames it. See
 * [`ExportTerminator`].
 */
export function endsWithVerdict(
  tail: string,
  terminator: ExportTerminator,
): boolean {
  const verdict = `${terminator.marker} VERDICT:`
  if (terminator.format === 'body') {
    // The body file ends with exactly one newline after the verdict comment,
    // which is its last physical line. The preamble quotes the marker too, but
    // on a line that begins `# A whole export`, never `# <marker>`.
    const body = tail.endsWith('\n') ? tail.slice(0, -1) : tail
    const lastLine = body.slice(body.lastIndexOf('\n') + 1)
    return lastLine.startsWith(`# ${verdict}`)
  }
  if (terminator.format === 'csv') {
    // The CSV ends with exactly one newline after the verdict row; the row is
    // the last physical line, and the server always quotes it.
    const body = tail.endsWith('\n') ? tail.slice(0, -1) : tail
    const lastLine = body.slice(body.lastIndexOf('\n') + 1)
    return lastLine.startsWith(`"${verdict}`)
  }
  // The JSON's last member is the completeness object; the file closes with
  // its brace. Inside any string the quotes would be escaped, so this member
  // can only be the real one.
  return (
    tail.trimEnd().endsWith('}') && tail.includes(`"statement":"${verdict}`)
  )
}

/**
 * The verdict statement a whole export ends with — `VERDICT: …` to the end of
 * the verdict row — or `null` when `endsWithVerdict` would refuse the tail.
 */
export function verdictStatement(
  tail: string,
  terminator: ExportTerminator,
): string | null {
  if (!endsWithVerdict(tail, terminator)) return null
  const prefix = `${terminator.marker} `
  if (terminator.format === 'body') {
    const body = tail.endsWith('\n') ? tail.slice(0, -1) : tail
    const lastLine = body.slice(body.lastIndexOf('\n') + 1)
    return lastLine.slice(`# ${prefix}`.length).trim()
  }
  if (terminator.format === 'csv') {
    // The first field of the last line, quoted: read to the first quote that
    // is not a doubled one, and undouble the rest.
    const body = tail.endsWith('\n') ? tail.slice(0, -1) : tail
    const lastLine = body.slice(body.lastIndexOf('\n') + 1)
    let field = ''
    for (let i = 1; i < lastLine.length; i += 1) {
      const ch = lastLine[i]
      if (ch === '"') {
        if (lastLine[i + 1] === '"') {
          field += '"'
          i += 1
          continue
        }
        break
      }
      field += ch
    }
    return field.slice(prefix.length).trim()
  }
  // JSON: the statement member's string, decoded as JSON decodes it.
  const key = '"statement":"'
  const start = tail.lastIndexOf(`${key}${terminator.marker} VERDICT:`)
  if (start < 0) return null
  let end = start + key.length
  while (end < tail.length && tail[end] !== '"') {
    end += tail[end] === '\\' ? 2 : 1
  }
  try {
    const text = JSON.parse(tail.slice(start + key.length - 1, end + 1)) as string
    return text.slice(prefix.length).trim()
  } catch {
    return null
  }
}

/** What the examiner is told before a download is held in memory. */
export interface MemoryDisclosure {
  filename: string
  /** The size the server stated, in bytes, or null if it stated none. */
  bytes: number | null
  /** The caller's own estimate, or null. Only consulted when the server is silent. */
  estimatedBytes: number | null
  /** True when that estimate is a floor rather than a figure. */
  estimatedBytesIsFloor: boolean
  /** A complete, quotable sentence naming the cost and the risk. */
  message: string
}

export interface DownloadOptions {
  method?: 'GET' | 'POST'
  query?: QueryParams
  /**
   * This endpoint's response has no size ceiling.
   *
   * Set by the callers whose payload grows with the case — the search export
   * walks the whole match set, which is millions of rows on a real case. It
   * turns on two things: streaming straight to a file the examiner chooses
   * where the browser can do it, and the in-memory disclosure where it cannot
   * even though nothing has stated a size. It is deliberately opt-in: a
   * thumbnail, a KML or an audit CSV is a download, not a save-as, and making
   * every one of them open a file dialog would be a worse product in order to
   * serve one screen.
   */
  unbounded?: boolean
  /**
   * The caller's own estimate of the payload size, used only for the
   * disclosure and only when the server states no `Content-Length` — which a
   * streamed export never does, since it does not know its own length until it
   * has finished writing it.
   */
  estimatedBytes?: number
  /**
   * The estimate above is a FLOOR, not a figure.
   *
   * Set when the count it was derived from is itself a lower bound — a search
   * whose scan stopped at its budget reports "at least N matches", and an
   * estimate built on it must not be quoted as "about N × a row". The
   * disclosure says "at least" in that case, because an examiner deciding
   * whether their machine can hold the file is entitled to know which side of
   * the number the uncertainty falls on.
   */
  estimatedBytesIsFloor?: boolean
  /**
   * The verdict a WHOLE file from this endpoint ends with, and how it is framed.
   *
   * The search and timeline exports end every file — including a complete one
   * — with a verdict row, and their own preamble states that a file without
   * that row is a fragment which must not be tendered. Naming it here lets the
   * client apply the same test the reader would: a transfer that ends cleanly
   * but short (a proxy that gave up, a server that stopped) is otherwise
   * indistinguishable from a successful download, and the examiner would be
   * left holding a plausible-looking exhibit with rows missing off the end.
   */
  terminator?: ExportTerminator
  /**
   * Ask the examiner to accept an in-memory download. Return false to decline.
   *
   * Called BEFORE any bytes are buffered and only when the payload is large or
   * its size is unknown. The default asks through `window.confirm`, so a caller
   * that forgets to pass one still cannot buffer a gigabyte silently; a page
   * with a better dialog to offer passes its own.
   */
  confirmBuffered?: (disclosure: MemoryDisclosure) => boolean | Promise<boolean>
}

/**
 * A file reached disk, and it is not the whole file.
 *
 * Thrown rather than returned because the caller must not present it as a
 * finished export. It carries what the examiner needs in order to know what is
 * on their disk: the name it was written under, how much of it arrived, and
 * whether those bytes were kept.
 */
export class DownloadIncompleteError extends Error {
  readonly filename: string
  readonly bytesWritten: number
  /** True when the bytes that did arrive are on disk and readable. */
  readonly partialFileKept: boolean

  constructor(
    message: string,
    filename: string,
    bytesWritten: number,
    partialFileKept: boolean,
    options?: { cause?: unknown },
  ) {
    super(message, options)
    this.name = 'DownloadIncompleteError'
    this.filename = filename
    this.bytesWritten = bytesWritten
    this.partialFileKept = partialFileKept
  }
}

/**
 * The subset of the File System Access API this file uses.
 *
 * Declared here rather than pulled from `lib.dom`, which does not yet carry
 * `showSaveFilePicker` or `FileSystemFileHandle.remove`. Structural, so it
 * cannot claim a capability the runtime does not have: everything optional is
 * probed before it is called.
 */
interface SaveFilePickerOptions {
  suggestedName?: string
  types?: { description: string; accept: Record<string, string[]> }[]
}

interface SaveFileHandle extends FileSystemFileHandle {
  /** Newer Chrome only; used to clear the empty file a failed request leaves. */
  remove?: () => Promise<void>
}

type SaveFilePicker = (
  options?: SaveFilePickerOptions,
) => Promise<SaveFileHandle>

function saveFilePicker(): SaveFilePicker | null {
  const candidate = (window as unknown as { showSaveFilePicker?: unknown })
    .showSaveFilePicker
  return typeof candidate === 'function'
    ? (candidate as SaveFilePicker).bind(window)
    : null
}

/** Extensions worth naming in the save dialog, so it does not append a second one. */
const PICKER_TYPES: Record<string, { description: string; mime: string }> = {
  csv: { description: 'Comma-separated values', mime: 'text/csv' },
  json: { description: 'JSON', mime: 'application/json' },
  txt: { description: 'Plain text', mime: 'text/plain' },
}

function pickerTypes(filename: string): SaveFilePickerOptions['types'] {
  const ext = filename.includes('.')
    ? filename.slice(filename.lastIndexOf('.') + 1).toLowerCase()
    : ''
  const type = PICKER_TYPES[ext]
  if (!type) return undefined
  return [{ description: type.description, accept: { [type.mime]: [`.${ext}`] } }]
}

/** A dismissed picker, as opposed to a browser that refused to show one. */
function isAbort(err: unknown): boolean {
  return err instanceof DOMException
    ? err.name === 'AbortError'
    : (err as { name?: string } | null)?.name === 'AbortError'
}

function cancelled(route: DownloadOutcome['route']): DownloadOutcome {
  return { route, cancelled: true, bytes: 0, terminated: null }
}

/**
 * Download an export endpoint as a file.
 *
 * Uses fetch (not a plain link) so the Authorization header and the CSRF token
 * are attached and a 401 clears the session, then takes one of two routes to
 * disk.
 *
 * # Why there are two routes
 *
 * The server streams its exports: a 4,000,000-row search export costs it one
 * page of rows at a time. This helper used to call `response.blob()`, which
 * materialises the entire response in the tab before a byte reaches disk — so
 * the out-of-memory failure the server had been fixed to avoid simply moved to
 * the examiner's machine, and arrived as a dead tab with no explanation.
 *
 * Where the browser offers the File System Access API, an `unbounded` download
 * is piped from `response.body` into a file the examiner chose, and the tab
 * holds one chunk at a time. Where it does not, the buffered route is still the
 * only one available — but it is taken KNOWINGLY: the examiner is told what it
 * will cost before anything is held, and can decline. A fallback that quietly
 * buffered would be this defect with a nicer name.
 *
 * Everything else — the small exports on seven other pages — keeps the buffered
 * route unchanged and unasked, because for them it was never a problem.
 *
 * # What a half-written file is allowed to look like
 *
 * A stream that dies at row 3,800,000 leaves bytes on disk under a name the
 * examiner chose. Those bytes are kept, exactly as they arrived: nothing is
 * appended to them, because a client that writes into an exhibit makes it
 * something other than what the server sent, and nothing is deleted, because
 * what arrived is evidence and destroying it to tidy up is worse than keeping a
 * fragment. The file identifies itself — the server's preamble states that an
 * export without its final verdict row is a fragment that must not be tendered
 * — and this helper applies that same test with `terminator` and throws
 * [`DownloadIncompleteError`] rather than reporting a download that succeeded.
 */
export async function downloadFile(
  path: string,
  filename: string,
  options: DownloadOptions = {},
): Promise<DownloadOutcome> {
  // The picker is opened BEFORE the request, and that ordering is load-bearing
  // twice over. `showSaveFilePicker` requires transient user activation, which
  // the awaited fetch would spend; and an examiner who dismisses the dialog has
  // decided not to export, so the server is never asked to start a walk that
  // nothing will read.
  let handle: SaveFileHandle | null = null
  if (options.unbounded) {
    const picker = saveFilePicker()
    if (picker) {
      try {
        handle = await picker({
          suggestedName: filename,
          types: pickerTypes(filename),
        })
      } catch (err) {
        // Dismissed: not a failure, and nothing to report as one.
        if (isAbort(err)) return cancelled('file-system')
        // Refused (insecure context, sandboxed frame, no activation left).
        // The buffered route still works, and its disclosure will say so.
        handle = null
      }
    }
  }

  let response: Response
  try {
    response = await request(path, options)
  } catch (err) {
    // The chosen file exists and is empty, because choosing it created it.
    // Clear it where the browser allows: an empty file named
    // `search-results.csv` is not an exhibit, and leaving one to be found later
    // invites exactly the wrong conclusion.
    await discard(handle)
    throw err
  }

  if (handle && response.body) {
    // The name the examiner CHOSE, not the name that was suggested to them.
    // `suggestedName` is an opening bid the save dialog exists to let them
    // change, and on this product changing it is the normal act: an export is
    // filed under an exhibit reference, not under `search-results.csv`. Every
    // sentence below this line names a file on the examiner's disk — "N MB
    // reached X and were kept exactly as sent", "X is a FRAGMENT … must not be
    // tendered" — and so does `DownloadIncompleteError.filename`, which the
    // search page prints verbatim on screen. Naming the suggestion sends the
    // examiner looking for a file that is not there, and leaves the file that
    // IS there, under their own exhibit reference, with nothing anywhere saying
    // it is a fragment: a truncated export nobody has been told to distrust is
    // the one most likely to be tendered.
    //
    // `|| filename` covers a handle that reports no name of its own; the
    // suggestion is then the best available answer and is at least the name the
    // dialog opened with.
    return await streamToFile(
      handle,
      response,
      handle.name || filename,
      options.terminator,
    )
  }
  // A handle with no body to pipe: nothing was streamed, so drop the empty file
  // and let the buffered route write the whole thing.
  await discard(handle)
  return await bufferToFile(response, filename, options)
}

/** The request itself: headers, the 401 hook, and the status check. */
async function request(
  path: string,
  options: DownloadOptions,
): Promise<Response> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (method !== 'GET') {
    const csrf = csrfToken()
    if (csrf) headers['x-csrf-token'] = csrf
  }
  const response = checkUnauthorized(
    await fetch(apiUrl(path, options.query), { method, headers }),
  )
  if (!response.ok) {
    throw new Error(`Export failed with status ${response.status}`)
  }
  return response
}

async function discard(handle: SaveFileHandle | null): Promise<void> {
  if (!handle?.remove) return
  try {
    await handle.remove()
  } catch {
    // Older browsers cannot remove a handle they just handed out. The file is
    // empty either way, which is not something that can be mistaken for an
    // export.
  }
}

/**
 * Pipe the response into the chosen file, one chunk at a time.
 *
 * The tab holds a chunk and the last few kilobytes, whatever the file's size.
 */
async function streamToFile(
  handle: SaveFileHandle,
  response: Response,
  filename: string,
  terminator: ExportTerminator | undefined,
): Promise<DownloadOutcome> {
  const writable = await handle.createWritable()
  const reader = response.body!.getReader()
  let bytes = 0
  let tail: Uint8Array<ArrayBufferLike> = new Uint8Array(0)
  let failure: unknown = null

  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (!value || value.byteLength === 0) continue
      await writable.write(value)
      bytes += value.byteLength
      if (terminator) tail = keepTail(tail, value)
    }
  } catch (err) {
    failure = err
    // Let go of the response as well as the file. The read loop can end
    // because the DISK refused — a full volume, a revoked permission — and the
    // body would otherwise stay locked and draining: this server holds an
    // index snapshot open for exactly as long as the download's stream lives,
    // so an abandoned reader keeps a case's segment files pinned for no
    // reason. Not awaited, for the same reason the declined disclosure's
    // cancel is not.
    void reader.cancel().catch(() => {})
  }

  // Closed, not aborted, even after a failure. `createWritable` stages the
  // write and only `close()` commits it, so aborting here would throw away the
  // rows that did arrive — and a fragment that says it is a fragment is worth
  // more to an examiner than nothing at all.
  let kept = true
  try {
    await writable.close()
  } catch (err) {
    kept = false
    failure = failure ?? err
  }

  if (failure) {
    throw new DownloadIncompleteError(
      interruptedMessage(filename, bytes, kept, terminator, failure),
      filename,
      bytes,
      kept,
      { cause: failure },
    )
  }

  if (terminator && !endsWithVerdict(decodeTail(tail), terminator)) {
    throw new DownloadIncompleteError(
      truncatedMessage(filename, bytes, terminator.marker),
      filename,
      bytes,
      true,
    )
  }

  return {
    route: 'file-system',
    cancelled: false,
    bytes,
    terminated: terminator ? true : null,
    verdict: terminator ? verdictStatement(decodeTail(tail), terminator) : null,
  }
}

/**
 * The route for browsers with no way to write a file as it arrives, and for
 * every small export.
 *
 * The whole response is held in the tab. That is stated first where it might
 * matter, and only then paid.
 */
async function bufferToFile(
  response: Response,
  filename: string,
  options: DownloadOptions,
): Promise<DownloadOutcome> {
  const stated = statedLength(response)
  const estimate = options.estimatedBytes ?? null
  if (needsDisclosure(stated, estimate, options.unbounded === true)) {
    const floor = options.estimatedBytesIsFloor === true
    const disclosure: MemoryDisclosure = {
      filename,
      bytes: stated,
      estimatedBytes: estimate,
      estimatedBytesIsFloor: floor,
      message: memoryMessage(filename, stated, estimate, floor),
    }
    const ask = options.confirmBuffered ?? defaultConfirm
    if (!(await ask(disclosure))) {
      // Declining cancels the body, which on this server drops the stream —
      // and with it the index snapshot the export was holding open. Nothing was
      // buffered, so there is nothing to free and nothing to report.
      //
      // Deliberately not awaited. A cancel is a request to stop reading, and
      // how long the transport takes to notice is not the examiner's business:
      // waiting on it would make a declined disclosure hang on a connection
      // that is already unwanted.
      void response.body?.cancel().catch(() => {})
      return cancelled('memory')
    }
  }

  const blob = await response.blob()

  // Only the tail is decoded, so the check costs a few kilobytes rather than a
  // second copy of the file.
  let terminated: boolean | null = null
  let verdict: string | null = null
  if (options.terminator) {
    const tail = await blob.slice(Math.max(0, blob.size - TAIL_BYTES)).text()
    terminated = endsWithVerdict(tail, options.terminator)
    verdict = verdictStatement(tail, options.terminator)
  }

  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  // Defer revocation: revoking synchronously right after click() can abort the
  // download before the browser has read the blob, yielding empty/corrupt
  // files on some browsers (BUG-169).
  setTimeout(() => URL.revokeObjectURL(url), 60_000)

  if (terminated === false) {
    // The file is in the downloads folder, and it is a fragment. Delivered
    // rather than withheld — it is what the server sent, and it says so itself
    // — but never reported as a completed export.
    throw new DownloadIncompleteError(
      truncatedMessage(filename, blob.size, options.terminator!.marker),
      filename,
      blob.size,
      true,
    )
  }

  return {
    route: 'memory',
    cancelled: false,
    bytes: blob.size,
    terminated,
    verdict,
  }
}

function statedLength(response: Response): number | null {
  const header = response.headers.get('Content-Length')
  if (header == null) return null
  const value = Number(header)
  return Number.isFinite(value) && value >= 0 ? value : null
}

/**
 * Whether holding this response in memory is worth stopping for.
 *
 * A stated size decides it. Where nothing states one, only an `unbounded`
 * caller is asked: for everything else an absent `Content-Length` means a small
 * file sent without one, and asking would be noise on seven pages to serve the
 * eighth.
 */
function needsDisclosure(
  stated: number | null,
  estimate: number | null,
  unbounded: boolean,
): boolean {
  if (stated != null) return stated >= MEMORY_DISCLOSURE_THRESHOLD_BYTES
  // `unbounded` before the estimate, not after it. An estimate derived from a
  // count the server has already said is a floor is itself a floor, and the
  // module knows which — the caller passes it. Checked the other way round, a
  // regex search whose count stopped at its budget produced a 20 MB estimate
  // for a match set of millions of rows, the estimate was under the threshold,
  // and the tab buffered the whole set with no disclosure: the exact failure
  // this threshold exists to prevent, reached through the one input it was
  // told not to trust.
  if (unbounded) return true
  if (estimate != null) return estimate >= MEMORY_DISCLOSURE_THRESHOLD_BYTES
  return false
}

function memoryMessage(
  filename: string,
  stated: number | null,
  estimate: number | null,
  estimateIsFloor: boolean,
): string {
  const roughly = estimateIsFloor
    ? `at least roughly ${formatBytes(estimate)} — the match count it is derived from is itself a lower bound, so it may be considerably more —`
    : `roughly ${formatBytes(estimate)},`
  const size =
    stated != null
      ? `The server states ${filename} is ${formatBytes(stated)}, and this tab needs at least that much free memory to hold it — briefly about twice that while it is written out.`
      : estimate != null
        ? `The server cannot state the size of a file it is still writing; from the match count, ${filename} is expected to be ${roughly} and this tab needs at least that much free memory to hold it.`
        : `Nothing can state the size of ${filename} in advance: this export has no row ceiling, so it may be far larger than this tab can hold.`
  // Say why the file is being held in memory, and say it truthfully. The
  // streaming path is taken only for `unbounded` downloads that this browser
  // can stream; a bounded-but-large download on Chrome lands here too, and
  // telling that examiner their browser "cannot save to disk as it arrives" —
  // on the browser that can — was a false statement in a confirm dialog.
  const why = saveFilePicker()
    ? `This download is not routed through the browser's save-to-disk path, so the whole file must be held `
    : `This browser cannot save a download to disk as it arrives, so the whole file must be held `
  const alternative = saveFilePicker()
    ? ``
    : ` A browser that supports saving to a chosen file — Chrome or Edge, over HTTPS — writes it straight to disk instead.`
  return (
    `${why}in this tab's memory first. ${size} If the tab runs out of memory the download fails and no ` +
    `file is written.${alternative} Continue?`
  )
}

/**
 * The disclosure of last resort.
 *
 * `window.confirm` is blunt, but it cannot be missed, it cannot be dismissed by
 * accident, and it comes before anything is spent. A caller with a better
 * dialog passes `confirmBuffered`; a caller that passes nothing still cannot
 * buffer a gigabyte in silence. Where there is no `confirm` at all, the answer
 * is no: not downloading is recoverable, and killing the tab is not.
 */
function defaultConfirm(disclosure: MemoryDisclosure): boolean {
  if (typeof window === 'undefined' || typeof window.confirm !== 'function') {
    return false
  }
  return window.confirm(disclosure.message)
}

/** Keep the last TAIL_BYTES of the stream, cheaply. */
function keepTail(
  tail: Uint8Array<ArrayBufferLike>,
  chunk: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBufferLike> {
  if (chunk.byteLength >= TAIL_BYTES) {
    return chunk.slice(chunk.byteLength - TAIL_BYTES)
  }
  const keep = Math.min(tail.byteLength, TAIL_BYTES - chunk.byteLength)
  const next = new Uint8Array(keep + chunk.byteLength)
  next.set(tail.subarray(tail.byteLength - keep), 0)
  next.set(chunk, keep)
  return next
}

/**
 * Decode the tail for the terminator test.
 *
 * The tail may begin mid-character, which `TextDecoder` renders as a
 * replacement character. That is harmless here: the terminator is ASCII and
 * sits at the very end of the file, so a mangled first character cannot hide
 * it, and a tail this size holds a whole verdict row several times over.
 */
function decodeTail(tail: Uint8Array<ArrayBufferLike>): string {
  return new TextDecoder().decode(tail)
}

function truncatedMessage(
  filename: string,
  bytes: number,
  terminator: string,
): string {
  return (
    `${filename} is a FRAGMENT. The transfer ended without the server's final ` +
    `"${terminator}" row, so rows are missing from the end of the file — ${formatBytes(bytes)} ` +
    `arrived and were kept exactly as sent, unaltered. The file's own preamble states that an ` +
    `export without that row must not be tendered as the result of this query. Re-run the export.`
  )
}

function interruptedMessage(
  filename: string,
  bytes: number,
  kept: boolean,
  terminator: ExportTerminator | undefined,
  cause: unknown,
): string {
  const why = cause instanceof Error ? cause.message : String(cause)
  const fate = kept
    ? `${formatBytes(bytes)} reached ${filename} and were kept exactly as sent, unaltered`
    : `${formatBytes(bytes)} arrived but could not be committed to ${filename}, which may be empty or partly written`
  const test = terminator
    ? `It is a FRAGMENT: it has no final "${terminator.marker}" row, which is how the file itself says so, and it must not be tendered as the result of this query.`
    : 'It is incomplete and must not be relied on as the whole file.'
  return `The transfer of ${filename} stopped: ${why}. ${fate}. ${test} Re-run the export.`
}
