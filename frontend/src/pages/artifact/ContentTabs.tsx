import { useQueryClient } from '@tanstack/react-query'
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from 'react'
import { splitHexRows } from '../../components/hex/HexView'
import { formatBytes, formatCount } from '../../lib/format'
import { incompleteReasonLabel } from '../../lib/incompleteness'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import {
  byteSearch,
  fetchContentRangeBytes,
  getArtifactHexPage,
  type ByteSearchResponse,
  type HexPage,
} from './api'
import { hexToBytes, inspectAt, parseOffsetInput } from './lib'

const HEX_PAGE = 4096
const TEXT_CHUNK = 262144
const MAX_RENDER_LINES = 5000
const EMPTY_BYTES = new Uint8Array(0)

function lastPageOffset(totalSize: number): number {
  if (totalSize <= HEX_PAGE) return 0
  return Math.floor((totalSize - 1) / HEX_PAGE) * HEX_PAGE
}

/** Hex grid with clickable byte cells feeding the data inspector. */
function ClickableHexGrid({
  offset,
  hex,
  ascii,
  selected,
  onSelect,
}: {
  offset: number
  hex: string
  ascii: string
  selected: number | null
  onSelect: (absoluteOffset: number) => void
}) {
  const rows = splitHexRows(offset, hex, ascii)
  if (rows.length === 0) {
    return <div className="empty-state">No data at this offset.</div>
  }
  return (
    <div className="hex-view mono">
      {rows.map((row) => (
        <div key={row.offset} className="hex-row">
          <span className="hex-offset">
            {row.offset.toString(16).padStart(8, '0')}
          </span>
          <span className="hex-bytes">
            {row.bytes.map((byte, i) => {
              const abs = row.offset + i
              const classes = ['av-hex-byte']
              if (byte === '00') classes.push('hex-zero')
              if (abs === selected) classes.push('selected')
              return (
                <button
                  key={i}
                  type="button"
                  className={classes.join(' ')}
                  title={`offset 0x${abs.toString(16)}`}
                  onClick={() => onSelect(abs)}
                >
                  {byte}
                </button>
              )
            })}
          </span>
          <span className="hex-ascii">{row.ascii}</span>
        </div>
      ))}
    </div>
  )
}

function DataInspector({
  bytes,
  pageOffset,
  selected,
}: {
  bytes: number[]
  pageOffset: number
  selected: number
}) {
  const fields = inspectAt(bytes, selected - pageOffset)
  return (
    <div className="panel av-inspector">
      <span className="av-inspector-title">
        Inspector at 0x{selected.toString(16)} ({selected})
      </span>
      {fields.map((field) => (
        <div key={field.label} className="av-inspector-field">
          <span className="av-label">{field.label}</span>
          <span className="mono">{field.value}</span>
        </div>
      ))}
    </div>
  )
}

export function HexTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  // The content on screen is identified by BOTH ids: artifact UUIDs are not
  // globally unique across cases, so gating on artifactId alone would let an
  // in-place case switch show case A's bytes under case B (BUG-259).
  const scopeKey = `${caseId}/${artifactId}`
  // Switching content must not carry the position or the byte-search results
  // over: an offset or match list from the previous artifact points into the
  // wrong content. Scoped rather than cleared in a `useEffect`, because
  // `offset` is part of the hex query key: on the render where the ids have
  // already changed but the effect has not run, react-query requests the NEW
  // artifact at the OLD artifact's offset — a read past the end of a smaller
  // file, reported as that file's content (B2-148 class).
  const [offset, setOffset] = useEntityScopedState(scopeKey, 0)
  const [jump, setJump] = useEntityScopedState(scopeKey, '')
  const [selected, setSelected] = useEntityScopedState<number | null>(
    scopeKey,
    null,
  )
  const [pattern, setPattern] = useEntityScopedState(scopeKey, '')
  const [matches, setMatches] = useEntityScopedState<ByteSearchResponse | null>(
    scopeKey,
    null,
  )
  const [searching, setSearching] = useEntityScopedState(scopeKey, false)
  const [searchError, setSearchError] = useEntityScopedState<string | null>(
    scopeKey,
    null,
  )
  // Generation guard for the async byte-search: bumped on every content switch
  // so an in-flight search for the previous artifact is disowned outright,
  // rather than merely being unreadable while another artifact is on screen.
  const searchGen = useRef(0)
  useEffect(() => {
    searchGen.current += 1
  }, [scopeKey])
  // keepPreviousData keeps the last page while the next loads — desirable when
  // paging within one artifact, but on a content switch the placeholder is the
  // previous artifact's bytes. The shared gate tags each response with the scope
  // it was fetched for so those bytes never render under the new chrome. `offset`
  // is deliberately NOT in the scope, so paging stays smooth.
  const query = useEntityScopedQuery<HexPage>(scopeKey, {
    queryKey: ['artifact-hex', caseId, artifactId, offset],
    queryFn: () => getArtifactHexPage(caseId, artifactId, offset, HEX_PAGE),
  })
  const stale = query.stale

  async function runByteSearch() {
    if (!pattern.trim()) return
    const gen = searchGen.current
    setSearching(true)
    setSearchError(null)
    try {
      const result = await byteSearch(caseId, artifactId, pattern.trim())
      // Bail if the artifact changed while the search was in flight — these
      // offsets belong to the previous artifact's content.
      if (searchGen.current !== gen) return
      setMatches(result)
    } catch (e) {
      if (searchGen.current !== gen) return
      setMatches(null)
      setSearchError((e as Error).message)
    } finally {
      if (searchGen.current === gen) setSearching(false)
    }
  }

  /** Jump the hex view to the page containing a byte-match and highlight it. */
  function goToMatch(matchOffset: number) {
    setOffset(Math.floor(matchOffset / HEX_PAGE) * HEX_PAGE)
    setSelected(matchOffset)
  }

  const bytes = useMemo(
    () => (query.data ? hexToBytes(query.data.hex) : []),
    [query.data],
  )
  const totalSize = stale ? null : (query.data?.total_size ?? null)
  // `offset` is where the examiner asked to go; `query.data.offset` is where the
  // bytes currently drawn actually start. `offset` is deliberately outside the
  // scope key so paging stays smooth, which means keepPreviousData holds the
  // PREVIOUS page on screen until the next one arrives. Labelling those bytes
  // with the requested offset states an address the data did not come from —
  // an examiner reading a value out of the grid would record the wrong file
  // offset for it. Label what is rendered, and say the requested page is still
  // loading (B2-021).
  const shownOffset = !stale && query.data != null ? query.data.offset : offset
  const pageLoading = shownOffset !== offset
  const atEnd =
    totalSize != null
      ? offset + HEX_PAGE >= totalSize
      : query.data != null && bytes.length < HEX_PAGE
  const goTo = (next: number) => {
    setOffset(next)
    setSelected(null)
  }
  const selectedInPage =
    selected != null &&
    query.data != null &&
    selected >= query.data.offset &&
    selected < query.data.offset + bytes.length
  // Short only when the server SAID so. Inventing it from `bytes.length <
  // HEX_PAGE` would flag the legitimate last page of every file.
  //
  // Deliberately not also requiring `requested_bytes`: a server that declares
  // the page incomplete without naming the figure has still declared it
  // incomplete, and suppressing the alert for want of a number would drop the
  // whole warning — the fail-open this fix exists to close. The number is
  // omitted from the sentence instead.
  const shortPage = !stale && query.data?.content_incomplete === true

  return (
    <div>
      <div className="av-hex-controls">
        <button
          className="btn"
          disabled={offset === 0}
          onClick={() => goTo(Math.max(0, offset - HEX_PAGE))}
        >
          Previous page
        </button>
        <span className="av-hex-offset mono">
          offset {shownOffset} (0x{shownOffset.toString(16)})
          {totalSize != null && ` of ${totalSize}`}
          {pageLoading && ` · loading 0x${offset.toString(16)}…`}
        </span>
        <button
          className="btn"
          disabled={query.data == null || atEnd}
          onClick={() => goTo(offset + HEX_PAGE)}
        >
          Next page
        </button>
        <button
          className="btn"
          disabled={totalSize == null || atEnd}
          onClick={() => totalSize != null && goTo(lastPageOffset(totalSize))}
        >
          Go to end
        </button>
        <form
          className="av-jump"
          onSubmit={(e) => {
            e.preventDefault()
            const parsed = parseOffsetInput(jump)
            if (parsed != null) goTo(parsed)
          }}
        >
          <label>
            Go to offset
            <input
              className="input mono"
              value={jump}
              onChange={(e) => setJump(e.target.value)}
              placeholder="0x0 or 512"
            />
          </label>
          <button className="btn" type="submit">
            Go
          </button>
        </form>
        <form
          className="av-jump av-bytesearch"
          onSubmit={(e) => {
            e.preventDefault()
            void runByteSearch()
          }}
        >
          <label>
            Find bytes
            <input
              className="input mono"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="ff d8 ff"
              aria-label="Byte pattern (hex)"
            />
          </label>
          <button className="btn" type="submit" disabled={searching}>
            {searching ? 'Searching…' : 'Find'}
          </button>
        </form>
      </div>
      {searchError && <div className="error-note">{searchError}</div>}
      {matches && (
        <div className="av-bytematches">
          <span className="av-bytematches-count">
            {formatCount(matches.offsets.length)}
            {matches.truncated ? '+' : ''} match
            {matches.offsets.length === 1 ? '' : 'es'}
          </span>
          {/*
            The scan stopped before the end of the declared content, so the
            bytes past `scanned_size` were never looked at. Without this line
            "0 matches" reads as "the pattern is not in this file", which is a
            conclusion the search did not support (B2-014).
          */}
          {matches.incomplete && (
            <span className="av-bytematches-incomplete" role="alert">
              Searched only {formatCount(matches.scanned_size)} of{' '}
              {formatCount(matches.total_size)} bytes — content ended early,
              so offsets past that point were not examined.
            </span>
          )}
          <div className="av-bytematches-list">
            {matches.offsets.slice(0, 200).map((o) => (
              <button
                key={o}
                type="button"
                className="av-bytematch mono"
                onClick={() => goToMatch(o)}
                title={`Go to offset ${o}`}
              >
                0x{o.toString(16)}
              </button>
            ))}
          </div>
        </div>
      )}
      {(query.isPending || stale) && (
        <div className="loading">Loading hex data...</div>
      )}
      {query.isError && (
        <div className="error-note">
          Failed to load hex data: {query.error?.message}
        </div>
      )}
      {/*
        A page that came up short. The grid below simply ends early while
        `total_size` still describes the whole object, so the shape on screen is
        exactly the shape of "the file ends here" — a different statement about
        the evidence, and the wrong one. The server distinguishes the two
        (`requested_bytes` vs the readable `limit`); this is where that reaches
        the examiner (B4-022).
      */}
      {shortPage && (
        <div className="error-note" role="alert" data-testid="av-hex-short">
          Only {formatCount(query.data!.limit)}
          {query.data!.requested_bytes != null
            ? ` of the ${formatCount(query.data!.requested_bytes)}`
            : ' of the'}{' '}
          bytes in this page could be read
          {query.data!.content_incomplete_reason
            ? `: ${incompleteReasonLabel(query.data!.content_incomplete_reason)}`
            : ''}
          . The grid below stops where the read failed, not where the content
          ends — this object is{' '}
          {totalSize != null ? formatCount(totalSize) : 'a larger'} bytes
          long. Do not read the end of the grid as the end of the file.
        </div>
      )}
      {query.data && !stale && (
        <ClickableHexGrid
          offset={query.data.offset}
          hex={query.data.hex}
          ascii={query.data.ascii}
          selected={selectedInPage ? selected : null}
          onSelect={setSelected}
        />
      )}
      {query.data && !stale && selectedInPage && selected != null && (
        <DataInspector
          bytes={bytes}
          pageOffset={query.data.offset}
          selected={selected}
        />
      )}
    </div>
  )
}

export type Encoding = 'utf-8' | 'utf-16le' | 'utf-16be'
type TextFormat = 'json' | 'xml' | 'plain'

/** Detect text encoding from a BOM, else a null-byte parity heuristic. */
export function detectEncoding(bytes: Uint8Array): Encoding {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return 'utf-16le'
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return 'utf-16be'
  }
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xef &&
    bytes[1] === 0xbb &&
    bytes[2] === 0xbf
  ) {
    return 'utf-8'
  }
  const sample = Math.min(bytes.length, 4096)
  let evenNull = 0
  let oddNull = 0
  for (let i = 0; i < sample; i++) {
    if (bytes[i] === 0) {
      if (i % 2 === 0) evenNull++
      else oddNull++
    }
  }
  const threshold = (sample / 2) * 0.3
  if (oddNull > threshold && oddNull > evenNull) return 'utf-16le'
  if (evenNull > threshold && evenNull > oddNull) return 'utf-16be'
  return 'utf-8'
}

/** TextDecoder strips a leading BOM for all three labels by default. */
export function decodeText(bytes: Uint8Array, encoding: Encoding): string {
  return new TextDecoder(encoding).decode(bytes)
}

/** Classify content as JSON (only when fully parseable), XML, or plain. */
function detectFormat(text: string): TextFormat {
  const head = text.trimStart()
  if (head.startsWith('{') || head.startsWith('[')) {
    try {
      JSON.parse(text)
      return 'json'
    } catch {
      // Not (yet) valid JSON — maybe truncated. Fall through.
    }
  }
  if (head.startsWith('<')) return 'xml'
  return 'plain'
}

/** Whitespace-only reindent of tag-delimited XML for a readable pretty view. */
function prettyXml(xml: string): string {
  const withBreaks = xml.replace(/>\s*</g, '>\n<')
  let indent = 0
  return withBreaks
    .split('\n')
    .map((raw) => {
      const line = raw.trim()
      if (/^<\/[^>]+>/.test(line)) indent = Math.max(0, indent - 1)
      const out = '  '.repeat(indent) + line
      const opensTag =
        /^<[^!?/][^>]*[^/]>$/.test(line) && !/<\/[^>]+>\s*$/.test(line)
      if (opensTag) indent += 1
      return out
    })
    .join('\n')
}

function LineBody({
  line,
  lineIndex,
  matchesByLine,
  query,
  activeMatch,
  activeRef,
}: {
  line: string
  lineIndex: number
  matchesByLine: Map<number, { start: number; globalIndex: number }[]>
  query: string
  activeMatch: number
  activeRef: RefObject<HTMLElement | null>
}) {
  const hits = query ? matchesByLine.get(lineIndex) : undefined
  if (!hits || hits.length === 0) {
    return <span className="av-text-linebody mono">{line}</span>
  }
  const nodes: ReactNode[] = []
  let cursor = 0
  for (const { start, globalIndex } of hits) {
    if (start > cursor) nodes.push(line.slice(cursor, start))
    const isActive = globalIndex === activeMatch
    nodes.push(
      <mark
        key={globalIndex}
        ref={
          isActive
            ? (el: HTMLElement | null) => {
                activeRef.current = el
              }
            : undefined
        }
        className={isActive ? 'av-text-match active' : 'av-text-match'}
      >
        {line.slice(start, start + query.length)}
      </mark>,
    )
    cursor = start + query.length
  }
  if (cursor < line.length) nodes.push(line.slice(cursor))
  return <span className="av-text-linebody mono">{nodes}</span>
}

export function TextTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const queryClient = useQueryClient()
  // Both ids identify the content: artifact UUIDs are not globally unique
  // across cases, so gating on artifactId alone would let an in-place case
  // switch show case A's text under case B (BUG-259).
  const scopeKey = `${caseId}/${artifactId}`
  // Switching content must not carry how much is loaded, the in-text search or
  // the match cursor over. Scoped rather than cleared in a `useEffect`, for the
  // same reason `offset` above is: `chunkCount` is part of the query key, so on
  // the render where the ids have already changed but the effect has not run,
  // react-query fetches the NEW artifact at the OLD artifact's chunk count —
  // ranges past the end of a smaller file — and that frame commits with the
  // previous artifact's needle highlighting this artifact's text and a match
  // count that belongs to neither (B2-148 class).
  const [chunkCount, setChunkCount] = useEntityScopedState(scopeKey, 1)
  const [wrap, setWrap] = useState(true)
  const [pretty, setPretty] = useState(false)
  const [search, setSearch] = useEntityScopedState(scopeKey, '')
  const [activeMatch, setActiveMatch] = useEntityScopedState(scopeKey, 0)
  const activeRef = useRef<HTMLElement | null>(null)

  const query = useEntityScopedQuery<{
    bytes: Uint8Array
    done: boolean
    totalSize: number | null
    loaded: number
  }>(scopeKey, {
    queryKey: ['artifact-text', caseId, artifactId, chunkCount],
    queryFn: async () => {
      const parts: Uint8Array[] = []
      let done = false
      let totalSize: number | null = null
      let loaded = 0
      for (let i = 0; i < chunkCount && !done; i++) {
        // Each 256 KiB range is fetched once and cached; "Load more" only
        // requests the next range.
        const chunk = await queryClient.fetchQuery({
          queryKey: ['artifact-text-chunk', caseId, artifactId, i],
          staleTime: Infinity,
          queryFn: () =>
            fetchContentRangeBytes(
              caseId,
              artifactId,
              i * TEXT_CHUNK,
              (i + 1) * TEXT_CHUNK - 1,
            ),
        })
        parts.push(chunk.bytes)
        loaded += chunk.byteLength
        if (chunk.totalSize != null) totalSize = chunk.totalSize
        done =
          chunk.byteLength < TEXT_CHUNK ||
          (chunk.totalSize != null && loaded >= chunk.totalSize)
      }
      const all = new Uint8Array(loaded)
      let offset = 0
      for (const part of parts) {
        all.set(part, offset)
        offset += part.byteLength
      }
      return { bytes: all, done, totalSize, loaded }
    },
  })

  // On a content switch keepPreviousData surfaces the previous artifact's bytes
  // as a placeholder; the shared gate withholds it so it never renders.
  const stale = query.stale
  const data = query.scoped ?? null
  const bytes = data?.bytes ?? EMPTY_BYTES
  const encoding = useMemo(() => detectEncoding(bytes), [bytes])
  const rawText = useMemo(() => decodeText(bytes, encoding), [bytes, encoding])
  const format = useMemo(() => detectFormat(rawText), [rawText])
  const displayText = useMemo(() => {
    if (!pretty) return rawText
    if (format === 'json') {
      try {
        return JSON.stringify(JSON.parse(rawText), null, 2)
      } catch {
        return rawText
      }
    }
    if (format === 'xml') return prettyXml(rawText)
    return rawText
  }, [rawText, pretty, format])

  const allLines = useMemo(() => displayText.split('\n'), [displayText])
  const lines = useMemo(
    () =>
      allLines.length > MAX_RENDER_LINES
        ? allLines.slice(0, MAX_RENDER_LINES)
        : allLines,
    [allLines],
  )
  const linesTruncated = allLines.length > MAX_RENDER_LINES

  // Find searches every line that has been LOADED, not the slice that is
  // rendered. Searching `lines` reported "0 / 0" for text that is present past
  // line 5000 in bytes the viewer already holds, which is a forensic search
  // saying the term does not occur when it does (B8-033).
  const matches = useMemo(() => {
    if (!search) return [] as { line: number; start: number }[]
    const needle = search.toLowerCase()
    const found: { line: number; start: number }[] = []
    allLines.forEach((line, li) => {
      const haystack = line.toLowerCase()
      let idx = haystack.indexOf(needle)
      while (idx !== -1) {
        found.push({ line: li, start: idx })
        idx = haystack.indexOf(needle, idx + needle.length)
      }
    })
    return found
  }, [allLines, search])

  // Matches past the rendered slice are counted and navigable, but cannot be
  // highlighted; the toolbar says which line the current one is on instead of
  // silently doing nothing.
  const hiddenMatches = matches.filter((m) => m.line >= lines.length).length
  const activeMatchLine = matches[activeMatch]?.line
  const activeIsHidden =
    activeMatchLine != null && activeMatchLine >= lines.length

  const matchesByLine = useMemo(() => {
    const map = new Map<number, { start: number; globalIndex: number }[]>()
    matches.forEach((m, globalIndex) => {
      const arr = map.get(m.line) ?? []
      arr.push({ start: m.start, globalIndex })
      map.set(m.line, arr)
    })
    return map
  }, [matches])

  useEffect(() => setActiveMatch(0), [search, displayText])
  useEffect(() => {
    const node = activeRef.current
    if (typeof node?.scrollIntoView === 'function') {
      node.scrollIntoView({ block: 'nearest' })
    }
  }, [activeMatch])

  if (query.isPending || stale) {
    return <div className="loading">Loading text...</div>
  }
  if (query.isError) {
    return (
      <div className="error-note">
        Failed to load text: {query.error?.message}
      </div>
    )
  }
  if (bytes.length === 0) {
    return (
      <div className="empty-state">
        <h3>No content</h3>
        <p>This artifact has no readable content.</p>
      </div>
    )
  }

  const canPretty = format === 'json' || format === 'xml'
  const goPrev = () =>
    setActiveMatch((a) =>
      matches.length ? (a - 1 + matches.length) % matches.length : 0,
    )
  const goNext = () =>
    setActiveMatch((a) => (matches.length ? (a + 1) % matches.length : 0))

  return (
    <div className="av-text-viewer">
      <div className="av-text-toolbar">
        <button
          className="btn"
          aria-pressed={wrap}
          onClick={() => setWrap((w) => !w)}
        >
          Wrap: {wrap ? 'on' : 'off'}
        </button>
        {canPretty && (
          <button
            className="btn"
            aria-pressed={pretty}
            onClick={() => setPretty((p) => !p)}
          >
            {pretty ? 'Raw' : `Pretty ${format.toUpperCase()}`}
          </button>
        )}
        <div className="av-text-search">
          <label>
            Find
            <input
              className="input mono"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="text to find"
            />
          </label>
          {search && (
            <span className="av-text-match-nav">
              <span className="mono">
                {matches.length ? activeMatch + 1 : 0} / {matches.length}
              </span>
              <button
                className="btn"
                disabled={matches.length === 0}
                aria-label="Previous match"
                onClick={goPrev}
              >
                Prev
              </button>
              <button
                className="btn"
                disabled={matches.length === 0}
                aria-label="Next match"
                onClick={goNext}
              >
                Next
              </button>
              {activeIsHidden && (
                <span className="av-note" data-testid="av-text-match-offscreen">
                  match on line {(activeMatchLine ?? 0) + 1}, past the{' '}
                  {formatCount(MAX_RENDER_LINES)} lines rendered below
                </span>
              )}
            </span>
          )}
        </div>
        {hiddenMatches > 0 && (
          <p className="av-note" data-testid="av-text-match-hidden">
            {formatCount(hiddenMatches)} of these{' '}
            {formatCount(matches.length)} matches are past line{' '}
            {formatCount(MAX_RENDER_LINES)} and are counted but not
            highlighted. The count covers every line loaded so far; text in
            bytes not yet loaded is not searched at all.
          </p>
        )}
      </div>
      <p className="av-note av-text-readout">
        Loaded {formatBytes(data?.loaded ?? bytes.length)}
        {data?.totalSize != null && ` of ${formatBytes(data.totalSize)}`} ·{' '}
        {formatCount(rawText.length)} chars ·{' '}
        {formatCount(allLines.length)} lines · {encoding.toUpperCase()}
      </p>
      <div className={wrap ? 'av-text-code' : 'av-text-code av-text-nowrap'}>
        {lines.map((line, li) => (
          <div className="av-text-line" key={li}>
            <span className="av-text-lineno mono" aria-hidden="true">
              {li + 1}
            </span>
            <LineBody
              line={line}
              lineIndex={li}
              matchesByLine={matchesByLine}
              query={search}
              activeMatch={activeMatch}
              activeRef={activeRef}
            />
          </div>
        ))}
      </div>
      {linesTruncated && (
        <p className="av-note">
          Showing the first {formatCount(MAX_RENDER_LINES)} lines. Download
          the file to view the remainder.
        </p>
      )}
      {data && !data.done && (
        <button
          className="btn av-load-more"
          disabled={query.isFetching}
          onClick={() => setChunkCount(chunkCount + 1)}
        >
          Load more
        </button>
      )}
    </div>
  )
}
