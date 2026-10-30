import { useQuery } from '@tanstack/react-query'
import { SkeletonTable } from '../../components/Skeleton'
import { Fragment, useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { HelpCircle } from 'lucide-react'
import { ApiRequestError } from '../../api/http'
import type { ArtifactType } from '../../api/types'
import { useProcessingActive } from '../../app/ProcessingContext'
import { useToast } from '../../components/toast/ToastProvider'
import { useRovingRows } from '../../hooks/useRovingRows'
import { DownloadIncompleteError, downloadFile } from '../../lib/download'
import { formatCount } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { HitsPager } from './HitsPager'
import { SearchIndexRepair } from './SearchIndexRepair'
import { ByteSweepPanel } from './ByteSweepPanel'
import { usePivot } from '../../app/PivotContext'
import {
  SEARCH_EXPORT_ROW_BYTES,
  exportTerminator,
  searchArtifacts,
} from './api'
import { parseKeywords } from './keywordList'
import { REGEX_PRESETS } from './presets'
import { snippetSegments } from './snippet'
import './search.css'

const ARTIFACT_TYPES: ArtifactType[] = [
  'Container',
  'RawEvidence',
  'Partition',
  'FileSystem',
  'FileEntry',
  'FileContent',
  'SystemArtifact',
  'ParsedRecord',
  'TimelineEvent',
  'UnallocatedSpace',
  'SlackSpace',
]

const LIMITS = [100, 500, 1000]

/** The page size used when the URL does not usefully state one. */
const DEFAULT_LIMIT = 100

/**
 * Read the page size out of the URL.
 *
 * `limit` reaches this page from a hand-edited or shared URL exactly as readily
 * as it reaches it from the dropdown, so it is validated here rather than
 * trusted. A value that is not a positive whole number is not a page size at
 * all, and forwarding it would put `NaN` in the query string and earn a
 * refusal naming a parameter the examiner never typed; it therefore reads as
 * the default, the same reading `offset` below gives a malformed value.
 *
 * A usable size the dropdown does not happen to offer — `?limit=300` — is
 * honoured rather than snapped to one of the three fixed choices: it is a
 * legitimate request this server will serve, and quietly changing the page size
 * behind a shared link would mean two examiners opening the same URL read
 * different slices of the match set. The dropdown states whatever size is in
 * force, and the pager below is laid out over the size the server APPLIED, so
 * an unoffered size is safe as well as honest.
 */
function parseLimit(raw: string | null): number {
  if (raw == null) return DEFAULT_LIMIT
  const limit = Number(raw)
  if (!Number.isInteger(limit) || limit < 1) return DEFAULT_LIMIT
  return limit
}

/**
 * How many terms one "Run all" pass will search for.
 *
 * The results table is a triage document: a term with a zero beside it is
 * evidence of absence to the examiner reading it. A term that was never run has
 * no row at all, which reads the same way as a term nobody typed — so whenever
 * this cap bites, the count of unrun terms is stated on screen.
 */
const KEYWORD_RUN_CAP = 200

/**
 * One row of the keyword-triage table.
 *
 * `count` is the server's `total_count` — how many artifacts match the term,
 * not how many rows came back — and `lowerBound` says whether that figure is
 * exact or a floor the scan stopped short of. The two are carried separately
 * because this table is copied into triage notes: "12" and "at least 12" lead
 * to different decisions about whether a term has been exhausted.
 *
 * `count: -1` marks a request that FAILED. It is rendered as "error", never as
 * a number, because a failed lookup is not a zero-hit result.
 */
interface KeywordHit {
  term: string
  count: number
  lowerBound: boolean
}

export function SearchPage() {
  const { caseId = '' } = useParams()
  const toast = useToast()
  const [searchParams, setSearchParams] = useSearchParams()

  // Submitted search lives in the URL so results are shareable.
  const submitted = {
    q: searchParams.get('q') ?? '',
    types: searchParams.get('types') ?? '',
    extensions: searchParams.get('extensions') ?? '',
    regex: searchParams.get('regex') === 'true',
    fuzzy: searchParams.get('fuzzy') === 'true',
    limit: parseLimit(searchParams.get('limit')),
    // Which page of the match set is on screen. In the URL rather than in
    // component state so that a page of hits is shareable in a handover and so
    // that Back walks the pages the examiner actually read — the same reason
    // the query itself lives there. A hand-edited or malformed value reads as
    // the first page rather than as NaN.
    offset: Math.max(
      0,
      Math.trunc(Number(searchParams.get('offset') ?? '0')) || 0,
    ),
    // The position a walk reached, when this page was arrived at by walking
    // rather than by jumping. In the URL for the same reasons the offset is —
    // shareable, and Back walks the pages actually read — with the difference
    // that a cursor can go stale: it is pinned to the index snapshot it was
    // minted against, and the server refuses it rather than re-basing it once
    // the index moves. That refusal is rendered below; it is the honest end of
    // a shared deep link, and a better one than silently showing a different
    // set of rows under the same page number.
    cursor: searchParams.get('cursor') ?? '',
  }

  const [q, setQ] = useState(submitted.q)
  const [types, setTypes] = useState<string[]>(
    submitted.types ? submitted.types.split(',') : [],
  )
  const [extensions, setExtensions] = useState(submitted.extensions)
  const [regex, setRegex] = useState(submitted.regex)
  const [fuzzy, setFuzzy] = useState(submitted.fuzzy)
  const [limit, setLimit] = useState(submitted.limit)
  const [helpOpen, setHelpOpen] = useState(false)
  const [exporting, setExporting] = useState<'json' | 'csv' | null>(null)
  const { openPivot } = usePivot()
  // What the last export attempt left on disk, when what it left was not a
  // whole file. Held on the page rather than in a toast because it describes a
  // file that still exists after the toast has gone.
  //
  // Scoped to the case for the same reason the keyword list below is: this page
  // stays mounted across a `:caseId` change, and this sentence is a statement
  // about a file written from ONE case's match set — "… is a FRAGMENT … it must
  // not be tendered as the result of this query". Left unscoped it keeps
  // standing under case B's heading, where an examiner reads it as a statement
  // about case B's export; nothing in the sentence names a case, and the
  // suggested filename it quotes is the same literal string for every case, so
  // nothing on screen tells the two apart. That either condemns a sound exhibit
  // or, once the note has outlived a successful export, teaches the examiner to
  // ignore the next real one. Scoping also disowns the note from an export
  // started under case A that fails only AFTER the examiner has moved on: the
  // setter is bound to the case it was captured under, so a late failure lands
  // where nothing reads it rather than on case B's screen.
  const [exportNote, setExportNote] = useEntityScopedState<string | null>(
    caseId,
    null,
  )
  // The keyword list itself is case-scoped too, not only its counts. It is an
  // examiner's term list for ONE investigation — names, handles, account
  // numbers — and this page stays mounted across a `:caseId` change, so an
  // unscoped textarea carries case A's terms into case B. Running them there
  // searches the wrong evidence for the wrong words and writes those counts
  // into case B's triage, with nothing on screen saying where the list came
  // from. Scoped rather than cleared in an effect, for the same reason the
  // counts below are.
  const [keywords, setKeywords] = useEntityScopedState(caseId, '')
  // The main search is case-keyed through its query key, but the keyword-list
  // hit counts are page state and this page stays mounted across a `:caseId`
  // route change. Case A's per-term counts would otherwise keep rendering as
  // case B's triage volumes — numbers an examiner writes into a report.
  //
  // Clearing them in a `useEffect` still painted one committed frame of case
  // A's counts under case B's heading; scoping them to the case makes the
  // counts unreadable outside the case they were measured in (BUG-261).
  const [kwResults, setKwResults] = useEntityScopedState<KeywordHit[] | null>(
    caseId,
    null,
  )
  const [kwRunning, setKwRunning] = useEntityScopedState(caseId, false)
  // Terms the last run left unsearched because of KEYWORD_RUN_CAP.
  const [kwSkipped, setKwSkipped] = useEntityScopedState(caseId, 0)
  const kwFileInput = useRef<HTMLInputElement>(null)
  // Generation guard: only the latest keyword-list run may write state, so a
  // slow earlier run can't clobber a later run's results or fire after unmount.
  const kwRunId = useRef(0)
  useEffect(() => () => void (kwRunId.current += 1), [])
  // Disown a run still in flight when the case changes. Scoping the results
  // already keeps its counts from being read under another case, but without
  // this the run would still be live and its counts would appear — unasked for,
  // and long after the fact — if the examiner navigated back to the case.
  useEffect(() => {
    kwRunId.current += 1
  }, [caseId])

  // Keep form state in sync with the URL so back/forward navigation
  // restores what was actually searched.
  const urlKey = searchParams.toString()
  useEffect(() => {
    setQ(searchParams.get('q') ?? '')
    const t = searchParams.get('types') ?? ''
    setTypes(t ? t.split(',') : [])
    setExtensions(searchParams.get('extensions') ?? '')
    setRegex(searchParams.get('regex') === 'true')
    setFuzzy(searchParams.get('fuzzy') === 'true')
    setLimit(parseLimit(searchParams.get('limit')))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlKey])

  const hasQuery = submitted.q.trim() !== ''

  // `offset` and `cursor` are mutually exclusive, and the server refuses a
  // request carrying both — rightly, since the two need not name the same
  // place and picking one by precedence would put rows on screen belonging to a
  // page nobody asked for.
  const requestQuery = {
    q: submitted.q,
    limit: submitted.limit,
    offset: submitted.cursor ? undefined : submitted.offset,
    cursor: submitted.cursor || undefined,
    types: submitted.types || undefined,
    extensions: submitted.extensions || undefined,
    regex: submitted.regex || undefined,
    // Fuzzy is a full-text feature; it is meaningless in regex mode.
    fuzzy: submitted.fuzzy && !submitted.regex ? 'true' : undefined,
  }

  const search = useQuery({
    queryKey: ['search', caseId, submitted],
    queryFn: () => searchArtifacts(caseId, requestQuery),
    enabled: caseId !== '' && hasQuery,
  })

  const hits = search.data?.results ?? []

  // A cursor the server would not honour, and its explanation.
  //
  // Recognised by its error CODE rather than by its prose, so the branch does
  // not depend on wording an examiner may one day see translated. The message
  // itself is passed through verbatim: the server is the only party that knows
  // WHICH promise the cursor could not keep — a moved index, a different query,
  // a mangled link — and each of those needs a different sentence.
  const cursorRefusal =
    search.error instanceof ApiRequestError &&
    search.error.code === 'SEARCH_CURSOR_REFUSED'
      ? search.error.message
      : null

  // A jump the server would not make, and its explanation.
  //
  // Distinct from a refused cursor, because the examiner's next move is
  // different. A cursor refusal means the walk has to start again; a jump
  // refusal means this POSITION cannot be jumped to on this search — the
  // extension filter runs after retrieval over a bounded window, or the scan
  // ran out of budget, so the deepest reachable offset is a property of the
  // data — and the way to it is to walk from the first page by cursor, or to
  // export. The server's sentence says how far a jump reaches and, above all,
  // that the match set does NOT end there; it is passed through verbatim.
  const jumpRefusal =
    search.error instanceof ApiRequestError &&
    search.error.code === 'SEARCH_OFFSET_UNREACHABLE'
      ? search.error.message
      : null

  // ---- Where this page of hits sits in the match set ----
  //
  // Every figure below comes from what the SERVER said it served, never from
  // what this page asked for. A server that ignored `offset` and returned the
  // first rows again would otherwise have them numbered 101–200 on the strength
  // of the request alone, which is a false position on a screen that gets
  // quoted. `offset` absent therefore means "this server does not page": no
  // pager is offered and the rows are not numbered, because neither claim can
  // be supported. It is the same reading the filters page gives an absent
  // `scan_complete` — absent is "not stated", not "zero".
  const servedOffset = search.data?.offset
  const canPage = servedOffset != null
  // The limit the server APPLIED. It clamps, so paging in the steps we asked
  // for rather than the ones it serves would skip or repeat matches.
  const pageSize = Math.max(1, search.data?.limit ?? submitted.limit)
  const totalMatches = search.data?.total_count ?? 0
  const totalIsFloor = search.data?.count_is_lower_bound === true
  // The deepest offset the endpoint will answer, if it said. Matches past
  // `maxOffset + pageSize` are counted in `total_count` and cannot be opened
  // from this screen; that shortfall is stated rather than left as a pager
  // that quietly stops.
  const maxOffset = search.data?.max_offset
  // The deepest page an OFFSET may name, expressed as the offset it starts at.
  //
  // Pages are laid out in steps of `pageSize` from offset 0, and the ceiling is
  // a fixed number of MATCHES that need not fall on that grid: with a page size
  // of 300 against a ceiling of 100,000, the last page whose offset the server
  // will answer starts at 99,900, and the next one along starts at 100,200 —
  // past the ceiling, and refused outright rather than served nearer. Rounding
  // down to the grid is what keeps every page this screen names by offset a
  // page the server will actually serve.
  const lastPageOffset =
    maxOffset != null ? Math.floor(maxOffset / pageSize) * pageSize : null
  // How far into the match set a JUMP can land. Not how far the evidence goes:
  // the cursor below walks past this, and the difference between "cannot be
  // jumped to" and "cannot be reached" is the difference between an
  // inconvenience and a false absence.
  const jumpableMatches =
    lastPageOffset != null
      ? Math.min(totalMatches, lastPageOffset + pageSize)
      : totalMatches
  const beyondJumpReach = Math.max(0, totalMatches - jumpableMatches)
  const page = canPage ? Math.floor(servedOffset / pageSize) + 1 : 1
  // Laid out over every match, because every match is now reachable — by
  // walking if not by jumping. A total that stopped at the jump ceiling would
  // tell an examiner standing on page 1,002 that they were past the end.
  const totalPages = Math.max(1, Math.ceil(totalMatches / pageSize))
  const lastJumpablePage = Math.max(1, Math.ceil(jumpableMatches / pageSize))

  // ---- Which control can reach the next page, and can anything reach it ----
  //
  // The cursor the server hands back with a page is the authority on whether
  // more follow: it is minted from the enumeration itself, so its presence is
  // the server's own evidence and its ABSENCE is the server's claim that the
  // set ended here. Where it is absent because the server is too old to state
  // one at all, the arithmetic below is the fallback, and it is the weaker
  // instrument — it can only guess from a count the server may have declined
  // to vouch for.
  const cursorStated = search.data != null && 'next_cursor' in search.data
  const nextCursor = search.data?.next_cursor ?? null
  // Whether a further page could be asked for by OFFSET. Asked separately from
  // whether there are further matches, because the ceiling is the server's
  // policy and the count is the case's evidence.
  const nextPageIsWithinCeiling =
    canPage && (maxOffset == null || servedOffset + pageSize <= maxOffset)
  // Two independent reasons to believe there is more, and either will do.
  //
  // The first is arithmetic over the stated count, which settles it whenever
  // the count is exact. The second is the shape of the page in hand: a page
  // that came back FULL is the server's own evidence that it stopped at the
  // limit rather than at the end of the matches. The second reason is what
  // keeps a floor from becoming a wall — `count_is_lower_bound` means the
  // server declined to say how many matches there are, and treating the number
  // it declined to vouch for as the end of the set would strand the examiner
  // at precisely the count that was never a total. Overshooting costs one
  // request and an honestly-labelled empty page; under-offering costs matches
  // the examiner is obliged to review and never learns exist.
  const countSuggestsMore =
    canPage &&
    (servedOffset + hits.length < totalMatches ||
      (totalIsFloor && hits.length >= pageSize))
  const hasNextPage = cursorStated
    ? nextCursor != null
    : nextPageIsWithinCeiling && countSuggestsMore
  // Prev is a jump like any other, so it stops where jumps stop. Past the
  // ceiling a walk can go forward and back to the top, but not back one step —
  // and the control says so rather than looking broken. Carrying the visited
  // cursors in the URL so Prev could replay them was considered and rejected;
  // the reasons are written out in `HitsPager`, and the short version is that
  // every page walked is already pushed onto the history stack by `goToPage` /
  // `goToNextPage` below, so the browser's Back does it without lengthening a
  // link that gets shared and quoted.
  const prevPageOffset = canPage ? Math.max(0, servedOffset - pageSize) : 0
  const prevPageIsReachable =
    canPage &&
    servedOffset > 0 &&
    (maxOffset == null || prevPageOffset <= maxOffset)

  // ---- Is this still one walk of one result set? ----
  //
  // The order a page boundary rests on is the index's own physical layout, and
  // in this product that layout moves while an examiner reads: ingest commits
  // new documents, and the display-name repair rewrites existing ones. Page 2
  // of the re-laid index does not continue page 1 of the old one — rows can
  // repeat across the seam and rows can fall through it. Nothing here can
  // prevent that, and refusing to serve the page would strand an examiner
  // working a case that is still being ingested, which is the ordinary case
  // rather than an edge. What this can do is decline to present two
  // enumerations as one, by holding the snapshot the current walk began at and
  // noticing when the server stops matching it.
  //
  // The anchor resets on any change to the query itself, and again whenever the
  // examiner lands on the first page: page 1 of whatever the index is now is a
  // coherent beginning in its own right, so the warning describes a walk, not a
  // permanent mark on the query.
  const walkKey = [
    caseId,
    submitted.q,
    submitted.types,
    submitted.extensions,
    String(submitted.regex),
    String(submitted.fuzzy),
    String(submitted.limit),
  ].join('\x00')
  const servedSnapshot = search.data?.index_snapshot
  // Assigned during render rather than from an effect, the way the filters page
  // resolves its active case: a page that arrives between the render and its
  // passive effects would otherwise be compared against the previous walk's
  // anchor and painted as a false alarm — or, worse, as a false all-clear.
  const walkAnchor = useRef<{ key: string; snapshot: string } | null>(null)
  if (servedSnapshot != null) {
    if (walkAnchor.current?.key !== walkKey || servedOffset === 0) {
      walkAnchor.current = { key: walkKey, snapshot: servedSnapshot }
    }
  }
  const indexMovedUnderThisWalk =
    servedSnapshot != null &&
    walkAnchor.current != null &&
    walkAnchor.current.key === walkKey &&
    walkAnchor.current.snapshot !== servedSnapshot

  // The corpus itself is still growing while ingest runs, which makes every
  // figure on this page a floor for a reason none of the server's flags
  // describe: they are about what the scan could count, this is about what had
  // been indexed by the time it ran.
  const processingActive = useProcessingActive()

  const navigate = useNavigate()
  // Keyboard navigation on the shared roving-tabindex primitive: the results
  // table is one tab stop, the arrows move real DOM focus (so a screen reader
  // reads out the row arrived at), and the hook scrolls the focused row into
  // view — with a limit of 1,000 the focus otherwise walks off the bottom of
  // the container. No `onMove` handler, because this table carries no selection
  // for a keyboard move to disturb.
  const roving = useRovingRows({
    count: hits.length,
    onActivate: (index) => {
      const hit = hits[index]
      if (hit) navigate(`/cases/${caseId}/artifacts/${hit.artifact_id}`)
    },
  })

  function toggleType(type: string) {
    setTypes((prev) =>
      prev.includes(type)
        ? prev.filter((t) => t !== type)
        : ARTIFACT_TYPES.filter((t) => prev.includes(t) || t === type),
    )
  }

  function submit(query: string, useRegex: boolean) {
    const trimmed = query.trim()
    if (!trimmed) return
    const next = new URLSearchParams()
    next.set('q', trimmed)
    if (types.length > 0) next.set('types', types.join(','))
    if (extensions.trim()) next.set('extensions', extensions.trim())
    if (useRegex) next.set('regex', 'true')
    if (fuzzy && !useRegex) next.set('fuzzy', 'true')
    if (limit !== DEFAULT_LIMIT) next.set('limit', String(limit))
    setSearchParams(next)
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault()
    submit(q, regex)
  }

  /**
   * Move to `page` (1-based) of the current match set.
   *
   * Pushed onto the history stack rather than replacing, so Back walks the
   * pages of hits the examiner actually read — under S3 that trail is part of
   * what a handover inherits, and the shell's per-history-entry scroll
   * restoration then returns each page to where it was left.
   */
  function goToPage(page: number) {
    const next = new URLSearchParams(searchParams)
    const offset = Math.max(0, (page - 1) * pageSize)
    // A jump abandons the walk: the cursor names a position in an enumeration
    // pinned to one snapshot, and an offset asks the index as it stands now.
    // Leaving both in the URL would ask the server for two different places at
    // once, which it refuses.
    next.delete('cursor')
    if (offset === 0) next.delete('offset')
    else next.set('offset', String(offset))
    setSearchParams(next)
  }

  /**
   * Move to the page after the one on screen.
   *
   * Two routes to the same enumeration, and which one is used is decided by the
   * server's ceiling rather than by preference. Within the ceiling this jumps by
   * offset, exactly as it always has: the URL stays a plain, hand-editable
   * position, Prev keeps working, and a shared link keeps meaning the same page
   * of the index as it stands. Past the ceiling an offset would be refused, and
   * the cursor the last page handed back is what carries the walk on — which is
   * also the point at which those matches stop being unreachable at all.
   *
   * If neither can reach, nothing moves. The pager does not offer the control
   * in that case, so this is the belt to that braces.
   */
  function goToNextPage() {
    const nextOffset = servedOffset != null ? servedOffset + pageSize : pageSize
    const withinCeiling = maxOffset == null || nextOffset <= maxOffset
    const next = new URLSearchParams(searchParams)
    if (withinCeiling && (!cursorStated || countSuggestsMore)) {
      next.delete('cursor')
      next.set('offset', String(nextOffset))
    } else if (nextCursor != null) {
      next.delete('offset')
      next.set('cursor', nextCursor)
    } else {
      return
    }
    setSearchParams(next)
  }

  /** Apply a built-in regex preset: fill the query, force regex on, run it. */
  function applyPreset(id: string) {
    const preset = REGEX_PRESETS.find((p) => p.id === id)
    if (!preset) return
    setQ(preset.pattern)
    setRegex(true)
    submit(preset.pattern, true)
  }

  /** Run every term in the keyword list, collecting per-term hit counts. */
  async function runKeywordList() {
    const all = parseKeywords(keywords)
    const terms = all.slice(0, KEYWORD_RUN_CAP)
    if (terms.length === 0) return
    const runId = ++kwRunId.current
    setKwRunning(true)
    setKwResults(null)
    setKwSkipped(all.length - terms.length)
    // Apply the same type/extension filters the form has set, so the per-term
    // hit counts reflect the current triage scope instead of the whole case.
    const filterTypes = types.length > 0 ? types.join(',') : undefined
    const filterExts = extensions.trim() || undefined
    try {
      const out: KeywordHit[] = []
      // Batch to avoid firing hundreds of requests at once.
      for (let i = 0; i < terms.length; i += 6) {
        const batch = terms.slice(i, i + 6).map((term) =>
          searchArtifacts(caseId, {
            q: term,
            limit: 1,
            types: filterTypes,
            extensions: filterExts,
            regex: regex || undefined,
          })
            .then((r) => ({
              term,
              count: r.total_count,
              // Regex and extension-filtered terms scan a capped candidate
              // window; the server flags the ones it could not count past, and
              // a floor shown as an exact prevalence is the wrong answer this
              // table is most likely to have quoted from it (B3-001).
              lowerBound: r.count_is_lower_bound === true,
            }))
            .catch(() => ({ term, count: -1, lowerBound: false })),
        )
        out.push(...(await Promise.all(batch)))
      }
      if (kwRunId.current === runId) setKwResults(out)
    } finally {
      if (kwRunId.current === runId) setKwRunning(false)
    }
  }

  function exportKeywords() {
    const blob = new Blob([parseKeywords(keywords).join('\n')], {
      type: 'text/plain',
    })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'keywords.txt'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    // Defer revocation: revoking synchronously right after click() can abort the
    // download before the browser reads the blob, yielding an empty keyword list
    // on some browsers (BUG-203, same pattern as BUG-169).
    setTimeout(() => URL.revokeObjectURL(url), 60_000)
  }

  async function importKeywords(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    const text = await file.text()
    setKeywords((prev) => (prev.trim() ? `${prev}\n${text}` : text))
  }

  async function onExport(format: 'json' | 'csv') {
    setExporting(format)
    setExportNote(null)
    try {
      // Deliberately without `offset` OR `cursor`: an export is of the MATCH
      // SET, not of the page the examiner happens to be looking at. The export
      // endpoint walks from the first match under its own ceiling and writes
      // its own shortfall into the file, so handing it this page's position
      // would silently produce an exhibit that starts in the middle and says
      // nothing about the matches before it.
      const {
        offset: _pageOffset,
        cursor: _walkPosition,
        ...exportQuery
      } = requestQuery
      await downloadFile(
        `/cases/${caseId}/search/export/${format}`,
        `search-results.${format}`,
        {
          query: exportQuery,
          // This export walks the WHOLE match set — millions of rows on a real
          // case — and the server streams it at a bounded cost to itself. Said
          // here so the helper writes it to a file as it arrives instead of
          // materialising it in this tab first, which would move the
          // out-of-memory failure from the server to the examiner's machine and
          // deliver it as a dead tab with nothing on screen to explain it.
          unbounded: true,
          // The file states its own completeness in its last row, and states in
          // its preamble that a file missing that row is a fragment. Handing the
          // marker over means a transfer that stops short is reported as one
          // rather than as a finished export.
          terminator: exportTerminator(format),
          // Only ever used to price the fallback, and only on a browser that has
          // no way to stream. `totalIsFloor` carries through so the sentence
          // reads "at least" when the count behind it is a lower bound. A floor
          // of ZERO — the first page of a thinly-spread extension filter, whose
          // candidate window held no survivor — is the one lower bound that
          // carries no information, so no estimate is offered from it: "at
          // least roughly 0 B" prices a file that may be gigabytes as nothing.
          estimatedBytes:
            totalIsFloor && totalMatches === 0
              ? undefined
              : totalMatches * SEARCH_EXPORT_ROW_BYTES[format],
          estimatedBytesIsFloor: totalIsFloor,
        },
      )
    } catch (err) {
      if (err instanceof DownloadIncompleteError) {
        // Not a toast alone. A toast clears itself after ten seconds, and this
        // is a statement about a file that is now on the examiner's disk under
        // a name that looks like an exhibit: it stays on the screen until the
        // next export attempt, in the words the helper used.
        setExportNote(err.message)
        toast.error(
          `The ${format.toUpperCase()} export is a fragment — see the note below the export buttons.`,
        )
      } else {
        toast.error('Export failed')
      }
    } finally {
      setExporting(null)
    }
  }

  const canExport = search.data != null

  // The page sizes the Limit control offers, always including the one actually
  // in force. A `?limit=300` in a shared link is honoured (see `parseLimit`),
  // and a `<select>` whose value matches none of its options renders as its
  // FIRST option — so without this the control would read "100" over a search
  // running 300-row pages, which is a false statement about the query that
  // produced the rows below it.
  const limitChoices = LIMITS.includes(limit)
    ? LIMITS
    : [...LIMITS, limit].sort((a, b) => a - b)

  return (
    <div>
      <h1 className="page-title">Search</h1>

      <form className="srch-form" onSubmit={onSubmit}>
        <div className="srch-field">
          <span>Query</span>
          <div className="srch-q-wrap">
            <input
              className="input srch-q"
              aria-label="Search query"
              autoFocus
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search indexed evidence"
            />
            <button
              type="button"
              className="btn btn-icon"
              aria-label="Search syntax help"
              aria-expanded={helpOpen}
              onClick={() => setHelpOpen((o) => !o)}
            >
              <HelpCircle size={15} />
            </button>
            {helpOpen && (
              <div className="srch-help-pop" role="note">
                <h4>Query syntax</h4>
                <dl>
                  <dt>terms</dt>
                  <dd>
                    Full-text mode tokenizes the query and ranks results by
                    relevance across indexed names and content.
                  </dd>
                  <dt>Boolean</dt>
                  <dd>
                    <code>AND</code>, <code>OR</code>, <code>NOT</code> and
                    grouping with <code>( )</code>, e.g.{' '}
                    <code>malware AND NOT test</code>. Prefix a term with{' '}
                    <code>+</code> (required) or <code>-</code> (excluded).
                  </dd>
                  <dt>Phrase &amp; proximity</dt>
                  <dd>
                    Quote an exact phrase (<code>&quot;error code&quot;</code>);
                    add <code>~N</code> for proximity within N words (
                    <code>&quot;report analysis&quot;~3</code>).
                  </dd>
                  <dt>Fuzzy</dt>
                  <dd>
                    Tick <strong>Fuzzy</strong> to match typos and spelling
                    variants (Levenshtein edit distance 2), e.g.{' '}
                    <code>forensik</code> finds <em>forensics</em>.
                  </dd>
                  <dt>Regex on</dt>
                  <dd>
                    The query is a Rust regular expression applied to stored
                    values. Use it for patterns that cross word boundaries
                    (card numbers, paths, hostnames). It scans the case, so
                    it is slower.
                  </dd>
                  <dt>Extensions</dt>
                  <dd>
                    Comma-separated file extensions, e.g.{' '}
                    <code>exe,dll</code>, limit results to those files.
                  </dd>
                </dl>
              </div>
            )}
          </div>
        </div>
        <fieldset className="srch-field srch-chipset">
          <legend>Artifact types</legend>
          <div className="srch-chips">
            {ARTIFACT_TYPES.map((t) => (
              <label
                key={t}
                className={`srch-chip${types.includes(t) ? ' selected' : ''}`}
              >
                <input
                  type="checkbox"
                  checked={types.includes(t)}
                  onChange={() => toggleType(t)}
                />
                {t}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="srch-field">
          Patterns
          <select
            className="select"
            aria-label="Pattern presets"
            value=""
            onChange={(e) => applyPreset(e.target.value)}
          >
            <option value="">Common patterns…</option>
            {REGEX_PRESETS.map((p) => (
              <option key={p.id} value={p.id} title={p.description}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <label className="srch-field">
          Extensions
          <input
            className="input srch-ext"
            aria-label="Extensions"
            value={extensions}
            onChange={(e) => setExtensions(e.target.value)}
            placeholder="exe,dll,pdf"
          />
        </label>
        <label className="srch-regex">
          <input
            type="checkbox"
            aria-label="Regex"
            checked={regex}
            onChange={(e) => setRegex(e.target.checked)}
          />
          Regex
        </label>
        <label className="srch-regex">
          <input
            type="checkbox"
            aria-label="Fuzzy"
            checked={fuzzy}
            disabled={regex}
            onChange={(e) => setFuzzy(e.target.checked)}
          />
          Fuzzy
        </label>
        <label className="srch-field">
          Limit
          <select
            className="select"
            aria-label="Limit"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            {limitChoices.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className="btn btn-primary">
          Search
        </button>
        <button
          type="button"
          className="btn"
          disabled={submitted.q.trim() === '' || regex}
          title={
            regex
              ? 'Pivot works on a literal value, not a regular expression'
              : 'Group every artifact matching this value by record kind'
          }
          onClick={() => openPivot(submitted.q)}
        >
          Pivot
        </button>
        <div className="srch-export">
          <button
            type="button"
            className="btn"
            disabled={!canExport || exporting !== null}
            onClick={() => onExport('json')}
          >
            {exporting === 'json' ? 'Exporting…' : 'Export JSON'}
          </button>
          <button
            type="button"
            className="btn"
            disabled={!canExport || exporting !== null}
            onClick={() => onExport('csv')}
          >
            {exporting === 'csv' ? 'Exporting…' : 'Export CSV'}
          </button>
        </div>
      </form>

      {exportNote && (
        <p className="error-note" role="note">
          {exportNote}
        </p>
      )}

      <details className="srch-kw">
        <summary>Keyword list ({parseKeywords(keywords).length})</summary>
        <div className="srch-kw-body">
          <textarea
            className="input srch-kw-text mono"
            aria-label="Keyword list"
            placeholder="One search term per line"
            rows={5}
            value={keywords}
            onChange={(e) => setKeywords(e.target.value)}
          />
          <div className="srch-kw-actions">
            <button
              type="button"
              className="btn"
              onClick={() => kwFileInput.current?.click()}
            >
              Import
            </button>
            <input
              ref={kwFileInput}
              type="file"
              accept=".txt,text/plain"
              className="srch-kw-file"
              aria-label="Import keyword list"
              onChange={importKeywords}
            />
            <button
              type="button"
              className="btn"
              onClick={exportKeywords}
              disabled={parseKeywords(keywords).length === 0}
            >
              Export
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={runKeywordList}
              disabled={kwRunning || parseKeywords(keywords).length === 0}
            >
              {kwRunning ? 'Running…' : 'Run all'}
            </button>
          </div>
          {kwResults && kwSkipped > 0 && (
            <div className="error-note" role="note">
              Only the first {formatCount(KEYWORD_RUN_CAP)} terms were searched.{' '}
              {formatCount(kwSkipped)} further term
              {kwSkipped === 1 ? ' was' : 's were'} not run and have no row
              below — that is not a zero-hit result for them.
            </div>
          )}
          {kwResults && (
            <table className="data-table srch-kw-results">
              <thead>
                <tr>
                  <th>Term</th>
                  <th>Hits</th>
                </tr>
              </thead>
              <tbody>
                {kwResults.map((r) => (
                  <tr key={r.term}>
                    <td>
                      <button
                        type="button"
                        className="link-button"
                        onClick={() => submit(r.term, regex)}
                      >
                        {r.term}
                      </button>
                    </td>
                    <td className="mono">
                      {r.count < 0
                        ? 'error'
                        : r.lowerBound
                          ? `≥ ${formatCount(r.count)}`
                          : formatCount(r.count)}
                      {r.lowerBound && (
                        <span
                          className="badge badge-warn"
                          title="The scan stopped at a server-side budget before counting every match, so this is a floor. More artifacts contain this term than the number shown."
                        >
                          lower bound
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </details>

      {/* Keyed on the case so a `:caseId` change throws the panel away rather
          than re-labelling it. This page stays mounted across that change, and
          the receipt for a repair of case A — or the banner saying case A's
          display names are being rewritten — is a statement about case A and
          about no other case. Left unkeyed it would sit there under case B's
          heading, which is the defect BUG-261 fixed for the keyword counts. */}
      <SearchIndexRepair key={caseId} caseId={caseId} />

      {/* The case-wide byte sweep (ROADMAP §1.2): the evidence bytes, not the
          index. Keyed on the case for the same reason as the panel above — an
          answer on screen is a statement about one case. */}
      <ByteSweepPanel key={`sweep-${caseId}`} caseId={caseId} />

      {!hasQuery ? (
        <div className="empty-state">
          <h3>Search across all indexed evidence</h3>
          <p>File names, content, parsed records and timeline events.</p>
        </div>
      ) : search.isPending ? (
        <SkeletonTable rows={10} cols={4} label="Searching" />
      ) : cursorRefusal != null ? (
        /* A refused cursor is not a failed search and must not be dressed as
           one. The walk this page belonged to was pinned to one state of the
           index, the index has moved (or the link was for another search), and
           the server declined to serve rows from a different enumeration under
           the same page number. That refusal is the honest answer — the
           alternative is a screen of rows that look like a continuation of a
           set that gained and lost members at the seam — so it is rendered as a
           statement about the walk, with the one control that is still sound. */
        <div className="empty-state">
          <h3>This page of results can no longer be shown</h3>
          <p>{cursorRefusal}</p>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => goToPage(1)}
          >
            Go back to the first page
          </button>
        </div>
      ) : jumpRefusal != null ? (
        /* A refused jump is not a failed search and is not the end of the
           match set. It is rendered as a statement about this position on this
           search, in the server's own words — which say how deep a jump can
           reach and which routes go past it — with the control that reaches:
           the first page, from which Next walks by cursor through every match
           the jump could not land on. The alternative was the empty page this
           replaced, which read as "nothing further to review" (SHIP-034). */
        <div className="empty-state" data-testid="search-jump-refused">
          <h3>This page cannot be jumped to on this search</h3>
          <p>{jumpRefusal}</p>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => goToPage(1)}
          >
            Go to the first page and walk from there
          </button>
        </div>
      ) : search.isError ? (
        <div className="error-note">Search failed: {search.error.message}</div>
      ) : /* "Nothing matched" is a claim about the CASE, and it may only be
            made about the first page. An empty page further in is a claim
            about a POSITION — the examiner stepped one page past the end, or
            opened a shared link to a page the index has since moved out from
            under. Rendering the two the same way puts "Nothing matched
            malware" on a screen beside a stated count of 250, which reads as
            evidence of absence and is the worst sentence this page can
            produce. So the deep-empty case falls through to the results branch
            below, where the count, the caveats and the pager are all still on
            screen and the rows are replaced by a statement about where the
            examiner is standing. */
      search.data.results.length === 0 && !(canPage && servedOffset > 0) ? (
        <div className="empty-state">
          <h3>No results</h3>
          <p>Nothing matched &ldquo;{submitted.q}&rdquo;.</p>
          {/* "No results" is only "absent" within the scope searched, so the
              server's statement of that scope sits beside it (SEARCH-002). */}
          {search.data.universe?.statement ? (
            <p className="srch-universe" role="note">
              <strong>What was searched:</strong>{' '}
              {search.data.universe.statement}
            </p>
          ) : (
            /* An older server states no scope. Silence would read as "absent
               from the evidence"; saying the scope is unknown does not. */
            <p className="srch-universe" role="note">
              The server did not state what this search covers, so this is not
              a finding that the term is absent from the evidence.
            </p>
          )}
        </div>
      ) : (
        <>
          <p className="srch-meta">
            {/* `total_count` is how many artifacts MATCH, not how many rows are
                in the table below. When the server could not count past its
                scan budget it says so, and the figure is a floor — rendering a
                floor identically to an exact count is the difference between
                "37 documents mention this term" and "at least 37 do", which is
                not a difference a report can absorb (B3-001). */}
            {search.data.count_is_lower_bound ? 'At least ' : ''}
            {formatCount(search.data.total_count)} matching{' '}
            {search.data.total_count === 1 ? 'artifact' : 'artifacts'} in{' '}
            {search.data.elapsed_ms} ms
          </p>
          {search.data.universe?.statement && (
            <details className="srch-universe">
              <summary>What this search covers</summary>
              <p>{search.data.universe.statement}</p>
            </details>
          )}
          {/* The position of these rows in that match set — a separate claim
              from the count above, and one this page may only make when the
              server stated which page it served. */}
          {canPage && (
            <p className="srch-position">
              Showing matches {formatCount(servedOffset + 1)}–
              {formatCount(servedOffset + hits.length)} of{' '}
              {totalIsFloor ? 'at least ' : ''}
              {formatCount(totalMatches)}.
            </p>
          )}
          {/* Derived from the rows in hand rather than from the server's
              `truncated` flag: a server old enough not to state its offset is
              exactly the one whose flags this page should not be leaning on. */}
          {!canPage && (totalMatches > hits.length || totalIsFloor) && (
            <p className="error-note" role="note">
              This server did not state which page of the match set it returned,
              so these rows cannot be numbered against the{' '}
              {totalIsFloor ? 'at least ' : ''}
              {formatCount(search.data.total_count)} matching{' '}
              {search.data.total_count === 1 ? 'artifact' : 'artifacts'} above,
              and there is no way to page past them. Narrow the query, or use
              the export, which carries a higher ceiling and states its own
              shortfall.
            </p>
          )}
          {processingActive && (
            <p className="warn-note" role="note">
              Processing is still running on this case, so the index behind
              these results is still growing. Every figure here is a floor as of
              the moment the search ran — an absence below is not evidence of
              absence. Run the search again to see what has been indexed since.
            </p>
          )}
          {/* Two claims that have to stay separate, because the difference
              between them is the difference between an inconvenience and a
              false absence: where JUMPING stops, and where the evidence stops.
              It stops nowhere — Next walks past this point — and the note says
              so before it says anything else.

              What the note deliberately does NOT do is state the export's
              reach. This screen is never told the export's ceiling: no field of
              the search response carries it, and the wording that used to
              assert the export "stops at the same depth" was reading that off
              `max_offset`, which happens to equal the export limit in the
              server's constants and is not the same depth anyway — jumping runs
              to the end of the page containing the ceiling, the export stops at
              the ceiling itself. An examiner quoting this screen for what an
              exhibit covers would have been over by up to a page. The export
              states its own shortfall in the file it produces, that statement
              is made by the party that knows, and the note points at it instead
              of competing with it. */}
          {beyondJumpReach > 0 && (
            <p className="warn-note" role="note">
              Jumping to a page stops at match {formatCount(jumpableMatches)}.{' '}
              {formatCount(beyondJumpReach)} further matching{' '}
              {beyondJumpReach === 1 ? 'artifact' : 'artifacts'} exist beyond
              it. They are still reachable: Next keeps walking past this point,
              one page at a time, and each page is fetched by resuming where the
              last one stopped. What is not available past it is jumping: no
              page number, and no Prev step on the pager — though your
              browser&rsquo;s Back button still returns to the pages you have
              already walked through. The export is a way past it: it walks
              the whole match set from the first match, with no row ceiling,
              and its final verdict row states whether it reached the end —
              that statement, not this one, says what the export covers. If the index changes while you walk,
              the walk is refused rather than continued onto a re-ordered set,
              and you will be told to start again.
            </p>
          )}
          {indexMovedUnderThisWalk && (
            <p className="warn-note" role="note">
              The search index changed while you were paging: evidence has been
              indexed, or the index has been repaired, since the earlier pages
              were fetched. The pages before this one were taken from a
              different state of the index, so across that boundary a matching
              artifact may have been shown twice or not at all. This page is a
              sound page of the index as it stands now; the walk that led here
              is not one continuous list. Go back to the first page to walk a
              single consistent set.
            </p>
          )}
          {search.data.count_is_lower_bound && (
            <p className="error-note" role="note">
              The match count above is a lower bound, not a total: more
              artifacts match than the number shown. This screen is not told
              which of the several reasons applies — counting stopped at a
              server-side budget, or the index itself is missing documents —
              and those mean different things, so it does not guess. An export
              of this query says which in its verdict row. Do not record the
              number as a prevalence figure.
            </p>
          )}
          {/* A position, not a verdict. The count above still stands and is
              still on screen; what is empty is this page of it. The `!= null`
              is the outer branch's invariant restated for the compiler: this
              case is only reachable when the server stated an offset past the
              first page. */}
          {hits.length === 0 && servedOffset != null ? (
            <div className="empty-state">
              <h3>No matches at this position</h3>
              <p>
                This page starts at match {formatCount(servedOffset + 1)}, and
                the server returned no rows there. Either the walk has run past
                the end of the match set, or the index has moved since this page
                number was chosen.
              </p>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => goToPage(1)}
              >
                Go back to the first page
              </button>
            </div>
          ) : (
            <table className="data-table srch-results">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Name</th>
                  <th>Snippet</th>
                  <th>Score</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((result, index) => (
                  <tr key={result.artifact_id} {...roving.getRowProps(index)}>
                    <td>
                      <span className="badge badge-accent">
                        {result.artifact_type}
                      </span>
                    </td>
                    <td>
                      {/* Kept a real link — an examiner opens hits in new tabs all
                        day — but taken out of the tab order, because the row
                        around it is now the table's single tab stop and Enter on
                        the row follows this same link. Left tabbable it would
                        put the table back to one tab stop per row, which is what
                        the roving hook exists to remove. */}
                      <Link
                        to={`/cases/${caseId}/artifacts/${result.artifact_id}`}
                        tabIndex={-1}
                      >
                        {result.name}
                      </Link>
                    </td>
                    <td className="srch-snippet">
                      {result.snippet != null &&
                        snippetSegments(result.snippet, result.highlights).map(
                          (seg, i) =>
                            seg.mark ? (
                              <mark key={i}>{seg.text}</mark>
                            ) : (
                              <Fragment key={i}>{seg.text}</Fragment>
                            ),
                        )}
                    </td>
                    <td className="mono">{result.score.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {canPage && (
            <HitsPager
              page={page}
              totalPages={totalPages}
              totalIsFloor={totalIsFloor}
              hasNext={hasNextPage}
              prevReachable={prevPageIsReachable}
              lastJumpablePage={lastJumpablePage}
              onPage={goToPage}
              onNext={goToNextPage}
            />
          )}
        </>
      )}
    </div>
  )
}
