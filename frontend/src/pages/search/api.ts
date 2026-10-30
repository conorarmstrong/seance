import type { ExportTerminator } from '../../lib/download'
import { apiFetch, type QueryParams } from '../../api/http'

export interface SearchResult {
  artifact_id: string
  case_id: string
  artifact_type: string
  name: string
  /** Plain-text excerpt around the first hit (no HTML). */
  snippet: string | null
  /** UTF-8 byte offset ranges into `snippet` marking hits (max 8). */
  highlights?: [number, number][] | null
  score: number
}

/**
 * The server's statement of a search's scope: `SearchResponse.universe` here,
 * `SearchPageResponse.universe` in `seance_api`, built by
 * `seance_search::search_universe`.
 */
export interface SearchUniverse {
  /** The whole statement, one paragraph, fit to show or quote. */
  statement: string
  content_artifact_types?: string[]
  content_bytes_per_artifact?: number
  min_run_chars?: number
  utf8?: string
  utf16?: string
  not_covered?: string[]
  /** The byte-sweep route, which reaches what the text index cannot. */
  byte_sweep_route?: string
  /** How this search matched: exact-form, fuzzy (approximate) or regex. */
  matching?: string
  /** The server build's text extractor version. */
  text_extractor_version?: number
  /**
   * Whether THIS case's documents were built by that extractor. `earlier`
   * means some were indexed by an older build, whose UTF-16 coverage was
   * ASCII only; the statement says a re-ingest is needed. `not_assessed`
   * means the statement was not checked against the case's index.
   */
  index_text_extractor?: 'current' | 'earlier' | 'no_file_documents' | 'not_assessed'
  index_text_extractor_versions?: number[]
  /** Known ways a hit is not the text it looks like (e.g. kana from hex). */
  known_false_matches?: string[]
}

export interface SearchResponse {
  results: SearchResult[]
  total_count: number
  query: string
  elapsed_ms: number
  /** True when the result set may be incomplete (server-side limits hit). */
  truncated?: boolean
  /**
   * True when `total_count` is a LOWER BOUND rather than an exact figure.
   *
   * `total_count` is how many artifacts MATCH, not how many rows came back — a
   * distinction the substring, regex and extension-filtered paths make, because
   * they stop at a document or time budget and never count past it. When that
   * happens the server sets this flag, and "at least N" must not be rendered as
   * "N": the keyword-triage table below reads these numbers as a term's
   * prevalence in the case, and a floor written into a triage note as an exact
   * count is a wrong answer, not a missing one.
   */
  count_is_lower_bound?: boolean
  /**
   * The offset the server ACTUALLY served this page from, counted in matches.
   *
   * Optional, and its absence is the load-bearing case: a server that does not
   * state where a page starts may have ignored the `offset` we asked for and
   * returned the first rows instead. Labelling those "matches 101–200" would
   * put a false position on a screen that gets quoted, so the page treats an
   * absent value as "this server cannot page" and offers no pager at all,
   * rather than assuming its own request was honoured. The same reasoning the
   * filters page applies to an absent `scan_complete`.
   */
  offset?: number
  /**
   * The limit the server actually applied, which is not necessarily the one
   * asked for — the endpoint clamps. Used to size the pages, so a clamped
   * request pages in the steps the server really serves.
   */
  limit?: number
  /**
   * The deepest offset this endpoint will serve.
   *
   * It is a ceiling on JUMPING, not on the evidence. The server answers an
   * offset by walking the case from the start and discarding what it passes, so
   * a deep offset is expensive whatever it names; `next_cursor` below is the
   * route past this number, and it resumes rather than re-walking. The screen
   * still has to state where jumping stops, because a pager that ran off the
   * end of what the server will answer would offer pages that come back as
   * refusals.
   */
  max_offset?: number
  /**
   * What the search could reach at all: which bytes were indexed, in which
   * encodings, and what was not (`SEARCH-002`). Built on the server from the
   * indexer's own constants. A zero-hit page is only "absent" within this, so
   * the page shows it beside "No results". Absent from a server too old to
   * state it.
   */
  universe?: SearchUniverse
  /**
   * An opaque token that continues this walk from where this page stopped.
   *
   * `null` is a claim rather than a shrug: the server reached the end of the
   * result set, and "that is all of them" may be rendered on the strength of
   * it. The field being ABSENT is the different case — a server too old to
   * state it — and then only the arithmetic against `total_count` can say
   * whether more follow.
   *
   * A cursor is valid only against the `index_snapshot` it was minted under and
   * the query it was minted for. Handing back a stale one is REFUSED by the
   * server (HTTP 409, code `SEARCH_CURSOR_REFUSED`) rather than re-based onto
   * whatever the index has since become, which is why this page can present a
   * walk as one walk.
   */
  next_cursor?: string | null
  /**
   * How many stored documents the server retrieved and examined to serve this
   * page. Diagnostic; not rendered.
   */
  examined_documents?: number
  /**
   * Fingerprint of the index snapshot this page was served from.
   *
   * Paging joins up only while the index behind it holds still, and in this
   * product it routinely does not: ingest commits new documents and the
   * display-name repair rewrites existing ones, both of which re-segment the
   * index and move the enumeration under an examiner who is part-way through
   * walking it. Two pages carrying the same value are two pages of one result
   * set. Two carrying different values are not, and presenting them as one walk
   * would assert a continuity the server never claimed.
   */
  index_snapshot?: string
}

export const searchArtifacts = (caseId: string, query: QueryParams) =>
  apiFetch<SearchResponse>(`/cases/${caseId}/search`, { query })

/** One access grant on a case, as `GET /cases/{id}/access` returns it. */
export interface CaseAccessGrant {
  user_id: string
  username: string
  access_level: string
}

/**
 * The case's access list — used here only as a question, never for its answer:
 * "would this server let me repair this case's index?"
 *
 * The repair endpoint is gated on owner-or-admin, and this endpoint is gated by
 * the very same server-side function, so a control offered on the strength of a
 * 200 here cannot drift away from what the repair will actually accept. Nothing
 * on the client can answer the question by itself: the session carries a role,
 * but a case's owner is not in it, so a non-admin's ownership is unknowable
 * without asking.
 */
export const listCaseAccess = (caseId: string) =>
  apiFetch<CaseAccessGrant[]>(`/cases/${caseId}/access`)

/** The receipt `POST /cases/{id}/search/reindex` returns. */
export interface SearchIndexRepairReceipt {
  repair_id: string
  /** Always "running": the repair has been spawned, not finished. */
  status: string
}

/**
 * Start a display-name repair over the documents this case already has indexed.
 *
 * `?force=true` is deliberately not a parameter here. It exists to rescue a case
 * whose server was killed mid-repair, leaving a request in the audit trail that
 * no terminal event will ever follow — a rare recovery whose cost, if misjudged,
 * is a second pass over the same index. An examiner cannot tell from this screen
 * whether the repair the server is refusing to duplicate is genuinely in flight
 * or merely a ghost, so a button that overrides the guard would be clicked on a
 * guess. The refusal the server sends back names the override and says what it
 * is for, and that message is put in front of the examiner verbatim; the rescue
 * itself stays a deliberate act, taken against the API by someone who has read
 * the audit log first.
 */
export const reindexCaseSearch = (caseId: string) =>
  apiFetch<SearchIndexRepairReceipt>(`/cases/${caseId}/search/reindex`, {
    method: 'POST',
  })

/** The receipt `POST /cases/{id}/search/backfill` returns. */
export interface SearchIndexBackfillReceipt {
  backfill_id: string
  /** Always "running": the sweep has been spawned, not finished. */
  status: string
  /** Artifacts the case held when the sweep was sized, for the progress bar. */
  artifacts: number
  /**
   * What a backfilled document does not carry, in the server's own words. It is
   * shown verbatim: an artifact read back from the database has no bytes behind
   * it, so the text extracted from a file at ingest is not reconstructed, and a
   * keyword search over those files is answered from metadata alone.
   */
  note: string
}

/**
 * Index the artifacts this case has in the database and not in the search
 * index (LIVE-028).
 *
 * The complement of `reindexCaseSearch`, which walks what is already indexed.
 * `?force=true` is left out for the same reason it is left out there.
 */
export const backfillCaseSearchIndex = (caseId: string) =>
  apiFetch<SearchIndexBackfillReceipt>(`/cases/${caseId}/search/backfill`, {
    method: 'POST',
  })

/**
 * The row every search export from this server ends with, whole or not.
 *
 * The server writes it as `SEARCH_EXPORT_TERMINAL` (`seance_api/src/lib.rs`)
 * into both the CSV and the JSON export, and its own preamble tells the reader
 * that a file WITHOUT it was cut short in transit and must not be tendered as
 * the result of the query. The download helper is given the same string so the
 * client applies that test at the moment the file is written, rather than
 * leaving an examiner to notice a missing last row in a file with four million
 * of them.
 *
 * If the server's marker ever changes, this becomes a client that calls whole
 * files fragments — which fails loudly and safely, in the direction of
 * disclosure rather than of a false all-clear.
 */
export const SEARCH_EXPORT_TERMINATOR = '### END OF EXPORT ###'

/**
 * The verdict row as the download helper checks for it, per format.
 *
 * The marker alone is not the test — the server writes it into the preamble's
 * own reading note and an evidence file can carry it in its name — so the
 * helper is told how a whole file of this format frames the verdict and looks
 * for that shape. See `ExportTerminator` in `lib/download.ts`.
 */
export function exportTerminator(format: 'csv' | 'json'): ExportTerminator {
  return { marker: SEARCH_EXPORT_TERMINATOR, format }
}

/**
 * Roughly what one exported row costs, per format, in bytes.
 *
 * Used for ONE purpose: telling an examiner on a browser that cannot stream to
 * disk roughly what holding the file in memory will cost, before they spend it.
 * It is never presented as a size, only as "roughly", and the caller marks it as
 * a floor when the match count behind it is one.
 *
 * Derived rather than guessed. A CSV row is two UUIDs (72), an artifact type, a
 * name, a comma-escaped snippet — `EXCERPT_RADIUS` is 120 characters each side
 * of the match in `seance_search`, so ~250 plus ellipses — and a four-decimal
 * score, with separators. JSON repeats the field names on every row and quotes
 * the numbers, which is the difference between the two figures. Both round UP:
 * an estimate that under-states what a tab is about to be asked to hold is the
 * one that gets an examiner into trouble.
 */
export const SEARCH_EXPORT_ROW_BYTES: Record<'csv' | 'json', number> = {
  csv: 400,
  json: 520,
}

// ---------------------------------------------------------------------------
// The case-wide byte sweep (ROADMAP §1.2): `POST /cases/{id}/search/sweep`.
// Unlike the index search above, it reads the evidence bytes themselves.
// ---------------------------------------------------------------------------

export type SweepRegion = 'live' | 'slack' | 'unallocated' | 'recovered' | 'raw'

/** Every region, in the order the server reports them. */
export const SWEEP_REGIONS: SweepRegion[] = [
  'live',
  'slack',
  'unallocated',
  'recovered',
  'raw',
]

export interface SweepPattern {
  kind: 'text' | 'bytes'
  value: string
}

export interface SweepCursor {
  artifact_id: string
  offset: number
}

export interface SweepRequest {
  patterns: SweepPattern[]
  codepages?: string[]
  scope?: {
    artifact_types?: string[]
    extensions?: string[]
    path_prefix?: string
    path_glob?: string
    regions?: SweepRegion[]
  }
  bounds?: { max_hits?: number; max_bytes?: number }
  resume?: SweepCursor
}

export interface SweepEndianAlias {
  encoding: string
  offset: number
  folded: boolean
}

export interface SweepHit {
  artifact_id: string
  artifact_type: string
  region: SweepRegion
  path?: string
  offset: number
  length: number
  pattern_index: number
  pattern_kind: 'text' | 'bytes'
  pattern_value: string
  encodings: string[]
  endian_aliases?: SweepEndianAlias[]
}

/**
 * The route's answer: `seance_search::sweep::SweepResponse` flattened into
 * `SweepRouteResponse`. Only the fields the panel reads are typed.
 */
export interface SweepResponse {
  hits: SweepHit[]
  scope_statement: string
  regions_searched: SweepRegion[]
  regions_not_searched: SweepRegion[]
  objects_offered: number
  objects_searched: number
  objects_empty: number
  objects_offered_by_region: Partial<Record<SweepRegion, number>>
  objects_searched_by_region: Partial<Record<SweepRegion, number>>
  bytes_scanned: number
  bytes_declared: number
  beyond_declared_size: {
    artifact_id: string
    declared_size: number
    source_size: number
    bytes_beyond: number
  }[]
  hits_endian_ambiguous: number
  max_hits: number
  hit_cap_reached: boolean
  max_bytes: number
  byte_cap_reached: boolean
  next_cursor: SweepCursor | null
  complete: boolean
  coverage_statement: string
  short_reads: { artifact_id: string; declared_size: number; bytes_read: number }[]
  read_failures: { artifact_id: string; offset: number; error: string }[]
  encodings_searched: string[]
  codepages_absent: string[]
  encodings_skipped: { pattern_index: number; encoding: string; reason: string }[]
  elapsed_ms: number
  max_hits_ceiling: number
  max_bytes_ceiling: number
  objects_ceiling: number
  object_stream_cut: boolean
  objects_without_bytes: number
  raw_objects_not_offered: number
  slack_statement: string
}

export const runSweep = (caseId: string, body: SweepRequest) =>
  apiFetch<SweepResponse>(`/cases/${caseId}/search/sweep`, {
    method: 'POST',
    body,
  })
