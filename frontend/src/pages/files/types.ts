// Local types for the file browser. Mirrors the
// GET /cases/:caseId/sources/:sourceId/files contract.

/** Hash-set triage result. Always present on a row; null when no match. */
export type KnownStatus = 'notable' | 'known' | null

export interface FileRow {
  id: string
  parent_id: string | null
  name: string
  path: string
  extension: string | null
  size: number | null
  created: string | null
  modified: string | null
  accessed: string | null
  is_directory: boolean
  is_deleted: boolean
  known_status: KnownStatus
  metadata?: Record<string, unknown> | null
}

/**
 * What a saved compound filter did to this listing, present ONLY when
 * `filter_id` was asked for.
 *
 * Its absence means no filter was applied. The server never emits it with
 * zeroes, because a block of zeroes reads as "a filter ran and everything was
 * fine" — which is the one thing an examiner must not conclude from silence.
 */
/** What "show unique only" set aside, and why (§2.8). */
export interface UniqueOnlyDisclosure {
  /**
   * Files matching these filters that carry no SHA-256, and so are NOT
   * listed: their uniqueness is unknown, not disproved.
   */
  unassessable: number
  /** The server's own sentence for the shortfall. */
  note: string
}

export interface FilterPopulationDisclosure {
  filter_id: string
  filter_name: string
  /**
   * Artifacts the filter matched, of EVERY artifact type and across the whole
   * case. A LOWER BOUND while `scan_complete` is false.
   */
  matched: number
  /**
   * Rows this grid lists, equal to `total_count`. Legitimately smaller than
   * `matched`: the grid shows file-system entries under one evidence source,
   * so parsed records and other sources' files are matches that are not rows
   * here. The gap is not rows going missing, and both numbers are shown.
   */
  listed: number
  /** False when the scan stopped at its row ceiling; matches past it were never examined. */
  scan_complete: boolean
  /** Rows the scan read and could not evaluate. Neither matches nor non-matches; paging never recovers them. */
  undecodable: number
  /** True when more artifacts matched than this grid will list. */
  population_capped: boolean
  population_cap: number
  /** True iff `inventory_incomplete_reason` is non-null. */
  inventory_incomplete: boolean
  /**
   * Which shortfall applies, in the server's closed vocabulary — the same
   * tokens `/filters/:id/apply` publishes, joined by `_and_` in a fixed order,
   * so one client switch covers both screens. Null only when the scan reached
   * the end of the case, listed every match, and evaluated every row it read.
   */
  inventory_incomplete_reason: string | null
}

export interface FilesResponse {
  items: FileRow[]
  total_count: number
  page: number
  page_size: number
  total_pages: number
  has_next: boolean
  has_previous: boolean
  filter?: FilterPopulationDisclosure
  /**
   * Present only under `unique_only` (§2.8): what that filter could not
   * assess. Absent means the filter was not applied — never that it was
   * applied and set nothing aside.
   */
  unique?: UniqueOnlyDisclosure
}

export type FileSortKey = 'name' | 'size' | 'modified' | 'created'
export type SortOrder = 'asc' | 'desc'

// Type alias (not interface) so it assigns to the http QueryParams
// index signature.
export type KnownFilter = 'notable' | 'known' | 'unknown'

export type FilesQuery = {
  parent_id?: string
  path?: string
  /**
   * A saved or predefined compound filter, whose population the listing is
   * restricted to. Every other parameter here still applies and NARROWS it
   * further; none of them widens it.
   */
  filter_id?: string
  name?: string
  extension?: string
  deleted_only?: boolean
  /**
   * Only files this case can demonstrate are one of a kind (§2.8). A file
   * carrying no SHA-256 is set aside, not listed — its uniqueness is unknown,
   * not disproved — and the response's `unique` block says how many.
   */
  unique_only?: boolean
  known?: KnownFilter
  dirs?: 'only' | 'exclude'
  sort?: FileSortKey
  order?: SortOrder
  page?: number
  page_size?: number
  include_metadata?: boolean
}

/** Result of a manifest ZIP export, read from response headers. */
export interface ExportResult {
  fileCount: number
  skippedCount: number
  /**
   * Exported files whose content came up SHORT of its declared size, and files
   * that were LONGER than declared. The server counts and reports both — under
   * separate keys, because missing data and a size discrepancy are different
   * claims — and the ZIP that leaves this screen is what goes into evidence.
   * Reading only the file and skipped counts made "Exported 500 files, 0
   * skipped" a clean bill of health over an export holding truncated content.
   *
   * `null` means the server did not report the count. That is "we were not
   * told", not "none": it must never render as a zero.
   */
  incompleteCount: number | null
  sizeMismatchCount: number | null
}

export interface FileHexResponse {
  offset: number
  /** Bytes actually readable at this offset — not necessarily what was asked for. */
  limit: number
  total_size: number
  hex: string
  ascii: string
  /** Bytes this page should have held: the request clipped to `total_size`. */
  requested_bytes?: number
  /**
   * True when the read came up short of `requested_bytes`. `total_size` still
   * describes the whole object, so without this the preview's "first N bytes"
   * line asserts bytes that were never read (B4-022).
   */
  content_incomplete?: boolean
  /** Stable reason id for `content_incomplete` (e.g. `short_read`). */
  content_incomplete_reason?: string | null
}

/**
 * Breadcrumb segment. `id` is null for path segments recovered from a
 * cold ?dir= deep link, where ancestor artifact ids are unknown; those
 * render as plain text instead of links.
 */
export interface Crumb {
  id: string | null
  name: string
}
