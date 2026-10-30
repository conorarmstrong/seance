import { apiFetch, apiUrl, checkUnauthorized, getToken } from '../../api/http'
import { fetchThumbnailBytes } from '../../lib/thumbnailFetch'
import type { ThumbnailResult } from '../../lib/thumbnailFetch'

// Page-local wrappers for the media gallery. They live here (not in the shared
// resources module) because the Gallery surface owns them.

/** Picture extensions surfaced by the gallery. */
export const IMAGE_EXTENSIONS = [
  'jpg',
  'jpeg',
  'png',
  'gif',
  'bmp',
  'webp',
  'heic',
  'heif',
  'tiff',
]

/** Video extensions surfaced by the gallery's Videos mode. */
export const VIDEO_EXTENSIONS = [
  'mp4',
  'mov',
  'm4v',
  'avi',
  'mkv',
  'webm',
  'wmv',
  '3gp',
]

/** Audio extensions surfaced by the gallery's Audio mode. */
export const AUDIO_EXTENSIONS = [
  'mp3',
  'm4a',
  'aac',
  'wav',
  'flac',
  'ogg',
  'opus',
  'amr',
  'caf',
  'aiff',
]

export type MediaKind = 'pictures' | 'videos' | 'audio'

/** Server-side sort column for the media listing. */
export type MediaSort = 'name' | 'size' | 'modified'
export type SortOrder = 'asc' | 'desc'

export function extensionsFor(kind: MediaKind): string[] {
  if (kind === 'videos') return VIDEO_EXTENSIONS
  if (kind === 'audio') return AUDIO_EXTENSIONS
  return IMAGE_EXTENSIONS
}

export interface SourceInfo {
  source_artifact_id: string
  name: string
  artifact_count: number
}

interface SourcesResponse {
  sources: SourceInfo[]
}

/** Evidence sources in the case, used to scope image discovery. */
export const listSources = (caseId: string): Promise<SourceInfo[]> =>
  apiFetch<SourcesResponse>(`/cases/${caseId}/stats/sources`).then(
    (r) => r.sources,
  )

export interface GalleryImage {
  id: string
  name: string
  /** Null for entries whose parser records a domain-relative path instead of
   * `path` (iOS backup files), so the generated column is empty. */
  path: string | null
  size: number | null
  extension: string | null
  modified: string | null
  created: string | null
  sourceId: string
  sourceName: string
  metadata: Record<string, unknown> | null
}

interface FileRowLike {
  id: string
  name: string
  path: string | null
  size: number | null
  extension: string | null
  modified?: string | null
  created?: string | null
  is_directory?: boolean
  metadata?: Record<string, unknown> | null
}

export interface ImagePage {
  images: GalleryImage[]
  total: number
  page: number
  hasNext: boolean
}

/**
 * One server-paginated page of image FileEntries. The server filters on every
 * image extension at once and pages the result, so the browser holds only what
 * it is showing — the gallery scrolls through pages instead of downloading the
 * whole case up front (which also silently capped at 500 per extension).
 *
 * `sourceId` of 'all' spans every source in the case.
 */
export async function fetchImagePage(
  caseId: string,
  sourceId: string,
  page: number,
  pageSize = 100,
  opts: {
    known?: 'notable' | 'any'
    kind?: MediaKind
    sort?: MediaSort
    order?: SortOrder
  } = {},
): Promise<ImagePage> {
  const base =
    sourceId === 'all'
      ? `/cases/${caseId}/files`
      : `/cases/${caseId}/sources/${sourceId}/files`
  const res = await apiFetch<{
    items: FileRowLike[]
    total_count: number
    page: number
    has_next: boolean
  }>(base, {
    query: {
      extensions: extensionsFor(opts.kind ?? 'pictures').join(','),
      dirs: 'exclude',
      page,
      page_size: pageSize,
      include_metadata: true,
      sort: opts.sort ?? 'name',
      order: opts.order ?? 'asc',
      ...(opts.known ? { known: opts.known } : {}),
    },
  })
  return {
    images: res.items.map((item) => ({
      id: item.id,
      name: item.name,
      path: item.path,
      size: item.size,
      extension: item.extension,
      modified: item.modified ?? null,
      created: item.created ?? null,
      sourceId,
      sourceName: '',
      metadata: item.metadata ?? null,
    })),
    total: res.total_count,
    page: res.page,
    hasNext: res.has_next,
  }
}

// ---- Bounded-concurrency thumbnail fetching ----
//
// A gallery view can hold hundreds of cells that all scroll into view at once.
// Firing every thumbnail request simultaneously would saturate the connection
// pool; this small semaphore caps in-flight thumbnail fetches.

const MAX_CONCURRENT = 6
let active = 0
const waiters: (() => void)[] = []

function acquire(): Promise<void> {
  if (active < MAX_CONCURRENT) {
    active += 1
    return Promise.resolve()
  }
  return new Promise<void>((resolve) => {
    waiters.push(() => {
      active += 1
      resolve()
    })
  })
}

function release(): void {
  active -= 1
  const next = waiters.shift()
  if (next) next()
}

/**
 * Fetch a thumbnail's bytes, or null when the artifact is not a raster image
 * (404). Raw fetch is used because the response is a binary blob that needs the
 * Authorization header attached. Fetches are concurrency-limited.
 *
 * Returns the Blob, not an object URL: see `fetchThumbnailBytes` for why the URL
 * has to be minted by whoever will still be around to revoke it (B4-027).
 */
export async function fetchThumbnail(
  caseId: string,
  artifactId: string,
  size = 160,
): Promise<ThumbnailResult | null> {
  await acquire()
  try {
    return await fetchThumbnailBytes(caseId, artifactId, { size })
  } finally {
    release()
  }
}

/**
 * Fetch a rendered thumbnail as a Blob. Used for formats no browser can display
 * natively (HEIC/HEIF), where the server's decode is the only way to show the
 * picture; the original bytes remain available through /content.
 */
export async function fetchThumbnailBlob(
  caseId: string,
  artifactId: string,
  size = 512,
): Promise<Blob> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const response = checkUnauthorized(
    await fetch(
      apiUrl(`/cases/${caseId}/artifacts/${artifactId}/thumbnail`, { size }),
      { headers },
    ),
  )
  if (!response.ok) {
    throw new Error(`Preview failed with status ${response.status}`)
  }
  return response.blob()
}

/** Fetch full image bytes as a Blob for the lightbox (auth header attached).
 * Same /content endpoint as the artifact viewer; re-exported so the gallery
 * surface keeps a single canonical implementation with backend-message errors. */
export { fetchContentBlob } from '../artifact/api'

export interface ExifRecord {
  id: string
  parent_id: string | null
  metadata: Record<string, unknown>
}

interface RecordsResponse {
  records: ExifRecord[]
  total: number
}

/** Server clamps page_size to this ceiling (FILES_MAX_PAGE_SIZE). */
const EXIF_PAGE_SIZE = 500
/** Bound the total EXIF records pulled in for one lightbox annotation pass. */
const EXIF_CAP = 20000

export interface ExifRecordsResult {
  records: ExifRecord[]
  /** Total EXIF records the case holds (may exceed `records.length`). */
  total: number
  /** True when EXIF_CAP stopped us short of `total`, so annotation under-reports. */
  truncated: boolean
}

/**
 * EXIF records for the case, used to annotate the lightbox. Joined to an image
 * by parent_id (the record's parent is the image artifact) with source_name as
 * a filename fallback. Pages through every record (bounded by EXIF_CAP) so a
 * case with more than one page of EXIF still annotates images past the first.
 *
 * What the examiner learns from `truncated`: whether "no GPS on this picture"
 * is a fact about the picture or an artefact of the cap. Past EXIF_CAP records
 * the index simply has no entry for the image, and the lightbox then shows no
 * camera, no capture time and no coordinates — indistinguishable from a
 * stripped file. The caller must warn when this is set (mirrors `getHashHits`).
 */
export const listExifRecords = async (
  caseId: string,
): Promise<ExifRecordsResult> => {
  const out: ExifRecord[] = []
  let total = 0
  let cappedShort = false
  for (let page = 1; ; page += 1) {
    const resp = await apiFetch<RecordsResponse>(`/cases/${caseId}/records`, {
      query: { type: 'exif', page, page_size: EXIF_PAGE_SIZE },
    })
    if (typeof resp.total === 'number') total = Math.max(total, resp.total)
    out.push(...resp.records)
    // A page shorter than the one we asked for is the server saying there is
    // nothing after it. Trusting `total` alone to stop the walk means a
    // response without a usable count spins until the cap, so terminate on the
    // page itself and use `total` only to judge completeness.
    if (resp.records.length < EXIF_PAGE_SIZE) break
    if (total > 0 && out.length >= total) break
    if (out.length >= EXIF_CAP) {
      cappedShort = true
      break
    }
  }
  const records = out.slice(0, EXIF_CAP)
  return {
    records,
    total: Math.max(total, records.length),
    truncated: cappedShort || records.length < total,
  }
}

export interface ImageIdsResult {
  ids: string[]
  /** True when `cap` stopped the walk before the last page of the selection. */
  truncated: boolean
}

/**
 * Every image artifact id in scope, for an action that means "all pictures"
 * (running OCR across the gallery). Pages server-side and stops at `cap`, which
 * mirrors the server's own batch ceiling, so this never walks an unbounded case.
 *
 * What the examiner learns from `truncated`: whether "run OCR on all pictures"
 * really covered all of them. Without it a selection larger than `cap` is
 * silently trimmed here, the server sees only the ids it was handed and reports
 * no truncation of its own, and the pictures past the cap are never analysed
 * while the toast says the batch was queued.
 */
export async function collectImageIds(
  caseId: string,
  sourceId: string,
  opts: { known?: 'notable' | 'any'; kind?: MediaKind } = {},
  cap = 5000,
): Promise<ImageIdsResult> {
  const ids: string[] = []
  let more = false
  for (let page = 1; ; page += 1) {
    const res = await fetchImagePage(caseId, sourceId, page, 500, opts)
    ids.push(...res.images.map((i) => i.id))
    if (!res.hasNext) break
    if (ids.length >= cap) {
      // The server says there is another page and we have run out of budget.
      more = true
      break
    }
  }
  return { ids: ids.slice(0, cap), truncated: more || ids.length > cap }
}
