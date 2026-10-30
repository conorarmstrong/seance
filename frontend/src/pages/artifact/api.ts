import { apiFetch, apiUrl, checkUnauthorized, getToken } from '../../api/http'
import type { Job, TimelineEvent, Uuid } from '../../api/types'

// Page-local wrappers for artifact-viewer endpoints that are not part of
// the shared resource client yet.

export interface AncestorEntry {
  id: Uuid
  name: string
  artifact_type: string
  /**
   * Present on a volume the BitLocker or LUKS decryptor opened during a run
   * (HUNT-254): its content, and everything beneath it, reads only while it is
   * unlocked for reading.
   */
  decrypted_volume?: 'bitlocker' | 'luks'
}

export interface HexPage {
  offset: number
  /** Bytes actually readable at this offset — not necessarily what was asked for. */
  limit: number
  hex: string
  ascii: string
  total_size: number
  /**
   * Bytes this page SHOULD have held: the requested length clipped to
   * `total_size`. Without it a short page is indistinguishable from the end of
   * the object, because `limit` is silently rewritten to what was readable.
   */
  requested_bytes?: number
  /**
   * True when fewer bytes were readable than `requested_bytes` — an unreadable
   * or sparse region mid-file. The page simply ends early otherwise while
   * `total_size` still claims the whole object, so an examiner reads "the file
   * stops here" from what is really "these bytes could not be read" (B4-022).
   */
  content_incomplete?: boolean
  /** Stable reason id for `content_incomplete` (e.g. `short_read`). */
  content_incomplete_reason?: string | null
}

export interface IntegrityCheck {
  id: number
  timestamp: string
  computed_md5: string | null
  computed_sha1: string | null
  computed_sha256: string | null
  expected_md5: string | null
  expected_sha1: string | null
  /**
   * Baseline SHA-256 the check was measured against. For an ordinary FileEntry
   * this is usually the ONLY baseline that exists, so without it the history
   * cannot show what "verified" was verified against.
   */
  expected_sha256: string | null
  status: string
  details: string | null
}

export interface VerifyJobStart {
  job_id: string
  status: string
}

/** Root-first ancestry chain, including the artifact itself as last entry. */
export const getArtifactAncestors = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<AncestorEntry[]>(
    `/cases/${caseId}/artifacts/${artifactId}/ancestors`,
  )

/** One contiguous device-image extent of an artifact's content. */
export interface PhysicalExtent {
  /** Byte offset on the backing device, or null for a sparse/synthetic gap. */
  device_offset: number | null
  length: number
  /** device_offset / sector_size, when device-backed and sector-aligned. */
  sector: number | null
  /** A sparse (hole) region: no bytes on the device, reads as zeros. */
  sparse: boolean
  /**
   * Which source the offset belongs to: `'device'` for the evidence image,
   * otherwise the auxiliary source's name — a pagefile, a swap device.
   *
   * A swapped-out page has real, recoverable bytes, but they are NOT in the
   * evidence image and were not in RAM at acquisition; they may predate it
   * considerably. Rendering such an offset as a plain device offset would send
   * an examiner to that offset on the disk and hand them unrelated bytes.
   */
  source: string
}

export type ExtentPrecision = 'exact' | 'encrypted' | 'compressed' | 'synthetic'

/** One level of the artifact's ancestry, annotated with its mapping. */
export interface PhysChainLevel {
  artifact_id: string
  name: string | null
  artifact_type: string
  offset_in_parent: number | null
  transform: string | null
  fragment_count: number | null
}

/** Device-absolute physical location of an artifact's content. */
export interface PhysicalLocation {
  device: {
    artifact_id: string
    name: string | null
    artifact_type: string
    path: string | null
    decoded_container: boolean
  }
  extents: PhysicalExtent[]
  precision: ExtentPrecision
  note: string | null
  truncated: boolean
  logical_size: number
  located_bytes: number
  sector_size: number
  chain: PhysChainLevel[]
}

/**
 * Where an artifact's bytes physically live on the backing device, traced
 * through its whole container/filesystem chain. May reject (derived records,
 * artifacts with no recorded content location) — callers should handle that.
 */
export const getPhysicalLocation = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<PhysicalLocation>(
    `/cases/${caseId}/artifacts/${artifactId}/physical-location`,
  )

export interface ChildArtifact {
  id: Uuid
  parent_id: Uuid | null
  artifact_type: string
  name: string
  has_children: boolean
  metadata?: Record<string, unknown>
}

/**
 * Direct children with their full metadata document. Used to locate derived
 * records parented to this artifact (an `exif` ParsedRecord for an image, a
 * `SqliteDatabaseForensics` summary for a database) without a dedicated
 * endpoint per record type.
 */
export const getArtifactChildrenWithMetadata = (
  caseId: Uuid,
  artifactId: Uuid,
) =>
  apiFetch<{ items?: ChildArtifact[] }>(
    `/cases/${caseId}/artifacts/${artifactId}/children`,
    { query: { include_metadata: true } },
  ).then((res) => res.items ?? [])

/** A parsed messaging record (ParsedRecord) with its untyped metadata. */
export interface MessagingRecord {
  id: Uuid
  parent_id: Uuid | null
  artifact_type: string
  metadata: Record<string, unknown>
}

interface RecordsResponse {
  records: MessagingRecord[]
  total: number
  page: number
  page_size: number
  type: string
}

/** Server clamps page_size to this ceiling (FILES_MAX_PAGE_SIZE). */
const RECORDS_PAGE_SIZE = 500
/** Bound the number of messages pulled into a single conversation view. */
const MESSAGES_CAP = 5000

/** What one messaging type yielded, and whether that was all of it. */
export interface MessagingRecords {
  records: MessagingRecord[]
  /** The server's count of records of this type under this source. */
  total: number
  /**
   * True when `MESSAGES_CAP` stopped the drain before `total` was reached.
   * Callers MUST surface this: a thread list built from a capped read is a
   * floor, and rendering it identically to a complete one tells an examiner a
   * conversation ended where the safety cap happened to fall.
   */
  truncated: boolean
  /** The cap that stopped the read, so a caller can name it. */
  cap: number
}

/**
 * Fetch every ParsedRecord of a messaging `type` (e.g. `iMessage`, `WhatsApp`)
 * beneath a source artifact's subtree. `source_id` scopes the query to this
 * database's records; pages are drained up to a safety cap.
 *
 * Returns the cap state alongside the rows rather than a bare array: the cap is
 * a fact about the evidence on screen, and an array cannot carry it.
 */
export async function getMessagingRecords(
  caseId: Uuid,
  sourceId: Uuid,
  type: string,
): Promise<MessagingRecords> {
  const out: MessagingRecord[] = []
  let total = 0
  let capped = false
  for (let page = 1; ; page += 1) {
    const resp = await apiFetch<RecordsResponse>(`/cases/${caseId}/records`, {
      query: {
        type,
        source_id: sourceId,
        page,
        page_size: RECORDS_PAGE_SIZE,
      },
    })
    total = resp.total
    out.push(...resp.records)
    const drained = resp.records.length < RECORDS_PAGE_SIZE
    if (drained || out.length >= resp.total) break
    if (out.length >= MESSAGES_CAP) {
      capped = true
      break
    }
  }
  return {
    records: out,
    total,
    // The cap counts only when it actually cut the read short. A type whose
    // whole set happens to be exactly the cap is complete, not truncated.
    truncated: capped && out.length < total,
    cap: MESSAGES_CAP,
  }
}

export interface ContentRangeBytes {
  bytes: Uint8Array
  byteLength: number
  /** Total content size from Content-Range, if the server reported it. */
  totalSize: number | null
}

/**
 * Build an Error from a failed content response, preferring the backend's JSON
 * error message (e.g. "no recorded content location: re-ingest…") over a bare
 * status. Content endpoints return binary on success and `{ error: { message } }`
 * on failure.
 */
async function contentError(response: Response): Promise<Error> {
  try {
    const body = (await response.json()) as {
      error?: { message?: string }
      message?: string
    }
    const msg = body?.error?.message ?? body?.message
    if (typeof msg === 'string' && msg) return new Error(msg)
  } catch {
    // response body was not JSON
  }
  return new Error(`Content request failed with status ${response.status}`)
}

/**
 * Fetch a byte range of an artifact's content as raw bytes. Unlike the text
 * helper this preserves the original encoding so the caller can detect and
 * decode UTF-16 / UTF-8 itself.
 */
export async function fetchContentRangeBytes(
  caseId: Uuid,
  artifactId: Uuid,
  start: number,
  endInclusive: number,
): Promise<ContentRangeBytes> {
  const headers = authHeaders()
  headers['Range'] = `bytes=${start}-${endInclusive}`
  const response = checkUnauthorized(
    await fetch(apiUrl(`/cases/${caseId}/artifacts/${artifactId}/content`), {
      headers,
    }),
  )
  if (!response.ok) {
    throw await contentError(response)
  }
  const buffer = await response.arrayBuffer()
  let totalSize: number | null = null
  const contentRange = response.headers.get('content-range')
  const match = contentRange?.match(/\/(\d+)\s*$/)
  if (match) {
    totalSize = Number(match[1])
  } else if (response.status === 200) {
    totalSize = buffer.byteLength
  }
  return {
    bytes: new Uint8Array(buffer),
    byteLength: buffer.byteLength,
    totalSize,
  }
}

export interface ByteSearchResponse {
  pattern_bytes: number
  total_size: number
  /** Match offsets into the artifact content, ascending. */
  offsets: number[]
  /** True if the match cap was hit. */
  truncated: boolean
  /** Bytes actually read and searched; less than `total_size` on short content. */
  scanned_size: number
  /**
   * True when the scan could not cover the whole declared content. "No matches"
   * then means "none in the part we could read", not "not present in this file",
   * and the two must never render identically.
   */
  incomplete: boolean
}

/** Search the artifact's raw bytes for a hex pattern (e.g. "ff d8 ff"). */
export const byteSearch = (
  caseId: Uuid,
  artifactId: Uuid,
  pattern: string,
  limit = 1000,
) =>
  apiFetch<ByteSearchResponse>(
    `/cases/${caseId}/artifacts/${artifactId}/byte-search`,
    { query: { pattern, limit } },
  )

export const getArtifactHexPage = (
  caseId: Uuid,
  artifactId: Uuid,
  offset: number,
  limit: number,
) =>
  apiFetch<HexPage>(`/cases/${caseId}/artifacts/${artifactId}/hex`, {
    query: { offset, limit },
  })

export const getIntegrityChecks = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<IntegrityCheck[]>(
    `/cases/${caseId}/artifacts/${artifactId}/integrity`,
  )

/** Start an integrity-verification job. Poll the job for completion. */
export const startVerify = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<VerifyJobStart>(
    `/cases/${caseId}/artifacts/${artifactId}/verify`,
    { method: 'POST' },
  )

export const getJob = (caseId: Uuid, jobId: string) =>
  apiFetch<Job>(`/cases/${caseId}/jobs/${jobId}`)

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  return headers
}

/**
 * Fetch an artifact's full content as a blob. Needed instead of a plain
 * <img src> because the API expects the Authorization header.
 */
export async function fetchContentBlob(
  caseId: Uuid,
  artifactId: Uuid,
): Promise<Blob> {
  const response = checkUnauthorized(
    await fetch(apiUrl(`/cases/${caseId}/artifacts/${artifactId}/content`), {
      headers: authHeaders(),
    }),
  )
  if (!response.ok) {
    throw await contentError(response)
  }
  return response.blob()
}

export interface ContentRangeText {
  text: string
  byteLength: number
  /** Total content size from Content-Range, if the server reported it. */
  totalSize: number | null
}

/** Fetch a byte range of an artifact's content decoded as text. */
export async function fetchContentRangeText(
  caseId: Uuid,
  artifactId: Uuid,
  start: number,
  endInclusive: number,
): Promise<ContentRangeText> {
  const headers = authHeaders()
  headers['Range'] = `bytes=${start}-${endInclusive}`
  const response = checkUnauthorized(
    await fetch(apiUrl(`/cases/${caseId}/artifacts/${artifactId}/content`), {
      headers,
    }),
  )
  if (!response.ok) {
    throw await contentError(response)
  }
  const blob = await response.blob()
  let totalSize: number | null = null
  const contentRange = response.headers.get('content-range')
  const match = contentRange?.match(/\/(\d+)\s*$/)
  if (match) {
    totalSize = Number(match[1])
  } else if (response.status === 200) {
    // Server ignored the Range header and sent the whole body.
    totalSize = blob.size
  }
  return { text: await blob.text(), byteLength: blob.size, totalSize }
}

/** Probe the thumbnail endpoint: 200 means the artifact is a raster image. */
export async function thumbnailAvailable(
  caseId: Uuid,
  artifactId: Uuid,
): Promise<boolean> {
  const response = checkUnauthorized(
    await fetch(
      apiUrl(`/cases/${caseId}/artifacts/${artifactId}/thumbnail`, {
        size: 64,
      }),
      { headers: authHeaders() },
    ),
  )
  if (response.ok) {
    // Drain the body so the connection can be reused.
    await response.blob()
    return true
  }
  return false
}

/**
 * `GET /cases/{id}/timeline/related/{artifactId}`: the artifact's own events,
 * its parent's and its children's first, then its siblings' in whatever budget
 * is left, newest first. `cap` travels with the rows so a list that stopped
 * there is never read as the whole history.
 */
export interface RelatedTimeline {
  events: TimelineEvent[]
  truncated: boolean
  cap: number
}

export const getRelatedTimeline = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<RelatedTimeline>(`/cases/${caseId}/timeline/related/${artifactId}`)

