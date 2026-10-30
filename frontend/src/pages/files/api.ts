import {
  apiFetch,
  apiUrl,
  checkUnauthorized,
  csrfToken,
  getToken,
  percentDecodeOrRaw,
} from '../../api/http'
import { fetchThumbnailBytes } from '../../lib/thumbnailFetch'
import type { ThumbnailResult } from '../../lib/thumbnailFetch'
import type {
  ExportResult,
  FileHexResponse,
  FilesQuery,
  FilesResponse,
} from './types'

/** Folder-aware file listing. Omit parent_id for the whole subtree (flat). */
export const listFiles = (
  caseId: string,
  sourceId: string,
  query: FilesQuery,
) =>
  apiFetch<FilesResponse>(`/cases/${caseId}/sources/${sourceId}/files`, {
    query,
  })

/** Hex preview; the response carries total_size for the full stream. */
export const getFileHex = (
  caseId: string,
  artifactId: string,
  offset: number,
  limit: number,
) =>
  apiFetch<FileHexResponse>(`/cases/${caseId}/artifacts/${artifactId}/hex`, {
    query: { offset, limit },
  })

/**
 * Fetch a thumbnail's bytes, or null when the artifact is not an image (404).
 * Uses raw fetch because the response is a binary blob and needs the
 * Authorization header attached. The caller mints the object URL so that it is
 * owned by something that will still exist to revoke it (B4-027).
 */
export function fetchThumbnail(
  caseId: string,
  artifactId: string,
  size = 96,
): Promise<ThumbnailResult | null> {
  return fetchThumbnailBytes(caseId, artifactId, { size })
}

function filenameFromDisposition(header: string | null): string {
  if (!header) return 'export.zip'
  const match = header.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i)
  if (!match) return 'export.zip'
  // A malformed percent escape must not cost the examiner the export. The ZIP
  // has already been produced, hashed and audited server-side, and this runs
  // BEFORE the blob is read, so an unguarded decode loses the download and
  // reports a failure that never happened (HUNT-029). The regex strips an RFC
  // 5987 `filename*=UTF-8''` prefix, so the capture is legitimately
  // percent-encoded for some producers and raw text for others; only the
  // tolerant decode reads both.
  return percentDecodeOrRaw(match[1])
}

/**
 * Evidence-preserving bulk export: POSTs the selected artifact ids and
 * streams back a ZIP (files + MANIFEST.json/csv with per-file hashes).
 * Uses raw fetch so the auth/CSRF headers ride along and the export count
 * headers can be read, then triggers a browser download from the blob.
 */
export async function exportFilesZip(
  caseId: string,
  artifactIds: string[],
): Promise<ExportResult> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const csrf = csrfToken()
  if (csrf) headers['x-csrf-token'] = csrf

  const response = checkUnauthorized(
    await fetch(apiUrl(`/cases/${caseId}/export/files`), {
      method: 'POST',
      headers,
      body: JSON.stringify({
        artifact_ids: artifactIds,
        include_manifest: true,
      }),
    }),
  )
  if (!response.ok) {
    throw new Error(`Export failed with status ${response.status}`)
  }

  const fileCount = Number(
    response.headers.get('X-Export-File-Count') ?? artifactIds.length,
  )
  const skippedCount = Number(
    response.headers.get('X-Export-Skipped-Count') ?? 0,
  )
  // Absent header means the server did not report the figure. Defaulting these
  // to 0 would turn "not told" into "none", which is the reading the manifest
  // exists to prevent.
  const optionalCount = (name: string): number | null => {
    const raw = response.headers.get(name)
    if (raw == null) return null
    const n = Number(raw)
    return Number.isFinite(n) ? n : null
  }
  const incompleteCount = optionalCount('X-Export-Incomplete-Count')
  const sizeMismatchCount = optionalCount('X-Export-Size-Mismatch-Count')
  const filename = filenameFromDisposition(
    response.headers.get('Content-Disposition'),
  )

  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  // Defer revocation: revoking synchronously right after click() can abort the
  // download before the browser reads the blob, corrupting the exported ZIP on
  // some browsers (BUG-169).
  setTimeout(() => URL.revokeObjectURL(url), 60_000)

  return { fileCount, skippedCount, incompleteCount, sizeMismatchCount }
}
