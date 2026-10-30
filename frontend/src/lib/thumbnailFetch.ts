import { apiUrl, checkUnauthorized, getToken } from '../api/http'

/**
 * Fetch a thumbnail's bytes, or null when the artifact is not a raster image
 * (404). Raw fetch is used because the response is a binary blob that needs the
 * Authorization header attached.
 *
 * Deliberately returns the Blob rather than an object URL. A function that
 * mints the URL leaks it whenever its caller is gone by the time the promise
 * settles — a gallery cell scrolled past mid-fetch, a file deselected before
 * its preview arrives — because the handle is created with nobody left to
 * revoke it, and react-query's `gcTime: 0` then drops the entry without one
 * either (B4-027). A Blob is ordinary garbage; the component that renders it
 * owns the URL's whole lifetime through `useObjectUrl`, which revokes exactly
 * what it created.
 *
 * Callers supply their own default `size`; the gallery wraps this in a
 * concurrency limiter, other surfaces call it directly.
 */
/**
 * A rendered preview and where its pixels came from.
 *
 * `fromDeviceCache` is the server's `X-Thumbnail-Source: device-cache` header,
 * which it sets whenever the PNG was NOT decoded from the artifact's own bytes
 * — a preview lifted from the device's thumbnail cache, or a keyframe pulled
 * out of a video. That is a different claim about the evidence: a cached
 * thumbnail can outlive, and disagree with, the file it was made from, so an
 * examiner must not read it as a rendering of the bytes in evidence. The header
 * exists so a client can say so, and nothing said it.
 */
export interface ThumbnailResult {
  blob: Blob
  fromDeviceCache: boolean
}

export async function fetchThumbnailBytes(
  caseId: string,
  artifactId: string,
  { size, signal }: { size: number; signal?: AbortSignal },
): Promise<ThumbnailResult | null> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const response = checkUnauthorized(
    await fetch(
      apiUrl(`/cases/${caseId}/artifacts/${artifactId}/thumbnail`, { size }),
      { headers, signal },
    ),
  )
  if (response.status === 404) return null
  if (!response.ok) {
    throw new Error(`Thumbnail failed with status ${response.status}`)
  }
  return {
    blob: await response.blob(),
    fromDeviceCache:
      response.headers.get('X-Thumbnail-Source') === 'device-cache',
  }
}
