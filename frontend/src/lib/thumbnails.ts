import { useEffect, useState } from 'react'
import { fetchThumbnail } from '../pages/gallery/api'

/**
 * Shared thumbnail previews for anywhere an artifact's image should appear
 * inline (map hover cards, chat attachments).
 *
 * Object URLs are cached across mounts so revisiting a point or scrolling a
 * conversation back and forth doesn't refetch, bounded FIFO so a long session
 * can't grow unbounded. Evicted URLs are revoked.
 */
const MAX_CACHED = 200

/**
 * A preview and the one thing an examiner must know about it: whether the
 * server decoded it from the artifact's own bytes.
 *
 * `fromDeviceCache` is the server's `X-Thumbnail-Source: device-cache` header —
 * a picture lifted from the device's thumbnail cache, or a keyframe pulled out
 * of a video. Such a preview can outlive and disagree with the file it was made
 * from, so rendering it as a plain image asserts something about the evidence
 * that nobody established. The gallery and the file detail pane have always
 * said so; this cache dropped the flag, so chat attachments and map hover cards
 * did not (B8-004).
 */
export interface ThumbnailPreview {
  url: string
  fromDeviceCache: boolean
}

const cache = new Map<string, ThumbnailPreview | null>()
/**
 * Fetches already running, by cache key. Two components mounting the same
 * artifact in the same tick used to start two independent fetches, so two object
 * URLs existed for one key: `remember` overwrote the first with the second and
 * the first was never revoked, and revoking it there would have blanked the
 * image the other component had already shown. Sharing the in-flight promise
 * means one key can only ever produce one object URL (B2-026).
 */
const inFlight = new Map<string, Promise<ThumbnailPreview | null>>()

/**
 * Cache key. Must include `caseId`, not just the artifact id: artifact UUIDs are
 * per-case (separate DBs) and can collide across cases, so keying on the id
 * alone could show one case's thumbnail for another case's artifact (BUG-201).
 */
function cacheKey(caseId: string, artifactId: string): string {
  return `${caseId}/${artifactId}`
}

function remember(id: string, preview: ThumbnailPreview | null): void {
  cache.set(id, preview)
  while (cache.size > MAX_CACHED) {
    const oldest = cache.keys().next().value as string | undefined
    if (oldest === undefined) break
    const evicted = cache.get(oldest)
    if (evicted) URL.revokeObjectURL(evicted.url)
    cache.delete(oldest)
  }
}

/** Drop every cached preview. Exported for tests, which need a cold cache to
 * observe fetch behaviour (the cache deliberately outlives component mounts). */
export function resetThumbnailCache(): void {
  for (const preview of cache.values()) {
    if (preview) URL.revokeObjectURL(preview.url)
  }
  cache.clear()
  inFlight.clear()
}

/**
 * The preview for `key`, fetching it at most once however many components ask
 * at the same moment.
 *
 * Only an *answer* is cached. A resolved `null` is the server saying this
 * artifact has no raster preview (404), which is a fact about the artifact and
 * will not change. A thrown fetch is not an answer: a 500, a dropped
 * connection, an aborted request. Remembering those as "no preview" turned a
 * momentary API blip into a permanent one — every chat chip and map card for
 * that artifact showed "no preview" for the rest of the session, reading as
 * "not an image / unreadable" when the file is perfectly previewable (B8-005).
 * A failure is therefore returned but not stored, so the next mount tries
 * again.
 */
function loadThumbnail(caseId: string, artifactId: string, key: string) {
  const running = inFlight.get(key)
  if (running) return running
  const started = fetchThumbnail(caseId, artifactId, 160)
    // The module cache owns this URL for as long as the entry lives and revokes
    // it on eviction, so minting it here (rather than in the fetch) keeps the
    // handle and its owner together (B4-027).
    .then((result) => {
      const preview: ThumbnailPreview | null = result
        ? {
            url: URL.createObjectURL(result.blob),
            fromDeviceCache: result.fromDeviceCache,
          }
        : null
      remember(key, preview)
      return preview
    })
    .catch(() => null)
    .finally(() => {
      // Only clear the slot if it is still this fetch; a later reset may have
      // replaced it.
      if (inFlight.get(key) === started) inFlight.delete(key)
    })
  inFlight.set(key, started)
  return started
}

/**
 * The preview for `artifactId`, or null when there is none (or the load
 * failed — a caller that must tell those apart should render the badge, which
 * only a successful load can carry).
 */
export function useThumbnail(
  caseId: string,
  artifactId?: string | null,
): ThumbnailPreview | null {
  const [preview, setPreview] = useState<ThumbnailPreview | null>(() =>
    artifactId ? (cache.get(cacheKey(caseId, artifactId)) ?? null) : null,
  )

  useEffect(() => {
    if (!artifactId) {
      setPreview(null)
      return
    }
    const key = cacheKey(caseId, artifactId)
    if (cache.has(key)) {
      setPreview(cache.get(key) ?? null)
      return
    }
    let cancelled = false
    // Blank any prior (possibly other-case) preview while the new one loads, so
    // a cache miss can never leave a stale cross-case thumbnail on screen.
    setPreview(null)
    void loadThumbnail(caseId, artifactId, key).then((next) => {
      if (!cancelled) setPreview(next)
    })
    return () => {
      cancelled = true
    }
  }, [caseId, artifactId])

  return preview
}

/**
 * The sentence shown wherever a derived preview is rendered.
 *
 * One wording, so the chat, the map, the gallery and the file pane make the
 * same claim about the same header.
 */
export const DERIVED_THUMBNAIL_NOTE =
  'Not decoded from this file. The server produced this preview from the device’s own thumbnail cache or a video keyframe, so it may not match the bytes in evidence.'
