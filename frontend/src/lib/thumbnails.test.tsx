import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchThumbnail } from '../pages/gallery/api'
import type { ThumbnailResult } from './thumbnailFetch'
import { resetThumbnailCache, useThumbnail } from './thumbnails'

vi.mock('../pages/gallery/api', () => ({
  fetchThumbnail: vi.fn(),
}))

const mockFetch = vi.mocked(fetchThumbnail)

/**
 * `fetchThumbnail` hands back the raw bytes and the cache mints the object URL
 * (B4-027), so the stub maps each distinguishable blob to a stable fake handle.
 */
const urlForBlob = new WeakMap<Blob, string>()
function blobNamed(url: string): Blob {
  const blob = new Blob([url])
  urlForBlob.set(blob, url)
  return blob
}

beforeEach(() => {
  URL.createObjectURL = vi.fn(
    (obj: Blob | MediaSource) =>
      urlForBlob.get(obj as Blob) ?? 'blob:stub',
  ) as unknown as typeof URL.createObjectURL
  URL.revokeObjectURL = vi.fn()
  resetThumbnailCache()
  mockFetch.mockReset()
})

afterEach(() => {
  resetThumbnailCache()
})

describe('useThumbnail cache keying (BUG-201)', () => {
  it('does not reuse one case\'s thumbnail for the same artifact id in another case', async () => {
    // Same artifact UUID, different cases (separate DBs can reuse ids).
    mockFetch.mockImplementation((caseId: string) =>
      Promise.resolve({
        blob: blobNamed(`url-for-${caseId}`),
        fromDeviceCache: false,
      }),
    )

    const a = renderHook(() => useThumbnail('case-A', 'shared-uuid'))
    await waitFor(() => expect(a.result.current?.url).toBe('url-for-case-A'))
    expect(mockFetch).toHaveBeenCalledWith('case-A', 'shared-uuid', 160)

    // A second case with the same artifact id must fetch its own thumbnail,
    // not read case-A's out of the cache.
    const b = renderHook(() => useThumbnail('case-B', 'shared-uuid'))
    await waitFor(() => expect(b.result.current?.url).toBe('url-for-case-B'))
    expect(mockFetch).toHaveBeenCalledWith('case-B', 'shared-uuid', 160)
    expect(mockFetch).toHaveBeenCalledTimes(2)

    // case-A stays cached under its own key — re-mounting it does not refetch.
    const a2 = renderHook(() => useThumbnail('case-A', 'shared-uuid'))
    await waitFor(() => expect(a2.result.current?.url).toBe('url-for-case-A'))
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })
})

describe('useThumbnail provenance (B8-004)', () => {
  it('keeps the server\'s "not decoded from this file" flag with the preview', async () => {
    // The header says the pixels came from the device's thumbnail cache or a
    // video keyframe rather than from the artifact's own bytes. Dropping it
    // here is what let chat chips and map cards render such a preview as a
    // picture of the evidence.
    mockFetch.mockResolvedValue({
      blob: blobNamed('blob:cached'),
      fromDeviceCache: true,
    })

    const hook = renderHook(() => useThumbnail('case-A', 'art-derived'))
    await waitFor(() => expect(hook.result.current?.url).toBe('blob:cached'))
    expect(hook.result.current?.fromDeviceCache).toBe(true)

    // And it survives the cache, so a second mount makes the same claim.
    const again = renderHook(() => useThumbnail('case-A', 'art-derived'))
    await waitFor(() =>
      expect(again.result.current?.fromDeviceCache).toBe(true),
    )
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })
})

describe('useThumbnail in-flight sharing (B2-026)', () => {
  it('fetches one object URL when several components mount the same preview at once', async () => {
    // Two components mounting the same artifact before either fetch resolves
    // used to start two fetches. The cache then held the second object URL and
    // the first was orphaned — never revoked, because revoking it would have
    // blanked the image the other component had already displayed. Over a long
    // gallery/map session that leaks one blob per race.
    let created = 0
    mockFetch.mockImplementation(() => {
      created += 1
      const blob = blobNamed(`blob:thumb-${created}`)
      return new Promise<ThumbnailResult | null>((resolve) =>
        setTimeout(() => resolve({ blob, fromDeviceCache: false }), 0),
      )
    })

    const first = renderHook(() => useThumbnail('case-A', 'art-1'))
    const second = renderHook(() => useThumbnail('case-A', 'art-1'))

    await waitFor(() => expect(first.result.current?.url).toBe('blob:thumb-1'))
    await waitFor(() => expect(second.result.current?.url).toBe('blob:thumb-1'))
    expect(mockFetch).toHaveBeenCalledTimes(1)
    expect(created).toBe(1)
  })

  it('shares one answer of "this artifact has no preview" with every waiting component', async () => {
    // A resolved null is the server's 404: this artifact is not a raster image.
    // That is a fact about the artifact, so it is cached and not asked again.
    mockFetch.mockImplementation(
      () =>
        new Promise<ThumbnailResult | null>((resolve) =>
          setTimeout(() => resolve(null), 0),
        ),
    )

    const first = renderHook(() => useThumbnail('case-A', 'art-2'))
    const second = renderHook(() => useThumbnail('case-A', 'art-2'))

    expect(mockFetch).toHaveBeenCalledTimes(1)
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5))
    })
    expect(first.result.current).toBeNull()
    expect(second.result.current).toBeNull()

    const third = renderHook(() => useThumbnail('case-A', 'art-2'))
    expect(third.result.current).toBeNull()
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it('does not remember a failed fetch as "no preview" (B8-005)', async () => {
    // A thrown fetch is a 500, a dropped connection, an abort — not an answer
    // about the artifact. Caching it turned a momentary API failure into a
    // permanent "no preview" on every chat chip and map card for that file for
    // the rest of the session, which reads as "not an image / unreadable".
    let attempts = 0
    mockFetch.mockImplementation(() => {
      attempts += 1
      return attempts === 1
        ? Promise.reject(new Error('network blip'))
        : Promise.resolve({
            blob: blobNamed('blob:recovered'),
            fromDeviceCache: false,
          })
    })

    const failed = renderHook(() => useThumbnail('case-A', 'art-3'))
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5))
    })
    expect(failed.result.current).toBeNull()

    // The next mount tries again, and gets the picture.
    const retried = renderHook(() => useThumbnail('case-A', 'art-3'))
    await waitFor(() =>
      expect(retried.result.current?.url).toBe('blob:recovered'),
    )
    expect(attempts).toBe(2)
  })
})
