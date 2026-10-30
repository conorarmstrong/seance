import { http, HttpResponse } from 'msw'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { server } from '../test/server'
import { fetchThumbnailBytes } from './thumbnailFetch'

const CASE = 'case-1'
const ART = 'art-1'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('fetchThumbnailBytes (B4-027)', () => {
  it('returns the bytes without minting an object URL', async () => {
    // The fetch used to create the URL itself. When its caller was gone by the
    // time the promise settled — a gallery cell scrolled past, a file
    // deselected — the handle was created with nobody left to revoke it, and
    // react-query's gcTime: 0 dropped the entry without one either. Returning
    // the Blob keeps the handle and its owner together.
    const createObjectURL = vi.fn(() => 'blob:leaked')
    const original = URL.createObjectURL
    URL.createObjectURL =
      createObjectURL as unknown as typeof URL.createObjectURL
    try {
      server.use(
        http.get(
          `/api/v1/cases/${CASE}/artifacts/${ART}/thumbnail`,
          () =>
            new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
              headers: { 'Content-Type': 'image/png' },
            }),
        ),
      )
      const result = await fetchThumbnailBytes(CASE, ART, { size: 160 })

      // Asserted by what it holds, not by which class minted it. jsdom has no
      // fetch, so msw answers through undici and `response.blob()` returns
      // Node's Blob while the global `Blob` is jsdom's — different classes, so
      // `toBeInstanceOf(Blob)` fails on a value that is one. In a browser they
      // are the same object and the question never arises. See
      // `src/test/setup.ts` for why aligning the global is worse than this.
      //
      // The bytes are the stronger check anyway: the PNG magic surviving the
      // round trip proves the payload arrived intact, where a class check only
      // proved the wrapper's provenance.
      expect(result!.blob.type).toBe('image/png')
      expect(result!.blob.size).toBe(4)
      expect(new Uint8Array(await result!.blob.arrayBuffer())).toEqual(
        new Uint8Array([137, 80, 78, 71]),
      )

      // No header: the server did not say the preview came from anywhere but
      // the artifact's own bytes.
      expect(result!.fromDeviceCache).toBe(false)
      expect(createObjectURL).not.toHaveBeenCalled()
    } finally {
      URL.createObjectURL = original
    }
  })

  it('reports a preview the server did not decode from the artifact', async () => {
    // `X-Thumbnail-Source: device-cache` says the PNG came from the device's own
    // thumbnail cache or a video keyframe, not from this file's bytes. Dropping
    // the header rendered it as a picture of the evidence — a cached thumbnail
    // can outlive and disagree with the file it was made from.
    server.use(
      http.get(
        `/api/v1/cases/${CASE}/artifacts/${ART}/thumbnail`,
        () =>
          new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
            headers: {
              'Content-Type': 'image/png',
              'X-Thumbnail-Source': 'device-cache',
            },
          }),
      ),
    )
    const result = await fetchThumbnailBytes(CASE, ART, { size: 160 })
    expect(result!.fromDeviceCache).toBe(true)
  })

  it('reports "no thumbnail" as null and a real failure as an error', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/artifacts/${ART}/thumbnail`, () =>
        HttpResponse.json({ error: { message: 'nope' } }, { status: 404 }),
      ),
    )
    await expect(
      fetchThumbnailBytes(CASE, ART, { size: 160 }),
    ).resolves.toBeNull()

    server.use(
      http.get(`/api/v1/cases/${CASE}/artifacts/${ART}/thumbnail`, () =>
        HttpResponse.json({ error: { message: 'boom' } }, { status: 500 }),
      ),
    )
    await expect(
      fetchThumbnailBytes(CASE, ART, { size: 160 }),
    ).rejects.toThrow(/status 500/)
  })
})
