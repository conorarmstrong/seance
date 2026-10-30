import { useEffect } from 'react'
import { useEntityScopedState } from './useEntityScopedState'

/**
 * An object URL for one entity's bytes, which is never readable under another
 * entity.
 *
 * The recurring defect this exists to eliminate: a preview holds the
 * `URL.createObjectURL` handle for the bytes it fetched in a plain `useState`,
 * and creates/revokes it in a `useEffect` keyed on the blob. When the artifact
 * on screen changes — the lightbox's Next button, an in-place `:artifactId`
 * navigation — the new artifact's name, path and size render immediately while
 * the handle in hand still points at the PREVIOUS artifact's bytes. The effect
 * that clears it runs after that frame has committed, so a video, image or PDF
 * is painted, captioned as the exhibit the examiner selected, from bytes that
 * came from a different one. Evidence misattribution in the most literal form
 * available to a UI: the wrong picture under the right filename.
 *
 * Deriving the handle from `scopeKey` during render closes the window
 * completely. On a scope change the hook reads back `null` in the very first
 * render, so callers show their loading state instead — "we have not fetched
 * this yet" rather than "here is the previous exhibit".
 *
 * `scopeKey` identifies the bytes: `` `${caseId}/${artifactId}` ``, plus
 * anything else that changes WHICH bytes are wanted (a thumbnail-versus-
 * original toggle). `blob` is the fetched bytes, or `null` while they are not
 * in hand.
 *
 * Revocation is unchanged and still exact: each created URL is revoked by the
 * cleanup of the effect that created it, so no handle outlives its blob and
 * none is revoked while still rendered.
 */
export function useObjectUrl(
  scopeKey: string,
  blob: Blob | null,
): string | null {
  const [url, setUrl] = useEntityScopedState<string | null>(scopeKey, null)

  useEffect(() => {
    if (!blob) {
      setUrl(null)
      return
    }
    const objectUrl = URL.createObjectURL(blob)
    setUrl(objectUrl)
    return () => URL.revokeObjectURL(objectUrl)
  }, [blob, setUrl])

  return url
}
