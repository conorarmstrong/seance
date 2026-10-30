import { Link } from 'react-router-dom'
import { DERIVED_THUMBNAIL_NOTE, useThumbnail } from '../../lib/thumbnails'
import type { GpsPoint } from './api'

export { resetThumbnailCache } from '../../lib/thumbnails'

/**
 * Hover preview for a map point: the photo's thumbnail alongside its filename
 * and coordinates. Only photo points carry an `imageId` (the EXIF record's
 * parent FileEntry); everything else shows the text card alone.
 *
 * When the point is a photo the whole card is a link to that image's artifact,
 * so clicking the preview opens it. The card stays put while the pointer is over
 * it (via `onEnter`/`onLeave`) so it can actually be clicked.
 */
export function GeoHoverCard({
  caseId,
  point,
  x,
  y,
  onEnter,
  onLeave,
}: {
  caseId: string
  point: GpsPoint
  /** Position within the map wrapper, in CSS pixels. */
  x: number
  y: number
  onEnter: () => void
  onLeave: () => void
}) {
  const thumb = useThumbnail(caseId, point.imageId)

  const body = (
    <>
      {thumb ? (
        <>
          <img
            className="geo-hover-img"
            data-testid="geo-hover-thumb"
            src={thumb.url}
            alt={thumb.fromDeviceCache ? 'Preview not decoded from this file' : ''}
          />
          {/* The server said it did not decode these pixels from the photo's
              own bytes. A cached thumbnail can outlive and disagree with the
              picture that was geotagged, so the card must not present it as a
              rendering of the evidence (B8-004). */}
          {thumb.fromDeviceCache && (
            <span
              className="badge badge-warn geo-hover-derived"
              role="note"
              data-testid="geo-derived-thumb"
              title={DERIVED_THUMBNAIL_NOTE}
              aria-label={DERIVED_THUMBNAIL_NOTE}
            >
              ⚠ not from this file
            </span>
          )}
        </>
      ) : (
        // Say so rather than silently showing a text-only card: a point with no
        // preview (not an image, or its bytes are unreadable) is different from
        // one whose preview is still loading.
        <div className="geo-hover-nopreview">
          {point.imageId ? 'No preview' : 'No image for this point'}
        </div>
      )}
      <div className="geo-hover-name">
        {point.sourceName ?? point.camera ?? point.type}
      </div>
      <div className="geo-hover-coords mono">
        {point.lat.toFixed(5)}, {point.lon.toFixed(5)}
      </div>
    </>
  )

  const common = {
    className: 'geo-hover',
    style: { left: x, top: y },
    onMouseEnter: onEnter,
    onMouseLeave: onLeave,
  }

  // A photo point links to its image artifact; other points are not clickable.
  return point.imageId ? (
    <Link
      {...common}
      to={`/cases/${caseId}/artifacts/${point.imageId}`}
      title="Open image artifact"
    >
      {body}
    </Link>
  ) : (
    <div {...common}>{body}</div>
  )
}
