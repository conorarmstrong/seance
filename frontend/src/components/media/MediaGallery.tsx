import {
  type MouseEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Modal } from '../Modal'
import { ArtifactIncompleteness, IncompleteBadge } from '../Incompleteness'
import { ContextMenu, type ContextMenuItem } from '../ContextMenu'
import { useToast } from '../toast/ToastProvider'
import {
  formatBytes,
  formatCount,
  formatUtc,
  truncateHash,
} from '../../lib/format'
import { useObjectUrl } from '../../lib/useObjectUrl'
import { useInfiniteScroll } from '../../lib/useInfiniteScroll'
import {
  fetchContentBlob,
  fetchThumbnail,
  fetchThumbnailBlob,
  type ExifRecord,
  type MediaSort,
  type SortOrder,
} from '../../pages/gallery/api'
import type { HashFlag } from '../../pages/gallery/hashHits'
import { useInView } from '../../pages/gallery/useInView'
import { VirtualCells } from '../../pages/gallery/VirtualCells'
import { measureColumns } from '../../pages/gallery/gridColumns'
import {
  createBookmark,
  deleteBookmark,
  getBookmarkedIds,
  listBookmarkCategories,
} from '../../api/resources'
import '../../pages/gallery/gallery.css'

export type { MediaSort, SortOrder }

/**
 * One item in a media browser, normalized across sources.
 *
 * A gallery item is a file; a chat-media item is an attachment record resolved
 * to its file. Either way the browser needs the same handful of fields, plus
 * the `artifactId` of the bytes it thumbnails, opens and bookmarks. That id is
 * null when the file is not in evidence, and the cell shows a placeholder.
 */
export interface MediaItem {
  /** Stable list key, unique within the item set. */
  key: string
  /** Artifact whose bytes back this item, or null if not in evidence. */
  artifactId: string | null
  name: string
  path: string | null
  size: number | null
  modified: string | null
  extension: string | null
  /** Source record metadata, for hashes shown in the sidebar. */
  metadata?: Record<string, unknown> | null
  sourceName?: string | null
}

const MISSING_DATE = '—'

/**
 * Label for a cell. Normally the filename, but iOS thumbnail caches name every
 * file after its pixel size and put the ORIGINAL photo's name on the containing
 * folder (".../IMG_4902.JPG/5003.JPG"), which would render thousands of cells
 * all reading "5003.JPG". When the parent folder is itself a media filename it
 * is the meaningful identity, so show "IMG_4902.JPG / 5003.JPG". The full path
 * remains on hover either way.
 */
function cellLabel(item: { name: string; path: string | null }): string {
  const segments = (item.path ?? '').split('/').filter(Boolean)
  const parent = segments.length >= 2 ? segments[segments.length - 2] : null
  if (parent && /\.(jpe?g|png|heic|heif|gif|tiff|mov|mp4)$/i.test(parent)) {
    return `${parent} / ${item.name}`
  }
  return item.name
}

function hashFor(
  meta: Record<string, unknown> | null | undefined,
  keys: string[],
): string | null {
  for (const key of keys) {
    const value = meta?.[key]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return null
}

function metaString(
  meta: Record<string, unknown> | null | undefined,
  key: string,
): string | null {
  const value = meta?.[key]
  return typeof value === 'string' && value.length > 0 ? value : null
}

/**
 * Starting estimates for a row's height in px, per layout. `VirtualCells`
 * measures the real one as soon as the grid has been laid out; these only have
 * to be close enough for the first paint.
 */
const TILE_ROW_ESTIMATE = 190
const LIST_ROW_ESTIMATE = 44

function Thumb({
  caseId,
  item,
  size,
  alt,
  enabled = true,
}: {
  caseId: string
  item: MediaItem
  size: number
  alt: string
  /** Gate the fetch on the cell being in view (the cell owns the observer). */
  enabled?: boolean
}) {
  const thumb = useQuery({
    queryKey: ['media-thumb', caseId, item.artifactId, size],
    queryFn: () => fetchThumbnail(caseId, item.artifactId!, size),
    enabled: enabled && !!item.artifactId,
    staleTime: Infinity,
    // The object URL is revoked on unmount, so a cell scrolled back into view
    // must refetch a fresh blob rather than reuse a revoked URL.
    gcTime: 0,
    retry: false,
  })
  // The query holds bytes; the URL is minted and revoked here, by the component
  // that renders it. A cell scrolled past while its fetch is in flight then
  // leaks nothing: no handle was created on its behalf (B4-027).
  const url = useObjectUrl(
    `${caseId}/${item.artifactId ?? 'none'}/${size}`,
    thumb.data?.blob ?? null,
  )
  // The server flags previews it did not decode from the artifact's own bytes.
  // A cached thumbnail can outlive and disagree with the file it was made from,
  // so it must not be shown as a picture of the evidence without saying so.
  const derived = thumb.data?.fromDeviceCache === true

  const placeholder = item.extension?.toUpperCase() ?? 'FILE'
  if (!url) {
    return (
      <span className="gl-cell-ph">{thumb.isFetching ? '…' : placeholder}</span>
    )
  }
  const derivedNote =
    'Not decoded from this file. The server produced this preview from the device’s own thumbnail cache or a video keyframe, so it may not match the bytes in evidence.'
  return (
    <>
      <img
        src={url}
        alt={derived ? `${alt} (not decoded from this file)` : alt}
        /* A window's worth of thumbnails still arrive together, and a
           synchronous decode of each blocks the main thread while the examiner
           is scrolling through them. The fetches themselves are already
           bounded — see the semaphore in pages/gallery/api. */
        decoding="async"
      />
      {derived && (
        <span
          className="badge badge-warn gl-derived-badge"
          role="note"
          data-testid="gl-derived-thumb"
          title={derivedNote}
          aria-label={derivedNote}
        >
          ⚠ not from this file
        </span>
      )}
    </>
  )
}

function MediaCell({
  caseId,
  item,
  index,
  highlighted,
  flag,
  bookmarked,
  resolved,
  onHighlight,
  onOpen,
  onContextMenu,
}: {
  caseId: string
  item: MediaItem
  index: number
  highlighted: boolean
  flag?: HashFlag
  bookmarked?: boolean
  /** True once a lookup for this item's bytes has completed. */
  resolved: boolean
  onHighlight: () => void
  onOpen: () => void
  onContextMenu?: (e: MouseEvent) => void
}) {
  const { ref, inView } = useInView<HTMLButtonElement>()
  return (
    <button
      ref={ref}
      type="button"
      data-idx={index}
      aria-selected={highlighted}
      className={highlighted ? 'gl-cell is-highlighted' : 'gl-cell'}
      // Single click selects (opens the properties sidebar); double-click opens
      // the lightbox. Blur after selecting so the window-level key handler owns
      // Space/Enter/arrows rather than the focused button.
      onClick={(e) => {
        onHighlight()
        e.currentTarget.blur()
      }}
      onDoubleClick={onOpen}
      onContextMenu={onContextMenu}
    >
      <span className="gl-cell-thumb">
        {bookmarked && (
          <span className="gl-bookmark" title="Bookmarked" aria-label="Bookmarked">
            ★
          </span>
        )}
        {flag && (
          <span
            className={
              flag.notable ? 'gl-flag gl-flag-notable' : 'gl-flag gl-flag-known'
            }
            title={`Hash match: ${flag.setName}`}
          >
            {flag.notable ? 'NOTABLE' : 'KNOWN'}
          </span>
        )}
        {/* Which pictures the toolbar's "N incomplete" count is about. A count
            with nothing marked leaves an examiner unable to act on it, and a
            thumbnail rendered from the first third of a JPEG looks like a whole
            photograph. */}
        <span className="gl-incomplete">
          <IncompleteBadge metadata={item.metadata} />
        </span>
        <Thumb
          caseId={caseId}
          item={item}
          size={160}
          alt={`Thumbnail of ${item.name}`}
          enabled={inView}
        />
      </span>
      <span className="gl-cell-name mono" title={item.path ?? undefined}>
        {cellLabel(item)}
      </span>
      {resolved && !item.artifactId && (
        <span className="gl-cell-missing">not in evidence</span>
      )}
    </button>
  )
}

/**
 * List-view counterpart of {@link MediaCell}: the same selection, opening and
 * context-menu behaviour, laid out as a row so size and date are visible.
 */
function MediaRow({
  caseId,
  item,
  index,
  highlighted,
  flag,
  bookmarked,
  onHighlight,
  onOpen,
  onContextMenu,
}: {
  caseId: string
  item: MediaItem
  index: number
  highlighted: boolean
  flag?: HashFlag
  bookmarked?: boolean
  onHighlight: () => void
  onOpen: () => void
  onContextMenu?: (e: MouseEvent) => void
}) {
  const { ref, inView } = useInView<HTMLButtonElement>()
  return (
    <button
      ref={ref}
      type="button"
      data-idx={index}
      aria-selected={highlighted}
      className={highlighted ? 'gl-row is-highlighted' : 'gl-row'}
      onClick={(e) => {
        onHighlight()
        e.currentTarget.blur()
      }}
      onDoubleClick={onOpen}
      onContextMenu={onContextMenu}
    >
      <span className="gl-row-thumb">
        <Thumb caseId={caseId} item={item} size={160} alt="" enabled={inView} />
      </span>
      <span className="gl-row-name" title={item.path ?? undefined}>
        {bookmarked && <span className="gl-row-star">★</span>}
        {cellLabel(item)}
        {flag && (
          <span
            className={
              flag.notable ? 'gl-flag gl-flag-notable' : 'gl-flag gl-flag-known'
            }
          >
            {flag.notable ? 'NOTABLE' : 'KNOWN'}
          </span>
        )}
        <IncompleteBadge metadata={item.metadata} />
      </span>
      <span className="gl-row-size mono">
        {item.size != null ? formatBytes(item.size) : MISSING_DATE}
      </span>
      <span className="gl-row-date mono">
        {item.modified ? formatUtc(item.modified) : MISSING_DATE}
      </span>
    </button>
  )
}

/** A clickable list-column header that shows and controls the sort. */
function SortHeader({
  column,
  label,
  sort,
  order,
  onSort,
}: {
  column: MediaSort
  label: string
  sort: MediaSort
  order: SortOrder
  onSort: (column: MediaSort) => void
}) {
  const active = sort === column
  return (
    <button
      type="button"
      role="columnheader"
      aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={active ? 'gl-th is-sorted' : 'gl-th'}
      onClick={() => onSort(column)}
    >
      {label}
      <span className="gl-th-arrow" aria-hidden="true">
        {active ? (order === 'asc' ? '↑' : '↓') : ''}
      </span>
    </button>
  )
}

function CopyCoords({ coords }: { coords: string }) {
  const toast = useToast()
  return (
    <button
      type="button"
      className="gl-copy"
      onClick={() => {
        void navigator.clipboard?.writeText(coords).then(
          () => toast.success('Coordinates copied'),
          () => toast.error('Copy failed'),
        )
      }}
    >
      copy
    </button>
  )
}

/** Small clickable preview of the highlighted item, shown atop the sidebar. */
function SidebarPreview({
  caseId,
  item,
  onOpen,
  mediaNoun,
}: {
  caseId: string
  item: MediaItem
  onOpen: () => void
  mediaNoun: string
}) {
  const thumb = useQuery({
    queryKey: ['media-thumb-lg', caseId, item.artifactId],
    queryFn: () => fetchThumbnail(caseId, item.artifactId!, 240),
    enabled: !!item.artifactId,
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
  })
  const url = useObjectUrl(
    `${caseId}/${item.artifactId ?? 'none'}/240`,
    thumb.data?.blob ?? null,
  )
  const derived = thumb.data?.fromDeviceCache === true

  return (
    <>
    <button
      type="button"
      className="gl-sb-preview"
      onClick={onOpen}
      disabled={!item.artifactId}
      title={`Open full ${mediaNoun} (Space)`}
    >
      {url ? (
        <img src={url} alt={`Preview of ${item.name}`} />
      ) : (
        <span className="gl-cell-ph">
          {thumb.isFetching ? '…' : (item.extension?.toUpperCase() ?? 'FILE')}
        </span>
      )}
    </button>
    {/* Stated as a sentence here, not a chip: the sidebar is where an examiner
        studies one item, and this is the difference between a picture of the
        evidence and a picture the device once cached of it. */}
    {url && derived && (
      <div className="warn-note" role="note" data-testid="gl-sb-derived-thumb">
        This preview was <strong>not decoded from this file</strong>. The server
        built it from the device&rsquo;s own thumbnail cache or a video
        keyframe, so it may not match the bytes held in evidence. Open the full{' '}
        {mediaNoun} to see the file itself.
      </div>
    )}
    </>
  )
}

/** Persistent right-hand properties panel for the highlighted item. */
function MediaSidebar({
  caseId,
  item,
  exif,
  extra,
  onOpen,
  mediaNoun,
}: {
  caseId: string
  item: MediaItem
  exif: ExifRecord | null
  /** Source-specific rows (e.g. a chat attachment's message link). */
  extra?: ReactNode
  onOpen: () => void
  mediaNoun: string
}) {
  const md5 = hashFor(item.metadata, ['md5', 'md5_hash'])
  const sha256 = hashFor(item.metadata, ['sha256', 'sha256_hash'])

  const format = item.extension ? item.extension.toUpperCase() : null
  const w = exif?.metadata?.['width']
  const h = exif?.metadata?.['height']
  const dims =
    typeof w === 'number' && typeof h === 'number' ? `${w} × ${h}` : null
  // Where the pixels could not be decoded (HEIC, TIFF) the parser falls back
  // to the size the EXIF header declares and says so in `dimensions_source`;
  // a declared size must not read as a measured one.
  const dimsDeclared = exif?.metadata?.['dimensions_source'] === 'exif_declared'
  // EXIF can declare dimensions that differ from the decoded bitstream — a
  // tamper signal the parser flags. Show the declared size alongside the real
  // one when they disagree.
  const dimsMismatch = exif?.metadata?.['dimensions_mismatch'] === true
  const exifW = exif?.metadata?.['exif_width']
  const exifH = exif?.metadata?.['exif_height']
  const declaredDims =
    dimsMismatch && typeof exifW === 'number' && typeof exifH === 'number'
      ? `${exifW} × ${exifH}`
      : null

  const camera =
    metaString(exif?.metadata, 'camera') ??
    ([metaString(exif?.metadata, 'make'), metaString(exif?.metadata, 'model')]
      .filter(Boolean)
      .join(' ') || null)
  const taken = metaString(exif?.metadata, 'datetime_original')
  const gpsLat = exif?.metadata?.['gps_lat']
  const gpsLon = exif?.metadata?.['gps_lon']
  const hasGps =
    exif?.metadata?.['has_gps'] === true &&
    typeof gpsLat === 'number' &&
    typeof gpsLon === 'number'
  const coords = hasGps ? `${gpsLat}, ${gpsLon}` : null

  return (
    <aside className="gl-sidebar" aria-label={`${mediaNoun} properties`}>
      <SidebarPreview
        caseId={caseId}
        item={item}
        onOpen={onOpen}
        mediaNoun={mediaNoun}
      />
      <h2 className="gl-sb-name mono" title={item.path ?? undefined}>
        {item.name}
      </h2>

      {/* Above the hashes deliberately: MD5 and SHA-256 below are computed over
          the bytes that were read, so on an incomplete file they identify the
          fragment and not the picture. An examiner must meet that before the
          hash they may be about to quote. */}
      <ArtifactIncompleteness metadata={item.metadata} />

      <table className="gl-meta-table mono">
        <tbody>
          {item.path && (
            <tr>
              <td>Path</td>
              <td>{item.path}</td>
            </tr>
          )}
          {item.sourceName && (
            <tr>
              <td>Source</td>
              <td>{item.sourceName}</td>
            </tr>
          )}
          <tr>
            <td>Size</td>
            <td>{item.size != null ? formatBytes(item.size) : MISSING_DATE}</td>
          </tr>
          {format && (
            <tr>
              <td>Format</td>
              <td>{format}</td>
            </tr>
          )}
          {dims && (
            <tr>
              <td>Dimensions</td>
              <td>
                {dims}
                {dimsDeclared && (
                  <span
                    className="gl-warn"
                    title="The image could not be decoded; this is the size its EXIF header declares, not a measured one"
                  >
                    {' '}
                    declared by EXIF, not measured
                  </span>
                )}
                {dimsMismatch && (
                  <span className="gl-warn" title="Actual decoded pixel size">
                    {' '}
                    actual
                  </span>
                )}
              </td>
            </tr>
          )}
          {declaredDims && (
            <tr>
              <td>EXIF claims</td>
              <td>
                <span className="gl-warn-strong">⚠ {declaredDims}</span>
              </td>
            </tr>
          )}
          {item.modified && (
            <tr>
              <td>Modified</td>
              <td>{formatUtc(item.modified)}</td>
            </tr>
          )}
          {md5 && (
            <tr>
              <td>MD5</td>
              <td title={md5}>{truncateHash(md5)}</td>
            </tr>
          )}
          {sha256 && (
            <tr>
              <td>SHA256</td>
              <td title={sha256}>{truncateHash(sha256)}</td>
            </tr>
          )}
        </tbody>
      </table>

      {extra}

      {exif && (
        <>
          <h3 className="gl-exif-head">EXIF</h3>
          <table className="gl-meta-table mono">
            <tbody>
              {camera && (
                <tr>
                  <td>Camera</td>
                  <td>{camera}</td>
                </tr>
              )}
              {taken && (
                <tr>
                  <td>Taken</td>
                  <td>{taken}</td>
                </tr>
              )}
              {coords && (
                <tr>
                  <td>GPS</td>
                  <td>
                    {coords}
                    <CopyCoords coords={coords} />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </>
      )}

      <div className="gl-sb-actions">
        {item.artifactId && (
          <>
            <button type="button" className="btn" onClick={onOpen}>
              View {mediaNoun}
            </button>
            <Link
              className="btn btn-primary"
              to={`/cases/${caseId}/artifacts/${item.artifactId}`}
            >
              Open artifact
            </Link>
          </>
        )}
        {!item.artifactId && (
          <span className="gl-sb-hint">
            This item's file is not in the evidence.
          </span>
        )}
      </div>
      {item.artifactId && (
        <p className="gl-sb-hint">Arrow keys to move · Space to enlarge</p>
      )}
    </aside>
  )
}

/** Full-media lightbox: the image/video plus prev/next and Open-artifact. */
function Lightbox({
  caseId,
  item,
  hasPrev,
  hasNext,
  onPrev,
  onNext,
  onClose,
}: {
  caseId: string
  item: MediaItem
  hasPrev: boolean
  hasNext: boolean
  onPrev: () => void
  onNext: () => void
  onClose: () => void
}) {
  // HEIC/HEIF are HEVC-coded: no browser renders the original bytes, so show
  // the server's decoded rendering at full size. /content keeps serving the
  // untouched original for download and hashing.
  const isHeif = /\.hei[cf]$/i.test(item.name)
  const isVideo = /\.(mp4|mov|m4v|avi|mkv|webm|wmv|3gp)$/i.test(item.name)
  // Browsers decode Opus/AAC/MP3/WAV natively (Opus in Ogg/CAF/WebM included),
  // so audio just needs a player over the original bytes — no dependency.
  const isAudio = /\.(mp3|m4a|aac|wav|flac|ogg|opus|amr|caf|aiff)$/i.test(
    item.name,
  )
  const content = useQuery({
    queryKey: ['media-content', caseId, item.artifactId, isHeif],
    queryFn: () =>
      // Audio, video and non-HEIF images all play/show from the original
      // bytes; only HEIF needs the server's decoded rendering.
      isHeif
        ? fetchThumbnailBlob(caseId, item.artifactId!, 512)
        : fetchContentBlob(caseId, item.artifactId!),
    enabled: !!item.artifactId,
    staleTime: Infinity,
    retry: false,
  })

  const blob = content.data ?? null
  // The lightbox stays mounted across Prev/Next: `item` — and with it the modal
  // title, the "Open artifact" link and the properties beneath — becomes the
  // next picture immediately, while an unscoped object URL still addresses the
  // previous one's bytes until an effect repairs it a frame later. That frame
  // is the previous exhibit displayed under this exhibit's name. Scoping the
  // handle to the artifact makes it read back null instead, so the modal shows
  // its own "Loading…" until the right bytes are in hand.
  const url = useObjectUrl(`${caseId}/${item.artifactId ?? ''}/${isHeif}`, blob)

  return (
    <Modal
      title={item.name}
      onClose={onClose}
      footer={
        <div className="gl-lightbox-foot">
          <div className="gl-lb-nav">
            <button
              type="button"
              className="btn"
              disabled={!hasPrev}
              onClick={onPrev}
              aria-label="Previous item"
            >
              ‹ Prev
            </button>
            <button
              type="button"
              className="btn"
              disabled={!hasNext}
              onClick={onNext}
              aria-label="Next item"
            >
              Next ›
            </button>
          </div>
          {item.artifactId && (
            <Link
              className="btn btn-primary"
              to={`/cases/${caseId}/artifacts/${item.artifactId}`}
            >
              Open artifact
            </Link>
          )}
        </div>
      }
    >
      <div className="gl-lightbox-image">
        {content.isError ? (
          <span className="error-note">Failed to load media</span>
        ) : url ? (
          isAudio ? (
            <div className="gl-audio">
              <span className="gl-audio-name mono">{item.name}</span>
              {/* eslint-disable-next-line jsx-a11y/media-has-caption */}
              <audio src={url} controls autoPlay />
            </div>
          ) : isVideo ? (
            // eslint-disable-next-line jsx-a11y/media-has-caption
            <video src={url} controls autoPlay className="gl-video" />
          ) : (
            <img src={url} alt={item.name} />
          )
        ) : (
          <span className="loading">Loading…</span>
        )}
      </div>
    </Modal>
  )
}

/**
 * Where the Safe view choice is kept.
 *
 * Per browser, not per case: it is a statement about what this examiner is
 * willing to have appear on their screen, and that does not change because they
 * opened a different exhibit.
 */
const SAFE_VIEW_KEY = 'seance_gallery_safe_view'

/** The stored choice; OFF when nothing is stored or storage cannot be read. */
function loadSafeView(): boolean {
  try {
    return localStorage.getItem(SAFE_VIEW_KEY) === '1'
  } catch {
    // Private windows and blocked site data throw on access. Falling back to
    // OFF matches the shipped default rather than inventing a third behaviour;
    // the control is in the toolbar and says which state it is in.
    return false
  }
}

function storeSafeView(on: boolean) {
  try {
    localStorage.setItem(SAFE_VIEW_KEY, on ? '1' : '0')
  } catch {
    // The toggle still holds for this page; only the memory of it is lost.
  }
}

export interface MediaGalleryProps {
  caseId: string
  /** Page heading. Omit when embedded under a shell that already has one. */
  title?: string
  /** Plural noun for counts and empty states, e.g. "images", "attachments". */
  noun: string
  /** Singular noun for actions, e.g. "image", "video", "attachment". */
  mediaNoun: string
  items: MediaItem[]
  /** Total across the whole set when more than `items` is loaded (server-paged). */
  total?: number
  loading?: boolean
  /** True once each item's bytes have been looked up, so a missing file can be
   * stated rather than merely absent while resolution is in flight. */
  resolved?: boolean
  sort: MediaSort
  order: SortOrder
  /** A column header was clicked: sort by it, reversing if already active. */
  onSort: (column: MediaSort) => void
  /** An explicit sort was chosen (dropdown column, order button). */
  onSortChange: (sort: MediaSort, order: SortOrder) => void
  /** Infinite scroll: omit for an in-memory set that is already complete. */
  hasNextPage?: boolean
  isFetchingNextPage?: boolean
  onLoadMore?: () => void
  flagFor?: (item: MediaItem) => HashFlag | undefined
  exifFor?: (item: MediaItem) => ExifRecord | null
  /** Source-specific sidebar rows for the highlighted item. */
  sidebarExtra?: (item: MediaItem) => ReactNode
  /** Toolbar controls between the count and the sort control. */
  toolbarStart?: ReactNode
  /** Toolbar controls after the view toggle. */
  toolbarEnd?: ReactNode
  /** Extra per-cell context-menu items, appended after the bookmark items. */
  extraCellMenuItems?: (item: MediaItem) => ContextMenuItem[]
  emptyState?: ReactNode
}

/**
 * A media browser: a responsive thumbnail grid (or detail list) with a
 * properties sidebar, a full-size lightbox, keyboard triage and bookmarking.
 *
 * It is purely presentational over a normalized {@link MediaItem} list: the
 * caller decides where items come from (a paged file grid, an in-memory set of
 * chat attachments) and how they sort, so the same rich interface serves every
 * media surface in the app.
 */
export function MediaGallery({
  caseId,
  title,
  noun,
  mediaNoun,
  items,
  total,
  loading,
  resolved = true,
  sort,
  order,
  onSort,
  onSortChange,
  hasNextPage,
  isFetchingNextPage,
  onLoadMore,
  flagFor,
  exifFor,
  sidebarExtra,
  toolbarStart,
  toolbarEnd,
  extraCellMenuItems,
  emptyState,
}: MediaGalleryProps) {
  const [layout, setLayout] = useState<'tiles' | 'list'>('tiles')
  // Examiner-wellbeing control: blur+greyscale every preview, with
  // click/hover-to-reveal. CSAM and other distressing material is a real
  // occupational hazard, and a gallery that shows it unbidden is a liability;
  // every commercial suite ships this.
  //
  // It is OFF by default and remembered per browser. The default changed on
  // 2026-09-07: most cases are ordinary disk images where blurring every
  // thumbnail is friction and nothing else, and an examiner who wants the
  // protection is the one who knows they want it.
  //
  // Remembering the choice is what makes that default safe, and is not a
  // convenience: with the old on-by-default, forgetting the toggle merely
  // re-protected you. Now, an examiner who turns it ON and then opens another
  // case would have got an unblurred grid of exactly the material the control
  // exists to hide. The persistence is the safeguard, not the polish.
  const [safeView, setSafeView] = useState(loadSafeView)
  const toggleSafeView = () => {
    setSafeView((v) => {
      storeSafeView(!v)
      return !v
    })
  }
  const [highlighted, setHighlighted] = useState(-1)
  const [modalOpen, setModalOpen] = useState(false)
  const [menu, setMenu] = useState<{
    x: number
    y: number
    item: MediaItem
  } | null>(null)
  const rootRef = useRef<HTMLDivElement>(null)
  const gridRef = useRef<HTMLDivElement>(null)
  const loadMoreRef = useRef<HTMLDivElement>(null)
  const toast = useToast()
  const queryClient = useQueryClient()
  // The case a mutation must have been sent to for its result to belong here.
  const activeCase = useRef(caseId)
  activeCase.current = caseId

  // Bookmarks: which items are already marked, and the categories a new one can
  // go into. Both are small case-wide lookups.
  const bookmarkIdsQuery = useQuery({
    // Under the ['bookmarks', caseId, …] prefix so a bookmark toggled from the
    // artifact viewer or Bookmarks page (which invalidate ['bookmarks', caseId])
    // also refreshes the gallery.
    queryKey: ['bookmarks', caseId, 'ids'],
    queryFn: () => getBookmarkedIds(caseId),
  })
  const bookmarkedIds = useMemo(
    () => new Set(bookmarkIdsQuery.data ?? []),
    [bookmarkIdsQuery.data],
  )
  const categoriesQuery = useQuery({
    queryKey: ['bookmark-categories', caseId],
    queryFn: () => listBookmarkCategories(caseId),
  })
  const refreshBookmarks = (forCase: string) => {
    // One prefix covers the ids query above and every other bookmark view.
    void queryClient.invalidateQueries({ queryKey: ['bookmarks', forCase] })
  }
  // The write goes to the case that was open when `mutate()` ran; `onSuccess`
  // runs in the latest render's closure, so the case it names has to be carried
  // through the mutation rather than read there (B5-012 class).
  const bookmarkMutation = useMutation({
    mutationFn: (v: { artifactId: string; categoryId?: string }) => {
      const forCase = caseId
      return createBookmark(forCase, {
        artifact_id: v.artifactId,
        category_id: v.categoryId,
      }).then(() => forCase)
    },
    onSuccess: (forCase) => {
      refreshBookmarks(forCase)
      if (forCase !== activeCase.current) return
      toast.success('Bookmarked')
    },
    onError: (err) => toast.error(`Failed to bookmark: ${err.message}`),
  })
  const unbookmarkMutation = useMutation({
    mutationFn: (artifactId: string) => {
      const forCase = caseId
      return deleteBookmark(forCase, artifactId).then(() => forCase)
    },
    onSuccess: (forCase) => {
      refreshBookmarks(forCase)
      if (forCase !== activeCase.current) return
      toast.success('Bookmark removed')
    },
    onError: (err) => toast.error(`Failed to remove bookmark: ${err.message}`),
  })

  // Rebuilding the list re-seats index N onto a different item, so the highlight
  // and open lightbox no longer refer to what the examiner picked — drop them.
  // This covers every set change (source, hash-match filter, kind, sort, order,
  // and a `:caseId` switch under a page that stays mounted), not just
  // sort/order. An infinite-scroll "load more" only appends: it keeps the whole
  // existing prefix pointing at the same items (compared by stable key, since
  // the mapped item objects are recreated each render), so it is not treated as
  // a set change and the highlight survives paging.
  //
  // Dropped during render rather than in a `useEffect`. `highlighted` is an
  // INDEX: the moment a new set arrives it addresses a different item, and an
  // effect only repairs that after the frame has committed — with the lightbox
  // open, that frame renders another artifact's name and fetches its bytes,
  // captioned as the picture the examiner had open. Adjusting the state while
  // rendering re-renders before anything is committed, so the wrong item is
  // never shown at all. The ref guard makes it terminate: the second render
  // sees the same `items` and does nothing.
  const prevItemsRef = useRef(items)
  if (prevItemsRef.current !== items) {
    const prev = prevItemsRef.current
    prevItemsRef.current = items
    const isAppend =
      items.length >= prev.length &&
      prev.every((it, i) => it.key === items[i]?.key)
    if (!isAppend) {
      setHighlighted(-1)
      setModalOpen(false)
    }
  }

  // Continuous scroll: pull the next page when the sentinel nears the viewport.
  // Wider margin than the record tables: thumbnails take longer to arrive, so
  // the next page is asked for further from the edge.
  useInfiniteScroll(loadMoreRef, {
    hasNextPage,
    isFetchingNextPage,
    onLoadMore,
    rootMargin: '600px',
  })

  const highlightedItem =
    highlighted >= 0 && highlighted < items.length ? items[highlighted] : null

  const toggleBookmark = (item: MediaItem) => {
    if (!item.artifactId) return
    if (bookmarkedIds.has(item.artifactId))
      unbookmarkMutation.mutate(item.artifactId)
    else bookmarkMutation.mutate({ artifactId: item.artifactId })
  }

  // Keyboard model: arrows move the highlight (↑/↓ by a row), Space toggles the
  // lightbox, Enter opens it, B bookmarks. Works whether or not the lightbox is
  // open — it always renders the highlighted item, so arrows page through it.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      if (t && ['INPUT', 'SELECT', 'TEXTAREA'].includes(t.tagName)) return
      const n = items.length
      if (n === 0) return

      switch (e.key) {
        case ' ':
        case 'Spacebar':
          if (modalOpen) return
          e.preventDefault()
          if (highlighted < 0) setHighlighted(0)
          else if (items[highlighted]?.artifactId) setModalOpen(true)
          return
        case 'Enter':
          if (!modalOpen && highlighted >= 0 && items[highlighted]?.artifactId) {
            e.preventDefault()
            setModalOpen(true)
          }
          return
        case 'b':
        case 'B': {
          if (highlighted < 0) return
          const target = items[highlighted]
          if (!target) return
          e.preventDefault()
          toggleBookmark(target)
          return
        }
        case 'Home':
        case 'End': {
          // Both address the ITEM SET, not the rendered window. The grid is
          // windowed, so the cell either of these moves to is routinely not in
          // the DOM when the key is pressed; `VirtualCells` pins the
          // highlighted index and renders it wherever the scroll happens to be,
          // which is what keeps "jump to the end" meaning the end of what has
          // been loaded rather than the end of what is on screen.
          if (t && t !== document.body && !rootRef.current?.contains(t)) return
          e.preventDefault()
          setHighlighted(e.key === 'Home' ? 0 : n - 1)
          return
        }
        case 'ArrowLeft':
        case 'ArrowRight':
        case 'ArrowUp':
        case 'ArrowDown': {
          // Only claim arrows when focus is neutral (on the body, the usual case
          // after a cell blurs itself on click) or inside the gallery. A control
          // focused elsewhere on the page keeps its native arrow behavior rather
          // than having it swallowed just because the gallery is mounted.
          if (t && t !== document.body && !rootRef.current?.contains(t)) return
          e.preventDefault()
          if (highlighted < 0) {
            setHighlighted(0)
            return
          }
          const cols = measureColumns(gridRef.current)
          const delta =
            e.key === 'ArrowLeft'
              ? -1
              : e.key === 'ArrowRight'
                ? 1
                : e.key === 'ArrowUp'
                  ? -cols
                  : cols
          setHighlighted((i) => Math.min(n - 1, Math.max(0, i + delta)))
          return
        }
        default:
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, highlighted, modalOpen, bookmarkedIds])

  // Keeping the highlighted cell in view is `VirtualCells`' job, not this
  // component's: the grid is windowed, so a move to a cell far down the set
  // brings that cell into existence one render later and inside the windowing
  // component — an effect here would run against a DOM that does not hold it
  // yet, find nothing, and never look again.

  const cellMenuItems = (item: MediaItem): ContextMenuItem[] => {
    const out: ContextMenuItem[] = []
    if (item.artifactId) {
      const marked = bookmarkedIds.has(item.artifactId)
      if (marked) {
        out.push({
          label: 'Remove bookmark',
          onClick: () => {
            unbookmarkMutation.mutate(item.artifactId!)
            setMenu(null)
          },
        })
      } else {
        out.push({
          label: `Bookmark ${mediaNoun}`,
          onClick: () => {
            bookmarkMutation.mutate({ artifactId: item.artifactId! })
            setMenu(null)
          },
        })
        for (const cat of categoriesQuery.data ?? []) {
          out.push({
            label: `Bookmark in ${cat.name}`,
            onClick: () => {
              bookmarkMutation.mutate({
                artifactId: item.artifactId!,
                categoryId: cat.id,
              })
              setMenu(null)
            },
          })
        }
      }
    }
    const extra = extraCellMenuItems?.(item) ?? []
    if (out.length > 0 && extra.length > 0)
      out[out.length - 1].separatorAfter = true
    return [...out, ...extra]
  }

  const countLabel = loading
    ? 'Loading…'
    : `${formatCount(total ?? items.length)} ${noun}`
  // How much of that population is actually in the browser. The grid is
  // windowed AND server-paged, so what is on screen is a slice of a slice: the
  // headline count stays the population an examiner would quote, and this says
  // how far the keys, the lightbox and Home/End can currently reach. Stated
  // only when the two differ, so it does not become noise on a small case.
  const loadedShortfall =
    total != null && total > items.length ? items.length : null

  return (
    <div ref={rootRef} className={safeView ? 'gl-safe-view' : undefined}>
      {title && <h1 className="page-title">{title}</h1>}

      <div className="gl-toolbar">
        <span className="gl-count">{countLabel}</span>
        {loadedShortfall != null && !loading && (
          <span className="gl-loaded" role="note" data-testid="gl-loaded">
            {formatCount(loadedShortfall)} of {formatCount(total!)} loaded —
            scrolling loads more
          </span>
        )}
        {toolbarStart}
        <div className="gl-filter">
          <label htmlFor="gl-sort">Sort</label>
          <select
            id="gl-sort"
            className="select"
            value={sort}
            onChange={(e) => onSortChange(e.target.value as MediaSort, order)}
          >
            <option value="name">Name</option>
            <option value="size">Size</option>
            <option value="modified">Date modified</option>
          </select>
          <button
            type="button"
            className="button gl-order"
            title={order === 'asc' ? 'Ascending' : 'Descending'}
            aria-label={`Sort ${order === 'asc' ? 'ascending' : 'descending'}`}
            onClick={() => onSortChange(sort, order === 'asc' ? 'desc' : 'asc')}
          >
            {order === 'asc' ? '↑' : '↓'}
          </button>
        </div>
        <div className="gl-filter">
          <span id="gl-layout-label">View</span>
          <div className="gl-seg" role="group" aria-labelledby="gl-layout-label">
            <button
              type="button"
              className={layout === 'tiles' ? 'is-active' : undefined}
              aria-pressed={layout === 'tiles'}
              onClick={() => setLayout('tiles')}
            >
              Tiles
            </button>
            <button
              type="button"
              className={layout === 'list' ? 'is-active' : undefined}
              aria-pressed={layout === 'list'}
              onClick={() => setLayout('list')}
            >
              List
            </button>
          </div>
        </div>
        <div className="gl-filter">
          <button
            type="button"
            className={safeView ? 'button gl-safe-toggle is-active' : 'button gl-safe-toggle'}
            aria-pressed={safeView}
            title={
              safeView
                ? 'Safe view on: previews are blurred until you hover or click. Protects examiners from unbidden exposure to distressing material.'
                : 'Safe view off: previews are shown in full.'
            }
            onClick={toggleSafeView}
          >
            {safeView ? '👁 Safe view: on' : '👁 Safe view: off'}
          </button>
        </div>
        {toolbarEnd}
      </div>

      {loading ? (
        <div className="loading">Loading {noun}…</div>
      ) : items.length === 0 ? (
        emptyState ?? (
          <div className="empty-state">
            <h3>No {noun}</h3>
            <p>Nothing to show here.</p>
          </div>
        )
      ) : (
        <div className="gl-layout">
          <div className="gl-main">
            {/* Windowed. Only the cells near the viewport are mounted, so a
                case with a hundred thousand pictures no longer builds a hundred
                thousand buttons, observers, queries, object URLs and decodes.
                What the examiner can REACH is unchanged: the highlight is an
                index into `items`, the keys below move it over the whole item
                set, and `VirtualCells` renders whichever cell it lands on. */}
            <VirtualCells
              className={layout === 'list' ? 'gl-list' : 'gl-grid'}
              containerRef={gridRef}
              count={items.length}
              cellHeight={
                layout === 'list' ? LIST_ROW_ESTIMATE : TILE_ROW_ESTIMATE
              }
              pinnedIndex={highlighted}
              head={
                layout === 'list' ? (
                  <div className="gl-list-head" role="row">
                    <span />
                    <SortHeader
                      column="name"
                      label="Name"
                      sort={sort}
                      order={order}
                      onSort={onSort}
                    />
                    <SortHeader
                      column="size"
                      label="Size"
                      sort={sort}
                      order={order}
                      onSort={onSort}
                    />
                    <SortHeader
                      column="modified"
                      label="Modified"
                      sort={sort}
                      order={order}
                      onSort={onSort}
                    />
                  </div>
                ) : null
              }
            >
              {(index) => {
                const item = items[index]
                const common = {
                  caseId,
                  item,
                  index,
                  highlighted: index === highlighted,
                  flag: flagFor?.(item),
                  bookmarked: item.artifactId
                    ? bookmarkedIds.has(item.artifactId)
                    : false,
                  onHighlight: () => setHighlighted(index),
                  onOpen: () => {
                    setHighlighted(index)
                    if (item.artifactId) setModalOpen(true)
                  },
                  onContextMenu: (e: MouseEvent) => {
                    const menuItems = cellMenuItems(item)
                    if (menuItems.length === 0) return
                    e.preventDefault()
                    setHighlighted(index)
                    setMenu({ x: e.clientX, y: e.clientY, item })
                  },
                }
                return layout === 'list' ? (
                  <MediaRow key={item.key} {...common} />
                ) : (
                  <MediaCell key={item.key} {...common} resolved={resolved} />
                )
              }}
            </VirtualCells>
            <div ref={loadMoreRef} className="gl-sentinel">
              {hasNextPage && onLoadMore && (
                <button
                  type="button"
                  className="button"
                  onClick={onLoadMore}
                  disabled={isFetchingNextPage}
                >
                  {isFetchingNextPage
                    ? `Loading more ${noun}…`
                    : `Load more ${noun}`}
                </button>
              )}
            </div>
          </div>

          {highlightedItem && (
            <MediaSidebar
              caseId={caseId}
              item={highlightedItem}
              exif={exifFor?.(highlightedItem) ?? null}
              extra={sidebarExtra?.(highlightedItem)}
              onOpen={() => {
                if (highlightedItem.artifactId) setModalOpen(true)
              }}
              mediaNoun={mediaNoun}
            />
          )}
        </div>
      )}

      {modalOpen && highlightedItem?.artifactId && (
        <Lightbox
          caseId={caseId}
          item={highlightedItem}
          hasPrev={highlighted > 0}
          hasNext={highlighted < items.length - 1}
          onPrev={() => setHighlighted((i) => Math.max(0, i - 1))}
          onNext={() => setHighlighted((i) => Math.min(items.length - 1, i + 1))}
          onClose={() => setModalOpen(false)}
        />
      )}

      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={cellMenuItems(menu.item)}
          onClose={() => setMenu(null)}
        />
      )}
    </div>
  )
}
