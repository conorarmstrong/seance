import { memo, useCallback, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import {
  WorldMap,
  projectLonLat,
  useWorldMapScale,
} from '../../components/viz/WorldMap'
import { LeafletMap } from './LeafletMap'
import { GeoHoverCard } from './GeoHoverCard'
import { useToast } from '../../components/toast/ToastProvider'
import { formatCount, formatUtc } from '../../lib/format'
import { collectGpsPoints, type GpsPoint } from './api'
import { buildTrack } from './track'
import { downloadFile } from '../../lib/download'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import './geo.css'

/**
 * Group points by record type for the side panel, newest first within a group.
 *
 * A location list is read to answer "where was this, and when": the time is the
 * point, and 14,804 rows in the order the database happened to return them
 * answer nothing (UI-029). Points with no time sort last — they are not newer
 * than everything, they are undated.
 */
function groupByType(points: GpsPoint[]): [string, GpsPoint[]][] {
  const groups = new Map<string, GpsPoint[]>()
  for (const p of points) {
    const list = groups.get(p.type)
    if (list) list.push(p)
    else groups.set(p.type, [p])
  }
  for (const list of groups.values()) {
    list.sort((a, b) => {
      if (a.timestamp && b.timestamp) return b.timestamp.localeCompare(a.timestamp)
      if (a.timestamp) return -1
      if (b.timestamp) return 1
      return 0
    })
  }
  return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))
}

/** EXIF DateTimeOriginal is camera-local "YYYY:MM:DD…"; show verbatim. */
function formatWhen(ts: string | null): string {
  if (!ts) return '—'
  if (/^\d{4}:\d{2}:\d{2}/.test(ts)) return ts
  return formatUtc(ts)
}

/** A single map marker. Memoized so selecting a point re-renders only the two
 * affected dots (previously active + newly active), not every dot on the map --
 * important when a case carries thousands of GPS points. */
const GeoDot = memo(function GeoDot({
  id,
  cx,
  cy,
  lat,
  lon,
  isActive,
  onSelect,
  onHover,
  onLeave,
}: {
  id: string
  cx: number
  cy: number
  lat: number
  lon: number
  isActive: boolean
  onSelect: (id: string) => void
  onHover: (id: string, clientX: number, clientY: number) => void
  onLeave: () => void
}) {
  // A marker drawn in map units keeps its size in degrees: zoomed to a town,
  // a 4-pixel dot became a blob covering the county (UI-029). Scaling by the
  // view keeps it the same size on screen at every zoom.
  const scale = useWorldMapScale()
  return (
    <g
      data-testid={`geo-dot-${id}`}
      data-cx={cx}
      data-cy={cy}
      aria-label={`${lat}, ${lon}`}
      onClick={() => onSelect(id)}
      onMouseEnter={(e) => onHover(id, e.clientX, e.clientY)}
      onMouseLeave={onLeave}
    >
      {/* A plotted point is ~4px on screen — too small to hover reliably — so
          an invisible larger circle carries the pointer events while the
          visible dot stays true to the coordinate. */}
      <circle cx={cx} cy={cy} r={5 * scale} className="wm-dot-hit" />
      <circle
        cx={cx}
        cy={cy}
        r={(isActive ? 3 : 2) * scale}
        className={isActive ? 'wm-dot wm-dot-active' : 'wm-dot'}
      />
    </g>
  )
})

export function GeoMapPage({ caseId: caseIdProp }: { caseId?: string } = {}) {
  const params = useParams() as { caseId?: string }
  const caseId = caseIdProp ?? (params.caseId as string)
  const toast = useToast()
  // The selected point and the hover card both name an artifact of THIS case,
  // and the workbench keeps this page mounted when `:caseId` changes. Stored
  // with the case they were picked in and resolved during render, so case A's
  // photo can never sit in case B's detail panel or hover preview — and no
  // post-render effect window exists in which the stale id could still be used
  // to fetch a thumbnail or build an artifact link (B2-054).
  const [selection, setSelection] = useState<{
    case: string
    id: string
  } | null>(null)
  const activeId = selection && selection.case === caseId ? selection.id : null
  // Live (OpenStreetMap) map is opt-in: it fetches tiles from a third party, so
  // it stays off until the examiner confirms the privacy trade-off. Scoped to
  // the case for the same reason the selection is: the confirmation was given
  // for THIS case's coordinates, and consent to send one case's locations off
  // the machine is not consent to send the next one's. The workbench mounts
  // this page with a `caseId` prop, where nothing guarantees a remount when the
  // case changes.
  const [liveMap, setLiveMap] = useEntityScopedState(caseId, false)
  const [showLiveConfirm, setShowLiveConfirm] = useState(false)
  // Stable so a selection change doesn't invalidate every memoized GeoDot.
  const handleSelect = useCallback(
    (id: string) => setSelection({ case: caseId, id }),
    [caseId],
  )

  // Hover preview (thumbnail + name + coords), positioned inside the map wrap.
  // The card is clickable (it links to the image artifact), so leaving a marker
  // hides it only after a short grace period — long enough to move the pointer
  // onto the card without it vanishing.
  const mapWrapRef = useRef<HTMLDivElement>(null)
  const hideTimer = useRef<number | null>(null)
  const [hoverState, setHoverState] = useState<{
    case: string
    id: string
    x: number
    y: number
  } | null>(null)
  const hover = hoverState && hoverState.case === caseId ? hoverState : null
  const cancelHide = useCallback(() => {
    if (hideTimer.current != null) {
      clearTimeout(hideTimer.current)
      hideTimer.current = null
    }
  }, [])
  const handleHover = useCallback(
    (id: string, clientX: number, clientY: number) => {
      cancelHide()
      const rect = mapWrapRef.current?.getBoundingClientRect()
      if (!rect) return
      setHoverState({
        case: caseId,
        id,
        x: clientX - rect.left + 14,
        y: clientY - rect.top + 14,
      })
    },
    [cancelHide, caseId],
  )
  const handleLeave = useCallback(() => {
    cancelHide()
    hideTimer.current = window.setTimeout(() => setHoverState(null), 160)
  }, [cancelHide])

  const pointsQuery = useQuery({
    queryKey: ['geo-points', caseId],
    queryFn: () => collectGpsPoints(caseId),
  })

  const points = pointsQuery.data?.points ?? []
  // Records carrying a fix the database could not decode into a point. They are
  // absent from the map and no amount of panning will find them, so the count
  // is said next to the total rather than left for the examiner to discover.
  const undecodable = pointsQuery.data?.undecodable ?? null
  const groups = useMemo(() => groupByType(points), [points])
  const active = points.find((p) => p.id === activeId) ?? null
  const hoverPoint = hover
    ? (points.find((p) => p.id === hover.id) ?? null)
    : null

  // Movement track: timed points in chronological order, revealed by a scrubber.
  const track = useMemo(() => buildTrack(points), [points])
  // Scoped to the case for the same reason the selection is: the scrubber
  // position is an index into THIS case's track, and this page stays mounted
  // across a `:caseId` change. Carried over, it truncates case B's movement
  // track at a point that means nothing there — a shorter journey than the
  // evidence shows, with nothing on screen saying it was cut.
  const [trackMode, setTrackMode] = useEntityScopedState(caseId, false)
  const [scrub, setScrub] = useEntityScopedState<number | null>(caseId, null)
  const upto = scrub ?? track.length
  const trackPoints = trackMode ? track.slice(0, upto) : []
  // The window the map opens on: the case's own points, not the globe.
  // Memoised on the point array so a re-render does not re-fit under an
  // examiner who has panned somewhere themselves.
  const fitPoints = useMemo(
    () => points.map((p) => projectLonLat(p.lon, p.lat)),
    [points],
  )
  const trackLine = trackPoints
    .map((p) => projectLonLat(p.lon, p.lat).join(','))
    .join(' ')
  const head = trackPoints[trackPoints.length - 1] ?? null

  if (pointsQuery.isPending) {
    return (
      <div>
        <h1 className="page-title">Map</h1>
        <div className="loading">Loading GPS coordinates…</div>
      </div>
    )
  }

  if (pointsQuery.isError) {
    return (
      <div>
        <h1 className="page-title">Map</h1>
        <div className="error-note">
          Failed to load GPS coordinates: {(pointsQuery.error as Error).message}
        </div>
      </div>
    )
  }

  if (points.length === 0) {
    return (
      <div>
        <h1 className="page-title">Map</h1>
        <div className="empty-state">
          <h3>No GPS coordinates</h3>
          <p>
            No records in this case carry latitude/longitude. Photos with
            geotags or location records will appear here once ingested.
          </p>
        </div>
      </div>
    )
  }

  const copyCoords = (coords: string) => {
    void navigator.clipboard?.writeText(coords).then(
      () => toast.success('Coordinates copied'),
      () => toast.error('Copy failed'),
    )
  }

  return (
    <div>
      <div className="geo-header">
        <h1 className="page-title">Map</h1>
        <div className="geo-export">
          {liveMap ? (
            <button className="btn" onClick={() => setLiveMap(false)}>
              Offline map
            </button>
          ) : (
            <button className="btn" onClick={() => setShowLiveConfirm(true)}>
              Live map (OpenStreetMap)…
            </button>
          )}
          <button
            className="btn"
            onClick={() =>
              downloadFile(`/cases/${caseId}/export/kml`, `geo_${caseId}.kml`).catch(
                () => toast.error('KML export failed'),
              )
            }
          >
            Export KML
          </button>
          <button
            className="btn"
            onClick={() =>
              downloadFile(
                `/cases/${caseId}/export/geojson`,
                `geo_${caseId}.geojson`,
              ).catch(() => toast.error('GeoJSON export failed'))
            }
          >
            Export GeoJSON
          </button>
        </div>
      </div>
      <p className="geo-summary">
        {formatCount(points.length)} GPS points across {groups.length}{' '}
        record {groups.length === 1 ? 'type' : 'types'}
        {undecodable != null && undecodable > 0 && (
          <span className="geo-summary-shortfall" role="note">
            {' '}
            &mdash; {formatCount(undecodable)} further record
            {undecodable === 1 ? '' : 's'} carry a fix that could not be
            decoded, and {undecodable === 1 ? 'is' : 'are'} not on this map
          </span>
        )}
      </p>

      {track.length >= 2 && (
        <div className="geo-track-bar">
          <label className="geo-track-toggle">
            <input
              type="checkbox"
              checked={trackMode}
              onChange={(e) => {
                setTrackMode(e.target.checked)
                setScrub(null)
              }}
            />
            Movement track
          </label>
          {trackMode && (
            <>
              <input
                type="range"
                className="geo-scrubber"
                min={1}
                max={track.length}
                value={upto}
                aria-label="Reveal track up to time"
                onChange={(e) => setScrub(Number(e.target.value))}
              />
              <span className="geo-track-when mono">
                {head ? formatWhen(head.timestamp) : '—'}
              </span>
              <span className="geo-track-count">
                {upto} / {track.length}
              </span>
            </>
          )}
        </div>
      )}

      <div className="geo-layout">
        <div className="geo-map-wrap" ref={mapWrapRef}>
          {liveMap ? (
            <LeafletMap
              points={points}
              activeId={activeId}
              onSelect={handleSelect}
              onHover={handleHover}
              onLeave={handleLeave}
              trackPoints={trackMode ? trackPoints : []}
            />
          ) : (
            <WorldMap
              ariaLabel="World map of all GPS coordinates in the case"
              fitTo={fitPoints}
            >
              {trackMode && trackPoints.length >= 2 && (
                <polyline
                  className="geo-track-line"
                  points={trackLine}
                  fill="none"
                />
              )}
              {trackMode && head && (
                <circle
                  cx={projectLonLat(head.lon, head.lat)[0]}
                  cy={projectLonLat(head.lon, head.lat)[1]}
                  r={3.5}
                  className="geo-track-head"
                />
              )}
              {points.map((p) => {
                const [cx, cy] = projectLonLat(p.lon, p.lat)
                return (
                  <GeoDot
                    key={p.id}
                    id={p.id}
                    cx={cx}
                    cy={cy}
                    lat={p.lat}
                    lon={p.lon}
                    isActive={p.id === activeId}
                    onSelect={handleSelect}
                    onHover={handleHover}
                    onLeave={handleLeave}
                  />
                )
              })}
            </WorldMap>
          )}
          {hover && hoverPoint && (
            <GeoHoverCard
              caseId={caseId}
              point={hoverPoint}
              x={hover.x}
              y={hover.y}
              onEnter={cancelHide}
              onLeave={handleLeave}
            />
          )}
        </div>

        <div className="geo-panel">
          <h2 className="geo-panel-head">Coordinates</h2>
          {groups.map(([type, list]) => (
            <div key={type}>
              <div className="geo-type-head">
                {type} · {list.length}
              </div>
              <div className="geo-list">
                {list.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    className={
                      p.id === activeId ? 'geo-row selected' : 'geo-row'
                    }
                    onClick={() => handleSelect(p.id)}
                  >
                    {/* When, then where. A row headed by eight characters of
                        an artifact id told the examiner nothing they could use;
                        the time is what a location list is read for. */}
                    <span className="geo-row-when mono">
                      {p.timestamp ? formatUtc(p.timestamp) : 'undated'}
                    </span>
                    <span className="geo-row-coords mono">
                      {p.lat.toFixed(4)}, {p.lon.toFixed(4)}
                    </span>
                    {(p.sourceName ?? p.camera) && (
                      <span className="geo-row-source">
                        {p.sourceName ?? p.camera}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          ))}

          {active && (
            <div className="geo-detail" data-testid="geo-detail">
              <table className="geo-detail-table mono">
                <tbody>
                  <tr>
                    <td>Source</td>
                    <td>{active.sourceName ?? '—'}</td>
                  </tr>
                  <tr>
                    <td>Type</td>
                    <td>{active.type}</td>
                  </tr>
                  <tr>
                    <td>Camera</td>
                    <td>{active.camera ?? '—'}</td>
                  </tr>
                  <tr>
                    <td>When</td>
                    <td>{formatWhen(active.timestamp)}</td>
                  </tr>
                  <tr>
                    <td>Coords</td>
                    <td>
                      {active.lat}, {active.lon}
                      <button
                        type="button"
                        className="geo-copy"
                        onClick={() =>
                          copyCoords(`${active.lat}, ${active.lon}`)
                        }
                      >
                        copy
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div className="geo-detail-actions">
                <Link
                  className="btn btn-primary"
                  to={`/cases/${caseId}/artifacts/${active.id}`}
                >
                  Jump to artifact
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>

      {showLiveConfirm && (
        <div
          className="geo-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-label="Switch to the live OpenStreetMap map"
          onClick={() => setShowLiveConfirm(false)}
        >
          <div className="geo-modal" onClick={(e) => e.stopPropagation()}>
            <h3>Switch to OpenStreetMap?</h3>
            <p>
              The live map fetches tiles from OpenStreetMap's servers. This sends
              the map area — and so the location of the GPS points in this case —
              off this machine to a third party. The offline map keeps everything
              on this workstation. Only continue if that is acceptable for this
              case and network.
            </p>
            <div className="geo-modal-actions">
              <button className="btn" onClick={() => setShowLiveConfirm(false)}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={() => {
                  setLiveMap(true)
                  setShowLiveConfirm(false)
                }}
              >
                Use OpenStreetMap
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
