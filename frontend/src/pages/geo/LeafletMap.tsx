import L from 'leaflet'
import { useEffect, useRef } from 'react'
import type { GpsPoint } from './api'
import 'leaflet/dist/leaflet.css'

/**
 * Live map over OpenStreetMap tiles. Rendered ONLY after the user explicitly
 * opts in (GeoMapPage gates it behind a confirmation), because fetching tiles
 * sends the case's coordinates to OSM's servers. Uses `circleMarker` (vector,
 * no image assets) so there are no bundler icon-path issues and nothing else is
 * fetched beyond the tiles themselves.
 */
export function LeafletMap({
  points,
  activeId,
  onSelect,
  onHover,
  onLeave,
  trackPoints,
}: {
  points: GpsPoint[]
  activeId: string | null
  onSelect: (id: string) => void
  /** Same hover card as the offline map, so a point previews its photo here
   * too rather than only showing a text tooltip. */
  onHover: (id: string, clientX: number, clientY: number) => void
  onLeave: () => void
  /** Movement track revealed so far (chronological); empty when off. Drawn as a
   * polyline with a head marker, the same feature the offline map has. */
  trackPoints: GpsPoint[]
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const markersRef = useRef<Map<string, L.CircleMarker>>(new Map())
  const trackLayerRef = useRef<L.Polyline | null>(null)
  const headLayerRef = useRef<L.CircleMarker | null>(null)

  // Build the map once per point set.
  useEffect(() => {
    const el = containerRef.current
    if (!el) return

    const map = L.map(el, { worldCopyJump: true })
    mapRef.current = map
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '© OpenStreetMap contributors',
    }).addTo(map)

    const markers = new Map<string, L.CircleMarker>()
    const latlngs: L.LatLngExpression[] = []
    for (const p of points) {
      const m = L.circleMarker([p.lat, p.lon], {
        radius: 5,
        weight: 1,
        color: '#ffffff',
        fillColor: '#2f6df6',
        fillOpacity: 0.9,
      })
      m.on('click', () => onSelect(p.id))
      m.on('mouseover', (e) => {
        const oe = e.originalEvent as MouseEvent | undefined
        if (oe) onHover(p.id, oe.clientX, oe.clientY)
      })
      m.on('mouseout', () => onLeave())
      m.addTo(map)
      markers.set(p.id, m)
      latlngs.push([p.lat, p.lon])
    }
    markersRef.current = markers

    if (latlngs.length > 0) {
      map.fitBounds(L.latLngBounds(latlngs), { padding: [30, 30], maxZoom: 16 })
    } else {
      map.setView([20, 0], 2)
    }

    return () => {
      map.remove()
      mapRef.current = null
      markersRef.current = new Map()
    }
  }, [points, onSelect, onHover, onLeave])

  // Draw / update the movement track as the scrubber reveals more of it, without
  // rebuilding the map. Cleared when the track is off (empty points).
  useEffect(() => {
    const map = mapRef.current
    if (!map) return
    trackLayerRef.current?.remove()
    headLayerRef.current?.remove()
    trackLayerRef.current = null
    headLayerRef.current = null
    if (trackPoints.length < 2) return

    const latlngs = trackPoints.map((p) => [p.lat, p.lon] as [number, number])
    trackLayerRef.current = L.polyline(latlngs, {
      color: '#f6a821',
      weight: 3,
      opacity: 0.85,
    }).addTo(map)

    const head = trackPoints[trackPoints.length - 1]
    headLayerRef.current = L.circleMarker([head.lat, head.lon], {
      radius: 6,
      weight: 2,
      color: '#111111',
      fillColor: '#f6a821',
      fillOpacity: 1,
    }).addTo(map)
  }, [trackPoints])

  // Highlight the active marker without rebuilding the map.
  useEffect(() => {
    for (const [id, m] of markersRef.current) {
      const active = id === activeId
      m.setStyle({
        fillColor: active ? '#f6a821' : '#2f6df6',
        color: active ? '#111111' : '#ffffff',
        radius: active ? 7 : 5,
      } as L.PathOptions)
      if (active) {
        m.bringToFront()
        mapRef.current?.panTo(m.getLatLng())
      }
    }
  }, [activeId])

  return <div ref={containerRef} className="geo-leaflet" />
}
