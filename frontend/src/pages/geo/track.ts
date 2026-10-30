import type { GpsPoint } from './api'

/**
 * Parse a geo point's timestamp to epoch milliseconds. Handles EXIF
 * `YYYY:MM:DD HH:MM:SS`, ISO strings, and bare unix seconds/ms. Returns null
 * when nothing usable is present.
 *
 * EXIF datetimes carry no timezone: they are the camera's local wall clock.
 * They are parsed in the viewer's local timezone (not forced to UTC), so the
 * track's absolute scrub times line up with the camera-local time the geo
 * sidebar displays instead of being shifted by a UTC assumption.
 */
export function parseGeoTime(ts: string | null): number | null {
  if (!ts) return null
  const exif = ts.match(/^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/)
  if (exif) {
    const t = new Date(
      Number(exif[1]),
      Number(exif[2]) - 1,
      Number(exif[3]),
      Number(exif[4]),
      Number(exif[5]),
      Number(exif[6]),
    ).getTime()
    return Number.isNaN(t) ? null : t
  }
  const n = Number(ts)
  if (ts.trim() !== '' && !Number.isNaN(n) && !/[-:T]/.test(ts)) {
    return n > 1e12 ? n : n * 1000
  }
  const p = Date.parse(ts)
  return Number.isNaN(p) ? null : p
}

export interface TrackPoint extends GpsPoint {
  epoch: number
}

/**
 * The subset of points that carry a usable timestamp, in chronological order.
 * These form the movement track; points without a time are shown on the map
 * but excluded from the path (their position in time is unknown).
 */
export function buildTrack(points: GpsPoint[]): TrackPoint[] {
  const timed: TrackPoint[] = []
  for (const p of points) {
    const epoch = parseGeoTime(p.timestamp)
    if (epoch != null) timed.push({ ...p, epoch })
  }
  timed.sort((a, b) => a.epoch - b.epoch)
  return timed
}
