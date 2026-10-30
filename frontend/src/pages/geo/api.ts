import { apiFetch } from '../../api/http'

export interface GpsPoint {
  /** Record artifact id (also the jump-to-artifact target). */
  id: string
  type: string
  lat: number
  lon: number
  camera: string | null
  timestamp: string | null
  sourceName: string | null
  /** Image artifact behind a photo point (the EXIF record's parent), for the
   * hover thumbnail. Null for non-photo points. */
  imageId?: string | null
}

interface GeoPointsResponse {
  /** The point array. Named `items` because every capped listing the server
   * returns uses the same key; reading `points` here silently yielded
   * `undefined`, which the map drew as a case with no GPS in it at all. */
  items: GpsPoint[]
  /** GPS-bearing records the database could not turn into a point. `null` when
   * the query cannot report it, which a client must not read as zero. */
  undecodable: number | null
}

/** The case's GPS points, and what is missing from them. */
export interface GpsPointSet {
  points: GpsPoint[]
  /** Records that carry a fix which could not be decoded into one. */
  undecodable: number | null
}

/**
 * Every GPS point in the case, from a single server endpoint. The server does
 * the per-record extraction (EXIF requires the explicit has_gps flag; other
 * types qualify on finite coordinates), so the map no longer fans out one
 * request per record type -- and no longer silently drops points past the old
 * 500-records-per-type client cap.
 *
 * `undecodable` is carried rather than discarded: a map missing fixes must not
 * be drawn as a map of every fix.
 */
export async function collectGpsPoints(caseId: string): Promise<GpsPointSet> {
  const res = await apiFetch<GeoPointsResponse>(`/cases/${caseId}/geo/points`)
  return { points: res.items ?? [], undecodable: res.undecodable ?? null }
}
