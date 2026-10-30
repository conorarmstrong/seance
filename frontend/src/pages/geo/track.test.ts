// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import type { GpsPoint } from './api'
import { buildTrack, parseGeoTime } from './track'

describe('parseGeoTime', () => {
  it('parses EXIF-style timestamps as camera-local wall clock', () => {
    // EXIF datetimes carry no zone; they are parsed in the local timezone
    // (matching the geo sidebar's display), not forced to UTC.
    expect(parseGeoTime('2023:06:15 14:30:00')).toBe(
      new Date(2023, 5, 15, 14, 30, 0).getTime(),
    )
  })
  it('parses ISO and bare unix seconds/ms', () => {
    expect(parseGeoTime('2023-01-02T03:04:05Z')).toBe(
      Date.parse('2023-01-02T03:04:05Z'),
    )
    expect(parseGeoTime('1700000000')).toBe(1_700_000_000_000)
    expect(parseGeoTime('1700000000000')).toBe(1_700_000_000_000)
  })
  it('returns null for missing or unparseable input', () => {
    expect(parseGeoTime(null)).toBeNull()
    expect(parseGeoTime('not a date')).toBeNull()
  })
})

function pt(id: string, ts: string | null): GpsPoint {
  return { id, type: 'exif', lat: 1, lon: 2, camera: null, timestamp: ts, sourceName: null }
}

describe('buildTrack', () => {
  it('keeps only timed points, sorted chronologically', () => {
    const track = buildTrack([
      pt('c', '2023:03:03 00:00:00'),
      pt('a', '2023:01:01 00:00:00'),
      pt('untimed', null),
      pt('b', '2023:02:02 00:00:00'),
    ])
    expect(track.map((p) => p.id)).toEqual(['a', 'b', 'c'])
    expect(track[0].epoch).toBeLessThan(track[1].epoch)
  })
})
