// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { decodeTimestamp } from './sqliteTime'

describe('decodeTimestamp', () => {
  it('raw returns null (show the raw value)', () => {
    expect(decodeTimestamp('1700000000', 'raw')).toBeNull()
  })

  it('decodes Unix seconds', () => {
    // 1700000000 = 2023-11-14T22:13:20Z
    expect(decodeTimestamp('1700000000', 'unix_s')).toBe('2023-11-14T22:13:20Z')
  })

  it('decodes Unix milliseconds', () => {
    expect(decodeTimestamp('1700000000000', 'unix_ms')).toBe(
      '2023-11-14T22:13:20Z',
    )
  })

  it('decodes WebKit / Chrome microseconds since 1601', () => {
    // 13350000000000000 µs -> 2024-01-... ; verify it lands in a sane year.
    const out = decodeTimestamp('13350000000000000', 'webkit')
    expect(out).not.toBeNull()
    expect(out!.startsWith('2024-')).toBe(true)
  })

  it('decodes Windows FILETIME (100 ns since 1601)', () => {
    // 133500000000000000 100ns ticks -> same instant as the webkit case /10.
    const out = decodeTimestamp('133500000000000000', 'filetime')
    expect(out).not.toBeNull()
    expect(out!.startsWith('2024-')).toBe(true)
  })

  it('decodes Cocoa / Mac absolute seconds since 2001', () => {
    // 0 -> 2001-01-01T00:00:00Z
    expect(decodeTimestamp('0', 'cocoa')).toBe('2001-01-01T00:00:00Z')
    // 700000000 -> 2023-03-...
    expect(decodeTimestamp('700000000', 'cocoa')!.startsWith('2023-')).toBe(true)
  })

  it('parses an ISO string', () => {
    expect(decodeTimestamp('2023-11-14T22:13:20Z', 'iso')).toBe(
      '2023-11-14T22:13:20Z',
    )
  })

  it('rejects a wrong interpretation (ms value read as seconds -> absurd year)', () => {
    // A millisecond value read as seconds lands ~year 55853 -> rejected.
    expect(decodeTimestamp('1700000000000', 'unix_s')).toBeNull()
  })

  it('rejects non-numeric values under numeric formats', () => {
    expect(decodeTimestamp('hello', 'unix_s')).toBeNull()
    expect(decodeTimestamp('', 'filetime')).toBeNull()
  })

  it('rejects an unparseable ISO string', () => {
    expect(decodeTimestamp('not a date', 'iso')).toBeNull()
  })
})

describe('decodeTimestamp precision (B5-005)', () => {
  // A tick count past Number.MAX_SAFE_INTEGER snaps to the nearest double when
  // it goes through Number(), and near a second boundary that snap lands the
  // decoded time in the following second. These raw values are one tick below
  // an exact second; the double path reports the second after the one the
  // database holds.
  it('decodes a FILETIME string exactly rather than through a double', () => {
    expect(decodeTimestamp('133699999999999999', 'filetime')).toBe(
      '2024-09-05T08:53:19Z',
    )
  })

  it('decodes a WebKit microsecond string exactly rather than through a double', () => {
    expect(decodeTimestamp('13399999999999999', 'webkit')).toBe(
      '2025-08-18T14:13:19Z',
    )
  })

  it('still decodes values that fit a double identically', () => {
    expect(decodeTimestamp('133700000000000000', 'filetime')).toBe(
      '2024-09-05T08:53:20Z',
    )
    expect(decodeTimestamp('1700000000', 'unix_s')).toBe('2023-11-14T22:13:20Z')
  })
})
