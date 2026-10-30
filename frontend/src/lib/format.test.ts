// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  formatBytes,
  formatCount,
  formatDecimal,
  formatUtc,
  truncateHash,
} from './format'

describe('formatBytes', () => {
  it('formats zero', () => {
    expect(formatBytes(0)).toBe('0 B')
  })

  it('formats bytes below 1 KiB', () => {
    expect(formatBytes(512)).toBe('512 B')
  })

  it('uses binary units, one decimal', () => {
    expect(formatBytes(1024)).toBe('1.0 KiB')
    expect(formatBytes(1536)).toBe('1.5 KiB')
    expect(formatBytes(1048576)).toBe('1.0 MiB')
    expect(formatBytes(5 * 1024 * 1024 * 1024)).toBe('5.0 GiB')
  })

  it('handles null and undefined', () => {
    expect(formatBytes(null)).toBe('—')
    expect(formatBytes(undefined)).toBe('—')
  })
})

describe('formatUtc', () => {
  it('renders ISO timestamps as explicit UTC', () => {
    expect(formatUtc('2026-07-09T14:32:05Z')).toBe('2026-07-09 14:32:05 UTC')
  })

  it('normalizes offsets to UTC', () => {
    expect(formatUtc('2026-07-09T16:32:05+02:00')).toBe(
      '2026-07-09 14:32:05 UTC',
    )
  })

  it('returns em dash for missing or invalid input', () => {
    expect(formatUtc(null)).toBe('—')
    expect(formatUtc(undefined)).toBe('—')
    expect(formatUtc('not-a-date')).toBe('—')
  })
})

describe('truncateHash', () => {
  it('keeps short values intact', () => {
    expect(truncateHash('abcd1234')).toBe('abcd1234')
  })

  it('truncates long digests with an ellipsis', () => {
    const sha256 =
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    expect(truncateHash(sha256)).toBe('e3b0c442…7852b855')
  })

  it('handles missing values', () => {
    expect(truncateHash(null)).toBe('—')
  })
})

describe('formatCount', () => {
  it('groups thousands with commas', () => {
    expect(formatCount(1234567)).toBe('1,234,567')
    expect(formatCount(93338)).toBe('93,338')
  })

  it('leaves values below a thousand ungrouped', () => {
    expect(formatCount(0)).toBe('0')
    expect(formatCount(999)).toBe('999')
  })

  it('does not follow the ambient locale', () => {
    // Under LC_ALL=de_DE.UTF-8 a bare toLocaleString() renders this as
    // "1.234.567", which an en-GB reader would take for a decimal. The helper
    // must render the same digits on every examiner's machine.
    expect(formatCount(1234567)).not.toBe((1234567).toLocaleString('de-DE'))
    expect(formatCount(1234567)).toBe((1234567).toLocaleString('en-US'))
  })

  it('handles negative values', () => {
    expect(formatCount(-4200)).toBe('-4,200')
  })

  it('handles null and undefined', () => {
    expect(formatCount(null)).toBe('—')
    expect(formatCount(undefined)).toBe('—')
  })

  it('returns em dash for NaN', () => {
    expect(formatCount(Number.NaN)).toBe('—')
  })
})

describe('formatDecimal', () => {
  it('defaults to one fraction digit', () => {
    expect(formatDecimal(3.14159)).toBe('3.1')
  })

  it('honours an explicit digit count', () => {
    expect(formatDecimal(3.14159, 3)).toBe('3.142')
    expect(formatDecimal(2, 0)).toBe('2')
  })

  it('pads to the requested digits', () => {
    expect(formatDecimal(2, 2)).toBe('2.00')
  })

  it('groups thousands and uses a dot for the fraction', () => {
    expect(formatDecimal(1234567.25, 2)).toBe('1,234,567.25')
  })

  it('does not follow the ambient locale', () => {
    // de-DE swaps the roles of "." and ",", so the same figure would read as
    // "1.234.567,25" on a colleague's machine.
    expect(formatDecimal(1234567.25, 2)).not.toBe(
      (1234567.25).toLocaleString('de-DE', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }),
    )
  })

  it('handles null and undefined', () => {
    expect(formatDecimal(null)).toBe('—')
    expect(formatDecimal(undefined)).toBe('—')
  })
})
