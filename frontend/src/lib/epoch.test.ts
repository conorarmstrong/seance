// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import corpus from '../test/fixtures/epoch-corpus.json'
import type { Placement } from './epoch'
import {
  censusClass,
  placeFromMetadata,
  placeValue,
  toEpochMs,
  valueToEpochMs,
} from './epoch'

/** One row of the corpus shared with `seance_core::timestamp`. */
type CorpusRow = {
  name: string
  keys: string[]
  input: Record<string, unknown>
  expect: Placement
}

describe('valueToEpochMs', () => {
  it('reads unix seconds and milliseconds', () => {
    expect(valueToEpochMs(1_700_000_000)).toBe(1_700_000_000_000)
    expect(valueToEpochMs(1_700_000_000_000)).toBe(1_700_000_000_000)
  })

  it('converts a Windows FILETIME (100 ns ticks since 1601) in range', () => {
    // 2021-01-01T00:00:00Z expressed as a FILETIME.
    const filetime = 132_539_328_000_000_000
    const ms = valueToEpochMs(filetime)
    expect(ms).not.toBeNull()
    expect(new Date(ms as number).getUTCFullYear()).toBe(2021)
    // Would previously overflow JS Date and throw here — must not now.
    expect(() => new Date(ms as number).toISOString()).not.toThrow()
  })

  it('parses ISO strings and bare numeric strings', () => {
    expect(valueToEpochMs('2023-01-02T03:04:05Z')).toBe(
      Date.parse('2023-01-02T03:04:05Z'),
    )
    expect(valueToEpochMs('1700000000')).toBe(1_700_000_000_000)
  })

  it('rejects tiny, non-finite, and unparseable values', () => {
    expect(valueToEpochMs(1000)).toBeNull()
    expect(valueToEpochMs('nope')).toBeNull()
    expect(valueToEpochMs(null)).toBeNull()
    expect(valueToEpochMs(Number.NaN)).toBeNull()
  })
})

describe('toEpochMs', () => {
  it('returns the first key that yields a usable value', () => {
    expect(toEpochMs({ a: 'x', b: 1_700_000_000 }, ['a', 'b'])).toBe(
      1_700_000_000_000,
    )
    expect(toEpochMs({ a: 'x' }, ['a', 'b'])).toBeNull()
  })
})

describe('valueToEpochMs precision (B5-005)', () => {
  it('converts a FILETIME string exactly instead of through a double', () => {
    // One 100 ns tick below an exact second. Through Number() the tick count
    // rounds up to the second boundary and the coerced time reads a whole
    // second later than the evidence.
    const ms = valueToEpochMs('133699999999999999')
    expect(ms).not.toBeNull()
    expect(new Date(ms!).toISOString()).toBe('2024-09-05T08:53:19.999Z')
  })

  it('leaves values inside the safe integer range unchanged', () => {
    expect(valueToEpochMs('1700000000')).toBe(1_700_000_000_000)
    expect(valueToEpochMs('1700000000000')).toBe(1_700_000_000_000)
  })
})

describe('the shared corpus', () => {
  // The corpus is the contract between this reader and the server-side
  // aggregation that must agree with it. Both languages read these same bytes,
  // so a divergence is a failing test rather than two different instants for
  // one record in front of one examiner.
  const rows = corpus.rows as CorpusRow[]

  it('is large enough to be the coverage argument it claims to be', () => {
    expect(rows.length).toBeGreaterThanOrEqual(40)
  })

  it.each(rows.map((row) => [row.name, row] as const))(
    'places %s',
    (_name, row) => {
      expect(placeFromMetadata(row.input, row.keys)).toEqual(row.expect)
    },
  )

  it('describes what the SHIPPING reader does, not a rule beside it', () => {
    // `valueToEpochMs` decides what four unrelated views render. If an
    // expectation could be edited to describe something those views do not do,
    // the corpus would pin a copy of the rule rather than the rule.
    for (const row of rows) {
      const ms = toEpochMs(row.input, row.keys)
      if ('placed_secs' in row.expect) {
        expect(ms, row.name).not.toBeNull()
        expect(Math.floor((ms as number) / 1000), row.name).toBe(
          row.expect.placed_secs,
        )
      } else {
        expect(ms, row.name).toBeNull()
      }
    }
  })

  it('exercises all four answers', () => {
    const seen = new Set(rows.map((row) => censusClass(placeFromMetadata(row.input, row.keys))))
    expect([...seen].sort()).toEqual([
      'placed_as_written',
      'placed_by_rescue',
      'unplaceable_absent',
      'unplaceable_value',
    ])
  })
})

describe('placeValue', () => {
  it('separates a key that is absent from one that cannot be read', () => {
    // Two different findings: the record never claimed a time, versus the
    // record holds something no reading of which is admissible.
    expect(placeValue(undefined)).toEqual({ unplaceable: 'absent' })
    expect(placeValue(null)).toEqual({ unplaceable: 'absent' })
    expect(placeValue(0)).toEqual({ unplaceable: 'value' })
    expect(placeValue('nope')).toEqual({ unplaceable: 'value' })
  })

  it('marks an instant reached only by assuming a unit', () => {
    expect(placeValue(1_709_640_000)).toEqual({
      placed_secs: 1_709_640_000,
      confidence: 'as_written',
    })
    expect(placeValue(1_709_640_000_000)).toEqual({
      placed_secs: 1_709_640_000,
      confidence: 'by_rescue',
    })
    expect(placeValue(133_500_000_000_000_000)).toEqual({
      placed_secs: 1_705_526_400,
      confidence: 'by_rescue',
    })
  })

  it('reports the second that contains a sub-second instant, before the epoch too', () => {
    expect(placeValue('2024-03-05T12:00:00.999Z')).toEqual({
      placed_secs: 1_709_640_000,
      confidence: 'as_written',
    })
    expect(placeValue('1969-12-31T23:59:59.500Z')).toEqual({
      placed_secs: -1,
      confidence: 'as_written',
    })
  })
})

describe('placeFromMetadata', () => {
  it('takes the first key that yields an instant, not the first non-null key', () => {
    // `{date: 0, timestamp: ...}` is a live shape. Read as "first non-null" it
    // lands in 1970; read as the browser reads it, in 2020.
    expect(placeFromMetadata({ date: 0, timestamp: 1_600_000_000 }, ['date', 'timestamp'])).toEqual(
      { placed_secs: 1_600_000_000, confidence: 'as_written' },
    )
  })

  it('says "value" when a key was there and unreadable, "absent" when none was', () => {
    expect(placeFromMetadata({ date: 'nope', timestamp: null }, ['date', 'timestamp'])).toEqual({
      unplaceable: 'value',
    })
    expect(placeFromMetadata({ date: null }, ['date', 'timestamp'])).toEqual({
      unplaceable: 'absent',
    })
  })
})

describe('valueToEpochMs is expressed through the shared rule', () => {
  it('still returns exactly what its five importers already render', () => {
    // The signature and every answer must be unchanged: four unrelated views
    // read this function, and a change here changes what they show.
    expect(valueToEpochMs(1_700_000_000)).toBe(1_700_000_000_000)
    expect(valueToEpochMs('2023-01-02T03:04:05Z')).toBe(
      Date.parse('2023-01-02T03:04:05Z'),
    )
    expect(valueToEpochMs('133699999999999999')).toBe(1_725_526_399_999)
    expect(valueToEpochMs(1000)).toBeNull()
    expect(valueToEpochMs(undefined)).toBeNull()
  })

  it('keeps the sub-second precision that the placement floors away', () => {
    expect(valueToEpochMs('2024-03-05T12:00:00.123Z')).toBe(1_709_640_000_123)
    expect(placeValue('2024-03-05T12:00:00.123Z')).toEqual({
      placed_secs: 1_709_640_000,
      confidence: 'as_written',
    })
  })

  it('has no ceiling, because four views render records beyond one', () => {
    // A ceiling belongs to a histogram's own acceptance window, not to the
    // shared reader: adding one here would reclassify year-2999 records as
    // unusable in views that render them today.
    expect(valueToEpochMs('2999-01-01T00:00:00Z')).toBe(32_472_144_000_000)
  })
})
