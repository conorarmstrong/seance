// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  buildConditionFromRows,
  buildSimpleFilter,
  coerceValue,
  describeCondition,
  type ConditionRow,
} from './filterModel'

describe('coerceValue', () => {
  it('coerces scalars by type', () => {
    expect(coerceValue('eq', 'true')).toBe(true)
    expect(coerceValue('eq', 'false')).toBe(false)
    expect(coerceValue('gt', '42')).toBe(42)
    expect(coerceValue('eq', 'report.pdf')).toBe('report.pdf')
  })
  it('splits an "in" list into coerced scalars', () => {
    expect(coerceValue('in', 'exe, dll, sys')).toEqual(['exe', 'dll', 'sys'])
    expect(coerceValue('in', '1, 2, 3')).toEqual([1, 2, 3])
  })
  it('ignores the value for exists', () => {
    expect(coerceValue('exists', '')).toBe(true)
  })
  it('keeps identifier-like strings as strings (BUG-199)', () => {
    // Forensic identifiers are stored as strings. Coercing them to numbers
    // loses the exact token, so the filter silently stops matching.
    expect(coerceValue('eq', '0123')).toBe('0123') // leading zero
    expect(coerceValue('eq', '00')).toBe('00')
    expect(coerceValue('eq', '447700900123')).toBe(447700900123) // fits exactly
    expect(coerceValue('eq', '00447700900123')).toBe('00447700900123')
    expect(coerceValue('eq', '353871234567890123')).toBe('353871234567890123') // > 2^53
    expect(coerceValue('eq', '1e3')).toBe('1e3') // scientific notation
    expect(coerceValue('eq', '+5')).toBe('+5')
    expect(coerceValue('eq', 'Infinity')).toBe('Infinity')
    expect(coerceValue('in', '0123, 456')).toEqual(['0123', 456])
  })
  it('still coerces genuine numeric input', () => {
    expect(coerceValue('eq', '42')).toBe(42)
    expect(coerceValue('eq', '-4.5')).toBe(-4.5)
    expect(coerceValue('eq', ' 42 ')).toBe(42)
  })
  it('keeps ordering operators numeric', () => {
    // Ordering has no meaning against a string on the backend, so a
    // numeric-looking bound is still read as a number here.
    expect(coerceValue('gte', '0')).toBe(0)
    expect(coerceValue('lt', '-4.5')).toBe(-4.5)
    expect(coerceValue('gt', '1e3')).toBe(1000)
    expect(coerceValue('lte', '1.50')).toBe(1.5)
  })
  it('passes substring operators through as text', () => {
    // contains/starts_with/ends_with compare string to string; a number would
    // never match.
    expect(coerceValue('contains', '0123')).toBe('0123')
    expect(coerceValue('starts_with', '447')).toBe('447')
    expect(coerceValue('ends_with', '2024')).toBe('2024')
  })
})

describe('buildSimpleFilter', () => {
  it('builds a simple condition', () => {
    expect(buildSimpleFilter('extension', 'in', 'exe,dll')).toEqual({
      type: 'simple',
      field: 'extension',
      operator: 'in',
      value: ['exe', 'dll'],
    })
  })
})

describe('describeCondition', () => {
  it('summarises simple, compound and not conditions', () => {
    expect(
      describeCondition({ type: 'simple', field: 'deleted', operator: 'eq', value: true }),
    ).toBe('deleted equals true')
    expect(
      describeCondition({ type: 'simple', field: 'extension', operator: 'in', value: ['exe', 'dll'] }),
    ).toBe('extension in (comma list) [exe, dll]')
    expect(
      describeCondition({
        type: 'compound',
        logic: 'and',
        conditions: [
          { type: 'simple', field: 'deleted', operator: 'eq', value: true },
          { type: 'not', condition: { type: 'simple', field: 'x', operator: 'exists', value: true } },
        ],
      }),
    ).toBe('(deleted equals true AND NOT x exists)')
  })
})

describe('buildConditionFromRows', () => {
  const row = (over: Partial<ConditionRow> = {}): ConditionRow => ({
    id: 'r1',
    field: 'extension',
    operator: 'eq',
    value: 'exe',
    negated: false,
    ...over,
  })

  it('emits a bare condition for a single row, not a one-child compound', () => {
    // The evaluator treats a one-child compound as that child, so wrapping is
    // harmless — but the saved JSON is read by humans (it is exported and
    // shared between cases), and an unnecessary wrapper reads as structure
    // that is not there.
    expect(buildConditionFromRows([row()], 'and')).toEqual({
      condition: { type: 'simple', field: 'extension', operator: 'eq', value: 'exe' },
    })
  })

  it('joins several rows with one connective and no nesting', () => {
    expect(
      buildConditionFromRows(
        [row(), row({ id: 'r2', field: 'deleted', operator: 'eq', value: 'true' })],
        'and',
      ),
    ).toEqual({
      condition: {
        type: 'compound',
        logic: 'and',
        conditions: [
          { type: 'simple', field: 'extension', operator: 'eq', value: 'exe' },
          { type: 'simple', field: 'deleted', operator: 'eq', value: true },
        ],
      },
    })
  })

  it('wraps only the negated row, never the group', () => {
    const built = buildConditionFromRows(
      [row({ negated: true }), row({ id: 'r2', field: 'size', operator: 'gt', value: '1000' })],
      'or',
    )
    expect(built).toEqual({
      condition: {
        type: 'compound',
        logic: 'or',
        conditions: [
          {
            type: 'not',
            condition: { type: 'simple', field: 'extension', operator: 'eq', value: 'exe' },
          },
          { type: 'simple', field: 'size', operator: 'gt', value: 1000 },
        ],
      },
    })
  })

  it('refuses to emit an empty condition list', () => {
    // An AND with no conditions is vacuously TRUE on the backend: it matches
    // every artifact in the case while carrying a name that says otherwise.
    // That is the worst thing this builder could produce, so it cannot.
    const built = buildConditionFromRows([], 'and')
    expect('error' in built).toBe(true)
    expect((built as { error: string }).error).toMatch(/at least one condition/i)
  })

  it('refuses a row with no field rather than dropping it', () => {
    // Dropping it would save a filter narrower or wider than the one on
    // screen, with nothing saying so.
    const built = buildConditionFromRows([row({ field: '  ' })], 'and')
    expect('error' in built).toBe(true)
    expect((built as { error: string }).error).toMatch(/field/i)
  })

  it('refuses an empty value on an operator that compares one', () => {
    // `contains ""` is true of every string, so an unfilled row silently widens
    // the population instead of narrowing it.
    const built = buildConditionFromRows([row({ operator: 'contains', value: '' })], 'and')
    expect('error' in built).toBe(true)
    expect((built as { error: string }).error).toMatch(/value/i)
  })

  it('needs no value for exists', () => {
    expect(
      buildConditionFromRows([row({ operator: 'exists', value: '' })], 'and'),
    ).toEqual({
      condition: { type: 'simple', field: 'extension', operator: 'exists', value: true },
    })
  })

  it('refuses an "in" list that reduces to nothing', () => {
    // `in []` matches nothing, which reads as "no artifacts have these
    // extensions" rather than as "you typed only commas".
    const built = buildConditionFromRows([row({ operator: 'in', value: ' , , ' })], 'and')
    expect('error' in built).toBe(true)
  })
})
