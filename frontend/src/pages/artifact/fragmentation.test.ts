// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { analyzeRuns } from './fragmentation'

describe('analyzeRuns', () => {
  it('returns null for missing, empty, or non-array input', () => {
    expect(analyzeRuns(undefined)).toBeNull()
    expect(analyzeRuns(null)).toBeNull()
    expect(analyzeRuns([])).toBeNull()
    expect(analyzeRuns('nope')).toBeNull()
    expect(analyzeRuns([['x']])).toBeNull() // no usable pairs
  })

  it('parses [offset, length] runs and counts physical fragments', () => {
    const a = analyzeRuns([
      [100, 50],
      [400, 30],
    ])!
    expect(a.runs).toHaveLength(2)
    expect(a.fragments).toBe(2)
    expect(a.totalLength).toBe(80)
    expect(a.hasSparse).toBe(false)
    expect(a.contiguous).toBe(false) // 100+50 != 400
    expect(a.runs[0]).toEqual({ offset: 100, length: 50, sparse: false })
  })

  it('treats a null offset as a sparse run, excluded from the fragment count', () => {
    const a = analyzeRuns([
      [0, 100],
      [null, 200],
    ])!
    expect(a.hasSparse).toBe(true)
    expect(a.runs[1].sparse).toBe(true)
    expect(a.fragments).toBe(1)
    expect(a.totalLength).toBe(300)
  })

  it('marks a single extent, and adjacent extents, as contiguous', () => {
    expect(analyzeRuns([[100, 500]])!.contiguous).toBe(true)
    expect(analyzeRuns([[100, 500]])!.fragments).toBe(1)
    // 100+50 == 150, so the two runs are one gapless extent on disk.
    expect(
      analyzeRuns([
        [100, 50],
        [150, 30],
      ])!.contiguous,
    ).toBe(true)
  })
})
