import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { MiniTimeline, densify, focusWindow } from './MiniTimeline'
import type { HistogramBucket } from '../../pages/timeline/api'

describe('focusWindow', () => {
  it('trims a handful of outliers off each end but never the mass', () => {
    // 1 outlier, a wide gap of zeros, then the real cluster, then 1 outlier.
    const dense = [1, 0, 0, 0, 500, 480, 510, 0, 0, 1]
    const { lo, hi, before, after } = focusWindow(dense)
    expect(before).toBe(1)
    expect(after).toBe(1)
    // The window holds the whole cluster and none of the outliers.
    expect(dense.slice(lo, hi + 1)).toEqual([500, 480, 510])
  })

  it('keeps a real cluster that exceeds the trim budget', () => {
    // The "outlier" is 3% of events — above the 1% budget — so it stays.
    const dense = [30, 0, 0, 500, 470]
    const { lo, before } = focusWindow(dense)
    expect(before).toBe(0)
    expect(lo).toBe(0)
  })

  it('keeps a small EARLY cluster that is not separated by a long gap', () => {
    // 0.4% of events, so within the count budget — but adjacent to the mass,
    // so it is real early activity, not an artefactual timestamp. The earliest
    // activity in a case is often the most important thing on it and must not
    // be trimmed merely for being sparse.
    const dense = [4, 0, 500, 496]
    const { lo, before } = focusWindow(dense)
    expect(before).toBe(0)
    expect(lo).toBe(0)
  })

  it('trims a sparse end only when a long empty gap separates it from the mass', () => {
    // Same 4 events, now separated by a gap of >=10% of the span.
    const dense = [4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 500, 496]
    const { lo, before } = focusWindow(dense)
    expect(before).toBe(4)
    expect(lo).toBe(12)
  })

  it('leaves an all-zero array untouched', () => {
    expect(focusWindow([0, 0, 0])).toEqual({ lo: 0, hi: 2, before: 0, after: 0 })
  })
})

describe('MiniTimeline', () => {
  // Server-style bucketing: ~20 buckets spanning the whole range. A FAT-epoch
  // outlier in 1980, then a dense 2021–2026 cluster near the end.
  const minTs = 315532800 // 1980-01-01
  const bs = 73051200 // ~845 days, so 1980→2026 is ~20 slots (under the cap)
  const buckets: HistogramBucket[] = [
    { start: minTs, count: 1 }, // 1980-01-01 outlier
    { start: minTs + 18 * bs, count: 400 }, // 2021-09
    { start: minTs + 19 * bs, count: 420 }, // 2024-01
  ]
  const maxTs = minTs + 20 * bs // 2026-04

  it('discloses the outlier rather than letting it squash the chart', () => {
    render(
      <MiniTimeline buckets={buckets} minTs={minTs} maxTs={maxTs} bucketSeconds={bs} />,
    )
    // The 1980 event is stated as outside the focused range, not hidden.
    expect(screen.getByText(/1 event outside this range/i)).toBeInTheDocument()
    expect(screen.getByText(/before 20/)).toBeInTheDocument()
    // The accessible label still carries the true full total and full span.
    expect(
      screen.getByRole('img', { name: /821 events from 1980-01-01/ }),
    ).toBeInTheDocument()
  })
})

describe('densify', () => {
  it('places counts at their true slot and fills gaps with zeros', () => {
    const out = densify([{ start: 0, count: 3 }, { start: 200, count: 5 }], 0, 200, 100)
    expect(out).toEqual([3, 0, 5])
  })
})
