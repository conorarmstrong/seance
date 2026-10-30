// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { histogramEventTotal } from './timelineTotal'

/**
 * LIVE-025: the artifact census counts stored TimelineEvent records — 75 in one
 * real case — while the timeline itself held 270,009, because most events are
 * derived from file MAC times rather than stored as artifacts. An examiner
 * reading the dashboard saw "75" and concluded the case had almost no temporal
 * evidence. The activity panel already loads the histogram; its buckets are the
 * honest count of what the timeline holds.
 */
describe('histogramEventTotal', () => {
  it('sums the buckets the histogram actually returned', () => {
    expect(
      histogramEventTotal({ buckets: [{ count: 270_000 }, { count: 9 }] }),
    ).toBe(270_009)
  })

  it('is zero for a case with no dated events', () => {
    expect(histogramEventTotal({ buckets: [] })).toBe(0)
  })

  it('is null when the histogram has not loaded, never a misleading zero', () => {
    expect(histogramEventTotal(undefined)).toBeNull()
  })
})
