/**
 * Where the bulk of a chart's events sit, and what falls outside.
 *
 * One implementation, shared by every time chart in the product, because three
 * charts deciding independently which events to draw is three chances for two
 * of them to disagree about the same case (UI-007). Used by:
 *
 * - `MiniTimeline` — the dashboard glance;
 * - `ActivityHistogram` — the timeline's own Activity chart;
 * - `EventHistogram` in `pages/analysis/RichCharts` — every rich viewer chart
 *   and the communications **Volume over time** chart, which draw through it.
 *
 * The problem it exists for: a single FAT-epoch 1980 timestamp, or one corrupt
 * far-future stamp, stretches a chart's axis across decades and collapses the
 * real activity into one or two bars. Nothing on such a chart is *false* — the
 * bars are where the events are — but it cannot be read, which on a
 * court-facing surface is its own kind of failure.
 *
 * What it must never do is hide an outlier. The window is narrowed only under
 * two conditions together, and every event outside it is counted and returned
 * so the caller can say so on screen. An examiner reading a focused chart is
 * told what was left out and how much of it there was.
 */

/**
 * Where the bulk of the events sit, so a handful of outlier timestamps — a FAT
 * epoch date in 1980, a corrupt far-future stamp — cannot stretch the axis
 * across decades and collapse the real activity into one bar. Trims at most a
 * small fraction of events off each end (never into the mass), and reports what
 * it trimmed so the outliers are disclosed, not hidden. Returns indices into
 * the dense array plus the counts that fell outside the window.
 */
export function focusWindow(
  dense: number[],
  trimFraction = 0.01,
  minGapFraction = 0.1,
): { lo: number; hi: number; before: number; after: number } {
  const total = dense.reduce((s, c) => s + c, 0)
  let lo = 0
  let hi = dense.length - 1
  if (total === 0) return { lo, hi, before: 0, after: 0 }

  // Two conditions must BOTH hold before an end is trimmed, because the
  // earliest activity in a case is often the most interesting thing on it and
  // must not be dropped merely for being sparse:
  //   1. it is a small share of all events (`trimFraction` per end), and
  //   2. it is SEPARATED from the mass by a long empty gap — which is what an
  //      artefactual timestamp (a FAT epoch in 1980, a corrupt far-future
  //      stamp) looks like, and what a genuine early cluster does not.
  const budget = total * trimFraction
  // At least two empty buckets: a single empty slot is ordinary quiet, not the
  // decades-wide void that separates an artefactual timestamp from real
  // activity, and on a short array the fractional floor would otherwise reach 1.
  const minGap = Math.max(2, Math.floor(dense.length * minGapFraction))

  const gapAfter = (i: number): number => {
    let g = 0
    for (let j = i + 1; j < dense.length && dense[j] === 0; j++) g++
    return g
  }
  const gapBefore = (i: number): number => {
    let g = 0
    for (let j = i - 1; j >= 0 && dense[j] === 0; j--) g++
    return g
  }

  let before = 0
  while (lo < hi && before + dense[lo] <= budget) {
    // An empty leading bucket is always safe to trim: it holds nothing.
    if (dense[lo] === 0) {
      lo++
      continue
    }
    if (gapAfter(lo) < minGap) break
    before += dense[lo]
    lo++
  }
  let after = 0
  while (hi > lo && after + dense[hi] <= budget) {
    if (dense[hi] === 0) {
      hi--
      continue
    }
    if (gapBefore(hi) < minGap) break
    after += dense[hi]
    hi--
  }
  return { lo, hi, before, after }
}
