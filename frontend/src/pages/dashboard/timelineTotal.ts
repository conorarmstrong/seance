/**
 * How many events the case's timeline holds, from the histogram already loaded
 * for the activity panel.
 *
 * The artifact census counts stored `TimelineEvent` records, which is a
 * different and much smaller number: most events are derived from file MAC
 * times at query time. Showing only the census made a case with 270,009 events
 * read as one with 75 (LIVE-025). Empty buckets are omitted by the server, so
 * summing the returned ones is the whole count.
 *
 * `null` while the histogram is absent — a zero there would be a claim about
 * the evidence that a pending request cannot support.
 */
export function histogramEventTotal(
  histogram: { buckets: { count: number }[] } | undefined,
): number | null {
  if (!histogram) return null
  return histogram.buckets.reduce((sum, bucket) => sum + bucket.count, 0)
}
