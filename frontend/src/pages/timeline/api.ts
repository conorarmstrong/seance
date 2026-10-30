import { apiFetch, type QueryParams } from '../../api/http'

// ---- Timeline histogram (page-local endpoint) ----

export interface HistogramBucket {
  /** Bucket start, unix seconds. */
  start: number
  count: number
}

/**
 * The window the server drew, when it was asked to focus on where the events
 * are (`focus=auto`), and what fell outside it.
 *
 * Null when nothing was trimmed — the chart already covers the activity, and
 * the client then has nothing to disclose because nothing was left out.
 *
 * `events_before` and `events_after` are counts of real events outside the
 * drawn window. They are the reason the focus is safe to apply: the chart
 * narrows, the population it describes does not (UI-007, UI-010).
 */
export interface ChartFocus {
  /** Window start, unix seconds, inclusive. */
  from: number
  /** Window end, unix seconds, exclusive. */
  to: number
  events_before: number
  events_after: number
}

export interface TimelineHistogram {
  /** Null when the case has no events matching the filters. */
  min_ts: number | null
  max_ts: number | null
  bucket_seconds: number | null
  /** Empty buckets are omitted by the server. */
  buckets: HistogramBucket[]
  /**
   * Present only when `focus=auto` was asked for AND the server narrowed the
   * window. `min_ts`/`max_ts` above still describe the whole extent either way.
   */
  focus?: ChartFocus | null
}

/**
 * Event-count histogram for the current filters. Takes the same filter
 * params as the timeline list (minus pagination) plus `buckets`.
 */
export const getTimelineHistogram = (caseId: string, query: QueryParams) =>
  apiFetch<TimelineHistogram>(`/cases/${caseId}/timeline/histogram`, { query })

// ---- Timeline swimlanes (per-source density) ----

export interface Swimlane {
  source: string
  total: number
  buckets: HistogramBucket[]
}

export interface TimelineSwimlanes {
  min_ts: number | null
  max_ts: number | null
  bucket_seconds: number | null
  lanes: Swimlane[]
  truncated_lanes: boolean
  /** As on the histogram, and derived from the summed lanes so the two charts
   * on this page draw one window rather than two. */
  focus?: ChartFocus | null
}

/** Per-source-module event density over time. Same filters as the histogram. */
export const getTimelineSwimlanes = (caseId: string, query: QueryParams) =>
  apiFetch<TimelineSwimlanes>(`/cases/${caseId}/timeline/swimlanes`, { query })

export interface ActivityCell {
  dow: number
  hour: number
  count: number
}

export interface TimelineActivity {
  cells: ActivityCell[]
  total: number
  max: number
}

export const getTimelineActivity = (caseId: string) =>
  apiFetch<TimelineActivity>(`/cases/${caseId}/timeline/activity`)
