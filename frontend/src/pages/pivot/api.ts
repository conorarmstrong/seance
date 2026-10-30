import { apiFetch } from '../../api/http'

export interface PivotSample {
  artifact_id: string
  artifact_type: string
  name: string
  snippet: string | null
}

export interface PivotGroup {
  kind: string
  count: number
  samples: PivotSample[]
}

export interface PivotResponse {
  value: string
  /** Exact number of artifacts in the case that reference the value. */
  total_matches: number
  /** How many of those were grouped (fewer than total_matches when capped). */
  grouped: number
  /** True when total_matches exceeds what was grouped, so counts are a sample. */
  truncated: boolean
  groups: PivotGroup[]
}

/** Every artifact touching `value`, grouped by record kind. */
export const getPivot = (caseId: string, value: string) =>
  apiFetch<PivotResponse>(
    `/cases/${caseId}/pivot?value=${encodeURIComponent(value)}`,
  )

/**
 * A pivot answer pinned to the case (ROADMAP §5.13).
 *
 * Carries the snapshot as it was when pinned. Whether the same value still
 * answers the same way is a separate question, asked at report time, and a
 * difference between the two reaches the document rather than being smoothed
 * over.
 */
export interface PinnedPivot {
  id: string
  case_id: string
  value: string
  note: string | null
  examiner: string
  /** Unix seconds. */
  pinned_at: number
  total_matches: number
  grouped: number
  truncated: boolean
  groups: PivotGroup[]
}

export interface PinnedPivotList {
  pivots: PinnedPivot[]
  count: number
  note: string
}

/** Pin this value's pivot answer to the case, or refresh the pin that is there. */
export const pinPivot = (caseId: string, value: string, note?: string) =>
  apiFetch<PinnedPivot>(`/cases/${caseId}/pivots`, {
    method: 'POST',
    body: { value, note },
  })

/** The case's pinned values, most recently pinned first. */
export const listPinnedPivots = (caseId: string) =>
  apiFetch<PinnedPivotList>(`/cases/${caseId}/pivots`)

/** Remove a pin. */
export const unpinPivot = (caseId: string, pivotId: string) =>
  apiFetch<{ unpinned: string }>(`/cases/${caseId}/pivots/${pivotId}`, {
    method: 'DELETE',
  })
