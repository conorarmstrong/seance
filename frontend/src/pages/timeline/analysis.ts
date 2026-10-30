import type { TimelineEvent } from '../../api/types'

/**
 * Timestamp-source analysis helpers for MFT-derived timeline events.
 *
 * The MFT parser emits one timeline event per timestamp. $STANDARD_INFORMATION
 * (SI) events carry plain descriptions ("Created", "Modified", ...); the
 * $FILE_NAME (FN) attribute produces parallel events whose `timestamp_desc`
 * ends in "(FN)" and whose metadata `timestamp_type` starts with "FN_".
 *
 * Timestomp flags (`timestomp_suspected` / `timestomp_reasons`) are written on
 * the FileEntry artifact metadata, not on the timeline event's `full_details`
 * (which the MFT parser overrides with a plain-text summary). We therefore key
 * off whatever the event payload itself carries and never fetch per-artifact
 * (one request per row would be far too expensive). See `timestompHint`.
 */

/** Parse an event's `full_details` JSON, returning an object or null. */
function detailsObject(event: TimelineEvent): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(event.full_details)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null
  } catch {
    return null
  }
}

/**
 * True for $FILE_NAME-derived events. The reliable, always-present signal is
 * the "(FN)" suffix on `timestamp_desc`; the `timestamp_type` "FN_" prefix is a
 * secondary check for payloads that carry the whole metadata document.
 */
export function isFnEvent(event: TimelineEvent): boolean {
  if (event.timestamp_desc.endsWith('(FN)')) return true
  const type = detailsObject(event)?.timestamp_type
  return typeof type === 'string' && type.startsWith('FN_')
}

export interface TimestompHint {
  reasons: string[]
}

/**
 * Timestomp hint sourced ONLY from the event payload's `full_details`. Returns
 * a hint when the payload carries `timestomp_suspected: true`, otherwise null.
 *
 * Limitation: MFT timeline events do not currently include this flag in
 * `full_details` (it lives on the FileEntry artifact metadata), so the badge
 * appears only for events whose own details carry the flag. We deliberately do
 * not fetch the artifact per row.
 */
export function timestompHint(event: TimelineEvent): TimestompHint | null {
  const details = detailsObject(event)
  if (!details || details.timestomp_suspected !== true) return null
  const raw = details.timestomp_reasons
  const reasons = Array.isArray(raw)
    ? raw.filter((r): r is string => typeof r === 'string')
    : []
  return { reasons }
}

export interface SiFnRow {
  label: string
  /** RFC3339 timestamp string, or null when absent. */
  si: string | null
  fn: string | null
}

const SI_FN_FIELDS: { label: string; si: string; fn: string }[] = [
  { label: 'Created', si: 'created', fn: 'fn_created' },
  { label: 'Modified', si: 'modified', fn: 'fn_modified' },
  { label: 'MFT Modified', si: 'mft_modified', fn: 'fn_mft_modified' },
  { label: 'Accessed', si: 'accessed', fn: 'fn_accessed' },
]

/**
 * SI/FN timestamp pairs from `full_details`, but only when the payload carries
 * both an SI and an FN timestamp (i.e. a comparison is meaningful). Returns
 * null otherwise.
 */
export function siFnPairs(event: TimelineEvent): SiFnRow[] | null {
  const d = detailsObject(event)
  if (!d) return null
  const str = (k: string) => (typeof d[k] === 'string' ? (d[k] as string) : null)
  const rows = SI_FN_FIELDS.map((f) => ({
    label: f.label,
    si: str(f.si),
    fn: str(f.fn),
  }))
  const hasSi = rows.some((r) => r.si !== null)
  const hasFn = rows.some((r) => r.fn !== null)
  if (!hasSi || !hasFn) return null
  return rows.filter((r) => r.si !== null || r.fn !== null)
}

export type AnalysisFilter = 'all' | 'fn' | 'timestomp'
