import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { listChildArtifacts } from '../api/resources'
import type { ArtifactListItem } from '../api/types'

export interface SourceFilter {
  /** The chosen source id, but ONLY while it still exists in the case; falls
   *  back to `undefined` (whole case) if the scoped source vanished. Consumers
   *  should query against this, never the raw `sourceId`. */
  activeSource: string | undefined
  /** The case's source acquisitions (the filter options). */
  sourceItems: ArtifactListItem[]
  /** True only when there is more than one source — a single-source case has
   *  nothing to disambiguate, so no filter should be offered. */
  multiSource: boolean
  /** The raw selection, including a value that may no longer exist. */
  sourceId: string | undefined
  setSourceId: (id: string | undefined) => void
}

/**
 * Shared state for a "scope this view to one acquisition" filter, used by the
 * Logical navigator and System Info.
 *
 * The subtle, previously-duplicated part is the stale-source guard: a source can
 * disappear (case reset, deletion) while its id is still selected, and querying
 * against a vanished source is wrong. `activeSource` collapses to the whole case
 * in that case. Keeping this in one hook means both navigators cannot drift on
 * that rule (CR-008).
 */
export function useSourceFilter(caseId: string | undefined): SourceFilter {
  const [sourceId, setSourceId] = useState<string | undefined>(undefined)
  const sources = useQuery({
    queryKey: ['tree', caseId, 'root'],
    queryFn: () => listChildArtifacts(caseId!, 'root', { sources_only: true }),
    enabled: !!caseId,
  })
  const sourceItems = sources.data?.items ?? []
  const multiSource = sourceItems.length > 1
  const activeSource =
    sourceId && sourceItems.some((s) => s.id === sourceId) ? sourceId : undefined
  return { activeSource, sourceItems, multiSource, sourceId, setSourceId }
}
