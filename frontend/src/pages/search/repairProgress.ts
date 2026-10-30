import { useEffect, useState } from 'react'
import { parseSseJson } from '../../hooks/processing'
import { subscribeSseEvent } from '../../hooks/sse'

/**
 * The orchestrator module id a search-index display-name repair reports under.
 * It is not a real analysis module; it is the pass `POST
 * /cases/{id}/search/reindex` spawns, borrowing the module-progress channel
 * because that is how this server reports long work.
 */
export const REPAIR_MODULE_ID = 'search.index_repair'

/**
 * The module id the backfill reports under (`LIVE-028`). A different pass over
 * the same case, on the same channel, and one an examiner reading results needs
 * to know about for the same reason: it changes what the index contains under
 * them while they read.
 */
export const BACKFILL_MODULE_ID = 'search.index_backfill'

/** How far the running pass has walked this case. */
export interface RepairProgress {
  /** Units the pass has examined so far. */
  done: number
  /** Units it expects to examine, or null if the server did not say. */
  total: number | null
  /**
   * Which pass this is. The two count different things — the repair walks
   * documents already in the index, the backfill walks the case's artifacts —
   * so the banner must not describe one in the other's words.
   */
  kind: 'repair' | 'backfill'
}

/**
 * The wire shape of the one event this reader cares about. The orchestrator
 * serializes `OrchestratorEvent` internally tagged, so a `ModuleProgress`
 * arrives as a flat object with an `event_type` discriminant.
 */
interface ModuleProgressEvent {
  event_type?: unknown
  case_id?: unknown
  module_id?: unknown
  units_done?: unknown
  units_total?: unknown
}

/**
 * Follow a search-index pass running over `caseId` — a display-name repair or a
 * backfill — or null when neither has been heard from.
 *
 * This reads the stream directly rather than riding on `useProcessingEvents`,
 * and the reason is that hook's filter rather than a
 * preference: it accepts a `ModuleProgress` only when the artifact it names was
 * registered by an ingest this browser submitted, or when the case already has
 * a run in flight. A repair is neither. It has no artifact at all — the pass is
 * case-wide, so the server scopes the event to the case in both id fields — and
 * it starts on a case that is otherwise idle. Widening that filter is not the
 * fix: it is what keeps two concurrently processing cases from bleeding their
 * progress into each other, so this reads the one event the search page needs
 * and leaves the shared reducer alone.
 *
 * The result is handed to every examiner on the case, not only the one who
 * pressed the button. A colleague reading results while display names are being
 * rewritten under them needs the same warning the examiner who started it gets;
 * two people looking at one case must not be shown different facts about it.
 *
 * It rides the tab's ONE shared `EventSource` rather than opening a second.
 * Browsers cap concurrent HTTP/1.1 connections per origin at about six, and an
 * examiner working three cases in three tabs had already spent that budget on
 * duplicates of the same broadcast — after which the next tab's PRIMARY
 * processing stream never connects, loops through backoff forever, and leaves
 * that tab asserting a run state nothing is updating. Taking one event off the
 * shared socket costs no connection and keeps the isolation described above
 * intact: the shared reducer never sees this handler, and this handler never
 * sees the reducer.
 */
export function useSearchRepairProgress(caseId: string): RepairProgress | null {
  const [progress, setProgress] = useState<RepairProgress | null>(null)

  useEffect(() => {
    // A repair heard about under the previous case says nothing about this one.
    setProgress(null)
    if (caseId === '') return

    const onModuleProgress = (event: MessageEvent) => {
      const data = parseSseJson(event.data) as ModuleProgressEvent | null
      if (!data || data.event_type !== 'ModuleProgress') return
      const kind =
        data.module_id === REPAIR_MODULE_ID
          ? ('repair' as const)
          : data.module_id === BACKFILL_MODULE_ID
            ? ('backfill' as const)
            : null
      if (kind === null) return
      // The case is matched strictly, and an event that names no case is
      // dropped rather than assumed to be this one. The stream is global: a
      // repair running over a different case is not a reason to tell this
      // examiner their results are being rewritten.
      if (data.case_id !== caseId) return
      if (typeof data.units_done !== 'number') return
      setProgress({
        done: data.units_done,
        total: typeof data.units_total === 'number' ? data.units_total : null,
        kind,
      })
    }

    return subscribeSseEvent('module_progress', onModuleProgress)
  }, [caseId])

  return progress
}
