import { useEffect, useReducer, useRef } from 'react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { getProcessingStatus } from '../api/resources'
import { useToast } from '../components/toast/ToastProvider'
import { formatCount } from '../lib/format'
import {
  acceptsCancel,
  clearProcessingSnapshot,
  initialProcessingFor,
  isTrackedArtifact,
  loadProcessingSnapshot,
  parseSseJson,
  reduceProcessing,
  runEnding,
  runPictureIsStale,
  RUN_SILENT_MS,
  saveProcessingSnapshot,
  type ProcessingAction,
  type ProcessingState,
} from './processing'
import { subscribeSseConnection, subscribeSseEvent } from './sse'

const SSE_EVENT_NAMES = [
  'processing_status',
  'module_progress',
  'acquisition_hash_progress',
  'decoded_media_hash_progress',
  'processing_cancelled',
  'ingest_completed',
  'ingest_failed',
  // Fires every ~500ms carrying just `{count}`; normalised below into an
  // ArtifactBatch action that smooths the count between PhaseProgress snapshots.
  'artifact_batch',
  // The server's broadcast overran this client and dropped events it never
  // saw (HUNT-044). Nothing in the picture drawn so far can be trusted to be
  // current, so it is re-read from the endpoints that hold it.
  'lagged',
] as const

/** How often the watchdog looks at a running run to see whether it is still
 *  being talked about. */
const WATCHDOG_TICK_MS = 15_000

/** While the stream is down and a run is in flight, ask the server directly at
 *  about this interval: HTTP often works when the SSE connection does not
 *  (a proxy that buffers, a socket a sleeping laptop left half-open), and it is
 *  the only way left to find out that the run ended. */
const STREAM_DOWN_RECHECK_MS = 15_000

/** Floor on how often reconciliation may hit the API, whatever asks for it. */
const RECONCILE_MIN_INTERVAL_MS = 5_000

/**
 * How long "nothing is running" has to keep being true before this client will
 * conclude anything from it.
 *
 * `GET /status` reports a counter the orchestrator's task guards decrement the
 * instant the last task finishes, but the orchestrator only broadcasts the
 * run's terminal event on its own two-second interval (the idle branch of the
 * select loop in seance_core/src/orchestrator.rs). So there is a window of up
 * to two seconds in which the server truthfully answers zero and the completion
 * event is still on its way over a perfectly healthy socket. A reading taken
 * inside it says nothing about whether an event was missed.
 *
 * This is that window plus a margin: a zero is confirmed by a second zero taken
 * after it before anything is inferred, and if the terminal event turns up in
 * between there is nothing left to infer. Deliberately longer than the
 * orchestrator's interval — if the two ever drift, the failure this must not
 * have is the fast one, where a healthy run is declared over on screen.
 */
const ZERO_TASKS_CONFIRM_MS = 3_000

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/** How often the write-through snapshot may touch sessionStorage. The state is
 *  serialised whole, and events arrive several times a second. */
const SNAPSHOT_MIN_INTERVAL_MS = 1_000

/**
 * Invalidate every case-scoped query, not a hand-maintained subset, so a
 * finished run refreshes all views (gallery, geo, entities, system-info,
 * analysis, comms, execution, files, …) instead of leaving them showing
 * pre-ingest data. Any query whose key mentions this case is stale.
 */
function invalidateCaseQueries(queryClient: QueryClient, caseId: string) {
  queryClient.invalidateQueries({
    predicate: (q) => Array.isArray(q.queryKey) && q.queryKey.includes(caseId),
  })
}

/**
 * Subscribes this case shell to the tab's shared orchestrator stream, filters
 * events to this case (see processing.ts for the filtering rule), reconciles
 * with the server whenever the stream has left a gap, and invalidates stale
 * queries when a run ends.
 *
 * The stream is a broadcast with no replay, so this hook's picture of the run
 * is only ever "what we last heard". Three things follow from that, and all
 * three are load-bearing:
 *
 *  - The connection state is part of the run state. "Processing" heard over a
 *    live socket and "processing" heard before the socket died are different
 *    claims, and `describeRunState` renders them differently.
 *  - A gap has to be closed against something other than the stream. There is
 *    no per-case status endpoint, but `GET /status` reports the process-wide
 *    count of queued and in-flight artifacts, and zero is the same condition
 *    the orchestrator itself uses to declare a run finished — so zero settles
 *    it for this case too. It settles it on the same CONDITION, though, not on
 *    the same TIMING: the counter reaches zero up to two seconds before the
 *    orchestrator broadcasts, so a zero is only conclusive once it has outlived
 *    that window (ZERO_TASKS_CONFIRM_MS). Anything above zero belongs to some
 *    case, not necessarily this one, and settles nothing.
 *  - What reconciliation learns is that the run ENDED, never how it ended or
 *    with what totals. Those were in the events that were missed, and the UI
 *    says so rather than presenting the last count heard as a result. It is
 *    also the one conclusion this hook draws from an ABSENCE, so it is the one
 *    that yields: a terminal event or a progress frame arriving afterwards is
 *    better evidence, and `reduceProcessing` lets it win.
 */
export function useProcessingEvents(caseId: string): ProcessingState {
  const [state, dispatch] = useReducer(
    reduceProcessing,
    caseId,
    (id) => loadProcessingSnapshot(id) ?? initialProcessingFor(id),
  )
  const queryClient = useQueryClient()
  const toast = useToast()

  // Refs so the SSE effect does not tear down on every render.
  const toastRef = useRef(toast)
  toastRef.current = toast
  const stateRef = useRef(state)
  stateRef.current = state

  // Re-key the reducer when the case changes without a remount. Client-side
  // navigation between two cases keeps CaseLayout (and this hook) mounted, but
  // useReducer's lazy initializer only runs once — so without this the state
  // stays pinned to the previous case and matchesCase() silently drops every
  // event for the new one. Reset during render (guarded, so it runs once per
  // change) so the panel never flashes the previous case's progress.
  const prevCaseId = useRef(caseId)
  if (prevCaseId.current !== caseId) {
    prevCaseId.current = caseId
    dispatch({
      type: 'reset',
      state: loadProcessingSnapshot(caseId) ?? initialProcessingFor(caseId),
    })
  }

  // ---- Reconciliation ----

  const reconcileRef = useRef<() => Promise<void>>(async () => {})
  const reconcilingRef = useRef(false)
  const lastReconcileRef = useRef(0)
  const disposedRef = useRef(false)

  reconcileRef.current = async () => {
    if (disposedRef.current || reconcilingRef.current) return
    if (Date.now() - lastReconcileRef.current < RECONCILE_MIN_INTERVAL_MS) return
    // Nothing to reconcile: this shell is not claiming a run is in flight.
    if (!stateRef.current.active) return
    reconcilingRef.current = true
    lastReconcileRef.current = Date.now()
    try {
      // True only when the server has answered that nothing at all is in
      // flight, in the scope the inference below needs. `scope` names what
      // `active_tasks` counted, and the inference holds for a count taken
      // across this whole process — nothing queued or running anywhere means
      // nothing queued or running for this case. A server that ever answers
      // with some other scope gets no conclusion drawn from it, and a count
      // above zero belongs to some case and not necessarily this one; both are
      // "draw no conclusion", which is the same instruction here, and both
      // leave the run unconfirmed rather than wrongly ended.
      const nothingInFlight = async (): Promise<boolean> => {
        const status = (await getProcessingStatus()) as {
          active_tasks: number
          scope?: string
        }
        if (status.scope != null && status.scope !== 'process') return false
        return status.active_tasks === 0
      }

      if (!(await nothingInFlight())) return
      if (disposedRef.current || !stateRef.current.active) return
      // Zero is not yet an answer: see ZERO_TASKS_CONFIRM_MS. Wait out the
      // orchestrator's broadcast interval and ask again. The state is re-read
      // after the wait because the thing most likely to have happened during it
      // is the terminal event arriving — and an event that ARRIVES outranks
      // anything inferred from its absence, so there is then nothing to infer.
      await wait(ZERO_TASKS_CONFIRM_MS)
      if (disposedRef.current || !stateRef.current.active) return
      if (!(await nothingInFlight())) return
      if (disposedRef.current || !stateRef.current.active) return
      dispatch({ type: 'run-ended-unobserved', at: Date.now() })
      // The completion event was the only thing that ever refreshed these,
      // and it is not coming.
      invalidateCaseQueries(queryClient, caseId)
    } catch {
      // The server could not be reached either. Nothing is claimed on the
      // strength of a failed request: the state stays as it is, which
      // describeRunState already reports as unconfirmed.
    } finally {
      reconcilingRef.current = false
    }
  }

  useEffect(() => {
    disposedRef.current = false
    return () => {
      disposedRef.current = true
    }
  }, [])

  // ---- The stream ----

  useEffect(() => {
    const onEvent = (event: MessageEvent) => {
      const parsed = parseSseJson(event.data)
      if (!parsed || typeof parsed !== 'object') return

      // The artifact_batch payload has no self-describing `event_type`, so key
      // off the SSE event name to tag it for the reducer. `case_id` is passed
      // through so the reducer can drop another case's throughput: without it
      // the panel adds every case's batches to the open case's live count.
      if (event.type === 'lagged') {
        void reconcileRef.current()
        invalidateCaseQueries(queryClient, caseId)
        return
      }

      if (event.type === 'artifact_batch') {
        const batch = parsed as { count?: number; case_id?: string }
        if (typeof batch.count === 'number') {
          dispatch({
            event_type: 'ArtifactBatch',
            case_id: batch.case_id,
            count: batch.count,
          })
        }
        return
      }

      const action = parsed as ProcessingAction

      dispatch(action)

      // Wire events are internally tagged (`event_type`); InternalActions
      // (`type`) are dispatched by the client, never received here.
      if (!('event_type' in action)) return

      if (
        action.event_type === 'ProcessingComplete' &&
        action.case_id === caseId
      ) {
        invalidateCaseQueries(queryClient, caseId)
        toastRef.current.success(
          `Processing complete — ${formatCount(action.total_artifacts)} artifacts`,
        )
      } else if (
        action.event_type === 'ProcessingCancelled' &&
        // The stream is global: every case's cancels arrive here. The toast has
        // to speak for exactly the cancels the reducer acts on, so it asks the
        // reducer's own predicate against the reducer's own subject
        // (`stateRef.current` still holds the state the reducer just saw —
        // React has not re-rendered yet). A separate expression answers
        // differently for any state whose `caseId` is null, and again for a run
        // reconciliation has already ended; in both directions the reducer
        // records the cancel while the toast says nothing, and the examiner is
        // left with a run that stopped and no explanation on screen.
        acceptsCancel(stateRef.current, action.case_id)
      ) {
        toastRef.current.info(
          `Processing cancelled — ${formatCount(action.artifacts_processed)} artifacts processed`,
        )
      } else if (
        action.event_type === 'IngestFailed' &&
        isTrackedArtifact(caseId, action.artifact_id)
      ) {
        toastRef.current.error(`Ingest failed: ${action.error ?? 'unknown error'}`)
      }
    }

    const unsubscribes = SSE_EVENT_NAMES.map((name) =>
      subscribeSseEvent(name, onEvent),
    )

    // The generation this shell last saw connected. Zero means it has not seen
    // the socket open at all yet, so the first open is a first connection and
    // not a reconnection — there is no gap to close before the beginning.
    let seenGeneration = 0
    const unsubscribeConnection = subscribeSseConnection((connection) => {
      dispatch({
        type: 'connection',
        connectionState: connection.status,
        at: connection.downSince ?? Date.now(),
      })
      if (connection.status !== 'live') return
      const reconnected = seenGeneration > 0 && connection.generation > seenGeneration
      seenGeneration = connection.generation
      if (!reconnected) return
      // Transient lanes may be stale after an outage; drop them and let fresh
      // events repopulate.
      dispatch({ type: 'reconnected' })
      // Everything broadcast during the outage is gone, possibly including the
      // event that ended the run. Ask.
      void reconcileRef.current()
    })

    return () => {
      for (const unsubscribe of unsubscribes) unsubscribe()
      unsubscribeConnection()
    }
  }, [caseId, queryClient])

  // A snapshot restored on mount is a picture of the run as the tab last saw
  // it, which may be minutes or a lid-close old. Check it against the server
  // before the shell spends the snapshot's TTL asserting a run that is over.
  useEffect(() => {
    // The rate limit exists to stop one shell hammering the endpoint, not to
    // make a different case wait its turn for its first answer.
    lastReconcileRef.current = 0
    if (stateRef.current.active) void reconcileRef.current()
  }, [caseId])

  // Coming back to a tab that was asleep is the moment the client is most
  // likely to be holding a picture from before a gap it never noticed — but
  // coming back to a tab that was never asleep is the commonest thing an
  // examiner does, and reconciliation is a claim-changing operation. So this
  // asks the same precondition the watchdog and reconnect paths have built in:
  // only when the picture could actually have a gap in it.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return
      if (!runPictureIsStale(stateRef.current, Date.now())) return
      void reconcileRef.current()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
  }, [])

  // Watchdog. A run that has stopped being talked about — because the socket is
  // down, or because the orchestrator behind a perfectly healthy socket is gone
  // — is a run this client can no longer vouch for, and the only way to find
  // out is to ask.
  const runActive = state.active
  useEffect(() => {
    if (!runActive) return
    const startedWatchingAt = Date.now()
    const timer = setInterval(() => {
      const current = stateRef.current
      const now = Date.now()
      const silentFor = now - (current.lastEventAt ?? startedWatchingAt)
      const downFor =
        current.streamDownSince != null ? now - current.streamDownSince : 0
      if (silentFor >= RUN_SILENT_MS || downFor >= STREAM_DOWN_RECHECK_MS) {
        void reconcileRef.current()
      }
    }, WATCHDOG_TICK_MS)
    return () => clearInterval(timer)
  }, [runActive])

  // ---- Write-through snapshot ----
  //
  // Throttled, because the state is serialised whole and events arrive several
  // times a second: an unthrottled write is an O(state) serialisation twice a
  // second for the length of the run, and on a case big enough to need the
  // snapshot it is the one most likely to blow the storage quota and switch the
  // protection off exactly when it was needed.
  const snapshotTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pendingSnapshot = useRef<ProcessingState | null>(null)
  const lastSnapshotAt = useRef(0)

  const cancelPendingSnapshot = () => {
    if (snapshotTimer.current) clearTimeout(snapshotTimer.current)
    snapshotTimer.current = null
    pendingSnapshot.current = null
  }

  useEffect(() => {
    const writeNow = (snapshot: ProcessingState) => {
      lastSnapshotAt.current = Date.now()
      pendingSnapshot.current = null
      saveProcessingSnapshot(snapshot)
    }

    // A run that ended — however this shell learned it ended — must not leave a
    // snapshot behind that re-asserts it on the next reload, and a write still
    // sitting in the throttle would do exactly that a second later.
    if (runEnding(state) != null) {
      cancelPendingSnapshot()
      clearProcessingSnapshot(caseId)
      return
    }
    if (!state.active && Object.keys(state.hashing).length === 0) return

    pendingSnapshot.current = state
    if (snapshotTimer.current) return
    const wait = Math.max(
      0,
      SNAPSHOT_MIN_INTERVAL_MS - (Date.now() - lastSnapshotAt.current),
    )
    // The leading write is immediate: a run that starts and a tab that reloads
    // a moment later must still restore.
    if (wait === 0) {
      writeNow(state)
      return
    }
    snapshotTimer.current = setTimeout(() => {
      snapshotTimer.current = null
      // Whatever the state has become by now, not the state that was current
      // when the throttle closed.
      if (pendingSnapshot.current) writeNow(pendingSnapshot.current)
    }, wait)
  }, [state, caseId])

  // Flush on the way out: an unmount inside the throttle window would otherwise
  // drop the very write a mid-run reload depends on.
  useEffect(() => {
    return () => {
      const pending = pendingSnapshot.current
      cancelPendingSnapshot()
      // A run that ended — however this shell learned it ended — must not be
      // written back out on the way past, or the next reload restores it and
      // re-asserts it. The effect above asks exactly this question.
      if (pending && runEnding(pending) == null) {
        saveProcessingSnapshot(pending)
      }
    }
  }, [])

  return state
}
