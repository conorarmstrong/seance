// Orchestrator SSE event handling. The server currently double-encodes
// some payloads (JSON string containing JSON); parseSseJson tolerates
// both encodings so the client survives the server-side fix.
//
// Case filtering rule (the /api/v1/events stream is global):
// - Events that carry `case_id` (PhaseStarted, PhaseProgress,
//   ProcessingComplete, ModuleError) are dropped unless they match the
//   case this reducer was initialised for.
// - Events without `case_id` are matched pragmatically:
//   - acquisition_hash_progress: shown only when its `source` path was
//     registered for this case via trackIngest (written by the ingest
//     modal on submit, persisted in sessionStorage across reloads).
//   - ingest_completed / ingest_failed: matched against tracked
//     artifact ids from the same registry.
//   - module_progress: accepted when its artifact_id is tracked, OR
//     while this case has an active run (a case-attributed PhaseStarted
//     was seen); accepted artifacts become tracked. Bleed is only
//     possible when two cases process concurrently, which single-run
//     orchestrator deployments do not do.
//   - processing_cancelled: accepted only while this case has an
//     active run.

import { formatCount } from '../lib/format'

export function parseSseJson(data: string): unknown {
  try {
    let value = JSON.parse(data)
    if (typeof value === 'string') value = JSON.parse(value)
    return value
  } catch {
    return null
  }
}

export interface ModuleErrorEvent {
  case_id: string
  module_id: string
  artifact_id: string
  error: string
}

export type ConnectionState = 'live' | 'reconnecting'

export type ModuleUnit = 'bytes' | 'items' | 'records' | 'files'

export interface ModuleActivity {
  moduleId: string
  artifactId: string
  unitsDone: number
  unitsTotal: number | null
  unit: ModuleUnit
  updatedAt: number
}

export interface HashActivity {
  source: string
  bytesDone: number
  bytesTotal: number
  updatedAt: number
  /** Number of files in the EWF segment set (>1 means a multi-part image). */
  segmentCount?: number
  /** Combined on-disk size of every segment file in the set, in bytes. */
  segmentBytesTotal?: number
}

export interface ProcessingState {
  /** Case this state was initialised for; null accepts all (legacy). */
  caseId: string | null
  connectionState: ConnectionState
  active: boolean
  complete: boolean
  phase: string | null
  processed: number
  byType: Record<string, number>
  totalArtifacts: number | null
  durationMs: number | null
  errors: ModuleErrorEvent[]
  /** Module errors dropped from `errors` to keep the array bounded (LIVE-030).
   *  Never subtract this from what the UI reports: see totalErrorCount. */
  errorsDropped: number
  tasksCompleted: number | null
  tasksTotal: number | null
  /** Smoothed live artifact count, advanced by artifact_batch between snapshots. */
  liveCount: number
  /** Throughput in artifacts/sec from the latest snapshot; null before any. */
  ratePerSec: number | null
  /** Estimated seconds remaining; null while discovering or unknown. */
  etaSeconds: number | null
  /** True while the task total is still being discovered (denominator untrusted). */
  discovering: boolean
  /** Module ids currently running, for the "what's working" reassurance label. */
  activeModules: string[]
  /** Monotonic task-percentage floor so the determinate bar never jumps backward. */
  taskPct: number
  /** Per-module activity lane, keyed by `${module_id}:${artifact_id}`. */
  modules: Record<string, ModuleActivity>
  /** Acquisition hashing lane, keyed by source path. */
  hashing: Record<string, HashActivity>
  cancelled: boolean
  cancelledArtifacts: number | null
  /** Epoch ms at which the event stream went down; null while connected. */
  streamDownSince: number | null
  /** Epoch ms of the most recent wire event this case's reducer acted on.
   *  Null before any has arrived. This is what makes "processing" a claim with
   *  a timestamp rather than a claim with no expiry date. */
  lastEventAt: number | null
  /** The run stopped, but this client never observed the terminal event: the
   *  server was asked and reported no work in flight. Deliberately NOT
   *  `complete`, which asserts a ProcessingComplete was seen and carries the
   *  final total that event brings with it. */
  endedUnobserved: boolean
}

export const initialProcessing: ProcessingState = {
  caseId: null,
  connectionState: 'live',
  active: false,
  complete: false,
  phase: null,
  processed: 0,
  byType: {},
  totalArtifacts: null,
  durationMs: null,
  errors: [],
  errorsDropped: 0,
  tasksCompleted: null,
  tasksTotal: null,
  liveCount: 0,
  ratePerSec: null,
  etaSeconds: null,
  discovering: false,
  activeModules: [],
  taskPct: 0,
  modules: {},
  hashing: {},
  cancelled: false,
  cancelledArtifacts: null,
  streamDownSince: null,
  lastEventAt: null,
  endedUnobserved: false,
}

export function initialProcessingFor(caseId: string): ProcessingState {
  return { ...initialProcessing, caseId }
}

// ---- Tracked-ingest registry ----
// Maps a case to the artifact ids / source paths it submitted for ingest,
// so unattributed SSE events can be assigned to the right case. Backed by
// sessionStorage so a mid-ingest reload keeps matching.

interface TrackedIngests {
  artifacts: string[]
  sources: Record<string, string> // source path -> artifact id
}

const trackingKey = (caseId: string) => `seance.ingest-tracking.${caseId}`

function loadTracking(caseId: string): TrackedIngests {
  try {
    const raw = sessionStorage.getItem(trackingKey(caseId))
    if (raw) {
      const parsed = JSON.parse(raw) as TrackedIngests
      if (Array.isArray(parsed.artifacts) && parsed.sources) return parsed
    }
  } catch {
    // Corrupt entry; start fresh.
  }
  return { artifacts: [], sources: {} }
}

function saveTracking(caseId: string, tracking: TrackedIngests) {
  try {
    sessionStorage.setItem(trackingKey(caseId), JSON.stringify(tracking))
  } catch {
    // Storage full or unavailable; matching degrades gracefully.
  }
}

export function trackIngest(
  caseId: string,
  entry: { artifactId: string; source?: string },
) {
  const tracking = loadTracking(caseId)
  if (!tracking.artifacts.includes(entry.artifactId)) {
    tracking.artifacts.push(entry.artifactId)
  }
  if (entry.source) tracking.sources[entry.source] = entry.artifactId
  saveTracking(caseId, tracking)
}

export function isTrackedArtifact(caseId: string, artifactId: string): boolean {
  return loadTracking(caseId).artifacts.includes(artifactId)
}

export function isTrackedSource(caseId: string, source: string): boolean {
  return source in loadTracking(caseId).sources
}

function sourceForArtifact(caseId: string, artifactId: string): string | null {
  const { sources } = loadTracking(caseId)
  for (const [source, id] of Object.entries(sources)) {
    if (id === artifactId) return source
  }
  return null
}

export function clearIngestTracking(caseId: string) {
  try {
    sessionStorage.removeItem(trackingKey(caseId))
  } catch {
    // Ignore.
  }
}

// ---- Snapshot persistence ----
// Write-through snapshot of the processing state so a mid-run reload
// shows the current phase instead of "idle". Cleared on completion or
// cancellation; stale snapshots expire after a TTL because a closed tab
// never sees the terminal event.

const SNAPSHOT_TTL_MS = 15 * 60 * 1000

const snapshotKey = (caseId: string) => `seance.processing.${caseId}`

export function saveProcessingSnapshot(state: ProcessingState) {
  if (!state.caseId) return
  try {
    sessionStorage.setItem(
      snapshotKey(state.caseId),
      JSON.stringify({ savedAt: Date.now(), state }),
    )
  } catch {
    // Storage unavailable; reload will just show idle.
  }
}

export function loadProcessingSnapshot(caseId: string): ProcessingState | null {
  try {
    const raw = sessionStorage.getItem(snapshotKey(caseId))
    if (!raw) return null
    const parsed = JSON.parse(raw) as {
      savedAt?: number
      state?: ProcessingState
    }
    if (
      !parsed.state ||
      parsed.state.caseId !== caseId ||
      typeof parsed.savedAt !== 'number' ||
      Date.now() - parsed.savedAt > SNAPSHOT_TTL_MS
    ) {
      sessionStorage.removeItem(snapshotKey(caseId))
      return null
    }
    // The restored picture is as old as the write that produced it. Dating it
    // from `savedAt` — rather than letting it read as if it had just arrived —
    // is what stops a tab reopened after the run finished from asserting
    // "processing" for the rest of the TTL: the state is stale on arrival, and
    // describeRunState says so until an event or a server reconciliation
    // replaces it.
    return {
      // Over the defaults, because a snapshot outlives the build that wrote it:
      // sessionStorage survives a deploy inside one tab session, so a state
      // saved by an older client is missing every field added since. Spread
      // bare, those arrive as `undefined` and turn counts into NaN on a screen
      // whose whole job is to report numbers accurately.
      ...initialProcessing,
      ...parsed.state,
      connectionState: 'live',
      streamDownSince: null,
      lastEventAt: parsed.savedAt,
    }
  } catch {
    return null
  }
}

export function clearProcessingSnapshot(caseId: string) {
  try {
    sessionStorage.removeItem(snapshotKey(caseId))
  } catch {
    // Ignore.
  }
}

// ---- Events and reducer ----

// The orchestrator serializes OrchestratorEvent with `#[serde(tag =
// "event_type")]` (internally tagged), so every wire event is a flat object
// with an `event_type` discriminant — NOT `{ PhaseProgress: {...} }`.
type TaggedEvent =
  | {
      event_type: 'ModuleProgress'
      // Optional on the wire: omitted only by legacy unscoped reporters. When
      // present, the reducer drops events for a different case (BUG-166).
      case_id?: string
      module_id: string
      artifact_id: string
      units_done: number
      units_total: number | null
      unit: ModuleUnit
    }
  | {
      event_type: 'ArtifactBatch'
      // The case the batched artifacts were produced for. Older servers sent a
      // bare count; when it is absent the batch is accepted, as elsewhere.
      case_id?: string
      count: number
    }
  | {
      event_type: 'AcquisitionHashProgress'
      case_id: string
      source: string
      bytes_done: number
      bytes_total: number
      segment_count?: number
      segment_bytes_total?: number
    }
  | {
      // The second hashing pass: a container's decoded stream re-hashed to
      // verify it against the hash recorded inside it. Keyed by artifact, not a
      // source path — the container is already an ingested artifact by now.
      event_type: 'DecodedMediaHashProgress'
      case_id: string
      artifact_id: string
      bytes_done: number
      bytes_total: number
    }
  | {
      event_type: 'ProcessingCancelled'
      // Optional: omitted when no case context was recorded for the cancel.
      case_id?: string
      artifacts_processed: number
    }
  | { event_type: 'IngestCompleted'; case_id: string; artifact_id: string }
  | { event_type: 'IngestFailed'; case_id: string; artifact_id: string; error: string }
  | { event_type: 'PhaseStarted'; case_id: string; phase: string; artifact_type: string }
  | {
      event_type: 'PhaseProgress'
      case_id: string
      artifacts_processed: number
      artifacts_by_type: [string, number][]
      tasks_completed?: number
      tasks_total?: number
      rate_per_sec?: number
      eta_seconds?: number | null
      discovering?: boolean
      active_modules?: string[]
    }
  | {
      event_type: 'ProcessingComplete'
      case_id: string
      total_artifacts: number
      total_duration_ms: number
      artifacts_by_type: [string, number][]
    }
  | {
      event_type: 'ModuleError'
      case_id: string
      module_id: string
      artifact_id: string
      error: string
    }

type InternalAction =
  // `at` is when the transition was observed; it defaults to now, which is what
  // a caller with no better timestamp should let it do.
  | { type: 'connection'; connectionState: ConnectionState; at?: number }
  | { type: 'reconnected' }
  | { type: 'reset'; state: ProcessingState }
  // The server was asked whether anything is still running and said no, but no
  // terminal event for this run was ever seen. See the reducer arm.
  | { type: 'run-ended-unobserved'; at?: number }

export type ProcessingAction = TaggedEvent | InternalAction

/** Keep the activity lane bounded on long runs. */
const MAX_MODULE_ENTRIES = 20

/**
 * How many module errors the state keeps.
 *
 * A damaged image can throw tens of thousands of them, and every one of them
 * used to be held in memory, re-serialised into the sessionStorage snapshot on
 * every artifact batch, and eventually pushed the write past the storage quota
 * — which silently disabled the mid-run reload protection on exactly the run
 * that needed it. The array is capped; the COUNT is not (see totalErrorCount),
 * because how many errors occurred is a fact about the evidence and must not
 * shrink to fit a buffer.
 */
export const MAX_RETAINED_ERRORS = 200

/** How many module errors this run produced, including those the bounded
 *  `errors` array no longer holds. This is the figure to put on screen. */
export function totalErrorCount(state: ProcessingState): number {
  return state.errors.length + state.errorsDropped
}

function pruneModules(
  modules: Record<string, ModuleActivity>,
): Record<string, ModuleActivity> {
  const entries = Object.entries(modules)
  if (entries.length <= MAX_MODULE_ENTRIES) return modules
  entries.sort((a, b) => b[1].updatedAt - a[1].updatedAt)
  return Object.fromEntries(entries.slice(0, MAX_MODULE_ENTRIES))
}

function matchesCase(state: ProcessingState, caseId: string): boolean {
  return state.caseId === null || state.caseId === caseId
}

/** True when a wire event names a case other than the one this shell tracks.
 *  Such events belong to a concurrently-processing case and must be dropped
 *  (BUG-166). Events with no `case_id` (legacy unscoped) are never foreign.
 *
 *  Exported so the toast layer in `useProcessingEvents` can ask exactly this
 *  question rather than its own. The two were separate expressions on separate
 *  subjects — the reducer on `state.caseId`, the toast on the hook's `caseId`
 *  prop — and they part company on any state whose `caseId` is null, which the
 *  type permits and `initialProcessing` is: the reducer accepts the foreign
 *  cancel and tears the shell down while the toast stays silent, leaving an
 *  examiner with a run that stopped and nothing said about it. Today the hook
 *  always seeds `caseId`, so the two happen to agree; sharing the predicate is
 *  what keeps that from depending on how the state was seeded. */
export function isForeignCase(
  state: ProcessingState,
  caseId: string | undefined,
): boolean {
  return caseId != null && state.caseId !== null && state.caseId !== caseId
}

/**
 * Whether a `ProcessingCancelled` on the wire is about the run this state holds.
 *
 * It is accepted after reconciliation has already inferred an ending, and that
 * is the point of it: "cancelled — N artifacts processed" and "ended, no
 * completion event received" are different statements about what the case now
 * holds, and only the cancel event carries the first one. The cancel poisons
 * the queue, so the server's in-flight count reaches zero while the event is
 * still queued behind the drain — exactly the window a reconcile samples. It
 * used to be dropped by an `if (!state.active)` guard, leaving the examiner who
 * pressed Stop with a run that reads as lost to a network gap (B5-013).
 *
 * A run that ended with an event this client SAW is not reopened: `complete`
 * and `cancelled` both imply neither `active` nor `endedUnobserved`, so they
 * fall out of this test on their own.
 *
 * Exported so the toast layer in `useProcessingEvents` asks exactly this
 * question rather than one of its own. The two were separate expressions on
 * separate subjects and parted company on any state whose `caseId` is null, and
 * again on any run reconciliation had already ended: the reducer records the
 * cancel while the toast stays silent, leaving an examiner with a run that
 * stopped and nothing said about it.
 */
export function acceptsCancel(
  state: ProcessingState,
  caseId: string | undefined,
): boolean {
  if (isForeignCase(state, caseId)) return false
  return state.active || state.endedUnobserved
}

/**
 * The three ways a run can be over, as ONE value.
 *
 * `complete`, `cancelled` and `endedUnobserved` are three booleans on the state
 * because the snapshot format and every reader of it are written that way, but
 * they describe one thing and at most one of them can be true. They used to be
 * assigned independently, and the combination that produced — a completion
 * event landing after reconciliation had already inferred an ending — put two
 * different artifact totals for one run on one panel, under a title saying no
 * completion event had ever reached this browser. Every terminal transition now
 * goes through `endRun`, whose argument is this union, so a state holding two
 * endings cannot be built here at all.
 */
type RunEnding =
  | {
      kind: 'complete'
      totalArtifacts: number
      durationMs: number
      byType: Record<string, number>
    }
  | { kind: 'cancelled'; artifactsProcessed: number | null }
  | { kind: 'ended-unobserved' }

function endRun(state: ProcessingState, ending: RunEnding): ProcessingState {
  return {
    ...state,
    active: false,
    complete: ending.kind === 'complete',
    cancelled: ending.kind === 'cancelled',
    endedUnobserved: ending.kind === 'ended-unobserved',
    // Each figure belongs to exactly one ending and is cleared under the other
    // two, so no screen can pair a total with an ending that did not report it.
    totalArtifacts: ending.kind === 'complete' ? ending.totalArtifacts : null,
    durationMs: ending.kind === 'complete' ? ending.durationMs : null,
    cancelledArtifacts:
      ending.kind === 'cancelled' ? ending.artifactsProcessed : null,
    byType: ending.kind === 'complete' ? ending.byType : state.byType,
    // Nothing is in flight any more, whichever way the run ended.
    activeModules: [],
    modules: {},
    etaSeconds: null,
    discovering: false,
    // The hashing lane survives an INFERRED ending only. All that ending rests
    // on is an empty task queue, and an acquisition hash runs before anything
    // is queued — so it is not evidence that hashing has stopped. A terminal
    // event is evidence that the whole run is done.
    hashing: ending.kind === 'ended-unobserved' ? state.hashing : {},
  }
}

export type RunEndingKind = 'complete' | 'cancelled' | 'ended-unobserved'

/**
 * The one ending this state holds, or null while nothing has ended.
 *
 * `endRun` guarantees at most one of the three flags is set, so for any state
 * this reducer produced there is nothing here to choose between. The order is
 * still stated, for the states it did not produce: `sessionStorage` outlives a
 * deploy inside one tab session, so a snapshot written by the build that had
 * the bug can be restored into this one carrying the contradictory pair. The
 * order is the rule that removed it — an ending this client OBSERVED outranks
 * one it inferred from an absence — with the cancel ahead of the completion
 * because "the case holds a partial result" is the weightier of the two claims
 * and must not be overwritten by a completion arriving behind it (B5-013).
 */
export function runEnding(state: ProcessingState): RunEndingKind | null {
  if (state.cancelled) return 'cancelled'
  if (state.complete) return 'complete'
  if (state.endedUnobserved) return 'ended-unobserved'
  return null
}

export function reduceProcessing(
  state: ProcessingState,
  action: ProcessingAction,
): ProcessingState {
  if ('type' in action) {
    if (action.type === 'connection') {
      if (state.connectionState === action.connectionState) return state
      return {
        ...state,
        connectionState: action.connectionState,
        // The moment the socket died is the moment everything on screen stopped
        // being confirmed by anything. Keeping it lets the UI date its own
        // uncertainty instead of quietly carrying the last frame forward.
        streamDownSince:
          action.connectionState === 'reconnecting'
            ? (action.at ?? Date.now())
            : null,
      }
    }
    if (action.type === 'reconnected') {
      // Transient per-module / hashing / active-module progress may be
      // stale after an outage; drop it and let fresh events repopulate.
      return { ...state, modules: {}, hashing: {}, activeModules: [] }
    }
    if (action.type === 'reset') {
      // The shell switched to a different case without remounting; replace
      // the whole state so it is re-keyed to the new case.
      return action.state
    }
    if (action.type === 'run-ended-unobserved') {
      // Reconciliation with the server, after this client had reason to believe
      // its picture was stale. The server reports no work in flight anywhere in
      // the process, and has gone on reporting that for longer than the
      // orchestrator's terminal-event interval (see ZERO_TASKS_CONFIRM_MS in
      // useProcessingEvents) — so this run is over and its terminal event is
      // not merely late.
      //
      // What is NOT known is anything the missed events carried: the final
      // total, the duration, the per-type breakdown, whether it finished or was
      // cancelled. So this sets neither `complete` nor `cancelled`, invents no
      // total, and leaves `processed` as what it is — the last count actually
      // heard, which the UI labels as such.
      //
      // It is also the only ending drawn from an absence rather than heard, and
      // therefore the only provisional one: a terminal event or a progress
      // frame arriving afterwards is better evidence than the silence this was
      // inferred from, and supersedes it.
      if (!state.active) return state
      return endRun(state, { kind: 'ended-unobserved' })
    }
    return state
  }

  const next = reduceWireEvent(state, action)
  // Anything the reducer acted on is fresh evidence about THIS case's run, and
  // dating it is what separates "processing, heard a second ago" from
  // "processing, heard before the laptop lid closed". An event the reducer
  // dropped — another case's, or one this shell does not track — proves the
  // socket is alive but says nothing about this run, so it does not count.
  if (next === state) return state
  return { ...next, lastEventAt: Date.now() }
}

function reduceWireEvent(
  state: ProcessingState,
  action: TaggedEvent,
): ProcessingState {
  switch (action.event_type) {
    case 'ModuleProgress': {
      // Drop a module lane that belongs to another case: while active, an
      // untracked foreign artifact would otherwise be auto-tracked into this
      // shell and bleed its progress across cases (BUG-166).
      if (isForeignCase(state, action.case_id)) return state
      const tracked =
        state.caseId === null ||
        isTrackedArtifact(state.caseId, action.artifact_id)
      if (!tracked && !state.active) return state
      if (!tracked && state.caseId) {
        trackIngest(state.caseId, { artifactId: action.artifact_id })
      }
      const key = `${action.module_id}:${action.artifact_id}`
      return {
        ...state,
        modules: pruneModules({
          ...state.modules,
          [key]: {
            moduleId: action.module_id,
            artifactId: action.artifact_id,
            unitsDone: action.units_done,
            unitsTotal: action.units_total,
            unit: action.unit,
            updatedAt: Date.now(),
          },
        }),
      }
    }
    case 'AcquisitionHashProgress': {
      if (isForeignCase(state, action.case_id)) return state
      if (state.caseId && !isTrackedSource(state.caseId, action.source)) {
        return state
      }
      return {
        ...state,
        hashing: {
          ...state.hashing,
          [action.source]: {
            source: action.source,
            bytesDone: action.bytes_done,
            bytesTotal: action.bytes_total,
            updatedAt: Date.now(),
            segmentCount: action.segment_count,
            segmentBytesTotal: action.segment_bytes_total,
          },
        },
      }
    }
    case 'DecodedMediaHashProgress': {
      if (isForeignCase(state, action.case_id)) return state
      if (
        state.caseId &&
        !isTrackedArtifact(state.caseId, action.artifact_id)
      ) {
        return state
      }
      // Shown in the same hashing lane, keyed by artifact so it cannot collide
      // with the acquisition source path.
      const key = `decoded:${action.artifact_id}`
      return {
        ...state,
        hashing: {
          ...state.hashing,
          [key]: {
            source: 'Decoded-media verification',
            bytesDone: action.bytes_done,
            bytesTotal: action.bytes_total,
            updatedAt: Date.now(),
          },
        },
      }
    }
    case 'ArtifactBatch': {
      // Smooth the displayed count between the ~2s authoritative
      // PhaseProgress snapshots. The batch is per case: a stream carrying two
      // cases (an admin, or the single-user default) would otherwise add
      // another case's throughput to this case's live count and ETA, so the
      // panel reports progress that never happened for the case on screen.
      // PhaseProgress reconciles liveCount back to the authoritative
      // artifacts_processed either way, but between snapshots the number the
      // examiner reads must belong to the case they are looking at.
      if (isForeignCase(state, action.case_id)) return state
      if (!state.active) return state
      return { ...state, liveCount: state.liveCount + action.count }
    }
    case 'ProcessingCancelled': {
      // A scoped cancel for another case must not tear down this shell
      // (BUG-166); a cancel that lands after reconciliation already inferred an
      // ending still counts. See acceptsCancel for both.
      if (!acceptsCancel(state, action.case_id)) return state
      return endRun(state, {
        kind: 'cancelled',
        artifactsProcessed: action.artifacts_processed,
      })
    }
    case 'IngestCompleted':
    case 'IngestFailed': {
      if (isForeignCase(state, action.case_id)) return state
      if (
        state.caseId &&
        !isTrackedArtifact(state.caseId, action.artifact_id)
      ) {
        return state
      }
      const source = state.caseId
        ? sourceForArtifact(state.caseId, action.artifact_id)
        : null
      const decodedKey = `decoded:${action.artifact_id}`
      const hasAcquisition = source != null && source in state.hashing
      const hasDecoded = decodedKey in state.hashing
      if (!hasAcquisition && !hasDecoded) return state
      const hashing = { ...state.hashing }
      if (hasAcquisition && source) delete hashing[source]
      if (hasDecoded) delete hashing[decodedKey]
      return { ...state, hashing }
    }
    case 'PhaseStarted': {
      if (!matchesCase(state, action.case_id)) return state
      return {
        ...initialProcessing,
        caseId: state.caseId,
        connectionState: state.connectionState,
        // Liveness is a fact about the socket, not about the run that just
        // started over it; a PhaseStarted heard during an outage is not
        // possible, but resetting these would claim a confirmation this
        // reducer has not been given.
        streamDownSince: state.streamDownSince,
        lastEventAt: state.lastEventAt,
        hashing: state.hashing,
        active: true,
        phase: action.phase,
        errors: state.active ? state.errors : [],
        errorsDropped: state.active ? state.errorsDropped : 0,
      }
    }
    case 'PhaseProgress': {
      if (!matchesCase(state, action.case_id)) return state
      // A run this shell has already recorded as cancelled does not come back
      // to life on a progress frame that was in flight when the cancel landed.
      // Only `PhaseStarted` — a genuinely new run — clears `cancelled`, so the
      // UI cannot flip cancelled → processing → complete (B6-031).
      //
      // `endedUnobserved` is deliberately NOT guarded the same way, and the
      // difference is the whole rule: `cancelled` is an event this client SAW,
      // while `endedUnobserved` is an inference drawn from an absence of
      // traffic — and this frame IS traffic, so it is the better evidence of
      // the two and retracts the inference (see the reducer arm). A frame that
      // turns out to be a straggler costs a run that reads as live until the
      // next watchdog tick, which was true at the moment it was heard; refusing
      // it costs a run reported as ended while its progress is arriving.
      if (state.cancelled) return state
      const discovering = action.discovering ?? false
      // Advance the monotonic task-percentage floor only once the total is
      // trustworthy; while discovering the bar is indeterminate anyway.
      let taskPct = state.taskPct
      if (!discovering && action.tasks_total && action.tasks_total > 0) {
        const pct = Math.min(
          100,
          Math.round(((action.tasks_completed ?? 0) / action.tasks_total) * 100),
        )
        taskPct = Math.max(taskPct, pct)
      }
      return {
        ...state,
        active: true,
        endedUnobserved: false,
        processed: action.artifacts_processed,
        // Reconcile the smoothed count back to the authoritative snapshot.
        liveCount: action.artifacts_processed,
        byType: Object.fromEntries(action.artifacts_by_type),
        tasksCompleted: action.tasks_completed ?? state.tasksCompleted,
        tasksTotal: action.tasks_total ?? state.tasksTotal,
        ratePerSec: action.rate_per_sec ?? state.ratePerSec,
        etaSeconds: action.eta_seconds ?? null,
        discovering,
        activeModules: action.active_modules ?? state.activeModules,
        taskPct,
      }
    }
    case 'ProcessingComplete': {
      if (!matchesCase(state, action.case_id)) return state
      // A cancel is an event this client heard and a statement the examiner
      // made about this run; a completion arriving behind it does not erase the
      // partial-result claim it carries. Same reasoning as the progress guard
      // above (B6-031, B5-013).
      if (state.cancelled) return state
      // Reaching this over an `endedUnobserved` state is the ordinary case, not
      // the odd one: reconciliation infers an ending from a queue that drains
      // up to two seconds before the orchestrator broadcasts. The event that
      // then arrives is the observation the inference stood in for, and it
      // replaces it whole — total, duration and breakdown included.
      return endRun(state, {
        kind: 'complete',
        totalArtifacts: action.total_artifacts,
        durationMs: action.total_duration_ms,
        byType: Object.fromEntries(action.artifacts_by_type),
      })
    }
    case 'ModuleError': {
      if (!matchesCase(state, action.case_id)) return state
      if (state.caseId) {
        trackIngest(state.caseId, { artifactId: action.artifact_id })
      }
      const errors = [
        ...state.errors,
        {
          case_id: action.case_id,
          module_id: action.module_id,
          artifact_id: action.artifact_id,
          error: action.error,
        },
      ]
      // Keep the newest, count the rest. The panel lists the last handful
      // anyway, and the total it prints comes from totalErrorCount, so nothing
      // an examiner reads gets smaller because the buffer filled up.
      const overflow = Math.max(0, errors.length - MAX_RETAINED_ERRORS)
      if (overflow > 0) errors.splice(0, overflow)
      return {
        ...state,
        errors,
        errorsDropped: state.errorsDropped + overflow,
      }
    }
    default:
      return state
  }
}

// ---- What the screen is allowed to claim ----

/**
 * How long an outage must last before the UI retracts its run state.
 *
 * `EventSource` reports every hiccup through `onerror` and the first retry is a
 * second behind it, so most outages are over before an examiner could read a
 * word about them. Announcing each one would make the status bar cry wolf,
 * which is its own kind of dishonesty; this is the point past which silence
 * stops being a blip and starts being a gap in the record.
 */
export const STREAM_DOWN_GRACE_MS = 3_000

/**
 * How long a run may go without a word before its state stops being a claim.
 *
 * `PhaseProgress` lands about every two seconds while a run is alive. A minute
 * of silence on a healthy socket means the run is not talking to us — a server
 * restart, an orchestrator crash — and the last frame we drew is not evidence
 * of anything current.
 */
export const RUN_SILENT_MS = 60_000

/**
 * How long a run may go unmentioned before this client's picture of it counts
 * as having a gap in it.
 *
 * `PhaseProgress` lands about every two seconds while a run is alive, so past
 * this the client is not looking at a cadence, it is looking at silence. Much
 * shorter than RUN_SILENT_MS, which is the point at which the UI retracts the
 * run state outright: this is only the point at which asking the server is
 * worth a round trip.
 */
export const PICTURE_STALE_MS = 10_000

/**
 * Whether this client may have missed something about the run it is showing.
 *
 * Reconciliation is a claim-changing operation — it can end a run on screen —
 * so it is only worth making when something is actually missing. The watchdog
 * and reconnect paths have that precondition built in (RUN_SILENT_MS,
 * STREAM_DOWN_RECHECK_MS, a generation bump). The visibility path had none: it
 * fired on every `visibilitychange`, which an examiner triggers dozens of times
 * an hour, each one an unconditional probe over a perfectly live socket.
 */
export function runPictureIsStale(state: ProcessingState, now: number): boolean {
  if (state.streamDownSince != null) return true
  // Nothing has ever been heard, so there is no cadence to be inside of.
  if (state.lastEventAt == null) return true
  return now - state.lastEventAt >= PICTURE_STALE_MS
}

export type RunStateKind =
  | 'idle'
  | 'processing'
  | 'complete'
  | 'cancelled'
  | 'ended-unobserved'
  | 'unknown'

export interface RunStateDescription {
  kind: RunStateKind
  /** Status text for the always-visible custody strip. */
  label: string
  /** Tone suffix for the strip's `custody-*` class. */
  tone: 'idle' | 'active' | 'done' | 'cancelled' | 'unknown'
  /** True once the stream has been down past the grace window. */
  streamDown: boolean
  /** True when what this says about a run IN FLIGHT is not backed by a live
   *  stream. False for a finished run: a total that was properly observed does
   *  not stop being true because the socket died afterwards — what an outage
   *  costs there is knowledge of anything that happened SINCE, which the label
   *  says instead. */
  unconfirmed: boolean
}

/** `HH:MM:SS UTC`, built by hand: this string is read off the screen into
 *  statements, so it must not vary with the machine's locale. */
export function formatUtcTime(ms: number): string {
  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
}

/**
 * Decide which of the run states this client can honestly claim, and in what
 * words.
 *
 * The stream is a live broadcast with no replay, so the client's picture is
 * only ever "what we last heard". Four situations used to render as two: a live
 * idle case and a case whose stream died looked identical ("idle"), and a live
 * run and a run whose completion event was dropped looked identical
 * ("processing"). Both collapses put a claim on screen the evidence does not
 * support, in the one bar an examiner is taught to read for run state — and the
 * second one also freezes every view behind it, because the completion event is
 * what invalidates the case's queries.
 *
 * Shared by the custody strip and the processing panel so the two cannot say
 * different things about one run.
 */
export function describeRunState(
  state: ProcessingState,
  now: number,
): RunStateDescription {
  const streamDown =
    state.streamDownSince != null && now - state.streamDownSince >= STREAM_DOWN_GRACE_MS
  const silent =
    state.active &&
    state.lastEventAt != null &&
    now - state.lastEventAt >= RUN_SILENT_MS
  const unconfirmed = streamDown || silent
  const downSuffix = streamDown ? ' · event stream down' : ''

  if (state.active) {
    if (unconfirmed) {
      return {
        kind: 'unknown',
        label: streamDown
          ? `run state unknown — event stream down since ${formatUtcTime(state.streamDownSince!)}`
          : `run state unknown — no progress reported since ${formatUtcTime(state.lastEventAt!)}`,
        tone: 'unknown',
        streamDown,
        unconfirmed: true,
      }
    }
    return {
      kind: 'processing',
      label: `processing · ${formatCount(state.processed)} artifacts`,
      tone: 'active',
      streamDown,
      unconfirmed: false,
    }
  }

  // One ending, chosen once. This used to test `endedUnobserved` first and each
  // flag separately, which let a run that both completed and had been
  // reconciled render its completion total and its last-count-heard side by
  // side. Reordering the tests would only have hidden that; the reducer no
  // longer produces the pair (see endRun), and this reads the single ending it
  // does produce.
  const ending = runEnding(state)

  if (ending === 'cancelled') {
    // A cancelled run is not an idle case: it stopped part-way, so what the
    // case holds is a partial result. The always-visible custody bar said
    // "idle" while the processing panel said "cancelled", and the bar is the
    // line an examiner reads for run state (B5-013).
    return {
      kind: 'cancelled',
      label:
        (state.cancelledArtifacts != null
          ? `cancelled · ${formatCount(state.cancelledArtifacts)} artifacts processed`
          : 'cancelled · artifacts processed not reported') + downSuffix,
      tone: 'cancelled',
      streamDown,
      unconfirmed: false,
    }
  }

  if (ending === 'complete') {
    // The total is nullable, and the optional chain this replaced rendered a
    // missing one as the literal "undefined". formatCount reports it with the
    // em dash this codebase uses everywhere else for "not reported".
    return {
      kind: 'complete',
      label: `complete · ${formatCount(state.totalArtifacts)} artifacts` + downSuffix,
      tone: 'done',
      streamDown,
      unconfirmed: false,
    }
  }

  if (ending === 'ended-unobserved') {
    return {
      kind: 'ended-unobserved',
      // The run is over — that much the server confirmed, twice, either side of
      // the interval on which the orchestrator broadcasts. Everything the
      // terminal event would have carried was missed, so no total is offered
      // here and none should be quoted from the last count on screen. The
      // wording does not say "while disconnected": the event can also be lost
      // over a socket that stayed up, and the client cannot tell which.
      label: 'run ended — no completion event received; final total not reported',
      tone: 'unknown',
      streamDown,
      unconfirmed: true,
    }
  }

  if (streamDown) {
    // "idle" is a positive statement about the case, and all the client has to
    // support it is that it has heard nothing. While the socket is down it has
    // no way to hear anything: a colleague may have started a verify run a
    // minute ago and this examiner would write down that the case sat still.
    return {
      kind: 'unknown',
      label: `run state unknown — event stream down since ${formatUtcTime(state.streamDownSince!)}`,
      tone: 'unknown',
      streamDown,
      unconfirmed: true,
    }
  }

  return { kind: 'idle', label: 'idle', tone: 'idle', streamDown, unconfirmed: false }
}
