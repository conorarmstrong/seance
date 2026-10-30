// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest'
import {
  acceptsCancel,
  clearIngestTracking,
  describeRunState,
  initialProcessingFor,
  isForeignCase,
  MAX_RETAINED_ERRORS,
  PICTURE_STALE_MS,
  reduceProcessing,
  runEnding,
  runPictureIsStale,
  totalErrorCount,
  type ProcessingAction,
  type ProcessingState,
} from './processing'

const CASE_A = '11111111-1111-1111-1111-111111111111'
const CASE_B = '22222222-2222-2222-2222-222222222222'

// An active shell tracking case A.
function activeShellForA() {
  return { ...initialProcessingFor(CASE_A), active: true }
}

describe('reduceProcessing case_id attribution (BUG-166)', () => {
  afterEach(() => {
    clearIngestTracking(CASE_A)
    clearIngestTracking(CASE_B)
  })

  it('drops a ModuleProgress that names a different case', () => {
    const state = activeShellForA()
    const next = reduceProcessing(state, {
      event_type: 'ModuleProgress',
      case_id: CASE_B,
      module_id: 'plugin.x',
      artifact_id: 'artifact-in-B',
      units_done: 1,
      units_total: 10,
      unit: 'bytes',
    })
    // Foreign event is ignored: same state, no module lane, no tainting.
    expect(next).toBe(state)
    expect(Object.keys(next.modules)).toHaveLength(0)
  })

  it('applies a ModuleProgress for its own case', () => {
    const state = activeShellForA()
    const next = reduceProcessing(state, {
      event_type: 'ModuleProgress',
      case_id: CASE_A,
      module_id: 'plugin.x',
      artifact_id: 'artifact-in-A',
      units_done: 5,
      units_total: 10,
      unit: 'bytes',
    })
    expect(Object.keys(next.modules)).toHaveLength(1)
  })

  it('ignores a ProcessingCancelled scoped to another case', () => {
    const state = activeShellForA()
    const next = reduceProcessing(state, {
      event_type: 'ProcessingCancelled',
      case_id: CASE_B,
      artifacts_processed: 3,
    })
    expect(next).toBe(state)
    expect(next.cancelled).toBe(false)
    expect(next.active).toBe(true)
  })

  it('honours a ProcessingCancelled for its own case', () => {
    const state = activeShellForA()
    const next = reduceProcessing(state, {
      event_type: 'ProcessingCancelled',
      case_id: CASE_A,
      artifacts_processed: 3,
    })
    expect(next.cancelled).toBe(true)
    expect(next.active).toBe(false)
  })

  it('still accepts an unscoped (legacy) event with no case_id', () => {
    const state = activeShellForA()
    const next = reduceProcessing(state, {
      event_type: 'ModuleProgress',
      module_id: 'plugin.x',
      artifact_id: 'legacy-artifact',
      units_done: 2,
      units_total: 4,
      unit: 'bytes',
    })
    expect(Object.keys(next.modules)).toHaveLength(1)
  })
})

/**
 * The reducer and the cancel toast must answer the same question.
 *
 * They used to be two expressions over two different subjects: the reducer
 * tested `state.caseId`, the toast in `useProcessingEvents` tested the hook's
 * own `caseId` prop. Those part company on any state whose `caseId` is null —
 * the reducer applies the foreign cancel and tears the shell down, the toast
 * says nothing, and the examiner is left with a run that stopped and no
 * explanation for it. `acceptsCancel` is the reducer's own question, exported
 * so the toast asks that one rather than an expression of its own; this pins
 * the equivalence so they cannot drift apart again.
 */
describe('the cancel toast and the reducer agree on which cancels count', () => {
  const cancel = (caseId?: string) => ({
    event_type: 'ProcessingCancelled' as const,
    case_id: caseId,
    artifacts_processed: 3,
  })

  const cases: {
    label: string
    state: () => ProcessingState
    eventCaseId?: string
  }[] = [
    { label: 'own case', state: activeShellForA, eventCaseId: CASE_A },
    { label: 'another case', state: activeShellForA, eventCaseId: CASE_B },
    { label: 'unscoped event', state: activeShellForA, eventCaseId: undefined },
    {
      label: 'unattributed state, scoped event',
      state: () => ({ ...activeShellForA(), caseId: null }),
      eventCaseId: CASE_B,
    },
    {
      label: 'unattributed state, unscoped event',
      state: () => ({ ...activeShellForA(), caseId: null }),
      eventCaseId: undefined,
    },
    { label: 'an idle case', state: () => initialProcessingFor(CASE_A), eventCaseId: CASE_A },
    {
      // The one the toast used to get wrong on its own: reconciliation has
      // already ended the run, so `active` is false, but the cancel still lands.
      label: 'a run reconciliation already ended',
      state: () =>
        reduceProcessing(activeShellForA(), { type: 'run-ended-unobserved' }),
      eventCaseId: CASE_A,
    },
  ]

  for (const { label, state: makeState, eventCaseId } of cases) {
    it(`agrees for a cancel from ${label}`, () => {
      const state = makeState()
      const action = cancel(eventCaseId)
      const reducerApplied = reduceProcessing(state, action).cancelled
      const toastAnnounces = acceptsCancel(state, action.case_id)
      expect(toastAnnounces).toBe(reducerApplied)
    })
  }

  it('still calls another case s cancel foreign', () => {
    expect(isForeignCase(activeShellForA(), CASE_B)).toBe(true)
  })
})

describe('a cancelled run does not come back to life (B6-031)', () => {
  it('ignores a PhaseProgress that arrives after the cancel', () => {
    const cancelled = reduceProcessing(activeShellForA(), {
      event_type: 'ProcessingCancelled',
      case_id: CASE_A,
      artifacts_processed: 42,
    })
    expect(cancelled.cancelled).toBe(true)
    expect(cancelled.active).toBe(false)

    // A progress frame the worker had already sent when the cancel landed.
    // Applying it flipped the shell back to "processing" and cleared the
    // cancel, so the run then read as complete when the final event arrived.
    const late = reduceProcessing(cancelled, {
      event_type: 'PhaseProgress',
      case_id: CASE_A,
      artifacts_processed: 99,
      artifacts_by_type: [],
      tasks_completed: 9,
      tasks_total: 10,
    })
    expect(late).toBe(cancelled)
    expect(late.cancelled).toBe(true)
    expect(late.active).toBe(false)
    expect(late.processed).toBe(cancelled.processed)
  })

  it('a genuinely new run clears the cancel through PhaseStarted', () => {
    const cancelled = reduceProcessing(activeShellForA(), {
      event_type: 'ProcessingCancelled',
      case_id: CASE_A,
      artifacts_processed: 42,
    })
    const restarted = reduceProcessing(cancelled, {
      event_type: 'PhaseStarted',
      case_id: CASE_A,
      phase: 'ingest',
      artifact_type: 'DiskImage',
    })
    expect(restarted.cancelled).toBe(false)
    expect(restarted.active).toBe(true)

    const progress = reduceProcessing(restarted, {
      event_type: 'PhaseProgress',
      case_id: CASE_A,
      artifacts_processed: 7,
      artifacts_by_type: [],
      tasks_completed: 1,
      tasks_total: 10,
    })
    expect(progress.active).toBe(true)
    expect(progress.processed).toBe(7)
  })
})

/**
 * The four states an examiner has to be able to tell apart.
 *
 * The stream is a live broadcast with no replay: an event missed while the
 * laptop slept, the VPN blipped or the server restarted is gone for good. So
 * "processing" heard ten minutes ago over a socket that has since died is not
 * the same claim as "processing" heard a second ago over a live one, and "idle"
 * is a positive statement the client can only make while it is actually
 * listening. `describeRunState` is the one place that decides which of those
 * four things is true, so the always-visible custody strip and the processing
 * panel cannot drift into saying different things about one run.
 */
describe('describeRunState', () => {
  const NOW = 1_700_000_000_000

  const live = (over: Partial<ProcessingState> = {}): ProcessingState => ({
    ...initialProcessingFor(CASE_A),
    lastEventAt: NOW - 1_000,
    ...over,
  })

  it('reports a live idle case as idle', () => {
    const run = describeRunState(live(), NOW)
    expect(run.kind).toBe('idle')
    expect(run.label).toBe('idle')
    expect(run.unconfirmed).toBe(false)
  })

  it('reports a live run as processing, with the count it heard', () => {
    const run = describeRunState(live({ active: true, processed: 1204331 }), NOW)
    expect(run.kind).toBe('processing')
    expect(run.label).toBe('processing · 1,204,331 artifacts')
    expect(run.unconfirmed).toBe(false)
  })

  it('will not say "idle" while the event stream is down', () => {
    // "idle" in an always-on status bar is a positive claim about the case. All
    // the client actually knows during an outage is that it has heard nothing —
    // a colleague may have started a verify run a minute ago.
    const run = describeRunState(
      live({ streamDownSince: NOW - 30_000, connectionState: 'reconnecting' }),
      NOW,
    )
    expect(run.kind).toBe('unknown')
    expect(run.streamDown).toBe(true)
    expect(run.label).toMatch(/^run state unknown — event stream down since /)
    expect(run.label).not.toMatch(/idle/)
  })

  it('rides out an outage shorter than the grace window without changing its claim', () => {
    // EventSource fires onerror on any hiccup and the first retry is a second
    // later. Retracting the run state for every blip would make the bar cry
    // wolf, which is its own kind of lie.
    const run = describeRunState(
      live({ active: true, processed: 12, streamDownSince: NOW - 500 }),
      NOW,
    )
    expect(run.kind).toBe('processing')
    expect(run.streamDown).toBe(false)
  })

  it('stops asserting a running run once the stream has been down past the grace window', () => {
    const run = describeRunState(
      live({ active: true, processed: 1204331, streamDownSince: NOW - 30_000 }),
      NOW,
    )
    expect(run.kind).toBe('unknown')
    expect(run.unconfirmed).toBe(true)
    // The count is deliberately absent: a figure printed beside "unknown" is a
    // figure that gets quoted, and this one may be half an hour stale.
    expect(run.label).not.toMatch(/1,204,331/)
  })

  it('stops asserting a running run that has gone silent on a live stream', () => {
    // A server restart mid-run leaves the socket healthy and the run gone.
    // PhaseProgress arrives about every two seconds while a run is alive.
    const run = describeRunState(
      live({ active: true, processed: 40, lastEventAt: NOW - 90_000 }),
      NOW,
    )
    expect(run.kind).toBe('unknown')
    expect(run.streamDown).toBe(false)
    expect(run.label).toMatch(/no progress reported since /)
  })

  it('reports a reconciled disconnect-ending as ended, without inventing a total', () => {
    const ended = reduceProcessing(
      { ...live({ active: true, processed: 1204331 }) },
      { type: 'run-ended-unobserved', at: NOW },
    )
    expect(ended.active).toBe(false)
    // Not `complete`: no ProcessingComplete was ever seen, so there is no
    // final total and the panel must not print one.
    expect(ended.complete).toBe(false)
    expect(ended.totalArtifacts).toBeNull()
    expect(ended.endedUnobserved).toBe(true)

    const run = describeRunState(ended, NOW)
    expect(run.kind).toBe('ended-unobserved')
    expect(run.label).toBe(
      'run ended — no completion event received; final total not reported',
    )
  })

  it('leaves an idle case alone when reconciliation says nothing is running', () => {
    const state = live()
    expect(reduceProcessing(state, { type: 'run-ended-unobserved', at: NOW })).toBe(state)
  })

  it('keeps observed terminal facts but says the stream is down', () => {
    const complete = describeRunState(
      live({ complete: true, totalArtifacts: 250, streamDownSince: NOW - 30_000 }),
      NOW,
    )
    expect(complete.kind).toBe('complete')
    expect(complete.label).toBe('complete · 250 artifacts · event stream down')
  })
})

/**
 * A run has ONE ending, and an ending this client heard outranks one it
 * inferred from an absence.
 *
 * `GET /status` answers with the process-wide in-flight count, which the
 * orchestrator's RAII guards drop to zero the instant the last task finishes —
 * but the orchestrator only broadcasts the terminal event on its next
 * two-second tick. So there is a window in which "nothing is running" is true
 * and the completion event is still on its way, and any reconciliation that
 * samples inside it concludes the run ended unobserved. When the real event
 * arrived a second later, nothing cleared that conclusion: the panel rendered
 * the completion total AND the last count heard, side by side, under a title
 * saying no completion event had ever reached this browser. Two different
 * artifact totals for one run, in the surface an examiner quotes.
 */
describe('a later observation supersedes an inferred ending', () => {
  const NOW = 1_700_000_000_000

  /** A run reconciliation ended without ever seeing a terminal event. */
  const reconciledEnding = () =>
    reduceProcessing(
      {
        ...initialProcessingFor(CASE_A),
        active: true,
        processed: 389204,
        liveCount: 389204,
        lastEventAt: NOW - 1_000,
      },
      { type: 'run-ended-unobserved', at: NOW },
    )

  const completion = {
    event_type: 'ProcessingComplete' as const,
    case_id: CASE_A,
    total_artifacts: 412806,
    total_duration_ms: 41_200,
    artifacts_by_type: [['FileEntry', 412806]] as [string, number][],
  }

  it('lets the completion event that arrives a second later take over', () => {
    const ended = reconciledEnding()
    expect(ended.endedUnobserved).toBe(true)

    const complete = reduceProcessing(ended, completion)
    expect(complete.endedUnobserved).toBe(false)
    expect(complete.complete).toBe(true)
    expect(complete.totalArtifacts).toBe(412806)
    expect(runEnding(complete)).toBe('complete')

    const run = describeRunState(complete, NOW)
    expect(run.kind).toBe('complete')
    expect(run.label).toBe('complete · 412,806 artifacts')
    expect(run.label).not.toMatch(/no completion event received/)
  })

  it('lets a cancel land after reconciliation, with the claim only it can make', () => {
    // "cancelled — 389,204 artifacts processed" and "ended, no completion event
    // received" are different statements about what the case now holds. The
    // examiner who pressed Stop is entitled to the first one, and the cancel
    // routinely arrives behind the drain that reconciliation sampled (B5-013).
    const cancelled = reduceProcessing(reconciledEnding(), {
      event_type: 'ProcessingCancelled',
      case_id: CASE_A,
      artifacts_processed: 389204,
    })
    expect(cancelled.cancelled).toBe(true)
    expect(cancelled.cancelledArtifacts).toBe(389204)
    expect(cancelled.endedUnobserved).toBe(false)
    expect(runEnding(cancelled)).toBe('cancelled')
    expect(describeRunState(cancelled, NOW).label).toBe(
      'cancelled · 389,204 artifacts processed',
    )
  })

  it('puts the run back when a progress frame proves it never ended', () => {
    // An inference drawn from silence is retracted by traffic. This is the
    // opposite of B6-031 on purpose: `cancelled` is an event this client SAW,
    // and a straggling frame does not undo it. `endedUnobserved` is a guess.
    const revived = reduceProcessing(reconciledEnding(), {
      event_type: 'PhaseProgress',
      case_id: CASE_A,
      artifacts_processed: 400000,
      artifacts_by_type: [],
    })
    expect(revived.active).toBe(true)
    expect(revived.endedUnobserved).toBe(false)
    expect(runEnding(revived)).toBeNull()
    expect(describeRunState(revived, Date.now()).kind).toBe('processing')
  })

  it('still picks up a new run whose PhaseStarted this client never heard', () => {
    // The reason `complete` is not in the PhaseProgress guard alongside
    // `cancelled`. A shell holding a finished run, a socket that was down
    // across the next run's PhaseStarted, and then frames for that run: the
    // frames are all this client will ever get to learn a run is in flight, so
    // they have to be allowed to say so.
    const finished = reduceProcessing(activeShellForA(), completion)
    expect(finished.complete).toBe(true)

    const next = reduceProcessing(finished, {
      event_type: 'PhaseProgress',
      case_id: CASE_A,
      artifacts_processed: 12,
      artifacts_by_type: [],
    })
    expect(next.active).toBe(true)
    expect(describeRunState(next, Date.now()).kind).toBe('processing')
  })

  it('never holds two endings at once, whichever order the events arrive in', () => {
    const cancel = {
      event_type: 'ProcessingCancelled' as const,
      case_id: CASE_A,
      artifacts_processed: 12,
    }
    const reconcile = { type: 'run-ended-unobserved' as const }
    const terminals: ProcessingAction[] = [completion, cancel, reconcile]

    for (const first of terminals) {
      for (const second of terminals) {
        const state = reduceProcessing(
          reduceProcessing(activeShellForA(), first),
          second,
        )
        const held = [state.complete, state.cancelled, state.endedUnobserved]
        expect(held.filter(Boolean)).toHaveLength(1)
        // ...and the total on screen belongs to the ending that is held.
        if (!state.complete) expect(state.totalArtifacts).toBeNull()
        if (!state.cancelled) expect(state.cancelledArtifacts).toBeNull()
      }
    }
  })
})

/**
 * Returning to a tab is the moment this client is most likely to be holding a
 * picture from before a gap it never noticed — but it is also something an
 * examiner does dozens of times an hour, and every one of those used to be an
 * unconditional `/status` probe that could land inside the orchestrator's emit
 * window and end a healthy run on screen. The watchdog and reconnect paths ask
 * only when something is actually missing; this is that precondition, so the
 * visibility path can ask the same question of itself.
 */
describe('runPictureIsStale', () => {
  const NOW = 1_700_000_000_000

  it('is false for a run that was talked about a moment ago', () => {
    const state = { ...initialProcessingFor(CASE_A), active: true, lastEventAt: NOW - 2_000 }
    expect(runPictureIsStale(state, NOW)).toBe(false)
  })

  it('is true once the run has gone unmentioned for longer than the cadence', () => {
    const state = {
      ...initialProcessingFor(CASE_A),
      active: true,
      lastEventAt: NOW - PICTURE_STALE_MS,
    }
    expect(runPictureIsStale(state, NOW)).toBe(true)
  })

  it('is true while the stream is down, however recent the last event was', () => {
    const state = {
      ...initialProcessingFor(CASE_A),
      active: true,
      lastEventAt: NOW - 100,
      streamDownSince: NOW - 100,
    }
    expect(runPictureIsStale(state, NOW)).toBe(true)
  })

  it('is true when this client has never heard anything at all', () => {
    const state = { ...initialProcessingFor(CASE_A), active: true, lastEventAt: null }
    expect(runPictureIsStale(state, NOW)).toBe(true)
  })
})

describe('stream liveness bookkeeping', () => {
  const NOW = 1_700_000_000_000

  it('records when the stream went down and clears it on reconnect', () => {
    const down = reduceProcessing(initialProcessingFor(CASE_A), {
      type: 'connection',
      connectionState: 'reconnecting',
      at: NOW,
    })
    expect(down.streamDownSince).toBe(NOW)
    const up = reduceProcessing(down, { type: 'connection', connectionState: 'live' })
    expect(up.streamDownSince).toBeNull()
  })

  it('timestamps events it acted on, and only those', () => {
    const state = { ...initialProcessingFor(CASE_A), active: true, lastEventAt: null }
    const ours = reduceProcessing(state, {
      event_type: 'PhaseProgress',
      case_id: CASE_A,
      artifacts_processed: 5,
      artifacts_by_type: [],
    })
    expect(ours.lastEventAt).toBeGreaterThan(0)

    // Another case's traffic proves the socket is alive but says nothing about
    // this run, so it must not pass for progress on this case.
    const theirs = reduceProcessing(state, {
      event_type: 'PhaseProgress',
      case_id: CASE_B,
      artifacts_processed: 900,
      artifacts_by_type: [],
    })
    expect(theirs.lastEventAt).toBeNull()
  })
})

describe('the module-error list stays bounded and the count stays honest', () => {
  it('caps the retained errors and counts what it dropped', () => {
    let state: ProcessingState = { ...initialProcessingFor(CASE_A), active: true }
    for (let i = 0; i < MAX_RETAINED_ERRORS + 50; i++) {
      state = reduceProcessing(state, {
        event_type: 'ModuleError',
        case_id: CASE_A,
        module_id: 'plugin.x',
        artifact_id: `art-${i}`,
        error: 'boom',
      })
    }
    expect(state.errors).toHaveLength(MAX_RETAINED_ERRORS)
    expect(state.errorsDropped).toBe(50)
    // The number an examiner reads is still the number that happened.
    expect(totalErrorCount(state)).toBe(MAX_RETAINED_ERRORS + 50)
    // The newest errors are the ones kept.
    expect(state.errors[state.errors.length - 1].artifact_id).toBe(
      `art-${MAX_RETAINED_ERRORS + 49}`,
    )
  })
})
