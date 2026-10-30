import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  clearIngestTracking,
  clearProcessingSnapshot,
  initialProcessing,
  initialProcessingFor,
  isTrackedArtifact,
  loadProcessingSnapshot,
  parseSseJson,
  reduceProcessing,
  saveProcessingSnapshot,
  trackIngest,
  type ProcessingState,
} from './processing'
import {
  getSseConnection,
  resetSseBus,
  subscribeSseConnection,
  subscribeSseEvent,
  type SseConnection,
} from './sse'

beforeEach(() => {
  sessionStorage.clear()
})

describe('parseSseJson', () => {
  it('parses single-encoded payloads', () => {
    expect(parseSseJson('{"a":1}')).toEqual({ a: 1 })
  })

  it('parses double-encoded payloads (current server quirk)', () => {
    const double = JSON.stringify(JSON.stringify({ a: 1 }))
    expect(parseSseJson(double)).toEqual({ a: 1 })
  })

  it('returns null on garbage', () => {
    expect(parseSseJson('not json')).toBeNull()
  })
})

// Events are internally tagged (`event_type`) to match the server's
// `#[serde(tag = "event_type")]` wire format.
describe('reduceProcessing', () => {
  it('activates on PhaseStarted', () => {
    const next = reduceProcessing(initialProcessing, {
      event_type: 'PhaseStarted',
      case_id: 'c',
      phase: 'Ingest',
      artifact_type: 'RawEvidence',
    })
    expect(next.active).toBe(true)
    expect(next.phase).toBe('Ingest')
  })

  it('tracks progress counts by type', () => {
    let state = reduceProcessing(initialProcessing, {
      event_type: 'PhaseStarted',
      case_id: 'c',
      phase: 'Ingest',
      artifact_type: 'RawEvidence',
    })
    state = reduceProcessing(state, {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 42,
      artifacts_by_type: [['FileEntry', 40], ['Partition', 2]],
    })
    expect(state.processed).toBe(42)
    expect(state.byType).toEqual({ FileEntry: 40, Partition: 2 })
  })

  it('records tasks completed and total from PhaseProgress', () => {
    let state = reduceProcessing(initialProcessingFor('c'), {
      event_type: 'PhaseStarted',
      case_id: 'c',
      phase: 'Extract',
      artifact_type: 'FileEntry',
    })
    state = reduceProcessing(state, {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 10,
      artifacts_by_type: [['FileEntry', 10]],
      tasks_completed: 3,
      tasks_total: 12,
    })
    expect(state.tasksCompleted).toBe(3)
    expect(state.tasksTotal).toBe(12)
  })

  it('completes and records errors', () => {
    let state = reduceProcessing(initialProcessing, {
      event_type: 'PhaseStarted',
      case_id: 'c',
      phase: 'Ingest',
      artifact_type: 'RawEvidence',
    })
    state = reduceProcessing(state, {
      event_type: 'ModuleError',
      case_id: 'c',
      module_id: 'mft',
      artifact_id: 'a',
      error: 'boom',
    })
    state = reduceProcessing(state, {
      event_type: 'ProcessingComplete',
      case_id: 'c',
      total_artifacts: 100,
      total_duration_ms: 5000,
      artifacts_by_type: [['FileEntry', 100]],
    })
    expect(state.active).toBe(false)
    expect(state.complete).toBe(true)
    expect(state.totalArtifacts).toBe(100)
    expect(state.errors).toHaveLength(1)
    expect(state.errors[0].module_id).toBe('mft')
  })
})

describe('reduceProcessing case filtering', () => {
  it('ignores case-attributed events from other cases (bleed regression)', () => {
    let state = initialProcessingFor('case-a')
    state = reduceProcessing(state, {
      event_type: 'PhaseStarted',
      case_id: 'case-b',
      phase: 'Ingest',
      artifact_type: 'x',
    })
    expect(state.active).toBe(false)

    state = reduceProcessing(state, {
      event_type: 'PhaseStarted',
      case_id: 'case-a',
      phase: 'Ingest',
      artifact_type: 'x',
    })
    expect(state.active).toBe(true)

    state = reduceProcessing(state, {
      event_type: 'PhaseProgress',
      case_id: 'case-b',
      artifacts_processed: 999,
      artifacts_by_type: [['FileEntry', 999]],
    })
    expect(state.processed).toBe(0)

    state = reduceProcessing(state, {
      event_type: 'ProcessingComplete',
      case_id: 'case-b',
      total_artifacts: 999,
      total_duration_ms: 1,
      artifacts_by_type: [],
    })
    expect(state.complete).toBe(false)
    expect(state.active).toBe(true)

    state = reduceProcessing(state, {
      event_type: 'ModuleError',
      case_id: 'case-b',
      module_id: 'mft',
      artifact_id: 'a',
      error: 'boom',
    })
    expect(state.errors).toHaveLength(0)
  })
})

describe('reduceProcessing new event types', () => {
  afterEach(() => {
    clearIngestTracking('case-a')
  })

  it('records module progress for tracked artifacts', () => {
    trackIngest('case-a', { artifactId: 'art-1' })
    const state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'ModuleProgress',
      module_id: 'mft',
      artifact_id: 'art-1',
      units_done: 512,
      units_total: 1024,
      unit: 'bytes',
    })
    expect(state.modules['mft:art-1']).toMatchObject({
      moduleId: 'mft',
      unitsDone: 512,
      unitsTotal: 1024,
      unit: 'bytes',
    })
  })

  it('drops module progress for untracked artifacts while idle', () => {
    const state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'ModuleProgress',
      module_id: 'mft',
      artifact_id: 'other-case-artifact',
      units_done: 1,
      units_total: null,
      unit: 'items',
    })
    expect(state.modules).toEqual({})
  })

  it('accepts and tracks module progress while this case is active', () => {
    let state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'PhaseStarted',
      case_id: 'case-a',
      phase: 'Extract',
      artifact_type: 'x',
    })
    state = reduceProcessing(state, {
      event_type: 'ModuleProgress',
      module_id: 'registry',
      artifact_id: 'art-2',
      units_done: 3,
      units_total: null,
      unit: 'items',
    })
    expect(state.modules['registry:art-2']).toBeDefined()
    expect(isTrackedArtifact('case-a', 'art-2')).toBe(true)
  })

  it('records acquisition hash progress only for tracked sources', () => {
    trackIngest('case-a', { artifactId: 'art-1', source: '/evidence/disk.dd' })
    let state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'AcquisitionHashProgress',
      case_id: 'case-a',
      source: '/evidence/disk.dd',
      bytes_done: 100,
      bytes_total: 400,
    })
    expect(state.hashing['/evidence/disk.dd']).toMatchObject({
      bytesDone: 100,
      bytesTotal: 400,
    })

    state = reduceProcessing(state, {
      event_type: 'AcquisitionHashProgress',
      case_id: 'case-a',
      source: '/somebody/elses.dd',
      bytes_done: 5,
      bytes_total: 10,
    })
    expect(state.hashing['/somebody/elses.dd']).toBeUndefined()
  })

  it('carries multi-segment set info on the hashing lane', () => {
    trackIngest('case-a', { artifactId: 'art-1', source: '/evidence/001.E01' })
    const state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'AcquisitionHashProgress',
      case_id: 'case-a',
      source: '/evidence/001.E01',
      bytes_done: 100,
      bytes_total: 400,
      segment_count: 18,
      segment_bytes_total: 37_600_000_000,
    })
    expect(state.hashing['/evidence/001.E01']).toMatchObject({
      segmentCount: 18,
      segmentBytesTotal: 37_600_000_000,
    })
  })

  it('records decoded-media hash progress for a tracked artifact and clears it on completion', () => {
    trackIngest('case-a', { artifactId: 'art-1', source: '/evidence/img.E01' })
    let state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'DecodedMediaHashProgress',
      case_id: 'case-a',
      artifact_id: 'art-1',
      bytes_done: 250,
      bytes_total: 1000,
    })
    expect(state.hashing['decoded:art-1']).toMatchObject({
      source: 'Decoded-media verification',
      bytesDone: 250,
      bytesTotal: 1000,
    })

    // An untracked artifact's decoded progress is dropped, like acquisition.
    const foreign = reduceProcessing(state, {
      event_type: 'DecodedMediaHashProgress',
      case_id: 'case-a',
      artifact_id: 'not-tracked',
      bytes_done: 1,
      bytes_total: 2,
    })
    expect(foreign.hashing['decoded:not-tracked']).toBeUndefined()

    // Ingest completion clears the decoded lane too.
    state = reduceProcessing(state, {
      event_type: 'IngestCompleted',
      case_id: 'case-a',
      artifact_id: 'art-1',
    })
    expect(state.hashing['decoded:art-1']).toBeUndefined()
  })

  it('clears the hashing line on IngestCompleted for the tracked artifact', () => {
    trackIngest('case-a', { artifactId: 'art-1', source: '/evidence/disk.dd' })
    let state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'AcquisitionHashProgress',
      case_id: 'case-a',
      source: '/evidence/disk.dd',
      bytes_done: 400,
      bytes_total: 400,
    })
    state = reduceProcessing(state, {
      event_type: 'IngestCompleted',
      case_id: 'case-a',
      artifact_id: 'art-1',
    })
    expect(state.hashing).toEqual({})
  })

  it('marks the run cancelled on ProcessingCancelled while active', () => {
    let state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'PhaseStarted',
      case_id: 'case-a',
      phase: 'Extract',
      artifact_type: 'x',
    })
    state = reduceProcessing(state, {
      event_type: 'ProcessingCancelled',
      artifacts_processed: 57,
    })
    expect(state.active).toBe(false)
    expect(state.cancelled).toBe(true)
    expect(state.cancelledArtifacts).toBe(57)
  })

  it('ignores ProcessingCancelled while idle', () => {
    const state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'ProcessingCancelled',
      artifacts_processed: 57,
    })
    expect(state.cancelled).toBe(false)
  })

  it('clears transient lanes on reconnect', () => {
    trackIngest('case-a', { artifactId: 'art-1', source: '/evidence/disk.dd' })
    let state = reduceProcessing(initialProcessingFor('case-a'), {
      event_type: 'PhaseStarted',
      case_id: 'case-a',
      phase: 'Extract',
      artifact_type: 'x',
    })
    state = reduceProcessing(state, {
      event_type: 'ModuleProgress',
      module_id: 'mft',
      artifact_id: 'art-1',
      units_done: 1,
      units_total: null,
      unit: 'items',
    })
    state = reduceProcessing(state, { type: 'reconnected' })
    expect(state.modules).toEqual({})
    expect(state.hashing).toEqual({})
    expect(state.active).toBe(true)
  })

  it('updates connection state', () => {
    const state = reduceProcessing(initialProcessingFor('case-a'), {
      type: 'connection',
      connectionState: 'reconnecting',
    })
    expect(state.connectionState).toBe('reconnecting')
  })
})

describe('reduceProcessing live-processing fields', () => {
  const start = (caseId = 'c') =>
    reduceProcessing(initialProcessingFor(caseId), {
      event_type: 'PhaseStarted',
      case_id: caseId,
      phase: 'Extract',
      artifact_type: 'x',
    })

  it('captures rate, eta, discovering and active modules from PhaseProgress', () => {
    const state = reduceProcessing(start(), {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 500,
      artifacts_by_type: [['FileEntry', 500]],
      tasks_completed: 3,
      tasks_total: 10,
      rate_per_sec: 1540,
      eta_seconds: 130,
      discovering: false,
      active_modules: ['plugin.ntfs.mft_parser'],
    })
    expect(state.ratePerSec).toBe(1540)
    expect(state.etaSeconds).toBe(130)
    expect(state.discovering).toBe(false)
    expect(state.activeModules).toEqual(['plugin.ntfs.mft_parser'])
    expect(state.taskPct).toBe(30)
  })

  it('holds a null eta and leaves taskPct at zero while discovering', () => {
    const state = reduceProcessing(start(), {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 10,
      artifacts_by_type: [],
      tasks_completed: 4,
      tasks_total: 8,
      rate_per_sec: 20,
      eta_seconds: null,
      discovering: true,
    })
    expect(state.discovering).toBe(true)
    expect(state.etaSeconds).toBeNull()
    expect(state.ratePerSec).toBe(20)
    // Denominator is untrusted while discovering, so no percentage floor yet.
    expect(state.taskPct).toBe(0)
  })

  it('keeps the task percentage floor monotonic when the total grows', () => {
    let state = reduceProcessing(start(), {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 0,
      artifacts_by_type: [],
      tasks_completed: 9,
      tasks_total: 10,
      discovering: false,
    })
    expect(state.taskPct).toBe(90)
    // Total jumps up (late discovery) — the raw percentage would drop.
    state = reduceProcessing(state, {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 0,
      artifacts_by_type: [],
      tasks_completed: 9,
      tasks_total: 100,
      discovering: false,
    })
    expect(state.taskPct).toBe(90)
  })

  it('smooths the live count with ArtifactBatch and reconciles on PhaseProgress', () => {
    let state = reduceProcessing(start(), {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 100,
      artifacts_by_type: [['FileEntry', 100]],
    })
    expect(state.liveCount).toBe(100)
    state = reduceProcessing(state, { event_type: 'ArtifactBatch', count: 50 })
    expect(state.liveCount).toBe(150)
    expect(state.processed).toBe(100)
    state = reduceProcessing(state, {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 160,
      artifacts_by_type: [['FileEntry', 160]],
    })
    expect(state.liveCount).toBe(160)
  })

  it('ignores ArtifactBatch while idle', () => {
    const state = reduceProcessing(initialProcessingFor('c'), {
      event_type: 'ArtifactBatch',
      count: 50,
    })
    expect(state.liveCount).toBe(0)
  })

  it('ignores an ArtifactBatch belonging to another case (B2-043)', () => {
    // One SSE stream carries every case the viewer may see. Counting another
    // case's batches here inflated the open case's live count and the ETA
    // derived from it, reporting progress that never happened for this case.
    let state = reduceProcessing(start(), {
      event_type: 'PhaseProgress',
      case_id: 'c',
      artifacts_processed: 100,
      artifacts_by_type: [['FileEntry', 100]],
    })
    state = reduceProcessing(state, {
      event_type: 'ArtifactBatch',
      case_id: 'other-case',
      count: 5000,
    })
    expect(state.liveCount).toBe(100)

    state = reduceProcessing(state, {
      event_type: 'ArtifactBatch',
      case_id: 'c',
      count: 7,
    })
    expect(state.liveCount).toBe(107)
  })
})

describe('processing snapshot persistence', () => {
  it('round-trips an active snapshot per case', () => {
    const state: ProcessingState = {
      ...initialProcessingFor('case-a'),
      active: true,
      phase: 'Extract',
      processed: 10,
    }
    saveProcessingSnapshot(state)
    const restored = loadProcessingSnapshot('case-a')
    expect(restored).toMatchObject({ active: true, phase: 'Extract', processed: 10 })
    expect(loadProcessingSnapshot('case-b')).toBeNull()
  })

  it('restores with a live connection state', () => {
    saveProcessingSnapshot({
      ...initialProcessingFor('case-a'),
      active: true,
      connectionState: 'reconnecting',
    })
    expect(loadProcessingSnapshot('case-a')?.connectionState).toBe('live')
  })

  it('expires snapshots older than the TTL', () => {
    vi.useFakeTimers()
    try {
      saveProcessingSnapshot({ ...initialProcessingFor('case-a'), active: true })
      vi.advanceTimersByTime(16 * 60 * 1000)
      expect(loadProcessingSnapshot('case-a')).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('clears snapshots', () => {
    saveProcessingSnapshot({ ...initialProcessingFor('case-a'), active: true })
    clearProcessingSnapshot('case-a')
    expect(loadProcessingSnapshot('case-a')).toBeNull()
  })
})

// ---- The tab's single event stream ----

type BusListener = (event: MessageEvent) => void

class MockSource {
  static instances: MockSource[] = []
  url: string
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  closed = false
  listeners = new Map<string, Set<BusListener>>()

  constructor(url: string) {
    this.url = url
    MockSource.instances.push(this)
  }

  addEventListener(name: string, listener: BusListener) {
    if (!this.listeners.has(name)) this.listeners.set(name, new Set())
    this.listeners.get(name)!.add(listener)
  }

  removeEventListener(name: string, listener: BusListener) {
    this.listeners.get(name)?.delete(listener)
  }

  close() {
    this.closed = true
  }

  emit(name: string, payload: unknown) {
    const event = { data: JSON.stringify(payload), type: name } as MessageEvent
    for (const listener of this.listeners.get(name) ?? []) listener(event)
  }
}

const openSource = () => MockSource.instances[MockSource.instances.length - 1]

describe('the shared /api/v1/events bus', () => {
  beforeEach(() => {
    MockSource.instances = []
    vi.stubGlobal('EventSource', MockSource)
    vi.useFakeTimers()
    resetSseBus()
  })

  afterEach(() => {
    resetSseBus()
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('opens one connection however many watchers subscribe', () => {
    // Browsers allow about six concurrent connections per origin. Every watcher
    // that opened its own stream spent part of a budget shared with every other
    // case tab, and the tab that lost the race got no processing stream at all:
    // it reconnects forever behind a run state nothing is updating.
    const seenA: unknown[] = []
    const seenB: unknown[] = []
    const offA = subscribeSseEvent('module_progress', (e) => seenA.push(e.data))
    const offB = subscribeSseEvent('module_progress', (e) => seenB.push(e.data))
    const offC = subscribeSseEvent('artifact_batch', () => {})

    expect(MockSource.instances).toHaveLength(1)
    openSource().emit('module_progress', { units_done: 1 })
    expect(seenA).toHaveLength(1)
    expect(seenB).toHaveLength(1)

    offA()
    openSource().emit('module_progress', { units_done: 2 })
    expect(seenA).toHaveLength(1)
    expect(seenB).toHaveLength(2)

    // The connection is held for as long as anyone is listening, and released
    // when the last one goes.
    offB()
    expect(openSource().closed).toBe(false)
    offC()
    expect(openSource().closed).toBe(true)
  })

  it('reconnects with backoff and reports the outage while it lasts', () => {
    const seen: SseConnection[] = []
    subscribeSseConnection((c) => seen.push(c))
    // A subscriber is told the current state at once, so one that arrives
    // during an outage does not have to wait for the next transition to find
    // out the stream is down.
    expect(seen).toHaveLength(1)
    expect(seen[0].status).toBe('live')

    openSource().onopen!()
    expect(getSseConnection().generation).toBe(1)

    openSource().onerror!()
    expect(getSseConnection().status).toBe('reconnecting')
    expect(getSseConnection().downSince).toBeTypeOf('number')
    expect(MockSource.instances).toHaveLength(1)

    vi.advanceTimersByTime(999)
    expect(MockSource.instances).toHaveLength(1)
    vi.advanceTimersByTime(1)
    expect(MockSource.instances).toHaveLength(2)

    // Second consecutive failure backs off further.
    openSource().onerror!()
    vi.advanceTimersByTime(1999)
    expect(MockSource.instances).toHaveLength(2)
    vi.advanceTimersByTime(1)
    expect(MockSource.instances).toHaveLength(3)

    openSource().onopen!()
    const now = getSseConnection()
    expect(now.status).toBe('live')
    expect(now.downSince).toBeNull()
    // The generation is how a subscriber learns it was disconnected, and
    // therefore that it may have missed events it will never be sent again.
    expect(now.generation).toBe(2)
  })

  it('re-attaches every subscription to the replacement connection', () => {
    const seen: unknown[] = []
    subscribeSseEvent('processing_status', (e) => seen.push(e.data))
    openSource().onopen!()
    openSource().onerror!()
    vi.advanceTimersByTime(1000)
    openSource().onopen!()
    openSource().emit('processing_status', { event_type: 'PhaseStarted' })
    expect(seen).toHaveLength(1)
  })

  it('stops retrying once the last subscriber has gone', () => {
    const off = subscribeSseEvent('module_progress', () => {})
    openSource().onerror!()
    off()
    vi.advanceTimersByTime(60_000)
    expect(MockSource.instances).toHaveLength(1)
  })
})

describe('a snapshot written by an older build', () => {
  it('is filled in from the defaults rather than restored with holes in it', () => {
    // sessionStorage outlives a deploy inside one tab session, so this is the
    // shape a client one version behind wrote: no errorsDropped, no liveness
    // bookkeeping. Spread bare, those come back `undefined` and every count
    // derived from them renders as NaN.
    sessionStorage.setItem(
      'seance.processing.case-old',
      JSON.stringify({
        savedAt: Date.now(),
        state: {
          caseId: 'case-old',
          connectionState: 'live',
          active: true,
          complete: false,
          phase: 'Extract',
          processed: 12,
          byType: {},
          totalArtifacts: null,
          durationMs: null,
          errors: [],
          tasksCompleted: null,
          tasksTotal: null,
          liveCount: 12,
          ratePerSec: null,
          etaSeconds: null,
          discovering: false,
          activeModules: [],
          taskPct: 0,
          modules: {},
          hashing: {},
          cancelled: false,
          cancelledArtifacts: null,
        },
      }),
    )
    const restored = loadProcessingSnapshot('case-old')!
    expect(restored.active).toBe(true)
    expect(restored.errorsDropped).toBe(0)
    expect(restored.endedUnobserved).toBe(false)
    expect(restored.streamDownSince).toBeNull()
  })

  it('dates the restored picture from when it was written', () => {
    // The snapshot is what the tab last saw, not what is happening now: a run
    // that ended during a lid-close used to be re-asserted as live for the
    // whole 15-minute TTL, with no event left to correct it.
    const state = { ...initialProcessingFor('case-b'), active: true, phase: 'Extract' }
    const savedAt = Date.now() - 4 * 60_000
    sessionStorage.setItem(
      'seance.processing.case-b',
      JSON.stringify({ savedAt, state }),
    )
    expect(loadProcessingSnapshot('case-b')?.lastEventAt).toBe(savedAt)
  })
})
