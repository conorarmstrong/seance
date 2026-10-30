import { useEffect, useState, type ReactElement } from 'react'
import {
  describeRunState,
  formatUtcTime,
  runEnding,
  totalErrorCount,
} from '../../hooks/processing'
import type {
  ModuleActivity,
  ProcessingState,
  RunEndingKind,
} from '../../hooks/processing'
import { formatBytes, formatCount, formatDecimal } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { useToast } from '../toast/ToastProvider'
import { cancelProcessing } from './api'
import './processing.css'

/**
 * Where the collapsed/expanded choice is kept.
 *
 * A preference about this examiner's own screen, not about the case, so it is
 * per-browser and deliberately outside the run scope: collapsing the panel
 * during one ingest should not silently re-open it for the next.
 */
const COLLAPSED_KEY = 'seance_processing_collapsed'

/** Read the stored preference, treating any storage failure as "expanded". */
function loadCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === '1'
  } catch {
    // Private windows and blocked site data throw on access rather than
    // returning null. The panel opens; nothing is lost but the preference.
    return false
  }
}

function storeCollapsed(collapsed: boolean) {
  try {
    localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0')
  } catch {
    // Not worth a toast: the panel still collapses for this session.
  }
}

/** Module lines with no update for this long fade out. */
const STALE_MS = 60_000
/** ... and are dropped from the panel entirely after this long. */
const DROP_MS = 120_000
const MAX_MODULE_LINES = 5
/** How many module-error lines the disclosure lists. Every error past this one
 *  is still counted in the summary above the list, and the note below the list
 *  says how many of them are not shown. */
const MAX_ERROR_LINES = 10

function basename(path: string): string {
  return path.split('/').pop() || path
}

function percent(done: number, total: number): number {
  if (total <= 0) return 0
  if (done >= total) return 100
  // 100 means done, and only done. Rounding gets there early — 148,215 of
  // 148,216 rounds to 100 while a task is still outstanding — so floor, and cap
  // below 100 until every unit is accounted for. Do NOT round up off zero
  // either: a run that has done nothing must not report 1%. A visible sliver on
  // the bar is CSS's job, not the number's.
  return Math.min(99, Math.floor((done / total) * 100))
}

/** Friendly names for the heavy modules; unknown dotted ids are prettified. */
const MODULE_NAMES: Record<string, string> = {
  'plugin.ntfs.mft_parser': 'NTFS MFT parser',
  'plugin.fs.ext4': 'ext4 filesystem',
  'plugin.disk.partition_parser': 'Partition table',
  'plugin.search.indexer': 'Search index',
  'plugin.recovery.unallocated_carver': 'Carving unallocated',
  'verify.integrity': 'Integrity verification',
}

function humanizeModuleId(id: string): string {
  if (MODULE_NAMES[id]) return MODULE_NAMES[id]
  // Bare tokens (no dot) are left as-is; dotted plugin ids get the last
  // segment prettified: `plugin.x.foo_bar` -> "Foo bar".
  if (!id.includes('.')) return id
  const seg = id.split('.').pop() ?? id
  return seg.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
}

/** Compact duration: "45s", "2m 10s", "1h 3m". */
function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s}s`
  if (s < 3600) {
    const m = Math.floor(s / 60)
    const rem = s % 60
    return rem === 0 ? `${m}m` : `${m}m ${rem}s`
  }
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return m === 0 ? `${h}h` : `${h}h ${m}m`
}

/** Humanised throughput, e.g. "1,540 artifacts/sec". */
function formatRate(rate: number): string {
  const value =
    rate >= 10 ? formatCount(Math.round(rate)) : formatDecimal(rate, 1)
  return `${value} artifacts/sec`
}

function Bar({ pct, indeterminate }: { pct?: number; indeterminate?: boolean }) {
  return (
    <div className="processing-bar" role="progressbar" aria-valuenow={pct}>
      <div
        className={`processing-bar-fill${indeterminate ? ' indeterminate' : ''}`}
        style={indeterminate ? undefined : { width: `${pct ?? 0}%` }}
      />
    </div>
  )
}

function ModuleLine({ activity, now }: { activity: ModuleActivity; now: number }) {
  const stale = now - activity.updatedAt > STALE_MS
  const label =
    activity.unit === 'bytes'
      ? activity.unitsTotal != null
        ? `${formatBytes(activity.unitsDone)} of ${formatBytes(activity.unitsTotal)}`
        : formatBytes(activity.unitsDone)
      : activity.unitsTotal != null
        ? `${formatCount(activity.unitsDone)} of ${formatCount(activity.unitsTotal)} ${activity.unit}`
        : `${formatCount(activity.unitsDone)} ${activity.unit}`
  return (
    <div className={`processing-module-line${stale ? ' stale' : ''}`}>
      <span className="processing-module-name">
        {humanizeModuleId(activity.moduleId)}
      </span>
      <span className="processing-module-count mono">{label}</span>
      {activity.unitsTotal != null ? (
        <Bar pct={percent(activity.unitsDone, activity.unitsTotal)} />
      ) : (
        <Bar indeterminate />
      )}
    </div>
  )
}

/**
 * The one figure a finished run is entitled to, chosen by how the run ended.
 *
 * This is a switch and not three sibling blocks on purpose. As three blocks, a
 * state that had both completed and been reconciled — which the reducer used to
 * be able to hold — rendered "412,806 artifacts · 41.2s" from one of them and
 * "389,204 artifacts — the last count heard" from the next, two different
 * totals for one run in the surface an examiner quotes. One ending in, one line
 * out; there is no arrangement of the state that gets two.
 */
function runTotalLine(
  state: ProcessingState,
  ending: RunEndingKind,
): ReactElement | null {
  switch (ending) {
    case 'complete':
      // The total is what the completion event carried. Without one there is
      // nothing here to say, and the strip says "not reported" for both of us.
      if (state.totalArtifacts == null) return null
      return (
        <div className="processing-count mono">
          {formatCount(state.totalArtifacts)} artifacts ·{' '}
          {((state.durationMs ?? 0) / 1000).toFixed(1)}s
        </div>
      )
    case 'cancelled':
      return (
        <div className="processing-count mono">
          {/* Never `?? 0`: a cancel whose event carried no count is "we do not
              know how much was done", and printing zero turns that into an
              affirmative claim that the run produced nothing. The custody strip
              says the same thing in the same words. */}
          {state.cancelledArtifacts != null
            ? `Cancelled — ${formatCount(state.cancelledArtifacts)} artifacts processed`
            : 'Cancelled — artifacts processed not reported'}
        </div>
      )
    case 'ended-unobserved':
      return (
        <div className="processing-count mono">
          {/* Deliberately not presented as a result. Everything the terminal
              event carried — the final total, the duration, the per-type
              breakdown — went missing with it, and the only number this client
              holds is the last progress frame it happened to hear. */}
          {formatCount(state.processed)} artifacts — the last count heard, not a
          final total
        </div>
      )
  }
}

export function ProcessingPanel({ state }: { state: ProcessingState }) {
  const toast = useToast()
  const [now, setNow] = useState(() => Date.now())
  // All three of these are statements about ONE case's run, and this panel
  // lives in the sidebar: it stays mounted when `:caseId` changes. An open
  // "Cancel processing?" confirmation opened over case A would otherwise still
  // be on screen under case B, and confirming it calls `cancelProcessing` with
  // the LIVE case id — stopping an acquisition the operator never asked to
  // stop, which on a running write-blocked read is destructive. Likewise a
  // dismissed panel must not silence the next case's progress. Scoped state
  // resolves during render, so these are gone in the first frame of the new
  // case rather than one effect later.
  const runScope = state.caseId ?? ''
  const [confirming, setConfirming] = useEntityScopedState(runScope, false)
  const [cancelRequested, setCancelRequested] = useEntityScopedState(
    runScope,
    false,
  )
  // Lets the operator dismiss a finished (complete/cancelled) panel to reclaim
  // sidebar space. A new run clears it so the next result is shown again.
  const [dismissed, setDismissed] = useEntityScopedState(runScope, false)

  // NOT run-scoped, unlike the three above: those are answers about one run and
  // must not carry to the next, while this is how the examiner wants the panel
  // to sit. It persists across runs, navigation and reloads.
  const [collapsed, setCollapsed] = useState(loadCollapsed)
  const toggleCollapsed = () => {
    setCollapsed((v) => {
      storeCollapsed(!v)
      return !v
    })
  }

  // The same derivation the custody strip uses, so the sidebar and the status
  // bar cannot end up making different claims about one run. `ending` is the
  // single way this run is over — everything below asks it rather than reading
  // the three terminal flags separately, which is how two of them once got on
  // screen at the same time.
  const run = describeRunState(state, now)
  const ending = runEnding(state)

  const hashEntries = Object.values(state.hashing)
  // What the disclosure lists, and how many errors it does not — the ones the
  // bounded state discarded plus the ones it holds but has no room for.
  const listedErrors = state.errors.slice(-MAX_ERROR_LINES)
  const unlistedErrors = totalErrorCount(state) - listedErrors.length
  const moduleEntries = Object.values(state.modules)
    .filter((m) => now - m.updatedAt <= DROP_MS)
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .slice(0, MAX_MODULE_LINES)

  // Tick so stale module lines fade without new events arriving — and, more
  // importantly, so the panel keeps re-deciding what it may claim. Both of the
  // states it must be able to report (the stream down past the grace window, a
  // live socket that has gone quiet) arrive as the passage of time and not as
  // an event, so a panel that only re-renders on events would never notice
  // either. Once a second while a run is in flight or the stream is down, so
  // the panel and the once-a-second custody strip change together.
  const hasModules = moduleEntries.length > 0
  const watchingRun = state.active || state.connectionState !== 'live'
  useEffect(() => {
    if (!hasModules && !watchingRun) return
    const timer = setInterval(() => setNow(Date.now()), watchingRun ? 1000 : 5000)
    return () => clearInterval(timer)
  }, [hasModules, watchingRun])

  // A new run resets the cancel flow and un-dismisses the panel so the next
  // result reappears even if the previous one was closed.
  useEffect(() => {
    if (state.active) {
      setDismissed(false)
    } else {
      setConfirming(false)
      setCancelRequested(false)
    }
  }, [state.active])

  // A run that ended while this client was disconnected is a result like any
  // other and needs somewhere to be said. Without this the panel rendered
  // nothing — not active, not complete, not cancelled — and the fact that the
  // run finished unobserved, which is what tells the examiner the figures on
  // the case pages are the ones to trust, had no home on screen.
  if (
    !state.active &&
    ending == null &&
    state.errors.length === 0 &&
    hashEntries.length === 0
  ) {
    return null
  }

  // Once dismissed, stay hidden until a new run resets it (effect above).
  if (dismissed) {
    return null
  }

  const requestCancel = async () => {
    if (!state.caseId) return
    setConfirming(false)
    setCancelRequested(true)
    try {
      await cancelProcessing(state.caseId)
    } catch {
      setCancelRequested(false)
      toast.error('Cancel request failed')
    }
  }

  let title = 'Processing complete'
  // A run this client can no longer vouch for does not get a title that reads
  // as a live one, however loudly the note underneath explains itself.
  if (state.active)
    title = `Processing — ${state.phase ?? 'working'}${run.unconfirmed ? ' (unconfirmed)' : ''}`
  else if (ending === 'cancelled') title = 'Processing cancelled'
  else if (ending === 'ended-unobserved')
    title = 'Run ended — completion not received'
  else if (ending == null && hashEntries.length > 0) title = 'Acquiring evidence'

  // Only the finished states get a close button; an in-progress run keeps its
  // Cancel control instead.
  const dismissible = ending != null

  return (
    <section className="processing-panel" aria-label="Processing activity">
      <div className="processing-title">
        {/* The heading travels with the button rather than sitting beside it,
            so the whole title line is the hit target. What the heading says is
            why collapsing is safe here: it names the phase while a run is live,
            so a collapsed panel still reports that work is going on and what
            kind. Nothing that could read as "finished" or "idle" is hidden. */}
        <button
          type="button"
          className="processing-disclose"
          aria-expanded={!collapsed}
          aria-controls="processing-body"
          onClick={toggleCollapsed}
          title={collapsed ? 'Show details' : 'Hide details'}
        >
          <span className="processing-caret" aria-hidden="true">
            {collapsed ? '\u25b8' : '\u25be'}
          </span>
          <span>{title}</span>
        </button>
        {(state.connectionState === 'reconnecting' || dismissible) && (
          <span className="processing-title-right">
            {state.connectionState === 'reconnecting' && (
              <span className="processing-conn">reconnecting…</span>
            )}
            {dismissible && (
              <button
                type="button"
                className="processing-close"
                aria-label="Dismiss"
                title="Dismiss"
                onClick={() => setDismissed(true)}
              >
                ×
              </button>
            )}
          </span>
        )}
      </div>

      <div id="processing-body" hidden={collapsed}>
        {run.unconfirmed && ending !== 'ended-unobserved' && (
          <div className="processing-unconfirmed">
            {/* When the socket died, the last thing it told us, and what that
                makes of every figure below. The silent-run wording already names
                the time of the last event, so it is not repeated there. */}
            {run.streamDown && state.lastEventAt != null
              ? `${run.label} · last confirmed ${formatUtcTime(state.lastEventAt)}.`
              : `${run.label}.`}{' '}
            The figures below are the last that arrived and may be out of date.
          </div>
        )}

        {ending === 'ended-unobserved' && (
          <div className="processing-unconfirmed">
            No completion event for this run ever reached this browser — the
            stream was down, or the event was dropped. The server reports no work
            in flight, so the run is over. The case views hold the totals; this
            panel cannot report a total it never received.
          </div>
        )}

        {hashEntries.map((h) => (
          <div key={h.source} className="processing-hash-line">
            <span className="processing-hash-label mono">
              Hashing {basename(h.source)} — {formatBytes(h.bytesDone)} of{' '}
              {formatBytes(h.bytesTotal)} ({percent(h.bytesDone, h.bytesTotal)}%)
            </span>
            {h.segmentCount != null && h.segmentCount > 1 && (
              <span className="processing-hash-set">
                Part of a {h.segmentCount}-file E01 set
                {h.segmentBytesTotal != null
                  ? ` · ${formatBytes(h.segmentBytesTotal)} total`
                  : ''}
              </span>
            )}
            <Bar pct={percent(h.bytesDone, h.bytesTotal)} />
          </div>
        ))}

        {state.active && (
          <div className="processing-count mono">
            {formatCount(Math.max(state.liveCount, state.processed))} artifacts
          </div>
        )}

        {state.active && state.activeModules.length > 0 && (
          <div className="processing-active">
            {state.activeModules.map(humanizeModuleId).join(' · ')}
          </div>
        )}

        {state.active && state.ratePerSec != null && (
          <div className="processing-eta mono">
            {state.etaSeconds != null
              ? `~${formatDuration(state.etaSeconds)} remaining · ${formatRate(state.ratePerSec)}`
              : formatRate(state.ratePerSec)}
          </div>
        )}

        {state.active && state.discovering && (
          <div className="processing-tasks">
            <span className="mono">Discovering tasks…</span>
            <Bar indeterminate />
          </div>
        )}
        {state.active &&
          !state.discovering &&
          state.tasksTotal != null &&
          state.tasksTotal > 0 && (
            <div className="processing-tasks">
              <span className="mono">
                {formatCount(state.tasksCompleted ?? 0)} /{' '}
                {formatCount(state.tasksTotal)} tasks (
                {Math.max(
                  state.taskPct,
                  percent(state.tasksCompleted ?? 0, state.tasksTotal),
                )}
                %)
              </span>
              <Bar
                pct={Math.max(
                  state.taskPct,
                  percent(state.tasksCompleted ?? 0, state.tasksTotal),
                )}
              />
            </div>
          )}

        {moduleEntries.length > 0 && (
          <div className="processing-modules">
            {moduleEntries.map((m) => (
              <ModuleLine
                key={`${m.moduleId}:${m.artifactId}`}
                activity={m}
                now={now}
              />
            ))}
          </div>
        )}

        {!state.active && ending != null && runTotalLine(state, ending)}

        {Object.keys(state.byType).length > 0 && (
          <div className="processing-types">
            {Object.entries(state.byType)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 6)
              .map(([type, count]) => (
                <span key={type} className="badge">
                  {type} {formatCount(count)}
                </span>
              ))}
          </div>
        )}

        {state.active && state.caseId && (
          <div className="processing-cancel">
            {confirming ? (
              <div className="processing-confirm">
                <span>
                  Stop processing? Already-extracted artifacts are kept.
                </span>
                <div className="processing-confirm-actions">
                  <button className="btn btn-danger" onClick={requestCancel}>
                    Stop
                  </button>
                  <button className="btn" onClick={() => setConfirming(false)}>
                    Keep running
                  </button>
                </div>
              </div>
            ) : (
              <button
                className="btn"
                disabled={cancelRequested}
                onClick={() => setConfirming(true)}
              >
                {cancelRequested ? 'Cancelling…' : 'Cancel processing'}
              </button>
            )}
          </div>
        )}

        {state.errors.length > 0 && (
          <details className="processing-errors">
            {/* The count is every error this run reported; the list is the tail
                the bounded state still holds. Saying which is which keeps the
                summary a statement about the evidence rather than about the
                size of a buffer. */}
            <summary>{formatCount(totalErrorCount(state))} module errors</summary>
            <ul>
              {listedErrors.map((err, i) => (
                <li key={i} className="mono">
                  {err.module_id}: {err.error}
                </li>
              ))}
            </ul>
            {/* The note used to be gated on the retention cap having bitten, so
                it appeared past 200 errors and nowhere below. But the list is ten
                lines long whatever the state holds, so the run with 74 errors —
                the common one — showed ten rows with nothing saying the other 64
                existed, which is the bounded list presented as the list. The gate
                is now "is anything missing from this list", which covers both
                bands: the errors the state discarded and the ones it holds but
                does not show. */}
            {unlistedErrors > 0 && (
              <p className="processing-errors-note">
                showing the most recent {formatCount(listedErrors.length)} ·{' '}
                {formatCount(unlistedErrors)} earlier errors are counted but not
                listed
              </p>
            )}
          </details>
        )}
      </div>
    </section>
  )
}
