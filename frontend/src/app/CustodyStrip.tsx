import { useEffect, useState } from 'react'
import { describeRunState, totalErrorCount } from '../hooks/processing'
import type { ProcessingState } from '../hooks/processing'
import { formatCount } from '../lib/format'

function utcClock(ms: number): string {
  const now = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${now.getUTCFullYear()}-${pad(now.getUTCMonth() + 1)}-${pad(now.getUTCDate())} ` +
    `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())} UTC`
  )
}

/**
 * The custody strip: a lab-instrument status bar pinned to the bottom of
 * the case workspace. Examiner identity, case reference, live processing
 * state, and a UTC clock — always visible, like the readout on bench gear.
 *
 * Because it is always visible it is also the only surface that can report a
 * dead event stream on a case that looks idle: the processing panel renders
 * nothing when nothing is running, so an outage during an idle-looking case
 * used to change no pixel anywhere while this bar went on asserting "idle".
 * The run state it prints is derived by `describeRunState`, shared with the
 * panel so the two cannot disagree about one run.
 */
export function CustodyStrip({
  examiner,
  reference,
  processing,
}: {
  examiner: string | null
  reference: string | null
  processing: ProcessingState
}) {
  // The clock ticks once a second anyway, so the strip re-evaluates what it is
  // entitled to claim once a second for free: an outage that passes the grace
  // window, or a run that goes quiet, is reported without waiting for an event
  // that may never come.
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])

  const run = describeRunState(processing, now)
  let status = run.label
  // Errors are counted, not listed, and the count includes the ones the bounded
  // list no longer holds — how many errors occurred is a fact about the
  // evidence and must not shrink to fit a buffer.
  const errorCount = totalErrorCount(processing)
  if (errorCount > 0) {
    status += ` · ${formatCount(errorCount)} module errors`
  }
  // `custody-unknown` has no dot colour of its own, which is the point: an
  // unknown run state must not pulse like a live one, and it has no business
  // borrowing the "finished" green either.
  const statusClass = `custody-${run.tone}`

  return (
    <footer className="custody-strip mono" aria-label="Case status">
      <span className="custody-cell">
        examiner <strong>{examiner ?? '—'}</strong>
      </span>
      <span className="custody-cell">
        ref <strong>{reference ?? '—'}</strong>
      </span>
      <span className={`custody-cell ${statusClass}`}>
        <span className="custody-dot" aria-hidden="true" /> {status}
      </span>
      <span className="custody-cell custody-clock">{utcClock(now)}</span>
    </footer>
  )
}
