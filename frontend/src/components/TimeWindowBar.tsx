import { useQuery } from '@tanstack/react-query'
import { formatUtc } from '../lib/format'
import { getTimelineHistogram } from '../pages/timeline/api'
import { MiniTimeline } from './viz/MiniTimeline'
import { useTimeWindow } from '../app/TimeWindowContext'
import './timeWindowBar.css'

/**
 * The persistent case-wide time window (ROADMAP §1.1).
 *
 * `MiniTimeline` was a display on the dashboard — it neither followed the
 * examiner across screens nor filtered anything. This is the same chart in the
 * case shell, so it is on screen wherever the examiner goes, and clicking a bar
 * narrows the case to that period.
 *
 * # Three things it must always say
 *
 * **What is in force.** The thing narrowing the view is set somewhere other
 * than the screen being read, and followed the examiner there. So the window is
 * printed in full, in UTC, beside a control that clears it — never a chip whose
 * meaning has to be hovered for.
 *
 * **Where it applies.** A window that filtered some screens and not others,
 * silently, would have an examiner reading an unfiltered population as a
 * filtered one or the reverse. The bar names the screens it is in force on, so
 * a screen outside that list is visibly outside it.
 *
 * **That it is not a statement about the case.** A narrowed screen shows a
 * subset, and the bar says so in the same breath as naming the window.
 *
 * # Why it is collapsed until a case has dated events
 *
 * A case mid-ingest, or one with no dated evidence, has no axis to narrow
 * along. The bar then renders nothing at all rather than an empty chart: a
 * control that cannot be used is a control that has to be explained, and there
 * is nothing here to explain.
 */

/**
 * The screens the window is in force on.
 *
 * Maintained by hand beside the screens that read `useTimeWindow`. A screen
 * added to one and not the other is the failure this list exists to prevent —
 * either a screen filters and does not say so, or the bar claims a screen it
 * does not reach.
 */
export const WINDOWED_SCREENS = ['Timeline'] as const

export function TimeWindowBar({ caseId }: { caseId: string }) {
  const { window, setWindow } = useTimeWindow()
  const histogram = useQuery({
    queryKey: ['case', caseId, 'timeline', 'histogram', 'window-bar'],
    queryFn: () => getTimelineHistogram(caseId, { buckets: 80 }),
    retry: false,
    enabled: caseId !== '',
  })

  const data = histogram.data
  // Nothing to narrow along. Rendering an empty chart with a clear button would
  // be a control that has to be explained, and there is nothing to explain.
  // A failed load is the same: the window is a convenience, and a broken
  // histogram must not put an error band across every screen in the case.
  if (!data || data.buckets.length === 0 || data.min_ts == null) {
    // A window set before the histogram failed is still in force, and saying so
    // matters more than the chart does.
    if (window == null) return null
  }

  return (
    <div className="twb" data-testid="time-window-bar">
      {data && data.buckets.length > 0 && data.min_ts != null && (
        <div className="twb-chart">
          <MiniTimeline
            buckets={data.buckets}
            minTs={data.min_ts}
            maxTs={data.max_ts}
            bucketSeconds={data.bucket_seconds}
            selected={window}
            onSelect={(from, to) => setWindow({ from, to })}
          />
        </div>
      )}

      <div className="twb-state">
        {window == null ? (
          <p className="twb-note" data-testid="twb-none">
            The whole case is in view. Click a bar to narrow every{' '}
            {WINDOWED_SCREENS.join(', ')} view to that period.
          </p>
        ) : (
          <>
            <p className="twb-note twb-active" data-testid="twb-active">
              <strong>
                {formatUtc(new Date(window.from * 1000).toISOString())} to{' '}
                {formatUtc(new Date(window.to * 1000).toISOString())}
              </strong>{' '}
              is in force on {WINDOWED_SCREENS.join(', ')}. Those views show a{' '}
              <strong>subset</strong> of the case while it is: a count on one of
              them is a count inside this window, not a count in the case.
              Nothing outside{' '}
              {WINDOWED_SCREENS.length === 1
                ? `the ${WINDOWED_SCREENS[0]}`
                : `those ${WINDOWED_SCREENS.length} views`}{' '}
              is narrowed by it.
            </p>
            <button
              type="button"
              className="twb-clear"
              onClick={() => setWindow(null)}
            >
              Show the whole case
            </button>
          </>
        )}
      </div>
    </div>
  )
}
