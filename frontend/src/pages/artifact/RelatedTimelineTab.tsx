import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import type { TimelineEvent } from '../../api/types'
import { formatCount, formatUtc } from '../../lib/format'
import { getRelatedTimeline } from './api'

/** An event's epoch seconds as the UTC text every other timeline screen shows. */
function eventTime(seconds: number): string {
  const date = new Date(seconds * 1000)
  // Out of Date's range (a corrupt or sentinel value): say so, never throw.
  return Number.isNaN(date.getTime()) ? `${seconds} (out of range)` : formatUtc(date.toISOString())
}

/**
 * Which artifact an event belongs to, relative to the one on screen.
 *
 * The route returns the artifact's own, its parent's, its children's and its
 * siblings' events without saying which is which. Own and parent can be told
 * from the ids this page already holds; a child and a sibling cannot be told
 * apart from the response alone, so the row says "child or sibling" and links
 * to the artifact rather than guessing.
 */
function relation(event: TimelineEvent, artifactId: string, parentId: string | null): string {
  if (event.artifact_id === artifactId) return 'this artifact'
  if (parentId && event.artifact_id === parentId) return 'parent'
  return 'child or sibling'
}

/**
 * The Timeline tab of the artifact page: the dated events around this artifact
 * (`GET /cases/{id}/timeline/related/{artifactId}`).
 *
 * Bounded server-side. When the list stops at the cap it says so, and says
 * which events were taken first, so a capped list is not read as the whole
 * history. A failed load is stated as a failure, never as an empty history.
 */
export function RelatedTimelineTab({
  caseId,
  artifactId,
  parentId,
}: {
  caseId: string
  artifactId: string
  parentId: string | null
}) {
  const query = useQuery({
    queryKey: ['related-timeline', caseId, artifactId],
    queryFn: () => getRelatedTimeline(caseId, artifactId),
  })

  if (query.isPending) {
    return <p className="av-related-loading">Loading the events around this artifact…</p>
  }
  if (query.isError) {
    return (
      <p className="error-note" role="alert">
        The events around this artifact could not be loaded: {query.error.message}. Nothing
        here says this artifact has no events.
      </p>
    )
  }

  const { events, truncated, cap } = query.data
  if (events.length === 0) {
    return (
      <div className="empty-state">
        <h3>No dated events</h3>
        <p>
          No timeline events are recorded for this artifact, its parent, its children or its
          siblings. Only what a parser put on the case timeline appears here.
        </p>
      </div>
    )
  }

  return (
    <div className="av-related">
      {truncated ? (
        <p className="warn-note" role="note" data-testid="av-related-capped">
          This list stops at {formatCount(cap)} events and is not the whole history. The
          artifact&rsquo;s own events and its parent&rsquo;s and children&rsquo;s were taken
          first, newest first; its siblings&rsquo; filled what was left. The case timeline holds
          the rest.
        </p>
      ) : (
        <p className="av-related-count">
          All {formatCount(events.length)} related {events.length === 1 ? 'event' : 'events'}:
          this artifact&rsquo;s own, its parent&rsquo;s, its children&rsquo;s and its
          siblings&rsquo;, newest first.
        </p>
      )}
      <table className="data-table" aria-label="Events around this artifact">
        <thead>
          <tr>
            <th>Time (UTC)</th>
            <th>Event</th>
            <th>Description</th>
            <th>Source module</th>
            <th>Artifact</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => {
            const rel = relation(event, artifactId, parentId)
            return (
              <tr key={event.id}>
                <td className="mono">{eventTime(event.timestamp)}</td>
                <td>{event.timestamp_desc}</td>
                <td>{event.short_desc}</td>
                <td className="mono">{event.source_module}</td>
                <td>
                  {rel === 'this artifact' ? (
                    rel
                  ) : (
                    <Link to={`/cases/${caseId}/artifacts/${event.artifact_id}`}>{rel}</Link>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
