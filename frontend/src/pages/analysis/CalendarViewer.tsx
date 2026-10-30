import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { formatUtc } from '../../lib/format'
import type { ParsedRecord, RecordMetadata } from './api'
import { AggregateEmpty, LoadMoreNote, useAggregatedRecords } from './aggregate'
import { toIso } from './cells'
import { MISSING, metaBool, metaFirst, metaStr } from './lib'
import { IncompletenessBanner } from '../../components/Incompleteness'
import type { ViewerProps } from './viewers'

/** Day bucket key from a dtstart. Uses the literal date to avoid tz drift. */
function dayKey(m: RecordMetadata): string {
  const dt = metaFirst(m, ['dtstart'])
  if (!dt) return '(no date)'
  if (/^\d{4}-\d{2}-\d{2}/.test(dt)) return dt.slice(0, 10)
  const t = Date.parse(toIso(dt))
  if (!Number.isNaN(t)) return new Date(t).toISOString().slice(0, 10)
  return '(no date)'
}

/** Sort key within a day: seconds since epoch, or 0 for all-day. */
function startSort(m: RecordMetadata): number {
  const dt = metaFirst(m, ['dtstart'])
  if (!dt) return 0
  const t = Date.parse(toIso(dt))
  return Number.isNaN(t) ? 0 : t
}

function timeRange(m: RecordMetadata): string {
  if (metaBool(m, 'all_day')) return 'All day'
  const start = metaFirst(m, ['dtstart'])
  const end = metaFirst(m, ['dtend'])
  const s = start ? formatUtc(toIso(start)) : MISSING
  if (!end) return s
  return `${s} → ${formatUtc(toIso(end))}`
}

interface Day {
  key: string
  events: ParsedRecord[]
}

function buildDays(records: ParsedRecord[]): Day[] {
  const byDay = new Map<string, ParsedRecord[]>()
  for (const r of records) {
    const k = dayKey(r.metadata)
    const list = byDay.get(k)
    if (list) list.push(r)
    else byDay.set(k, [r])
  }
  const days: Day[] = [...byDay.entries()].map(([key, events]) => ({
    key,
    events: events.sort((a, b) => startSort(a.metadata) - startSort(b.metadata)),
  }))
  days.sort((a, b) => a.key.localeCompare(b.key))
  return days
}

function dayHeading(key: string): string {
  const t = Date.parse(`${key}T00:00:00Z`)
  if (Number.isNaN(t)) return key
  const d = new Date(t)
  const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][d.getUTCDay()]
  return `${weekday} ${key}`
}

export function CalendarViewer({ caseId, type }: ViewerProps): ReactNode {
  const load = useAggregatedRecords(caseId, type, {
    queryKey: 'analysis-calendar',
    loadingLabel: 'Loading events…',
  })

  const days = useMemo(() => buildDays(load.records), [load.records])

  if (load.gate) return load.gate
  if (days.length === 0) {
    return (
      <AggregateEmpty
        title="No events"
        body="No calendar events were parsed."
        loaded={load.records.length}
        listed={days.length}
        listedNoun="calendar event"
      />
    )
  }

  return (
    <div className="an-agenda">
      {/* This viewer loads its own records, so the page shell's banner (over its
    page-1 fetch) does not describe what is on screen here. The parsers stamp
    the standard pair on records they could not finish; read it over the set
    this viewer actually holds (B4-023/B4-024). */}
      <IncompletenessBanner summary={load.incompleteness} noun="events" />
      {load.truncated && (
        <LoadMoreNote
          shown={load.records.length}
          total={load.total}
          noun="events"
          onLoadMore={load.loadMore}
        />
      )}
      {days.map((day) => (
        <section key={day.key} className="an-agenda-day" data-testid="an-agenda-day">
          <h3 className="an-agenda-date mono">{dayHeading(day.key)}</h3>
          <ul className="an-agenda-events">
            {day.events.map((r) => {
              const m = r.metadata
              const attendees = metaStr(m, 'attendees')
              const status = metaStr(m, 'status')
              return (
                <li key={r.id} className="an-event" tabIndex={0}>
                  <div className="an-event-time mono">{timeRange(m)}</div>
                  <div className="an-event-body">
                    <div className="an-event-summary">
                      {metaStr(m, 'summary') ?? '(untitled)'}
                      {status && <span className="badge an-event-status">{status}</span>}
                    </div>
                    <dl className="an-kv an-event-meta">
                      {metaStr(m, 'location') && (
                        <div style={{ display: 'contents' }}>
                          <dt>Location</dt>
                          <dd>{metaStr(m, 'location')}</dd>
                        </div>
                      )}
                      {metaStr(m, 'organizer') && (
                        <div style={{ display: 'contents' }}>
                          <dt>Organizer</dt>
                          <dd className="mono">{metaStr(m, 'organizer')}</dd>
                        </div>
                      )}
                      {attendees && (
                        <div style={{ display: 'contents' }}>
                          <dt>Attendees</dt>
                          <dd className="mono">{attendees}</dd>
                        </div>
                      )}
                    </dl>
                  </div>
                </li>
              )
            })}
          </ul>
        </section>
      ))}
    </div>
  )
}
