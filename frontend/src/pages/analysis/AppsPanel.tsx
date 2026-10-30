import { useQuery } from '@tanstack/react-query'
import { formatCount } from '../../lib/format'
import { getAppRecordCounts, type AppRecordCount } from './api'

/**
 * "What is on this device": the case's records grouped by the application they
 * came from (§2.12).
 *
 * The triage question this answers is not "how many records are there" — the
 * record-type list already answers that — but "which programs was this person
 * using, and how much did each leave behind". So the grouping is by app, and
 * the record types that made up each group are shown underneath, because an
 * examiner who sees `WhatsApp — 4,102` will next want to know whether that is
 * messages, attachments or both.
 *
 * Two things are deliberately visible rather than smoothed over:
 *
 * * **How each group was attributed.** A record may name its app (SRUM, the
 *   Windows Timeline) or its type may be an app (the messengers, which carry
 *   no app field). Those are different confidences and the chip says which.
 * * **What belongs to no app at all.** Most of a case is not an application —
 *   file entries, registry keys, network flows — and those records are counted
 *   separately and never distributed among the apps. Without that line the
 *   panel would read as a breakdown of the whole case when it is a breakdown
 *   of the part that belongs to programs.
 */
const ATTRIBUTION_LABEL: Record<AppRecordCount['attribution'], string> = {
  named_by_record: 'named by the record',
  record_type: 'from the record type',
  named_by_record_and_record_type: 'named by the record and by its type',
  unknown: 'attribution not recorded',
}

const ATTRIBUTION_TITLE: Record<AppRecordCount['attribution'], string> = {
  named_by_record:
    'These records name this application themselves — Windows resource usage (SRUM), the Windows Timeline, a macOS bundle identifier.',
  record_type:
    'These records are this application by their kind: a WhatsApp message is a WhatsApp message, and the parser writes no separate app field.',
  named_by_record_and_record_type:
    'Both signals reached this group: some of these records name the application and others are it by their kind.',
  unknown:
    'This group carries no record of how it was attributed, which should not happen; treat the grouping as unverified.',
}

export function AppsPanel({
  caseId,
  sourceId,
}: {
  caseId: string
  sourceId?: string
}) {
  const query = useQuery({
    queryKey: ['analysis-apps', caseId, sourceId ?? null],
    queryFn: () => getAppRecordCounts(caseId, sourceId),
    enabled: caseId !== '',
  })

  if (query.isPending) {
    return <div className="loading">Loading applications…</div>
  }
  // A failed load must not read as "no applications": that is a statement
  // about the device.
  if (query.isError) {
    return (
      <div className="error-note" role="note">
        Applications unavailable: {query.error.message}. Nothing here says this
        case holds no application records.
      </div>
    )
  }

  const data = query.data
  if (!data) return null
  const { apps, unattributed } = data

  if (apps.length === 0) {
    return (
      <section className="an-group" data-testid="an-apps">
        <div className="an-group-head">
          <h2 className="an-group-name">Applications</h2>
        </div>
        <div className="empty-state">
          <h3>No application records</h3>
          <p>
            Nothing parsed from this case is attributable to an application.
            {unattributed.records > 0 && (
              <> {unattributed.note}</>
            )}
          </p>
        </div>
      </section>
    )
  }

  return (
    <section className="an-group" data-testid="an-apps">
      <div className="an-group-head">
        <h2 className="an-group-name">Applications</h2>
        <span className="an-group-count mono">
          {formatCount(apps.length)}{' '}
          {apps.length === 1 ? 'application' : 'applications'}
        </span>
      </div>
      <p className="an-group-blurb">
        What was on this device, by the records each program left behind. The
        figures below cover the records that belong to an application; they are
        not a breakdown of the whole case.
      </p>
      <div className="an-grid">
        {apps.map((app) => (
          <div key={app.app} className="an-card an-card-static">
            <div className="an-card-head">
              <div className="an-card-name" title={app.app}>
                {app.app}
              </div>
              <span
                className="badge an-card-generic"
                title={ATTRIBUTION_TITLE[app.attribution]}
              >
                {ATTRIBUTION_LABEL[app.attribution]}
              </span>
            </div>
            <div className="an-card-count mono">
              {formatCount(app.records)}
              <span className="an-card-count-unit"> records</span>
            </div>
            <div className="an-card-type mono" title={app.record_types.join(', ')}>
              {app.record_types.join(', ')}
            </div>
          </div>
        ))}
      </div>
      {/* Always rendered, in both directions: "nothing was set aside" is a
          positive statement, and its absence would leave a reader to assume
          the per-app figures add up to the case when they may not. */}
      <p
        className={
          unattributed.records > 0 ? 'warn-note' : 'an-group-blurb'
        }
        role="note"
        data-testid="an-apps-unattributed"
      >
        {unattributed.note}
      </p>
    </section>
  )
}
