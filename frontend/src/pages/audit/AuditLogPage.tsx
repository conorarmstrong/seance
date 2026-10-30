import { useRef, useState } from 'react'
import { SkeletonTable } from '../../components/Skeleton'
import { useParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import type { AuditEvent } from '../../api/types'
import { Pager } from '../../components/Pager'
import { useToast } from '../../components/toast/ToastProvider'
import { downloadFile } from '../../lib/download'
import { formatCount, formatUtc } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { useRovingRows } from '../../hooks/useRovingRows'
import type { RovingRowProps } from '../../hooks/useRovingRows'
import { getAuditLog, verifyAuditChain } from './api'
import type { ChainVerification } from './api'
import './audit.css'

const LIMITS = [100, 250, 500]

function prettyDetails(details: string | null): string {
  if (!details) return ''
  try {
    const parsed = JSON.parse(details)
    if (typeof parsed === 'object' && parsed !== null) {
      return JSON.stringify(parsed, null, 2)
    }
  } catch {
    // Not JSON; show as-is.
  }
  return details
}

/** datetime-local value (treated as UTC) -> RFC3339, or undefined. */
function toRfc3339(value: string): string | undefined {
  if (!value) return undefined
  const ms = Date.parse(`${value}Z`)
  if (Number.isNaN(ms)) return undefined
  return new Date(ms).toISOString()
}

/** Stable identity for a row so expansion survives data changes. */
function eventKey(event: AuditEvent): string {
  return [event.timestamp, event.user_id, event.action, event.resource_id].join(
    '|',
  )
}

/**
 * What an intact verdict is worth, in one sentence the examiner can quote.
 *
 * "Chain intact" on its own reads as "the log is unaltered", and on an unkeyed
 * chain that is a claim the evidence does not support: anyone with database
 * access could rewrite an entry and recompute every hash after it. A chain
 * keyed part-way through — every installation that set SEANCE_AUDIT_HMAC_KEY on
 * an existing log — is neither keyed nor unkeyed, and the boundary is the fact
 * that lets the examiner say which entries are evidence-grade (DEPLOY-001).
 * The numbers come from the server; nothing here is inferred.
 */
function chainKeyingSentence(v: ChainVerification): string {
  if (v.tamper_evident) {
    // "the entries present", not "the log" — the completeness line below states
    // that deletion of the most recent entries is a separate, unproven question.
    return `Tamper-evident: every entry was written under a server-held key, so this verification is evidence that the entries present have not been altered or reordered.`
  }
  if (v.tamper_evident_from != null) {
    return `Tamper-evident from entry #${v.tamper_evident_from} only: ${formatCount(v.unkeyed_rows)} earlier entries were written unkeyed and verified as internally consistent, not as unaltered. From entry #${v.tamper_evident_from} the chain is keyed (${formatCount(v.keyed_rows)} entries) and this verification is evidence that those entries have not been altered.`
  }
  return `NOT tamper-evident: the chain is unkeyed (SEANCE_AUDIT_HMAC_KEY is not set), so this verification shows the log is internally consistent, not that it is unaltered — anyone with database access could rewrite an entry and recompute the hashes after it.`
}

export function AuditLogPage() {
  const { caseId } = useParams<{ caseId: string }>()
  const toast = useToast()

  // This page stays mounted when `:caseId` changes, and every value below is a
  // criterion applied to the log of whichever case is on screen. Case A's user,
  // action, resource or date filter left in place shows case B's audit log
  // trimmed to something the examiner never asked for — most often empty, which
  // reads as "case B has no audit history" for a case that has one. The page
  // offset is the same problem past case B's end. Scoping them to the case they
  // were entered under means the criteria and the log always describe the same
  // case (B2-027).
  const scope = caseId ?? ''
  const [limit, setLimit] = useEntityScopedState(scope, 100)
  const [offset, setOffset] = useEntityScopedState(scope, 0)
  const [userFilter, setUserFilter] = useEntityScopedState(scope, '')
  const [actionFilter, setActionFilter] = useEntityScopedState(scope, '')
  const [resourceTypeFilter, setResourceTypeFilter] = useEntityScopedState(
    scope,
    '',
  )
  const [fromFilter, setFromFilter] = useEntityScopedState(scope, '')
  const [toFilter, setToFilter] = useEntityScopedState(scope, '')
  const [expanded, setExpanded] = useEntityScopedState<string | null>(scope, null)
  const [exporting, setExporting] = useState(false)

  const filters = {
    user: userFilter.trim() || undefined,
    action: actionFilter.trim() || undefined,
    resource_type: resourceTypeFilter.trim() || undefined,
    from: toRfc3339(fromFilter),
    to: toRfc3339(toFilter),
  }

  const logQuery = useQuery({
    queryKey: ['audit', caseId, limit, offset, filters],
    queryFn: () => getAuditLog(caseId!, { limit, offset, ...filters }),
    enabled: !!caseId,
  })

  // The verdict is still tagged with the case it was requested from, and only
  // shown while that case is on screen: a mutation result outlives the render it
  // was produced in, so a stale verdict would otherwise sit above another case's
  // table as though it had just been computed there.
  //
  // What it is NOT is a statement about one case. `verify_audit_chain` ignores
  // the case id it is given and walks the whole `audit_log` table in id order,
  // because a hash chain has no per-case subsequence to verify — every entry's
  // hash covers the entry before it whichever case that entry belongs to. So a
  // break introduced in case A fails verification for every case, and "N entries
  // verified" counts entries from cases the examiner is not looking at. The
  // banner below says so in as many words: a false integrity alarm attributed to
  // a clean case is a wrong answer in a report, not a missing one (B6-028).
  const verify = useMutation({
    mutationFn: () =>
      verifyAuditChain(caseId!).then((result) => ({
        result,
        forCase: caseId ?? '',
      })),
    onError: (err: Error) => toast.error(err.message),
  })
  const verdict =
    verify.data && verify.data.forCase === scope ? verify.data.result : null

  const events = logQuery.data?.events ?? []
  const total = logQuery.data?.total ?? 0
  const totalPages = Math.max(Math.ceil(total / limit), 1)
  const page = Math.floor(offset / limit) + 1

  // The table is one tab stop on the shared roving-tabindex primitive, and
  // Enter opens the focused entry's details. Before this the rows answered to
  // nothing but a mouse click, so an entry's details — the parameters of what
  // was done to the evidence, which is the part that gets quoted — were
  // unreachable from the keyboard entirely, and a page of 500 entries had no
  // way to be walked at all.
  const eventsRef = useRef(events)
  eventsRef.current = events
  const roving = useRovingRows({
    count: events.length,
    onActivate: (index) => {
      const event = eventsRef.current[index]
      if (!event) return
      const key = eventKey(event)
      setExpanded(expanded === key ? null : key)
    },
  })

  const setFilter = (setter: (value: string) => void) => (value: string) => {
    setter(value)
    setOffset(0)
  }

  const exportCsv = async () => {
    setExporting(true)
    try {
      // Carry the active UI filters so the export matches the visible table
      // rather than dumping the whole case log.
      await downloadFile(`/cases/${caseId}/export/audit_log/csv`, 'audit_log.csv', {
        method: 'POST',
        query: filters,
      })
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Export failed')
    } finally {
      setExporting(false)
    }
  }

  return (
    <div>
      <h1 className="page-title">Audit log</h1>
      <p className="audit-intro">
        Every examiner action recorded for this case.
      </p>

      <div className="audit-filters">
        <label className="audit-filter">
          User
          <input
            className="input"
            aria-label="Filter by user"
            placeholder="exact user id"
            value={userFilter}
            onChange={(e) => setFilter(setUserFilter)(e.target.value)}
          />
        </label>
        <label className="audit-filter">
          Action
          <input
            className="input"
            aria-label="Filter by action"
            placeholder="e.g. case.open"
            value={actionFilter}
            onChange={(e) => setFilter(setActionFilter)(e.target.value)}
          />
        </label>
        <label className="audit-filter">
          Resource type
          <input
            className="input"
            aria-label="Filter by resource type"
            placeholder="e.g. artifact"
            value={resourceTypeFilter}
            onChange={(e) => setFilter(setResourceTypeFilter)(e.target.value)}
          />
        </label>
        <label className="audit-filter">
          From (UTC)
          <input
            type="datetime-local"
            className="input"
            aria-label="From (UTC)"
            value={fromFilter}
            onChange={(e) => setFilter(setFromFilter)(e.target.value)}
          />
        </label>
        <label className="audit-filter">
          To (UTC)
          <input
            type="datetime-local"
            className="input"
            aria-label="To (UTC)"
            value={toFilter}
            onChange={(e) => setFilter(setToFilter)(e.target.value)}
          />
        </label>
      </div>

      <div className="page-actions">
        <button
          className="btn"
          disabled={verify.isPending}
          onClick={() => verify.mutate()}
        >
          {verify.isPending ? 'Verifying…' : 'Verify chain'}
        </button>
        <button className="btn" disabled={exporting} onClick={exportCsv}>
          Export CSV
        </button>
        <label className="audit-limit">
          Rows per page
          <select
            className="select"
            value={limit}
            onChange={(e) => {
              setLimit(Number(e.target.value))
              setOffset(0)
            }}
          >
            {LIMITS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </label>
      </div>

      {verdict &&
        (verdict.valid ? (
          <div className="audit-chain-banner audit-chain-ok" role="status">
            Chain intact — {formatCount(verdict.checked)} entries verified
            across the whole audit log, which covers every case in this
            installation, not this case alone.
            <div className="audit-chain-keying">{chainKeyingSentence(verdict)}</div>
            {/* Completeness is a different question from alteration: a hash
                chain cannot show that recent entries were DELETED, so this
                states whether that was checked against an external anchor. When
                it was not, the wording says "unchecked", never "complete". */}
            {/* Optional-chained: a server that predates this field must leave
                the page readable rather than blanking it. */}
            {verdict.completeness?.note && (
              <div className="audit-chain-keying">
                {verdict.completeness.anchored
                  ? verdict.completeness.note
                  : `Completeness not checked: ${verdict.completeness.note}`}
              </div>
            )}
            {verdict.head_hash != null && (
              <div className="audit-chain-keying">
                Chain head to anchor: entry #{verdict.head_id},{' '}
                <code>{verdict.head_hash}</code>. Record this outside the server
                to detect a deleted tail later.
              </div>
            )}
          </div>
        ) : (
          <div className="audit-chain-banner audit-chain-broken" role="alert">
            CHAIN BROKEN at entry #{verdict.broken_at} of the audit log.{' '}
            {formatCount(verdict.checked)} entries were verified before the
            break. The chain spans every case in this installation, so the broken
            entry is not necessarily one of this case&rsquo;s — open the audit
            log at that entry to see which case it belongs to before recording a
            tampering finding against this one.
            {verdict.break_reason && (
              <div className="audit-chain-keying">Reason: {verdict.break_reason}</div>
            )}
          </div>
        ))}

      {logQuery.isPending && <SkeletonTable rows={10} cols={5} label="Loading audit log" />}
      {logQuery.isError && (
        <div className="error-note">{logQuery.error.message}</div>
      )}
      {logQuery.data && events.length === 0 && (
        <div className="empty-state">
          <h3>No audit events</h3>
          <p>Nothing matches the current filters for this case.</p>
        </div>
      )}
      {logQuery.data && events.length > 0 && (
        <div className="panel">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>User</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Resource ID</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, index) => {
                const key = eventKey(event)
                return (
                  <AuditRow
                    key={key}
                    event={event}
                    expanded={expanded === key}
                    rowProps={roving.getRowProps(index)}
                    onToggle={() =>
                      setExpanded(expanded === key ? null : key)
                    }
                  />
                )
              })}
            </tbody>
          </table>
          <Pager
            page={page}
            totalPages={totalPages}
            totalCount={total}
            onPage={(p) => setOffset((p - 1) * limit)}
          />
        </div>
      )}
    </div>
  )
}

function AuditRow({
  event,
  expanded,
  rowProps,
  onToggle,
}: {
  event: AuditEvent
  expanded: boolean
  rowProps: RovingRowProps
  onToggle: () => void
}) {
  return (
    <>
      <tr
        className="audit-row"
        {...rowProps}
        aria-expanded={expanded}
        onClick={onToggle}
      >
        <td className="mono audit-time">{formatUtc(event.timestamp)}</td>
        <td className="mono">{event.user_id}</td>
        <td>
          <span className="badge badge-accent">{event.action}</span>
        </td>
        <td>{event.resource_type}</td>
        <td>
          <div className="mono audit-id" title={event.resource_id}>
            {event.resource_id}
          </div>
        </td>
        <td>
          <div className="audit-trunc" title={event.details ?? undefined}>
            {event.details}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr className="audit-details-row">
          <td colSpan={6}>
            <pre className="audit-details" data-testid="audit-details">
              {prettyDetails(event.details)}
            </pre>
          </td>
        </tr>
      )}
    </>
  )
}
