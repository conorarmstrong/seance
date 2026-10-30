import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { RecordMetadata } from './api'
import { AggregateEmpty, LoadMoreNote, useAggregatedRecords } from './aggregate'
import { ArtifactLink } from './cells'
import { MISSING, metaNum, metaStr } from './lib'
import { IncompletenessBanner } from '../../components/Incompleteness'
import type { ViewerProps } from './viewers'
import { formatCount } from '../../lib/format'

/** Summary counts header, rendered when the parser emitted a summary record. */
function ContactSummary({ meta }: { meta: RecordMetadata }) {
  const stats: [string, number | null][] = [
    ['Contacts', metaNum(meta, 'contact_count')],
    ['With phone', metaNum(meta, 'with_phone_count')],
    ['With email', metaNum(meta, 'with_email_count')],
  ]
  const platform = metaStr(meta, 'platform')
  return (
    <div className="an-summary" data-testid="an-contact-summary">
      {stats.map(([label, n]) => (
        <div key={label} className="an-stat">
          {/* Never `?? 0`: the summary not carrying a count means the parser
              did not report one, which is a different statement from "none".
              Printing zero would make the UI assert, for example, that no
              contact in this address book has a phone number. `MISSING` is the
              vocabulary the rest of this folder already uses for unknown. */}
          <span
            className="an-stat-num mono"
            title={n == null ? 'Not reported by the parser' : undefined}
          >
            {n == null ? MISSING : formatCount(n)}
          </span>
          <span className="an-stat-label">{label}</span>
        </div>
      ))}
      {platform && <span className="badge an-summary-tag">{platform}</span>}
    </div>
  )
}

/** Concatenate the fields a search query can match against. */
function haystack(m: RecordMetadata): string {
  return [
    metaStr(m, 'display_name'),
    metaStr(m, 'phone_numbers'),
    metaStr(m, 'emails'),
    metaStr(m, 'organization'),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
}

export function ContactViewer({ caseId, type }: ViewerProps): ReactNode {
  const [q, setQ] = useState('')

  const load = useAggregatedRecords(caseId, type, {
    queryKey: 'analysis-contacts',
    loadingLabel: 'Loading contacts…',
  })

  const records = load.records
  const summary = records.find((r) => metaStr(r.metadata, 'subtype') === 'summary')

  const contacts = useMemo(() => {
    const list = records.filter((r) => metaStr(r.metadata, 'subtype') === 'contact')
    return list.sort((a, b) =>
      (metaStr(a.metadata, 'display_name') ?? '').localeCompare(
        metaStr(b.metadata, 'display_name') ?? '',
      ),
    )
  }, [records])

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return contacts
    return contacts.filter((r) => haystack(r.metadata).includes(needle))
  }, [contacts, q])

  if (load.gate) return load.gate
  if (contacts.length === 0) {
    return (
      <AggregateEmpty
        title="No contacts"
        body="No contact records were parsed for this case."
        loaded={records.length}
        listed={contacts.length}
        listedNoun="contact row"
      />
    )
  }

  return (
    <div>
      {summary && <ContactSummary meta={summary.metadata} />}
      {/* This viewer loads its own records, so the page shell's banner (over its
    page-1 fetch) does not describe what is on screen here. The parsers stamp
    the standard pair on records they could not finish; read it over the set
    this viewer actually holds (B4-023/B4-024). */}
      <IncompletenessBanner summary={load.incompleteness} noun="contacts" />
      <input
        className="input an-contact-search"
        type="search"
        aria-label="Search contacts"
        placeholder="Search name, phone, email or organization"
        value={q}
        onChange={(e) => setQ(e.target.value)}
      />
      {load.truncated && (
        <LoadMoreNote
          shown={contacts.length}
          total={load.total}
          noun="records"
          onLoadMore={load.loadMore}
        />
      )}
      {filtered.length === 0 ? (
        <p className="an-mail-nobody">No contacts match “{q}”.</p>
      ) : (
        <table className="data-table an-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Phone numbers</th>
              <th>Emails</th>
              <th>Organization</th>
              <th>Platform</th>
              <th>Artifact</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => {
              const m = r.metadata
              return (
                <tr key={r.id} tabIndex={0} data-testid="an-contact-row">
                  <td>{metaStr(m, 'display_name') ?? MISSING}</td>
                  <td className="mono">{metaStr(m, 'phone_numbers') ?? MISSING}</td>
                  <td className="mono">{metaStr(m, 'emails') ?? MISSING}</td>
                  <td>{metaStr(m, 'organization') ?? MISSING}</td>
                  <td>{metaStr(m, 'platform') ?? MISSING}</td>
                  <td>
                    <ArtifactLink caseId={caseId} id={r.id}>
                      open
                    </ArtifactLink>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}
