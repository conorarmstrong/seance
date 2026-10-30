import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import {
  getDuplicates,
  getNearDuplicateImages,
  type DuplicateGroup,
} from '../../api/resources'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { formatCount } from '../../lib/format'
import './duplicates.css'

const MISSING = '—'

/** One duplicate group as an expandable row. */
function GroupRow({
  caseId,
  group,
}: {
  caseId: string
  group: DuplicateGroup
}) {
  const [open, setOpen] = useState(false)
  const first = group.members[0]
  return (
    <div className="dup-group">
      <button
        type="button"
        className="dup-group-head"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="dup-count badge badge-accent">{group.count}×</span>
        <span className="dup-name mono">{first?.name ?? MISSING}</span>
        <span className="dup-hash mono" title={group.hash}>
          {group.hash.slice(0, 16)}…
        </span>
      </button>
      {open && (
        <ul className="dup-members">
          {group.members.map((m) => (
            <li key={m.id} className="dup-member">
              <Link to={`/cases/${caseId}/artifacts/${m.id}`} className="mono">
                {m.name ?? m.id}
              </Link>
              <span className="dup-path mono">{m.path ?? MISSING}</span>
            </li>
          ))}
          {group.count > group.members.length && (
            <li className="dup-more">
              + {group.count - group.members.length} more copies
            </li>
          )}
        </ul>
      )}
    </div>
  )
}

/** PDQ near-duplicate image groups: re-encodes, resizes and light edits of the
 *  same picture that exact SHA-256 duplicates miss. A lead for review, never an
 *  identification — the grade is carried through from the server. */
function NearDuplicateImages({ caseId }: { caseId: string }) {
  const query = useQuery({
    queryKey: ['near-duplicates', caseId],
    queryFn: () => getNearDuplicateImages(caseId),
    enabled: !!caseId,
  })

  if (query.isPending)
    return <div className="loading">Finding near-duplicate images…</div>
  if (query.isError)
    return <div className="error-note">{(query.error as Error).message}</div>
  const data = query.data

  return (
    <section className="dup-near">
      <h2>Near-duplicate images</h2>
      <p className="dup-sub">
        {formatCount(data.group_count)} perceptual{' '}
        {data.group_count === 1 ? 'group' : 'groups'} (PDQ within{' '}
        {data.threshold} bits) across {formatCount(data.images_scanned)}{' '}
        hashed {data.images_scanned === 1 ? 'image' : 'images'}
        {data.scan_truncated ? ' — image scan capped' : ''}. A lead for review,
        not an identification.
      </p>
      {data.group_count === 0 ? (
        <div className="empty-state">
          <h3>No near-duplicate images</h3>
          <p>
            No two perceptually-hashed images in this case are within{' '}
            {data.threshold} PDQ bits of each other.
          </p>
        </div>
      ) : (
        <div className="dup-list">
          {data.groups.map((g, gi) => (
            <div className="dup-group" key={gi}>
              <div className="dup-group-head">
                <span className="dup-count badge badge-accent">{g.count}×</span>
                <span className="dup-name">near-duplicate image set</span>
              </div>
              <ul className="dup-members">
                {g.members.map((m) => (
                  <li key={m.record_id} className="dup-member">
                    {m.image_artifact_id ? (
                      <Link
                        to={`/cases/${caseId}/artifacts/${m.image_artifact_id}`}
                        className="mono"
                      >
                        {m.image_artifact_id}
                      </Link>
                    ) : (
                      <span className="mono">{MISSING}</span>
                    )}
                    <span className="dup-hash mono" title={m.pdq_hex}>
                      {m.pdq_hex.slice(0, 16)}…
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}

export function DuplicatesPage() {
  const { caseId } = useParams<{ caseId: string }>()
  // Client-side filter over this case's duplicate groups. The page stays
  // mounted across a `:caseId` change, and a filename fragment from case A
  // matches nothing in case B — the examiner is shown "No duplicates" for a
  // case that has them, with no visible reason why (B2-092).
  const [q, setQ] = useEntityScopedState(caseId ?? '', '')
  const query = useQuery({
    queryKey: ['duplicates', caseId],
    queryFn: () => getDuplicates(caseId!),
    enabled: !!caseId,
  })

  const filtered = useMemo(() => {
    const groups = query.data?.groups ?? []
    const needle = q.trim().toLowerCase()
    if (!needle) return groups
    return groups.filter((g) =>
      g.members.some(
        (m) =>
          m.name?.toLowerCase().includes(needle) ||
          m.path?.toLowerCase().includes(needle),
      ),
    )
  }, [query.data, q])

  if (query.isPending)
    return <div className="loading">Finding duplicate content…</div>
  if (query.isError) {
    return <div className="error-note">{(query.error as Error).message}</div>
  }
  const data = query.data

  return (
    <div className="dup">
      <header className="dup-head">
        <h1>Duplicates</h1>
        <p className="dup-sub">
          {formatCount(data.group_count)} duplicate-content{' '}
          {data.group_count === 1 ? 'group' : 'groups'} (matching SHA-256),{' '}
          {formatCount(data.redundant_copies)} redundant{' '}
          {data.redundant_copies === 1 ? 'copy' : 'copies'}
          {data.truncated ? ' — showing the largest groups' : ''}.
        </p>
      </header>

      {data.group_count === 0 ? (
        <div className="empty-state">
          <h3>No duplicates</h3>
          <p>No two hashed artifacts in this case share a SHA-256.</p>
        </div>
      ) : (
        <>
          <input
            className="dup-search"
            type="text"
            placeholder="Filter by name or path…"
            aria-label="Filter duplicates"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          {filtered.length === 0 && q.trim() !== '' ? (
            // Without this the page shows case-wide counts above an empty list,
            // which reads as "no duplicates in this case" when in fact the
            // filter matched nothing (B5-033).
            <div className="empty-state" data-testid="dup-no-matches">
              <h3>No groups match this filter</h3>
              <p>
                None of the {formatCount(data.group_count)} duplicate
                {data.group_count === 1 ? ' group' : ' groups'} in this case has
                a name or path matching “{q}”. Clear the filter to see them all.
              </p>
            </div>
          ) : filtered.length === 0 ? (
            // No filter is set, the case reports groups, and none came back.
            // Blaming a filter that is not there would be a fabricated
            // explanation; the honest statement is that the two disagree.
            <div className="warn-note" role="note" data-testid="dup-none-returned">
              This case reports {formatCount(data.group_count)} duplicate
              {data.group_count === 1 ? ' group' : ' groups'}, but the server
              returned none to list. The groups are not shown here and their
              absence from this page is not a finding that they do not exist.
            </div>
          ) : (
            <div className="dup-list">
              {filtered.map((g) => (
                <GroupRow key={g.hash} caseId={caseId!} group={g} />
              ))}
            </div>
          )}
        </>
      )}

      <NearDuplicateImages caseId={caseId!} />
    </div>
  )
}
