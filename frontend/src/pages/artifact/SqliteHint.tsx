import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { getArtifactChildrenWithMetadata } from './api'
import { metadataNumber } from './lib'
import { formatCount } from '../../lib/format'

// Only file-shaped artifacts can be a SQLite database, so the extra children
// fetch is skipped for containers, partitions, records, and the like.
const DB_TYPES = new Set(['FileEntry', 'FileContent'])

function count(
  summary: Record<string, unknown> | null,
  key: string,
): string {
  if (!summary) return '—'
  const value = metadataNumber(summary, key)
  return value != null ? formatCount(value) : '—'
}

/**
 * Compact SQLite forensic summary shown on the Overview of a database
 * artifact: live / deleted / carved row counts from the
 * `SqliteDatabaseForensics` summary record, plus a link into the row viewer.
 * Renders nothing unless the artifact has SQLite forensic children.
 */
export function SqliteHint({
  caseId,
  artifactId,
  artifactType,
}: {
  caseId: string
  artifactId: string
  artifactType: string
}) {
  const enabled = DB_TYPES.has(artifactType)
  const query = useQuery({
    queryKey: ['artifact-sqlite-summary', caseId, artifactId],
    enabled,
    queryFn: () => getArtifactChildrenWithMetadata(caseId, artifactId),
  })
  const children = query.data ?? []
  let summary: Record<string, unknown> | null = null
  let hasRows = false
  for (const child of children) {
    const type = child.metadata?.type
    if (type === 'SqliteDatabaseForensics') summary = child.metadata ?? null
    else if (type === 'SqliteRow') hasRows = true
  }
  if (!summary && !hasRows) return null

  return (
    <section className="panel av-sqlite">
      <h3 className="av-ts-title">SQLite forensic summary</h3>
      <div className="av-sqlite-counts">
        <span className="av-sqlite-stat">
          <span className="av-label">Live rows</span>
          <span className="av-value mono">{count(summary, 'live_rows')}</span>
        </span>
        <span className="av-sqlite-stat">
          <span className="av-label">Deleted rows</span>
          <span className="av-value mono av-danger">
            {count(summary, 'deleted_rows')}
          </span>
        </span>
        <span className="av-sqlite-stat">
          <span className="av-label">Carved rows</span>
          <span className="av-value mono">{count(summary, 'carved_rows')}</span>
        </span>
      </div>
      <Link
        className="link-button"
        to={`/cases/${caseId}/analysis?type=SqliteRow&source_id=${artifactId}`}
      >
        View recovered rows
      </Link>
    </section>
  )
}
