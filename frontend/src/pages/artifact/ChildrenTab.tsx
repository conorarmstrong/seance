import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { FolderTree } from 'lucide-react'
import { listChildArtifacts } from '../../api/resources'
import type { ArtifactListItem } from '../../api/types'
import { formatCount } from '../../lib/format'
import { QuickFilterBar, useQuickFilter } from '../../components/QuickFilter'

function childHref(caseId: string, child: ArtifactListItem): string {
  // A file system's contents are browsed in the lazy file tree, not as a flat
  // artifact page.
  if (child.artifact_type === 'FileSystem') {
    return `/cases/${caseId}/files/${child.id}?view=tree`
  }
  return `/cases/${caseId}/artifacts/${child.id}`
}

// Render this many child rows at first; a scroll sentinel reveals the next
// chunk. Keeps a parent with thousands of children from mounting all at once.
const CHUNK = 100

export function ChildrenTab({
  caseId,
  artifactId,
  parentType,
}: {
  caseId: string
  artifactId: string
  parentType: string
}) {
  // A FileSystem holds every file as a flat child (tens of thousands of rows),
  // so listing them here would fetch and mount the whole tree at once. The
  // purpose-built file tree loads folders on demand — send the user there.
  if (parentType === 'FileSystem') {
    return (
      <div className="empty-state">
        <FolderTree size={28} aria-hidden="true" />
        <h3>Browse this file system as a tree</h3>
        <p>
          File-system contents open in the expandable file tree, which loads
          folders on demand as you drill in.
        </p>
        <Link
          className="btn btn-primary"
          to={`/cases/${caseId}/files/${artifactId}?view=tree`}
        >
          Open file tree
        </Link>
      </div>
    )
  }

  return <ChildrenList caseId={caseId} artifactId={artifactId} />
}

function ChildrenList({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const query = useQuery({
    queryKey: ['artifact-children', caseId, artifactId],
    queryFn: () => listChildArtifacts(caseId, artifactId),
  })
  const children = query.data?.items ?? []
  // The listing can stop at the page ceiling; an unmarked table reads as this
  // artifact's complete contents.
  const childrenTruncated = query.data?.truncated === true
  // A quick type-ahead over the children (§1.1). The scoping key is the parent
  // artifact, not the case: a needle typed on one artifact's children is about
  // that artifact, and carrying it to the next one shows an empty tab for an
  // artifact that has children.
  const search = useQuickFilter(artifactId, children, (c) => [
    c.name,
    c.artifact_type,
  ])
  const shown = search.rows
  const [count, setCount] = useState(CHUNK)
  const sentinelRef = useRef<HTMLTableRowElement>(null)

  useEffect(() => {
    if (count >= shown.length) return
    // No IntersectionObserver (e.g. tests): reveal everything rather than hide.
    if (typeof IntersectionObserver === 'undefined') {
      setCount(shown.length)
      return
    }
    const el = sentinelRef.current
    if (!el) return
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setCount((c) => Math.min(c + CHUNK, shown.length))
        }
      },
      { rootMargin: '300px' },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [count, shown.length])

  if (query.isPending) {
    return <div className="loading">Loading children...</div>
  }
  if (query.isError) {
    return (
      <div className="error-note">
        Failed to load children: {query.error.message}
      </div>
    )
  }
  if (children.length === 0) {
    // "Nothing was derived" and "we could not list what was derived" are
    // different claims, and only the first is a finding about the evidence.
    if (childrenTruncated) {
      return (
        <div className="empty-state">
          <h3>Children not listed</h3>
          <p>
            The listing stopped at its ceiling before returning any rows. This
            artifact may well have children; none could be shown here.
          </p>
        </div>
      )
    }
    return (
      <div className="empty-state">
        <h3>No child artifacts</h3>
        <p>Nothing has been derived from this artifact yet.</p>
      </div>
    )
  }
  return (
    <div>
      <p className="av-note">
        {children.length} {children.length === 1 ? 'child' : 'children'}
      </p>
      <QuickFilterBar
        filter={search}
        noun="child"
        plural="children"
        placeholder="Filter children…"
        // The listing itself can stop at the page ceiling, and then this
        // filter searched only what came back.
        loadedIsSubset={childrenTruncated}
      />
      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
          </tr>
        </thead>
        <tbody>
          {shown.slice(0, count).map((child) => (
            <tr key={child.id}>
              <td>
                <Link to={childHref(caseId, child)}>{child.name}</Link>
              </td>
              <td>
                <span className="badge">{child.artifact_type}</span>
              </td>
            </tr>
          ))}
          {count < shown.length && (
            <tr ref={sentinelRef}>
              <td colSpan={2} className="av-note">
                Loading {formatCount(shown.length - count)} more…
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
