import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  MediaGallery,
  type MediaItem,
  type MediaSort,
  type SortOrder,
} from '../../components/media/MediaGallery'
import { getAllRecords, resolveFiles, type RecordMetadata } from './api'
import { metaFirst, metaNum, metaStr } from './lib'
import {
  IncompletenessChip,
  useIncompleteness,
} from '../../components/Incompleteness'
import type { ViewerProps } from './viewers'
import { formatCount } from '../../lib/format'

/**
 * Chat media on the same rich browser as the main gallery — thumbnails,
 * properties sidebar, keyboard triage, bookmarks and a full-size lightbox — so
 * an examiner works attachments the same way everywhere.
 *
 * This is a thin data adapter: it loads the whole attachment set, resolves each
 * one to its file, and hands normalized items to {@link MediaGallery}. Media
 * with no message link (the referencing message was deleted) is exactly what
 * this view is for, so it defaults to those with a filter for the full set.
 */

type Scope = 'unlinked' | 'all'

/** True when the chat database records which message this media belongs to. */
function isLinked(m: RecordMetadata): boolean {
  return metaStr(m, 'message_guid') != null || metaNum(m, 'message_rowid') != null
}

function mediaPath(m: RecordMetadata): string | null {
  return metaStr(m, 'filename')
}

function compareItems(sort: MediaSort, order: SortOrder) {
  const dir = order === 'asc' ? 1 : -1
  return (a: MediaItem, b: MediaItem) => {
    let d = 0
    if (sort === 'size') d = (a.size ?? 0) - (b.size ?? 0)
    else if (sort === 'modified')
      d = (a.modified ?? '').localeCompare(b.modified ?? '')
    else d = a.name.localeCompare(b.name)
    return d * dir
  }
}

export function makeChatMediaViewer(appLabel: string) {
  return function ChatMediaViewer({ caseId, type }: ViewerProps): ReactNode {
    // Own the whole attachment set so the browser can sort and filter across
    // all of it, not just a page. A chat database's media count is bounded
    // (thousands), so this is safe to hold.
    const recordsQuery = useQuery({
      queryKey: ['chat-media-records', caseId, type],
      queryFn: () => getAllRecords(caseId, type, { maxPages: 200 }),
      staleTime: Infinity,
    })
    const records = useMemo(
      () => recordsQuery.data?.records ?? [],
      [recordsQuery.data],
    )
    // getAllRecords caps at maxPages; a huge chat DB can exceed it, so warn
    // rather than silently listing only part of the attachment set.
    const truncated = recordsQuery.data?.truncated ?? false

    const linkedCount = useMemo(
      () => records.filter((r) => isLinked(r.metadata)).length,
      [records],
    )
    const unlinkedCount = records.length - linkedCount
    const [scope, setScope] = useState<Scope | null>(null)
    const effectiveScope: Scope =
      scope ?? (unlinkedCount > 0 ? 'unlinked' : 'all')

    const shown = useMemo(
      () =>
        effectiveScope === 'all'
          ? records
          : records.filter((r) => !isLinked(r.metadata)),
      [records, effectiveScope],
    )

    // Resolve every shown attachment's bytes in one batched (chunked) call.
    const paths = useMemo(
      () =>
        shown.map((r) => mediaPath(r.metadata)).filter((p): p is string => !!p),
      [shown],
    )
    const filesQuery = useQuery({
      queryKey: ['chat-media-files', caseId, paths.join('|')],
      queryFn: () => resolveFiles(caseId, paths),
      enabled: paths.length > 0,
      staleTime: Infinity,
    })

    // This viewer loads its own attachment records, so the page shell's banner
    // does not describe them; the toolbar is the one place with room here
    // (B4-023).
    const incompleteness = useIncompleteness(records)

    const [sort, setSort] = useState<MediaSort>('name')
    const [order, setOrder] = useState<SortOrder>('asc')
    const applySort = (column: MediaSort) => {
      if (column === sort) setOrder((o) => (o === 'asc' ? 'desc' : 'asc'))
      else {
        setSort(column)
        setOrder(column === 'name' ? 'asc' : 'desc')
      }
    }

    const items = useMemo(() => {
      const files = filesQuery.data ?? {}
      const list: MediaItem[] = shown.map((r) => {
        const m = r.metadata
        const p = mediaPath(m)
        const name = metaFirst(m, ['transfer_name', 'filename']) ?? 'attachment'
        const created = metaNum(m, 'created_date')
        return {
          key: r.id,
          artifactId: (p ? files[p] : undefined) ?? null,
          name,
          path: p,
          size: metaNum(m, 'total_bytes'),
          modified:
            created != null ? new Date(created * 1000).toISOString() : null,
          extension: name.includes('.') ? name.split('.').pop()! : null,
          metadata: m,
        }
      })
      return list.sort(compareItems(sort, order))
    }, [shown, filesQuery.data, sort, order])

    const sidebarExtra = (item: MediaItem) => {
      const m = item.metadata ?? {}
      const mime = metaStr(m, 'mime_type')
      const linked = isLinked(m)
      return (
        <table className="gl-meta-table mono">
          <tbody>
            {mime && (
              <tr>
                <td>Type</td>
                <td>{mime}</td>
              </tr>
            )}
            <tr>
              <td>Message</td>
              <td>{linked ? 'linked' : 'no link (deleted?)'}</td>
            </tr>
          </tbody>
        </table>
      )
    }

    const note =
      effectiveScope === 'unlinked'
        ? `${formatCount(shown.length)} with no message link — the referencing message is missing or was deleted. ${formatCount(linkedCount)} others are shown against their own ${appLabel} message.`
        : `${formatCount(shown.length)} loaded, ${formatCount(linkedCount)} of them linked to a message.`

    return (
      <MediaGallery
        caseId={caseId}
        noun="attachments"
        mediaNoun="attachment"
        items={items}
        loading={recordsQuery.isPending}
        resolved={filesQuery.isSuccess || paths.length === 0}
        sort={sort}
        order={order}
        onSort={applySort}
        onSortChange={(s, o) => {
          setSort(s)
          setOrder(o)
        }}
        sidebarExtra={sidebarExtra}
        emptyState={
          <div className="empty-state">
            <h3>No {appLabel} media</h3>
            <p>This chat database has no attachments to show.</p>
          </div>
        }
        toolbarStart={
          <div className="gl-filter">
            <div
              className="gl-seg"
              role="group"
              aria-label="Which media to show"
            >
              <button
                type="button"
                className={effectiveScope === 'unlinked' ? 'is-active' : undefined}
                aria-pressed={effectiveScope === 'unlinked'}
                onClick={() => setScope('unlinked')}
              >
                Unlinked
              </button>
              <button
                type="button"
                className={effectiveScope === 'all' ? 'is-active' : undefined}
                aria-pressed={effectiveScope === 'all'}
                onClick={() => setScope('all')}
              >
                All media
              </button>
            </div>
            <span className="gl-note" title={note}>
              {formatCount(linkedCount)} linked
            </span>
            <IncompletenessChip summary={incompleteness} noun="attachments" />
            {truncated && (
              <span
                className="gl-warn"
                role="note"
                title={`Only the first ${formatCount(records.length)} attachments were loaded (page cap reached); more exist but are not listed.`}
              >
                ⚠ partial list
              </span>
            )}
            {/* A failed path→artifact lookup left every cell with no "open" and
                no "not in evidence", which reads as "still loading" forever.
                Whether this media is in the evidence is unknown here, and that
                is what the examiner has to be told (B4-031). */}
            {filesQuery.isError && (
              <span
                className="gl-warn"
                role="note"
                data-testid="chat-media-resolve-failed"
                title={`Locating these attachments in the evidence failed: ${
                  (filesQuery.error as Error).message
                }. Whether each one is present could not be established, so an item with no open action here is not a finding that it is absent.`}
              >
                ⚠ lookup failed
              </span>
            )}
          </div>
        }
      />
    )
  }
}
