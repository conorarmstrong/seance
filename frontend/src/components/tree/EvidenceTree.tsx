import { useCallback, useMemo } from 'react'
import type { ComponentType } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  ChevronRight,
  ChevronDown,
  Package,
  HardDrive,
  Layers,
  FolderTree,
  File as FileIcon,
  Cog,
  FileText,
  SquareDashed,
  MemoryStick,
} from 'lucide-react'
import { listChildArtifacts } from '../../api/resources'
import type { ArtifactListItem } from '../../api/types'
import { getMemoryImages, type MemoryImageSummary } from '../../pages/memory/api'
import { captureSourceIndex } from './captures'
import { useTreeKeyboard, type TreeKeyboard } from './useTreeKeyboard'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { formatBytes, formatCount } from '../../lib/format'
import './tree.css'

/** Nothing expanded. A shared reference so the case-scoped state can hand it
 *  back verbatim under another case; `setExpanded` copies before writing. */
const NOTHING_EXPANDED: ReadonlySet<string> = new Set<string>()

const TYPE_ICONS: Record<string, ComponentType<{ size?: number; className?: string }>> = {
  Container: Package,
  RawEvidence: HardDrive,
  Partition: Layers,
  FileSystem: FolderTree,
  FileEntry: FileIcon,
  FileContent: FileIcon,
  SystemArtifact: Cog,
  ParsedRecord: FileText,
  UnallocatedSpace: SquareDashed,
}

/**
 * Human-readable node label built from artifact metadata where available
 * (partition scheme/type, filesystem type, sizes). Falls back to the raw
 * artifact name when metadata is missing.
 */
function nodeLabel(item: ArtifactListItem): string {
  const md = item.metadata
  if (!md) return item.name
  if (item.artifact_type === 'Partition') {
    const parts: string[] = []
    const id = md.partition_id
    if (typeof id === 'number' || typeof id === 'string') {
      parts.push(`Partition ${id}`)
    }
    const kind = md.partition_type_name ?? md.partition_scheme
    if (typeof kind === 'string' && kind) parts.push(kind)
    if (typeof md.size_bytes === 'number') {
      parts.push(formatBytes(md.size_bytes))
    }
    return parts.length > 0 ? parts.join(' · ') : item.name
  }
  if (item.artifact_type === 'FileSystem') {
    const fs = md.filesystem_type
    if (typeof fs === 'string' && fs) return `${fs} filesystem`
    return item.name
  }
  if (item.artifact_type === 'UnallocatedSpace') {
    if (typeof md.size_bytes === 'number') {
      return `Unallocated · ${formatBytes(md.size_bytes)}`
    }
    return item.name
  }
  return item.name
}

function TreeNode({
  caseId,
  item,
  depth,
  onSelect,
  selectedId,
  captureBySource,
  nav,
  isExpanded,
  setExpanded,
}: {
  caseId: string
  item: ArtifactListItem
  depth: number
  onSelect?: (item: ArtifactListItem) => void
  selectedId?: string
  /** Source artifact id → the RAM capture decoded from it (Phase 1c/2). */
  captureBySource: Map<string, MemoryImageSummary>
  nav: TreeKeyboard
  isExpanded: (id: string) => boolean
  setExpanded: (id: string, expanded: boolean) => void
}) {
  // A FileSystem's children are every file (flat, tens of thousands). Expanding
  // it here would fetch and mount the whole tree, so it is a leaf: its link
  // opens the lazy file tree instead.
  const isFileSystem = item.artifact_type === 'FileSystem'
  const expandable = item.has_children && !isFileSystem
  const expanded = expandable && isExpanded(item.id)
  const children = useQuery({
    queryKey: ['tree', caseId, item.id],
    queryFn: () => listChildArtifacts(caseId, item.id),
    enabled: expanded,
  })

  // The artifact's canonical address. The `workbench?artifact=` form still
  // redirects here, but emitting it would send every click through a redirect
  // and — worse — put the superseded address in the URL bar, which is the one an
  // examiner copies into a note or a statement.
  const target = `/cases/${caseId}/artifacts/${encodeURIComponent(item.id)}`

  // A RAM capture was decoded from this artifact. The node still browses the
  // underlying bytes (a capture's source can be a whole disk, or a file inside a
  // filesystem — both remain legitimately browsable); the tag is the one-click
  // way from the acquisition into that capture's memory analysis.
  const capture = captureBySource.get(item.id)

  return (
    <li
      {...nav.rowProps({ id: item.id, expandable, expanded })}
      aria-selected={selectedId ? selectedId === item.id : undefined}
    >
      <div className="tree-row" style={{ paddingLeft: depth * 14 }}>
        {expandable ? (
          <button
            className="tree-caret"
            // Not a tab stop: the row is. The caret and the label used to be
            // two stops per node, which is what made a deep tree unreachable
            // by keyboard. It stays a real button so a click and a screen
            // reader's own button navigation both still work.
            tabIndex={-1}
            aria-label={expanded ? 'Collapse' : 'Expand'}
            onClick={() => setExpanded(item.id, !expanded)}
          >
            {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </button>
        ) : (
          <span className="tree-caret-spacer" />
        )}
        <span className="tree-glyph" aria-hidden="true">
          {(() => {
            const Glyph = TYPE_ICONS[item.artifact_type] ?? FileIcon
            return <Glyph size={14} />
          })()}
        </span>
        {onSelect ? (
          <button
            className={
              selectedId === item.id
                ? 'tree-label tree-label-btn active'
                : 'tree-label tree-label-btn'
            }
            tabIndex={-1}
            onClick={() => onSelect(item)}
            title={item.name}
          >
            {nodeLabel(item)}
          </button>
        ) : (
          <Link
            className="tree-label"
            tabIndex={-1}
            to={target}
            title={item.name}
          >
            {nodeLabel(item)}
          </Link>
        )}
        {/* The one control in a row that is deliberately left in the tab
            order. Everything else inside a row is `tabIndex={-1}`, because a
            stop per row is what made this tree unreachable by keyboard — but
            this tag is not per row: it appears only on the artifact a RAM
            capture was decoded from, which is a handful of nodes in a case and
            usually none. It also goes somewhere the row's own Enter cannot,
            since Enter opens the artifact and this opens that capture's memory
            analysis, so removing it from the tab order would leave the memory
            lens with no keyboard path at all. */}
        {capture && (
          <Link
            className="tree-ram-tag"
            to={`/cases/${caseId}/memory?image=${capture.image_id}`}
            title="RAM capture — open its memory analysis"
          >
            <MemoryStick size={11} aria-hidden="true" />
            RAM
          </Link>
        )}
      </div>
      {expanded && (
        <ul className="tree-list" role="group">
          {children.isLoading && (
            <li
              role="none"
              className="tree-note"
              style={{ paddingLeft: (depth + 1) * 14 }}
            >
              loading…
            </li>
          )}
          {/* An expanded node that fails to load its children used to render
              nothing at all — indistinguishable from a partition or container
              that holds nothing, under a node the server said HAS children
              (B8-032). */}
          {children.isError && (
            <li
              role="none"
              className="tree-note tree-note-error"
              style={{ paddingLeft: (depth + 1) * 14 }}
              data-testid="tree-children-error"
            >
              could not load contents: {(children.error as Error).message} —{' '}
              <button
                type="button"
                className="link-button"
                onClick={() => void children.refetch()}
              >
                retry
              </button>
            </li>
          )}
          {/* Derived parser output (SqliteRow, iMessage, EXIF, …) is not part of
              the evidence file hierarchy — thousands of them would drown the
              tree. Keep the physical tree to files/containers; the records live
              in the Analysis views (grouped by type, and by database→table for
              SQLite), reached from the Logical view. */}
          {children.data?.items
            .filter((child) => child.artifact_type !== 'ParsedRecord')
            .map((child) => (
              <TreeNode
                key={child.id}
                caseId={caseId}
                item={child}
                depth={depth + 1}
                onSelect={onSelect}
                selectedId={selectedId}
                captureBySource={captureBySource}
                nav={nav}
                isExpanded={isExpanded}
                setExpanded={setExpanded}
              />
            ))}
          {(() => {
            const records =
              children.data?.items.filter(
                (c) => c.artifact_type === 'ParsedRecord',
              ).length ?? 0
            return records > 0 ? (
              <li
                role="none"
                className="tree-note tree-note-records"
                style={{ paddingLeft: (depth + 1) * 14 }}
                title="Parsed records are grouped in the Analysis views"
              >
                {formatCount(records)} parsed record
                {records === 1 ? '' : 's'} — see Analysis
              </li>
            ) : null
          })()}
          {children.data?.items.length === 0 && (
            <li
              role="none"
              className="tree-note"
              style={{ paddingLeft: (depth + 1) * 14 }}
            >
              empty
            </li>
          )}
          {/* A listing that stopped at the page ceiling is not the contents of
              this container, and an unmarked tree is read as if it were. */}
          {children.data?.truncated && (
            <li
              role="none"
              className="tree-note tree-note-records"
              style={{ paddingLeft: (depth + 1) * 14 }}
              title="More children exist than are listed here"
            >
              more not shown — listing was capped
            </li>
          )}
        </ul>
      )}
    </li>
  )
}

export function EvidenceTree({
  caseId,
  onSelect,
  selectedId,
}: {
  caseId: string
  onSelect?: (item: ArtifactListItem) => void
  selectedId?: string
}) {
  const roots = useQuery({
    queryKey: ['tree', caseId, 'root'],
    queryFn: () => listChildArtifacts(caseId, 'root', { sources_only: true }),
  })

  // The case's RAM captures, indexed by the artifact each was decoded from, so
  // any source node in the tree can advertise its capture. A failure here leaves
  // the tree fully usable, just without the RAM markers — never a broken tree.
  const captures = useQuery({
    queryKey: ['memory-images', caseId],
    queryFn: () => getMemoryImages(caseId),
    retry: false,
  })
  const captureBySource = useMemo(
    () => captureSourceIndex(captures.data?.images),
    [captures.data],
  )

  // Expansion is held here rather than in each node for two reasons. The keys
  // that act on a node other than the one pressed — Right stepping into a
  // folder it just opened, Left closing the parent of the focused row — need
  // something above the nodes to act on. And a node's own `useState` died with
  // the node: the tree collapsed to its roots every time the sidebar
  // remounted, which for a three-week examination is a dozen re-expansions a
  // day. Scoped to the case, so one case's open nodes can never be shown as
  // another's (the ids would not match, but the ceremony is the same one
  // LogicalTree keeps and the guarantee is worth having explicitly).
  const [expandedIds, setExpandedIds] = useEntityScopedState<ReadonlySet<string>>(
    caseId,
    NOTHING_EXPANDED,
  )
  const isExpanded = useCallback(
    (id: string) => expandedIds.has(id),
    [expandedIds],
  )
  const setExpanded = useCallback(
    (id: string, next: boolean) => {
      setExpandedIds((prev) => {
        if (prev.has(id) === next) return prev
        const copy = new Set(prev)
        if (next) copy.add(id)
        else copy.delete(id)
        return copy
      })
    },
    [setExpandedIds],
  )
  const nav = useTreeKeyboard({ setExpanded })

  if (roots.isLoading) return <div className="tree-note">loading…</div>
  if (roots.isError) {
    return <div className="tree-note">Could not load evidence sources.</div>
  }
  if (!roots.data || roots.data.items.length === 0) {
    return (
      <div className="tree-note">
        No evidence yet. Use Ingest Evidence to add a source.
      </div>
    )
  }

  return (
    <ul
      ref={nav.treeRef}
      className="tree-list tree-root"
      role="tree"
      aria-label="Evidence sources"
    >
      {roots.data.items.map((item) => (
        <TreeNode
          key={item.id}
          caseId={caseId}
          item={item}
          depth={0}
          onSelect={onSelect}
          selectedId={selectedId}
          captureBySource={captureBySource}
          nav={nav}
          isExpanded={isExpanded}
          setExpanded={setExpanded}
        />
      ))}
    </ul>
  )
}
