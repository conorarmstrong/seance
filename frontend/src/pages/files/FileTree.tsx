import { useQuery } from '@tanstack/react-query'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { ChevronRight, ChevronDown, Folder } from 'lucide-react'
import { iconForName } from '../../lib/fileIcon'
import { formatBytes, formatCount } from '../../lib/format'
import { IncompleteBadge } from '../../components/Incompleteness'
import { SkeletonList } from '../../components/Skeleton'
import {
  useTreeKeyboard,
  type TreeKeyboard,
} from '../../components/tree/useTreeKeyboard'
import { listFiles } from './api'
import type { FileRow } from './types'

// Per-level fetch cap. A directory with more than this many immediate entries
// shows a truncation note rather than silently hiding children (see project
// ethos: no silent caps). Very large directories are better browsed via the
// filtered "All files" view.
const TREE_PAGE_SIZE = 1000

// Fetch one level of the tree by directory path. The tree is derived from the
// `path` column, not parent_id: parsers store every file as a flat child of
// the FileSystem artifact, so parent_id nesting is unreliable. An empty prefix
// lists the filesystem root.
function useChildren(
  caseId: string,
  sourceId: string,
  prefix: string,
  enabled: boolean,
) {
  return useQuery({
    queryKey: ['files-pathtree', caseId, sourceId, prefix],
    queryFn: () =>
      listFiles(caseId, sourceId, {
        path: prefix,
        sort: 'name',
        order: 'asc',
        page: 1,
        page_size: TREE_PAGE_SIZE,
        include_metadata: true,
      }),
    enabled,
  })
}

/** Directories first, then files; both alphabetical (file-explorer order). */
function orderNodes(items: FileRow[]): FileRow[] {
  return [...items].sort((a, b) => {
    if (a.is_directory !== b.is_directory) return a.is_directory ? -1 : 1
    return a.name.localeCompare(b.name)
  })
}

function isCarved(row: FileRow): boolean {
  return !row.is_directory && row.name.startsWith('carved_')
}

/** How many child rows to render per level before scroll reveals more. */
const RENDER_CHUNK = 60

/**
 * The expansion contract, owned by the tree root and handed to every node.
 *
 * Expansion has to live above the nodes because the keys act on rows other than
 * the one that was pressed — Right stepping into a folder it has just opened,
 * Left closing the parent of the focused row — and because a node's own state
 * would not survive its subtree being collapsed out from under it.
 *
 * It is keyed by ARTIFACT ID rather than by path, which is what the shared
 * keyboard hook addresses rows by (`data-node-id`). Keying it by path instead
 * would give a key press and a click on the same row two different names for
 * the same folder.
 */
interface TreeNav {
  keys: TreeKeyboard
  isExpanded: (id: string) => boolean
  setExpanded: (id: string, expanded: boolean) => void
  onSelect: (row: FileRow) => void
  onOpen: (row: FileRow) => void
}

/**
 * Renders a level's children incrementally: only the first RENDER_CHUNK rows
 * are in the DOM, and a scroll sentinel reveals the next chunk as it comes into
 * view. A directory with thousands of entries stays smooth instead of mounting
 * every row at once. `resetKey` (the parent path) resets the window when the
 * level changes.
 */
function LazyChildren({
  items,
  resetKey,
  pad,
  render,
}: {
  items: FileRow[]
  resetKey: string
  pad: number
  render: (item: FileRow) => ReactNode
}) {
  const [count, setCount] = useState(RENDER_CHUNK)
  const sentinelRef = useRef<HTMLLIElement>(null)

  useEffect(() => {
    setCount(RENDER_CHUNK)
  }, [resetKey])

  useEffect(() => {
    if (count >= items.length) return
    // No IntersectionObserver (e.g. tests): reveal everything rather than hide.
    if (typeof IntersectionObserver === 'undefined') {
      setCount(items.length)
      return
    }
    const el = sentinelRef.current
    if (!el) return
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setCount((c) => Math.min(c + RENDER_CHUNK, items.length))
        }
      },
      { rootMargin: '260px' },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [count, items.length])

  return (
    <>
      {items.slice(0, count).map(render)}
      {count < items.length && (
        <li
          ref={sentinelRef}
          role="none"
          className="ft-note"
          style={{ paddingLeft: pad }}
        >
          Loading {formatCount(items.length - count)} more…
        </li>
      )}
    </>
  )
}

function TreeNode({
  caseId,
  sourceId,
  node,
  depth,
  selectedId,
  nav,
}: {
  caseId: string
  sourceId: string
  node: FileRow
  depth: number
  selectedId: string | null
  nav: TreeNav
}) {
  const isDir = node.is_directory
  const expanded = isDir && nav.isExpanded(node.id)
  const children = useChildren(caseId, sourceId, node.path, isDir && expanded)
  const ordered = useMemo(
    () => (children.data ? orderNodes(children.data.items) : []),
    [children.data],
  )
  const pad = 6 + depth * 16

  const rowClass = ['ft-row']
  if (node.id === selectedId) rowClass.push('selected')

  return (
    <li
      // The row, not the caret and name inside it, is the tab stop and the
      // keyboard's unit: exactly one node in the whole tree is tabbable, so
      // Tab-ing past a tree opened six levels deep costs one press rather than
      // two per node. `rowProps` carries that contract, shared with the
      // navigator trees so there is one implementation of it and not two.
      {...nav.keys.rowProps({
        id: node.id,
        expandable: isDir,
        expanded,
        // Enter on a file opens the artifact; on a folder the shared contract
        // toggles it, which is what `expandable` above already says.
        activate: isDir ? undefined : () => nav.onOpen(node),
        // Space does what a single click on this row does: a folder opens or
        // closes, a file fills the detail pane without leaving the tree.
        preview: isDir
          ? () => nav.setExpanded(node.id, !expanded)
          : () => nav.onSelect(node),
      })}
      aria-selected={node.id === selectedId}
    >
      <div
        className={rowClass.join(' ')}
        style={{ paddingLeft: pad }}
        onClick={() => {
          if (isDir) nav.setExpanded(node.id, !expanded)
          else nav.onSelect(node)
        }}
        onDoubleClick={() => {
          if (isDir) nav.setExpanded(node.id, !expanded)
          else nav.onOpen(node)
        }}
        title={node.path}
      >
        {isDir ? (
          <span className="ft-caret" aria-hidden="true">
            {expanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
          </span>
        ) : (
          <span className="ft-caret ft-caret-empty" aria-hidden="true" />
        )}
        {isDir ? (
          <Folder size={14} className="ft-glyph ft-glyph-dir" aria-hidden="true" />
        ) : (
          (() => {
            const Icon = iconForName(node.name)
            return <Icon size={14} className="ft-glyph ft-glyph-file" aria-hidden="true" />
          })()
        )}
        <span className={node.is_deleted ? 'ft-name ft-name-deleted' : 'ft-name'}>
          {node.name}
        </span>
        {!isDir && node.size != null && (
          <span className="ft-size mono">{formatBytes(node.size)}</span>
        )}
        {node.is_deleted && (
          <span className="badge badge-danger ft-badge">Deleted</span>
        )}
        {!node.is_deleted && isCarved(node) && (
          <span className="badge badge-accent ft-badge">Carved</span>
        )}
        {node.known_status === 'notable' && (
          <span
            className="badge fg-badge-notable ft-badge"
            title="Hash-set hit on a NOTABLE / known-bad set."
          >
            Notable
          </span>
        )}
        {/* The standard incompleteness stamps, the same signal the grid and the
            folder sidebar show. This level already fetches the metadata; a
            folder whose entry listing the parser could not finish, or a file
            whose bytes are partial, would otherwise sit in the tree looking
            exactly like a whole one. */}
        <IncompleteBadge metadata={node.metadata} />
      </div>
      {isDir && expanded && (
        <ul className="ft-list" role="group">
          {children.isPending && (
            <li role="none" className="ft-note" style={{ paddingLeft: pad + 22 }}>
              loading…
            </li>
          )}
          {children.isError && (
            <li role="none" className="ft-note" style={{ paddingLeft: pad + 22 }}>
              failed to load
            </li>
          )}
          {children.data && (
            <LazyChildren
              items={ordered}
              resetKey={node.path}
              pad={pad + 22}
              render={(child) => (
                <TreeNode
                  key={child.id}
                  caseId={caseId}
                  sourceId={sourceId}
                  node={child}
                  depth={depth + 1}
                  selectedId={selectedId}
                  nav={nav}
                />
              )}
            />
          )}
          {children.data && children.data.items.length === 0 && (
            <li role="none" className="ft-note" style={{ paddingLeft: pad + 22 }}>
              empty
            </li>
          )}
          {children.data &&
            children.data.total_count > children.data.items.length && (
              <li role="none" className="ft-note" style={{ paddingLeft: pad + 22 }}>
                {formatCount(
                  children.data.total_count - children.data.items.length,
                )}{' '}
                more entries not shown at this level
              </li>
            )}
        </ul>
      )}
    </li>
  )
}

/**
 * Single-pane, fully expandable file-system tree. Each directory lazily
 * fetches its children (folders and files) when first expanded. Clicking a
 * file selects it (populating the detail pane); double-click opens it.
 *
 * The WAI-ARIA tree keyboard contract — Up/Down between visible rows, Right to
 * open then step in, Left to close then step out, Home/End, type-ahead, Enter
 * to activate, Space to preview — comes from `useTreeKeyboard`, the same
 * implementation the evidence and logical trees run. This component announced
 * `role="tree"` long before it behaved like one, which told a screen-reader
 * user to expect arrow keys that did nothing: a promise that is worse than
 * announcing a plain list, because the user cannot tell a broken tree from one
 * they are driving wrongly. Having then written the contract out twice, in two
 * files, was the same hazard one step further on — the second copy is where a
 * key silently stops behaving like the first.
 */
export function FileTree({
  caseId,
  sourceId,
  selectedId,
  onSelect,
  onOpen,
}: {
  caseId: string
  sourceId: string
  selectedId: string | null
  onSelect: (row: FileRow) => void
  onOpen: (row: FileRow) => void
}) {
  const roots = useChildren(caseId, sourceId, '', true)
  const orderedRoots = useMemo(
    () => (roots.data ? orderNodes(roots.data.items) : []),
    [roots.data],
  )

  const [expandedIds, setExpandedIds] = useState<ReadonlySet<string>>(
    () => new Set<string>(),
  )

  const setExpanded = useCallback((id: string, next: boolean) => {
    setExpandedIds((prev) => {
      if (prev.has(id) === next) return prev
      const copy = new Set(prev)
      if (next) copy.add(id)
      else copy.delete(id)
      return copy
    })
  }, [])

  // The rows are named by `.ft-name`, not by the navigator trees'
  // `.tree-label`, so the type-ahead is told where to read a row's name.
  const keys = useTreeKeyboard({ setExpanded, labelSelector: '.ft-name' })

  const nav = useMemo<TreeNav>(
    () => ({
      keys,
      isExpanded: (id: string) => expandedIds.has(id),
      setExpanded,
      onSelect,
      onOpen,
    }),
    [expandedIds, keys, onOpen, onSelect, setExpanded],
  )

  return (
    <div className="ft">
      {roots.isPending ? (
        <SkeletonList rows={12} label="Loading file system" />
      ) : roots.isError ? (
        <div className="ft-note">Could not load file system.</div>
      ) : roots.data.items.length === 0 ? (
        <div className="ft-note">No entries.</div>
      ) : (
        <ul
          ref={nav.keys.treeRef}
          className="ft-list"
          role="tree"
          aria-label="File system tree"
        >
          <LazyChildren
            items={orderedRoots}
            resetKey=""
            pad={0}
            render={(node) => (
              <TreeNode
                key={node.id}
                caseId={caseId}
                sourceId={sourceId}
                node={node}
                depth={0}
                selectedId={selectedId}
                nav={nav}
              />
            )}
          />
          {roots.data.total_count > roots.data.items.length && (
            <li role="none" className="ft-note">
              {formatCount(
                roots.data.total_count - roots.data.items.length,
              )}{' '}
              more entries not shown at this level
            </li>
          )}
        </ul>
      )}
    </div>
  )
}
