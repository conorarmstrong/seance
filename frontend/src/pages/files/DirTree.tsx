import { useQuery } from '@tanstack/react-query'
import { useCallback, useState } from 'react'
import { ChevronRight, ChevronDown } from 'lucide-react'
import { IncompleteBadge } from '../../components/Incompleteness'
import {
  useTreeKeyboard,
  type TreeKeyboard,
} from '../../components/tree/useTreeKeyboard'
import { listFiles } from './api'
import type { FileRow } from './types'
import { formatCount } from '../../lib/format'

// Per-level fetch cap (the server clamps page_size to this ceiling). A level
// with more immediate subfolders than this shows a truncation note rather than
// silently hiding them — see `hiddenAtLevel` below. Sibling `FileTree` uses the
// same rule.
const TREE_PAGE_SIZE = 500

/**
 * How many subfolders at this level the server holds but did not send.
 *
 * What the examiner learns: whether the folders listed under a node are ALL of
 * that node's folders. Only page 1 is ever fetched, so without this a directory
 * with more than `TREE_PAGE_SIZE` immediate subfolders renders as a complete
 * level. A wrong answer here looks like an evidence tree with no folder at the
 * expected path — an absence the examiner would report as fact, when the folder
 * was merely on page 2.
 */
function hiddenAtLevel(data: { total_count: number; items: unknown[] }): number {
  return Math.max(0, data.total_count - data.items.length)
}

// Directory-only listing of one path level. An empty prefix lists the
// filesystem root. The hierarchy is read from the `path` column, not
// parent_id, so it works even when files are stored flat under the
// FileSystem artifact.
function useDirChildren(
  caseId: string,
  sourceId: string,
  prefix: string,
  enabled: boolean,
) {
  return useQuery({
    queryKey: ['files-dirtree', caseId, sourceId, prefix],
    queryFn: () =>
      listFiles(caseId, sourceId, {
        path: prefix,
        dirs: 'only',
        sort: 'name',
        order: 'asc',
        page: 1,
        page_size: TREE_PAGE_SIZE,
        // The filesystem parsers (ext4, FAT/exFAT, XFS, btrfs, APFS) stamp
        // `directory_parse_incomplete` on the folder whose listing they could
        // not finish, and that stamp lives in the artifact's metadata. Without
        // asking for it the tree cannot tell a folder that held four files from
        // one whose listing stopped at a cap — and the tree is where an
        // examiner decides a path is not in the evidence. Sibling `FileTree`
        // already fetches metadata for the same rows.
        include_metadata: true,
      }),
    enabled,
  })
}

function TreeNode({
  caseId,
  sourceId,
  node,
  depth,
  currentDirPath,
  keys,
  isExpanded,
  setExpanded,
  onSelect,
}: {
  caseId: string
  sourceId: string
  node: FileRow
  depth: number
  currentDirPath: string
  keys: TreeKeyboard
  isExpanded: (id: string) => boolean
  setExpanded: (id: string, expanded: boolean) => void
  onSelect: (path: string) => void
}) {
  const expanded = isExpanded(node.id)
  const children = useDirChildren(caseId, sourceId, node.path, expanded)
  const isCurrent = currentDirPath === node.path

  return (
    <li
      // The row is the tree's single tab stop and the unit its keys act on, so
      // the caret and the label below stop being tab stops of their own: a
      // Windows path six folders deep cost twelve Tab presses to walk past.
      // Every subfolder can hold subfolders until it has been opened and shown
      // not to, so `expandable` is true for all of them; a folder that turns
      // out to be empty says "no subfolders" once it is open.
      //
      // Neither `activate` nor `preview` is overridden, so the shared contract
      // stands as written: Enter opens the folder in place and Space clicks the
      // row's label, which navigates the grid into it. Those are exactly the
      // two destinations the mouse already has — the caret and the label.
      {...keys.rowProps({ id: node.id, expandable: true, expanded })}
      aria-current={isCurrent ? 'true' : undefined}
    >
      <div className="fg-tree-row" style={{ paddingLeft: depth * 14 }}>
        <button
          type="button"
          className="fg-tree-caret"
          // Not a tab stop: the row above is. It stays clickable, and it keeps
          // its own label because a screen-reader user driving it with the
          // pointer still has to be told which folder it opens.
          tabIndex={-1}
          aria-expanded={expanded}
          aria-label={expanded ? `Collapse ${node.name}` : `Expand ${node.name}`}
          onClick={() => setExpanded(node.id, !expanded)}
        >
          {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </button>
        <button
          type="button"
          className={isCurrent ? 'fg-tree-label current' : 'fg-tree-label'}
          tabIndex={-1}
          title={node.path}
          onClick={() => onSelect(node.path)}
        >
          {node.name}
        </button>
        {/* A folder the parser could not enumerate in full. The count of
            subfolders below is then a floor, and so is every "no such path"
            conclusion drawn from this tree. */}
        <IncompleteBadge metadata={node.metadata} />
      </div>
      {expanded && (
        <ul className="fg-tree-list" role="group">
          {children.isPending && (
            <li
              role="none"
              className="fg-tree-note"
              style={{ paddingLeft: (depth + 1) * 14 }}
            >
              loading…
            </li>
          )}
          {children.isError && (
            <li
              role="none"
              className="fg-tree-note"
              style={{ paddingLeft: (depth + 1) * 14 }}
            >
              failed to load
            </li>
          )}
          {children.data?.items.map((child) => (
            <TreeNode
              key={child.id}
              caseId={caseId}
              sourceId={sourceId}
              node={child}
              depth={depth + 1}
              currentDirPath={currentDirPath}
              keys={keys}
              isExpanded={isExpanded}
              setExpanded={setExpanded}
              onSelect={onSelect}
            />
          ))}
          {children.data?.items.length === 0 && (
            <li
              role="none"
              className="fg-tree-note"
              style={{ paddingLeft: (depth + 1) * 14 }}
            >
              no subfolders
            </li>
          )}
          {children.data && hiddenAtLevel(children.data) > 0 && (
            <li
              className="fg-tree-note fg-tree-truncated"
              role="note"
              style={{ paddingLeft: (depth + 1) * 14 }}
            >
              {formatCount(hiddenAtLevel(children.data))} more folders not
              shown at this level
            </li>
          )}
        </ul>
      )}
    </li>
  )
}

/**
 * The folder sidebar beside the file grid: a directory-only tree that lazily
 * fetches each level and navigates the grid into whichever folder is clicked.
 *
 * Its keyboard contract comes from `useTreeKeyboard`, the same implementation
 * the file system tree and the two navigator trees run, so an examiner who has
 * learned the keys in one of them has learned them here. Before that this was a
 * plain list of buttons that announced nothing, and cost two Tab presses per
 * folder to walk past.
 */
export function DirTree({
  caseId,
  sourceId,
  currentDirPath,
  onSelect,
}: {
  caseId: string
  sourceId: string
  currentDirPath: string
  onSelect: (path: string | null) => void
}) {
  const roots = useDirChildren(caseId, sourceId, '', true)

  // Expansion is held here rather than in each node because the keys act on
  // rows other than the one pressed — Right stepping into a folder it just
  // opened, Left closing the parent of the focused row — and because a node's
  // own state would not survive its subtree collapsing out from under it. It is
  // keyed by artifact id, which is what the hook addresses rows by.
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
  const isExpanded = useCallback(
    (id: string) => expandedIds.has(id),
    [expandedIds],
  )
  const keys = useTreeKeyboard({
    setExpanded,
    labelSelector: '.fg-tree-label',
  })

  return (
    <nav className="fg-tree" aria-label="Directory tree">
      <button
        type="button"
        className={
          currentDirPath === ''
            ? 'fg-tree-label fg-tree-root current'
            : 'fg-tree-label fg-tree-root'
        }
        aria-current={currentDirPath === '' ? 'true' : undefined}
        onClick={() => onSelect(null)}
      >
        Root
      </button>
      {roots.isPending ? (
        <div className="fg-tree-note">loading…</div>
      ) : roots.isError ? (
        <div className="fg-tree-note">Could not load folders.</div>
      ) : roots.data.items.length === 0 ? (
        <div className="fg-tree-note">No folders.</div>
      ) : (
        <ul
          ref={keys.treeRef}
          className="fg-tree-list"
          role="tree"
          aria-label="Folders"
        >
          {roots.data.items.map((node) => (
            <TreeNode
              key={node.id}
              caseId={caseId}
              sourceId={sourceId}
              node={node}
              depth={0}
              currentDirPath={currentDirPath}
              keys={keys}
              isExpanded={isExpanded}
              setExpanded={setExpanded}
              onSelect={onSelect}
            />
          ))}
          {hiddenAtLevel(roots.data) > 0 && (
            <li className="fg-tree-note fg-tree-truncated" role="note">
              {formatCount(hiddenAtLevel(roots.data))} more folders not shown
              at this level
            </li>
          )}
        </ul>
      )}
    </nav>
  )
}
