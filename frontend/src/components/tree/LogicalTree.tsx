import type {
  ComponentType,
  MouseEvent as ReactMouseEvent,
  ReactNode,
} from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { formatCount } from '../../lib/format'
import {
  Boxes,
  Calendar,
  ChevronDown,
  ChevronRight,
  Cog,
  Database,
  Globe,
  Image as ImageIcon,
  Mail,
  MapPin,
  MessageSquare,
  Package,
  Phone,
  Play,
  Users, 
  Film,
  Music,
} from 'lucide-react'
import { getMediaCounts } from '../../api/resources'
import { useCallback } from 'react'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { useTreeKeyboard } from './useTreeKeyboard'
import { useSourceFilter } from '../../lib/useSourceFilter'
import { SourceSelect } from '../SourceSelect'
import { getRecordTypes } from '../../pages/analysis/api'
import {
  buildLogicalTree,
  CATEGORY_VIEW,
  type CategoryKey,
  type CategoryView,
} from './categories'
import './tree.css'

const CATEGORY_ICONS: Record<CategoryKey, ComponentType<{ size?: number }>> = {
  chats: MessageSquare,
  contacts: Users,
  calls: Phone,
  email: Mail,
  calendar: Calendar,
  web: Globe,
  apps: Package,
  execution: Play,
  system: Cog,
  storage: Database,
  other: Boxes,
}

/**
 * The canonical address of each category view, relative to `/cases/<id>/`.
 *
 * These leaves used to link to `/workbench?view=<view>`, which was the address
 * of every view before the route table settled on one address per view and left
 * the workbench form behind as a redirect. The links still arrived — that is
 * why nothing caught it — but an examiner following one watched the address bar
 * change to a URL they had not clicked, anything copied or bookmarked before
 * the redirect landed recorded the superseded form, and every click cost a
 * second navigation. The rail and the ⌘K palette were already pointing at the
 * addresses below; the navigator was the surface still pointing at the old one.
 *
 * Videos and audio are the gallery under a different `?kind=` rather than pages
 * of their own, so the query string is part of the address here: dropping it
 * would collapse all three leaves onto pictures.
 *
 * Held as a literal rather than imported from the route table, because the
 * route module pulls in the case shell — which contains this tree. The join is
 * asserted instead: LogicalTree.test.tsx builds every expectation below by
 * asking the route table what the old `?view=` form redirects to, so a view
 * that moves fails here rather than drifting.
 */
const VIEW_PATH: Record<CategoryView, string> = {
  gallery: 'gallery',
  videos: 'gallery?kind=videos',
  audio: 'gallery?kind=audio',
  geo: 'geo',
  comms: 'communications',
  execution: 'execution',
}

/** Nothing expanded. Shared reference (`useEntityScopedState` returns it
 *  verbatim under another case); `toggle` copies before writing, never mutates. */
const NOTHING_EXPANDED: Set<string> = new Set()

/** Leaf categories backed by file/geo counts (not record-derived). */
const MEDIA_CATEGORIES: {
  key: string
  label: string
  icon: ComponentType<{ size?: number }>
  view: CategoryView
  countKey: 'pictures' | 'videos' | 'audio' | 'geolocation'
  /** Media kinds sit under a "Media" parent; Geolocation stays top-level. */
  underMedia?: boolean
}[] = [
  {
    key: 'pictures',
    label: 'Pictures',
    icon: ImageIcon,
    view: 'gallery',
    countKey: 'pictures',
    underMedia: true,
  },
  {
    key: 'videos',
    label: 'Videos',
    icon: Film,
    view: 'videos',
    countKey: 'videos',
    underMedia: true,
  },
  {
    key: 'audio',
    label: 'Audio',
    icon: Music,
    view: 'audio',
    countKey: 'audio',
    underMedia: true,
  },
  {
    key: 'geolocation',
    label: 'Geolocation',
    icon: MapPin,
    view: 'geo',
    countKey: 'geolocation',
  },
]

/**
 * The logical navigator lens: evidence grouped by examiner category with live
 * counts. Media categories (Pictures, Geolocation) and category overviews
 * (Chats → comms, Program Execution → execution) open a dedicated view; record
 * categories expand to their member types. In the workbench (callbacks given)
 * selection happens in place; in the sidebar each leaf is a link to that view's
 * own canonical address — the same one the nav rail and the ⌘K palette use, so
 * the three routes to a view all quote the same URL.
 */
export function LogicalTree({
  caseId,
  onSelectType,
  selectedType,
  onTypeContextMenu,
  onSelectView,
  selectedView,
}: {
  caseId: string
  onSelectType?: (type: string) => void
  selectedType?: string
  onTypeContextMenu?: (
    e: ReactMouseEvent,
    node: { type: string; label: string; count: number },
  ) => void
  onSelectView?: (view: CategoryView) => void
  selectedView?: CategoryView
}) {
  // Which acquisition the examiner has scoped the lens to, or undefined for the
  // whole case. A RAM/disk capture yields records too, so the Logical lens must
  // be able to attribute what it shows to the source it came from — the same
  // provenance discipline the Memory lens already enforces.
  const source = useSourceFilter(caseId)
  const activeSource = source.activeSource

  // Shares the cache key with AnalysisIndexPage for the case-wide view; a scoped
  // view keys on the source so counts never carry across a source change.
  const query = useQuery({
    queryKey: activeSource
      ? ['analysis-types', caseId, activeSource]
      : ['analysis-types', caseId],
    queryFn: () => getRecordTypes(caseId, activeSource),
  })
  const media = useQuery({
    queryKey: ['media-counts', caseId],
    queryFn: () => getMediaCounts(caseId),
  })
  // Scoped to the case: this tree lives in the sidebar, and only the routed
  // Outlet is remounted when `:caseId` changes. In plain state the expand set
  // survived that switch, so case A's open categories stayed open under case B
  // -- and the keys are category slugs ('chats'), which exist in both cases, so
  // the stale entries do match and the examiner is shown another case's chrome.
  const [open, setOpen] = useEntityScopedState<Set<string>>(
    caseId,
    NOTHING_EXPANDED,
  )

  // The keyboard contract, shared with the evidence tree. It has to be built
  // before the loading and error returns below, and it owns nothing: expansion
  // stays in `open` above, which is where it has to be for the keys that act
  // on a row other than the one pressed.
  const setExpanded = useCallback(
    (key: string, next: boolean) => {
      setOpen((prev) => {
        if (prev.has(key) === next) return prev
        const copy = new Set(prev)
        if (next) copy.add(key)
        else copy.delete(key)
        return copy
      })
    },
    [setOpen],
  )
  const nav = useTreeKeyboard({ setExpanded })

  // A record type's destination — the canonical records-viewer address, not the
  // `workbench?type=` form that now only redirects onto it. The source filter
  // travels with it, so the table it opens lists exactly the rows this scoped
  // count promised; a link that dropped the scope would show case-wide rows
  // under a heading the examiner had narrowed to one acquisition.
  const typeHref = (type: string) => {
    const base = `/cases/${caseId}/analysis/${encodeURIComponent(type)}`
    return activeSource ? `${base}?source=${activeSource}` : base
  }

  // The source filter, offered only for a multi-source case. It always renders
  // (even over a loading/empty tree) so scoping to a source that turns out to
  // hold no records is never a dead end — the examiner can switch back.
  const sourceFilter = (
    <SourceSelect
      filter={source}
      id="logical-source"
      wrapperClassName="tree-source-filter"
      labelClassName="tree-source-filter-label"
      selectClassName="tree-source-select"
    />
  )

  const frame = (children: ReactNode) => (
    <div className="tree-logical">
      {sourceFilter}
      {children}
    </div>
  )

  if (query.isLoading) return frame(<div className="tree-note">loading…</div>)
  if (query.isError) {
    return frame(<div className="tree-note">Could not load artifacts.</div>)
  }

  const categories = buildLogicalTree(query.data?.record_types ?? [])
  // Media counts and the aggregate category views (gallery/geo/comms/execution)
  // are not source-attributable in this build, so while a source is scoped they
  // are withheld rather than shown case-wide under a per-source lens. The record
  // categories below stay, fully scoped end to end.
  const specials = activeSource
    ? []
    : MEDIA_CATEGORIES.filter((m) => (media.data?.[m.countKey] ?? 0) > 0)

  if (categories.length === 0 && specials.length === 0) {
    return frame(
      <div className="tree-note">
        {activeSource
          ? 'This source has no parsed records.'
          : 'No parsed records yet. Run analysis to populate this view.'}
      </div>,
    )
  }

  const toggle = (key: string) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })

  // A label that opens a view: an in-place button in the workbench, or a link
  // into the workbench with that view preselected from the sidebar.
  const viewLabel = (label: string, view: CategoryView) =>
    onSelectView ? (
      <button
        className={`tree-label tree-label-btn${selectedView === view ? ' active' : ''}`}
        tabIndex={-1}
        onClick={() => onSelectView(view)}
        title={label}
      >
        {label}
      </button>
    ) : (
      <Link
        className="tree-label"
        tabIndex={-1}
        to={`/cases/${caseId}/${VIEW_PATH[view]}`}
        title={label}
      >
        {label}
      </Link>
    )

  const mediaKinds = specials.filter((m) => m.underMedia)
  const mediaTotal = mediaKinds.reduce(
    (n, m) => n + (media.data?.[m.countKey] ?? 0),
    0,
  )
  const mediaOpen = open.has('__media')

  const mediaLeaf = (m: (typeof MEDIA_CATEGORIES)[number], nested: boolean) => {
    const Icon = m.icon
    return (
      <li
        key={m.key}
        {...nav.rowProps({ id: m.key, expandable: false, expanded: false })}
      >
        <div className={nested ? 'tree-row tree-row-nested' : 'tree-row'}>
          <span className="tree-caret-spacer" />
          <span className="tree-glyph" aria-hidden="true">
            <Icon size={14} />
          </span>
          {viewLabel(m.label, m.view)}
          <span className="tree-count mono">
            {formatCount(media.data?.[m.countKey] ?? 0)}
          </span>
        </div>
      </li>
    )
  }

  return frame(
    <ul
      ref={nav.treeRef}
      className="tree-list tree-root"
      role="tree"
      aria-label="Evidence by category"
    >
      {mediaKinds.length > 0 && (
        <li
          {...nav.rowProps({
            id: '__media',
            expandable: true,
            expanded: mediaOpen,
          })}
        >
          <div className="tree-row">
            <button
              className="tree-caret"
              // Not a tab stop: the row is. Two stops per node — caret then
              // label — is what made the navigator unreachable by keyboard.
              tabIndex={-1}
              aria-label={mediaOpen ? 'Collapse Media' : 'Expand Media'}
              onClick={() => toggle('__media')}
            >
              {mediaOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
            <span className="tree-glyph" aria-hidden="true">
              <ImageIcon size={14} />
            </span>
            <span className="tree-label">Media</span>
            <span className="tree-count mono">
              {formatCount(mediaTotal)}
            </span>
          </div>
          {mediaOpen && (
            <ul className="tree-list" role="group">
              {mediaKinds.map((m) => mediaLeaf(m, true))}
            </ul>
          )}
        </li>
      )}
      {specials.filter((m) => !m.underMedia).map((m) => {
        const Icon = m.icon
        return (
          <li
            key={m.key}
            {...nav.rowProps({ id: m.key, expandable: false, expanded: false })}
          >
            <div className="tree-row">
              <span className="tree-caret-spacer" />
              <span className="tree-glyph" aria-hidden="true">
                <Icon size={14} />
              </span>
              {viewLabel(m.label, m.view)}
              <span className="tree-count mono">
                {formatCount(media.data?.[m.countKey] ?? 0)}
              </span>
            </div>
          </li>
        )
      })}
      {categories.map((cat) => {
        const Icon = CATEGORY_ICONS[cat.key] ?? Boxes
        const expanded = open.has(cat.key)
        // While scoped to a source, a category's dedicated aggregate view
        // (Chats→comms, Program Execution→execution) is case-wide and cannot
        // honour the filter, so the category behaves as a plain expandable one:
        // its scoped typed children carry the source into their own tables.
        const view = activeSource ? undefined : CATEGORY_VIEW[cat.key]
        return (
          <li
            key={cat.key}
            {...nav.rowProps({
              id: cat.key,
              expandable: true,
              expanded,
            })}
          >
            <div className="tree-row">
              <button
                className="tree-caret"
                tabIndex={-1}
                aria-label={expanded ? 'Collapse' : 'Expand'}
                onClick={() => toggle(cat.key)}
              >
                {expanded ? (
                  <ChevronDown size={16} />
                ) : (
                  <ChevronRight size={16} />
                )}
              </button>
              <span className="tree-glyph" aria-hidden="true">
                <Icon size={14} />
              </span>
              {view ? (
                viewLabel(cat.label, view)
              ) : (
                <button
                  className="tree-label tree-cat-label"
                  tabIndex={-1}
                  onClick={() => toggle(cat.key)}
                >
                  {cat.label}
                </button>
              )}
              <span className="tree-count mono">
                {formatCount(cat.count)}
              </span>
            </div>
            {expanded && (
              <ul className="tree-list" role="group">
                {cat.children.map((node) => (
                  <li
                    key={node.type}
                    {...nav.rowProps({
                      id: node.type,
                      expandable: false,
                      expanded: false,
                    })}
                  >
                    <div
                      className="tree-row"
                      style={{ paddingLeft: 14 }}
                      onContextMenu={
                        onTypeContextMenu
                          ? (e) => onTypeContextMenu(e, node)
                          : undefined
                      }
                    >
                      <span className="tree-caret-spacer" />
                      {onSelectType ? (
                        <button
                          className={`tree-label tree-label-btn${selectedType === node.type ? ' active' : ''}`}
                          tabIndex={-1}
                          onClick={() => onSelectType(node.type)}
                          title={node.label}
                        >
                          {node.label}
                        </button>
                      ) : (
                        <Link
                          className="tree-label"
                          tabIndex={-1}
                          to={typeHref(node.type)}
                          title={node.label}
                        >
                          {node.label}
                        </Link>
                      )}
                      <span className="tree-count mono">
                        {formatCount(node.count)}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </li>
        )
      })}
    </ul>,
  )
}
