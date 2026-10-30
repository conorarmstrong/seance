import {
  LayoutDashboard,
  Clock,
  Search,
  Share2,
  Fingerprint,
  Bookmark,
  Filter,
  FileDigit,
  ScrollText,
  Settings,
  HelpCircle,
  MonitorCog,
  CopyCheck,
  MemoryStick,
  MessagesSquare,
  Images,
  Flag,
  MapPin,
  TerminalSquare,
  Database,
} from 'lucide-react'
import type { ComponentType } from 'react'

export interface NavItem {
  to: string
  label: string
  icon: ComponentType<{ size?: number; className?: string }>
  end?: boolean
}

export interface NavSection {
  /** Section heading, or `null` for an unlabelled group (none today). */
  section: string
  items: NavItem[]
}

// The case sidebar, grouped so it says which QUESTION each click answers rather
// than presenting a flat list where a per-acquisition destination (Memory) sits
// next to case admin (Settings). Five groups:
//
//   Overview  — the front door.
//   Analyse   — cross-cutting analyses that deliberately span ALL evidence.
//   Evidence  — machine-state readers scoped to acquired evidence. Memory lives
//               here: a RAM capture is evidence (an acquisition with a hash and
//               custody), NOT a cross-cutting tool. It leads into the acquisition
//               navigator directly below it.
//   Curate    — examiner-authored artifacts (bookmarks, filters, hash sets).
//   Admin     — case management and help.
//
// Browsing INDIVIDUAL RECORDS by type is still the job of the Physical/Logical
// navigator below this rail, so there is no "Workbench" item; you reach a single
// record from the navigator. The five category OVERVIEWS are a different thing
// and they are in the rail: Communications, Gallery, Map, Execution and Parsed
// Records answer whole questions ("who did they talk to", "where has this
// device been") over the entire case, and each used to be reachable only by
// noticing the Physical/Logical toggle at the bottom of the sidebar and
// switching lenses. An examiner inheriting a case does not know that toggle
// exists, so those five surfaces were, in practice, never opened by the second
// examiner at all.
//
// The Analyse group reads in four runs: the two universal entry points
// (Timeline, Search), then the four question-shaped subject views, then the
// derived cross-cutting analyses, then the index of everything parsed.
export const NAV_SECTIONS: NavSection[] = [
  {
    section: 'Overview',
    items: [{ to: '', label: 'Dashboard', icon: LayoutDashboard, end: true }],
  },
  {
    section: 'Analyse',
    items: [
      // First, because it is the answer to "where do I start". It is the only
      // surface in the rail that carries Séance's own claims rather than
      // transcriptions of the evidence, and the page says so before its first
      // row (§2.2).
      { to: 'findings', label: 'Findings', icon: Flag },
      { to: 'timeline', label: 'Timeline', icon: Clock },
      { to: 'search', label: 'Search', icon: Search },
      // Each of these four is labelled with the heading the page itself
      // carries, so the rail, the browser tab and a screenshot pasted into a
      // statement all name the same surface. "Gallery" is the pictures view
      // specifically -- the videos and audio galleries are separate addresses
      // (`gallery?kind=`), offered in the command palette rather than given
      // three near-identical rail rows.
      { to: 'communications', label: 'Communications', icon: MessagesSquare },
      { to: 'gallery', label: 'Gallery', icon: Images },
      { to: 'geo', label: 'Map', icon: MapPin },
      { to: 'execution', label: 'Execution', icon: TerminalSquare },
      { to: 'connections', label: 'Connections', icon: Share2 },
      { to: 'entities', label: 'Entities', icon: Fingerprint },
      { to: 'duplicates', label: 'Duplicates', icon: CopyCheck },
      // "Parsed Records", not the page's own "Analysis": an item called
      // Analysis inside a group called Analyse says nothing about which of the
      // two it is. The page's own subtitle is "Parsed forensic records grouped
      // by type", which is what this index actually is.
      { to: 'analysis', label: 'Parsed Records', icon: Database },
    ],
  },
  {
    section: 'Evidence',
    items: [
      { to: 'system-info', label: 'System Info', icon: MonitorCog },
      { to: 'memory', label: 'Memory', icon: MemoryStick },
    ],
  },
  {
    section: 'Curate',
    items: [
      { to: 'bookmarks', label: 'Bookmarks', icon: Bookmark },
      { to: 'filters', label: 'Filters', icon: Filter },
      { to: 'hash-sets', label: 'Hash Sets', icon: FileDigit },
    ],
  },
  {
    section: 'Admin',
    items: [
      { to: 'audit', label: 'Audit Log', icon: ScrollText },
      { to: 'settings', label: 'Settings', icon: Settings },
      { to: 'help', label: 'Help', icon: HelpCircle },
    ],
  },
]

/**
 * Every nav item, flattened across sections.
 *
 * The command palette (⌘K) and any other consumer that needs the full item list
 * MUST derive it from here, never from a section, or a whole group of views
 * silently becomes unreachable from the palette.
 */
export const NAV_ITEMS: NavItem[] = NAV_SECTIONS.flatMap((s) => s.items)

/**
 * The count to show on the Memory nav item, or `null` to show none.
 *
 * A case with zero or one capture needs no count: the Memory shell itself makes
 * a single capture (or the absence of one) obvious. The badge earns its place
 * only when the case holds MORE than one capture, where it answers a question
 * the flat rail otherwise hides — "how many machines' RAM is in this case?" —
 * before the examiner has clicked in. `undefined` (count not yet loaded) shows
 * nothing rather than a flash of `0`.
 */
export function memoryCountBadge(imageCount: number | undefined): number | null {
  if (imageCount === undefined || imageCount <= 1) return null
  return imageCount
}
