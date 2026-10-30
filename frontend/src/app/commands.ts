import type { Command } from '../components/CommandPalette'
import { NAV_ITEMS } from './nav'

/**
 * A view inside one case, named the way an examiner would ask for it.
 *
 * `to` is the address relative to `/cases/:caseId` — the SAME string the nav
 * rail uses — so the rail and the ⌘K palette cannot drift into offering two
 * different addresses for one view. It may carry a query string where the query
 * is what distinguishes the view (the videos and audio galleries).
 */
export interface CaseDestination {
  to: string
  label: string
  /**
   * The words an examiner says out loud for this view but which never appear
   * in its label. These are matched by the palette in addition to the label,
   * and the one that matched is shown on the row — so someone who typed
   * "whatsapp" is told, on the spot, that the view is called Communications.
   */
  keywords: string[]
}

/**
 * Aliases for the rail's views, keyed by the address so a relabelled item keeps
 * its aliases.
 *
 * The list is deliberately the vocabulary of the QUESTION, not of the schema:
 * "who did they talk to" arrives as "chats" or "whatsapp", never as
 * "communications", and a palette that matched only the filing name answered
 * every one of those with "No matches" — which reads as the product not having
 * the view at all rather than as the query being loose.
 */
const NAV_ALIASES: Record<string, string[]> = {
  '': ['overview', 'home', 'front page', 'case summary', 'sources'],
  timeline: ['events', 'chronology', 'when', 'activity', 'super timeline'],
  search: ['find', 'keyword', 'grep', 'full text', 'query'],
  communications: [
    'chats',
    'messages',
    'texts',
    'sms',
    'imessage',
    'whatsapp',
    'calls',
    'email',
    'conversations',
    'contacted',
  ],
  gallery: ['pictures', 'photos', 'images', 'media', 'exif', 'thumbnails'],
  geo: [
    'geo',
    'gps',
    'location',
    'geolocation',
    'where',
    'coordinates',
    'places',
    'track',
  ],
  execution: [
    'programs',
    'prefetch',
    'amcache',
    'shimcache',
    'what ran',
    'launched',
    'executables',
    'lnk',
  ],
  connections: ['graph', 'relationships', 'link analysis', 'who knows who'],
  entities: ['people', 'names', 'identifiers', 'phone numbers', 'selectors'],
  duplicates: ['dupes', 'duplicate files', 'same file', 'copies', 'hash matches'],
  analysis: [
    'records',
    'parsed records',
    'record types',
    'browser history',
    'artifacts by type',
    'tables',
  ],
  'system-info': [
    'os',
    'operating system',
    'hostname',
    'time zone',
    'user accounts',
    'build',
  ],
  memory: ['ram', 'volatile', 'memory dump', 'processes', 'capture', 'volatility'],
  bookmarks: ['starred', 'flagged', 'tagged', 'exhibits', 'marked'],
  filters: ['saved filters', 'criteria', 'rules'],
  'hash-sets': ['hashes', 'known files', 'nsrl', 'hashset', 'md5', 'sha1'],
  audit: ['who did what', 'actions', 'activity log', 'examiner actions'],
  settings: ['case settings', 'configuration', 'examiner name', 'preferences'],
  help: ['shortcuts', 'documentation', 'keyboard', 'manual', 'how to'],
}

/**
 * Addressable views that are deliberately NOT rail rows.
 *
 * The videos and audio galleries are their own views with their own populations
 * and their own empty states, but three near-identical rows would cost more rail
 * than they are worth. The palette is where they belong: an examiner who wants
 * video says "video", and until now the only way to reach it was to find the
 * Logical lens toggle and expand Media.
 */
const PALETTE_ONLY: CaseDestination[] = [
  {
    to: 'gallery?kind=videos',
    label: 'Videos',
    keywords: ['video', 'movies', 'clips', 'footage'],
  },
  {
    to: 'gallery?kind=audio',
    label: 'Audio',
    keywords: ['sound', 'recordings', 'voice', 'voicemail', 'music'],
  },
]

/**
 * Every view in a case that the palette can jump to, rail rows first in rail
 * order.
 *
 * Derived from NAV_ITEMS rather than restated, because a hand-kept second list
 * is how five whole analytical surfaces came to be missing from the palette in
 * the first place.
 */
export const CASE_DESTINATIONS: CaseDestination[] = [
  ...NAV_ITEMS.map((item) => ({
    to: item.to,
    label: item.label,
    keywords: NAV_ALIASES[item.to] ?? [],
  })),
  ...PALETTE_ONLY,
]

/**
 * The absolute address of a destination within one case.
 *
 * The dashboard is `/cases/<id>`, never `/cases/<id>/`: a trailing slash is a
 * second address for the same view, which is the ambiguity this change exists
 * to remove.
 */
export function destinationPath(caseId: string, to: string): string {
  return to ? `/cases/${caseId}/${to}` : `/cases/${caseId}`
}

/**
 * The ⌘K command list for one case: one "Go to …" per view, then the actions
 * that are not a view.
 */
export function buildCaseCommands(
  caseId: string,
  navigate: (to: string) => void,
): Command[] {
  const commands: Command[] = CASE_DESTINATIONS.map((dest) => ({
    id: dest.to || 'dashboard',
    label: `Go to ${dest.label}`,
    keywords: dest.keywords,
    run: () => navigate(destinationPath(caseId, dest.to)),
  }))
  commands.push({
    id: 'cases',
    label: 'Switch case',
    run: () => navigate('/'),
  })
  return commands
}
