import { humanizeType } from '../../pages/analysis/lib'

/** One ParsedRecord `type` in a category, with its display label and count. */
export interface LogicalTypeNode {
  type: string
  label: string
  count: number
}

/** An examiner category (Chats, Contacts, …) aggregating its member types. */
export interface LogicalCategory {
  key: CategoryKey
  label: string
  count: number
  children: LogicalTypeNode[]
}

/** Record types that are internal plumbing, never shown to analysts. Kept in
 * sync with AnalysisIndexPage's INTERNAL set. */
const INTERNAL = new Set(['file_hash', 'allocation_map', 'CarvingSummary'])

/** Examiner categories in display order (user data first, system last). */
export const CATEGORY_ORDER = [
  'chats',
  'contacts',
  'calls',
  'email',
  'calendar',
  'web',
  'apps',
  'execution',
  'system',
  'storage',
  'other',
] as const

export type CategoryKey = (typeof CATEGORY_ORDER)[number]

export const CATEGORY_LABELS: Record<CategoryKey, string> = {
  chats: 'Chats',
  contacts: 'Contacts',
  calls: 'Calls',
  email: 'Email',
  calendar: 'Calendar',
  web: 'Web & Downloads',
  apps: 'Installed Apps',
  execution: 'Program Execution',
  system: 'System & Logs',
  storage: 'Databases & Files',
  other: 'Other',
}

/**
 * Known ParsedRecord `type` discriminators mapped to an examiner category.
 * Anything not listed (a new parser's type) falls back to 'other', so the tree
 * degrades gracefully rather than hiding data.
 */
const TYPE_CATEGORY: Record<string, CategoryKey> = {
  NtfsBootSector: 'system',
  ShimDatabase: 'system',
  ShimExe: 'system',
  ShimDatabaseCoverage: 'system',
  iMessage: 'chats',
  iMessageAttachment: 'chats',
  WhatsApp: 'chats',
  WhatsAppAttachment: 'chats',
  Signal: 'chats',
  AndroidSms: 'chats',
  AndroidSmsSummary: 'chats',
  Viber: 'chats',
  Kik: 'chats',
  Skype: 'chats',
  LINE: 'chats',
  TelegramMessage: 'chats',
  FacebookMessenger: 'chats',
  WeChat: 'chats',
  Instagram: 'chats',
  Snapchat: 'chats',
  SnapchatContact: 'contacts',
  TwitterDM: 'chats',
  InstalledApp: 'apps',
  InstalledAppSummary: 'apps',
  Contact: 'contacts',
  SignalContact: 'contacts',
  CallLog: 'calls',
  EmailMessage: 'email',
  CalendarEvent: 'calendar',
  Reminder: 'calendar',
  BrowserHistory: 'web',
  BrowserDownload: 'web',
  BrowserBookmark: 'web',
  BrowserCookie: 'web',
  BrowserAutofill: 'web',
  BrowserLogin: 'web',
  BrowserSession: 'web',
  AndroidNote: 'other',
  exif: 'other',
  PrefetchEntry: 'execution',
  AmcacheEntry: 'execution',
  ShimcacheEntry: 'execution',
  LnkFile: 'execution',
  SrumAppResourceUsage: 'execution',
  PeSignature: 'execution',
  ShellHistoryEntry: 'execution',
  RegistryHive: 'system',
  // The registry-resident artifacts (ROADMAP §2.5, §2.6). Anything not listed
  // here falls to 'other', so every one of these showed the whole of Windows
  // execution and device history as "Other" until they were mapped.
  UserAssistEntry: 'execution',
  UserAssistCoverage: 'execution',
  BamEntry: 'execution',
  BamCoverage: 'execution',
  // The Windows side of `InstalledApp`, which has been mapped all along.
  InstalledProgram: 'apps',
  TypedUrl: 'web',
  UsbDevice: 'system',
  LocalAccount: 'system',
  DeviceInstallEvent: 'system',
  StickyNote: 'other',
  StickyNoteRecovered: 'other',
  StickyNotesCoverage: 'other',
  StickyNotesParseStatus: 'other',
  DeviceInstallLogCoverage: 'system',
  MountedDevice: 'system',
  NetworkInterface: 'system',
  WindowsSearchState: 'system',
  MuiCacheEntry: 'system',
  MuiCacheCoverage: 'system',
  ShellMruEntry: 'system',
  MruCoverage: 'system',
  // An entered destination, not a connection: the record itself carries
  // `connection_succeeded: false`, so 'execution' would over-claim it.
  RdpDestinationEntry: 'system',
  EvtxLogEntry: 'system',
  // Recovered events (ROADMAP §2.4) sit beside the live log as their own
  // child: the same family, a different type, never one population.
  EvtxRecoveredLogEntry: 'system',
  EvtxRecoveryStatus: 'system',
  // Keys and values from a hive's unallocated cells (ROADMAP §5.9), beside
  // the hive they came out of and apart from its live tree by type.
  RecoveredRegistryKey: 'system',
  RecoveredRegistryValue: 'system',
  // A DestList entry is a document the shell recorded as opened through an
  // application, the same class of evidence as a shortcut file.
  JumpListDestListEntry: 'execution',
  JumpListDestList: 'execution',
  JumpListCarvedShortcut: 'execution',
  JumpListCarveStatus: 'execution',
  // BITS jobs are queued transfers and a persistence surface; the Search
  // index and RDP cache are not evidence that anything ran.
  BitsJob: 'execution',
  BitsFileTransfer: 'execution',
  BitsCarvedFileTransfer: 'execution',
  WindowsSearchItem: 'system',
  RdpBitmapCache: 'system',
  // iOS Safari (ROADMAP §1.5): the same family as the desktop browser records.
  SafariBookmark: 'web',
  SafariBookmarkFolder: 'web',
  SafariBookmarksSummary: 'web',
  SafariOpenTab: 'web',
  SafariWindow: 'web',
  SafariTabsSummary: 'web',
  WebSearchQuery: 'web',
  SafariSearchesSummary: 'web',
  ShellBagEntry: 'system',
  RecycleBinEntry: 'system',
  UsnJournalEntry: 'system',
  VssSnapshot: 'system',
  VssPriorVersion: 'system',
  PlistFile: 'system',
  SrumNetworkDataUsage: 'system',
  SrumNetworkConnectivity: 'system',
  SrumEnergyUsage: 'system',
  SrumDatabase: 'system',
  PowerLogEvent: 'system',
  PowerLogSummary: 'system',
  TrashEntry: 'system',
  RecentFileEntry: 'system',
  ThumbcacheEntry: 'system',
  FreedesktopThumbnail: 'system',
  FSEventsRecord: 'system',
  DSStoreEntry: 'system',
  Voicemail: 'calls',
  Note: 'other',
  PhotoAsset: 'other',
  SqliteRow: 'storage',
  SqliteDatabaseForensics: 'storage',
  FileSignatureAnalysis: 'storage',
}

/** The examiner category a raw record `type` belongs to. */
export function categoryForType(type: string): CategoryKey {
  return TYPE_CATEGORY[type] ?? 'other'
}

/** Category-overview views that supersede a sidebar item. Clicking such a
 * category opens its dedicated view (embedded in the workbench) instead of just
 * expanding: Chats → the communications overview, Program Execution → the
 * execution timeline. Media categories (Pictures→gallery, Geolocation→geo) use
 * the same view kinds but are not record-derived. */
export type CategoryView =
  | 'gallery'
  | 'videos'
  | 'audio'
  | 'geo'
  | 'comms'
  | 'execution'

export const CATEGORY_VIEW: Partial<Record<CategoryKey, CategoryView>> = {
  chats: 'comms',
  execution: 'execution',
}

/**
 * Roll a flat list of `{type, count}` (from `/record_types`) up into the
 * examiner categories shown by the logical navigator. Internal types and
 * non-positive counts are dropped; children sort by count; only non-empty
 * categories are returned, in CATEGORY_ORDER.
 */
export function buildLogicalTree(
  recordTypes: { type: string; count: number }[],
): LogicalCategory[] {
  const groups = new Map<CategoryKey, LogicalTypeNode[]>()
  for (const { type, count } of recordTypes) {
    if (INTERNAL.has(type) || count <= 0) continue
    const key = categoryForType(type)
    const node: LogicalTypeNode = { type, label: humanizeType(type), count }
    const existing = groups.get(key)
    if (existing) existing.push(node)
    else groups.set(key, [node])
  }

  const out: LogicalCategory[] = []
  for (const key of CATEGORY_ORDER) {
    const children = groups.get(key)
    if (!children || children.length === 0) continue
    children.sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    const count = children.reduce((sum, n) => sum + n.count, 0)
    out.push({ key, label: CATEGORY_LABELS[key], count, children })
  }
  return out
}
