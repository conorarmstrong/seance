import type { RecordMetadata } from './api'

/** Sentinel for absent values, matching src/lib/format. */
export const MISSING = '—'

/** Acronyms that should not be title-cased word-by-word. */
const ACRONYMS: Record<string, string> = {
  url: 'URL',
  urls: 'URLs',
  id: 'ID',
  ids: 'IDs',
  gps: 'GPS',
  mac: 'MAC',
  exif: 'EXIF',
  evtx: 'EVTX',
  usn: 'USN',
  srum: 'SRUM',
  ntfs: 'NTFS',
  yara: 'YARA',
  ual: 'UAL',
  tty: 'TTY',
  uid: 'UID',
  pid: 'PID',
  bom: 'BOM',
  lnk: 'LNK',
  sqlite: 'SQLite',
  mft: 'MFT',
  os: 'OS',
  dns: 'DNS',
  asep: 'ASEP',
}

/**
 * Precise display labels for known ParsedRecord `type` discriminators. Falls
 * back to generic humanization for anything not listed here.
 */
const TYPE_LABELS: Record<string, string> = {
  BrowserHistory: 'Browser History',
  BrowserDownload: 'Browser Downloads',
  BrowserBookmark: 'Browser Bookmarks',
  BrowserCookie: 'Browser Cookies',
  BrowserAutofill: 'Browser Autofill',
  BrowserLogin: 'Browser Saved Logins',
  BrowserSession: 'Browser Open Tabs',
  PrefetchEntry: 'Prefetch',
  RegistryHive: 'Registry Hives',
  LnkFile: 'Shortcuts (LNK)',
  EvtxLogEntry: 'Windows Event Log',
  RecycleBinEntry: 'Recycle Bin',
  ShellBagEntry: 'Shellbags',
  AmcacheEntry: 'Amcache',
  ShimcacheEntry: 'Shimcache',
  SrumAppResourceUsage: 'SRUM App Resource Usage',
  SrumNetworkDataUsage: 'SRUM Network Data Usage',
  SrumNetworkConnectivity: 'SRUM Network Connectivity',
  SrumEnergyUsage: 'SRUM Energy Usage',
  SrumDatabase: 'SRUM Database',
  NtfsLogFileRecord: 'NTFS $LogFile Transactions',
  YaraMatch: 'YARA Matches',
  LoginSession: 'Login Sessions',
  FailedLogin: 'Failed Logins',
  BootEvent: 'Boot & Shutdown',
  LastLogin: 'Last Login (lastlog)',
  AuditEvent: 'Audit Events (macOS)',
  AuditTrailStatus: 'Audit Trails',
  KeychainItem: 'Keychain Items',
  KeychainStatus: 'Keychains',
  IosKeychainItem: 'iOS Keychain Items',
  IosKeychainSummary: 'iOS Keychains',
  AslMessage: 'Apple System Log',
  AslStatus: 'Apple System Log Stores',
  ICloudKeychainDevice: 'iCloud Keychain Devices',
  ShellMruEntry: 'Recently Opened (Registry MRU)',
  UnifiedLogMessage: 'Unified Log Messages',
  UnifiedLog: 'Unified Log Files',
  UnifiedLogCatalogue: 'Unified Log Catalogues',
  UnifiedLogImage: 'Binaries That Logged',
  SpotlightItem: 'Spotlight Indexed Items',
  SpotlightStore: 'Spotlight Metadata Stores',
  SpotlightStoreStatus: 'Spotlight Stores Not Parsed',
  SpotlightProperty: 'Spotlight Indexed Attributes',
  SpotlightContentType: 'Spotlight Content Types',
  exif: 'EXIF (Photos)',
  SqliteRow: 'Recovered SQLite Rows',
  SqliteDatabaseForensics: 'SQLite Database Forensics',
  iMessage: 'iMessage',
  iMessageAttachment: 'iMessage Media',
  WhatsAppAttachment: 'WhatsApp Media',
  WhatsApp: 'WhatsApp',
  Signal: 'Signal',
  Viber: 'Viber',
  Kik: 'Kik',
  Skype: 'Skype',
  LINE: 'LINE',
  TelegramMessage: 'Telegram',
  FacebookMessenger: 'Facebook Messenger',
  WeChat: 'WeChat',
  Instagram: 'Instagram',
  Snapchat: 'Snapchat',
  TwitterDM: 'Twitter/X DMs',
  SignalContact: 'Signal Contacts',
  SignalBackup: 'Signal Backup',
  OcrText: 'OCR (Text in Images)',
  AndroidSms: 'Android SMS/MMS',
  AndroidSmsSummary: 'Android SMS Summary',
  InstalledApp: 'Installed Apps',
  InstalledAppSummary: 'Installed Apps Summary',
  AndroidNote: 'Notes (Google Keep)',
  CalendarEvent: 'Calendar Events',
  EmailMessage: 'Email',
  CallLog: 'Call History',
  Contact: 'Contacts',
  FileSignatureAnalysis: 'File Signature Analysis',
  UsnJournalEntry: 'USN Journal',
  PlistFile: 'Property Lists',
  VssSnapshot: 'Volume Shadow Snapshots',
  VssPriorVersion: 'Prior Versions (Shadow Copies)',
  PeSignature: 'PE / Authenticode',
  Voicemail: 'Voicemail',
  Reminder: 'Reminders (iOS)',
  Note: 'Notes (Apple)',
  PhotoAsset: 'Photos (Camera Roll)',
  PowerLogEvent: 'PowerLog Events',
  PowerLogSummary: 'PowerLog Summary',
  ShellHistoryEntry: 'Shell History',
  TrashEntry: 'Trash (Linux)',
  RecentFileEntry: 'Recently Used Files',
  ThumbcacheEntry: 'Thumbnail Cache (Windows)',
  FreedesktopThumbnail: 'Thumbnails (Linux/GNOME)',
  FSEventsRecord: 'FSEvents (macOS)',
  DSStoreEntry: '.DS_Store Metadata',
  WindowsTimelineActivity: 'Windows Timeline',
  // The Windows Uninstall-key inventory (SOFTWARE and NTUSER). Distinct from
  // `InstalledApp`, which is the Android package list.
  InstalledProgram: 'Installed programs',
  // Packet-capture records (seance_plugin_pcap). The capture itself is one
  // record per file, so it stays singular; the rest are lists.
  NetworkCapture: 'Network capture',
  NetworkFlow: 'Network flows',
  DnsResolution: 'DNS resolutions',
  NetworkCaptureRefusal: 'Network capture refusals',
  // A container that was recognised and deliberately not served: an EWF
  // logical evidence file, whose files this build does not enumerate. It is
  // here so that such an exhibit reads as refused, never as empty.
  ContainerRefusal: 'Containers not read',
  // A browser profile file this parser claimed and could not read. Typed apart
  // from `BrowserHistory` on purpose: the index groups by record type, so a
  // failure typed as the thing it failed to produce is counted as one of them.
  BrowserHistoryParseStatus: 'Browser profiles not read',
  // Read out of the reassembled TCP streams of a capture.
  HttpTransaction: 'HTTP requests and responses',
  // A network the machine has BEEN on, from the NetworkList keys — as against
  // `WifiNetwork`, which is a network it was configured FOR.
  NetworkProfile: 'Networks joined',
  // A network the machine was configured FOR — macOS known networks and the
  // Windows WLAN profiles, one type on purpose.
  WifiNetwork: 'Wireless networks',
  TlsSession: 'TLS sessions',
  TlsCertificate: 'TLS certificates',
  ArpBinding: 'Address claims (ARP)',
  NtfsIndexEntry: 'NTFS directory index entries ($I30)',
  // An event recovered from a carved chunk, chunk slack or a loose record
  // (ROADMAP §2.4). Its own type, its own label: the label is the only thing
  // a reader sees before the rows, and "Windows Event Log" over a table of
  // chunk-slack records would present recovered events as live ones.
  EvtxRecoveredLogEntry: 'Windows Event Log (recovered)',
  EvtxRecoveryStatus: 'Windows Event Log recovery status',
  // Keys and values read out of a hive's unallocated cells (ROADMAP §5.9).
  // Never merged with the live tree; the label carries the provenance.
  RecoveredRegistryKey: 'Registry keys (recovered from unallocated cells)',
  RecoveredRegistryValue: 'Registry values (recovered from unallocated cells)',
  // The YARA surface records (ROADMAP §2.3): one per region scanned, one per
  // hive whose value inventory was scanned, and one per file whose decoded
  // spans were not all scanned.
  YaraRegionScanned: 'YARA regions scanned',
  YaraRegistryCoverage: 'YARA registry coverage',
  YaraDecodeCoverage: 'YARA decode coverage',
  // The bulk feature scanner's most-common-values record (ROADMAP §2.1).
  FeatureHistogramSummary: 'Feature histograms',
  // Jump lists (ROADMAP §2.5): the DestList entries, the per-file DestList
  // summary, and the fallback carve's records.
  JumpListDestListEntry: 'Jump list entries (DestList)',
  JumpListDestList: 'Jump list DestList summaries',
  JumpListCarvedShortcut: 'Jump list shortcuts (carved)',
  JumpListCarveStatus: 'Jump list carve status',
  // BITS queue, Search index and RDP bitmap cache (ROADMAP §2.5).
  BitsJob: 'BITS jobs',
  BitsFileTransfer: 'BITS file records (unlinked)',
  BitsCarvedFileTransfer: 'BITS file records (carved)',
  BitsQueueFile: 'BITS queue files',
  BitsQueueDatabase: 'BITS queue databases',
  BitsQueueIncomplete: 'BITS queues not decoded',
  WindowsSearchItem: 'Search index rows',
  WindowsSearchIndex: 'Search index summaries',
  WindowsSearchIndexIncomplete: 'Search indexes not decoded',
  RdpBitmapCache: 'RDP bitmap cache files',
  RdpBitmapCacheIncomplete: 'RDP bitmap caches not decoded',
  // iOS Safari and HealthKit (ROADMAP §1.5).
  SafariBookmark: 'Safari bookmarks (iOS)',
  SafariBookmarkFolder: 'Safari bookmark folders (iOS)',
  SafariBookmarksSummary: 'Safari bookmark stores (iOS)',
  SafariOpenTab: 'Safari open tabs (iOS)',
  SafariWindow: 'Safari windows (iOS)',
  SafariTabsSummary: 'Safari tab stores (iOS)',
  WebSearchQuery: 'Web searches',
  SafariSearchesSummary: 'Safari search stores (iOS)',
  HealthSample: 'HealthKit samples',
  HealthKitSummary: 'HealthKit stores',
  // Autostart entries (ROADMAP §2.5). A WMI subscription recovered from
  // repository bytes nothing references is its own type, and its own label.
  AsepEntry: 'Autostart entries (ASEP)',
  RecoveredAsepEntry: 'Autostart entries (ASEP, recovered)',
  // A parser that met a schema outside the range it was validated on, or a
  // column it could not resolve (ROADMAP §1.4a).
  ParserStaleWarning: 'Parser schema warnings',
  // The Windows memory stages of ROADMAP §5.3, one record per stage.
  MemoryProcessorBlocks: 'Memory: processor blocks',
  MemoryBigPool: 'Memory: big-page pool',
  MemoryVirtualMap: 'Memory: kernel virtual-address map',
  MemoryHiveCellRoutines: 'Memory: hive cell routines',
  MemoryVersionInfo: 'Memory: image version resources',
  MemoryMbrScan: 'Memory: boot sectors (MBR scan)',
  MemoryScheduledTasks: 'Memory: scheduled tasks',
  MemoryTrueCrypt: 'Memory: TrueCrypt/VeraCrypt',
  MemoryConsoleHistory: 'Memory: console command history',
  // The Linux memory stages (ROADMAP §4.2), one record per stage.
  LinuxMemoryOpenFiles: 'Linux memory: open files',
  LinuxMemoryProcessMaps: 'Linux memory: process maps',
  LinuxMemoryMounts: 'Linux memory: mounts',
  LinuxMemoryKernelHooks: 'Linux memory: kernel hooks',
  LinuxMemoryCommandLines: 'Linux memory: command lines',
  Unknown: 'Unknown',
}

/**
 * Turn a raw ParsedRecord `type` (e.g. `BrowserHistory`, `SqliteRow`) into a
 * human label. Known types use a curated label; others split
 * snake_case / PascalCase and preserve known acronyms.
 */
export function humanizeType(type: string): string {
  if (TYPE_LABELS[type]) return TYPE_LABELS[type]
  const lower = type.toLowerCase()
  if (ACRONYMS[lower]) return ACRONYMS[lower]
  const words = type
    // split snake_case and PascalCase boundaries
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[_\s]+/)
    .filter(Boolean)
  return words
    .map((w) => ACRONYMS[w.toLowerCase()] ?? w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

/** Humanize a metadata key for the generic key/value table. */
export function humanizeKey(key: string): string {
  return humanizeType(key)
}

/** Coerce a metadata value to a display string, or null when absent/empty. */
export function metaStr(meta: RecordMetadata, key: string): string | null {
  const v = meta[key]
  if (v == null) return null
  if (typeof v === 'string') return v.length ? v : null
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  if (Array.isArray(v)) {
    const parts = v.map((x) => (x == null ? '' : String(x))).filter(Boolean)
    return parts.length ? parts.join(', ') : null
  }
  try {
    return JSON.stringify(v)
  } catch {
    return null
  }
}

/** First present key from a list of candidate metadata keys. */
export function metaFirst(meta: RecordMetadata, keys: string[]): string | null {
  for (const k of keys) {
    const v = metaStr(meta, k)
    if (v != null) return v
  }
  return null
}

/** Coerce a metadata value to a number, or null. */
export function metaNum(meta: RecordMetadata, key: string): number | null {
  const v = meta[key]
  if (typeof v === 'number' && Number.isFinite(v)) return v
  if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) {
    return Number(v)
  }
  return null
}

/** Coerce a metadata value to a boolean flag. */
export function metaBool(meta: RecordMetadata, key: string): boolean {
  const v = meta[key]
  if (typeof v === 'boolean') return v
  if (typeof v === 'string') return v === 'true' || v === '1'
  if (typeof v === 'number') return v !== 0
  return false
}
