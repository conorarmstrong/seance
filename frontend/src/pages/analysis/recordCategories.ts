/**
 * What a record type is *about*, so the Analysis index reads as a case rather
 * than a ranking of parser output.
 *
 * The index ordered types by count. On a real macOS image that opened with
 * 78,093 recovered SQLite rows, 37,738 file-signature analyses and 16,528
 * perceptual hashes — all of them things the tool derived — while the five
 * iMessages, the call log, the browser history and the device the case is
 * actually about sat below the fold. Counting is not importance.
 *
 * Rules, not an allow-list: a type nobody has categorised still appears, under
 * "Other records". A parser that ships tomorrow must show up the day it ships,
 * not the day somebody remembers to add it to a list.
 */

export type RecordCategory =
  | 'People and messages'
  | 'Places and times'
  | 'Activity'
  | 'The device'
  | 'Files and media'
  | 'Derived analysis'
  | 'What could not be read'
  | 'Other records'

/** The order the groups are read in, and the order they are rendered in. */
export const CATEGORY_ORDER: RecordCategory[] = [
  'People and messages',
  'Places and times',
  'Activity',
  'The device',
  'Files and media',
  'Other records',
  'Derived analysis',
  'What could not be read',
]

/** One line of guidance under each group heading. */
export const CATEGORY_BLURB: Record<RecordCategory, string> = {
  'People and messages':
    'Who this exhibit was in contact with, and what was said.',
  'Places and times': 'Where the device was, and when it was in use.',
  Activity: 'What was opened, run, searched for and downloaded.',
  'The device': 'What the exhibit is, what is installed on it, and its settings.',
  'Files and media': 'Documents, pictures and recordings, and what they carry.',
  'Other records': 'Record types this index has no category for. Nothing is hidden.',
  'Derived analysis':
    'What Séance computed from the evidence rather than read out of it.',
  'What could not be read':
    'Records stating a shortfall: evidence that was located and not fully recovered. A completeness answer rests on these.',
}

/** Types named outright, where a rule would be a guess. */
const NAMED: Record<string, RecordCategory> = {
  // Named, not matched. The `/boot/` alternative in the "Places and times"
  // rule below fires first on this type and would file the volume's own
  // geometry as somewhere the device had been -- a false statement about what
  // the record is (ROADMAP §1.7).
  NtfsBootSector: 'The device',
  // A shim database is a persistence surface, and the rule list would file
  // `ShimExe` under Activity on `execut`— which it is not: a shim entry is not
  // a record that anything ran (ROADMAP §1.7).
  ShimDatabase: 'The device',
  ShimExe: 'The device',
  ShimDatabaseCoverage: 'What could not be read',
  // The registry-resident artifacts (ROADMAP §2.5, §2.6). Each of these is
  // named because the word rules below either miss it or file it wrongly, and
  // "wrongly" here means the group heading contradicts what the parser says
  // the record is.
  //
  // `WindowsSearchState` is the indexer SERVICE's configuration -- the record
  // itself carries `index_populated: false` and says that a service set to
  // start automatically on a freshly imaged machine has indexed nothing. The
  // `search` rule filed it under "What was opened, run, searched for and
  // downloaded", which invites reading a start type as searches performed.
  WindowsSearchState: 'The device',
  // An interface's addresses and DHCP lease are the exhibit's settings. The
  // `network` rule filed them under Activity, which reads as traffic.
  NetworkInterface: 'The device',
  // MUICache records carry `execution_evidence: false`, because the shell
  // writes here for a properties dialog and a context menu too. Activity would
  // be exactly the over-claim the parser refuses to make.
  MuiCacheEntry: 'The device',
  // A local account is what the exhibit holds, not something a user did. The
  // `account` word rule would otherwise file it under People and messages,
  // beside the mail accounts and chat handles, which is a different thing.
  LocalAccount: 'The device',
  // A device install is a record of hardware arriving on the exhibit. The
  // `install` word rule already files it under The device; naming it keeps it
  // there if the rule list ever changes, beside the USB records it corroborates.
  DeviceInstallEvent: 'The device',
  DeviceInstallLogCoverage: 'What could not be read',
  // A sticky note is something a person wrote. The `note` word matches no rule
  // and it would otherwise fall to "Other records", away from the documents.
  StickyNote: 'Files and media',
  StickyNoteRecovered: 'Files and media',
  StickyNotesCoverage: 'What could not be read',
  StickyNotesParseStatus: 'What could not be read',
  // These four are records of what was done, and no word rule matches them.
  UserAssistEntry: 'Activity',
  BamEntry: 'Activity',
  TypedUrl: 'Activity',
  RdpDestinationEntry: 'Activity',
  iMessage: 'People and messages',
  EmailMessage: 'People and messages',
  Contact: 'People and messages',
  CallLog: 'People and messages',
  ChatMessage: 'People and messages',
  Message: 'People and messages',
  SmsMessage: 'People and messages',
  Conversation: 'People and messages',

  CachedLocation: 'Places and times',
  LoginSession: 'Places and times',
  BootEvent: 'Places and times',
  // A refused login is evidence of an attempt at a time from a place. The
  // `failed` word rule would file it under What could not be read, beside the
  // records that say a file would not parse — which is the opposite of what it
  // is: somebody tried, and the machine wrote it down.
  FailedLogin: 'Places and times',
  // One record from a macOS audit trail: a login, a logout, an
  // authentication, or an administrative act, each with the account and the
  // address it came from.
  AuditEvent: 'Places and times',
  // The trail's own provenance row, which is also where a trail that could not
  // be read in full says so. Filed with the other `*ParseStatus` rows.
  AuditTrailStatus: 'What could not be read',
  // A stored credential: which service and account, and since when. The
  // secret is locked, but the item is a fact about the person's accounts, so
  // it belongs with the accounts and not with the shortfalls — and the `key`
  // and `chain` in its name match no word rule, so it would otherwise fall to
  // "Other records".
  KeychainItem: 'The device',
  KeychainStatus: 'What could not be read',
  // An iOS backup's keychain item (HUNT-111): the same fact about the
  // person's accounts as the Mac's. The summary counts what could not be read
  // (the ThisDeviceOnly items), so it goes with the other shortfalls.
  IosKeychainItem: 'The device',
  IosKeychainSummary: 'What could not be read',
  // One Apple System Log entry. The `log` in its name matches no word rule,
  // and on macOS this store is where the login history is, so it belongs with
  // the other records of what was done.
  AslMessage: 'Activity',
  AslStatus: 'What could not be read',
  // A device the Apple ID's keychain circle held — which may be a device the
  // evidence does not contain. It belongs with the exhibit's hardware facts,
  // and the `keychain` in its name matches no word rule.
  ICloudKeychainDevice: 'The device',
  WifiNetwork: 'The device',
  CalendarSummary: 'Places and times',
  CalendarEvent: 'Places and times',

  BrowserHistory: 'Activity',
  BrowserSearch: 'Activity',
  BrowserDownload: 'Activity',
  BrowserBookmark: 'Activity',
  BrowserSession: 'Activity',
  BrowserCookie: 'Activity',
  BrowserAutofill: 'Activity',
  LocalStorageItem: 'Activity',
  BrowserCacheEntry: 'Activity',
  ShellHistoryEntry: 'Activity',
  RecentFileEntry: 'Activity',
  LnkFile: 'Activity',
  NetworkFlow: 'Activity',
  DnsResolution: 'Activity',
  NetworkCapture: 'Activity',
  HttpTransaction: 'Activity',
  // Being on a network is something the machine did, at a time.
  NetworkProfile: 'Activity',
  TlsSession: 'Activity',
  // A certificate is a thing the case holds, like an installed program: what
  // a host claimed to be, not something it did.
  TlsCertificate: 'The device',
  ArpBinding: 'The device',

  HostDeviceInfo: 'The device',
  MobileDeviceInfo: 'The device',
  IosBackupInfo: 'The device',
  InstalledApp: 'The device',
  InstalledAppSummary: 'The device',
  InstalledProgram: 'The device',
  BluetoothPairing: 'The device',
  RegistryHive: 'The device',
  PlistFile: 'The device',
  Permission: 'The device',
  AsepCoverage: 'The device',

  MediaProperties: 'Files and media',
  PhotoAsset: 'Files and media',
  FreedesktopThumbnail: 'Files and media',
  OfficeDocument: 'Files and media',
  DSStoreEntry: 'Files and media',
  exif: 'Files and media',

  SqliteRow: 'Derived analysis',
  SqliteDatabaseForensics: 'Derived analysis',
  FileSignatureAnalysis: 'Derived analysis',
  PerceptualHash: 'Derived analysis',
  Feature: 'Derived analysis',
  FeatureSummary: 'Derived analysis',
  // The most-common-values record the same scanner publishes (ROADMAP §2.1):
  // computed from the evidence, like its sibling.
  FeatureHistogramSummary: 'Derived analysis',
  // A YARA region record is a measurement over the bytes read (entropy, a
  // match count); the two coverage records are statements of what the scan
  // did not reach, and the `coverage` rule files them there.
  YaraRegionScanned: 'Derived analysis',
  // A WMI event subscription recovered from repository bytes nothing
  // references (ROADMAP §2.5): the same subject as `AsepEntry`, which the
  // `asep` rule files under The device, named here so the pair cannot drift
  // apart if the rule list changes. The TYPE keeps them apart.
  AsepEntry: 'The device',
  RecoveredAsepEntry: 'The device',
  // One record per parser that met a schema outside the range it was
  // validated on, or a column it could not resolve (ROADMAP §1.4a). Its
  // records still parsed; this one says on what basis. No word rule matches
  // `Stale` or `Warning`, so it would otherwise fall to Other records.
  ParserStaleWarning: 'What could not be read',
  // The EVTX carve's own account of itself (ROADMAP §2.4): the bounds it hit,
  // the chunks it could not open, the records it could only partly render.
  // `Status` alone matches no rule.
  EvtxRecoveryStatus: 'What could not be read',
  // iOS Safari (ROADMAP §1.5). `Safari` matches no rule; these are what was
  // bookmarked, open and searched for, which is Activity.
  SafariBookmark: 'Activity',
  SafariBookmarkFolder: 'Activity',
  SafariOpenTab: 'Activity',
  SafariWindow: 'Activity',
  // A HealthKit sample is a timed observation carrying the zone it was
  // recorded in: when the device was in use, and where its clock was set.
  HealthSample: 'Places and times',
  PeSignature: 'Derived analysis',
  // Spotlight's metadata index (ROADMAP §1.6). All five are named because no
  // word rule matches them, and because where they are filed decides what a
  // reader takes them to say.
  //
  // The store record's headline content is the measurement that most of the
  // store is not decodable — 74 of the 86 blocks in the corpus's larger store
  // — so it is filed as the shortfall statement it is, on the same principle
  // as the rule list's own ordering: a type is a statement about a shortfall
  // whatever else its name says.
  SpotlightStore: 'What could not be read',
  // And the row a store that would not parse leaves behind, so that an
  // unreadable index never renders as a volume that was never indexed.
  SpotlightStoreStatus: 'What could not be read',
  // One indexed file or folder: its name, its path, its sizes and its dates,
  // as Spotlight recorded them. Filed with the files — this is an observation
  // about a document, a picture or a folder, and it is the only Spotlight
  // record type that is. The `spotlight` in its name matches no word rule.
  //
  // It is NOT filed with what could not be read even though Spotlight indexes
  // files that have since been deleted: the record is a real observation about
  // a file that existed, and it says on itself that its presence is not
  // presence on the volume now.
  SpotlightItem: 'Files and media',
  // The index's own attribute schema on this exhibit. It names no file and no
  // time, so it belongs with what the device is and how it was configured.
  SpotlightProperty: 'The device',
  // And the content types the index knew about. NOT 'Files and media': that
  // group is documents, pictures and recordings that were recovered, and a
  // content type beside them would read as a file on the volume — which the
  // record explicitly refuses to say, because the per-item records that would
  // name the files are not decodable and the type may be there because of a
  // file since deleted.
  SpotlightContentType: 'The device',
  // A registry MRU entry: a document the shell recorded as opened. That is
  // what was opened, so it goes with Activity — where the word rules would
  // have sent it anyway ("recent" is not in them, but nothing else matches
  // either, so it would have fallen to Other records).
  ShellMruEntry: 'Activity',
  // The unified log's format-string catalogue (ROADMAP §1.6). A catalogue is
  // not a log: it holds the sentences the OS would have substituted arguments
  // into, and says nothing about whether any of them was written.
  //
  // `UnifiedLogImage` is an inventory of the code on the machine that logs —
  // a path, a UUID and a load address per binary — so it belongs with what
  // the exhibit is and what is installed on it. NOT with Activity: a
  // catalogue entry is not a record that the binary ran, and standing it
  // beside prefetch would invite exactly that reading. The `log` in the name
  // matches no word rule either way.
  UnifiedLogImage: 'The device',
  // And the per-file record, which is mostly a statement about how much of
  // the catalogue could be read.
  UnifiedLogCatalogue: 'What could not be read',
  // The log's own messages are what the machine recorded happening.
  UnifiedLogMessage: 'Activity',
}

/**
 * Word rules, applied when the name is not one this file knows. Ordered: the
 * first match wins, and the shortfall rules come first because a type is a
 * statement about a shortfall whatever else its name says
 * (`BrowserCacheParseStatus` is not browser activity — it is the browser cache
 * that would not parse). `coverage` is in that first rule for the same reason:
 * a `*Coverage` record exists to say what a population does and does not
 * include, so it belongs with the records a completeness answer rests on
 * whatever artifact it is about.
 */
const RULES: [RegExp, RecordCategory][] = [
  [
    /(parse_?status|parsestatus|incomplete|unparsed|refusal|error|failed|encrypted|missing|truncated|scanstatus|scan_status|walkstatus|walk_status|coverage)/i,
    'What could not be read',
  ],
  [/(message|chat|contact|call|mail|sms|conversation|account)/i, 'People and messages'],
  [/(location|geo|position|session|boot|login|logon|shutdown|calendar)/i, 'Places and times'],
  [/(browser|history|search|download|execut|prefetch|shim|amcache|jumplist|shellbag|usn|srum|command|shell|network|dns|flow)/i, 'Activity'],
  [/(device|install|hardware|registry|plist|setting|wifi|bluetooth|sim|carrier|profile|persistence|asep)/i, 'The device'],
  [/(photo|image|media|video|audio|thumbnail|document|exif|file_?entry)/i, 'Files and media'],
  [/(hash|signature|entropy|carv|feature|summary|analysis|forensics|row)/i, 'Derived analysis'],
]

export function categoryOf(type: string): RecordCategory {
  const named = NAMED[type]
  if (named) return named
  for (const [pattern, category] of RULES) {
    if (pattern.test(type)) return category
  }
  return 'Other records'
}

export interface RecordTypeCount {
  type: string
  count: number
}

export interface RecordTypeGroup {
  category: RecordCategory
  blurb: string
  types: RecordTypeCount[]
  /** Records in this group, for the heading. */
  total: number
}

/**
 * Group the case's record types. Groups come in [`CATEGORY_ORDER`]; inside a
 * group the biggest population leads, which is a useful ordering once the
 * groups themselves carry the meaning. An empty group is not rendered.
 */
export function groupRecordTypes(types: RecordTypeCount[]): RecordTypeGroup[] {
  const byCategory = new Map<RecordCategory, RecordTypeCount[]>()
  for (const entry of types) {
    const category = categoryOf(entry.type)
    const list = byCategory.get(category) ?? []
    list.push(entry)
    byCategory.set(category, list)
  }
  return CATEGORY_ORDER.flatMap((category) => {
    const list = byCategory.get(category)
    if (!list || list.length === 0) return []
    const sorted = [...list].sort(
      (a, b) => b.count - a.count || a.type.localeCompare(b.type),
    )
    return [
      {
        category,
        blurb: CATEGORY_BLURB[category],
        types: sorted,
        total: sorted.reduce((n, t) => n + t.count, 0),
      },
    ]
  })
}
