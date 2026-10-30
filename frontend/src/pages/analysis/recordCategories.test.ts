import { describe, expect, it } from 'vitest'
import {
  CATEGORY_ORDER,
  categoryOf,
  groupRecordTypes,
} from './recordCategories'

describe('what a record type is about', () => {
  it('puts what people did before what the tool derived', () => {
    // On the Magnet 2021 macOS case the index opened with 78,093 recovered
    // SQLite rows, 37,738 signature analyses and 16,528 perceptual hashes,
    // because it ranked by count. The five iMessages, the call log and the
    // device the case is about were below the fold.
    expect(CATEGORY_ORDER.indexOf(categoryOf('iMessage'))).toBeLessThan(
      CATEGORY_ORDER.indexOf(categoryOf('PerceptualHash')),
    )
    expect(CATEGORY_ORDER.indexOf(categoryOf('CallLog'))).toBeLessThan(
      CATEGORY_ORDER.indexOf(categoryOf('SqliteRow')),
    )
  })

  it('knows the kinds an examiner asks for by name', () => {
    expect(categoryOf('EmailMessage')).toBe('People and messages')
    expect(categoryOf('Contact')).toBe('People and messages')
    expect(categoryOf('CachedLocation')).toBe('Places and times')
    expect(categoryOf('LoginSession')).toBe('Places and times')
    // A refused login is evidence of an attempt at a time from a place. The
    // `failed` word rule would have filed it beside the records that say a
    // file would not parse, which is the opposite of what it is.
    expect(categoryOf('FailedLogin')).toBe('Places and times')
    // One record from a macOS audit trail: the platform's only login history.
    expect(categoryOf('AuditEvent')).toBe('Places and times')
    // A stored credential is a fact about the exhibit's accounts. Neither
    // `key` nor `chain` matches a word rule, so without a name it would fall
    // to "Other records" and disappear from the index an examiner scans.
    expect(categoryOf('KeychainItem')).toBe('The device')
    // On macOS the Apple System Log store is where the login history is, so
    // its entries belong with the records of what was done. The `log` in the
    // name matches no word rule.
    expect(categoryOf('AslMessage')).toBe('Activity')
    // A device the Apple ID trusted, which may not be in the evidence at all.
    expect(categoryOf('ICloudKeychainDevice')).toBe('The device')
    // HUNT-111: an iOS backup's keychain items sit with the Mac's; the
    // summary, which counts the device-bound items nothing could read, sits
    // with the other shortfalls.
    expect(categoryOf('IosKeychainItem')).toBe('The device')
    expect(categoryOf('IosKeychainSummary')).toBe('What could not be read')
    expect(categoryOf('BrowserHistory')).toBe('Activity')
    expect(categoryOf('ShellHistoryEntry')).toBe('Activity')
    expect(categoryOf('HostDeviceInfo')).toBe('The device')
    expect(categoryOf('IosBackupInfo')).toBe('The device')
    expect(categoryOf('MediaProperties')).toBe('Files and media')
    expect(categoryOf('SqliteRow')).toBe('Derived analysis')
  })

  it('files every coverage record with what could not be read', () => {
    // A `*Coverage` record exists to say what a population does and does not
    // include. Five of them shipped and four were landing in "Other records",
    // where the group a completeness answer rests on does not include them.
    for (const type of [
      'UserAssistCoverage',
      'BamCoverage',
      'MuiCacheCoverage',
      'MruCoverage',
      'ShimDatabaseCoverage',
      'DeviceInstallLogCoverage',
      'StickyNotesCoverage',
      'StickyNotesParseStatus',
    ]) {
      expect(categoryOf(type)).toBe('What could not be read')
    }
  })

  it('does not read a configuration as something the user did', () => {
    // `WindowsSearchState` is the indexer SERVICE's configuration, and the
    // parser says so in as many words: a service set to start automatically on
    // a machine imaged minutes after installation has indexed nothing. The
    // word rule matched `search` and filed it under "What was opened, run,
    // searched for and downloaded" — which invites reading a start type as
    // searches the user performed.
    expect(categoryOf('WindowsSearchState')).toBe('The device')
    // And `NetworkInterface` matched `network`. An interface's addresses and
    // DHCP lease are the exhibit's settings; they are not a record of traffic.
    expect(categoryOf('NetworkInterface')).toBe('The device')
    // MUICache carries `execution_evidence: false`, so Activity would be the
    // same over-claim the parser refuses to make.
    expect(categoryOf('MuiCacheEntry')).toBe('The device')
    // `LocalAccount` would otherwise match the `account` rule and be filed
    // with the mail accounts and chat handles under People and messages.
    expect(categoryOf('LocalAccount')).toBe('The device')
    expect(categoryOf('DeviceInstallEvent')).toBe('The device')
    // A note is a document somebody wrote, and belongs with the documents
    // rather than in "Other records" where no word rule would have placed it.
    expect(categoryOf('StickyNote')).toBe('Files and media')
  })

  it('files the registry execution artefacts as activity', () => {
    // These four ARE records of what was done, and all four were landing in
    // "Other records" because no word rule happens to match their names.
    expect(categoryOf('UserAssistEntry')).toBe('Activity')
    expect(categoryOf('BamEntry')).toBe('Activity')
    expect(categoryOf('TypedUrl')).toBe('Activity')
    expect(categoryOf('RdpDestinationEntry')).toBe('Activity')
  })

  it('groups every "could not be read" record together, whatever it is called', () => {
    // These are the records a completeness answer rests on, and they were
    // scattered through the index by count: one here, eight there.
    for (const type of [
      'UtmpParseStatus',
      'BrowserCacheParseStatus',
      'ArchiveScanStatus',
      'ContainerRefusal',
      'BrowserHistoryParseStatus',
      'SqliteSpillIncomplete',
      'NetworkCaptureRefusal',
      'EncryptedArchive',
      'SourceUnparsed',
      'SquashFsError',
    ]) {
      expect(categoryOf(type)).toBe('What could not be read')
    }
  })

  it('places a type it has never seen rather than hiding it', () => {
    // A new parser's records must appear the day it ships, not the day
    // somebody remembers to add them to a list.
    expect(categoryOf('QuantumEntanglementLog')).toBe('Other records')
  })

  it('orders groups by the order of the list, and types inside a group by count', () => {
    const groups = groupRecordTypes([
      { type: 'PerceptualHash', count: 16528 },
      { type: 'iMessage', count: 5 },
      { type: 'EmailMessage', count: 64 },
      { type: 'UtmpParseStatus', count: 73 },
    ])
    expect(groups.map((g) => g.category)).toEqual([
      'People and messages',
      'Derived analysis',
      'What could not be read',
    ])
    expect(groups[0].types.map((t) => t.type)).toEqual([
      'EmailMessage',
      'iMessage',
    ])
    expect(groups[0].total).toBe(69)
  })
})

describe('NtfsBootSector is named, not matched (ROADMAP §1.7)', () => {
  /**
   * The rule list has `/(location|geo|position|session|boot|login|logon|shutdown|calendar)/i`
   * -> 'Places and times', and it is tried before the device rule. A type
   * called `NtfsBootSector` matches on `boot`, so without a NAMED entry the
   * volume's own geometry would be filed under where the device had been and
   * when it was in use — a false statement about what the record is.
   */
  it('files the volume geometry under the device, not under places and times', () => {
    expect(categoryOf('NtfsBootSector')).toBe('The device')
  })

  /** And the rule that would have caught it is still there, so this test is
   *  pinning the NAMED entry rather than a rule that has since changed. */
  it('still has the boot rule that makes the NAMED entry necessary', () => {
    expect(categoryOf('BootSession')).toBe('Places and times')
  })
})

describe('shim databases are named, not matched (ROADMAP §1.7)', () => {
  /**
   * `ShimExe` matches the Activity rule on `execut`, and a shim entry is
   * explicitly NOT a record that anything executed — it says the operating
   * system would apply a fix to a program matching a pattern. Filing it under
   * Activity would put it beside prefetch and Amcache, which are execution
   * evidence, and invite exactly the inference the record refuses to make.
   */
  it('files a shim entry under the device rather than under activity', () => {
    expect(categoryOf('ShimExe')).toBe('The device')
    expect(categoryOf('ShimDatabase')).toBe('The device')
  })

  /** And the rule that makes the NAMED entry necessary is still there. */
  it('still has the activity rule that would have caught it', () => {
    expect(categoryOf('PrefetchExecution')).toBe('Activity')
  })

  /** The coverage record belongs with what could not be read. */
  it('files the coverage record with what could not be read', () => {
    expect(categoryOf('ShimDatabaseCoverage')).toBe('What could not be read')
  })
})

describe("Spotlight's index is filed by what it says (ROADMAP §1.6)", () => {
  /**
   * The store record's content is mostly the measurement that the store is
   * not decodable — 74 of 86 blocks in the corpus's larger store — so a
   * completeness answer about Spotlight rests on it. That is the definition
   * of the shortfall group.
   */
  it('files the store record with what could not be read', () => {
    expect(categoryOf('SpotlightStore')).toBe('What could not be read')
    expect(categoryOf('SpotlightStoreStatus')).toBe('What could not be read')
  })

  /**
   * And the two vocabularies are not files. Filing a content type under
   * 'Files and media' would stand it beside recovered documents and read as a
   * file on the volume, which the record explicitly refuses to say.
   */
  it('does not file the index vocabularies as files that were recovered', () => {
    expect(categoryOf('SpotlightProperty')).toBe('The device')
    expect(categoryOf('SpotlightContentType')).toBe('The device')
  })

  /** Both would otherwise fall to 'Other records', which is what makes the
   *  NAMED entries necessary rather than decorative. */
  it('would have had no category from the word rules', () => {
    expect(categoryOf('QuuxProperty')).toBe('Other records')
    expect(categoryOf('QuuxContentType')).toBe('Other records')
  })
})

describe("the unified log's catalogue is an inventory, not execution (ROADMAP §1.6)", () => {
  /**
   * A `/var/db/uuidtext` entry means the machine held logging metadata for a
   * binary. Filing it under Activity would stand it beside prefetch and
   * Amcache, which ARE execution evidence, and invite reading a catalogue
   * entry as a run.
   */
  it('files a binary with a logging catalogue under the device', () => {
    expect(categoryOf('UnifiedLogImage')).toBe('The device')
  })

  /** And the rule that makes the NAMED entry necessary is still there. */
  it('still has the activity rule that would have caught it', () => {
    expect(categoryOf('PrefetchExecution')).toBe('Activity')
  })

  /** The per-file record is mostly a statement about how much could be read. */
  it('files the catalogue file record with what could not be read', () => {
    expect(categoryOf('UnifiedLogCatalogue')).toBe('What could not be read')
    expect(categoryOf('UnifiedLogMessage')).toBe('Activity')
  })
})

describe('what the 2026-09 waves added (recovered, coverage and new parsers)', () => {
  /** The histogram is the sibling of `FeatureSummary`: what the scanner
   *  computed, not something read out of the evidence. */
  it('files the feature histogram with the derived analysis', () => {
    expect(categoryOf('FeatureHistogramSummary')).toBe('Derived analysis')
    expect(categoryOf('FeatureHistogramSummary')).toBe(categoryOf('FeatureSummary'))
  })

  /** A recovered event is shown APART from a live one by type, and beside it
   *  by group: it is the same kind of record with a different provenance, and
   *  a reader looking for event logs must find both in one place. */
  it('keeps recovered event-log entries in the group of the live ones', () => {
    expect(categoryOf('EvtxRecoveredLogEntry')).toBe(categoryOf('EvtxLogEntry'))
  })

  /** The recovery status record is the statement of what the carve could and
   *  could not reach: bounds hit, chunks unopenable, records partial. */
  it('files the EVTX recovery status with what could not be read', () => {
    expect(categoryOf('EvtxRecoveryStatus')).toBe('What could not be read')
  })

  /** A recovered key or value is a fact about the exhibit's registry, filed
   *  with the hive it came out of -- the TYPE keeps it apart from live keys. */
  it('files recovered registry cells with the device, beside the hive', () => {
    expect(categoryOf('RecoveredRegistryKey')).toBe('The device')
    expect(categoryOf('RecoveredRegistryValue')).toBe('The device')
    expect(categoryOf('RecoveredRegistryKey')).toBe(categoryOf('RegistryHive'))
  })

  /** A region record is a measurement (entropy over the bytes read); the two
   *  coverage records say what the scan did not reach. */
  it('files the YARA region and coverage records where they belong', () => {
    expect(categoryOf('YaraRegionScanned')).toBe('Derived analysis')
    expect(categoryOf('YaraRegistryCoverage')).toBe('What could not be read')
    expect(categoryOf('YaraDecodeCoverage')).toBe('What could not be read')
  })

  /** A parser that met a schema outside its validated range says so on a
   *  record of its own; it belongs with the shortfall statements. */
  it('files a parser schema warning with what could not be read', () => {
    expect(categoryOf('ParserStaleWarning')).toBe('What could not be read')
  })

  /** A WMI subscription recovered from bytes nothing references is filed with
   *  the live autostart entries -- same subject, its own TYPE. */
  it('files a recovered autostart entry with the live ones', () => {
    expect(categoryOf('RecoveredAsepEntry')).toBe(categoryOf('AsepEntry'))
    expect(categoryOf('RecoveredAsepEntry')).toBe('The device')
  })

  it('files jump list DestList entries as activity', () => {
    expect(categoryOf('JumpListDestListEntry')).toBe('Activity')
  })

  it('files the iOS Safari records as activity and HealthKit samples with times', () => {
    expect(categoryOf('SafariBookmark')).toBe('Activity')
    expect(categoryOf('SafariBookmarkFolder')).toBe('Activity')
    expect(categoryOf('SafariOpenTab')).toBe('Activity')
    expect(categoryOf('SafariWindow')).toBe('Activity')
    expect(categoryOf('WebSearchQuery')).toBe('Activity')
    expect(categoryOf('HealthSample')).toBe('Places and times')
  })
})
