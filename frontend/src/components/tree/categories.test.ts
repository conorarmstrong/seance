// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { buildLogicalTree, categoryForType } from './categories'

const rt = (type: string, count: number) => ({ type, count })

describe('buildLogicalTree', () => {
  it('groups messaging types into one Chats category with a summed count', () => {
    const tree = buildLogicalTree([
      rt('WhatsApp', 3110),
      rt('iMessage', 1486),
      rt('AndroidSms', 904),
    ])
    const chats = tree.find((c) => c.key === 'chats')
    expect(chats).toBeDefined()
    expect(chats!.label).toBe('Chats')
    expect(chats!.count).toBe(3110 + 1486 + 904)
    // Children are sorted by count desc and labelled via humanizeType.
    expect(chats!.children.map((n) => n.type)).toEqual([
      'WhatsApp',
      'iMessage',
      'AndroidSms',
    ])
    expect(chats!.children.find((n) => n.type === 'AndroidSms')!.label).toBe(
      'Android SMS/MMS',
    )
  })

  it('maps browser record types into the Web category', () => {
    const tree = buildLogicalTree([
      rt('BrowserHistory', 6201),
      rt('BrowserDownload', 106),
    ])
    const web = tree.find((c) => c.key === 'web')!
    expect(web.count).toBe(6307)
    expect(web.children.map((n) => n.label)).toContain('Browser History')
  })

  it('buckets unknown types into Other', () => {
    const tree = buildLogicalTree([rt('SomethingNew', 5)])
    const other = tree.find((c) => c.key === 'other')!
    expect(other.count).toBe(5)
    expect(other.children[0].type).toBe('SomethingNew')
  })

  it('excludes internal/derived record types', () => {
    const tree = buildLogicalTree([
      rt('file_hash', 999),
      rt('allocation_map', 5),
      rt('CarvingSummary', 2),
      rt('Contact', 3),
    ])
    expect(tree.flatMap((c) => c.children.map((n) => n.type))).toEqual([
      'Contact',
    ])
    expect(tree).toHaveLength(1)
    expect(tree[0].key).toBe('contacts')
  })

  it('skips zero and negative counts', () => {
    const tree = buildLogicalTree([
      rt('Contact', 0),
      rt('CallLog', -3),
      rt('EmailMessage', 4),
    ])
    expect(tree.map((c) => c.key)).toEqual(['email'])
  })

  it('returns categories in a stable examiner order', () => {
    const tree = buildLogicalTree([
      rt('RegistryHive', 10), // system
      rt('WhatsApp', 5), // chats
      rt('Contact', 3), // contacts
    ])
    expect(tree.map((c) => c.key)).toEqual(['chats', 'contacts', 'system'])
  })

  it('files the registry-resident artifacts rather than leaving them in Other', () => {
    // Eleven record types shipped for ROADMAP §2.5 and §2.6 and every one fell
    // to 'other', so the examiner tree showed "Other (n)" for the whole of
    // Windows execution and device history. `InstalledProgram` -- the Windows
    // side of `InstalledApp`, which IS mapped -- had been there longer.
    expect(categoryForType('UserAssistEntry')).toBe('execution')
    expect(categoryForType('BamEntry')).toBe('execution')
    expect(categoryForType('InstalledProgram')).toBe('apps')
    expect(categoryForType('TypedUrl')).toBe('web')
    for (const type of [
      'UsbDevice',
      'MountedDevice',
      'NetworkInterface',
      'WindowsSearchState',
      'MuiCacheEntry',
      'ShellMruEntry',
      'RdpDestinationEntry',
      'LocalAccount',
      'DeviceInstallEvent',
    ]) {
      expect(categoryForType(type)).toBe('system')
    }
  })

  it('keeps a coverage record beside the population it describes', () => {
    // This tree has no shortfall category, so a coverage record files with its
    // own family -- as `ShimDatabaseCoverage` already does. Putting it in
    // 'other' would separate "what this population excludes" from the
    // population, which is where a reader stops finding it.
    expect(categoryForType('UserAssistCoverage')).toBe(
      categoryForType('UserAssistEntry'),
    )
    expect(categoryForType('BamCoverage')).toBe(categoryForType('BamEntry'))
    expect(categoryForType('MuiCacheCoverage')).toBe(
      categoryForType('MuiCacheEntry'),
    )
    expect(categoryForType('MruCoverage')).toBe(
      categoryForType('ShellMruEntry'),
    )
  })

  it('returns an empty array for no record types', () => {
    expect(buildLogicalTree([])).toEqual([])
  })
})

describe('recovered records sit beside their live counterparts, as their own type', () => {
  it('files recovered event-log entries and the recovery status with the live log', () => {
    expect(categoryForType('EvtxRecoveredLogEntry')).toBe(
      categoryForType('EvtxLogEntry'),
    )
    expect(categoryForType('EvtxRecoveryStatus')).toBe(
      categoryForType('EvtxLogEntry'),
    )
  })

  it('files recovered registry cells with the hive they came from', () => {
    expect(categoryForType('RecoveredRegistryKey')).toBe(
      categoryForType('RegistryHive'),
    )
    expect(categoryForType('RecoveredRegistryValue')).toBe(
      categoryForType('RegistryHive'),
    )
  })

  it('shows a recovered event log as its own child of the category, never merged with the live one', () => {
    const tree = buildLogicalTree([
      { type: 'EvtxLogEntry', count: 10 },
      { type: 'EvtxRecoveredLogEntry', count: 3 },
    ])
    const system = tree.find((c) => c.key === 'system')
    expect(system?.children.map((c) => c.label)).toEqual([
      'Windows Event Log',
      'Windows Event Log (recovered)',
    ])
  })

  it('files jump list entries with execution and the iOS Safari records with the web', () => {
    expect(categoryForType('JumpListDestListEntry')).toBe('execution')
    expect(categoryForType('SafariBookmark')).toBe('web')
    expect(categoryForType('SafariOpenTab')).toBe('web')
    expect(categoryForType('WebSearchQuery')).toBe('web')
  })
})
