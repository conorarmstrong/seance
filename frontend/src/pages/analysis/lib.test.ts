import { describe, expect, it } from 'vitest'
import { humanizeType } from './lib'

/**
 * A record type's label is what the index, the tree and the viewer heading
 * say it is. For a recovered or coverage record the label has to carry the
 * provenance, because the label is the only thing a reader sees before the
 * rows -- "Windows Event Log" over a table of carved chunk-slack records
 * would present recovered events as live ones.
 */
describe('labels for recovered, coverage and newly parsed record types', () => {
  it('names a recovered event log apart from the live one', () => {
    expect(humanizeType('EvtxLogEntry')).toBe('Windows Event Log')
    expect(humanizeType('EvtxRecoveredLogEntry')).toBe(
      'Windows Event Log (recovered)',
    )
    expect(humanizeType('EvtxRecoveryStatus')).toMatch(/recovery/i)
  })

  it('names recovered registry cells as recovered, apart from the hive', () => {
    expect(humanizeType('RecoveredRegistryKey')).toMatch(/recovered/i)
    expect(humanizeType('RecoveredRegistryValue')).toMatch(/recovered/i)
    expect(humanizeType('RecoveredRegistryKey')).not.toBe(
      humanizeType('RecoveredRegistryValue'),
    )
  })

  it('names the YARA region, registry and decode records without a generic split', () => {
    expect(humanizeType('YaraRegionScanned')).toBe('YARA regions scanned')
    expect(humanizeType('YaraRegistryCoverage')).toBe('YARA registry coverage')
    expect(humanizeType('YaraDecodeCoverage')).toBe('YARA decode coverage')
  })

  it('names the feature histogram, the jump list DestList and the iOS records', () => {
    expect(humanizeType('FeatureHistogramSummary')).toBe('Feature histograms')
    expect(humanizeType('JumpListDestListEntry')).toBe('Jump list entries (DestList)')
    expect(humanizeType('BitsCarvedFileTransfer')).toBe('BITS file records (carved)')
    expect(humanizeType('WindowsSearchItem')).toBe('Search index rows')
    expect(humanizeType('SafariBookmark')).toBe('Safari bookmarks (iOS)')
    expect(humanizeType('SafariOpenTab')).toBe('Safari open tabs (iOS)')
    expect(humanizeType('WebSearchQuery')).toBe('Web searches')
    expect(humanizeType('HealthSample')).toBe('HealthKit samples')
    expect(humanizeType('ParserStaleWarning')).toBe('Parser schema warnings')
  })

  it('names a recovered autostart entry apart from a live one', () => {
    expect(humanizeType('AsepEntry')).toBe('Autostart entries (ASEP)')
    expect(humanizeType('RecoveredAsepEntry')).toBe('Autostart entries (ASEP, recovered)')
    expect(humanizeType('AsepCoverage')).toBe('ASEP Coverage')
  })

  it('names the eight Windows memory stage records and the two Linux ones', () => {
    expect(humanizeType('MemoryProcessorBlocks')).toBe('Memory: processor blocks')
    expect(humanizeType('MemoryBigPool')).toBe('Memory: big-page pool')
    expect(humanizeType('MemoryVirtualMap')).toBe('Memory: kernel virtual-address map')
    expect(humanizeType('MemoryHiveCellRoutines')).toBe('Memory: hive cell routines')
    expect(humanizeType('MemoryVersionInfo')).toBe('Memory: image version resources')
    expect(humanizeType('MemoryMbrScan')).toBe('Memory: boot sectors (MBR scan)')
    expect(humanizeType('MemoryScheduledTasks')).toBe('Memory: scheduled tasks')
    expect(humanizeType('MemoryTrueCrypt')).toBe('Memory: TrueCrypt/VeraCrypt')
    expect(humanizeType('LinuxMemoryKernelHooks')).toBe('Linux memory: kernel hooks')
    expect(humanizeType('LinuxMemoryCommandLines')).toBe('Linux memory: command lines')
    expect(humanizeType('LinuxMemoryOpenFiles')).toBe('Linux memory: open files')
    expect(humanizeType('LinuxMemoryMounts')).toBe('Linux memory: mounts')
  })
})
