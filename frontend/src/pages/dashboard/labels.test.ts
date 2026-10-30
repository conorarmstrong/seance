// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { fsUsageLabel } from './labels'

/**
 * LIVE-018: a macOS container holds a dozen APFS volumes. Labelling each by its
 * filesystem TYPE rendered twelve identical "Disk usage — APFS" rows, so the
 * examiner could not tell Macintosh HD from Preboot, Recovery or VM — while the
 * volume name was already loaded on the very region being labelled.
 */
describe('fsUsageLabel', () => {
  const region = (name: string | null, fs_type: string | null) => ({
    name,
    fs_type,
  })

  it('names the volume, not just its filesystem type', () => {
    expect(fsUsageLabel(region('Macintosh HD', 'apfs'))).toBe(
      'Macintosh HD (APFS)',
    )
  })

  it('tells sibling volumes of one type apart', () => {
    const labels = [
      region('Macintosh HD', 'apfs'),
      region('Macintosh HD - Data', 'apfs'),
      region('Preboot', 'apfs'),
      region('Recovery', 'apfs'),
    ].map(fsUsageLabel)
    expect(new Set(labels).size).toBe(4)
  })

  // Not a house style: a name that already carries its type is left to say it
  // once rather than being padded into "NTFS volume (NTFS)".
  it('does not repeat a type the name already states', () => {
    expect(fsUsageLabel(region('NTFS volume', 'ntfs'))).toBe('NTFS volume')
  })

  it('falls back to the type when the region is unnamed', () => {
    expect(fsUsageLabel(region('', 'apfs'))).toBe('APFS')
  })

  it('falls back to the name when the type is unknown', () => {
    expect(fsUsageLabel(region('Volume 3', null))).toBe('Volume 3')
  })

  // Real APFS volume regions come back with a null name, though the response
  // type declared `string`. Trusting the declaration crashed the whole
  // dashboard to a blank page on the first macOS case (LIVE-018).
  it('survives a region the server left unnamed', () => {
    expect(fsUsageLabel(region(null, 'apfs'))).toBe('APFS')
  })

  it('has something to say even when the region is wholly anonymous', () => {
    expect(fsUsageLabel(region(null, null))).toBe('File system')
  })
})
