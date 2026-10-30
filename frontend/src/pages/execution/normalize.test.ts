// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import type { ParsedRecord } from '../analysis/api'
import { basename, normalizeExecution, toEpochMs } from './normalize'

function rec(id: string, metadata: Record<string, unknown>): ParsedRecord {
  return { id, parent_id: null, artifact_type: 'ParsedRecord', metadata }
}

describe('basename', () => {
  it('takes the last segment of windows and posix paths', () => {
    expect(basename('C:\\Windows\\System32\\cmd.exe')).toBe('cmd.exe')
    expect(basename('/usr/bin/bash')).toBe('bash')
    expect(basename('lone.exe')).toBe('lone.exe')
    expect(basename(null)).toBeNull()
  })
})

describe('toEpochMs', () => {
  it('reads unix seconds, unix ms, and ISO strings', () => {
    expect(toEpochMs({ t: 1_700_000_000 }, ['t'])).toBe(1_700_000_000_000)
    expect(toEpochMs({ t: 1_700_000_000_000 }, ['t'])).toBe(1_700_000_000_000)
    expect(toEpochMs({ t: '2023-01-02T03:04:05Z' }, ['t'])).toBe(
      Date.parse('2023-01-02T03:04:05Z'),
    )
    expect(toEpochMs({ t: 'nope' }, ['t'])).toBeNull()
  })
})

describe('normalizeExecution', () => {
  it('maps each source type into unified events with program + time + detail', () => {
    const prefetch = normalizeExecution('PrefetchEntry', [
      rec('p1', {
        executable_name: 'CMD.EXE',
        run_count: 5,
        last_execution_time: 1_700_000_000,
      }),
    ])
    expect(prefetch).toHaveLength(1)
    expect(prefetch[0]).toMatchObject({
      program: 'CMD.EXE',
      source: 'Prefetch',
      detail: '5 runs',
      time: 1_700_000_000_000,
    })

    const amcache = normalizeExecution('AmcacheEntry', [
      rec('a1', { file_path: 'C:\\tools\\mimikatz.exe', publisher: 'Unknown' }),
    ])
    expect(amcache[0]).toMatchObject({
      program: 'mimikatz.exe',
      fullPath: 'C:\\tools\\mimikatz.exe',
      source: 'Amcache',
      detail: 'Unknown',
    })

    const shim = normalizeExecution('ShimcacheEntry', [
      rec('s1', { path: '\\Device\\X\\evil.exe', exec_flag: true }),
    ])
    expect(shim[0]).toMatchObject({ program: 'evil.exe', detail: 'executed' })

    const lnk = normalizeExecution('LnkFile', [
      rec('l1', { target_local_path: 'C:\\Users\\a\\report.docx' }),
    ])
    expect(lnk[0]).toMatchObject({ program: 'report.docx', source: 'Shortcut' })
  })

  it('maps focus/open timeline activities and drops non-execution types', () => {
    const focus = normalizeExecution('WindowsTimelineActivity', [
      rec('t1', {
        activity_type: 6,
        executable: 'C:\\Program Files\\Microsoft Office\\WINWORD.EXE',
        app_display_name: 'Microsoft Word',
        display_text: 'pshashes.txt',
        content_uri: 'file:///C:/Users/bob/Desktop/pshashes.txt',
        start_time: 1546300800,
        duration_seconds: 45,
      }),
    ])
    expect(focus).toHaveLength(1)
    expect(focus[0]).toMatchObject({
      program: 'WINWORD.EXE',
      fullPath: 'file:///C:/Users/bob/Desktop/pshashes.txt',
      source: 'Timeline',
      detail: 'pshashes.txt · 45s',
      time: 1546300800000,
    })

    // Clipboard (10) and system (11/12/15) activities are not execution evidence.
    const clip = normalizeExecution('WindowsTimelineActivity', [
      rec('t2', {
        activity_type: 10,
        executable: 'C:\\Windows\\explorer.exe',
        clipboard_text: 'hunter2',
      }),
    ])
    expect(clip).toEqual([])
  })

  it('drops records without a program name and ignores unknown types', () => {
    expect(normalizeExecution('PrefetchEntry', [rec('p', {})])).toEqual([])
    expect(normalizeExecution('Nonsense', [rec('x', { a: 1 })])).toEqual([])
  })
})
