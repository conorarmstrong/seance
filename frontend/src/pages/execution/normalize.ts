import type { ParsedRecord } from '../analysis/api'
import { metaNum, metaStr } from '../analysis/lib'
import { toEpochMs } from '../../lib/epoch'

// Re-exported so existing importers (comms, tests) keep a single entry point.
export { toEpochMs }

export type ExecSource =
  | 'Prefetch'
  | 'Amcache'
  | 'Shimcache'
  | 'Shortcut'
  | 'Timeline'

/** One normalised program-execution / access event from any of the sources. */
export interface ExecEvent {
  artifactId: string
  /** Executable / target file name (basename). */
  program: string
  fullPath: string | null
  /** Epoch milliseconds, or null when the source carried no usable time. */
  time: number | null
  source: ExecSource
  /** Source-specific note (run count, publisher, executed flag, arguments). */
  detail: string
}

/** Last path segment of a Windows or POSIX path. */
export function basename(path: string | null): string | null {
  if (!path) return null
  const parts = path.split(/[\\/]/).filter(Boolean)
  return parts.length ? parts[parts.length - 1] : path
}

/**
 * Normalise one ParsedRecord type into unified execution events. Unknown types
 * yield an empty list. Records missing a program name are dropped (they cannot
 * be correlated).
 */
export function normalizeExecution(
  type: string,
  records: ParsedRecord[],
): ExecEvent[] {
  const out: ExecEvent[] = []
  for (const r of records) {
    const m = r.metadata
    let ev: ExecEvent | null = null
    switch (type) {
      case 'PrefetchEntry': {
        const program = metaStr(m, 'executable_name')
        if (program) {
          const runs = metaNum(m, 'run_count')
          ev = {
            artifactId: r.id,
            program,
            fullPath: null,
            time: toEpochMs(m, ['last_execution_time']),
            source: 'Prefetch',
            detail: runs != null ? `${runs} run${runs === 1 ? '' : 's'}` : '',
          }
        }
        break
      }
      case 'AmcacheEntry': {
        const fullPath = metaStr(m, 'file_path')
        const program = basename(fullPath)
        if (program) {
          ev = {
            artifactId: r.id,
            program,
            fullPath,
            time: toEpochMs(m, ['link_date']),
            source: 'Amcache',
            detail: metaStr(m, 'publisher') ?? '',
          }
        }
        break
      }
      case 'ShimcacheEntry': {
        const fullPath = metaStr(m, 'path')
        const program = basename(fullPath)
        if (program) {
          ev = {
            artifactId: r.id,
            program,
            fullPath,
            time: toEpochMs(m, ['last_modified']),
            source: 'Shimcache',
            detail: m.exec_flag === true ? 'executed' : '',
          }
        }
        break
      }
      case 'LnkFile': {
        const fullPath = metaStr(m, 'target_local_path') ?? metaStr(m, 'relative_path')
        const program = basename(fullPath)
        if (program) {
          ev = {
            artifactId: r.id,
            program,
            fullPath,
            time: toEpochMs(m, ['target_modified', 'target_created', 'target_accessed']),
            source: 'Shortcut',
            detail: metaStr(m, 'arguments') ?? '',
          }
        }
        break
      }
      case 'WindowsTimelineActivity': {
        // Only focus (6) and open (5) activities are program-execution
        // evidence; clipboard/system/notification types are not.
        const t = metaNum(m, 'activity_type')
        if (t !== 5 && t !== 6) break
        const exe = metaStr(m, 'executable')
        const program = basename(exe) ?? metaStr(m, 'app_display_name')
        if (program) {
          const dt = metaStr(m, 'display_text')
          const dur = metaNum(m, 'duration_seconds') ?? metaNum(m, 'active_duration_seconds')
          const durStr = dur != null && dur > 0 ? `${dur}s` : ''
          ev = {
            artifactId: r.id,
            program,
            fullPath: metaStr(m, 'content_uri') ?? exe,
            time: toEpochMs(m, ['start_time', 'date']),
            source: 'Timeline',
            detail: [dt, durStr].filter(Boolean).join(' · '),
          }
        }
        break
      }
    }
    if (ev) out.push(ev)
  }
  return out
}

/** The ParsedRecord types the execution view correlates. */
export const EXECUTION_TYPES = [
  'PrefetchEntry',
  'AmcacheEntry',
  'ShimcacheEntry',
  'LnkFile',
  'WindowsTimelineActivity',
] as const
