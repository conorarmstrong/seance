/**
 * Per-browser history of statements run in the SQLite query editor.
 *
 * This is a convenience for the examiner at this keyboard, not a record of
 * the case: it lives in this browser's localStorage, keyed by case id so two
 * cases never mix, and is capped at {@link SQLITE_HISTORY_MAX} entries with the
 * oldest dropped first. Nothing here reaches the server or another examiner;
 * the query editor says so on screen.
 */

/** Most entries kept per case; the oldest is dropped past this. */
export const SQLITE_HISTORY_MAX = 50

export interface SqliteHistoryEntry {
  sql: string
  /** Database file name the statement ran against, as the rail shows it. */
  database: string | null
  /** The database file's artifact id, which is what the server was asked for. */
  artifactId: string | null
  /** ISO-8601 instant the run was recorded. */
  at: string
  outcome: 'ok' | 'error'
  /** Rows the server returned, on an `ok` run. */
  rowCount?: number
  /** Whether the server's row cap bound that run, on an `ok` run. */
  capped?: boolean
  /** The server's refusal or SQL error, on an `error` run. */
  error?: string
}

const KEY_PREFIX = 'seance.sqlite.query_history.'

export function historyKey(caseId: string): string {
  return `${KEY_PREFIX}${caseId}`
}

function isEntry(v: unknown): v is SqliteHistoryEntry {
  if (v == null || typeof v !== 'object') return false
  const o = v as Record<string, unknown>
  return (
    typeof o.sql === 'string' &&
    typeof o.at === 'string' &&
    (o.outcome === 'ok' || o.outcome === 'error') &&
    (o.database == null || typeof o.database === 'string') &&
    (o.artifactId == null || typeof o.artifactId === 'string')
  )
}

/**
 * The stored history for a case, newest first. Anything unreadable — a
 * private window, cleared site data, a value another build wrote — reads as
 * empty rather than throwing into the viewer.
 */
export function loadHistory(caseId: string): SqliteHistoryEntry[] {
  let raw: string | null
  try {
    raw = localStorage.getItem(historyKey(caseId))
  } catch {
    return []
  }
  if (raw == null) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter(isEntry)
  } catch {
    return []
  }
}

function save(caseId: string, entries: SqliteHistoryEntry[]): void {
  try {
    localStorage.setItem(historyKey(caseId), JSON.stringify(entries))
  } catch {
    // Storage unavailable or full: the history is a convenience and the
    // query result on screen is unaffected.
  }
}

/**
 * Record a run at the head of the case's history. A re-run of the same
 * statement against the same database replaces its earlier entry rather than
 * duplicating it; the list is then cut to {@link SQLITE_HISTORY_MAX}.
 * Returns the history as now stored.
 */
export function recordHistory(
  caseId: string,
  entry: SqliteHistoryEntry,
): SqliteHistoryEntry[] {
  const rest = loadHistory(caseId).filter(
    (e) => !(e.sql === entry.sql && e.artifactId === entry.artifactId),
  )
  const next = [entry, ...rest].slice(0, SQLITE_HISTORY_MAX)
  save(caseId, next)
  return next
}

export function clearHistory(caseId: string): void {
  try {
    localStorage.removeItem(historyKey(caseId))
  } catch {
    // Nothing to clear if storage is unreachable.
  }
}
