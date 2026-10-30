import { beforeEach, describe, expect, it } from 'vitest'
import {
  SQLITE_HISTORY_MAX,
  clearHistory,
  historyKey,
  loadHistory,
  recordHistory,
  type SqliteHistoryEntry,
} from './SqliteQueryHistory'

function entry(sql: string, extra: Partial<SqliteHistoryEntry> = {}): SqliteHistoryEntry {
  return {
    sql,
    database: 'History',
    artifactId: 'db-1',
    at: '2026-09-19T10:00:00.000Z',
    outcome: 'ok',
    rowCount: 3,
    capped: false,
    ...extra,
  }
}

describe('SQLite query history', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('keys the store by case id so two cases never share a history', () => {
    expect(historyKey('case-a')).not.toBe(historyKey('case-b'))
    expect(historyKey('case-a')).toContain('case-a')
    recordHistory('case-a', entry('SELECT 1'))
    expect(loadHistory('case-b')).toEqual([])
    expect(loadHistory('case-a')).toHaveLength(1)
  })

  it('returns the newest entry first', () => {
    recordHistory('c', entry('SELECT 1', { at: '2026-09-19T10:00:00.000Z' }))
    recordHistory('c', entry('SELECT 2', { at: '2026-09-19T10:00:01.000Z' }))
    expect(loadHistory('c').map((e) => e.sql)).toEqual(['SELECT 2', 'SELECT 1'])
  })

  it('moves a re-run of the same statement on the same database to the top instead of duplicating it', () => {
    recordHistory('c', entry('SELECT 1'))
    recordHistory('c', entry('SELECT 2'))
    recordHistory('c', entry('SELECT 1', { at: '2026-09-19T11:00:00.000Z' }))
    const h = loadHistory('c')
    expect(h.map((e) => e.sql)).toEqual(['SELECT 1', 'SELECT 2'])
    expect(h[0].at).toBe('2026-09-19T11:00:00.000Z')
  })

  it('keeps the same statement against a different database as a separate entry', () => {
    recordHistory('c', entry('SELECT 1', { artifactId: 'db-1' }))
    recordHistory('c', entry('SELECT 1', { artifactId: 'db-2' }))
    expect(loadHistory('c')).toHaveLength(2)
  })

  it(`keeps at most ${SQLITE_HISTORY_MAX} entries, dropping the oldest`, () => {
    for (let i = 0; i < SQLITE_HISTORY_MAX + 5; i++) {
      recordHistory('c', entry(`SELECT ${i}`))
    }
    const h = loadHistory('c')
    expect(h).toHaveLength(SQLITE_HISTORY_MAX)
    expect(h[0].sql).toBe(`SELECT ${SQLITE_HISTORY_MAX + 4}`)
    expect(h.some((e) => e.sql === 'SELECT 0')).toBe(false)
  })

  it('records a failed run with its error so the history is not only the successes', () => {
    recordHistory('c', entry('SELEC 1', { outcome: 'error', error: 'near "SELEC": syntax error', rowCount: undefined }))
    const [e] = loadHistory('c')
    expect(e.outcome).toBe('error')
    expect(e.error).toContain('syntax error')
  })

  it('treats an unreadable stored value as an empty history rather than throwing', () => {
    localStorage.setItem(historyKey('c'), '{not json')
    expect(loadHistory('c')).toEqual([])
    localStorage.setItem(historyKey('c'), JSON.stringify([{ nope: true }, 42]))
    expect(loadHistory('c')).toEqual([])
  })

  it('clears one case only', () => {
    recordHistory('a', entry('SELECT 1'))
    recordHistory('b', entry('SELECT 1'))
    clearHistory('a')
    expect(loadHistory('a')).toEqual([])
    expect(loadHistory('b')).toHaveLength(1)
  })
})
