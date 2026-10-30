// Runs in the plain node environment: this file touches no DOM and shells out
// to the sqlite3 CLI to prove each template against the real fixture it names.
// @vitest-environment node
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  SQLITE_QUERY_TEMPLATES,
  templateApplicability,
  type SqliteQueryTemplate,
} from './SqliteTemplates'

/** Repository root: this file is frontend/src/pages/analysis/. */
const REPO_ROOT = resolve(__dirname, '../../../..')

function sqlite3Available(): boolean {
  try {
    execFileSync('sqlite3', ['-version'], { stdio: 'pipe' })
    return true
  } catch {
    return false
  }
}

function runJson(dbPath: string, sql: string): unknown[] {
  const out = execFileSync('sqlite3', ['-readonly', '-json', dbPath, sql], {
    stdio: 'pipe',
    encoding: 'utf8',
  })
  return out.trim() === '' ? [] : (JSON.parse(out) as unknown[])
}

function fixtureTables(dbPath: string): string[] {
  const rows = runJson(
    dbPath,
    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
  ) as { name: string }[]
  return rows.map((r) => r.name)
}

describe('SQLite query templates (shape)', () => {
  it('has a unique id per template', () => {
    const ids = SQLITE_QUERY_TEMPLATES.map((t) => t.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('is one statement each, with no trailing second statement', () => {
    for (const t of SQLITE_QUERY_TEMPLATES) {
      const body = t.sql.trim().replace(/;\s*$/, '')
      expect(body, t.id).not.toContain(';')
      expect(body.toUpperCase(), t.id).toMatch(/^(SELECT|WITH)\b/)
    }
  })

  it('only the schema template applies to any database; every other one names its tables', () => {
    for (const t of SQLITE_QUERY_TEMPLATES) {
      if (t.id === 'schema') expect(t.requires).toEqual([])
      else expect(t.requires.length, t.id).toBeGreaterThan(0)
    }
  })

  it('names the real fixture each template was proven against', () => {
    for (const t of SQLITE_QUERY_TEMPLATES) {
      expect(t.fixture, t.id).toMatch(/^(reference|test_data)\//)
    }
  })
})

describe('templateApplicability', () => {
  const t: SqliteQueryTemplate = {
    id: 't',
    title: 't',
    artifact: 'x',
    requires: ['urls', 'visits'],
    sql: 'SELECT 1',
    notes: '',
    fixture: 'reference/x',
  }

  it('is applicable when every required table is in the schema', () => {
    expect(templateApplicability(t, ['urls', 'visits', 'meta'])).toEqual({
      applicable: true,
      missing: [],
      schemaKnown: true,
    })
  })

  it('names the missing tables when it is not', () => {
    expect(templateApplicability(t, ['urls'])).toEqual({
      applicable: false,
      missing: ['visits'],
      schemaKnown: true,
    })
  })

  it('does not call a template inapplicable when the schema was never listed', () => {
    // An empty table list means the summary carried none — "could not look",
    // not "these tables are absent".
    expect(templateApplicability(t, [])).toEqual({
      applicable: true,
      missing: [],
      schemaKnown: false,
    })
  })
})

describe('SQLite query templates (against their real fixtures)', () => {
  const haveSqlite3 = sqlite3Available()

  for (const t of SQLITE_QUERY_TEMPLATES) {
    const dbPath = resolve(REPO_ROOT, t.fixture)
    const present = haveSqlite3 && existsSync(dbPath)
    it.skipIf(!present)(
      `${t.id}: runs against ${t.fixture} and returns rows`,
      () => {
        const tables = fixtureTables(dbPath)
        for (const req of t.requires) {
          expect(tables, `${t.id} requires ${req}`).toContain(req)
        }
        const rows = runJson(dbPath, t.sql)
        expect(rows.length, t.id).toBeGreaterThan(0)
      },
    )
  }
})

/**
 * HUNT-202: `ios_messages` decodes `message.date` by magnitude. The template's
 * named fixture holds seconds-scale dates only, so the nanosecond branch is
 * proven here — on synthetic rows whose values are copied from a real device
 * (the Magnet 2022 iPhone 8 `sms.db`, iOS 15) and, when that file is on the
 * machine, on the device's own rows — and the threshold is the one
 * `seance_core::time` applies (`COCOA_NS_THRESHOLD`, 1e12, strictly greater).
 */
describe('ios_messages: date_utc_by_magnitude', () => {
  const haveSqlite3 = sqlite3Available()
  const template = SQLITE_QUERY_TEMPLATES.find((t) => t.id === 'ios_messages')!

  it('uses the threshold seance_core::time uses (1e12, strictly greater)', () => {
    expect(template.sql).toContain('m.date > 1000000000000')
    expect(template.sql).not.toContain('100000000000 THEN')
  })

  /** A scratch database with the two tables the template reads. */
  function scratchDb(dates: (number | bigint)[]): string {
    const dir = mkdtempSync(join(tmpdir(), 'ios-messages-'))
    const path = join(dir, 'sms.db')
    const rows = dates
      .map((d, i) => `(${i + 1}, ${d}, 1, ${i % 2}, 'iMessage', 'row ${i + 1}')`)
      .join(', ')
    execFileSync('sqlite3', [
      path,
      `CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
       INSERT INTO handle VALUES (1, '+15555550123');
       CREATE TABLE message (ROWID INTEGER PRIMARY KEY, date INTEGER, handle_id INTEGER,
                             is_from_me INTEGER, service TEXT, text TEXT);
       INSERT INTO message (ROWID, date, handle_id, is_from_me, service, text) VALUES ${rows};`,
    ])
    return path
  }

  it.skipIf(!haveSqlite3)(
    'decodes iOS 11+ nanoseconds and pre-iOS 11 seconds, and a zero date to nothing',
    () => {
      // 666111965690755968: the newest message.date on the Magnet 2022
      // iPhone 8; 470777093: the newest in plaso's imessage_chat.db.
      const db = scratchDb([666111965690755968n, 470777093, 0])
      const rows = runJson(db, template.sql) as {
        ROWID: number
        date_raw: number
        date_utc_by_magnitude: string | null
      }[]
      const byId = new Map(rows.map((r) => [r.ROWID, r]))
      expect(byId.get(1)!.date_utc_by_magnitude).toBe('2022-02-09 15:06:05')
      expect(byId.get(2)!.date_utc_by_magnitude).toBe('2015-12-02 19:24:53')
      // A zero date is "no date", as the crate reads it — not 2001-01-01.
      expect(byId.get(3)!.date_utc_by_magnitude).toBeNull()
    },
  )

  // The device's own database, extracted from `2022 CTF - iOS Full File
  // System.zip` (…/private/var/mobile/Library/SMS/sms.db with its -wal and
  // -shm, sha256 cf66790d…aaf0). Not in the tree; point the variable at a copy.
  const deviceDb = process.env.SEANCE_MAGNET2022_SMS_DB ?? ''
  it.skipIf(!haveSqlite3 || !deviceDb || !existsSync(deviceDb))(
    'decodes every message on the Magnet 2022 iPhone 8 sms.db into February 2022',
    () => {
      const rows = runJson(deviceDb, template.sql) as {
        date_raw: number
        date_utc_by_magnitude: string | null
      }[]
      expect(rows.length).toBe(13)
      for (const r of rows) {
        expect(r.date_raw).toBeGreaterThan(1e12)
        expect(r.date_utc_by_magnitude).toMatch(/^2022-0[12]-\d\d \d\d:\d\d:\d\d$/)
      }
      expect(rows[0].date_utc_by_magnitude).toBe('2022-02-09 15:06:05')
    },
  )
})
