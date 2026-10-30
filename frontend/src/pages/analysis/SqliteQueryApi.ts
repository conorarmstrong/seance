import { apiFetch } from '../../api/http'

/**
 * Client for `POST /api/v1/cases/{id}/sqlite/query`: one SQL statement
 * against a database artifact of the case.
 *
 * This file is the CONTRACT the client is written against, not a description
 * of what the server has been observed to do. The client asks for one
 * statement and a row ceiling; everything about how the statement was run —
 * whether the connection was read-only, whether it ran over a staged copy
 * rather than the evidence file, which row cap and timeout applied — arrives
 * as fields on the response (`read_only`, `source`, `row_cap`, `capped`,
 * `timeout_ms`). A screen may say "read-only over the staged copy" only when
 * a result's `read_only` and `source` say so, and must print `row_cap` and
 * `capped` beside every result. A server that does not answer to this shape
 * is shown as not having attested, never assumed to comply.
 */

/** Rows the client asks for. The server's `row_cap` in the answer is the one that applied. */
export const SQLITE_QUERY_ROW_CAP = 1000

/** One result cell. A blob is never inlined; its size is reported instead. */
export type SqliteCell =
  | null
  | number
  | string
  | boolean
  | { blob: true; size: number }

export interface SqliteQueryRequest {
  /** The database file's artifact id (`database_artifact` on its rows and summary). */
  artifact_id: string
  /** Exactly one statement. */
  sql: string
  /** Row ceiling to ask for; the server may lower it and says which applied. */
  max_rows?: number
}

export interface SqliteQueryResponse {
  columns: string[]
  rows: SqliteCell[][]
  /** Rows in `rows`. */
  row_count: number
  /** The ceiling that applied to this run. */
  row_cap: number
  /** True when at least one more row existed past `row_cap`. */
  capped: boolean
  elapsed_ms: number
  /** The statement timeout that applied. */
  timeout_ms: number
  /** Attestation that the connection was opened read-only. */
  read_only: boolean
  /** Attestation of what was queried. Anything but `staged_copy` is not the contract. */
  source: 'staged_copy' | string
  artifact_id: string
  /** Database file name, as its summary names it. */
  database: string | null
  /**
   * Why the staged main file is not the whole database, if it is not
   * (`cap_reached`, `short_read`). `null` when it was staged whole.
   */
  content_incomplete: string | null
  /** Why the `-wal` sibling was not staged in full, if it was not. `null` when whole or absent. */
  wal_incomplete: string | null
}

/**
 * Error codes the contract names (HTTP 400 unless noted). A server that
 * answers to this contract uses them; the client shows whatever code it is
 * actually given, verbatim, and never maps an unknown one onto these.
 */
export const SQLITE_QUERY_ERROR_CODES = {
  /** More than one statement, or trailing text after the first. */
  notSingleStatement: 'sql_not_single_statement',
  /**
   * Refused by one of three gates, in this order: the first keyword after any
   * leading comments is not SELECT or WITH (checked before SQLite sees the
   * text, so every PRAGMA, EXPLAIN, ATTACH, transaction control and write is
   * refused here whether or not the table it names exists); the read-only
   * authorizer denied an action at prepare (it allows only read, select,
   * function and recursive, and denies every PRAGMA, read-only or not); or
   * SQLite reports the prepared statement as not read-only.
   */
  notReadOnly: 'sql_not_readonly',
  /** SQLite rejected the statement (syntax, unknown table, ...). */
  sqlError: 'sql_error',
  /** The statement ran past `timeout_ms` and was interrupted. */
  timeout: 'sql_timeout',
  /** The artifact is not a SQLite database this case holds (404). */
  notADatabase: 'not_a_sqlite_database',
} as const

export function runSqliteQuery(
  caseId: string,
  req: SqliteQueryRequest,
  signal?: AbortSignal,
): Promise<SqliteQueryResponse> {
  if (req.sql.trim() === '') {
    return Promise.reject(new Error('No statement to run.'))
  }
  return apiFetch<SqliteQueryResponse>(`/cases/${caseId}/sqlite/query`, {
    method: 'POST',
    body: { max_rows: SQLITE_QUERY_ROW_CAP, ...req },
    signal,
  })
}
