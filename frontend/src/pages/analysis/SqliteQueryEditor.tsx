import { useEffect, useMemo, useState } from 'react'
import type { KeyboardEvent, ReactNode } from 'react'
import { useMutation } from '@tanstack/react-query'
import { ApiRequestError } from '../../api/http'
import { formatCount, formatUtc } from '../../lib/format'
import { decodeTimestamp, TIME_FORMATS, type TimeFormat } from './sqliteTime'
import {
  runSqliteQuery,
  SQLITE_QUERY_ROW_CAP,
  type SqliteCell,
  type SqliteQueryResponse,
} from './SqliteQueryApi'
import {
  clearHistory,
  loadHistory,
  recordHistory,
  SQLITE_HISTORY_MAX,
  type SqliteHistoryEntry,
} from './SqliteQueryHistory'
import { SQLITE_QUERY_TEMPLATES, templateApplicability } from './SqliteTemplates'
import './SqliteQueryEditor.css'

/** The database the editor runs against, as the viewer's rail knows it. */
export interface SqliteQueryTarget {
  name: string
  /** The database file's artifact id; null when the summary carried none. */
  artifactId: string | null
  /** Table names off the summary's schema list; empty when it carried none. */
  tableNames: string[]
}

export interface SqliteQueryEditorProps {
  caseId: string
  database: SqliteQueryTarget | null
}

/** A cell as text: NULL and blobs are named, never rendered as an empty string. */
function cellText(v: SqliteCell): string {
  if (v == null) return 'NULL'
  if (typeof v === 'object') return `[blob ${formatCount(v.size)} bytes]`
  return String(v)
}

/** The value a cell shows under the column's interpret-as setting. */
function cellDisplay(
  v: SqliteCell,
  fmt: TimeFormat | undefined,
): { text: string; decoded: boolean } {
  const raw = cellText(v)
  if (fmt && fmt !== 'raw' && v != null && typeof v !== 'object') {
    const d = decodeTimestamp(raw, fmt)
    if (d != null) return { text: d, decoded: true }
  }
  return { text: raw, decoded: false }
}

function errorText(e: unknown): { code: string | null; message: string } {
  if (e instanceof ApiRequestError) return { code: e.code, message: e.message }
  if (e instanceof Error) return { code: null, message: e.message }
  return { code: null, message: String(e) }
}

export function SqliteQueryEditor({
  caseId,
  database,
}: SqliteQueryEditorProps): ReactNode {
  const [sql, setSql] = useState('')
  const [templateId, setTemplateId] = useState('')
  const [colFmt, setColFmt] = useState<Record<string, TimeFormat>>({})
  const [history, setHistory] = useState<SqliteHistoryEntry[]>(() =>
    loadHistory(caseId),
  )

  useEffect(() => {
    setHistory(loadHistory(caseId))
  }, [caseId])

  const artifactId = database?.artifactId ?? null
  const tableNames = useMemo(() => database?.tableNames ?? [], [database])

  const templates = useMemo(
    () =>
      SQLITE_QUERY_TEMPLATES.map((t) => ({
        t,
        fit: templateApplicability(t, tableNames),
      })),
    [tableNames],
  )
  const schemaKnown = tableNames.length > 0
  const applicable = templates.filter((x) => x.fit.applicable)
  const inapplicable = templates.filter((x) => !x.fit.applicable)
  const activeTemplate = SQLITE_QUERY_TEMPLATES.find((t) => t.id === templateId) ?? null

  const run = useMutation({
    mutationFn: (statement: string) => {
      if (artifactId == null) {
        return Promise.reject(new Error('No artifact id to send the query for.'))
      }
      return runSqliteQuery(caseId, { artifact_id: artifactId, sql: statement })
    },
    onSuccess: (res, statement) => {
      setColFmt({})
      setHistory(
        recordHistory(caseId, {
          sql: statement,
          database: database?.name ?? null,
          artifactId,
          at: new Date().toISOString(),
          outcome: 'ok',
          rowCount: res.row_count,
          capped: res.capped,
        }),
      )
    },
    onError: (e, statement) => {
      const { code, message } = errorText(e)
      setHistory(
        recordHistory(caseId, {
          sql: statement,
          database: database?.name ?? null,
          artifactId,
          at: new Date().toISOString(),
          outcome: 'error',
          error: code ? `${code}: ${message}` : message,
        }),
      )
    },
  })

  const canRun = artifactId != null && sql.trim() !== '' && !run.isPending
  const submit = () => {
    if (canRun) run.mutate(sql)
  }
  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      submit()
    }
  }

  const result: SqliteQueryResponse | null = run.data ?? null
  // Only the server's own attestation earns the words "read-only over the
  // staged copy"; a result without it is shown, but not described as one.
  const attested =
    result != null && result.read_only === true && result.source === 'staged_copy'
  const failure = run.isError ? errorText(run.error) : null

  return (
    <section className="sq-editor" aria-label="SQL query">
      {/*
        Before a run, this header may state only what the client will ASK
        for. Whether the run was read-only, and what it ran over, are the
        server's to attest on a result; they are printed from that result
        below, never assumed here.
      */}
      <div className="sq-head" data-testid="sqlite-query-head">
        <span>
          <strong>SQL query</strong>
          {database ? (
            <>
              {' '}
              on <span className="mono">{database.name}</span>
            </>
          ) : null}
        </span>
        <span className="sq-scope">
          Sends one statement and asks for at most{' '}
          {formatCount(SQLITE_QUERY_ROW_CAP)} rows. Each result reports the cap
          that applied, whether it was hit, and what the server attests the
          statement ran over.
        </span>
      </div>

      {artifactId == null && (
        <div className="warn-note" role="note" data-testid="sqlite-query-no-artifact">
          This database's summary carries no artifact id, so there is nothing
          to send a query for. Rows can still be read in the grid.
        </div>
      )}

      <div className="sq-controls">
        <label>
          Template{' '}
          <select
            aria-label="Query template"
            value={templateId}
            onChange={(e) => {
              const id = e.target.value
              setTemplateId(id)
              const t = SQLITE_QUERY_TEMPLATES.find((x) => x.id === id)
              if (t) setSql(t.sql)
            }}
          >
            <option value="">(choose a template)</option>
            <optgroup label={schemaKnown ? 'Applicable to this database' : 'All templates'}>
              {applicable.map(({ t }) => (
                <option key={t.id} value={t.id}>
                  {t.title}
                </option>
              ))}
            </optgroup>
            {inapplicable.length > 0 && (
              <optgroup label="Not applicable: tables this database lacks">
                {inapplicable.map(({ t, fit }) => (
                  <option key={t.id} value={t.id} disabled>
                    {t.title} (missing {fit.missing.join(', ')})
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </label>
        {!schemaKnown && (
          <span className="sq-scope" data-testid="sqlite-template-unchecked">
            This database's summary carried no table list, so template
            applicability was not checked; one that names a table this file
            lacks will fail when run.
          </span>
        )}
      </div>

      {activeTemplate && (
        <div className="sq-notes" data-testid="sqlite-template-notes">
          {activeTemplate.artifact}. {activeTemplate.notes} Proven against{' '}
          <span className="mono">{activeTemplate.fixture}</span>.
        </div>
      )}

      <textarea
        className="sq-sql"
        aria-label="SQL statement"
        placeholder="SELECT … (one statement; Ctrl+Enter runs it)"
        spellCheck={false}
        value={sql}
        onChange={(e) => setSql(e.target.value)}
        onKeyDown={onKeyDown}
      />

      <div className="sq-controls">
        <button
          type="button"
          className="btn btn-primary"
          disabled={!canRun}
          onClick={submit}
        >
          Run
        </button>
        {run.isPending && <span className="sq-scope">Running…</span>}
      </div>

      {failure && (
        <div className="error-note" role="alert">
          {failure.code ? (
            <>
              <span className="mono">{failure.code}</span>: {failure.message}
            </>
          ) : (
            failure.message
          )}
        </div>
      )}

      {result && !run.isError && (
        <>
          <div className="sq-status" data-testid="sqlite-query-status">
            <span>
              {formatCount(result.row_count)} row
              {result.row_count === 1 ? '' : 's'} in{' '}
              {formatCount(result.elapsed_ms)} ms
              {result.columns.length > 0
                ? `, ${formatCount(result.columns.length)} column${
                    result.columns.length === 1 ? '' : 's'
                  }`
                : ''}
              .
            </span>
            {result.capped ? (
              <span className="badge badge-warn">
                The cap of {formatCount(result.row_cap)} rows was hit; more rows
                exist than are shown.
              </span>
            ) : (
              <span>
                The cap of {formatCount(result.row_cap)} rows was not reached.
              </span>
            )}
            {attested ? (
              <span>
                This ran read-only over the staged copy of{' '}
                <span className="mono">{result.database ?? database?.name ?? '?'}</span>
                , not the evidence file, with a {formatCount(result.timeout_ms)}{' '}
                ms timeout.
              </span>
            ) : (
              <span className="badge badge-warn">
                The server did not attest that this ran read-only over a staged
                copy (read_only={String(result.read_only)}, source=
                {String(result.source)}).
              </span>
            )}
          </div>
          {(result.content_incomplete != null || result.wal_incomplete != null) && (
            <div className="warn-note" role="note" data-testid="sqlite-query-incomplete">
              The server reports that what it ran over is not the whole
              database
              {result.content_incomplete != null && (
                <>
                  : the main file was not staged in full (
                  <span className="mono">{result.content_incomplete}</span>)
                </>
              )}
              {result.wal_incomplete != null && (
                <>
                  {result.content_incomplete != null ? '; ' : ': '}its write-ahead
                  log was not staged in full (
                  <span className="mono">{result.wal_incomplete}</span>)
                </>
              )}
              . Rows past the bytes it staged are not in this result, and their
              absence is not a finding.
            </div>
          )}
          <div className="sq-result-scroll">
            <table className="data-table an-table an-db-grid">
              <thead>
                <tr>
                  {result.columns.map((c, i) => (
                    <th key={`${c}-${i}`} className="mono an-db-col">
                      <div className="an-db-col-head">
                        <span className="an-db-col-name" title={c}>
                          {c}
                        </span>
                      </div>
                      <select
                        className="an-db-col-fmt"
                        aria-label={`Interpret ${c} as`}
                        value={colFmt[c] ?? 'raw'}
                        onChange={(e) =>
                          setColFmt((f) => ({
                            ...f,
                            [c]: e.target.value as TimeFormat,
                          }))
                        }
                      >
                        {TIME_FORMATS.map((tf) => (
                          <option key={tf.id} value={tf.id}>
                            {tf.label}
                          </option>
                        ))}
                      </select>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.rows.map((row, ri) => (
                  <tr key={ri}>
                    {result.columns.map((c, ci) => {
                      const disp = cellDisplay(row[ci] ?? null, colFmt[c])
                      return (
                        <td
                          key={`${c}-${ci}`}
                          className={disp.decoded ? 'mono an-db-ts' : 'mono'}
                          title={disp.decoded ? cellText(row[ci] ?? null) : undefined}
                        >
                          {disp.text}
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <div className="sq-history-head">
        <span data-testid="sqlite-history-scope">
          History: this browser only, for this case, newest first, at most{' '}
          {SQLITE_HISTORY_MAX} entries. It is not part of the case record.
        </span>
        {history.length > 0 && (
          <button
            type="button"
            className="link-button"
            onClick={() => {
              clearHistory(caseId)
              setHistory([])
            }}
          >
            Clear history
          </button>
        )}
      </div>
      {history.length > 0 && (
        <ul className="sq-history" aria-label="Query history">
          {history.map((h) => (
            <li key={`${h.at}-${h.artifactId ?? ''}-${h.sql}`}>
              <button
                type="button"
                className="sq-history-item"
                title={`${h.sql}\n${formatUtc(h.at)}${h.database ? ` on ${h.database}` : ''}`}
                onClick={() => {
                  setSql(h.sql)
                  setTemplateId('')
                }}
              >
                <span className="sq-history-sql mono">{h.sql}</span>
                <span className="sq-history-meta">
                  {h.database ?? ''}
                  {h.database ? ' · ' : ''}
                  {h.outcome === 'ok'
                    ? `${formatCount(h.rowCount ?? 0)} rows${h.capped ? ' (capped)' : ''}`
                    : 'error'}
                  {' · '}
                  {formatUtc(h.at)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
