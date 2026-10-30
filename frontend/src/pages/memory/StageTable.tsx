import type { ReactNode } from 'react'
import { ConfidenceChip, ConfidenceHeader } from './confidence'
import { fieldText, fieldTitle } from './normalize'
import type { Field, StageRow } from './normalize'
import { formatCount } from '../../lib/format'
import { QuickFilterBar, useQuickFilter } from '../../components/QuickFilter'

/**
 * The one table every list-shaped memory lens renders.
 *
 * It exists so that three rules cannot be implemented differently on different
 * screens. The confidence chip is always the first column, before the data. A
 * key the analysis did not record renders as the words "not recorded", never as
 * an empty cell — a blank reads as "there is nothing there", which is a claim
 * nobody made. And a value the analysis did record is shown verbatim rather
 * than reformatted into something prettier that no longer matches the evidence.
 */

/** One column, reading a key out of the row's analysis blob. */
export interface BlobColumn {
  /** Stable identifier, used as the React key. */
  id: string
  header: string
  /** Blob key to read when `render` is not given. */
  field?: string
  /**
   * Custom cell. Return `null` to fall through to the "not recorded" wording,
   * so a renderer can decline without inventing a blank.
   */
  render?: (data: Record<string, unknown>) => ReactNode
  mono?: boolean
}

/**
 * A decoded field in a table cell.
 *
 * The value when it was read; otherwise the word for the *particular* absence
 * the analysis stated, with the sentence explaining it on hover. Never the
 * table's generic "not recorded" fallback, which says the analysis wrote
 * nothing down — a different claim from "this object has no name" and from
 * "the bytes holding the name could not be read".
 */
export function FieldCell({ field }: { field: Field<string | number> }) {
  if (field.known) return <>{String(field.value)}</>
  return (
    <span className="mem-note" title={fieldTitle(field)}>
      {fieldText(field)}
    </span>
  )
}

/** Turn a JSON value into something displayable, or null when it is absent. */
function displayValue(value: unknown): ReactNode | null {
  if (value == null) return null
  if (typeof value === 'string') return value === '' ? null : value
  if (typeof value === 'number') return formatCount(value)
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (Array.isArray(value)) {
    return value.length === 0 ? null : value.map((v) => String(v)).join(', ')
  }
  // A nested object: show its JSON rather than "[object Object]". An examiner
  // reading a structure the UI does not model yet is better served by the
  // literal bytes of it than by a placeholder.
  return JSON.stringify(value)
}

export function StageTable({
  rows,
  columns,
  rowClassName,
  filter,
}: {
  rows: StageRow[]
  columns: BlobColumn[]
  rowClassName?: (data: Record<string, unknown>) => string | undefined
  /**
   * A quick type-ahead over the rendered cells (§1.1).
   *
   * Given here rather than on each lens so every list-shaped memory lens gets
   * the same box with the same wording — the same reason the confidence chip
   * and the "not recorded" fallback live here. `scopeId` is what the needle is
   * held against (a pid, a capture); `noun` names the rows.
   *
   * It searches the rows the lens has, which for a per-process lens is that
   * process's whole table and for a capped one is a subset — `loadedIsSubset`
   * is the lens's answer to that, and it must be truthful: the filter's count
   * is otherwise read as a count in the capture.
   */
  filter?: {
    scopeId: string
    noun: string
    plural?: string
    loadedIsSubset?: boolean
    total?: number
  }
}) {
  // The needle searches what the table SHOWS, cell by cell, which is the only
  // set a reader can check the count against. Searching the blob instead would
  // match on keys no column renders.
  const cellText = (row: StageRow) =>
    columns.map((column) => {
      const content = column.render
        ? column.render(row.data)
        : displayValue(column.field ? row.data[column.field] : null)
      return typeof content === 'string' ? content : null
    })
  const search = useQuickFilter(filter?.scopeId ?? '', rows, cellText)
  const shown = filter ? search.rows : rows

  return (
    <>
    {filter && (
      <QuickFilterBar
        filter={search}
        noun={filter.noun}
        plural={filter.plural}
        loadedIsSubset={filter.loadedIsSubset}
        total={filter.total}
        placeholder={`Filter ${filter.plural ?? `${filter.noun}s`}…`}
      />
    )}
    <table className="data-table">
      <thead>
        <tr>
          <ConfidenceHeader />
          {columns.map((column) => (
            <th scope="col" key={column.id}>
              {column.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {shown.map((row) => (
          <tr key={row.key} className={rowClassName?.(row.data)}>
            <td>
              <ConfidenceChip
                confidence={row.confidence}
                provenance={[{ label: 'record', value: row.recordId }]}
              />
            </td>
            {columns.map((column) => {
              const content = column.render
                ? column.render(row.data)
                : displayValue(column.field ? row.data[column.field] : null)
              return (
                <td key={column.id} className={column.mono ? 'mono' : undefined}>
                  {content ?? (
                    <span
                      className="mem-note"
                      title="The analysis recorded no value for this field. That is not the same as an empty value."
                    >
                      not recorded
                    </span>
                  )}
                </td>
              )
            })}
          </tr>
        ))}
      </tbody>
    </table>
    </>
  )
}
