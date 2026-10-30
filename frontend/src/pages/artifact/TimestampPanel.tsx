import { formatUtc } from '../../lib/format'
import { metadataBool, metadataString, metadataStringArray } from './lib'

/**
 * One thing the $SI/$FN comparison noticed, as the MFT parser writes it.
 *
 * `strength` is the whole point (HUNT-051). A weak indicator is one an ordinary
 * copy, move or rename produces — `also_produced_by` names which — and it is
 * shown as an observation. Only a strong indicator, which no ordinary operation
 * produces, carries the tampering verdict.
 */
interface TimestampIndicator {
  reason: string
  strength: 'strong' | 'weak'
  also_produced_by?: string | null
}

function indicatorsOf(metadata: Record<string, unknown>): TimestampIndicator[] {
  const raw = metadata.timestamp_indicators
  if (!Array.isArray(raw)) return []
  return raw.flatMap((entry) => {
    if (typeof entry !== 'object' || entry === null) return []
    const e = entry as Record<string, unknown>
    const reason = typeof e.reason === 'string' ? e.reason : null
    if (!reason) return []
    return [
      {
        reason,
        strength: e.strength === 'strong' ? 'strong' : 'weak',
        also_produced_by:
          typeof e.also_produced_by === 'string' ? e.also_produced_by : null,
      } as TimestampIndicator,
    ]
  })
}

// MACB analysis: each column pairs the Standard Information ($SI) key with the
// FileName ($FN) key that carries the same attribute. $FN timestamps are
// updated far less often by user-space tooling, so a disagreement between the
// two is the classic timestomping signal.
const MACB_COLUMNS: [string, string, string][] = [
  ['created', 'fn_created', 'Created'],
  ['modified', 'fn_modified', 'Modified'],
  ['mft_modified', 'fn_mft_modified', 'MFT Changed'],
  ['accessed', 'fn_accessed', 'Accessed'],
]

/**
 * Forensic timestamp analysis for MFT-parsed FileEntry artifacts: a two-row
 * MACB table ($SI vs $FN) and a timestomping verdict. Renders nothing unless
 * $FN timestamps are present (i.e. this artifact came from the MFT parser).
 */
export function TimestampPanel({
  metadata,
}: {
  metadata: Record<string, unknown>
}) {
  const hasFn = MACB_COLUMNS.some(([, fnKey]) => metadataString(metadata, fnKey))
  if (!hasFn) return null

  const suspected = metadataBool(metadata, 'timestomp_suspected')
  const reasons = metadataStringArray(metadata, 'timestomp_reasons')
  const indicators = indicatorsOf(metadata)
  const weak = indicators.filter((i) => i.strength === 'weak')
  const cell = (key: string) => {
    const value = metadataString(metadata, key)
    return value ? formatUtc(value) : '—'
  }

  return (
    <section className="av-ts">
      <h3 className="av-ts-title">Timestamp analysis</h3>
      {suspected === true && (
        <div className="av-ts-warning" role="alert">
          <span className="av-ts-warning-head">
            Possible timestomping detected
          </span>
          <span className="av-ts-warning-sub">
            No ordinary copy, move or rename produces this.
          </span>
          {reasons.length > 0 && (
            <ul className="av-ts-reasons">
              {reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      {/* Weak indicators are observations, not a verdict, and they are shown
          as such: an ordinary copy or move produces each one, and this panel
          used to render them in the same red box as tampering — on a sixth of
          a stock Windows install (HUNT-051). Each carries the ordinary
          operation that also produces it, so the reader can weigh it. */}
      {suspected !== true && weak.length > 0 && (
        <div className="av-ts-note" role="note" data-testid="av-ts-indicators">
          <span className="av-ts-note-head">
            {weak.length === 1
              ? '1 timestamp indicator, which ordinary file activity also produces'
              : `${weak.length} timestamp indicators, which ordinary file activity also produces`}
          </span>
          <ul className="av-ts-reasons">
            {weak.map((i) => (
              <li key={i.reason}>
                {i.reason}
                {i.also_produced_by ? ` — also produced by ${i.also_produced_by}` : ''}
              </li>
            ))}
          </ul>
          <span className="av-ts-note-foot">
            Nothing here says this file was tampered with. The $SI and $FN
            values are in the table below; read them against what the file is.
          </span>
        </div>
      )}
      {suspected === false && weak.length === 0 && (
        <p className="av-ts-ok">$SI and $FN timestamps are consistent.</p>
      )}
      <table className="data-table av-ts-table">
        <thead>
          <tr>
            <th>Source</th>
            {MACB_COLUMNS.map(([, , label]) => (
              <th key={label}>{label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Standard ($SI)</td>
            {MACB_COLUMNS.map(([siKey]) => (
              <td key={siKey} className="mono">
                {cell(siKey)}
              </td>
            ))}
          </tr>
          <tr>
            <td>FileName ($FN)</td>
            {MACB_COLUMNS.map(([, fnKey]) => (
              <td key={fnKey} className="mono">
                {cell(fnKey)}
              </td>
            ))}
          </tr>
        </tbody>
      </table>
    </section>
  )
}
