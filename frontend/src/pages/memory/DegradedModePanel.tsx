import { Link } from 'react-router-dom'

/**
 * The screen shown when structured analysis cannot run.
 *
 * This exists because "0 processes" would be a lie of omission. Without an
 * admitted symbol table the kernel structure layouts are unknown, so processes,
 * modules, handles and connections cannot be enumerated at all — and Séance
 * will not guess offsets, because a wrong layout does not fail, it produces a
 * complete and confident wrong answer.
 *
 * The panel therefore does three things an empty table cannot: it says why, it
 * names **the exact symbol identifier to fetch** so the examiner can turn a
 * failed analysis into a successful one, and it lists what still works without
 * symbols so the capture is not written off.
 */

/** The symbol identity pulled out of the analysis's own failure text. */
export interface WantedSymbols {
  pdb: string
  guid: string
  age: string
}

/**
 * Extract the symbol identity from a discovery failure.
 *
 * The analysis renders `SymbolsNotFound` as
 * `no symbol file matches the kernel: ntkrnlmp.pdb GUID <32 hex> age <n>. …`,
 * and that GUID plus age is the single actionable fact on this screen.
 *
 * Returns null when the text does not carry one. Nothing is guessed and no
 * "closest match" is offered: a near-match symbol table produces a complete,
 * confident, wrong analysis, so half an identifier is worse than none.
 */
export function extractWantedSymbols(
  failure: string | null | undefined,
): WantedSymbols | null {
  if (!failure) return null
  const match = failure.match(
    /no symbol file matches the kernel:\s*(\S+)\s+GUID\s+([0-9A-Fa-f]{8,32})\s+age\s+(\d+)/,
  )
  if (match == null) return null
  return { pdb: match[1], guid: match[2], age: match[3] }
}

/** Capabilities that need no symbols, as case-relative paths. */
const WITHOUT_SYMBOLS: { label: string; to: string; description: string }[] = [
  {
    label: 'Search',
    to: 'search',
    description:
      'Full-text search over strings extracted from the capture, indexed like any other evidence.',
  },
  {
    label: 'Timeline',
    to: 'timeline',
    description:
      'Anything already dated from this capture still appears on the case timeline.',
  },
  {
    label: 'Analysis records',
    to: 'analysis',
    description:
      'Records carved or signature-matched out of the capture, decoded from fixed layouts rather than from symbols.',
  },
]

export function DegradedModePanel({
  caseId,
  /** Which lens is degraded, or null when the whole capture is. */
  lens,
  /** The analysis's own account of why it could not proceed. */
  failure,
  /** Directories the symbol search covered. */
  symbolDirs,
  /** Facts established without symbols: format, architecture, size. */
  identified,
}: {
  caseId: string
  lens?: string | null
  failure: string | null
  symbolDirs: string[]
  identified: { label: string; value: string }[]
}) {
  const wanted = extractWantedSymbols(failure)

  return (
    <section className="mem-degraded" aria-labelledby="mem-degraded-title">
      <div className="error-note" role="note">
        <h2 className="mem-degraded-title" id="mem-degraded-title">
          {lens
            ? `${lens} is not available for this capture.`
            : 'Structured analysis is not available for this capture.'}
        </h2>
        <p>
          {failure ??
            'The analysis did not say why it could not proceed. That is missing information, not a clean result.'}
        </p>
        <p>
          Séance will not guess structure offsets. A wrong layout produces
          plausible, wrong answers rather than an error, so nothing is
          enumerated until a symbol table is admitted.
        </p>
      </div>

      {identified.length > 0 && (
        <div className="panel">
          <h3 className="panel-title">Identified so far</h3>
          <dl className="mem-kv">
            {identified.map((fact) => (
              <div className="mem-kv-row" key={fact.label}>
                <dt>{fact.label}</dt>
                <dd className="mono">{fact.value}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      <div className="panel">
        <h3 className="panel-title">The symbols to fetch</h3>
        {wanted == null ? (
          <p className="mem-note">
            The failure above does not name a symbol identity, so there is
            nothing to fetch from it. Read it for what is missing rather than
            assuming symbols are the cause — a capture can also fail before it
            ever gets as far as looking for them.
          </p>
        ) : (
          <>
            <p>
              Matching is on the exact build identity below, never on a similar
              name. A near-enough symbol table is refused for the same reason a
              wrong one is.
            </p>
            <dl className="mem-kv">
              <div className="mem-kv-row">
                <dt>PDB</dt>
                <dd className="mono">{wanted.pdb}</dd>
              </div>
              <div className="mem-kv-row">
                <dt>GUID</dt>
                <dd className="mono">{wanted.guid}</dd>
              </div>
              <div className="mem-kv-row">
                <dt>age</dt>
                <dd className="mono">{wanted.age}</dd>
              </div>
            </dl>
            <div className="mem-command">
              <code className="mono">{`${wanted.pdb}/${wanted.guid}${wanted.age}/${wanted.pdb}`}</code>
              <button
                type="button"
                className="btn"
                onClick={() => {
                  void navigator.clipboard
                    ?.writeText(
                      `${wanted.pdb}/${wanted.guid}${wanted.age}/${wanted.pdb}`,
                    )
                    .catch(() => {})
                }}
              >
                Copy symbol path
              </button>
            </div>
            <p className="mem-note">
              That is the path a Microsoft symbol server serves the PDB from.
              Convert it to an ISF and place it in one of the directories below,
              then re-run the analysis.
            </p>
          </>
        )}
        <h4 className="mem-subhead">Directories searched</h4>
        {symbolDirs.length === 0 ? (
          <p className="mem-note">
            The analysis did not report which directories it searched, so it
            cannot be said whether the symbol store was reachable at all.
          </p>
        ) : (
          <ul className="mem-steps">
            {symbolDirs.map((dir) => (
              <li className="mono" key={dir}>
                {dir}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="panel">
        <h3 className="panel-title">What you can still do</h3>
        <p className="mem-note">
          None of these needs kernel symbols. The capture is decoded and its
          bytes are readable, so it is not written off.
        </p>
        <ul className="mem-available">
          {WITHOUT_SYMBOLS.map((item) => (
            <li key={item.label}>
              <Link className="btn" to={`/cases/${caseId}/${item.to}`}>
                {item.label}
              </Link>
              <span className="mem-note">{item.description}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
