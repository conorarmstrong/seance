import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ApiRequestError } from '../../api/http'
import { formatBytes, formatCount } from '../../lib/format'
import { getPhysicalLocation, type PhysicalExtent } from './api'
import { CopyButton } from './MetadataTabs'

/** `0x`-prefixed uppercase hex for a byte offset. */
function hex(n: number): string {
  return `0x${n.toString(16).toUpperCase()}`
}

/** True when this extent's bytes live somewhere other than the evidence image. */
function isAuxiliary(e: PhysicalExtent): boolean {
  return e.source !== 'device'
}

/** How an extent's offset reads in the table. */
function offsetLabel(e: PhysicalExtent): string {
  if (e.device_offset != null) return hex(e.device_offset)
  return e.sparse ? 'sparse (zeros)' : 'no device range'
}

/**
 * What the offset in this row is an offset *into*.
 *
 * Never blank for an auxiliary extent. A pagefile offset rendered the same way
 * as a device offset is the one display mistake this column exists to prevent:
 * the number is real, and it is a coordinate in a different file.
 */
function sourceLabel(e: PhysicalExtent): string {
  if (e.device_offset == null) return '—'
  return isAuxiliary(e) ? e.source : 'device image'
}

/**
 * Device-absolute physical location of an artifact's content, traced through
 * its whole container/filesystem chain to the backing device.
 *
 * Fragmentation-aware: a fragmented file shows one row per device extent. Honest
 * about non-linear boundaries: compressed / encrypted / reconstructed / in-memory
 * content shows an explanatory note instead of a fabricated offset. Renders
 * nothing for artifacts with no recorded content location (derived records), so
 * the enclosing inspector section collapses.
 */
export function PhysicalLocationSection({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const query = useQuery({
    queryKey: ['physical-location', caseId, artifactId],
    queryFn: () => getPhysicalLocation(caseId, artifactId),
    retry: false,
    staleTime: Infinity,
  })

  // A rejected request (400/404) is the endpoint saying this artifact has no
  // content location — a derived record, or one with no content path — so the
  // section collapses, which is the honest answer.
  //
  // Any OTHER failure is not that answer, and collapsing on it too said "this
  // exhibit has no place on the device" whenever the server or the connection
  // faltered. Where an exhibit's bytes physically live is the thing an examiner
  // is asked about in the witness box, so a failure to establish it is stated
  // rather than dressed up as an absence (the BUG-204 / B8-021 class).
  const rejected =
    query.error instanceof ApiRequestError &&
    (query.error.status === 404 || query.error.status === 400)
  if (rejected) return null
  if (query.isError) {
    return (
      <div className="av-phys">
        <h3>Physical location</h3>
        <p className="error-note" role="note" data-testid="av-phys-error">
          The physical location of this content could not be established:{' '}
          {(query.error as Error).message}. Nothing here says this artifact has
          no place on the device.
        </p>
      </div>
    )
  }
  if (query.isPending) {
    return (
      <div className="av-phys">
        <h3>Physical location</h3>
        <p className="av-phys-muted">Locating…</p>
      </div>
    )
  }

  const loc = query.data
  const backed = loc.extents.filter((e) => e.device_offset != null)
  // Extents whose bytes are in a pagefile or swap device rather than in the
  // evidence image. Counted separately because "N bytes located" would
  // otherwise imply all N are on the disk an examiner is holding.
  const auxiliary = backed.filter(isAuxiliary)
  const auxiliaryNames = Array.from(new Set(auxiliary.map((e) => e.source)))

  return (
    <div className="av-phys">
      <h3>Physical location</h3>

      <p className="av-phys-device">
        On{' '}
        <Link to={`/cases/${caseId}/artifacts/${loc.device.artifact_id}`}>
          <strong>{loc.device.name ?? 'the backing device'}</strong>
        </Link>
        {loc.device.decoded_container && (
          <span className="av-phys-badge" title="Offsets are into the decoded disk image">
            decoded image
          </span>
        )}
      </p>

      {loc.note && (
        <p className={`av-phys-note av-phys-${loc.precision}`}>{loc.note}</p>
      )}

      {backed.length > 0 && (
        <table className="av-phys-extents mono">
          <thead>
            <tr>
              <th>Offset</th>
              <th>In</th>
              <th>Sector</th>
              <th>Length</th>
              <th aria-label="Copy offset" />
            </tr>
          </thead>
          <tbody>
            {loc.extents.map((e, i) => (
              <tr
                key={i}
                className={
                  e.device_offset == null
                    ? 'av-phys-gap'
                    : isAuxiliary(e)
                      ? 'av-phys-auxiliary'
                      : undefined
                }
              >
                <td title={e.device_offset != null ? `${e.device_offset} (decimal)` : undefined}>
                  {offsetLabel(e)}
                </td>
                <td
                  title={
                    isAuxiliary(e)
                      ? `These bytes are in ${e.source}, not in the evidence image. A page ` +
                        'recovered from a pagefile was written there before acquisition and ' +
                        'may predate it.'
                      : undefined
                  }
                >
                  {sourceLabel(e)}
                </td>
                <td>{e.sector != null ? formatCount(e.sector) : '—'}</td>
                <td>{formatBytes(e.length)}</td>
                <td>
                  {e.device_offset != null && (
                    <CopyButton
                      value={String(e.device_offset)}
                      label={isAuxiliary(e) ? `offset in ${e.source}` : 'device offset'}
                    />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p className="av-phys-summary">
        {backed.length > 0 ? (
          <>
            {backed.length} extent{backed.length === 1 ? '' : 's'} ·{' '}
            {formatBytes(loc.located_bytes)} of {formatBytes(loc.logical_size)} located
            {auxiliary.length > 0 && (
              <>
                {' '}
                · {auxiliary.length} of them in {auxiliaryNames.join(', ')} rather than
                the evidence image
              </>
            )}
          </>
        ) : (
          <>No contiguous device range for {formatBytes(loc.logical_size)}.</>
        )}
        {loc.truncated && ' · list truncated (highly fragmented)'}
      </p>

      <details className="av-phys-chain">
        <summary>Evidence chain ({loc.chain.length})</summary>
        <ol>
          {loc.chain.map((lvl) => (
            <li key={lvl.artifact_id}>
              <span className="av-phys-chain-name" title={lvl.name ?? undefined}>
                {lvl.name ?? lvl.artifact_type}
              </span>
              <span className="av-phys-chain-type">{lvl.artifact_type}</span>
              {lvl.offset_in_parent != null && (
                <span className="av-phys-chain-off">@ {hex(lvl.offset_in_parent)}</span>
              )}
              {lvl.transform && <span className="av-phys-badge">{lvl.transform}</span>}
              {lvl.fragment_count != null && lvl.fragment_count > 1 && (
                <span className="av-phys-frag">{lvl.fragment_count} fragments</span>
              )}
            </li>
          ))}
        </ol>
      </details>
    </div>
  )
}
