import { Fragment } from 'react'
import { getRegistryData } from '../../api/resources'
import type {
  RegistryExplorerResponse,
  RegistryProvenance,
  RegistryValue,
} from '../../api/types'
import { Modal } from '../../components/Modal'
import { formatBytes } from '../../lib/format'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { useEntityScopedState } from '../../lib/useEntityScopedState'

function humanReason(reason: string): string {
  switch (reason) {
    case 'clean':
      return 'hive was clean'
    case 'no_logs_found':
      return 'no transaction logs found'
    case 'recovered':
      return 'recovered'
    case 'sequence_gap':
      return 'sequence gap in logs'
    case 'hash_mismatch':
      return 'log entry hash mismatch'
    case 'logs_invalid':
      return 'transaction logs invalid'
    default:
      return reason
  }
}

function logFormatLabel(format: string): string {
  if (format === 'new_hvle') return 'HvLE'
  if (format === 'legacy_dirt') return 'DIRT'
  return format
}

// Forensic provenance stamp: tells the examiner whether the registry state
// shown below is the recovered (post-replay) hive, the on-disk (pre-replay)
// hive, or a clean hive that needed no replay. See ROADMAP 1.12.
function RegistryProvenanceBanner({
  p,
  onJump,
}: {
  p: RegistryProvenance | null | undefined
  onJump: (path: string) => void
}) {
  if (p == null) return null

  const seqRange =
    p.replay_sequence_start != null && p.replay_sequence_end != null
      ? `${p.replay_sequence_start} -> ${p.replay_sequence_end}`
      : null

  if (p.logs_replayed) {
    return (
      <div className="av-reg-prov av-reg-prov-ok" role="status">
        <div className="av-reg-prov-head">
          <span className="badge badge-ok">Recovered from logs</span>
          <span>
            Hive was <strong>dirty</strong> at acquisition; replayed{' '}
            <strong>{p.log_entries_applied}</strong> log{' '}
            {p.log_entries_applied === 1 ? 'entry' : 'entries'} /{' '}
            <strong>{p.dirty_pages_applied}</strong> dirty pages from{' '}
            <span className="mono">{p.log_files.join(', ')}</span> (
            {logFormatLabel(p.log_format)} format
            {seqRange != null && (
              <>
                , seq <span className="mono">{seqRange}</span>
              </>
            )}
            ). Registry state below reflects the <strong>recovered</strong> hive.
          </span>
        </div>
        {p.changed_keys.length > 0 && (
          <details className="av-reg-changed">
            <summary>
              Show {p.changed_keys.length} changed key
              {p.changed_keys.length === 1 ? '' : 's'}
            </summary>
            <ul>
              {p.changed_keys.map((path) => (
                <li key={path}>
                  <button
                    className="link-button mono"
                    onClick={() => onJump(path)}
                  >
                    {path}
                  </button>
                </li>
              ))}
            </ul>
          </details>
        )}
      </div>
    )
  }

  if (p.hive_dirty) {
    return (
      <div className="av-reg-prov av-reg-prov-warn" role="status">
        <div className="av-reg-prov-head">
          <span className="badge badge-danger">Dirty — not recovered</span>
          <span>
            Hive was dirty (seq {p.primary_sequence}/{p.secondary_sequence}) but
            logs could not be applied ({humanReason(p.replay_reason)}). State
            below is the <strong>on-disk</strong> hive and may be stale.
          </span>
        </div>
      </div>
    )
  }

  return (
    <div className="av-reg-prov av-reg-prov-neutral" role="status">
      <div className="av-reg-prov-head">
        <span className="badge">Clean hive</span>
        <span>Sequence numbers matched; no transaction-log replay needed.</span>
      </div>
    </div>
  )
}

export function RegistryTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  // The hive on screen is identified by BOTH ids: artifact UUIDs are not
  // globally unique across cases, so gating on artifactId alone would let an
  // in-place case switch show case A's hive under case B (BUG-259).
  const scopeKey = `${caseId}/${artifactId}`
  // Switching hives must not carry the previous one's navigation over. Scoped
  // rather than cleared in a `useEffect`, because `keyPath` is part of the
  // query key below: on the render where the ids have already changed but the
  // effect has not run, react-query fetches the NEW hive at the OLD hive's key
  // path. The server answers for a path that may not exist there — an examiner
  // reading "key not found" would take it as a fact about the new hive
  // (B2-148 class).
  const [keyPath, setKeyPath] = useEntityScopedState<string | null>(
    scopeKey,
    null,
  )
  const [selected, setSelected] = useEntityScopedState<RegistryValue | null>(
    scopeKey,
    null,
  )
  // keepPreviousData holds the prior hive while the new one loads; the shared
  // gate tags each response with the scope it was fetched for, so a carried-over
  // placeholder reads as still-loading instead of rendering one hive's keys
  // under another artifact's (or another case's) chrome.
  const query = useEntityScopedQuery<RegistryExplorerResponse>(scopeKey, {
    queryKey: ['artifact-registry', caseId, artifactId, keyPath],
    queryFn: () =>
      getRegistryData(
        caseId,
        artifactId,
        keyPath != null ? { key_path: keyPath } : undefined,
      ),
  })

  if (query.isError) {
    return (
      <div className="error-note">
        Failed to load registry data: {query.error?.message}
      </div>
    )
  }
  const data = query.scoped
  if (data == null) {
    return <div className="loading">Loading registry hive...</div>
  }

  return (
    <div className="av-reg">
      <RegistryProvenanceBanner p={data.provenance} onJump={setKeyPath} />
      <div className="panel">
        <div className="av-reg-nav">
          <button
            className="btn"
            disabled={data.parent_key_path == null}
            onClick={() => setKeyPath(data.parent_key_path)}
          >
            Up
          </button>
          <span className="av-reg-crumbs mono">
            {data.breadcrumbs.map(([name, path], i) => (
              <Fragment key={path}>
                {i > 0 && <span className="av-breadcrumb-sep">\</span>}
                <button
                  className="link-button mono"
                  onClick={() => setKeyPath(path)}
                >
                  {name}
                </button>
              </Fragment>
            ))}
          </span>
        </div>
        {data.subkeys.length === 0 ? (
          <p className="av-note">No subkeys.</p>
        ) : (
          <ul className="av-reg-list">
            {data.subkeys.map((key) => (
              <li key={key.key_path}>
                <button
                  className="link-button mono"
                  onClick={() => setKeyPath(key.key_path)}
                >
                  {key.key_name}
                </button>
                <span className="av-reg-count">
                  {key.subkey_count} keys · {key.value_count} values
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="panel av-reg-values">
        <h3 className="panel-title">
          Values <span className="mono">{data.current_key_path}</span>
        </h3>
        {data.values.length === 0 ? (
          <p className="av-note">No values in this key.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Data</th>
                <th>Size</th>
              </tr>
            </thead>
            <tbody>
              {data.values.map((value) => (
                <tr
                  key={value.value_name}
                  onClick={() => setSelected(value)}
                >
                  <td className="mono">{value.value_name || '(default)'}</td>
                  <td>{value.value_type}</td>
                  <td>
                    <span className="mono av-reg-data">
                      {value.value_data}
                    </span>
                  </td>
                  <td>{formatBytes(value.raw_data_size)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {selected && (
        <Modal
          title={selected.value_name || '(default)'}
          onClose={() => setSelected(null)}
        >
          <p>
            <span className="badge">{selected.value_type}</span>{' '}
            {formatBytes(selected.raw_data_size)}
          </p>
          <pre className="av-json">{selected.value_data}</pre>
        </Modal>
      )}
    </div>
  )
}
