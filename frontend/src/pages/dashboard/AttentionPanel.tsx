import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { formatCount } from '../../lib/format'
import {
  getAttentionQueue,
  supplyCredential,
  type AttentionItem,
} from './api'

/**
 * The queue of recoverable problems (ROADMAP §2.11).
 *
 * A case could hold the sentence "this iOS backup is encrypted and no password
 * was provided: no files from it are in this case" and offer the examiner
 * nowhere to act on it. The statement was honest; the next step was invisible.
 * This is the next step.
 *
 * # What is deliberately not offered
 *
 * A dead affordance on a forensic tool is worse than none: an examiner who
 * types a password into a field that cannot reach the decryptor concludes the
 * password is wrong. So the field appears **only** where a per-artifact secret
 * really reaches the module — since HUNT-120 that includes BitLocker and LUKS
 * volumes, a header-encrypted 7z and the Signal for iOS store, whose secret
 * goes to the credential route rather than into the artifact's metadata. Where the credential is read once at start-up, the
 * row names the environment variable and says the evidence has to be ingested
 * again. Where this build cannot read the content at all, the row says that and
 * offers nothing.
 *
 * # And why an empty queue says something
 *
 * The queue is about what can still be *done*, not about what was read. An
 * empty one is the most natural thing in the world to read as a clean case, so
 * the panel carries the server's own sentence saying it is not the case's
 * completeness record.
 */
function SecretForm({
  caseId,
  item,
  onDone,
}: {
  caseId: string
  item: AttentionItem
  onDone: () => void
}) {
  const [secret, setSecret] = useState('')
  const action = item.action
  const [kind, setKind] = useState(
    action?.kind === 'supply_secret' ? action.secret_key : '',
  )
  // One run per artifact, not per statement about it: a volume that was
  // reported locked and then failed an unlock has two records and one target.
  const targets = Array.from(new Set(item.examples.map((e) => e.target_id)))
  const run = useMutation({
    mutationFn: async () => {
      if (action?.kind !== 'supply_secret') return
      // Every blocked artifact in the group, because an examiner supplying one
      // backup's password means "unlock this", not "unlock the first example".
      for (const target of targets) {
        await supplyCredential(caseId, target, kind, secret)
      }
    },
    // The field is cleared whatever happened: a secret must not sit in the
    // page after it has been sent.
    onSettled: () => setSecret(''),
    onSuccess: () => onDone(),
  })

  if (action?.kind !== 'supply_secret') return null
  const choices = [
    { secret_key: action.secret_key, label: action.label },
    ...action.alternatives,
  ]
  const label =
    choices.find((c) => c.secret_key === kind)?.label ?? action.label
  const fieldId = `at-secret-${item.record_type}-${item.scheme ?? ''}`

  return (
    <form
      className="at-form"
      onSubmit={(e) => {
        e.preventDefault()
        if (secret !== '') run.mutate()
      }}
    >
      {choices.length > 1 && (
        <>
          <label className="at-label" htmlFor={`${fieldId}-kind`}>
            Kind of secret
          </label>
          <select
            id={`${fieldId}-kind`}
            className="at-input"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            {choices.map((c) => (
              <option key={c.secret_key} value={c.secret_key}>
                {c.label}
              </option>
            ))}
          </select>
        </>
      )}
      <label className="at-label" htmlFor={fieldId}>
        {label}
      </label>
      <input
        id={fieldId}
        className="at-input"
        type="password"
        autoComplete="off"
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
      />
      <button
        type="submit"
        className="at-run"
        disabled={secret === '' || run.isPending}
      >
        {run.isPending
          ? `Re-running on ${formatCount(targets.length)}…`
          : `Unlock and re-run (${formatCount(targets.length)})`}
      </button>
      {item.examples_truncated && (
        <p className="at-note" role="note">
          This will re-run on the {formatCount(targets.length)} listed
          here, not on all {formatCount(item.count)}. The rest keep their
          current state; re-open this queue after the run to reach them.
        </p>
      )}
      {run.isError && (
        <p className="error-note" role="alert">
          That did not run: {(run.error as Error).message}. Nothing was
          decrypted and nothing in the case has changed.
        </p>
      )}
      {run.isSuccess && (
        <p className="at-note" role="status">
          Queued. A re-run is a job like any other — watch it on this page. If
          the secret opens it, what it held appears beneath it and the record
          saying it was locked is superseded. A wrong password fails the job
          rather than changing the case.
        </p>
      )}
    </form>
  )
}

function Row({ caseId, item }: { caseId: string; item: AttentionItem }) {
  const queryClient = useQueryClient()
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['attention', caseId] })
    queryClient.invalidateQueries({ queryKey: ['jobs', caseId] })
  }
  const action = item.action

  return (
    <li className="at-item" data-testid="at-item">
      <div className="at-item-head">
        <span className="at-problem">
          {item.problem ?? `${item.record_type} — not read`}
        </span>
        <span className="at-count mono">
          {formatCount(item.count)} artifact
          {item.count === 1 ? '' : 's'}
        </span>
      </div>

      {item.guidance && <p className="at-guidance">{item.guidance}</p>}
      {item.unrecognised_note && (
        <p className="at-guidance" data-testid="at-unrecognised">
          {item.unrecognised_note}
        </p>
      )}

      {action?.kind === 'supply_secret' && (
        <SecretForm caseId={caseId} item={item} onDone={refresh} />
      )}
      {action?.kind === 'supply_at_startup' && (
        <p className="at-startup" data-testid="at-startup">
          No field is offered here because one would not reach the decryptor:
          set <code className="mono">{action.env}</code> (or pass{' '}
          <code className="mono">{action.flag}</code>) and ingest the evidence
          again.
        </p>
      )}
      {action?.kind === 'unsupported' && (
        <p className="at-startup" data-testid="at-unsupported">
          Nothing can be supplied here: this build cannot read it.
        </p>
      )}

      <ul className="at-examples">
        {item.examples.map((e) => (
          <li key={e.artifact_id}>
            <Link to={`/cases/${caseId}/artifacts/${e.artifact_id}`}>
              {e.name ?? e.artifact_id}
            </Link>
          </li>
        ))}
        {item.examples_truncated && (
          <li className="at-more">
            + {formatCount(item.count - item.examples.length)} more of the same
          </li>
        )}
      </ul>
    </li>
  )
}

export function AttentionPanel({ caseId }: { caseId: string }) {
  const query = useQuery({
    queryKey: ['attention', caseId],
    queryFn: () => getAttentionQueue(caseId),
    enabled: caseId !== '',
  })

  if (query.isPending) return null
  // A failed load must not render as an empty queue: an examiner would
  // conclude there is nothing outstanding.
  if (query.isError) {
    return (
      <div className="panel">
        <h2 className="panel-title">Needs attention</h2>
        <div className="error-note" role="note" data-testid="at-error">
          Unavailable: {(query.error as Error).message}. Nothing here says this
          case has no outstanding problems.
        </div>
      </div>
    )
  }
  const data = query.data
  if (!data) return null

  return (
    <div className="panel at" data-testid="attention-panel">
      <div className="panel-head">
        <h2 className="panel-title">Needs attention</h2>
        {data.artifacts > 0 && (
          <span className="at-total mono">
            {formatCount(data.actionable_artifacts)} of{' '}
            {formatCount(data.artifacts)} can be acted on
          </span>
        )}
      </div>

      {data.items.length === 0 ? (
        <p className="dash-muted" data-testid="at-empty">
          Nothing recoverable is outstanding.
        </p>
      ) : (
        <ul className="at-list">
          {data.items.map((item) => (
            <Row
              key={`${item.record_type}|${item.scheme ?? ''}|${item.reason}`}
              caseId={caseId}
              item={item}
            />
          ))}
        </ul>
      )}

      {/* The server's own sentence, always. An empty queue reads as a clean
          case otherwise, and this queue is not the completeness record —
          rewriting it here would let the two drift. */}
      <p className="at-scope" role="note" data-testid="at-scope">
        {data.scope_note}
      </p>
    </div>
  )
}
