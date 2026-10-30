import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { lockForReading, unlockForReading } from '../../api/resources'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import type { Artifact } from '../../api/types'
import { getArtifactAncestors, type AncestorEntry } from './api'

/**
 * Unlock-to-read for anything on a BitLocker or LUKS volume decrypted during a
 * run (HUNT-254).
 *
 * The key a run derived is gone when the run ends, so the decrypted volume and
 * every file beneath it are refused (the only bytes on the evidence are
 * ciphertext). This panel sends the secret to `POST …/unlock` with a volume
 * kind; the server tries it on the locked volume and, if it opens it, holds
 * the decrypting key in its memory for this case only, with a time limit.
 * "Lock again" is `DELETE` on the same route. Both are audited by kind, never
 * by value. Nothing is re-run and nothing is added to the case; the secret is
 * not stored in the browser — the field is cleared once it has been sent.
 *
 * Shown when the artifact or one of its ancestors is marked
 * `decrypted_volume` by the ancestors route — the server's own flag, not a
 * guess from a name.
 */

type Family = 'bitlocker' | 'luks'

const KINDS: Record<Family, { kind: string; label: string }[]> = {
  bitlocker: [
    { kind: 'bitlocker_password', label: 'Password' },
    { kind: 'bitlocker_recovery_password', label: 'Recovery password' },
  ],
  luks: [{ kind: 'luks_passphrase', label: 'Passphrase' }],
}

const TITLE: Record<Family, string> = {
  bitlocker: 'BitLocker',
  luks: 'LUKS',
}

/** The nearest decrypted volume in the chain (the artifact itself included). */
function decryptedVolumeIn(chain: AncestorEntry[]): Family | null {
  for (let i = chain.length - 1; i >= 0; i--) {
    const d = chain[i].decrypted_volume
    if (d === 'bitlocker' || d === 'luks') return d
  }
  return null
}

type Verdict =
  | { state: 'unlocked'; hours: number }
  | { state: 'locked'; wasUnlocked: boolean }
  | { state: 'error'; message: string }

export function VolumeReadUnlockPanel({
  caseId,
  artifact,
}: {
  caseId: string
  artifact: Artifact
}) {
  // The same query the artifact page makes, so this costs no extra request.
  const ancestors = useQuery({
    queryKey: ['artifact-ancestors', caseId, artifact.id],
    queryFn: () => getArtifactAncestors(caseId, artifact.id),
  })
  const family = ancestors.data ? decryptedVolumeIn(ancestors.data) : null

  // Scoped to the artifact so a typed secret and a verdict never follow the
  // examiner to another artifact (BUG-259 class).
  const scope = `${caseId}/${artifact.id}`
  const [value, setValue] = useEntityScopedState(scope, '')
  const [chosen, setChosen] = useEntityScopedState<string | null>(scope, null)
  const [verdict, setVerdict] = useEntityScopedState<Verdict | null>(
    scope,
    null,
  )
  const queryClient = useQueryClient()

  // Content refused for anything in this case may now read (or, after a
  // lock, be refused again): ask again.
  const refresh = () =>
    queryClient.invalidateQueries({
      predicate: (q) => q.queryKey.includes(caseId),
    })

  const unlock = useMutation({
    mutationFn: (t: {
      secret: string
      kind: string
      artifactId: string
      scope: string
    }) => unlockForReading(caseId, t.artifactId, t.kind, t.secret),
    onSuccess: (r, t) => {
      void refresh()
      if (t.scope !== scope) return
      setValue('')
      setVerdict({
        state: 'unlocked',
        hours: Math.round((r.expires_in_secs / 3600) * 10) / 10,
      })
    },
    onError: (err, t) => {
      if (t.scope !== scope) return
      setVerdict({ state: 'error', message: err.message })
    },
  })
  const lock = useMutation({
    mutationFn: (t: { artifactId: string; scope: string }) =>
      lockForReading(caseId, t.artifactId),
    onSuccess: (r, t) => {
      void refresh()
      if (t.scope !== scope) return
      setVerdict({ state: 'locked', wasUnlocked: r.was_unlocked })
    },
    onError: (err, t) => {
      if (t.scope !== scope) return
      setVerdict({ state: 'error', message: err.message })
    },
  })

  if (!family) return null
  const kinds = KINDS[family]
  const kind =
    chosen && kinds.some((k) => k.kind === chosen) ? chosen : kinds[0].kind
  const title = TITLE[family]
  const secretLabel =
    family === 'luks'
      ? 'LUKS passphrase to read this volume'
      : `BitLocker ${kinds.find((k) => k.kind === kind)?.label.toLowerCase()} to read this volume`
  const busy =
    (unlock.isPending && unlock.variables?.scope === scope) ||
    (lock.isPending && lock.variables?.scope === scope)

  return (
    <form
      className="av-unlock"
      onSubmit={(e) => {
        e.preventDefault()
        // Sent exactly as typed: a trimmed secret is a different secret.
        if (value.trim().length > 0) {
          unlock.mutate({
            secret: value,
            kind,
            artifactId: artifact.id,
            scope,
          })
        }
      }}
    >
      <h3>On a decrypted {title} volume</h3>
      <p className="av-unlock-hint">
        The key is not kept after the run that decrypted the volume, so its
        content — and this artifact&apos;s — is refused until the volume is
        unlocked for reading.
      </p>
      <div className="av-unlock-row">
        {kinds.length > 1 && (
          <select
            className="input"
            aria-label="Credential kind"
            value={kind}
            onChange={(e) => setChosen(e.target.value)}
          >
            {kinds.map((k) => (
              <option key={k.kind} value={k.kind}>
                {k.label}
              </option>
            ))}
          </select>
        )}
        <input
          type="password"
          className="input"
          aria-label={secretLabel}
          placeholder={family === 'luks' ? 'Passphrase' : 'Password'}
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <button
          type="submit"
          className="btn btn-primary"
          disabled={value.trim().length === 0 || busy}
        >
          Unlock to read
        </button>
        <button
          type="button"
          className="btn"
          disabled={busy}
          onClick={() => lock.mutate({ artifactId: artifact.id, scope })}
        >
          Lock again
        </button>
      </div>
      {verdict && (
        <p
          className={
            verdict.state === 'error' ? 'av-unlock-bad' : 'av-unlock-ok'
          }
          role="status"
        >
          {verdict.state === 'unlocked'
            ? `Unlocked for reading in this case for ${verdict.hours} h, or until locked again or the server restarts.`
            : verdict.state === 'locked'
              ? verdict.wasUnlocked
                ? 'Locked again: the key is forgotten.'
                : 'It was not unlocked.'
              : `Not unlocked — ${verdict.message}`}
        </p>
      )}
      <p className="av-unlock-note">
        The volume&apos;s key is held in the server&apos;s memory for this case
        only; the secret is not kept, and neither is written to the case, an
        export or the audit log. The audit log records each unlock and lock by
        kind, never the secret.
      </p>
    </form>
  )
}
