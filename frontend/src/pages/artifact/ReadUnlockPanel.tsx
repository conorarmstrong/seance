import { useMutation, useQueryClient } from '@tanstack/react-query'
import { lockForReading, unlockForReading } from '../../api/resources'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import type { Artifact } from '../../api/types'

/**
 * Unlock-to-read for a file of an encrypted iOS backup (BUG-026).
 *
 * After ingest the backup password is gone, so the file's content (preview,
 * hex, download, export, re-hash) is refused: the only bytes on disk are
 * ciphertext. This panel sends the password to `POST …/unlock`, which checks
 * it against the backup's keybag and holds the unwrapped class keys in the
 * server's memory for this case only, with a time limit. While they are held
 * the backup's files read as their plaintext (not one ingest could not open
 * for want of a key or protection class). "Lock again" is `DELETE`
 * on the same route. Both are audited by kind, never by value.
 *
 * It is not the credential route: nothing is re-run and nothing new is added
 * to the case. The password is not stored in the browser either — the field is
 * cleared once it has been sent.
 */

const KIND = 'ios_backup_password'

/** A file record of an encrypted iOS backup: the only thing this unlocks. */
export function readUnlockableFor(artifact: Artifact): boolean {
  const md = artifact.metadata as Record<string, unknown>
  return (
    md.type === 'IosBackupFile' &&
    md.encrypted === true &&
    md.is_directory !== true &&
    typeof md.backup_path === 'string' &&
    typeof md.file_id === 'string'
  )
}

type Verdict =
  | { state: 'unlocked'; hours: number }
  | { state: 'locked'; wasUnlocked: boolean }
  | { state: 'error'; message: string }

export function ReadUnlockPanel({
  caseId,
  artifact,
}: {
  caseId: string
  artifact: Artifact
}) {
  // Scoped to the artifact so a typed password and a verdict never follow the
  // examiner to another file (BUG-259 class).
  const scope = `${caseId}/${artifact.id}`
  const [value, setValue] = useEntityScopedState(scope, '')
  const [verdict, setVerdict] = useEntityScopedState<Verdict | null>(
    scope,
    null,
  )
  const queryClient = useQueryClient()

  // Whatever was refused for this artifact is asked for again.
  const refresh = (artifactId: string) =>
    queryClient.invalidateQueries({
      predicate: (q) => q.queryKey.includes(artifactId),
    })

  const unlock = useMutation({
    mutationFn: (t: { secret: string; artifactId: string; scope: string }) =>
      unlockForReading(caseId, t.artifactId, KIND, t.secret),
    onSuccess: (r, t) => {
      void refresh(t.artifactId)
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
      void refresh(t.artifactId)
      if (t.scope !== scope) return
      setVerdict({ state: 'locked', wasUnlocked: r.was_unlocked })
    },
    onError: (err, t) => {
      if (t.scope !== scope) return
      setVerdict({ state: 'error', message: err.message })
    },
  })

  if (!readUnlockableFor(artifact)) return null
  const busy =
    (unlock.isPending && unlock.variables?.scope === scope) ||
    (lock.isPending && lock.variables?.scope === scope)

  return (
    <form
      className="av-unlock"
      onSubmit={(e) => {
        e.preventDefault()
        // Sent exactly as typed: a trimmed password is a different password.
        if (value.trim().length > 0) {
          unlock.mutate({ secret: value, artifactId: artifact.id, scope })
        }
      }}
    >
      <h3>Encrypted iOS backup file</h3>
      <p className="av-unlock-hint">
        The password is not kept after ingest, so this file&apos;s content is
        refused until the backup is unlocked for reading.
      </p>
      <div className="av-unlock-row">
        <input
          type="password"
          className="input"
          aria-label="iOS backup password to read this backup's files"
          placeholder="Backup password"
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
                ? 'Locked again: the keys are forgotten.'
                : 'It was not unlocked.'
              : `Not unlocked — ${verdict.message}`}
        </p>
      )}
      <p className="av-unlock-note">
        The backup&apos;s keys are held in the server&apos;s memory for this
        case only; the password is not kept, and neither is written to the case,
        an export or the audit log. The audit log records each unlock and lock
        by kind, never the password.
      </p>
    </form>
  )
}
