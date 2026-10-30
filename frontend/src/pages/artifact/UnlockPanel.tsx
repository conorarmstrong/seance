import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getJob, supplyCredential } from '../../api/resources'
import { useToast } from '../../components/toast/ToastProvider'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import type { Artifact } from '../../api/types'

/**
 * Prompt for the passphrase of an encrypted artifact and re-run its parser with
 * it.
 *
 * The passphrase goes to `POST …/credential` with its credential kind
 * (`SEC-204`; it used to go in `run_module`'s retired `secrets` map). The
 * server holds it zeroed for that one run, never merges it into the artifact's
 * metadata, never writes it to the job record, the audit log or the case, and
 * audits the attempt and its outcome by kind. It is not stored in the browser
 * either — the field is cleared once the run is queued.
 *
 * The verdict is the **job's** outcome. A rejected secret persists nothing, so
 * the artifact's children never change and polling them would wait forever.
 */

interface Unlockable {
  /** The credential kind the route takes for this secret. */
  kind: string
  label: string
  hint: string
  /**
   * Only offer the unlock when the record's `status` is this.
   *
   * A record type can cover more than one state: `IosBackupInfo` is emitted for
   * a backup nobody has the password for AND for one that decrypted with parts
   * missing. Offering a passphrase box on the second would invite the examiner
   * to re-supply a password that already worked.
   */
  status?: string
}

/** Encrypted things a passphrase can currently open, keyed by record type. */
const UNLOCKABLE: Record<string, Unlockable> = {
  SignalBackup: {
    kind: 'signal_backup_passphrase',
    label: 'Signal backup',
    hint: "Signal's 30-digit backup passphrase, spaces optional.",
  },
  // An encrypted iOS backup's own record says "provide the password to decrypt
  // and extract them". Until HUNT-085 the only way to provide it was a
  // process-level secret at startup, so acting on that sentence meant
  // restarting the server with the case already open.
  IosBackupInfo: {
    kind: 'ios_backup_password',
    label: 'iOS backup',
    hint: 'The backup password set in iTunes/Finder when the backup was made.',
    // Not the partial-decryption states: there a password already worked.
    status: 'encrypted_no_password',
  },
  // A crypt14 or crypt15 backup whose key file (/data/data/com.whatsapp/files/
  // key, or encrypted_backup.key for crypt15) is not in the case (ROADMAP
  // §5.7). Only while it awaits a key.
  WhatsAppBackup: {
    kind: 'whatsapp_key',
    label: 'WhatsApp backup',
    hint: "The key file as hex, or 64 hex digits: a crypt14 install's bare key, or a crypt15's end-to-end backup key.",
    status: 'AwaitingKey',
  },
}

/** The unlock definition for an artifact, when it is locked and we can try. */
export function unlockableFor(artifact: Artifact): Unlockable | null {
  const md = artifact.metadata as Record<string, unknown>
  const type = typeof md.type === 'string' ? md.type : null
  if (!type) return null
  const def = UNLOCKABLE[type]
  if (!def) return null
  // Already decrypted: nothing to unlock.
  if (md.decrypted === true) return null
  // A type that covers several states offers the unlock only in the locked one.
  if (def.status !== undefined && md.status !== def.status) return null
  return def
}

export function UnlockPanel({
  caseId,
  artifact,
}: {
  caseId: string
  artifact: Artifact
}) {
  const def = unlockableFor(artifact)
  // Both the typed passphrase and the "an attempt was made" flag belong to the
  // artifact they were entered against. The artifact page stays mounted when
  // `:artifactId` changes, so unscoped they follow the examiner to the next
  // locked backup: the previous secret sits in the field ready to be submitted
  // against a container it was never meant for, and the verdict line reports
  // "Passphrase accepted"/"Passphrase rejected" for THIS artifact on the
  // strength of an attempt made on a different one — a decryption result
  // asserted about evidence nobody tried to decrypt. Scoped on both ids
  // because artifact UUIDs are per-case (BUG-259 class).
  const unlockScope = `${caseId}/${artifact.id}`
  const [value, setValue] = useEntityScopedState(unlockScope, '')
  // The job the attempt started, scoped like the field: the verdict line
  // belongs to the artifact the passphrase was submitted for.
  const [attemptJob, setAttemptJob] = useEntityScopedState<string | null>(
    unlockScope,
    null,
  )
  const attempted = attemptJob !== null
  const toast = useToast()
  const queryClient = useQueryClient()

  // After a run, watch the JOB for the verdict. The orchestrator fails the job
  // with its own sentence when the module reports the secret rejected, and a
  // rejected run persists nothing — so the artifact's children cannot say.
  const outcome = useQuery({
    queryKey: ['unlock-outcome', caseId, artifact.id, attemptJob],
    queryFn: async () => {
      const job = await getJob(caseId, attemptJob as string)
      if (job.status === 'complete') return { decrypted: true, error: null }
      if (job.status === 'failed')
        return { decrypted: false, error: job.error_message }
      return null
    },
    enabled: attempted,
    // The job runs asynchronously, so keep looking until it finishes.
    refetchInterval: (q) => (q.state.data ? false : 2000),
  })

  // The attempt is scoped by the VARIABLES it was submitted with, not by the
  // render that handles its response. Scoping the state alone is not enough:
  // react-query invokes the latest `onSuccess`, so a submit that settles after
  // the examiner has moved to the next locked container writes `attempted` into
  // THAT artifact's scope. Its panel then says "Working… the result appears
  // here when the job finishes" and polls `unlock-outcome` for an artifact
  // nobody tried to decrypt — and the line that follows reports a passphrase as
  // accepted or rejected for that exhibit. Comparing the scope the request was
  // issued under with the live one makes a late response land nowhere.
  const run = useMutation({
    mutationFn: (target: {
      secret: string
      caseId: string
      artifactId: string
      kind: string
      scope: string
    }) =>
      supplyCredential(
        target.caseId,
        target.artifactId,
        target.kind,
        target.secret,
      ),
    onSuccess: (result, target) => {
      // The invalidations name the artifact the run was STARTED for, so a late
      // response still refreshes the right panel rather than the one on screen.
      void queryClient.invalidateQueries({ queryKey: ['jobs', target.caseId] })
      if (target.scope !== unlockScope) return
      // Do not keep the passphrase around once it has been handed over.
      setValue('')
      setAttemptJob(result.job_id)
      toast.success('Decrypting…')
    },
    onError: (err, target) => {
      if (target.scope !== unlockScope) return
      toast.error(`Could not start decryption: ${err.message}`)
    },
  })
  // "Decrypting…" belongs to the artifact the passphrase was submitted for.
  // `isPending` is a property of the mutation, not of what is on screen, so on
  // its own it disables the next locked container's Decrypt button and labels
  // it as decrypting while nothing has been submitted for it.
  const runningHere = run.isPending && run.variables?.scope === unlockScope

  if (!def) return null

  return (
    <form
      className="av-unlock"
      onSubmit={(e) => {
        e.preventDefault()
        // Sent exactly as typed: a password may begin or end with a space,
        // and a trimmed one is a different (wrong) password. Only an entry
        // that is nothing but whitespace is not sent.
        const secret = value
        if (secret.trim().length > 0) {
          run.mutate({
            secret,
            caseId,
            // The artifact the backup IS — the locked record's parent — not
            // the record, which has no bytes (and, for an iOS backup, no
            // folder) of its own.
            artifactId: artifact.parent_id ?? artifact.id,
            kind: def.kind,
            scope: unlockScope,
          })
        }
      }}
    >
      <h3>Locked {def.label}</h3>
      <p className="av-unlock-hint">{def.hint}</p>
      <div className="av-unlock-row">
        <input
          type="password"
          className="input"
          aria-label={`Passphrase for this ${def.label}`}
          placeholder="Passphrase"
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <button
          type="submit"
          className="btn btn-primary"
          disabled={value.trim().length === 0 || runningHere}
        >
          {runningHere ? 'Decrypting…' : 'Decrypt'}
        </button>
      </div>
      {attempted && (
        <p
          className={
            outcome.data == null
              ? 'av-unlock-note'
              : outcome.data.decrypted
                ? 'av-unlock-ok'
                : 'av-unlock-bad'
          }
          role="status"
        >
          {outcome.data == null
            ? 'Working… the result appears here when the job finishes.'
            : outcome.data.decrypted
              ? 'Passphrase accepted. Reload to see what it opened.'
              : `Not decrypted${
                  outcome.data.error ? ` — ${outcome.data.error}` : ''
                }`}
        </p>
      )}
      <p className="av-unlock-note">
        Used for this run only. It is not saved to the case, the job record or
        the audit log; the audit log records that a passphrase was supplied and
        whether it opened the backup, never the passphrase.
      </p>
    </form>
  )
}
