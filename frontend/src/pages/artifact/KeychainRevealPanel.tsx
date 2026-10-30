import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { apiFetch } from '../../api/http'
import type { Artifact } from '../../api/types'
import { useEntityScopedState } from '../../lib/useEntityScopedState'

/**
 * The audited reveal of one iOS backup keychain item's secret (HUNT-111).
 *
 * Ingest decrypts a keychain item's attributes and withholds its secret: the
 * value is never stored in the case, an export or the search index. This panel
 * is the only way to see it. It calls
 * `POST /cases/:caseId/keychain/:recordId/reveal`, which re-derives the secret
 * from the backup (so the backup must be unlocked for reading, BUG-026), writes
 * the `ios_keychain_secret_revealed` audit event, and only then returns the
 * value. If the call fails for any reason — the backup is locked, the audit
 * write failed, the grant is read-only — nothing is shown but the server's
 * reason. The discipline is the memory-credential reveal's
 * (`MemoryCredentialsPage`).
 *
 * The revealed value is held in this component's state only, scoped to the
 * artifact: it is gone when the examiner opens another item or leaves the page,
 * and a second look is a second audited reveal.
 */

/** Served by `reveal_ios_keychain_secret` in `seance_api/src/keychain_reveal.rs`. */
interface KeychainRevealResponse {
  value: string
  /** `hex` when the secret's bytes are not UTF-8 (a key, a token blob). */
  encoding: 'utf8' | 'hex'
  /** Always null: the audit writer does not return the row id it wrote. */
  audit_event_id: string | null
}

const revealKeychainSecret = (
  caseId: string,
  recordId: string,
  credential?: RevealCredential,
) =>
  apiFetch<KeychainRevealResponse>(
    `/cases/${caseId}/keychain/${recordId}/reveal`,
    credential === undefined
      ? { method: 'POST' }
      : { method: 'POST', body: { [credential.kind]: credential.value } },
  )

/** The API takes exactly one: the keychain password, or the hex of `/var/db/SystemKey` (System.keychain). */
type RevealCredential = { kind: 'password' | 'system_key'; value: string }

/** A macOS keychain item with a wrapped secret: a password item or a private key (a certificate has none). */
function isMacosPasswordItem(md: Record<string, unknown>): boolean {
  return (
    md.type === 'KeychainItem' &&
    ['generic_password', 'internet_password', 'appleshare_password', 'private_key'].includes(
      String(md.item_kind),
    ) &&
    md.secret_wrapping !== undefined
  )
}

/** An iOS backup keychain item or a macOS password item: the records this panel speaks for. */
export function keychainRevealFor(artifact: Artifact): boolean {
  const md = artifact.metadata as Record<string, unknown>
  return md.type === 'IosKeychainItem' || isMacosPasswordItem(md)
}

type Outcome =
  | { state: 'revealed'; value: string; encoding: 'utf8' | 'hex' }
  | { state: 'refused'; message: string }

/** Why an item that is not revealable is not, in the record's own terms. */
function notRevealable(md: Record<string, unknown>): string | null {
  const state = md.state
  if (state === 'device_bound')
    return 'This item is bound to the device (a ThisDeviceOnly class): its key is wrapped under a hardware key a backup does not carry, so nothing in it was read and there is no secret to reveal.'
  if (state === 'authentication_failed')
    return 'This item did not authenticate when it was read, so nothing in it was decrypted and there is no secret to reveal.'
  if (state !== 'read')
    return 'This item was not read, so there is no secret to reveal.'
  if (md.secret_state !== 'withheld')
    return 'This item carries no secret: the item holds attributes only. That is not a secret that was empty.'
  return null
}

export function KeychainRevealPanel({
  caseId,
  artifact,
}: {
  caseId: string
  artifact: Artifact
}) {
  // Scoped so a revealed value never follows the examiner to another item.
  const scope = `${caseId}/${artifact.id}`
  const [outcome, setOutcome] = useEntityScopedState<Outcome | null>(
    scope,
    null,
  )

  // A macOS reveal takes the keychain password again: it is used for that one request and kept
  // nowhere, so it is cleared from the field as soon as it is sent.
  const [password, setPassword] = useState('')
  const [kind, setKind] = useState<RevealCredential['kind']>('password')

  const reveal = useMutation({
    mutationFn: (t: {
      recordId: string
      scope: string
      credential?: RevealCredential
    }) => revealKeychainSecret(caseId, t.recordId, t.credential),
    onSuccess: (r, t) => {
      if (t.scope !== scope) return
      setOutcome({ state: 'revealed', value: r.value, encoding: r.encoding })
    },
    onError: (err, t) => {
      if (t.scope !== scope) return
      setOutcome({ state: 'refused', message: err.message })
    },
  })

  if (!keychainRevealFor(artifact)) return null
  const md = artifact.metadata as Record<string, unknown>
  const macos = isMacosPasswordItem(md)
  const why = macos ? null : notRevealable(md)
  const busy = reveal.isPending && reveal.variables?.scope === scope

  return (
    <div className="av-unlock">
      <h3>Keychain secret</h3>
      {why ? (
        <p className="av-unlock-hint">{why}</p>
      ) : macos ? (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (password.length === 0) return
            // Sent exactly as typed: a trimmed password is a different password.
            reveal.mutate({
              recordId: artifact.id,
              scope,
              credential: { kind, value: password },
            })
            setPassword('')
          }}
        >
          <p className="av-unlock-hint">
            This password item&apos;s secret is wrapped under the
            keychain&apos;s master key and is not stored in the case, shown,
            exported or searchable. Revealing it takes the keychain password, or
            for System.keychain the 96 hex characters of{' '}
            <code>/var/db/SystemKey</code>, which is used for that one request and kept nowhere, re-reads the
            keychain file, decrypts this item, and is recorded in the case audit
            log against your account. A reveal that cannot be recorded does not
            happen.
          </p>
          <div className="av-unlock-row">
            <select
              className="input"
              aria-label="Credential kind"
              value={kind}
              onChange={(e) =>
                setKind(e.target.value as RevealCredential['kind'])
              }
            >
              <option value="password">Keychain password</option>
              <option value="system_key">SystemKey (hex)</option>
            </select>
            <input
              type="password"
              className="input"
              aria-label="Keychain password to reveal this item"
              placeholder={
                kind === 'password' ? 'Keychain password' : 'SystemKey, 96 hex'
              }
              autoComplete="off"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={password.length === 0 || busy}
            >
              Reveal secret
            </button>
          </div>
          {outcome?.state === 'revealed' && (
            <p className="av-unlock-ok">
              <span className="mem-revealed">{outcome.value}</span>
              {outcome.encoding === 'hex' && (
                <>
                  {' '}
                  <span className="av-unlock-note">
                    (the secret&apos;s bytes are not UTF-8, so they are shown as
                    hex)
                  </span>
                </>
              )}
            </p>
          )}
          {outcome?.state === 'refused' && (
            <p className="av-unlock-bad" role="status">
              Not revealed — {outcome.message}
            </p>
          )}
        </form>
      ) : (
        <>
          <p className="av-unlock-hint">
            The secret decrypted at ingest but is withheld: it is not stored in
            the case, shown, exported or searchable. Revealing it re-derives it
            from the backup, which must be unlocked for reading (from any of the
            backup&apos;s files), and is recorded in the case audit log against
            your account. A reveal that cannot be recorded does not happen.
          </p>
          <div className="av-unlock-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => reveal.mutate({ recordId: artifact.id, scope })}
            >
              Reveal secret
            </button>
          </div>
          {outcome?.state === 'revealed' && (
            <p className="av-unlock-ok">
              <span className="mem-revealed">{outcome.value}</span>
              {outcome.encoding === 'hex' && (
                <>
                  {' '}
                  <span className="av-unlock-note">
                    (the secret&apos;s bytes are not UTF-8, so they are shown as
                    hex)
                  </span>
                </>
              )}
            </p>
          )}
          {outcome?.state === 'refused' && (
            <p className="av-unlock-bad" role="status">
              Not revealed — {outcome.message}
            </p>
          )}
        </>
      )}
    </div>
  )
}
