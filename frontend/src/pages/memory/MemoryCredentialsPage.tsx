import { useMutation } from '@tanstack/react-query'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import {
  getMemoryCoverage,
  getMemoryCredentials,
  revealCredential,
  MEMORY_CREDENTIAL_STAGE,
  type MemoryCoverageResponse,
  type MemoryCredentialsResult,
} from './api'
import type { ParsedRecord } from '../analysis/api'
import { useMemoryContext } from './memoryContext'
import {
  failureSummary,
  filetimeText,
  inventoryCount,
  readCredentialInventory,
  splitCredentialsByImage,
  type CredentialInventory,
} from './normalize'

/**
 * Credential material in memory: what was located, and what — if anything — was
 * recovered from it.
 *
 * **The page is inventory-first.** It leads with a listing of the credential
 * stores held in RAM: which hives were resident, which local accounts the SAM
 * names and under which relative identifiers, what the LSA secrets are *called*,
 * how many cached domain logons are present. Over that inventory, the words
 * "recovered" and "revealed" appear only over records that actually carry a
 * value — so an examiner never reads "recovered credentials" over what is only
 * the NAME of a stored secret.
 *
 * The analysis now DOES recover values for modern local accounts: it emits a
 * `MemoryCredential` record per account whose NT hash it decrypted (the boot
 * key from the SYSTEM hive, the hashed boot key from SAM, the per-account AES+DES
 * unwrap). The LSA secrets and older-form hashes remain located but not
 * decrypted. For the recovered records, five rules hold, all visible on screen:
 *
 * 1. Values are **masked by default**.
 * 2. Every reveal is a **server round trip that writes an audit event**, and if
 *    that write fails the value stays masked. A reveal nobody can attest to is
 *    worse than no reveal.
 * 3. The **hash format is labelled** (LM / NT / MSCACHE / MSCACHEv2 / DCC2), so
 *    an examiner cannot mis-feed a cracker with the wrong algorithm.
 * 4. The **derivation chain is shown**, because an examiner must be able to
 *    attest to method: which key the bootkey came from, which value the hash
 *    came from, which transform was applied.
 * 5. Nothing here is exported by a single click; export is a separate,
 *    confirmed and audited action that lives with the case export.
 *
 * That table renders only when such a record exists. It is not drawn empty as a
 * promise of a capability the analysis does not have.
 */

/** What this stage does, in the page's own words, when the record states none. */
const INVENTORY_ONLY =
  'The credential stage locates and inventories the credential stores held in RAM — the SAM and SECURITY hives, the LSA secrets, the cached domain logons. It recovers the NT hashes of modern local accounts (shown below as recovered values); the LSA secrets and any older-form hashes are located but not decrypted.'

/** Read a string field from a record's untyped metadata. */
function str(record: ParsedRecord, key: string): string | null {
  const value = (record.metadata as Record<string, unknown>)[key]
  return typeof value === 'string' && value !== '' ? value : null
}

/** Read the derivation chain, tolerating a producer that supplied none. */
function chain(record: ParsedRecord): { step: string; source: string }[] {
  const raw = (record.metadata as Record<string, unknown>).derivation_chain
  if (!Array.isArray(raw)) return []
  const out: { step: string; source: string }[] = []
  for (const entry of raw) {
    if (entry != null && typeof entry === 'object') {
      const step = (entry as Record<string, unknown>).step
      const source = (entry as Record<string, unknown>).source
      if (typeof step === 'string') {
        out.push({
          step,
          source: typeof source === 'string' ? source : 'source not stated',
        })
      }
    }
  }
  return out
}

export function MemoryCredentialsPage() {
  const { caseId, imageId, scopeKey } = useMemoryContext()
  const [revealed, setRevealed] = useEntityScopedState<Record<string, string>>(
    scopeKey,
    EMPTY_REVEALS,
  )
  const [failed, setFailed] = useEntityScopedState<Record<string, string>>(
    scopeKey,
    EMPTY_REVEALS,
  )

  const query = useEntityScopedQuery<MemoryCredentialsResult>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'credentials'],
    queryFn: () => getMemoryCredentials(caseId),
    retry: false,
  })

  // Read alongside the records, and only used when there are none: an empty
  // list from the generic records endpoint cannot tell "the credential stage
  // ran and found no store" from "no stage on this build reads the credential
  // stores at all", and only the first of those is a finding.
  const coverageQuery = useEntityScopedQuery<MemoryCoverageResponse>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'coverage'],
    queryFn: () => getMemoryCoverage(caseId, imageId),
    retry: false,
  })

  // A reveal is scoped by the variables it was started with, not by the render
  // that happens to handle its response. react-query calls the LATEST
  // `onSuccess`, so if the examiner changes capture (or case) while the request
  // is in flight, the setter in hand belongs to the new scope, and capture A's
  // cleartext is written into capture B's state. Today the row keying means
  // nothing renders it — but a recovered secret must not be parked against the
  // wrong machine on the strength of that, and the mutation's shared pending
  // flag IS visible: without the scope test, capture A's in-flight reveal
  // disables capture B's Reveal buttons, so this page reports activity on a
  // capture where none is happening. Comparing the scope the request was
  // issued under with the live one makes a late response land nowhere.
  const reveal = useMutation({
    mutationFn: (target: { recordId: string; caseId: string; scope: string }) =>
      revealCredential(target.caseId, target.recordId),
    onSuccess: (response, target) => {
      if (target.scope !== scopeKey) return
      setRevealed((previous) => ({
        ...previous,
        [target.recordId]: response.value,
      }))
    },
    onError: (error: unknown, target) => {
      if (target.scope !== scopeKey) return
      setFailed((previous) => ({
        ...previous,
        [target.recordId]:
          error instanceof Error ? error.message : 'the server did not say why',
      }))
    },
  })
  const revealRecord = (recordId: string) =>
    reveal.mutate({ recordId, caseId, scope: scopeKey })

  if (query.isPending || query.stale) {
    return <div className="loading">Loading the credential inventory…</div>
  }

  if (query.isError || query.scoped == null) {
    return (
      <div className="error-note" role="note">
        <strong>The credential inventory could not be loaded.</strong> This is a
        load error, not a capture whose credential stores held nothing.
      </div>
    )
  }

  const values = splitCredentialsByImage(query.scoped.records, imageId)
  const inventories = splitCredentialsByImage(query.scoped.inventory, imageId)
  const otherCaptureTotal = values.otherCaptures.reduce(
    (n, o) => n + o.count,
    0,
  )

  // Credential values recovered from OTHER captures in this case, tallied so
  // the per-capture filter is visible to the examiner instead of silently
  // emptying the page (B4-026). Rendered above both the tables and the empty
  // state, because the empty state is exactly where the omission misleads.
  const otherCapturesNote = otherCaptureTotal > 0 && (
    <div className="warn-note" role="note" data-testid="mem-other-captures">
      <strong>
        {otherCaptureTotal} further credential
        {otherCaptureTotal === 1 ? '' : 's'} in this case{' '}
        {otherCaptureTotal === 1 ? 'belongs' : 'belong'} to{' '}
        {values.otherCaptures.length === 1
          ? 'another capture'
          : `${values.otherCaptures.length} other captures`}
        .
      </strong>{' '}
      They are not listed here because they were not recovered from this
      capture. An absence on this page is therefore not an absence in the case —
      open the capture named to see them.
      <ul>
        {values.otherCaptures.map((other) => (
          <li className="mono" key={other.imageId}>
            {other.imageId} · {other.count} credential
            {other.count === 1 ? '' : 's'}
          </li>
        ))}
      </ul>
    </div>
  )

  // Inventories that name no capture are shown beside the attributed ones,
  // marked, rather than dropped by the filter.
  const shownInventories = [
    ...inventories.attributed.map((record) => ({ record, attributed: true })),
    ...inventories.unattributed.map((record) => ({ record, attributed: false })),
  ]

  if (shownInventories.length === 0 && values.attributed.length === 0) {
    return (
      <>
        {otherCapturesNote}
        <NoInventory
          pending={coverageQuery.isPending || coverageQuery.stale}
          coverage={coverageQuery.scoped}
          otherCaptureInventories={inventories.otherCaptures.length}
        />
        {values.unattributed.length > 0 && (
          <UnattributedValues records={values.unattributed} />
        )}
      </>
    )
  }

  return (
    <div className="mem-credentials">
      {values.attributed.length === 0 ? (
        <div className="warn-note" role="note">
          <strong>Nothing here is decrypted.</strong> {INVENTORY_ONLY} What is
          listed below are names, identifiers and counts, and they must be read
          as that.
        </div>
      ) : (
        <div className="warn-note" role="note">
          <strong>The inventory and the values are separate claims.</strong>{' '}
          {INVENTORY_ONLY} The values further down came from records that carry
          one; nothing in the inventory did.
        </div>
      )}

      {otherCapturesNote}

      {query.scoped.truncated && (
        <div className="warn-note" role="note">
          <strong>This page is a floor.</strong> More credential records exist
          than were fetched, so treat everything below as a minimum.
        </div>
      )}

      {shownInventories.map(({ record, attributed }) => (
        <InventoryPanel
          key={record.id}
          inventory={readCredentialInventory(record)}
          attributed={attributed}
        />
      ))}

      {values.attributed.length > 0 && (
        <RecoveredValues
          records={values.attributed}
          revealed={revealed}
          failed={failed}
          revealDisabled={
            reveal.isPending && reveal.variables?.scope === scopeKey
          }
          onReveal={revealRecord}
        />
      )}

      {values.unattributed.length > 0 && (
        <UnattributedValues records={values.unattributed} />
      )}
    </div>
  )
}

/** Stable empty map, returned by `useEntityScopedState` after a scope change. */
const EMPTY_REVEALS: Record<string, string> = {}

/**
 * One capture's credential-store inventory.
 *
 * Every heading here says what the row is: an account NAME, a secret NAME, a
 * COUNT of cached logons. None of them is a value, and the panel never implies
 * one could be produced from what is on it.
 */
function InventoryPanel({
  inventory,
  attributed,
}: {
  inventory: CredentialInventory
  attributed: boolean
}) {
  return (
    <section className="panel" aria-label="Credential store inventory">
      <h2 className="panel-title">Credential stores located</h2>

      {!attributed && (
        <div className="warn-note" role="note">
          <strong>This inventory names no capture.</strong> It is shown rather
          than hidden by the capture filter, but which capture it describes
          cannot be stated.
        </div>
      )}

      <p className="mem-note">{inventory.decryptionStatement ?? INVENTORY_ONLY}</p>

      {inventory.plaintextRecovered === true && (
        <div className="error-note" role="note">
          <strong>This record claims plaintext was recovered.</strong> That
          contradicts the record type, which carries an inventory and no value.
          Treat the claim as unresolved and read the record itself before
          reporting anything from it.
        </div>
      )}
      {inventory.plaintextRecovered == null && (
        <p className="mem-note">
          The record does not state whether anything was decrypted. No value is
          present on it, and none is shown.
        </p>
      )}

      {inventory.inventoryComplete === false && (
        <div className="warn-note" role="note">
          <strong>This inventory is a floor, not a total.</strong>{' '}
          {inventory.incompleteReason ??
            'The producer did not record why it is short.'}{' '}
          An account, hive or secret missing from the lists below may be one that
          was not reached rather than one that does not exist.
        </div>
      )}
      {inventory.inventoryComplete == null && (
        <div className="warn-note" role="note">
          <strong>
            This record does not say whether the inventory is complete.
          </strong>{' '}
          The lists below cannot be read as the whole of what the machine holds.
        </div>
      )}
      {inventory.truncated === true && inventory.inventoryComplete !== false && (
        <div className="warn-note" role="note">
          A listing stopped at its cap, so the rows below are a floor.
        </div>
      )}
      {inventory.undecodableEntries > 0 && (
        <div className="warn-note" role="note">
          {inventory.undecodableEntries} entr
          {inventory.undecodableEntries === 1 ? 'y' : 'ies'} in this record could
          not be decoded and {inventory.undecodableEntries === 1 ? 'is' : 'are'}{' '}
          not listed below. The lists are short by that many.
        </div>
      )}

      <dl className="mem-kv">
        <div className="mem-kv-row">
          <dt>local accounts named</dt>
          <dd className="mono">{inventoryCount(inventory.accountCount)}</dd>
        </div>
        <div className="mem-kv-row">
          <dt>LSA secrets named</dt>
          <dd className="mono">{inventoryCount(inventory.secretCount)}</dd>
        </div>
        <div className="mem-kv-row">
          <dt>cached domain logons present</dt>
          <dd className="mono">{inventoryCount(inventory.cachedLogons)}</dd>
        </div>
        <div className="mem-kv-row">
          <dt>credential values recovered</dt>
          <dd className="mono">
            {inventoryCount(inventory.credentialsRecovered)}
          </dd>
        </div>
      </dl>
      <p className="mem-note">
        A cached logon is counted, not read: the count says how many cached
        domain credentials are present, and nothing about whose they are or what
        they are.
      </p>

      <h3 className="mem-subhead">Hives</h3>
      {inventory.hives.length === 0 ? (
        <p className="mem-note">
          The record lists no hive. That is not a statement that neither hive was
          resident — nothing here says which hives were looked for.
        </p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">hive</th>
              <th scope="col">reachable</th>
              <th scope="col">bins read from</th>
              <th scope="col">detail</th>
            </tr>
          </thead>
          <tbody>
            {inventory.hives.map((hive, index) => (
              <tr key={`${hive.hive ?? 'hive'}-${index}`}>
                <td className="mono">{hive.hive ?? 'not named'}</td>
                <td>
                  {hive.available == null ? (
                    <span className="badge badge-warn">not stated</span>
                  ) : hive.available ? (
                    'yes'
                  ) : (
                    <span className="badge badge-danger">no</span>
                  )}
                </td>
                <td className="mono">
                  {hive.binSource ?? 'not stated'}
                  {hive.binSourceAuthoritative === false && (
                    <span className="mem-note">
                      {' '}
                      not where this build keeps them, so a key it could not
                      reach may be present and unread
                    </span>
                  )}
                </td>
                <td>{hive.detail ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h3 className="mem-subhead">Local account names</h3>
      <p className="mem-note">
        Names and relative identifiers, read from the SAM key names. No hash was
        read for any of them.
      </p>
      {inventory.accounts.length === 0 ? (
        <p className="mem-note">
          No account name is listed on this record.
          {inventory.accountCount != null && inventory.accountCount > 0
            ? ` The record counts ${inventory.accountCount}, so the list is short of its own count.`
            : ''}
        </p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">account name</th>
              <th scope="col">rid</th>
              <th scope="col">rid corroborated</th>
              <th scope="col">key last written</th>
              <th scope="col">notes</th>
            </tr>
          </thead>
          <tbody>
            {inventory.accounts.map((account, index) => (
              <tr key={`${account.name ?? 'account'}-${index}`}>
                <td className="mono">{account.name ?? 'name not recorded'}</td>
                <td className="mono">
                  {account.rid == null ? (
                    <span
                      className="mem-note"
                      title="The key carried no readable relative identifier. That is a fact about the read, not an account without a RID."
                    >
                      not read
                    </span>
                  ) : (
                    account.rid
                  )}
                </td>
                <td>
                  {account.ridCorroborated == null ? (
                    <span className="mem-note">not stated</span>
                  ) : account.ridCorroborated ? (
                    'yes'
                  ) : (
                    <span className="badge badge-warn">
                      no key under Users names this rid
                    </span>
                  )}
                </td>
                <td className="mono">
                  {filetimeText(account.lastWriteFiletime)}
                </td>
                <td>
                  {account.notes.length === 0 ? '—' : account.notes.join('; ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h3 className="mem-subhead">LSA secret names</h3>
      <p className="mem-note">
        The names of the secrets stored on this machine. Each value is encrypted
        and was not read, so a name here says a secret of that name exists — not
        what it is.
      </p>
      {inventory.secrets.length === 0 ? (
        <p className="mem-note">
          No secret name is listed on this record.
          {inventory.secretCount != null && inventory.secretCount > 0
            ? ` The record counts ${inventory.secretCount}, so the list is short of its own count.`
            : ''}
        </p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">secret name</th>
              <th scope="col">key last written</th>
            </tr>
          </thead>
          <tbody>
            {inventory.secrets.map((secret, index) => (
              <tr key={`${secret.name ?? 'secret'}-${index}`}>
                <td className="mono">{secret.name ?? 'name not recorded'}</td>
                <td className="mono">
                  {filetimeText(secret.lastWriteFiletime)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {inventory.listings.length > 0 && (
        <>
          <h3 className="mem-subhead">Keys this survey tried to enumerate</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">key</th>
                <th scope="col">enumerated in full</th>
                <th scope="col">detail</th>
              </tr>
            </thead>
            <tbody>
              {inventory.listings.map((listing, index) => (
                <tr key={`${listing.key ?? 'key'}-${index}`}>
                  <td className="mono">{listing.key ?? 'not named'}</td>
                  <td>
                    {listing.complete == null ? (
                      <span className="mem-note">not stated</span>
                    ) : listing.complete ? (
                      'yes'
                    ) : (
                      <span className="badge badge-warn">no</span>
                    )}
                  </td>
                  <td>{listing.detail ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  )
}

/**
 * Recovered credential VALUES, masked, with the audited reveal.
 *
 * Rendered only when a record carrying a value exists. No stage in the tree
 * emits one today, and drawing this table empty would advertise a recovery
 * capability the analysis does not have.
 */
function RecoveredValues({
  records,
  revealed,
  failed,
  revealDisabled,
  onReveal,
}: {
  records: ParsedRecord[]
  revealed: Record<string, string>
  failed: Record<string, string>
  revealDisabled: boolean
  onReveal: (recordId: string) => void
}) {
  return (
    <section className="panel" aria-label="Recovered credential values">
      <h2 className="panel-title">Recovered credential values</h2>
      <div className="warn-note" role="note">
        These records carry a value that was recovered, which the inventory
        above does not. Values are masked. Revealing one is recorded in the case
        audit log against your account, and a reveal that cannot be recorded
        does not happen. Export is a separate, confirmed action and is not
        offered here.
      </div>
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">account</th>
            <th scope="col">format</th>
            <th scope="col">value</th>
            <th scope="col">derivation</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record) => {
            const value = revealed[record.id]
            const failure = failed[record.id]
            const steps = chain(record)
            return (
              <tr key={record.id}>
                <td className="mono">
                  {str(record, 'username') ?? 'account not recorded'}
                  {str(record, 'rid') && (
                    <span className="mem-note"> rid {str(record, 'rid')}</span>
                  )}
                </td>
                <td>
                  {str(record, 'hash_format') ?? (
                    <span className="badge badge-danger">
                      format not stated — do not feed this to a cracker
                    </span>
                  )}
                </td>
                <td className="mono">
                  {value != null ? (
                    <span className="mem-revealed">{value}</span>
                  ) : (
                    <>
                      <span aria-label="value masked">••••••••••••••••</span>
                      <button
                        type="button"
                        className="btn"
                        disabled={revealDisabled}
                        onClick={() => onReveal(record.id)}
                      >
                        Reveal
                      </button>
                    </>
                  )}
                  {failure != null && value == null && (
                    <div className="error-note" role="note">
                      This reveal was not recorded in the audit log, so the value
                      stays masked. ({failure})
                    </div>
                  )}
                </td>
                <td>
                  {steps.length === 0 ? (
                    <span className="mem-note">
                      The producer recorded no derivation chain. Method cannot be
                      attested for this value.
                    </span>
                  ) : (
                    <ol className="mem-chain">
                      {steps.map((step) => (
                        <li key={`${step.step}-${step.source}`}>
                          <span className="mem-step-title">{step.step}</span>
                          <span className="mono mem-note">{step.source}</span>
                        </li>
                      ))}
                    </ol>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </section>
  )
}

/** Value records that name no capture: listed, never dropped by the filter. */
function UnattributedValues({ records }: { records: ParsedRecord[] }) {
  return (
    <div className="warn-note" role="note">
      <strong>
        {records.length} credential value{records.length === 1 ? '' : 's'} could
        not be attributed to a capture.
      </strong>{' '}
      They are listed below rather than hidden by the capture filter, because a
      credential lost to a filter an examiner cannot see is worse than one shown
      with a caveat. Which capture they came from cannot be stated.
      <ul>
        {records.map((record) => (
          <li className="mono" key={record.id}>
            {str(record, 'username') ?? record.id} ·{' '}
            {str(record, 'hash_format') ?? 'format not stated'}
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * The empty state, worded from what the credential stage actually did.
 *
 * "The stores were read and nothing was in them" is a finding. It is only true
 * if a stage read them. When the coverage table says the credential stage did
 * not run — which is the case on a build that has no credential stage at all —
 * the empty page is not a finding about the capture and must not be dressed as
 * one. And in no branch does it claim that no credential was *recovered*: this
 * stage recovers none by design, so that sentence would be true of every
 * capture ever analysed and would read as a finding about this one.
 */
function NoInventory({
  pending,
  coverage,
  otherCaptureInventories,
}: {
  pending: boolean
  coverage: MemoryCoverageResponse | null | undefined
  otherCaptureInventories: number
}) {
  const stage = coverage?.stages.find(
    (entry) => entry.stage === MEMORY_CREDENTIAL_STAGE,
  )

  const elsewhere = otherCaptureInventories > 0 && (
    <p className="mem-note">
      {otherCaptureInventories} other capture
      {otherCaptureInventories === 1 ? '' : 's'} in this case{' '}
      {otherCaptureInventories === 1 ? 'has' : 'have'} an inventory. This page
      shows only the capture selected above.
    </p>
  )

  // Which of the three sentences below is true depends entirely on coverage, so
  // none of them is shown until it has arrived.
  if (pending) {
    return <div className="loading">Reading which credential stages ran…</div>
  }

  if (coverage == null) {
    return (
      <div className="warn-note" role="note">
        <strong>No credential record exists for this capture.</strong> Stage
        coverage could not be read, so whether any credential stage ran is
        unknown. This is not a finding that the capture held no credential
        store.
        {elsewhere}
      </div>
    )
  }

  if (stage == null || stage.status === 'did_not_run' || stage.status === 'failed') {
    return (
      <div className="error-note" role="note">
        <strong>No credential stage ran on this capture.</strong>{' '}
        {stage == null
          ? 'This build reports no credential stage at all, so nothing located or listed the SAM, the LSA secrets or the cached domain logons.'
          : `${stage.status_meaning} ${failureSummary(stage.failures)}`}{' '}
        An empty page is not evidence that the capture held no credential store,
        so none is shown.
        {elsewhere}
      </div>
    )
  }

  return (
    <div className="empty-state">
      <h3>No credential store was inventoried</h3>
      <p>
        The credential stage ran and reported no store on this capture. That
        covers the sources it reads — the SAM and SECURITY hives, the LSA
        secrets and the cached domain logons — and says nothing about credentials
        held only in a process that had already exited.
      </p>
      <p>
        It is also not a statement about decryption: {INVENTORY_ONLY}
      </p>
      {stage.count_is_floor && (
        <p className="mem-note">
          The stage reported its own result as a floor, so even this is a lower
          bound rather than a total.
        </p>
      )}
      {elsewhere}
    </div>
  )
}
