import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { Artifact } from '../../api/types'
import { formatCount } from '../../lib/format'
import {
  lookupOwnership,
  MAX_LOOKUP_PAGES,
  securityIdOf,
  type OwnershipRecord,
} from './ownership'

const str = (m: Record<string, unknown>, k: string): string | null =>
  typeof m[k] === 'string' ? (m[k] as string) : null
const num = (m: Record<string, unknown>, k: string): number | null =>
  typeof m[k] === 'number' ? (m[k] as number) : null

const hex = (n: number, width = 0) =>
  `0x${n.toString(16).toUpperCase().padStart(width, '0')}`

/** `S-1-5-18 (Local System)`, or the bare SID when it is not in the table. */
function principal(sid: string | null, name: string | null): string {
  if (!sid) return 'none set in the descriptor'
  return name ? `${sid} (${name})` : sid
}

/** One ACE as a row. Every field shown is one the descriptor record carries. */
function AceRow({ ace }: { ace: Record<string, unknown> }) {
  const effect = str(ace, 'effect') ?? str(ace, 'ace_type_name') ?? '?'
  const who = str(ace, 'sid')
    ? principal(str(ace, 'sid'), str(ace, 'sid_name'))
    : 'no trustee decoded'
  const rights =
    str(ace, 'access_mask_desc') ??
    (num(ace, 'access_mask') != null ? hex(num(ace, 'access_mask') as number, 8) : '—')
  const flags = Array.isArray(ace.flag_names) ? (ace.flag_names as string[]) : []
  const error = str(ace, 'ace_error')
  return (
    <li className="av-own-ace">
      <span className={`av-own-effect av-own-${effect}`}>{effect}</span>{' '}
      <span className="mono">{who}</span> — {rights}
      {ace.inherited === true && <span className="av-phys-badge">inherited</span>}
      {flags.length > 0 && (
        <span className="av-phys-muted"> [{flags.join(', ')}]</span>
      )}
      {error && <span className="error-note"> {error}</span>}
    </li>
  )
}

/** A DACL or SACL: its state, then its ACEs as the record lists them. */
function AclBlock({
  label,
  prefix,
  m,
}: {
  label: string
  prefix: 'dacl' | 'sacl'
  m: Record<string, unknown>
}) {
  const state = str(m, `${prefix}_state`)
  const aces = Array.isArray(m[prefix])
    ? (m[prefix] as Record<string, unknown>[])
    : []
  const truncated = m[`${prefix}_truncated`] === true
  let stateNote: string | null = null
  if (state === 'absent')
    stateNote =
      prefix === 'dacl'
        ? 'No DACL: every principal has full access.'
        : 'No SACL: nothing is audited.'
  else if (state === 'null')
    stateNote =
      prefix === 'dacl'
        ? 'NULL DACL: every principal has full access.'
        : 'NULL SACL.'
  else if (state === 'unreadable')
    stateNote = `Unreadable${str(m, `${prefix}_error`) ? `: ${str(m, `${prefix}_error`)}` : ''}.`
  else if (state === 'present' && aces.length === 0)
    stateNote =
      prefix === 'dacl'
        ? 'Empty DACL: it grants nobody anything.'
        : 'Empty SACL.'
  if (state == null) return null
  return (
    <div className="av-own-acl" data-testid={`av-own-${prefix}`}>
      <div className="av-own-row">
        <span className="av-label">{label}</span>
        <span>{state}</span>
      </div>
      {stateNote && <p className="av-phys-muted">{stateNote}</p>}
      {aces.length > 0 && (
        <ol className="av-own-aces">
          {aces.map((ace, i) => (
            <AceRow key={i} ace={ace} />
          ))}
        </ol>
      )}
      {truncated && (
        <p className="error-note">
          ACL truncated
          {str(m, `${prefix}_truncation_reason`)
            ? `: ${str(m, `${prefix}_truncation_reason`)}`
            : ''}
          . Entries past the cut are not shown and are not known.
        </p>
      )}
    </div>
  )
}

/** Where the descriptor came from: the store, the hash as read, the offset. */
function Provenance({
  caseId,
  d,
}: {
  caseId: string
  d: OwnershipRecord
}) {
  const m = d.metadata
  const hash = num(m, 'descriptor_hash')
  const offset = num(m, 'sds_offset')
  return (
    <p className="av-own-source" data-testid="av-own-source">
      From{' '}
      <Link to={`/cases/${caseId}/artifacts/${d.id}`}>
        <code>{str(m, 'source_stream') ?? '$Secure:$SDS'}</code>
      </Link>
      , security id {String(m.security_id)}
      {hash != null && <>, hash {hex(hash, 8)} (as read, not recomputed)</>}
      {offset != null && (
        <>
          , at stream offset {hex(offset)} ({formatCount(offset)})
        </>
      )}
      .
      {m.recovered_from_mirror === true && (
        <> Recovered from the 256 KiB mirror copy; the primary copy did not decode.</>
      )}
      {m.sds_offset_mismatch === true && (
        <> The store&rsquo;s declared offset for this entry disagrees with where it was found.</>
      )}
    </p>
  )
}

function Found({ caseId, d }: { caseId: string; d: OwnershipRecord }) {
  const m = d.metadata
  const error = str(m, 'security_descriptor_error')
  if (error) {
    return (
      <>
        <Provenance caseId={caseId} d={d} />
        <p className="error-note" data-testid="av-own-undecodable">
          The descriptor with this id is in the store but could not be decoded:{' '}
          {error}. The owner and ACL are unknown, not absent.
        </p>
      </>
    )
  }
  const owner = str(m, 'owner_error')
    ? `unreadable: ${str(m, 'owner_error')}`
    : principal(str(m, 'owner_sid'), str(m, 'owner_name'))
  const group = str(m, 'group_error')
    ? `unreadable: ${str(m, 'group_error')}`
    : principal(str(m, 'group_sid'), str(m, 'group_name'))
  return (
    <>
      <div className="av-own-row">
        <span className="av-label">Owner</span>
        <span className="mono" data-testid="av-own-owner">
          {owner}
        </span>
      </div>
      <div className="av-own-row">
        <span className="av-label">Group</span>
        <span className="mono">{group}</span>
      </div>
      {str(m, 'integrity_level') && (
        <div className="av-own-row">
          <span className="av-label">Integrity level</span>
          <span>{str(m, 'integrity_level')}</span>
        </div>
      )}
      <AclBlock label="DACL" prefix="dacl" m={m} />
      <AclBlock label="SACL" prefix="sacl" m={m} />
      {m.descriptor_partial === true && (
        <p className="error-note">
          Parts of this descriptor would not decode; what is shown is what did.
        </p>
      )}
      <Provenance caseId={caseId} d={d} />
      <p className="av-phys-muted">
        A bare SID is not in the well-known table; account names are not read
        from the SAM.
      </p>
    </>
  )
}

/**
 * Owner, group and ACL of an NTFS file, looked up by its `security_id` in the
 * same volume's `$Secure:$SDS` store (HUNT-178). Every state says what was and
 * was not established; none renders as "no owner".
 */
export function OwnershipSection({
  caseId,
  artifact,
}: {
  caseId: string
  artifact: Artifact
}) {
  const securityId = securityIdOf(artifact)
  const query = useQuery({
    queryKey: ['artifact-ownership', caseId, artifact.id, securityId],
    queryFn: () => lookupOwnership(caseId, artifact),
    enabled: securityId != null && securityId !== 0,
    retry: false,
    staleTime: Infinity,
  })

  const head = <h3>Owner and permissions</h3>
  if (securityId == null) {
    return (
      <div className="av-own" data-testid="av-own">
        {head}
        <p className="av-phys-muted" data-testid="av-own-no-id">
          This entry carries no NTFS <code>security_id</code>. Only the NTFS MFT
          parser publishes one, from a 72-byte (NTFS 3.x){' '}
          <code>$STANDARD_INFORMATION</code>; a FAT, ext4 or other file-system
          entry, an NTFS 1.x record, or a file inside a container has none, so
          no owner or ACL is looked up.
        </p>
      </div>
    )
  }
  if (securityId === 0) {
    return (
      <div className="av-own" data-testid="av-own">
        {head}
        <p className="av-phys-muted" data-testid="av-own-zero">
          <code>security_id</code> is 0, as read from the record. NTFS numbers
          <code> $SDS</code> descriptors from 256, so 0 names no descriptor and
          no owner or ACL can be joined.
        </p>
      </div>
    )
  }
  if (query.isPending) {
    return (
      <div className="av-own" data-testid="av-own">
        {head}
        <p className="av-phys-muted">Looking up security id {securityId}…</p>
      </div>
    )
  }
  if (query.isError) {
    return (
      <div className="av-own" data-testid="av-own">
        {head}
        <p className="error-note" data-testid="av-own-error">
          The descriptor for security id {securityId} could not be looked up:{' '}
          {(query.error as Error).message}. Nothing here says the file has no
          owner.
        </p>
      </div>
    )
  }

  const r = query.data
  let body: ReactNode
  switch (r.state) {
    case 'no-id':
    case 'zero':
      body = null
      break
    case 'no-volume':
      body = (
        <p className="av-phys-muted" data-testid="av-own-no-volume">
          Security id {securityId}, but this entry has no parent volume to scope
          the lookup to, and ids from different volumes are unrelated.
        </p>
      )
      break
    case 'no-store':
      body = (
        <p className="error-note" data-testid="av-own-no-store">
          Security id {securityId}. No <code>$Secure:$SDS</code> store record
          from this file&rsquo;s volume is in the case, so its descriptors were
          not examined: the MFT parser did not resolve <code>$Secure</code>, or
          the descriptor module did not run on it. The owner is unknown here, not
          absent.
          {r.storesCapped &&
            ` Only the first ${formatCount(MAX_LOOKUP_PAGES * 500)} store records in the case were checked.`}
        </p>
      )
      break
    case 'store-unread': {
      const m = r.store.metadata
      body = (
        <div data-testid="av-own-store-unread">
          <p className="error-note">
            Security id {securityId}. This volume&rsquo;s{' '}
            <Link to={`/cases/${caseId}/artifacts/${r.store.id}`}>
              <code>$Secure:$SDS</code> store
            </Link>{' '}
            was not read
            {str(m, 'read_incomplete') ? ` (${str(m, 'read_incomplete')})` : ''}
            , so no descriptor could be looked up.
          </p>
          {str(m, 'content_incomplete_detail') && (
            <p className="av-phys-muted">{str(m, 'content_incomplete_detail')}</p>
          )}
        </div>
      )
      break
    }
    case 'not-found': {
      const m = r.store.metadata
      const partial =
        m.inventory_incomplete === true || m.store_listing_incomplete === true
      body = (
        <div data-testid="av-own-not-found">
          <p className={partial ? 'error-note' : 'av-phys-muted'}>
            Security id {securityId} is not among the{' '}
            {num(m, 'unique_security_ids') != null
              ? formatCount(num(m, 'unique_security_ids') as number)
              : ''}{' '}
            descriptors decoded from this volume&rsquo;s{' '}
            <Link to={`/cases/${caseId}/artifacts/${r.store.id}`}>
              <code>$Secure:$SDS</code> store
            </Link>
            .
            {partial
              ? ' That listing is not the whole store, so the id is not shown to be absent from the volume.'
              : ' The store was read whole; the id names no descriptor in it.'}
            {r.candidatesCapped &&
              ` Only the first ${formatCount(MAX_LOOKUP_PAGES * 500)} candidate records were checked.`}
          </p>
          {partial && str(m, 'inventory_incomplete_detail') && (
            <p className="av-phys-muted">{str(m, 'inventory_incomplete_detail')}</p>
          )}
        </div>
      )
      break
    }
    case 'found':
      body = <Found caseId={caseId} d={r.descriptor} />
      break
  }

  return (
    <div className="av-own" data-testid="av-own">
      {head}
      {body}
    </div>
  )
}
