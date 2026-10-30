import { apiFetch } from '../../api/http'
import type { Artifact, Uuid } from '../../api/types'

/**
 * The owner and ACL of an NTFS file, joined from `$Secure:$SDS` (HUNT-178).
 *
 * NTFS 3.x keeps no descriptor in the file's MFT record; its 72-byte
 * `$STANDARD_INFORMATION` carries a `security_id`, which the MFT parser
 * publishes on the FileEntry, and `seance_plugin_secure_sds` publishes one
 * `NtfsSecurityDescriptor` record per unique id in the volume's store. The key
 * means nothing across volumes, so the join is scoped: a descriptor counts only
 * when it hangs under the `$Secure:$SDS` stream entry whose parent is this
 * file's own parent — the volume (or bare `$MFT`) the MFT parser read both from.
 *
 * Everything here goes through the existing `/records` listing. The store
 * records are few (one per volume), so they are listed by type across the case
 * and each is placed by its stream entry's parent; the descriptor is then
 * searched for under that stream entry alone — a subtree of one store — by the
 * listing's substring search on `security_id`, and matched exactly here,
 * because `256` is also a substring of `1256`.
 */

export const DESCRIPTOR_TYPE = 'NtfsSecurityDescriptor'
export const STORE_TYPE = 'NtfsSecurityDescriptorStore'

export interface OwnershipRecord {
  id: Uuid
  parent_id: Uuid | null
  artifact_type: string
  metadata: Record<string, unknown>
}

interface RecordsPage {
  records: OwnershipRecord[]
  total: number
}

const PAGE_SIZE = 500
/** Pages of store records or descriptor candidates read before stopping. */
export const MAX_LOOKUP_PAGES = 20

/** Drain a records listing up to the page cap; `capped` when it stopped short. */
async function drainRecords(
  caseId: Uuid,
  query: Record<string, string | number>,
): Promise<{ records: OwnershipRecord[]; capped: boolean }> {
  const records: OwnershipRecord[] = []
  for (let page = 1; page <= MAX_LOOKUP_PAGES; page += 1) {
    const resp = await apiFetch<RecordsPage>(`/cases/${caseId}/records`, {
      query: { ...query, page, page_size: PAGE_SIZE },
    })
    records.push(...resp.records)
    if (resp.records.length < PAGE_SIZE || records.length >= resp.total) {
      return { records, capped: false }
    }
  }
  return { records, capped: true }
}

/** What the lookup found for one file. */
export type OwnershipLookup =
  | { state: 'no-id' }
  | { state: 'zero' }
  | { state: 'no-volume' }
  | { state: 'no-store'; securityId: number; storesCapped: boolean }
  | {
      state: 'store-unread'
      securityId: number
      store: OwnershipRecord
    }
  | {
      state: 'not-found'
      securityId: number
      store: OwnershipRecord
      candidatesCapped: boolean
    }
  | {
      state: 'found'
      securityId: number
      store: OwnershipRecord
      descriptor: OwnershipRecord
    }

/** The file's `security_id`, or null when the entry does not carry one. */
export function securityIdOf(artifact: Artifact): number | null {
  const v = artifact.metadata.security_id
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 ? v : null
}

/** True for a store record that says none of its bytes were read. */
export function storeWasNotRead(store: OwnershipRecord): boolean {
  const m = store.metadata
  return m.read_incomplete != null && m.bytes_scanned === 0
}

/**
 * Resolve a file's descriptor. Throws on a request failure — the caller says
 * the lookup failed, which is not any of the states above.
 */
export async function lookupOwnership(
  caseId: Uuid,
  artifact: Artifact,
): Promise<OwnershipLookup> {
  const securityId = securityIdOf(artifact)
  if (securityId == null) return { state: 'no-id' }
  if (securityId === 0) return { state: 'zero' }
  const volumeId = artifact.parent_id
  if (volumeId == null) return { state: 'no-volume' }

  const stores = await drainRecords(caseId, { type: STORE_TYPE })
  // Place each store by the parent of the stream entry it hangs under.
  const ours: OwnershipRecord[] = []
  const streamParents = new Map<Uuid, Uuid | null>()
  for (const store of stores.records) {
    const streamId = store.parent_id
    if (streamId == null) continue
    if (!streamParents.has(streamId)) {
      const stream = await apiFetch<Artifact>(
        `/cases/${caseId}/artifacts/${streamId}`,
      )
      streamParents.set(streamId, stream.parent_id)
    }
    if (streamParents.get(streamId) === volumeId) ours.push(store)
  }
  if (ours.length === 0) {
    return { state: 'no-store', securityId, storesCapped: stores.capped }
  }

  const read = ours.filter((s) => !storeWasNotRead(s))
  if (read.length === 0) {
    return { state: 'store-unread', securityId, store: ours[0] }
  }

  let candidatesCapped = false
  for (const store of read) {
    const candidates = await drainRecords(caseId, {
      type: DESCRIPTOR_TYPE,
      source_id: store.parent_id as Uuid,
      q: String(securityId),
      q_keys: 'security_id',
    })
    candidatesCapped ||= candidates.capped
    const descriptor = candidates.records.find(
      (r) => r.metadata.security_id === securityId,
    )
    if (descriptor) {
      return { state: 'found', securityId, store, descriptor }
    }
  }
  return { state: 'not-found', securityId, store: read[0], candidatesCapped }
}
