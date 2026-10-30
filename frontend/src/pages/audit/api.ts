import { apiFetch } from '../../api/http'
import type { AuditLogResponse } from '../../api/types'

export interface AuditLogParams {
  limit: number
  offset: number
  /** Exact-match server-side filters. */
  user?: string
  action?: string
  resource_type?: string
  /** RFC3339 timestamps. */
  from?: string
  to?: string
}

export const getAuditLog = (caseId: string, params: AuditLogParams) =>
  apiFetch<AuditLogResponse>(`/cases/${caseId}/audit_log`, {
    query: { ...params },
  })

export interface ChainVerification {
  valid: boolean
  checked: number
  broken_at: number | null
  /**
   * True only when a server-held key is configured AND every checked entry was
   * written under one. On an unkeyed entry `valid` means "internally
   * consistent", not "unaltered": anyone with database access could have
   * rewritten it and recomputed the hashes after it.
   */
  tamper_evident: boolean
  /** Entries that recomputed under a server-held key (current or retired). */
  keyed_rows: number
  /** Entries that recomputed only as a plain SHA-256 digest. */
  unkeyed_rows: number
  /**
   * Id of the first entry of the keyed run that reaches the chain head: from
   * here a passing verification is evidence of no alteration. Null when no
   * entry is keyed. A chain keyed part-way through (a key set on an existing
   * log) has this set while `tamper_evident` is false.
   */
  tamper_evident_from: number | null
  /** Why verification stopped at `broken_at`; null when valid. */
  break_reason: string | null
  /** The server's own wording of what the verdict is worth; quoted verbatim. */
  tamper_evidence_note: string
  /**
   * The chain HEAD — id and hash of the last chained entry — on a chain that
   * verified. Null when the chain is empty or broken. A hash chain cannot prove
   * that entries were not deleted from the END (the shortened chain still
   * verifies), so the head is published to be recorded OUTSIDE the database and
   * compared on a later verification: that comparison is the only thing that
   * can catch a truncated tail.
   */
  head_id: number | null
  head_hash: string | null
  /**
   * Whether any recent entry was DELETED — a separate question from whether the
   * entries present are unaltered (`valid`/`tamper_evident`). Answerable only
   * against an anchor recorded outside this database, so `anchored` is false
   * until one is supplied. Optional because a server predating this field must
   * not blank the page. `verdict` is the machine-readable form: `not_checked`
   * until an anchor is supplied, then `intact` / `truncated` / `diverged`.
   */
  completeness?: {
    anchored: boolean
    intact?: boolean
    verdict?: 'not_checked' | 'intact' | 'truncated' | 'diverged'
    expected_head_id?: number | null
    expected_head?: string | null
    note: string
  }
}

export const verifyAuditChain = (caseId: string) =>
  apiFetch<ChainVerification>(`/cases/${caseId}/audit_log/verify`)
