import { apiFetch } from '../../api/http'
import { supplyCredential } from '../../api/resources'
import type { Uuid } from '../../api/types'

// Local contracts for the dashboard stats endpoints.

export interface SourceStat {
  source_artifact_id: Uuid
  name: string
  artifact_count: number
  /**
   * False when the root-artifact walk did not produce a name for this source
   * and `name` is its UUID. The server sends it so an unnamed source can be
   * told apart from one whose name this response failed to fetch; a card that
   * ignored it would show a bare UUID with nothing to say why.
   */
  name_resolved?: boolean
  /**
   * The source's acquisition state, read off its own record: `verifying` while
   * the acquisition hash is still running, `baseline_recorded` once it is on
   * file, `acquisition_failed` when no baseline could be established at all.
   *
   * It travels with the count because it is what makes the count readable. A
   * source still being hashed has not finished being processed, so its zero
   * means "not yet"; a source with no baseline is an exhibit the case holds and
   * cannot vouch for. `null` is absent, never a default — an exhibit ingested
   * before acquisition states existed carries none, and so does one whose
   * record the name walk did not reach (`name_resolved: false`). Neither is a
   * statement that no baseline was recorded.
   */
  integrity_state?: string | null
  /** Why the acquisition baseline could not be established, when it could not. */
  acquisition_error?: string | null
  /**
   * Whether the walk that produced `artifact_count` ever ended (HUNT-113):
   * `completed`, `interrupted` (a stopped process never finished it),
   * `cancelled` (the examiner stopped it). `null` or absent means no run was
   * recorded for the source — an exhibit ingested before runs were recorded —
   * which is not a statement that its walk finished.
   */
  processing_state?: string | null
  /**
   * The sentence the source carries about an unfinished walk, in the words
   * stamped on its own record. Present only when `processing_state` says the
   * walk did not end.
   */
  processing_note?: string | null
}

export interface SourceStatsResponse {
  sources: SourceStat[]
  /**
   * The listing disclosure this endpoint carries, and it is about the NAMES,
   * not about the sources or their counts: the counts come from their own
   * complete aggregate query, while the names come from a paged walk of the
   * case's root artifacts that can be capped or hit rows that will not decode.
   */
  inventory_incomplete?: boolean
  inventory_incomplete_reason?: string | null
  /**
   * Root-artifact rows read and not decoded. `null` means the query has no
   * channel for the fact, which must never be read as zero.
   */
  undecodable?: number | null
}

export interface FileSizeBucket {
  /** Bucket p covers file sizes in [2^p, 2^(p+1)). */
  pow2: number
  count: number
}

export interface FileSizeStatsResponse {
  buckets: FileSizeBucket[]
}

export const getSourceStats = (caseId: Uuid) =>
  apiFetch<SourceStatsResponse>(`/cases/${caseId}/stats/sources`)

// --- the mobile source-type triage label (ROADMAP §1.4) --------------------

/** One quoted marker record a kind rests on. */
export interface SourceKindBasisRecord {
  record_id: Uuid
  record_type: string
  corroborated_by: { field: string; value: string } | null
  source_file: string | null
}

export interface SourceKindRow {
  source_artifact_id: Uuid
  name: string
  /**
   * `android_device` | `android_backup` | `ios_device` | `ios_backup` |
   * `mixed` | `none_recognised` | `not_assessed`. `none_recognised` is sent
   * only for a source whose walk completed and produced records; every other
   * absence is `not_assessed`, with `not_assessed_reason`.
   */
  label: string
  kinds: string[]
  basis: { kind: string; marker_records: number; records: SourceKindBasisRecord[] }[]
  /** Whether the absence of further kinds is a statement. */
  assessed: boolean
  not_assessed_reason: string | null
  walk_state: string
  has_records: boolean | null
  capped: boolean
}

export interface SourceKindsResponse {
  sources: SourceKindRow[]
  looked_for: {
    record_type: string
    kind: string
    /** A field that must hold one of `one_of` for the record to count. */
    requires_field?: { field: string; one_of: string[] } | null
    /** Path fragments, one of which the store's path must contain. */
    requires_path_containing?: string[]
    written_by: string
  }[]
  capped_types: string[]
  /** Marker records (or unread mobile stores) whose source could not be reached.
   *  Any at all and no source is `none_recognised`: the server says why in each
   *  row's `not_assessed_reason`. */
  unattributed: number
  /** Every listed candidate whose source could not be reached, markers or not. */
  unattributed_candidates?: number
  message: string
  roots_listed_whole?: boolean
}

/** Its own endpoint, so the three screens reading `/stats/sources` never pay for it. */
export const getSourceKinds = (caseId: Uuid) =>
  apiFetch<SourceKindsResponse>(`/cases/${caseId}/source_kinds`)

export const getFileSizeStats = (caseId: Uuid) =>
  apiFetch<FileSizeStatsResponse>(`/cases/${caseId}/stats/file_sizes`)

// --- the queue of recoverable problems (ROADMAP §2.11) ---------------------

/** One artifact a recoverable problem is blocking. */
export interface BlockedArtifact {
  /** The status record that reports the problem. */
  artifact_id: Uuid
  /**
   * The artifact a module would be re-run on: the reported record's parent
   * where it has one, else the record itself. A status record has no bytes, so
   * re-running a decryptor on it would do nothing.
   */
  target_id: Uuid
  name: string | null
  detail: string | null
}

/**
 * What can be done, as a token the panel switches on.
 *
 * `supply_secret` is the only one that gets a field. `route` says which
 * endpoint takes the secret; the only one is `credential`, which hands it to
 * the module for one run without touching metadata, holds it zeroed, and
 * audits it by kind and outcome (HUNT-120 — BitLocker, LUKS, 7z, Signal, and
 * since SEC-204 the iOS backup; `run_module`'s `secrets` map is retired). The credential behind
 * `supply_at_startup` is read once when the process starts, so a per-artifact
 * secret could not reach the decryptor, and offering one would be a dead
 * affordance — an examiner who typed a password into it would conclude the
 * password was wrong. No remedy in this build uses it now.
 */
export type RemedyAction =
  | {
      kind: 'supply_secret'
      module_id: string
      /** The credential kind. */
      secret_key: string
      label: string
      route: 'credential'
      /** Other kinds of secret the same row accepts, each with its label. */
      alternatives: { secret_key: string; label: string }[]
    }
  | { kind: 'supply_at_startup'; flag: string; env: string }
  | { kind: 'unsupported' }

export interface AttentionItem {
  record_type: string
  /** `LUKS` / `BitLocker`, where one record type reports more than one thing. */
  scheme: string | null
  reason: string
  /** Artifacts in this group, case-wide. */
  count: number
  examples: BlockedArtifact[]
  /** More exist than are listed, so `examples` is a subset. */
  examples_truncated: boolean
  /** `null` where this build carries no instruction for the blockage. */
  problem: string | null
  guidance: string | null
  action: RemedyAction | null
  unrecognised_note: string | null
}

export interface AttentionQueue {
  items: AttentionItem[]
  groups: number
  artifacts: number
  /** How many of them something can actually be done about. */
  actionable_artifacts: number
  reasons_examined: string[]
  /**
   * Why an empty queue is not a statement about the examination. Rendered
   * verbatim: rewriting it in the client would let the two drift.
   */
  scope_note: string
}

/** The recoverable problems in a case, each carrying what to do about it. */
export const getAttentionQueue = (caseId: Uuid) =>
  apiFetch<AttentionQueue>(`/cases/${caseId}/attention`)

/** Re-exported so the panel has one import surface (HUNT-120, SEC-204). */
export { supplyCredential }
