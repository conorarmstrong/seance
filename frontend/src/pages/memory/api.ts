import { apiFetch } from '../../api/http'
import { getRecords, type ParsedRecord } from '../analysis/api'

/**
 * Typed client for the memory-analysis endpoints under
 * `/api/v1/cases/:caseId/memory/…`.
 *
 * These types mirror `seance_api/src/memory.rs` exactly; nothing here invents a
 * field. Two properties of that contract shape everything above it.
 *
 * **Every stage answers in an envelope, not as a bare array.** The envelope
 * carries `status`, `stage_ran`, `count_is_floor` and the failure records that
 * explain an absence. That is what lets the UI keep "the scan found nothing"
 * apart from "the scan never ran" — the single distinction this whole surface
 * exists to preserve.
 *
 * **Result rows arrive as opaque `data` blobs.** The server hands back the
 * analysis metadata intact rather than reshaping it, so nothing is lost in
 * translation. Decoding those blobs into view rows is `normalize.ts`'s job, and
 * it is done there because the blobs use tagged fields (`known` /
 * `not_declared` / `unavailable` / `not_applicable`) that must never be
 * flattened into a plain value or a plain blank.
 *
 * **Addresses: prefer the `_hex` key.** JSON numbers are IEEE doubles and every
 * x64 kernel address is above 2^53, so a pointer sent as a number can arrive
 * here already rounded — by up to about a kilobyte — and no amount of
 * formatting can recover the lost bits. The analysis therefore emits every
 * address twice: `base` as a number, for the consumers that have always read
 * it, and `base_hex` as an exact string. A renderer that quotes a pointer must
 * read the `_hex` sibling when it is present and fall back to `toHex` only when
 * it is not.
 */

/** How one discovered fact about the image was established. Weakest last. */
export type EvidenceGrade = 'confirmed' | 'validated' | 'scanned' | 'supplied'

/**
 * What one stage's response says about itself.
 *
 * `did_not_run` is the value the API exists to make expressible: it is not
 * "found nothing", and it must never render as an empty table.
 * `not_determined` appears only on per-process views, when the search for a PID
 * stopped at a cap before it had seen everything.
 */
export type StageStatus =
  | 'complete'
  | 'incomplete'
  | 'failed'
  | 'did_not_run'
  | 'not_determined'

/** A record saying a stage could not run, and why. */
export interface StageFailure {
  id: string
  image_id: string | null
  name: string | null
  /** Which stage failed. Null when the producer did not say. */
  stage: string | null
  /** Several stages skipped together because a prerequisite failed. */
  stages: string[] | null
  /** The failure text, in the producer's words. */
  failure: string | null
  pid: number | null
  process_name: string | null
  profile_evidence: string | null
}

/** One result record, with the analysis metadata kept intact under `data`. */
export interface StageRecord {
  id: string
  image_id: string | null
  data: Record<string, unknown>
}

/**
 * One stage's results plus everything needed to say how much of the stage ran.
 *
 * `record_count` is the database's own count, so `count_is_floor` distinguishes
 * "this is the total" from "this is at least this many" without guessing from a
 * short page.
 */
export interface StageEnvelope {
  stage: string
  record_type: string
  /**
   * Every record type this stage's rows can arrive as, primary first.
   *
   * A stage can produce more than one shape of record over its life, and all of
   * them are that stage having run.
   *
   * Optional because an API build older than the field does not send it. Absent
   * means "only `record_type`", never "no record types".
   */
  record_types?: string[]
  /** One sentence saying what an examiner learns from this stage. */
  describes: string
  per_process: boolean
  image_id: string | null
  scoped_to_image: boolean
  stage_ran: boolean
  status: StageStatus
  status_meaning: string
  record_count: number
  records_returned: number
  records_truncated: boolean
  rows_incomplete: number
  rows_completeness_ungraded: number
  count_is_floor: boolean
  failures: StageFailure[]
  failures_truncated: boolean
  records: StageRecord[]
  /** Per-process views only: the PID asked for. */
  pid?: number
  /** Per-process views only: how many records of this type exist in total. */
  stage_records_total?: number
  /** Per-process views only: false when the search stopped at a cap. */
  search_exhaustive?: boolean
  records_scanned?: number
  /** Per-process views only, and only on a capped miss. */
  status_meaning_override?: string
}

/** Whether an image has been analysed at all, and what that means. */
export type AnalysisState = 'not_analysed' | 'discovery_failed' | 'analysed'

/** The profile summary carried on each row of the image list. */
export interface ImageProfileSummary {
  record_id: string
  established: boolean
  analysed_os: string | null
  analysed_by: string | null
  pdb: string | null
  nt_build: number | null
  weakest_evidence: EvidenceGrade | null
  /** Null means the producer did not say — not the same as "not verified". */
  symbols_verified: boolean | null
  failure: string | null
}

/** One memory capture in the case. */
export interface MemoryImageSummary {
  image_id: string
  /**
   * The evidence this capture was decoded from — the raw image, or the file
   * inside a filesystem the dump was found in.
   *
   * The navigator hides ParsedRecord children, so an examiner browsing the
   * physical tree sees that file and never the MemoryImage record. This is what
   * lets the artifact they ARE looking at offer a way into its own analysis.
   * Null on an older API build, which must read as "cannot link", never as
   * "this capture came from nowhere".
   */
  source_artifact_id: string | null
  name: string | null
  image_format: string | null
  architecture: string | null
  /** Bytes actually addressable through the decoded layer. */
  addressable_bytes: number | null
  file_bytes: number | null
  /** Size the container claims. A mismatch with `file_bytes` is a finding. */
  declared_size: number | null
  size_mismatch: boolean
  decode_failed: boolean
  /**
   * Whether the container declared its content complete. Null means it did not
   * say, which is not the same as complete and must not render as such.
   */
  content_complete: boolean | null
  content_complete_known: boolean
  incomplete: unknown
  analysis_state: AnalysisState
  analysis_state_meaning: string
  profile: ImageProfileSummary | null
  stage_failures: number
}

export interface MemoryImagesResponse {
  case_id: string
  images: MemoryImageSummary[]
  image_count: number
  images_truncated: boolean
  /** False when a per-image summary may understate what the image holds. */
  summaries_complete: boolean
}

/** One discovered fact with the grade behind it. */
export interface GradedFact {
  /** `directory_table_base`, `kernel_base`, `kdbg`. */
  fact: string
  present: boolean
  /**
   * The raw value, promoted verbatim out of the profile record. A 64-bit
   * address arrives as a JSON number and may therefore be rounded; see the note
   * on `_hex` keys at the top of this file.
   */
  value: unknown
  evidence: EvidenceGrade | null
  /** False when the value is present but nobody graded it. */
  graded: boolean
}

/** The honesty surface of the profile screen. */
export interface EvidenceBlock {
  weakest_evidence: EvidenceGrade | null
  weakest_evidence_known: boolean
  symbols_verified: boolean | null
  symbols_verified_known: boolean
  symbols_state: string | null
  symbols_provenance: unknown
  facts: GradedFact[]
  /** Facts that are present but carry no grade. Each one is a hole. */
  ungraded_facts: number
  note: string
}

export interface MemoryProfileResponse {
  case_id: string
  image_id: string
  /** The image record's own metadata, verbatim. */
  image: Record<string, unknown>
  analysis_state: AnalysisState
  analysis_state_meaning: string
  record_id?: string
  profile_established: boolean
  /** The profile record's metadata, or null when none exists. */
  profile: Record<string, unknown> | null
  weakest_evidence?: EvidenceGrade | null
  symbols_verified?: boolean | null
  symbols_verified_known?: boolean
  /** Null when no profile was established: grading absent facts would lie. */
  evidence: EvidenceBlock | null
  discovery: unknown
  failure?: string | null
  symbol_dirs_searched?: string[] | null
}

/** One stage's line in the coverage table. */
export interface CoverageStage {
  stage: string
  record_type: string
  /** As on {@link StageEnvelope}; absent from an API build older than it. */
  record_types?: string[]
  describes: string
  per_process: boolean
  /**
   * Whether the analysis that ran against this capture says it has this stage.
   *
   * False means the build that produced these records predates the stage, so
   * `did_not_run` is a fact about the build rather than about the evidence.
   * Absent means this API build does not report the distinction at all, which
   * is not the same as `false` and must not be rendered as it.
   */
  declared_by_analysis?: boolean
  /**
   * False for a stage this build of the API has no row for: the row was built
   * from the analysis's own manifest, `describes` is the analysis's sentence,
   * and there is no dedicated route for it. Such a stage is listed rather than
   * dropped, because a stage absent from coverage reads as nothing to find.
   */
  described_by_api?: boolean
  stage_ran: boolean
  status: StageStatus
  status_meaning: string
  record_count: number
  rows_examined: number
  /** False when the tally cap bit, so completeness rests on a sample. */
  completeness_established_for_all_rows: boolean
  rows_incomplete: number
  rows_completeness_ungraded: number
  count_is_floor: boolean
  failures: StageFailure[]
}

export interface MemoryCoverageResponse {
  case_id: string
  image_id: string | null
  scoped_to_image: boolean
  stages: CoverageStage[]
  status_by_stage: Record<string, StageStatus>
  summary: {
    complete: number
    incomplete: number
    failed: number
    did_not_run: number
    total_stages: number
  }
  /** Failures naming a stage this build does not know: listed, never dropped. */
  unattributed_failures: StageFailure[]
  failures_truncated: boolean
  coverage_complete: boolean
  /** How many stages the analysis's own manifest named. */
  stages_declared_by_analysis?: number
  /**
   * False when no analysis manifest was found for this capture, so the stage
   * list here is only the stages this build of the API knows of. Not evidence
   * that the analysis ran nothing else. Absent when the API build predates the
   * manifest, which again is not `false`.
   */
  analysis_declared_its_stages?: boolean
  note: string
}

/**
 * The process list and the tree built from it.
 *
 * Returned together because they fail together: a tree with no list behind it
 * is not a shorter tree, it is no tree at all.
 */
export interface MemoryProcessesResponse {
  case_id: string
  image_id: string | null
  list: StageEnvelope
  tree: StageEnvelope
}

const base = (caseId: string) => `/cases/${caseId}/memory`

/** Every memory capture in the case, for the capture selector. */
export const getMemoryImages = (caseId: string) =>
  apiFetch<MemoryImagesResponse>(`${base(caseId)}/images`)

/** Identification, layer facts, symbol provenance and evidence grades. */
export const getMemoryProfile = (caseId: string, imageId: string) =>
  apiFetch<MemoryProfileResponse>(`${base(caseId)}/profile/${imageId}`)

/** Which analysis stages ran, which did not, and why. */
export const getMemoryCoverage = (caseId: string, imageId: string) =>
  apiFetch<MemoryCoverageResponse>(`${base(caseId)}/coverage`, {
    query: { image: imageId },
  })

/** The active process list and the tree derived from it. */
export const getMemoryProcesses = (caseId: string, imageId: string) =>
  apiFetch<MemoryProcessesResponse>(`${base(caseId)}/processes`, {
    query: { image: imageId },
  })

/** Which listing saw each process and which did not — the concealment table. */
export const getMemoryCrossview = (caseId: string, imageId: string) =>
  apiFetch<StageEnvelope>(`${base(caseId)}/crossview`, {
    query: { image: imageId },
  })

/** One process's virtual address descriptors. */
export const getProcessVads = (caseId: string, imageId: string, pid: number) =>
  apiFetch<StageEnvelope>(`${base(caseId)}/processes/${pid}/vads`, {
    query: { image: imageId },
  })

/** One process's handle table. */
export const getProcessHandles = (
  caseId: string,
  imageId: string,
  pid: number,
) =>
  apiFetch<StageEnvelope>(`${base(caseId)}/processes/${pid}/handles`, {
    query: { image: imageId },
  })

/** One process's loaded user-mode modules. */
export const getProcessModules = (
  caseId: string,
  imageId: string,
  pid: number,
) =>
  apiFetch<StageEnvelope>(`${base(caseId)}/processes/${pid}/modules`, {
    query: { image: imageId },
  })

/** Network endpoints and connections recovered from memory. */
export const getMemoryNetwork = (caseId: string, imageId: string) =>
  apiFetch<StageEnvelope>(`${base(caseId)}/network`, {
    query: { image: imageId },
  })

/** Windows services as they stood in memory. */
export const getMemoryServices = (caseId: string, imageId: string) =>
  apiFetch<StageEnvelope>(`${base(caseId)}/services`, {
    query: { image: imageId },
  })

/** Registry hives mapped into kernel memory, including volatile-only hives. */
export const getMemoryHives = (caseId: string, imageId: string) =>
  apiFetch<StageEnvelope>(`${base(caseId)}/registry/hives`, {
    query: { image: imageId },
  })

/** Process-image tampering signals: hollowing, ghosting, unbacked executable memory. */
export const getMemoryTampering = (caseId: string, imageId: string) =>
  apiFetch<StageEnvelope>(`${base(caseId)}/tampering`, {
    query: { image: imageId },
  })

/**
 * Record that an examiner revealed one credential, and get the value back.
 *
 * Revealing a recovered secret is an evidential act, so it is a server round
 * trip rather than a client-side toggle: the server writes the hash-chained
 * audit event and only then returns the value. If this call fails the value
 * stays masked, because a reveal nobody can attest to must not happen.
 *
 * Served by `reveal_memory_credential` in `seance_api/src/memory.rs`.
 */
export interface CredentialRevealResponse {
  value: string
  /**
   * Always null: the audit writer does not return the row id it wrote. The
   * event is in the case audit log against the examiner's account, and this
   * field claims no id an examiner could not look up.
   */
  audit_event_id: string | null
}

export const revealCredential = (caseId: string, recordId: string) =>
  apiFetch<CredentialRevealResponse>(
    `${base(caseId)}/credentials/${recordId}/reveal`,
    { method: 'POST' },
  )

/**
 * Credential material in memory: what was found, and what was recovered.
 *
 * Two record types, deliberately kept apart, because they are two different
 * claims:
 *
 * * **`MemoryCredentials`** — the *inventory*. Which credential stores were
 *   resident, which local accounts exist and with which relative identifiers,
 *   what the LSA secrets are called, how many cached domain logons there are.
 *   Nothing in it is decrypted, and it carries `plaintext_recovered: false` to
 *   say so. This is what the Windows analysis emits.
 * * **`MemoryCredential`** — one *recovered credential value*, which a client
 *   can ask to have revealed through the audited reveal route. Nothing in the
 *   tree emits one today.
 *
 * Rendering the first as the second would put "recovered credentials" on screen
 * over a list of account names nobody decrypted anything to obtain, which in a
 * report is a claim about the tool's capability that is not true.
 *
 * There is no bespoke credentials list endpoint and this page does not invent
 * one: both are ordinary `ParsedRecord`s, so they come from the generic records
 * endpoint that already exists. Volumes are tiny — single digits per capture —
 * so the generic path is the right one.
 *
 * What the generic path cannot say is whether *anything ran*. An empty list
 * from it is indistinguishable from a build on which no stage reads the
 * credential stores at all, so the page reads the `credentials` stage out of
 * `/coverage` before it words its empty state. Mirror of the `credentials`
 * entry in `STAGES` in `seance_api/src/memory.rs`.
 */
export const MEMORY_CREDENTIAL_TYPE = 'MemoryCredential'

/** Record type of the credential inventory the analysis emits. */
export const MEMORY_CREDENTIAL_INVENTORY_TYPE = 'MemoryCredentials'

/** Stage key the coverage response uses for the credential stores. */
export const MEMORY_CREDENTIAL_STAGE = 'credentials'

export interface MemoryCredentialsResult {
  /**
   * Recovered credential values, each revealable through `revealCredential`.
   * Empty on every build that does not decrypt, which is every build today.
   */
  records: ParsedRecord[]
  /**
   * Credential-store inventories: one per capture that ran the stage. Present
   * where `records` is empty means the stores were read and listed and no
   * secret was recovered — which is a finding, and a different one from "the
   * stage never ran".
   */
  inventory: ParsedRecord[]
  total: number
  /** True when the page cap stopped us short of `total`. */
  truncated: boolean
}

/**
 * One page of credential records, and the inventories beside them.
 *
 * Deliberately unscoped at the transport: the records endpoint filters by
 * evidence source, and a capture is an artifact rather than a source, so
 * passing the capture id there could return nothing for a case that plainly has
 * credentials. Attribution to a capture is done on the records themselves (see
 * `splitCredentialsByImage`), where a record naming no capture is shown under a
 * note instead of being silently dropped.
 */
export async function getMemoryCredentials(
  caseId: string,
): Promise<MemoryCredentialsResult> {
  const pageSize = 200
  const [values, inventory] = await Promise.all([
    getRecords(caseId, {
      type: MEMORY_CREDENTIAL_TYPE,
      page: 1,
      page_size: pageSize,
    }),
    getRecords(caseId, {
      type: MEMORY_CREDENTIAL_INVENTORY_TYPE,
      page: 1,
      page_size: pageSize,
    }),
  ])
  return {
    records: values.records,
    inventory: inventory.records,
    total: values.total,
    truncated:
      values.total > values.records.length ||
      inventory.total > inventory.records.length,
  }
}
