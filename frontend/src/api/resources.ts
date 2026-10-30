import { apiFetch, type QueryParams } from "./http";
import type {
  AnalysisTreeNode,
  Artifact,
  ArtifactBookmark,
  ArtifactDeletionImpact,
  ArtifactDeletionResult,
  ArtifactListItem,
  AuditLogResponse,
  BookmarkCategory,
  BookmarkWithArtifact,
  Case,
  CaseStats,
  ConversationViewerResponse,
  FileBrowserResponse,
  FileSystemGridResponse,
  HashSetInfo,
  HashSetMatch,
  HexResponse,
  IngestResponse,
  IngestionProfile,
  Job,
  ModuleInfo,
  PaginatedTimeline,
  ProcessingLogEntry,
  ProcessingStatus,
  RecentArtifact,
  RegistryExplorerResponse,
  SavedFilter,
  SearchResponse,
  TimelineSchema,
  TimelineTag,
  Uuid,
  VerifyResult,
  VirtualColumnDef,
  VirtualColumnSet,
} from "./types";

// ---- Cases ----

/**
 * A listing that travels with the flags saying whether it is all of them.
 *
 * The API wraps paged listings rather than returning a bare array, because a
 * bookmark list or a child-artifact list that stopped at its ceiling reads as
 * the complete set to anyone who cannot see that it stopped. `items` is never
 * absent; the flags default to the honest reading when a server predates them,
 * which is "we do not know that this is everything".
 */
export interface CappedItems<T> {
  items: T[];
  /** The limit the server actually applied, after its own clamp. */
  limit: number | null;
  /** True when rows match that are not in `items`. */
  truncated: boolean;
  /** True when `items.length` is a floor for the real count. */
  count_is_lower_bound: boolean;
}

async function cappedItems<T>(
  path: string,
  query?: QueryParams,
): Promise<CappedItems<T>> {
  const res = await apiFetch<{
    items?: T[];
    limit?: number;
    truncated?: boolean;
    count_is_lower_bound?: boolean;
  }>(path, query ? { query } : undefined);
  return {
    items: res.items ?? [],
    limit: typeof res.limit === "number" ? res.limit : null,
    truncated: res.truncated === true,
    count_is_lower_bound: res.count_is_lower_bound === true,
  };
}

export const listCases = (query?: QueryParams) =>
  apiFetch<Case[]>("/cases", { query });
export const getCase = (id: Uuid) => apiFetch<Case>(`/cases/${id}`);
export const createCase = (body: {
  name?: string;
  reference_number?: string;
  examiner_name?: string;
}) => apiFetch<Case>("/cases", { method: "POST", body });
export const updateCase = (
  id: Uuid,
  body: { name?: string; reference_number?: string; examiner_name?: string },
) => apiFetch<Case>(`/cases/${id}`, { method: "PUT", body });
/** Accepted, not finished: the case is marked and hidden at once, its rows go in the background. */
export const deleteCase = (id: Uuid) =>
  apiFetch<{ case_id: Uuid; status: "deleting" }>(`/cases/${id}`, { method: "DELETE" });
export const getCaseStats = (id: Uuid) =>
  apiFetch<CaseStats>(`/cases/${id}/stats`);

/** One hive's answer for a field the hives do not agree on. */
export interface SystemIdentityValue {
  /** Which hive said it, e.g. `SYSTEM #2`. */
  hive: string;
  value: string;
}

/**
 * A field the case's hives disagree about.
 *
 * The API reports the field itself as `null` when this happens rather than
 * picking the first hive's answer, because attributing one machine's computer
 * name or timezone to another is a court-facing error. That makes the conflict
 * list the only thing that distinguishes "the evidence does not say" from "the
 * evidence says two different things" — which is why it has to be shown.
 */
export interface SystemIdentityConflict {
  /** Dotted field path, e.g. `computer_name`, `os.product_name`. */
  field: string;
  /** The registry value name the answers came from. */
  value_name: string;
  values: SystemIdentityValue[];
  detail: string;
}

/** Which control set one hive names as the running configuration. */
export interface SystemControlSet {
  hive: string;
  current_control_set: string;
}

/** Consolidated Windows system facts compiled from the parsed registry hives. */
/** One registry hive the case holds and the parser could not read. */
export interface UnparsedHive {
  /** The hive's name as detected: `SOFTWARE`, `SYSTEM`, `NTUSER.DAT`, … */
  hive: string;
  /** The hive reader's own message. `null` when none was recorded. */
  error: string | null;
  /** Whether its base block said it was never cleanly flushed. */
  hive_dirty?: boolean | null;
  /** Why transaction-log replay did or did not put it back together. */
  replay_reason?: string | null;
}

/** One local account's detail, from the SAM `F` and `V` values. */
export interface LocalAccountDetail {
  username?: string | null;
  rid?: number | null;
  /** Null when the account has never logged on; the reason says which. */
  last_logon?: string | null;
  last_logon_absent_reason?: string | null;
  last_password_set?: string | null;
  login_count?: number | null;
  account_enabled?: boolean | null;
  comment?: string | null;
  full_name?: string | null;
  stored_password_hash_present?: boolean | null;
  account_key_note?: string | null;
  rid_conflict?: string | null;
}

export interface SystemInfo {
  os: {
    product_name: string | null;
    release_id: string | null;
    current_version: string | null;
    build: string | null;
    registered_owner: string | null;
    registered_organization: string | null;
    install_date: string | null;
  };
  computer_name: string | null;
  timezone: string | null;
  last_shutdown: string | null;
  /**
   * One entry per local account whose own SAM key was read: the RID, the last
   * logon, the logon count and whether the account is enabled, out of the `F`
   * and `V` binary values (ROADMAP §2.6).
   *
   * A DIFFERENT population from `sam_accounts`, which is every name in the SAM
   * name index. `local_accounts_note` reconciles the two counts, so the shorter
   * list is never read as the whole answer.
   */
  local_accounts?: LocalAccountDetail[];
  local_accounts_note?: string | null;
  /**
   * Winlogon's pre-filled account: the last interactive logon, not proof of who
   * was at the keyboard.
   */
  last_logon_user?: string | null;
  /** The domain or workgroup Winlogon authenticated that logon against. */
  logon_domain?: string | null;
  /** The machine's network domain from its TCP/IP parameters, when set. */
  network_domain?: string | null;
  /** Profile DIRECTORIES. An account that never logged on has none (LIVE-029). */
  users: string[];
  /** How many hives contributed a profile list, so a two-machine case shows it. */
  profile_source_hives?: number;
  /** Local ACCOUNTS from SAM. A different population from `users`. */
  sam_accounts?: string[];
  /** How many hives contributed a SAM account list. */
  sam_source_hives?: number;
  usb_devices: Array<Record<string, unknown>>;
  hive_count: number;
  /**
   * Hives the case holds and the parser refused. A machine whose every hive was
   * refused compiled to exactly the same empty page as a machine with no
   * registry (HUNT-054), so the refusals are named with the reader's own
   * reason. An empty array means every hive parsed, not that nobody looked.
   */
  unparsed_hives?: UnparsedHive[];
  /** The control set each hive names; the scoping the fields above were read under. */
  control_sets?: SystemControlSet[];
  /** Non-empty means a null field above is a disagreement, not an absence. */
  identity_conflicts?: SystemIdentityConflict[];
  /** Notes the resolver filed while reading the hives (e.g. no Select\Current). */
  identity_notes?: string[];
  truncated?: boolean;
}
/**
 * Consolidated System Info. With `sourceId`, scopes to a single acquisition so
 * a case holding more than one machine's registry can be read one machine at a
 * time instead of as a merged whole.
 */
export const getSystemInfo = (id: Uuid, sourceId?: string) =>
  apiFetch<SystemInfo>(`/cases/${id}/system_info`, {
    query: { source_id: sourceId },
  });

/** One reading of one device fact, and where it was read. */
export interface DeviceFactReading {
  value: string;
  /** The file it came from. */
  source_file: string;
  /** The property or plist key inside that file. */
  source_key: string;
}

/** One device fact, with every reading of it. */
export interface DeviceFact {
  fact: string;
  /**
   * False when the sources gave more than one value for a fact that can only
   * have one. Always true for a `multi_valued` fact.
   */
  agreed: boolean;
  /**
   * True for a fact a device can legitimately have several of — accounts, SIM
   * numbers, ICCIDs. Several values there is the ordinary case, not a
   * contradiction.
   */
  multi_valued: boolean;
  readings: DeviceFactReading[];
}

/** One device the case holds facts about. */
export interface MobileDevice {
  platform: string;
  facts: DeviceFact[];
  /** How many of its facts the sources disagreed about. */
  disagreements: number;
}

/** A source the device facts were compiled from that could not be read whole. */
export interface DeviceInfoShortfall {
  source_file: string;
  reason: string | null;
  detail: string | null;
}

/**
 * "Whose phone is this?" — compiled from the Android property files and the iOS
 * backup manifest the parsers already read (HUNT-079). Empty on a case holding
 * no mobile evidence; `system_info` is the Windows equivalent.
 */
export interface DeviceInfo {
  devices: MobileDevice[];
  incomplete: DeviceInfoShortfall[];
  truncated?: boolean;
}

export const getDeviceInfo = (id: Uuid, sourceId?: string) =>
  apiFetch<DeviceInfo>(`/cases/${id}/device_info`, {
    query: { source_id: sourceId },
  });

/** Artifacts that share a SHA-256 (duplicate content across the evidence). */
export interface DuplicateMember {
  id: Uuid;
  name: string | null;
  path: string | null;
  artifact_type: string;
}
export interface DuplicateGroup {
  hash: string;
  count: number;
  members: DuplicateMember[];
}
export interface DuplicatesResult {
  groups: DuplicateGroup[];
  group_count: number;
  redundant_copies: number;
  truncated: boolean;
}
export const getDuplicates = (id: Uuid) =>
  apiFetch<DuplicatesResult>(`/cases/${id}/duplicates`);

/** One value a finding rests on, addressable by name. */
export interface FindingEvidence {
  name: string;
  value: string;
}

/**
 * One investigative lead (ROADMAP §2.2).
 *
 * The shape exists to keep apart two things a "detection" would merge, and the
 * screen must keep them apart too: `observation` is the invariant that broke,
 * stated as a fact and checkable against the artifact it names, while
 * `inference` is what the pattern may indicate and is opinion. `qualification`
 * is never empty — a finding with nothing to qualify has not been thought
 * about — and `grade` is always `investigative_lead`.
 */
export interface Finding {
  finding_kind: string;
  /** The human label for the row. */
  name: string;
  confidence: 'strong' | 'notable' | 'weak';
  confidence_rank: number;
  observation: string;
  evidence: FindingEvidence[];
  inference: string | null;
  qualification: string;
  device_offset: number | null;
  source_module: string;
  subject_artifact_id: Uuid;
  grade: string;
  grade_note: string;
  /**
   * Raised during ingest and stored, so it is in the database, the search
   * index and the pivot, and `artifact_id` opens it. The cross-view findings
   * are computed when the list is requested and carry `false` with a
   * `not_persisted_note`; they have no artifact of their own.
   */
  persisted: boolean;
  artifact_id?: Uuid;
  not_persisted_note?: string;
}

/** What this build can look for at all. */
export interface FindingDetection {
  kind: string;
  module: string;
  looks_for: string;
}

/**
 * Whether the two detections that need the whole case at once could run, and
 * what they were able to cover.
 */
export interface CrossViewStatus {
  ran: boolean;
  declined: string | null;
  findings: number;
  file_entries_compared_against: number;
  limits: string[];
  complete: boolean;
}

export interface FindingsResult {
  findings: Finding[];
  listed: number;
  total: number;
  truncated: boolean;
  by_confidence: Record<string, number>;
  by_kind: Record<string, number>;
  cross_view: CrossViewStatus;
  detections: FindingDetection[];
  grade: string;
  grade_note: string;
  absence_note: string;
}

/**
 * The ranked triage list: the things that look wrong, most confident first.
 *
 * `detections` and `absence_note` travel with every response and are not
 * decoration — an empty list means either "nothing matched the detections this
 * build has" or "nothing here looks for what you are after", and a screen that
 * cannot tell them apart invites the reader to conclude the case is clean.
 */
export const getFindings = (id: Uuid, sourceId?: Uuid) =>
  apiFetch<FindingsResult>(`/cases/${id}/findings`, {
    query: { source_id: sourceId },
  });

export interface NearDuplicateMember {
  record_id: Uuid;
  image_artifact_id: Uuid | null;
  pdq_hex: string;
}
export interface NearDuplicateGroup {
  count: number;
  members: NearDuplicateMember[];
}
export interface NearDuplicatesResult {
  groups: NearDuplicateGroup[];
  group_count: number;
  threshold: number;
  images_scanned: number;
  scan_truncated: boolean;
  grade: string;
  note: string;
}
/** PDQ perceptual near-duplicate image groups. `threshold` is the Hamming
 *  cut-off in bits (default 31). A perceptual match is a lead, not an ID. */
export const getNearDuplicateImages = (id: Uuid, threshold = 31) =>
  apiFetch<NearDuplicatesResult>(`/cases/${id}/near_duplicate_images`, {
    query: { threshold: String(threshold) },
  });
export const getRecentArtifacts = (id: Uuid) =>
  apiFetch<RecentArtifact[]>(`/cases/${id}/recent`);
/**
 * An examiner's declaration that a source is a memory capture.
 *
 * A raw memory dump has no magic, so the memory pipeline analyses a headerless
 * image only when the case declares it. The two keys are two different
 * assertions and the analysis treats them differently:
 *
 * - `memory_image: true` — "this file is memory, captured raw". No format is
 *   named, so no header can contradict it.
 * - `memory_image_format: "<name>"` — names the format. A header that says
 *   otherwise wins and the disagreement is recorded against the image.
 *
 * Send one or the other, never both: naming a format is the stronger claim and
 * a bare flag alongside it would leave the record ambiguous about what was
 * actually asserted.
 */
export interface MemoryDeclaration {
  memory_image?: true;
  memory_image_format?: string;
}

export const ingestSource = (
  id: Uuid,
  body: {
    path: string;
    artifact_type?: string;
    profile?: string;
  } & MemoryDeclaration,
) => apiFetch<IngestResponse>(`/cases/${id}/ingest`, { method: "POST", body });

// ---- Timeline ----

export const getTimeline = (caseId: Uuid, query: QueryParams) =>
  apiFetch<PaginatedTimeline>(`/cases/${caseId}/timeline`, { query });
export const getTimelineModules = (caseId: Uuid) =>
  apiFetch<Record<string, number>>(`/cases/${caseId}/timeline/modules`);
export const getTimelineSchema = (caseId: Uuid) =>
  apiFetch<TimelineSchema>(`/cases/${caseId}/timeline/schema`);
export const getTimelineTags = (caseId: Uuid) =>
  apiFetch<TimelineTag[]>(`/cases/${caseId}/timeline/tags`);
export const createTimelineTag = (caseId: Uuid, eventId: Uuid, note?: string) =>
  apiFetch<TimelineTag>(`/cases/${caseId}/timeline/tags/${eventId}`, {
    method: "POST",
    body: { event_id: eventId, note },
  });
export const updateTimelineTag = (caseId: Uuid, eventId: Uuid, note: string) =>
  apiFetch<TimelineTag>(`/cases/${caseId}/timeline/tags/${eventId}`, {
    method: "PUT",
    body: { note },
  });
export const deleteTimelineTag = (caseId: Uuid, eventId: Uuid) =>
  apiFetch<{ success: boolean }>(`/cases/${caseId}/timeline/tags/${eventId}`, {
    method: "DELETE",
  });

// ---- Virtual columns ----

export const getVirtualColumns = (caseId: Uuid) =>
  apiFetch<VirtualColumnSet>(`/cases/${caseId}/virtual_columns`);
export const createVirtualColumn = (caseId: Uuid, body: VirtualColumnDef) =>
  apiFetch<VirtualColumnDef>(`/cases/${caseId}/virtual_columns`, {
    method: "POST",
    body,
  });
export const updateVirtualColumn = (caseId: Uuid, body: VirtualColumnDef) =>
  apiFetch<VirtualColumnDef>(`/cases/${caseId}/virtual_columns/${body.id}`, {
    method: "PUT",
    body,
  });
export const deleteVirtualColumn = (caseId: Uuid, columnId: string) =>
  apiFetch<null>(`/cases/${caseId}/virtual_columns/${columnId}`, {
    method: "DELETE",
  });

// ---- Analysis tree / search ----

export const getAnalysisTree = (caseId: Uuid) =>
  apiFetch<AnalysisTreeNode>(`/cases/${caseId}/analysis/tree`);
export const searchArtifacts = (caseId: Uuid, query: QueryParams) =>
  apiFetch<SearchResponse>(`/cases/${caseId}/search`, { query });

// ---- Artifacts ----

export const getArtifact = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<Artifact>(`/cases/${caseId}/artifacts/${artifactId}`);
export const deleteArtifact = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<ArtifactDeletionResult>(`/cases/${caseId}/artifacts/${artifactId}`, {
    method: "DELETE",
  });
export const getDeletionImpact = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<ArtifactDeletionImpact>(
    `/cases/${caseId}/artifacts/${artifactId}/deletion-impact`,
  );
export const listChildArtifacts = (
  caseId: Uuid,
  parentId: Uuid | "root",
  query?: QueryParams,
) =>
  cappedItems<ArtifactListItem>(
    `/cases/${caseId}/artifacts/${parentId}/children`,
    query,
  );
/** Capped, not a bare array: the server answers this with a `CappedListing`,
 * and reading the body as an array gave `.map` an object to walk. */
export const getProcessingHistory = (caseId: Uuid, artifactId: Uuid) =>
  cappedItems<ProcessingLogEntry>(
    `/cases/${caseId}/artifacts/${artifactId}/processing-history`,
  );
export const getArtifactJobs = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<Job[]>(`/cases/${caseId}/artifacts/${artifactId}/jobs`);
export const getArtifactHex = (
  caseId: Uuid,
  artifactId: Uuid,
  offset: number,
  limit: number,
) =>
  apiFetch<HexResponse>(`/cases/${caseId}/artifacts/${artifactId}/hex`, {
    query: { offset, limit },
  });
export const getConversation = (
  caseId: Uuid,
  artifactId: Uuid,
  query?: QueryParams,
) =>
  apiFetch<ConversationViewerResponse>(
    `/cases/${caseId}/artifacts/${artifactId}/conversation`,
    { query },
  );
export const getRegistryData = (
  caseId: Uuid,
  artifactId: Uuid,
  query?: QueryParams,
) =>
  apiFetch<RegistryExplorerResponse>(
    `/cases/${caseId}/artifacts/${artifactId}/registry`,
    { query },
  );
export const getFileSystemGrid = (
  caseId: Uuid,
  sourceId: Uuid,
  query: QueryParams,
) =>
  apiFetch<FileSystemGridResponse>(
    `/cases/${caseId}/sources/${sourceId}/files`,
    { query },
  );
export const verifyArtifact = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<VerifyResult>(`/cases/${caseId}/artifacts/${artifactId}/verify`, {
    method: "POST",
  });
export const checkArtifactHash = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<HashSetMatch[]>(
    `/cases/${caseId}/artifacts/${artifactId}/hash_check`,
  );
/**
 * Re-run one module on one artifact. It carries no secret: the server refuses
 * a `secrets` map (SEC-204) — a secret goes through {@link supplyCredential}.
 */
export const runModule = (caseId: Uuid, artifactId: Uuid, moduleId: string) =>
  apiFetch<{ job_id: string; status: string }>(
    `/cases/${caseId}/artifacts/${artifactId}/run_module`,
    { method: "POST", body: { module_id: moduleId } },
  );

/**
 * Supply a secret for one locked artifact (HUNT-120, SEC-204): the module for
 * `kind` runs again on it, once, with the secret. The server holds it zeroed
 * for that run only and audits the attempt and its outcome by kind, never by
 * value. `kind` is a credential kind (`ios_backup_password`,
 * `signal_backup_passphrase`, `bitlocker_password`, …).
 */
export const supplyCredential = (
  caseId: Uuid,
  artifactId: Uuid,
  kind: string,
  secret: string,
) =>
  apiFetch<{
    job_id: string;
    status: string;
    kind: string;
    module_id: string;
    note: string;
  }>(`/cases/${caseId}/artifacts/${artifactId}/credential`, {
    method: "POST",
    body: { kind, secret },
  });

/**
 * Unlock an encrypted iOS backup for reading (BUG-026). The server checks the
 * password against the backup's keybag and holds the unwrapped class keys in
 * its memory, for this case only, until they expire, the backup is locked
 * again, the case is deleted or the server restarts. The password itself is
 * not kept. `artifactId` is the backup folder or any file of the backup.
 *
 * With a volume kind (`bitlocker_password`, `bitlocker_recovery_password`,
 * `luks_passphrase`; HUNT-254) it unlocks a BitLocker or LUKS volume decrypted
 * during a run: `artifactId` is the locked volume, the decrypted volume or
 * anything beneath it, and the decrypting key is held under the same rules.
 */
export const unlockForReading = (
  caseId: Uuid,
  artifactId: Uuid,
  kind: string,
  secret: string,
) =>
  apiFetch<{
    status: string;
    kind: string;
    expires_in_secs: number;
    /** iOS backups: how many files the unlocked keys open. */
    file_count?: number;
    /** BitLocker / LUKS volumes (HUNT-254): the locked volume now held. */
    volume_artifact_id?: string;
    note: string;
  }>(`/cases/${caseId}/artifacts/${artifactId}/unlock`, {
    method: "POST",
    body: { kind, secret },
  });

/**
 * Forget the keys {@link unlockForReading} holds for this backup (BUG-026) or
 * volume (HUNT-254).
 */
export const lockForReading = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<{ status: string; kind: string; was_unlocked: boolean }>(
    `/cases/${caseId}/artifacts/${artifactId}/unlock`,
    { method: "DELETE" },
  );

/** One ad-hoc job, by id. */
export const getJob = (caseId: Uuid, jobId: string) =>
  apiFetch<Job>(`/cases/${caseId}/jobs/${jobId}`);

/** Batch ad-hoc: run a module across every ParsedRecord of a category type. */
export const analyzeCategory = (
  caseId: Uuid,
  moduleId: string,
  recordType: string,
) =>
  apiFetch<{ job_ids: string[]; targets: number; truncated: boolean }>(
    `/cases/${caseId}/analyze`,
    { method: "POST", body: { module_id: moduleId, record_type: recordType } },
  );

/**
 * Batch ad-hoc: run a module across an explicit set of artifacts (content
 * resolved server-side). Powers "Run OCR on all pictures" from the gallery.
 */
export const runModuleBatch = (
  caseId: Uuid,
  moduleId: string,
  artifactIds: Uuid[],
) =>
  apiFetch<{ job_ids: string[]; targets: number; truncated: boolean }>(
    `/cases/${caseId}/run_module_batch`,
    {
      method: "POST",
      body: { module_id: moduleId, artifact_ids: artifactIds },
    },
  );

/** File/media category counts for the logical navigator. */
export interface MediaCounts {
  pictures: number;
  videos: number;
  audio: number;
  documents: number;
  geolocation: number;
}
export const getMediaCounts = (caseId: Uuid) =>
  apiFetch<MediaCounts>(`/cases/${caseId}/stats/media_counts`);

// ---- Bookmarks ----

export const listBookmarkCategories = (caseId: Uuid) =>
  apiFetch<BookmarkCategory[]>(`/cases/${caseId}/bookmarks/categories`);
export const createBookmarkCategory = (
  caseId: Uuid,
  body: { name: string; color?: string; parent_id?: Uuid },
) =>
  apiFetch<BookmarkCategory>(`/cases/${caseId}/bookmarks/categories`, {
    method: "POST",
    body,
  });
export const deleteBookmarkCategory = (caseId: Uuid, categoryId: Uuid) =>
  apiFetch<{ success: boolean }>(
    `/cases/${caseId}/bookmarks/categories/${categoryId}`,
    { method: "DELETE" },
  );
export const listBookmarks = (caseId: Uuid, category?: Uuid) =>
  cappedItems<BookmarkWithArtifact>(`/cases/${caseId}/bookmarks`, { category });
export const getBookmarkedIds = (caseId: Uuid) =>
  apiFetch<Uuid[]>(`/cases/${caseId}/bookmarks/ids`);
export const createBookmark = (
  caseId: Uuid,
  body: { artifact_id: Uuid; category_id?: Uuid; note?: string },
) =>
  apiFetch<ArtifactBookmark>(`/cases/${caseId}/bookmarks`, {
    method: "POST",
    body,
  });
export const updateBookmark = (
  caseId: Uuid,
  artifactId: Uuid,
  body: { category_id?: Uuid | null; note?: string | null },
) =>
  apiFetch<ArtifactBookmark>(`/cases/${caseId}/bookmarks/${artifactId}`, {
    method: "PUT",
    body,
  });
export const deleteBookmark = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<{ success: boolean }>(`/cases/${caseId}/bookmarks/${artifactId}`, {
    method: "DELETE",
  });

// ---- Hash sets ----

export const listHashSets = (caseId: Uuid) =>
  apiFetch<HashSetInfo[]>(`/cases/${caseId}/hash_sets`);
export const createHashSet = (
  caseId: Uuid,
  body: {
    name: string;
    description?: string;
    set_type?: string;
    hash_algorithm?: string;
  },
) =>
  apiFetch<{ id: Uuid; status: string }>(`/cases/${caseId}/hash_sets`, {
    method: "POST",
    body,
  });
export const deleteHashSet = (caseId: Uuid, hashSetId: Uuid) =>
  apiFetch<{ status: string }>(`/cases/${caseId}/hash_sets/${hashSetId}`, {
    method: "DELETE",
  });

// Project VIC / CAID (VICS) interop.
export const importVicsHashSet = (
  caseId: Uuid,
  body: { name: string; vics_json: string },
) =>
  apiFetch<{
    id: Uuid;
    status: string;
    set_type: string;
    entries_imported: number;
    media_skipped_no_hash: number;
  }>(`/cases/${caseId}/hash_sets/vics_import`, {
    method: "POST",
    body,
  });

export const exportVicsHashSet = (caseId: Uuid, hashSetId: Uuid) =>
  apiFetch<unknown>(`/cases/${caseId}/hash_sets/${hashSetId}/vics_export`);

// ---- Profiles ----

export const listProfiles = (caseId: Uuid) =>
  apiFetch<IngestionProfile[]>(`/cases/${caseId}/profiles`);
export const getActiveProfile = (caseId: Uuid) =>
  apiFetch<IngestionProfile | null>(`/cases/${caseId}/profiles/active`);
export const createProfile = (
  caseId: Uuid,
  body: {
    name: string;
    description: string;
    enabled_modules: string[];
    disabled_modules: string[];
  },
) =>
  apiFetch<IngestionProfile>(`/cases/${caseId}/profiles`, {
    method: "POST",
    body,
  });
export const activateProfile = (caseId: Uuid, profileId: string) =>
  apiFetch<{ status: string }>(
    `/cases/${caseId}/profiles/${profileId}/activate`,
    { method: "POST" },
  );
export const deleteProfile = (caseId: Uuid, profileId: string) =>
  apiFetch<null>(`/cases/${caseId}/profiles/${profileId}`, {
    method: "DELETE",
  });

// ---- Jobs ----

/** Capped, not a bare array. The server stopped returning one when job listing
 * gained a ceiling; an examiner deciding whether an analysis was ever run must
 * be able to see that the list stopped rather than read absence as proof. */
export const listJobs = (caseId: Uuid) =>
  cappedItems<Job>(`/cases/${caseId}/jobs`);

// ---- Filters ----

export const listFilters = (caseId: Uuid) =>
  apiFetch<SavedFilter[]>(`/cases/${caseId}/filters`);

export const createFilter = (
  caseId: Uuid,
  body: { name: string; description?: string; filter: unknown },
) =>
  apiFetch<SavedFilter>(`/cases/${caseId}/filters`, { method: "POST", body });

export const deleteFilter = (caseId: Uuid, id: Uuid) =>
  apiFetch<{ deleted: boolean }>(`/cases/${caseId}/filters/${id}`, {
    method: "DELETE",
  });

export interface FilterApplyResult {
  results: {
    id: Uuid;
    parent_id: Uuid | null;
    artifact_type: string;
    metadata: Record<string, unknown>;
  }[];
  total: number;
  /**
   * False when the case-wide scan stopped at its row ceiling, which makes
   * `total` a floor rather than the match count. Optional because a response
   * without the field cannot be read as "the scan completed": absent is
   * "not stated", and the page must show that as unknown, never as complete.
   */
  scan_complete?: boolean;
  /**
   * Rows the scan reached and could not decode.
   *
   * Distinct from `scan_complete`, and paging cannot repair it: the scan ran to
   * the end and still could not read these rows, so artifacts this filter might
   * have matched were examined and lost rather than never reached. A complete
   * scan with a non-zero count here still produces a `total` that is a floor.
   *
   * Optional for the same reason as `scan_complete`: absent is "not stated",
   * never "zero".
   */
  undecodable?: number;
  /** True when this result is short in either sense. */
  inventory_incomplete?: boolean;
  /** Which shortfall applies, in the server's closed vocabulary. */
  inventory_incomplete_reason?: string | null;
}

export const applyFilter = (
  caseId: Uuid,
  id: Uuid,
  opts?: { limit?: number; offset?: number },
) =>
  apiFetch<FilterApplyResult>(`/cases/${caseId}/filters/${id}/apply`, {
    query: { limit: opts?.limit ?? 200, offset: opts?.offset ?? 0 },
  });

// ---- Audit ----

export const getAuditLog = (caseId: Uuid, limit: number, offset: number) =>
  apiFetch<AuditLogResponse>(`/cases/${caseId}/audit_log`, {
    query: { limit, offset },
  });

// ---- Misc ----

/**
 * List a directory on the SERVER, for the ingest browser.
 *
 * `caseId` is mandatory and is not decoration. The per-case access layer only
 * recognises a case named in the URL path, and this route has none, so until it
 * carried a case the only thing standing between any authenticated user and the
 * server's evidence tree was authentication itself. The server now refuses a
 * request that names no case, so omitting it here is a 400, not a wider listing.
 */
export const browseFilesystem = (caseId: Uuid, path?: string) =>
  apiFetch<FileBrowserResponse>("/filesystem/browse", {
    query: { case_id: caseId, path },
  });

export interface EvidenceRootsResponse {
  restricted: boolean;
  roots: string[];
}
/**
 * The configured evidence roots, for the ingest browser's root switcher.
 *
 * Case-scoped for the same reason `browseFilesystem` is: the root list is the
 * map of the evidence store, not harmless metadata.
 */
export const getEvidenceRoots = (caseId: Uuid) =>
  apiFetch<EvidenceRootsResponse>("/evidence-roots", {
    query: { case_id: caseId },
  });
export const listModules = (artifactType?: string) =>
  apiFetch<ModuleInfo[]>("/modules", {
    query: { artifact_type: artifactType },
  });
export const getProcessingStatus = () => apiFetch<ProcessingStatus>("/status");
export const getVersion = () =>
  apiFetch<{ version: string; name: string }>("/version");
