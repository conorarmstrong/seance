// TypeScript mirror of the seance_api REST contract.
// Field names match the Rust serde serialization exactly.

export type Uuid = string

export type ArtifactType =
  | 'Container'
  | 'RawEvidence'
  | 'Partition'
  | 'FileSystem'
  | 'FileEntry'
  | 'FileContent'
  | 'SystemArtifact'
  | 'ParsedRecord'
  | 'TimelineEvent'
  | 'UnallocatedSpace'
  // The unused tail of one live file's last cluster (HUNT-124). Allocated, so
  // never counted as unallocated space.
  | 'SlackSpace'

// ---- Auth ----

export interface LoginResponse {
  token: string
  expires_at: number
  username: string
  role: string
  must_change_password?: boolean
  user_id?: string
}

// ---- Cases ----

export interface Case {
  id: Uuid
  name: string
  status: string
  reference_number: string | null
  examiner_name: string | null
  created_at: string
  last_accessed_at: string | null
}

export interface CaseStats {
  total_artifacts: number
  artifact_counts_by_type: Record<string, number>
}

export interface RecentArtifact {
  id: Uuid
  artifact_type: string
  display_name: string
  created_at: string
}

export interface IngestResponse {
  artifact_id: Uuid
  status: string
  /**
   * Things the operator needs to know about this ingest while they can still
   * act on them — today, that a memory-shaped source was ingested without the
   * declaration the memory pipeline needs (HUNT-081). Absent when there is
   * nothing to say.
   */
  notes?: string[]
}

// ---- Timeline ----

export interface TimelineEvent {
  id: Uuid
  case_id: Uuid
  artifact_id: Uuid
  timestamp: number
  timestamp_desc: string
  source_module: string
  short_desc: string
  full_details: string
  is_tagged?: boolean
  tag_note?: string
  dynamic_fields?: Record<string, unknown>
}

export interface TimelinePagination {
  total_count: number
  page: number
  page_size: number
  total_pages: number
  has_next: boolean
  has_previous: boolean
}

export interface PaginatedTimeline {
  events: TimelineEvent[]
  pagination: TimelinePagination
}

export interface TimelineTag {
  id: Uuid
  case_id: Uuid
  event_id: Uuid
  examiner: string | null
  note: string | null
  created_at: number
}

export interface TimelineSchemaField {
  path: string
  field_type: string
  frequency: number
  sample_value: unknown
}

export interface TimelineSchema {
  available_fields: TimelineSchemaField[]
}

// ---- Virtual columns ----

export type VirtualColumnType = 'string' | 'integer' | 'timestamp' | 'boolean'

export interface VirtualColumnSource {
  path: string
  /**
   * Legacy and not consulted: its vocabulary ("registry", "ntfs.mft") matches
   * nothing an event carries. Superseded by `source_modules`.
   */
  artifact_types: string[]
  /**
   * Modules whose events this source may answer for, by full `source_module`
   * id. Absent or empty means any module. Optional on the wire: a custom
   * column stored before this field existed has none.
   */
  source_modules?: string[]
}

export interface VirtualColumnDef {
  id: string
  name: string
  description: string
  type: VirtualColumnType
  sources: VirtualColumnSource[]
  default_visible: boolean
  built_in: boolean
}

export interface VirtualColumnSet {
  virtual_columns: VirtualColumnDef[]
}

// ---- Analysis tree ----

export interface AnalysisTreeNode {
  id: string
  name: string
  node_type: 'category' | 'artifact_group'
  count: number
  children: AnalysisTreeNode[]
}

// ---- Search ----

export interface SearchResult {
  artifact_id: Uuid
  case_id: Uuid
  artifact_type: string
  name: string
  snippet: string | null
  score: number
}

export interface SearchResponse {
  results: SearchResult[]
  total_count: number
  query: string
  elapsed_ms: number
  /** True when the result set may be incomplete (server-side limits hit). */
  truncated?: boolean
}

// ---- Artifacts ----

export interface Artifact {
  id: Uuid
  case_id: Uuid
  parent_id: Uuid | null
  artifact_type: ArtifactType
  metadata: Record<string, unknown>
}

export interface ArtifactListItem {
  id: Uuid
  parent_id: Uuid | null
  artifact_type: string
  name: string
  has_children: boolean
  metadata?: Record<string, unknown>
}

export interface ArtifactDeletionImpact {
  artifact_count: number
  timeline_event_count: number
}

export interface ArtifactDeletionResult {
  deleted_artifacts: number
  deleted_timeline_events: number
}

export interface ProcessingLogEntry {
  id: number
  case_id: Uuid
  artifact_id: Uuid
  module_id: string
  status: string
  artifacts_produced: number
  error_message: string | null
  duration_ms: number
  created_at: number
}

export type JobStatus = 'pending' | 'running' | 'complete' | 'failed'

export interface Job {
  id: string
  case_id: string
  module_id: string
  target_artifact_id: string
  status: JobStatus
  artifacts_produced: number
  error_message: string | null
  created_at: number
  completed_at: number | null
}

export interface HexResponse {
  offset: number
  limit: number
  hex: string
  ascii: string
}

// ---- File system grid ----

export interface FileSystemGridItem {
  id: Uuid
  name: string
  extension: string | null
  size: number | null
  created: string | null
  modified: string | null
  accessed: string | null
  is_directory: boolean
  is_deleted: boolean
  is_carved: boolean
  record_number: number | null
}

export interface FileSystemGridResponse {
  items: FileSystemGridItem[]
  total_count: number
  page: number
  page_size: number
  total_pages: number
  has_next: boolean
  has_previous: boolean
}

// ---- Registry explorer ----

export interface RegistryKey {
  key_path: string
  key_name: string
  last_modified: string | null
  subkey_count: number
  value_count: number
  has_children: boolean
}

export interface RegistryValue {
  value_name: string
  value_type: string
  value_data: string
  raw_data_size: number
}

// Transaction-log replay provenance (ROADMAP 1.12). Mirrors the API's
// RegistryReplayProvenance serde struct. Absent for hives parsed before the
// feature shipped (backward-compatible) -> `provenance` is null/omitted.
export interface RegistryProvenance {
  logs_replayed: boolean
  hive_dirty: boolean
  replay_reason: string
  log_format: string
  log_files: string[]
  primary_sequence: number
  secondary_sequence: number
  log_entries_applied: number
  dirty_pages_applied: number
  replay_sequence_start: number | null
  replay_sequence_end: number | null
  hive_last_written_before: string | null
  hive_last_written_after: string | null
  changed_keys: string[]
}

export interface RegistryExplorerResponse {
  current_key_path: string
  parent_key_path: string | null
  subkeys: RegistryKey[]
  values: RegistryValue[]
  breadcrumbs: [string, string][]
  provenance?: RegistryProvenance | null
}

// ---- Conversations ----

export interface ConversationThread {
  thread_id: string
  contact_name: string
  contact_identifier: string
  message_count: number
  last_message_time: string | null
  is_group: boolean
}

export interface ConversationMessage {
  message_id: string
  thread_id: string
  sender: string
  content: string
  timestamp: string
  is_outgoing: boolean
  message_type: string
  attachment_path: string | null
}

export interface ConversationViewerResponse {
  threads: ConversationThread[]
  messages: ConversationMessage[]
  current_thread: string | null
  total_messages: number
  page: number
  has_more: boolean
}

// ---- Bookmarks ----

export interface BookmarkCategory {
  id: Uuid
  case_id: Uuid
  name: string
  color: string
  created_at: number
  bookmark_count?: number
  /** The folder this one sits under; null (or absent) at the top level. */
  parent_id?: Uuid | null
}

export interface ArtifactBookmark {
  id: Uuid
  case_id: Uuid
  artifact_id: Uuid
  category_id: Uuid | null
  category_name: string | null
  category_color: string | null
  note: string | null
  examiner: string | null
  created_at: number
  updated_at: number
}

export interface BookmarkWithArtifact {
  bookmark: ArtifactBookmark
  artifact_type: string
  artifact_name: string
}

// ---- Hash sets ----

export interface HashSetInfo {
  id: Uuid
  case_id: Uuid
  name: string
  description: string | null
  set_type: string
  hash_algorithm: string
  entry_count: number
  imported_at: number
}

export interface HashSetMatch {
  hash_value: string
  hash_set_name: string
  hash_set_id: Uuid
  set_type: string
  product_name: string | null
}

// ---- Profiles ----

export interface IngestionProfile {
  id: string
  case_id: string
  name: string
  description: string
  enabled_modules: string[]
  disabled_modules: string[]
  is_active: boolean
  created_at: number
  warnings?: string[]
}

// ---- Filters ----

export interface SavedFilter {
  id: Uuid
  case_id: Uuid
  name: string
  description: string
  filter: unknown
  is_predefined: boolean
  created_at: number
  updated_at: number
}

// ---- Audit ----

export interface AuditEvent {
  timestamp: string
  user_id: string
  action: string
  resource_type: string
  resource_id: string
  details: string | null
}

export interface AuditLogResponse {
  events: AuditEvent[]
  total: number
  limit: number
  offset: number
}

// ---- Integrity ----

export interface VerifyResult {
  artifact_id: Uuid
  status: 'verified' | 'mismatch' | 'no_reference'
  computed_md5: string
  computed_sha1: string
  computed_sha256: string
  expected_md5: string | null
  expected_sha1: string | null
}

// ---- Filesystem browse ----

export interface FileBrowserEntry {
  name: string
  path: string
  is_dir: boolean
  size: number | null
  modified: string | null
}

export interface FileBrowserResponse {
  current_path: string
  parent_path: string | null
  entries: FileBrowserEntry[]
}

// ---- Modules / status ----

export interface ModuleInfo {
  id: string
  version: string
  subscribes_to: string[]
  execution_mode: string
}

/**
 * `GET /status`. `active_tasks` counts outstanding work across EVERY case the
 * server is serving, and `scope` names that; it must never be presented as
 * the open case's progress. The per-case answer is `cases`, keyed by case id
 * (a case with nothing queued or in flight is absent, not zero), and
 * `unattributed_tasks` is the process count less the sum of `cases` — work
 * no case can claim yet (an ingest still hashing its image before its first
 * artifact exists), which is why a case absent from `cases` may still have
 * work in flight. The two readings are taken at different instants. A server
 * assembled without the census answers `cases: null` with
 * `cases_unavailable` saying so — a count it could not take, never an empty
 * map. The fields are optional here because an older server omits them.
 */
export interface ProcessingStatus {
  active_tasks: number
  scope?: 'process' | string
  cases?: Record<string, { active_tasks: number }> | null
  unattributed_tasks?: number | null
  cases_unavailable?: string
}
