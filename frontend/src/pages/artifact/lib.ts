import type { Artifact } from '../../api/types'
import { formatUtc } from '../../lib/format'

export type TabId =
  | 'preview'
  | 'memory'
  | 'diskmap'
  | 'allocation'
  | 'files'
  | 'treemap'
  | 'entropy'
  | 'layout'
  | 'hex'
  | 'text'
  | 'children'
  | 'registry'
  | 'conversation'
  | 'rawjson'
  | 'timeline'
  | 'processing'
  | 'run'

export interface TabDef {
  id: TabId
  label: string
}

const HEX_TYPES = new Set([
  'RawEvidence',
  'FileEntry',
  'FileContent',
  'Container',
  'Partition',
  'UnallocatedSpace',
  'SlackSpace',
])

const TEXT_TYPES = new Set(['FileEntry', 'FileContent'])

const CHILD_TYPES = new Set([
  'Container',
  'RawEvidence',
  'Partition',
  'FileSystem',
])

/**
 * Types that represent a whole device/image and can carry a partition layout.
 * These get a Disk Map tab rendering the proportional partition/filesystem
 * strip from the source's disk-region descendants.
 */
const DISK_LAYOUT_TYPES = new Set(['RawEvidence', 'Container'])

// heic/heif/tiff can't be decoded by the browser from their raw bytes, but the
// preview renders them from the server thumbnail (see PreviewTab.ImagePreview),
// so they get a preview-by-name tab like the gallery lists them — without
// depending on the thumbnail probe, which the source-size cap can skip on large
// phone HEICs.
const RASTER_EXTS = new Set([
  'png',
  'jpg',
  'jpeg',
  'gif',
  'bmp',
  'webp',
  'heic',
  'heif',
  'tiff',
])

const TEXT_EXTS = new Set([
  'txt',
  'log',
  'json',
  'xml',
  'csv',
  'tsv',
  'ini',
  'conf',
  'cfg',
  'toml',
  'html',
  'htm',
  'js',
  'ts',
  'jsx',
  'tsx',
  'css',
  'py',
  'sh',
  'bat',
  'ps1',
  'md',
  'yaml',
  'yml',
  'rs',
  'c',
  'h',
  'cpp',
  'hpp',
  'go',
  'java',
  'rb',
  'php',
  'sql',
])

/** Known messaging-database filenames, lower-cased for comparison. */
const MESSAGING_DB_NAMES = new Set([
  'chat.db',
  'sms.db',
  'msgstore.db',
  'chatstorage.sqlite',
])

/** Artifact types that can be a file-shaped messaging database. */
const MESSAGING_DB_TYPES = new Set(['FileEntry', 'FileContent', 'SystemArtifact'])

/**
 * True when the artifact name looks like a messaging database. Permissive
 * (suffix/substring), mirroring the backend detectors, so renamed or
 * path-prefixed copies (e.g. `imessage_chat.db`, `whatsapp_chat.db`) still get
 * a Conversation tab. The tab renders an empty state if no messages are found.
 */
export function isMessagingDbName(name: string): boolean {
  const n = name.trim().toLowerCase()
  if (MESSAGING_DB_NAMES.has(n)) return true
  return (
    n.endsWith('chat.db') ||
    n.endsWith('sms.db') ||
    n.endsWith('msgstore.db') ||
    n.endsWith('chatstorage.sqlite') ||
    n.includes('imessage') ||
    n.includes('whatsapp')
  )
}

const VIDEO_EXTS = new Set([
  'mp4',
  'm4v',
  'mov',
  'webm',
  'ogv',
  'wmv',
  'avi',
  'mkv',
])

const OFFICE_EXTS = new Set([
  'doc',
  'docx',
  'xls',
  'xlsx',
  'ppt',
  'pptx',
  'odt',
  'ods',
  'odp',
])

export type PreviewKind = 'image' | 'text' | 'video' | 'office' | 'pdf'

/** Preview mode implied by the artifact name's extension, if any. */
export function previewKindForName(name: string): PreviewKind | null {
  const dot = name.lastIndexOf('.')
  if (dot < 0 || dot === name.length - 1) return null
  const ext = name.slice(dot + 1).toLowerCase()
  if (RASTER_EXTS.has(ext)) return 'image'
  if (VIDEO_EXTS.has(ext)) return 'video'
  if (ext === 'pdf') return 'pdf'
  if (OFFICE_EXTS.has(ext)) return 'office'
  if (TEXT_EXTS.has(ext)) return 'text'
  return null
}

/** Types whose content endpoints (hex/content/thumbnail) are meaningful. */
export function isContentBearing(artifactType: string): boolean {
  return HEX_TYPES.has(artifactType)
}

/** Derived-record types with no byte content on disk. */
const CONTENTLESS_TYPES = new Set(['ParsedRecord', 'TimelineEvent'])

/**
 * Whether the artifact has downloadable / integrity-verifiable byte content.
 * Parsed records and timeline events are derived structured data with no bytes
 * to hash or download, so those actions are hidden for them.
 */
export function hasByteContent(artifactType: string): boolean {
  return !CONTENTLESS_TYPES.has(artifactType)
}

/**
 * Server caps thumbnail source reads (see get_artifact_thumbnail); probing a
 * larger source just returns 413. Kept in sync with THUMBNAIL_MAX_SOURCE_BYTES.
 */
export const THUMBNAIL_MAX_SOURCE_BYTES = 64 * 1024 * 1024

/** Only bare files can be a decodable raster image. Structural types
 * (Partition, FileSystem, Container, RawEvidence) resolve to the whole device,
 * so probing them wastes a request and returns 413 on anything over the cap. */
const THUMBNAILABLE_TYPES = new Set(['FileEntry', 'FileContent'])

/** Whether it is worth probing the thumbnail endpoint for this artifact. */
export function canProbeThumbnail(artifact: Artifact): boolean {
  if (!THUMBNAILABLE_TYPES.has(artifact.artifact_type)) return false
  const size =
    metadataNumber(artifact.metadata, 'size') ??
    metadataNumber(artifact.metadata, 'file_size')
  return size == null || size <= THUMBNAIL_MAX_SOURCE_BYTES
}

export function metadataString(
  metadata: Record<string, unknown>,
  key: string,
): string | null {
  const value = metadata[key]
  return typeof value === 'string' && value !== '' ? value : null
}

export function metadataNumber(
  metadata: Record<string, unknown>,
  key: string,
): number | null {
  const value = metadata[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

export function metadataBool(
  metadata: Record<string, unknown>,
  key: string,
): boolean | null {
  const value = metadata[key]
  return typeof value === 'boolean' ? value : null
}

/**
 * Whether a marker is PRESENT, whatever shape the producer wrote it in.
 *
 * The incompleteness markers are not one type across the tree: MFT and F2FS
 * write `compression_unsupported` as a reason string
 * (`"ntfs_lznt1_oversize"`, `"f2fs"`), BTRFS writes it as `true`. Reading such a
 * marker with `metadataBool` returns `null` for every string producer, so the
 * warning it gates renders for one filesystem and silently not for the others —
 * and on this screen the badge below it then states the opposite. The backend's
 * own hash plugin has always tested these markers with a type-agnostic
 * `present()`; this is the same rule on the client.
 *
 * `false`, `null` and an empty string are absent. Anything else is present.
 */
export function metadataMarker(
  metadata: Record<string, unknown>,
  key: string,
): boolean {
  const value = metadata[key]
  if (value === undefined || value === null || value === false) return false
  if (typeof value === 'string') return value !== ''
  return true
}

export function metadataStringArray(
  metadata: Record<string, unknown>,
  key: string,
): string[] {
  const value = metadata[key]
  if (!Array.isArray(value)) return []
  return value.filter((v): v is string => typeof v === 'string')
}

export function artifactDisplayName(artifact: Artifact): string {
  const name = metadataString(artifact.metadata, 'name')
  if (name) return name
  const sourcePath = metadataString(artifact.metadata, 'source_path')
  if (sourcePath) {
    const parts = sourcePath.split(/[\\/]/).filter(Boolean)
    if (parts.length > 0) return parts[parts.length - 1]
  }
  return artifact.id
}

export function tabsForArtifact(
  artifact: Artifact,
  previewKind?: PreviewKind | null,
  /**
   * Id of the `MemoryImage` record decoded FROM this artifact, when there is
   * one. Passed in rather than derived here because it is a per-case lookup,
   * and this function is pure.
   */
  memoryImageId?: string | null,
): TabDef[] {
  const type = artifact.artifact_type
  const metaType = metadataString(artifact.metadata, 'type') ?? ''
  // Overview/Properties/EXIF are not tabs: they live in the always-visible
  // Inspector pane (ArtifactInspector) so they can be read beside any viewer.
  // This list is only the content viewers shown in the center column.
  const tabs: TabDef[] = []
  // First, deliberately. An examiner who has found a RAM capture in the
  // evidence tree is here to analyse it, and the navigator hides the
  // MemoryImage record, so without this there is no route from the file to its
  // own analysis except leaving the tree and re-finding it in a dropdown.
  if (memoryImageId) tabs.push({ id: 'memory', label: 'Memory' })
  if (previewKind) tabs.push({ id: 'preview', label: 'Preview' })
  if (DISK_LAYOUT_TYPES.has(type)) tabs.push({ id: 'diskmap', label: 'Disk Map' })
  // A parsed filesystem carries a cluster allocation bitmap, a lazy folder
  // tree, and a size treemap. It shows empty states when the data is absent.
  if (type === 'FileSystem') {
    tabs.push({ id: 'files', label: 'Files' })
    tabs.push({ id: 'treemap', label: 'Treemap' })
    tabs.push({ id: 'allocation', label: 'Allocation Map' })
  }
  if (HEX_TYPES.has(type)) tabs.push({ id: 'hex', label: 'Hex' })
  if (TEXT_TYPES.has(type)) tabs.push({ id: 'text', label: 'Text' })
  // Per-file structural views. Entropy applies to any readable (non-directory)
  // file; the layout/fragmentation map to any artifact carrying a data-run map.
  const isFile =
    (type === 'FileEntry' || type === 'FileContent') &&
    artifact.metadata.is_directory !== true
  if (isFile) tabs.push({ id: 'entropy', label: 'Entropy' })
  if (
    Array.isArray(artifact.metadata.data_runs) &&
    artifact.metadata.data_runs.length > 0
  ) {
    tabs.push({ id: 'layout', label: 'Layout' })
  }
  if (CHILD_TYPES.has(type)) tabs.push({ id: 'children', label: 'Children' })
  if (type === 'SystemArtifact' && metaType === 'RegistryHive') {
    tabs.push({ id: 'registry', label: 'Registry' })
  }
  // A messaging database is a file whose name matches a known chat store; its
  // parsed messages live as ParsedRecord children fetched by the tab itself.
  if (MESSAGING_DB_TYPES.has(type) && isMessagingDbName(artifactDisplayName(artifact))) {
    tabs.push({ id: 'conversation', label: 'Conversation' })
  }
  if (type === 'ParsedRecord' || type === 'TimelineEvent') {
    tabs.push({ id: 'rawjson', label: 'Raw JSON' })
  }
  // The dated events around this artifact (its own, parent's, children's and
  // siblings'): any artifact can have them, so the tab is always offered and
  // says so when there are none.
  tabs.push({ id: 'timeline', label: 'Timeline' })
  tabs.push({ id: 'processing', label: 'Processing' })
  tabs.push({ id: 'run', label: 'Run Module' })
  return tabs
}

/** Parse a hex ("0x1f4" or bare "1f4") or decimal offset. Null if invalid. */
export function parseOffsetInput(raw: string): number | null {
  const text = raw.trim()
  if (!text) return null
  let value: number
  if (/^0x[0-9a-f]+$/i.test(text)) {
    value = parseInt(text.slice(2), 16)
  } else if (/^[0-9]+$/.test(text)) {
    value = parseInt(text, 10)
  } else if (/^[0-9a-f]+$/i.test(text)) {
    value = parseInt(text, 16)
  } else {
    return null
  }
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

export function formatMs(ms: number | null | undefined): string {
  if (ms == null || Number.isNaN(ms)) return '—'
  if (ms < 1000) return `${ms} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
}

/** Parse an API hex string ("41 42 ...") into byte values. */
export function hexToBytes(hex: string): number[] {
  const trimmed = hex.trim()
  if (!trimmed) return []
  return trimmed.split(/\s+/).map((b) => parseInt(b, 16))
}

export interface InspectorField {
  label: string
  value: string
}

function readLe(bytes: number[], index: number, width: number): bigint | null {
  if (index < 0 || index + width > bytes.length) return null
  let value = 0n
  for (let i = width - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[index + i] & 0xff)
  }
  return value
}

/** Difference between the FILETIME epoch (1601) and Unix epoch, in 100ns. */
const FILETIME_UNIX_OFFSET = 116444736000000000n

/** Format epoch milliseconds as UTC if the year is plausible (1980-2099). */
function plausibleUtc(epochMs: number): string | null {
  if (!Number.isFinite(epochMs)) return null
  const date = new Date(epochMs)
  const year = date.getUTCFullYear()
  if (Number.isNaN(year) || year < 1980 || year >= 2100) return null
  return formatUtc(date.toISOString())
}

/**
 * Decode fixed-width integers and timestamp interpretations at a byte
 * position. Fields whose width runs past the loaded page are omitted;
 * timestamp interpretations only appear when the value is plausible.
 */
export function inspectAt(bytes: number[], index: number): InspectorField[] {
  const fields: InspectorField[] = []
  const u8 = readLe(bytes, index, 1)
  if (u8 != null) fields.push({ label: 'u8', value: u8.toString() })
  const u16 = readLe(bytes, index, 2)
  if (u16 != null) fields.push({ label: 'u16le', value: u16.toString() })
  const u32 = readLe(bytes, index, 4)
  if (u32 != null) {
    fields.push({ label: 'u32le', value: u32.toString() })
    const i32 = u32 >= 0x80000000n ? u32 - 0x100000000n : u32
    fields.push({ label: 'i32le', value: i32.toString() })
  }
  const u64 = readLe(bytes, index, 8)
  if (u64 != null) fields.push({ label: 'u64le', value: u64.toString() })
  if (u32 != null) {
    const unix = plausibleUtc(Number(u32) * 1000)
    if (unix) fields.push({ label: 'Unix time (u32le s)', value: unix })
  }
  if (u64 != null) {
    const ms = Number((u64 - FILETIME_UNIX_OFFSET) / 10000n)
    const filetime = plausibleUtc(ms)
    if (filetime) fields.push({ label: 'FILETIME (u64le)', value: filetime })
  }
  return fields
}

/** Badge class for processing/job status strings. */
export function statusBadgeClass(status: string): string {
  const value = status.toLowerCase()
  if (value === 'success' || value === 'complete' || value === 'completed') {
    return 'badge badge-ok'
  }
  if (value === 'failed' || value === 'error') return 'badge badge-danger'
  if (value === 'running' || value === 'pending') return 'badge badge-accent'
  return 'badge'
}
