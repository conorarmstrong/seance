/** One extent of a file's on-disk layout. A sparse run has no backing offset. */
export interface FileRun {
  offset: number | null
  length: number
  sparse: boolean
}

export interface RunAnalysis {
  runs: FileRun[]
  /** Sum of all run lengths (the file's mapped size). */
  totalLength: number
  /** Number of physical (non-sparse) extents. >1 means fragmented. */
  fragments: number
  /** Any sparse (unallocated / zero-filled) run present. */
  hasSparse: boolean
  /** Non-sparse extents are in ascending, gapless disk order. */
  contiguous: boolean
}

/**
 * Normalise an artifact's `data_runs` metadata into a layout analysis.
 *
 * `data_runs` is stored as an array of `[offset_bytes | null, length_bytes]`
 * pairs (a null offset marks a sparse run). Returns null when the value is
 * absent or not a usable run list.
 */
export function analyzeRuns(raw: unknown): RunAnalysis | null {
  if (!Array.isArray(raw) || raw.length === 0) return null

  const runs: FileRun[] = []
  for (const entry of raw) {
    if (!Array.isArray(entry) || entry.length < 2) continue
    const [off, len] = entry
    const length = typeof len === 'number' && Number.isFinite(len) ? len : null
    if (length == null || length < 0) continue
    const offset = typeof off === 'number' && Number.isFinite(off) ? off : null
    runs.push({ offset, length, sparse: offset == null })
  }
  if (runs.length === 0) return null

  const totalLength = runs.reduce((s, r) => s + r.length, 0)
  const physical = runs.filter((r) => !r.sparse)
  const fragments = physical.length

  // Contiguous when every physical extent begins exactly where the previous
  // one ended (ascending, gapless). A single extent is trivially contiguous.
  let contiguous = true
  for (let i = 1; i < physical.length; i++) {
    const prev = physical[i - 1]
    if ((prev.offset as number) + prev.length !== physical[i].offset) {
      contiguous = false
      break
    }
  }

  return {
    runs,
    totalLength,
    fragments,
    hasSparse: runs.some((r) => r.sparse),
    contiguous,
  }
}
