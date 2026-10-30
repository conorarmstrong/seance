import type { MemoryImageSummary } from '../../pages/memory/api'

/**
 * Index the case's RAM captures by the evidence artifact each was decoded from,
 * so the acquisition tree can mark the source node and offer a way into the
 * capture's memory analysis.
 *
 * Captures whose source is unknown (`source_artifact_id === null`, an older API
 * build) are skipped: they cannot be pinned to a tree node, so they carry no
 * marker at all rather than a marker on the wrong node. If two captures somehow
 * name the same source, the last one wins — the marker is a doorway into the
 * Memory shell, which lists every capture, so the tie is immaterial.
 */
export function captureSourceIndex(
  images: MemoryImageSummary[] | undefined,
): Map<string, MemoryImageSummary> {
  const index = new Map<string, MemoryImageSummary>()
  for (const image of images ?? []) {
    if (image.source_artifact_id) index.set(image.source_artifact_id, image)
  }
  return index
}
