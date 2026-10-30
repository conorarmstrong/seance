export interface SnippetSegment {
  text: string
  mark: boolean
}

/**
 * Split a plain-text snippet into marked/unmarked segments from the
 * server's highlight ranges. Ranges are byte offsets into the UTF-8
 * encoding of the snippet, so slicing happens on a byte view and each
 * segment is decoded back to a string. Ranges are clamped, sorted and
 * merged defensively.
 */
export function snippetSegments(
  snippet: string,
  highlights: [number, number][] | null | undefined,
): SnippetSegment[] {
  const bytes = new TextEncoder().encode(snippet)
  const decoder = new TextDecoder()

  const ranges = (highlights ?? [])
    .map(
      ([start, end]) =>
        [Math.max(0, start), Math.min(bytes.length, end)] as [number, number],
    )
    .filter(([start, end]) => start < end)
    .sort((a, b) => a[0] - b[0])

  const merged: [number, number][] = []
  for (const range of ranges) {
    const last = merged[merged.length - 1]
    if (last && range[0] <= last[1]) {
      last[1] = Math.max(last[1], range[1])
    } else {
      merged.push([range[0], range[1]])
    }
  }

  const segments: SnippetSegment[] = []
  let pos = 0
  for (const [start, end] of merged) {
    if (start > pos) {
      segments.push({ text: decoder.decode(bytes.subarray(pos, start)), mark: false })
    }
    segments.push({ text: decoder.decode(bytes.subarray(start, end)), mark: true })
    pos = end
  }
  if (pos < bytes.length) {
    segments.push({ text: decoder.decode(bytes.subarray(pos)), mark: false })
  }
  return segments
}
