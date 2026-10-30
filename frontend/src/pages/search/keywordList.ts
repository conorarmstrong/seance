/**
 * Keyword lists: reusable sets of search terms (a law-enforcement staple).
 * The list is edited/imported as newline-separated text; this parses it into
 * trimmed, de-duplicated, non-empty terms in first-seen order.
 */
export function parseKeywords(text: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const line of text.split(/\r?\n/)) {
    const term = line.trim()
    if (term && !seen.has(term)) {
      seen.add(term)
      out.push(term)
    }
  }
  return out
}
