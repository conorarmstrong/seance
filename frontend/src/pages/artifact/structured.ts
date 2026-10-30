/**
 * Structured-text detection and pretty-printing for the content preview.
 * Pure, dependency-free (the Artifact CSP blocks external libraries): JSON and
 * XML are reformatted as indented text, CSV/TSV is parsed into a row grid.
 */

export type StructuredKind = 'json' | 'xml' | 'csv'

/**
 * Best-effort format detection. Extension is authoritative; JSON is also
 * content-sniffed (very common in `.txt`/extensionless artifacts). XML/CSV are
 * extension-gated to avoid misfiring on HTML or prose.
 */
export function detectStructured(
  name: string,
  text: string,
): StructuredKind | null {
  const ext = name.includes('.')
    ? name.slice(name.lastIndexOf('.') + 1).toLowerCase()
    : ''
  if (ext === 'json') return 'json'
  if (ext === 'xml' || ext === 'svg' || ext === 'xhtml') return 'xml'
  if (ext === 'csv' || ext === 'tsv') return 'csv'
  const t = text.trimStart()
  if (t.startsWith('{') || t.startsWith('[')) return 'json'
  return null
}

/** Reformat JSON with 2-space indentation, or `null` if it doesn't parse. */
export function prettyJson(text: string): string | null {
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return null
  }
}

/** Reformat XML with indentation, or `null` if it doesn't parse. */
export function prettyXml(text: string): string | null {
  try {
    const doc = new DOMParser().parseFromString(text, 'application/xml')
    if (doc.getElementsByTagName('parsererror').length > 0) return null
    const root = doc.documentElement
    if (!root) return null
    const decl = text.trimStart().startsWith('<?xml')
      ? '<?xml version="1.0"?>\n'
      : ''
    return decl + indentNode(root, 0)
  } catch {
    return null
  }
}

function indentNode(node: Node, depth: number): string {
  const pad = '  '.repeat(depth)
  if (node.nodeType === Node.COMMENT_NODE) {
    return `${pad}<!--${node.textContent ?? ''}-->`
  }
  if (node.nodeType !== Node.ELEMENT_NODE) return ''
  const el = node as Element
  const attrs = Array.from(el.attributes)
    .map((a) => ` ${a.name}="${a.value}"`)
    .join('')
  const kids = Array.from(el.childNodes).filter(
    (c) =>
      c.nodeType === Node.ELEMENT_NODE ||
      c.nodeType === Node.COMMENT_NODE ||
      (c.nodeType === Node.TEXT_NODE && (c.textContent ?? '').trim() !== ''),
  )
  const tag = el.tagName
  if (kids.length === 0) return `${pad}<${tag}${attrs}/>`
  if (kids.length === 1 && kids[0].nodeType === Node.TEXT_NODE) {
    return `${pad}<${tag}${attrs}>${(kids[0].textContent ?? '').trim()}</${tag}>`
  }
  const inner = kids
    .map((c) =>
      c.nodeType === Node.TEXT_NODE
        ? `${'  '.repeat(depth + 1)}${(c.textContent ?? '').trim()}`
        : indentNode(c, depth + 1),
    )
    .filter(Boolean)
    .join('\n')
  return `${pad}<${tag}${attrs}>\n${inner}\n${pad}</${tag}>`
}

/**
 * Parse delimited text (CSV, or TSV when `delimiter` is a tab) into rows,
 * honouring quoted fields with embedded delimiters, newlines, and `""` escapes.
 * Returns `null` for empty input.
 */
export function parseDelimited(
  text: string,
  delimiter = ',',
): string[][] | null {
  const rows: string[][] = []
  let field = ''
  let row: string[] = []
  let inQuotes = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"'
          i++
        } else {
          inQuotes = false
        }
      } else {
        field += ch
      }
    } else if (ch === '"') {
      inQuotes = true
    } else if (ch === delimiter) {
      row.push(field)
      field = ''
    } else if (ch === '\n') {
      row.push(field)
      rows.push(row)
      row = []
      field = ''
    } else if (ch !== '\r') {
      field += ch
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field)
    rows.push(row)
  }
  return rows.length > 0 ? rows : null
}

/** Delimiter for a CSV/TSV artifact, from its filename. */
export function delimiterFor(name: string): string {
  return name.toLowerCase().endsWith('.tsv') ? '\t' : ','
}
