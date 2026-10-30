import { describe, expect, it } from 'vitest'
import {
  detectStructured,
  parseDelimited,
  prettyJson,
  prettyXml,
} from './structured'

describe('detectStructured', () => {
  it('detects by extension', () => {
    expect(detectStructured('a.json', '')).toBe('json')
    expect(detectStructured('a.xml', '')).toBe('xml')
    expect(detectStructured('a.svg', '')).toBe('xml')
    expect(detectStructured('a.csv', '')).toBe('csv')
    expect(detectStructured('a.tsv', '')).toBe('csv')
  })

  it('content-sniffs JSON but not XML/CSV', () => {
    expect(detectStructured('note.txt', '  {"a":1}')).toBe('json')
    expect(detectStructured('note.txt', '[1,2,3]')).toBe('json')
    // Bare angle-bracket / prose is NOT treated as structured (avoid HTML).
    expect(detectStructured('page.txt', '<html></html>')).toBeNull()
    expect(detectStructured('note.txt', 'just prose')).toBeNull()
  })
})

describe('prettyJson', () => {
  it('indents valid JSON', () => {
    expect(prettyJson('{"a":1,"b":[2,3]}')).toBe(
      '{\n  "a": 1,\n  "b": [\n    2,\n    3\n  ]\n}',
    )
  })
  it('returns null on invalid/truncated JSON', () => {
    expect(prettyJson('{"a":1,')).toBeNull()
  })
})

describe('prettyXml', () => {
  it('indents nested elements and inlines single text children', () => {
    const out = prettyXml('<root><a>1</a><b><c>2</c></b></root>')
    expect(out).toBe('<root>\n  <a>1</a>\n  <b>\n    <c>2</c>\n  </b>\n</root>')
  })
  it('returns null on malformed XML', () => {
    expect(prettyXml('<root><unclosed>')).toBeNull()
  })
})

describe('parseDelimited', () => {
  it('parses simple CSV rows', () => {
    expect(parseDelimited('a,b,c\n1,2,3')).toEqual([
      ['a', 'b', 'c'],
      ['1', '2', '3'],
    ])
  })
  it('honours quoted fields with commas, newlines, and escaped quotes', () => {
    const rows = parseDelimited('name,note\n"Smith, J","said ""hi""\nbye"')
    expect(rows).toEqual([
      ['name', 'note'],
      ['Smith, J', 'said "hi"\nbye'],
    ])
  })
  it('parses TSV with a tab delimiter', () => {
    expect(parseDelimited('a\tb\n1\t2', '\t')).toEqual([
      ['a', 'b'],
      ['1', '2'],
    ])
  })
  it('returns null for empty input', () => {
    expect(parseDelimited('')).toBeNull()
  })
})
