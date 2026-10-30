// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { snippetSegments } from './snippet'

describe('snippetSegments', () => {
  it('returns a single unmarked segment without highlights', () => {
    expect(snippetSegments('hello world', null)).toEqual([
      { text: 'hello world', mark: false },
    ])
    expect(snippetSegments('hello world', [])).toEqual([
      { text: 'hello world', mark: false },
    ])
  })

  it('marks a single ASCII range', () => {
    expect(snippetSegments('found malware string', [[6, 13]])).toEqual([
      { text: 'found ', mark: false },
      { text: 'malware', mark: true },
      { text: ' string', mark: false },
    ])
  })

  it('treats offsets as UTF-8 byte offsets, not char indices', () => {
    // "naïve café " is 13 bytes (ï and é are 2 bytes each).
    expect(snippetSegments('naïve café malware end', [[13, 20]])).toEqual([
      { text: 'naïve café ', mark: false },
      { text: 'malware', mark: true },
      { text: ' end', mark: false },
    ])
  })

  it('handles multiple ranges and range at the end', () => {
    expect(
      snippetSegments('aa bb cc', [
        [0, 2],
        [6, 8],
      ]),
    ).toEqual([
      { text: 'aa', mark: true },
      { text: ' bb ', mark: false },
      { text: 'cc', mark: true },
    ])
  })

  it('merges overlapping ranges and sorts unordered input', () => {
    expect(
      snippetSegments('abcdef', [
        [3, 5],
        [1, 4],
      ]),
    ).toEqual([
      { text: 'a', mark: false },
      { text: 'bcde', mark: true },
      { text: 'f', mark: false },
    ])
  })

  it('clamps out-of-range offsets and drops empty ranges', () => {
    expect(snippetSegments('abc', [[-2, 99]])).toEqual([
      { text: 'abc', mark: true },
    ])
    expect(snippetSegments('abc', [[2, 2]])).toEqual([
      { text: 'abc', mark: false },
    ])
  })
})
