// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { parseKeywords } from './keywordList'

describe('parseKeywords', () => {
  it('trims, drops blanks, and de-duplicates preserving order', () => {
    expect(parseKeywords('  alpha \n\nbeta\r\nalpha\n  \ngamma')).toEqual([
      'alpha',
      'beta',
      'gamma',
    ])
  })
  it('returns empty for blank input', () => {
    expect(parseKeywords('   \n \n')).toEqual([])
  })
})
