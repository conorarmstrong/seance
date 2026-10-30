// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { REGEX_PRESETS } from './presets'

describe('REGEX_PRESETS', () => {
  it('every preset compiles as a regular expression', () => {
    for (const p of REGEX_PRESETS) {
      expect(() => new RegExp(p.pattern), `${p.id} should compile`).not.toThrow()
    }
  })

  it('presets match representative selectors', () => {
    const re = (id: string) =>
      new RegExp(REGEX_PRESETS.find((p) => p.id === id)!.pattern)
    expect(re('email').test('john.doe@example.com')).toBe(true)
    expect(re('ipv4').test('address 192.168.1.1 here')).toBe(true)
    expect(re('url').test('see https://example.com/path?x=1')).toBe(true)
    expect(re('ssn').test('SSN 123-45-6789')).toBe(true)
    expect(re('ccn').test('card 4111 1111 1111 1111')).toBe(true)
    expect(re('phone').test('call +1 (415) 555-1234')).toBe(true)
    expect(re('mac').test('00:1A:2B:3C:4D:5E')).toBe(true)
    expect(re('btc').test('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')).toBe(true)
  })

  it('ids are unique', () => {
    const ids = REGEX_PRESETS.map((p) => p.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})
