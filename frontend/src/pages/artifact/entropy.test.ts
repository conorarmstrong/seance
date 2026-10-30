// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { entropyProfile, shannonEntropy } from './entropy'

describe('shannonEntropy', () => {
  it('is 0 for an empty or single-value buffer', () => {
    expect(shannonEntropy(new Uint8Array(0))).toBe(0)
    expect(shannonEntropy(new Uint8Array(1000))).toBe(0) // all zeros
  })

  it('is 8 bits for a uniform distribution over all 256 byte values', () => {
    const bytes = new Uint8Array(256)
    for (let i = 0; i < 256; i++) bytes[i] = i
    expect(shannonEntropy(bytes)).toBeCloseTo(8, 10)
  })

  it('is 1 bit for two equally likely values', () => {
    const bytes = new Uint8Array(1000)
    for (let i = 0; i < 1000; i++) bytes[i] = i % 2
    expect(shannonEntropy(bytes)).toBeCloseTo(1, 10)
  })
})

describe('entropyProfile', () => {
  it('returns one entropy value per window (with a 1-byte floor)', () => {
    const bytes = new Uint8Array(1000)
    const profile = entropyProfile(bytes, 10, 1)
    expect(profile.length).toBe(10)
    expect(profile.every((v) => v === 0)).toBe(true) // all zeros -> 0 entropy
  })

  it('distinguishes a low-entropy half from a high-entropy half', () => {
    const bytes = new Uint8Array(512)
    // first half all zeros, second half all distinct values
    for (let i = 256; i < 512; i++) bytes[i] = i - 256
    const profile = entropyProfile(bytes, 2)
    expect(profile[0]).toBeCloseTo(0, 6)
    expect(profile[1]).toBeGreaterThan(7.9)
  })

  it('does not collapse a small high-entropy file to zero (min window size)', () => {
    // 512 distinct bytes: with the default 256-byte floor this is 2 windows of
    // 256, each near-maximal entropy — not a flat 0 from 1-byte windows.
    const bytes = new Uint8Array(512)
    for (let i = 0; i < 512; i++) bytes[i] = i % 256
    const profile = entropyProfile(bytes, 480)
    expect(profile.length).toBeLessThanOrEqual(2)
    expect(Math.max(...profile)).toBeGreaterThan(7.9)
  })

  it('handles empty input and non-positive window counts', () => {
    expect(entropyProfile(new Uint8Array(0), 4)).toEqual([])
    expect(entropyProfile(new Uint8Array(10), 0)).toEqual([])
  })
})
