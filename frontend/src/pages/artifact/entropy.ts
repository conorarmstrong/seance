/** Shannon entropy of a byte window, in bits per byte (0..8). */
export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0
  const counts = new Uint32Array(256)
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++
  let h = 0
  for (let i = 0; i < 256; i++) {
    const c = counts[i]
    if (c === 0) continue
    const p = c / bytes.length
    h -= p * Math.log2(p)
  }
  return h
}

/**
 * Entropy across a buffer, one value per window. Splits `bytes` into at most
 * `windows` slices and returns the entropy of each, so the caller can plot
 * entropy against file position (encryption/packing shows as a flat ~8,
 * text/zeros as low, code/binary in between).
 *
 * Each window is at least `minWindowBytes` bytes. Shannon entropy is capped at
 * log2(window size), so a too-small window understates (a 1-byte window is
 * always 0). The floor keeps small files meaningful: a 512-byte encrypted blob
 * reads near 8 bits rather than collapsing to a flat 0.
 */
export function entropyProfile(
  bytes: Uint8Array,
  windows: number,
  minWindowBytes = 256,
): number[] {
  if (bytes.length === 0 || windows <= 0) return []
  const size = Math.max(minWindowBytes, Math.ceil(bytes.length / windows))
  const out: number[] = []
  for (let start = 0; start < bytes.length; start += size) {
    out.push(shannonEntropy(bytes.subarray(start, Math.min(start + size, bytes.length))))
  }
  return out
}
