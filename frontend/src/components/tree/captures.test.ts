// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, it, expect } from 'vitest'
import type { MemoryImageSummary } from '../../pages/memory/api'
import { captureSourceIndex } from './captures'

function capture(over: Partial<MemoryImageSummary>): MemoryImageSummary {
  return {
    image_id: 'img',
    source_artifact_id: null,
    name: null,
    image_format: null,
    architecture: null,
    addressable_bytes: null,
    file_bytes: null,
    declared_size: null,
    size_mismatch: false,
    decode_failed: false,
    content_complete: null,
    content_complete_known: false,
    incomplete: null,
    analysis_state: 'complete' as MemoryImageSummary['analysis_state'],
    analysis_state_meaning: '',
    profile: null,
    stage_failures: 0,
    ...over,
  }
}

describe('captureSourceIndex', () => {
  it('maps each source artifact to its capture', () => {
    const index = captureSourceIndex([
      capture({ image_id: 'a', source_artifact_id: 'src-1' }),
      capture({ image_id: 'b', source_artifact_id: 'src-2' }),
    ])
    expect(index.get('src-1')?.image_id).toBe('a')
    expect(index.get('src-2')?.image_id).toBe('b')
    expect(index.size).toBe(2)
  })

  it('skips captures with no known source rather than mis-pinning them', () => {
    const index = captureSourceIndex([
      capture({ image_id: 'a', source_artifact_id: null }),
      capture({ image_id: 'b', source_artifact_id: 'src-2' }),
    ])
    expect(index.has('src-2')).toBe(true)
    expect(index.size).toBe(1)
  })

  it('tolerates an absent image list', () => {
    expect(captureSourceIndex(undefined).size).toBe(0)
  })
})
