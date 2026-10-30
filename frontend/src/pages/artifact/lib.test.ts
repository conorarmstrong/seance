import { describe, expect, it } from 'vitest'
import type { Artifact } from '../../api/types'
import { formatUtc } from '../../lib/format'
import {
  artifactDisplayName,
  formatMs,
  hexToBytes,
  inspectAt,
  parseOffsetInput,
  previewKindForName,
  tabsForArtifact,
} from './lib'

function makeArtifact(overrides: Partial<Artifact>): Artifact {
  return {
    id: 'art-1',
    case_id: 'case-1',
    parent_id: null,
    artifact_type: 'FileContent',
    metadata: {},
    ...overrides,
  }
}

describe('artifactDisplayName', () => {
  it('prefers metadata.name', () => {
    const a = makeArtifact({
      metadata: { name: 'report.docx', source_path: '/x/other.bin' },
    })
    expect(artifactDisplayName(a)).toBe('report.docx')
  })

  it('falls back to source_path basename', () => {
    const a = makeArtifact({ metadata: { source_path: '/mnt/img/photo.jpg' } })
    expect(artifactDisplayName(a)).toBe('photo.jpg')
  })

  it('handles windows separators in source_path', () => {
    const a = makeArtifact({
      metadata: { source_path: 'C:\\Users\\bob\\file.txt' },
    })
    expect(artifactDisplayName(a)).toBe('file.txt')
  })

  it('falls back to the artifact id', () => {
    const a = makeArtifact({ metadata: {} })
    expect(artifactDisplayName(a)).toBe('art-1')
  })
})

describe('parseOffsetInput', () => {
  it('parses decimal', () => {
    expect(parseOffsetInput('512')).toBe(512)
  })

  it('parses 0x-prefixed hex', () => {
    expect(parseOffsetInput('0x200')).toBe(512)
  })

  it('parses bare hex digits', () => {
    expect(parseOffsetInput('ff')).toBe(255)
  })

  it('rejects garbage and empty input', () => {
    expect(parseOffsetInput('zz')).toBeNull()
    expect(parseOffsetInput('')).toBeNull()
    expect(parseOffsetInput('   ')).toBeNull()
  })
})

describe('formatMs', () => {
  it('formats sub-second values in ms', () => {
    expect(formatMs(42)).toBe('42 ms')
  })

  it('formats seconds', () => {
    expect(formatMs(1500)).toBe('1.5 s')
  })

  it('formats minutes', () => {
    expect(formatMs(90000)).toBe('1m 30s')
  })

  it('handles missing values', () => {
    expect(formatMs(null)).toBe('—')
    expect(formatMs(undefined)).toBe('—')
  })
})

describe('tabsForArtifact', () => {
  const ids = (a: Artifact) => tabsForArtifact(a).map((t) => t.id)

  it('gives FileContent hex and text tabs', () => {
    const tabs = ids(makeArtifact({ artifact_type: 'FileContent' }))
    expect(tabs).toContain('hex')
    expect(tabs).toContain('text')
    expect(tabs).not.toContain('children')
    expect(tabs).not.toContain('registry')
    expect(tabs).not.toContain('rawjson')
  })

  it('gives every artifact a Timeline tab for the events around it', () => {
    for (const artifact_type of ['FileEntry', 'FileContent', 'ParsedRecord', 'RawEvidence'] as const) {
      expect(ids(makeArtifact({ artifact_type }))).toContain('timeline')
    }
  })

  it('always includes processing and run, but not overview/properties', () => {
    // Overview and Properties are no longer tabs — they live in the Inspector.
    const tabs = ids(makeArtifact({ artifact_type: 'TimelineEvent' }))
    expect(tabs).toEqual(expect.arrayContaining(['processing', 'run']))
    expect(tabs).not.toContain('overview')
    expect(tabs).not.toContain('properties')
  })

  it('gives RawEvidence hex and children tabs', () => {
    const tabs = ids(makeArtifact({ artifact_type: 'RawEvidence' }))
    expect(tabs).toContain('hex')
    expect(tabs).toContain('children')
    expect(tabs).not.toContain('text')
  })

  it('gives whole-device artifacts a disk map tab', () => {
    expect(ids(makeArtifact({ artifact_type: 'RawEvidence' }))).toContain(
      'diskmap',
    )
    expect(ids(makeArtifact({ artifact_type: 'Container' }))).toContain(
      'diskmap',
    )
  })

  it('omits the disk map tab for non-device artifacts', () => {
    expect(ids(makeArtifact({ artifact_type: 'FileEntry' }))).not.toContain(
      'diskmap',
    )
    expect(ids(makeArtifact({ artifact_type: 'FileSystem' }))).not.toContain(
      'diskmap',
    )
  })

  it('gives FileSystem a children tab but no hex', () => {
    const tabs = ids(makeArtifact({ artifact_type: 'FileSystem' }))
    expect(tabs).toContain('children')
    expect(tabs).not.toContain('hex')
  })

  it('gives FileSystem an allocation map tab (but not device types)', () => {
    expect(ids(makeArtifact({ artifact_type: 'FileSystem' }))).toContain(
      'allocation',
    )
    expect(ids(makeArtifact({ artifact_type: 'RawEvidence' }))).not.toContain(
      'allocation',
    )
    expect(ids(makeArtifact({ artifact_type: 'FileEntry' }))).not.toContain(
      'allocation',
    )
  })

  it('gives a readable file an entropy tab, and a layout tab only with data_runs', () => {
    const plain = makeArtifact({
      artifact_type: 'FileEntry',
      metadata: { name: 'a.bin' },
    })
    expect(ids(plain)).toContain('entropy')
    expect(ids(plain)).not.toContain('layout')

    const fragged = makeArtifact({
      artifact_type: 'FileEntry',
      metadata: {
        name: 'a.bin',
        data_runs: [
          [0, 100],
          [400, 50],
        ],
      },
    })
    expect(ids(fragged)).toContain('layout')

    // Directories and non-file types get neither.
    expect(
      ids(
        makeArtifact({
          artifact_type: 'FileEntry',
          metadata: { name: 'dir', is_directory: true },
        }),
      ),
    ).not.toContain('entropy')
    expect(ids(makeArtifact({ artifact_type: 'FileSystem' }))).not.toContain(
      'entropy',
    )
  })

  it('gives FileSystem files and treemap tabs', () => {
    const tabs = ids(makeArtifact({ artifact_type: 'FileSystem' }))
    expect(tabs).toContain('files')
    expect(tabs).toContain('treemap')
    // Not on plain files or whole-device artifacts.
    expect(ids(makeArtifact({ artifact_type: 'FileEntry' }))).not.toContain(
      'treemap',
    )
    expect(ids(makeArtifact({ artifact_type: 'RawEvidence' }))).not.toContain(
      'files',
    )
  })

  it('gives registry hives a registry tab', () => {
    const tabs = ids(
      makeArtifact({
        artifact_type: 'SystemArtifact',
        metadata: { type: 'RegistryHive' },
      }),
    )
    expect(tabs).toContain('registry')
    expect(tabs).not.toContain('conversation')
  })

  it('gives a chat.db file a conversation tab', () => {
    const tabs = ids(
      makeArtifact({
        artifact_type: 'FileEntry',
        metadata: { name: 'chat.db' },
      }),
    )
    expect(tabs).toContain('conversation')
    expect(tabs).not.toContain('registry')
  })

  it('recognises other messaging databases case-insensitively', () => {
    expect(
      ids(makeArtifact({ metadata: { name: 'ChatStorage.sqlite' } })),
    ).toContain('conversation')
    expect(
      ids(
        makeArtifact({
          artifact_type: 'FileEntry',
          metadata: { name: 'MsgStore.DB' },
        }),
      ),
    ).toContain('conversation')
  })

  it('omits the conversation tab for non-messaging files', () => {
    const tabs = ids(
      makeArtifact({
        artifact_type: 'FileEntry',
        metadata: { name: 'notes.txt' },
      }),
    )
    expect(tabs).not.toContain('conversation')
  })

  it('gives parsed records a raw JSON tab', () => {
    expect(ids(makeArtifact({ artifact_type: 'ParsedRecord' }))).toContain(
      'rawjson',
    )
    expect(ids(makeArtifact({ artifact_type: 'TimelineEvent' }))).toContain(
      'rawjson',
    )
  })
})

describe('previewKindForName', () => {
  it('detects raster image extensions', () => {
    expect(previewKindForName('photo.PNG')).toBe('image')
    expect(previewKindForName('scan.jpeg')).toBe('image')
    expect(previewKindForName('anim.webp')).toBe('image')
  })

  it('detects text-like extensions', () => {
    expect(previewKindForName('notes.txt')).toBe('text')
    expect(previewKindForName('config.INI')).toBe('text')
    expect(previewKindForName('data.json')).toBe('text')
  })

  it('detects video extensions', () => {
    expect(previewKindForName('clip.MOV')).toBe('video')
    expect(previewKindForName('capture.wmv')).toBe('video')
    expect(previewKindForName('movie.mp4')).toBe('video')
    expect(previewKindForName('rec.mkv')).toBe('video')
  })

  it('detects office document extensions', () => {
    expect(previewKindForName('report.DOC')).toBe('office')
    expect(previewKindForName('sheet.xlsx')).toBe('office')
    expect(previewKindForName('deck.pptx')).toBe('office')
  })

  it('detects PDF', () => {
    expect(previewKindForName('document.pdf')).toBe('pdf')
    expect(previewKindForName('SCAN.PDF')).toBe('pdf')
  })

  it('returns null for unknown or missing extensions', () => {
    expect(previewKindForName('DCIM0001')).toBeNull()
    expect(previewKindForName('trailing.')).toBeNull()
  })
})

describe('tabsForArtifact preview ordering', () => {
  it('puts the preview tab first when a preview kind is given', () => {
    const tabs = tabsForArtifact(
      {
        id: 'a',
        case_id: 'c',
        parent_id: null,
        artifact_type: 'FileContent',
        metadata: {},
      },
      'image',
    )
    expect(tabs[0].id).toBe('preview')
  })

  it('omits the preview tab when no preview kind is given', () => {
    const tabs = tabsForArtifact({
      id: 'a',
      case_id: 'c',
      parent_id: null,
      artifact_type: 'FileContent',
      metadata: {},
    })
    expect(tabs.some((t) => t.id === 'preview')).toBe(false)
  })
})

describe('hexToBytes', () => {
  it('parses space-separated hex bytes', () => {
    expect(hexToBytes('00 ff 41')).toEqual([0, 255, 65])
  })

  it('handles empty input', () => {
    expect(hexToBytes('')).toEqual([])
    expect(hexToBytes('   ')).toEqual([])
  })
})

describe('inspectAt', () => {
  const field = (fields: { label: string; value: string }[], label: string) =>
    fields.find((f) => f.label === label)?.value

  it('decodes little-endian integers', () => {
    // 0x5CA02880 = 1554000000
    const bytes = hexToBytes('80 28 a0 5c 00 00 00 00')
    const fields = inspectAt(bytes, 0)
    expect(field(fields, 'u8')).toBe('128')
    expect(field(fields, 'u16le')).toBe('10368')
    expect(field(fields, 'u32le')).toBe('1554000000')
    expect(field(fields, 'i32le')).toBe('1554000000')
    expect(field(fields, 'u64le')).toBe('1554000000')
  })

  it('decodes negative i32 values', () => {
    const fields = inspectAt(hexToBytes('ff ff ff ff'), 0)
    expect(field(fields, 'u32le')).toBe('4294967295')
    expect(field(fields, 'i32le')).toBe('-1')
  })

  it('interprets plausible unix timestamps as UTC', () => {
    const fields = inspectAt(hexToBytes('80 28 a0 5c 00 00 00 00'), 0)
    expect(field(fields, 'Unix time (u32le s)')).toBe(
      formatUtc(new Date(1554000000 * 1000).toISOString()),
    )
  })

  it('omits implausible timestamp interpretations', () => {
    const fields = inspectAt(hexToBytes('01 00 00 00 00 00 00 00'), 0)
    expect(field(fields, 'Unix time (u32le s)')).toBeUndefined()
    expect(field(fields, 'FILETIME (u64le)')).toBeUndefined()
  })

  it('interprets plausible FILETIME values as UTC', () => {
    // 132000000000000000 * 100ns since 1601 = 2019-04-17T16:00:00Z epoch ms
    const filetime = 132000000000000000n
    const bytes: number[] = []
    for (let i = 0; i < 8; i++) {
      bytes.push(Number((filetime >> BigInt(8 * i)) & 0xffn))
    }
    const fields = inspectAt(bytes, 0)
    const expectedMs = Number((filetime - 116444736000000000n) / 10000n)
    expect(field(fields, 'FILETIME (u64le)')).toBe(
      formatUtc(new Date(expectedMs).toISOString()),
    )
  })

  it('omits fields whose width runs past the loaded bytes', () => {
    const fields = inspectAt(hexToBytes('41 42'), 1)
    expect(field(fields, 'u8')).toBe('66')
    expect(field(fields, 'u16le')).toBeUndefined()
    expect(field(fields, 'u32le')).toBeUndefined()
    expect(field(fields, 'u64le')).toBeUndefined()
  })
})
