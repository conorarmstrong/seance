// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { StageEnvelope } from './api'
import {
  buildProcessRows,
  deriveConfidence,
  envelopeStatus,
  failureSummary,
  fieldText,
  fieldTitle,
  formatAddress,
  formatQualifiedCount,
  formatTime,
  hexAddress,
  incompleteLabel,
  laneAxis,
  placeOnLane,
  presenceFor,
  presenceLabel,
  readCrossview,
  fieldLeaf,
  readNumberField,
  readProcesses,
  readStageRows,
  readTamperingSignals,
  readWireText,
  readWireTextOf,
  wireKind,
  readSymbolState,
  readTimeField,
  readTreeNodes,
  recordConfidence,
  filetimeText,
  inventoryCount,
  readCredentialInventory,
  splitCredentialsByImage,
  timeText,
  toHex,
} from './normalize'

function envelope(overrides: Partial<StageEnvelope> = {}): StageEnvelope {
  return {
    stage: 'processes',
    record_type: 'MemoryProcessList',
    describes: 'the active process list',
    per_process: false,
    image_id: 'image-1',
    scoped_to_image: true,
    stage_ran: true,
    status: 'complete',
    status_meaning: 'Ran, and every record declared itself complete.',
    record_count: 1,
    records_returned: 1,
    records_truncated: false,
    rows_incomplete: 0,
    rows_completeness_ungraded: 0,
    count_is_floor: false,
    failures: [],
    failures_truncated: false,
    records: [],
    ...overrides,
  }
}

describe('readField', () => {
  it('reads a value the analysis said it knew', () => {
    expect(readNumberField({ kind: 'known', value: 4 })).toEqual({
      known: true,
      value: 4,
    })
  })

  it('keeps "this build has no such member" apart from "the bytes were unreadable"', () => {
    const notDeclared = readNumberField({
      kind: 'not_declared',
      member: 'WoW64Process',
    })
    const unavailable = readNumberField({
      kind: 'unavailable',
      detail: 'page not in the capture',
    })
    expect(notDeclared).toEqual({
      known: false,
      reason: 'not_declared',
      detail: 'WoW64Process',
    })
    expect(unavailable).toEqual({
      known: false,
      reason: 'unavailable',
      detail: 'page not in the capture',
    })
    expect(fieldText(notDeclared)).not.toBe(fieldText(unavailable))
  })

  it('refuses a value of the wrong type rather than coercing it', () => {
    expect(readNumberField({ kind: 'known', value: 'four' })).toMatchObject({
      known: false,
      reason: 'malformed',
    })
  })

  it('treats an envelope shape it does not recognise as malformed, never as a value', () => {
    expect(readNumberField({ kind: 'brand_new_kind' })).toMatchObject({
      known: false,
      reason: 'malformed',
    })
    expect(readNumberField(4)).toMatchObject({ known: false, reason: 'malformed' })
  })

  it('renders a different word for every kind of absence', () => {
    const words = new Set(
      [
        readNumberField({ kind: 'not_applicable' }),
        readNumberField({ kind: 'not_declared', member: 'x' }),
        readNumberField({ kind: 'unavailable', detail: 'y' }),
        readNumberField(null),
      ].map(fieldText),
    )
    expect(words.size).toBe(4)
  })

  it('explains what an absence does and does not mean on hover', () => {
    expect(
      fieldTitle(readNumberField({ kind: 'unavailable', detail: 'page missing' })),
    ).toMatch(/could not be read/)
  })
})

describe('readWireText (B8-037)', () => {
  it('decodes a handle name the walk recovered', () => {
    // `HandleName::to_json`. Read as a plain string this was null, so a handle
    // table full of file and key paths rendered "not recorded" on every row.
    expect(
      readWireText({ kind: 'name', name: '\\Device\\HarddiskVolume2\\pagefile.sys' }),
    ).toEqual({
      known: true,
      value: '\\Device\\HarddiskVolume2\\pagefile.sys',
    })
  })

  it('decodes a hive path and a VAD mapped file', () => {
    expect(
      readWireText({
        kind: 'path',
        text: '\\SystemRoot\\System32\\Config\\SOFTWARE',
        source: 'FileFullPath',
        well_formed: true,
      }),
    ).toEqual({ known: true, value: '\\SystemRoot\\System32\\Config\\SOFTWARE' })
    expect(readWireText({ kind: 'known', value: 'Spooler' })).toEqual({
      known: true,
      value: 'Spooler',
    })
  })

  it('keeps "there is nothing to name" apart from "the name would not read"', () => {
    for (const kind of ['unnamed', 'no_mapped_file', 'no_backing_file']) {
      expect(readWireText({ kind })).toEqual({
        known: false,
        reason: 'none',
        detail: '',
      })
    }
    expect(
      readWireText({ kind: 'unavailable', detail: 'the object body is not in the capture' }),
    ).toEqual({
      known: false,
      reason: 'unavailable',
      detail: 'the object body is not in the capture',
    })
  })

  it('carries the reason out of a hive name that could not be read', () => {
    expect(
      readWireText({
        kind: 'unavailable',
        incomplete: { reason: 'read_hole', detail: 'the page is absent' },
      }),
    ).toEqual({
      known: false,
      reason: 'unavailable',
      detail: 'read_hole: the page is absent',
    })
  })

  it('reports an envelope it does not know as malformed, never as an absence', () => {
    // A producer that renames a kind must not silently blank a column: a
    // malformed cell is a question an examiner can ask, an empty one is not.
    expect(readWireText({ kind: 'renamed_by_a_future_build' })).toEqual({
      known: false,
      reason: 'malformed',
      detail: 'unknown envelope kind renamed_by_a_future_build',
    })
    expect(readWireText(42).known).toBe(false)
    expect(readWireText({ kind: 'name' })).toEqual({
      known: false,
      reason: 'malformed',
      detail: 'a name envelope carried no text',
    })
  })

  it('still reads a flat string alias, since some producers emit both', () => {
    expect(readWireText('svchost.exe')).toEqual({
      known: true,
      value: 'svchost.exe',
    })
  })

  it('prefers a key that decoded a value, keeping the first stated reason otherwise', () => {
    const data = {
      name: { kind: 'unavailable', detail: 'paged out' },
      object_name: 'fallback.dll',
    }
    expect(readWireTextOf(data, ['name', 'object_name'])).toEqual({
      known: true,
      value: 'fallback.dll',
    })
    expect(readWireTextOf(data, ['name'])).toEqual({
      known: false,
      reason: 'unavailable',
      detail: 'paged out',
    })
    // A key nothing sent at all is "not stated": unanswered. Deliberately NOT
    // `not_recorded`, whose hover sentence is written for a zero FILETIME —
    // "the event did not happen" — and would be a claim about the machine that
    // a missing key cannot support.
    expect(readWireTextOf({}, ['name'])).toEqual({
      known: false,
      reason: 'not_stated',
      detail: '',
    })
  })

  it('takes the leaf of a path without inventing one for an absence', () => {
    expect(
      fieldLeaf(readWireText({ kind: 'name', name: 'C:\\Windows\\explorer.exe' })),
    ).toEqual({ known: true, value: 'explorer.exe' })
    expect(fieldLeaf(readWireText({ kind: 'unnamed' })).known).toBe(false)
  })

  it('exposes the producer\'s own kind tag', () => {
    expect(wireKind({ kind: 'no_backing_file' })).toBe('no_backing_file')
    expect(wireKind('a string')).toBeNull()
  })
})

describe('readTimeField', () => {
  it('reads a recorded time', () => {
    expect(
      readTimeField({ kind: 'at', rfc3339: '2025-03-11T09:14:02Z' }),
    ).toEqual({ known: true, value: '2025-03-11T09:14:02Z' })
  })

  it('calls an absent time not applicable rather than malformed', () => {
    // The Linux task list carries no creation or exit time — task_struct is not
    // where those live. Reading a missing key as "malformed" told an examiner
    // the evidence was corrupt on every one of 133 rows. Absent and unparseable
    // are different claims.
    for (const missing of [undefined, null]) {
      const field = readTimeField(missing)
      expect(field.known).toBe(false)
      expect(field.known === false && field.reason).toBe('not_applicable')
    }
    // A value that is present and the wrong shape is still malformed.
    const bad = readTimeField('2025-03-11')
    expect(bad.known === false && bad.reason).toBe('malformed')
  })

  it('never renders a zero FILETIME as 1601', () => {
    const field = readTimeField({ kind: 'not_recorded' })
    expect(field.known).toBe(false)
    expect(timeText(field)).toBe('—')
    expect(timeText(field)).not.toMatch(/1601/)
  })

  it('keeps an implausible stored time rather than dropping it', () => {
    const field = readTimeField({ kind: 'implausible', raw: '-12' })
    expect(field).toMatchObject({ known: false, reason: 'implausible', detail: '-12' })
    expect(timeText(field)).toBe('implausible value')
  })

  it('distinguishes an unreadable time from one that was never recorded', () => {
    expect(timeText(readTimeField({ kind: 'unavailable', detail: 'x' }))).not.toBe(
      timeText(readTimeField({ kind: 'not_recorded' })),
    )
  })
})

describe('deriveConfidence', () => {
  const clean = {
    derivation: 'linked' as const,
    sources: ['list walk'],
    incomplete: null,
    symbol_confidence: 'verified' as const,
    profile_evidence: 'confirmed' as const,
  }

  it('grades a clean list-walked row as linked', () => {
    expect(deriveConfidence(clean).level).toBe('linked')
  })

  it('grades a row with no confidence metadata as unreliable rather than assuming it is clean', () => {
    expect(deriveConfidence(null).level).toBe('unreliable')
  })

  it('grades a pool-scanned row as scanned even when every other axis is clean', () => {
    expect(
      deriveConfidence({ ...clean, derivation: 'scanned' }).level,
    ).toBe('scanned')
  })

  it('grades a row read through a scanned profile as scanned, because everything downstream inherits it', () => {
    expect(
      deriveConfidence({ ...clean, profile_evidence: 'scanned' }).level,
    ).toBe('scanned')
  })

  it('grades a row whose profile grade was never stated as approximate', () => {
    expect(
      deriveConfidence({ ...clean, profile_evidence: null }).level,
    ).toBe('approximate')
  })

  it('grades a row decoded with no admitted symbol table as unreliable', () => {
    expect(
      deriveConfidence({ ...clean, symbol_confidence: null }).level,
    ).toBe('unreliable')
  })

  it('grades a row decoded with unverified symbols as approximate', () => {
    expect(
      deriveConfidence({ ...clean, symbol_confidence: 'unverified' }).level,
    ).toBe('approximate')
  })

  it('grades a row with unread bytes as partial and names what was missing', () => {
    const verdict = deriveConfidence({
      ...clean,
      incomplete: { reason: 'read_hole', detail: '0x1000 for 4 KiB' },
    })
    expect(verdict.level).toBe('partial')
    expect(verdict.reasons.find((r) => r.axis === 'reads')?.detail).toMatch(
      /0x1000 for 4 KiB/,
    )
  })

  it('grades a carved row with no corroboration as unreliable', () => {
    expect(
      deriveConfidence({ ...clean, derivation: 'carved', sources: [] }).level,
    ).toBe('unreliable')
  })

  it('grades a carved row corroborated twice as scanned, not unreliable', () => {
    expect(
      deriveConfidence({
        ...clean,
        derivation: 'carved',
        sources: ['pool scan', 'thread owner'],
      }).level,
    ).toBe('scanned')
  })

  it('takes the weakest axis when several are degraded', () => {
    expect(
      deriveConfidence({
        ...clean,
        derivation: 'scanned',
        incomplete: { reason: 'cap_reached', detail: null },
        symbol_confidence: 'unverified',
      }).level,
    ).toBe('approximate')
  })

  it('reports all five axes so the popover can never be half-empty', () => {
    expect(deriveConfidence(clean).reasons.map((r) => r.axis)).toEqual([
      'derivation',
      'corroboration',
      'reads',
      'symbols',
      'profile',
    ])
  })
})

describe('recordConfidence', () => {
  it('reads the grade the analysis stamped rather than assuming one', () => {
    const confidence = recordConfidence('processes', {
      profile_evidence: 'validated',
      symbols_verified: true,
      content_complete: true,
    })
    expect(confidence).toMatchObject({
      derivation: 'linked',
      symbol_confidence: 'verified',
      profile_evidence: 'validated',
      incomplete: null,
    })
  })

  it('marks a record from an unfinished stage incomplete', () => {
    expect(
      recordConfidence('processes', { content_complete: false })?.incomplete,
    ).toMatchObject({ reason: 'stage_incomplete' })
  })

  it('grades a suspicious-thread record as inferred', () => {
    // MEM-024: the finding is inferred from which VAD a start address lands
    // in, not read from a structure that states it.
    expect(recordConfidence('suspicious_threads', {}).derivation).toBe(
      'inferred',
    )
  })

  it('calls a pool-scan row scanned whatever the row looks like', () => {
    expect(recordConfidence('pool_scan', {}).derivation).toBe('scanned')
  })

  it('leaves the symbol grade unstated when the analysis did not stamp one', () => {
    expect(recordConfidence('processes', {}).symbol_confidence).toBeNull()
  })
})

describe('envelopeStatus', () => {
  it('reports a stage that did not run, and never as an empty result', () => {
    const status = envelopeStatus(
      envelope({
        status: 'did_not_run',
        status_meaning: 'Nothing ran.',
        record_count: 0,
      }),
    )
    expect(status.kind).toBe('not_run')
  })

  it('names the failure records alongside the stage status', () => {
    const status = envelopeStatus(
      envelope({
        status: 'failed',
        status_meaning: 'Produced no results.',
        record_count: 0,
        failures: [
          {
            id: 'f1',
            image_id: 'image-1',
            name: null,
            stage: 'processes',
            stages: null,
            failure: 'PsActiveProcessHead was not readable',
            pid: null,
            process_name: null,
            profile_evidence: null,
          },
        ],
      }),
    )
    expect(status.kind).toBe('not_run')
    expect(status.kind === 'not_run' && status.message).toMatch(
      /PsActiveProcessHead was not readable/,
    )
  })

  it('treats a missing envelope as not run, because nothing is known about it', () => {
    expect(envelopeStatus(undefined).kind).toBe('not_run')
  })

  it('reports a capped stage as partial and names the cap', () => {
    const status = envelopeStatus(
      envelope({
        status: 'incomplete',
        count_is_floor: true,
        records_truncated: true,
        record_count: 5000,
        records_returned: 500,
      }),
    )
    expect(status.kind).toBe('partial')
    expect(status.kind === 'partial' && status.message).toMatch(/500 of 5,000/)
  })

  it('reports a per-process search that stopped at a cap as undetermined, not as empty', () => {
    const status = envelopeStatus(
      envelope({
        status: 'not_determined',
        status_meaning: 'The search stopped at the scan cap.',
        record_count: 0,
      }),
    )
    expect(status.kind).toBe('undetermined')
  })

  it('distinguishes a stage that ran and found nothing from one that did not run', () => {
    // The stage ran: it emitted one record. That record held no rows, which is
    // the "found nothing" answer, and it must not read like the "did not run"
    // answer above.
    const ran = envelope({
      status: 'complete',
      status_meaning: 'Ran, and every record it produced declared itself complete.',
      record_count: 1,
      records_returned: 1,
      records: [{ id: 'r1', image_id: 'image-1', data: { connections: [] } }],
    })
    expect(envelopeStatus(ran, 0)).toEqual({ kind: 'empty' })
    expect(envelopeStatus(envelope({ record_count: 0 })).kind).toBe('not_run')
  })

  it('reports a stage with rows to show as complete', () => {
    const ran = envelope({
      status: 'complete',
      record_count: 1,
      records_returned: 1,
      records: [{ id: 'r1', image_id: 'image-1', data: { connections: [{}] } }],
    })
    expect(envelopeStatus(ran, 1)).toEqual({ kind: 'complete' })
  })

  it('never calls a stage complete just because it emitted a record with no rows in it', () => {
    // The regression this guards: `record_count` counts records, not rows, so a
    // stage that ran and found nothing looks identical to a full one unless the
    // decoded row count is consulted.
    const ran = envelope({
      status: 'complete',
      record_count: 1,
      records_returned: 1,
      records: [{ id: 'r1', image_id: 'image-1', data: { services: [] } }],
    })
    expect(envelopeStatus(ran).kind).toBe('complete')
    expect(envelopeStatus(ran, 0).kind).toBe('empty')
  })
})

describe('failureSummary', () => {
  it('names the pid a per-process failure belongs to', () => {
    expect(
      failureSummary([
        {
          id: 'f',
          image_id: null,
          name: null,
          stage: 'handles',
          stages: null,
          failure: 'object table unreadable',
          pid: 1064,
          process_name: 'svchost.exe',
          profile_evidence: null,
        },
      ]),
    ).toBe('handles (pid 1064 svchost.exe): object table unreadable')
  })

  it('says so when a failure record carried no reason', () => {
    expect(
      failureSummary([
        {
          id: 'f',
          image_id: null,
          name: null,
          stage: null,
          stages: null,
          failure: null,
          pid: null,
          process_name: null,
          profile_evidence: null,
        },
      ]),
    ).toBe('a stage: no reason recorded')
  })
})

describe('readProcesses', () => {
  const known = (value: unknown) => ({ kind: 'known', value })

  it('reads the Linux task list, which names its rows tasks and not processes', () => {
    // Windows calls the array `processes` and the name `image_file_name`; the
    // Linux tier walks init_task and calls them `tasks` and `comm`. Reading only
    // the Windows spelling showed a real capture's 133 processes as none at all,
    // under a coverage table that said the stage had run.
    const rows = readProcesses(
      envelope({
        records: [
          {
            id: 'r1',
            image_id: 'image-1',
            data: {
              tasks: [
                { pid: known(1), ppid: known(0), comm: known('init') },
                { pid: known(17), ppid: known(2), comm: known('kswapd0') },
              ],
            },
          },
        ],
      }),
    )
    expect(rows).toHaveLength(2)
    expect(rows.map((r) => (r.name.known ? r.name.value : null))).toEqual([
      'init',
      'kswapd0',
    ])
    expect(rows.map((r) => (r.pid.known ? r.pid.value : null))).toEqual([1, 17])
  })

  it('decodes every process out of the list record', () => {
    const rows = readProcesses(
      envelope({
        records: [
          {
            id: 'r1',
            image_id: 'image-1',
            data: {
              profile_evidence: 'confirmed',
              symbols_verified: true,
              content_complete: true,
              processes: [
                {
                  address: 0x1000,
                  direction: 'forward',
                  pid: known(4),
                  ppid: known(0),
                  image_file_name: known('System'),
                  threads: known(120),
                  handles: known(3000),
                  session_id: known(0),
                  create_time: { kind: 'at', rfc3339: '2025-03-11T09:14:02Z' },
                  exit_time: { kind: 'not_recorded' },
                  has_exited: false,
                  unreadable_fields: [],
                  notes: [],
                },
              ],
            },
          },
        ],
      }),
    )
    expect(rows).toHaveLength(1)
    expect(rows[0].pid).toEqual({ known: true, value: 4 })
    expect(rows[0].address).toBe('0x1000')
    expect(rows[0].confidence.derivation).toBe('linked')
  })

  it('reads the _EPROCESS address from its exact hex sibling', () => {
    // The named consumer of the B3-M04 fix. A rounded _EPROCESS address quoted
    // in a report is off by up to a kilobyte and points at nothing.
    const rows = readProcesses(
      envelope({
        records: [
          {
            id: 'r1',
            image_id: 'image-1',
            data: {
              processes: [
                {
                  address: 0xfffff8030a1b2c30,
                  address_hex: '0xfffff8030a1b2c37',
                  direction: 'forward',
                  pid: known(4),
                },
              ],
            },
          },
        ],
      }),
    )
    expect(rows[0].address).toBe('0xfffff8030a1b2c37')
    expect(rows[0].address).not.toContain('rounded')
  })

  it('marks a row whose fields could not be read as incomplete rather than blank', () => {
    const rows = readProcesses(
      envelope({
        records: [
          {
            id: 'r1',
            image_id: 'image-1',
            data: {
              ...{ profile_evidence: 'confirmed', symbols_verified: true },
              processes: [
                {
                  address: 0x2000,
                  pid: { kind: 'unavailable', detail: 'page missing' },
                  unreadable_fields: ['pid'],
                },
              ],
            },
          },
        ],
      }),
    )
    expect(rows[0].unreadableFields).toEqual(['pid'])
    expect(rows[0].confidence.incomplete).toMatchObject({
      reason: 'unreadable_fields',
    })
    expect(rows[0].pid.known).toBe(false)
  })

  it('returns nothing at all for a stage that produced no record', () => {
    expect(readProcesses(envelope({ records: [] }))).toEqual([])
    expect(readProcesses(undefined)).toEqual([])
  })
})

describe('readTreeNodes and buildProcessRows', () => {
  const rows = readProcesses(
    envelope({
      records: [
        {
          id: 'r1',
          image_id: 'image-1',
          data: {
            profile_evidence: 'confirmed',
            symbols_verified: true,
            processes: [
              { address: 1, pid: { kind: 'known', value: 4 } },
              { address: 2, pid: { kind: 'known', value: 380 } },
            ],
          },
        },
      ],
    }),
  )

  it('reads a tree node address from its exact hex sibling', () => {
    const nodes = readTreeNodes(
      envelope({
        records: [
          {
            id: 't1',
            image_id: 'image-1',
            data: {
              nodes: [
                {
                  address: 0xfffff8030a1b2c30,
                  address_hex: '0xfffff8030a1b2c37',
                  pid: 4,
                  parent: null,
                  children: [],
                  depth: 0,
                  link: { kind: 'root' },
                },
              ],
            },
          },
        ],
      }),
    )
    expect(nodes[0].address).toBe('0xfffff8030a1b2c37')
  })

  it('uses the depth the analysis assigned rather than recomputing parentage', () => {
    const nodes = readTreeNodes(
      envelope({
        records: [
          {
            id: 't1',
            image_id: 'image-1',
            data: {
              nodes: [
                {
                  address: 1,
                  pid: 4,
                  parent: null,
                  children: [1],
                  depth: 0,
                  link: { kind: 'root' },
                },
                {
                  address: 2,
                  pid: 380,
                  parent: 0,
                  children: [],
                  depth: 1,
                  link: { kind: 'unverified', detail: 'pid match only' },
                },
              ],
            },
          },
        ],
      }),
    )
    const built = buildProcessRows(rows, nodes)
    expect(built.map((entry) => entry.depth)).toEqual([0, 1])
    expect(built[1].link).toBe('unverified')
    expect(built[1].linkDetail).toBe('pid match only')
  })

  it('falls back to a flat list when the tree stage produced nothing', () => {
    const built = buildProcessRows(rows, [])
    expect(built.map((entry) => entry.depth)).toEqual([0, 0])
    expect(built.every((entry) => entry.link === 'unknown')).toBe(true)
  })

  it('does not recurse forever on a child list that points back up', () => {
    const nodes = readTreeNodes(
      envelope({
        records: [
          {
            id: 't1',
            image_id: 'image-1',
            data: {
              nodes: [
                { address: 1, pid: 4, parent: null, children: [1], depth: 0 },
                { address: 2, pid: 380, parent: 0, children: [0], depth: 1 },
              ],
            },
          },
        ],
      }),
    )
    const built = buildProcessRows(rows, nodes)
    expect(built).toHaveLength(2)
  })

  it('appends a node the roots never reached rather than dropping it', () => {
    const nodes = readTreeNodes(
      envelope({
        records: [
          {
            id: 't1',
            image_id: 'image-1',
            data: {
              nodes: [
                { address: 1, pid: 4, parent: null, children: [], depth: 0 },
                {
                  address: 2,
                  pid: 380,
                  parent: 7,
                  children: [],
                  depth: 1,
                  link: { kind: 'orphaned' },
                },
              ],
            },
          },
        ],
      }),
    )
    const built = buildProcessRows(rows, nodes)
    expect(built.map((entry) => entry.index).sort()).toEqual([0, 1])
  })

  it('keeps a process the tree stage produced no node for, rather than dropping it', () => {
    // The tree stage and the list stage cap independently. A tree that stopped
    // one node short must not remove a recovered process from the screen.
    const nodes = readTreeNodes(
      envelope({
        records: [
          {
            id: 't1',
            image_id: 'image-1',
            data: {
              nodes: [
                { address: 1, pid: 4, parent: null, children: [], depth: 0 },
              ],
            },
          },
        ],
      }),
    )
    const built = buildProcessRows(rows, nodes)
    expect(built).toHaveLength(rows.length)
    const orphan = built.find((entry) => entry.index === 1)
    expect(orphan?.link).toBe('unknown')
    expect(orphan?.linkDetail).toMatch(/produced no node for this process/i)
  })

  it('reads an unknown link kind as unknown rather than as confirmed', () => {
    const nodes = readTreeNodes(
      envelope({
        records: [
          {
            id: 't1',
            image_id: 'image-1',
            data: {
              nodes: [
                {
                  address: 1,
                  pid: 4,
                  parent: null,
                  children: [],
                  depth: 0,
                  link: { kind: 'brand_new' },
                },
              ],
            },
          },
        ],
      }),
    )
    expect(nodes[0].link).toBe('unknown')
  })
})

describe('readCrossview and presenceFor', () => {
  const view = readCrossview(
    envelope({
      stage: 'cross_view',
      records: [
        {
          id: 'c1',
          image_id: 'image-1',
          data: {
            methods: [
              { key: 'list', label: 'list walk', ran: true },
              { key: 'scan', label: 'pool scan', ran: true },
              {
                key: 'csrss',
                label: 'csrss handles',
                ran: false,
                error: 'no csrss recovered',
              },
            ],
            processes: [
              { pid: 4, image_file_name: 'System', seen: { list: true, scan: false } },
            ],
          },
        },
      ],
    }),
  )

  it('reports a strategy that saw the process', () => {
    expect(presenceFor(view.methods[0], view.rows[0])).toBe('seen')
  })

  it('reports a strategy that ran and did not see the process', () => {
    expect(presenceFor(view.methods[1], view.rows[0])).toBe('not_seen')
  })

  it('reports a strategy that did not run as unknown, never as not seen', () => {
    expect(presenceFor(view.methods[2], view.rows[0])).toBe('unknown')
  })

  it('reports a process no strategy mentioned as unknown rather than absent', () => {
    expect(presenceFor(view.methods[0], undefined)).toBe('unknown')
  })

  it('names the strategies that did not run separately from those that saw nothing', () => {
    expect(presenceLabel(view.methods, view.rows[0])).toBe(
      'seen by list walk; not seen by pool scan; not checked by csrss handles',
    )
  })
})

describe('readStageRows', () => {
  it('flattens the first matching array key', () => {
    const rows = readStageRows(
      envelope({
        stage: 'network',
        records: [
          {
            id: 'n1',
            image_id: 'image-1',
            data: {
              profile_evidence: 'confirmed',
              symbols_verified: true,
              connections: [{ state: 'ESTABLISHED' }, { state: 'CLOSED' }],
            },
          },
        ],
      }),
      ['connections'],
    )
    expect(rows).toHaveLength(2)
    expect(rows[0].confidence.derivation).toBe('scanned')
  })

  it('yields no row for a stage whose row array is present and empty', () => {
    // The defect this guards against: an empty array read as "no matching key",
    // falling through to the record-as-one-row case and putting a fabricated
    // connection on screen for a scan that recovered none.
    const rows = readStageRows(
      envelope({
        stage: 'network',
        records: [
          {
            id: 'n1',
            image_id: 'image-1',
            data: { profile_evidence: 'confirmed', connections: [] },
          },
        ],
      }),
      ['connections', 'endpoints'],
    )
    expect(rows).toHaveLength(0)
  })

  it('still finds rows under a later key when an earlier one is present but empty', () => {
    const rows = readStageRows(
      envelope({
        stage: 'network',
        records: [
          {
            id: 'n1',
            image_id: 'image-1',
            data: { connections: [], endpoints: [{ state: 'LISTENING' }] },
          },
        ],
      }),
      ['connections', 'endpoints'],
    )
    expect(rows).toHaveLength(1)
    expect(rows[0].data.state).toBe('LISTENING')
  })

  it('keeps a record that holds no matching array as one row rather than dropping it', () => {
    const rows = readStageRows(
      envelope({
        stage: 'handles',
        records: [{ id: 'h1', image_id: 'image-1', data: { count: 12 } }],
      }),
      ['handles'],
    )
    expect(rows).toHaveLength(1)
    expect(rows[0].data.count).toBe(12)
  })
})

describe('readTamperingSignals', () => {
  /** `TamperingScan::to_json`: one record, processes in `examined`, signals inside those. */
  const scan = (examined: unknown) =>
    envelope({
      stage: 'tampering',
      records: [
        {
          id: 't1',
          image_id: 'image-1',
          data: { examined, examined_count: 1, skipped: [], skipped_total: 0 },
        },
      ],
    })

  it('reaches the signals two levels down and attributes each to its process', () => {
    const { rows, unreadable } = readTamperingSignals(
      scan([
        {
          pid: 712,
          image_file_name: 'lsass.exe',
          signals: [{ signal: 'image_base_mismatch' }, { signal: 'no_vad_at_image_base' }],
        },
      ]),
    )
    expect(rows).toHaveLength(2)
    expect(unreadable).toBe(0)
    expect(rows[0].data.signal).toBe('image_base_mismatch')
    // The process is on the level between, so the card can name a subject.
    expect(rows[0].record.image_file_name).toBe('lsass.exe')
    expect(rows[1].record.pid).toBe(712)
    expect(rows[0].key).not.toBe(rows[1].key)
  })

  it('yields no row for a scan that examined processes and found nothing', () => {
    // And emphatically not one row made out of the record itself: this lens
    // renders every row as a finding, so a fabricated row here is a fabricated
    // accusation.
    const { rows, unreadable } = readTamperingSignals(
      scan([{ pid: 4, image_file_name: 'System', signals: [] }]),
    )
    expect(rows).toHaveLength(0)
    expect(unreadable).toBe(0)
  })

  it('counts a record it cannot read instead of reporting it as no signals', () => {
    expect(readTamperingSignals(scan(undefined)).unreadable).toBe(1)
    expect(readTamperingSignals(scan([{ pid: 4 }])).unreadable).toBe(1)
    expect(readTamperingSignals(scan([{ pid: 4, signals: [7] }])).unreadable).toBe(1)
  })

  it('has nothing to say about an envelope that never arrived', () => {
    expect(readTamperingSignals(null)).toEqual({ rows: [], unreadable: 0 })
  })
})

describe('readSymbolState', () => {
  it('normalises the Debug spelling the analysis serialises', () => {
    expect(readSymbolState('Verified')).toBe('verified')
    expect(readSymbolState('NoMatch')).toBe('no_match')
  })

  it('returns nothing for an absent or unrecognised state, never verified', () => {
    expect(readSymbolState(undefined)).toBeNull()
    expect(readSymbolState('something else')).toBeNull()
  })
})

describe('formatting', () => {
  // One test below stubs the process-wide default locale; leaving that stub in
  // place would silently change what every later test in this file formats.
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('qualifies a total with the rows that weaken it', () => {
    expect(
      formatQualifiedCount(41, [
        { count: 3, label: 'exited' },
        { count: 0, label: 'hidden' },
      ]),
    ).toBe('41 (3 exited)')
  })

  it('renders a bare total only when nothing weakens it', () => {
    expect(formatQualifiedCount(41, [{ count: 0, label: 'exited' }])).toBe('41')
  })

  it('groups every figure the same way, whatever the runtime locale', () => {
    // These strings are read off the screen and quoted into statements, so the
    // separators cannot depend on which machine the examiner is sitting at: on
    // a de-DE runtime a bare `toLocaleString` renders 5000 as "5.000", which an
    // en-GB reader takes for five. Stubbing the default locale rather than
    // reading it, because that is exactly what a de-DE runner does to these
    // numbers.
    vi.spyOn(Number.prototype, 'toLocaleString').mockImplementation(function (
      this: number,
    ) {
      return new Intl.NumberFormat('de-DE').format(Number(this))
    })

    expect(formatQualifiedCount(41_000, [{ count: 3_500, label: 'exited' }])).toBe(
      '41,000 (3,500 exited)',
    )
    expect(inventoryCount(9_000)).toBe('9,000')
    const status = envelopeStatus(
      envelope({
        status: 'incomplete',
        count_is_floor: true,
        records_truncated: true,
        record_count: 5000,
        records_returned: 500,
      }),
    )
    expect(status.kind === 'partial' && status.message).toMatch(/500 of 5,000/)
  })

  it('renders a missing address as a dash, never as 0x0', () => {
    expect(formatAddress(null)).toBe('—')
    expect(toHex(null)).toBeNull()
  })

  it('renders an address in hex', () => {
    expect(toHex(0x1ad000)).toBe('0x1ad000')
  })

  it('marks a kernel address that JSON could not carry exactly, rather than printing it as exact', () => {
    // Every x64 kernel pointer is larger than 2^53 and arrives as a double, so
    // its low bits may already have been rounded. Printing it bare would put a
    // pointer in a report that is wrong by up to a kilobyte.
    const kernel = 0xfffff8030a1b2c30
    expect(Number.isSafeInteger(kernel)).toBe(false)
    expect(toHex(kernel)).toContain('(may be rounded)')
  })

  it('does not qualify an address that is exactly representable', () => {
    expect(toHex(0x7ffd0000)).toBe('0x7ffd0000')
    expect(toHex(0x7ffd0000)).not.toContain('rounded')
  })

  it('prefers the exact _hex sibling over the rounded JSON number', () => {
    // serde_json encodes u64 as an IEEE double; 0xfffff8030a1b2c30 does not
    // survive that, so the number here is already the wrong address. The
    // sibling string is the only exact form on the wire and must win.
    const row = {
      address: 0xfffff8030a1b2c30,
      address_hex: '0xfffff8030a1b2c37',
    }
    expect(hexAddress(row, 'address')).toBe('0xfffff8030a1b2c37')
  })

  it('drops the rounding caveat once the exact form is in hand', () => {
    // A caveat on a value that does not need one teaches an examiner to
    // discount the ones that do.
    const row = {
      address: 0xfffff8030a1b2c30,
      address_hex: '0xfffff8030a1b2c37',
    }
    expect(hexAddress(row, 'address')).not.toContain('rounded')
    expect(toHex(row.address)).toContain('rounded')
  })

  it('falls back to the number, caveat and all, when no sibling was sent', () => {
    const row = { address: 0xfffff8030a1b2c30 }
    expect(hexAddress(row, 'address')).toContain('(may be rounded)')
  })

  it('ignores a sibling that is not a hex literal rather than quoting it', () => {
    // A string this code cannot parse is not evidence of an address. The
    // numeric path at least states its own doubt.
    expect(hexAddress({ address: 0x1000, address_hex: 'ffff' }, 'address')).toBe(
      '0x1000',
    )
    expect(hexAddress({ address: 0x1000, address_hex: '' }, 'address')).toBe(
      '0x1000',
    )
  })

  it('returns null when neither form is present', () => {
    expect(hexAddress({}, 'address')).toBeNull()
    expect(hexAddress(null, 'address')).toBeNull()
  })

  it('renders a missing or unparseable time as a dash', () => {
    expect(formatTime(null)).toBe('—')
    expect(formatTime('not a time')).toBe('—')
  })

  it('renders a time in UTC', () => {
    expect(formatTime('2025-03-11T17:41:55Z')).toBe('2025-03-11 17:41:55Z')
  })

  it('falls back to the raw reason for an incompleteness it has no phrase for', () => {
    expect(incompleteLabel({ reason: 'novel_reason', detail: 'x' })).toBe(
      'novel_reason (x)',
    )
  })
})

describe('lane placement', () => {
  it('uses the real bounds when both are known', () => {
    expect(
      laneAxis('2025-03-11T09:00:00Z', '2025-03-11T17:00:00Z', [])?.bounded,
    ).toBe(true)
  })

  it('falls back to the row span and says so when a bound is missing', () => {
    const axis = laneAxis(null, '2025-03-11T17:00:00Z', [1000, 5000])
    expect(axis?.bounded).toBe(false)
    expect(axis?.label).toMatch(/were not established/)
  })

  it('returns no axis at all when nothing carries a time, rather than inventing one', () => {
    expect(laneAxis(null, null, [null, null])).toBeNull()
  })

  it('places a bar proportionally and clamps one that runs past the axis', () => {
    const axis = { startMs: 0, endMs: 1000, bounded: true, label: 'x' }
    expect(placeOnLane(axis, 250, 750)).toMatchObject({
      leftPercent: 25,
      widthPercent: 50,
    })
    expect(placeOnLane(axis, -500, 5000)).toMatchObject({
      leftPercent: 0,
      widthPercent: 100,
    })
    expect(placeOnLane(axis, null, 500).startUnknown).toBe(true)
    expect(placeOnLane(axis, 500, null).openEnded).toBe(true)
  })
})

describe('splitCredentialsByImage', () => {
  const rec = (
    id: string,
    metadata: Record<string, unknown>,
    parent: string | null,
  ) => ({ id, parent_id: parent, artifact_type: 'ParsedRecord', metadata })

  it('attributes a record that names the selected capture', () => {
    expect(
      splitCredentialsByImage(
        [rec('a', { memory_image_id: 'image-1' }, null)],
        'image-1',
      ).attributed.map((r) => r.id),
    ).toEqual(['a'])
  })

  it('excludes a record that names a different capture but counts it (B4-026)', () => {
    // Dropping it silently makes a multi-capture case read as a single-capture
    // one: the page shows no credentials with no sign that another capture has
    // them.
    expect(
      splitCredentialsByImage(
        [
          rec('a', { memory_image_id: 'other' }, null),
          rec('b', { memory_image_id: 'other' }, null),
          rec('c', { memory_image_id: 'third' }, null),
        ],
        'image-1',
      ),
    ).toEqual({
      attributed: [],
      unattributed: [],
      otherCaptures: [
        { imageId: 'other', count: 2 },
        { imageId: 'third', count: 1 },
      ],
    })
  })

  it('surfaces a record that names no capture rather than dropping it', () => {
    expect(
      splitCredentialsByImage([rec('a', {}, null)], 'image-1').unattributed.map(
        (r) => r.id,
      ),
    ).toEqual(['a'])
  })
})

describe('readCredentialInventory (B3-M01)', () => {
  const record = (metadata: Record<string, unknown>) => ({
    id: 'inv-1',
    parent_id: 'image-1',
    artifact_type: 'ParsedRecord',
    metadata,
  })

  it('decodes the listing the stage actually produces', () => {
    const inventory = readCredentialInventory(
      record({
        plaintext_recovered: false,
        credentials_recovered: 0,
        decryption: 'located and inventoried; not decrypted',
        hives: [
          {
            hive: 'SECURITY',
            available: true,
            bin_source: 'mapped hive bins',
            bin_source_authoritative: false,
            detail: null,
          },
        ],
        accounts: [
          {
            name: 'Administrator',
            rid: 500,
            rid_corroborated: true,
            last_write_filetime: 0,
            notes: ['name read from the key'],
          },
        ],
        account_count: 1,
        secrets: [{ name: 'DPAPI_SYSTEM', last_write_filetime: 0 }],
        secret_count: 1,
        cached_logons: 4,
        listings: [{ key: 'SAM\\Domains', complete: false, detail: 'capped' }],
        inventory_complete: false,
        inventory_incomplete_reason: 'a listing stopped at its cap',
        truncated: true,
      }),
    )

    expect(inventory.plaintextRecovered).toBe(false)
    expect(inventory.credentialsRecovered).toBe(0)
    expect(inventory.accounts).toEqual([
      {
        name: 'Administrator',
        rid: 500,
        ridCorroborated: true,
        lastWriteFiletime: 0,
        notes: ['name read from the key'],
      },
    ])
    expect(inventory.secrets).toEqual([
      { name: 'DPAPI_SYSTEM', lastWriteFiletime: 0 },
    ])
    expect(inventory.hives[0].binSourceAuthoritative).toBe(false)
    expect(inventory.cachedLogons).toBe(4)
    expect(inventory.listings[0]).toEqual({
      key: 'SAM\\Domains',
      complete: false,
      detail: 'capped',
    })
    expect(inventory.inventoryComplete).toBe(false)
    expect(inventory.incompleteReason).toBe('a listing stopped at its cap')
    expect(inventory.truncated).toBe(true)
    expect(inventory.undecodableEntries).toBe(0)
  })

  it('never defaults a count the producer did not state to zero', () => {
    // "No cached domain logon is present" is a finding about the machine.
    // "Nothing counted them" is a hole in the analysis. A zero standing in for
    // the second states the first.
    const inventory = readCredentialInventory(record({}))
    expect(inventory.cachedLogons).toBeNull()
    expect(inventory.accountCount).toBeNull()
    expect(inventory.secretCount).toBeNull()
    expect(inventory.credentialsRecovered).toBeNull()
    expect(inventory.plaintextRecovered).toBeNull()
    expect(inventory.inventoryComplete).toBeNull()
    expect(inventoryCount(inventory.cachedLogons)).toBe('not stated')
    expect(inventoryCount(0)).toBe('0')
  })

  it('counts array entries it could not decode instead of shortening the list', () => {
    const inventory = readCredentialInventory(
      record({
        accounts: [{ name: 'a' }, 'not an object', null],
        secrets: [42],
      }),
    )
    expect(inventory.accounts).toHaveLength(1)
    expect(inventory.undecodableEntries).toBe(3)
  })

  it('falls back to the stage-level incompleteness reason', () => {
    const inventory = readCredentialInventory(
      record({
        content_incomplete_reason: 'the SAM hive was not reachable',
      }),
    )
    expect(inventory.incompleteReason).toBe('the SAM hive was not reachable')
  })
})

describe('filetimeText', () => {
  it('renders a real FILETIME and dashes the zero the producer sends for none', () => {
    expect(filetimeText(132000000000000000)).toBe('2019-04-17 18:40:00Z')
    expect(filetimeText(0)).toBe('—')
    expect(filetimeText(null)).toBe('—')
    // A tick count outside the representable range is a dash, never a guess.
    expect(filetimeText(1e20)).toBe('—')
  })
})
