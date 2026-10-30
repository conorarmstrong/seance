// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  incompleteReasonLabel,
  incompletenessSentence,
  readIncompleteness,
  summarizeIncompleteness,
  UNREADABLE_FLAG_REASON,
} from './incompleteness'

/**
 * The plugin tree stamps `content_incomplete` / `content_incomplete_reason` and
 * `inventory_incomplete` / `inventory_incomplete_reason` at ~809 sites. Before
 * this module nothing in `frontend/src` read either key, so a truncated hive
 * and a hive that genuinely held three values rendered identically. These pin
 * the reading rules; the component tests pin that they reach the screen.
 */
describe('readIncompleteness', () => {
  it('reads a content stamp with its reason', () => {
    expect(
      readIncompleteness({
        content_incomplete: true,
        content_incomplete_reason: 'cap_reached',
      }),
    ).toEqual([{ scope: 'content', reason: 'cap_reached', detail: null }])
  })

  it('reads an inventory stamp with its reason', () => {
    expect(
      readIncompleteness({
        inventory_incomplete: true,
        inventory_incomplete_reason: 'hive_not_read_in_full',
      }),
    ).toEqual([
      { scope: 'inventory', reason: 'hive_not_read_in_full', detail: null },
    ])
  })

  it('reads both scopes off one record', () => {
    expect(
      readIncompleteness({
        content_incomplete: true,
        content_incomplete_reason: 'short_read',
        inventory_incomplete: true,
        inventory_incomplete_reason: 'cap_reached',
      }),
    ).toEqual([
      { scope: 'content', reason: 'short_read', detail: null },
      { scope: 'inventory', reason: 'cap_reached', detail: null },
    ])
  })

  it('treats an absent or false flag as complete', () => {
    expect(readIncompleteness({})).toEqual([])
    expect(readIncompleteness({ content_incomplete: false })).toEqual([])
    expect(readIncompleteness(null)).toEqual([])
    expect(readIncompleteness(undefined)).toEqual([])
  })

  it('keeps a flag with no reason as incomplete, not as complete', () => {
    // Absence of a reason is not absence of the problem. A parser that set the
    // flag and recorded nothing else still said the result is short.
    expect(readIncompleteness({ content_incomplete: true })).toEqual([
      { scope: 'content', reason: null, detail: null },
    ])
  })

  it('ignores a blank reason string rather than showing an empty phrase', () => {
    expect(
      readIncompleteness({
        content_incomplete: true,
        content_incomplete_reason: '   ',
      }),
    ).toEqual([{ scope: 'content', reason: null, detail: null }])
  })

  it('fails closed when the flag is present but is not a boolean', () => {
    // Metadata is untyped JSON. A flag this code cannot read is a question it
    // cannot answer, and "cannot answer" must never render as "complete".
    for (const flag of ['true', 'false', 1, 0, {}, []]) {
      expect(readIncompleteness({ content_incomplete: flag })).toEqual([
        { scope: 'content', reason: UNREADABLE_FLAG_REASON, detail: null },
      ])
    }
  })

  it('reads the filesystem parsers’ folder flag as the same kind of stamp', () => {
    // ext4, FAT/exFAT, XFS, btrfs, APFS and ISO 9660 stamp
    // `directory_parse_incomplete` on the FOLDER whose listing they could not
    // finish. It predates content/inventory and is written at ~31 sites. Read
    // through the same reader, or the file browser — the place an examiner
    // decides a path is not in the evidence — shows a capped folder listing
    // as a complete one.
    expect(
      readIncompleteness({
        directory_parse_incomplete: true,
        directory_parse_incomplete_reason: 'fat_chain_incomplete',
      }),
    ).toEqual([
      { scope: 'directory', reason: 'fat_chain_incomplete', detail: null },
    ])
  })

  it('keeps the folder flag incomplete when the parser recorded no reason', () => {
    // The ext4 path stamps the flag alone.
    expect(readIncompleteness({ directory_parse_incomplete: true })).toEqual([
      { scope: 'directory', reason: null, detail: null },
    ])
  })

  it('carries the parser’s own sentence alongside the reason token', () => {
    // `compressed` is a category; the detail says what to do about this record.
    expect(
      readIncompleteness({
        content_incomplete: true,
        content_incomplete_reason: 'compressed',
        content_incomplete_detail:
          '7z uses solid compression; per-entry content is not extracted by this ingest',
      }),
    ).toEqual([
      {
        scope: 'content',
        reason: 'compressed',
        detail:
          '7z uses solid compression; per-entry content is not extracted by this ingest',
      },
    ])
  })
})

describe('incompleteReasonLabel', () => {
  it('gives a sentence for each shared IncompleteReason', () => {
    // The five in seance_core::io::IncompleteReason.
    for (const reason of [
      'cap_reached',
      'short_read',
      'unresolved_structure',
      'encrypted',
      'compressed',
    ]) {
      const label = incompleteReasonLabel(reason)
      expect(label).not.toBe(reason)
      expect(label.length).toBeGreaterThan(reason.length)
    }
  })

  it('keeps a parser-specific reason it has no phrase for', () => {
    // The vocabulary is open — plugins stamp their own reasons. Swallowing one
    // would leave a warning with nothing an examiner could act on.
    expect(incompleteReasonLabel('btrfs_extent_off_primary_device')).toBe(
      'btrfs extent off primary device',
    )
  })

  it('says so when no reason was recorded', () => {
    expect(incompleteReasonLabel(null)).toBe('no reason was recorded')
  })

  it('distinguishes the two shared reasons an examiner must act on differently', () => {
    expect(incompleteReasonLabel('cap_reached')).not.toBe(
      incompleteReasonLabel('encrypted'),
    )
  })
})

describe('summarizeIncompleteness', () => {
  const clean = { metadata: { name: 'a' } }
  const capped = {
    metadata: { content_incomplete: true, content_incomplete_reason: 'cap_reached' },
  }
  const short = {
    metadata: { content_incomplete: true, content_incomplete_reason: 'short_read' },
  }

  it('counts what it inspected and what was stamped', () => {
    const summary = summarizeIncompleteness([clean, capped, capped, short])
    expect(summary.examined).toBe(4)
    expect(summary.affected).toBe(3)
  })

  it('tallies each distinct reason, most frequent first', () => {
    const summary = summarizeIncompleteness([short, capped, capped])
    expect(summary.tallies).toEqual([
      { scope: 'content', reason: 'cap_reached', count: 2 },
      { scope: 'content', reason: 'short_read', count: 1 },
    ])
  })

  it('counts a record with two scopes once, but tallies both reasons', () => {
    const summary = summarizeIncompleteness([
      {
        metadata: {
          content_incomplete: true,
          content_incomplete_reason: 'short_read',
          inventory_incomplete: true,
          inventory_incomplete_reason: 'cap_reached',
        },
      },
    ])
    expect(summary.affected).toBe(1)
    expect(summary.tallies).toHaveLength(2)
  })

  it('reports nothing affected for an all-clean set', () => {
    const summary = summarizeIncompleteness([clean, clean])
    expect(summary).toEqual({
      examined: 2,
      affected: 0,
      tallies: [],
      superseded: 0,
    })
  })

  it('handles a missing record set without pretending it inspected any', () => {
    expect(summarizeIncompleteness(null)).toEqual({
      examined: 0,
      affected: 0,
      tallies: [],
      superseded: 0,
    })
  })
})

describe('incompletenessSentence', () => {
  it('names scope and reason for each stamp', () => {
    const sentence = incompletenessSentence([
      { scope: 'content', reason: 'cap_reached', detail: null },
      { scope: 'inventory', reason: null, detail: null },
    ])
    expect(sentence).toContain('content incomplete')
    expect(sentence).toContain('safety cap')
    expect(sentence).toContain('listing incomplete')
    expect(sentence).toContain('no reason was recorded')
  })

  it('is empty for a complete record', () => {
    expect(incompletenessSentence([])).toBe('')
  })

  it('carries the parser’s sentence into the badge text, not just the token', () => {
    // The badge is the one place an examiner may never click past, so nothing
    // the parser wrote is dropped for want of room.
    expect(
      incompletenessSentence([
        {
          scope: 'directory',
          reason: 'btrfs_max_dir_entries',
          detail: 'stopped after 65536 entries',
        },
      ]),
    ).toContain('stopped after 65536 entries')
  })
})

// UI-042: `content_incomplete_reasons` lists every reason a record was stamped
// with (the jump-list parser, and the SQLite staging stamp since HUNT-186, which
// keeps the first reason primary and adds a short read beside it). Only the
// primary was read, so the second reached the screen only when the parser's
// sentence happened to mention it.
const TWO_REASONS = {
  content_incomplete: true,
  content_incomplete_reason: 'unresolved_structure',
  content_incomplete_reasons: ['unresolved_structure', 'short_read'],
}

describe('a second incompleteness reason (UI-042)', () => {
  it('is read off the record beside the primary one', () => {
    const [stamp] = readIncompleteness(TWO_REASONS)
    expect(stamp.reason).toBe('unresolved_structure')
    expect(stamp.additionalReasons).toEqual(['short_read'])
  })

  it('reaches the badge sentence in words, not only the primary', () => {
    const sentence = incompletenessSentence(readIncompleteness(TWO_REASONS))
    expect(sentence).toContain('could not be located or parsed')
    expect(sentence).toContain('fewer bytes than the structure requires')
  })

  it('is tallied in a listing summary under its own reason', () => {
    const summary = summarizeIncompleteness([{ metadata: TWO_REASONS }])
    expect(summary.affected).toBe(1)
    expect(summary.tallies.map((t) => t.reason).sort()).toEqual([
      'short_read',
      'unresolved_structure',
    ])
  })

  it('takes the list as the reason when no singular reason was written', () => {
    const [stamp] = readIncompleteness({
      content_incomplete: true,
      content_incomplete_reasons: ['cap_reached', 'short_read'],
    })
    expect(stamp.reason).toBe('cap_reached')
    expect(stamp.additionalReasons).toEqual(['short_read'])
  })

  it('adds nothing for a record with one reason, listed or not', () => {
    const [stamp] = readIncompleteness({
      content_incomplete: true,
      content_incomplete_reason: 'cap_reached',
      content_incomplete_reasons: ['cap_reached'],
    })
    expect(stamp.additionalReasons).toBeUndefined()
  })
})
