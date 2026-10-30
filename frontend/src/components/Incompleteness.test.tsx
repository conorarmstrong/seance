import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { summarizeIncompleteness } from '../lib/incompleteness'
import {
  ArtifactIncompleteness,
  IncompleteBadge,
  IncompletenessBanner,
  IncompletenessChip,
} from './Incompleteness'

/**
 * The consumer end of the standard pair. Each of these fails against a UI that
 * reads the flag but drops the reason, or that shows a warning whether or not
 * anything was stamped.
 */
const capped = {
  metadata: {
    content_incomplete: true,
    content_incomplete_reason: 'cap_reached',
  },
}
const encrypted = {
  metadata: {
    content_incomplete: true,
    content_incomplete_reason: 'encrypted',
  },
}
const clean = { metadata: { name: 'whole' } }

describe('IncompletenessBanner', () => {
  it('states how many of the records shown are short', () => {
    render(
      <IncompletenessBanner
        summary={summarizeIncompleteness([clean, capped, capped])}
        noun="hive records"
      />,
    )
    const note = screen.getByRole('note')
    expect(note).toHaveTextContent('2 of the 3 hive records')
  })

  it('names the reason, not merely that something is incomplete', () => {
    // "512 MiB hive cap reached" and "records could not be decoded" call for
    // different follow-up; a banner that says only "incomplete" tells the
    // examiner nothing they can act on.
    render(
      <IncompletenessBanner summary={summarizeIncompleteness([capped])} />,
    )
    expect(screen.getByRole('note')).toHaveTextContent('safety cap')
  })

  it('keeps two different reasons apart instead of merging them', () => {
    render(
      <IncompletenessBanner
        summary={summarizeIncompleteness([capped, encrypted])}
      />,
    )
    const note = screen.getByRole('note')
    expect(note).toHaveTextContent('safety cap')
    expect(note).toHaveTextContent('encrypted')
  })

  it('says a reason was not recorded rather than going quiet', () => {
    render(
      <IncompletenessBanner
        summary={summarizeIncompleteness([
          { metadata: { inventory_incomplete: true } },
        ])}
      />,
    )
    const note = screen.getByRole('note')
    expect(note).toHaveTextContent('listing incomplete')
    expect(note).toHaveTextContent('no reason was recorded')
  })

  it('renders nothing when nothing is stamped', () => {
    // A banner that is always present is a banner an examiner stops reading.
    const { container } = render(
      <IncompletenessBanner summary={summarizeIncompleteness([clean, clean])} />,
    )
    expect(container).toBeEmptyDOMElement()
  })
})

describe('ArtifactIncompleteness', () => {
  it('explains what an incomplete artifact means for what is derived from it', () => {
    render(<ArtifactIncompleteness metadata={capped.metadata} />)
    const note = screen.getByRole('note')
    expect(note).toHaveTextContent('content incomplete')
    expect(note).toHaveTextContent('safety cap')
  })

  it('shows the raw reason token beside the phrase', () => {
    // The phrase is for reading; the token is what an examiner quotes and what
    // matches the artifact's own metadata.
    render(<ArtifactIncompleteness metadata={encrypted.metadata} />)
    expect(screen.getByRole('note')).toHaveTextContent('encrypted')
  })

  it('renders nothing for a whole artifact', () => {
    const { container } = render(
      <ArtifactIncompleteness metadata={clean.metadata} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing when there is no metadata at all', () => {
    const { container } = render(<ArtifactIncompleteness metadata={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the parser’s own sentence, which the token cannot carry', () => {
    // `compressed` says a category. The detail says what actually happened to
    // this record, and it is the only part an examiner can act on.
    render(
      <ArtifactIncompleteness
        metadata={{
          content_incomplete: true,
          content_incomplete_reason: 'compressed',
          content_incomplete_detail:
            '7z uses solid compression; per-entry content is not extracted by this ingest',
        }}
      />,
    )
    expect(screen.getByRole('note')).toHaveTextContent(
      'solid compression; per-entry content is not extracted',
    )
  })

  it('reports a folder whose listing the filesystem parser could not finish', () => {
    // The ~31 `directory_parse_incomplete` sites are the same defect as the
    // pair, under the filesystem parsers' older name. An examiner reading a
    // folder must be told the listing is a floor.
    render(
      <ArtifactIncompleteness
        metadata={{
          directory_parse_incomplete: true,
          directory_parse_incomplete_reason: 'fat_chain_incomplete',
        }}
      />,
    )
    const note = screen.getByRole('note')
    expect(note).toHaveTextContent('folder listing incomplete')
    expect(note).toHaveTextContent('cluster chain')
  })
})

describe('IncompleteBadge', () => {
  it('carries the reason in its accessible name, not just a warning glyph', () => {
    render(<IncompleteBadge metadata={capped.metadata} />)
    expect(screen.getByRole('note')).toHaveAccessibleName(
      /content incomplete.*safety cap/i,
    )
  })

  it('renders nothing for a complete record', () => {
    const { container } = render(<IncompleteBadge metadata={clean.metadata} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('IncompletenessChip', () => {
  it('carries the counts and every reason in its accessible name', () => {
    render(
      <IncompletenessChip
        summary={summarizeIncompleteness([clean, capped, encrypted])}
        noun="images"
      />,
    )
    const chip = screen.getByRole('note')
    expect(chip).toHaveAccessibleName(/2 of the 3 images/)
    expect(chip).toHaveAccessibleName(/safety cap/)
    expect(chip).toHaveAccessibleName(/encrypted/)
  })

  it('renders nothing when nothing is stamped', () => {
    const { container } = render(
      <IncompletenessChip summary={summarizeIncompleteness([clean])} />,
    )
    expect(container).toBeEmptyDOMElement()
  })
})

describe('a shortfall a later run answered', () => {
  // HUNT-090. An encrypted iOS backup ingested without a password records that
  // no files from it are in the case. Supplying the password is the action that
  // record asks for — and it leaves the sentence standing. Warning about it
  // afterwards sends an examiner looking for data that is in the same case.
  const superseded = {
    content_incomplete: true,
    content_incomplete_reason: 'encrypted',
    inventory_incomplete: true,
    inventory_incomplete_reason: 'encrypted',
    superseded: true,
    superseded_by: '41f15f15-bd59-4b47-9150-d0e093873cc2',
  }

  it('is shown as history, not as a live warning', () => {
    render(<ArtifactIncompleteness metadata={superseded} />)
    const note = screen.getByRole('note')
    expect(note.className).not.toContain('warn-note')
    expect(note.textContent).toMatch(/superseded/i)
    expect(note.textContent).toMatch(/subsequently recovered/i)
    // What it recorded is still readable: the refusal happened.
    expect(note.textContent).toMatch(/encrypted/)
    // And it names the record that answered it.
    expect(note.textContent).toContain('41f15f15-bd59-4b47-9150-d0e093873cc2')
  })

  it('does not count towards the incomplete total of a listing', () => {
    const summary = summarizeIncompleteness([
      { metadata: superseded },
      { metadata: { content_incomplete: true, content_incomplete_reason: 'cap_reached' } },
    ])
    expect(summary.examined).toBe(2)
    expect(summary.affected).toBe(1)
    expect(summary.superseded).toBe(1)
    // The surviving shortfall is the only one tallied.
    expect(summary.tallies).toHaveLength(1)
    expect(summary.tallies[0].reason).toBe('cap_reached')
  })

  it('is still stated when nothing else in the listing is short', () => {
    const summary = summarizeIncompleteness([{ metadata: superseded }])
    render(<IncompletenessBanner summary={summary} noun="records" />)
    expect(screen.getByRole('note').textContent).toMatch(
      /1 records here recorded a shortfall that a later run answered/i,
    )
  })

  it('badges as superseded, keeping the reason in the accessible name', () => {
    render(<IncompleteBadge metadata={superseded} />)
    const badge = screen.getByRole('note')
    expect(badge.textContent).toBe('superseded')
    expect(badge.className).not.toContain('badge-warn')
    expect(badge.getAttribute('aria-label')).toMatch(/encrypted at rest/i)
  })
})

describe('a second incompleteness reason (UI-042)', () => {
  it('is rendered on the artifact banner with its token and its meaning', () => {
    render(
      <ArtifactIncompleteness
        metadata={{
          content_incomplete: true,
          content_incomplete_reason: 'unresolved_structure',
          content_incomplete_reasons: ['unresolved_structure', 'short_read'],
        }}
      />,
    )
    const note = screen.getByRole('note')
    expect(note).toHaveTextContent('unresolved_structure')
    expect(note).toHaveTextContent('short_read')
    expect(note).toHaveTextContent('fewer bytes than the structure requires')
  })
})
