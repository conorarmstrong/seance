import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import {
  AgreementGlyph,
  ConfidenceChip,
  EvidenceBadge,
  SymbolStatusBanner,
} from './confidence'
import type { RecordConfidence } from './normalize'

const clean: RecordConfidence = {
  derivation: 'linked',
  sources: ['list walk'],
  incomplete: null,
  symbol_confidence: 'verified',
  profile_evidence: 'confirmed',
}

describe('ConfidenceChip', () => {
  it('shows the weakest axis as the chip label', () => {
    const { container } = render(
      <ConfidenceChip
        confidence={{ ...clean, incomplete: { reason: 'cap_reached', detail: null } }}
      />,
    )
    expect(container.querySelector('.mem-conf-summary .badge')?.textContent).toBe(
      'partial',
    )
  })

  it('renders a row with no confidence metadata as unreliable rather than as clean', () => {
    const { container } = render(<ConfidenceChip confidence={null} />)
    expect(container.querySelector('.mem-conf-summary .badge')?.textContent).toBe(
      'unreliable',
    )
  })

  it('gives a scanned row a different accessible label from a linked one', () => {
    const linked = render(<ConfidenceChip confidence={clean} />)
    const linkedLabel = linked.container
      .querySelector('summary')
      ?.getAttribute('aria-label')
    linked.unmount()

    const scanned = render(
      <ConfidenceChip confidence={{ ...clean, derivation: 'scanned' }} />,
    )
    const scannedLabel = scanned.container
      .querySelector('summary')
      ?.getAttribute('aria-label')

    expect(linkedLabel).not.toBe(scannedLabel)
    expect(scannedLabel).toMatch(/scanned/)
  })

  it('explains every axis when the popover is opened', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <ConfidenceChip
        confidence={{
          derivation: 'scanned',
          sources: ['pool scan'],
          incomplete: { reason: 'read_hole', detail: '0x2000 for 8 KiB' },
          symbol_confidence: 'unverified',
          profile_evidence: 'scanned',
        }}
        provenance={[{ label: 'EPROCESS', value: '0x1000' }]}
      />,
    )
    await user.click(container.querySelector('summary')!)
    expect(screen.getByText('derivation')).toBeInTheDocument()
    expect(screen.getByText('corroboration')).toBeInTheDocument()
    expect(screen.getByText('reads')).toBeInTheDocument()
    expect(screen.getByText('symbols')).toBeInTheDocument()
    expect(screen.getByText('profile')).toBeInTheDocument()
    expect(screen.getByText(/0x2000 for 8 KiB/)).toBeInTheDocument()
    expect(screen.getByText('EPROCESS')).toBeInTheDocument()
  })
})

describe('EvidenceBadge', () => {
  it('states a grade the server did not supply as an explicit gap, not a pass', () => {
    render(<EvidenceBadge grade={null} />)
    expect(screen.getByText('not stated')).toBeInTheDocument()
  })

  it('describes a scanned value as unconfirmed', () => {
    render(<EvidenceBadge grade="scanned" />)
    expect(
      screen.getByLabelText(/no independent check available/i),
    ).toBeInTheDocument()
  })

  it('describes a confirmed value as read and then proved', () => {
    render(<EvidenceBadge grade="confirmed" />)
    expect(screen.getByLabelText(/confirmed by using it/i)).toBeInTheDocument()
  })
})

describe('SymbolStatusBanner', () => {
  it('says structured enumeration cannot run when no symbol table matched', () => {
    render(<SymbolStatusBanner state="no_match" />)
    expect(screen.getByText(/cannot run/i)).toBeInTheDocument()
  })

  it('says an unverified table proved nothing rather than reporting it as fine', () => {
    render(<SymbolStatusBanner state="unverified" />)
    expect(screen.getByText(/nothing proved it either/i)).toBeInTheDocument()
  })

  it('treats a state the profile never reported as its own case, not as verified', () => {
    render(<SymbolStatusBanner state={null} />)
    expect(screen.getByText('symbols not stated')).toBeInTheDocument()
    expect(screen.getByText(/the question was not answered/i)).toBeInTheDocument()
  })
})

describe('AgreementGlyph', () => {
  const methods = [
    { key: 'list', label: 'list walk', ran: true, error: null },
    { key: 'scan', label: 'pool scan', ran: true, error: null },
    { key: 'csrss', label: 'csrss handles', ran: false, error: 'stage crashed' },
  ]

  it('marks a strategy that did not run as not checked, never as not seen', () => {
    render(
      <AgreementGlyph
        methods={methods}
        row={{
          pid: 4,
          name: 'System',
          seen: { list: true, scan: false, csrss: false },
        }}
      />,
    )
    expect(
      screen.getByLabelText(
        'seen by list walk; not seen by pool scan; not checked by csrss handles',
      ),
    ).toBeInTheDocument()
  })

  it('says so when no strategy reported at all, rather than drawing an empty vector', () => {
    render(<AgreementGlyph methods={[]} row={undefined} />)
    expect(
      screen.getByLabelText('no enumeration strategies reported'),
    ).toBeInTheDocument()
  })
})
