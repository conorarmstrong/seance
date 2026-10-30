import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { TimelineEvent } from '../../api/types'
import { TagNoteModal } from './TagNoteModal'

const EVENT = {
  id: 'ev-1',
  case_id: 'case-1',
  artifact_id: 'art-1',
  timestamp: 1_767_225_600,
  timestamp_desc: 'File created',
  source_module: 'mft',
  short_desc: 'USB device inserted',
  full_details: '',
  tag_note: null,
} as unknown as TimelineEvent

describe('TagNoteModal', () => {
  it('tells the examiner the note is written for the report, before they write it', () => {
    render(
      <TagNoteModal
        event={EVENT}
        saving={false}
        onSave={() => {}}
        onClose={() => {}}
      />,
    )

    const box = screen.getByLabelText('Note')
    // The destination is attached to the field itself, so a screen reader
    // announces it as part of the control rather than as loose page text.
    const described = box.getAttribute('aria-describedby')
    expect(described).toBeTruthy()
    expect(document.getElementById(described!)?.textContent).toMatch(
      /Timeline Highlights/,
    )
    expect(document.getElementById(described!)?.textContent).toMatch(
      /your name/i,
    )
  })
})
