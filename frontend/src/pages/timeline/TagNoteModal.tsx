import { useState } from 'react'
import type { TimelineEvent } from '../../api/types'
import { Modal } from '../../components/Modal'

/**
 * Where a tag note goes, said on the form that collects it.
 *
 * It did not use to go anywhere. `gather_report_data` mapped tagged events
 * through `|(event, _examiner, _note)|` and the report's Timeline Highlights
 * table printed timestamp, description and source module only — so the sentence
 * an examiner wrote to explain why an event mattered lived inside the
 * application and never reached the document a court reads. The note and the
 * attribution now reach the HTML report, the PDF and the workbook, and the form
 * says so: an examiner writing here is writing for the record, and needs to
 * know that before they write it rather than after it is disclosed.
 */
const NOTE_DESTINATION =
  'This note and your name are printed in the report’s Timeline Highlights ' +
  'section, beside the event. Write it as something a court will read.'

export function TagNoteModal({
  event,
  saving,
  onSave,
  onClose,
}: {
  event: TimelineEvent
  saving: boolean
  onSave: (note: string) => void
  onClose: () => void
}) {
  const [note, setNote] = useState(event.tag_note ?? '')

  return (
    <Modal
      title="Tag note"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={saving}
            onClick={() => onSave(note.trim())}
          >
            {saving ? 'Saving…' : 'Save note'}
          </button>
        </>
      }
    >
      <div className="tl-form-field">
        <label htmlFor="tl-tag-note-input">Note</label>
        <textarea
          id="tl-tag-note-input"
          className="input tl-note-input"
          rows={4}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Why is this event significant?"
          aria-describedby="tl-tag-note-destination"
        />
        {/* Styled inline rather than through timeline.css: this modal is the
            only thing that needs the rule, and the surrounding
            `.tl-form-field` already supplies the size and spacing. */}
        <p
          id="tl-tag-note-destination"
          style={{ margin: 0, color: 'var(--text-2)' }}
        >
          {NOTE_DESTINATION}
        </p>
      </div>
    </Modal>
  )
}
