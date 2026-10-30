import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'

import { Modal } from './Modal'

function Harness() {
  const [open, setOpen] = useState(false)
  return (
    <div>
      <button onClick={() => setOpen(true)}>open modal</button>
      {open && (
        <Modal
          title="Test modal"
          onClose={() => setOpen(false)}
          footer={<button>Save</button>}
        >
          <input aria-label="Field" />
        </Modal>
      )}
    </div>
  )
}

describe('Modal', () => {
  it('moves initial focus to the first focusable element', async () => {
    render(<Harness />)
    await userEvent.click(screen.getByText('open modal'))
    expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus()
  })

  it('respects autoFocus inside the modal body', async () => {
    function AutoFocusHarness() {
      const [open, setOpen] = useState(false)
      return (
        <div>
          <button onClick={() => setOpen(true)}>open modal</button>
          {open && (
            <Modal title="Auto" onClose={() => setOpen(false)}>
              <input aria-label="Auto field" autoFocus />
            </Modal>
          )}
        </div>
      )
    }
    render(<AutoFocusHarness />)
    await userEvent.click(screen.getByText('open modal'))
    expect(screen.getByLabelText('Auto field')).toHaveFocus()
  })

  it('traps Tab and Shift+Tab within the dialog', async () => {
    render(<Harness />)
    await userEvent.click(screen.getByText('open modal'))
    // Focus order: Close button, input, Save button.
    expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus()
    await userEvent.tab()
    expect(screen.getByLabelText('Field')).toHaveFocus()
    await userEvent.tab()
    expect(screen.getByRole('button', { name: 'Save' })).toHaveFocus()
    // Tab from the last element wraps to the first.
    await userEvent.tab()
    expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus()
    // Shift+Tab from the first wraps back to the last.
    await userEvent.tab({ shift: true })
    expect(screen.getByRole('button', { name: 'Save' })).toHaveFocus()
  })

  it('closes on Escape and restores focus to the opener', async () => {
    render(<Harness />)
    const opener = screen.getByText('open modal')
    await userEvent.click(opener)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(opener).toHaveFocus()
  })
})
