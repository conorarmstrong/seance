import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SavedViewsMenu } from './SavedViewsMenu'

const KEY = 'seance.views.test'

beforeEach(() => localStorage.clear())

describe('SavedViewsMenu', () => {
  it('saves the current query and applies it later', async () => {
    const onApply = vi.fn()
    render(
      <SavedViewsMenu
        storageKey={KEY}
        currentQuery="search=malware"
        onApply={onApply}
      />,
    )

    await userEvent.click(screen.getByRole('button', { name: /Views/ }))
    expect(screen.getByText('No saved views yet')).toBeInTheDocument()

    await userEvent.type(screen.getByLabelText('View name'), 'Malware hunt')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual([
      { name: 'Malware hunt', query: 'search=malware' },
    ])

    await userEvent.click(screen.getByRole('button', { name: 'Malware hunt' }))
    expect(onApply).toHaveBeenCalledWith('search=malware')
  })

  it('deletes a saved view', async () => {
    localStorage.setItem(KEY, JSON.stringify([{ name: 'Old', query: 'x=1' }]))
    render(
      <SavedViewsMenu storageKey={KEY} currentQuery="" onApply={vi.fn()} />,
    )

    await userEvent.click(screen.getByRole('button', { name: /Views/ }))
    expect(screen.getByRole('button', { name: 'Old' })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Delete view Old' }))
    expect(screen.queryByRole('button', { name: 'Old' })).toBeNull()
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual([])
  })

  it('lists the views of the case in the storage key it was last given (B2-017)', async () => {
    // `storageKey` carries the case. The hosting pages stay mounted when
    // `:caseId` changes, so a menu that read localStorage only at mount showed
    // case A's saved views under case B and applied case A's filter query to
    // case B's table.
    const KEY_A = 'seance.views.timeline.case-A'
    const KEY_B = 'seance.views.timeline.case-B'
    localStorage.setItem(KEY_A, JSON.stringify([{ name: 'A view', query: 'a=1' }]))
    localStorage.setItem(KEY_B, JSON.stringify([{ name: 'B view', query: 'b=2' }]))

    const { rerender } = render(
      <SavedViewsMenu storageKey={KEY_A} currentQuery="" onApply={vi.fn()} />,
    )
    await userEvent.click(screen.getByRole('button', { name: /Views/ }))
    expect(screen.getByRole('button', { name: 'A view' })).toBeInTheDocument()

    rerender(
      <SavedViewsMenu storageKey={KEY_B} currentQuery="" onApply={vi.fn()} />,
    )
    await userEvent.click(screen.getByRole('button', { name: /Views/ }))
    expect(screen.getByRole('button', { name: 'B view' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'A view' })).toBeNull()
  })

  it('never writes one case\'s view list into another case\'s key (B2-017)', async () => {
    // `persist` always writes the CURRENT key. With the list stuck on the one
    // loaded at mount, the next save copied case A's entire view list into case
    // B's localStorage entry, so case A's saved filters became case B's.
    const KEY_A = 'seance.views.timeline.case-A'
    const KEY_B = 'seance.views.timeline.case-B'
    localStorage.setItem(KEY_A, JSON.stringify([{ name: 'A view', query: 'a=1' }]))

    const { rerender } = render(
      <SavedViewsMenu storageKey={KEY_A} currentQuery="a=1" onApply={vi.fn()} />,
    )
    rerender(
      <SavedViewsMenu storageKey={KEY_B} currentQuery="b=2" onApply={vi.fn()} />,
    )

    await userEvent.click(screen.getByRole('button', { name: /Views/ }))
    await userEvent.type(screen.getByLabelText('View name'), 'B only')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(JSON.parse(localStorage.getItem(KEY_B)!)).toEqual([
      { name: 'B only', query: 'b=2' },
    ])
    // Case A's own entry is untouched.
    expect(JSON.parse(localStorage.getItem(KEY_A)!)).toEqual([
      { name: 'A view', query: 'a=1' },
    ])
  })

  it('closes the menu and clears the pending name when the case changes', async () => {
    const KEY_A = 'seance.views.timeline.case-A'
    const KEY_B = 'seance.views.timeline.case-B'
    const { rerender } = render(
      <SavedViewsMenu storageKey={KEY_A} currentQuery="" onApply={vi.fn()} />,
    )
    await userEvent.click(screen.getByRole('button', { name: /Views/ }))
    await userEvent.type(screen.getByLabelText('View name'), 'Half typed')

    rerender(
      <SavedViewsMenu storageKey={KEY_B} currentQuery="" onApply={vi.fn()} />,
    )

    expect(screen.queryByLabelText('View name')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /Views/ }))
    expect(screen.getByLabelText('View name')).toHaveValue('')
  })
})
