import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { CommandPalette, type Command } from './CommandPalette'

// ⌘K bubbles from the body up to the window listener.
function pressCmdK() {
  fireEvent.keyDown(document.body, { key: 'k', metaKey: true })
}

describe('CommandPalette', () => {
  it('opens on ⌘K, filters, and runs a command on Enter', async () => {
    const runTimeline = vi.fn()
    const commands: Command[] = [
      { id: 'a', label: 'Go to Timeline', run: runTimeline },
      { id: 'b', label: 'Go to Gallery', run: vi.fn() },
    ]
    render(<CommandPalette commands={commands} />)

    expect(screen.queryByRole('dialog')).toBeNull()
    pressCmdK()
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    await userEvent.type(screen.getByLabelText('Command'), 'timel')
    expect(screen.getByText('Go to Timeline')).toBeInTheDocument()
    expect(screen.queryByText('Go to Gallery')).toBeNull()

    fireEvent.keyDown(screen.getByLabelText('Command'), { key: 'Enter' })
    expect(runTimeline).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('offers a search fallback that calls onSearch', async () => {
    const onSearch = vi.fn()
    render(
      <CommandPalette
        commands={[{ id: 'a', label: 'Go to Timeline', run: vi.fn() }]}
        onSearch={onSearch}
      />,
    )
    pressCmdK()
    await userEvent.type(screen.getByLabelText('Command'), 'malware.exe')

    const item = screen.getByText(/Search evidence for/)
    expect(item).toBeInTheDocument()
    await userEvent.click(item)
    expect(onSearch).toHaveBeenCalledWith('malware.exe')
  })

  it('closes on Escape', () => {
    render(
      <CommandPalette commands={[{ id: 'a', label: 'X', run: vi.fn() }]} />,
    )
    pressCmdK()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.keyDown(screen.getByLabelText('Command'), { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('CommandPalette keyboard ergonomics', () => {
  const many: Command[] = Array.from({ length: 30 }, (_, i) => ({
    id: `c${i}`,
    label: `Go to View ${i}`,
    run: vi.fn(),
  }))

  it('keeps the selected row on screen while arrowing down a long list', async () => {
    // The list is capped at 46vh, so past roughly the twelfth item the active
    // row leaves it and the examiner is arrowing blind.
    const scrollIntoView = vi.fn()
    ;(HTMLElement.prototype as unknown as Record<string, unknown>).scrollIntoView =
      scrollIntoView
    try {
      render(<CommandPalette commands={many} />)
      pressCmdK()
      scrollIntoView.mockClear()

      const input = screen.getByLabelText('Command')
      fireEvent.keyDown(input, { key: 'ArrowDown' })

      expect(scrollIntoView).toHaveBeenCalledWith({ block: 'nearest' })
    } finally {
      delete (HTMLElement.prototype as unknown as Record<string, unknown>)
        .scrollIntoView
    }
  })

  it('gives focus back to where the examiner was when it closes', async () => {
    render(
      <div>
        <button>somewhere in the page</button>
        <CommandPalette commands={many} />
      </div>,
    )
    const anchor = screen.getByText('somewhere in the page')
    anchor.focus()

    pressCmdK()
    // The palette focuses its input on a zero-delay timeout, after the render.
    await waitFor(() => expect(screen.getByLabelText('Command')).toHaveFocus())
    fireEvent.keyDown(screen.getByLabelText('Command'), { key: 'Escape' })

    // Focus landing on <body> would make the next Tab restart from the top of
    // the page, undoing the position the palette was supposed to preserve.
    await waitFor(() => expect(anchor).toHaveFocus())
  })

  it('matches on a subsequence, not only a contiguous substring', async () => {
    render(
      <CommandPalette
        commands={[
          { id: 'a', label: 'Go to Timeline', run: vi.fn() },
          { id: 'b', label: 'Go to Gallery', run: vi.fn() },
        ]}
      />,
    )
    pressCmdK()
    // "tml" is how a hand in a hurry types "timeline"; a bare `includes`
    // finds nothing and the palette looks broken.
    await userEvent.type(screen.getByLabelText('Command'), 'tml')
    expect(screen.getByText('Go to Timeline')).toBeInTheDocument()
    expect(screen.queryByText('Go to Gallery')).toBeNull()
  })

  it('ranks a word-start match above a match scattered through the label', async () => {
    render(
      <CommandPalette
        commands={[
          { id: 'a', label: 'Go to Saved Exhibit Archive', run: vi.fn() },
          { id: 'b', label: 'Go to Search', run: vi.fn() },
        ]}
      />,
    )
    pressCmdK()
    await userEvent.type(screen.getByLabelText('Command'), 'sea')

    // Both labels contain s, e and a in that order, so both match. The one
    // that spells "sea" as a run at the start of a word is the one the
    // examiner meant, and it has to be the row Enter would take.
    const labels = screen
      .getAllByRole('option')
      .map((el) => el.textContent ?? '')
    expect(labels).toHaveLength(2)
    expect(labels[0]).toContain('Go to Search')
  })

  it('finds a view by a word the examiner says but the label never uses', async () => {
    // "Where are the chats" is the question; "Communications" is the answer's
    // filing name. Matching the label alone answers "No matches", and the
    // examiner concludes the product has no comms view at all.
    render(
      <CommandPalette
        commands={[
          { id: 'a', label: 'Go to Timeline', run: vi.fn() },
          {
            id: 'b',
            label: 'Go to Communications',
            keywords: ['chats', 'messages', 'whatsapp'],
            run: vi.fn(),
          },
        ]}
      />,
    )
    pressCmdK()
    await userEvent.type(screen.getByLabelText('Command'), 'whatsapp')

    expect(screen.getByText('Go to Communications')).toBeInTheDocument()
    expect(screen.queryByText('Go to Timeline')).toBeNull()
  })

  it('shows which alias matched, so the examiner learns the view’s real name', async () => {
    render(
      <CommandPalette
        commands={[
          {
            id: 'b',
            label: 'Go to Communications',
            keywords: ['chats', 'messages'],
            run: vi.fn(),
          },
        ]}
      />,
    )
    pressCmdK()
    await userEvent.type(screen.getByLabelText('Command'), 'chats')

    // Without this the row reads as an unexplained hit: the examiner typed a
    // word that appears nowhere in the row they are being offered.
    const option = screen.getAllByRole('option')[0]
    expect(option.textContent).toContain('chats')
  })

  it('does not annotate a row with an alias when the row’s own name matched', async () => {
    // Which view outranks which is settled against the real destination list in
    // commands.test.ts. What belongs here is the rule the palette itself owns:
    // an alias is shown only when it is what made the row match, so it never
    // reads as a second, competing name for a view the query already named.
    render(
      <CommandPalette
        commands={[
          { id: 'a', label: 'Go to Gallery', keywords: ['media'], run: vi.fn() },
        ]}
      />,
    )
    pressCmdK()
    await userEvent.type(screen.getByLabelText('Command'), 'gallery')

    const option = screen.getAllByRole('option')[0]
    expect(option.textContent).toBe('Go to Gallery')
  })

  it('ranks an exact alias above letters scavenged out of an unrelated label', async () => {
    // "gps" really does appear as a subsequence of "Go to Duplicates", and no
    // examiner who types gps wants the duplicates page ahead of the map. This
    // is why an alias match is penalised rather than demoted to a lower tier.
    render(
      <CommandPalette
        commands={[
          { id: 'a', label: 'Go to Duplicates', run: vi.fn() },
          { id: 'b', label: 'Go to Map', keywords: ['gps'], run: vi.fn() },
        ]}
      />,
    )
    pressCmdK()
    await userEvent.type(screen.getByLabelText('Command'), 'gps')

    const labels = screen.getAllByRole('option').map((el) => el.textContent ?? '')
    expect(labels[0]).toContain('Go to Map')
  })

  it('keeps a command’s own hint rather than overwriting it with an alias', async () => {
    render(
      <CommandPalette
        commands={[
          {
            id: 'a',
            label: 'Go to Gallery',
            hint: '⇧G',
            keywords: ['photos'],
            run: vi.fn(),
          },
        ]}
      />,
    )
    pressCmdK()
    await userEvent.type(screen.getByLabelText('Command'), 'photos')
    const option = screen.getAllByRole('option')[0]
    expect(option.textContent).toContain('⇧G')
  })

  it('exposes the list as a listbox and names the active option', async () => {
    render(<CommandPalette commands={many} />)
    pressCmdK()
    const input = screen.getByLabelText('Command')
    expect(screen.getByRole('listbox')).toBeInTheDocument()

    const first = screen.getAllByRole('option')[0]
    expect(input).toHaveAttribute('aria-activedescendant', first.id)
    expect(first).toHaveAttribute('aria-selected', 'true')

    fireEvent.keyDown(input, { key: 'ArrowDown' })
    const second = screen.getAllByRole('option')[1]
    expect(input).toHaveAttribute('aria-activedescendant', second.id)
  })
})
